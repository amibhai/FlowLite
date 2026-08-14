"""A deliberately small, strict YAML subset parser.

FlowLite's core has no third-party dependencies, but its configuration files are
YAML. When PyYAML is installed FlowLite always uses it. When it is not, this
module parses the subset of YAML that FlowLite's own configuration format uses:

* block mappings nested by space indentation
* block sequences (``- value`` and ``- key: value``)
* inline flow sequences and mappings (``[a, b]``, ``{a: 1}``)
* scalars: null, booleans, ints, floats, single/double quoted and plain strings
* ``#`` comments and a leading ``---`` document marker

Anything outside that subset -- anchors, aliases, tags, block scalars, multiple
documents, tab indentation -- raises :class:`~flowlite.errors.ConfigError` with a
line number rather than guessing. Silently misreading a config is far worse than
refusing to read it, so this parser fails loudly and tells the operator to
``pip install PyYAML``.
"""

from __future__ import annotations

import re
from typing import Any, List, Tuple

from .errors import ConfigError

__all__ = ["safe_load", "parse"]

_UNSUPPORTED = {
    "&": "anchors",
    "*": "aliases",
    "!": "tags",
    "|": "block scalars",
    ">": "folded scalars",
    "%": "directives",
}

_INT_RE = re.compile(r"^[+-]?\d+$")
_HEX_RE = re.compile(r"^[+-]?0[xX][0-9a-fA-F]+$")
_OCT_RE = re.compile(r"^[+-]?0[oO][0-7]+$")
_FLOAT_RE = re.compile(r"^[+-]?(\d+\.\d*|\.\d+|\d+)([eE][+-]?\d+)?$")

_NULLS = {"", "~", "null", "Null", "NULL"}
_TRUES = {"true", "True", "TRUE", "yes", "Yes", "YES", "on", "On", "ON"}
_FALSES = {"false", "False", "FALSE", "no", "No", "NO", "off", "Off", "OFF"}


def _fail(lineno: int, message: str) -> ConfigError:
    return ConfigError(
        f"line {lineno}: {message}. FlowLite's built-in YAML reader supports only a "
        f"simple subset; install PyYAML (pip install PyYAML) for full YAML support."
    )


def _strip_comment(line: str) -> str:
    """Remove a trailing ``#`` comment, honouring quotes and brackets."""
    out: List[str] = []
    quote = ""
    prev_space = True
    for ch in line:
        if quote:
            out.append(ch)
            if ch == quote:
                quote = ""
            prev_space = False
            continue
        if ch in "'\"":
            quote = ch
            out.append(ch)
            prev_space = False
            continue
        if ch == "#" and prev_space:
            break
        out.append(ch)
        prev_space = ch in " \t"
    return "".join(out).rstrip()


def _split_top_level(text: str, sep: str) -> List[str]:
    """Split on ``sep`` outside quotes and outside ``[]``/``{}`` nesting."""
    parts: List[str] = []
    buf: List[str] = []
    quote = ""
    depth = 0
    for ch in text:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = ""
            continue
        if ch in "'\"":
            quote = ch
            buf.append(ch)
            continue
        if ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        if ch == sep and depth == 0:
            parts.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    parts.append("".join(buf))
    return parts


def _split_key(text: str, lineno: int) -> Tuple[str, str] | None:
    """Split ``key: value`` at the first structural colon. ``None`` if absent."""
    quote = ""
    depth = 0
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = ""
            continue
        if ch in "'\"":
            quote = ch
            continue
        if ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        elif ch == ":" and depth == 0:
            rest = text[i + 1 :]
            if rest == "" or rest[0] in " \t":
                return text[:i].strip(), rest.strip()
    if quote:
        raise _fail(lineno, "unterminated quoted string")
    return None


def _unquote(text: str, lineno: int) -> str:
    quote = text[0]
    if len(text) < 2 or text[-1] != quote:
        raise _fail(lineno, "unterminated quoted string")
    body = text[1:-1]
    if quote == "'":
        return body.replace("''", "'")
    # Double quotes: support the escapes that realistically appear in configs.
    out: List[str] = []
    i = 0
    escapes = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", '"': '"', "\\": "\\", "/": "/"}
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body):
            nxt = body[i + 1]
            if nxt in escapes:
                out.append(escapes[nxt])
                i += 2
                continue
            if nxt == "u" and i + 5 < len(body) + 1:
                try:
                    out.append(chr(int(body[i + 2 : i + 6], 16)))
                    i += 6
                    continue
                except ValueError:
                    raise _fail(lineno, "invalid \\u escape") from None
            raise _fail(lineno, f"unsupported escape sequence '\\{nxt}'")
        out.append(ch)
        i += 1
    return "".join(out)


def _scalar(text: str, lineno: int) -> Any:
    text = text.strip()
    if text[:1] in ("'", '"'):
        return _unquote(text, lineno)
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1].strip()
        if not inner:
            return []
        return [_scalar(p.strip(), lineno) for p in _split_top_level(inner, ",")]
    if text.startswith("{") and text.endswith("}"):
        inner = text[1:-1].strip()
        result: dict = {}
        if not inner:
            return result
        for part in _split_top_level(inner, ","):
            kv = _split_key(part.strip(), lineno)
            if kv is None:
                raise _fail(lineno, f"flow mapping entry {part.strip()!r} is not 'key: value'")
            result[_scalar(kv[0], lineno)] = _scalar(kv[1], lineno) if kv[1] else None
        return result
    if text and text[0] in _UNSUPPORTED:
        raise _fail(lineno, f"{_UNSUPPORTED[text[0]]} are not supported")
    if text in _NULLS:
        return None
    if text in _TRUES:
        return True
    if text in _FALSES:
        return False
    if _INT_RE.match(text):
        return int(text)
    if _HEX_RE.match(text):
        return int(text, 16)
    if _OCT_RE.match(text):
        return int(text, 8)
    if _FLOAT_RE.match(text):
        return float(text)
    if text in (".inf", ".Inf", ".INF"):
        return float("inf")
    if text in ("-.inf", "-.Inf", "-.INF"):
        return float("-inf")
    if text in (".nan", ".NaN", ".NAN"):
        return float("nan")
    return text


class _Line:
    __slots__ = ("indent", "text", "lineno")

    def __init__(self, indent: int, text: str, lineno: int) -> None:
        self.indent = indent
        self.text = text
        self.lineno = lineno


def _tokenize(source: str) -> List[_Line]:
    lines: List[_Line] = []
    for lineno, raw in enumerate(source.splitlines(), start=1):
        if raw.strip() in ("---", "..."):
            continue
        if "\t" in raw[: len(raw) - len(raw.lstrip(" \t"))]:
            raise _fail(lineno, "tab character used for indentation (YAML forbids tabs)")
        stripped = _strip_comment(raw)
        if not stripped.strip():
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        lines.append(_Line(indent, stripped.strip(), lineno))
    return lines


class _Parser:
    def __init__(self, lines: List[_Line]) -> None:
        self.lines = lines
        self.pos = 0

    def peek(self) -> _Line | None:
        return self.lines[self.pos] if self.pos < len(self.lines) else None

    def parse_block(self, indent: int) -> Any:
        line = self.peek()
        if line is None:
            return None
        if line.text.startswith("- "):
            return self.parse_sequence(indent)
        if line.text == "-":
            return self.parse_sequence(indent)
        return self.parse_mapping(indent)

    def parse_sequence(self, indent: int) -> List[Any]:
        items: List[Any] = []
        while True:
            line = self.peek()
            if line is None or line.indent < indent:
                break
            if line.indent > indent:
                raise _fail(line.lineno, "unexpected indentation inside a sequence")
            if not (line.text == "-" or line.text.startswith("- ")):
                break
            self.pos += 1
            body = line.text[1:].strip()
            child_indent = line.indent + 2
            if not body:
                nxt = self.peek()
                if nxt is not None and nxt.indent > line.indent:
                    items.append(self.parse_block(nxt.indent))
                else:
                    items.append(None)
                continue
            kv = _split_key(body, line.lineno)
            if kv is None:
                items.append(_scalar(body, line.lineno))
                continue
            # "- key: value" starts an inline mapping whose remaining keys are
            # indented to the column where `key` began.
            mapping: dict = {}
            key, value = kv
            key_col = line.indent + 2
            if value:
                mapping[_scalar(key, line.lineno)] = _scalar(value, line.lineno)
            else:
                nxt = self.peek()
                if nxt is not None and nxt.indent > key_col - 1 and nxt.indent > line.indent:
                    mapping[_scalar(key, line.lineno)] = self.parse_block(nxt.indent)
                else:
                    mapping[_scalar(key, line.lineno)] = None
            rest = self.parse_mapping(key_col) if self._at_indent(key_col) else {}
            mapping.update(rest)
            items.append(mapping)
            child_indent  # noqa: B018  (documented: sequence children align at indent+2)
        return items

    def _at_indent(self, indent: int) -> bool:
        line = self.peek()
        return line is not None and line.indent == indent and not line.text.startswith("- ")

    def parse_mapping(self, indent: int) -> dict:
        mapping: dict = {}
        while True:
            line = self.peek()
            if line is None or line.indent < indent:
                break
            if line.indent > indent:
                raise _fail(line.lineno, "unexpected indentation (expected a new key)")
            if line.text.startswith("- ") or line.text == "-":
                break
            kv = _split_key(line.text, line.lineno)
            if kv is None:
                raise _fail(line.lineno, f"expected 'key: value', found {line.text!r}")
            key_text, value_text = kv
            key = _scalar(key_text, line.lineno)
            self.pos += 1
            if value_text:
                mapping[key] = _scalar(value_text, line.lineno)
                continue
            nxt = self.peek()
            if nxt is None or nxt.indent <= indent:
                # A bare "key:" with nothing under it, unless a sequence follows
                # at the same indent (YAML allows sequences not to be indented).
                if nxt is not None and nxt.indent == indent and nxt.text.startswith("- "):
                    mapping[key] = self.parse_sequence(indent)
                else:
                    mapping[key] = None
                continue
            mapping[key] = self.parse_block(nxt.indent)
        return mapping


def parse(source: str) -> Any:
    """Parse a YAML subset document into Python objects."""
    lines = _tokenize(source)
    if not lines:
        return None
    parser = _Parser(lines)
    result = parser.parse_block(lines[0].indent)
    leftover = parser.peek()
    if leftover is not None:
        raise _fail(leftover.lineno, "could not parse the rest of the document")
    return result


def safe_load(source: str) -> Any:
    """PyYAML-compatible entry point used when PyYAML itself is unavailable."""
    return parse(source)
