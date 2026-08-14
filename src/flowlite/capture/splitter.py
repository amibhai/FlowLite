"""Split a live capture byte stream into valid, self-contained files.

When a capture tool writes to standard output (``tcpdump -w -``), the file
header appears exactly once, at the very start of the stream. Naively cutting
that stream on a timer produces one valid file and a series of headerless
fragments that begin mid-packet -- every reader rejects them. That is why the
previous design had to tear down and re-establish the SSH session for every
rotation, losing every packet in the reconnect gap.

This splitter buffers the stream, tracks record boundaries, and rotates only
*between* records, re-emitting the file header (and for pcapng the section and
interface blocks) at the start of each new file. Rotation is therefore lossless
and every output file stands alone.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Callable, List, Optional

from ..errors import ParseError

__all__ = ["StreamSplitter", "make_splitter"]

_PCAP_MAGICS = {
    0xA1B2C3D4: (">", False),
    0xA1B23C4D: (">", True),
    0xD4C3B2A1: ("<", False),
    0x4D3CB2A1: ("<", True),
}
_PCAPNG_SHB = 0x0A0D0D0A
_MAX_RECORD = 16 * 1024 * 1024
# Guard against a stream that never yields a parseable header.
_MAX_HEADER_WAIT = 1024 * 1024


class StreamSplitter:
    """Base class: feed bytes in, get complete capture files out."""

    def __init__(self, on_file_complete: Optional[Callable[[Path, int], None]] = None) -> None:
        self._buffer = bytearray()
        self._handle = None
        self._path: Optional[Path] = None
        self._bytes_in_file = 0
        self._records_in_file = 0
        self.on_file_complete = on_file_complete
        self.total_records = 0
        self.total_bytes = 0
        self.header_ready = False
        # How many bytes of the sniffed stream head the preamble already covers,
        # so the caller does not feed the file header back in as record data.
        self.head_bytes_consumed = 0

    # -- file lifecycle ---------------------------------------------------- #

    def open_file(self, path: str | Path) -> None:
        """Begin a new output file, writing whatever preamble the format needs."""
        self.close_file()
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        self._handle = target.open("wb")
        self._path = target
        self._bytes_in_file = 0
        self._records_in_file = 0
        preamble = self.preamble()
        if preamble:
            self._handle.write(preamble)
            self._bytes_in_file += len(preamble)

    def close_file(self) -> None:
        if self._handle is None:
            return
        try:
            self._handle.flush()
            self._handle.close()
        except OSError:
            pass
        completed, records = self._path, self._records_in_file
        self._handle = None
        self._path = None
        if completed is not None and self.on_file_complete is not None:
            self.on_file_complete(completed, records)

    @property
    def current_path(self) -> Optional[Path]:
        return self._path

    @property
    def bytes_in_file(self) -> int:
        return self._bytes_in_file

    @property
    def records_in_file(self) -> int:
        return self._records_in_file

    @property
    def pending_bytes(self) -> int:
        return len(self._buffer)

    def preamble(self) -> bytes:  # pragma: no cover - overridden
        return b""

    # -- ingestion --------------------------------------------------------- #

    def feed(self, data: bytes) -> int:
        """Consume stream bytes; returns the number of complete records written."""
        if not data:
            return 0
        self._buffer.extend(data)
        self.total_bytes += len(data)
        return self._drain()

    def _drain(self) -> int:  # pragma: no cover - overridden
        return 0

    def _write(self, payload: bytes) -> None:
        if self._handle is None:
            return
        self._handle.write(payload)
        self._bytes_in_file += len(payload)
        self._records_in_file += 1
        self.total_records += 1

    def flush(self) -> None:
        if self._handle is not None:
            try:
                self._handle.flush()
            except OSError:
                pass


class PcapSplitter(StreamSplitter):
    """Splitter for the classic pcap stream format."""

    def __init__(self, file_header: bytes, endian: str, on_file_complete=None) -> None:
        super().__init__(on_file_complete)
        self.file_header = bytes(file_header)
        self.endian = endian
        self._record_header = struct.Struct(endian + "IIII")
        self.header_ready = True
        self.head_bytes_consumed = 24

    def preamble(self) -> bytes:
        return self.file_header

    def _drain(self) -> int:
        written = 0
        buffer = self._buffer
        while len(buffer) >= 16:
            _ts_sec, _ts_frac, caplen, _origlen = self._record_header.unpack_from(buffer, 0)
            if caplen > _MAX_RECORD:
                raise ParseError(
                    f"capture stream declares a {caplen}-byte packet, which means the stream is "
                    f"corrupt or is not pcap data"
                )
            total = 16 + caplen
            if len(buffer) < total:
                break
            self._write(bytes(buffer[:total]))
            del buffer[:total]
            written += 1
        return written


class PcapngSplitter(StreamSplitter):
    """Splitter for pcapng, re-emitting section and interface blocks per file."""

    def __init__(self, endian: str, on_file_complete=None) -> None:
        super().__init__(on_file_complete)
        self.endian = endian
        self._preamble_blocks: List[bytes] = []
        self.header_ready = False

    def preamble(self) -> bytes:
        return b"".join(self._preamble_blocks)

    def _drain(self) -> int:
        written = 0
        buffer = self._buffer
        while len(buffer) >= 12:
            block_type, total_len = struct.unpack_from(self.endian + "II", buffer, 0)
            if total_len < 12 or total_len > _MAX_RECORD:
                raise ParseError(
                    f"pcapng stream declares a {total_len}-byte block, which means the stream is "
                    f"corrupt or is not pcapng data"
                )
            if len(buffer) < total_len:
                break
            block = bytes(buffer[:total_len])
            del buffer[:total_len]

            if block_type == _PCAPNG_SHB:
                # A new section resets the preamble that later files must repeat.
                self._preamble_blocks = [block]
                self.header_ready = True
                if self._handle is not None and self._bytes_in_file == 0:
                    self._handle.write(block)
                    self._bytes_in_file += len(block)
                continue
            if block_type == 0x00000001:  # Interface Description Block
                self._preamble_blocks.append(block)
                if self._handle is not None:
                    self._handle.write(block)
                    self._bytes_in_file += len(block)
                continue

            self._write(block)
            written += 1
        return written


def make_splitter(
    stream_head: bytes, on_file_complete: Optional[Callable[[Path, int], None]] = None
) -> StreamSplitter:
    """Build the right splitter for a stream, given its first bytes.

    Args:
        stream_head: At least 4 bytes; for classic pcap, at least 24.

    Raises:
        ParseError: if the bytes are neither pcap nor pcapng. Detecting this in
            the first few bytes turns "the remote command printed an error
            message instead of packets" into an immediate, legible failure
            instead of an hour of writing a garbage file.
    """
    if len(stream_head) < 4:
        raise ParseError("capture stream ended before a file header could be read")
    (magic_be,) = struct.unpack(">I", stream_head[:4])
    if magic_be == _PCAPNG_SHB:
        if len(stream_head) >= 12:
            bom = struct.unpack_from("<I", stream_head, 8)[0]
            endian = "<" if bom == 0x1A2B3C4D else ">"
        else:
            endian = "<"
        return PcapngSplitter(endian, on_file_complete)
    if magic_be in _PCAP_MAGICS:
        endian, _nanos = _PCAP_MAGICS[magic_be]
        if len(stream_head) < 24:
            raise ParseError("capture stream ended inside the pcap file header")
        return PcapSplitter(stream_head[:24], endian, on_file_complete)

    preview = stream_head[:120].decode("utf-8", "replace").strip()
    raise ParseError(
        "the capture command did not produce pcap data. "
        f"First bytes were: {preview!r}. This usually means the remote command failed "
        "(wrong interface name, missing permissions, or a device CLI that needs a shell "
        "prefix such as `bash -c`). Set capture.ssh.command to the exact command for your device."
    )


def header_bytes_needed(stream_head: bytes) -> int:
    """How many more bytes are needed before :func:`make_splitter` can decide."""
    if len(stream_head) < 4:
        return 4 - len(stream_head)
    (magic_be,) = struct.unpack(">I", stream_head[:4])
    if magic_be in _PCAP_MAGICS:
        return max(0, 24 - len(stream_head))
    if magic_be == _PCAPNG_SHB:
        return max(0, 12 - len(stream_head))
    return 0


MAX_HEADER_WAIT = _MAX_HEADER_WAIT
