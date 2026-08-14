"""Capture-file reader for classic pcap and pcapng, plus gzip/bzip2 wrappers.

The previous implementation used ``dpkt.pcap.Reader`` and therefore rejected
pcapng outright -- which is what modern ``tcpdump``, ``dumpcap`` and Wireshark
write by default, and what most switches produce when asked to export a capture.
Silently failing on the industry-default capture format is not acceptable in a
tool whose entire job is reading capture files.

This reader handles:

* classic pcap, both byte orders, microsecond and nanosecond resolution
* pcapng: multiple sections, per-interface link types and timestamp resolutions,
  Enhanced/Simple/obsolete Packet Blocks
* transparent gzip and bzip2 decompression, detected by magic number
* truncated files -- a capture killed mid-write yields every complete packet and
  a warning, rather than an exception that discards the whole hour
"""

from __future__ import annotations

import bz2
import gzip
import struct
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Callable, Dict, List, Optional, Tuple

from ..errors import ParseError

__all__ = ["CaptureFile", "CaptureInfo", "open_capture", "read_packets"]

_PCAP_MAGIC_LE = 0xD4C3B2A1
_PCAP_MAGIC_BE = 0xA1B2C3D4
_PCAP_MAGIC_NS_LE = 0x4D3CB2A1
_PCAP_MAGIC_NS_BE = 0xA1B23C4D
_PCAPNG_SHB = 0x0A0D0D0A
_PCAPNG_BYTE_ORDER = 0x1A2B3C4D

_BLOCK_IDB = 0x00000001
_BLOCK_SPB = 0x00000003
_BLOCK_OPB = 0x00000002
_BLOCK_EPB = 0x00000006

# A single packet larger than this indicates a corrupt length field, not a jumbo
# frame; 16 MiB is far beyond any real link MTU including 9k jumbo + encaps.
_MAX_SANE_CAPLEN = 16 * 1024 * 1024
_MAX_SANE_BLOCK = 64 * 1024 * 1024


@dataclass
class CaptureInfo:
    """What a capture file turned out to contain."""

    path: Path
    format: str = "unknown"  # "pcap" | "pcapng"
    linktypes: Dict[int, int] = field(default_factory=dict)  # interface id -> linktype
    packets_read: int = 0
    bytes_read: int = 0
    truncated: bool = False
    skipped_blocks: int = 0
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    warnings: List[str] = field(default_factory=list)

    @property
    def primary_linktype(self) -> int:
        if not self.linktypes:
            return -1
        return next(iter(self.linktypes.values()))

    @property
    def duration_s(self) -> float:
        if self.first_ts is None or self.last_ts is None:
            return 0.0
        return max(0.0, self.last_ts - self.first_ts)


def _open_maybe_compressed(path: Path) -> BinaryIO:
    """Open ``path``, transparently decompressing gzip/bzip2 by magic number."""
    raw = path.open("rb")
    try:
        magic = raw.read(3)
        raw.seek(0)
    except OSError:
        raw.close()
        raise
    if magic[:2] == b"\x1f\x8b":
        raw.close()
        return gzip.open(str(path), "rb")  # type: ignore[return-value]
    if magic[:3] == b"BZh":
        raw.close()
        return bz2.open(str(path), "rb")  # type: ignore[return-value]
    return raw


class _Buffered:
    """Exact-length reads over a stream, tracking how much was consumed."""

    def __init__(self, stream: BinaryIO) -> None:
        self._stream = stream
        self.consumed = 0

    def read(self, size: int) -> bytes:
        if size <= 0:
            return b""
        chunks: List[bytes] = []
        remaining = size
        while remaining > 0:
            chunk = self._stream.read(remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        self.consumed += len(data)
        return data

    def close(self) -> None:
        try:
            self._stream.close()
        except OSError:
            pass


class CaptureFile:
    """Iterate ``(timestamp, packet_bytes, linktype)`` triples from a capture."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.info = CaptureInfo(path=self.path)
        self._stream: Optional[_Buffered] = None

    def __enter__(self) -> CaptureFile:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        if self._stream is not None:
            self._stream.close()
            self._stream = None

    def __iter__(self) -> Iterator[Tuple[float, bytes, int]]:
        return self.packets()

    def packets(self) -> Iterator[Tuple[float, bytes, int]]:
        """Yield every complete packet in the file."""
        if not self.path.exists():
            raise ParseError(f"Capture file does not exist: {self.path}")
        if self.path.stat().st_size == 0:
            self.info.warnings.append("file is empty")
            return

        handle = _open_maybe_compressed(self.path)
        self._stream = _Buffered(handle)
        try:
            magic = self._stream.read(4)
            if len(magic) < 4:
                self.info.warnings.append("file is shorter than a file header")
                self.info.truncated = True
                return
            (magic_be,) = struct.unpack(">I", magic)
            if magic_be == _PCAPNG_SHB:
                self.info.format = "pcapng"
                yield from self._iter_pcapng()
            elif magic_be in (_PCAP_MAGIC_BE, _PCAP_MAGIC_NS_BE, _PCAP_MAGIC_LE, _PCAP_MAGIC_NS_LE):
                self.info.format = "pcap"
                yield from self._iter_pcap(magic_be)
            else:
                raise ParseError(
                    f"{self.path.name} is not a pcap or pcapng capture "
                    f"(magic 0x{magic_be:08x}). Supported: pcap, pcapng, optionally gzip/bzip2 "
                    f"compressed."
                )
        finally:
            self.info.bytes_read = self._stream.consumed if self._stream else 0
            self.close()

    # -- classic pcap ----------------------------------------------------- #

    def _iter_pcap(self, magic_be: int) -> Iterator[Tuple[float, bytes, int]]:
        assert self._stream is not None
        if magic_be in (_PCAP_MAGIC_BE, _PCAP_MAGIC_NS_BE):
            endian = ">"
        else:
            endian = "<"
        nanos = magic_be in (_PCAP_MAGIC_NS_BE, _PCAP_MAGIC_NS_LE)
        divisor = 1_000_000_000.0 if nanos else 1_000_000.0

        rest = self._stream.read(20)
        if len(rest) < 20:
            self.info.truncated = True
            self.info.warnings.append("file header is truncated")
            return
        _vmaj, _vmin, _tz, _sig, _snap, linktype = struct.unpack(endian + "HHiIII", rest)
        linktype = linktype & 0x0FFFFFFF  # high bits carry FCS metadata
        self.info.linktypes[0] = linktype

        header = struct.Struct(endian + "IIII")
        while True:
            head = self._stream.read(16)
            if len(head) == 0:
                return
            if len(head) < 16:
                self.info.truncated = True
                self.info.warnings.append("final packet header is truncated")
                return
            ts_sec, ts_frac, caplen, origlen = header.unpack(head)
            if caplen > _MAX_SANE_CAPLEN:
                raise ParseError(
                    f"{self.path.name}: packet {self.info.packets_read + 1} claims {caplen} "
                    f"captured bytes, which means the file is corrupt"
                )
            data = self._stream.read(caplen)
            if len(data) < caplen:
                self.info.truncated = True
                self.info.warnings.append("final packet payload is truncated")
                return
            ts = ts_sec + ts_frac / divisor
            self._note(ts)
            yield ts, data, linktype
            del origlen

    # -- pcapng ------------------------------------------------------------ #

    def _iter_pcapng(self) -> Iterator[Tuple[float, bytes, int]]:
        assert self._stream is not None
        stream = self._stream
        # We already consumed the 4-byte SHB block type.
        pending_block_type: Optional[int] = _PCAPNG_SHB
        endian = "<"
        unpack_u32: Callable[[bytes, int], Tuple[int, ...]] = struct.Struct("<I").unpack_from
        # interface id -> (linktype, timestamp divisor)
        interfaces: Dict[int, Tuple[int, float]] = {}
        if_index = 0

        while True:
            if pending_block_type is None:
                head = stream.read(4)
                if len(head) == 0:
                    return
                if len(head) < 4:
                    self.info.truncated = True
                    return
                block_type = struct.unpack(endian + "I", head)[0]
            else:
                block_type = pending_block_type
                pending_block_type = None

            len_bytes = stream.read(4)
            if len(len_bytes) < 4:
                self.info.truncated = True
                self.info.warnings.append("block header is truncated")
                return

            if block_type == _PCAPNG_SHB:
                # Byte order is declared inside the SHB and may flip per section.
                total_len_le = struct.unpack("<I", len_bytes)[0]
                body_head = stream.read(4)
                if len(body_head) < 4:
                    self.info.truncated = True
                    return
                bom = struct.unpack("<I", body_head)[0]
                if bom == _PCAPNG_BYTE_ORDER:
                    endian = "<"
                    total_len = total_len_le
                elif struct.unpack(">I", body_head)[0] == _PCAPNG_BYTE_ORDER:
                    endian = ">"
                    total_len = struct.unpack(">I", len_bytes)[0]
                else:
                    raise ParseError(
                        f"{self.path.name}: pcapng section has an invalid byte-order magic"
                    )
                unpack_u32 = struct.Struct(endian + "I").unpack_from
                if total_len < 16 or total_len > _MAX_SANE_BLOCK:
                    raise ParseError(
                        f"{self.path.name}: implausible pcapng section length {total_len}"
                    )
                remainder = stream.read(total_len - 12)
                if len(remainder) < total_len - 12:
                    self.info.truncated = True
                    return
                interfaces = {}
                if_index = 0
                continue

            total_len = struct.unpack(endian + "I", len_bytes)[0]
            if total_len < 12 or total_len > _MAX_SANE_BLOCK:
                raise ParseError(
                    f"{self.path.name}: pcapng block type 0x{block_type:08x} declares an "
                    f"implausible length of {total_len} bytes"
                )
            body = stream.read(total_len - 12)
            if len(body) < total_len - 12:
                self.info.truncated = True
                self.info.warnings.append("final pcapng block is truncated")
                return
            trailer = stream.read(4)
            if len(trailer) < 4:
                self.info.truncated = True
                return

            if block_type == _BLOCK_IDB:
                if len(body) < 8:
                    self.info.skipped_blocks += 1
                    continue
                linktype = struct.unpack_from(endian + "H", body, 0)[0]
                divisor = _pcapng_ts_divisor(body[8:], endian)
                interfaces[if_index] = (linktype, divisor)
                self.info.linktypes[if_index] = linktype
                if_index += 1

            elif block_type == _BLOCK_EPB:
                if len(body) < 20:
                    self.info.skipped_blocks += 1
                    continue
                iface_id, ts_hi, ts_lo, caplen, _origlen = struct.unpack_from(
                    endian + "IIIII", body, 0
                )
                if caplen > len(body) - 20 or caplen > _MAX_SANE_CAPLEN:
                    self.info.skipped_blocks += 1
                    continue
                linktype, divisor = interfaces.get(iface_id, (1, 1_000_000.0))
                ts = ((ts_hi << 32) | ts_lo) / divisor
                self._note(ts)
                yield ts, bytes(body[20 : 20 + caplen]), linktype

            elif block_type == _BLOCK_SPB:
                if len(body) < 4:
                    self.info.skipped_blocks += 1
                    continue
                (origlen,) = unpack_u32(body, 0)
                caplen = min(origlen, len(body) - 4)
                linktype, _divisor = interfaces.get(0, (1, 1_000_000.0))
                ts = self.info.last_ts if self.info.last_ts is not None else 0.0
                self._note(ts)
                yield ts, bytes(body[4 : 4 + caplen]), linktype

            elif block_type == _BLOCK_OPB:
                if len(body) < 20:
                    self.info.skipped_blocks += 1
                    continue
                ts_hi, ts_lo, caplen, _origlen = struct.unpack_from(endian + "IIII", body, 4)
                if caplen > len(body) - 20:
                    self.info.skipped_blocks += 1
                    continue
                linktype, divisor = interfaces.get(0, (1, 1_000_000.0))
                ts = ((ts_hi << 32) | ts_lo) / divisor
                self._note(ts)
                yield ts, bytes(body[20 : 20 + caplen]), linktype

            else:
                self.info.skipped_blocks += 1

    def _note(self, ts: float) -> None:
        self.info.packets_read += 1
        if self.info.first_ts is None:
            self.info.first_ts = ts
        self.info.last_ts = ts


def _pcapng_ts_divisor(options: bytes, endian: str) -> float:
    """Read ``if_tsresol`` (option code 9) from an Interface Description Block."""
    offset = 0
    while offset + 4 <= len(options):
        code, length = struct.unpack_from(endian + "HH", options, offset)
        offset += 4
        if code == 0:  # opt_endofopt
            break
        value = options[offset : offset + length]
        offset += length + ((4 - length % 4) % 4)
        if code == 9 and value:
            resol = value[0]
            if resol & 0x80:
                return float(2 ** (resol & 0x7F))
            return float(10**resol)
    return 1_000_000.0


def open_capture(path: str | Path) -> CaptureFile:
    """Open a capture file for iteration."""
    return CaptureFile(path)


def read_packets(path: str | Path) -> Tuple[List[Tuple[float, bytes, int]], CaptureInfo]:
    """Read an entire capture into memory. Convenience for tests and small files."""
    capture = CaptureFile(path)
    packets = list(capture.packets())
    return packets, capture.info
