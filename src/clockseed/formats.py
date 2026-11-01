"""File-header checks used as known plaintext.

Short magics are rejected on purpose. A two-byte match such as bare ``MZ``
shows up by chance once the search window gets wide.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FormatMatch:
    name: str
    extension: str
    score: int


def identify(data: bytes) -> FormatMatch | None:
    if len(data) >= 16 and data.startswith(b"SQLite format 3\x00"):
        return FormatMatch("SQLite", ".sqlite", 16)
    if len(data) >= 12 and data.startswith(b"RIFF") and data[8:12] in {
        b"WAVE",
        b"AVI ",
        b"WEBP",
    }:
        return FormatMatch("RIFF", ".riff", 12)
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return FormatMatch("PNG", ".png", 8)
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return FormatMatch("OLE Compound File", ".ole", 8)
    if len(data) >= 8 and data[4:8] == b"ftyp":
        return FormatMatch("MP4", ".mp4", 8)
    if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        return FormatMatch("GIF", ".gif", 6)
    if data.startswith(b"Rar!\x1a\x07"):
        return FormatMatch("RAR", ".rar", 6)
    if data.startswith(b"7z\xbc\xaf\x27\x1c"):
        return FormatMatch("7z", ".7z", 6)
    if data.startswith(b"%PDF-"):
        return FormatMatch("PDF", ".pdf", 5)
    if data.startswith(b"{\\rtf"):
        return FormatMatch("RTF", ".rtf", 5)
    if data.startswith(b"<?xml"):
        return FormatMatch("XML", ".xml", 5)
    if _looks_like_elf(data):
        return FormatMatch("ELF", "", 5)
    if _looks_like_jpeg(data):
        return FormatMatch("JPEG", ".jpg", 4)
    if data.startswith(b"PK\x03\x04"):
        return FormatMatch("ZIP", ".zip", 4)
    if data.startswith(b"\x1f\x8b\x08"):
        return FormatMatch("gzip", ".gz", 3)
    if _looks_like_pe(data):
        return FormatMatch("Windows PE", ".exe", 64)
    return None


def _looks_like_jpeg(data: bytes) -> bool:
    return len(data) >= 4 and data.startswith(b"\xff\xd8\xff") and data[3] >= 0xC0


def _looks_like_elf(data: bytes) -> bool:
    return (
        len(data) >= 6
        and data.startswith(b"\x7fELF")
        and data[4] in (1, 2)
        and data[5] in (1, 2)
    )


def _looks_like_pe(data: bytes) -> bool:
    if len(data) < 0x40 or not data.startswith(b"MZ"):
        return False
    offset = int.from_bytes(data[0x3C:0x40], "little")
    if offset < 0x40 or offset + 4 > len(data):
        return False
    return data[offset : offset + 4] == b"PE\x00\x00"
