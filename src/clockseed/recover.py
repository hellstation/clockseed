"""Search a clock window for an AES key and decrypt with it."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

from Crypto.Cipher import AES

from clockseed.formats import FormatMatch, identify
from clockseed.prng import PURE_RUNTIMES, keystream

BLOCK = 16
PROBE = 512
MAX_WINDOW = 86_400

DEFAULT_RUNTIMES = PURE_RUNTIMES
DEFAULT_KEY_LENGTHS = (32, 24, 16)
DEFAULT_LAYOUTS = ("ecb", "cbc-zero", "cbc-derived", "cbc-prepended")

LAYOUT_LABELS = {
    "ecb": "ECB",
    "cbc-zero": "CBC with a zero IV",
    "cbc-derived": "CBC with an IV taken from rand()",
    "cbc-prepended": "CBC with a prepended IV",
}

ENCRYPTED_SUFFIXES = (
    ".enc",
    ".encrypted",
    ".locked",
    ".crypt",
    ".crypted",
    ".aes",
    ".crypto",
)


class ClockseedError(Exception):
    """Bad arguments or a file the tool will not overwrite."""


@dataclass(frozen=True)
class Sample:
    name: str
    prefix: bytes
    size: int


@dataclass(frozen=True)
class Solution:
    seed: int
    runtime: str
    key: bytes
    layout: str
    iv: bytes | None
    match: FormatMatch
    distance: int

    @property
    def aes(self) -> str:
        return {16: "AES-128", 24: "AES-192", 32: "AES-256"}[len(self.key)]

    @property
    def layout_label(self) -> str:
        return LAYOUT_LABELS[self.layout]


@dataclass(frozen=True)
class CrackResult:
    solution: Solution | None
    seeds_checked: int
    matched_name: str | None


def iter_seeds(center: int, window: int) -> Iterable[tuple[int, int]]:
    if window < 0:
        raise ClockseedError("window must be zero or positive")
    if window > MAX_WINDOW:
        raise ClockseedError(
            f"window is {window}s; the maximum is {MAX_WINDOW}s (24 hours). "
            "Move --timestamp closer to the sample start."
        )
    yield center, 0
    for distance in range(1, window + 1):
        # Earlier first. The process starts, then the file's mtime is written.
        yield center - distance, distance
        yield center + distance, distance


def restored_name(filename: str) -> str:
    lower = filename.lower()
    for suffix in ENCRYPTED_SUFFIXES:
        if lower.endswith(suffix) and len(filename) > len(suffix):
            trimmed = filename[: -len(suffix)]
            if trimmed not in {"", ".", ".."}:
                return trimmed
    return filename + ".recovered"


def cipher_span(size: int, layout: str, ignore_tail: int) -> tuple[int, int] | None:
    """Return ``(offset, length)`` of the ciphertext, or None if it cannot fit."""
    if ignore_tail < 0 or size <= ignore_tail:
        return None
    usable = size - ignore_tail
    if layout == "cbc-prepended":
        if usable < BLOCK * 2 or (usable - BLOCK) % BLOCK != 0:
            return None
        return BLOCK, usable - BLOCK
    if usable < BLOCK or usable % BLOCK != 0:
        return None
    return 0, usable


def crack_bytes(
    blob: bytes,
    *,
    center: int,
    window: int = 120,
    size: int | None = None,
    runtimes: Sequence[str] = DEFAULT_RUNTIMES,
    key_lengths: Sequence[int] = DEFAULT_KEY_LENGTHS,
    layouts: Sequence[str] = DEFAULT_LAYOUTS,
    ignore_tail: int = 0,
) -> CrackResult:
    sample = Sample("input", blob, len(blob) if size is None else size)
    return crack_samples(
        [sample],
        center=center,
        window=window,
        runtimes=runtimes,
        key_lengths=key_lengths,
        layouts=layouts,
        ignore_tail=ignore_tail,
    )


def crack_samples(
    samples: Sequence[Sample],
    *,
    center: int,
    window: int = 120,
    runtimes: Sequence[str] = DEFAULT_RUNTIMES,
    key_lengths: Sequence[int] = DEFAULT_KEY_LENGTHS,
    layouts: Sequence[str] = DEFAULT_LAYOUTS,
    ignore_tail: int = 0,
) -> CrackResult:
    _check_choices(runtimes, key_lengths, layouts)
    best: Solution | None = None
    matched_name: str | None = None
    seeds_checked = 0
    stream_len = max(key_lengths) + BLOCK

    for seed, distance in iter_seeds(center, window):
        seeds_checked += 1
        for runtime in runtimes:
            stream = keystream(runtime, seed, stream_len)
            for key_len in key_lengths:
                key = stream[:key_len]
                derived_iv = stream[key_len : key_len + BLOCK]
                for layout in layouts:
                    iv = _layout_iv(layout, derived_iv)
                    for sample in samples:
                        plain = _probe(
                            sample.prefix,
                            sample.size,
                            key,
                            layout,
                            iv,
                            ignore_tail,
                        )
                        if plain is None:
                            continue
                        match = identify(plain)
                        if match is None:
                            continue
                        if best is not None and (
                            match.score < best.match.score
                            or (
                                match.score == best.match.score
                                and distance >= best.distance
                            )
                        ):
                            continue
                        best = Solution(
                            seed=seed,
                            runtime=runtime,
                            key=key,
                            layout=layout,
                            iv=iv,
                            match=match,
                            distance=distance,
                        )
                        matched_name = sample.name
    return CrackResult(best, seeds_checked, matched_name)


def decrypt_bytes(
    blob: bytes,
    solution: Solution,
    ignore_tail: int = 0,
) -> tuple[bytes, int]:
    span = cipher_span(len(blob), solution.layout, ignore_tail)
    if span is None:
        raise ClockseedError(
            "ciphertext length is not a multiple of the AES block for "
            f"{solution.layout_label}"
        )
    offset, length = span
    ciphertext = blob[offset : offset + length]
    if solution.layout == "ecb":
        plain = AES.new(solution.key, AES.MODE_ECB).decrypt(ciphertext)
    else:
        iv = blob[:BLOCK] if solution.layout == "cbc-prepended" else solution.iv
        if iv is None:
            raise ClockseedError(f"{solution.layout} is missing an IV")
        plain = AES.new(solution.key, AES.MODE_CBC, iv).decrypt(ciphertext)
    return _unpad_pkcs7(plain)


def _layout_iv(layout: str, derived_iv: bytes) -> bytes | None:
    if layout == "ecb":
        return None
    if layout == "cbc-zero":
        return b"\x00" * BLOCK
    if layout == "cbc-derived":
        return derived_iv
    if layout == "cbc-prepended":
        return None
    raise ClockseedError(f"unknown layout {layout!r}")


def _probe(
    prefix: bytes,
    size: int,
    key: bytes,
    layout: str,
    iv: bytes | None,
    ignore_tail: int,
) -> bytes | None:
    span = cipher_span(size, layout, ignore_tail)
    if span is None:
        return None
    offset, length = span
    take = min(PROBE, length)
    take -= take % BLOCK
    if take < BLOCK or offset + take > len(prefix):
        return None
    ciphertext = prefix[offset : offset + take]
    try:
        if layout == "ecb":
            return AES.new(key, AES.MODE_ECB).decrypt(ciphertext)
        if layout == "cbc-prepended":
            if len(prefix) < BLOCK:
                return None
            iv = prefix[:BLOCK]
        if iv is None:
            return None
        return AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)
    except ValueError:
        return None


def _unpad_pkcs7(data: bytes) -> tuple[bytes, int]:
    if not data or len(data) % BLOCK != 0:
        return data, 0
    pad = data[-1]
    if not 1 <= pad <= BLOCK:
        return data, 0
    if data[-pad:] != bytes([pad]) * pad:
        return data, 0
    return data[:-pad], pad


def _check_choices(
    runtimes: Sequence[str],
    key_lengths: Sequence[int],
    layouts: Sequence[str],
) -> None:
    if not runtimes:
        raise ClockseedError("pick at least one runtime")
    if not key_lengths:
        raise ClockseedError("pick at least one key length")
    if not layouts:
        raise ClockseedError("pick at least one layout")
    for length in key_lengths:
        if length not in (16, 24, 32):
            raise ClockseedError(f"key length {length} is not 16, 24, or 32")
    unknown = [name for name in layouts if name not in LAYOUT_LABELS]
    if unknown:
        raise ClockseedError(f"unknown layout {unknown[0]!r}")
    # Touch every runtime once so a typo fails before the search starts.
    for name in runtimes:
        keystream(name, 1, 1)
