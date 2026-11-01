"""C rand() generators a sample might actually have used.

Host libc is the wrong tool here. A Windows sample recovered on macOS, or a
glibc sample recovered on musl, will not reproduce the key. Each class below
is the generator itself, so the search does not depend on the machine it runs on.
"""

from __future__ import annotations

import ctypes
import platform
from typing import Protocol

_MASK32 = 0xFFFFFFFF
_MASK64 = (1 << 64) - 1


class Rng(Protocol):
    def srand(self, seed: int) -> None: ...

    def rand(self) -> int: ...


def _as_i32(value: int) -> int:
    value &= _MASK32
    if value >= 0x80000000:
        return value - 0x100000000
    return value


def _cdiv(left: int, right: int) -> int:
    """C integer division, which truncates toward zero."""
    if left < 0:
        return -((-left) // right)
    return left // right


def _cmod(left: int, right: int) -> int:
    """C integer remainder, which follows the sign of the dividend."""
    if left < 0:
        return -((-left) % right)
    return left % right


class MsvcrtRng:
    """Classic Visual C / Universal CRT rand().

    ``hold = hold * 214013 + 2531011`` mod 2^32, then ``(hold >> 16) & 0x7fff``.
    This is msvcrt.dll and ucrtbase.dll. RAND_MAX is 32767.
    """

    def __init__(self) -> None:
        self._hold = 1

    def srand(self, seed: int) -> None:
        self._hold = seed & _MASK32

    def rand(self) -> int:
        self._hold = (self._hold * 214013 + 2531011) & _MASK32
        return (self._hold >> 16) & 0x7FFF


class MuslRng:
    """musl libc rand(), a 64-bit LCG.

    ``srand`` stores ``seed - 1`` in 32-bit unsigned arithmetic. ``rand`` returns
    the top bits of a 64-bit state: ``state = state * 6364136223846793005 + 1``.
    """

    def __init__(self) -> None:
        self._state = 0

    def srand(self, seed: int) -> None:
        self._state = ((seed & _MASK32) - 1) & _MASK32

    def rand(self) -> int:
        self._state = (6364136223846793005 * self._state + 1) & _MASK64
        return self._state >> 33


class GlibcRng:
    """glibc rand(), which is random() with a 31-word state. Not a small LCG.

    Default type is the degree-31 additive generator (128 bytes of state).
    ``srand`` fills that table, then discards ``31 * 10`` outputs. The value
    returned to the caller drops the low bit.
    """

    DEGREE = 31
    SEPARATION = 3

    def __init__(self) -> None:
        self._state = [0] * self.DEGREE
        self._front = self.SEPARATION
        self._rear = 0

    def srand(self, seed: int) -> None:
        seed &= _MASK32
        if seed == 0:
            seed = 1
        word = _as_i32(seed)
        self._state = [0] * self.DEGREE
        self._state[0] = seed
        for index in range(1, self.DEGREE):
            high = _cdiv(word, 127773)
            low = _cmod(word, 127773)
            word = 16807 * low - 2836 * high
            if word < 0:
                word += 2147483647
            self._state[index] = word & _MASK32
        self._front = self.SEPARATION
        self._rear = 0
        for _ in range(self.DEGREE * 10):
            self.rand()

    def rand(self) -> int:
        mixed = (self._state[self._front] + self._state[self._rear]) & _MASK32
        self._state[self._front] = mixed
        self._front += 1
        if self._front >= self.DEGREE:
            self._front = 0
            self._rear += 1
        else:
            self._rear += 1
            if self._rear >= self.DEGREE:
                self._rear = 0
        return mixed >> 1


class NativeRng:
    """Host srand/rand. Useful only when this machine is the build target.

    The state is process-global. Prefer the pure Python generators.
    """

    _library: ctypes.CDLL | None = None

    def __init__(self) -> None:
        if NativeRng._library is None:
            NativeRng._library = _load_host_libc()
        self._library = NativeRng._library

    def srand(self, seed: int) -> None:
        self._library.srand(seed & _MASK32)

    def rand(self) -> int:
        value = int(self._library.rand())
        if value < 0:
            raise OSError("host rand() returned a negative value")
        return value


def _load_host_libc() -> ctypes.CDLL:
    system = platform.system()
    if system == "Windows":
        library = ctypes.CDLL("msvcrt.dll")
    elif system == "Darwin":
        library = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
    elif system == "Linux":
        library = ctypes.CDLL("libc.so.6")
    else:
        raise OSError(f"no native C runtime mapped for {system}")
    library.srand.argtypes = [ctypes.c_uint]
    library.srand.restype = None
    library.rand.argtypes = []
    library.rand.restype = ctypes.c_int
    return library


RUNTIMES: dict[str, type] = {
    "msvcrt": MsvcrtRng,
    "glibc": GlibcRng,
    "musl": MuslRng,
    "native": NativeRng,
}

# What `--runtime all` searches. `native` stays opt-in: it follows the host,
# which is the bug this tool exists to avoid.
PURE_RUNTIMES = ("msvcrt", "glibc", "musl")


def make_rng(name: str) -> Rng:
    try:
        cls = RUNTIMES[name]
    except KeyError:
        known = ", ".join(RUNTIMES)
        raise ValueError(f"unknown runtime {name!r}; choose from {known}") from None
    return cls()


def keystream(name: str, seed: int, count: int) -> bytes:
    """``count`` key bytes, each ``rand() % 256`` after ``srand(seed)``."""
    rng = make_rng(name)
    rng.srand(seed)
    return bytes(rng.rand() & 0xFF for _ in range(count))
