# clockseed

Recover AES-encrypted files when the key came from `srand(time(NULL))` and `rand()`.

A locker that does this has already given the key away. `time(NULL)` is a count of seconds, so the key is one of a few hundred values around the moment the sample started, not one of 2^256. clockseed tries that window and writes the plaintext back.

It only helps when the sample really did build the key that way. A proper hybrid scheme, AES per file wrapped with an RSA public key, does not fall to this. There is no private key in the binary, and no clock to guess.

Use it on files you are allowed to decrypt.

![Pic](https://i.pinimg.com/736x/1b/6f/59/1b6f59a1fc2a6e9904cc04dfbf760eec.jpg)

## Why the runtime is the whole trick

`rand()` is not one algorithm.

| Runtime | Where it shows up | What `srand` / `rand` actually are |
| --- | --- | --- |
| `msvcrt` | `msvcrt.dll` and the Windows Universal CRT | 32-bit LCG: `state * 214013 + 2531011`, then the high bits |
| `glibc` | Linux, the usual desktop and server libc | the BSD `random()` generator, 31 words of state, not a small LCG |
| `musl` | Alpine and a lot of static builds | 64-bit LCG, and `srand` stores `seed - 1` |
| `native` | whatever this machine links | the host functions, via `ctypes` |

Python's `random` module is a different generator again (Mersenne Twister). Calling it with the same seed produces a different key. Calling the host `rand()` is just as wrong when the sample was built for another C runtime: a Windows binary recovered on a Mac will not match macOS `rand()`.

clockseed reimplements the three generators above. The default search tries all three. `native` is opt-in, for the case where you know the sample used this machine's libc.

The key bytes are `rand() % 256`, repeated until the AES key is full. 32, 24, and 16 bytes are tried, so AES-256, AES-192, and AES-128 are all in scope.

## What it tries

For each candidate seed:

- **ECB.** The whole file is ciphertext.
- **CBC, zero IV.** Same, with a 16-byte IV of zeros.
- **CBC, IV from `rand()`.** The IV is the next 16 keystream bytes after the key.
- **CBC, prepended IV.** The first 16 bytes of the file are the IV. The rest is ciphertext.

A hit has to decrypt to a header clockseed knows: PDF, PNG, JPEG, GIF, ZIP and the Office formats that are ZIP, RAR, 7z, gzip, SQLite, RTF, XML, OLE, RIFF, MP4, ELF, and a Windows PE whose `MZ` is followed by a real `PE` header. A bare two-byte `MZ` is not accepted. It collides too often.

The search starts at the timestamp and walks outward. It keeps the strongest header. At the same strength, the closer second wins, and at the same distance the earlier second wins: the process starts, then the file is written. In a directory, one cracked file supplies the key for the rest. That matches a sample that called `srand` once at startup. If each file was seeded on its own, pass `--per-file`.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Python 3.9 or newer. The only dependency is PyCryptodome.

## Usage

```bash
clockseed secret.pdf.enc
clockseed ./locked --output-dir ./restored
clockseed note.enc --runtime msvcrt --timestamp 1773322200 --window 60
clockseed ./locked --time birth
clockseed secret.pdf.enc --dry-run
```

`secret.pdf.enc` is written back as `secret.pdf`, next to the source. A directory is written to `NAME-restored`, keeping subfolders. An existing file is left alone unless you pass `--force`.

The clock comes from the file's modification time. Copying the file onto another disk often replaces that with "now", which will miss. `--time birth` uses the creation time where the filesystem has one. `--timestamp` sets the center yourself, in Unix seconds. Put it on the second the sample started, and keep the window tight. The seed is the process start, so the earliest encrypted file is a better center than the last one.

`--ignore-tail N` drops N trailing bytes before the length check. Use it when the sample appends a marker after the ciphertext.

```bash
clockseed --help
```

## Worked run

This file was AES-256-ECB. Windows `rand()` was seeded with `1700000700`, and the mtime is 15 seconds later. The plaintext length was already a multiple of the block, so PKCS7 added a full extra block of 16 bytes.

```text
$ clockseed budget.pdf.enc --runtime msvcrt --window 30
searching budget.pdf.enc, ±30s around 2023-11-15 01:25:15 +03 (1700000715)
seed 1700000700 (2023-11-15 01:25:00 +03), msvcrt, 15s off the timestamp
  AES-256 ECB
  key 1c2fdf83277de9cc5dedaa9615c55f0082beee23e666be9b03c3cc44d239fc41
  matched PDF on budget.pdf.enc
  checked 61 timestamps
  wrote budget.pdf (PDF, removed 16 bytes of PKCS7)
```

`tests/test_clockseed.py` does the same thing and checks the plaintext. It covers the glibc and musl generators, a prepended IV, a shared key across a directory, and the refusal to overwrite an existing file.

## Limits

- The loop really is `key[i] = rand() % 256` (or the same thing written as a cast to `unsigned char`). A sample that packs whole `rand()` words into the key, or that hashes the seed first, will not open.
- The plaintext has to start with a header this tool knows. An encrypted custom format needs a different known-plaintext check.
- The seed has to fall inside the window. The default is ±120 seconds, and the cap is 24 hours. Move `--timestamp` instead of searching a month.
- ECB and the three CBC layouts above are the ones that get tried. CTR, GCM, and a hardcoded IV that is not zero and not from `rand()` are out of scope.
- This does not recover a key that was wrapped with RSA.