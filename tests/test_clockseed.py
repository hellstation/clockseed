import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from Crypto.Cipher import AES

from clockseed.cli import main
from clockseed.prng import GlibcRng, MsvcrtRng, MuslRng, keystream
from clockseed.recover import crack_bytes, decrypt_bytes, restored_name

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"


def pad(data: bytes) -> bytes:
    count = 16 - (len(data) % 16)
    return data + bytes([count]) * count


def encrypt(plaintext: bytes, seed: int, runtime: str, layout: str, key_len: int = 32) -> bytes:
    stream = keystream(runtime, seed, key_len + 16)
    key = stream[:key_len]
    derived = stream[key_len : key_len + 16]
    body = pad(plaintext)
    if layout == "ecb":
        return AES.new(key, AES.MODE_ECB).encrypt(body)
    if layout == "cbc-zero":
        return AES.new(key, AES.MODE_CBC, b"\x00" * 16).encrypt(body)
    if layout == "cbc-derived":
        return AES.new(key, AES.MODE_CBC, derived).encrypt(body)
    if layout == "cbc-prepended":
        iv = b"0123456789abcdef"
        return iv + AES.new(key, AES.MODE_CBC, iv).encrypt(body)
    raise AssertionError(layout)


class GeneratorTests(unittest.TestCase):
    def test_msvcrt_matches_the_visual_c_sequence(self):
        rng = MsvcrtRng()
        rng.srand(1)
        self.assertEqual([rng.rand() for _ in range(4)], [41, 18467, 6334, 26500])

    def test_glibc_matches_the_published_seed_1_sequence(self):
        rng = GlibcRng()
        rng.srand(1)
        self.assertEqual(
            [rng.rand() for _ in range(10)],
            [
                1804289383,
                846930886,
                1681692777,
                1714636915,
                1957747793,
                424238335,
                719885386,
                1649760492,
                596516649,
                1189641421,
            ],
        )

    def test_glibc_treats_a_zero_seed_as_one(self):
        zero = GlibcRng()
        zero.srand(0)
        one = GlibcRng()
        one.srand(1)
        self.assertEqual(zero.rand(), one.rand())

    def test_musl_seed_encoding(self):
        rng = MuslRng()
        rng.srand(1)
        self.assertEqual(rng.rand(), 0)
        rng.srand(2)
        self.assertEqual(rng.rand(), 740882966)


class RecoverTests(unittest.TestCase):
    def test_names(self):
        self.assertEqual(restored_name("budget.pdf.enc"), "budget.pdf")
        self.assertEqual(restored_name("notes.bin"), "notes.bin.recovered")

    def test_ecb_roundtrip_off_the_mtime(self):
        seed = 1_700_000_000
        plain = b"%PDF-1.7\nclockseed\n" + b"A" * 40
        blob = encrypt(plain, seed, "msvcrt", "ecb")
        found = crack_bytes(
            blob,
            center=seed + 17,
            window=30,
            runtimes=("msvcrt",),
            layouts=("ecb",),
        )
        self.assertIsNotNone(found.solution)
        solution = found.solution
        self.assertEqual(solution.seed, seed)
        self.assertEqual(solution.runtime, "msvcrt")
        self.assertEqual(solution.layout, "ecb")
        self.assertEqual(solution.aes, "AES-256")
        self.assertEqual(decrypt_bytes(blob, solution)[0], plain)

    def test_glibc_cbc_iv_from_the_same_stream(self):
        seed = 1_700_000_100
        plain = b"\x89PNG\r\n\x1a\n" + b"png-body"
        blob = encrypt(plain, seed, "glibc", "cbc-derived", key_len=16)
        found = crack_bytes(
            blob,
            center=seed,
            window=0,
            key_lengths=(16,),
            runtimes=("glibc",),
            layouts=("cbc-derived",),
        )
        self.assertEqual(found.solution.runtime, "glibc")
        self.assertEqual(found.solution.layout, "cbc-derived")
        self.assertEqual(found.solution.aes, "AES-128")
        self.assertEqual(decrypt_bytes(blob, found.solution)[0], plain)

    def test_prepended_iv_and_musl(self):
        seed = 1_700_000_200
        plain = b"PK\x03\x04" + b"zip-body-bytes"
        blob = encrypt(plain, seed, "musl", "cbc-prepended")
        found = crack_bytes(
            blob,
            center=seed - 4,
            window=4,
            runtimes=("musl",),
            layouts=("cbc-prepended",),
        )
        self.assertEqual(found.solution.layout, "cbc-prepended")
        self.assertEqual(decrypt_bytes(blob, found.solution)[0], plain)

    def test_miss_outside_the_window(self):
        blob = encrypt(b"%PDF-1.7\nnope\n", 50_000, "msvcrt", "ecb")
        found = crack_bytes(blob, center=10, window=2, runtimes=("msvcrt",))
        self.assertIsNone(found.solution)

    def test_ignore_tail(self):
        seed = 1_700_000_300
        plain = b"%PDF-1.7\nwith-tail\n"
        blob = encrypt(plain, seed, "msvcrt", "ecb") + b"TRAILER!"
        found = crack_bytes(
            blob,
            center=seed,
            window=0,
            ignore_tail=8,
            runtimes=("msvcrt",),
            layouts=("ecb",),
        )
        self.assertIsNotNone(found.solution)
        self.assertEqual(decrypt_bytes(blob, found.solution, ignore_tail=8)[0], plain)


class CommandTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _plant(self, name: str, plaintext: bytes, seed: int, mtime: int) -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(encrypt(plaintext, seed, "msvcrt", "ecb"))
        os.utime(path, (mtime, mtime))
        return path

    def test_directory_reuses_one_key(self):
        seed = 1_700_000_400
        self._plant("locked/a.pdf.enc", b"%PDF-1.7\nfirst\n", seed, seed + 5)
        self._plant("locked/b.png.enc", b"\x89PNG\r\n\x1a\nsecond", seed, seed + 40)
        out = self.root / "restored"
        status = main(
            [
                str(self.root / "locked"),
                "--output-dir",
                str(out),
                "--runtime",
                "msvcrt",
                "--layout",
                "ecb",
                "--window",
                "60",
                "-q",
            ]
        )
        self.assertEqual(status, 0)
        self.assertTrue((out / "a.pdf").read_bytes().startswith(b"%PDF-1.7\n"))
        self.assertTrue((out / "b.png").read_bytes().startswith(b"\x89PNG"))

    def test_per_file_seeds(self):
        first = 1_700_000_500
        second = first + 10_000
        self._plant("locked/one.pdf.enc", b"%PDF-1.7\none\n", first, first)
        self._plant("locked/two.pdf.enc", b"%PDF-1.7\ntwo\n", second, second)
        out = self.root / "restored"
        status = main(
            [
                str(self.root / "locked"),
                "--output-dir",
                str(out),
                "--per-file",
                "--runtime",
                "msvcrt",
                "--layout",
                "ecb",
                "--window",
                "0",
                "-q",
            ]
        )
        self.assertEqual(status, 0)
        self.assertIn(b"one", (out / "one.pdf").read_bytes())
        self.assertIn(b"two", (out / "two.pdf").read_bytes())

    def test_refuses_to_overwrite(self):
        seed = 1_700_000_600
        source = self._plant("note.pdf.enc", b"%PDF-1.7\nkeep\n", seed, seed)
        target = self.root / "note.pdf"
        target.write_bytes(b"original")
        status = main([str(source), "--runtime", "msvcrt", "--window", "0"])
        self.assertEqual(status, 2)
        self.assertEqual(target.read_bytes(), b"original")

    def test_module_help(self):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(SRC)
        proc = subprocess.run(
            [sys.executable, "-m", "clockseed", "--help"],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("srand(time(NULL))", proc.stdout)


if __name__ == "__main__":
    unittest.main()
