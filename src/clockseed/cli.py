"""Command line for clockseed."""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

from clockseed import __version__
from clockseed.formats import identify
from clockseed.prng import PURE_RUNTIMES, RUNTIMES
from clockseed.recover import (
    BLOCK,
    DEFAULT_LAYOUTS,
    CrackResult,
    ClockseedError,
    Sample,
    Solution,
    cipher_span,
    crack_samples,
    decrypt_bytes,
    restored_name,
)

PROBE_READ = BLOCK + 512


def console_main() -> None:
    """Setuptools entry point. ``main`` returns a status so tests can call it."""
    raise SystemExit(main())


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code
        return code if isinstance(code, int) else 2
    try:
        return _run(args)
    except ClockseedError as exc:
        print(f"clockseed: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"clockseed: {exc}", file=sys.stderr)
        return 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="clockseed",
        description=(
            "Recover AES-encrypted files when the key was generated with "
            "srand(time(NULL)) and rand()."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  clockseed secret.pdf.enc\n"
            "  clockseed ./locked --output-dir ./restored\n"
            "  clockseed note.enc --runtime msvcrt --timestamp 1773322200\n"
        ),
    )
    parser.add_argument("path", type=Path, help="encrypted file or directory")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="where to write one restored file",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="directory for restored files (default for a directory: NAME-restored)",
    )
    parser.add_argument(
        "-w",
        "--window",
        type=int,
        default=120,
        help="seconds to search on each side of the timestamp (default: 120)",
    )
    parser.add_argument(
        "-t",
        "--timestamp",
        type=int,
        help="Unix time to center the search on, instead of the file mtime",
    )
    parser.add_argument(
        "--time",
        choices=("mtime", "birth"),
        default="mtime",
        help="which file timestamp to center on when --timestamp is omitted (default: mtime)",
    )
    parser.add_argument(
        "--runtime",
        default="all",
        help="msvcrt, glibc, musl, native, or all (default: all, which skips native)",
    )
    parser.add_argument(
        "--key-bytes",
        default="32,24,16",
        help="AES key lengths to try, comma-separated (default: 32,24,16)",
    )
    parser.add_argument(
        "--layout",
        default="all",
        help="ecb, cbc-zero, cbc-derived, cbc-prepended, or all (default: all)",
    )
    parser.add_argument(
        "--per-file",
        action="store_true",
        help="search a separate seed for every file",
    )
    parser.add_argument(
        "--ignore-tail",
        type=int,
        default=0,
        help="ignore this many trailing bytes; they are not ciphertext",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print the key and write nothing",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="overwrite an existing output file",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="print only output paths",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"clockseed {__version__}",
    )
    return parser


def _run(args: argparse.Namespace) -> int:
    source = args.path
    if not source.exists():
        raise ClockseedError(f"no such file: {source}")
    if args.ignore_tail < 0:
        raise ClockseedError("--ignore-tail must be zero or positive")
    if args.output is not None and args.output_dir is not None:
        raise ClockseedError("pass either --output or --output-dir")

    runtimes = _parse_choice(args.runtime, set(RUNTIMES), list(PURE_RUNTIMES))
    layouts = _parse_choice(args.layout, set(DEFAULT_LAYOUTS), list(DEFAULT_LAYOUTS))
    key_lengths = _parse_key_lengths(args.key_bytes)
    files = _collect(source)
    if not files:
        print(f"clockseed: no files in {source}", file=sys.stderr)
        return 1

    output_dir = args.output_dir
    if source.is_dir():
        if args.output is not None:
            raise ClockseedError("a directory needs --output-dir, not --output")
        if output_dir is None:
            output_dir = source.with_name(source.name + "-restored")
        if _is_inside(output_dir, source):
            raise ClockseedError("output directory is inside the input directory")
    elif output_dir is not None and _is_inside(output_dir, source.parent):
        pass

    if args.per_file or len(files) == 1:
        return _restore_each(args, files, output_dir, runtimes, layouts, key_lengths)
    return _restore_shared(args, files, output_dir, runtimes, layouts, key_lengths)


def _restore_shared(args, files, output_dir, runtimes, layouts, key_lengths) -> int:
    center = args.timestamp if args.timestamp is not None else _earliest(files, args.time)
    samples = [_sample(path) for path in files]
    if not args.quiet:
        _announce(len(files), center, args.window)
    result = crack_samples(
        samples,
        center=center,
        window=args.window,
        runtimes=runtimes,
        key_lengths=key_lengths,
        layouts=layouts,
        ignore_tail=args.ignore_tail,
    )
    if result.solution is None:
        _miss(args.window)
        return 1
    if not args.quiet:
        _print_solution(result)
    written, recognized = _write_all(args, files, output_dir, result.solution)
    if written == 0:
        print("clockseed: the key was found, but no file could be written", file=sys.stderr)
        return 1
    if not args.quiet and len(files) > 1 and recognized < len(files):
        print(
            "clockseed: some files have no known header. "
            "If each file was seeded on its own, rerun with --per-file.",
            file=sys.stderr,
        )
    return 0


def _restore_each(args, files, output_dir, runtimes, layouts, key_lengths) -> int:
    written = 0
    for path in files:
        center = args.timestamp if args.timestamp is not None else _file_time(path, args.time)
        if not args.quiet:
            _announce(1, center, args.window, label=str(path))
        result = crack_samples(
            [_sample(path)],
            center=center,
            window=args.window,
            runtimes=runtimes,
            key_lengths=key_lengths,
            layouts=layouts,
            ignore_tail=args.ignore_tail,
        )
        if result.solution is None:
            print(f"clockseed: no key for {path}", file=sys.stderr)
            continue
        if not args.quiet:
            _print_solution(result)
        count, _ = _write_all(args, [path], output_dir, result.solution)
        written += count
    if written == 0:
        _miss(args.window)
        return 1
    return 0


def _write_all(args, files: list[Path], output_dir: Path | None, solution: Solution):
    written = 0
    recognized = 0
    root = args.path if args.path.is_dir() else None
    for path in files:
        destination = _destination(path, args.output, output_dir, root)
        blob = path.read_bytes()
        if cipher_span(len(blob), solution.layout, args.ignore_tail) is None:
            print(
                f"clockseed: skip {path}: length does not fit {solution.layout_label}",
                file=sys.stderr,
            )
            continue
        plain, removed = decrypt_bytes(blob, solution, args.ignore_tail)
        match = identify(plain[:PROBE_READ])
        if match is not None:
            recognized += 1
        if args.dry_run:
            if args.quiet:
                print(destination)
            else:
                label = match.name if match is not None else "no known header"
                print(f"  dry run {path.name} -> {destination} ({label})")
            written += 1
            continue
        if destination.exists() and not args.force:
            raise ClockseedError(
                f"{destination} already exists; pass --force to overwrite"
            )
        if destination.resolve() == path.resolve():
            raise ClockseedError(f"refusing to overwrite the input {path}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(plain)
        written += 1
        if args.quiet:
            print(destination)
        else:
            label = match.name if match is not None else "no known header"
            padding = f", removed {removed} bytes of PKCS7" if removed else ""
            print(f"  wrote {destination} ({label}{padding})")
    return written, recognized


def _sample(path: Path) -> Sample:
    with path.open("rb") as handle:
        prefix = handle.read(PROBE_READ)
    return Sample(str(path), prefix, path.stat().st_size)


def _destination(
    path: Path,
    output: Path | None,
    output_dir: Path | None,
    root: Path | None,
) -> Path:
    name = restored_name(path.name)
    if output is not None:
        return output
    if output_dir is not None:
        relative = path.relative_to(root) if root is not None else Path(name)
        return output_dir / relative.parent / name
    return path.with_name(name)


def _collect(source: Path) -> list[Path]:
    if source.is_file():
        return [source]
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(source, followlinks=False):
        dirnames[:] = sorted(name for name in dirnames if not name.startswith("."))
        for name in sorted(filenames):
            if name.startswith("."):
                continue
            found.append(Path(dirpath) / name)
    return found


def _file_time(path: Path, source: str) -> int:
    stat = path.stat()
    if source == "birth":
        birth = getattr(stat, "st_birthtime", None)
        if birth is None:
            raise ClockseedError(
                "this system has no file creation time; pass --timestamp"
            )
        return int(birth)
    return int(stat.st_mtime)


def _earliest(files: list[Path], source: str) -> int:
    return min(_file_time(path, source) for path in files)


def _announce(count: int, center: int, window: int, label: str | None = None) -> None:
    moment = time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime(center))
    target = label or f"{count} file(s)"
    print(
        f"searching {target}, ±{window}s around {moment} ({center})",
        file=sys.stderr,
    )


def _print_solution(result: CrackResult) -> None:
    solution = result.solution
    assert solution is not None
    moment = time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime(solution.seed))
    side = "at the timestamp" if solution.distance == 0 else f"{solution.distance}s off the timestamp"
    print(
        f"seed {solution.seed} ({moment}), {solution.runtime}, {side}\n"
        f"  {solution.aes} {solution.layout_label}\n"
        f"  key {solution.key.hex()}\n"
        f"  matched {solution.match.name} on {result.matched_name}\n"
        f"  checked {result.seeds_checked} timestamps"
    )


def _miss(window: int) -> None:
    print(
        "clockseed: no key matched a known file header in that window. "
        f"The search covered ±{window}s. Widen --window, or set --timestamp "
        "to the second the sample started.",
        file=sys.stderr,
    )


def _parse_choice(value: str, allowed: set[str], everything: list[str]) -> list[str]:
    parts = [item.strip().lower() for item in value.split(",") if item.strip()]
    if not parts:
        raise ClockseedError("empty list")
    if parts == ["all"]:
        return everything
    unknown = [item for item in parts if item not in allowed]
    if unknown:
        known = ", ".join(sorted(allowed))
        raise ClockseedError(f"unknown value {unknown[0]!r}; choose from {known}, or all")
    return parts


def _parse_key_lengths(value: str) -> list[int]:
    lengths: list[int] = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            length = int(item)
        except ValueError as exc:
            raise ClockseedError(f"bad key length {item!r}") from exc
        if length not in (16, 24, 32):
            raise ClockseedError(f"key length {length} is not 16, 24, or 32")
        lengths.append(length)
    if not lengths:
        raise ClockseedError("pick at least one key length")
    return lengths


def _is_inside(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True
