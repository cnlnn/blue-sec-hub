#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import subprocess
import tarfile
import tomllib
import zipfile
from pathlib import Path, PurePosixPath

from quality_gate import evaluate as evaluate_quality, load as load_quality


ROOT = Path(__file__).resolve().parents[1]


def project_version() -> str:
    value = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return str(value["project"]["version"])


def check_tag(tag: str, version: str) -> None:
    if tag != f"v{version}":
        raise SystemExit(f"release tag {tag!r} does not match project version v{version}")


def tracked_files() -> list[tuple[Path, int]]:
    result = subprocess.run(
        ["git", "ls-files", "--stage", "-z"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    files: list[tuple[Path, int]] = []
    for raw in result.split(b"\0"):
        if not raw:
            continue
        metadata, relative = raw.split(b"\t", 1)
        mode = int(metadata.split(b" ", 1)[0], 8)
        path = ROOT / relative.decode("utf-8")
        if path.is_file():
            files.append((path, mode))
    return sorted(files, key=lambda item: item[0].relative_to(ROOT).as_posix())


def archive_name(path: Path, prefix: str) -> str:
    relative = PurePosixPath(path.relative_to(ROOT).as_posix())
    return str(PurePosixPath(prefix) / relative)


def build_tar_gz(
    destination: Path,
    files: list[tuple[Path, int]],
    prefix: str,
) -> None:
    with destination.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                for path, index_mode in files:
                    body = path.read_bytes()
                    info = tarfile.TarInfo(archive_name(path, prefix))
                    info.size = len(body)
                    info.mode = 0o755 if index_mode & 0o111 else 0o644
                    info.mtime = 0
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    archive.addfile(info, io.BytesIO(body))


def build_zip(
    destination: Path,
    files: list[tuple[Path, int]],
    prefix: str,
) -> None:
    with zipfile.ZipFile(
        destination,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for path, index_mode in files:
            info = zipfile.ZipInfo(archive_name(path, prefix))
            info.date_time = (1980, 1, 1, 0, 0, 0)
            info.compress_type = zipfile.ZIP_DEFLATED
            mode = 0o755 if index_mode & 0o111 else 0o644
            info.external_attr = (mode & 0xFFFF) << 16
            archive.writestr(info, path.read_bytes())


def write_checksums(out_dir: Path, artifacts: list[Path]) -> Path:
    destination = out_dir / "SHA256SUMS"
    lines = [
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}"
        for path in artifacts
    ]
    destination.write_text("\n".join(lines) + "\n", encoding="ascii")
    return destination


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a Blue Sec Hub source release")
    parser.add_argument("--tag", required=True)
    parser.add_argument("--out", type=Path, default=ROOT / "dist")
    parser.add_argument(
        "--quality-result",
        type=Path,
        help="result from the pinned Web/API/SPA benchmark suite",
    )
    parser.add_argument(
        "--artifact-only",
        action="store_true",
        help="Build installable archives after source/platform validation without claiming behavioral certification",
    )
    args = parser.parse_args()

    version = project_version()
    check_tag(args.tag, version)
    if not args.quality_result and not args.artifact_only:
        raise SystemExit("release requires a benchmark --quality-result")
    if args.quality_result:
        if not args.quality_result.is_file():
            raise SystemExit("release requires a benchmark --quality-result")
        quality = evaluate_quality(
            load_quality(ROOT / "benchmarks" / "quality-gates.json"),
            load_quality(args.quality_result),
        )
        if not quality["passed"]:
            raise SystemExit("release benchmark quality gates did not pass")
    elif args.artifact_only:
        print("[artifact-only] behavioral benchmark certification is not claimed")
    files = tracked_files()
    if not files:
        raise SystemExit("release has no tracked files")
    args.out.mkdir(parents=True, exist_ok=True)
    prefix = f"blue-sec-hub-{version}"
    tar_path = args.out / f"{prefix}.tar.gz"
    zip_path = args.out / f"{prefix}.zip"
    build_tar_gz(tar_path, files, prefix)
    build_zip(zip_path, files, prefix)
    checksum_path = write_checksums(args.out, [tar_path, zip_path])
    print(tar_path)
    print(zip_path)
    print(checksum_path)


if __name__ == "__main__":
    main()
