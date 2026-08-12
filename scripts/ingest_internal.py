#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree

from hub_config import configured_report_sources
from report_formats import FormatError, extract_document


DATA_ROOT = Path(
    os.environ.get(
        "BLUE_SEC_DATA",
        Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
        / "blue-sec-hub",
    )
)
INTERNAL = DATA_ROOT / "internal"
DOCUMENTS = INTERNAL / "documents"
MANIFEST = INTERNAL / "manifest.jsonl"
TEXT_SUFFIXES = {
    ".csv",
    ".har",
    ".http",
    ".json",
    ".jsonl",
    ".log",
    ".md",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}
MAX_BYTES = 100 * 1024 * 1024
DOCUMENT_SUFFIXES = {".docx", ".docm", ".pdf", ".xlsx"}
SECURITY_REPORT_SUFFIXES = {
    ".docx", ".docm", ".doc", ".pdf", ".xlsx", ".xls",
    ".csv", ".txt", ".md", ".html", ".htm", ".mhtml",
}


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def extract_docx(path: Path) -> str:
    with zipfile.ZipFile(path) as archive:
        root = ElementTree.fromstring(archive.read("word/document.xml"))
    paragraphs: list[str] = []
    paragraph_tag = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}p"
    text_tag = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t"
    for paragraph in root.iter(paragraph_tag):
        text = "".join(node.text or "" for node in paragraph.iter(text_tag))
        if text:
            paragraphs.append(text)
    return "\n".join(paragraphs)


def extract_xlsx(path: Path) -> str:
    namespace = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
    with zipfile.ZipFile(path) as archive:
        shared: list[str] = []
        if "xl/sharedStrings.xml" in archive.namelist():
            root = ElementTree.fromstring(archive.read("xl/sharedStrings.xml"))
            for item in root.iter(f"{namespace}si"):
                shared.append("".join(node.text or "" for node in item.iter(f"{namespace}t")))

        output: list[str] = []
        sheets = sorted(
            name
            for name in archive.namelist()
            if name.startswith("xl/worksheets/sheet") and name.endswith(".xml")
        )
        for sheet in sheets:
            output.append(f"\n## {sheet}\n")
            root = ElementTree.fromstring(archive.read(sheet))
            for row in root.iter(f"{namespace}row"):
                values: list[str] = []
                for cell in row.iter(f"{namespace}c"):
                    value_node = cell.find(f"{namespace}v")
                    if value_node is None:
                        inline = cell.find(f"{namespace}is")
                        value = (
                            "".join(
                                node.text or ""
                                for node in inline.iter(f"{namespace}t")
                            )
                            if inline is not None
                            else ""
                        )
                    else:
                        value = value_node.text or ""
                        if cell.get("t") == "s" and value.isdigit():
                            value = shared[int(value)]
                    values.append(value)
                output.append("\t".join(values))
    return "\n".join(output)


def extract(path: Path) -> str | None:
    suffix = path.suffix.lower()
    if suffix in SECURITY_REPORT_SUFFIXES:
        document = extract_document(path)
        if document is not None:
            return str(document.get("text") or "")
    if suffix in TEXT_SUFFIXES:
        return path.read_text(encoding="utf-8", errors="replace")
    if suffix == ".pdf":
        result = subprocess.run(
            ["pdftotext", "-layout", str(path), "-"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return result.stdout
    if suffix in {".docx", ".docm"}:
        return extract_docx(path)
    if suffix == ".xlsx":
        return extract_xlsx(path)
    return None


def walk(sources: list[tuple[Path, str]]):
    for path, mode in sources:
        if path.is_file():
            candidates = [path]
        elif path.is_dir():
            candidates = path.rglob("*")
        else:
            continue
        for child in candidates:
            suffix = child.suffix.casefold()
            if mode == "documents" and suffix not in DOCUMENT_SUFFIXES:
                continue
            if mode == "security-reports" and suffix not in SECURITY_REPORT_SUFFIXES:
                continue
            if path.is_dir():
                relative = child.relative_to(path)
                if child.is_file() and not any(part.startswith(".") for part in relative.parts):
                    yield child
            elif child.is_file():
                yield child


def main() -> None:
    parser = argparse.ArgumentParser(description="Index local security reports and evidence")
    parser.add_argument("paths", nargs="*", type=Path)
    parser.add_argument(
        "--configured",
        action="store_true",
        help="include all configured report roots",
    )
    args = parser.parse_args()
    sources = [(path, "all") for path in args.paths]
    if args.configured or not sources:
        sources.extend(configured_report_sources())
    if not sources:
        raise SystemExit(
            "no report paths supplied or configured; use blue-sec-config add-report-root"
        )
    resolved_sources = sorted(
        {(path.expanduser().resolve(), mode) for path, mode in sources},
        key=lambda item: (str(item[0]), item[1]),
    )
    available_sources: list[tuple[Path, str]] = []
    for path, mode in resolved_sources:
        if path.exists():
            available_sources.append((path, mode))
        else:
            print(f"[skip:missing] {path}")
    if not available_sources:
        raise SystemExit("no configured or supplied report paths are currently available")

    DOCUMENTS.mkdir(parents=True, exist_ok=True)
    known = set()
    if MANIFEST.exists():
        for line in MANIFEST.read_text(encoding="utf-8").splitlines():
            try:
                entry = json.loads(line)
                known.add((entry["sha256"], entry["source"]))
            except (KeyError, json.JSONDecodeError):
                continue

    added = skipped = 0
    with MANIFEST.open("a", encoding="utf-8") as manifest:
        for path in walk(available_sources):
            try:
                size = path.stat().st_size
                if size > MAX_BYTES:
                    skipped += 1
                    print(f"[skip:size] {path}")
                    continue
                sha256 = digest(path)
                key = (sha256, str(path))
                if key in known:
                    skipped += 1
                    continue
                content = extract(path)
                target = None
                if content is not None:
                    target = DOCUMENTS / f"{sha256}.txt"
                    header = (
                        f"source: {path}\n"
                        f"sha256: {sha256}\n"
                        f"indexed_at: {datetime.now(timezone.utc).isoformat()}\n\n"
                    )
                    target.write_text(header + content, encoding="utf-8")
                entry = {
                    "source": str(path),
                    "sha256": sha256,
                    "bytes": size,
                    "indexed_at": datetime.now(timezone.utc).isoformat(),
                    "text": str(target) if target else None,
                }
                manifest.write(json.dumps(entry, ensure_ascii=False) + "\n")
                known.add(key)
                added += 1
                print(f"[indexed] {path}")
            except (
                OSError,
                subprocess.CalledProcessError,
                zipfile.BadZipFile,
                ElementTree.ParseError,
                IndexError,
                FormatError,
            ) as error:
                skipped += 1
                print(f"[skip:error] {path}: {error}")
    print(f"[ok] indexed={added} skipped={skipped} manifest={MANIFEST}")


if __name__ == "__main__":
    main()
