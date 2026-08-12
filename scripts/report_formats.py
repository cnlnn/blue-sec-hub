#!/usr/bin/env python3
from __future__ import annotations

import html
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from xml.etree import ElementTree


EXTRACTOR_VERSION = "1.4.0"
MAX_ARCHIVE_FILES = 5000
MAX_ARCHIVE_BYTES = 250 * 1024 * 1024
MAX_XML_BYTES = 50 * 1024 * 1024
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
    ".html",
    ".htm",
    ".mhtml",
}
WORD_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
SHEET_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
CORE_NS = "http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
DC_NS = "http://purl.org/dc/elements/1.1/"
DCTERMS_NS = "http://purl.org/dc/terms/"

HEADER_SECRET = re.compile(
    r"(?im)^(\s*(?:authorization|proxy-authorization|cookie|set-cookie|"
    r"x-api-key|x-auth-token|access[-_]?token|refresh[-_]?token)"
    r"\s*[:=]\s*)([^\r\n]+)"
)
INLINE_SECRET = re.compile(
    r"(?i)\b((?:password|passwd|pwd|secret|client_secret|api_key|"
    r"access_token|refresh_token|ak|sk)\s*[:=]\s*)"
    r"([\"']?)[^\s,;\"']{6,}\2"
)
JWT = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"
)
PHONE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")
CN_ID = re.compile(r"(?<!\d)\d{17}[0-9Xx](?!\d)")
EMAIL = re.compile(
    r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@"
    r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![A-Za-z0-9.-])"
)


class FormatError(ValueError):
    pass


class VisibleTextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hidden = 0
        self.parts: list[str] = []

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        if tag.casefold() in {"script", "style", "noscript", "svg"}:
            self.hidden += 1
        elif tag.casefold() in {"p", "div", "br", "tr", "li", "h1", "h2", "h3"}:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() in {"script", "style", "noscript", "svg"} and self.hidden:
            self.hidden -= 1
        elif tag.casefold() in {"p", "div", "tr", "li"}:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self.hidden:
            self.parts.append(data)

    def text(self) -> str:
        return "\n".join(
            line.strip()
            for line in "".join(self.parts).splitlines()
            if line.strip()
        )


def redact(text: str) -> tuple[str, int]:
    count = 0

    def replace_header(match: re.Match[str]) -> str:
        nonlocal count
        count += 1
        return f"{match.group(1)}<redacted>"

    def replace_inline(match: re.Match[str]) -> str:
        nonlocal count
        count += 1
        return f"{match.group(1)}<redacted>"

    text = HEADER_SECRET.sub(replace_header, text)
    text = INLINE_SECRET.sub(replace_inline, text)
    text, jwt_count = JWT.subn("<redacted-jwt>", text)
    text, phone_count = PHONE.subn("<redacted-phone>", text)
    text, id_count = CN_ID.subn("<redacted-cn-id>", text)
    text, email_count = EMAIL.subn("<redacted-email>", text)
    return text, count + jwt_count + phone_count + id_count + email_count


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def node_text(node: ElementTree.Element) -> str:
    output: list[str] = []
    for child in node.iter():
        name = local_name(child.tag)
        if name == "t":
            output.append(child.text or "")
        elif name == "tab":
            output.append("\t")
        elif name in {"br", "cr"}:
            output.append("\n")
    return "".join(output).strip()


def paragraph_style(node: ElementTree.Element) -> str | None:
    style = node.find(f"./{{{WORD_NS}}}pPr/{{{WORD_NS}}}pStyle")
    if style is None:
        return None
    return style.get(f"{{{WORD_NS}}}val")


def checked_archive(path: Path) -> zipfile.ZipFile:
    try:
        archive = zipfile.ZipFile(path)
    except zipfile.BadZipFile as error:
        raise FormatError(f"invalid Office archive: {path.name}") from error
    entries = archive.infolist()
    if len(entries) > MAX_ARCHIVE_FILES:
        archive.close()
        raise FormatError(f"archive contains too many files: {len(entries)}")
    uncompressed = sum(entry.file_size for entry in entries)
    if uncompressed > MAX_ARCHIVE_BYTES:
        archive.close()
        raise FormatError(f"archive expands beyond {MAX_ARCHIVE_BYTES} bytes")
    return archive


def read_xml(archive: zipfile.ZipFile, name: str) -> ElementTree.Element:
    try:
        info = archive.getinfo(name)
    except KeyError as error:
        raise FormatError(f"archive is missing {name}") from error
    if info.file_size > MAX_XML_BYTES:
        raise FormatError(f"XML part is too large: {name}")
    return ElementTree.fromstring(archive.read(name))


def append_block(
    blocks: list[dict[str, Any]],
    identifier: str,
    kind: str,
    text: str,
    **metadata: Any,
) -> int:
    text, redactions = redact(text.strip())
    if not text:
        return 0
    block = {"id": identifier, "kind": kind, "text": text}
    block.update({key: value for key, value in metadata.items() if value is not None})
    blocks.append(block)
    return redactions


def extract_word_part(
    root: ElementTree.Element,
    part: str,
    blocks: list[dict[str, Any]],
) -> int:
    redactions = 0
    paragraph_number = 0
    table_number = 0
    row_number = 0
    children = list(root.find(f".//{{{WORD_NS}}}body") or root)
    for child in children:
        name = local_name(child.tag)
        if name == "p":
            paragraph_number += 1
            redactions += append_block(
                blocks,
                f"{part}:p{paragraph_number:04d}",
                "paragraph",
                node_text(child),
                style=paragraph_style(child),
            )
        elif name == "tbl":
            table_number += 1
            row_number = 0
            for row in child.findall(f"./{{{WORD_NS}}}tr"):
                row_number += 1
                cells = [
                    node_text(cell)
                    for cell in row.findall(f"./{{{WORD_NS}}}tc")
                ]
                redactions += append_block(
                    blocks,
                    f"{part}:t{table_number:04d}:r{row_number:04d}",
                    "table-row",
                    " | ".join(value for value in cells if value),
                    cells=[redact(value)[0] for value in cells],
                )
    return redactions


def extract_docx(path: Path) -> dict[str, Any]:
    blocks: list[dict[str, Any]] = []
    metadata: dict[str, Any] = {}
    redactions = 0
    with checked_archive(path) as archive:
        root = read_xml(archive, "word/document.xml")
        redactions += extract_word_part(root, "body", blocks)

        for name in sorted(archive.namelist()):
            if not re.fullmatch(r"word/(?:header|footer)\d+\.xml", name):
                continue
            part = Path(name).stem
            redactions += extract_word_part(read_xml(archive, name), part, blocks)

        if "docProps/core.xml" in archive.namelist():
            core = read_xml(archive, "docProps/core.xml")
            fields = {
                "title": (DC_NS, "title"),
                "created": (DCTERMS_NS, "created"),
                "modified": (DCTERMS_NS, "modified"),
            }
            for key, (namespace, field) in fields.items():
                node = core.find(f".//{{{namespace}}}{field}")
                if node is not None and node.text:
                    metadata[key] = node.text.strip()

        image_count = sum(
            1 for name in archive.namelist() if name.startswith("word/media/")
        )

    return {
        "format": "docx",
        "blocks": blocks,
        "text": "\n".join(block["text"] for block in blocks),
        "metadata": metadata,
        "stats": {
            "blocks": len(blocks),
            "images": image_count,
            "redactions": redactions,
        },
    }


def extract_pdf(path: Path) -> dict[str, Any]:
    result = subprocess.run(
        ["pdftotext", "-layout", str(path), "-"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    blocks: list[dict[str, Any]] = []
    redactions = 0
    for page_number, page in enumerate(result.stdout.split("\f"), start=1):
        for line_number, line in enumerate(page.splitlines(), start=1):
            redactions += append_block(
                blocks,
                f"page:{page_number:04d}:line:{line_number:04d}",
                "line",
                line,
            )
    return {
        "format": "pdf",
        "blocks": blocks,
        "text": "\n".join(block["text"] for block in blocks),
        "metadata": {},
        "stats": {
            "blocks": len(blocks),
            "pages": max(1, len(result.stdout.split("\f"))),
            "redactions": redactions,
        },
    }


def extract_xlsx(path: Path) -> dict[str, Any]:
    blocks: list[dict[str, Any]] = []
    redactions = 0
    with checked_archive(path) as archive:
        shared: list[str] = []
        if "xl/sharedStrings.xml" in archive.namelist():
            root = read_xml(archive, "xl/sharedStrings.xml")
            for item in root.iter(f"{{{SHEET_NS}}}si"):
                shared.append(node_text(item))
        sheets = sorted(
            name
            for name in archive.namelist()
            if name.startswith("xl/worksheets/sheet") and name.endswith(".xml")
        )
        for sheet_number, sheet in enumerate(sheets, start=1):
            root = read_xml(archive, sheet)
            for row in root.iter(f"{{{SHEET_NS}}}row"):
                values: list[str] = []
                for cell in row.iter(f"{{{SHEET_NS}}}c"):
                    value_node = cell.find(f"{{{SHEET_NS}}}v")
                    value = value_node.text if value_node is not None else ""
                    if cell.get("t") == "s" and value and value.isdigit():
                        index = int(value)
                        value = shared[index] if index < len(shared) else value
                    values.append(value or "")
                row_id = row.get("r") or str(len(blocks) + 1)
                redactions += append_block(
                    blocks,
                    f"sheet:{sheet_number:04d}:row:{row_id}",
                    "table-row",
                    " | ".join(values),
                    cells=[redact(value)[0] for value in values],
                )
    return {
        "format": "xlsx",
        "blocks": blocks,
        "text": "\n".join(block["text"] for block in blocks),
        "metadata": {},
        "stats": {
            "blocks": len(blocks),
            "sheets": len(sheets),
            "redactions": redactions,
        },
    }


def extract_text(path: Path) -> dict[str, Any]:
    raw = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix.casefold() in {".html", ".htm", ".mhtml"}:
        parser = VisibleTextParser()
        parser.feed(raw)
        raw = html.unescape(parser.text())
    blocks: list[dict[str, Any]] = []
    redactions = 0
    for line_number, line in enumerate(raw.splitlines(), start=1):
        redactions += append_block(
            blocks,
            f"line:{line_number:06d}",
            "line",
            line,
        )
    return {
        "format": path.suffix.casefold().lstrip(".") or "text",
        "blocks": blocks,
        "text": "\n".join(block["text"] for block in blocks),
        "metadata": {},
        "stats": {"blocks": len(blocks), "redactions": redactions},
    }


def extract_legacy_markup(path: Path) -> dict[str, Any] | None:
    prefix = path.read_bytes()[:4096]
    charset_match = re.search(
        rb"charset\s*=\s*[\"']?([A-Za-z0-9._-]+)",
        prefix,
        re.IGNORECASE,
    )
    declared = (
        charset_match.group(1).decode("ascii", errors="ignore")
        if charset_match
        else None
    )
    encodings = tuple(
        dict.fromkeys(
            item
            for item in (
                declared,
                "utf-8-sig",
                "utf-16",
                "utf-16-le",
                "utf-16-be",
                "gb18030",
                "latin-1",
            )
            if item
        )
    )
    decoded = None
    kind = None
    for encoding in encodings:
        try:
            candidate = prefix.decode(encoding)
        except (LookupError, UnicodeError):
            continue
        lowered = candidate.lstrip().casefold()
        if lowered.startswith("<?xml"):
            kind = "xml"
        elif lowered.startswith("<!doctype html") or "<html" in lowered:
            kind = "html"
        if kind:
            decoded = path.read_text(encoding=encoding, errors="replace")
            break
    if decoded is None:
        return None
    parser = VisibleTextParser()
    parser.feed(decoded)
    text = html.unescape(parser.text())
    blocks: list[dict[str, Any]] = []
    redactions = 0
    for line_number, line in enumerate(text.splitlines(), start=1):
        redactions += append_block(
            blocks,
            f"line:{line_number:06d}",
            "line",
            line,
        )
    return {
        "format": path.suffix.casefold().lstrip("."),
        "blocks": blocks,
        "text": "\n".join(block["text"] for block in blocks),
        "metadata": {"conversion": f"legacy-{kind}-text"},
        "stats": {"blocks": len(blocks), "redactions": redactions},
    }


def extract_legacy(path: Path) -> dict[str, Any]:
    markup_value = extract_legacy_markup(path)
    if markup_value is not None:
        return markup_value
    soffice = shutil.which("libreoffice") or shutil.which("soffice")
    if not soffice:
        raise FormatError("LibreOffice is unavailable for legacy document conversion")
    output_format = "docx" if path.suffix.casefold() == ".doc" else "xlsx"
    sandbox_parent = Path(
        os.environ.get(
            "BLUE_SEC_CACHE",
            Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
            / "blue-sec-hub",
        )
    ) / "office-sandbox"
    sandbox_parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    sandbox_parent.chmod(0o700)
    with tempfile.TemporaryDirectory(
        prefix="blue-sec-office-",
        dir=sandbox_parent,
    ) as temporary_name:
        temporary = Path(temporary_name)
        temporary.chmod(0o700)
        profile = temporary / "profile"
        output = temporary / "output"
        profile.mkdir(mode=0o700)
        output.mkdir(mode=0o700)
        environment = os.environ.copy()
        environment.update(
            {
                "HOME": str(temporary),
                "TMPDIR": str(temporary),
                "DISPLAY": "",
                "SAL_USE_VCLPLUGIN": "svp",
            }
        )
        command = [
            soffice,
            "--headless",
            "--safe-mode",
            "--nologo",
            "--nodefault",
            "--nofirststartwizard",
            "--norestore",
            f"-env:UserInstallation=file://{profile}",
            "--convert-to",
            output_format,
            "--outdir",
            str(output),
            str(path),
        ]
        bwrap = shutil.which("bwrap") if os.name == "posix" else None
        if not bwrap:
            raise FormatError("legacy Office isolation is unavailable")
        sandbox_input = f"/run/blue-sec-input{path.suffix.casefold()}"
        command[-1] = sandbox_input
        command = [
            bwrap,
            "--die-with-parent",
            "--unshare-net",
            "--ro-bind",
            "/",
            "/",
            "--tmpfs",
            "/tmp",
            "--tmpfs",
            "/run",
            "--ro-bind",
            str(path),
            sandbox_input,
            "--bind",
            str(temporary),
            str(temporary),
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            *command,
        ]
        subprocess.run(
            command,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=int(os.environ.get("BLUE_SEC_OFFICE_TIMEOUT", "45")),
            env=environment,
        )
        candidates = list(output.glob(f"*.{output_format}"))
        if len(candidates) != 1:
            raise FormatError("legacy conversion did not produce one document")
        value = (
            extract_docx(candidates[0])
            if output_format == "docx"
            else extract_xlsx(candidates[0])
        )
        value["format"] = path.suffix.casefold().lstrip(".")
        value["metadata"]["conversion"] = "isolated-libreoffice"
        return value


def extract_document(path: Path) -> dict[str, Any] | None:
    suffix = path.suffix.casefold()
    if suffix in {".doc", ".xls"}:
        return extract_legacy(path)
    if suffix in {".docx", ".docm"}:
        return extract_docx(path)
    if suffix == ".pdf":
        return extract_pdf(path)
    if suffix == ".xlsx":
        return extract_xlsx(path)
    if suffix in TEXT_SUFFIXES:
        return extract_text(path)
    return None
