#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {".json", ".jsonl", ".md", ".markdown", ".txt"}


def data_root() -> Path:
    return Path(
        os.environ.get(
            "BLUE_SEC_DATA",
            Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
            / "blue-sec-hub",
        )
    )


def index_path() -> Path:
    return data_root() / "search" / "knowledge.sqlite3"


def source_lock() -> dict[str, Any]:
    try:
        return json.loads((ROOT / "sources.lock.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"sources": {}}


def source_metadata(path: Path, roots: list[tuple[str, Path]]) -> dict[str, str]:
    lock = source_lock().get("sources", {})
    for kind, root in roots:
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        name = relative.parts[0] if kind == "upstreams" and relative.parts else kind
        metadata = lock.get(name, {}) if kind == "upstreams" else {}
        trust = str(metadata.get("trust") or ("internal" if kind in {"internal", "reports", "overlays", "vendored"} else "community"))
        return {
            "source_kind": kind,
            "source_name": name,
            "source_commit": str(metadata.get("commit") or "local"),
            "trust": trust,
            "instruction_authority": "false",
        }
    return {
        "source_kind": "unknown",
        "source_name": "unknown",
        "source_commit": "unknown",
        "trust": "untrusted",
        "instruction_authority": "false",
    }


def iter_documents(roots: list[tuple[str, Path]]) -> Iterable[tuple[Path, str]]:
    for _, root in roots:
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.suffix.casefold() not in TEXT_SUFFIXES:
                continue
            if path.stat().st_size > 5 * 1024 * 1024:
                continue
            try:
                yield path, path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue


def root_fingerprint(roots: list[tuple[str, Path]]) -> str:
    value = hashlib.sha256()
    for path, content in iter_documents(roots):
        value.update(str(path).encode())
        value.update(hashlib.sha256(content.encode()).digest())
    value.update(hashlib.sha256(json.dumps(source_lock(), sort_keys=True).encode()).digest())
    return value.hexdigest()


def chunks(content: str, limit: int = 1600) -> Iterable[tuple[int, int, str]]:
    pending: list[str] = []
    start = 1
    size = 0
    lines = content.splitlines()
    for number, line in enumerate(lines, start=1):
        clean = line.strip()
        if not clean:
            if pending:
                yield start, number - 1, "\n".join(pending)
                pending, size = [], 0
            continue
        if pending and size + len(clean) > limit:
            yield start, number - 1, "\n".join(pending)
            pending, size, start = [], 0, number
        if not pending:
            start = number
        pending.append(clean)
        size += len(clean)
    if pending:
        yield start, len(lines), "\n".join(pending)


def build(roots: list[tuple[str, Path]], destination: Path | None = None) -> dict[str, Any]:
    target = destination or index_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary_name = tempfile.mkstemp(prefix=".knowledge-", suffix=".sqlite3", dir=target.parent)
    os.close(handle)
    temporary = Path(temporary_name)
    documents = 0
    chunk_count = 0
    try:
        connection = sqlite3.connect(temporary)
        connection.executescript(
            """
            PRAGMA journal_mode=DELETE;
            CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE documents (
                id INTEGER PRIMARY KEY,
                path TEXT NOT NULL UNIQUE,
                title TEXT NOT NULL,
                source_kind TEXT NOT NULL,
                source_name TEXT NOT NULL,
                source_commit TEXT NOT NULL,
                trust TEXT NOT NULL,
                instruction_authority INTEGER NOT NULL,
                content_sha256 TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE chunks (
                id INTEGER PRIMARY KEY,
                document_id INTEGER NOT NULL REFERENCES documents(id),
                line_start INTEGER NOT NULL,
                line_end INTEGER NOT NULL,
                body TEXT NOT NULL
            );
            CREATE VIRTUAL TABLE chunks_fts USING fts5(body, content='chunks', content_rowid='id');
            """
        )
        for path, content in iter_documents(roots):
            metadata = source_metadata(path, roots)
            title = next((line.lstrip("# ").strip() for line in content.splitlines() if line.strip()), path.stem)
            cursor = connection.execute(
                """INSERT INTO documents
                (path,title,source_kind,source_name,source_commit,trust,instruction_authority,content_sha256,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    str(path),
                    title[:500],
                    metadata["source_kind"],
                    metadata["source_name"],
                    metadata["source_commit"],
                    metadata["trust"],
                    0,
                    hashlib.sha256(content.encode()).hexdigest(),
                    datetime.fromtimestamp(path.stat().st_mtime, UTC).isoformat(),
                ),
            )
            document_id = int(cursor.lastrowid)
            documents += 1
            for line_start, line_end, body in chunks(content):
                chunk_cursor = connection.execute(
                    "INSERT INTO chunks(document_id,line_start,line_end,body) VALUES (?,?,?,?)",
                    (document_id, line_start, line_end, body),
                )
                connection.execute(
                    "INSERT INTO chunks_fts(rowid,body) VALUES (?,?)",
                    (int(chunk_cursor.lastrowid), body),
                )
                chunk_count += 1
        fingerprint = root_fingerprint(roots)
        connection.executemany(
            "INSERT INTO metadata(key,value) VALUES (?,?)",
            (
                ("schema_version", "1"),
                ("root_fingerprint", fingerprint),
                ("generated_at", datetime.now(UTC).isoformat()),
            ),
        )
        connection.commit()
        connection.close()
        os.replace(temporary, target)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return {
        "schema_version": 1,
        "path": str(target),
        "documents": documents,
        "chunks": chunk_count,
        "root_fingerprint": fingerprint,
    }


def is_current(roots: list[tuple[str, Path]], path: Path | None = None) -> bool:
    target = path or index_path()
    if not target.is_file():
        return False
    try:
        connection = sqlite3.connect(target)
        row = connection.execute(
            "SELECT value FROM metadata WHERE key='root_fingerprint'"
        ).fetchone()
        connection.close()
        return bool(row and row[0] == root_fingerprint(roots))
    except sqlite3.Error:
        return False


def search(
    terms: list[str], roots: list[tuple[str, Path]], limit: int
) -> list[dict[str, Any]]:
    if not is_current(roots):
        build(roots)
    query = " OR ".join(f'"{term.replace(chr(34), chr(34) * 2)}"' for term in terms if term)
    if not query:
        return []
    connection = sqlite3.connect(index_path())
    connection.row_factory = sqlite3.Row
    rows = connection.execute(
        """
        SELECT d.path,d.title,d.source_kind,d.source_name,d.source_commit,d.trust,
               d.instruction_authority,d.content_sha256,d.updated_at,
               c.line_start,c.line_end,c.body,bm25(chunks_fts) AS rank
        FROM chunks_fts
        JOIN chunks c ON c.id=chunks_fts.rowid
        JOIN documents d ON d.id=c.document_id
        WHERE chunks_fts MATCH ?
        ORDER BY rank, d.trust='internal' DESC, d.updated_at DESC
        LIMIT ?
        """,
        (query, limit),
    ).fetchall()
    connection.close()
    results = [dict(row) for row in rows]
    normalized_terms = [term.casefold() for term in terms if term]
    trust_weight = {"internal": 3, "official": 2, "community": 1, "untrusted": 0}
    for item in results:
        body = str(item["body"]).casefold()
        coverage = sum(term in body for term in normalized_terms) / max(1, len(normalized_terms))
        item["retrieval"] = {
            "lexical_rank": item.pop("rank"),
            "term_coverage": round(coverage, 4),
            "trust_weight": trust_weight.get(str(item["trust"]), 0),
            "reranker": "fts5-coverage-trust-fusion-v1",
            "embedding": "not-configured",
        }
    results.sort(
        key=lambda item: (
            -float(item["retrieval"]["term_coverage"]),
            -int(item["retrieval"]["trust_weight"]),
            float(item["retrieval"]["lexical_rank"]),
            str(item["path"]),
        )
    )
    return results
