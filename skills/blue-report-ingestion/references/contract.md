# Versioned Report Contract

## Versions

- `schema_version`: report artifact field contract.
- `extractor_version`: file-format and redaction behavior.
- `profile_set_version`: tracked profile collection version.
- `profile_set_digest`: tracked and local profile content digest.
- `cache_key`: digest of source SHA-256 and all processing versions.

Changing any processing contract creates a new artifact. It never rewrites the source report.

## Artifact

```json
{
  "schema_version": 1,
  "extractor_version": "1.2.0",
  "profile_set_version": 1,
  "cache_key": "sha256",
  "source": {
    "sha256": "sha256",
    "bytes": 0,
    "format": "docx"
  },
  "document": {
    "title": "report title",
    "system_name": "reported name",
    "system_id": "stable-id",
    "report_date": "YYYY-MM-DD",
    "status": "reported"
  },
  "recognition": {
    "profile_id": "profile-name",
    "profile_version": 1,
    "confidence": "high"
  },
  "findings": [],
  "blocks": []
}
```

`findings` are reviewable drafts, not accepted vulnerability records. `blocks` contain redacted text and stable IDs such as `body:p0001`, `body:t0002:r0003`, or `page:0001:line:0010`.

## Local Profile

```json
{
  "schema_version": 1,
  "labels": {
    "system_name": ["业务系统"],
    "weakness": ["风险类型"]
  },
  "profiles": [
    {
      "id": "vendor-report",
      "version": 1,
      "signals": ["厂商固定标题", "固定章节名"],
      "minimum_signals": 2
    }
  ]
}
```

Use only reusable labels and structural signals. Do not include target identifiers or report evidence.
