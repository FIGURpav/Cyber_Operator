"""Generate a private Markdown appendix of all logged AI queries."""

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REQUIRED_FIELDS = (
    "query_id",
    "timestamp_utc",
    "scope",
    "host_ids",
    "purpose",
    "model",
    "context_refs",
    "prompt_sha256",
    "prompt_text",
)


def fatal(message: str) -> None:
    """Print a concise error to stderr and exit with a non-zero status."""
    print(f"error: {message}", file=sys.stderr)
    sys.exit(1)


def _contains_traversal(path: str) -> bool:
    """Return True if the path contains a '..' component."""
    return ".." in Path(path).parts


def validate_workspace(workspace: str) -> Path:
    """Return a safe, absolute workspace path or exit if it is unusable."""
    if _contains_traversal(workspace):
        fatal(f"workspace path must not contain '..': {workspace!r}")

    resolved = Path(workspace).resolve(strict=False)

    if not resolved.exists():
        fatal(f"workspace does not exist: {workspace!r}")
    if not resolved.is_dir():
        fatal(f"workspace is not a directory: {workspace!r}")

    global_md = resolved / "global.md"
    if not global_md.is_file():
        fatal(f"workspace is missing global.md: {workspace!r}")

    queries_dir = resolved / "queries"
    if not queries_dir.exists():
        fatal(f"workspace is missing queries/ directory: {workspace!r}")
    if not queries_dir.is_dir():
        fatal(f"queries/ is not a directory: {queries_dir!r}")

    report_dir = resolved / "report"
    if not report_dir.exists():
        fatal(f"workspace is missing report/ directory: {workspace!r}")
    if not report_dir.is_dir():
        fatal(f"report/ is not a directory: {report_dir!r}")

    return resolved


def _max_backtick_run(text: str) -> int:
    """Return the length of the longest run of consecutive backticks."""
    max_run = 0
    current = 0
    for ch in text:
        if ch == "`":
            current += 1
            max_run = max(max_run, current)
        else:
            current = 0
    return max_run


def _fence(text: str) -> str:
    """Return a Markdown code fence longer than any backtick run in text."""
    return "`" * max(_max_backtick_run(text) + 1, 3)


def _validate_record(record: dict[str, Any], filename: str) -> None:
    """Validate a query record or exit with a concise error."""
    missing = [field for field in REQUIRED_FIELDS if field not in record]
    if missing:
        fatal(
            f"query record {filename} is missing required fields: "
            f"{', '.join(missing)}"
        )

    if record.get("schema_version") != "1.0":
        fatal(
            f"query record {filename} has unsupported schema_version: "
            f"{record.get('schema_version')!r}"
        )

    query_id = record["query_id"]
    if query_id != Path(filename).stem:
        fatal(
            f"query record {filename} has query_id {query_id!r} "
            f"that does not match filename"
        )

    prompt_text = record["prompt_text"]
    if not isinstance(prompt_text, str):
        fatal(f"query record {filename} has invalid prompt_text: expected string")

    expected_sha256 = hashlib.sha256(prompt_text.encode("utf-8")).hexdigest()
    if record["prompt_sha256"] != expected_sha256:
        fatal(
            f"query record {filename} has prompt_sha256 that does not match "
            f"prompt text"
        )

    if not isinstance(record.get("host_ids"), list):
        fatal(f"query record {filename} has invalid host_ids: expected list")


def load_query_records(queries_dir: Path) -> list[dict[str, Any]]:
    """Load and validate all query records, sorted by filename."""
    try:
        query_files = sorted(queries_dir.glob("QRY-*.json"))
    except OSError as exc:
        fatal(f"cannot read queries directory: {exc}")

    records: list[dict[str, Any]] = []
    for query_file in query_files:
        if not query_file.is_file():
            fatal(f"query path is not a regular file: {query_file.name}")

        try:
            with query_file.open("r", encoding="utf-8", newline="") as handle:
                try:
                    record = json.load(handle)
                except json.JSONDecodeError as exc:
                    fatal(f"malformed JSON in query file {query_file.name}: {exc}")
        except UnicodeDecodeError as exc:
            fatal(f"query file {query_file.name} is not valid UTF-8: {exc}")
        except OSError as exc:
            fatal(f"cannot read query file {query_file.name}: {exc}")

        if not isinstance(record, dict):
            fatal(f"invalid query record in {query_file.name}: expected object")

        _validate_record(record, query_file.name)
        records.append(record)

    return records


def _format_host_ids(host_ids: list[str]) -> str:
    """Format host IDs for display."""
    return ", ".join(host_ids) if host_ids else "global"


def _format_context_refs(context_refs: list[str]) -> str:
    """Format context references for display."""
    return ", ".join(context_refs) if context_refs else "none"


def build_appendix(
    workspace: Path, records: list[dict[str, Any]], now: datetime
) -> str:
    """Generate the Markdown appendix content."""
    lines: list[str] = [
        "# AI Query Appendix",
        "",
        "## Appendix Metadata",
        "",
        f"- **Generated**: {now.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}",
        f"- **Source Workspace**: {workspace}",
        f"- **Total Queries**: {len(records)}",
        "",
    ]

    if not records:
        lines.extend(["No AI queries have been logged.", ""])
    else:
        for record in records:
            query_id = record["query_id"]
            lines.extend(
                [
                    f"## {query_id}",
                    "",
                    f"- **Timestamp**: {record['timestamp_utc']}",
                    f"- **Scope**: {record['scope']}",
                    f"- **Host IDs**: {_format_host_ids(record['host_ids'])}",
                    f"- **Purpose**: {record['purpose']}",
                    f"- **Model**: {record['model']}",
                    (
                        "- **Context References**: "
                        f"{_format_context_refs(record['context_refs'])}"
                    ),
                    f"- **Prompt SHA-256**: {record['prompt_sha256']}",
                    "",
                    "### Prompt",
                    "",
                ]
            )
            fence = _fence(record["prompt_text"])
            lines.extend([fence, record["prompt_text"], fence, ""])

    content = "\n".join(lines)
    if not content.endswith("\n"):
        content += "\n"
    return content


def write_output(output_path: Path, content: str, replace: bool) -> str:
    """Write content atomically and return 'created' or 'replaced'."""
    existed = output_path.exists()
    if existed and not replace:
        fatal(f"output file already exists: {output_path}")

    tmp = output_path.with_suffix(output_path.suffix + ".tmp")
    try:
        tmp.write_text(content, encoding="utf-8")
        tmp.replace(output_path)
    except OSError as exc:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass
        fatal(f"failed to write output file: {exc}")

    return "replaced" if existed else "created"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Generate a Markdown appendix of logged AI queries."
    )
    parser.add_argument(
        "--workspace",
        required=True,
        help="explicit private workspace directory",
    )
    parser.add_argument(
        "--replace",
        action="store_true",
        help="replace an existing generated appendix",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None, now: datetime | None = None) -> int:
    """CLI entry point."""
    args = parse_args(argv)
    workspace = validate_workspace(args.workspace)

    queries_dir = workspace / "queries"
    report_dir = workspace / "report"
    output_path = report_dir / "AI_QUERY_APPENDIX.md"

    records = load_query_records(queries_dir)

    if now is None:
        now = datetime.now(UTC)

    content = build_appendix(workspace, records, now)
    status = write_output(output_path, content, args.replace)

    print(f"output: {output_path}")
    print(f"queries: {len(records)}")
    print(f"status: {status}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
