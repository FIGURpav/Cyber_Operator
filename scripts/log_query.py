"""Log every prompt sent to an AI assistant as an immutable JSON record."""

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

if __package__:
    from . import artifact_io
else:
    import artifact_io  # type: ignore[no-redef]

HOST_ID_PATTERN = "H{:02d}"
VALID_HOST_IDS = {HOST_ID_PATTERN.format(i) for i in range(1, 100)}


def fatal(message: str) -> None:
    """Print an error to stderr and exit with a non-zero status."""
    print(f"error: {message}", file=sys.stderr)
    sys.exit(1)


def validate_host_id(host_id: str) -> None:
    """Validate that a host ID is in the H01..H99 range."""
    if not host_id:
        fatal("host ID must not be empty")
    if not host_id.isascii():
        fatal(f"host ID must be ASCII: {host_id!r}")
    if host_id != host_id.strip():
        fatal(f"host ID must not contain whitespace: {host_id!r}")
    if host_id == "H00":
        fatal("host ID H00 is reserved; expected H01 through H99")
    if host_id not in VALID_HOST_IDS:
        fatal(
            "invalid host ID; expected 'H' followed by exactly two decimal "
            f"digits from 01 to 99, e.g. H01, got {host_id!r}"
        )


def validate_host_ids(host_ids: list[str] | None) -> list[str]:
    """Validate host IDs and remove duplicates while preserving order."""
    seen: set[str] = set()
    ordered: list[str] = []
    for host_id in host_ids or []:
        validate_host_id(host_id)
        if host_id not in seen:
            seen.add(host_id)
            ordered.append(host_id)
    return ordered


def _has_control_characters(value: str) -> bool:
    """Return True if value contains ASCII control characters."""
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in value)


def validate_purpose(purpose: str) -> str:
    """Validate and return a purpose string."""
    if not purpose:
        fatal("purpose is required")
    if _has_control_characters(purpose):
        fatal("purpose must not contain control characters")
    if "\n" in purpose or "\r" in purpose:
        fatal("purpose must not contain newline characters")
    if not purpose.strip():
        fatal("purpose must not contain only whitespace")
    if not purpose.isprintable():
        fatal("purpose must be printable text")
    if len(purpose) > 120:
        fatal(f"purpose too long: {len(purpose)} characters (max 120)")
    return purpose


def validate_model(model: str) -> str:
    """Validate and return a model name."""
    if not model:
        fatal("model is required")
    if _has_control_characters(model):
        fatal("model must not contain control characters")
    if "\n" in model or "\r" in model:
        fatal("model must not contain newline characters")
    if not model.strip():
        fatal("model must not contain only whitespace")
    if not model.isprintable():
        fatal("model must be printable text")
    if len(model) > 100:
        fatal(f"model name too long: {len(model)} characters (max 100)")
    return model


def validate_context_refs(context_refs: list[str] | None) -> list[str]:
    """Validate context references and return them in order."""
    validated: list[str] = []
    for ref in context_refs or []:
        if not ref:
            fatal("context reference must not be empty")
        if _has_control_characters(ref):
            fatal("context reference must not contain control characters")
        if "\n" in ref or "\r" in ref:
            fatal("context reference must not contain newline characters")
        if ref.startswith("/"):
            fatal(f"context reference must be relative, not absolute: {ref!r}")
        parts = ref.replace("\\", "/").split("/")
        if ".." in parts:
            fatal(f"context reference must not contain '..': {ref!r}")
        if "" in parts:
            fatal(f"context reference must not contain empty components: {ref!r}")
        validated.append(ref)
    return validated


def validate_workspace(workspace: str) -> Path:
    """Return a safe workspace path or exit if the workspace is unusable."""
    path = Path(workspace)

    for part in path.parts:
        if part == "..":
            fatal(f"workspace path must not contain '..': {workspace!r}")

    resolved = path.resolve(strict=False)

    if not resolved.exists():
        fatal(f"workspace does not exist: {workspace!r}")
    if not resolved.is_dir():
        fatal(f"workspace is not a directory: {workspace!r}")
    if not (resolved / "global.md").is_file():
        fatal(f"workspace is missing global.md: {workspace!r}")
    if not (resolved / "queries").is_dir():
        fatal(f"workspace is missing queries/ directory: {workspace!r}")

    return resolved


def read_prompt(prompt_file: str | None) -> tuple[bytes, str]:
    """Read prompt bytes from a file or standard input and validate them."""
    if prompt_file is not None:
        path = Path(prompt_file)
        if not path.exists():
            fatal(f"prompt file does not exist: {prompt_file!r}")
        if not path.is_file():
            fatal(f"prompt file is not a regular file: {prompt_file!r}")
        try:
            raw = path.read_bytes()
        except OSError as exc:
            fatal(f"cannot read prompt file: {exc}")
    else:
        try:
            raw = sys.stdin.buffer.read()
        except OSError as exc:
            fatal(f"cannot read standard input: {exc}")

    if len(raw) == 0:
        fatal("prompt input is empty")

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        fatal(f"prompt input is not valid UTF-8: {exc}")

    if not text.strip():
        fatal("prompt input contains only whitespace")

    return raw, text


def build_query_id(now: datetime) -> str:
    """Generate a query ID from a UTC datetime with microsecond precision."""
    return now.strftime("QRY-%Y%m%dT%H%M%S%fZ")


def build_record(
    query_id: str,
    now: datetime,
    host_ids: list[str],
    purpose: str,
    model: str,
    context_refs: list[str],
    prompt_bytes: bytes,
    prompt_text: str,
) -> dict[str, Any]:
    """Build the canonical query record dictionary."""
    scope = "host" if host_ids else "global"
    sha256 = hashlib.sha256(prompt_bytes).hexdigest()
    return {
        "schema_version": "1.0",
        "query_id": query_id,
        "timestamp_utc": now.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "scope": scope,
        "host_ids": host_ids,
        "purpose": purpose,
        "model": model,
        "context_refs": context_refs,
        "prompt_sha256": sha256,
        "prompt_text": prompt_text,
    }


def write_record(workspace: Path, query_id: str, record: dict[str, Any]) -> Path:
    """Write the record atomically without overwriting an existing file."""
    queries_dir = workspace / "queries"
    destination = queries_dir / f"{query_id}.json"

    if destination.exists():
        fatal(f"query record already exists: {destination}")

    try:
        artifact_io.publish_file(
            destination,
            json.dumps(record, indent=2, ensure_ascii=False) + "\n",
        )
    except OSError as exc:
        fatal(f"failed to write query record: {exc}")

    return destination


def log_query(
    workspace: str,
    purpose: str,
    host_ids: list[str] | None = None,
    model: str = "Kimi K2.7 Code",
    context_refs: list[str] | None = None,
    prompt_file: str | None = None,
    now: datetime | None = None,
) -> tuple[Path, dict[str, Any]]:
    """Create a canonical query record and write it to the workspace."""
    validated_workspace = validate_workspace(workspace)
    validated_host_ids = validate_host_ids(host_ids)
    validated_purpose = validate_purpose(purpose)
    validated_model = validate_model(model)
    validated_context_refs = validate_context_refs(context_refs)
    prompt_bytes, prompt_text = read_prompt(prompt_file)

    if now is None:
        now = datetime.now(UTC)
    query_id = build_query_id(now)

    record = build_record(
        query_id=query_id,
        now=now,
        host_ids=validated_host_ids,
        purpose=validated_purpose,
        model=validated_model,
        context_refs=validated_context_refs,
        prompt_bytes=prompt_bytes,
        prompt_text=prompt_text,
    )

    destination = write_record(validated_workspace, query_id, record)
    return destination, record


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Record a prompt before it is sent to an AI assistant."
    )
    parser.add_argument(
        "--workspace",
        required=True,
        help="explicit private workspace directory",
    )
    parser.add_argument(
        "--purpose",
        required=True,
        help="short description of why the prompt is being sent",
    )
    parser.add_argument(
        "--host-id",
        action="append",
        dest="host_ids",
        help="host identifier, e.g. H01; may be repeated",
    )
    parser.add_argument(
        "--model",
        default="Kimi K2.7 Code",
        help="model name (default: 'Kimi K2.7 Code')",
    )
    parser.add_argument(
        "--context",
        action="append",
        dest="context_refs",
        help="context reference supplied to the model; may be repeated",
    )
    parser.add_argument(
        "--prompt-file",
        default=None,
        help="path to a file containing the prompt (default: read stdin)",
    )
    return parser.parse_args(argv)


def _workspace_relative(path: Path) -> str:
    """Return a workspace-relative path string when possible."""
    try:
        return path.relative_to(Path.cwd()).as_posix()
    except ValueError:
        return path.as_posix()


def main(argv: list[str] | None = None, now: datetime | None = None) -> int:
    """CLI entry point."""
    args = parse_args(argv)

    destination, record = log_query(
        workspace=args.workspace,
        purpose=args.purpose,
        host_ids=args.host_ids,
        model=args.model,
        context_refs=args.context_refs,
        prompt_file=args.prompt_file,
        now=now,
    )

    scope = record["scope"]
    host_display = ", ".join(record["host_ids"]) if record["host_ids"] else "global"

    print(f"query_id: {record['query_id']}")
    print(f"scope: {scope}")
    print(f"hosts: {host_display}")
    print(f"purpose: {record['purpose']}")
    print(f"path: {_workspace_relative(destination)}")
    print(f"prompt_sha256: {record['prompt_sha256']}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
