"""Resolve the per-workspace target-artifact handling mode."""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path

if __package__:
    from . import operational_profile
else:
    import operational_profile  # type: ignore[no-redef]

STANDARD = "standard"
NO_DOWNLOAD = "no-download"
MODES = (STANDARD, NO_DOWNLOAD)
ARTIFACT_HANDLING_PREFIX = "- Artifact handling:"
ARTIFACT_HANDLING_STEM_RE = re.compile(
    r"^\s*-\s*artifact(?:[ _-]+)handling\b",
    re.IGNORECASE,
)
MAX_LOCAL_PROCESSING_ENTRIES = 10_000


class ArtifactHandlingError(RuntimeError):
    """The workspace artifact-handling mode is malformed or unsupported."""


def validate_mode(mode: str) -> str:
    """Return one supported canonical artifact-handling mode."""
    if mode not in MODES:
        raise ArtifactHandlingError(
            "artifact handling must be one of: " + ", ".join(MODES)
        )
    return mode


def parse_mode_text(text: str) -> str:
    """Parse one canonical mode line; legacy contexts default to standard."""
    matches = [line for line in text.splitlines() if ARTIFACT_HANDLING_STEM_RE.match(line)]
    if not matches:
        return STANDARD
    if len(matches) != 1:
        raise ArtifactHandlingError(
            "TASK_CONTEXT.md contains duplicate artifact handling entries"
        )
    line = matches[0]
    expected_prefix = ARTIFACT_HANDLING_PREFIX + " "
    if not line.startswith(expected_prefix):
        raise ArtifactHandlingError(
            "TASK_CONTEXT.md contains a malformed artifact handling entry"
        )
    mode = line[len(expected_prefix) :]
    if mode != mode.strip() or not mode:
        raise ArtifactHandlingError(
            "TASK_CONTEXT.md contains a malformed artifact handling entry"
        )
    return validate_mode(mode)


def render_mode_text(text: str, mode: str) -> str:
    """Replace or append the single canonical artifact-handling line."""
    validate_mode(mode)
    parse_mode_text(text)
    canonical = f"{ARTIFACT_HANDLING_PREFIX} {mode}"
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.startswith(ARTIFACT_HANDLING_PREFIX):
            lines[index] = canonical
            return "\n".join(lines) + ("\n" if text.endswith("\n") else "")
    separator = "" if not text or text.endswith("\n") else "\n"
    return text + separator + canonical + "\n"


def validate_local_processing(workspace: Path) -> None:
    """Validate the optional classified local-processing tree without reading data."""
    private = workspace / "private"
    local_processing = private / "local_processing"
    try:
        local_processing_metadata = local_processing.lstat()
    except FileNotFoundError:
        return

    try:
        private_metadata = private.lstat()
    except FileNotFoundError as exc:
        raise ArtifactHandlingError(
            "private/local_processing has no real private parent"
        ) from exc
    for metadata, label in (
        (private_metadata, "private"),
        (local_processing_metadata, "private/local_processing"),
    ):
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ArtifactHandlingError(
                f"{label} must be a real non-symlink directory"
            )
        if metadata.st_uid != os.geteuid():
            raise ArtifactHandlingError(f"{label} must be owned by the current user")
        if stat.S_IMODE(metadata.st_mode) != 0o700:
            raise ArtifactHandlingError(f"{label} must use private mode 0700")

    entry_count = 0

    def walk_error(_error: OSError) -> None:
        raise ArtifactHandlingError("private/local_processing is not traversable")

    for root, directories, files in os.walk(
        local_processing,
        followlinks=False,
        onerror=walk_error,
    ):
        for name in directories:
            entry_count += 1
            metadata = (Path(root) / name).lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise ArtifactHandlingError(
                    "private/local_processing directories must be current-user-owned "
                    "real directories with mode 0700"
                )
        for name in files:
            entry_count += 1
            metadata = (Path(root) / name).lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise ArtifactHandlingError(
                    "private/local_processing files must be current-user-owned "
                    "real files with mode 0600"
                )
        if entry_count > MAX_LOCAL_PROCESSING_ENTRIES:
            raise ArtifactHandlingError(
                "private/local_processing exceeds the metadata entry limit"
            )


def workspace_mode(workspace: Path) -> str:
    """Resolve one existing context; only a missing legacy field defaults."""
    if __package__:
        from . import engagement_config
    else:
        import engagement_config
    try:
        managed = engagement_config.load(workspace)
    except (ValueError, RuntimeError, OSError) as exc:
        raise ArtifactHandlingError(str(exc)) from exc
    if managed is not None:
        validate_local_processing(workspace)
        return managed["definition"]["artifact_handling"]
    context = workspace / "TASK_CONTEXT.md"
    try:
        mode = parse_mode_text(operational_profile.read_context(context))
    except operational_profile.OperationalProfileError as exc:
        raise ArtifactHandlingError(str(exc)) from exc
    validate_local_processing(workspace)
    return mode


def policy_matrix(mode: str) -> tuple[tuple[str, str], ...]:
    """Local persistence only; remote storage is independently configured."""
    validate_mode(mode)
    return (
        ("local target-origin files", "OFF" if mode == NO_DOWNLOAD else "subject to engagement approval"),
        ("temporary or encoded target-file copies", "OFF" if mode == NO_DOWNLOAD else "subject to engagement approval"),
        ("operator-generated observations and reports", "ON — provenance required"),
        ("remote storage", "independent switch; no automatic transfer"),
        ("automatic fallback", "OFF"),
        ("authorization, scope and impact rules", "UNCHANGED"),
    )


def require_local_persistence(workspace: Path, origin: str) -> None:
    """Guard supported file intake before reading or writing artifact bytes."""
    if origin not in {"target-file", "operator-generated"}:
        raise ArtifactHandlingError("origin must be target-file or operator-generated")
    context = workspace / "TASK_CONTEXT.md"
    if __package__:
        from . import engagement_config
    else:
        import engagement_config
    mode = workspace_mode(workspace) if context.exists() or context.is_symlink() or engagement_config.is_managed(workspace) else STANDARD
    if mode == NO_DOWNLOAD and origin == "target-file":
        raise ArtifactHandlingError("no-download forbids persisting target-origin files on local disk")
    if origin == "target-file" and engagement_config.is_managed(workspace):
        try:
            state = engagement_config.status(workspace)
        except (ValueError, RuntimeError, OSError) as exc:
            raise ArtifactHandlingError(str(exc)) from exc
        if state["status"] != "active":
            raise ArtifactHandlingError("target-file persistence requires a current reviewed configuration within its assessment window")
