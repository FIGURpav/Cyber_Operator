"""Resolve the per-workspace operational profile from TASK_CONTEXT.md."""

from __future__ import annotations

import stat
from pathlib import Path

STRICT = "strict"
CONTROLLED_ENGAGEMENT = "controlled-engagement"
PROFILES = (STRICT, CONTROLLED_ENGAGEMENT)
PROFILE_PREFIX = "- Operational profile:"
MAX_CONTEXT_BYTES = 64 * 1024


class OperationalProfileError(RuntimeError):
    """The workspace profile is malformed or cannot be read safely."""


def validate_profile(profile: str) -> str:
    """Return one supported canonical profile name."""
    if profile not in PROFILES:
        raise OperationalProfileError(
            "operational profile must be one of: " + ", ".join(PROFILES)
        )
    return profile


def parse_profile_text(text: str) -> str:
    """Parse one canonical profile line; legacy contexts default to strict."""
    matches = [line for line in text.splitlines() if line.startswith(PROFILE_PREFIX)]
    if not matches:
        return STRICT
    if len(matches) != 1:
        raise OperationalProfileError(
            "TASK_CONTEXT.md contains duplicate operational profile entries"
        )
    line = matches[0]
    expected_prefix = PROFILE_PREFIX + " "
    if not line.startswith(expected_prefix):
        raise OperationalProfileError(
            "TASK_CONTEXT.md contains a malformed operational profile entry"
        )
    profile = line[len(expected_prefix) :]
    if profile != profile.strip() or not profile:
        raise OperationalProfileError(
            "TASK_CONTEXT.md contains a malformed operational profile entry"
        )
    return validate_profile(profile)


def render_profile_text(text: str, profile: str) -> str:
    """Replace or append the single canonical operational-profile line."""
    validate_profile(profile)
    current = parse_profile_text(text)
    canonical = f"{PROFILE_PREFIX} {profile}"
    if current != STRICT or any(
        line.startswith(PROFILE_PREFIX) for line in text.splitlines()
    ):
        lines = text.splitlines()
        for index, line in enumerate(lines):
            if line.startswith(PROFILE_PREFIX):
                lines[index] = canonical
                break
        return "\n".join(lines) + ("\n" if text.endswith("\n") else "")
    separator = "" if not text or text.endswith("\n") else "\n"
    return text + separator + canonical + "\n"


def read_context(path: Path) -> str:
    """Read one bounded real context file without following a symlink."""
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise OperationalProfileError("TASK_CONTEXT.md is missing") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise OperationalProfileError(
            "TASK_CONTEXT.md must be a real non-symlink regular file"
        )
    if metadata.st_size > MAX_CONTEXT_BYTES:
        raise OperationalProfileError("TASK_CONTEXT.md is unexpectedly large")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise OperationalProfileError("TASK_CONTEXT.md is unreadable") from exc


def workspace_profile(workspace: Path) -> str:
    """Resolve a workspace profile; legacy workspaces without context are strict."""
    if __package__:
        from . import engagement_config
    else:
        import engagement_config
    try:
        if engagement_config.load(workspace) is not None:
            return STRICT
    except (ValueError, RuntimeError, OSError) as exc:
        raise OperationalProfileError(str(exc)) from exc
    context = workspace / "TASK_CONTEXT.md"
    try:
        context.lstat()
    except FileNotFoundError:
        return STRICT
    return parse_profile_text(read_context(context))
