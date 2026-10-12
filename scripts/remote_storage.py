"""Independent remote artifact-location registration; no network or transfer code."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

MODES = ("disabled", "approved")
PREFIXES = ("- Remote storage:", "- Remote storage location:", "- Remote storage approval:")
STEM = re.compile(r"^\s*-\s*remote[ _-]+storage\b", re.IGNORECASE)


class RemoteStorageError(ValueError):
    """Invalid or incomplete storage metadata."""


@dataclass(frozen=True)
class Settings:
    mode: str = "disabled"
    location: str = "none"
    approval: str = "none"

    def validate(self) -> Settings:
        if self.mode not in MODES:
            raise RemoteStorageError("remote storage must be disabled or approved")
        for value in (self.location, self.approval):
            if not isinstance(value, str) or not value or value != value.strip() or len(value) > 1024 or any(ord(c) < 32 or ord(c) == 127 for c in value):
                raise RemoteStorageError("remote storage fields must be bounded single-line text")
        if self.mode == "disabled":
            if (self.location, self.approval) != ("none", "none"):
                raise RemoteStorageError("disabled remote storage must not retain a location or approval")
        else:
            try:
                parsed = urlsplit(self.location)
            except ValueError as exc:
                raise RemoteStorageError("location is malformed") from exc
            if parsed.scheme not in {"https", "s3", "ssh"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
                raise RemoteStorageError("location must be a credential-free https, s3 or ssh URI without query or fragment")
            try:
                _ = parsed.port
            except ValueError as exc:
                raise RemoteStorageError("location has an invalid port") from exc
            if self.approval == "none":
                raise RemoteStorageError("approved remote storage requires an approval reference")
        return self


def parse(text: str) -> Settings:
    entries = [line for line in text.splitlines() if STEM.match(line)]
    if not entries:
        return Settings()
    values = []
    for prefix in PREFIXES:
        matching = [line for line in entries if line.startswith(prefix + " ")]
        if len(matching) != 1:
            raise RemoteStorageError("remote storage context fields are missing, malformed or duplicated")
        values.append(matching[0][len(prefix) + 1:])
    if len(entries) != len(PREFIXES):
        raise RemoteStorageError("unexpected remote storage context field")
    return Settings(*values).validate()


def render(text: str, settings: Settings) -> str:
    parse(text)
    settings.validate()
    lines = [line for line in text.splitlines() if not STEM.match(line)]
    lines.extend(f"{prefix} {value}" for prefix, value in zip(PREFIXES, (settings.mode, settings.location, settings.approval), strict=True))
    return "\n".join(lines) + "\n"


DISABLED = Settings()


def workspace_settings(workspace):
    """Use the canonical definition for managed workspaces, legacy context otherwise."""
    if __package__:
        from . import engagement_config, operational_profile
    else:
        import engagement_config
        import operational_profile
    managed = engagement_config.load(workspace)
    if managed is not None:
        value = managed["definition"]
        return Settings(value["remote_storage"], value["remote_location"], value["remote_approval"]).validate()
    return parse(operational_profile.read_context(workspace / "TASK_CONTEXT.md"))
