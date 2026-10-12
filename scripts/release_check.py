"""Validate shareable source content and create an allowlisted release archive."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
import zipfile
from pathlib import Path

ROOT_FILES = {"README.md", "AGENTS.md", "CHANGELOG.md", "pyproject.toml", "uv.lock", ".gitignore", ".gitattributes", "config.example.toml", "Cyber-Operator.code-workspace", "RELEASE_INVENTORY.json"}
TREES = {"scripts", "tests", "templates", "docs", "knowledge_base", ".github"}
IGNORED = {".venv", "__pycache__", ".pytest_cache", ".ruff_cache", ".git"}
TEXT_SUFFIXES = {".py", ".md", ".toml", ".lock", ".json", ".yml", ".yaml", ".svg", ".mmd", ".code-workspace"}
PRIVATE_NAMES = {"TASK_CONTEXT.md", "ACTIVE_TASK", "engagement.json", "engagement_events.jsonl", "engagement_intake.json", "engagement_manifest.json", "credentials.jsonl", ".env"}
MARKERS = re.compile(r"\b(?:" + "OS" + "AI" + r"\+?|" + "H" + "TB" + r"|Off" + "Sec" + r")\b|\bexam[-_](?:fast|no[-_]download)|[A-Z]:[\\/]Users[\\/][^\\/\s]+|/ho" + r"me/[^/\s]+/", re.IGNORECASE)


def release_files(root: Path) -> list[Path]:
    files = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if any(part in IGNORED for part in relative.parts):
            continue
        if path.is_symlink():
            raise ValueError(f"release refuses symlink: {relative}")
        if not path.is_file():
            continue
        if relative.parts[0] not in TREES and relative.as_posix() not in ROOT_FILES:
            raise ValueError(f"unapproved release path: {relative}")
        if path.name in PRIVATE_NAMES or path.suffix in {".jsonl", ".pem", ".key", ".pfx", ".zip"} or any(part in {"private", "workspaces", "evidence", "private_knowledge"} for part in relative.parts):
            raise ValueError(f"private runtime data in release: {relative}")
        if path.suffix not in TEXT_SUFFIXES and not path.name.startswith("cyber-") and path.name not in ROOT_FILES:
            raise ValueError(f"unreviewed file type: {relative}")
        text = path.read_text(encoding="utf-8")
        if MARKERS.search(relative.as_posix()) or MARKERS.search(text):
            raise ValueError(f"legacy branding or personal home path: {relative}")
        files.append(path)
    return files


def package(root: Path, destination: Path) -> dict:
    files = [path for path in release_files(root) if path.name != "RELEASE_INVENTORY.json"]
    destination = destination.expanduser().resolve()
    if destination == root or root in destination.parents:
        raise ValueError("release archive must be outside the source checkout")
    if destination.exists():
        raise ValueError("release archive already exists; refusing overwrite")
    inventory = []
    with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in files:
            relative = path.relative_to(root).as_posix()
            data = path.read_bytes()
            info = zipfile.ZipInfo("Cyber-Operator/" + relative, date_time=(2026, 10, 9, 0, 0, 0))
            info.create_system = 3
            mode = 0o755 if path.name.startswith("cyber-") and path.parent.name == "scripts" else 0o644
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
            inventory.append({"path": relative, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
        archive.writestr("Cyber-Operator/RELEASE_INVENTORY.json", json.dumps(inventory, indent=2) + "\n")
    with zipfile.ZipFile(destination) as archive:
        if archive.testzip() is not None:
            raise ValueError("archive CRC verification failed")
    return {"files": len(files), "sha256": hashlib.sha256(destination.read_bytes()).hexdigest()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zip", type=Path)
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parent.parent
    try:
        result = package(root, args.zip) if args.zip else {"files": len(release_files(root)), "private_runtime": "absent"}
        print(json.dumps(result, indent=2))
        return 0
    except (ValueError, OSError, UnicodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
