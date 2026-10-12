#!/usr/bin/env python3
"""Validate private reusable knowledge without exposing its contents."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import sys
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote

MAX_FILE_BYTES = 2 * 1024 * 1024
QUICK_CARD_WORD_LIMIT = 600
NORMALIZED_NOTE_WORD_LIMIT = 2_000
TYPED_KINDS = {
    "authorized-test-method",
    "normalized-note",
    "operational-playbook",
    "quick-card",
}
FORBIDDEN_SUFFIXES = {
    ".bin",
    ".class",
    ".dll",
    ".exe",
    ".o",
    ".obj",
    ".pdb",
    ".pyc",
}
FORBIDDEN_NAMES = {"shellcode.h"}
MARKDOWN_LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
FRONTMATTER_KEY_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_-]*):(?:\s*(.*))?$")
WORD_RE = re.compile(r"\b[\w.+/#-]+\b", re.UNICODE)
POSSIBLE_SECRET_RE = re.compile(
    r"(?:"
    r"-----BEGIN (?:OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----"
    r"|AKIA[0-9A-Z]{16}"
    r"|glpat-[A-Za-z0-9_-]{20,}"
    r"|gh[pousr]_[A-Za-z0-9]{20,}"
    r"|xox[baprs]-[A-Za-z0-9-]{20,}"
    r")"
)


@dataclass(frozen=True, order=True)
class Issue:
    """One deterministic validation failure."""

    code: str
    path: str
    detail: str


@dataclass(frozen=True)
class ValidationSummary:
    """Counts safe to print without private document contents."""

    files: int
    markdown_files: int
    identifiers: int
    routable_documents: int
    reachable_documents: int


def _relative(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _is_real_directory(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    return stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode)


def _iter_entries(root: Path) -> list[Path]:
    entries: list[Path] = []
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in sorted(directories):
            entries.append(current_path / name)
        for name in sorted(files):
            entries.append(current_path / name)
    return entries


def _frontmatter(text: str) -> tuple[dict[str, str | list[str]], str | None]:
    lines = text.splitlines()
    if not lines or lines[0] != "---":
        return {}, None
    try:
        closing = lines.index("---", 1)
    except ValueError:
        return {}, "frontmatter opening delimiter has no closing delimiter"

    metadata: dict[str, str | list[str]] = {}
    current_list: str | None = None
    for line in lines[1:closing]:
        if line.startswith("  - ") and current_list is not None:
            value = line[4:].strip().strip('"\'')
            existing = metadata[current_list]
            if isinstance(existing, list):
                existing.append(value)
            continue
        if not line or line.startswith(" "):
            continue
        match = FRONTMATTER_KEY_RE.match(line)
        if not match:
            current_list = None
            continue
        key, raw_value = match.groups()
        if key in metadata:
            return metadata, f"duplicate frontmatter key: {key}"
        value = (raw_value or "").strip().strip('"\'')
        if value:
            metadata[key] = value
            current_list = None
        else:
            metadata[key] = []
            current_list = key
    return metadata, None


def _visible_markdown(text: str) -> tuple[str, bool]:
    visible: list[str] = []
    fence_char: str | None = None
    fence_length = 0
    for line in text.splitlines():
        match = re.match(r"^\s*([`~]{3,})(.*)$", line)
        if fence_char is None:
            if match:
                marker = match.group(1)
                if len(set(marker)) == 1:
                    fence_char = marker[0]
                    fence_length = len(marker)
                    continue
            visible.append(line)
            continue
        if match:
            marker = match.group(1)
            remainder = match.group(2).strip()
            if (
                marker[0] == fence_char
                and len(marker) >= fence_length
                and not remainder
            ):
                fence_char = None
                fence_length = 0
    return "\n".join(visible), fence_char is not None


def _link_destination(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith("<") and ">" in raw:
        return raw[1 : raw.index(">")]
    return raw.split(maxsplit=1)[0]


def _resolved_link(root: Path, source: Path, raw: str) -> Path | None:
    destination = unquote(_link_destination(raw))
    if not destination or destination.startswith("#"):
        return None
    if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", destination):
        return None
    destination = destination.split("#", 1)[0]
    if not destination:
        return source
    candidate = Path(destination)
    if candidate.is_absolute():
        return candidate
    return (source.parent / candidate).resolve(strict=False)


def _expected_type(relative: Path) -> str | None:
    parts = relative.parts
    if relative.name == "README.md":
        if len(parts) >= 4 and parts[0] == "methods":
            return "authorized-test-method"
        return None
    if parts[0] == "playbooks":
        return "operational-playbook"
    if parts[0] == "quick-cards":
        return "quick-card"
    if parts[0] == "notes" and "normalized" in parts:
        return "normalized-note"
    return None


def _is_module_playbook(relative: Path) -> bool:
    return (
        len(relative.parts) >= 3
        and relative.parts[0] == "playbooks"
        and relative.parts[1].startswith("module-")
        and relative.name != "README.md"
    )


def _is_routable(relative: Path, metadata: dict[str, str | list[str]]) -> bool:
    parts = relative.parts
    if metadata.get("type") in TYPED_KINDS:
        return True
    if relative.name == "README.md":
        return False
    if parts[0] == "notes" and len(parts) >= 3:
        return True
    return parts[0] in {"commands", "sources"}


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_knowledge_base(root: Path) -> tuple[list[Issue], ValidationSummary]:
    """Return validation issues and secret-free summary counts."""

    root = root.expanduser().absolute()
    issues: list[Issue] = []
    if not _is_real_directory(root):
        issue = Issue("invalid-root", ".", "root must be a real directory")
        return [issue], ValidationSummary(0, 0, 0, 0, 0)

    root_mode = stat.S_IMODE(root.lstat().st_mode)
    if root_mode != 0o700:
        issues.append(
            Issue("directory-mode", ".", f"expected 0700, found {root_mode:04o}")
        )

    entries = _iter_entries(root)
    regular_files: list[Path] = []
    markdown: dict[Path, str] = {}
    metadata_by_path: dict[Path, dict[str, str | list[str]]] = {}
    id_owners: dict[str, list[Path]] = defaultdict(list)
    hashes: dict[str, list[Path]] = defaultdict(list)

    for path in entries:
        relative = Path(_relative(root, path))
        metadata = path.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISLNK(metadata.st_mode):
            issues.append(Issue("symlink", relative.as_posix(), "symlinks are forbidden"))
            continue
        if stat.S_ISDIR(metadata.st_mode):
            if mode != 0o700:
                issues.append(
                    Issue(
                        "directory-mode",
                        relative.as_posix(),
                        f"expected 0700, found {mode:04o}",
                    )
                )
            if path.name == "__pycache__":
                issues.append(
                    Issue("build-output", relative.as_posix(), "Python cache directory")
                )
            continue
        if not stat.S_ISREG(metadata.st_mode):
            issues.append(
                Issue("special-file", relative.as_posix(), "only regular files are allowed")
            )
            continue

        regular_files.append(path)
        if mode != 0o600:
            issues.append(
                Issue(
                    "file-mode",
                    relative.as_posix(),
                    f"expected 0600, found {mode:04o}",
                )
            )
        if path.suffix.lower() in FORBIDDEN_SUFFIXES or path.name in FORBIDDEN_NAMES:
            issues.append(
                Issue(
                    "build-output",
                    relative.as_posix(),
                    "generated or compiled artifact is forbidden",
                )
            )
        if metadata.st_size > MAX_FILE_BYTES:
            issues.append(
                Issue(
                    "oversized-file",
                    relative.as_posix(),
                    f"maximum is {MAX_FILE_BYTES} bytes; found {metadata.st_size}",
                )
            )
            continue
        if metadata.st_size:
            hashes[_hash_file(path)].append(path)
        if path.suffix.lower() != ".md":
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            issues.append(Issue("invalid-utf8", relative.as_posix(), "not valid UTF-8"))
            continue
        markdown[path] = text
        frontmatter, error = _frontmatter(text)
        metadata_by_path[path] = frontmatter
        if error:
            issues.append(Issue("frontmatter", relative.as_posix(), error))
        identifier = frontmatter.get("id")
        if isinstance(identifier, str) and identifier:
            id_owners[identifier].append(path)
        visible, unclosed = _visible_markdown(text)
        if unclosed:
            issues.append(
                Issue("unclosed-fence", relative.as_posix(), "unclosed code fence")
            )
        if not path.name.endswith(".template") and POSSIBLE_SECRET_RE.search(text):
            issues.append(
                Issue(
                    "possible-secret",
                    relative.as_posix(),
                    "possible credential or private-key material",
                )
            )

        expected = _expected_type(relative)
        actual = frontmatter.get("type")
        if expected and actual != expected:
            issues.append(
                Issue(
                    "document-type",
                    relative.as_posix(),
                    f"expected type {expected}",
                )
            )
        if actual in TYPED_KINDS:
            required = {"id", "status", "title", "type"}
            if actual == "normalized-note":
                required.update({"module", "section"})
            if actual in {"authorized-test-method", "quick-card"}:
                required.add("source_playbook")
            for key in sorted(required):
                if not frontmatter.get(key):
                    issues.append(
                        Issue(
                            "missing-metadata",
                            relative.as_posix(),
                            f"missing {key}",
                        )
                    )
        if _is_module_playbook(relative) and not frontmatter.get("source_notes"):
            issues.append(
                Issue(
                    "missing-metadata",
                    relative.as_posix(),
                    "module playbook requires source_notes",
                )
            )

        word_count = len(WORD_RE.findall(visible))
        if actual == "quick-card" and word_count > QUICK_CARD_WORD_LIMIT:
            issues.append(
                Issue(
                    "word-limit",
                    relative.as_posix(),
                    f"quick card has {word_count} words; maximum is {QUICK_CARD_WORD_LIMIT}",
                )
            )
        if actual == "normalized-note" and word_count > NORMALIZED_NOTE_WORD_LIMIT:
            issues.append(
                Issue(
                    "word-limit",
                    relative.as_posix(),
                    f"normalized note has {word_count} words; maximum is {NORMALIZED_NOTE_WORD_LIMIT}",
                )
            )

    for digest, paths in hashes.items():
        if len(paths) > 1:
            joined = ", ".join(sorted(_relative(root, path) for path in paths))
            issues.append(Issue("duplicate-content", ".", f"{digest}: {joined}"))

    for identifier, paths in id_owners.items():
        if len(paths) > 1:
            joined = ", ".join(sorted(_relative(root, path) for path in paths))
            issues.append(Issue("duplicate-id", ".", f"{identifier}: {joined}"))

    id_types: dict[str, str] = {}
    for identifier, paths in id_owners.items():
        if len(paths) == 1:
            value = metadata_by_path[paths[0]].get("type")
            if isinstance(value, str):
                id_types[identifier] = value

    for path, frontmatter in metadata_by_path.items():
        relative = _relative(root, path)
        for key in ("source_note", "source_playbook"):
            value = frontmatter.get(key)
            if not isinstance(value, str) or not value:
                continue
            if value not in id_owners:
                issues.append(Issue("unresolved-id", relative, f"{key}: {value}"))
            elif key == "source_playbook" and id_types.get(value) != "operational-playbook":
                issues.append(
                    Issue("invalid-relation", relative, f"{value} is not a playbook")
                )
        source_notes = frontmatter.get("source_notes")
        if isinstance(source_notes, list):
            for value in source_notes:
                if value not in id_owners:
                    issues.append(
                        Issue("unresolved-id", relative, f"source_notes: {value}")
                    )

    adjacency: dict[Path, set[Path]] = defaultdict(set)
    for path, text in markdown.items():
        visible, _ = _visible_markdown(text)
        for match in MARKDOWN_LINK_RE.finditer(visible):
            destination = _resolved_link(root, path, match.group(1))
            if destination is None:
                continue
            try:
                destination.relative_to(root)
            except ValueError:
                issues.append(
                    Issue(
                        "link-escape",
                        _relative(root, path),
                        "local link escapes the knowledge root",
                    )
                )
                continue
            if not destination.exists():
                issues.append(
                    Issue(
                        "broken-link",
                        _relative(root, path),
                        _relative(root, destination),
                    )
                )
                continue
            if destination.suffix.lower() == ".md":
                adjacency[path].add(destination)

    index_root = root / "indexes" / "README.md"
    reachable: set[Path] = set()
    if index_root not in markdown:
        issues.append(
            Issue("missing-root-index", "indexes/README.md", "root index is required")
        )
    else:
        queue = deque([index_root])
        while queue:
            current = queue.popleft()
            if current in reachable:
                continue
            reachable.add(current)
            queue.extend(sorted(adjacency[current] - reachable))

    routable = {
        path
        for path, frontmatter in metadata_by_path.items()
        if _is_routable(Path(_relative(root, path)), frontmatter)
    }
    for path in sorted(routable - reachable):
        issues.append(
            Issue(
                "unreachable-document",
                _relative(root, path),
                "not reachable from indexes/README.md",
            )
        )

    summary = ValidationSummary(
        files=len(regular_files),
        markdown_files=len(markdown),
        identifiers=len(id_owners),
        routable_documents=len(routable),
        reachable_documents=len(routable & reachable),
    )
    return sorted(set(issues)), summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate private reusable knowledge without printing content."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).parents[1] / "private_knowledge",
        help="private knowledge root",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    issues, summary = validate_knowledge_base(args.root)
    state = "PASS" if not issues else "FAIL"
    print(f"private knowledge validation: {state}")
    print(f"files: {summary.files}")
    print(f"markdown files: {summary.markdown_files}")
    print(f"identifiers: {summary.identifiers}")
    print(
        "routable documents: "
        f"{summary.reachable_documents}/{summary.routable_documents} reachable"
    )
    if issues:
        print(f"issues: {len(issues)}")
        for issue in issues:
            print(f"ERROR {issue.code} {issue.path}: {issue.detail}")
        return 1
    print("issues: 0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
