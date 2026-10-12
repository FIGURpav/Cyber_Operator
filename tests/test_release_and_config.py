import json
import zipfile
from pathlib import Path

import pytest

from scripts import release_check, runtime_config


def test_runtime_environment_takes_precedence_over_config(tmp_path, monkeypatch):
    config = tmp_path / "settings.toml"
    configured = tmp_path / "configured"
    explicit = tmp_path / "explicit"
    config.write_text(f'[paths]\nworkspace_root = "{configured.as_posix()}"\n')
    monkeypatch.setenv("CYBER_CONFIG", str(config))
    monkeypatch.delenv("CYBER_WORKSPACE_ROOT", raising=False)
    assert runtime_config.workspace_root() == configured
    monkeypatch.setenv("CYBER_WORKSPACE_ROOT", str(explicit))
    assert runtime_config.workspace_root() == explicit
    monkeypatch.setenv("CYBER_WORKSPACE_ROOT", "relative-path")
    with pytest.raises(ValueError, match="absolute"):
        runtime_config.workspace_root()


def test_release_refuses_private_data_and_personal_paths(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    readme = root / "README.md"
    readme.write_text("Synthetic documentation")
    assert release_check.release_files(root) == [readme]
    readme.write_text("/" + "home/" + "private-user/project")
    with pytest.raises(ValueError, match="personal"):
        release_check.release_files(root)
    readme.write_text("Synthetic documentation")
    private = root / "scripts" / "credentials.jsonl"
    private.parent.mkdir()
    private.write_text("{}")
    with pytest.raises(ValueError, match="private runtime"):
        release_check.release_files(root)


def test_release_archive_is_allowlisted_hashed_and_executable(tmp_path):
    root = tmp_path / "source"
    (root / "scripts").mkdir(parents=True)
    (root / "scripts/cyber-example").write_text("#!/bin/sh\nexit 0\n")
    (root / ".venv").mkdir()
    (root / ".venv/private-cache").write_text("not included")
    archive = root / ".." / "release.zip"
    result = release_check.package(root, archive)
    assert result["files"] == 1
    with zipfile.ZipFile(archive) as handle:
        names = set(handle.namelist())
        assert names == {"Cyber-Operator/scripts/cyber-example", "Cyber-Operator/RELEASE_INVENTORY.json"}
        metadata = json.loads(handle.read("Cyber-Operator/RELEASE_INVENTORY.json"))
        assert metadata[0]["path"] == "scripts/cyber-example"
        assert handle.getinfo("Cyber-Operator/scripts/cyber-example").external_attr >> 16 & 0o777 == 0o755
    with pytest.raises(ValueError, match="refusing overwrite"):
        release_check.package(root, archive)


def test_release_refuses_symlink(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    outside = tmp_path / "private"
    outside.write_text("private data")
    (root / "README.md").symlink_to(outside)
    with pytest.raises(ValueError, match="symlink"):
        release_check.release_files(root)


def test_real_source_release_check():
    files = release_check.release_files(Path(__file__).parents[1])
    assert len(files) > 100
