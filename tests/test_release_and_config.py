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


def test_private_knowledge_default_and_override(tmp_path, monkeypatch):
    monkeypatch.delenv("CYBER_CONFIG", raising=False)
    monkeypatch.delenv("CYBER_KNOWLEDGE_ROOT", raising=False)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    assert runtime_config.knowledge_root() == tmp_path / "cyber-operator/private-knowledge"
    monkeypatch.setenv("CYBER_KNOWLEDGE_ROOT", str(tmp_path / "reviewed-notes"))
    assert runtime_config.knowledge_root() == tmp_path / "reviewed-notes"


def test_truthful_model_default_and_source_alias():
    from scripts import log_query, source_intake

    assert log_query.parse_args(["--workspace", "/tmp/synthetic", "--purpose", "review"]).model == "unknown"
    new = source_intake.parser().parse_args(["add", "--assessment", "review", "--path", "notes"])
    old = source_intake.parser().parse_args(["add", "--lab", "review", "--path", "notes"])
    assert vars(new) == vars(old)


@pytest.mark.parametrize("encoded", [False, True])
def test_release_refuses_private_editor_paths(tmp_path, encoded):
    root = tmp_path / "source"
    root.mkdir()
    path = "\\\\wsl.localhost\\Example-Distro\\" + "home\\" + "private-user\\workspaces"
    content = json.dumps({"folders": [{"path": path}]}) if encoded else path
    (root / "Cyber-Operator.code-workspace").write_text(content)
    with pytest.raises(ValueError, match="personal"):
        release_check.release_files(root)


def test_release_refuses_non_english_documentation(tmp_path):
    readme = tmp_path / "README.md"
    readme.write_text("\u017bak", encoding="utf-8")
    with pytest.raises(ValueError, match="English"):
        release_check.release_files(tmp_path)


def test_release_refuses_cookie_data_under_allowed_filename(tmp_path):
    (tmp_path / "README.md").write_text("# Netscape HTTP Cookie File\n")
    with pytest.raises(ValueError, match="cookie"):
        release_check.release_files(tmp_path)


def test_release_includes_gitlab_pipeline(tmp_path):
    pipeline = tmp_path / ".gitlab-ci.yml"
    pipeline.write_text("stages: [validate]\n")
    assert release_check.release_files(tmp_path) == [pipeline]


def test_release_pdf_requires_reviewed_path_and_bytes(tmp_path):
    import shutil

    source = Path(__file__).parents[1]
    relative = next(iter(release_check.REVIEWED_PDFS))
    pdf = tmp_path / relative
    pdf.parent.mkdir(parents=True)
    shutil.copyfile(source / relative, pdf)
    assert release_check.release_files(tmp_path) == [pdf]
    pdf.write_bytes(pdf.read_bytes() + b'changed')
    with pytest.raises(ValueError, match='checksum mismatch'):
        release_check.release_files(tmp_path)
    pdf.unlink()
    (pdf.parent / 'unreviewed.pdf').write_bytes(b'%PDF-1.4')
    with pytest.raises(ValueError, match='unreviewed file type'):
        release_check.release_files(tmp_path)