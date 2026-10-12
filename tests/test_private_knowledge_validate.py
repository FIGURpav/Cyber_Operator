import contextlib
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).parents[1] / "scripts"
MODULE_PATH = SCRIPTS / "private_knowledge_validate.py"
SPEC = importlib.util.spec_from_file_location("private_knowledge_validate", MODULE_PATH)
assert SPEC and SPEC.loader
private_knowledge_validate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = private_knowledge_validate
SPEC.loader.exec_module(private_knowledge_validate)


class PrivateKnowledgeValidateTests(unittest.TestCase):
    def _directory(self, path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(0o700)

    def _file(self, path: Path, text: str) -> None:
        self._directory(path.parent)
        path.write_text(text, encoding="utf-8")
        path.chmod(0o600)

    def _valid_tree(self, root: Path) -> None:
        root.chmod(0o700)
        self._file(
            root / "indexes" / "README.md",
            "# Index\n\n[Card](../quick-cards/operator/card.md)\n"
            "[Method](../methods/module-01/example/README.md)\n",
        )
        self._file(
            root / "quick-cards" / "operator" / "card.md",
            "---\nid: QC-1\ntitle: Card\nsource_playbook: PB-1\n"
            "type: quick-card\nstatus: complete\n---\n\n"
            "# Card\n\n[Playbook](../../playbooks/operator/playbook.md)\n",
        )
        self._file(
            root / "playbooks" / "operator" / "playbook.md",
            "---\nid: PB-1\ntitle: Playbook\ntype: operational-playbook\n"
            "status: complete\n---\n\n# Playbook\n\n"
            "[Note](../../notes/module-01/normalized/note.md)\n",
        )
        self._file(
            root / "notes" / "module-01" / "normalized" / "note.md",
            "---\nid: NOTE-1\ntitle: Note\nmodule: 1\nsection: 1.1\n"
            "type: normalized-note\nstatus: complete\n---\n\n# Note\n",
        )
        self._file(
            root / "methods" / "module-01" / "example" / "README.md",
            "---\nid: METHOD-1\ntitle: Method\nsource_playbook: PB-1\n"
            "type: authorized-test-method\nstatus: complete\n---\n\n"
            "# Method\n",
        )
        for path in root.rglob("*"):
            if path.is_dir():
                path.chmod(0o700)

    def test_valid_synthetic_tree_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._valid_tree(root)
            issues, summary = private_knowledge_validate.validate_knowledge_base(root)
            self.assertEqual(issues, [])
            self.assertEqual(summary.routable_documents, 4)
            self.assertEqual(summary.reachable_documents, 4)

    def test_detects_structural_and_artifact_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._valid_tree(root)
            duplicate = root / "quick-cards" / "operator" / "duplicate.md"
            self._file(
                duplicate,
                "---\nid: QC-1\ntitle: Duplicate\nsource_playbook: PB-MISSING\n"
                "type: quick-card\nstatus: complete\n---\n\n"
                "# Duplicate\n\n[Missing](missing.md)\n\n```text\n",
            )
            duplicate.chmod(0o644)
            artifact = root / "methods" / "module-01" / "payload.exe"
            self._file(artifact, "synthetic")
            os.symlink("card.md", root / "quick-cards" / "operator" / "link.md")

            issues, _ = private_knowledge_validate.validate_knowledge_base(root)
            codes = {issue.code for issue in issues}
            self.assertTrue(
                {
                    "broken-link",
                    "build-output",
                    "duplicate-id",
                    "file-mode",
                    "symlink",
                    "unclosed-fence",
                    "unreachable-document",
                    "unresolved-id",
                }.issubset(codes)
            )

    def test_cli_output_is_metadata_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._valid_tree(root)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = private_knowledge_validate.main(["--root", str(root)])
            self.assertEqual(result, 0)
            rendered = output.getvalue()
            self.assertIn("private knowledge validation: PASS", rendered)
            self.assertIn("issues: 0", rendered)
            self.assertNotIn("# Playbook", rendered)


if __name__ == "__main__":
    unittest.main()
