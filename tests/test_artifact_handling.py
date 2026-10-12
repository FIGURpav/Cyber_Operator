import tempfile
import unittest
from pathlib import Path

from scripts import artifact_handling


class ArtifactHandlingTests(unittest.TestCase):
    def test_legacy_context_defaults_to_standard(self):
        self.assertEqual(
            artifact_handling.parse_mode_text("- Current task: legacy\n"),
            artifact_handling.STANDARD,
        )

    def test_supported_modes_round_trip(self):
        for mode in artifact_handling.MODES:
            with self.subTest(mode=mode):
                rendered = artifact_handling.render_mode_text(
                    "- Current task: synthetic\n",
                    mode,
                )
                self.assertEqual(artifact_handling.parse_mode_text(rendered), mode)

    def test_render_replaces_only_the_canonical_line(self):
        before = (
            "- Current task: synthetic\n"
            "- Artifact handling: standard\n"
            "- Operational profile: strict\n"
        )
        after = artifact_handling.render_mode_text(
            before,
            artifact_handling.NO_DOWNLOAD,
        )
        self.assertEqual(
            after,
            before.replace(
                "- Artifact handling: standard",
                "- Artifact handling: no-download",
            ),
        )

    def test_unknown_duplicate_and_malformed_entries_are_rejected(self):
        for text in (
            "- Artifact handling: unknown\n",
            "- Artifact handling:\n",
            "- Artifact handling:  standard\n",
            "- Artifact handling : no-download\n",
            "  - Artifact handling: no-download\n",
            "- artifact handling: no-download\n",
            "- artifact_handling: no-download\n",
            (
                "- Artifact handling: standard\n"
                "- Artifact handling: no-download\n"
            ),
        ):
            with self.subTest(text=text), self.assertRaises(
                artifact_handling.ArtifactHandlingError
            ):
                artifact_handling.parse_mode_text(text)

    def test_existing_legacy_context_without_field_is_standard(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "TASK_CONTEXT.md").write_text(
                "- Current task: legacy\n",
                encoding="utf-8",
            )
            self.assertEqual(
                artifact_handling.workspace_mode(Path(tmp)),
                artifact_handling.STANDARD,
            )

    def test_workspace_without_context_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp, self.assertRaisesRegex(
            artifact_handling.ArtifactHandlingError,
            "TASK_CONTEXT.md is missing",
        ):
            artifact_handling.workspace_mode(Path(tmp))

    def test_local_processing_requires_private_regular_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "TASK_CONTEXT.md").write_text(
                "- Artifact handling: no-download\n",
                encoding="utf-8",
            )
            private = workspace / "private"
            private.mkdir(mode=0o700)
            local_processing = private / "local_processing"
            local_processing.mkdir(mode=0o700)
            database = local_processing / "analysis.db"
            database.write_bytes(b"synthetic")
            database.chmod(0o644)

            with self.assertRaisesRegex(
                artifact_handling.ArtifactHandlingError,
                "files must be current-user-owned real files with mode 0600",
            ):
                artifact_handling.workspace_mode(workspace)
            database.chmod(0o600)
            self.assertEqual(
                artifact_handling.workspace_mode(workspace),
                artifact_handling.NO_DOWNLOAD,
            )

            database.unlink()
            (local_processing / "unsafe-link").symlink_to(workspace / "TASK_CONTEXT.md")
            with self.assertRaisesRegex(
                artifact_handling.ArtifactHandlingError,
                "files must be current-user-owned real files with mode 0600",
            ):
                artifact_handling.workspace_mode(workspace)

    def test_no_download_matrix_exposes_critical_boundaries(self):
        matrix = dict(artifact_handling.policy_matrix(artifact_handling.NO_DOWNLOAD))
        self.assertEqual(matrix["local target-origin files"], "OFF")
        self.assertEqual(matrix["temporary or encoded target-file copies"], "OFF")
        self.assertEqual(matrix["remote storage"], "independent switch; no automatic transfer")
        self.assertEqual(matrix["automatic fallback"], "OFF")
        self.assertEqual(matrix["authorization, scope and impact rules"], "UNCHANGED")

    def test_workspace_rejects_unsafe_context_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            target = workspace / "target"
            target.write_text(
                "- Artifact handling: no-download\n",
                encoding="utf-8",
            )
            (workspace / "TASK_CONTEXT.md").symlink_to(target)
            with self.assertRaises(artifact_handling.ArtifactHandlingError):
                artifact_handling.workspace_mode(workspace)


if __name__ == "__main__":
    unittest.main()
