import contextlib
import io
import stat
import tempfile
import unittest
from pathlib import Path

from scripts import task_collection, workspace_lifecycle

SCRIPTS = Path(__file__).parents[1] / "scripts"


class TaskCollectionTests(unittest.TestCase):
    def test_close_cli_is_preview_first_hash_gated_and_explicitly_reopenable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan = task_collection.build_module_plan(
                root,
                "close-test",
                "strict",
                "chat",
                "standard",
            )
            task_collection.apply_module_plan(plan, SCRIPTS)
            workspace = root / "close-test"
            lifecycle = workspace / workspace_lifecycle.LEDGER
            before = lifecycle.read_bytes()

            preview_output = io.StringIO()
            with contextlib.redirect_stdout(preview_output):
                self.assertEqual(
                    task_collection.main(
                        [
                            "--root",
                            str(root),
                            "close",
                            "--module",
                            "close-test",
                            "--reason",
                            "Operator requested synthetic close",
                        ]
                    ),
                    0,
                )
            self.assertEqual(lifecycle.read_bytes(), before)
            digest = next(
                line.split(": ", 1)[1]
                for line in preview_output.getvalue().splitlines()
                if line.startswith("close_plan_sha256:")
            )

            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(
                    task_collection.main(
                        [
                            "--root",
                            str(root),
                            "close",
                            "--module",
                            "close-test",
                            "--reason",
                            "Operator requested synthetic close",
                            "--close-plan-sha256",
                            digest,
                            "--ack-operator-requested-close",
                            "--apply",
                        ]
                    ),
                    0,
                )
            self.assertTrue(workspace_lifecycle.is_closed(workspace))

            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(
                    task_collection.main(
                        [
                            "--root",
                            str(root),
                            "reopen",
                            "--module",
                            "close-test",
                            "--reason",
                            "Operator resumed synthetic work",
                            "--ack-operator-requested-reopen",
                            "--apply",
                        ]
                    ),
                    0,
                )
            self.assertFalse(workspace_lifecycle.is_closed(workspace))

    def test_init_select_resolve_and_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan = task_collection.build_module_plan(root, "8.1.2_PickleEx")
            self.assertFalse(plan.exists)
            self.assertEqual(
                task_collection.apply_module_plan(plan, SCRIPTS), "created"
            )
            repeated = task_collection.build_module_plan(root, "8.1.2_PickleEx")
            self.assertTrue(repeated.exists)
            self.assertEqual(
                task_collection.apply_module_plan(repeated, SCRIPTS), "existing"
            )
            task_collection.write_active_module(root, "8.1.2_PickleEx")
            self.assertEqual(
                task_collection.read_active_module(root), "8.1.2_PickleEx"
            )
            self.assertEqual(
                task_collection.list_modules(root), ["8.1.2_PickleEx"]
            )

    def test_context_identifies_module_and_source(self):
        context = task_collection.render_task_context("8.1.2")
        self.assertIn("Current task: 8.1.2", context)
        self.assertIn("Active source task: 8.1.2", context)
        self.assertIn("Operational profile: strict", context)
        self.assertIn("Intake mode: source", context)
        self.assertIn("Artifact handling: standard", context)

    def test_chat_intake_context_is_explicitly_source_free(self):
        context = task_collection.render_task_context(
            "11",
            "controlled-engagement",
            "chat",
        )
        self.assertIn("Current task: 11", context)
        self.assertIn("Active source task: none", context)
        self.assertIn("Operational profile: controlled-engagement", context)
        self.assertIn("Intake mode: chat", context)
        self.assertIn("Artifact handling: standard", context)
        self.assertIn("Source mount: not required for chat intake", context)

    def test_context_can_enable_no_download_during_setup(self):
        context = task_collection.render_task_context(
            "engagement",
            "controlled-engagement",
            "chat",
            "no-download",
        )
        self.assertIn("Artifact handling: no-download", context)

    def test_init_cli_requires_explicit_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SystemExit) as raised:
                task_collection.main(
                    [
                        "--root",
                        tmp,
                        "init",
                        "--module",
                        "missing-profile",
                        "--artifact-handling",
                        "standard",
                    ]
                )
            self.assertEqual(raised.exception.code, 2)

    def test_init_cli_requires_explicit_artifact_handling(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SystemExit) as raised:
                task_collection.main(
                    [
                        "--root",
                        tmp,
                        "init",
                        "--module",
                        "missing-artifact-mode",
                        "--profile",
                        "strict",
                    ]
                )
            self.assertEqual(raised.exception.code, 2)

    def test_controlled_engagement_init_and_atomic_profile_switch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan = task_collection.build_module_plan(root, "engagement", "controlled-engagement")
            self.assertEqual(
                task_collection.apply_module_plan(plan, SCRIPTS), "created"
            )
            context_path = root / "engagement" / "TASK_CONTEXT.md"
            original = context_path.read_text(encoding="utf-8")
            self.assertEqual(task_collection.read_module_profile(root, "engagement"), "controlled-engagement")

            self.assertEqual(task_collection.read_module_intake_mode(root, "engagement"), "source")
            self.assertEqual(
                task_collection.read_module_artifact_handling(root, "engagement"),
                "standard",
            )

            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(
                    task_collection.main(
                        [
                            "--root",
                            str(root),
                            "profile",
                            "--module",
                            "engagement",
                            "--set",
                            "strict",
                        ]
                    ),
                    0,
                )
            self.assertEqual(context_path.read_text(encoding="utf-8"), original)

            task_collection.write_module_profile(root, "engagement", "strict")
            updated = context_path.read_text(encoding="utf-8")
            self.assertEqual(task_collection.read_module_profile(root, "engagement"), "strict")
            self.assertEqual(
                updated,
                original.replace(
                    "- Operational profile: controlled-engagement",
                    "- Operational profile: strict",
                ),
            )

    def test_legacy_context_defaults_to_strict_and_can_be_upreviewed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan = task_collection.build_module_plan(root, "legacy")
            task_collection.apply_module_plan(plan, SCRIPTS)
            context_path = root / "legacy" / "TASK_CONTEXT.md"
            legacy = context_path.read_text(encoding="utf-8").replace(
                "- Operational profile: strict\n", ""
            )
            context_path.write_text(legacy, encoding="utf-8")
            self.assertEqual(task_collection.read_module_profile(root, "legacy"), "strict")
            task_collection.write_module_profile(root, "legacy", "controlled-engagement")
            self.assertTrue(
                context_path.read_text(encoding="utf-8").endswith(
                    "- Operational profile: controlled-engagement\n"
                )
            )

    def test_legacy_artifact_mode_defaults_to_standard_and_can_be_upreviewed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan = task_collection.build_module_plan(root, "legacy-artifacts")
            task_collection.apply_module_plan(plan, SCRIPTS)
            context_path = root / "legacy-artifacts" / "TASK_CONTEXT.md"
            legacy = context_path.read_text(encoding="utf-8").replace(
                "- Artifact handling: standard\n", ""
            )
            context_path.write_text(legacy, encoding="utf-8")
            self.assertEqual(
                task_collection.read_module_artifact_handling(
                    root, "legacy-artifacts"
                ),
                "standard",
            )
            task_collection.write_module_artifact_handling(
                root,
                "legacy-artifacts",
                "no-download",
            )
            self.assertTrue(
                context_path.read_text(encoding="utf-8").endswith(
                    "- Artifact handling: no-download\n"
                )
            )

    def test_unknown_and_duplicate_profiles_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan = task_collection.build_module_plan(root, "broken")
            task_collection.apply_module_plan(plan, SCRIPTS)
            context_path = root / "broken" / "TASK_CONTEXT.md"
            original = context_path.read_text(encoding="utf-8")
            for invalid in (
                original.replace("strict", "unknown", 1),
                original + "- Operational profile: controlled-engagement\n",
            ):
                with self.subTest(invalid=invalid):
                    context_path.write_text(invalid, encoding="utf-8")
                    with self.assertRaises(task_collection.CollectionError):
                        task_collection.read_module_profile(root, "broken")
            context_path.write_text(original, encoding="utf-8")

    def test_unknown_duplicate_and_malformed_artifact_modes_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan = task_collection.build_module_plan(root, "broken-artifacts")
            task_collection.apply_module_plan(plan, SCRIPTS)
            context_path = root / "broken-artifacts" / "TASK_CONTEXT.md"
            original = context_path.read_text(encoding="utf-8")
            for invalid in (
                original.replace(
                    "Artifact handling: standard",
                    "Artifact handling: unknown",
                ),
                original + "- Artifact handling: no-download\n",
                original.replace(
                    "Artifact handling: standard",
                    "Artifact handling:",
                ),
            ):
                with self.subTest(invalid=invalid):
                    context_path.write_text(invalid, encoding="utf-8")
                    with self.assertRaises(task_collection.CollectionError):
                        task_collection.read_module_artifact_handling(
                            root,
                            "broken-artifacts",
                        )
            context_path.write_text(original, encoding="utf-8")

    def test_artifact_handling_cli_preview_apply_and_risk_ack(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan = task_collection.build_module_plan(root, "switch")
            task_collection.apply_module_plan(plan, SCRIPTS)
            context_path = root / "switch" / "TASK_CONTEXT.md"
            original = context_path.read_bytes()

            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(
                    task_collection.main(
                        [
                            "--root",
                            str(root),
                            "artifact-handling",
                            "--module",
                            "switch",
                            "--set",
                            "no-download",
                        ]
                    ),
                    0,
                )
            self.assertEqual(context_path.read_bytes(), original)

            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(
                    task_collection.main(
                        [
                            "--root",
                            str(root),
                            "artifact-handling",
                            "--module",
                            "switch",
                            "--set",
                            "no-download",
                            "--apply",
                        ]
                    ),
                    0,
                )
            self.assertEqual(
                task_collection.read_module_artifact_handling(root, "switch"),
                "no-download",
            )
            local_processing = root / "switch" / "private" / "local_processing"
            self.assertTrue(local_processing.is_dir())
            self.assertEqual(stat.S_IMODE(local_processing.stat().st_mode), 0o700)

            stderr = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
                stderr
            ):
                self.assertEqual(
                    task_collection.main(
                        [
                            "--root",
                            str(root),
                            "artifact-handling",
                            "--module",
                            "switch",
                            "--set",
                            "standard",
                            "--apply",
                        ]
                    ),
                    1,
                )
            self.assertIn("--ack-local-full-file-risk", stderr.getvalue())
            self.assertEqual(
                task_collection.read_module_artifact_handling(root, "switch"),
                "no-download",
            )

            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(
                    task_collection.main(
                        [
                            "--root",
                            str(root),
                            "artifact-handling",
                            "--module",
                            "switch",
                            "--set",
                            "standard",
                            "--ack-local-full-file-risk",
                            "--apply",
                        ]
                    ),
                    0,
                )
            self.assertEqual(
                task_collection.read_module_artifact_handling(root, "switch"),
                "standard",
            )

    def test_canonical_writer_enforces_risk_ack_and_allows_no_op(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan = task_collection.build_module_plan(
                root,
                "writer-boundary",
                artifact_handling_mode="no-download",
            )
            task_collection.apply_module_plan(plan, SCRIPTS)
            context = root / "writer-boundary" / "TASK_CONTEXT.md"

            with self.assertRaisesRegex(
                task_collection.CollectionError,
                "--ack-local-full-file-risk",
            ):
                task_collection.write_module_artifact_handling(
                    root,
                    "writer-boundary",
                    "standard",
                )
            self.assertIn(
                "Artifact handling: no-download",
                context.read_text(encoding="utf-8"),
            )

            task_collection.write_module_artifact_handling(
                root,
                "writer-boundary",
                "standard",
                acknowledge_local_full_file_risk=True,
            )
            before = context.read_bytes()
            self.assertEqual(
                task_collection.write_module_artifact_handling(
                    root,
                    "writer-boundary",
                    "standard",
                ),
                ("standard", "standard"),
            )
            self.assertEqual(context.read_bytes(), before)

    def test_init_cli_persists_selected_artifact_handling_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(
                    task_collection.main(
                        [
                            "--root",
                            tmp,
                            "init",
                            "--module",
                            "engagement",
                            "--profile",
                            "controlled-engagement",
                            "--artifact-handling",
                            "no-download",
                            "--apply",
                        ]
                    ),
                    0,
                )
            self.assertEqual(
                task_collection.read_module_artifact_handling(Path(tmp), "engagement"),
                "no-download",
            )
            local_processing = Path(tmp) / "engagement" / "private" / "local_processing"
            self.assertTrue(local_processing.is_dir())
            self.assertEqual(stat.S_IMODE(local_processing.stat().st_mode), 0o700)

    def test_existing_init_never_changes_artifact_handling(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            initial = task_collection.build_module_plan(root, "existing")
            task_collection.apply_module_plan(initial, SCRIPTS)
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(
                stderr
            ):
                self.assertEqual(
                    task_collection.main(
                        [
                            "--root",
                            str(root),
                            "init",
                            "--module",
                            "existing",
                            "--profile",
                            "controlled-engagement",
                            "--artifact-handling",
                            "no-download",
                            "--apply",
                        ]
                    ),
                    1,
                )
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("module already exists", stderr.getvalue())
            self.assertIn("strict/source/standard", stderr.getvalue())
            self.assertEqual(
                task_collection.read_module_artifact_handling(root, "existing"),
                "standard",
            )

    def test_profile_and_artifact_switches_preserve_each_other(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan = task_collection.build_module_plan(
                root,
                "orthogonal",
                "strict",
                "source",
                "no-download",
            )
            task_collection.apply_module_plan(plan, SCRIPTS)
            task_collection.write_module_profile(root, "orthogonal", "controlled-engagement")
            self.assertEqual(
                task_collection.read_module_artifact_handling(root, "orthogonal"),
                "no-download",
            )
            task_collection.write_module_artifact_handling(
                root,
                "orthogonal",
                "standard",
                acknowledge_local_full_file_risk=True,
            )
            self.assertEqual(
                task_collection.read_module_profile(root, "orthogonal"),
                "controlled-engagement",
            )

    def test_chat_intake_module_is_created_and_validated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan = task_collection.build_module_plan(
                root,
                "11",
                "controlled-engagement",
                "chat",
            )
            self.assertEqual(plan.intake_mode, "chat")
            self.assertEqual(task_collection.apply_module_plan(plan, SCRIPTS), "created")
            self.assertEqual(task_collection.read_module_intake_mode(root, "11"), "chat")

    def test_chat_intake_rejects_named_active_source(self):
        context = task_collection.render_task_context("11", "controlled-engagement", "chat")
        malformed = context.replace("Active source task: none", "Active source task: 11")
        with self.assertRaises(task_collection.CollectionError):
            task_collection.parse_intake_mode_text(malformed)

    def test_source_intake_rejects_none_active_source(self):
        context = task_collection.render_task_context("11", "strict", "source")
        malformed = context.replace("Active source task: 11", "Active source task: none")
        with self.assertRaises(task_collection.CollectionError):
            task_collection.parse_intake_mode_text(malformed)

    def test_unknown_and_duplicate_intake_modes_are_rejected(self):
        context = task_collection.render_task_context("11")
        for malformed in (
            context.replace("Intake mode: source", "Intake mode: unknown"),
            context + "- Intake mode: chat\n",
        ):
            with self.subTest(malformed=malformed), self.assertRaises(
                task_collection.CollectionError
            ):
                task_collection.parse_intake_mode_text(malformed)

    def test_rejects_legacy_canonical_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "hosts").mkdir()
            with self.assertRaises(task_collection.CollectionError):
                task_collection.validate_collection_root(root)

    def test_rejects_reserved_and_nested_module_names(self):
        for value in (
            "_archive",
            "ACTIVE_TASK",
            "private",
            "hosts",
            "module/task",
            "../task",
        ):
            with self.subTest(value=value), self.assertRaises(
                task_collection.CollectionError
            ):
                task_collection.validate_module_name(value)

    def test_active_marker_must_reference_existing_module(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "ACTIVE_TASK").write_text("missing\n", encoding="utf-8")
            with self.assertRaises(task_collection.CollectionError):
                task_collection.read_active_module(root)


if __name__ == "__main__":
    unittest.main()
