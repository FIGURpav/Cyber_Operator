import json
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import source_intake


class SourceIntakeTests(unittest.TestCase):
    def make_task_workspace(self, root: Path) -> Path:
        task = root / "task"
        task.mkdir(mode=0o700)
        (task / "inbox").mkdir(mode=0o700)
        (task / "TASK_CONTEXT.md").write_text(
            "- Current task: synthetic\n", encoding="utf-8"
        )
        return task

    def test_file_plan_defaults_to_basename(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "input" / "scan.txt"
            source.parent.mkdir()
            source.write_text("result\n", encoding="utf-8")
            plan = source_intake.build_plan(
                lab="8.1.3", source_value=str(source), dest_value=None,
                rw_root=root / "rw", ro_root=root / "ro",
            )
            self.assertEqual(plan.destination, root / "rw" / "8.1.3" / "scan.txt")
            self.assertEqual(plan.size, 7)

    def test_directory_hash_is_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "sample"
            source.mkdir()
            (source / "b.txt").write_text("B", encoding="utf-8")
            (source / "a.txt").write_text("A", encoding="utf-8")
            items = source_intake.inspect_source(source)
            self.assertEqual(
                source_intake.tree_digest(source, items),
                source_intake.tree_digest(source, tuple(reversed(items))),
            )

    def test_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target"
            target.write_text("x", encoding="utf-8")
            link = root / "link"
            link.symlink_to(target)
            with self.assertRaises(source_intake.IntakeError):
                source_intake.inspect_source(link)

    def test_rejects_source_inside_rw_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rw = root / "rw"
            source = rw / "8.1.3" / "already.txt"
            source.parent.mkdir(parents=True)
            source.write_text("x", encoding="utf-8")
            with self.assertRaises(source_intake.IntakeError):
                source_intake.build_plan(
                    lab="8.1.3", source_value=str(source), dest_value=None,
                    rw_root=rw, ro_root=root / "ro",
                )

    def test_rejects_existing_destination(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "incoming" / "scan.txt"
            source.parent.mkdir()
            source.write_text("new", encoding="utf-8")
            destination = root / "rw" / "8.1.3" / "scan.txt"
            destination.parent.mkdir(parents=True)
            destination.write_text("old", encoding="utf-8")
            with self.assertRaises(source_intake.IntakeError):
                source_intake.build_plan(
                    lab="8.1.3", source_value=str(source), dest_value=None,
                    rw_root=root / "rw", ro_root=root / "ro",
                )

    def test_detects_private_key_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "key.txt"
            source.write_bytes(b"-----BEGIN PRIVATE KEY-----\n")
            items = source_intake.inspect_source(source)
            self.assertTrue(source_intake.sensitive_hits(items))

    def test_rejects_symlink_destination_ancestor(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outside = root / "outside"
            outside.mkdir()
            rw = root / "rw"
            rw.mkdir()
            (rw / "8.1.3").symlink_to(outside, target_is_directory=True)
            source = root / "scan.txt"
            source.write_text("x", encoding="utf-8")
            with self.assertRaises(source_intake.IntakeError):
                source_intake.build_plan(
                    lab="8.1.3", source_value=str(source), dest_value=None,
                    rw_root=rw, ro_root=root / "ro",
                )

    def test_apply_copies_verifies_and_writes_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rw = root / "rw"
            rw.mkdir()
            ro = root / "ro"
            ro.symlink_to(rw, target_is_directory=True)
            task = root / "task"
            source = root / "incoming" / "result.txt"
            source.parent.mkdir()
            source.write_text("verified\n", encoding="utf-8")
            plan = source_intake.build_plan(
                lab="8.1.3", source_value=str(source), dest_value="evidence/result-copy.txt",
                rw_root=rw, ro_root=ro,
            )
            with mock.patch.object(source_intake, "check_ro_mount"):
                source_intake.apply_plan(plan, task_root=task, ro_root=ro.resolve())
            self.assertEqual(
                (rw / "8.1.3" / "evidence" / "result-copy.txt").read_text(encoding="utf-8"),
                "verified\n",
            )
            records = (task / "intake" / "source_manifest.jsonl").read_text(encoding="utf-8")
            self.assertIn('"action": "source_add"', records)

    def test_task_bootstrap_plan_uses_private_inbox_destination(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ro = root / "ro"
            source = ro / "8.1.2_PickleEx"
            source.mkdir(parents=True)
            (source / "hosts").write_text("192.0.2.10\n", encoding="utf-8")
            task = self.make_task_workspace(root)

            plan = source_intake.build_task_bootstrap_plan(
                source_task_value="8.1.2_PickleEx",
                ro_root=ro,
                task_root=task,
            )

            self.assertEqual(
                plan.destination,
                task / "inbox" / "source" / "8.1.2_PickleEx",
            )
            self.assertFalse(plan.existing_match)

    def test_task_bootstrap_copies_privately_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ro = root / "ro"
            source = ro / "lab"
            (source / "nmap").mkdir(parents=True)
            (source / "hosts").write_text("192.0.2.10\n", encoding="utf-8")
            (source / "nmap" / "initial").write_text("scan\n", encoding="utf-8")
            task = self.make_task_workspace(root)

            plan = source_intake.build_task_bootstrap_plan(
                source_task_value="lab", ro_root=ro, task_root=task
            )
            self.assertEqual(source_intake.apply_task_bootstrap(plan), "copied")

            destination = task / "inbox" / "source" / "lab"
            self.assertEqual(
                (destination / "nmap" / "initial").read_text(encoding="utf-8"),
                "scan\n",
            )
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o700)
            self.assertEqual(
                stat.S_IMODE((destination / "hosts").stat().st_mode), 0o600
            )
            manifest = task / "intake" / "source_manifest.jsonl"
            records = [json.loads(line) for line in manifest.read_text().splitlines()]
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["source_task"], "lab")

            repeated = source_intake.build_task_bootstrap_plan(
                source_task_value="lab", ro_root=ro, task_root=task
            )
            self.assertTrue(repeated.existing_match)
            self.assertEqual(source_intake.apply_task_bootstrap(repeated), "existing")
            self.assertEqual(len(manifest.read_text().splitlines()), 1)

    def test_existing_match_revalidates_source_and_destination_at_apply(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ro = root / "ro"
            source = ro / "lab"
            source.mkdir(parents=True)
            source_file = source / "course.txt"
            source_file.write_text("provided\n", encoding="utf-8")
            task = self.make_task_workspace(root)

            initial = source_intake.build_task_bootstrap_plan(
                source_task_value="lab",
                ro_root=ro,
                task_root=task,
            )
            self.assertEqual(source_intake.apply_task_bootstrap(initial), "copied")
            repeated = source_intake.build_task_bootstrap_plan(
                source_task_value="lab",
                ro_root=ro,
                task_root=task,
            )
            self.assertTrue(repeated.existing_match)

            source_file.write_text("changed\n", encoding="utf-8")
            with self.assertRaisesRegex(
                source_intake.IntakeError,
                "task source changed after preview",
            ):
                source_intake.apply_task_bootstrap(repeated)

            source_file.write_text("provided\n", encoding="utf-8")
            (repeated.destination / "course.txt").write_text(
                "changed\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                source_intake.IntakeError,
                "task source destination changed after preview",
            ):
                source_intake.apply_task_bootstrap(repeated)

    def test_task_bootstrap_rejects_changed_existing_destination(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ro = root / "ro"
            source = ro / "lab"
            source.mkdir(parents=True)
            (source / "hosts").write_text("192.0.2.10\n", encoding="utf-8")
            task = self.make_task_workspace(root)
            destination = task / "inbox" / "source" / "lab"
            destination.mkdir(parents=True)
            (destination / "hosts").write_text("different\n", encoding="utf-8")

            with self.assertRaises(source_intake.IntakeError):
                source_intake.build_task_bootstrap_plan(
                    source_task_value="lab", ro_root=ro, task_root=task
                )

    def test_task_bootstrap_blocks_possible_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ro = root / "ro"
            source = ro / "lab"
            source.mkdir(parents=True)
            (source / "notes.txt").write_text(
                "password: synthetic-only\n", encoding="utf-8"
            )
            task = self.make_task_workspace(root)
            plan = source_intake.build_task_bootstrap_plan(
                source_task_value="lab", ro_root=ro, task_root=task
            )

            self.assertTrue(plan.sensitive_hits)
            with self.assertRaises(source_intake.IntakeError):
                source_intake.apply_task_bootstrap(plan)

    def test_no_download_requires_and_records_source_origin_attestation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ro = root / "ro"
            source = ro / "lab"
            source.mkdir(parents=True)
            (source / "course.txt").write_text("provided\n", encoding="utf-8")
            task = self.make_task_workspace(root)
            (task / "TASK_CONTEXT.md").write_text(
                "- Current task: synthetic\n"
                "- Artifact handling: no-download\n",
                encoding="utf-8",
            )

            plan = source_intake.build_task_bootstrap_plan(
                source_task_value="lab",
                ro_root=ro,
                task_root=task,
            )
            self.assertEqual(plan.artifact_handling, "no-download")
            with self.assertRaisesRegex(
                source_intake.IntakeError,
                "--attest-preexisting-nontarget-source",
            ):
                source_intake.apply_task_bootstrap(plan)
            self.assertFalse(plan.destination.exists())

            self.assertEqual(
                source_intake.apply_task_bootstrap(
                    plan,
                    attest_preexisting_nontarget_source=True,
                ),
                "copied",
            )
            records = [
                json.loads(line)
                for line in (
                    task / "intake" / "source_manifest.jsonl"
                ).read_text(encoding="utf-8").splitlines()
            ]
            self.assertIs(records[-1]["source_origin_attested"], True)

    def test_task_bootstrap_rejects_malformed_artifact_handling(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ro = root / "ro"
            source = ro / "lab"
            source.mkdir(parents=True)
            (source / "course.txt").write_text("provided\n", encoding="utf-8")
            task = self.make_task_workspace(root)
            (task / "TASK_CONTEXT.md").write_text(
                "- Artifact handling : no-download\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                source_intake.IntakeError,
                "malformed artifact handling",
            ):
                source_intake.build_task_bootstrap_plan(
                    source_task_value="lab",
                    ro_root=ro,
                    task_root=task,
                )

    def test_task_bootstrap_rejects_artifact_mode_change_after_preview(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ro = root / "ro"
            source = ro / "lab"
            source.mkdir(parents=True)
            (source / "course.txt").write_text("provided\n", encoding="utf-8")
            task = self.make_task_workspace(root)

            plan = source_intake.build_task_bootstrap_plan(
                source_task_value="lab",
                ro_root=ro,
                task_root=task,
            )
            (task / "TASK_CONTEXT.md").write_text(
                "- Current task: synthetic\n"
                "- Artifact handling: no-download\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                source_intake.IntakeError,
                "artifact handling changed after preview",
            ):
                source_intake.apply_task_bootstrap(plan)
            self.assertFalse(plan.destination.exists())

    def test_task_bootstrap_requires_direct_child_selector(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ro = root / "ro"
            (ro / "module" / "lab").mkdir(parents=True)
            task = self.make_task_workspace(root)
            with self.assertRaises(source_intake.IntakeError):
                source_intake.build_task_bootstrap_plan(
                    source_task_value="module/lab", ro_root=ro, task_root=task
                )

    def test_task_bootstrap_resolves_collection_active_module(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ro = root / "ro"
            source = ro / "lab"
            source.mkdir(parents=True)
            (source / "hosts").write_text("192.0.2.10\n", encoding="utf-8")
            collection = root / "collection"
            collection.mkdir()
            task = self.make_task_workspace(collection)
            task.rename(collection / "lab")
            (collection / "ACTIVE_TASK").write_text("lab\n", encoding="utf-8")

            plan = source_intake.build_task_bootstrap_plan(
                source_task_value="lab", ro_root=ro, task_root=collection
            )
            self.assertEqual(plan.task_root, collection / "lab")


if __name__ == "__main__":
    unittest.main()
