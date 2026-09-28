import os
import subprocess
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

from scripts import git_operations as go


ROOT = Path(__file__).resolve().parent


class GitOperationsSecurityTest(unittest.TestCase):
    def setUp(self):
        self.go = go
        self.go.SECURITY_RULES = self.go.load_security_rules_from_config(
            str(ROOT / "note_security_scan_config.json")
        )
        self.go.SECURITY_ALLOWLIST = self.go.load_allowlist_from_config(
            str(ROOT / "note_security_scan_config.json")
        )

    def run_git(self, repo, *args):
        return subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            check=True,
        )

    def init_repo(self):
        temp_dir = tempfile.TemporaryDirectory()
        repo = Path(temp_dir.name)
        self.run_git(repo, "init", "-q")
        self.run_git(repo, "config", "user.email", "demo@example.invalid")
        self.run_git(repo, "config", "user.name", "demo")
        return temp_dir, repo

    def test_outgoing_blob_scan_finds_secret_removed_from_current_tree(self):
        temp_dir, repo = self.init_repo()
        self.addCleanup(temp_dir.cleanup)

        note = repo / "note.md"
        note.write_text("base content\n", encoding="utf-8")
        self.run_git(repo, "add", "note.md")
        self.run_git(repo, "commit", "-qm", "base")
        base_commit = self.run_git(repo, "rev-parse", "HEAD").stdout.strip()

        note.write_text("password = leaked-secret\n", encoding="utf-8")
        self.run_git(repo, "commit", "-qam", "leak")

        note.write_text("clean content\n", encoding="utf-8")
        self.run_git(repo, "commit", "-qam", "clean")

        log_temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(log_temp_dir.cleanup)
        with (
            mock.patch.object(self.go, "run_optional_gitleaks", return_value=[]),
            mock.patch.object(
                self.go,
                "scan_log_directory",
                return_value=log_temp_dir.name,
                create=True,
            ),
        ):
            cwd = os.getcwd()
            os.chdir(repo)
            try:
                ok = self.go.run_security_scan_for_git_objects(
                    "history", [f"{base_commit}..HEAD"]
                )
            finally:
                os.chdir(cwd)

        self.assertFalse(ok)

    def test_git_command_failure_is_scan_error(self):
        with mock.patch.object(
            self.go, "run_git", side_effect=self.go.SecurityScanError("fatal: bad ref")
        ):
            with self.assertRaises(self.go.SecurityScanError):
                self.go.collect_full_scan_files()

    def test_unreadable_candidate_file_blocks_scan(self):
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        path = Path(temp_dir.name) / "large.md"
        path.write_text("x" * (self.go.MAX_TEXT_FILE_BYTES + 1), encoding="utf-8")

        with self.assertRaises(self.go.SecurityScanError):
            self.go.scan_file(str(path))

    def test_ds_store_is_not_a_text_candidate(self):
        self.assertFalse(self.go.is_text_candidate(".DS_Store"))
        self.assertFalse(self.go.is_text_candidate("docs/.DS_Store"))

    def test_missing_gitleaks_does_not_block_when_builtin_scan_passes(self):
        temp_dir, repo = self.init_repo()
        self.addCleanup(temp_dir.cleanup)
        (repo / "note.md").write_text("clean content\n", encoding="utf-8")
        self.run_git(repo, "add", "note.md")
        self.run_git(repo, "commit", "-qm", "clean")

        log_temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(log_temp_dir.cleanup)
        with (
            mock.patch.object(self.go, "shutil_which", return_value=None),
            mock.patch.object(
                self.go,
                "scan_log_directory",
                return_value=log_temp_dir.name,
                create=True,
            ),
        ):
            cwd = os.getcwd()
            os.chdir(repo)
            try:
                ok = self.go.run_security_scan("full", ["note.md"])
            finally:
                os.chdir(cwd)

        self.assertTrue(ok)

    def test_expanded_rules_detect_common_tokens(self):
        text = "\n".join(
            [
                "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature",
                "token = ghp_abcdefghijklmnopqrstuvwxyz0123456789",
                "aws_access_key_id = ASIA1234567890ABCDEF",
                "-----BEGIN PGP PRIVATE KEY BLOCK-----",
            ]
        )

        rules = {finding.rule for finding in self.go.scan_text("note.md", text)}

        self.assertIn("bearer-token", rules)
        self.assertIn("github-token", rules)
        self.assertIn("cloud-access-key", rules)
        self.assertIn("private-key-block", rules)

    def test_allowlist_keeps_placeholders_and_gitmodules_ssh_urls(self):
        placeholder = self.go.scan_text("note.md", "password: ${PASSWORD}\n")
        gitmodules = self.go.scan_text(".gitmodules", "url = git@github.com:TDAkory/MyNote.git\n")

        self.assertEqual([], placeholder)
        self.assertEqual([], gitmodules)

    def test_write_scan_log_wraps_permission_error_as_security_scan_error(self):
        with mock.patch.object(
            self.go.os, "makedirs", side_effect=PermissionError("denied")
        ):
            with self.assertRaisesRegex(
                self.go.SecurityScanError, "写入安全扫描日志失败"
            ):
                self.go.write_scan_log("scan-only", [], [], "PASS")

    def test_scan_log_target_uses_root_and_sanitized_relative_path(self):
        target_func = getattr(self.go, "scan_log_target", None)
        self.assertIsNotNone(target_func, "scan_log_target must be implemented")

        with mock.patch.object(self.go, "my_note_root", return_value="/repo"):
            self.assertEqual("root", target_func("/repo"))
            self.assertEqual("CppLearn", target_func("/repo/CppLearn"))
            self.assertEqual(
                "Cpp-Learn-Basic-Concept-C-26",
                target_func("/repo/Cpp Learn/Basic Concept/C++26"),
            )

    def test_write_scan_log_creates_timestamped_flat_log_with_content(self):
        directory_func = getattr(self.go, "scan_log_directory", None)
        self.assertIsNotNone(directory_func, "scan_log_directory must be implemented")

        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        finding = self.go.SecurityFinding(
            severity="HIGH",
            rule="demo-rule",
            path="note.md",
            line_number=7,
            matched_text="redacted",
            message="demo finding",
        )
        with (
            mock.patch.object(
                self.go, "scan_log_directory", return_value=temp_dir.name
            ),
            mock.patch.object(self.go, "scan_log_target", return_value="CppLearn"),
        ):
            log_path = self.go.write_scan_log(
                "incremental-scan-only", ["note.md"], [finding], "BLOCKED"
            )

        name = Path(log_path).name
        self.assertRegex(
            name,
            r"^CppLearn_\d{8}-\d{6}-\d{3}_incremental-scan-only_BLOCKED(?:_\d+)?\.log$",
        )
        content = Path(log_path).read_text(encoding="utf-8")
        self.assertIn("repository:", content)
        self.assertIn("mode: incremental-scan-only", content)
        self.assertIn("result: BLOCKED", content)
        self.assertIn("[HIGH] demo-rule", content)
        self.assertIn("file: note.md", content)

    def test_write_scan_log_keeps_latest_twenty_per_target(self):
        directory_func = getattr(self.go, "scan_log_directory", None)
        self.assertIsNotNone(directory_func, "scan_log_directory must be implemented")

        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        with mock.patch.object(
            self.go, "scan_log_directory", return_value=temp_dir.name
        ):
            with mock.patch.object(
                self.go, "scan_log_target", return_value="AppFrameThoughts"
            ):
                other_log = self.go.write_scan_log("full", [], [], "PASS")
            with mock.patch.object(
                self.go, "scan_log_target", return_value="CppLearn"
            ):
                for index in range(21):
                    self.go.write_scan_log(f"scan-{index:02d}", [], [], "PASS")

        log_dir = Path(temp_dir.name)
        self.assertEqual(20, len(list(log_dir.glob("CppLearn_*.log"))))
        self.assertTrue(Path(other_log).exists())
        self.assertEqual(1, len(list(log_dir.glob("AppFrameThoughts_*.log"))))

    def test_write_scan_log_concurrent_collision_preserves_both_logs(self):
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        results = []
        failures = []

        class FixedDateTime(self.go.datetime):
            @classmethod
            def now(cls, tz=None):
                return cls(2026, 9, 14, 12, 0, 0, 123000, tzinfo=tz)

        def write_one():
            try:
                results.append(self.go.write_scan_log("full", [], [], "PASS"))
            except BaseException as error:  # Preserve assertion details from worker.
                failures.append(error)

        with (
            mock.patch.object(
                self.go, "scan_log_directory", return_value=temp_dir.name
            ),
            mock.patch.object(self.go, "scan_log_target", return_value="CppLearn"),
            mock.patch.object(self.go, "datetime", FixedDateTime),
        ):
            threads = [threading.Thread(target=write_one) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=3)

        self.assertEqual([], failures)
        self.assertEqual(2, len(set(results)))
        self.assertEqual(2, len(list(Path(temp_dir.name).glob("CppLearn_*.log"))))

    def test_prune_scan_logs_does_not_match_longer_target_prefix(self):
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        log_dir = Path(temp_dir.name)
        neighbor = log_dir / "CppLearn_extra_20260101-000000-000_full_PASS.log"
        neighbor.write_text("neighbor\n", encoding="utf-8")
        for index in range(20):
            (log_dir / f"CppLearn_20260101-000000-{index:03d}_full_PASS.log").write_text(
                "old\n", encoding="utf-8"
            )

        self.go.prune_scan_logs(temp_dir.name, "CppLearn", keep=1)

        self.assertTrue(neighbor.exists())
        self.assertEqual(1, len(list(log_dir.glob("CppLearn_20*.log"))))

    def test_write_scan_log_removes_temporary_file_when_publish_fails(self):
        directory_func = getattr(self.go, "scan_log_directory", None)
        self.assertIsNotNone(directory_func, "scan_log_directory must be implemented")

        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        with (
            mock.patch.object(
                self.go, "scan_log_directory", return_value=temp_dir.name
            ),
            mock.patch.object(self.go, "scan_log_target", return_value="CppLearn"),
            mock.patch.object(
                self.go.os, "replace", side_effect=PermissionError("denied")
            ),
        ):
            with self.assertRaisesRegex(
                self.go.SecurityScanError, "写入安全扫描日志失败"
            ):
                self.go.write_scan_log("scan-only", [], [], "PASS")

        self.assertEqual([], list(Path(temp_dir.name).iterdir()))

    def test_write_scan_log_warns_when_rotation_cleanup_fails(self):
        directory_func = getattr(self.go, "scan_log_directory", None)
        self.assertIsNotNone(directory_func, "scan_log_directory must be implemented")

        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        log_dir = Path(temp_dir.name)
        for index in range(20):
            (log_dir / f"CppLearn_20260101-000000-{index:03d}_full_PASS.log").write_text(
                "old\n", encoding="utf-8"
            )

        stderr = StringIO()
        with (
            mock.patch.object(
                self.go, "scan_log_directory", return_value=temp_dir.name
            ),
            mock.patch.object(self.go, "scan_log_target", return_value="CppLearn"),
            mock.patch.object(
                self.go.os, "remove", side_effect=PermissionError("denied")
            ),
            redirect_stderr(stderr),
        ):
            new_log = self.go.write_scan_log("full", [], [], "PASS")

        self.assertTrue(Path(new_log).exists())
        self.assertIn("清理旧安全扫描日志失败", stderr.getvalue())

    def test_run_security_scan_reports_log_write_failure_without_traceback(self):
        output = StringIO()
        with (
            mock.patch.object(self.go, "run_optional_gitleaks", return_value=[]),
            mock.patch.object(
                self.go,
                "write_scan_log",
                side_effect=self.go.SecurityScanError("写入安全扫描日志失败: denied"),
            ),
            redirect_stdout(output),
        ):
            ok = self.go.run_security_scan("scan-only", [])

        self.assertFalse(ok)
        self.assertIn("[ERROR] scan-error", output.getvalue())
        self.assertIn("日志文件: 未写入", output.getvalue())
        self.assertNotIn("Traceback", output.getvalue())

    def test_git_object_scan_reports_log_write_failure_without_traceback(self):
        output = StringIO()
        with (
            mock.patch.object(self.go, "iter_git_blobs_for_ranges", return_value=[]),
            mock.patch.object(self.go, "run_optional_gitleaks", return_value=[]),
            mock.patch.object(
                self.go,
                "write_scan_log",
                side_effect=self.go.SecurityScanError("写入安全扫描日志失败: denied"),
            ),
            redirect_stdout(output),
        ):
            ok = self.go.run_security_scan_for_git_objects("history", ["base..HEAD"])

        self.assertFalse(ok)
        self.assertIn("[ERROR] scan-error", output.getvalue())
        self.assertIn("日志文件: 未写入", output.getvalue())
        self.assertNotIn("Traceback", output.getvalue())


if __name__ == "__main__":
    unittest.main()
