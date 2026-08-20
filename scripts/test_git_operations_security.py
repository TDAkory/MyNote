import os
import subprocess
import tempfile
import unittest
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

        with mock.patch.object(self.go, "run_optional_gitleaks", return_value=[]):
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

        with mock.patch.object(self.go, "shutil_which", return_value=None):
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


if __name__ == "__main__":
    unittest.main()
