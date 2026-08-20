import unittest
from unittest import mock

import mynote


class MyNoteEntrypointTest(unittest.TestCase):
    def test_sync_subcommand_dispatches_to_git_operations(self):
        with mock.patch.object(mynote.git_operations, "main", return_value=0) as main:
            result = mynote.main(["sync", "--scan-only", "--subfolder", ""])

        self.assertEqual(0, result)
        main.assert_called_once_with(["--scan-only", "--subfolder", ""])

    def test_index_subcommand_dispatches_to_markdown_index(self):
        with mock.patch.object(mynote.markdown_index, "main", return_value=0) as main:
            result = mynote.main(["index", "gen", "."])

        self.assertEqual(0, result)
        main.assert_called_once_with(["gen", "."])

    def test_legacy_options_dispatch_to_sync(self):
        with mock.patch.object(mynote.git_operations, "main", return_value=0) as main:
            result = mynote.main(["--scan-only", "--subfolder", ""])

        self.assertEqual(0, result)
        main.assert_called_once_with(["--scan-only", "--subfolder", ""])

    def test_unknown_subcommand_returns_usage_error(self):
        with mock.patch.object(mynote.git_operations, "main", return_value=0) as main:
            result = mynote.main(["unknown"])

        self.assertEqual(2, result)
        main.assert_not_called()


if __name__ == "__main__":
    unittest.main()
