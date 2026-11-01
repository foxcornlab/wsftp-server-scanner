#!/usr/bin/env python3
"""Tests for wsftp_scanner.py. Run: python3 -m unittest discover -s tests -v"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wsftp_scanner import (  # noqa: E402
    GROUP_A, GROUP_B, find_wsftp, grade, parse_version,
)


class TestParse(unittest.TestCase):
    def test_plain_and_marketing_forms(self):
        self.assertEqual(parse_version("2024.0.6"), (2024, 0, 6))
        self.assertEqual(parse_version("2025.0.4"), (2025, 0, 4))
        self.assertEqual(parse_version("9.0.6"), (2024, 0, 6))
        self.assertEqual(parse_version("10.0.3"), (2025, 0, 3))
        self.assertEqual(parse_version("2024.0.6 (build 123)"), (2024, 0, 6))
        self.assertEqual(parse_version("8.8.3"), (8, 8, 3))

    def test_unparseable(self):
        self.assertIsNone(parse_version(""))
        self.assertIsNone(parse_version("not-a-version"))
        self.assertIsNone(parse_version("2024.x.6"))


class TestGrade(unittest.TestCase):
    def test_fifteen_cves_listed(self):
        self.assertEqual(len(GROUP_A) + len(GROUP_B), 15)
        self.assertEqual(len(GROUP_A), 3)
        self.assertEqual(len(GROUP_B), 12)

    def test_trap_2024_branch(self):
        # First patched build: group A fixed, group B still open.
        result = grade(parse_version("2024.0.6"))
        self.assertEqual(result["verdict"], "VULNERABLE")
        self.assertEqual(result["groups"][0]["verdict"], "FIXED")
        self.assertEqual(result["groups"][1]["verdict"], "VULNERABLE")
        self.assertIn("TRAP", result["detail"])

    def test_trap_2025_branch(self):
        result = grade(parse_version("2025.0.3"))
        self.assertEqual(result["verdict"], "VULNERABLE")
        self.assertEqual(result["groups"][0]["verdict"], "FIXED")
        self.assertEqual(result["groups"][1]["verdict"], "VULNERABLE")

    def test_fully_patched_both_branches(self):
        for version in ("2024.0.7", "2025.0.4", "2024.0.8", "2025.0.5"):
            result = grade(parse_version(version))
            self.assertEqual(result["verdict"], "FIXED", version)
            self.assertTrue(all(g["verdict"] == "FIXED" for g in result["groups"]))

    def test_marketing_numbers_grade_the_same(self):
        self.assertEqual(
            grade(parse_version("9.0.6"))["verdict"],
            grade(parse_version("2024.0.6"))["verdict"])
        self.assertEqual(
            grade(parse_version("10.0.4"))["verdict"], "FIXED")

    def test_old_branch_has_no_fix(self):
        result = grade(parse_version("8.8.3"))
        self.assertEqual(result["verdict"], "VULNERABLE")
        self.assertTrue(all(g["verdict"] == "NO_FIX_IN_BRANCH" for g in result["groups"]))

    def test_unlisted_branch_is_unknown_not_clean(self):
        result = grade(parse_version("2026.0.1"))
        self.assertEqual(result["verdict"], "UNKNOWN")

    def test_unparseable_is_unknown(self):
        self.assertEqual(grade(None)["verdict"], "UNKNOWN")


class TestRegistryMatching(unittest.TestCase):
    def test_exact_server_entry_wins(self):
        entries = [
            {"DisplayName": "WS_FTP Pro", "DisplayVersion": "12.4.1"},
            {"DisplayName": "Progress WS_FTP Server", "DisplayVersion": "2024.0.5"},
        ]
        self.assertEqual(find_wsftp(entries)["DisplayVersion"], "2024.0.5")

    def test_no_server_entry(self):
        self.assertIsNone(find_wsftp([
            {"DisplayName": "WS_FTP Pro", "DisplayVersion": "12.4.1"},
        ]))


class TestCli(unittest.TestCase):
    SCRIPT = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "wsftp_scanner.py")

    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, self.SCRIPT, *args],
            capture_output=True, text=True, timeout=30)

    def test_trap_exit_code(self):
        proc = self.run_cli("--version", "2024.0.6")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("TRAP", proc.stdout)

    def test_clean_exit_code(self):
        proc = self.run_cli("--version", "2025.0.4")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("FIXED", proc.stdout)

    def test_json_output(self):
        proc = self.run_cli("--version", "2025.0.3", "--json")
        self.assertEqual(proc.returncode, 2)
        data = json.loads(proc.stdout)
        self.assertEqual(data["verdict"], "VULNERABLE")
        self.assertEqual(len(data["groups"]), 2)

    def test_registry_json_path(self):
        entries = [
            {"DisplayName": "Progress WS_FTP Server", "DisplayVersion": "2024.0.6"},
        ]
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump(entries, handle)
            path = handle.name
        try:
            proc = self.run_cli("--registry-json", path)
            self.assertEqual(proc.returncode, 2)
            self.assertIn("2024.0.6", proc.stdout)
        finally:
            os.unlink(path)

    def test_list_counts_fifteen(self):
        proc = self.run_cli("--list")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout.count("CVE-2026-"), 15)


if __name__ == "__main__":
    unittest.main()
