"""set_integrity.py edits only the integrity keys of server.json (no SSH: the edit is a plain function).
    py -3.12 -m unittest tools.tests.test_set_integrity -v
"""
import argparse
import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "deploy"))
import set_integrity  # noqa: E402
from remote import Target, add_target_args  # noqa: E402

OLD = {"admin_token": "kept", "integrity_mode": "enforce", "min_client_version": "0.1.4",
       "integrity_releases": {"0.1.4": ["a" * 64, "b" * 64]}}


class SetIntegrity(unittest.TestCase):
    def test_a_forced_update_replaces_the_old_hashes_and_raises_the_minimum(self):
        new = set_integrity.edited(OLD, "enforce", "0.1.5=" + "c" * 64, "0.1.5")
        self.assertEqual(new, {"admin_token": "kept", "integrity_mode": "enforce", "min_client_version": "0.1.5",
                               "integrity_releases": {"0.1.5": ["c" * 64]}})
        self.assertEqual(OLD["min_client_version"], "0.1.4")   # the input is not changed

    def test_the_mode_alone_keeps_releases_and_minimum(self):
        new = set_integrity.edited(OLD, "log")
        self.assertEqual((new["integrity_releases"], new["min_client_version"]), (OLD["integrity_releases"], "0.1.4"))

    def test_wrong_values_are_refused(self):
        for release, minimum in (("0.1.5=abc", None), ("0.1.5", None), ("v5=" + "c" * 64, None), (None, "0.1")):
            with self.assertRaises(SystemExit):
                set_integrity.edited(OLD, "enforce", release, minimum)


class FakeTarget:
    """Records each command; answers like a server where Go is live (or not) and whose check passes (or not)."""

    def __init__(self, live: bool, check_passes: bool = True):
        parser = argparse.ArgumentParser()
        add_target_args(parser)
        self.real = Target(parser.parse_args(["--host", "root@203.0.113.10"]))
        self.live, self.check_passes, self.commands = live, check_passes, []

    def __getattr__(self, name):
        return getattr(self.real, name)

    def ssh(self, command, check=True, stdin=None):
        self.commands.append(command)
        if command.startswith("test -e"):
            return "live\n" if self.live else ""
        if command.startswith("cat /"):
            return json.dumps(OLD)
        if ("--check-config" in command or "server_config" in command) and not self.check_passes:
            sys.exit("Server command failed")
        return ""

    def health(self):
        return "{}"


class Run(unittest.TestCase):
    def setUp(self):
        self.sleep, set_integrity.time.sleep = set_integrity.time.sleep, lambda seconds: None

    def tearDown(self):
        set_integrity.time.sleep = self.sleep

    def changes(self, target):
        return [c for c in target.commands if c.startswith(("mv ", "cp ")) or "systemctl restart" in c]

    def test_the_dry_run_asks_the_go_binary_and_changes_nothing(self):
        target = FakeTarget(live=True)
        set_integrity.run(target, "enforce", "0.1.5=" + "c" * 64, "0.1.5", apply=False)
        self.assertTrue(any("/opt/splatoon/go/splatoon-nex --config /opt/splatoon/server.json.new --check-config" in c
                            for c in target.commands))
        self.assertEqual(self.changes(target), [])
        self.assertEqual(target.commands[-1], "rm -f /opt/splatoon/server.json.new")

    def test_apply_restarts_the_go_unit_after_the_check_and_the_backup(self):
        target = FakeTarget(live=True)
        set_integrity.run(target, "enforce", "0.1.5=" + "c" * 64, "0.1.5", apply=True)
        changes = self.changes(target)
        self.assertTrue(changes[0].startswith("cp -p /opt/splatoon/server.json /opt/splatoon/server.json.bak-"))
        self.assertEqual(changes[1], "mv /opt/splatoon/server.json.new /opt/splatoon/server.json && "
                                     "systemctl restart splatoon-nex-go")
        check = next(i for i, c in enumerate(target.commands) if "--check-config" in c)
        self.assertLess(check, target.commands.index(changes[0]))

    def test_a_refused_file_is_removed_and_nothing_changes(self):
        target = FakeTarget(live=True, check_passes=False)
        with self.assertRaises(SystemExit):
            set_integrity.run(target, "enforce", "0.1.5=" + "c" * 64, "0.1.5", apply=True)
        self.assertEqual(self.changes(target), [])
        self.assertEqual(target.commands[-1], "rm -f /opt/splatoon/server.json.new")

    def test_the_python_server_is_still_checked_by_its_own_code(self):
        target = FakeTarget(live=False)
        set_integrity.run(target, "log", None, None, apply=True)
        self.assertTrue(any("server_config" in c for c in target.commands))
        self.assertTrue(self.changes(target)[-1].endswith("systemctl restart splatoon-nex"))


if __name__ == "__main__":
    unittest.main()
