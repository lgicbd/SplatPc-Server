"""Deploy scripts must never touch the live Go server by mistake (no SSH: a fake target answers).
    py -3.12 -m unittest tools.tests.test_deploy_guards -v
"""
import argparse
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "deploy"))
import deploy_go  # noqa: E402
import go_test_env  # noqa: E402
from remote import Target, add_target_args  # noqa: E402


def make_target() -> Target:
    parser = argparse.ArgumentParser()
    add_target_args(parser)
    return Target(parser.parse_args(["--host", "root@203.0.113.10"]))


class FakeTarget:
    """Records each command; the live flag exists when live is true."""

    def __init__(self, live: bool):
        self.real = make_target()
        self.live, self.commands = live, []

    def __getattr__(self, name):
        return getattr(self.real, name)

    def ssh(self, command, check=True, stdin=None):
        self.commands.append(command)
        return "live\n" if self.live and command.startswith("test -e") else ""


class ParallelGuardTests(unittest.TestCase):
    def test_parallel_refuses_when_go_is_live_and_runs_nothing_else(self):
        target = FakeTarget(live=True)
        with self.assertRaises(SystemExit) as stopped:
            deploy_go.parallel(target, deploy_go.Go(target, 60100))
        self.assertIn("go_test_env.py", str(stopped.exception))
        self.assertEqual(len(target.commands), 1)
        self.assertTrue(target.commands[0].startswith("test -e /opt/splatoon/go/live"))

    def test_stop_parallel_still_refuses_when_go_is_live(self):
        target = FakeTarget(live=True)
        with self.assertRaises(SystemExit):
            deploy_go.stop_parallel(target, deploy_go.Go(target, 60100))
        self.assertEqual(len(target.commands), 1)


class TestEnvTests(unittest.TestCase):
    def setUp(self):
        self.target = make_target()
        self.env = go_test_env.TestEnv(self.target, 60100)
        self.go = deploy_go.Go(self.target, 60100)

    def test_paths_and_unit_never_are_the_live_ones(self):
        self.assertNotEqual(go_test_env.TEST_SERVICE, deploy_go.GO_SERVICE)
        for test_path, live_path in ((self.env.dir, self.go.dir), (self.env.config, self.target.config),
                                     (self.env.config, self.go.config), (self.env.db, self.target.db),
                                     (self.env.log, self.go.log), (self.env.binary, self.go.binary)):
            self.assertNotEqual(test_path, live_path)
        self.assertNotIn("[Install]", self.env.unit())          # never started at boot
        self.assertIn(f"--config {self.env.config}", self.env.unit())

    def test_config_is_moved_to_the_test_ports_and_database(self):
        live = {"auth_port": 60000, "secure_port": 60001, "registration_port": 60002, "natcheck": True,
                "natcheck_addresses": ["198.51.100.1"], "integrity_mode": "enforce", "accounts_db": self.target.db}
        config = go_test_env.test_config(live, self.env)
        self.assertEqual((config["auth_port"], config["secure_port"], config["registration_port"]), (60100, 60101, 60102))
        self.assertEqual((config["accounts_db"], config["integrity_mode"], config["natcheck"]), (self.env.db, "log", False))
        self.assertNotIn("natcheck_addresses", config)
        self.assertEqual(live["integrity_mode"], "enforce")     # the live dictionary is not changed

    def test_test_ports_overlapping_the_live_server_are_refused(self):
        live = {"auth_port": 60000, "secure_port": 60001, "registration_port": 60002}
        for port in (59999, 60000, 60002, 10024, 10125):
            with self.subTest(port=port), self.assertRaises(SystemExit):
                go_test_env.test_config(live, go_test_env.TestEnv(self.target, port))


if __name__ == "__main__":
    unittest.main()
