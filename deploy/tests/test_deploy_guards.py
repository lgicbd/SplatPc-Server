"""The test server of go_test_env.py must never share a path, port or unit with the live Go server (no SSH).
    py -3 -m unittest discover -s deploy/tests -v
"""
import argparse
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import go_server  # noqa: E402
import go_test_env  # noqa: E402
from remote import Target, add_target_args  # noqa: E402


def make_target() -> Target:
    parser = argparse.ArgumentParser()
    add_target_args(parser)
    return Target(parser.parse_args(["--host", "root@203.0.113.10"]))


class TestEnvTests(unittest.TestCase):
    def setUp(self):
        self.target = make_target()
        self.env = go_test_env.TestEnv(self.target, 60100)
        self.go = go_server.Go(self.target)

    def test_paths_and_unit_never_are_the_live_ones(self):
        self.assertNotEqual(go_test_env.TEST_SERVICE, self.target.service)
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
