"""set_integrity.py edits only the integrity keys of server.json (no SSH: the edit is a plain function).
    py -3.12 -m unittest tools.tests.test_set_integrity -v
"""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "deploy"))
import set_integrity  # noqa: E402

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


if __name__ == "__main__":
    unittest.main()
