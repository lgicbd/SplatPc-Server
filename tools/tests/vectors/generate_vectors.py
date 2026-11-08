"""Writes the Go server's reference vectors from the Python library (invented values only).

py -3.12 tools/tests/vectors/generate_vectors.py  -> testdata/vectors/*.txt
Removed with the Python server: the vectors stay as plain files.
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))

from nintendo.nex import kerberos  # noqa: E402

OUT = ROOT / "testdata" / "vectors"


def derive_key():
    lines = []
    for pid, password in ((0x5eea2491, "abcdefghijklmnop"), (0x10000000, "0123456789ABCDEF"),
                          (0x7fffffff, "zzzzzzzzzzzzzzzz"), (1, "AAAAaaaa00001111")):
        key = kerberos.KeyDerivationOld().derive_key(password.encode("ascii"), pid)
        lines.append(f"{pid:08x} {password} {key.hex()}")
    return lines


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "derive_key.txt").write_text("\n".join(derive_key()) + "\n", encoding="ascii", newline="\n")


if __name__ == "__main__":
    main()
