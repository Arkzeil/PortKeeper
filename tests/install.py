#!/usr/bin/env python3
"""Install into a temporary DESTDIR and exercise only the installed artifacts."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


parser = argparse.ArgumentParser()
parser.add_argument("--cmake", required=True)
parser.add_argument("--build-dir", type=Path, required=True)
parser.add_argument("--bindir", required=True)
parser.add_argument("--mandir", required=True)
parser.add_argument("--version", required=True)
parser.add_argument("--config", default="")
ARGS = parser.parse_args()


class Installation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="portkeeper-install-")
        cls.addClassCleanup(temporary.cleanup)
        cls.root = Path(temporary.name)
        cls.stage = cls.root / "stage"
        cls.prefix = Path("/opt/portkeeper smoke test")
        cls.env = dict(os.environ, DESTDIR=str(cls.stage))
        manifest = ARGS.build_dir / "install_manifest.txt"
        original_manifest = manifest.read_bytes() if manifest.exists() else None

        def restore_manifest():
            if original_manifest is None:
                if manifest.exists():
                    manifest.unlink()
            else:
                manifest.write_bytes(original_manifest)

        cls.addClassCleanup(restore_manifest)
        command = [ARGS.cmake, "--install", str(ARGS.build_dir), "--prefix", str(cls.prefix)]
        if ARGS.config:
            command += ["--config", ARGS.config]
        result = subprocess.run(command, env=cls.env, capture_output=True, text=True, timeout=15)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)

        def staged(directory, name):
            target = Path(directory) / name
            if not target.is_absolute():
                target = cls.prefix / target
            return cls.stage / target.relative_to("/")

        cls.binary = staged(ARGS.bindir, "portkeeper")
        cls.manual = staged(ARGS.mandir, "man1/portkeeper.1")
        cls.tools = cls.root / "tools"
        cls.tools.mkdir()
        (cls.tools / "ss").write_text(f"#!{sys.executable}\n")
        (cls.tools / "ss").chmod(0o755)
        cls.run_env = dict(os.environ, PATH=str(cls.tools))

    def run_installed(self, *arguments, expected=0, env=None):
        result = subprocess.run([str(self.binary), *arguments], env=env or self.run_env,
                                cwd=self.root, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def test_installed_binary(self):
        self.assertTrue(self.binary.is_file())
        self.assertTrue(os.access(self.binary, os.X_OK))
        version = self.run_installed("--version")
        self.assertEqual(version.stdout, f"portkeeper {ARGS.version}\n")
        self.assertIn("Usage:", self.run_installed("--help").stdout)
        result = self.run_installed("list", "--json")
        self.assertEqual(json.loads(result.stdout), {"schema_version": 1, "sockets": []})
        empty = self.root / "empty-path"
        empty.mkdir()
        result = self.run_installed("list", "--json", expected=4,
                                    env=dict(self.run_env, PATH=str(empty)))
        self.assertEqual(result.stdout, "")
        self.assertIn("iproute2", result.stderr)

    def test_installed_manual(self):
        self.assertEqual(self.manual.read_bytes(), (ARGS.build_dir / "portkeeper.1").read_bytes())
        page = self.manual.read_text()
        self.assertIn(f'"Portkeeper {ARGS.version}"', page)
        self.assertNotIn("@PROJECT_VERSION@", page)
        help_text = self.run_installed("--help").stdout
        for option in set(re.findall(r"--[a-z][a-z-]*", help_text)):
            self.assertIn(option, page.replace(r"\-", "-"))
        for code in range(10):
            self.assertIn(f".B {code}\n", page)

    def test_manual_rendering(self):
        groff = shutil.which("groff")
        man = shutil.which("man")
        if not groff or not man:
            self.skipTest("groff and man are needed to check manual rendering")
        result = subprocess.run([groff, "-ww", "-Tutf8", "-man", str(self.manual)],
                                text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        env = dict(os.environ, MANPAGER="cat", PAGER="cat", MANWIDTH="80", GROFF_NO_SGR="1")
        result = subprocess.run([man, "-M", str(self.manual.parent.parent), "1", "portkeeper"], env=env,
                                text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"Portkeeper {ARGS.version}", result.stdout)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]], verbosity=2)
