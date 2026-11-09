import base64
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "gfwlist2dnsmasq.sh"
RULES = b"[AutoProxy 0.2.9]\n||example.test\n||notexample.test\n||sub.example.test\n"
PREVIOUS = b"# previous working configuration\n"


class ConversionTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.output = self.root / "output.conf"
        self.output.write_bytes(PREVIOUS)
        self.payload = self.root / "download.b64"
        self.wrapper("curl", """
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o|-O) dest=$2; shift;;
        -o*|-O*) dest=${1#??};;
    esac
    shift
done
[ "${TEST_DOWNLOAD_RC:-0}" = 0 ] || exit "$TEST_DOWNLOAD_RC"
cat "$TEST_PAYLOAD" > "$dest"
""")
        self.wrapper("mktemp", 'exec "' + shutil.which("mktemp") + '" -d "$TEST_ROOT/work.XXXXXX"\n')

    def wrapper(self, name, source):
        path = self.bin / name
        path.write_text("#!/bin/sh\n" + source)
        path.chmod(0o755)

    def file(self, name, content):
        path = self.root / name
        path.write_bytes(content)
        return str(path)

    def run_script(self, *args, rules=RULES, raw=None, env=None, shell="sh", output=None):
        self.payload.write_bytes(base64.b64encode(rules) if raw is None else raw)
        test_env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                        TEST_ROOT=str(self.root), TEST_PAYLOAD=str(self.payload))
        test_env.update(env or {})
        return subprocess.run(
            [shell, str(SCRIPT), "-o", str(output or self.output), *map(str, args)],
            cwd=self.root, env=test_env, capture_output=True, timeout=20,
        )

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))

    def test_empty_and_blank_exclusions_are_noops(self):
        for content in (b"", b"\n", b"\r\n \t\n"):
            with self.subTest(content=content):
                exclude = self.file("exclude.txt", content)
                self.assert_success(self.run_script("-l", "--exclude-domain-file", exclude))
                self.assertIn("example.test", self.output.read_text().splitlines())

    def test_exclusion_matches_whole_domains(self):
        exclude = self.file("exclude.txt", b"\nexample.test\r\n\n")
        self.assert_success(self.run_script("-l", "--exclude-domain-file", exclude))
        domains = self.output.read_text().splitlines()
        self.assertNotIn("example.test", domains)
        self.assertIn("notexample.test", domains)
        self.assertIn("sub.example.test", domains)

    def test_extra_domains_are_added_after_exclusions(self):
        exclude = self.file("exclude.txt", b"example.test\n")
        extra = self.file("extra.txt", b"example.test\nextra.test\n")
        self.assert_success(self.run_script("-l", "--exclude-domain-file", exclude,
                                            "--extra-domain-file", extra))
        self.assertIn("example.test", self.output.read_text().splitlines())
        self.assertIn("extra.test", self.output.read_text().splitlines())

    def test_explicitly_excluding_every_domain_is_valid(self):
        self.assert_success(self.run_script("-l"))
        exclude = self.file("exclude.txt", self.output.read_bytes())
        self.assert_success(self.run_script("-l", "--exclude-domain-file", exclude))
        self.assertEqual(self.output.read_bytes(), b"")


if __name__ == "__main__":
    unittest.main()
