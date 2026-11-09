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
if [ "${TEST_HTTP_ERROR:-0}" = 1 ]; then
    case " $* " in *" -f "*) exit 22;; esac
fi
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

    def assert_failure_preserves_output(self, result):
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.output.read_bytes(), PREVIOUS)

    def test_default_dns_and_ipset_outputs(self):
        for args in ((), ("-s", "gfwlist,proxy")):
            with self.subTest(args=args):
                self.assert_success(self.run_script(*args))
                output = self.output.read_text()
                self.assertIn("server=/example.test/127.0.0.1#5353\n", output)
                self.assertEqual("ipset=/example.test/gfwlist,proxy\n" in output, bool(args))

    def test_download_failure_preserves_output(self):
        self.assert_failure_preserves_output(self.run_script(env={"TEST_DOWNLOAD_RC": "7"}))

    def test_decode_errors_stop_the_parent_shell(self):
        for body in (b"%%%", base64.b64encode(RULES) + b"%%%"):
            with self.subTest(body=body):
                self.assert_failure_preserves_output(self.run_script(raw=body))

    def test_failed_temp_directory_creation_stops_processing(self):
        self.wrapper("mktemp", "exit 1\n")
        self.assert_failure_preserves_output(self.run_script())

    def test_sort_failure_preserves_output(self):
        self.wrapper("sort", "exit 1\n")
        self.assert_failure_preserves_output(self.run_script())

    def test_output_copy_failure_is_reported(self):
        self.wrapper("cp", "exit 1\n")
        self.assert_failure_preserves_output(self.run_script())

    def test_invalid_ports_preserve_output(self):
        for value in ("", "abc", "53.5", "0", "65536", "-1", " 53", "9" * 200):
            with self.subTest(port=value):
                self.assert_failure_preserves_output(self.run_script("-p", value))

    def test_invalid_dns_addresses_preserve_output(self):
        for value in ("", "999.1.1.1", "-n", "not-an-ip"):
            with self.subTest(address=value):
                self.assert_failure_preserves_output(self.run_script("-d", value))

    def test_options_require_values_in_sh_and_bash(self):
        for shell in ("sh", "bash"):
            if not shutil.which(shell):
                continue
            for flag in ("-d", "-p", "-s", "-o", "--extra-domain-file", "--exclude-domain-file"):
                with self.subTest(shell=shell, flag=flag):
                    self.assert_failure_preserves_output(self.run_script(flag, shell=shell))

    def test_valid_ipv4_ipv6_and_port_limits(self):
        for address, port in (("127.0.0.1", "1"), ("::1", "53"),
                              ("2001:4860:4860::8888", "65535")):
            with self.subTest(address=address, port=port):
                self.assert_success(self.run_script("-d", address, "-p", port))
                self.assertIn("/" + address + "#" + port, self.output.read_text())

    def test_empty_or_wrong_format_downloads_preserve_output(self):
        for body in (b"", b"<html>Access denied</html>\n", b"[AutoProxy 0.2.9]\n! comments only\n"):
            with self.subTest(body=body):
                self.assert_failure_preserves_output(self.run_script(rules=body))

    def test_http_error_preserves_output_even_with_a_valid_body(self):
        self.assert_failure_preserves_output(self.run_script(env={"TEST_HTTP_ERROR": "1"}))

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
