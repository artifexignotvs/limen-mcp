import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from limen_mcp.__main__ import main
from limen_mcp.audit import MAX_BYTES, parse_config


class AuditTests(unittest.TestCase):
    def audit(self, server, root="mcpServers"):
        return parse_config(json.dumps({root: {"fixture": server}}).encode())

    def rules(self, server):
        return {finding.rule_id for finding in self.audit(server).findings}

    def test_clean_local_configuration(self):
        report = self.audit({"command": "python", "args": ["-m", "local_server"]})
        self.assertEqual(report.exit_code(), 0)
        self.assertEqual(report.findings, [])
        self.assertEqual(report.servers, 1)

    def test_empty_configuration_is_not_missing_configuration(self):
        self.assertEqual(parse_config(b'{"mcpServers":{}}').exit_code(), 0)
        self.assertEqual(parse_config(b'{}').exit_code(), 2)

    def test_both_roots_are_audited(self):
        report = parse_config(b'{"mcpServers":{"a":{"url":"http://example.invalid"}},"servers":{"b":{"command":"npx","args":["tool"]}}}')
        self.assertEqual(report.servers, 2)
        self.assertEqual({finding.rule_id for finding in report.findings}, {"LM010", "LM030"})

    def test_remote_plaintext_and_loopback(self):
        for url in ("http://example.invalid/mcp", "http://10.0.0.1/mcp", "http://localhost.example.invalid/mcp", "http://0.0.0.0/mcp"):
            with self.subTest(url=url):
                self.assertIn("LM010", self.rules({"url": url}))
        for url in ("https://example.invalid/mcp", "http://localhost/mcp", "http://127.0.0.1/mcp", "http://[::1]/mcp", "http://127.2.3.4/mcp"):
            with self.subTest(url=url):
                self.assertNotIn("LM010", self.rules({"url": url}))

    def test_unknown_transport_is_reported(self):
        self.assertIn("LM002", self.rules({"url": "https://example.invalid", "type": "custom"}))
        self.assertIn("LM011", self.rules({"url": "custom://example.invalid"}))

    def test_invalid_shapes_and_urls(self):
        cases = [None, [], {"args": "wrong"}, {"command": 5}, {"command": ""},
                 {"command": "x", "env": {"X": 9}}, {"command": "x", "headers": []},
                 {"command": "x", "url": "https://example.invalid"},
                 {"url": "https://example.invalid", "type": "stdio"},
                 {"command": "x", "type": "stdio", "transport": "sse"},
                 {"url": "https://[bad"}, {"url": "https://example.invalid:bad"}, {"url": "/relative"}]
        for server in cases:
            with self.subTest(server=server):
                self.assertEqual(self.audit(server).exit_code(), 2)

    def test_credentials_are_redacted_from_every_report_field(self):
        marker = "sensitive-marker-73921"
        content = {"mcpServers": {marker: {
            "url": f"https://{marker}:{marker}@example.invalid/mcp?api_key={marker}",
            "headers": {"Authorization": f"Bearer {marker}"},
            "env": {f"{marker}_TOKEN": marker, "API_KEY": marker},
            "args": ["--password", marker, f"--token={marker}"],
        }}}
        report = parse_config(json.dumps(content).encode())
        self.assertGreaterEqual(len(report.findings), 4)
        self.assertNotIn(marker, json.dumps(report.to_dict()))

    def test_command_credentials_are_redacted(self):
        marker = "sensitive-marker-71981"
        report = self.audit({"command": "tool", "args": ["--password", marker, f"--api-key={marker}"]})
        self.assertEqual(len(report.findings), 2)
        self.assertNotIn(marker, json.dumps(report.to_dict()))

    def test_placeholders_and_empty_secret_fields(self):
        report = self.audit({"command": "tool", "env": {"API_KEY": "${INPUT_KEY}", "TOKEN": "$TOKEN", "PASSWORD": "%PASSWORD%", "SECRET": "", "TOKEN_PATH": "/fixture/value"}})
        self.assertEqual(report.findings, [])

    def test_placeholder_fallback_literals_are_not_hidden(self):
        for value in ("${TOKEN:-sensitive-fallback}", "${TOKEN:=sensitive-fallback}", "${TOKEN-sensitive-fallback}"):
            with self.subTest(value=value):
                report = self.audit({"command": "tool", "env": {"TOKEN": value}})
                self.assertIn("LM001", {finding.rule_id for finding in report.findings})
                self.assertNotIn("sensitive-fallback", json.dumps(report.to_dict()))
        for value in ("${env:TOKEN}", "${input:service.token}", "Bearer ${input:service-token}"):
            self.assertNotIn("LM001", self.rules({"url": "https://example.invalid", "headers": {"Authorization": value}}))

    def test_url_controls_and_invalid_authority_are_rejected_without_echo(self):
        for url in ("https://sensitive-marker-81311.invalid/\n", "http://local\thost/", "https://example.invalid:0/", "https://example.invalid\\other/", "https://example.invalid/private path"):
            with self.subTest(url=url):
                report = self.audit({"url": url})
                self.assertEqual(report.exit_code(), 2)
                self.assertNotIn("sensitive-marker-81311", json.dumps(report.to_dict()))

    def test_npx_exact_scoped_and_prerelease_versions(self):
        for package in ("tool@1.2.3", "@scope/tool@1.2.3", "@scope/tool@1.2.3-rc.2"):
            self.assertNotIn("LM030", self.rules({"command": "/usr/bin/npx", "args": ["-y", package]}))
        for package in ("tool", "tool@latest", "@scope/tool", "tool@^1.0.0", "tool@1"):
            self.assertIn("LM030", self.rules({"command": "npx", "args": [package]}))

    def test_npx_explicit_package_flags_and_command_boundary(self):
        self.assertNotIn("LM030", self.rules({"command": "npx", "args": ["--package", "tool@1.2.3", "tool-command", "--package", "unrelated"]}))
        self.assertIn("LM030", self.rules({"command": "npx.cmd", "args": ["--package=tool@latest", "tool"]}))
        self.assertIn("LM090", self.rules({"command": "npx", "args": ["--unsupported", "tool"]}))

    def test_npx_explicit_shell_command_is_reported(self):
        for args in (["-c", "sensitive-command-string"], ["--package", "tool@1.2.3", "--call", "sensitive-command-string"], ["--call=sensitive-command-string"]):
            with self.subTest(args=args):
                report = self.audit({"command": "npx", "args": args})
                self.assertIn("LM020", {finding.rule_id for finding in report.findings})
                self.assertNotIn("sensitive-command-string", json.dumps(report.to_dict()))
                self.assertEqual(report.exit_code(), 1)
        self.assertNotIn("LM020", self.rules({"command": "npx", "args": ["tool@1.2.3", "--call", "application-argument"]}))

    def test_uvx_pins_and_additional_requirements(self):
        self.assertNotIn("LM031", self.rules({"command": "uvx", "args": ["tool@1.2.3"]}))
        self.assertNotIn("LM031", self.rules({"command": "uv", "args": ["tool", "run", "--from", "package[extra]==1.2.3", "command"]}))
        self.assertIn("LM031", self.rules({"command": "uvx", "args": ["--from=tool>=1.2", "tool"]}))
        self.assertIn("LM031", self.rules({"command": "uvx", "args": ["--with", "dependency", "tool@1.2.3"]}))

    def test_launcher_incomplete_coverage_and_uv_argument_locations(self):
        for command, args in (("npx", ["-y"]), ("uvx", ["--offline"]), ("uvx", ["--with", "dep==1.0"])):
            self.assertIn("LM090", self.rules({"command": command, "args": args}))
        report = self.audit({"command": "uv", "args": ["tool", "run", "--from", "package", "command"]})
        self.assertEqual(report.findings[0].location, "mcpServers.server[1].args[3]")

    def test_authorization_placeholder_is_not_literal_secret(self):
        self.assertNotIn("LM001", self.rules({"url": "https://example.invalid", "headers": {"Authorization": "Bearer ${AUTH_INPUT}"}}))

    def test_shell_body_is_not_claimed_to_be_audited(self):
        report = self.audit({"command": "bash", "args": ["-lc", "npx unpinned"]})
        self.assertEqual({finding.rule_id for finding in report.findings}, {"LM020"})
        self.assertIn("LM020", self.rules({"command": "cmd.exe", "args": ["/c", "anything"]}))
        self.assertNotIn("LM020", self.rules({"command": "python", "args": ["-c", "print(1)"]}))

    def test_shell_command_options_after_startup_options(self):
        for command, args in (
            ("bash", ["--noprofile", "--norc", "-lc", "sensitive-command-string"]),
            ("sh", ["-o", "errexit", "-c", "sensitive-command-string"]),
            ("pwsh", ["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "sensitive-command-string"]),
            ("pwsh", ["-NoProfile", "-e", "synthetic-base64"]),
            ("powershell.exe", ["-NoProfile", "-ec", "synthetic-base64"]),
            ("cmd.exe", ["/D", "/Q", "/V:OFF", "/C", "sensitive-command-string"]),
        ):
            with self.subTest(command=command):
                report = self.audit({"command": command, "args": args})
                self.assertIn("LM020", {finding.rule_id for finding in report.findings})
                self.assertNotIn("sensitive-command-string", json.dumps(report.to_dict()))

    def test_shell_script_arguments_are_not_shell_options(self):
        for command, args in (("bash", ["script.sh", "-c", "argument"]), ("bash", ["--", "script.sh", "-c"]), ("pwsh", ["-NoProfile", "-File", "script.ps1", "-Command", "argument"])):
            with self.subTest(command=command):
                self.assertNotIn("LM020", self.rules({"command": command, "args": args}))

    def test_docker_privileges_namespaces_and_confinement(self):
        rules = self.rules({"command": "docker", "args": ["run", "--rm", "-i", "--privileged", "--network=host", "--pid", "host", "--cap-add=SYS_ADMIN", "--security-opt", "seccomp=unconfined", "image:1"]})
        self.assertTrue({"LM040", "LM041", "LM042", "LM043", "LM044"}.issubset(rules))
        self.assertNotIn("LM040", self.rules({"command": "docker", "args": ["run", "--privileged=false", "image:1"]}))

    def test_docker_boolean_and_capability_aliases(self):
        for value in ("1", "t", "T", "TRUE", "true", "True"):
            with self.subTest(value=value):
                self.assertIn("LM040", self.rules({"command": "docker", "args": ["run", f"--privileged={value}", "image:1"]}))
        for value in ("0", "f", "F", "FALSE", "false", "False"):
            self.assertNotIn("LM040", self.rules({"command": "docker", "args": ["run", f"--privileged={value}", "image:1"]}))
        for capability in ("CAP_SYS_ADMIN", "CAP_SYS_PTRACE"):
            self.assertIn("LM043", self.rules({"command": "docker", "args": ["run", f"--cap-add={capability}", "image:1"]}))
        self.assertIn("LM090", self.rules({"command": "docker", "args": ["run", "--privileged=invalid", "image:1"]}))

    def test_docker_socket_even_readonly_and_broad_mount(self):
        self.assertIn("LM045", self.rules({"command": "docker", "args": ["run", "-v", "/var/run/docker.sock:/socket:ro", "image:1"]}))
        self.assertIn("LM046", self.rules({"command": "docker", "args": ["run", "--mount", "type=bind,src=/,target=/host,readonly", "image:1"]}))
        self.assertIn("LM046", self.rules({"command": "docker", "args": ["run", "-v/etc:/host:ro", "image:1"]}))
        self.assertNotIn("LM046", self.rules({"command": "docker", "args": ["run", "-v", "named-volume:/data", "image:1"]}))

    def test_docker_image_command_is_not_treated_as_docker_options(self):
        self.assertEqual(self.rules({"command": "docker", "args": ["run", "image:1", "--privileged", "--network=host"]}), {"LM048"})

    def test_docker_environment_inheritance_is_explicit(self):
        self.assertIn("LM047", self.rules({"command": "docker", "args": ["run", "-e", "TOKEN", "image:1"]}))
        self.assertNotIn("LM047", self.rules({"command": "tool"}))
        self.assertIn("LM001", self.rules({"command": "docker", "args": ["run", "-e", "TOKEN=fixture-only", "image:1"]}))

    def test_docker_unknown_flags_do_not_guess_argument_boundaries(self):
        self.assertEqual(self.rules({"command": "docker", "args": ["run", "--unknown", "--privileged", "image:1"]}), {"LM090"})

    def test_parse_failures_never_include_payload(self):
        marker = b"sensitive-marker-81400"
        for data in (b'{"' + marker, b'{"mcpServers":{},"mcpServers":{"' + marker + b'":{}}}', b'\xff' + marker,
                     b'{"mcpServers":NaN}', b'{"mcpServers":{},"value":1e999}', b'[' * 2000 + marker, marker * MAX_BYTES):
            with self.subTest(size=len(data)):
                report = parse_config(data)
                self.assertEqual(report.exit_code(), 2)
                self.assertNotIn(marker.decode(), json.dumps(report.to_dict()))

    def test_severity_exit_codes(self):
        report = self.audit({"command": "npx", "args": ["tool"]})
        self.assertEqual(report.exit_code(), 1)
        self.assertEqual(report.exit_code("high"), 0)
        self.assertEqual(report.exit_code("never"), 0)
        self.assertEqual(self.audit({}).exit_code("never"), 2)

    def test_deterministic_report_with_reordered_server_names(self):
        a = {"z": {"command": "npx", "args": ["tool"]}, "a": {"url": "http://example.invalid"}}
        b = dict(reversed(list(a.items())))
        self.assertEqual(parse_config(json.dumps({"servers": a}).encode()).to_dict(), parse_config(json.dumps({"servers": b}).encode()).to_dict())

    def test_cli_formats_and_read_errors_are_redacted(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fixture.json"
            path.write_text('{"mcpServers":{"sensitive-marker-11993":{"command":"tool","env":{"TOKEN":"sensitive-marker-11993"}}}}')
            for format_name in ("json", "text"):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    code = main([str(path), "--format", format_name])
                self.assertEqual(code, 1)
                self.assertNotIn("sensitive-marker-11993", output.getvalue())
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main([str(Path(temporary) / "sensitive-missing-file"), "--format", "json"])
            self.assertEqual(code, 2)
            self.assertNotIn("sensitive-missing-file", output.getvalue())
            self.assertEqual(json.loads(output.getvalue())["summary"]["errors"], 1)

    def test_cli_stdin(self):
        output = io.StringIO()
        fake_stdin = io.TextIOWrapper(io.BytesIO(b'{"servers":{"local":{"command":"tool"}}}'))
        with patch("sys.stdin", fake_stdin), contextlib.redirect_stdout(output):
            self.assertEqual(main(["-", "--format", "json"]), 0)
        self.assertEqual(json.loads(output.getvalue())["summary"]["servers"], 1)


if __name__ == "__main__":
    unittest.main()
