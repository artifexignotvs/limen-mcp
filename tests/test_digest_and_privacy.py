import json
import unittest

from limen_mcp.audit import parse_config
from limen_mcp.reporting import compare, sarif, snapshot


class DigestTests(unittest.TestCase):
    def audit(self, args):
        return parse_config(json.dumps({"mcpServers": {"private-name": {"command": "docker", "args": args}}}).encode())

    def rules(self, args):
        return {f.rule_id for f in self.audit(args).findings}

    def test_implicit_and_explicit_tags_are_mutable(self):
        for image in ("image", "image:latest", "image:1.2.3", "registry.invalid:5000/team/image:1.2.3"):
            with self.subTest(image=image):
                self.assertIn("LM048", self.rules(["run", image]))

    def test_sha256_form_is_recognized_but_privileges_still_reported(self):
        image = "registry.invalid/team/image:1.2.3@sha256:" + "a" * 64
        self.assertEqual(self.rules(["run", image]), set())
        self.assertEqual(self.rules(["run", "--privileged", image]), {"LM040"})

    def test_digest_malformed_or_unknown_algorithm_is_explicit(self):
        for image in ("image@sha256:abc", "image@sha512:" + "a" * 128, "image@sha256:" + "Z" * 64, "@sha256:" + "a" * 64):
            with self.subTest(image=image):
                self.assertEqual(self.rules(["create", image]), {"LM049"})

    def test_terminator_and_value_options_preserve_image_boundary(self):
        digest = "image@sha256:" + "b" * 64
        self.assertEqual(self.rules(["run", "--name", "private-name", "--", digest, "--privileged"]), set())
        self.assertEqual(self.rules(["run", "--network=bridge", digest]), set())

    def test_unsupported_option_never_guesses_image(self):
        self.assertEqual(self.rules(["run", "--future", "not-an-image", "image"]), {"LM090"})

    def test_missing_image_is_incomplete(self):
        for args in (["run"], ["create", "--"], ["run", "--name"]):
            with self.subTest(args=args):
                self.assertEqual(self.rules(args), {"LM090"})

    def test_new_exports_withhold_all_dynamic_material(self):
        source = {"mcpServers": {"private-server-secret": {
            "command": "/private/path/docker", "args": ["run", "-e", "PRIVATE_TOKEN=credential-secret", "registry-secret/image:latest"],
            "env": {"API_TOKEN": "environment-secret"}}}}
        report = parse_config(json.dumps(source).encode()).to_dict()
        for value in (sarif(report["findings"]), snapshot(report["findings"], "fixture")):
            text = json.dumps(value)
            for secret in ("private-server-secret", "/private/path", "credential-secret", "registry-secret", "environment-secret", "API_TOKEN", "PRIVATE_TOKEN"):
                self.assertNotIn(secret, text)

    def test_server_renaming_does_not_falsely_change_aggregate_baseline(self):
        first = parse_config(b'{"mcpServers":{"a":{"command":"npx","args":["pkg"]},"b":{"command":"local"}}}')
        second = parse_config(b'{"mcpServers":{"z":{"command":"npx","args":["pkg"]},"b":{"command":"local"}}}')
        self.assertNotEqual(first.findings[0].location, second.findings[0].location)
        diff = compare(snapshot(first.to_dict()["findings"], "fixture"), snapshot(second.to_dict()["findings"], "fixture"))
        self.assertEqual(diff["summary"]["unchanged"], 1)
        self.assertEqual(diff["summary"]["added"], 0)


if __name__ == "__main__":
    unittest.main()
