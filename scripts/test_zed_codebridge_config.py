#!/usr/bin/env python3
"""Negative tests for the credential-free Zed CodeBridge config gate."""
import json
import unittest

from check_zed_codebridge_config import verify_config

GOOD = {"context_servers": {"CodeBridge": {"url": "https://kmjtechno.com/mcp"}}}


class ZedCodeBridgeConfigTests(unittest.TestCase):
    def test_canonical_credential_free_entry_passes(self):
        self.assertTrue(verify_config(json.dumps(GOOD)))

    def test_other_non_codebridge_settings_are_preserved(self):
        self.assertTrue(verify_config(json.dumps({**GOOD, "ui_font_size": 14})))

    def test_wrong_endpoint_fails(self):
        for url in ("http://kmjtechno.com/mcp", "https://kmjtechno.com/mcp/",
                    "https://example.com/mcp"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                verify_config(json.dumps({"context_servers": {"CodeBridge": {"url": url}}}))

    def test_embedded_auth_headers_or_tokens_fail(self):
        for key in ("headers", "authorization", "token", "env"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                verify_config(json.dumps({"context_servers": {"CodeBridge": {
                    "url": "https://kmjtechno.com/mcp", key: "secret"}}}))

    def test_duplicate_or_misnamed_servers_fail(self):
        for raw in (
            '{"context_servers":{"CodeBridge":{"url":"https://kmjtechno.com/mcp"},"codebridge":{"url":"https://kmjtechno.com/mcp"}}}',
            '{"context_servers":{"codebridge":{"url":"https://kmjtechno.com/mcp"}}}',
            '{"context_servers":{"CodeBridge":{"url":"https://kmjtechno.com/mcp"},"CodeBridge":{"url":"https://kmjtechno.com/mcp"}}}',
        ):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                verify_config(raw)

    def test_missing_or_malformed_configuration_fails(self):
        for raw in ("{}", "[]", "{", '{"context_servers":[]}',
                    '{"context_servers":{"CodeBridge":null}}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                verify_config(raw)


if __name__ == "__main__":
    unittest.main()
