#!/usr/bin/env python3
"""Fail-closed, credential-free Zed CodeBridge project configuration gate.

This checks only the committed configuration, not OAuth, device identity,
project grants, actual network reachability or release readiness.
"""
import json
import sys
from pathlib import Path

EXPECTED_NAME = "CodeBridge"
EXPECTED_URL = "https://kmjtechno.com/mcp"


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def verify_config(raw):
    try:
        settings = json.loads(raw, object_pairs_hook=no_duplicate_keys)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"invalid or ambiguous JSON: {exc}") from exc
    if not isinstance(settings, dict):
        raise ValueError("Zed settings root must be an object")
    servers = settings.get("context_servers")
    if not isinstance(servers, dict):
        raise ValueError("context_servers must be an object")
    matches = [name for name in servers if name.casefold() == EXPECTED_NAME.casefold()]
    if matches != [EXPECTED_NAME]:
        raise ValueError("exactly one canonical CodeBridge server name is required")
    entry = servers[EXPECTED_NAME]
    if not isinstance(entry, dict) or set(entry) != {"url"}:
        raise ValueError("CodeBridge must contain only the remote URL, no headers or credentials")
    if entry["url"] != EXPECTED_URL:
        raise ValueError("CodeBridge endpoint must be the canonical HTTPS MCP URL")
    return True


def main():
    path = Path(__file__).resolve().parents[1] / ".zed" / "settings.json"
    try:
        verify_config(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"ZED_CODEBRIDGE_CONFIG=FAIL: {exc}", file=sys.stderr)
        return 1
    print("ZED_CODEBRIDGE_CONFIG=PASS_STATIC_ONLY")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
