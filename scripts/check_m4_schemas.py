#!/usr/bin/env python3
"""Deterministic structural checks for the M4 REALNET-60 JSON Schemas."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schemas"

MASTER = "m4-realnet-manifest-v1.schema.json"
WRAPPERS = {
    "m4-campaign-v1.schema.json": "urn:kmj:omnidesk:m4:realnet-manifest:1.0.0",
    "m4-run-v1.schema.json": "urn:kmj:omnidesk:m4:realnet-manifest:1.0.0#/$defs/run",
    "m4-endpoint-v1.schema.json": "urn:kmj:omnidesk:m4:realnet-manifest:1.0.0#/$defs/endpointRecord",
    "m4-direct-attempt-v1.schema.json": "urn:kmj:omnidesk:m4:realnet-manifest:1.0.0#/$defs/directRecord",
    "m4-reconnect-v1.schema.json": "urn:kmj:omnidesk:m4:realnet-manifest:1.0.0#/$defs/reconnectRecord",
    "m4-artifact-v1.schema.json": "urn:kmj:omnidesk:m4:realnet-manifest:1.0.0#/$defs/artifactRecord",
}

EXPECTED_DEFS = {
    "gitSha",
    "sha256",
    "build",
    "campaign",
    "endpoint",
    "direct",
    "reconnect",
    "run",
    "artifact",
    "endpointRecord",
    "directRecord",
    "reconnectRecord",
    "artifactRecord",
}

SCENARIOS = {
    "T1_BROADBAND_BROADBAND",
    "T2_BROADBAND_CGNAT",
    "T3_CGNAT_CGNAT",
    "T4_RESTRICTIVE_NETWORK",
    "T5_IPV4_IPV6",
    "T6_RECONNECT",
}


def load(name: str) -> dict:
    path = SCHEMA_DIR / name
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    assert value["$schema"] == "https://json-schema.org/draft/2020-12/schema", name
    return value


def main() -> None:
    master = load(MASTER)
    assert master["$id"] == "urn:kmj:omnidesk:m4:realnet-manifest:1.0.0"
    assert master["additionalProperties"] is False

    defs = master["$defs"]
    missing = EXPECTED_DEFS - defs.keys()
    assert not missing, f"missing definitions: {sorted(missing)}"

    run = defs["run"]
    assert run["additionalProperties"] is False
    assert set(run["properties"]["scenario"]["enum"]) == SCENARIOS
    assert run["properties"]["endpoint_a"]["$ref"] == "#/$defs/endpointRecord"
    assert run["properties"]["endpoint_b"]["$ref"] == "#/$defs/endpointRecord"

    direct = defs["directRecord"]
    reconnect = defs["reconnectRecord"]
    artifact = defs["artifactRecord"]

    assert direct["additionalProperties"] is False
    assert reconnect["additionalProperties"] is False
    assert artifact["additionalProperties"] is False
    assert "UNKNOWN" not in direct["properties"]["failure_code"]["enum"]
    assert "RECONNECT_LOG" in artifact["properties"]["kind"]["enum"] or "RECONNECT_LOG" in defs["artifactRecord"]["properties"]["kind"]["enum"]

    runs = master["properties"]["runs"]
    assert runs["minItems"] == 60
    assert runs["minContains"] == 10

    # T2-T6 each add their own >=10 VALID-run constraint; T1 is on runs itself.
    assert len(master.get("allOf", [])) >= 5

    for name, expected_ref in WRAPPERS.items():
        wrapper = load(name)
        assert wrapper["$ref"] == expected_ref, f"{name}: wrong $ref"

    # Ensure every schema file is valid JSON and no duplicate $id is introduced.
    ids = set()
    for path in sorted(SCHEMA_DIR.glob("m4-*.schema.json")):
        schema = load(path.name)
        schema_id = schema.get("$id")
        if schema_id:
            assert schema_id not in ids, f"duplicate $id: {schema_id}"
            ids.add(schema_id)

    print("M4 schema conformance: PASS")


if __name__ == "__main__":
    main()
