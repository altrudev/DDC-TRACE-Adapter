import time
import pytest

from ddc_trace_adapter.adapter import sign_trace_record

agentrust_trace = pytest.importorskip("agentrust_trace")


def source():
    return {
        "schema": "ddc-trace-source/0.1",
        "issued_at": int(time.time()),
        "subject": "spiffe://altru.dev/ddc/scientific-investigator",
        "source_event_id": "INV-SCI-CONFORMANCE-0001",
        "model": {"provider": "example", "model_id": "review-model"},
        "runtime": {"measurement": "sha256:" + "1" * 64},
        "policy": {
            "bundle_hash": "sha256:" + "2" * 64,
            "enforcement_mode": "enforce",
        },
        "data_class": "internal",
        "build_provenance": {
            "slsa_level": 0,
            "digest": "sha256:" + "3" * 64,
        },
        "appraisal": {
            "status": "none",
            "verifier": "https://ddcal.ca/",
        },
        "references": [{
            "rel": "behavior-trace",
            "id": "INV-SCI-CONFORMANCE-0001",
            "resolver": "Altru.dev",
            "digest": "sha256:" + "4" * 64,
        }],
    }


def test_reference_library_signs_and_verifies():
    key = agentrust_trace.generate_key()
    signed = sign_trace_record(source(), key)
    assert signed["signature"]
    assert signed["cnf"]["jwk"]["kty"] == "OKP"
