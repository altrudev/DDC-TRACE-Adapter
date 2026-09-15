import pytest

from ddc_trace_adapter.adapter import (
    SourceEvidenceError,
    build_unsigned_trace_record,
    validate_source,
)


def source():
    return {
        "schema": "ddc-trace-source/0.1",
        "issued_at": 1789416000,
        "subject": "spiffe://altru.dev/ddc/scientific-investigator",
        "source_event_id": "INV-SCI-0003/42f5ac7bd8e64910a3c6e8f12470bd35",
        "model": {"provider": "example", "model_id": "review-model"},
        "runtime": {"measurement": "sha256:" + "a" * 64},
        "policy": {
            "bundle_hash": "sha256:" + "b" * 64,
            "enforcement_mode": "enforce",
            "version": "ddc-scientific-v0.6",
        },
        "data_class": "internal",
        "build_provenance": {
            "slsa_level": 0,
            "digest": "sha256:" + "c" * 64,
        },
        "appraisal": {
            "status": "none",
            "verifier": "https://ddcal.ca/",
        },
        "references": [{
            "rel": "behavior-trace",
            "id": "INV-SCI-0003",
            "resolver": "Altru.dev",
            "digest": "sha256:" + "d" * 64,
        }],
    }


def test_maps_to_software_only_third_party_record():
    record = build_unsigned_trace_record(source(), now=1789416001)
    assert record["eat_profile"] == "tag:agentrust-io.com,2026:trace-v0.2"
    assert record["runtime"]["platform"] == "software-only"
    assert record["origin"]["kind"] == "third-party-control-plane"


def test_never_upgrades_imported_ddc_to_hardware_attestation():
    s = source()
    s["runtime"]["platform"] = "intel-tdx"
    record = build_unsigned_trace_record(s, now=1789416001)
    assert record["runtime"]["platform"] == "software-only"


def test_requires_explicit_model_identity():
    s = source()
    del s["model"]["model_id"]
    with pytest.raises(SourceEvidenceError):
        validate_source(s)


def test_requires_build_digest():
    s = source()
    del s["build_provenance"]["digest"]
    with pytest.raises(SourceEvidenceError):
        validate_source(s)


def test_requires_external_evidence_reference():
    s = source()
    s["references"] = []
    with pytest.raises(SourceEvidenceError):
        validate_source(s)
