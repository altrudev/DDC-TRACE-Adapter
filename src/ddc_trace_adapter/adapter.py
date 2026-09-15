from __future__ import annotations

import copy
import time
from typing import Any

TRACE_PROFILE = "tag:agentrust-io.com,2026:trace-v0.2"
SOURCE_SCHEMA = "ddc-trace-source/0.1"


class SourceEvidenceError(ValueError):
    pass


def _require_object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SourceEvidenceError(f"{name} must be an object")
    return value


def _require_string(obj: dict[str, Any], key: str, path: str) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value:
        raise SourceEvidenceError(f"{path}.{key} must be a non-empty string")
    return value


def _digest(value: str, path: str) -> str:
    valid = (
        value.startswith("sha256:") and len(value) == 71
        or value.startswith("sha384:") and len(value) == 103
    )
    if not valid:
        raise SourceEvidenceError(f"{path} must be sha256:<hex> or sha384:<hex>")
    try:
        bytes.fromhex(value.split(":", 1)[1])
    except ValueError as exc:
        raise SourceEvidenceError(f"{path} digest is not hexadecimal") from exc
    return value


def validate_source(source: dict[str, Any]) -> None:
    if not isinstance(source, dict):
        raise SourceEvidenceError("source evidence must be a JSON object")
    if source.get("schema") != SOURCE_SCHEMA:
        raise SourceEvidenceError(f"schema must equal {SOURCE_SCHEMA!r}")

    issued_at = source.get("issued_at")
    if isinstance(issued_at, bool) or not isinstance(issued_at, int):
        raise SourceEvidenceError("issued_at must be Unix epoch seconds")

    subject = _require_string(source, "subject", "$")
    if not (subject.startswith("spiffe://") or subject.startswith("did:")):
        raise SourceEvidenceError("subject must be a SPIFFE or DID URI")
    _require_string(source, "source_event_id", "$")

    model = _require_object(source.get("model"), "model")
    _require_string(model, "provider", "$.model")
    _require_string(model, "model_id", "$.model")
    if "weights_digest" in model:
        _digest(
            _require_string(model, "weights_digest", "$.model"),
            "$.model.weights_digest",
        )

    runtime = _require_object(source.get("runtime"), "runtime")
    _digest(
        _require_string(runtime, "measurement", "$.runtime"),
        "$.runtime.measurement",
    )

    policy = _require_object(source.get("policy"), "policy")
    _digest(
        _require_string(policy, "bundle_hash", "$.policy"),
        "$.policy.bundle_hash",
    )
    mode = _require_string(policy, "enforcement_mode", "$.policy")
    if mode not in {"enforce", "advisory", "silent", "declared"}:
        raise SourceEvidenceError("unsupported policy.enforcement_mode")

    _require_string(source, "data_class", "$")

    build = _require_object(source.get("build_provenance"), "build_provenance")
    slsa = build.get("slsa_level")
    if isinstance(slsa, bool) or not isinstance(slsa, int) or slsa not in range(4):
        raise SourceEvidenceError("build_provenance.slsa_level must be 0..3")
    _digest(
        _require_string(build, "digest", "$.build_provenance"),
        "$.build_provenance.digest",
    )

    appraisal = _require_object(source.get("appraisal"), "appraisal")
    _require_string(appraisal, "verifier", "$.appraisal")

    refs = source.get("references")
    if not isinstance(refs, list) or not refs:
        raise SourceEvidenceError("references must be a non-empty array")
    for i, ref in enumerate(refs):
        ref = _require_object(ref, f"references[{i}]")
        _require_string(ref, "rel", f"$.references[{i}]")
        _require_string(ref, "id", f"$.references[{i}]")
        _require_string(ref, "resolver", f"$.references[{i}]")
        if "digest" in ref:
            _digest(
                _require_string(ref, "digest", f"$.references[{i}]"),
                f"$.references[{i}].digest",
            )


def build_unsigned_trace_record(
    source: dict[str, Any], *, now: int | None = None
) -> dict[str, Any]:
    validate_source(source)
    issued = int(time.time()) if now is None else now

    runtime = {
        "platform": "software-only",
        "measurement": source["runtime"]["measurement"],
    }
    if source["runtime"].get("nonce"):
        runtime["nonce"] = source["runtime"]["nonce"]

    appraisal = copy.deepcopy(source["appraisal"])
    appraisal.setdefault("status", "none")

    record: dict[str, Any] = {
        "eat_profile": TRACE_PROFILE,
        "iat": issued,
        "subject": source["subject"],
        "model": copy.deepcopy(source["model"]),
        "runtime": runtime,
        "policy": copy.deepcopy(source["policy"]),
        "data_class": source["data_class"],
        "build_provenance": copy.deepcopy(source["build_provenance"]),
        "appraisal": appraisal,
        "origin": {
            "kind": "third-party-control-plane",
            "producer": "DDC Scientific Investigator",
            "source_event_id": source["source_event_id"],
            "ingested_at": issued,
        },
        "references": copy.deepcopy(source["references"]),
    }

    if source.get("tool_transcript") is not None:
        record["tool_transcript"] = copy.deepcopy(source["tool_transcript"])

    return record


def sign_trace_record(
    source: dict[str, Any], private_key: Any, *, now: int | None = None
) -> dict[str, Any]:
    from agentrust_trace import sign_record, verify_record

    unsigned = build_unsigned_trace_record(source, now=now)
    signed = sign_record(unsigned, private_key)
    verify_record(signed, public_key_or_jwk=private_key.public_key())
    return signed
