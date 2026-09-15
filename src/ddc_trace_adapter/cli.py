from __future__ import annotations

import argparse
import json
from pathlib import Path


def _read_json(path: str):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _load_private_key(path: str):
    from cryptography.hazmat.primitives import serialization
    return serialization.load_pem_private_key(
        Path(path).read_bytes(), password=None
    )


def _load_public_key(path: str):
    from cryptography.hazmat.primitives import serialization

    value = Path(path).read_bytes()
    try:
        return serialization.load_pem_private_key(
            value, password=None
        ).public_key()
    except ValueError:
        return serialization.load_pem_public_key(value)


def emit(args) -> int:
    from .adapter import sign_trace_record

    signed = sign_trace_record(
        _read_json(args.input),
        _load_private_key(args.private_key),
    )
    Path(args.output).write_text(
        json.dumps(signed, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(args.output)
    return 0


def verify(args) -> int:
    from agentrust_trace import verify_record

    verify_record(
        _read_json(args.record),
        public_key_or_jwk=_load_public_key(args.public_key),
    )
    print("PASS: TRACE record signature, schema, profile and freshness verified")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="ddc-trace")
    sub = parser.add_subparsers(dest="command", required=True)

    e = sub.add_parser("emit")
    e.add_argument("--input", required=True)
    e.add_argument("--private-key", required=True)
    e.add_argument("--output", required=True)
    e.set_defaults(func=emit)

    v = sub.add_parser("verify")
    v.add_argument("--record", required=True)
    v.add_argument("--public-key", required=True)
    v.set_defaults(func=verify)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
