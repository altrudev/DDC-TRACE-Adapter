# DDC Scientific Investigator integration with TRACE

This integration exports sanitized DDC Scientific Investigator execution evidence as a signed TRACE v0.2 software-only Trust Record using the released `agentrust-trace` package.

It does not claim that DDC evidence is hardware attestation, that TRACE verifies scientific correctness, or that TRACE conformance establishes the validity of a DDC scientific-state transition.

## Run it

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
```

Emit and verify with `ddc-trace`, then run the released `agentrust-trace-tests` suite at the level actually passed.

## What is verified

The adapter emits `origin.kind: third-party-control-plane` and `runtime.platform: software-only`, signs through the TRACE reference library, and binds the source DDC event through TRACE source-event metadata and references.

A Marketplace conformance level must not be declared until the released suite passes.
