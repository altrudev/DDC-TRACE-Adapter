# DDC source evidence envelope

The adapter accepts only a sanitized JSON object with schema `ddc-trace-source/0.1`.

Required inputs include the scientific workload subject, source-event ID, exact model identity, software measurement digest, policy bundle hash and enforcement mode, data classification, build provenance digest, verifier identity, and at least one external DDC evidence reference.

The adapter deliberately forces:

```json
{
  "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
  "runtime": {"platform": "software-only"},
  "origin": {
    "kind": "third-party-control-plane",
    "producer": "DDC Scientific Investigator"
  }
}
```

It never upgrades imported DDC/DSR evidence to hardware attestation.
