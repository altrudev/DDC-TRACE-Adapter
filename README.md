# DDC TRACE Adapter

Public TRACE v0.2 adapter for **DDC Scientific Investigator**, created by **Valentyn Rukhaylo / Altru.dev**.

This repository contains only the public interoperability adapter. It does **not** contain proprietary DDC Runtime, DDC Radial, DSR, or DDCRE implementation code.

The adapter maps a sanitized DDC scientific-execution evidence envelope into a signed TRACE Trust Record using AgenTrust's released reference library. Imported DDC evidence is represented as `origin.kind: third-party-control-plane` with `runtime.platform: software-only`; it is never presented as hardware attestation.

## Status

Initial adapter implementation. TRACE conformance level is intentionally **not claimed yet**. A level will be declared only after the released `agentrust-trace-tests` suite passes at that level.

## Ownership

Adapter implementation: © 2026 Valentyn Rukhaylo / Altru.dev.

Licensed under Apache-2.0. DDC Scientific Investigator and the wider DDC implementation remain separately owned and are not licensed by this repository.
