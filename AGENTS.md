# AGENTS.md

## Project

`Transiever.ManageSieve` is a cross-platform .NET protocol library for RFC 5804
ManageSieve. It owns streaming parsing, command serialization, TCP/TLS
transport, SASL authentication, session-state validation, and structured command
results.

It must not reference Outlook, SieveRuler rule models, provider-specific policy,
or any mail-client stack outside ManageSieve.

## Layout

```text
Transiever.ManageSieve.slnx
docs/architecture.md
docs/testing.md
src/
  Transiever.ManageSieve/
  Transiever.ManageSieve.UnitTest/
  Transiever.ManageSieve.IntegrationTest/
  Transiever.ManageSieve.LiveTest/
```

The library targets `net10.0`.
Nullable reference types and implicit global usings are enabled.

## Contracts

`IManageSieveClient` represents one stateful RFC 5804 connection and exposes the
command surface documented in `src/Transiever.ManageSieve/README.md`.

Script content uses `ReadOnlyMemory<byte>` because protocol literals are
octet-counted. Keep encoding decisions outside the protocol contract.

ManageSieve extensions and SASL mechanisms must be capability-driven. Add SASL
mechanisms only with deterministic challenge tests.

Do not add separate interfaces for every command. Add abstractions only for real
collaborators such as authentication, transport, parsing, or client creation.

## Protocol And Security

Protocol constraints and layering are documented once in `docs/architecture.md`.
Keep that file authoritative when parser, transport, session-state, or public
API behavior changes.

Security defaults are conservative:

* never send plaintext credentials over an unencrypted connection by default;
* use normal .NET certificate validation in the public client;
* do not expose an accept-any-certificate switch through the primary API;
* redact credentials and script contents from diagnostics.

## Commands

```bash
dotnet restore Transiever.ManageSieve.slnx
dotnet build Transiever.ManageSieve.slnx
dotnet test Transiever.ManageSieve.slnx
```

Unit tests require no network.
Docker-backed integration tests skip when Docker is unavailable.
Live-provider tests stay skipped unless explicitly enabled through environment variables.
Testing policy lives in `docs/testing.md`.

## Repository Boundaries

`Transiever.SieveRuler` consumes this library for remote inspection, validation,
upload, activation, and rollback primitives. `Transiever.OutlookResiever` consumes
SieveRuler and does not reference this library directly.

This library provides protocol operations and structured server results. It does
not decide how rules are merged, which content is application-owned, whether a
candidate should be activated, or how provider UI compatibility is preserved.

Until publication, SieveRuler has one temporary sibling project reference to this
repository. Replace it with a versioned package before release.

## Change Style

Make incremental changes backed by tests. Prefer small protocol-focused types,
clear state transitions, and explicit failure behavior over broad abstractions.
Update this file, the root README, package README, architecture, and testing docs
when their contracts change.
