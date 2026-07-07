# AGENTS.md

## Project Boundary

`Transiever.ManageSieve` is a cross-platform .NET protocol library for RFC 5804 ManageSieve.
It owns streaming parsing, command serialization, TCP/TLS transport, SASL authentication, session-state validation, and structured command results.

It must not reference Outlook, SieveRuler rule models, provider-specific policy, or any mail-client stack outside ManageSieve.
Consumers own reconciliation and deployment policy.

## Agent Index

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

## Canonical Docs

| Topic                                                                   | Owner                                  |
| ----------------------------------------------------------------------- | -------------------------------------- |
| Public API, script operations, and security behavior                    | `src/Transiever.ManageSieve/README.md` |
| Protocol layering, parser constraints, API rules, and security defaults | `docs/architecture.md`                 |
| Unit, Docker-backed integration, and live-provider test policy          | `docs/testing.md`                      |
| Public overview, docs map, example, and development commands            | `README.md`                            |
| Repo boundary, validation, release constraints, and agent workflow      | `AGENTS.md`                            |

Do not update every document by default.
Update the canonical owner for the changed behavior.

## Validation

```bash
dotnet restore Transiever.ManageSieve.slnx
dotnet build Transiever.ManageSieve.slnx
dotnet test Transiever.ManageSieve.slnx
```

Unit tests require no network.
Docker-backed integration tests skip when Docker is unavailable.
Live-provider tests stay skipped unless explicitly enabled through environment variables.
Normal CI must never require live provider credentials.

## Non-Negotiables

`IManageSieveClient` represents one stateful RFC 5804 connection.
`IManageSieveClientFactory` creates independently owned clients.
Script content uses `ReadOnlyMemory<byte>` because protocol literals are octet-counted.

ManageSieve extensions and SASL mechanisms must be capability-driven.
Add SASL mechanisms only with deterministic challenge tests.

Never send plaintext credentials over an unencrypted connection by default.
Use normal .NET certificate validation in the public client.
Do not expose an accept-any-certificate switch through the primary API.
Redact credentials and script contents from diagnostics.

`Transiever.SieveRuler` consumes this library through the published NuGet package.
`Transiever.OutlookResiever` consumes SieveRuler and does not reference this library directly.

## When Docs Change

Update `AGENTS.md` only for agent workflow, repo boundary, validation, release constraints, or non-negotiable safety rules.
Update focused docs and READMEs through the ownership table above.
Keep documentation accurate, but do not duplicate the same contract across every Markdown file.

GitHub Actions are repository-local.
Releases are manual, stable from `main`, and `beta` from `dev`.
NuGet publishing uses GitHub OIDC trusted publishing; do not add a `NUGET_TOKEN` secret.
