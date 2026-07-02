# AGENTS.md

## Project

`Transiever.ManageSieve` is a cross-platform .NET protocol library for RFC 5804 ManageSieve.
It owns these protocol concerns:

* Streaming parsing.
* Command serialization.
* TCP/TLS transport.
* SASL authentication.
* Session-state validation.
* Structured command results.

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

## Protocol and Security

Protocol constraints and layering are documented once in `docs/architecture.md`.
Keep that file authoritative when parser, transport, session-state, or public
API behavior changes.

Security defaults are conservative:

* Never send plaintext credentials over an unencrypted connection by default.
* Use normal .NET certificate validation in the public client.
* Do not expose an accept-any-certificate switch through the primary API.
* Redact credentials and script contents from diagnostics.

## Commands

```bash
dotnet restore Transiever.ManageSieve.slnx
dotnet build Transiever.ManageSieve.slnx
dotnet test Transiever.ManageSieve.slnx
```

Unit tests require no network.
Docker-backed integration tests skip when Docker is unavailable.
They build a pinned Dovecot/Pigeonhole image.
They use the image's bundled test certificate through the internal certificate-validation seam.
They wait on the mapped host port instead of requiring extra socket tooling inside the container.
Live-provider tests stay skipped unless explicitly enabled through environment variables.
Testing policy lives in `docs/testing.md`.

## GitHub CI and Releases

GitHub Actions are repository-local because this repository must publish and build independently from the umbrella workspace.

`ci.yml` runs restore, Release build, and tests on pull requests and pushes to `main` and `dev`.
Live-provider tests remain skipped unless their explicit environment variables are configured,
and normal CI must never require live provider credentials.

`pr-title.yml` validates pull request titles as Conventional Commits so squash merges can drive semantic-release versioning.

`release.yml` is manual only.
Run it from `main` for stable releases and from `dev` for `beta` prereleases.
The first release is expected to start on `dev` and naturally produce `1.0.0-beta.1`; do not seed a `0.1.0` tag for release automation.

Release publishing uses `semantic-release` and `@droidsolutions-oss/semantic-release-nuget` with `usePackageVersion: true`.
Calculated versions are passed to `dotnet pack` without committing version changes back into project files.

NuGet.org publishing uses trusted publishing through GitHub OIDC, not a long-lived NuGet API key.
Do not add a `NUGET_TOKEN` secret for this workflow.
Configure the GitHub repository variable `NUGET_USER` to the NuGet.org username or organization that owns `Transiever.ManageSieve`.

The NuGet.org trusted publishing policy for this repository must match:

```text
Repository owner: <GitHub owner or organization>
Repository: ManageSieve
Workflow: release.yml
Environment: release
```

The release workflow must keep `id-token: write`, `environment: release`, and the `NuGet/login@v1` step.
That step exchanges the GitHub OIDC token for a temporary `NUGET_API_KEY`.
The workflow passes that key to the semantic-release NuGet plugin through `tokenEnvVar: "NUGET_API_KEY"`.

## Repository Boundaries

`Transiever.SieveRuler` consumes this library for remote inspection, validation, upload, activation, and rollback primitives.
`Transiever.OutlookResiever` consumes SieveRuler and does not reference this library directly.

This library provides protocol operations and structured server results.
It does not decide how rules are merged.
It does not decide which content is application-owned.
It does not decide whether a candidate should be activated or how provider UI compatibility is preserved.

SieveRuler consumes this library through the published NuGet package.

## Change Style

Make incremental changes backed by tests.
Prefer small protocol-focused types, clear state transitions, and explicit failure behavior over broad abstractions.
Update this file, the root README, package README, architecture, and testing docs when their contracts change.
