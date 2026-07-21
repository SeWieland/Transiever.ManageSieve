# Transiever.ManageSieve

Cross-platform .NET library for inspecting and managing server-side Sieve scripts through the RFC 5804 ManageSieve protocol.
It also ships `msieve`, a tiny policy-neutral CLI for direct server inspection and basic script operations.

## Install

Install the self-contained Windows build with Scoop:

```powershell
scoop bucket add transiever https://github.com/SeWieland/Transiever.ScoopBucket
scoop install transiever/msieve
```

Install the self-contained Linux x64 build with Homebrew:

```bash
brew install SeWieland/transiever/msieve
```

The client implements these ManageSieve concerns:

* TCP and TLS transport.
* Streaming response parsing.
* SASL authentication.
* Session-state validation.
* Timeouts.
* The RFC 5804 command surface.

## Documentation Map

Start here, then follow the focused guides:

* [library guide](src/Transiever.ManageSieve/README.md) for public API, script operations, and security behavior.
* [CLI guide](src/Transiever.ManageSieve.Cli/README.md) for `msieve` commands, options, and operator workflow.
* [architecture](docs/architecture.md) for protocol layering, parsing constraints, public API rules, and repository boundaries.
* [testing](docs/testing.md) for unit, Docker-backed integration, and opt-in live-provider test policy.

## Repository Layout

```text
src/Transiever.ManageSieve/                 Packable library
src/Transiever.ManageSieve.Cli/             Packable msieve CLI
src/Transiever.ManageSieve.Cli.UnitTest/    CLI parsing, configuration, and command tests
src/Transiever.ManageSieve.UnitTest/        Parser, serializer, session, and API tests
src/Transiever.ManageSieve.IntegrationTest/ Docker-backed Dovecot/Pigeonhole tests
src/Transiever.ManageSieve.LiveTest/        Explicitly enabled live-provider tests
```

## Feature Summary

* Stateful async client API for the RFC 5804 command surface.
* Streaming parser for fragmented responses, quoted strings, response codes, and byte-counted literals.
* TCP, STARTTLS, and implicit TLS transport with platform certificate validation.
* SASL authentication abstraction with PLAIN support.
* `msieve` CLI commands for capabilities, list, get, check, put, activate, deactivate, and delete.
* Deterministic unit tests plus optional Docker and live-provider coverage.
  Docker coverage uses a pinned Dovecot/Pigeonhole container and pins the container certificate through an internal test seam.

## Example

```csharp
ManageSieveClientOptions options = new()
{
    Host = "sieve.example.com"
};

IManageSieveClientFactory factory = new ManageSieveClientFactory();
await using IManageSieveClient client = factory.CreateClient(options);

await client.ConnectAsync();
await client.StartTlsAsync();
await client.AuthenticateAsync(
    new ManageSievePlainAuthenticator("user@example.com", password));

IReadOnlyList<ManageSieveScriptInfo> scripts =
    await client.ListScriptsAsync();
```

The default security mode is `StartTlsRequired` on port `4190`.
Plaintext mode is explicit.
`ManageSievePlainAuthenticator` refuses to send credentials unless the connection is protected by TLS.
Normal platform certificate validation is always used by the public client.

## Development

```bash
dotnet build Transiever.ManageSieve.slnx
dotnet test Transiever.ManageSieve.slnx
dotnet run --project src/Transiever.ManageSieve.Cli -- --help
```

Testing details live in [docs/testing.md](docs/testing.md).

## Publication Note

GitHub Actions produce releases.
Stable releases come from `main`.
Beta prereleases come from `dev` and may be unstable.
Releases publish NuGet packages and attach trimmed Native-AOT `msieve` assets for `win-x64`, `win-x86`, and `linux-x64`.

`Transiever.SieveRuler` consumes this library through the published NuGet package.
