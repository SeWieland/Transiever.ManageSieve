# Transiever.ManageSieve

Cross-platform .NET library for inspecting and managing server-side Sieve scripts
through the RFC 5804 ManageSieve protocol.

The client implements TCP and TLS transport, streaming response parsing, SASL authentication,
session-state validation, timeouts, and the RFC 5804 command surface.

## Documentation Map

Start here, then follow the focused guides:

* [library guide](src/Transiever.ManageSieve/README.md) for the public API, script operations, and security behavior.
* [architecture](docs/architecture.md) for protocol layering, parsing constraints, public API rules, and repository boundaries.
* [testing](docs/testing.md) for unit, Docker-backed integration, and opt-in live-provider test policy.

## Repository Layout

```text
src/Transiever.ManageSieve/                 Packable library
src/Transiever.ManageSieve.UnitTest/        Parser, serializer, session, and API tests
src/Transiever.ManageSieve.IntegrationTest/ Docker-backed Dovecot/Pigeonhole tests
src/Transiever.ManageSieve.LiveTest/        Explicitly enabled live-provider tests
```

## Feature Summary

* Stateful async client API for the RFC 5804 command surface.
* Streaming parser for fragmented responses, quoted strings, response codes, and byte-counted literals.
* TCP, STARTTLS, and implicit TLS transport with platform certificate validation.
* SASL authentication abstraction with PLAIN support.
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
Plaintext mode is explicit, and `ManageSievePlainAuthenticator` refuses to send credentials unless the connection is protected by TLS.
Normal platform certificate validation is always used by the public client.

## Development

```bash
dotnet build Transiever.ManageSieve.slnx
dotnet test Transiever.ManageSieve.slnx
```

Testing details live in [docs/testing.md](docs/testing.md).

## Publication Note

The current development build is consumed by sibling `Transiever.SieveRuler`
through a temporary project reference.
This must become a versioned package reference before independent publication.

See [AGENTS.md](AGENTS.md) for repository maintenance guidance.
