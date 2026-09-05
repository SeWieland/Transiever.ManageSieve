# Transiever.ManageSieve

`Transiever.ManageSieve` provides an async-first .NET 10 client for ManageSieve.

It implements the RFC 5804 command surface over TCP, STARTTLS, or implicit TLS.
The protocol reader handles these response details:

* Fragmented input.
* Quoted strings.
* Byte-counted literals.
* Capability data.
* `OK`, `NO`, and `BYE` completion responses.

## Install

```bash
dotnet add package Transiever.ManageSieve
```

The package is available on [NuGet.org](https://www.nuget.org/packages/Transiever.ManageSieve).
For a human-oriented overview and tool picker, see the [Transiever ManageSieve guide](https://sewieland.github.io/transiever/dotnet-managesieve-client/).

## Main contracts

* `IManageSieveClient` represents one stateful ManageSieve session.
* `IManageSieveClientFactory` creates independently owned clients.
* `IManageSieveAuthenticator` represents a SASL challenge/response mechanism.
* `ManageSieveClientOptions` configures endpoint, security mode, and timeouts.
* `ManageSieveCapabilities` exposes standard capabilities and preserves unknown capability values.
* `ManageSieveCommandResult` exposes server messages, response codes, and warnings.
* `ManageSievePlainAuthenticator` provides SASL PLAIN and is rejected on an unsecured connection.
* `ManageSieveScramSha256Authenticator` provides the protected `SCRAM-SHA-256` password exchange.
* Typed exceptions distinguish connection, authentication, protocol, and command failures.

See the [authentication guide](https://github.com/SeWieland/Transiever.ManageSieve/blob/main/docs/authentication.md) for the SASL lifecycle, security, memory ownership, diagnostics, and failure contract.

See the [architecture guide](https://github.com/SeWieland/Transiever.ManageSieve/blob/main/docs/architecture.md) for protocol constraints and the [testing guide](https://github.com/SeWieland/Transiever.ManageSieve/blob/main/docs/testing.md) for test policy.

### SCRAM-SHA-256

Construct `ManageSieveScramSha256Authenticator` with a printable-ASCII user name, password, and optional authorization identity:

```csharp
IManageSieveAuthenticator authenticator =
    new ManageSieveScramSha256Authenticator("user", password, authorizationIdentity: null);

await client.StartTlsAsync();
await client.AuthenticateAsync(authenticator);
```

The mechanism name is exactly `SCRAM-SHA-256`, and it refuses an unprotected connection.
User names, passwords, and authorization identities are limited to printable ASCII and 1,024 bytes; a user name is required, a password may be empty, and the authorization identity is optional.
The client uses an 18-byte cryptographically random nonce encoded with standard Base64 for production exchanges.
The deterministic nonce seam is internal test behavior and is not part of the public API.
The exchange contract, bounds, proof validation, diagnostics, and cleanup ownership are defined in the [authentication guide](https://github.com/SeWieland/Transiever.ManageSieve/blob/main/docs/authentication.md).

## Script operations

```csharp
IReadOnlyList<ManageSieveScriptInfo> scripts =
    await client.ListScriptsAsync(cancellationToken);

ManageSieveScript active = await client.GetScriptAsync("active", cancellationToken);

ManageSieveCommandResult validation =
    await client.CheckScriptAsync(candidateBytes, cancellationToken);

await client.PutScriptAsync("candidate", candidateBytes, cancellationToken);
await client.SetActiveScriptAsync("candidate", cancellationToken);
```

Pass `null` to `SetActiveScriptAsync` to disable Sieve processing, matching the empty script-name behavior of `SETACTIVE`.

Script payloads are bytes rather than strings.
Literal sizes are byte counts, and downloaded content must be preservable exactly.

Consumers own reconciliation and deployment policy.
`Transiever.ManageSieve` does not parse, merge, optimize, or silently replace Sieve content.

The public client always uses platform TLS validation.
A certificate-validation injection point exists only as an internal test seam.
Disposable integration tests use it to trust the exact certificate presented by the test container.
This avoids creating an accept-any-certificate public option.

`Transiever.SieveRuler` consumes this library through the published NuGet package.
Its Docker integration test is granted internal access only to pin the test container certificate.
