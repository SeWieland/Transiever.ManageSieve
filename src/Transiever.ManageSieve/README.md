# Transiever.ManageSieve

`Transiever.ManageSieve` provides an async-first .NET 10 client for ManageSieve.

It implements the RFC 5804 command surface over TCP, STARTTLS, or implicit TLS.
The protocol reader handles these response details:

* Fragmented input.
* Quoted strings.
* Byte-counted literals.
* Capability data.
* `OK`, `NO`, and `BYE` completion responses.

## Main contracts

* `IManageSieveClient` represents one stateful ManageSieve session.
* `IManageSieveClientFactory` creates independently owned clients.
* `IManageSieveAuthenticator` represents a SASL challenge/response mechanism.
* `ManageSieveClientOptions` configures endpoint, security mode, and timeouts.
* `ManageSieveCapabilities` exposes standard capabilities and preserves unknown capability values.
* `ManageSieveCommandResult` exposes server messages, response codes, and warnings.
* `ManageSievePlainAuthenticator` provides SASL PLAIN and is rejected on an unsecured connection.
* Typed exceptions distinguish connection, authentication, protocol, and command failures.

Architecture and protocol constraints are documented in [../../docs/architecture.md](../../docs/architecture.md).
Testing policy is documented in [../../docs/testing.md](../../docs/testing.md).

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
