# Transiever.ManageSieve

`Transiever.ManageSieve` provides an async-first .NET 10 client for ManageSieve.

It implements the RFC 5804 command surface over TCP, STARTTLS, or implicit TLS.
The protocol reader handles fragmented input, quoted strings, byte-counted
literals, capability data, and `OK`, `NO`, and `BYE` completion responses.

## Main contracts

* `IManageSieveClient` represents one stateful ManageSieve session.
* `IManageSieveClientFactory` creates independently owned clients.
* `IManageSieveAuthenticator` represents a SASL challenge/response mechanism.
* `ManageSieveClientOptions` configures endpoint, security mode, and timeouts.
* `ManageSieveCapabilities` exposes standard capabilities and preserves unknown
  capability values.
* `ManageSieveCommandResult` exposes server messages, response codes, and
  warnings.
* `ManageSievePlainAuthenticator` provides SASL PLAIN and is rejected on an
  unsecured connection.
* Typed exceptions distinguish connection, authentication, protocol, and
  command failures.

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

Pass `null` to `SetActiveScriptAsync` to disable Sieve processing, matching the
empty script-name behavior of `SETACTIVE`.

Script payloads are bytes rather than strings because literal sizes are byte
counts and downloaded content must be preservable exactly.

Consumers own reconciliation and deployment policy.
`Transiever.ManageSieve` does not parse, merge, optimize, or silently replace
Sieve content.

The public client always uses platform TLS validation. A certificate-validation
injection point exists only as an internal test seam so disposable integration
tests can trust their generated certificate without creating an
accept-any-certificate public option.

The initial `Transiever.SieveRuler` integration references this project
directly until a versioned NuGet package is available. Its Docker integration
test is granted internal access only to pin the generated test certificate.
