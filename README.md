# Transiever.ManageSieve

Transiever.ManageSieve is a .NET-native, async-first client for the ManageSieve protocol
defined by RFC 5804.

The client implements TCP and TLS transport, streaming response parsing, SASL
authentication, session-state validation, timeouts, and the RFC 5804 command
surface.

## Available API surface

`IManageSieveClient` exposes:

* Connect, capability refresh, STARTTLS, authentication, and unauthentication
* HAVESPACE quota preflight
* List and retrieve scripts
* Validate and upload scripts
* Activate a script or disable Sieve processing
* Rename and delete scripts
* NOOP, logout, and asynchronous disposal

Script content uses `ReadOnlyMemory<byte>` because ManageSieve literals are
octet-counted and must not be altered by text conversion.

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

The default security mode is `StartTlsRequired` on port `4190`. Plaintext mode
is explicit, and `ManageSievePlainAuthenticator` refuses to send credentials
unless the connection is protected by TLS. Normal platform certificate
validation is always used by the public client.

## Build and test

```bash
dotnet build Transiever.ManageSieve.slnx
dotnet test Transiever.ManageSieve.slnx
```

The solution has three test layers:

* `Transiever.ManageSieve.UnitTest` is deterministic and requires no network or Docker.
* `Transiever.ManageSieve.IntegrationTest` builds a pinned Dovecot/Pigeonhole image with
  Testcontainers. It is skipped when the Docker CLI or daemon is unavailable.
* `Transiever.ManageSieve.LiveTest` is skipped unless explicitly enabled.

Live-provider configuration is read only from environment variables:

```text
TRANSIEVER_LIVE_TESTS=true
TRANSIEVER_LIVE_HOST=sieve.example.com
TRANSIEVER_LIVE_PORT=4190
TRANSIEVER_LIVE_USERNAME=user@example.com
TRANSIEVER_LIVE_PASSWORD=secret
TRANSIEVER_LIVE_SECURITY_MODE=StartTlsRequired
```

`TRANSIEVER_LIVE_PORT` and `TRANSIEVER_LIVE_SECURITY_MODE` are optional. Live
tests are read-only by default. Guarded upload/rename/delete coverage requires
the additional `TRANSIEVER_LIVE_WRITES=true` flag. Live tests never call
`SETACTIVE`.

Each live write test snapshots script names, active state, and content hashes,
uses unique `transiever-test-{guid}` names, and deletes only inactive names it
created after the snapshot. Existing scripts are never overwritten, renamed,
activated, deactivated, or deleted. If cleanup fails, the test reports the
exact temporary names for manual removal; broad prefix cleanup is intentionally
not attempted.

## Relationship to SieveRuler

`Transiever.SieveRuler` uses this API to retrieve existing scripts, inspect server
capabilities, validate candidates, upload staged scripts, and explicitly
activate them.

The current pre-publication integration uses a temporary sibling
`ProjectReference`. The intended published dependency remains a versioned NuGet
package.

`Transiever.SieveRuler` remains responsible for parsing and preserving existing
Sieve, reconciling rules, presenting previews, and deciding whether deployment
is safe. `Transiever.OutlookResiever` is a source adapter above
`Transiever.SieveRuler`. `Transiever.ManageSieve` owns only ManageSieve protocol
behavior.

See [AGENTS.md](AGENTS.md) for architecture and contribution guidance.
