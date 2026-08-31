# Transiever.ManageSieve Testing

This document is the canonical testing policy for the ManageSieve repository.

The architecture and protocol constraints live in [architecture](architecture.md).

## Test Layers

`Transiever.ManageSieve.UnitTest` is deterministic and requires no network or Docker.
It should cover parser, serializer, state-transition, authentication, timeout, cancellation, disposal, and public API behavior.
The reusable internal `SaslConformanceHarness` supplies scripted fragmented streams and transports for offline authentication tests.
It records exact wire bytes and non-secret buffer observations without contacting a server or requiring credentials.

`Transiever.ManageSieve.IntegrationTest` uses Testcontainers and a pinned Dovecot/Pigeonhole image.
It skips when Docker is unavailable.
The fixture waits for the mapped host port.
It pins the image's bundled test certificate through the internal certificate-validation seam.
It covers the ManageSieve commands supported by that Dovecot/Pigeonhole build.
Commands that the pinned server rejects remain covered by deterministic client tests instead of the Docker round trip.
`UNAUTHENTICATE` is one example.

`Transiever.ManageSieve.LiveTest` is skipped unless explicitly enabled.
Live tests are for provider interoperability checks only and must remain non-destructive by default.

## Unit Coverage Priorities

Prioritize:

* Segmented in-memory parser input.
* Serializer escaping.
* Capability parsing.
* Fragmented responses, quoted strings, literals, response codes, and malformed input.
* Session-state transitions.
* Authentication challenge/response tests without real credentials.
* Authentication lifecycle ownership, completion with and without server-final data, synchronized `NO` preservation,
  indeterminate-disconnect cleanup, fixed diagnostics, and absence of wire-level SASL cancellation.
* Cancellation, timeout, and disposal behavior.
* Script round trips containing ASCII, Unicode, CRLF, and large literals.
* Deterministic fake transport coverage for client-level tests.

## Live-Provider Configuration

Set `TRANSIEVER_LIVE_TESTS=true` to enable live-provider tests.
Connection settings fall back to the shared [`TRANSIEVER_SIEVE_*` server configuration](../src/Transiever.ManageSieve.Cli/README.md#server-configuration).
`TRANSIEVER_LIVE_HOST`, `TRANSIEVER_LIVE_PORT`, `TRANSIEVER_LIVE_USERNAME`, `TRANSIEVER_LIVE_PASSWORD`, and `TRANSIEVER_LIVE_SECURITY_MODE` optionally override their corresponding shared values for a dedicated live-test account.
Values are literal; `$TRANSIEVER_SIEVE_HOST` is not expanded.

```text
TRANSIEVER_LIVE_TESTS=true
TRANSIEVER_SIEVE_HOST=sieve.example.com
TRANSIEVER_SIEVE_PORT=4190
TRANSIEVER_SIEVE_USERNAME=user@example.com
TRANSIEVER_SIEVE_PASSWORD=secret
TRANSIEVER_SIEVE_SECURITY_MODE=StartTlsRequired
```

`TRANSIEVER_SIEVE_PORT` and `TRANSIEVER_SIEVE_SECURITY_MODE` are optional.

Live tests are read-only by default.
Guarded upload, rename, and delete coverage additionally requires:

```text
TRANSIEVER_LIVE_WRITES=true
```

Live tests must never call `SETACTIVE`.

## Live Write Safety

Each live write test snapshots script names, active state, and content hashes.
It uses unique `transiever-test-{guid}` names and deletes only inactive names it created after the snapshot.

Existing scripts are never overwritten, renamed, activated, deactivated, or deleted.

If cleanup fails, the test reports the exact temporary names for manual removal.
Broad prefix cleanup is intentionally not attempted.

Authentication cleanup has the same narrow guarantee: `Abort` is local and must not attempt wire-level recovery.
An indeterminate exchange closes the transport; if `Abort` throws, the client reports cleanup failure and also closes the transport.
Buffer clearing is best effort and cannot guarantee erasure from immutable strings, GC/runtime copies,
framework, operating-system, or transport buffers, captured wire copies, or server memory.
