# Transiever.ManageSieve Testing

This document is the canonical testing policy for the ManageSieve repository.

The architecture and protocol constraints live in [architecture](architecture.md).

## Test Layers

`Transiever.ManageSieve.UnitTest` is deterministic and requires no network or Docker.
It should cover parser, serializer, state-transition, authentication, timeout, cancellation, disposal, and public API behavior.

`Transiever.ManageSieve.IntegrationTest` uses Testcontainers and a pinned Dovecot/Pigeonhole image. It skips when Docker is unavailable.
The fixture waits for the mapped host port, pins the image's bundled test certificate through the internal certificate-validation seam,
and covers the ManageSieve commands supported by that Dovecot/Pigeonhole build.
Commands that the pinned server rejects, such as `UNAUTHENTICATE`, remain covered by deterministic client tests instead of the Docker round trip.

`Transiever.ManageSieve.LiveTest` is skipped unless explicitly enabled.
Live tests are for provider interoperability checks only and must remain non-destructive by default.

## Unit Coverage Priorities

Prioritize:

* segmented in-memory parser input;
* serializer escaping;
* capability parsing;
* fragmented responses, quoted strings, literals, response codes, and malformed input;
* session-state transitions;
* authentication challenge/response tests without real credentials;
* cancellation, timeout, and disposal behavior;
* script round trips containing ASCII, Unicode, CRLF, and large literals;
* deterministic fake transport coverage for client-level tests.

## Live-Provider Configuration

Live-provider configuration is read only from environment variables:

```text
TRANSIEVER_LIVE_TESTS=true
TRANSIEVER_LIVE_HOST=sieve.example.com
TRANSIEVER_LIVE_PORT=4190
TRANSIEVER_LIVE_USERNAME=user@example.com
TRANSIEVER_LIVE_PASSWORD=secret
TRANSIEVER_LIVE_SECURITY_MODE=StartTlsRequired
```

`TRANSIEVER_LIVE_PORT` and `TRANSIEVER_LIVE_SECURITY_MODE` are optional.

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
