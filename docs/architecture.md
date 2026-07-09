# Transiever.ManageSieve Architecture

This document is the canonical description of the ManageSieve protocol boundary, layering, public API rules, and security constraints.
Test policy lives in [testing](testing.md).

## System Boundary

```text
consumer application
    -> Transiever.ManageSieve
        -> RFC 5804 ManageSieve server

operator
    -> msieve
        -> Transiever.ManageSieve
            -> RFC 5804 ManageSieve server
```

`Transiever.ManageSieve` owns protocol execution only.
It does not parse or generate Sieve rules.
It does not reconcile application-owned content.
It does not optimize filters, discover mail accounts, or decide whether a candidate should be activated.
The `msieve` CLI is a thin operator surface over the same protocol library.
It exposes direct capabilities, script inspection, validation, upload, activation, deactivation, and delete operations.
It does not add backups, rollback, history, reconciliation, Outlook import, provider metadata, Sieve generation, or credential storage.

`Transiever.SieveRuler` consumes this library for remote inspection, validation, upload, activation, and rollback primitives.
`Transiever.OutlookResiever` consumes SieveRuler and does not reference this library directly.

## Layers

```text
Public asynchronous client API
    -> command and session-state handling
    -> ManageSieve response parser and command serializer
    -> transport abstraction
    -> TCP/TLS stream
```

The TCP/TLS factory and transport are internal.
Integration tests use `InternalsVisibleTo` to trust only the exact certificate presented by the disposable Dovecot test container.
The public API must not expose certificate-validation overrides.

## Protocol Constraints

ManageSieve is a stateful, text-oriented protocol with byte-counted literals.
Implementation work must account for these constraints:

* Parse from bytes or a stream.
* Do not assume every response is one line.
* Treat literal lengths as byte counts, not .NET character counts.
* Preserve script contents exactly when sending and receiving literals.
* Treat `OK`, `NO`, and `BYE` as distinct outcomes.
* Re-read capabilities after a successful TLS upgrade.
* Serialize commands on a connection unless protocol behavior proves safe otherwise.
* Validate legal session states before sending commands.
* Propagate cancellation and apply configurable operation timeouts.

The parser is the main correctness boundary.
Do not build it around ad hoc string splitting.

## Public API

`IManageSieveClient` represents one stateful connection and exposes the RFC 5804 command surface:

* `AUTHENTICATE`, `STARTTLS`, `LOGOUT`, and `CAPABILITY`.
* `HAVESPACE`, `PUTSCRIPT`, `LISTSCRIPTS`, and `SETACTIVE`.
* `GETSCRIPT`, `DELETESCRIPT`, `RENAMESCRIPT`, `CHECKSCRIPT`, and `NOOP`.
* Recommended `UNAUTHENTICATE`.

Use standard .NET async naming with a final optional `CancellationToken`.
Prefer immutable result models and read-only collections.
Use `IAsyncDisposable` where shutdown requires asynchronous I/O.

Command methods return structured values only when the server has meaningful data.
`NO` and unexpected `BYE` responses use typed exceptions carrying response codes.
Successful warnings remain available on `ManageSieveCommandResult`.

Avoid unnecessary framework dependencies.
The main library should use the .NET base class libraries unless a dependency has a clear, documented benefit.

## Security Defaults

Security-sensitive behavior is explicit and conservative:

* Never send plaintext credentials over an unencrypted connection by default.
* Use normal .NET certificate validation by default.
* Do not add an accept-any-certificate switch to the primary API.
* Clear or release sensitive authentication buffers as soon as practical.
* Put credentials behind an authentication abstraction instead of general connection options.
* Redact authentication exchanges, credentials, and full scripts from diagnostics.

Any insecure compatibility option must be clearly named, opt-in, and tested.

## Non-Goals

This repository does not provide:

* A Sieve language compiler or rule generator.
* IMAP, SMTP, or general mail-client behavior.
* A GUI.
* Automatic credential storage.
* Provider-specific account discovery.
* Connection pooling or command pipelining.
* Deployment, reconciliation, or provider UI compatibility policy.
