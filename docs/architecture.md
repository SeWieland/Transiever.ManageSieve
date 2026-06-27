# Transiever.ManageSieve Architecture

This document is the canonical description of the ManageSieve protocol boundary,
layering, public API rules, and security constraints.

The root [README](../README.md) is the repo entry point.
The library API summary lives in [../src/Transiever.ManageSieve/README.md](../src/Transiever.ManageSieve/README.md).
Test policy lives in [testing](testing.md).

## System Boundary

```text
consumer application
    -> Transiever.ManageSieve
        -> RFC 5804 ManageSieve server
```

`Transiever.ManageSieve` owns protocol execution only.
It does not parse or generate Sieve rules, reconcile application-owned content,
optimize filters, discover mail accounts, or decide whether a candidate should be activated.

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

* parse from bytes or a stream; do not assume every response is one line;
* literal lengths are byte counts, not .NET character counts;
* preserve script contents exactly when sending and receiving literals;
* treat `OK`, `NO`, and `BYE` as distinct outcomes;
* re-read capabilities after a successful TLS upgrade;
* serialize commands on a connection unless protocol behavior proves safe otherwise;
* validate legal session states before sending commands;
* propagate cancellation and apply configurable operation timeouts.

The parser is the main correctness boundary.
Do not build it around ad hoc string splitting.

## Public API

`IManageSieveClient` represents one stateful connection and exposes the RFC 5804 command surface:

* `AUTHENTICATE`, `STARTTLS`, `LOGOUT`, and `CAPABILITY`;
* `HAVESPACE`, `PUTSCRIPT`, `LISTSCRIPTS`, and `SETACTIVE`;
* `GETSCRIPT`, `DELETESCRIPT`, `RENAMESCRIPT`, `CHECKSCRIPT`, and `NOOP`;
* recommended `UNAUTHENTICATE`.

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

* never send plaintext credentials over an unencrypted connection by default;
* use normal .NET certificate validation by default;
* do not add an accept-any-certificate switch to the primary API;
* clear or release sensitive authentication buffers as soon as practical;
* put credentials behind an authentication abstraction instead of general connection options;
* redact authentication exchanges, credentials, and full scripts from diagnostics.

Any insecure compatibility option must be clearly named, opt-in, and tested.

## Non-Goals

This repository does not provide:

* a Sieve language compiler or rule generator;
* IMAP, SMTP, or general mail-client behavior;
* a CLI or GUI;
* automatic credential storage;
* provider-specific account discovery;
* connection pooling or command pipelining;
* deployment, reconciliation, or provider UI compatibility policy.
