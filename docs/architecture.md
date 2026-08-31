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

### Authentication lifecycle

`IManageSieveAuthenticator` adds three lifecycle members:
`AllowsUnprotectedConnection`, `CompleteAsync`, and `Abort`.
`GetInitialResponseAsync` and `RespondAsync` provide the initial and challenge responses for the exchange.
`AllowsUnprotectedConnection` defaults to `false`.
The client invokes the initial callback once, invokes the response callback for each decoded challenge,
and invokes `CompleteAsync` only after a successful `OK` response and before entering `Authenticated`.
`CompleteAsync` receives `null` when the final response has no `SASL` response code,
or the decoded bytes from the single quoted-string or literal argument of `OK (SASL ...)`.

Response-memory ownership is explicit.
Memory returned by an authenticator remains owned by the authenticator and is not modified by the client.
It must remain valid until the client invokes `CompleteAsync` or `Abort`,
when the authenticator is responsible for clearing retained mutable response and secret buffers.
Challenge and server-final memory is owned by the client for the duration of the callback only;
an authenticator must not retain it after the callback returns.
The client clears its encoded frames, decoded challenge data, and decoded server-final data after use.
Clearing is best effort and cannot guarantee erasure from immutable strings, GC/runtime copies,
framework, operating-system, or transport buffers, captured wire copies, or server memory.

Authentication requires a protected connection unless the authenticator explicitly opts in through `AllowsUnprotectedConnection`.
Capability advertisement is checked before invoking the authenticator or writing `AUTHENTICATE`.

Authentication failure handling preserves only synchronized outcomes.
If the server returns `NO`, the exchange is synchronized: the client calls `Abort` and,
when cleanup succeeds, keeps the transport and preserves the connected or secured session so another attempt can be made.
Failures before the `AUTHENTICATE` frame is written likewise remain on the existing session after local cleanup.
If the server returns `BYE`, or an I/O error, timeout, cancellation, malformed response, or callback failure occurs after authentication bytes were written,
the result is indeterminate: the client calls `Abort` and closes the transport; the session becomes `Disconnected`.
If `Abort` itself throws, cleanup is reported as `ManageSieve authentication cleanup failed.` and the transport is closed.
The client never sends a wire-level SASL cancellation frame.

Authentication diagnostics are fixed and do not include server prose, callback exception text, credentials, or SASL data.
The public messages include `The selected SASL mechanism requires a protected connection.`,
`The server did not advertise the selected SASL mechanism.`,
`ManageSieve authentication failed.`, `ManageSieve authenticator failed.`,
`ManageSieve authentication cleanup failed.`, `ManageSieve server closed the connection during authentication.`,
and `ManageSieve authentication timed out.` as applicable.
For a server `NO`, `ManageSieveAuthenticationException.ResponseCode` contains only the response-code atom,
such as `AUTHENTICATIONFAILED`, never its arguments.

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
