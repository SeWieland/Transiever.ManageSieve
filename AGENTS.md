# AGENTS.md

## Project: Transiever.ManageSieve

Transiever.ManageSieve is intended to be a .NET-native client library for the ManageSieve
protocol. Its purpose is to let .NET applications inspect and manage server-side
Sieve scripts without shelling out to an external client or depending on a
platform-specific mail stack.

The repository has an implemented RFC 5804 protocol client with unit,
Docker-backed integration, and explicitly enabled live-provider test layers.

## Current State

Target environment:

* .NET 10
* Cross-platform class library
* Nullable reference types enabled
* Implicit global usings enabled
* xUnit test project
* Public API contract for the RFC 5804 command surface
* Streaming parser and command serializer
* TCP, STARTTLS, and implicit TLS transport
* SASL authentication abstraction and PLAIN implementation
* Testcontainers integration coverage against Dovecot/Pigeonhole

Repository layout:

```text
Transiever.ManageSieve.slnx
README.md
.editorconfig

src/
    Transiever.ManageSieve/
        Transiever.ManageSieve.csproj
        README.md
        IManageSieveClient.cs
        IManageSieveClientFactory.cs
        IManageSieveAuthenticator.cs
        ManageSieveClient.cs
        ManageSieveClientOptions.cs
        ManageSieveModels.cs
        ManageSieveExceptions.cs

    Transiever.ManageSieve.UnitTest/
        Transiever.ManageSieve.UnitTest.csproj

    Transiever.ManageSieve.IntegrationTest/
        Transiever.ManageSieve.IntegrationTest.csproj
        docker/

    Transiever.ManageSieve.LiveTest/
        Transiever.ManageSieve.LiveTest.csproj
```

The public project name is intentionally rooted in the `Transiever` pun and
uses the longer `Transiever.ManageSieve` form for clarity.

## Build and Test Commands

Run these commands from the repository root:

```bash
dotnet restore Transiever.ManageSieve.slnx
dotnet build Transiever.ManageSieve.slnx
dotnet test Transiever.ManageSieve.slnx
```

## Intended Scope

The public API covers the common script-management workflow:

* Connect to a ManageSieve endpoint
* Read server capabilities
* Negotiate TLS securely
* Authenticate
* List scripts and identify the active script
* Download a script
* Check or upload a script
* Activate, rename, and delete scripts
* Log out and dispose the connection cleanly

ManageSieve is defined by RFC 5804. Extension commands and authentication
mechanisms must be capability-driven rather than assumed to exist.

All existing protocol methods execute real commands. New protocol behavior must
retain streaming-parser coverage and an appropriate integration or live test
when unit tests alone cannot establish interoperability.

## Architecture Direction

Keep the initial design small and layered:

```text
Public asynchronous client API
    -> command/session state handling
    -> ManageSieve response parser and serializer
    -> transport abstraction
    -> TCP/TLS stream
```

Current source boundaries:

```text
src/Transiever.ManageSieve/
    ManageSieveClient.cs
    ManageSieveProtocol.cs
    ManageSieveTransport.cs
    ManageSievePlainAuthenticator.cs
```

The TCP/TLS factory and transport are internal. Do not expose certificate
validation overrides publicly. Integration tests use `InternalsVisibleTo` to
trust only the exact generated test certificate.

## Protocol Constraints

ManageSieve is a stateful, text-oriented protocol with byte-counted literals.
Implementation work must account for the following:

* Parse from bytes or a stream; do not assume every response is one line.
* Literal lengths are byte counts, not .NET character counts.
* Preserve script contents exactly when sending and receiving literals.
* Treat `OK`, `NO`, and `BYE` as distinct outcomes.
* Re-read capabilities after a successful TLS upgrade.
* Serialize commands on a connection unless protocol behavior proves safe
  otherwise.
* Validate legal session states before sending commands.
* Propagate cancellation and apply configurable operation timeouts.
* Avoid logging credentials or full scripts by default.

Do not build the parser around a collection of ad hoc string splits. The parser
is the main correctness boundary and should have focused tests for fragmented
input, quoted strings, escapes, literals, response codes, and malformed input.

## Security Defaults

Security-sensitive behavior should be explicit and conservative:

* Never send plaintext credentials over an unencrypted connection by default.
* Use normal .NET certificate validation by default.
* Do not add an accept-any-certificate switch to the primary API.
* Clear or release sensitive authentication buffers as soon as practical.
* Put credentials behind an authentication abstraction rather than embedding
  usernames and passwords in general connection options.
* Redact authentication exchanges from diagnostics.

Any insecure compatibility option must be clearly named, opt-in, and tested.

## Public API Guidelines

* Use the standard .NET asynchronous pattern with `Task`/`ValueTask` and a final
  optional `CancellationToken`.
* Prefer immutable result models and read-only collections.
* Use `IAsyncDisposable` where connection shutdown requires asynchronous I/O.
* Keep transport/protocol details out of the normal consumer API.
* Return structured capability and script metadata rather than requiring users
  to parse protocol text.
* Use specific exceptions for connection, authentication, protocol, and command
  failures when callers can act on the distinction.
* Do not expose a public API until its naming and cancellation/error semantics
  have tests.

Avoid unnecessary framework dependencies. The main library should use the .NET
base class libraries unless a dependency has a clear, documented benefit.

## Testing Direction

Tests must not require access to a real mail server by default.

Prioritize:

* Parser tests using segmented in-memory input
* Serializer and escaping tests
* Capability parsing
* Session-state transition tests
* Authentication challenge/response tests without real credentials
* Cancellation, timeout, and disposal behavior
* Script round trips containing ASCII, Unicode, CRLF, and large literals
* A deterministic fake transport for client-level tests

`Transiever.ManageSieve.IntegrationTest` uses Testcontainers and a pinned
Dovecot/Pigeonhole image. It skips during discovery when Docker is unavailable.

`Transiever.ManageSieve.LiveTest` is disabled unless `TRANSIEVER_LIVE_TESTS=true` and is
configured entirely through environment variables. Writes additionally require
`TRANSIEVER_LIVE_WRITES=true`; live tests must never call `SETACTIVE`. Preserve
the snapshot, unique-name ownership, inactive-only cleanup, and disabled
parallelization safeguards documented in the root README.

## Remaining Implementation Priorities

1. Add SASL mechanisms only when they have deterministic challenge tests.
2. Expand protocol fixtures for server compatibility issues as they are found.
3. Add optional diagnostics that redact credentials and script contents.
4. Finalize package metadata and release automation.

## Public API Decisions

`IManageSieveClient` represents one stateful connection and exposes all RFC 5804
commands:

* `AUTHENTICATE`, `STARTTLS`, `LOGOUT`, and `CAPABILITY`
* `HAVESPACE`, `PUTSCRIPT`, `LISTSCRIPTS`, and `SETACTIVE`
* `GETSCRIPT`, `DELETESCRIPT`, `RENAMESCRIPT`, `CHECKSCRIPT`, and `NOOP`
* Recommended `UNAUTHENTICATE`

`SetActiveScriptAsync(null)` disables Sieve processing. Script content uses
`ReadOnlyMemory<byte>` because protocol literals are octet-counted. Keep string
encoding decisions outside the protocol contract.

Command methods return structured values only when the server has meaningful
data. Once implemented, `NO` and unexpected `BYE` responses should use typed
exceptions carrying response codes; successful warnings remain available on
`ManageSieveCommandResult`.

Do not add separate interfaces for every command. The session itself is the
stateful protocol boundary. Add abstractions only for real collaborators such as
authentication, transport, parsing, or client creation.

## Relationship to SieveRuler and OutlookResiever

`Transiever.SieveRuler` consumes `Transiever.ManageSieve` for remote
inspection, validation, upload, and activation. `Transiever.OutlookResiever`
consumes `Transiever.SieveRuler` and does not reference
`Transiever.ManageSieve` directly. All repositories remain independently
usable.

`Transiever.ManageSieve` provides protocol operations and structured server
results. It does not decide how Outlook rules are merged with an existing
script, which content is application-owned, or whether a candidate should be
activated. Those reconciliation, preservation, preview, and confirmation
policies belong to `Transiever.SieveRuler`.

`Transiever.ManageSieve` must not:

* Reference Outlook or Outlook COM APIs
* Depend on `Transiever.SieveRuler` or `Transiever.OutlookResiever` models
* Assume provider-specific behavior in its protocol core
* Automatically upload scripts without an explicit caller action
* Parse or optimize `Transiever.SieveRuler`'s canonical rule model

Provider-specific compatibility behavior should sit above the protocol layer.

During initial integration, `Transiever.SieveRuler` references this project
through a hard relative `ProjectReference`.
`Transiever.SieveRuler.IntegrationTest` is granted
internal access only to pin the disposable test container certificate. No
certificate-validation override is exposed through the public API. Replace the
application project reference with a NuGet package before publication.

## Non-Goals for the First Pass

Do not implement yet:

* A Sieve language compiler or rule generator
* IMAP, SMTP, or general mail-client functionality
* A CLI or GUI
* Automatic credential storage
* Provider-specific account discovery
* Connection pooling or command pipelining
* A large dependency-injection framework

## Change Style

Make incremental changes backed by tests. Prefer small protocol-focused types,
clear state transitions, and explicit failure behavior over broad abstractions.
Keep the repository buildable after each change.
