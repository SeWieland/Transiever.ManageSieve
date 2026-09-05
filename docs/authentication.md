# Authentication

This guide is the canonical contract for SASL authentication in `Transiever.ManageSieve`.
It describes the checks before an exchange, authenticator callbacks, session outcomes, memory ownership, and safe diagnostics.
The ManageSieve protocol is defined by [RFC 5804](https://www.rfc-editor.org/rfc/rfc5804),
and its authentication exchange uses the [SASL framework](https://www.rfc-editor.org/rfc/rfc4422).

## Why choose a mechanism?

SASL mechanisms define how a client proves its identity to the server.
`PLAIN` sends the authorization identity, authentication identity, and password as a Base64-encoded response; Base64 is not encryption, so this client requires protected transport before using it.
`SCRAM-SHA-256` proves knowledge of the password through a salted challenge-response exchange instead of sending the password itself.
It also allows a server to store salted verification material that is not by itself sufficient to impersonate the client, reducing the impact of a credential-database disclosure.
It is specified by [RFC 5802](https://www.rfc-editor.org/rfc/rfc5802) and the SHA-256 registration in [RFC 7677](https://www.rfc-editor.org/rfc/rfc7677).
This implementation still requires protected transport for SCRAM and supports the non-PLUS mechanism only; it does not provide channel binding.

## Before authentication

`AuthenticateAsync` first validates the current client state, the authenticator, and the transport policy.
Authenticators require protected transport by default because `AllowsUnprotectedConnection` defaults to `false`.
`ManageSievePlainAuthenticator` keeps that default and refuses to send credentials on an unprotected connection.
An authenticator may opt in to an unprotected connection only by explicitly setting `AllowsUnprotectedConnection`.

The selected mechanism must be in the server's advertised capabilities before `GetInitialResponseAsync` is invoked or `AUTHENTICATE` is written.
After `STARTTLS`, the capabilities read over the protected transport are authoritative; a mechanism advertised only before TLS is not sufficient.
Failed preconditions produce no authenticator callback and no authentication wire output.

## SCRAM-SHA-256

`ManageSieveScramSha256Authenticator(userName, password, authorizationIdentity?)` implements exactly `SCRAM-SHA-256` and requires protected transport.
The user name is non-empty; the password may be empty; the optional authorization identity may be omitted or empty, with an empty value treated as absent.
All three values must be printable ASCII and at most 1,024 bytes.
Commas and equals signs in identities are escaped using the SCRAM `=2C` and `=3D` forms.
Unicode and SASLprep are not supported.

Production instances generate an 18-byte cryptographically random nonce and encode it with standard Base64.
An internal-only nonce factory makes offline tests deterministic; it is not public API.

The exchange sends a client-first message in the form `n,,n=<user>,r=<client-nonce>` or `n,a=<authzid>,n=<user>,r=<client-nonce>`.
The first server challenge must contain ordered, unique `r=`, `s=`, and `i=` fields, followed only by syntactically valid optional extensions.
Mandatory extensions (`m=`), missing, duplicate, reordered, or malformed mandatory fields are rejected; assigned attribute names are rejected where a message permits only unassigned extensions.
The server nonce must be printable, contain the exact client nonce as a prefix, add at least one character, and be no more than 256 bytes.
The decoded salt must be 1 to 1,024 bytes, and the iteration count must be 4,096 to 1,000,000.
The client-final message uses the Base64-encoded GS2 header in `c=` and the server nonce, binding any authorization identity into the proof.
Proof derivation uses SHA-256 PBKDF2 and HMAC over the exact client-first-bare, server-first, and client-final-without-proof bytes.

The server must return a final `v=<base64-server-signature>` message.
It may arrive as `OK (SASL ...)` final data, or as a final challenge followed by the authenticator's explicitly empty response and `CompleteAsync(null)`.
The signature must decode to exactly 32 bytes and is compared with a fixed-time comparison before completion.
Server errors (`e=`), malformed or replayed messages, extra challenges, and invalid proofs produce the fixed redacted `SCRAM-SHA-256 authentication failed.` exception.
Optional final extensions are accepted only when they use unassigned attribute names.

Complete SCRAM messages are limited to 1 to 16,384 UTF-8 bytes.
Base64 is strict and canonical, with no whitespace, invalid alphabet, misplaced padding, or alternate encoding.

## Exchange lifecycle

After the checks, `ManageSieveAuthenticationExchange` asks for an optional initial response.
`null` means that the `AUTHENTICATE` command has no initial-response argument.
An empty memory value is present but encodes as an explicitly empty response, while non-empty bytes are Base64-encoded and sent as the argument.

The exchange reads the server's continuation responses through the streaming parser.
Each challenge must contain exactly one string value containing valid Base64; the decoded challenge is passed to `RespondAsync` for the duration of that callback.
The returned response remains authenticator-owned, is Base64-encoded by the client, and is written as the next exchange response.
The exchange repeats this challenge cycle until a terminal response.

The server can carry final data in either of two forms.
A mechanism may receive its final server data as the last challenge and return an empty response; in that form `CompleteAsync` receives `null`.
Alternatively, `OK (SASL ...)` carries exactly one quoted-string or literal argument, which is Base64-decoded and passed to `CompleteAsync`.
No SASL response code, or a non-SASL response code, also supplies `null`.
Decoded empty data is distinct from absent data.
`CompleteAsync` is called exactly once after `OK` and must succeed before the client enters `Authenticated`.

An unsuccessful attempt after authenticator processing begins calls `Abort` exactly once.
`Abort` is synchronous local cleanup and never sends a wire-level SASL cancellation response.
Precondition failures before authenticator processing do not call `Abort`.

```mermaid
flowchart TD
    A[Validate TLS and mechanism] --> B[Get initial response]
    B --> C[Send AUTHENTICATE]
    C --> D{Server response}
    D -->|Challenge| E[Decode challenge]
    E --> F[Call RespondAsync]
    F --> G[Send response]
    G --> D
    D -->|OK| H[Decode final data]
    H --> I[Call CompleteAsync]
    I --> J[Authenticated]
```

## Connection outcomes

The client preserves a synchronized session only when no authentication bytes were initiated or a terminal `NO` was parsed.
Cancellation while waiting for the command lock, or before the first authentication write, preserves the current connected or secured session and propagates caller cancellation.
If authenticator processing began but no first write was initiated, `Abort` runs and the pre-wire session remains reusable unless cleanup fails.

A terminal server `NO` is synchronized rejection.
The client calls `Abort`, preserves the pre-authentication `Connected` or `Secured` state, and raises `ManageSieveAuthenticationException`.
The exception's `ResponseCode` contains only the response-code atom, such as `AUTHENTICATIONFAILED`.

`BYE`, partial writes, transport I/O failures, cancellation after transmission, operation timeout, malformed challenge or success data, and authenticator response or completion failures make the exchange indeterminate.
The client calls `Abort`, resets and disposes the transport, clears capabilities, and enters `Disconnected`.
The original caller cancellation is preserved; a linked operation timeout becomes `ManageSieve authentication timed out.`
Protocol failures and authenticator failures retain their safe typed categories.

If `Abort` throws, or transport cleanup reports failure, the client drops the connection, clears capabilities, enters `Disconnected`, attempts transport disposal, and reports the fixed `ManageSieve authentication cleanup failed.` diagnostic.
The client never attempts wire-level recovery after a local failure.

```mermaid
flowchart TD
    A[Authentication fails] --> B{Processing began?}
    B -->|Yes| C[Call Abort]
    B -->|No| D[Keep prior session]
    C --> E{Cleanup failed?}
    E -->|Yes| F[Drop connection; try disposal]
    E -->|No| G{Recovery state}
    G -->|Not started| D
    G -->|Server NO| H[Keep prior session]
    G -->|Disconnect required| F
    F --> I[Disconnected]
```

## Memory ownership

The client owns decoded challenge arrays and decoded `OK (SASL ...)` data.
Those buffers are valid only during `RespondAsync` or `CompleteAsync` and are cleared after the callback returns, including when it throws.
The client also owns encoded `AUTHENTICATE` and challenge-response frames and clears each frame after its awaited write completes.

Buffers returned by `GetInitialResponseAsync` or `RespondAsync` remain authenticator-owned; the client does not mutate them.
They must remain valid until `CompleteAsync` or `Abort`, when the authenticator clears its retained mutable response and secret buffers.
Callback memory remains client-owned, so an authenticator must not retain challenge or server-final data after the callback.

Clearing is best effort within managed code.
It cannot guarantee erasure from immutable input strings, garbage-collector or runtime copies, framework, operating-system, or transport buffers, captured wire copies, or server memory.

For SCRAM, the authenticator clears explicitly owned mutable password-derived buffers, client proof, server signature, response, decoded salt, and retained exchange buffers during completion or abort.
Immutable strings, framework/OS/transport buffers, and copied test transcripts are outside that erasure claim.

```mermaid
flowchart LR
    subgraph Client
        A[Decode server data] --> B[Callback memory]
        B --> C[Clear after callback]
        D[Serialize frame] --> E[Clear after write]
    end
    subgraph Authenticator
        F[Create response buffer] --> G[Own response and secrets]
        G --> H[Clear on Complete or Abort]
    end
```

## Diagnostic guarantees

Authentication diagnostics are fixed and redacted.
They do not include server prose, callback exception text, credentials, encoded or decoded SASL data, or raw frames.
Applicable fixed messages include `The selected SASL mechanism requires a protected connection.`,
`The server did not advertise the selected SASL mechanism.`,
`ManageSieve authentication failed.`,
`ManageSieve authenticator failed.`,
`ManageSieve authentication cleanup failed.`,
`ManageSieve server closed the connection during authentication.`,
and `ManageSieve authentication timed out.`

For a server `NO`, `ManageSieveAuthenticationException.ResponseCode` contains only the case-insensitive response-code atom and never its arguments or prose.
SCRAM-specific failures likewise never include the user name, nonce, salt, proof, server-final data, server error text, credentials, or inner cryptographic exception.

## Related documentation

See the [architecture guide](architecture.md) for parser, session, transport, and component-boundary details.
See the [testing guide](testing.md) for offline conformance coverage and live-provider test policy.
