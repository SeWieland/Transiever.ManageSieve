# Authentication

This guide defines the ManageSieve host contract: transport checks, protocol framing, callback ownership, session recovery, and diagnostics.
The protocol follows [RFC 5804](https://www.rfc-editor.org/rfc/rfc5804).

`Transiever.SaslClient` owns the PLAIN, SCRAM-SHA-256, SCRAM-SHA-256-PLUS, OAUTHBEARER, and EXTERNAL mechanism implementations.
See its [authentication guide](https://github.com/SeWieland/Transiever.SaslClient/blob/main/docs/authentication.md) for message formats, proof validation, input limits, and mechanism lifecycle rules.
Existing ManageSieve authenticator classes remain compatibility wrappers; `ManageSieveSaslMechanismAdapter` accepts an `ISaslMechanism` through the same host checks.

## Before authentication

`AuthenticateAsync` first validates the current client state, the authenticator, and the transport policy.
Authenticators require protected transport by default because `AllowsUnprotectedConnection` defaults to `false`.
`ManageSievePlainAuthenticator` keeps that default and refuses to send credentials on an unprotected connection.
An authenticator may opt in to an unprotected connection only by explicitly setting `AllowsUnprotectedConnection`.

The selected mechanism must be in the server's advertised capabilities before `GetInitialResponseAsync` is invoked or `AUTHENTICATE` is written.
After `STARTTLS`, the capabilities read over the protected transport are authoritative; a mechanism advertised only before TLS is not sufficient.
`CanUseScramSha256Plus` is false before TLS, when PLUS is not advertised, for TLS 1.3, or when the endpoint binding is unavailable or unsupported.
During `AuthenticateAsync`, the client rechecks the binding under the command lock, fetches it immediately before `GetInitialResponseAsync`, and clears the attempt-owned bytes after the exchange; it does not cache a binding beyond the attempt.
Failed preconditions produce no authenticator callback and no authentication wire output.
Authenticators with `RequiresClientCertificate` set to `true` additionally require a configured certificate with a usable private key and negotiated mutual TLS with a selected local certificate.
This capability defaults to `false` for existing authenticators.
These checks run before callbacks, authentication writes, and acquisition of the command lock.

## SCRAM-SHA-256

`ManageSieveScramSha256Authenticator(userName, password, authorizationIdentity?)` delegates to the SASL package.
See the [SCRAM limits and proof contract](https://github.com/SeWieland/Transiever.SaslClient/blob/main/docs/authentication.md#mechanism-specific-limits); ManageSieve delivers final data through the exchange lifecycle below.

## SCRAM-SHA-256-PLUS

`ManageSieveScramSha256PlusAuthenticator(userName, password, authorizationIdentity?)` implements exactly `SCRAM-SHA-256-PLUS`.
Its public API has no binding or context parameter: the client obtains the verified peer certificate's endpoint binding and supplies it to the authenticator for one locked authentication attempt.
The client supplies `tls-server-end-point` bytes under the package's [channel-binding contract](https://github.com/SeWieland/Transiever.SaslClient/blob/main/docs/authentication.md#channel-binding).
The channel binding is the exact DER certificate hash selected by these supported certificate signature algorithm OIDs:

- SHA-256: MD5 (`1.2.840.113549.2.5`), RSA with MD5 (`1.2.840.113549.1.1.4`), SHA-1 (`1.3.14.3.2.26`), RSA with SHA-1 (`1.2.840.113549.1.1.5`), DSA with SHA-1 (`1.2.840.10040.4.3`), ECDSA with SHA-1 (`1.2.840.10045.4.1`), SHA-256 (`2.16.840.1.101.3.4.2.1`), RSA PKCS#1 v1.5 with SHA-256 (`1.2.840.113549.1.1.11`), and ECDSA with SHA-256 (`1.2.840.10045.4.3.2`).
- SHA-384: SHA-384 (`2.16.840.1.101.3.4.2.2`), RSA PKCS#1 v1.5 with SHA-384 (`1.2.840.113549.1.1.12`), and ECDSA with SHA-384 (`1.2.840.10045.4.3.3`).
- SHA-512: SHA-512 (`2.16.840.1.101.3.4.2.3`), RSA PKCS#1 v1.5 with SHA-512 (`1.2.840.113549.1.1.13`), and ECDSA with SHA-512 (`1.2.840.10045.4.3.4`).

Missing certificates and all other signature algorithm OIDs fail closed, including RSA-PSS and DSA with SHA-2.

Only TLS 1.2 is supported for this binding.
TLS 1.3 fails closed with the fixed `SCRAM-SHA-256-PLUS requires a supported TLS 1.2 channel binding.` message because the public .NET API does not expose the RFC 9266 `tls-exporter` primitive.
The implementation does not substitute `tls-unique`, `TransportContext`, fallback authentication, or native interop.
An unavailable binding is a PLUS failure, not a reason to emit an unbound SCRAM exchange.

## OAUTHBEARER

`ManageSieveOAuthBearerAuthenticator(accessToken, host, port, authorizationIdentity?)` takes a caller-supplied token and the effective ManageSieve endpoint.
Token acquisition, renewal, and storage remain with the caller.
See the [SASL mechanism limits](https://github.com/SeWieland/Transiever.SaslClient/blob/main/docs/authentication.md#mechanism-specific-limits) for token grammar, message encoding, and safe OAuth error parsing.

After a valid error challenge, `ServerError` exposes the compatibility record `ManageSieveOAuthBearerError` with `Status`, `Scope`, and `OpenIdConfiguration`.
ManageSieve encodes the mechanism's dummy response as `AQ==`.
A terminal `NO` leaves the record inspectable, raises a redacted authentication exception, and preserves the synchronized session.
The client never fetches an `OpenIdConfiguration` URL.

## EXTERNAL

`ManageSieveExternalAuthenticator(authorizationIdentity: null)` implements [RFC 4422 EXTERNAL](https://www.rfc-editor.org/rfc/rfc4422#appendix-A) over protected transport.
Set `ManageSieveClientOptions.ClientCertificate` before connecting so the certificate can participate in the TLS handshake.
This single caller-owned `X509Certificate2` configures local identity only; normal platform validation of the server certificate remains unchanged.
Keep the certificate undisposed for the full client lifetime and dispose it after the client.
The library never disposes or mutates it and does not acquire, enroll, renew, import, or store certificates.

The client requires both a configured certificate with a private key and transport evidence of completed mutual TLS with a non-null selected local certificate.
A missing, disposed, public-only, or unpresented identity fails with `A verified TLS client certificate is required.` before any authenticator callback or authentication output.
The synchronized session and its capabilities are preserved.
A TLS authentication failure instead clears capabilities, disconnects, and raises `ManageSieveConnectionException` with `TLS authentication failed.` and no inner cryptographic exception.
This generic failure does not distinguish client-certificate selection from server-certificate validation failures.

The server owns certificate-to-account mapping and authorization.
An omitted or empty authorization identity uses the TLS identity and is sent as `AUTHENTICATE "EXTERNAL" ""` followed by CRLF.
Non-empty identities are strict UTF-8 without normalization, exclude NUL and invalid UTF-16, and allow at most 1,024 UTF-8 octets.
Constructor failures never include the identity or an inner encoding exception.
EXTERNAL rejects challenges and any present server-final data, including empty data; only `CompleteAsync(null)` completes the attempt.
Mechanism cleanup and diagnostics follow the [SASL memory contract](https://github.com/SeWieland/Transiever.SaslClient/blob/main/docs/authentication.md#memory-and-diagnostics); connection recovery follows the shared rules below.
See the [CLI guide](https://github.com/SeWieland/Transiever.ManageSieve/blob/main/src/Transiever.ManageSieve.Cli/README.md#external) for explicit PKCS#12 loading.

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

## Memory ownership

The client owns decoded challenge arrays and decoded `OK (SASL ...)` data.
Those buffers are valid only during `RespondAsync` or `CompleteAsync` and are cleared after the callback returns, including when it throws.
The client also owns encoded `AUTHENTICATE` and challenge-response frames and clears each frame after its awaited write completes.

Buffers returned by `GetInitialResponseAsync` or `RespondAsync` remain authenticator-owned; the client does not mutate them.
They must remain valid until `CompleteAsync` or `Abort`, when the authenticator clears its retained mutable response and secret buffers.
Callback memory remains client-owned, so an authenticator must not retain challenge or server-final data after the callback.

Mechanism-owned cleanup and its best-effort erasure limits are documented in the [SASL memory contract](https://github.com/SeWieland/Transiever.SaslClient/blob/main/docs/authentication.md#memory-and-diagnostics).

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

## Related documentation

See the [architecture guide](https://github.com/SeWieland/Transiever.ManageSieve/blob/main/docs/architecture.md) for parser, session, transport, and component-boundary details.
See the [testing guide](https://github.com/SeWieland/Transiever.ManageSieve/blob/main/docs/testing.md) for offline conformance coverage and live-provider test policy.
