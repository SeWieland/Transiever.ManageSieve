# `msieve`

This guide is the canonical command reference for the ManageSieve CLI.
See the [ManageSieve project overview](https://github.com/SeWieland/Transiever.ManageSieve#readme) and [ManageSieve library guide](https://github.com/SeWieland/Transiever.ManageSieve/blob/main/src/Transiever.ManageSieve/README.md) for the public client API.

## Install

```bash
dotnet tool install --global Transiever.ManageSieve.Cli
```

The global-tool package is available on [NuGet.org](https://www.nuget.org/packages/Transiever.ManageSieve.Cli).
For a tool-selection guide and self-contained installation options, see the [Transiever ManageSieve CLI guide](https://sewieland.github.io/transiever/managesieve-cli/).

Commands:

```bash
msieve capabilities
msieve list
msieve get active --output active.sieve
msieve check --file candidate.sieve
msieve put candidate --file candidate.sieve
msieve put candidate --file candidate.sieve --activate
msieve activate candidate
msieve deactivate
msieve delete old-script
```

During development, replace `msieve` with:

```bash
dotnet run --project src/Transiever.ManageSieve.Cli --
```

Install the self-contained Linux x64 build with Homebrew:

```bash
brew install SeWieland/transiever/msieve
```

GitHub releases attach self-contained `msieve` assets for `win-x64`, `win-x86`, and `linux-x64`.
.NET does not define a portable `linux-x86` RID, so no Linux x86 asset is produced.

## Commands

`capabilities` connects to the server, applies the configured transport security, and prints advertised capabilities.
It does not authenticate and requires only host, port, and security configuration.

`list` prints server-side script names and marks the active script with `*`.

`get <script-name>` downloads one script.
Use `--output <file>` to write the exact script bytes to disk.
Without `--output`, the raw script bytes are written to standard output.

`check --file <file>` validates a local script with `CHECKSCRIPT`.
It does not store or activate the content.

`put <script-name> --file <file>` uploads the exact file bytes with `PUTSCRIPT`.
Use `--activate` to run `SETACTIVE` after a successful upload.

`activate <script-name>` activates an existing script.
`deactivate` disables active Sieve processing.
`delete <script-name>` deletes a server-side script.

The CLI is policy-neutral.
It does not reconcile scripts, create backups, manage history, import Outlook rules, generate Sieve, or apply provider-specific policy.

## Server Configuration

Configure ManageSieve through environment variables:

```text
TRANSIEVER_SIEVE_HOST=sieve.example.com
TRANSIEVER_SIEVE_PORT=4190
TRANSIEVER_SIEVE_USERNAME=user@example.com
TRANSIEVER_SIEVE_PASSWORD=secret
TRANSIEVER_SIEVE_SECURITY_MODE=StartTlsRequired
TRANSIEVER_SIEVE_SASL_MECHANISM=auto
```

Use `--sieve-host`, `--sieve-port`, `--sieve-username`, `--sieve-password`,
`--sieve-security-mode`, and `--sieve-sasl-mechanism` to override those values
for a targeted command.
The port and security mode are optional.
The default is port `4190` with required STARTTLS.
`ImplicitTls` is also supported.

Authentication uses `--sieve-sasl-mechanism auto|plain|scram-sha-256|scram-sha-256-plus|oauthbearer|external` or the
`TRANSIEVER_SIEVE_SASL_MECHANISM` environment variable.
The precedence is command-line option, environment variable, then the default
`auto`.
In `auto` mode, the CLI considers `SCRAM-SHA-256-PLUS`, then `SCRAM-SHA-256`,
then `PLAIN`.
PLUS is selected only when the server advertises it and the connected client
reports it locally usable, including a supported TLS 1.2 channel binding.
An advertised but locally unusable PLUS mechanism is skipped in auto mode so
that bare SCRAM or PLAIN can be used when advertised.
An explicit `plain`, `scram-sha-256`, or `scram-sha-256-plus` selection fails if
that mechanism is not advertised; explicit PLUS also fails when it is not
locally usable and never downgrades to another mechanism.
These selection failures occur before credentials are loaded, so they do not
prompt for a password or emit authentication bytes.
Use `msieve capabilities` to inspect the server's advertised `SASL mechanisms`
before choosing an explicit mechanism; this command does not authenticate.

Authenticated commands refuse plaintext credentials.
If the password variable is absent, an interactive terminal prompts without echoing it.

### OAUTHBEARER

Select `OAUTHBEARER` explicitly with:

```text
--sieve-sasl-mechanism oauthbearer
```

OAuth delegation lets a caller grant access without sharing its password, following [RFC 7628](https://www.rfc-editor.org/rfc/rfc7628) and the [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750) bearer-token model.
Because possession is authority, anyone who obtains the token can use it until the provider expires or revokes it; protect token input and transport accordingly.

The CLI reads one non-empty token line from standard input when
`--sieve-oauth-token-stdin` is present.
Without that selector, it uses a hidden interactive TTY prompt.
Bearer-token values are never accepted in command-line arguments or environment variables.
Redirected or noninteractive input without `--sieve-oauth-token-stdin` fails before authentication.

The CLI establishes protected transport and checks the authoritative post-TLS `SASL` advertisement before it reads the token.
It passes the effective host and port, including command-line and environment overrides, to `ManageSieveOAuthBearerAuthenticator`.
Plaintext transport, a missing post-TLS `OAUTHBEARER` advertisement, and authentication rejection all fail without downgrading to another mechanism.

`auto` never selects `OAUTHBEARER`.
Its order remains advertised, locally usable `SCRAM-SHA-256-PLUS`, then `SCRAM-SHA-256`, then `PLAIN`.
Use `msieve capabilities` to inspect the server's advertised SASL mechanisms only; it performs no OAuth or OpenID Connect discovery and never requests a token.

### EXTERNAL

Use EXTERNAL when the service identifies callers through TLS client certificates, as specified by [RFC 4422](https://www.rfc-editor.org/rfc/rfc4422#appendix-A) and the [RFC 5804 authentication exchange](https://www.rfc-editor.org/rfc/rfc5804#section-2.1).
Select it explicitly and supply an existing PKCS#12/PFX file:

```bash
msieve list --sieve-host sieve.example.com --sieve-sasl-mechanism external --sieve-client-certificate client.pfx
```

`--sieve-client-certificate` overrides `TRANSIEVER_SIEVE_CLIENT_CERTIFICATE`.
The certificate password comes from `TRANSIEVER_SIEVE_CLIENT_CERTIFICATE_PASSWORD`, or a hidden interactive prompt when that variable is absent.
No certificate-password command-line option exists.
On Windows, the CLI uses a temporary current-user key container for Schannel and .NET removes it when the certificate is disposed.
On other operating systems, the private key stays memory-only through ephemeral key storage.
The CLI does not set `PersistKeySet`, `Exportable`, or `MachineKeySet`, and does not install the certificate in an OS store.
It keeps the certificate alive for the command and disposes it after the client on handled completion and failure paths.
Load errors contain fixed configuration text without file paths, passwords, certificate details, or inner cryptographic errors.
Certificate creation, enrollment, renewal, OS-store import, and account mapping remain outside the CLI.

Unlike password and bearer-token input, the certificate and its password must be loaded before connecting because the identity participates in the TLS handshake.
After TLS, the server must advertise EXTERNAL, and the library requires evidence that a client certificate was actually presented through mutual TLS before authentication output.
Normal server-certificate validation remains in force.
EXTERNAL failures never retry or downgrade to another mechanism.

The CLI always sends an empty authorization identity, asking the server to use the identity associated with the certificate.
Custom authorization identities are available only through the library API.
`auto` never selects EXTERNAL or loads a certificate; its password-family order remains unchanged.
`msieve capabilities` also does not load a certificate: it reports advertisement only, which does not prove certificate presentation, acceptance, or account authorization.
