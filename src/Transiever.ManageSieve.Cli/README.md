# `msieve`

This guide is the canonical command reference for the ManageSieve CLI.
Repository overview lives in [../../README.md](../../README.md).
Library API details live in [../Transiever.ManageSieve/README.md](../Transiever.ManageSieve/README.md).

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
```

Use `--sieve-host`, `--sieve-port`, `--sieve-username`, `--sieve-password`,
and `--sieve-security-mode` to override those values for a targeted command.
The port and security mode are optional.
The default is port `4190` with required STARTTLS.
`ImplicitTls` is also supported.

Authenticated commands refuse plaintext credentials.
If the password variable is absent, an interactive terminal prompts without echoing it.
