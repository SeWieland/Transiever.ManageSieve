using System.Security.Cryptography.X509Certificates;
using Transiever.ManageSieve;

namespace Transiever.ManageSieve.Cli;

public sealed class ManageSieveCliApplication
{
    private readonly IManageSieveClientFactory _clientFactory;
    private readonly ISieveServerConfigurationProvider _configurationProvider;
    private readonly Stream _standardOutput;
    private readonly TextWriter _textOutput;

    public ManageSieveCliApplication(
        IManageSieveClientFactory clientFactory,
        ISieveServerConfigurationProvider configurationProvider,
        Stream standardOutput,
        TextWriter textOutput)
    {
        _clientFactory = clientFactory;
        _configurationProvider = configurationProvider;
        _standardOutput = standardOutput;
        _textOutput = textOutput;
    }

    public async Task<int> RunAsync(
        CommandLineOptions options,
        CancellationToken cancellationToken = default)
    {
        switch (options.Command)
        {
            case ManageSieveCliCommand.Capabilities:
                await ShowCapabilitiesAsync(options, cancellationToken);
                return 0;
            case ManageSieveCliCommand.List:
                await ListScriptsAsync(options, cancellationToken);
                return 0;
            case ManageSieveCliCommand.Get:
                await GetScriptAsync(options, cancellationToken);
                return 0;
            case ManageSieveCliCommand.Check:
                await CheckScriptAsync(options, cancellationToken);
                return 0;
            case ManageSieveCliCommand.Put:
                await PutScriptAsync(options, cancellationToken);
                return 0;
            case ManageSieveCliCommand.Activate:
                await ActivateScriptAsync(options, cancellationToken);
                return 0;
            case ManageSieveCliCommand.Deactivate:
                await DeactivateScriptAsync(options, cancellationToken);
                return 0;
            case ManageSieveCliCommand.Delete:
                await DeleteScriptAsync(options, cancellationToken);
                return 0;
            default:
                throw new InvalidOperationException(
                    $"Unsupported command: {options.Command}");
        }
    }

    private async Task ShowCapabilitiesAsync(
        CommandLineOptions options,
        CancellationToken cancellationToken)
    {
        ManageSieveClientOptions connectionOptions = _configurationProvider.GetConnectionOptions(options);
        await using IManageSieveClient client =
            await ConnectAsync(connectionOptions, cancellationToken);
        ManageSieveCapabilities capabilities =
            await client.RefreshCapabilitiesAsync(cancellationToken);
        ManageSieveSaslMechanism requestedMechanism =
            _configurationProvider.GetSaslMechanism(options);
        string selection = DescribeSaslSelection(
            requestedMechanism,
            capabilities.SaslMechanisms,
            client,
            connectionOptions.SecurityMode);
        ConsolePresentation.PrintCapabilities(
            _textOutput,
            capabilities,
            selection,
            GetLocallyUsableSaslMechanisms(
                capabilities.SaslMechanisms,
                client,
                connectionOptions.SecurityMode),
            GetSaslExclusion(
                capabilities.SaslMechanisms,
                client,
                connectionOptions.SecurityMode));
    }

    private async Task ListScriptsAsync(
        CommandLineOptions options,
        CancellationToken cancellationToken)
    {
        await using CliClientSession session =
            await ConnectAuthenticatedAsync(options, cancellationToken);
        IManageSieveClient client = session.Client;
        IReadOnlyList<ManageSieveScriptInfo> scripts =
            await client.ListScriptsAsync(cancellationToken);
        ConsolePresentation.PrintScripts(_textOutput, scripts);
    }

    private async Task GetScriptAsync(
        CommandLineOptions options,
        CancellationToken cancellationToken)
    {
        await using CliClientSession session =
            await ConnectAuthenticatedAsync(options, cancellationToken);
        IManageSieveClient client = session.Client;
        ManageSieveScript script =
            await client.GetScriptAsync(options.ScriptName!, cancellationToken);

        if (options.OutputFile is { Length: > 0 } outputFile)
        {
            await File.WriteAllBytesAsync(
                outputFile,
                script.Content.ToArray(),
                cancellationToken);
            _textOutput.WriteLine($"Wrote {outputFile}.");
            return;
        }

        await _standardOutput.WriteAsync(script.Content, cancellationToken);
    }

    private async Task CheckScriptAsync(
        CommandLineOptions options,
        CancellationToken cancellationToken)
    {
        byte[] content = await File.ReadAllBytesAsync(
            options.File!,
            cancellationToken);
        await using CliClientSession session =
            await ConnectAuthenticatedAsync(options, cancellationToken);
        IManageSieveClient client = session.Client;
        ManageSieveCommandResult result =
            await client.CheckScriptAsync(content, cancellationToken);
        ConsolePresentation.PrintResult(_textOutput, "Script is valid.", result);
    }

    private async Task PutScriptAsync(
        CommandLineOptions options,
        CancellationToken cancellationToken)
    {
        byte[] content = await File.ReadAllBytesAsync(
            options.File!,
            cancellationToken);
        await using CliClientSession session =
            await ConnectAuthenticatedAsync(options, cancellationToken);
        IManageSieveClient client = session.Client;
        ManageSieveCommandResult result =
            await client.PutScriptAsync(
                options.ScriptName!,
                content,
                cancellationToken);
        ConsolePresentation.PrintResult(
            _textOutput,
            $"Uploaded '{options.ScriptName}'.",
            result);

        if (options.Activate)
        {
            ManageSieveCommandResult activation =
                await client.SetActiveScriptAsync(
                    options.ScriptName,
                    cancellationToken);
            ConsolePresentation.PrintResult(
                _textOutput,
                $"Activated '{options.ScriptName}'.",
                activation);
        }
    }

    private async Task ActivateScriptAsync(
        CommandLineOptions options,
        CancellationToken cancellationToken)
    {
        await using CliClientSession session =
            await ConnectAuthenticatedAsync(options, cancellationToken);
        IManageSieveClient client = session.Client;
        ManageSieveCommandResult result =
            await client.SetActiveScriptAsync(
                options.ScriptName,
                cancellationToken);
        ConsolePresentation.PrintResult(
            _textOutput,
            $"Activated '{options.ScriptName}'.",
            result);
    }

    private async Task DeactivateScriptAsync(
        CommandLineOptions options,
        CancellationToken cancellationToken)
    {
        await using CliClientSession session =
            await ConnectAuthenticatedAsync(options, cancellationToken);
        IManageSieveClient client = session.Client;
        ManageSieveCommandResult result =
            await client.SetActiveScriptAsync(null, cancellationToken);
        ConsolePresentation.PrintResult(
            _textOutput,
            "Deactivated Sieve processing.",
            result);
    }

    private async Task DeleteScriptAsync(
        CommandLineOptions options,
        CancellationToken cancellationToken)
    {
        await using CliClientSession session =
            await ConnectAuthenticatedAsync(options, cancellationToken);
        IManageSieveClient client = session.Client;
        ManageSieveCommandResult result =
            await client.DeleteScriptAsync(
                options.ScriptName!,
                cancellationToken);
        ConsolePresentation.PrintResult(
            _textOutput,
            $"Deleted '{options.ScriptName}'.",
            result);
    }

    private async Task<CliClientSession> ConnectAuthenticatedAsync(
        CommandLineOptions options,
        CancellationToken cancellationToken)
    {
        // Certificates are loaded before TLS; passwords and tokens wait for TLS and capabilities.
        ManageSieveSaslMechanism requestedMechanism = _configurationProvider.GetSaslMechanism(options);
        ManageSieveClientOptions connectionOptions =
            _configurationProvider.GetAuthenticatedConnectionOptions(
                options,
                requestedMechanism);
        if (connectionOptions.SecurityMode == ManageSieveSecurityMode.PlainText)
        {
            connectionOptions.ClientCertificate?.Dispose();
            throw new InvalidOperationException(
                "msieve does not send credentials over a plaintext ManageSieve connection.");
        }

        IManageSieveClient client;
        try
        {
            client = await ConnectAsync(connectionOptions, cancellationToken);
        }
        catch
        {
            connectionOptions.ClientCertificate?.Dispose();
            throw;
        }

        try
        {
            ManageSieveCapabilities capabilities = client.Capabilities ??
                await client.RefreshCapabilitiesAsync(cancellationToken);
            string selectedMechanism = SelectSaslMechanism(
                requestedMechanism,
                capabilities.SaslMechanisms,
                client);

            IManageSieveAuthenticator authenticator;
            if (selectedMechanism == "EXTERNAL")
            {
                authenticator = new ManageSieveExternalAuthenticator();
            }
            else if (selectedMechanism == "OAUTHBEARER")
            {
                string token = _configurationProvider.GetOAuthBearerToken(options);
                authenticator = new ManageSieveOAuthBearerAuthenticator(
                    token,
                    connectionOptions.Host,
                    connectionOptions.Port);
            }
            else
            {
                SieveServerConfiguration configuration =
                    _configurationProvider.GetAuthenticatedConfiguration(options);
                authenticator = selectedMechanism switch
                {
                    "SCRAM-SHA-256-PLUS" => new ManageSieveScramSha256PlusAuthenticator(
                        configuration.UserName,
                        configuration.Password),
                    "SCRAM-SHA-256" => new ManageSieveScramSha256Authenticator(
                        configuration.UserName,
                        configuration.Password),
                    _ => new ManageSievePlainAuthenticator(
                        configuration.UserName,
                        configuration.Password)
                };
            }

            await client.AuthenticateAsync(authenticator, cancellationToken);
            return new CliClientSession(client, connectionOptions.ClientCertificate);
        }
        catch
        {
            try
            {
                await client.DisposeAsync();
            }
            finally
            {
                connectionOptions.ClientCertificate?.Dispose();
            }

            throw;
        }
    }

    private static string SelectSaslMechanism(
        ManageSieveSaslMechanism requested,
        IReadOnlySet<string> advertised,
        IManageSieveClient client)
    {
        if (requested == ManageSieveSaslMechanism.Auto)
        {
            if (ContainsMechanism(advertised, "SCRAM-SHA-256-PLUS") &&
                client.CanUseScramSha256Plus)
            {
                return "SCRAM-SHA-256-PLUS";
            }

            if (ContainsMechanism(advertised, "SCRAM-SHA-256"))
            {
                return "SCRAM-SHA-256";
            }

            if (ContainsMechanism(advertised, "PLAIN"))
            {
                return "PLAIN";
            }

            throw new ManageSieveAuthenticationException(
                "The server did not advertise a locally usable SCRAM-SHA-256-PLUS, SCRAM-SHA-256, or PLAIN mechanism.");
        }

        string mechanism = requested switch
        {
            ManageSieveSaslMechanism.Plain => "PLAIN",
            ManageSieveSaslMechanism.ScramSha256 => "SCRAM-SHA-256",
            ManageSieveSaslMechanism.ScramSha256Plus => "SCRAM-SHA-256-PLUS",
            ManageSieveSaslMechanism.OAuthBearer => "OAUTHBEARER",
            ManageSieveSaslMechanism.External => "EXTERNAL",
            _ => throw new ManageSieveAuthenticationException(
                $"Unknown Sieve SASL mechanism: {requested}.")
        };
        if (!ContainsMechanism(advertised, mechanism))
        {
            throw new ManageSieveAuthenticationException(
                $"The server did not advertise the selected SASL mechanism: {mechanism}.");
        }

        if (requested == ManageSieveSaslMechanism.ScramSha256Plus &&
            !client.CanUseScramSha256Plus)
        {
            throw new ManageSieveAuthenticationException(
                "SCRAM-SHA-256-PLUS is not locally usable on this connection.");
        }

        return mechanism;
    }

    private static string DescribeSaslSelection(
        ManageSieveSaslMechanism requestedMechanism,
        IReadOnlySet<string> advertised,
        IManageSieveClient client,
        ManageSieveSecurityMode securityMode)
    {
        string requested = FormatSaslMechanism(requestedMechanism);
        if (securityMode == ManageSieveSecurityMode.PlainText)
        {
            return $"{requested} rejects: A protected connection is required.";
        }

        try
        {
            string selected = SelectSaslMechanism(
                requestedMechanism,
                advertised,
                client);
            return requestedMechanism == ManageSieveSaslMechanism.External
                ? $"{requested} rejects: A verified TLS client certificate is not available to capabilities."
                : $"{requested} selects {selected}";
        }
        catch (ManageSieveAuthenticationException exception)
        {
            if (requestedMechanism == ManageSieveSaslMechanism.ScramSha256Plus &&
                ContainsMechanism(advertised, "SCRAM-SHA-256-PLUS") &&
                !client.CanUseScramSha256Plus)
            {
                return $"{requested} rejects: SCRAM-SHA-256-PLUS requires supported TLS channel binding.";
            }

            return $"{requested} rejects: {exception.Message}";
        }
    }

    private static IReadOnlySet<string> GetLocallyUsableSaslMechanisms(
        IReadOnlySet<string> advertised,
        IManageSieveClient client,
        ManageSieveSecurityMode securityMode) =>
        securityMode == ManageSieveSecurityMode.PlainText
            ? new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            : advertised.Where(mechanism =>
            mechanism.Equals("PLAIN", StringComparison.OrdinalIgnoreCase) ||
            mechanism.Equals("SCRAM-SHA-256", StringComparison.OrdinalIgnoreCase) ||
            mechanism.Equals("SCRAM-SHA-256-PLUS", StringComparison.OrdinalIgnoreCase) &&
            client.CanUseScramSha256Plus)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

    private static bool ContainsMechanism(
        IReadOnlySet<string> advertised,
        string mechanism) =>
        advertised.Contains(mechanism, StringComparer.OrdinalIgnoreCase);

    private static string? GetSaslExclusion(
        IReadOnlySet<string> advertised,
        IManageSieveClient client,
        ManageSieveSecurityMode securityMode) =>
        securityMode != ManageSieveSecurityMode.PlainText &&
        ContainsMechanism(advertised, "SCRAM-SHA-256-PLUS") &&
        !client.CanUseScramSha256Plus
            ? "SCRAM-SHA-256-PLUS requires supported TLS channel binding."
            : null;

    private static string FormatSaslMechanism(ManageSieveSaslMechanism mechanism) =>
        mechanism switch
        {
            ManageSieveSaslMechanism.Auto => "auto",
            ManageSieveSaslMechanism.Plain => "plain",
            ManageSieveSaslMechanism.ScramSha256 => "scram-sha-256",
            ManageSieveSaslMechanism.ScramSha256Plus => "scram-sha-256-plus",
            ManageSieveSaslMechanism.OAuthBearer => "oauthbearer",
            ManageSieveSaslMechanism.External => "external",
            _ => mechanism.ToString().ToLowerInvariant()
        };

    private async Task<IManageSieveClient> ConnectAsync(
        ManageSieveClientOptions options,
        CancellationToken cancellationToken)
    {
        IManageSieveClient client = _clientFactory.CreateClient(options);
        try
        {
            await client.ConnectAsync(cancellationToken);
            if (options.SecurityMode == ManageSieveSecurityMode.StartTlsRequired)
            {
                await client.StartTlsAsync(cancellationToken);
            }

            return client;
        }
        catch
        {
            await client.DisposeAsync();
            throw;
        }
    }

    private sealed class CliClientSession(
        IManageSieveClient client,
        X509Certificate2? certificate) : IAsyncDisposable
    {
        public IManageSieveClient Client { get; } = client;

        public async ValueTask DisposeAsync()
        {
            try
            {
                await Client.DisposeAsync();
            }
            finally
            {
                certificate?.Dispose();
            }
        }
    }
}
