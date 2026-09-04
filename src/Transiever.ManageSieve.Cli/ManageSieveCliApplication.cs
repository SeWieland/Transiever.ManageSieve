using Transiever.ManageSieve;

namespace Transiever.ManageSieve.Cli;

public sealed class ManageSieveCliApplication
{
    private readonly IManageSieveClientFactory clientFactory;
    private readonly ISieveServerConfigurationProvider configurationProvider;
    private readonly Stream standardOutput;
    private readonly TextWriter textOutput;

    public ManageSieveCliApplication(
        IManageSieveClientFactory clientFactory,
        ISieveServerConfigurationProvider configurationProvider,
        Stream standardOutput,
        TextWriter textOutput)
    {
        this.clientFactory = clientFactory;
        this.configurationProvider = configurationProvider;
        this.standardOutput = standardOutput;
        this.textOutput = textOutput;
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
        ManageSieveClientOptions connectionOptions =
            configurationProvider.GetConnectionOptions(options);
        await using IManageSieveClient client =
            await ConnectAsync(connectionOptions, cancellationToken);
        ManageSieveCapabilities capabilities =
            await client.RefreshCapabilitiesAsync(cancellationToken);
        ConsolePresentation.PrintCapabilities(textOutput, capabilities);
    }

    private async Task ListScriptsAsync(
        CommandLineOptions options,
        CancellationToken cancellationToken)
    {
        await using IManageSieveClient client =
            await ConnectAuthenticatedAsync(options, cancellationToken);
        IReadOnlyList<ManageSieveScriptInfo> scripts =
            await client.ListScriptsAsync(cancellationToken);
        ConsolePresentation.PrintScripts(textOutput, scripts);
    }

    private async Task GetScriptAsync(
        CommandLineOptions options,
        CancellationToken cancellationToken)
    {
        await using IManageSieveClient client =
            await ConnectAuthenticatedAsync(options, cancellationToken);
        ManageSieveScript script =
            await client.GetScriptAsync(options.ScriptName!, cancellationToken);

        if (options.OutputFile is { Length: > 0 } outputFile)
        {
            await File.WriteAllBytesAsync(
                outputFile,
                script.Content.ToArray(),
                cancellationToken);
            textOutput.WriteLine($"Wrote {outputFile}.");
            return;
        }

        await standardOutput.WriteAsync(script.Content, cancellationToken);
    }

    private async Task CheckScriptAsync(
        CommandLineOptions options,
        CancellationToken cancellationToken)
    {
        byte[] content = await File.ReadAllBytesAsync(
            options.File!,
            cancellationToken);
        await using IManageSieveClient client =
            await ConnectAuthenticatedAsync(options, cancellationToken);
        ManageSieveCommandResult result =
            await client.CheckScriptAsync(content, cancellationToken);
        ConsolePresentation.PrintResult(textOutput, "Script is valid.", result);
    }

    private async Task PutScriptAsync(
        CommandLineOptions options,
        CancellationToken cancellationToken)
    {
        byte[] content = await File.ReadAllBytesAsync(
            options.File!,
            cancellationToken);
        await using IManageSieveClient client =
            await ConnectAuthenticatedAsync(options, cancellationToken);
        ManageSieveCommandResult result =
            await client.PutScriptAsync(
                options.ScriptName!,
                content,
                cancellationToken);
        ConsolePresentation.PrintResult(
            textOutput,
            $"Uploaded '{options.ScriptName}'.",
            result);

        if (options.Activate)
        {
            ManageSieveCommandResult activation =
                await client.SetActiveScriptAsync(
                    options.ScriptName,
                    cancellationToken);
            ConsolePresentation.PrintResult(
                textOutput,
                $"Activated '{options.ScriptName}'.",
                activation);
        }
    }

    private async Task ActivateScriptAsync(
        CommandLineOptions options,
        CancellationToken cancellationToken)
    {
        await using IManageSieveClient client =
            await ConnectAuthenticatedAsync(options, cancellationToken);
        ManageSieveCommandResult result =
            await client.SetActiveScriptAsync(
                options.ScriptName,
                cancellationToken);
        ConsolePresentation.PrintResult(
            textOutput,
            $"Activated '{options.ScriptName}'.",
            result);
    }

    private async Task DeactivateScriptAsync(
        CommandLineOptions options,
        CancellationToken cancellationToken)
    {
        await using IManageSieveClient client =
            await ConnectAuthenticatedAsync(options, cancellationToken);
        ManageSieveCommandResult result =
            await client.SetActiveScriptAsync(null, cancellationToken);
        ConsolePresentation.PrintResult(
            textOutput,
            "Deactivated Sieve processing.",
            result);
    }

    private async Task DeleteScriptAsync(
        CommandLineOptions options,
        CancellationToken cancellationToken)
    {
        await using IManageSieveClient client =
            await ConnectAuthenticatedAsync(options, cancellationToken);
        ManageSieveCommandResult result =
            await client.DeleteScriptAsync(
                options.ScriptName!,
                cancellationToken);
        ConsolePresentation.PrintResult(
            textOutput,
            $"Deleted '{options.ScriptName}'.",
            result);
    }

    private async Task<IManageSieveClient> ConnectAuthenticatedAsync(
        CommandLineOptions options,
        CancellationToken cancellationToken)
    {
        // Credentials are requested only after TLS and capability validation.
        ManageSieveClientOptions connectionOptions =
            configurationProvider.GetConnectionOptions(options);
        if (connectionOptions.SecurityMode == ManageSieveSecurityMode.PlainText)
        {
            throw new InvalidOperationException(
                "msieve does not send credentials over a plaintext ManageSieve connection.");
        }

        ManageSieveSaslMechanism requestedMechanism =
            configurationProvider.GetSaslMechanism(options);
        IManageSieveClient client =
            await ConnectAsync(connectionOptions, cancellationToken);

        try
        {
            ManageSieveCapabilities capabilities = client.Capabilities ??
                await client.RefreshCapabilitiesAsync(cancellationToken);
            string selectedMechanism = SelectSaslMechanism(
                requestedMechanism,
                capabilities.SaslMechanisms);

            SieveServerConfiguration configuration =
                configurationProvider.GetAuthenticatedConfiguration(options);
            IManageSieveAuthenticator authenticator = selectedMechanism switch
            {
                "SCRAM-SHA-256" => new ManageSieveScramSha256Authenticator(
                    configuration.UserName,
                    configuration.Password),
                _ => new ManageSievePlainAuthenticator(
                    configuration.UserName,
                    configuration.Password)
            };

            await client.AuthenticateAsync(authenticator, cancellationToken);
            return client;
        }
        catch
        {
            await client.DisposeAsync();
            throw;
        }
    }

    private static string SelectSaslMechanism(
        ManageSieveSaslMechanism requested,
        IReadOnlySet<string> advertised)
    {
        if (requested == ManageSieveSaslMechanism.Auto)
        {
            if (advertised.Contains("SCRAM-SHA-256"))
            {
                return "SCRAM-SHA-256";
            }

            if (advertised.Contains("PLAIN"))
            {
                return "PLAIN";
            }

            throw new ManageSieveAuthenticationException(
                "The server did not advertise SCRAM-SHA-256 or PLAIN.");
        }

        string mechanism = requested switch
        {
            ManageSieveSaslMechanism.Plain => "PLAIN",
            ManageSieveSaslMechanism.ScramSha256 => "SCRAM-SHA-256",
            _ => throw new ManageSieveAuthenticationException(
                $"Unknown Sieve SASL mechanism: {requested}.")
        };
        if (!advertised.Contains(mechanism))
        {
            throw new ManageSieveAuthenticationException(
                $"The server did not advertise the selected SASL mechanism: {mechanism}.");
        }

        return mechanism;
    }

    private async Task<IManageSieveClient> ConnectAsync(
        ManageSieveClientOptions options,
        CancellationToken cancellationToken)
    {
        IManageSieveClient client = clientFactory.CreateClient(options);
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
}
