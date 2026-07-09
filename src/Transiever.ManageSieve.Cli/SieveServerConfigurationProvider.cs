using Transiever.ManageSieve;

namespace Transiever.ManageSieve.Cli;

public sealed record SieveServerConfiguration(
    ManageSieveClientOptions Options,
    string UserName,
    string Password);

public interface ISieveServerConfigurationProvider
{
    ManageSieveClientOptions GetConnectionOptions(CommandLineOptions options);

    SieveServerConfiguration GetAuthenticatedConfiguration(
        CommandLineOptions options);
}

public sealed class EnvironmentSieveServerConfigurationProvider
    : ISieveServerConfigurationProvider
{
    private readonly Func<string, string?> readEnvironment;
    private readonly Func<bool> isInputRedirected;
    private readonly Func<string> readPassword;

    public EnvironmentSieveServerConfigurationProvider()
        : this(
            Environment.GetEnvironmentVariable,
            () => Console.IsInputRedirected,
            ReadPassword)
    {
    }

    public EnvironmentSieveServerConfigurationProvider(
        Func<string, string?> readEnvironment,
        Func<bool> isInputRedirected,
        Func<string> readPassword)
    {
        this.readEnvironment = readEnvironment;
        this.isInputRedirected = isInputRedirected;
        this.readPassword = readPassword;
    }

    public ManageSieveClientOptions GetConnectionOptions(
        CommandLineOptions options)
    {
        string host = options.SieveHost ?? Required("HOST");
        int port = options.SievePort ?? ReadPort();
        ManageSieveSecurityMode security =
            options.SieveSecurity ?? ReadSecurityMode();

        return new ManageSieveClientOptions
        {
            Host = host,
            Port = port,
            SecurityMode = security
        };
    }

    public SieveServerConfiguration GetAuthenticatedConfiguration(
        CommandLineOptions options)
    {
        ManageSieveClientOptions clientOptions = GetConnectionOptions(options);
        if (clientOptions.SecurityMode == ManageSieveSecurityMode.PlainText)
        {
            throw new InvalidOperationException(
                "msieve does not send credentials over a plaintext ManageSieve connection.");
        }

        string userName = options.SieveUserName ?? Required("USERNAME");
        string password =
            options.SievePassword ?? Read("PASSWORD") ?? ReadPasswordOrThrow();

        return new SieveServerConfiguration(clientOptions, userName, password);
    }

    private int ReadPort()
    {
        string? value = Read("PORT");
        if (string.IsNullOrWhiteSpace(value))
        {
            return ManageSieveClientOptions.DefaultPort;
        }

        if (int.TryParse(value, out int parsed) &&
            parsed is >= 1 and <= 65535)
        {
            return parsed;
        }

        throw new InvalidOperationException(
            "Environment variable TRANSIEVER_SIEVE_PORT must be a TCP port from 1 to 65535.");
    }

    private ManageSieveSecurityMode ReadSecurityMode()
    {
        string? value = Read("SECURITY_MODE");
        if (string.IsNullOrWhiteSpace(value))
        {
            return ManageSieveSecurityMode.StartTlsRequired;
        }

        if (Enum.TryParse(
            value,
            ignoreCase: true,
            out ManageSieveSecurityMode mode))
        {
            return mode;
        }

        throw new InvalidOperationException(
            $"Unknown Sieve security mode: {value}");
    }

    private string Required(string suffix)
    {
        return Read(suffix) is { Length: > 0 } value
            ? value
            : throw new InvalidOperationException(
                $"Environment variable TRANSIEVER_SIEVE_{suffix} is required.");
    }

    private string? Read(string suffix) =>
        readEnvironment($"TRANSIEVER_SIEVE_{suffix}");

    private string ReadPasswordOrThrow()
    {
        if (isInputRedirected())
        {
            throw new InvalidOperationException(
                "TRANSIEVER_SIEVE_PASSWORD is required when input is redirected.");
        }

        return readPassword();
    }

    private static string ReadPassword()
    {
        Console.Write("ManageSieve password: ");
        var password = new System.Text.StringBuilder();
        while (true)
        {
            ConsoleKeyInfo key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                break;
            }

            if (key.Key == ConsoleKey.Backspace)
            {
                if (password.Length > 0)
                {
                    password.Length--;
                }

                continue;
            }

            if (!char.IsControl(key.KeyChar))
            {
                password.Append(key.KeyChar);
            }
        }

        Console.WriteLine();
        return password.ToString();
    }
}
