using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Transiever.ManageSieve;

namespace Transiever.ManageSieve.Cli;

public sealed record SieveServerConfiguration(
    ManageSieveClientOptions Options,
    string UserName,
    string Password);

public interface ISieveServerConfigurationProvider
{
    ManageSieveClientOptions GetConnectionOptions(CommandLineOptions options);

    ManageSieveClientOptions GetAuthenticatedConnectionOptions(
        CommandLineOptions options,
        ManageSieveSaslMechanism requestedMechanism) =>
        GetConnectionOptions(options);

    ManageSieveSaslMechanism GetSaslMechanism(CommandLineOptions options);

    SieveServerConfiguration GetAuthenticatedConfiguration(
        CommandLineOptions options);

    string GetOAuthBearerToken(CommandLineOptions options);
}

public sealed class EnvironmentSieveServerConfigurationProvider
    : ISieveServerConfigurationProvider
{
    private readonly Func<string, string?> _readEnvironment;
    private readonly Func<bool> _isInputRedirected;
    private readonly Func<string> _readPassword;
    private readonly Func<string> _readOAuthToken;
    private readonly Func<string?> _readLine;
    private readonly Func<string> _readCertificatePassword;
    private readonly Func<string, string?, X509KeyStorageFlags, X509Certificate2>
        _loadPkcs12;

    public EnvironmentSieveServerConfigurationProvider()
        : this(
            Environment.GetEnvironmentVariable,
            () => Console.IsInputRedirected,
            ReadPassword,
            ReadOAuthToken,
            Console.ReadLine,
            ReadCertificatePassword)
    {
    }

    public EnvironmentSieveServerConfigurationProvider(
        Func<string, string?> readEnvironment,
        Func<bool> isInputRedirected,
        Func<string> readPassword,
        Func<string>? readOAuthToken = null,
        Func<string?>? readLine = null)
        : this(
            readEnvironment,
            isInputRedirected,
            readPassword,
            readOAuthToken,
            readLine,
            null,
            null)
    {
    }

    internal EnvironmentSieveServerConfigurationProvider(
        Func<string, string?> readEnvironment,
        Func<bool> isInputRedirected,
        Func<string> readPassword,
        Func<string>? readOAuthToken,
        Func<string?>? readLine,
        Func<string>? readCertificatePassword = null,
        Func<string, string?, X509KeyStorageFlags, X509Certificate2>? loadPkcs12 = null)
    {
        _readEnvironment = readEnvironment;
        _isInputRedirected = isInputRedirected;
        _readPassword = readPassword;
        _readOAuthToken = readOAuthToken ?? readPassword;
        _readLine = readLine ?? Console.ReadLine;
        _readCertificatePassword = readCertificatePassword ?? ReadCertificatePassword;
        _loadPkcs12 = loadPkcs12 ??
            ((path, password, flags) =>
                X509CertificateLoader.LoadPkcs12FromFile(path, password, flags));
    }

    public ManageSieveClientOptions GetConnectionOptions(
        CommandLineOptions options)
    {
        string host = options.SieveHost ?? Required("HOST");
        int port = options.SievePort ?? ReadPort();
        ManageSieveSecurityMode security = options.SieveSecurity ?? ReadSecurityMode();

        return new ManageSieveClientOptions
        {
            Host = host,
            Port = port,
            SecurityMode = security
        };
    }

    public ManageSieveClientOptions GetAuthenticatedConnectionOptions(
        CommandLineOptions options,
        ManageSieveSaslMechanism requestedMechanism)
    {
        ManageSieveClientOptions connectionOptions = GetConnectionOptions(options);
        if (requestedMechanism != ManageSieveSaslMechanism.External)
        {
            return connectionOptions;
        }

        if (connectionOptions.SecurityMode == ManageSieveSecurityMode.PlainText)
        {
            throw new InvalidOperationException(
                "msieve does not use EXTERNAL over a plaintext ManageSieve connection.");
        }

        return connectionOptions with
        {
            ClientCertificate = LoadClientCertificate(options)
        };
    }

    public ManageSieveSaslMechanism GetSaslMechanism(
        CommandLineOptions options) =>
        options.SieveSaslMechanism ?? ReadSaslMechanism();

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

    public string GetOAuthBearerToken(CommandLineOptions options)
    {
        if (GetSaslMechanism(options) != ManageSieveSaslMechanism.OAuthBearer)
        {
            throw new InvalidOperationException(
                "An OAuth bearer token is valid only with the oauthbearer SASL mechanism.");
        }

        if (options.SieveOAuthTokenStdin)
        {
            return _readLine() is { Length: > 0 } token
                ? token
                : throw new InvalidOperationException(
                    "Standard input did not contain an OAuth bearer token.");
        }

        if (_isInputRedirected())
        {
            throw new InvalidOperationException(
                "Use --sieve-oauth-token-stdin to read an OAuth bearer token from redirected standard input.");
        }

        return _readOAuthToken();
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
            out ManageSieveSecurityMode mode) &&
            Enum.IsDefined(mode))
        {
            return mode;
        }

        throw new InvalidOperationException(
            $"Unknown Sieve security mode: {value}");
    }

    private ManageSieveSaslMechanism ReadSaslMechanism()
    {
        string? value = Read("SASL_MECHANISM");
        if (string.IsNullOrWhiteSpace(value))
        {
            return ManageSieveSaslMechanism.Auto;
        }

        return value.ToLowerInvariant() switch
        {
            "auto" => ManageSieveSaslMechanism.Auto,
            "plain" => ManageSieveSaslMechanism.Plain,
            "scram-sha-256" => ManageSieveSaslMechanism.ScramSha256,
            "scram-sha-256-plus" => ManageSieveSaslMechanism.ScramSha256Plus,
            "oauthbearer" => ManageSieveSaslMechanism.OAuthBearer,
            "external" => ManageSieveSaslMechanism.External,
            _ => throw new InvalidOperationException(
                $"Unknown Sieve SASL mechanism: {value}")
        };
    }

    private string Required(string suffix)
    {
        return Read(suffix) is { Length: > 0 } value
            ? value
            : throw new InvalidOperationException(
                $"Environment variable TRANSIEVER_SIEVE_{suffix} is required.");
    }

    private string? Read(string suffix) =>
        _readEnvironment($"TRANSIEVER_SIEVE_{suffix}");

    private string ReadPasswordOrThrow()
    {
        if (_isInputRedirected())
        {
            throw new InvalidOperationException(
                "TRANSIEVER_SIEVE_PASSWORD is required when input is redirected.");
        }

        return _readPassword();
    }

    private static string ReadPassword() =>
        ReadSecret("ManageSieve password: ");

    private static string ReadCertificatePassword() =>
        ReadSecret("ManageSieve client certificate password: ");

    private static string ReadOAuthToken() =>
        ReadSecret("ManageSieve OAuth bearer token: ");

    private static string ReadSecret(string prompt)
    {
        Console.Write(prompt);
        var secret = new System.Text.StringBuilder();
        while (true)
        {
            ConsoleKeyInfo key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                break;
            }

            if (key.Key == ConsoleKey.Backspace)
            {
                if (secret.Length > 0)
                {
                    secret.Length--;
                }

                continue;
            }

            if (!char.IsControl(key.KeyChar))
            {
                secret.Append(key.KeyChar);
            }
        }

        Console.WriteLine();
        return secret.ToString();
    }

    private X509Certificate2 LoadClientCertificate(CommandLineOptions options)
    {
        string path = options.SieveClientCertificate ??
            Required("CLIENT_CERTIFICATE");
        string? password = Read("CLIENT_CERTIFICATE_PASSWORD");
        if (password is null)
        {
            if (_isInputRedirected())
            {
                throw new InvalidOperationException(
                    "TRANSIEVER_SIEVE_CLIENT_CERTIFICATE_PASSWORD is required when input is redirected.");
            }

            password = _readCertificatePassword();
        }

        X509Certificate2? certificate = null;
        try
        {
            certificate = _loadPkcs12(
                path,
                password,
                OperatingSystem.IsWindows()
                    ? X509KeyStorageFlags.UserKeySet
                    : X509KeyStorageFlags.EphemeralKeySet);
            if (!certificate.HasPrivateKey)
            {
                certificate.Dispose();
                certificate = null;
                throw new InvalidOperationException();
            }

            return certificate;
        }
        catch (Exception exception) when (
            exception is ArgumentException or
            CryptographicException or
            IOException or
            InvalidOperationException or
            NotSupportedException or
            UnauthorizedAccessException)
        {
            certificate?.Dispose();
            throw new InvalidOperationException(
                "The configured Sieve client certificate could not be loaded.");
        }
    }
}
