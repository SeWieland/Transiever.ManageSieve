using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Transiever.ManageSieve;
using Transiever.ManageSieve.Cli;

namespace Transiever.ManageSieve.Cli.UnitTest;

public sealed class SieveServerConfigurationProviderTests
{
    [Fact]
    public void ConnectionOptionsUseEnvironmentDefaults()
    {
        var provider = CreateProvider(
            new Dictionary<string, string?>
            {
                ["TRANSIEVER_SIEVE_HOST"] = "sieve.example.com"
            });

        ManageSieveClientOptions options =
            provider.GetConnectionOptions(CommandLineOptions.Parse(["capabilities"]));

        Assert.Equal("sieve.example.com", options.Host);
        Assert.Equal(4190, options.Port);
        Assert.Equal(ManageSieveSecurityMode.StartTlsRequired, options.SecurityMode);
    }

    [Fact]
    public void OptionsOverrideEnvironment()
    {
        var provider = CreateProvider(
            new Dictionary<string, string?>
            {
                ["TRANSIEVER_SIEVE_HOST"] = "env.example.com",
                ["TRANSIEVER_SIEVE_PORT"] = "4190",
                ["TRANSIEVER_SIEVE_SECURITY_MODE"] = "StartTlsRequired"
            });

        ManageSieveClientOptions options = provider.GetConnectionOptions(
            CommandLineOptions.Parse(
            [
                "capabilities",
                "--sieve-host",
                "override.example.com",
                "--sieve-port",
                "2000",
                "--sieve-security-mode",
                "ImplicitTls"
            ]));

        Assert.Equal("override.example.com", options.Host);
        Assert.Equal(2000, options.Port);
        Assert.Equal(ManageSieveSecurityMode.ImplicitTls, options.SecurityMode);
    }

    [Fact]
    public void SaslMechanismDefaultsToAuto()
    {
        var provider = CreateProvider(
            new Dictionary<string, string?>());

        Assert.Equal(
            ManageSieveSaslMechanism.Auto,
            provider.GetSaslMechanism(CommandLineOptions.Parse(["list"])));
    }

    [Fact]
    public void SaslMechanismOptionOverridesEnvironment()
    {
        var provider = CreateProvider(
            new Dictionary<string, string?>
            {
                ["TRANSIEVER_SIEVE_SASL_MECHANISM"] = "scram-sha-256"
            });

        Assert.Equal(
            ManageSieveSaslMechanism.ScramSha256Plus,
            provider.GetSaslMechanism(
                CommandLineOptions.Parse(
                    ["list", "--sieve-sasl-mechanism", "scram-sha-256-plus"])));
    }

    [Fact]
    public void SaslMechanismReadsEnvironment()
    {
        var provider = CreateProvider(
            new Dictionary<string, string?>
            {
                ["TRANSIEVER_SIEVE_SASL_MECHANISM"] = "scram-sha-256-plus"
            });

        Assert.Equal(
            ManageSieveSaslMechanism.ScramSha256Plus,
            provider.GetSaslMechanism(CommandLineOptions.Parse(["list"])));
    }

    [Fact]
    public void ExternalCertificateUsesOptionPathAndEnvironmentPassword()
    {
        string? loadedPath = null;
        string? loadedPassword = null;
        X509KeyStorageFlags loadedFlags = default;
        using X509Certificate2 certificate = CreateCertificate();
        var provider = CreateProvider(
            new Dictionary<string, string?>
            {
                ["TRANSIEVER_SIEVE_HOST"] = "sieve.example.com",
                ["TRANSIEVER_SIEVE_SASL_MECHANISM"] = "external",
                ["TRANSIEVER_SIEVE_CLIENT_CERTIFICATE"] = "environment.pfx",
                ["TRANSIEVER_SIEVE_CLIENT_CERTIFICATE_PASSWORD"] = "environment-secret"
            },
            loadPkcs12: (path, password, flags) =>
            {
                loadedPath = path;
                loadedPassword = password;
                loadedFlags = flags;
                return certificate;
            });

        ManageSieveClientOptions options = provider.GetAuthenticatedConnectionOptions(
            CommandLineOptions.Parse(
                ["list", "--sieve-client-certificate", "option.pfx"]),
            ManageSieveSaslMechanism.External);

        Assert.Same(certificate, options.ClientCertificate);
        Assert.Equal("option.pfx", loadedPath);
        Assert.Equal("environment-secret", loadedPassword);
        Assert.Equal(
            OperatingSystem.IsWindows()
                ? X509KeyStorageFlags.UserKeySet
                : X509KeyStorageFlags.EphemeralKeySet,
            loadedFlags);
        Assert.False(loadedFlags.HasFlag(X509KeyStorageFlags.PersistKeySet));
        Assert.False(loadedFlags.HasFlag(X509KeyStorageFlags.Exportable));
        Assert.False(loadedFlags.HasFlag(X509KeyStorageFlags.MachineKeySet));
    }

    [Fact]
    public void ExternalCertificateUsesHiddenPromptWhenPasswordEnvironmentIsMissing()
    {
        var passwordReads = 0;
        using X509Certificate2 certificate = CreateCertificate();
        var provider = CreateProvider(
            new Dictionary<string, string?>
            {
                ["TRANSIEVER_SIEVE_HOST"] = "sieve.example.com",
                ["TRANSIEVER_SIEVE_SASL_MECHANISM"] = "external",
                ["TRANSIEVER_SIEVE_CLIENT_CERTIFICATE"] = "client.pfx"
            },
            readCertificatePassword: () =>
            {
                passwordReads++;
                return "prompt-secret";
            },
            loadPkcs12: (_, password, _) =>
            {
                Assert.Equal("prompt-secret", password);
                return certificate;
            });

        _ = provider.GetAuthenticatedConnectionOptions(
            CommandLineOptions.Parse(["list"]),
            ManageSieveSaslMechanism.External);

        Assert.Equal(1, passwordReads);
    }

    [Fact]
    public void CapabilitiesDoesNotLoadExternalCertificate()
    {
        var loadCount = 0;
        var provider = CreateProvider(
            new Dictionary<string, string?>
            {
                ["TRANSIEVER_SIEVE_HOST"] = "sieve.example.com",
                ["TRANSIEVER_SIEVE_SASL_MECHANISM"] = "external",
                ["TRANSIEVER_SIEVE_CLIENT_CERTIFICATE"] = "client.pfx"
            },
            loadPkcs12: (_, _, _) =>
            {
                loadCount++;
                return CreateCertificate();
            });

        ManageSieveClientOptions options = provider.GetConnectionOptions(
            CommandLineOptions.Parse(["capabilities"]));

        Assert.Null(options.ClientCertificate);
        Assert.Equal(0, loadCount);
    }

    [Fact]
    public void AutoDoesNotLoadConfiguredExternalCertificate()
    {
        var loadCount = 0;
        var provider = CreateProvider(
            new Dictionary<string, string?>
            {
                ["TRANSIEVER_SIEVE_HOST"] = "sieve.example.com",
                ["TRANSIEVER_SIEVE_CLIENT_CERTIFICATE"] = "client.pfx"
            },
            loadPkcs12: (_, _, _) =>
            {
                loadCount++;
                return CreateCertificate();
            });

        ManageSieveClientOptions options = provider.GetAuthenticatedConnectionOptions(
            CommandLineOptions.Parse(["list"]),
            ManageSieveSaslMechanism.Auto);

        Assert.Null(options.ClientCertificate);
        Assert.Equal(0, loadCount);
    }

    [Fact]
    public void PlaintextExternalFailsBeforeCertificateLoading()
    {
        var loadCount = 0;
        var provider = CreateProvider(
            new Dictionary<string, string?>
            {
                ["TRANSIEVER_SIEVE_HOST"] = "sieve.example.com",
                ["TRANSIEVER_SIEVE_SECURITY_MODE"] = "PlainText",
                ["TRANSIEVER_SIEVE_CLIENT_CERTIFICATE"] = "client.pfx"
            },
            loadPkcs12: (_, _, _) =>
            {
                loadCount++;
                return CreateCertificate();
            });

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(
            () => provider.GetAuthenticatedConnectionOptions(
                CommandLineOptions.Parse(["list"]),
                ManageSieveSaslMechanism.External));

        Assert.Contains("plaintext", exception.Message);
        Assert.Equal(0, loadCount);
    }

    [Fact]
    public void CertificateLoadFailureUsesFixedDiagnostic()
    {
        var provider = CreateProvider(
            new Dictionary<string, string?>
            {
                ["TRANSIEVER_SIEVE_HOST"] = "sieve.example.com",
                ["TRANSIEVER_SIEVE_CLIENT_CERTIFICATE_PASSWORD"] = "super-secret"
            },
            loadPkcs12: (path, password, _) =>
                throw new CryptographicException($"bad {path} {password}"));

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(
            () => provider.GetAuthenticatedConnectionOptions(
                CommandLineOptions.Parse(
                    ["list", "--sieve-client-certificate", "private-client.pfx"]),
                ManageSieveSaslMechanism.External));

        Assert.Equal(
            "The configured Sieve client certificate could not be loaded.",
            exception.Message);
        Assert.DoesNotContain("private-client.pfx", exception.Message);
        Assert.DoesNotContain("super-secret", exception.Message);
    }

    [Fact]
    public void OAuthBearerTokenReadsOneLineOnlyWhenStdinIsSelected()
    {
        var lineReads = 0;
        var hiddenReads = 0;
        var provider = CreateProvider(
            new Dictionary<string, string?>
            {
                ["TRANSIEVER_SIEVE_SASL_MECHANISM"] = "oauthbearer",
                ["TRANSIEVER_SIEVE_OAUTH_TOKEN"] = "environment-token"
            },
            inputRedirected: true,
            readOAuthToken: () =>
            {
                hiddenReads++;
                return "hidden-token";
            },
            readLine: () =>
            {
                lineReads++;
                return "stdin-token";
            });

        string token = provider.GetOAuthBearerToken(
            CommandLineOptions.Parse(
                ["list", "--sieve-oauth-token-stdin"]));

        Assert.Equal("stdin-token", token);
        Assert.Equal(1, lineReads);
        Assert.Equal(0, hiddenReads);
    }

    [Fact]
    public void OAuthBearerTokenUsesHiddenPromptOnInteractiveInput()
    {
        var lineReads = 0;
        var hiddenReads = 0;
        var provider = CreateProvider(
            new Dictionary<string, string?>
            {
                ["TRANSIEVER_SIEVE_SASL_MECHANISM"] = "oauthbearer"
            },
            readOAuthToken: () =>
            {
                hiddenReads++;
                return "hidden-token";
            },
            readLine: () =>
            {
                lineReads++;
                return "stdin-token";
            });

        string token = provider.GetOAuthBearerToken(
            CommandLineOptions.Parse(["list"]));

        Assert.Equal("hidden-token", token);
        Assert.Equal(0, lineReads);
        Assert.Equal(1, hiddenReads);
    }

    [Fact]
    public void OAuthBearerTokenRejectsRedirectedInputWithoutStdinSelector()
    {
        var inputReads = 0;
        var provider = CreateProvider(
            new Dictionary<string, string?>
            {
                ["TRANSIEVER_SIEVE_SASL_MECHANISM"] = "oauthbearer",
                ["TRANSIEVER_SIEVE_OAUTH_TOKEN"] = "environment-token"
            },
            inputRedirected: true,
            readOAuthToken: () =>
            {
                inputReads++;
                return "hidden-token";
            },
            readLine: () =>
            {
                inputReads++;
                return "stdin-token";
            });

        InvalidOperationException exception =
            Assert.Throws<InvalidOperationException>(
                () => provider.GetOAuthBearerToken(
                    CommandLineOptions.Parse(["list"])));

        Assert.Contains("--sieve-oauth-token-stdin", exception.Message);
        Assert.Equal(0, inputReads);
    }

    [Fact]
    public void OAuthBearerTokenRejectsNonOAuthSelectionWithoutReadingInput()
    {
        var inputReads = 0;
        var provider = CreateProvider(
            new Dictionary<string, string?>(),
            readOAuthToken: () =>
            {
                inputReads++;
                return "hidden-token";
            },
            readLine: () =>
            {
                inputReads++;
                return "stdin-token";
            });

        Assert.Throws<InvalidOperationException>(
            () => provider.GetOAuthBearerToken(
                CommandLineOptions.Parse(["list"])));

        Assert.Equal(0, inputReads);
    }

    [Fact]
    public void SaslMechanismRejectsInvalidEnvironmentValue()
    {
        var provider = CreateProvider(
            new Dictionary<string, string?>
            {
                ["TRANSIEVER_SIEVE_SASL_MECHANISM"] = "login"
            });

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(
            () => provider.GetSaslMechanism(CommandLineOptions.Parse(["list"])));

        Assert.Contains("SASL mechanism", exception.Message);
    }

    [Theory]
    [InlineData("3")]
    [InlineData("99")]
    public void ConnectionOptionsRejectUndefinedSecurityModeFromEnvironment(string mode)
    {
        var provider = CreateProvider(
            new Dictionary<string, string?>
            {
                ["TRANSIEVER_SIEVE_HOST"] = "sieve.example.com",
                ["TRANSIEVER_SIEVE_SECURITY_MODE"] = mode
            });

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(
            () => provider.GetConnectionOptions(CommandLineOptions.Parse(["list"])));

        Assert.Contains("security mode", exception.Message);
    }

    [Fact]
    public void AuthenticatedConfigurationReadsCredentials()
    {
        var provider = CreateProvider(
            new Dictionary<string, string?>
            {
                ["TRANSIEVER_SIEVE_HOST"] = "sieve.example.com",
                ["TRANSIEVER_SIEVE_USERNAME"] = "user@example.com",
                ["TRANSIEVER_SIEVE_PASSWORD"] = "secret"
            });

        SieveServerConfiguration configuration =
            provider.GetAuthenticatedConfiguration(
                CommandLineOptions.Parse(["list"]));

        Assert.Equal("user@example.com", configuration.UserName);
        Assert.Equal("secret", configuration.Password);
    }

    [Fact]
    public void AuthenticatedConfigurationRejectsPlaintextCredentials()
    {
        var provider = CreateProvider(
            new Dictionary<string, string?>
            {
                ["TRANSIEVER_SIEVE_HOST"] = "sieve.example.com",
                ["TRANSIEVER_SIEVE_USERNAME"] = "user@example.com",
                ["TRANSIEVER_SIEVE_PASSWORD"] = "secret",
                ["TRANSIEVER_SIEVE_SECURITY_MODE"] = "PlainText"
            });

        InvalidOperationException exception =
            Assert.Throws<InvalidOperationException>(
                () => provider.GetAuthenticatedConfiguration(
                    CommandLineOptions.Parse(["list"])));

        Assert.Contains("plaintext", exception.Message);
    }

    [Fact]
    public void MissingPasswordThrowsWhenInputIsRedirected()
    {
        var provider = CreateProvider(
            new Dictionary<string, string?>
            {
                ["TRANSIEVER_SIEVE_HOST"] = "sieve.example.com",
                ["TRANSIEVER_SIEVE_USERNAME"] = "user@example.com"
            },
            inputRedirected: true);

        InvalidOperationException exception =
            Assert.Throws<InvalidOperationException>(
                () => provider.GetAuthenticatedConfiguration(
                    CommandLineOptions.Parse(["list"])));

        Assert.Contains("TRANSIEVER_SIEVE_PASSWORD", exception.Message);
    }

    private static EnvironmentSieveServerConfigurationProvider CreateProvider(
        IReadOnlyDictionary<string, string?> environment,
        bool inputRedirected = false,
        Func<string>? readOAuthToken = null,
        Func<string?>? readLine = null,
        Func<string>? readCertificatePassword = null,
        Func<string, string?, X509KeyStorageFlags, X509Certificate2>? loadPkcs12 = null) =>
        new(
            name => environment.TryGetValue(name, out string? value)
                ? value
                : null,
            () => inputRedirected,
            () => "prompted",
            readOAuthToken ?? (() => "oauth-token"),
            readLine ?? (() => null),
            readCertificatePassword,
            loadPkcs12);

    private static X509Certificate2 CreateCertificate()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=CLI test",
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-1),
            DateTimeOffset.UtcNow.AddMinutes(5));
    }
}
