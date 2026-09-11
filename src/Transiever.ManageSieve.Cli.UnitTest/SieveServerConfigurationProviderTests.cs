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
        Func<string?>? readLine = null) =>
        new(
            name => environment.TryGetValue(name, out string? value)
                ? value
                : null,
            () => inputRedirected,
            () => "prompted",
            readOAuthToken ?? (() => "oauth-token"),
            readLine ?? (() => null));
}
