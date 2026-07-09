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
        bool inputRedirected = false) =>
        new(
            name => environment.TryGetValue(name, out string? value)
                ? value
                : null,
            () => inputRedirected,
            () => "prompted");
}
