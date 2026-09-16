using Transiever.ManageSieve;
using Transiever.ManageSieve.Cli;

namespace Transiever.ManageSieve.Cli.UnitTest;

public sealed class CommandLineOptionsTests
{
    [Fact]
    public void ParseReturnsHelpWhenNoArgumentsAreProvided()
    {
        CommandLineOptions options = CommandLineOptions.Parse([]);

        Assert.True(options.ShowHelp);
    }

    [Fact]
    public void ParseReadsPutArgumentsAndOverrides()
    {
        CommandLineOptions options = CommandLineOptions.Parse(
        [
            "put",
            "candidate",
            "--file",
            "candidate.sieve",
            "--activate",
            "--sieve-host",
            "sieve.example.com",
            "--sieve-port",
            "4190",
            "--sieve-username",
            "user",
            "--sieve-security-mode",
            "ImplicitTls",
            "--sieve-sasl-mechanism",
            "scram-sha-256"
        ]);

        Assert.Equal(ManageSieveCliCommand.Put, options.Command);
        Assert.Equal("candidate", options.ScriptName);
        Assert.Equal("candidate.sieve", options.File);
        Assert.True(options.Activate);
        Assert.Equal("sieve.example.com", options.SieveHost);
        Assert.Equal(4190, options.SievePort);
        Assert.Equal("user", options.SieveUserName);
        Assert.Equal(ManageSieveSecurityMode.ImplicitTls, options.SieveSecurity);
        Assert.Equal(ManageSieveSaslMechanism.ScramSha256, options.SieveSaslMechanism);
    }

    [Fact]
    public void ParseRejectsPasswordValueWithoutDisplayingIt()
    {
        const string password = "password-sentinel";

        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => CommandLineOptions.Parse(
                ["list", "--sieve-password", password]));

        Assert.Equal(
            "Passwords cannot be supplied through --sieve-password.",
            exception.Message);
        Assert.DoesNotContain(password, exception.Message);
    }

    [Theory]
    [InlineData("--sieve-password=review-sentinel")]
    [InlineData("--sieve-password-stdin", "-review-sentinel")]
    public void ParseRedactsPasswordValuesBeforeOrAfterTheCommand(params string[] args)
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => CommandLineOptions.Parse(args.Length == 1 ? args : ["list", ..args]));

        Assert.Equal("Secret input cannot be supplied through an option value.", exception.Message);
        Assert.DoesNotContain("review-sentinel", exception.Message);
    }

    [Theory]
    [InlineData("--sieve-password")]
    [InlineData("--sieve-password-stdin")]
    [InlineData("--sieve-client-certificate-password")]
    [InlineData("--sieve-client-certificate-password-stdin")]
    [InlineData("--sieve-oauth-token")]
    [InlineData("--sieve-oauth-token-stdin")]
    public void ParseRejectsSecretOptionValuesWithoutDisplayingThem(
        string optionName)
    {
        const string password = "password-sentinel";

        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => CommandLineOptions.Parse(
                ["list", $"{optionName}={password}"]));

        Assert.Equal(
            "Secret input cannot be supplied through an option value.",
            exception.Message);
        Assert.DoesNotContain(password, exception.Message);
    }

    [Theory]
    [InlineData("auto", ManageSieveSaslMechanism.Auto)]
    [InlineData("plain", ManageSieveSaslMechanism.Plain)]
    [InlineData("scram-sha-256", ManageSieveSaslMechanism.ScramSha256)]
    [InlineData("scram-sha-256-plus", ManageSieveSaslMechanism.ScramSha256Plus)]
    [InlineData("oauthbearer", ManageSieveSaslMechanism.OAuthBearer)]
    [InlineData("external", ManageSieveSaslMechanism.External)]
    public void ParseReadsSaslMechanism(string value, ManageSieveSaslMechanism expected)
    {
        CommandLineOptions options = CommandLineOptions.Parse(
            ["list", "--sieve-sasl-mechanism", value]);

        Assert.Equal(expected, options.SieveSaslMechanism);
    }

    [Fact]
    public void ParseRejectsUnknownSaslMechanism()
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => CommandLineOptions.Parse(
                ["list", "--sieve-sasl-mechanism", "login"]));

        Assert.Contains("SASL mechanism", exception.Message);
    }

    [Fact]
    public void ParseReadsOAuthBearerTokenStdinAsBooleanSelector()
    {
        CommandLineOptions options = CommandLineOptions.Parse(
            ["list", "--sieve-oauth-token-stdin"]);

        Assert.True(options.SieveOAuthTokenStdin);
    }

    [Fact]
    public void ParseReadsPasswordStdinAsBooleanSelector()
    {
        CommandLineOptions options = CommandLineOptions.Parse(
            ["list", "--sieve-password-stdin"]);

        Assert.True(options.SievePasswordStdin);
    }

    [Fact]
    public void ParseReadsClientCertificatePathWithoutAcceptingPassword()
    {
        CommandLineOptions options = CommandLineOptions.Parse(
            ["list", "--sieve-sasl-mechanism", "external", "--sieve-client-certificate", "client.pfx"]);

        Assert.Equal("client.pfx", options.SieveClientCertificate);
        Assert.Throws<ArgumentException>(() => CommandLineOptions.Parse(
            ["list", "--sieve-client-certificate-password", "secret"]));
    }

    [Fact]
    public void ParseReadsClientCertificatePasswordStdinAsBooleanSelector()
    {
        CommandLineOptions options = CommandLineOptions.Parse(
            ["list", "--sieve-client-certificate-password-stdin"]);

        Assert.True(options.SieveClientCertificatePasswordStdin);
    }

    [Fact]
    public void ParseRejectsTokenValuedOption()
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => CommandLineOptions.Parse(
                ["list", "--sieve-oauth-token", "secret"]));

        Assert.Contains("Unknown option", exception.Message);
    }

    [Fact]
    public void ParseDoesNotTreatValueAfterOAuthBearerTokenStdinAsToken()
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => CommandLineOptions.Parse(
                ["list", "--sieve-oauth-token-stdin", "secret"]));

        Assert.Contains("Unexpected argument", exception.Message);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("65536")]
    [InlineData("abc")]
    public void ParseRejectsInvalidPorts(string port)
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => CommandLineOptions.Parse(["list", "--sieve-port", port]));

        Assert.Contains("TCP port", exception.Message);
    }

    [Fact]
    public void ParseRejectsUnknownOptions()
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => CommandLineOptions.Parse(["list", "--unknown"]));

        Assert.Contains("Unknown option", exception.Message);
    }

    [Theory]
    [InlineData("3")]
    [InlineData("99")]
    public void ParseRejectsUndefinedSieveSecurityModes(string mode)
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => CommandLineOptions.Parse(
                ["list", "--sieve-security-mode", mode]));

        Assert.Contains("security mode", exception.Message);
    }

    [Fact]
    public void ParseRequiresScriptNameForGet()
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => CommandLineOptions.Parse(["get"]));

        Assert.Contains("requires a script name", exception.Message);
    }

    [Fact]
    public void ParseRequiresFileForCheck()
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => CommandLineOptions.Parse(["check"]));

        Assert.Contains("requires --file", exception.Message);
    }
}
