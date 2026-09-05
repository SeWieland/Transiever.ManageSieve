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
            "--sieve-password",
            "secret",
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
        Assert.Equal("secret", options.SievePassword);
        Assert.Equal(ManageSieveSecurityMode.ImplicitTls, options.SieveSecurity);
        Assert.Equal(ManageSieveSaslMechanism.ScramSha256, options.SieveSaslMechanism);
    }

    [Theory]
    [InlineData("auto", ManageSieveSaslMechanism.Auto)]
    [InlineData("plain", ManageSieveSaslMechanism.Plain)]
    [InlineData("scram-sha-256", ManageSieveSaslMechanism.ScramSha256)]
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
