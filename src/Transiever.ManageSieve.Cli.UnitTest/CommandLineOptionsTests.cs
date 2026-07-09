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
            "ImplicitTls"
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
