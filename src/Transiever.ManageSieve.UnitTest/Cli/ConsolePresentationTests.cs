using Transiever.ManageSieve.Cli;

namespace Transiever.ManageSieve.Cli.UnitTest;

public sealed class ConsolePresentationTests
{
    [Fact]
    public void HelpListsExplicitSecretInputSelectors()
    {
        using var output = new StringWriter();

        ConsolePresentation.PrintHelp(output);

        string help = output.ToString();
        Assert.Contains("oauthbearer", help, StringComparison.Ordinal);
        Assert.Contains("--sieve-password-stdin", help, StringComparison.Ordinal);
        Assert.Contains(
            "--sieve-client-certificate-password-stdin",
            help,
            StringComparison.Ordinal);
        Assert.Contains("--sieve-oauth-token-stdin", help, StringComparison.Ordinal);
        Assert.DoesNotContain("--sieve-password <", help, StringComparison.Ordinal);
        Assert.DoesNotContain(
            "--sieve-client-certificate-password <",
            help,
            StringComparison.Ordinal);
        Assert.DoesNotContain("--sieve-oauth-token <", help, StringComparison.Ordinal);
    }
}
