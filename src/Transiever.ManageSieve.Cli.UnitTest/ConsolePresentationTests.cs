using Transiever.ManageSieve.Cli;

namespace Transiever.ManageSieve.Cli.UnitTest;

public sealed class ConsolePresentationTests
{
    [Fact]
    public void HelpListsOAuthBearerAndSafeTokenInput()
    {
        using var output = new StringWriter();

        ConsolePresentation.PrintHelp(output);

        string help = output.ToString();
        Assert.Contains("oauthbearer", help, StringComparison.Ordinal);
        Assert.Contains("--sieve-oauth-token-stdin", help, StringComparison.Ordinal);
        Assert.DoesNotContain("--sieve-oauth-token <", help, StringComparison.Ordinal);
    }
}
