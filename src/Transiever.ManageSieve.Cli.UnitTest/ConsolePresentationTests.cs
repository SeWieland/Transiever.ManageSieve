using Transiever.ManageSieve.Cli;

namespace Transiever.ManageSieve.Cli.UnitTest;

public sealed class ConsolePresentationTests
{
    [Fact]
    public void Help_lists_scram_sha_256_plus()
    {
        using var output = new StringWriter();

        ConsolePresentation.PrintHelp(output);

        Assert.Contains(
            "auto, plain, scram-sha-256, or scram-sha-256-plus.",
            output.ToString(),
            StringComparison.Ordinal);
    }
}
