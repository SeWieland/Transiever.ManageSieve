using Transiever.ManageSieve;

namespace Transiever.ManageSieve.Cli;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        CommandLineOptions options;
        try
        {
            options = CommandLineOptions.Parse(args);
        }
        catch (ArgumentException exception)
        {
            Console.Error.WriteLine(exception.Message);
            ConsolePresentation.PrintHelp(Console.Out);
            return 1;
        }

        if (options.ShowHelp)
        {
            ConsolePresentation.PrintHelp(Console.Out);
            return 0;
        }

        var cli = new ManageSieveCliApplication(
            new ManageSieveClientFactory(),
            new EnvironmentSieveServerConfigurationProvider(),
            Console.OpenStandardOutput(),
            Console.Out);

        try
        {
            return await cli.RunAsync(options);
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(exception.Message);
            return 1;
        }
    }
}
