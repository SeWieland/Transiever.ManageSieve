using System.Globalization;
using Transiever.ManageSieve;

namespace Transiever.ManageSieve.Cli;

public sealed class CommandLineOptions
{
    public ManageSieveCliCommand Command { get; private init; }

    public string? ScriptName { get; private init; }

    public string? File { get; private init; }

    public string? OutputFile { get; private init; }

    public bool Activate { get; private init; }

    public string? SieveHost { get; private init; }

    public int? SievePort { get; private init; }

    public string? SieveUserName { get; private init; }

    public string? SievePassword { get; private init; }

    public ManageSieveSecurityMode? SieveSecurity { get; private init; }

    public bool ShowHelp { get; private init; }

    public static CommandLineOptions Parse(IReadOnlyList<string> args)
    {
        if (args.Count == 0 || IsHelp(args[0]))
        {
            return new CommandLineOptions { ShowHelp = true };
        }

        ManageSieveCliCommand command = ParseCommand(args[0])
            ?? throw new ArgumentException($"Unknown command: {args[0]}");
        var index = 1;
        string? scriptName = null;
        string? file = null;
        string? outputFile = null;
        var activate = false;
        string? sieveHost = null;
        int? sievePort = null;
        string? sieveUserName = null;
        string? sievePassword = null;
        ManageSieveSecurityMode? sieveSecurity = null;

        while (index < args.Count)
        {
            string option = args[index];
            switch (option)
            {
                case "--file":
                    file = ReadOptionValue(args, ref index, option);
                    break;
                case "--output":
                    outputFile = ReadOptionValue(args, ref index, option);
                    break;
                case "--activate":
                    activate = true;
                    break;
                case "--sieve-host":
                    sieveHost = ReadOptionValue(args, ref index, option);
                    break;
                case "--sieve-port":
                    sievePort = ReadPortOption(args, ref index, option);
                    break;
                case "--sieve-username":
                    sieveUserName = ReadOptionValue(args, ref index, option);
                    break;
                case "--sieve-password":
                    sievePassword = ReadOptionValue(args, ref index, option);
                    break;
                case "--sieve-security-mode":
                    sieveSecurity = ParseSieveSecurity(
                        ReadOptionValue(args, ref index, option));
                    break;
                case "-h":
                case "--help":
                    return new CommandLineOptions { ShowHelp = true };
                default:
                    if (option.StartsWith("-", StringComparison.Ordinal))
                    {
                        throw new ArgumentException($"Unknown option: {option}");
                    }

                    if (!CommandAcceptsScriptName(command) ||
                        scriptName is not null)
                    {
                        throw new ArgumentException(
                            $"Unexpected argument: {option}");
                    }

                    scriptName = option;
                    break;
            }

            index++;
        }

        Validate(command, scriptName, file, outputFile, activate);

        return new CommandLineOptions
        {
            Command = command,
            ScriptName = scriptName,
            File = file,
            OutputFile = outputFile,
            Activate = activate,
            SieveHost = sieveHost,
            SievePort = sievePort,
            SieveUserName = sieveUserName,
            SievePassword = sievePassword,
            SieveSecurity = sieveSecurity
        };
    }

    private static ManageSieveCliCommand? ParseCommand(string value) =>
        value.ToLowerInvariant() switch
        {
            "capabilities" => ManageSieveCliCommand.Capabilities,
            "list" => ManageSieveCliCommand.List,
            "get" => ManageSieveCliCommand.Get,
            "check" => ManageSieveCliCommand.Check,
            "put" => ManageSieveCliCommand.Put,
            "activate" => ManageSieveCliCommand.Activate,
            "deactivate" => ManageSieveCliCommand.Deactivate,
            "delete" => ManageSieveCliCommand.Delete,
            _ => null
        };

    private static bool CommandAcceptsScriptName(ManageSieveCliCommand command) =>
        command is ManageSieveCliCommand.Get or
            ManageSieveCliCommand.Put or
            ManageSieveCliCommand.Activate or
            ManageSieveCliCommand.Delete;

    private static void Validate(
        ManageSieveCliCommand command,
        string? scriptName,
        string? file,
        string? outputFile,
        bool activate)
    {
        if (command is (ManageSieveCliCommand.Get or
            ManageSieveCliCommand.Put or
            ManageSieveCliCommand.Activate or
            ManageSieveCliCommand.Delete) &&
            string.IsNullOrWhiteSpace(scriptName))
        {
            throw new ArgumentException(
                $"{command.ToString().ToLowerInvariant()} requires a script name.");
        }

        if (command is (ManageSieveCliCommand.Check or
            ManageSieveCliCommand.Put) &&
            string.IsNullOrWhiteSpace(file))
        {
            throw new ArgumentException(
                $"{command.ToString().ToLowerInvariant()} requires --file.");
        }

        if (outputFile is not null &&
            command is not ManageSieveCliCommand.Get)
        {
            throw new ArgumentException("--output is only valid with get.");
        }

        if (activate &&
            command is not ManageSieveCliCommand.Put)
        {
            throw new ArgumentException("--activate is only valid with put.");
        }
    }

    private static bool IsHelp(string value) =>
        value is "-h" or "--help" or "help";

    private static string ReadOptionValue(
        IReadOnlyList<string> args,
        ref int index,
        string option)
    {
        index++;
        if (index >= args.Count ||
            args[index].StartsWith("--", StringComparison.Ordinal))
        {
            throw new ArgumentException($"{option} requires a value.");
        }

        return args[index];
    }

    private static int ReadPortOption(
        IReadOnlyList<string> args,
        ref int index,
        string option)
    {
        string value = ReadOptionValue(args, ref index, option);
        if (!int.TryParse(
                value,
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out int parsed) ||
            parsed is < 1 or > 65535)
        {
            throw new ArgumentException(
                $"{option} must be a TCP port from 1 to 65535.");
        }

        return parsed;
    }

    private static ManageSieveSecurityMode ParseSieveSecurity(string value)
    {
        if (Enum.TryParse(
            value,
            ignoreCase: true,
            out ManageSieveSecurityMode mode))
        {
            return mode;
        }

        throw new ArgumentException($"Unknown Sieve security mode: {value}");
    }
}
