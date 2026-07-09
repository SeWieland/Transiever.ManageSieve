using Transiever.ManageSieve;

namespace Transiever.ManageSieve.Cli;

public static class ConsolePresentation
{
    public static void PrintHelp(TextWriter output)
    {
        output.WriteLine("Usage:");
        output.WriteLine("  msieve capabilities");
        output.WriteLine("  msieve list");
        output.WriteLine("  msieve get <script-name> [--output <file>]");
        output.WriteLine("  msieve check --file <file>");
        output.WriteLine("  msieve put <script-name> --file <file> [--activate]");
        output.WriteLine("  msieve activate <script-name>");
        output.WriteLine("  msieve deactivate");
        output.WriteLine("  msieve delete <script-name>");
        output.WriteLine();
        output.WriteLine("ManageSieve options:");
        output.WriteLine("  --sieve-host <host>          Override TRANSIEVER_SIEVE_HOST.");
        output.WriteLine("  --sieve-port <port>          Override TRANSIEVER_SIEVE_PORT.");
        output.WriteLine("  --sieve-username <name>      Override TRANSIEVER_SIEVE_USERNAME.");
        output.WriteLine("  --sieve-password <value>     Override TRANSIEVER_SIEVE_PASSWORD.");
        output.WriteLine("  --sieve-security-mode <mode> Override TRANSIEVER_SIEVE_SECURITY_MODE.");
        output.WriteLine("  -h, --help                   Show this help.");
        output.WriteLine();
        output.WriteLine("The default security mode is StartTlsRequired on port 4190.");
        output.WriteLine("Plaintext authentication is refused.");
    }

    public static void PrintCapabilities(
        TextWriter output,
        ManageSieveCapabilities capabilities)
    {
        output.WriteLine($"Implementation: {Display(capabilities.Implementation)}");
        output.WriteLine($"Protocol: {Display(capabilities.ProtocolVersion)}");
        output.WriteLine($"Owner: {Display(capabilities.Owner)}");
        output.WriteLine($"Language: {Display(capabilities.Language)}");
        output.WriteLine($"Max redirects: {Display(capabilities.MaxRedirects)}");
        output.WriteLine($"STARTTLS: {Display(capabilities.SupportsStartTls)}");
        output.WriteLine(
            $"SASL mechanisms: {Display(capabilities.SaslMechanisms)}");
        output.WriteLine(
            $"Sieve extensions: {Display(capabilities.SieveExtensions)}");
        output.WriteLine(
            $"Notifications: {Display(capabilities.NotificationMethods)}");

        if (capabilities.Additional.Count > 0)
        {
            output.WriteLine("Additional:");
            foreach (KeyValuePair<string, string?> item in
                capabilities.Additional.OrderBy(
                    value => value.Key,
                    StringComparer.OrdinalIgnoreCase))
            {
                output.WriteLine(
                    item.Value is null
                        ? $"  {item.Key}"
                        : $"  {item.Key}: {item.Value}");
            }
        }
    }

    public static void PrintScripts(
        TextWriter output,
        IReadOnlyList<ManageSieveScriptInfo> scripts)
    {
        if (scripts.Count == 0)
        {
            output.WriteLine("No scripts found.");
            return;
        }

        foreach (ManageSieveScriptInfo script in scripts)
        {
            string marker = script.IsActive ? "*" : " ";
            output.WriteLine($"{marker} {script.Name}");
        }
    }

    public static void PrintResult(
        TextWriter output,
        string summary,
        ManageSieveCommandResult result)
    {
        output.WriteLine(summary);
        if (!string.IsNullOrWhiteSpace(result.Message))
        {
            output.WriteLine($"Message: {result.Message}");
        }

        if (!string.IsNullOrWhiteSpace(result.ResponseCode))
        {
            output.WriteLine($"Response code: {result.ResponseCode}");
        }

        foreach (string warning in result.Warnings)
        {
            output.WriteLine($"Warning: {warning}");
        }
    }

    private static string Display(string? value) =>
        string.IsNullOrWhiteSpace(value) ? "<none>" : value;

    private static string Display(int? value) =>
        value?.ToString(System.Globalization.CultureInfo.InvariantCulture) ??
        "<none>";

    private static string Display(bool value) => value ? "yes" : "no";

    private static string Display(IReadOnlySet<string> values) =>
        values.Count == 0
            ? "<none>"
            : string.Join(", ", values.Order(StringComparer.OrdinalIgnoreCase));
}
