using System.Globalization;

namespace Transiever.ManageSieve;

internal static class ManageSieveProtocolMapper
{
    public static ManageSieveCapabilities MapCapabilities(
        IReadOnlyList<ManageSieveDataLine> lines)
    {
        string? implementation = null;
        string? version = null;
        string? owner = null;
        string? language = null;
        int? maxRedirects = null;
        bool startTls = false;
        HashSet<string> sasl = new(StringComparer.OrdinalIgnoreCase);
        HashSet<string> sieve = new(StringComparer.OrdinalIgnoreCase);
        HashSet<string> notify = new(StringComparer.OrdinalIgnoreCase);
        Dictionary<string, string?> additional = new(StringComparer.OrdinalIgnoreCase);

        foreach (ManageSieveDataLine line in lines)
        {
            string name = line.Values[0].Text;
            string? value = line.Values.Count > 1 ? line.Values[1].Text : null;
            switch (name.ToUpperInvariant())
            {
                case "IMPLEMENTATION":
                    implementation = value;
                    break;
                case "VERSION":
                    version = value;
                    break;
                case "OWNER":
                    owner = value;
                    break;
                case "LANGUAGE":
                    language = value;
                    break;
                case "MAXREDIRECTS":
                    if (int.TryParse(value, CultureInfo.InvariantCulture, out int parsed))
                    {
                        maxRedirects = parsed;
                    }
                    break;
                case "STARTTLS":
                    startTls = true;
                    break;
                case "SASL":
                    AddWords(sasl, value);
                    break;
                case "SIEVE":
                    AddWords(sieve, value);
                    break;
                case "NOTIFY":
                    AddWords(notify, value);
                    break;
                default:
                    additional[name] = value;
                    break;
            }
        }

        return new ManageSieveCapabilities
        {
            Implementation = implementation,
            ProtocolVersion = version,
            Owner = owner,
            Language = language,
            MaxRedirects = maxRedirects,
            SupportsStartTls = startTls,
            SaslMechanisms = sasl,
            SieveExtensions = sieve,
            NotificationMethods = notify,
            Additional = additional
        };
    }

    public static IReadOnlyList<ManageSieveScriptInfo> MapScripts(
        IReadOnlyList<ManageSieveDataLine> lines) =>
        lines.Select(line =>
        {
            if (line.Values.Count is < 1 or > 2)
            {
                throw new ManageSieveProtocolException(
                    "LISTSCRIPTS returned an invalid script entry.");
            }

            return new ManageSieveScriptInfo(
                line.Values[0].Text,
                line.Values.Count == 2 &&
                line.Values[1].Text.Equals("ACTIVE", StringComparison.OrdinalIgnoreCase));
        }).ToArray();

    public static ManageSieveScript MapScript(
        string name,
        IReadOnlyList<ManageSieveDataLine> lines)
    {
        if (lines.Count != 1 || lines[0].Values.Count != 1)
        {
            throw new ManageSieveProtocolException(
                "GETSCRIPT returned an invalid script literal.");
        }

        return new ManageSieveScript(name, lines[0].Values[0].Bytes);
    }

    public static ManageSieveCommandResult MapResult(ManageSieveResponse response) =>
        new()
        {
            Message = response.Message,
            ResponseCode = response.ResponseCode,
            Warnings = response.ResponseCode?.StartsWith(
                "WARNINGS",
                StringComparison.OrdinalIgnoreCase) == true &&
                response.Message is not null
                ? [response.Message]
                : []
        };

    private static void AddWords(HashSet<string> destination, string? value)
    {
        if (value is null)
        {
            return;
        }

        foreach (string item in value.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            destination.Add(item);
        }
    }
}
