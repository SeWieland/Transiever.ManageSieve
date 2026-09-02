using System.Text;

namespace Transiever.ManageSieve;

internal static class ManageSieveCommandSerializer
{
    public static ReadOnlyMemory<byte> Line(string command, params string[] arguments)
    {
        string value = arguments.Length == 0
            ? $"{command}\r\n"
            : $"{command} {string.Join(' ', arguments)}\r\n";
        return Encoding.UTF8.GetBytes(value);
    }

    public static string Quote(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.ContainsAny('\r', '\n', '\0'))
        {
            throw new ArgumentException("Quoted strings cannot contain CR, LF, or NUL.", nameof(value));
        }

        return $"\"{value.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal)}\"";
    }

    public static IReadOnlyList<ReadOnlyMemory<byte>> LiteralCommand(
        string command,
        string? scriptName,
        ReadOnlyMemory<byte> content)
    {
        string prefix = scriptName is null
            ? $"{command} {{{content.Length}+}}\r\n"
            : $"{command} {Quote(scriptName)} {{{content.Length}+}}\r\n";
        return [Encoding.ASCII.GetBytes(prefix), content, "\r\n"u8.ToArray()];
    }

    public static byte[] Authentication(
        string mechanism,
        ReadOnlyMemory<byte>? initialResponse)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(mechanism);
        string command = $"AUTHENTICATE {Quote(mechanism)}";
        if (initialResponse is { } response)
        {
            command += $" {Quote(Convert.ToBase64String(response.Span))}";
        }

        return Encoding.ASCII.GetBytes(command + "\r\n");
    }

    public static byte[] QuotedBase64(ReadOnlyMemory<byte> response) =>
        Encoding.ASCII.GetBytes($"{Quote(Convert.ToBase64String(response.Span))}\r\n");
}
