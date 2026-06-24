using System.Buffers;
using System.Globalization;
using System.Text;

namespace Transiever.ManageSieve;

internal enum ManageSieveResponseStatus
{
    Continue,
    Ok,
    No,
    Bye
}

internal sealed record ManageSieveProtocolValue(ReadOnlyMemory<byte> Bytes)
{
    public string Text => Encoding.UTF8.GetString(Bytes.Span);
}

internal sealed record ManageSieveDataLine(IReadOnlyList<ManageSieveProtocolValue> Values);

internal sealed record ManageSieveResponse(
    ManageSieveResponseStatus Status,
    IReadOnlyList<ManageSieveDataLine> Data,
    string? ResponseCode = null,
    string? Message = null);

internal sealed class ManageSieveProtocolReader(Stream stream)
{
    private readonly Stream stream = stream ?? throw new ArgumentNullException(nameof(stream));

    public async ValueTask<ManageSieveResponse> ReadResponseAsync(
        CancellationToken cancellationToken,
        bool allowContinuation = false)
    {
        List<ManageSieveDataLine> data = [];
        while (true)
        {
            byte[] line = await ReadLineAsync(cancellationToken).ConfigureAwait(false);
            if (TryParseStatus(line, out ManageSieveResponse? status))
            {
                return status! with { Data = data };
            }

            IReadOnlyList<ManageSieveProtocolValue> values =
                await ParseDataLineAsync(line, cancellationToken).ConfigureAwait(false);
            data.Add(new ManageSieveDataLine(values));

            if (allowContinuation && data.Count == 1 && values.Count == 1 &&
                IsAuthenticationChallenge(line))
            {
                return new ManageSieveResponse(
                    ManageSieveResponseStatus.Continue,
                    data);
            }
        }
    }

    private async ValueTask<IReadOnlyList<ManageSieveProtocolValue>> ParseDataLineAsync(
        byte[] line,
        CancellationToken cancellationToken)
    {
        List<ManageSieveProtocolValue> values = [];
        int position = 0;
        while (position < line.Length)
        {
            SkipSpaces(line, ref position);
            if (position >= line.Length)
            {
                break;
            }

            if (line[position] == (byte)'{')
            {
                int close = Array.IndexOf(line, (byte)'}', position + 1);
                if (close < 0)
                {
                    throw new ManageSieveProtocolException("A literal length was not terminated.");
                }

                string lengthText = Encoding.ASCII.GetString(
                    line,
                    position + 1,
                    close - position - 1).TrimEnd('+');
                if (!int.TryParse(
                    lengthText,
                    NumberStyles.None,
                    CultureInfo.InvariantCulture,
                    out int length) ||
                    length < 0)
                {
                    throw new ManageSieveProtocolException("A literal length was invalid.");
                }

                if (close != line.Length - 1)
                {
                    throw new ManageSieveProtocolException(
                        "A response literal marker must end its line.");
                }

                byte[] literal = GC.AllocateUninitializedArray<byte>(length);
                await ReadExactlyAsync(literal, cancellationToken).ConfigureAwait(false);
                await ExpectCrLfAsync(cancellationToken).ConfigureAwait(false);
                values.Add(new ManageSieveProtocolValue(literal));
                return values;
            }

            values.Add(new ManageSieveProtocolValue(ParseToken(line, ref position)));
        }

        if (values.Count == 0)
        {
            throw new ManageSieveProtocolException("The server returned an empty response line.");
        }

        return values;
    }

    private static byte[] ParseToken(byte[] line, ref int position)
    {
        if (line[position] != (byte)'"')
        {
            int start = position;
            while (position < line.Length && line[position] != (byte)' ')
            {
                position++;
            }

            return line[start..position];
        }

        position++;
        var writer = new ArrayBufferWriter<byte>();
        while (position < line.Length)
        {
            byte current = line[position++];
            if (current == (byte)'"')
            {
                return writer.WrittenSpan.ToArray();
            }

            if (current == (byte)'\\')
            {
                if (position >= line.Length)
                {
                    throw new ManageSieveProtocolException(
                        "A quoted response ended with an incomplete escape.");
                }

                current = line[position++];
                if (current is not ((byte)'\\' or (byte)'"'))
                {
                    throw new ManageSieveProtocolException(
                        "A quoted response contained an invalid escape.");
                }
            }

            writer.GetSpan(1)[0] = current;
            writer.Advance(1);
        }

        throw new ManageSieveProtocolException("A quoted response was not terminated.");
    }

    private static bool TryParseStatus(
        byte[] line,
        out ManageSieveResponse? response)
    {
        string text = Encoding.UTF8.GetString(line);
        int separator = text.IndexOf(' ');
        string atom = separator < 0 ? text : text[..separator];
        ManageSieveResponseStatus? status = atom.ToUpperInvariant() switch
        {
            "OK" => ManageSieveResponseStatus.Ok,
            "NO" => ManageSieveResponseStatus.No,
            "BYE" => ManageSieveResponseStatus.Bye,
            _ => null
        };

        if (status is null)
        {
            response = null;
            return false;
        }

        string remainder = separator < 0 ? string.Empty : text[(separator + 1)..].TrimStart();
        string? responseCode = null;
        if (remainder.StartsWith('('))
        {
            int close = remainder.IndexOf(')');
            if (close < 0)
            {
                throw new ManageSieveProtocolException(
                    "A response code was not terminated.");
            }

            responseCode = remainder[1..close];
            remainder = remainder[(close + 1)..].TrimStart();
        }

        string? message = null;
        if (remainder.Length > 0)
        {
            byte[] messageBytes = Encoding.UTF8.GetBytes(remainder);
            int position = 0;
            message = Encoding.UTF8.GetString(ParseToken(messageBytes, ref position));
            SkipSpaces(messageBytes, ref position);
            if (position != messageBytes.Length)
            {
                throw new ManageSieveProtocolException(
                    "Unexpected data followed a status message.");
            }
        }

        response = new ManageSieveResponse(
            status.Value,
            [],
            responseCode,
            message);
        return true;
    }

    private static bool IsAuthenticationChallenge(byte[] line) =>
        line.Length >= 2 &&
        (line[0] == (byte)'"' || line[0] == (byte)'{');

    private async ValueTask<byte[]> ReadLineAsync(CancellationToken cancellationToken)
    {
        var writer = new ArrayBufferWriter<byte>();
        byte[] oneByte = new byte[1];
        bool sawCr = false;
        while (true)
        {
            int read = await stream.ReadAsync(oneByte, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new ManageSieveConnectionException(
                    "The server closed the connection while sending a response.");
            }

            byte current = oneByte[0];
            if (sawCr)
            {
                if (current != (byte)'\n')
                {
                    throw new ManageSieveProtocolException(
                        "A server response used an invalid line ending.");
                }

                return writer.WrittenSpan[..^1].ToArray();
            }

            writer.GetSpan(1)[0] = current;
            writer.Advance(1);
            sawCr = current == (byte)'\r';
        }
    }

    private async ValueTask ReadExactlyAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        int position = 0;
        while (position < buffer.Length)
        {
            int read = await stream.ReadAsync(buffer[position..], cancellationToken)
                .ConfigureAwait(false);
            if (read == 0)
            {
                throw new ManageSieveConnectionException(
                    "The server closed the connection inside a response literal.");
            }

            position += read;
        }
    }

    private async ValueTask ExpectCrLfAsync(CancellationToken cancellationToken)
    {
        byte[] terminator = new byte[2];
        await ReadExactlyAsync(terminator, cancellationToken).ConfigureAwait(false);
        if (terminator[0] != (byte)'\r' || terminator[1] != (byte)'\n')
        {
            throw new ManageSieveProtocolException(
                "A response literal was not followed by CRLF.");
        }
    }

    private static void SkipSpaces(byte[] line, ref int position)
    {
        while (position < line.Length && line[position] == (byte)' ')
        {
            position++;
        }
    }
}

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

    public static ReadOnlyMemory<byte> Authentication(
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

    public static ReadOnlyMemory<byte> QuotedBase64(ReadOnlyMemory<byte> response) =>
        Encoding.ASCII.GetBytes($"{Quote(Convert.ToBase64String(response.Span))}\r\n");
}

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
