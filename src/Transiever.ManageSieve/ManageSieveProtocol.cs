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

internal enum ManageSieveProtocolValueKind
{
    Atom,
    QuotedString,
    Literal
}

internal sealed record ManageSieveProtocolValue(
    ReadOnlyMemory<byte> Bytes,
    ManageSieveProtocolValueKind Kind)
{
    public string Text => Encoding.UTF8.GetString(Bytes.Span);
}

internal sealed record ManageSieveDataLine(IReadOnlyList<ManageSieveProtocolValue> Values);

internal sealed record ManageSieveResponseCode(
    string Atom,
    IReadOnlyList<ManageSieveProtocolValue> Arguments,
    string Text);

internal sealed record ManageSieveResponse(
    ManageSieveResponseStatus Status,
    IReadOnlyList<ManageSieveDataLine> Data,
    ManageSieveResponseCode? Code = null,
    string? Message = null)
{
    public string? ResponseCode => Code?.Text;
}

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
            ManageSieveResponse? status =
                await ParseStatusAsync(line, cancellationToken).ConfigureAwait(false);
            if (status is not null)
            {
                return status with { Data = data };
            }

            IReadOnlyList<ManageSieveProtocolValue> values;
            try
            {
                values = await ParseDataLineAsync(line, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (ManageSieveProtocolException) when (allowContinuation)
            {
                throw new ManageSieveProtocolException(
                    "The server returned an invalid SASL challenge.");
            }
            if (allowContinuation)
            {
                if (values.Count != 1 ||
                    values[0].Kind is not (
                        ManageSieveProtocolValueKind.QuotedString or
                        ManageSieveProtocolValueKind.Literal) ||
                    !IsAuthenticationChallenge(line))
                {
                    throw new ManageSieveProtocolException(
                        "The server returned an invalid SASL challenge.");
                }

                return new ManageSieveResponse(
                    ManageSieveResponseStatus.Continue,
                    [new ManageSieveDataLine(values)]);
            }

            data.Add(new ManageSieveDataLine(values));
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
                int length = ParseLiteralLength(line, position);
                byte[] literal = GC.AllocateUninitializedArray<byte>(length);
                await ReadExactlyAsync(literal, cancellationToken).ConfigureAwait(false);
                await ExpectCrLfAsync(cancellationToken).ConfigureAwait(false);
                values.Add(new ManageSieveProtocolValue(
                    literal,
                    ManageSieveProtocolValueKind.Literal));
                return values;
            }

            ManageSieveProtocolValueKind kind = line[position] == (byte)'"'
                ? ManageSieveProtocolValueKind.QuotedString
                : ManageSieveProtocolValueKind.Atom;
            values.Add(new ManageSieveProtocolValue(
                ParseToken(line, ref position),
                kind));
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

    private async ValueTask<ManageSieveResponse?> ParseStatusAsync(
        byte[] line,
        CancellationToken cancellationToken)
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
            return null;
        }

        int position = separator < 0 ? line.Length : separator + 1;
        SkipSpaces(line, ref position);
        ManageSieveResponseCode? responseCode = null;
        if (position < line.Length && line[position] == (byte)'(')
        {
            int codeStart = ++position;
            int atomStart = position;
            while (position < line.Length && IsAtomCharacter(line[position]))
            {
                position++;
            }

            if (position == atomStart)
            {
                throw new ManageSieveProtocolException("A response code atom was missing.");
            }

            if (position < line.Length &&
                line[position] is not ((byte)' ' or (byte)')'))
            {
                throw new ManageSieveProtocolException("A response code atom was invalid.");
            }

            string responseCodeAtom = Encoding.ASCII.GetString(
                line,
                atomStart,
                position - atomStart);
            List<ManageSieveProtocolValue> arguments = [];
            string? responseCodeText = null;
            while (position < line.Length)
            {
                if (line[position] == (byte)')')
                {
                    responseCodeText = Encoding.UTF8.GetString(
                        line,
                        codeStart,
                        position - codeStart);
                    position++;
                    break;
                }

                if (line[position] != (byte)' ')
                {
                    throw new ManageSieveProtocolException(
                        "A response code argument was not separated by a space.");
                }

                SkipSpaces(line, ref position);
                if (position >= line.Length)
                {
                    break;
                }

                if (line[position] == (byte)')')
                {
                    throw new ManageSieveProtocolException(
                        "A response code argument was missing.");
                }

                if (line[position] == (byte)'{')
                {
                    int length = ParseLiteralLength(line, position);
                    byte[] literal = GC.AllocateUninitializedArray<byte>(length);
                    await ReadExactlyAsync(literal, cancellationToken).ConfigureAwait(false);
                    arguments.Add(new ManageSieveProtocolValue(
                        literal,
                        ManageSieveProtocolValueKind.Literal));

                    int prefixLength = line.Length - codeStart;
                    byte[] codeBytes = GC.AllocateUninitializedArray<byte>(
                        prefixLength + 2 + literal.Length);
                    line.AsSpan(codeStart).CopyTo(codeBytes);
                    "\r\n"u8.CopyTo(codeBytes.AsSpan(prefixLength));
                    literal.CopyTo(codeBytes, prefixLength + 2);
                    responseCodeText = Encoding.UTF8.GetString(codeBytes);

                    line = await ReadLineAsync(cancellationToken).ConfigureAwait(false);
                    if (line.Length == 0 || line[0] != (byte)')')
                    {
                        throw new ManageSieveProtocolException(
                            "A response-code literal was not followed by a closing parenthesis.");
                    }

                    position = 1;
                    break;
                }

                arguments.Add(ParseResponseCodeArgument(line, ref position));
            }

            if (responseCodeText is null)
            {
                throw new ManageSieveProtocolException("A response code was not terminated.");
            }

            responseCode = new ManageSieveResponseCode(
                responseCodeAtom,
                arguments,
                responseCodeText);
        }

        if (responseCode is not null &&
            position < line.Length &&
            line[position] != (byte)' ')
        {
            throw new ManageSieveProtocolException(
                "A status message was not separated by a space.");
        }

        SkipSpaces(line, ref position);
        string? message = null;
        if (position < line.Length)
        {
            message = Encoding.UTF8.GetString(ParseToken(line, ref position));
            SkipSpaces(line, ref position);
            if (position != line.Length)
            {
                throw new ManageSieveProtocolException(
                    "Unexpected data followed a status message.");
            }
        }

        return new ManageSieveResponse(
            status.Value,
            [],
            responseCode,
            message);
    }

    private static int ParseLiteralLength(byte[] line, int position)
    {
        int close = Array.IndexOf(line, (byte)'}', position + 1);
        if (close < 0)
        {
            throw new ManageSieveProtocolException("A literal length was not terminated.");
        }

        ReadOnlySpan<byte> lengthBytes = line.AsSpan(position + 1, close - position - 1);
        if (!int.TryParse(
            Encoding.ASCII.GetString(lengthBytes),
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

        return length;
    }

    private static ManageSieveProtocolValue ParseResponseCodeArgument(
        byte[] line,
        ref int position)
    {
        if (line[position] == (byte)'"')
        {
            return new ManageSieveProtocolValue(
                ParseToken(line, ref position),
                ManageSieveProtocolValueKind.QuotedString);
        }

        int start = position;
        while (position < line.Length &&
            line[position] is not ((byte)' ' or (byte)')'))
        {
            position++;
        }

        return new ManageSieveProtocolValue(
            line[start..position],
            ManageSieveProtocolValueKind.Atom);
    }

    private static bool IsAtomCharacter(byte value) =>
        value is (byte)'!' or
            >= (byte)'#' and <= (byte)'\'' or
            >= (byte)'*' and <= (byte)'[' or
            >= (byte)']' and <= (byte)'z' or
            >= (byte)'|' and <= (byte)'~';

    private static bool IsAuthenticationChallenge(byte[] line)
    {
        if (line.Length < 2)
        {
            return false;
        }

        if (line[0] == (byte)'{')
        {
            return line[^1] == (byte)'}';
        }

        if (line[0] != (byte)'"')
        {
            return false;
        }

        for (int position = 1; position < line.Length; position++)
        {
            if (line[position] == (byte)'\\')
            {
                position++;
            }
            else if (line[position] == (byte)'"')
            {
                return position == line.Length - 1;
            }
        }

        return false;
    }

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
