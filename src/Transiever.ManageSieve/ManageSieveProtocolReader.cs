using System.Buffers;
using System.Buffers.Text;
using System.Text;

namespace Transiever.ManageSieve;

internal sealed class ManageSieveProtocolReader(Stream stream)
{
    private readonly Stream stream = stream ?? throw new ArgumentNullException(nameof(stream));

    public async ValueTask<ManageSieveResponse> ReadResponseAsync(
        CancellationToken cancellationToken,
        bool allowAuthenticationChallenge = false)
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
            catch (ManageSieveProtocolException) when (allowAuthenticationChallenge)
            {
                throw new ManageSieveProtocolException(
                    "The server returned an invalid SASL challenge.");
            }
            if (allowAuthenticationChallenge)
            {
                return CreateAuthenticationChallenge(line, values);
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

    private static byte[] ParseToken(ReadOnlySpan<byte> line, ref int position)
    {
        if (line[position] != (byte)'"')
        {
            int start = position;
            while (position < line.Length && line[position] != (byte)' ')
            {
                position++;
            }

            return line[start..position].ToArray();
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
        if (!TryParseStatus(line, out ManageSieveResponseStatus status, out int position))
        {
            return null;
        }

        SkipSpaces(line, ref position);
        ManageSieveResponseCode? code = null;
        if (position < line.Length && line[position] == (byte)'(')
        {
            (code, line, position) = await ParseResponseCodeAsync(
                line,
                position,
                cancellationToken).ConfigureAwait(false);
        }

        string? message = ParseStatusMessage(line, ref position);
        return new ManageSieveResponse(status, [], code, message);
    }

    private static bool TryParseStatus(
        ReadOnlySpan<byte> line,
        out ManageSieveResponseStatus status,
        out int position)
    {
        if (line.Length >= 2 && Ascii.EqualsIgnoreCase(line[..2], "OK"u8) &&
            (line.Length == 2 || line[2] == (byte)' '))
        {
            status = ManageSieveResponseStatus.Ok;
            position = 2;
            return true;
        }

        if (line.Length >= 2 && Ascii.EqualsIgnoreCase(line[..2], "NO"u8) &&
            (line.Length == 2 || line[2] == (byte)' '))
        {
            status = ManageSieveResponseStatus.No;
            position = 2;
            return true;
        }

        if (line.Length >= 3 && Ascii.EqualsIgnoreCase(line[..3], "BYE"u8) &&
            (line.Length == 3 || line[3] == (byte)' '))
        {
            status = ManageSieveResponseStatus.Bye;
            position = 3;
            return true;
        }

        status = default;
        position = 0;
        return false;
    }

    private async ValueTask<(
        ManageSieveResponseCode Code,
        byte[] Line,
        int Position)> ParseResponseCodeAsync(
        byte[] line,
        int position,
        CancellationToken cancellationToken)
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

        return (
            new ManageSieveResponseCode(
                responseCodeAtom,
                arguments,
                responseCodeText),
            line,
            position);
    }

    private static string? ParseStatusMessage(
        ReadOnlySpan<byte> line,
        ref int position)
    {
        if (position < line.Length &&
            position > 0 &&
            line[position - 1] == (byte)')' &&
            line[position] != (byte)' ')
        {
            throw new ManageSieveProtocolException(
                "A status message was not separated by a space.");
        }

        SkipSpaces(line, ref position);
        if (position >= line.Length)
        {
            return null;
        }

        string message = Encoding.UTF8.GetString(ParseToken(line, ref position));
        SkipSpaces(line, ref position);
        if (position != line.Length)
        {
            throw new ManageSieveProtocolException(
                "Unexpected data followed a status message.");
        }

        return message;
    }

    private static int ParseLiteralLength(ReadOnlySpan<byte> line, int position)
    {
        int close = position + 1;
        while (close < line.Length && line[close] != (byte)'}')
        {
            close++;
        }

        if (close >= line.Length)
        {
            throw new ManageSieveProtocolException("A literal length was not terminated.");
        }

        ReadOnlySpan<byte> lengthBytes = line[(position + 1)..close];
        foreach (byte value in lengthBytes)
        {
            if (value is < (byte)'0' or > (byte)'9')
            {
                throw new ManageSieveProtocolException("A literal length was invalid.");
            }
        }

        if (!Utf8Parser.TryParse(lengthBytes, out int length, out int bytesConsumed) ||
            bytesConsumed != lengthBytes.Length ||
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
        ReadOnlySpan<byte> line,
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
            line[start..position].ToArray(),
            ManageSieveProtocolValueKind.Atom);
    }

    private static bool IsAtomCharacter(byte value) =>
        value is (byte)'!' or
            >= (byte)'#' and <= (byte)'\'' or
            >= (byte)'*' and <= (byte)'[' or
            >= (byte)']' and <= (byte)'z' or
            >= (byte)'|' and <= (byte)'~';

    private static bool IsAuthenticationChallenge(ReadOnlySpan<byte> line)
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

    private static ManageSieveResponse CreateAuthenticationChallenge(
        ReadOnlySpan<byte> line,
        IReadOnlyList<ManageSieveProtocolValue> values)
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

    private static void SkipSpaces(ReadOnlySpan<byte> line, ref int position)
    {
        while (position < line.Length && line[position] == (byte)' ')
        {
            position++;
        }
    }
}
