using System.Text;

namespace Transiever.ManageSieve.UnitTest;

public sealed class ManageSieveProtocolTests
{
    [Fact]
    public async Task Parser_HandlesFragmentedCapabilitiesQuotedEscapesAndStatus()
    {
        var reader = new ManageSieveProtocolReader(
            new FragmentedStream(
                "\"IMPLEMENTATION\" \"Test \\\"Server\\\"\"\r\n" +
                "\"SIEVE\" \"fileinto vacation\"\r\n" +
                "\"STARTTLS\"\r\n" +
                "OK (WARNINGS) \"ready\"\r\n"));

        ManageSieveResponse response = await reader.ReadResponseAsync(default);
        ManageSieveCapabilities capabilities =
            ManageSieveProtocolMapper.MapCapabilities(response.Data);

        Assert.Equal(ManageSieveResponseStatus.Ok, response.Status);
        Assert.Equal("WARNINGS", response.ResponseCode);
        Assert.Equal("ready", response.Message);
        Assert.Equal("Test \"Server\"", capabilities.Implementation);
        Assert.True(capabilities.SupportsStartTls);
        Assert.Contains("vacation", capabilities.SieveExtensions);
    }

    [Fact]
    public async Task Parser_PreservesLiteralOctets()
    {
        byte[] literal = [0, 1, 13, 10, 255];
        byte[] response = Encoding.ASCII.GetBytes($"{{{literal.Length}}}\r\n")
            .Concat(literal)
            .Concat("\r\nOK\r\n"u8.ToArray())
            .ToArray();
        var reader = new ManageSieveProtocolReader(new FragmentedStream(response));

        ManageSieveResponse parsed = await reader.ReadResponseAsync(default);

        Assert.Equal(literal, parsed.Data[0].Values[0].Bytes.ToArray());
    }

    [Theory]
    [InlineData("\"unterminated\r\n")]
    [InlineData("\"bad\\q\"\r\n")]
    [InlineData("{x}\r\n")]
    [InlineData("OK (BROKEN\r\n")]
    public async Task Parser_RejectsMalformedResponses(string response)
    {
        var reader = new ManageSieveProtocolReader(new FragmentedStream(response));

        await Assert.ThrowsAsync<ManageSieveProtocolException>(
            () => reader.ReadResponseAsync(default).AsTask());
    }

    [Fact]
    public void Serializer_EscapesNamesAndUsesOctetLength()
    {
        Assert.Equal(
            "RENAME \"a\\\\b\\\"c\"\r\n",
            Encoding.UTF8.GetString(
                ManageSieveCommandSerializer.Line(
                    "RENAME",
                    ManageSieveCommandSerializer.Quote("a\\b\"c")).Span));

        IReadOnlyList<ReadOnlyMemory<byte>> frames =
            ManageSieveCommandSerializer.LiteralCommand(
                "PUTSCRIPT",
                "candidate",
                "ä"u8.ToArray());

        Assert.Equal("PUTSCRIPT \"candidate\" {2+}\r\n", Encoding.ASCII.GetString(frames[0].Span));
        Assert.Equal("ä"u8.ToArray(), frames[1].ToArray());
        Assert.Equal("\r\n", Encoding.ASCII.GetString(frames[2].Span));
    }

    private sealed class FragmentedStream : MemoryStream
    {
        public FragmentedStream(string value)
            : this(Encoding.UTF8.GetBytes(value))
        {
        }

        public FragmentedStream(byte[] value)
            : base(value)
        {
        }

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default) =>
            base.ReadAsync(buffer[..Math.Min(buffer.Length, 1)], cancellationToken);
    }
}
