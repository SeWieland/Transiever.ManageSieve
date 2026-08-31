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

        ManageSieveResponse response = await reader.ReadResponseAsync(
            TestContext.Current.CancellationToken);
        ManageSieveCapabilities capabilities =
            ManageSieveProtocolMapper.MapCapabilities(response.Data);

        Assert.Equal(ManageSieveResponseStatus.Ok, response.Status);
        Assert.Equal("WARNINGS", response.Code?.Atom);
        Assert.Empty(response.Code?.Arguments ?? []);
        Assert.Equal("WARNINGS", response.Code?.Text);
        Assert.Equal("WARNINGS", response.ResponseCode);
        Assert.Equal("ready", response.Message);
        Assert.Equal("Test \"Server\"", capabilities.Implementation);
        Assert.True(capabilities.SupportsStartTls);
        Assert.Contains("vacation", capabilities.SieveExtensions);
    }

    [Theory]
    [InlineData("OK (SASL \"c2VydmVyLWZpbmFs\")\r\n", "c2VydmVyLWZpbmFs")]
    [InlineData("OK (SASL \"\")\r\n", "")]
    public async Task ResponseCode_ParsesQuotedArgumentBytes(
        string input,
        string expectedArgument)
    {
        var reader = new ManageSieveProtocolReader(new FragmentedStream(input));

        ManageSieveResponse response = await reader.ReadResponseAsync(
            TestContext.Current.CancellationToken);

        Assert.Equal("SASL", response.Code?.Atom);
        Assert.Equal(expectedArgument, response.Code?.Arguments.Single().Text);
        Assert.Equal(
            ManageSieveProtocolValueKind.QuotedString,
            response.Code?.Arguments.Single().Kind);
        Assert.Equal(input[4..^3], response.ResponseCode);
        Assert.Null(response.Message);
    }

    [Fact]
    public async Task ResponseCode_ParsesLiteralArgumentAcrossStatusLine()
    {
        const string input =
            "OK (SASL {16}\r\nc2VydmVyLWZpbmFs) \"authenticated\"\r\n";
        var reader = new ManageSieveProtocolReader(new FragmentedStream(input));

        ManageSieveResponse response = await reader.ReadResponseAsync(
            TestContext.Current.CancellationToken);

        Assert.Equal("SASL", response.Code?.Atom);
        Assert.Equal("c2VydmVyLWZpbmFs"u8.ToArray(),
            response.Code?.Arguments.Single().Bytes.ToArray());
        Assert.Equal(
            ManageSieveProtocolValueKind.Literal,
            response.Code?.Arguments.Single().Kind);
        Assert.Equal("SASL {16}\r\nc2VydmVyLWZpbmFs", response.ResponseCode);
        Assert.Equal("authenticated", response.Message);
    }

    [Fact]
    public async Task ResponseCode_PreservesBareAtomArgumentForExtensions()
    {
        var reader = new ManageSieveProtocolReader(
            new FragmentedStream("OK (EXTENSION bare) \"safe\"\r\n"));

        ManageSieveResponse response = await reader.ReadResponseAsync(
            TestContext.Current.CancellationToken);

        Assert.Equal(ManageSieveProtocolValueKind.Atom,
            response.Code?.Arguments.Single().Kind);
        Assert.Equal("bare", response.Code?.Arguments.Single().Text);
        Assert.Equal("EXTENSION bare", response.ResponseCode);
        Assert.Equal("safe", response.Message);
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

        ManageSieveResponse parsed = await reader.ReadResponseAsync(
            TestContext.Current.CancellationToken);

        Assert.Equal(literal, parsed.Data[0].Values[0].Bytes.ToArray());
    }

    [Theory]
    [InlineData("\"unterminated\r\n")]
    [InlineData("\"bad\\q\"\r\n")]
    [InlineData("{x}\r\n")]
    [InlineData("OK (BROKEN\r\n")]
    [InlineData("OK (\"BROKEN\")\r\n")]
    [InlineData("OK (SASL )\r\n")]
    [InlineData("OK (SASL \"bad\\q\")\r\n")]
    [InlineData("OK (SASL {3}\r\nabcd)\r\n")]
    [InlineData("OK (SASL {4}\r\nYWJj unexpected)\r\n")]
    [InlineData("OK (WARNINGS)\"safe\"\r\n")]
    [InlineData("OK (SASL {4}\r\nYWJj)\"safe\"\r\n")]
    [InlineData("{1+}\r\na\r\nOK\r\n")]
    [InlineData("OK (SASL {4+}\r\nYWJj)\r\n")]
    public async Task Parser_RejectsMalformedResponses(string response)
    {
        var reader = new ManageSieveProtocolReader(new FragmentedStream(response));

        await Assert.ThrowsAsync<ManageSieveProtocolException>(
            () => reader.ReadResponseAsync(
                TestContext.Current.CancellationToken).AsTask());
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
