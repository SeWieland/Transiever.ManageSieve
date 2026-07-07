using System.Text;

namespace Transiever.ManageSieve.UnitTest;

public sealed class ManageSieveClientContractTests
{
    [Fact]
    public void Options_UseManageSieveDefaults()
    {
        ManageSieveClientOptions options = new()
        {
            Host = "sieve.example.com"
        };

        Assert.Equal(4190, options.Port);
        Assert.Equal(ManageSieveSecurityMode.StartTlsRequired, options.SecurityMode);
        Assert.Equal(TimeSpan.FromSeconds(30), options.ConnectTimeout);
        Assert.Equal(TimeSpan.FromSeconds(30), options.OperationTimeout);
    }

    [Fact]
    public void Constructor_RejectsInvalidEndpointAndTimeouts()
    {
        Assert.Throws<ArgumentException>(() => CreateClient(host: " "));
        Assert.Throws<ArgumentOutOfRangeException>(() => CreateClient(port: 0));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => CreateClient(connectTimeout: TimeSpan.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => CreateClient(operationTimeout: TimeSpan.Zero));
    }

    [Fact]
    public async Task PlainAuthenticator_RejectsUnsecuredConnection()
    {
        var transport = new ScriptedTransport(
            "\"IMPLEMENTATION\" \"test\"\r\n\"SASL\" \"PLAIN\"\r\nOK\r\n"u8.ToArray());
        var client = CreateClient(
            securityMode: ManageSieveSecurityMode.PlainText,
            transport: transport);
        await client.ConnectAsync();

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => client.AuthenticateAsync(
                new ManageSievePlainAuthenticator("user", "secret")).AsTask());
    }

    [Fact]
    public async Task Client_TransitionsThroughTlsAuthenticationAndLogout()
    {
        byte[] responses = Encoding.ASCII.GetBytes(
            "\"IMPLEMENTATION\" \"test\"\r\n" +
            "\"STARTTLS\"\r\n" +
            "\"SASL\" \"PLAIN\"\r\n" +
            "OK\r\n" +
            "OK\r\n" +
            "\"IMPLEMENTATION\" \"test tls\"\r\n" +
            "\"SASL\" \"PLAIN\"\r\n" +
            "OK\r\n" +
            "OK\r\n" +
            "OK\r\n");
        var transport = new ScriptedTransport(responses);
        var client = CreateClient(transport: transport);

        await client.ConnectAsync();
        Assert.Equal(ManageSieveSessionState.Connected, client.State);

        await client.StartTlsAsync();
        Assert.Equal(ManageSieveSessionState.Secured, client.State);
        Assert.Equal("test tls", client.Capabilities?.Implementation);

        await client.AuthenticateAsync(
            new ManageSievePlainAuthenticator("user", "secret"));
        Assert.Equal(ManageSieveSessionState.Authenticated, client.State);

        await client.LogoutAsync();
        Assert.Equal(ManageSieveSessionState.Closed, client.State);

        string commands = Encoding.ASCII.GetString(transport.Written);
        Assert.Contains("STARTTLS\r\n", commands);
        Assert.Contains("AUTHENTICATE \"PLAIN\" \"AHVzZXIAc2VjcmV0\"\r\n", commands);
        Assert.EndsWith("LOGOUT\r\n", commands);
    }

    [Fact]
    public async Task Commands_MapResultsAndPreserveLiteralBytes()
    {
        byte[] script = [0x6b, 0x65, 0x65, 0x70, 0x3b, 0x0d, 0x0a, 0xc3, 0xa4];
        byte[] responses = Encoding.UTF8.GetBytes(
            "\"SASL\" \"TEST\"\r\nOK\r\n" +
            "OK\r\n" +
            "\"one\"\r\n\"two\" ACTIVE\r\nOK\r\n" +
            $"{{{script.Length}}}\r\n")
            .Concat(script)
            .Concat("\r\nOK\r\nNO (QUOTA/MAXSIZE) \"too large\"\r\nOK \"valid\"\r\n"u8.ToArray())
            .ToArray();
        var transport = new ScriptedTransport(responses, secure: true);
        var client = CreateClient(
            securityMode: ManageSieveSecurityMode.ImplicitTls,
            transport: transport);

        await client.ConnectAsync();
        await client.AuthenticateAsync(new TestAuthenticator());

        IReadOnlyList<ManageSieveScriptInfo> scripts = await client.ListScriptsAsync();
        ManageSieveScript downloaded = await client.GetScriptAsync("two");
        ManageSieveSpaceAvailability space = await client.HaveSpaceAsync("new", 100);
        ManageSieveCommandResult validation = await client.CheckScriptAsync(script);

        Assert.Collection(
            scripts,
            item => Assert.Equal(new ManageSieveScriptInfo("one", false), item),
            item => Assert.Equal(new ManageSieveScriptInfo("two", true), item));
        Assert.Equal(script, downloaded.Content.ToArray());
        Assert.False(space.HasSpace);
        Assert.Equal("QUOTA/MAXSIZE", space.ResponseCode);
        Assert.Equal("valid", validation.Message);
    }

    [Fact]
    public async Task Authentication_ProcessesSaslChallengeAndRefreshesCapabilities()
    {
        byte[] responses = Encoding.ASCII.GetBytes(
            "\"SASL\" \"TEST\"\r\nOK\r\n" +
            "\"Y2hhbGxlbmdl\"\r\n" +
            "\"IMPLEMENTATION\" \"authenticated\"\r\n" +
            "\"SASL\" \"TEST\"\r\n" +
            "OK\r\n");
        var transport = new ScriptedTransport(responses, secure: true);
        var authenticator = new ChallengeAuthenticator();
        var client = CreateClient(
            securityMode: ManageSieveSecurityMode.ImplicitTls,
            transport: transport);
        await client.ConnectAsync();

        await client.AuthenticateAsync(authenticator);

        Assert.Equal("challenge"u8.ToArray(), authenticator.Challenge);
        Assert.Equal("authenticated", client.Capabilities?.Implementation);
        Assert.EndsWith(
            "\"cmVzcG9uc2U=\"\r\n",
            Encoding.ASCII.GetString(transport.Written));
    }

    [Fact]
    public async Task OperationTimeout_IsReportedWithoutMaskingCallerCancellation()
    {
        var transport = new ScriptedTransport(
            "\"IMPLEMENTATION\" \"test\"\r\nOK\r\n"u8.ToArray(),
            blockAfterInput: true);
        var client = CreateClient(
            operationTimeout: TimeSpan.FromMilliseconds(20),
            transport: transport);
        await client.ConnectAsync();

        await Assert.ThrowsAsync<TimeoutException>(
            () => client.NoOpAsync().AsTask());

        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => client.NoOpAsync(cancellationToken: cancellation.Token).AsTask());
    }

    [Fact]
    public async Task DisposeAsync_IsIdempotentAndClosesClient()
    {
        var client = CreateClient();

        await client.DisposeAsync();
        await client.DisposeAsync();

        Assert.Equal(ManageSieveSessionState.Closed, client.State);
        await Assert.ThrowsAsync<ObjectDisposedException>(
            () => client.ConnectAsync().AsTask());
    }

    private static ManageSieveClient CreateClient(
        string host = "sieve.example.com",
        int port = 4190,
        ManageSieveSecurityMode securityMode = ManageSieveSecurityMode.StartTlsRequired,
        TimeSpan? connectTimeout = null,
        TimeSpan? operationTimeout = null,
        ScriptedTransport? transport = null) =>
        new(
            new ManageSieveClientOptions
            {
                Host = host,
                Port = port,
                SecurityMode = securityMode,
                ConnectTimeout = connectTimeout ?? TimeSpan.FromSeconds(30),
                OperationTimeout = operationTimeout ?? TimeSpan.FromSeconds(30)
            },
            new ScriptedTransportFactory(
                transport ?? new ScriptedTransport([])));

    private sealed class TestAuthenticator : IManageSieveAuthenticator
    {
        public string Mechanism => "TEST";

        public ValueTask<ReadOnlyMemory<byte>?> GetInitialResponseAsync(
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<ReadOnlyMemory<byte>?>(null);

        public ValueTask<ReadOnlyMemory<byte>> RespondAsync(
            ReadOnlyMemory<byte> challenge,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(ReadOnlyMemory<byte>.Empty);
    }

    private sealed class ChallengeAuthenticator : IManageSieveAuthenticator
    {
        public string Mechanism => "TEST";

        public byte[]? Challenge { get; private set; }

        public ValueTask<ReadOnlyMemory<byte>?> GetInitialResponseAsync(
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<ReadOnlyMemory<byte>?>(null);

        public ValueTask<ReadOnlyMemory<byte>> RespondAsync(
            ReadOnlyMemory<byte> challenge,
            CancellationToken cancellationToken = default)
        {
            Challenge = challenge.ToArray();
            return ValueTask.FromResult<ReadOnlyMemory<byte>>("response"u8.ToArray());
        }
    }

    private sealed class ScriptedTransportFactory(ScriptedTransport transport)
        : IManageSieveTransportFactory
    {
        public IManageSieveTransport Create(ManageSieveClientOptions options) => transport;
    }

    private sealed class ScriptedTransport(
        byte[] input,
        bool secure = false,
        bool blockAfterInput = false)
        : IManageSieveTransport
    {
        private readonly ScriptedStream stream = new(input, blockAfterInput);

        public Stream Stream => stream;

        public bool IsSecure { get; private set; } = secure;

        public byte[] Written => stream.Written;

        public ValueTask ConnectAsync(CancellationToken cancellationToken) =>
            ValueTask.CompletedTask;

        public ValueTask UpgradeTlsAsync(
            string targetHost,
            CancellationToken cancellationToken)
        {
            IsSecure = true;
            return ValueTask.CompletedTask;
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class ScriptedStream(byte[] input, bool blockAfterInput) : Stream
    {
        private readonly MemoryStream input = new(input);
        private readonly MemoryStream output = new();

        public byte[] Written => output.ToArray();

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override Task FlushAsync(CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public override int Read(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            int read = await input.ReadAsync(buffer[..Math.Min(1, buffer.Length)], cancellationToken);
            if (read > 0 || !blockAfterInput)
            {
                return read;
            }

            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return 0;
        }

        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();

        public override void SetLength(long value) =>
            throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) =>
            output.Write(buffer, offset, count);

        public override ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default) =>
            output.WriteAsync(buffer, cancellationToken);
    }
}
