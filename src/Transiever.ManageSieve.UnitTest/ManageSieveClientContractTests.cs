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
        var transport = new ScriptedManageSieveTransport(responses, secure: true);
        var client = CreateClient(
            securityMode: ManageSieveSecurityMode.ImplicitTls,
            transport: transport);

        await client.ConnectAsync(TestContext.Current.CancellationToken);
        await client.AuthenticateAsync(
            new ScriptedAuthenticator(), TestContext.Current.CancellationToken);

        IReadOnlyList<ManageSieveScriptInfo> scripts = await client.ListScriptsAsync(
            TestContext.Current.CancellationToken);
        ManageSieveScript downloaded = await client.GetScriptAsync(
            "two", TestContext.Current.CancellationToken);
        ManageSieveSpaceAvailability space = await client.HaveSpaceAsync(
            "new", 100, TestContext.Current.CancellationToken);
        ManageSieveCommandResult validation = await client.CheckScriptAsync(
            script, TestContext.Current.CancellationToken);

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
    public async Task OperationTimeout_IsReportedWithoutMaskingCallerCancellation()
    {
        var transport = new ScriptedManageSieveTransport(
            "\"IMPLEMENTATION\" \"test\"\r\nOK\r\n"u8.ToArray(),
            blockAfterInput: true);
        var client = CreateClient(
            operationTimeout: TimeSpan.FromMilliseconds(20),
            transport: transport);
        await client.ConnectAsync(TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<TimeoutException>(
            () => client.NoOpAsync(
                cancellationToken: TestContext.Current.CancellationToken).AsTask());

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
            () => client.ConnectAsync(
                TestContext.Current.CancellationToken).AsTask());
    }

    [Fact]
    public async Task DisposeAsync_DisposesConnectedTransport()
    {
        var transport = new ScriptedManageSieveTransport(
            "OK\r\n"u8.ToArray());
        var client = CreateClient(transport: transport);

        await client.ConnectAsync(TestContext.Current.CancellationToken);
        await client.DisposeAsync();

        Assert.True(transport.IsDisposed);
    }

    private static ManageSieveClient CreateClient(
        string host = "sieve.example.com",
        int port = 4190,
        ManageSieveSecurityMode securityMode = ManageSieveSecurityMode.StartTlsRequired,
        TimeSpan? connectTimeout = null,
        TimeSpan? operationTimeout = null,
        ScriptedManageSieveTransport? transport = null) =>
        new(
            new ManageSieveClientOptions
            {
                Host = host,
                Port = port,
                SecurityMode = securityMode,
                ConnectTimeout = connectTimeout ?? TimeSpan.FromSeconds(30),
                OperationTimeout = operationTimeout ?? TimeSpan.FromSeconds(30)
            },
            transport ?? new ScriptedManageSieveTransport(ReadOnlyMemory<byte>.Empty));
}
