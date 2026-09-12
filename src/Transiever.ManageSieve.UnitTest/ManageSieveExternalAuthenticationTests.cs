using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using static Transiever.ManageSieve.UnitTest.SaslConformanceHarness;

namespace Transiever.ManageSieve.UnitTest;

public sealed class ManageSieveExternalAuthenticationTests
{
    private static readonly byte[] Greeting = "\"SASL\" \"EXTERNAL\"\r\nOK\r\n"u8.ToArray();

    [Theory]
    [InlineData(null, "AUTHENTICATE \"EXTERNAL\" \"\"\r\n")]
    [InlineData("alice@example.com", "AUTHENTICATE \"EXTERNAL\" \"YWxpY2VAZXhhbXBsZS5jb20=\"\r\n")]
    [InlineData("Jörg", "AUTHENTICATE \"EXTERNAL\" \"SsO2cmc=\"\r\n")]
    public async Task ExternalAuthentication_WritesExactInitialResponse(
        string? identity,
        string expectedFrame)
    {
        using X509Certificate2 certificate = CreateClientCertificate();
        await using SaslConformanceHarness harness = await SaslConformanceHarness.ConnectAsync(
            Greeting.Concat("OK\r\n"u8.ToArray()).ToArray(),
            hasClientCertificate: true,
            clientCertificate: certificate);

        await harness.Client.AuthenticateAsync(
            new ManageSieveExternalAuthenticator(identity),
            TestContext.Current.CancellationToken);

        AssertTranscriptEqual(
            System.Text.Encoding.ASCII.GetBytes(expectedFrame),
            harness.Transport.Written.Span);
        Assert.Equal(ManageSieveSessionState.Authenticated, harness.Client.State);
    }

    [Fact]
    public async Task ExternalAuthentication_RequiresSecureTransportEvenWhenAuthenticatorAllowsPlaintext()
    {
        using X509Certificate2 certificate = CreateClientCertificate();
        await using SaslConformanceHarness harness = await SaslConformanceHarness.ConnectAsync(
            Greeting,
            securityMode: ManageSieveSecurityMode.PlainText,
            secure: false,
            hasClientCertificate: true,
            clientCertificate: certificate);

        await AssertPreWireFailureAsync(
            harness,
            new RecordingCertificateAuthenticator { AllowsUnprotectedConnection = true },
            ManageSieveSessionState.Connected);
    }

    [Fact]
    public async Task ExternalAuthentication_RequiresConfiguredCertificate()
    {
        await using SaslConformanceHarness harness = await SaslConformanceHarness.ConnectAsync(
            Greeting,
            hasClientCertificate: true);

        await AssertPreWireFailureAsync(
            harness,
            new RecordingCertificateAuthenticator(),
            ManageSieveSessionState.Secured);
    }

    [Fact]
    public async Task ExternalAuthentication_RequiresPrivateKey()
    {
        using X509Certificate2 certificate = CreateClientCertificate();
        using X509Certificate2 publicOnly = X509CertificateLoader.LoadCertificate(
            certificate.RawData);
        await using SaslConformanceHarness harness = await SaslConformanceHarness.ConnectAsync(
            Greeting,
            hasClientCertificate: true,
            clientCertificate: publicOnly);

        await AssertPreWireFailureAsync(
            harness,
            new RecordingCertificateAuthenticator(),
            ManageSieveSessionState.Secured);
    }

    [Fact]
    public async Task ExternalAuthentication_TreatsDisposedCertificateAsUnusable()
    {
        X509Certificate2 certificate = CreateClientCertificate();
        certificate.Dispose();
        await using SaslConformanceHarness harness = await SaslConformanceHarness.ConnectAsync(
            Greeting,
            hasClientCertificate: true,
            clientCertificate: certificate);

        await AssertPreWireFailureAsync(
            harness,
            new RecordingCertificateAuthenticator(),
            ManageSieveSessionState.Secured);
    }

    [Fact]
    public async Task ExternalAuthentication_RequiresPresentedCertificate()
    {
        using X509Certificate2 certificate = CreateClientCertificate();
        await using SaslConformanceHarness harness = await SaslConformanceHarness.ConnectAsync(
            Greeting,
            hasClientCertificate: false,
            clientCertificate: certificate);

        await AssertPreWireFailureAsync(
            harness,
            new RecordingCertificateAuthenticator(),
            ManageSieveSessionState.Secured);
    }

    [Fact]
    public async Task ExternalAuthentication_ServerRejectionPreservesSecuredSession()
    {
        const string identity = "private-authorization-identity";
        using X509Certificate2 certificate = CreateClientCertificate();
        await using SaslConformanceHarness harness = await SaslConformanceHarness.ConnectAsync(
            Greeting.Concat(
                "NO (AUTHENTICATIONFAILED) \"certificate mapping rejected\"\r\n"u8.ToArray())
                .ToArray(),
            hasClientCertificate: true,
            clientCertificate: certificate);

        ManageSieveAuthenticationException exception =
            await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
                () => harness.Client.AuthenticateAsync(
                    new ManageSieveExternalAuthenticator(identity),
                    TestContext.Current.CancellationToken).AsTask());

        Assert.Equal("ManageSieve authentication failed.", exception.Message);
        Assert.Equal("AUTHENTICATIONFAILED", exception.ResponseCode);
        Assert.DoesNotContain(identity, exception.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("certificate mapping rejected", exception.ToString(), StringComparison.Ordinal);
        Assert.Equal(ManageSieveSessionState.Secured, harness.Client.State);
        Assert.Contains("EXTERNAL", harness.Client.Capabilities!.SaslMechanisms);
    }

    [Theory]
    [InlineData("\"Y2hhbGxlbmdl\"\r\n")]
    [InlineData("OK (SASL \"\")\r\n")]
    public async Task ExternalAuthentication_UnexpectedServerDataDisconnects(string response)
    {
        using X509Certificate2 certificate = CreateClientCertificate();
        await using SaslConformanceHarness harness = await SaslConformanceHarness.ConnectAsync(
            Greeting.Concat(System.Text.Encoding.ASCII.GetBytes(response)).ToArray(),
            hasClientCertificate: true,
            clientCertificate: certificate);

        await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
            () => harness.Client.AuthenticateAsync(
                new ManageSieveExternalAuthenticator(),
                TestContext.Current.CancellationToken).AsTask());

        Assert.Equal(ManageSieveSessionState.Disconnected, harness.Client.State);
        Assert.Null(harness.Client.Capabilities);
        Assert.True(harness.Transport.IsDisposed);
    }

    [Fact]
    public async Task ExternalAuthentication_ServerByeDisconnects()
    {
        using X509Certificate2 certificate = CreateClientCertificate();
        await using SaslConformanceHarness harness = await SaslConformanceHarness.ConnectAsync(
            Greeting.Concat("BYE \"closing\"\r\n"u8.ToArray()).ToArray(),
            hasClientCertificate: true,
            clientCertificate: certificate);

        ManageSieveConnectionException exception =
            await Assert.ThrowsAsync<ManageSieveConnectionException>(
                () => harness.Client.AuthenticateAsync(
                    new ManageSieveExternalAuthenticator(),
                    TestContext.Current.CancellationToken).AsTask());

        Assert.Equal(
            "ManageSieve server closed the connection during authentication.",
            exception.Message);
        Assert.Equal(ManageSieveSessionState.Disconnected, harness.Client.State);
        Assert.True(harness.Transport.IsDisposed);
    }

    [Fact]
    public async Task ExternalAuthentication_CancellationAfterWriteDisconnects()
    {
        using X509Certificate2 certificate = CreateClientCertificate();
        await using SaslConformanceHarness harness = await SaslConformanceHarness.ConnectAsync(
            Greeting,
            blockAfterInput: true,
            hasClientCertificate: true,
            clientCertificate: certificate);
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(
            TestContext.Current.CancellationToken);

        Task authentication = harness.Client.AuthenticateAsync(
            new ManageSieveExternalAuthenticator(),
            cancellation.Token).AsTask();
        await harness.Transport.WaitForWriteAsync();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => authentication);

        AssertTranscriptEqual(
            "AUTHENTICATE \"EXTERNAL\" \"\"\r\n"u8,
            harness.Transport.Written.Span);
        Assert.Equal(ManageSieveSessionState.Disconnected, harness.Client.State);
        Assert.True(harness.Transport.IsDisposed);
    }

    [Theory]
    [InlineData("authentication")]
    [InlineData("io")]
    [InlineData("cryptographic")]
    public async Task ImplicitTlsFailureIsGenericAndDisconnects(string failureKind)
    {
        var transport = new ScriptedManageSieveTransport(
            ReadOnlyMemory<byte>.Empty,
            upgradeTlsException: TlsFailure(failureKind));
        var client = new ManageSieveClient(
            new ManageSieveClientOptions
            {
                Host = "sieve.example.com",
                SecurityMode = ManageSieveSecurityMode.ImplicitTls
            },
            transport);

        ManageSieveConnectionException exception =
            await Assert.ThrowsAsync<ManageSieveConnectionException>(
                () => client.ConnectAsync(TestContext.Current.CancellationToken).AsTask());

        Assert.Equal("TLS authentication failed.", exception.Message);
        Assert.Null(exception.InnerException);
        Assert.DoesNotContain("sensitive", exception.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.Equal(ManageSieveSessionState.Disconnected, client.State);
        Assert.Null(client.Capabilities);
        Assert.True(transport.IsDisposed);
    }

    [Theory]
    [InlineData("authentication")]
    [InlineData("io")]
    [InlineData("cryptographic")]
    public async Task StartTlsFailureIsGenericAndDisconnects(string failureKind)
    {
        var transport = new ScriptedManageSieveTransport(
            "\"STARTTLS\"\r\nOK\r\nOK\r\n"u8.ToArray(),
            upgradeTlsException: TlsFailure(failureKind));
        var client = new ManageSieveClient(
            new ManageSieveClientOptions { Host = "sieve.example.com" },
            transport);
        await client.ConnectAsync(TestContext.Current.CancellationToken);

        ManageSieveConnectionException exception =
            await Assert.ThrowsAsync<ManageSieveConnectionException>(
                () => client.StartTlsAsync(TestContext.Current.CancellationToken).AsTask());

        Assert.Equal("TLS authentication failed.", exception.Message);
        Assert.Null(exception.InnerException);
        Assert.DoesNotContain("sensitive", exception.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.Equal(ManageSieveSessionState.Disconnected, client.State);
        Assert.Null(client.Capabilities);
        Assert.True(transport.IsDisposed);
    }

    [Fact]
    public async Task ImplicitTlsCallerCancellationDisconnectsAndPreservesCancellation()
    {
        var transport = new ScriptedManageSieveTransport(
            ReadOnlyMemory<byte>.Empty,
            blockTlsUpgrade: true);
        var client = new ManageSieveClient(
            new ManageSieveClientOptions
            {
                Host = "sieve.example.com",
                SecurityMode = ManageSieveSecurityMode.ImplicitTls
            },
            transport);
        using var cancellation = new CancellationTokenSource();

        Task connect = client.ConnectAsync(cancellation.Token).AsTask();
        await transport.WaitForTlsUpgradeAsync();
        cancellation.Cancel();
        OperationCanceledException exception =
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => connect);

        Assert.Equal(cancellation.Token, exception.CancellationToken);
        AssertDisconnected(client, transport);
    }

    [Fact]
    public async Task ImplicitTlsTimeoutDisconnects()
    {
        var transport = new ScriptedManageSieveTransport(
            ReadOnlyMemory<byte>.Empty,
            blockTlsUpgrade: true);
        var client = new ManageSieveClient(
            new ManageSieveClientOptions
            {
                Host = "sieve.example.com",
                SecurityMode = ManageSieveSecurityMode.ImplicitTls,
                ConnectTimeout = TimeSpan.FromMilliseconds(20)
            },
            transport);

        ManageSieveConnectionException exception =
            await Assert.ThrowsAsync<ManageSieveConnectionException>(
                () => client.ConnectAsync(TestContext.Current.CancellationToken).AsTask());

        Assert.Equal("Connecting to sieve.example.com:4190 timed out.", exception.Message);
        Assert.Null(exception.InnerException);
        AssertDisconnected(client, transport);
    }

    [Fact]
    public async Task ImplicitTlsFailureOnFirstEncryptedReadIsGenericAndDisconnects()
    {
        var transport = new ScriptedManageSieveTransport(ReadOnlyMemory<byte>.Empty);
        var client = new ManageSieveClient(
            new ManageSieveClientOptions
            {
                Host = "sieve.example.com",
                SecurityMode = ManageSieveSecurityMode.ImplicitTls
            },
            transport);

        ManageSieveConnectionException exception =
            await Assert.ThrowsAsync<ManageSieveConnectionException>(
                () => client.ConnectAsync(TestContext.Current.CancellationToken).AsTask());

        Assert.Equal("TLS authentication failed.", exception.Message);
        Assert.Null(exception.InnerException);
        AssertDisconnected(client, transport);
    }

    [Fact]
    public async Task StartTlsCallerCancellationDisconnectsAndPreservesCancellation()
    {
        var transport = new ScriptedManageSieveTransport(
            "\"STARTTLS\"\r\nOK\r\nOK\r\n"u8.ToArray(),
            blockTlsUpgrade: true);
        var client = new ManageSieveClient(
            new ManageSieveClientOptions { Host = "sieve.example.com" },
            transport);
        await client.ConnectAsync(TestContext.Current.CancellationToken);
        using var cancellation = new CancellationTokenSource();

        Task startTls = client.StartTlsAsync(cancellation.Token).AsTask();
        await transport.WaitForTlsUpgradeAsync();
        cancellation.Cancel();
        OperationCanceledException exception =
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => startTls);

        Assert.Equal(cancellation.Token, exception.CancellationToken);
        AssertDisconnected(client, transport);
    }

    [Fact]
    public async Task StartTlsTimeoutDisconnects()
    {
        var transport = new ScriptedManageSieveTransport(
            "\"STARTTLS\"\r\nOK\r\nOK\r\n"u8.ToArray(),
            blockTlsUpgrade: true);
        var client = new ManageSieveClient(
            new ManageSieveClientOptions
            {
                Host = "sieve.example.com",
                OperationTimeout = TimeSpan.FromMilliseconds(20)
            },
            transport);
        await client.ConnectAsync(TestContext.Current.CancellationToken);

        TimeoutException exception = await Assert.ThrowsAsync<TimeoutException>(
            () => client.StartTlsAsync(TestContext.Current.CancellationToken).AsTask());

        Assert.Equal(
            "ManageSieve command STARTTLS exceeded 00:00:00.0200000.",
            exception.Message);
        AssertDisconnected(client, transport);
    }

    [Fact]
    public async Task StartTlsFailureOnFirstEncryptedReadIsGenericAndDisconnects()
    {
        var transport = new ScriptedManageSieveTransport(
            "\"STARTTLS\"\r\nOK\r\nOK\r\n"u8.ToArray());
        var client = new ManageSieveClient(
            new ManageSieveClientOptions { Host = "sieve.example.com" },
            transport);
        await client.ConnectAsync(TestContext.Current.CancellationToken);

        ManageSieveConnectionException exception =
            await Assert.ThrowsAsync<ManageSieveConnectionException>(
                () => client.StartTlsAsync(TestContext.Current.CancellationToken).AsTask());

        Assert.Equal("TLS authentication failed.", exception.Message);
        Assert.Null(exception.InnerException);
        AssertDisconnected(client, transport);
    }

    private static async Task AssertPreWireFailureAsync(
        SaslConformanceHarness harness,
        RecordingCertificateAuthenticator authenticator,
        ManageSieveSessionState expectedState)
    {
        ManageSieveAuthenticationException exception =
            await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
                () => harness.Client.AuthenticateAsync(
                    authenticator,
                    TestContext.Current.CancellationToken).AsTask());

        Assert.Equal("A verified TLS client certificate is required.", exception.Message);
        Assert.Empty(authenticator.Calls);
        Assert.Empty(harness.Transport.Written.ToArray());
        Assert.Equal(expectedState, harness.Client.State);
        Assert.Contains("EXTERNAL", harness.Client.Capabilities!.SaslMechanisms);
        Assert.False(harness.Transport.IsDisposed);
    }

    private static X509Certificate2 CreateClientCertificate()
    {
        using RSA key = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=client",
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-1),
            DateTimeOffset.UtcNow.AddMinutes(5));
    }

    private static Exception TlsFailure(string kind) =>
        kind switch
        {
            "authentication" => new AuthenticationException("sensitive TLS detail"),
            "io" => new IOException("sensitive TLS detail"),
            "cryptographic" => new CryptographicException("sensitive TLS detail"),
            _ => throw new ArgumentOutOfRangeException(nameof(kind))
        };

    private static void AssertDisconnected(
        ManageSieveClient client,
        ScriptedManageSieveTransport transport)
    {
        Assert.Equal(ManageSieveSessionState.Disconnected, client.State);
        Assert.Null(client.Capabilities);
        Assert.True(transport.IsDisposed);
    }

    private sealed class RecordingCertificateAuthenticator : IManageSieveAuthenticator
    {
        public string Mechanism => "EXTERNAL";

        public bool AllowsUnprotectedConnection { get; init; }

        public bool RequiresClientCertificate => true;

        public List<string> Calls { get; } = [];

        public ValueTask<ReadOnlyMemory<byte>?> GetInitialResponseAsync(
            CancellationToken cancellationToken = default)
        {
            Calls.Add("Initial");
            return ValueTask.FromResult<ReadOnlyMemory<byte>?>(ReadOnlyMemory<byte>.Empty);
        }

        public ValueTask<ReadOnlyMemory<byte>> RespondAsync(
            ReadOnlyMemory<byte> challenge,
            CancellationToken cancellationToken = default)
        {
            Calls.Add("Respond");
            return ValueTask.FromResult(ReadOnlyMemory<byte>.Empty);
        }

        public ValueTask CompleteAsync(
            ReadOnlyMemory<byte>? serverData,
            CancellationToken cancellationToken = default)
        {
            Calls.Add("Complete");
            return ValueTask.CompletedTask;
        }

        public void Abort() => Calls.Add("Abort");
    }
}
