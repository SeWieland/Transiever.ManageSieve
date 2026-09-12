using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Transiever.ManageSieve.IntegrationTest;

public sealed class ExternalMutualTlsTests
{
    [Fact]
    public async Task External_SendsEmptyIdentityAfterMutualTls()
    {
        using GeneratedCertificate serverIdentity = CreateServerCertificate();
        X509Certificate2 serverCertificate = serverIdentity.Certificate;
        using GeneratedCertificate clientIdentity = CreateClientCertificate();
        X509Certificate2 clientCertificate = clientIdentity.Certificate;
        byte[] expectedClientHash = SHA256.HashData(clientCertificate.RawData);
        bool clientCertificateObserved = false;
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(
            TestContext.Current.CancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(15));
        Task server = RunAcceptingServerAsync(
            listener,
            serverCertificate,
            expectedClientHash,
            () => clientCertificateObserved = true,
            timeout.Token);
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var options = new ManageSieveClientOptions
        {
            Host = "localhost",
            Port = port,
            SecurityMode = ManageSieveSecurityMode.ImplicitTls,
            ClientCertificate = clientCertificate,
            ConnectTimeout = TimeSpan.FromSeconds(10),
            OperationTimeout = TimeSpan.FromSeconds(10)
        };

        try
        {
            await using var client = new ManageSieveClient(
                options,
                new TcpManageSieveTransportFactory(
                    ExactCertificateValidator(serverCertificate)));
            await client.ConnectAsync(timeout.Token);
            await client.AuthenticateAsync(
                new ManageSieveExternalAuthenticator(),
                timeout.Token);

            Assert.Equal(ManageSieveSessionState.Authenticated, client.State);
            await server;
            Assert.True(clientCertificateObserved);
        }
        finally
        {
            timeout.Cancel();
            listener.Stop();
            await ObserveAsync(server);
            CryptographicOperations.ZeroMemory(expectedClientHash);
        }

        Assert.True(clientCertificate.HasPrivateKey);
    }

    [Fact]
    public async Task MissingClientCertificate_FailsTlsHandshake()
    {
        using GeneratedCertificate serverIdentity = CreateServerCertificate();
        X509Certificate2 serverCertificate = serverIdentity.Certificate;
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(
            TestContext.Current.CancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(15));
        var observation = new MissingCertificateObservation();
        Task server = RunRejectingServerAsync(
            listener,
            serverCertificate,
            observation,
            timeout.Token);
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var client = new ManageSieveClient(
            new ManageSieveClientOptions
            {
                Host = "localhost",
                Port = port,
                SecurityMode = ManageSieveSecurityMode.ImplicitTls,
                ConnectTimeout = TimeSpan.FromSeconds(10),
                OperationTimeout = TimeSpan.FromSeconds(10)
            },
            new TcpManageSieveTransportFactory(
                ExactCertificateValidator(serverCertificate)));

        try
        {
            ManageSieveConnectionException exception =
                await Assert.ThrowsAsync<ManageSieveConnectionException>(
                    () => client.ConnectAsync(timeout.Token).AsTask());

            Assert.Equal("TLS authentication failed.", exception.Message);
            Assert.Null(exception.InnerException);
            Assert.Equal(ManageSieveSessionState.Disconnected, client.State);
            Assert.Null(client.Capabilities);
            await server;
            Assert.True(observation.HandshakeRejected);
            Assert.False(observation.ApplicationBytesObserved);
        }
        finally
        {
            await client.DisposeAsync();
            timeout.Cancel();
            listener.Stop();
            await ObserveAsync(server);
        }
    }

    private static async Task RunAcceptingServerAsync(
        TcpListener listener,
        X509Certificate2 serverCertificate,
        byte[] expectedClientHash,
        Action recordClientCertificate,
        CancellationToken cancellationToken)
    {
        using TcpClient connection = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var tls = new SslStream(
            connection.GetStream(),
            leaveInnerStreamOpen: false,
            (_, certificate, _, _) =>
            {
                if (certificate is null)
                {
                    return false;
                }

                byte[] actualHash = SHA256.HashData(certificate.GetRawCertData());
                try
                {
                    bool matches = CryptographicOperations.FixedTimeEquals(
                        actualHash,
                        expectedClientHash);
                    if (matches)
                    {
                        recordClientCertificate();
                    }

                    return matches;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(actualHash);
                }
            });
        await tls.AuthenticateAsServerAsync(
            ServerOptions(serverCertificate),
            cancellationToken);
        await tls.WriteAsync(
            "\"SASL\" \"EXTERNAL\"\r\nOK\r\n"u8.ToArray(),
            cancellationToken);
        await tls.FlushAsync(cancellationToken);

        byte[] command = await ReadLineAsync(tls, cancellationToken);
        Assert.Equal(
            "AUTHENTICATE \"EXTERNAL\" \"\"\r\n"u8.ToArray(),
            command);

        await tls.WriteAsync("OK\r\n"u8.ToArray(), cancellationToken);
        await tls.FlushAsync(cancellationToken);
    }

    private static async Task RunRejectingServerAsync(
        TcpListener listener,
        X509Certificate2 serverCertificate,
        MissingCertificateObservation observation,
        CancellationToken cancellationToken)
    {
        using TcpClient connection = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var tls = new SslStream(
            connection.GetStream(),
            leaveInnerStreamOpen: false,
            (_, certificate, _, _) => certificate is not null);
        try
        {
            await tls.AuthenticateAsServerAsync(
                ServerOptions(serverCertificate),
                cancellationToken);
            byte[] buffer = new byte[1];
            observation.ApplicationBytesObserved =
                await tls.ReadAsync(buffer, cancellationToken) > 0;
        }
        catch (AuthenticationException)
        {
            observation.HandshakeRejected = true;
        }
        catch (IOException)
        {
            observation.HandshakeRejected = true;
        }
    }

    private static SslServerAuthenticationOptions ServerOptions(
        X509Certificate2 serverCertificate) =>
        new()
        {
            ServerCertificate = serverCertificate,
            ClientCertificateRequired = true,
            EnabledSslProtocols = SslProtocols.Tls12,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck
        };

    private static RemoteCertificateValidationCallback ExactCertificateValidator(
        X509Certificate2 expectedCertificate)
    {
        byte[] expectedHash = SHA256.HashData(expectedCertificate.RawData);
        return (_, certificate, _, _) =>
        {
            if (certificate is null)
            {
                return false;
            }

            byte[] actualHash = SHA256.HashData(certificate.GetRawCertData());
            try
            {
                return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(actualHash);
            }
        };
    }

    private static X509Certificate2 CreateCertificate(
        string subject,
        string enhancedKeyUsage)
    {
        using RSA key = RSA.Create(2048);
        return CreateCertificate(subject, enhancedKeyUsage, key);
    }

    private static GeneratedCertificate CreateServerCertificate()
        => CreateTlsCertificate(
            "CN=loopback-server",
            "1.3.6.1.5.5.7.3.1");

    private static GeneratedCertificate CreateClientCertificate()
        => CreateTlsCertificate(
            "CN=loopback-client",
            "1.3.6.1.5.5.7.3.2");

    private static GeneratedCertificate CreateTlsCertificate(
        string subject,
        string enhancedKeyUsage)
    {
        if (!OperatingSystem.IsWindows())
        {
            return new GeneratedCertificate(
                CreateCertificate(subject, enhancedKeyUsage),
                null);
        }

        string keyName = $"Transiever.ManageSieve.Tests.{Guid.NewGuid():N}";
        try
        {
            var parameters = new CngKeyCreationParameters
            {
                ExportPolicy = CngExportPolicies.None,
                KeyCreationOptions = CngKeyCreationOptions.None,
                KeyUsage = CngKeyUsages.Signing,
                Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider
            };
            using CngKey key = CngKey.Create(CngAlgorithm.Rsa, keyName, parameters);
            using var rsa = new RSACng(key);
            return new GeneratedCertificate(
                CreateCertificate(subject, enhancedKeyUsage, rsa),
                keyName);
        }
        catch
        {
            DeleteWindowsKey(keyName);
            throw;
        }
    }

    private static X509Certificate2 CreateCertificate(
        string subject,
        string enhancedKeyUsage,
        RSA key)
    {
        var request = new CertificateRequest(
            subject,
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                true));
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid(enhancedKeyUsage) },
                true));
        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-1),
            DateTimeOffset.UtcNow.AddMinutes(5));
    }

    private static void DeleteWindowsKey(string keyName)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException();
        }

        CngProvider provider = CngProvider.MicrosoftSoftwareKeyStorageProvider;
        if (!CngKey.Exists(keyName, provider))
        {
            return;
        }

        using CngKey key = CngKey.Open(keyName, provider);
        key.Delete();
        if (CngKey.Exists(keyName, provider))
        {
            throw new InvalidOperationException(
                "The temporary loopback TLS key could not be removed.");
        }
    }

    private static async Task<byte[]> ReadLineAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        using var line = new MemoryStream();
        byte[] oneByte = new byte[1];
        while (line.Length < 4096)
        {
            int read = await stream.ReadAsync(oneByte, cancellationToken);
            if (read == 0)
            {
                throw new IOException("The loopback client closed before sending a command.");
            }

            line.WriteByte(oneByte[0]);
            if (line.Length >= 2)
            {
                byte[] current = line.GetBuffer();
                int length = checked((int)line.Length);
                if (current[length - 2] == '\r' && current[length - 1] == '\n')
                {
                    return line.ToArray();
                }
            }
        }

        throw new IOException("The loopback command exceeded its fixed test bound.");
    }

    private static async Task ObserveAsync(Task task)
    {
        try
        {
            await task;
        }
        catch (OperationCanceledException)
        {
            // Cleanup preserves the test's primary result.
        }
        catch (ObjectDisposedException)
        {
            // Cleanup preserves the test's primary result.
        }
        catch (IOException)
        {
            // Cleanup preserves the test's primary result.
        }
        catch (AuthenticationException)
        {
            // Cleanup preserves the test's primary result.
        }
    }

    private sealed class MissingCertificateObservation
    {
        public bool HandshakeRejected { get; set; }

        public bool ApplicationBytesObserved { get; set; }
    }

    private sealed class GeneratedCertificate(
        X509Certificate2 certificate,
        string? windowsKeyName) : IDisposable
    {
        private bool disposed;

        public X509Certificate2 Certificate { get; } = certificate;

        public void Dispose()
        {
            if (disposed)
            {
                return;
            }

            disposed = true;
            try
            {
                Certificate.Dispose();
            }
            finally
            {
                if (windowsKeyName is not null)
                {
                    DeleteWindowsKey(windowsKeyName);
                }
            }
        }
    }
}
