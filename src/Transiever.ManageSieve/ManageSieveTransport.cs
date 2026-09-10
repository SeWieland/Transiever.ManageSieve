using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Transiever.ManageSieve;

internal interface IManageSieveTransportFactory
{
    IManageSieveTransport Create(ManageSieveClientOptions options);
}

internal interface IManageSieveTransport : IAsyncDisposable
{
    Stream Stream { get; }

    bool IsSecure { get; }

    bool TryGetTlsServerEndPointBinding(out byte[] binding);

    ValueTask ConnectAsync(CancellationToken cancellationToken);

    ValueTask UpgradeTlsAsync(string targetHost, CancellationToken cancellationToken);
}

internal sealed class TcpManageSieveTransportFactory(
    RemoteCertificateValidationCallback? certificateValidationCallback = null)
    : IManageSieveTransportFactory
{
    public static TcpManageSieveTransportFactory Instance { get; } = new();

    public IManageSieveTransport Create(ManageSieveClientOptions options) =>
        new TcpManageSieveTransport(options, certificateValidationCallback);
}

internal sealed class TcpManageSieveTransport(
    ManageSieveClientOptions options,
    RemoteCertificateValidationCallback? certificateValidationCallback)
    : IManageSieveTransport
{
    private readonly TcpClient _client = new();
    private Stream? _stream;

    public Stream Stream =>
        _stream ?? throw new InvalidOperationException("The transport is not connected.");

    public bool IsSecure => _stream is SslStream;

    public bool TryGetTlsServerEndPointBinding(out byte[] binding)
    {
        if (_stream is not SslStream ssl)
        {
            binding = [];
            return false;
        }

        X509Certificate? remoteCertificate = ssl.RemoteCertificate;
        X509Certificate2? certificate = remoteCertificate as X509Certificate2;
        bool ownsCertificate = certificate is null;
        certificate ??= remoteCertificate is null
            ? null
            : new X509Certificate2(remoteCertificate);
        byte[]? certificateDer = null;

        try
        {
            certificateDer = certificate?.RawData;
            binding = DeriveTlsServerEndPointBinding(
                ssl.SslProtocol,
                certificateDer is null
                    ? ReadOnlySpan<byte>.Empty
                    : certificateDer,
                certificate?.SignatureAlgorithm.Value);
            return true;
        }
        finally
        {
            if (certificateDer is not null)
            {
                CryptographicOperations.ZeroMemory(certificateDer);
            }

            if (ownsCertificate)
            {
                certificate?.Dispose();
            }
        }
    }

    internal static byte[] DeriveTlsServerEndPointBinding(
        SslProtocols sslProtocol,
        ReadOnlySpan<byte> certificateDer,
        string? signatureAlgorithmOid)
    {
        if (sslProtocol != SslProtocols.Tls12 ||
            certificateDer.IsEmpty ||
            signatureAlgorithmOid is null)
        {
            throw CreateUnsupportedTlsServerEndPointBindingException();
        }

        // Source: https://github.com/dotnet/runtime/blob/9c868a69706dd2ce2494fe9d746835ebac3fcb31/src/libraries/System.Net.Security/src/System/Net/Security/Pal.Managed/EndpointChannelBindingToken.cs#L28
        return signatureAlgorithmOid switch
        {
            "1.2.840.113549.1.1.4" or
            "1.2.840.113549.2.5" or
            "1.3.14.3.2.26" or
            "1.2.840.10040.4.3" or
            "1.2.840.10045.4.1" or
            "1.2.840.113549.1.1.5" or
            "2.16.840.1.101.3.4.2.1" or
            "1.2.840.10045.4.3.2" or
            "1.2.840.113549.1.1.11" => SHA256.HashData(certificateDer),
            "2.16.840.1.101.3.4.2.2" or
            "1.2.840.10045.4.3.3" or
            "1.2.840.113549.1.1.12" => SHA384.HashData(certificateDer),
            "2.16.840.1.101.3.4.2.3" or
            "1.2.840.10045.4.3.4" or
            "1.2.840.113549.1.1.13" => SHA512.HashData(certificateDer),
            _ => throw CreateUnsupportedTlsServerEndPointBindingException()
        };
    }

    private static ManageSieveAuthenticationException CreateUnsupportedTlsServerEndPointBindingException() =>
        new("SCRAM-SHA-256-PLUS requires a supported TLS 1.2 channel binding.");

    public async ValueTask ConnectAsync(CancellationToken cancellationToken)
    {
        await _client.ConnectAsync(options.Host, options.Port, cancellationToken)
            .ConfigureAwait(false);
        _stream = _client.GetStream();
    }

    public async ValueTask UpgradeTlsAsync(
        string targetHost,
        CancellationToken cancellationToken)
    {
        var ssl = new SslStream(
            Stream,
            leaveInnerStreamOpen: false,
            certificateValidationCallback);
        await ssl.AuthenticateAsClientAsync(
            new SslClientAuthenticationOptions
            {
                TargetHost = targetHost,
                EnabledSslProtocols = SslProtocols.None
            },
            cancellationToken).ConfigureAwait(false);
        _stream = ssl;
    }

    public async ValueTask DisposeAsync()
    {
        if (_stream is not null)
        {
            await _stream.DisposeAsync().ConfigureAwait(false);
        }

        _client.Dispose();
    }
}
