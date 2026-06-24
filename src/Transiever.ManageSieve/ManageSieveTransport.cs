using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;

namespace Transiever.ManageSieve;

internal interface IManageSieveTransportFactory
{
    IManageSieveTransport Create(ManageSieveClientOptions options);
}

internal interface IManageSieveTransport : IAsyncDisposable
{
    Stream Stream { get; }

    bool IsSecure { get; }

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
    private readonly TcpClient client = new();
    private Stream? stream;

    public Stream Stream =>
        stream ?? throw new InvalidOperationException("The transport is not connected.");

    public bool IsSecure => stream is SslStream;

    public async ValueTask ConnectAsync(CancellationToken cancellationToken)
    {
        await client.ConnectAsync(options.Host, options.Port, cancellationToken)
            .ConfigureAwait(false);
        stream = client.GetStream();
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
        stream = ssl;
    }

    public async ValueTask DisposeAsync()
    {
        if (stream is not null)
        {
            await stream.DisposeAsync().ConfigureAwait(false);
        }

        client.Dispose();
    }
}
