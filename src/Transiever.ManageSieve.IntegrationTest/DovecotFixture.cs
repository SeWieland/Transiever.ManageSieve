using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Containers;
using DotNet.Testcontainers.Images;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Transiever.ManageSieve.IntegrationTest;

public sealed class DovecotFixture : IAsyncLifetime
{
    private const string ImageName = "transiever-integration-dovecot:2.3.21.1";
    private IFutureDockerImage? image;
    private IContainer? container;
    private byte[]? certificateHash;

    public string? UnavailableReason { get; private set; }

    public async Task InitializeAsync()
    {
        try
        {
            string dockerDirectory = Path.Combine(AppContext.BaseDirectory, "docker");
            image = new ImageFromDockerfileBuilder()
                .WithDockerfileDirectory(dockerDirectory)
                .WithDockerfile("Dockerfile")
                .WithName(ImageName)
                .WithCleanUp(true)
                .Build();
            await image.CreateAsync();

            container = new ContainerBuilder(image)
                .WithPortBinding(4190, true)
                .WithWaitStrategy(
                    Wait.ForUnixContainer().UntilExternalTcpPortIsAvailable(4190))
                .WithCleanUp(true)
                .Build();
            await container.StartAsync();

            ExecResult certificate = await container.ExecAsync(
                ["sh", "-c", "base64 -w0 /etc/dovecot/cert.pem"]);
            using X509Certificate2 parsed =
                X509Certificate2.CreateFromPem(
                    System.Text.Encoding.ASCII.GetString(
                        Convert.FromBase64String(certificate.Stdout.Trim())));
            certificateHash = SHA256.HashData(parsed.RawData);
        }
        catch (Exception exception)
        {
            UnavailableReason =
                $"Docker-backed ManageSieve tests are unavailable: {exception.Message}";
            await DisposeAsync();
        }
    }

    public ManageSieveClient CreateClient()
    {
        if (container is null || certificateHash is null)
        {
            throw new InvalidOperationException(UnavailableReason);
        }

        var options = new ManageSieveClientOptions
        {
            Host = "localhost",
            Port = container.GetMappedPublicPort(4190),
            SecurityMode = ManageSieveSecurityMode.StartTlsRequired,
            ConnectTimeout = TimeSpan.FromSeconds(30),
            OperationTimeout = TimeSpan.FromSeconds(30)
        };
        return new ManageSieveClient(
            options,
            new TcpManageSieveTransportFactory(ValidateCertificate));
    }

    public async Task DisposeAsync()
    {
        if (container is not null)
        {
            await container.DisposeAsync();
            container = null;
        }

        if (image is not null)
        {
            await image.DisposeAsync();
            image = null;
        }
    }

    private bool ValidateCertificate(
        object sender,
        X509Certificate? certificate,
        X509Chain? chain,
        SslPolicyErrors sslPolicyErrors) =>
        certificate is not null &&
        CryptographicOperations.FixedTimeEquals(
            SHA256.HashData(certificate.GetRawCertData()),
            certificateHash!);
}
