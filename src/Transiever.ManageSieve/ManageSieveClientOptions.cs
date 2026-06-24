namespace Transiever.ManageSieve;

public sealed record ManageSieveClientOptions
{
    public const int DefaultPort = 4190;

    public required string Host { get; init; }

    public int Port { get; init; } = DefaultPort;

    public ManageSieveSecurityMode SecurityMode { get; init; } =
        ManageSieveSecurityMode.StartTlsRequired;

    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(30);

    public TimeSpan OperationTimeout { get; init; } = TimeSpan.FromSeconds(30);
}
