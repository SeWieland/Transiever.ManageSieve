namespace Transiever.ManageSieve;

/// <summary>
/// Connection settings for a ManageSieve client.
/// </summary>
public sealed record ManageSieveClientOptions
{
    /// <summary>
    /// Gets the default ManageSieve port.
    /// </summary>
    public const int DefaultPort = 4190;

    /// <summary>
    /// Gets the server host name or IP address.
    /// </summary>
    public required string Host { get; init; }

    /// <summary>
    /// Gets the server port.
    /// </summary>
    public int Port { get; init; } = DefaultPort;

    /// <summary>
    /// Gets the transport security policy.
    /// </summary>
    public ManageSieveSecurityMode SecurityMode { get; init; } =
        ManageSieveSecurityMode.StartTlsRequired;

    /// <summary>
    /// Gets the maximum time allowed for the initial TCP connection.
    /// </summary>
    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Gets the maximum time allowed for a ManageSieve command.
    /// </summary>
    public TimeSpan OperationTimeout { get; init; } = TimeSpan.FromSeconds(30);
}
