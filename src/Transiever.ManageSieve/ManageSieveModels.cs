namespace Transiever.ManageSieve;

/// <summary>
/// Capabilities advertised by a ManageSieve server.
/// </summary>
public sealed record ManageSieveCapabilities
{
    public string? Implementation { get; init; }

    public string? ProtocolVersion { get; init; }

    public string? Owner { get; init; }

    public string? Language { get; init; }

    public int? MaxRedirects { get; init; }

    public bool SupportsStartTls { get; init; }

    public IReadOnlySet<string> SaslMechanisms { get; init; } =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    public IReadOnlySet<string> SieveExtensions { get; init; } =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    public IReadOnlySet<string> NotificationMethods { get; init; } =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyDictionary<string, string?> Additional { get; init; } =
        new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
}

/// <summary>
/// Identifies a server-side script and whether it is active.
/// </summary>
public sealed record ManageSieveScriptInfo(
    string Name,
    bool IsActive);

/// <summary>
/// Represents a complete script retrieved from the server.
/// </summary>
public sealed record ManageSieveScript(
    string Name,
    ReadOnlyMemory<byte> Content);

/// <summary>
/// Result details returned from a ManageSieve command.
/// </summary>
public sealed record ManageSieveCommandResult
{
    public string? Message { get; init; }

    public string? ResponseCode { get; init; }

    public IReadOnlyList<string> Warnings { get; init; } = [];
}

/// <summary>
/// Indicates whether a server can accept a script upload of a given size.
/// </summary>
public sealed record ManageSieveSpaceAvailability
{
    public required bool HasSpace { get; init; }

    public string? Message { get; init; }

    public string? ResponseCode { get; init; }
}
