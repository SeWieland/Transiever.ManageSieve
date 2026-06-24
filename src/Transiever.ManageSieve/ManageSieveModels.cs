namespace Transiever.ManageSieve;

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

public sealed record ManageSieveScriptInfo(
    string Name,
    bool IsActive);

public sealed record ManageSieveScript(
    string Name,
    ReadOnlyMemory<byte> Content);

public sealed record ManageSieveCommandResult
{
    public string? Message { get; init; }

    public string? ResponseCode { get; init; }

    public IReadOnlyList<string> Warnings { get; init; } = [];
}

public sealed record ManageSieveSpaceAvailability
{
    public required bool HasSpace { get; init; }

    public string? Message { get; init; }

    public string? ResponseCode { get; init; }
}
