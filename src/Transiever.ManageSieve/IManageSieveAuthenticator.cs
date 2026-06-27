namespace Transiever.ManageSieve;

/// <summary>
/// Supplies SASL responses for ManageSieve authentication.
/// </summary>
public interface IManageSieveAuthenticator
{
    /// <summary>
    /// Gets the SASL mechanism name.
    /// </summary>
    string Mechanism { get; }

    /// <summary>
    /// Returns the initial client response, if the mechanism uses one.
    /// </summary>
    ValueTask<ReadOnlyMemory<byte>?> GetInitialResponseAsync(
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Produces the next response for a server challenge.
    /// </summary>
    ValueTask<ReadOnlyMemory<byte>> RespondAsync(
        ReadOnlyMemory<byte> challenge,
        CancellationToken cancellationToken = default);
}
