namespace Transiever.ManageSieve;

// Compatibility note: public authentication types intentionally remain in the root namespace;
// they will align with the Authentication folder namespace in the next major release.
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
    /// Gets a value indicating whether the mechanism may run without TLS.
    /// </summary>
    bool AllowsUnprotectedConnection => false;

    /// <summary>
    /// Returns the initial client response, if the mechanism uses one.
    /// </summary>
    /// <remarks>
    /// The returned response memory remains owned by the authenticator and must stay valid
    /// until <see cref="CompleteAsync"/> or <see cref="Abort"/> is invoked.
    /// </remarks>
    ValueTask<ReadOnlyMemory<byte>?> GetInitialResponseAsync(
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Produces the next response for a server challenge.
    /// </summary>
    /// <remarks>
    /// The returned response memory remains owned by the authenticator and must stay valid
    /// until <see cref="CompleteAsync"/> or <see cref="Abort"/> is invoked.
    /// </remarks>
    ValueTask<ReadOnlyMemory<byte>> RespondAsync(
        ReadOnlyMemory<byte> challenge,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Completes the exchange before the client enters the authenticated state.
    /// </summary>
    /// <remarks>
    /// The server data memory is owned by the client and is valid only for the duration of this callback.
    /// The authenticator must not retain it after the callback returns.
    /// The authenticator must clear mutable response or secret buffers it retained before returning.
    /// </remarks>
    ValueTask CompleteAsync(
        ReadOnlyMemory<byte>? serverData,
        CancellationToken cancellationToken = default) =>
        ValueTask.CompletedTask;

    /// <summary>
    /// Performs non-throwing local cleanup without sending wire-level cancellation.
    /// </summary>
    /// <remarks>
    /// The authenticator must clear mutable response or secret buffers it retained before returning.
    /// </remarks>
    void Abort()
    {
    }
}
