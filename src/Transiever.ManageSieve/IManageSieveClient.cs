namespace Transiever.ManageSieve;

/// <summary>
/// Represents an active ManageSieve session.
/// </summary>
public interface IManageSieveClient : IAsyncDisposable
{
    /// <summary>
    /// Gets the connection settings used for this client.
    /// </summary>
    ManageSieveClientOptions Options { get; }

    /// <summary>
    /// Gets the current session state.
    /// </summary>
    ManageSieveSessionState State { get; }

    /// <summary>
    /// Gets the latest capabilities advertised by the server, if known.
    /// </summary>
    ManageSieveCapabilities? Capabilities { get; }

    /// <summary>
    /// Opens a TCP connection and reads the server greeting.
    /// </summary>
    ValueTask ConnectAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Issues CAPABILITY and updates the cached server capabilities.
    /// </summary>
    ValueTask<ManageSieveCapabilities> RefreshCapabilitiesAsync(
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Starts TLS on an already connected session when the server and settings allow it.
    /// </summary>
    ValueTask StartTlsAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Authenticates the session with the supplied SASL mechanism.
    /// </summary>
    ValueTask AuthenticateAsync(
        IManageSieveAuthenticator authenticator,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Ends the authenticated state without closing the underlying transport.
    /// </summary>
    ValueTask UnauthenticateAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks whether the server has enough space for a script upload.
    /// </summary>
    ValueTask<ManageSieveSpaceAvailability> HaveSpaceAsync(
        string scriptName,
        long contentOctetCount,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Lists the scripts stored on the server.
    /// </summary>
    ValueTask<IReadOnlyList<ManageSieveScriptInfo>> ListScriptsAsync(
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the content of a single script.
    /// </summary>
    ValueTask<ManageSieveScript> GetScriptAsync(
        string scriptName,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates script content without storing it.
    /// </summary>
    ValueTask<ManageSieveCommandResult> CheckScriptAsync(
        ReadOnlyMemory<byte> content,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Stores a script on the server.
    /// </summary>
    ValueTask<ManageSieveCommandResult> PutScriptAsync(
        string scriptName,
        ReadOnlyMemory<byte> content,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Marks the specified script active, or clears the active script when null.
    /// </summary>
    ValueTask<ManageSieveCommandResult> SetActiveScriptAsync(
        string? scriptName,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Renames an existing script.
    /// </summary>
    ValueTask<ManageSieveCommandResult> RenameScriptAsync(
        string currentName,
        string newName,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes a script from the server.
    /// </summary>
    ValueTask<ManageSieveCommandResult> DeleteScriptAsync(
        string scriptName,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Sends a NOOP command to keep the session alive or probe server health.
    /// </summary>
    ValueTask<ManageSieveCommandResult> NoOpAsync(
        string? tag = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Logs out and closes the session.
    /// </summary>
    ValueTask LogoutAsync(CancellationToken cancellationToken = default);
}
