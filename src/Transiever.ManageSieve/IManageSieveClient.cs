namespace Transiever.ManageSieve;

public interface IManageSieveClient : IAsyncDisposable
{
    ManageSieveClientOptions Options { get; }

    ManageSieveSessionState State { get; }

    ManageSieveCapabilities? Capabilities { get; }

    ValueTask ConnectAsync(CancellationToken cancellationToken = default);

    ValueTask<ManageSieveCapabilities> RefreshCapabilitiesAsync(
        CancellationToken cancellationToken = default);

    ValueTask StartTlsAsync(CancellationToken cancellationToken = default);

    ValueTask AuthenticateAsync(
        IManageSieveAuthenticator authenticator,
        CancellationToken cancellationToken = default);

    ValueTask UnauthenticateAsync(CancellationToken cancellationToken = default);

    ValueTask<ManageSieveSpaceAvailability> HaveSpaceAsync(
        string scriptName,
        long contentOctetCount,
        CancellationToken cancellationToken = default);

    ValueTask<IReadOnlyList<ManageSieveScriptInfo>> ListScriptsAsync(
        CancellationToken cancellationToken = default);

    ValueTask<ManageSieveScript> GetScriptAsync(
        string scriptName,
        CancellationToken cancellationToken = default);

    ValueTask<ManageSieveCommandResult> CheckScriptAsync(
        ReadOnlyMemory<byte> content,
        CancellationToken cancellationToken = default);

    ValueTask<ManageSieveCommandResult> PutScriptAsync(
        string scriptName,
        ReadOnlyMemory<byte> content,
        CancellationToken cancellationToken = default);

    ValueTask<ManageSieveCommandResult> SetActiveScriptAsync(
        string? scriptName,
        CancellationToken cancellationToken = default);

    ValueTask<ManageSieveCommandResult> RenameScriptAsync(
        string currentName,
        string newName,
        CancellationToken cancellationToken = default);

    ValueTask<ManageSieveCommandResult> DeleteScriptAsync(
        string scriptName,
        CancellationToken cancellationToken = default);

    ValueTask<ManageSieveCommandResult> NoOpAsync(
        string? tag = null,
        CancellationToken cancellationToken = default);

    ValueTask LogoutAsync(CancellationToken cancellationToken = default);
}
