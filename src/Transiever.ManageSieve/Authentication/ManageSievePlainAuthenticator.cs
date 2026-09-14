using Transiever.SaslClient;

namespace Transiever.ManageSieve;

/// <summary>SASL PLAIN authenticator for ManageSieve.</summary>
public sealed class ManageSievePlainAuthenticator(
    string userName,
    string password,
    string? authorizationIdentity = null)
    : IManageSieveAuthenticator
{
    private readonly ManageSieveSaslMechanismAdapter _adapter = new(
        new SaslPlainAuthenticator(userName, password, authorizationIdentity),
        preserveFailureMessage: true);

    public string Mechanism => _adapter.Mechanism;

    public ValueTask<ReadOnlyMemory<byte>?> GetInitialResponseAsync(
        CancellationToken cancellationToken = default) =>
        _adapter.GetInitialResponseAsync(cancellationToken);

    public ValueTask<ReadOnlyMemory<byte>> RespondAsync(
        ReadOnlyMemory<byte> challenge,
        CancellationToken cancellationToken = default) =>
        _adapter.RespondAsync(challenge, cancellationToken);

    public ValueTask CompleteAsync(
        ReadOnlyMemory<byte>? serverData,
        CancellationToken cancellationToken = default) =>
        _adapter.CompleteAsync(serverData, cancellationToken);

    public void Abort() => _adapter.Abort();
}
