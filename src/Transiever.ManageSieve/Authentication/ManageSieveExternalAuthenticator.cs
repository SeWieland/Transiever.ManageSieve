using Transiever.SaslClient;

namespace Transiever.ManageSieve;

/// <summary>SASL EXTERNAL authenticator for a verified TLS client identity.</summary>
public sealed class ManageSieveExternalAuthenticator : IManageSieveAuthenticator
{
    private readonly ManageSieveSaslMechanismAdapter _adapter;

    public ManageSieveExternalAuthenticator(string? authorizationIdentity = null)
    {
        _adapter = new ManageSieveSaslMechanismAdapter(
            new SaslExternalAuthenticator(authorizationIdentity),
            preserveFailureMessage: true);
    }

    public string Mechanism => _adapter.Mechanism;

    public bool RequiresClientCertificate => _adapter.RequiresClientCertificate;

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
