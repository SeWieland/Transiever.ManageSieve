using Transiever.SaslClient;

namespace Transiever.ManageSieve;

/// <summary>SCRAM-SHA-256 SASL authenticator.</summary>
public sealed class ManageSieveScramSha256Authenticator : IManageSieveAuthenticator
{
    private readonly ManageSieveSaslMechanismAdapter _adapter;

    public ManageSieveScramSha256Authenticator(
        string userName, string password, string? authorizationIdentity = null)
        : this(new SaslScramSha256Authenticator(
            userName, password, authorizationIdentity))
    {
    }

    internal ManageSieveScramSha256Authenticator(
        SaslScramSha256Authenticator mechanism)
    {
        _adapter = new ManageSieveSaslMechanismAdapter(
            mechanism,
            preserveFailureMessage: true);
    }

    public string Mechanism => _adapter.Mechanism;

    public bool AllowsUnprotectedConnection => _adapter.AllowsUnprotectedConnection;

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
