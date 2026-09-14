using Transiever.SaslClient;

namespace Transiever.ManageSieve;

/// <summary>SCRAM-SHA-256 channel-bound SASL authenticator.</summary>
public sealed class ManageSieveScramSha256PlusAuthenticator :
    IManageSieveAuthenticator,
    IManageSieveChannelBindingAuthenticator
{
    private readonly ManageSieveSaslMechanismAdapter _adapter;

    public ManageSieveScramSha256PlusAuthenticator(
        string userName, string password, string? authorizationIdentity = null)
        : this(new SaslScramSha256PlusAuthenticator(
            userName, password, authorizationIdentity))
    {
    }

    internal ManageSieveScramSha256PlusAuthenticator(
        SaslScramSha256PlusAuthenticator mechanism)
    {
        _adapter = new ManageSieveSaslMechanismAdapter(
            mechanism,
            preserveFailureMessage: true);
    }

    public string Mechanism => _adapter.Mechanism;

    public bool AllowsUnprotectedConnection => _adapter.AllowsUnprotectedConnection;

    string IManageSieveChannelBindingAuthenticator.ChannelBindingName =>
        ((IManageSieveChannelBindingAuthenticator)_adapter).ChannelBindingName;

    void IManageSieveChannelBindingAuthenticator.SetChannelBinding(
        ReadOnlyMemory<byte> binding) =>
        ((IManageSieveChannelBindingAuthenticator)_adapter).SetChannelBinding(binding);

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
