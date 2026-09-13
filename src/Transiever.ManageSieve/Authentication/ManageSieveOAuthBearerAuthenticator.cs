using Transiever.SaslClient;

namespace Transiever.ManageSieve;

public sealed record ManageSieveOAuthBearerError(
    string Status, string? Scope, string? OpenIdConfiguration);

public sealed class ManageSieveOAuthBearerAuthenticator : IManageSieveAuthenticator
{
    private readonly SaslOAuthBearerAuthenticator _mechanism;
    private readonly ManageSieveSaslMechanismAdapter _adapter;

    public ManageSieveOAuthBearerAuthenticator(
        string accessToken,
        string host,
        int port,
        string? authorizationIdentity = null)
    {
        _mechanism = new SaslOAuthBearerAuthenticator(
            accessToken, host, port, authorizationIdentity);
        _adapter = new ManageSieveSaslMechanismAdapter(
            _mechanism, preserveFailureMessage: true);
    }

    public string Mechanism => _adapter.Mechanism;

    public bool AllowsUnprotectedConnection => _adapter.AllowsUnprotectedConnection;

    public ManageSieveOAuthBearerError? ServerError { get; private set; }

    public ValueTask<ReadOnlyMemory<byte>?> GetInitialResponseAsync(
        CancellationToken cancellationToken = default) =>
        _adapter.GetInitialResponseAsync(cancellationToken);

    public async ValueTask<ReadOnlyMemory<byte>> RespondAsync(
        ReadOnlyMemory<byte> challenge,
        CancellationToken cancellationToken = default)
    {
        ReadOnlyMemory<byte> response = await _adapter
            .RespondAsync(challenge, cancellationToken)
            .ConfigureAwait(false);
        if (_mechanism.ServerError is { } error)
        {
            ServerError = new ManageSieveOAuthBearerError(
                error.Status, error.Scope, error.OpenIdConfiguration);
        }

        return response;
    }

    public ValueTask CompleteAsync(
        ReadOnlyMemory<byte>? serverData,
        CancellationToken cancellationToken = default) =>
        _adapter.CompleteAsync(serverData, cancellationToken);

    public void Abort() => _adapter.Abort();
}
