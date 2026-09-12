using System.Security.Cryptography;
using System.Text;

namespace Transiever.ManageSieve;

/// <summary>
/// SASL EXTERNAL authenticator for a verified TLS client identity.
/// </summary>
public sealed class ManageSieveExternalAuthenticator : IManageSieveAuthenticator
{
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private readonly string _authorizationIdentity;
    private byte[]? _response;
    private ExternalState _state;

    public ManageSieveExternalAuthenticator(string? authorizationIdentity = null)
    {
        _authorizationIdentity = ValidateIdentity(authorizationIdentity);
    }

    public string Mechanism => "EXTERNAL";

    public bool RequiresClientCertificate => true;

    public ValueTask<ReadOnlyMemory<byte>?> GetInitialResponseAsync(
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        EnsureActive(ExternalState.Ready);
        _response = Utf8.GetBytes(_authorizationIdentity);
        _state = ExternalState.AwaitingCompletion;
        return ValueTask.FromResult<ReadOnlyMemory<byte>?>(_response);
    }

    public ValueTask<ReadOnlyMemory<byte>> RespondAsync(
        ReadOnlyMemory<byte> challenge,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        EnsureActive(ExternalState.AwaitingCompletion);
        return ValueTask.FromException<ReadOnlyMemory<byte>>(
            new ManageSieveAuthenticationException(
                "SASL EXTERNAL does not support server challenges."));
    }

    public ValueTask CompleteAsync(
        ReadOnlyMemory<byte>? serverData,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        EnsureActive(ExternalState.AwaitingCompletion);
        if (serverData is not null)
        {
            return ValueTask.FromException(
                new ManageSieveAuthenticationException(
                    "SASL EXTERNAL does not accept server completion data."));
        }

        ClearResponse();
        _state = ExternalState.Completed;
        return ValueTask.CompletedTask;
    }

    public void Abort()
    {
        ClearResponse();
        _state = ExternalState.Aborted;
    }

    private static string ValidateIdentity(string? authorizationIdentity)
    {
        string identity = authorizationIdentity ?? string.Empty;
        if (identity.Contains('\0'))
        {
            throw new ArgumentException(
                "The EXTERNAL authorization identity cannot contain NUL.",
                nameof(authorizationIdentity));
        }

        int encodedLength;
        try
        {
            encodedLength = Utf8.GetByteCount(identity);
        }
        catch (EncoderFallbackException)
        {
            throw new ArgumentException(
                "The EXTERNAL authorization identity must be valid Unicode.",
                nameof(authorizationIdentity));
        }

        if (encodedLength > 1024)
        {
            throw new ArgumentException(
                "The EXTERNAL authorization identity exceeds 1024 UTF-8 octets.",
                nameof(authorizationIdentity));
        }

        return identity;
    }

    private void EnsureActive(ExternalState expected)
    {
        if (_state != expected)
        {
            throw new ManageSieveAuthenticationException(
                "SASL EXTERNAL exchange is not active.");
        }
    }

    private void ClearResponse()
    {
        byte[]? response = Interlocked.Exchange(ref _response, null);
        if (response is not null)
        {
            CryptographicOperations.ZeroMemory(response);
        }
    }

    private enum ExternalState
    {
        Ready,
        AwaitingCompletion,
        Completed,
        Aborted
    }
}
