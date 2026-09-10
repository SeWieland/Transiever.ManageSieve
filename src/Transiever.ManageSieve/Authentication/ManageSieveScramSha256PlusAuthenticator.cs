namespace Transiever.ManageSieve;

using Transiever.ManageSieve.Authentication;

internal interface IManageSieveChannelBindingAuthenticator
{
    string ChannelBindingName { get; }

    void SetChannelBinding(ReadOnlyMemory<byte> binding);
}

/// <summary>SCRAM-SHA-256 channel-bound SASL authenticator.</summary>
public sealed class ManageSieveScramSha256PlusAuthenticator :
    IManageSieveAuthenticator,
    IManageSieveChannelBindingAuthenticator
{
    private const string ChannelBindingNameValue = "tls-server-end-point";
    private const string UnsupportedBindingMessage =
        "SCRAM-SHA-256-PLUS requires a supported TLS 1.2 channel binding.";

    private readonly string _userName;
    private readonly string _password;
    private readonly string? _authorizationIdentity;
    private readonly string _nonce;
    private ScramSha256Exchange? _exchange;
    private byte[]? _channelBinding;
    private bool _finished;

    public ManageSieveScramSha256PlusAuthenticator(
        string userName, string password, string? authorizationIdentity = null)
        : this(userName, password, authorizationIdentity, CreateNonce)
    {
    }

    internal ManageSieveScramSha256PlusAuthenticator(
        string userName,
        string password,
        string? authorizationIdentity,
        Func<string> nonceFactory)
    {
        ArgumentNullException.ThrowIfNull(nonceFactory);
        ManageSieveScramSha256Authenticator.ValidateAsciiInput(
            userName, nameof(userName), allowEmpty: false);
        ManageSieveScramSha256Authenticator.ValidateAsciiInput(
            password, nameof(password), allowEmpty: true);
        if (authorizationIdentity is not null)
        {
            ManageSieveScramSha256Authenticator.ValidateAsciiInput(
                authorizationIdentity, nameof(authorizationIdentity), allowEmpty: true);
        }

        string nonce = nonceFactory();
        ManageSieveScramSha256Authenticator.ValidateNonce(nonce);
        _userName = userName;
        _password = password;
        _authorizationIdentity = authorizationIdentity;
        _nonce = nonce;
    }

    public string Mechanism => "SCRAM-SHA-256-PLUS";

    public bool AllowsUnprotectedConnection => false;

    string IManageSieveChannelBindingAuthenticator.ChannelBindingName =>
        ChannelBindingNameValue;

    void IManageSieveChannelBindingAuthenticator.SetChannelBinding(
        ReadOnlyMemory<byte> binding)
    {
        if (binding.IsEmpty)
        {
            if (_channelBinding is not null || _exchange is not null)
            {
                ClearState();
            }

            throw CreateUnsupportedBindingException();
        }

        if (_finished)
        {
            throw CreateAuthenticationFailure();
        }

        if (_channelBinding is not null)
        {
            ClearState();
            throw CreateUnsupportedBindingException();
        }

        _channelBinding = binding.ToArray();
    }

    public async ValueTask<ReadOnlyMemory<byte>?> GetInitialResponseAsync(
        CancellationToken cancellationToken = default)
    {
        try
        {
            ScramSha256Exchange exchange = GetExchange();
            return await exchange.GetInitialResponseAsync(cancellationToken)
                .ConfigureAwait(false);
        }
        catch
        {
            ClearState();
            throw;
        }
    }

    public async ValueTask<ReadOnlyMemory<byte>> RespondAsync(
        ReadOnlyMemory<byte> challenge,
        CancellationToken cancellationToken = default)
    {
        try
        {
            ScramSha256Exchange exchange = GetExchange();
            return await exchange.RespondAsync(challenge, cancellationToken)
                .ConfigureAwait(false);
        }
        catch
        {
            ClearState();
            throw;
        }
    }

    public async ValueTask CompleteAsync(
        ReadOnlyMemory<byte>? serverData,
        CancellationToken cancellationToken = default)
    {
        try
        {
            ScramSha256Exchange exchange = GetExchange();
            await exchange.CompleteAsync(serverData, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            ClearState();
        }
    }

    public void Abort() => ClearState();

    private ScramSha256Exchange GetExchange()
    {
        if (_finished)
        {
            throw CreateAuthenticationFailure();
        }

        if (_channelBinding is null)
        {
            throw CreateUnsupportedBindingException();
        }

        return _exchange ??= new ScramSha256Exchange(
            _userName,
            _password,
            _authorizationIdentity,
            _nonce,
            ChannelBindingNameValue,
            _channelBinding);
    }

    private void ClearState()
    {
        _finished = true;
        _exchange?.Abort();
        _exchange = null;
        byte[]? binding = Interlocked.Exchange(ref _channelBinding, null);
        if (binding is not null)
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(binding);
        }
    }

    private static string CreateNonce() =>
        Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(18));

    private static ManageSieveAuthenticationException CreateUnsupportedBindingException() =>
        new(UnsupportedBindingMessage);

    private static ManageSieveAuthenticationException CreateAuthenticationFailure() =>
        new("SCRAM-SHA-256 authentication failed.");
}
