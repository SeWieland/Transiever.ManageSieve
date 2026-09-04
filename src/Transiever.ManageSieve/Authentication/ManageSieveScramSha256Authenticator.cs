using System.Security.Cryptography;
using System.Text;
using Transiever.ManageSieve.Authentication;

namespace Transiever.ManageSieve;

/// <summary>SCRAM-SHA-256 SASL authenticator.</summary>
public sealed class ManageSieveScramSha256Authenticator : IManageSieveAuthenticator
{
    private readonly ScramSha256Exchange exchange;

    public ManageSieveScramSha256Authenticator(
        string userName, string password, string? authorizationIdentity = null)
        : this(userName, password, authorizationIdentity, CreateNonce)
    {
    }

    internal ManageSieveScramSha256Authenticator(
        string userName,
        string password,
        string? authorizationIdentity,
        Func<string> nonceFactory)
    {
        ArgumentNullException.ThrowIfNull(nonceFactory);
        ValidateAsciiInput(userName, nameof(userName), allowEmpty: false);
        ValidateAsciiInput(password, nameof(password), allowEmpty: true);
        if (authorizationIdentity is not null)
        {
            ValidateAsciiInput(authorizationIdentity, nameof(authorizationIdentity), allowEmpty: true);
        }
        string nonce = nonceFactory();
        ValidateNonce(nonce);
        exchange = new ScramSha256Exchange(userName, password, authorizationIdentity, nonce);
    }

    public string Mechanism => "SCRAM-SHA-256";

    public bool AllowsUnprotectedConnection => false;

    public ValueTask<ReadOnlyMemory<byte>?> GetInitialResponseAsync(
        CancellationToken cancellationToken = default) =>
        exchange.GetInitialResponseAsync(cancellationToken);

    public ValueTask<ReadOnlyMemory<byte>> RespondAsync(
        ReadOnlyMemory<byte> challenge,
        CancellationToken cancellationToken = default) =>
        exchange.RespondAsync(challenge, cancellationToken);

    public ValueTask CompleteAsync(
        ReadOnlyMemory<byte>? serverData,
        CancellationToken cancellationToken = default) =>
        exchange.CompleteAsync(serverData, cancellationToken);

    public void Abort() => exchange.Abort();

    private static string CreateNonce() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(18));

    private static void ValidateAsciiInput(string value, string parameterName, bool allowEmpty)
    {
        ArgumentNullException.ThrowIfNull(value, parameterName);
        if ((!allowEmpty && value.Length == 0) || value.Length > 1024 ||
            value.Any(character => character is < '\x20' or > '\x7e'))
        {
            throw new ArgumentException(
                "Value must contain printable ASCII characters and be at most 1024 bytes.",
                parameterName);
        }
    }

    private static void ValidateNonce(string nonce)
    {
        ArgumentNullException.ThrowIfNull(nonce);
        if (nonce.Length is 0 or > 256 || nonce.Any(
                character => !ScramSha256Exchange.IsPrintableNonceCharacter(character)))
        {
            throw new ArgumentException("Nonce must contain printable SCRAM characters and be at most 256 bytes.", nameof(nonce));
        }
    }

}
