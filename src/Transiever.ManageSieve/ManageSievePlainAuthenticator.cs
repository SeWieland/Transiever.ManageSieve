using System.Security.Cryptography;
using System.Text;

namespace Transiever.ManageSieve;

/// <summary>
/// SASL PLAIN authenticator for ManageSieve.
/// </summary>
public sealed class ManageSievePlainAuthenticator(
    string userName,
    string password,
    string? authorizationIdentity = null)
    : IManageSieveAuthenticator
{
    public string Mechanism => "PLAIN";

    public ValueTask<ReadOnlyMemory<byte>?> GetInitialResponseAsync(
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        byte[] authenticationIdentity = Encoding.UTF8.GetBytes(userName);
        byte[] secret = Encoding.UTF8.GetBytes(password);
        byte[] authorization = Encoding.UTF8.GetBytes(authorizationIdentity ?? string.Empty);
        byte[] response = new byte[
            authorization.Length + authenticationIdentity.Length + secret.Length + 2];

        try
        {
            authorization.CopyTo(response, 0);
            authenticationIdentity.CopyTo(response, authorization.Length + 1);
            secret.CopyTo(response, authorization.Length + authenticationIdentity.Length + 2);
            return ValueTask.FromResult<ReadOnlyMemory<byte>?>(response);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(authenticationIdentity);
            CryptographicOperations.ZeroMemory(secret);
            CryptographicOperations.ZeroMemory(authorization);
        }
    }

    public ValueTask<ReadOnlyMemory<byte>> RespondAsync(
        ReadOnlyMemory<byte> challenge,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        throw new ManageSieveAuthenticationException(
            "SASL PLAIN does not support additional server challenges.");
    }
}
