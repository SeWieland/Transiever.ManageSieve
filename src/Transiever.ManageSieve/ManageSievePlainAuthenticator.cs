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
    private byte[]? response;

    public string Mechanism => "PLAIN";

    public ValueTask<ReadOnlyMemory<byte>?> GetInitialResponseAsync(
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ClearResponse();
        byte[] authenticationIdentity = Encoding.UTF8.GetBytes(userName);
        byte[] secret = Encoding.UTF8.GetBytes(password);
        byte[] authorization = Encoding.UTF8.GetBytes(authorizationIdentity ?? string.Empty);
        byte[] credentialResponse = new byte[
            authorization.Length + authenticationIdentity.Length + secret.Length + 2];

        try
        {
            authorization.CopyTo(credentialResponse, 0);
            authenticationIdentity.CopyTo(credentialResponse, authorization.Length + 1);
            secret.CopyTo(
                credentialResponse,
                authorization.Length + authenticationIdentity.Length + 2);
            response = credentialResponse;
            return ValueTask.FromResult<ReadOnlyMemory<byte>?>(credentialResponse);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(credentialResponse);
            throw;
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

    public ValueTask CompleteAsync(
        ReadOnlyMemory<byte>? serverData,
        CancellationToken cancellationToken = default)
    {
        ClearResponse();
        return ValueTask.CompletedTask;
    }

    public void Abort() => ClearResponse();

    private void ClearResponse()
    {
        byte[]? responseToClear = Interlocked.Exchange(ref response, null);
        if (responseToClear is not null)
        {
            CryptographicOperations.ZeroMemory(responseToClear);
        }
    }
}
