using System.Security.Cryptography;
using System.Text;

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

internal sealed class ScramSha256Exchange
{
    private const int MaximumMessageLength = 16_384;
    private const int MaximumSaltLength = 1_024;
    private const int MinimumIterations = 4_096;
    private const int MaximumIterations = 1_000_000;
    private const string AuthenticationFailure = "SCRAM-SHA-256 authentication failed.";
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    private readonly string clientFirstBare;
    private readonly string clientNonce;
    private readonly string encodedGs2Header;
    private readonly string initialMessage;
    private readonly string password;
    private byte[]? expectedServerSignature;
    private byte[]? response;
    private byte[]? salt;
    private bool aborted;
    private bool completed;
    private bool initialSent;
    private bool serverFinalValidated;
    private bool serverFirstReceived;

    internal ScramSha256Exchange(
        string userName, string password, string? authorizationIdentity, string nonce)
    {
        string user = EscapeIdentity(userName);
        string gs2Header = string.IsNullOrEmpty(authorizationIdentity)
            ? "n,,"
            : $"n,a={EscapeIdentity(authorizationIdentity)},";
        clientFirstBare = $"n={user},r={nonce}";
        clientNonce = nonce;
        encodedGs2Header = Convert.ToBase64String(Encoding.UTF8.GetBytes(gs2Header));
        initialMessage = $"{gs2Header}{clientFirstBare}";
        this.password = password;
    }

    internal ReadOnlyMemory<byte> Salt => salt;

    internal ReadOnlyMemory<byte> ExpectedServerSignature => expectedServerSignature;

    internal ValueTask<ReadOnlyMemory<byte>?> GetInitialResponseAsync(
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (initialSent || aborted || completed)
        {
            Abort();
            throw CreateAuthenticationFailure();
        }

        ClearResponse();
        response = Encoding.UTF8.GetBytes(initialMessage);
        initialSent = true;
        return ValueTask.FromResult<ReadOnlyMemory<byte>?>(response);
    }

    internal ValueTask<ReadOnlyMemory<byte>> RespondAsync(
        ReadOnlyMemory<byte> challenge,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!initialSent || serverFinalValidated || aborted || completed)
        {
            Abort();
            throw CreateAuthenticationFailure();
        }

        if (serverFirstReceived)
        {
            try
            {
                ValidateServerFinal(challenge.Span);
                serverFinalValidated = true;
                ClearRetainedData();
                response = [];
                return ValueTask.FromResult<ReadOnlyMemory<byte>>(response);
            }
            catch
            {
                aborted = true;
                ClearRetainedData();
                throw;
            }
        }

        byte[]? decodedSalt = null;
        byte[]? finalResponse = null;
        byte[]? serverSignature = null;
        try
        {
            string serverFirst = ParseServerFirst(
                challenge.Span, clientNonce, out string serverNonce,
                out byte[] parsedSalt, out int parsedIterations);
            decodedSalt = parsedSalt;
            string finalWithoutProof = $"c={encodedGs2Header},r={serverNonce}";
            string completeAuthMessage = $"{clientFirstBare},{serverFirst},{finalWithoutProof}";
            finalResponse = CreateClientFinal(
                password, parsedSalt, parsedIterations, completeAuthMessage,
                finalWithoutProof, out byte[] derivedServerSignature);
            serverSignature = derivedServerSignature;

            ClearResponse();
            ClearExpectedServerSignature();
            response = finalResponse;
            salt = parsedSalt;
            expectedServerSignature = derivedServerSignature;
            serverFirstReceived = true;

            byte[] transferredResponse = finalResponse;
            decodedSalt = null;
            finalResponse = null;
            serverSignature = null;
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(transferredResponse);
        }
        catch (CryptographicException)
        {
            aborted = true;
            ClearRetainedData();
            throw CreateAuthenticationFailure();
        }
        catch
        {
            aborted = true;
            ClearRetainedData();
            throw;
        }
        finally
        {
            ClearBuffer(decodedSalt);
            ClearBuffer(finalResponse);
            ClearBuffer(serverSignature);
        }
    }

    internal ValueTask CompleteAsync(
        ReadOnlyMemory<byte>? serverData,
        CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!serverFirstReceived || aborted || completed ||
                (serverFinalValidated ? serverData is not null : serverData is null))
            {
                throw CreateAuthenticationFailure();
            }

            if (!serverFinalValidated)
            {
                ValidateServerFinal(serverData!.Value.Span);
                serverFinalValidated = true;
            }

            completed = true;
            return ValueTask.CompletedTask;
        }
        catch (ManageSieveAuthenticationException)
        {
            aborted = true;
            throw;
        }
        finally
        {
            ClearRetainedData();
        }
    }

    internal void Abort()
    {
        aborted = true;
        ClearRetainedData();
    }

    internal void ClearRetainedData()
    {
        ClearResponse();
        ClearExpectedServerSignature();
        byte[]? saltToClear = Interlocked.Exchange(ref salt, null);
        if (saltToClear is not null)
        {
            CryptographicOperations.ZeroMemory(saltToClear);
        }
    }

    private void ValidateServerFinal(ReadOnlySpan<byte> data)
    {
        string[] attributes = ParseAttributes(data, out _);
        if (attributes[0][0] != 'v' ||
            attributes.Skip(1).Any(attribute => IsReservedScramAttribute(attribute[0])))
        {
            throw CreateAuthenticationFailure();
        }

        byte[] signature = DecodeCanonicalBase64(attributes[0][2..]);
        try
        {
            if (signature.Length != 32 || expectedServerSignature is null ||
                !CryptographicOperations.FixedTimeEquals(signature, expectedServerSignature))
            {
                throw CreateAuthenticationFailure();
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signature);
        }
    }

    private static byte[] CreateClientFinal(
        string password,
        byte[] salt,
        int iterations,
        string authMessage,
        string finalWithoutProof,
        out byte[] expectedServerSignature)
    {
        byte[] passwordBytes = [];
        byte[] authMessageBytes = [];
        byte[] saltedPassword = [];
        byte[] clientKey = [];
        byte[] storedKey = [];
        byte[] clientSignature = [];
        byte[] clientProof = [];
        byte[] serverKey = [];
        byte[]? serverSignature = null;
        try
        {
            passwordBytes = Encoding.UTF8.GetBytes(password);
            authMessageBytes = Encoding.UTF8.GetBytes(authMessage);
            saltedPassword = Rfc2898DeriveBytes.Pbkdf2(
                passwordBytes, salt, iterations, HashAlgorithmName.SHA256, 32);
            clientKey = HMACSHA256.HashData(saltedPassword, "Client Key"u8);
            storedKey = SHA256.HashData(clientKey);
            clientSignature = HMACSHA256.HashData(storedKey, authMessageBytes);
            clientProof = new byte[clientKey.Length];
            for (int index = 0; index < clientProof.Length; index++)
            {
                clientProof[index] = (byte)(clientKey[index] ^ clientSignature[index]);
            }

            serverKey = HMACSHA256.HashData(saltedPassword, "Server Key"u8);
            serverSignature = HMACSHA256.HashData(serverKey, authMessageBytes);
            byte[] finalResponse = Encoding.UTF8.GetBytes(
                $"{finalWithoutProof},p={Convert.ToBase64String(clientProof)}");
            expectedServerSignature = serverSignature;
            serverSignature = null;
            return finalResponse;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
            CryptographicOperations.ZeroMemory(authMessageBytes);
            CryptographicOperations.ZeroMemory(saltedPassword);
            CryptographicOperations.ZeroMemory(clientKey);
            CryptographicOperations.ZeroMemory(storedKey);
            CryptographicOperations.ZeroMemory(clientSignature);
            CryptographicOperations.ZeroMemory(clientProof);
            CryptographicOperations.ZeroMemory(serverKey);
            if (serverSignature is not null)
            {
                CryptographicOperations.ZeroMemory(serverSignature);
            }
        }
    }

    internal static bool IsPrintableNonceCharacter(char character) =>
        character is >= '\x21' and <= '\x2b' or >= '\x2d' and <= '\x7e';

    private static bool IsReservedScramAttribute(char name) =>
        name is 'a' or 'c' or 'e' or 'i' or 'm' or 'n' or 'p' or 'r' or 's' or 'v';

    private static string ParseServerFirst(
        ReadOnlySpan<byte> data,
        string expectedNoncePrefix,
        out string nonce,
        out byte[] salt,
        out int iterations)
    {
        string[] attributes = ParseAttributes(data, out string message);
        if (attributes.Length < 3 || attributes[0][0] != 'r' ||
            attributes[1][0] != 's' || attributes[2][0] != 'i' ||
            attributes.Skip(3).Any(attribute => IsReservedScramAttribute(attribute[0])))
        {
            throw CreateAuthenticationFailure();
        }

        nonce = attributes[0][2..];
        if (nonce.Length > 256 || nonce.Length <= expectedNoncePrefix.Length ||
            !nonce.StartsWith(expectedNoncePrefix, StringComparison.Ordinal) ||
            nonce.Any(character => !IsPrintableNonceCharacter(character)))
        {
            throw CreateAuthenticationFailure();
        }

        string iterationText = attributes[2][2..];
        if (iterationText[0] is < '1' or > '9' ||
            !iterationText.All(character => character is >= '0' and <= '9') ||
            !int.TryParse(
                iterationText,
                System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture,
                out iterations) ||
            iterations is < MinimumIterations or > MaximumIterations)
        {
            throw CreateAuthenticationFailure();
        }

        salt = DecodeCanonicalBase64(attributes[1][2..]);
        return message;
    }

    private static string[] ParseAttributes(ReadOnlySpan<byte> data, out string message)
    {
        if (data.Length is 0 or > MaximumMessageLength)
        {
            throw CreateAuthenticationFailure();
        }

        try
        {
            message = StrictUtf8.GetString(data);
        }
        catch (DecoderFallbackException)
        {
            throw CreateAuthenticationFailure();
        }

        string[] attributes = message.Split(',');
        HashSet<char> names = [];
        foreach (string attribute in attributes)
        {
            if (attribute.Length < 3 || attribute[1] != '=' ||
                attribute[0] is not (>= 'A' and <= 'Z' or >= 'a' and <= 'z') ||
                attribute.AsSpan(2).Contains('\0') ||
                !names.Add(attribute[0]) || attribute[0] == 'm')
            {
                throw CreateAuthenticationFailure();
            }
        }

        return attributes;
    }

    private static byte[] DecodeCanonicalBase64(string value)
    {
        if (value.Length is 0 or > 1_368 || value.Length % 4 != 0)
        {
            throw CreateAuthenticationFailure();
        }

        int padding = value.EndsWith("==", StringComparison.Ordinal)
            ? 2
            : value.EndsWith('=') ? 1 : 0;
        int decodedLength = value.Length / 4 * 3 - padding;
        if (decodedLength is 0 or > MaximumSaltLength ||
            value.AsSpan(0, value.Length - padding).ContainsAnyExcept(
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"))
        {
            throw CreateAuthenticationFailure();
        }

        for (int index = value.Length - padding; index < value.Length; index++)
        {
            if (value[index] != '=')
            {
                throw CreateAuthenticationFailure();
            }
        }

        byte[] decoded = new byte[decodedLength];
        if (!Convert.TryFromBase64String(value, decoded, out int written) ||
            written != decodedLength ||
            !string.Equals(Convert.ToBase64String(decoded), value, StringComparison.Ordinal))
        {
            CryptographicOperations.ZeroMemory(decoded);
            throw CreateAuthenticationFailure();
        }

        return decoded;
    }

    private static ManageSieveAuthenticationException CreateAuthenticationFailure() =>
        new(AuthenticationFailure);

    private static void ClearBuffer(byte[]? buffer)
    {
        if (buffer is not null)
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    private void ClearResponse()
    {
        byte[]? toClear = Interlocked.Exchange(ref response, null);
        if (toClear is not null)
        {
            CryptographicOperations.ZeroMemory(toClear);
        }
    }

    private void ClearExpectedServerSignature()
    {
        byte[]? toClear = Interlocked.Exchange(ref expectedServerSignature, null);
        if (toClear is not null)
        {
            CryptographicOperations.ZeroMemory(toClear);
        }
    }

    private static string EscapeIdentity(string value) =>
        value.Replace("=", "=3D", StringComparison.Ordinal)
            .Replace(",", "=2C", StringComparison.Ordinal);
}
