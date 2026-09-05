using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Transiever.ManageSieve;

namespace Transiever.ManageSieve.Authentication;

internal sealed class ScramSha256Exchange
{
    private const int MaximumMessageLength = 16_384;
    private const int MaximumSaltLength = 1_024;
    private const int MinimumIterations = 4_096;
    private const int MaximumIterations = 1_000_000;
    private const string AuthenticationFailure = "SCRAM-SHA-256 authentication failed.";
    private static readonly UTF8Encoding _strictUtf8 = new(false, true);

    private readonly string _clientFirstBare;
    private readonly string _clientNonce;
    private readonly string _encodedGs2Header;
    private readonly string _initialMessage;
    private readonly string _password;
    private byte[]? _expectedServerSignature;
    private byte[]? _response;
    private byte[]? _salt;
    private bool _aborted;
    private bool _completed;
    private bool _initialSent;
    private bool _serverFinalValidated;
    private bool _serverFirstReceived;

    internal ScramSha256Exchange(
        string userName, string password, string? authorizationIdentity, string nonce)
    {
        string user = EscapeIdentity(userName);
        string gs2Header = string.IsNullOrEmpty(authorizationIdentity)
            ? "n,,"
            : $"n,a={EscapeIdentity(authorizationIdentity)},";
        _clientFirstBare = $"n={user},r={nonce}";
        _clientNonce = nonce;
        _encodedGs2Header = Convert.ToBase64String(Encoding.UTF8.GetBytes(gs2Header));
        _initialMessage = $"{gs2Header}{_clientFirstBare}";
        _password = password;
    }

    internal ReadOnlyMemory<byte> Salt => _salt;

    internal ReadOnlyMemory<byte> ExpectedServerSignature => _expectedServerSignature;

    internal ValueTask<ReadOnlyMemory<byte>?> GetInitialResponseAsync(
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (_initialSent || _aborted || _completed)
        {
            Abort();
            throw CreateAuthenticationFailure();
        }

        ClearResponse();
        _response = Encoding.UTF8.GetBytes(_initialMessage);
        _initialSent = true;
        return ValueTask.FromResult<ReadOnlyMemory<byte>?>(_response);
    }

    internal ValueTask<ReadOnlyMemory<byte>> RespondAsync(
        ReadOnlyMemory<byte> challenge,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!_initialSent || _serverFinalValidated || _aborted || _completed)
        {
            Abort();
            throw CreateAuthenticationFailure();
        }

        if (_serverFirstReceived)
        {
            try
            {
                ValidateServerFinal(challenge.Span);
                _serverFinalValidated = true;
                ClearRetainedData();
                _response = [];
                return ValueTask.FromResult<ReadOnlyMemory<byte>>(_response);
            }
            catch
            {
                _aborted = true;
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
                challenge.Span, _clientNonce, out string serverNonce,
                out byte[] parsedSalt, out int parsedIterations);
            decodedSalt = parsedSalt;
            string finalWithoutProof = $"c={_encodedGs2Header},r={serverNonce}";
            string completeAuthMessage = $"{_clientFirstBare},{serverFirst},{finalWithoutProof}";
            finalResponse = CreateClientFinal(
                _password, parsedSalt, parsedIterations, completeAuthMessage,
                finalWithoutProof, out byte[] derivedServerSignature);
            serverSignature = derivedServerSignature;

            ClearResponse();
            ClearExpectedServerSignature();
            _response = finalResponse;
            _salt = parsedSalt;
            _expectedServerSignature = derivedServerSignature;
            _serverFirstReceived = true;

            byte[] transferredResponse = finalResponse;
            decodedSalt = null;
            finalResponse = null;
            serverSignature = null;
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(transferredResponse);
        }
        catch (CryptographicException)
        {
            _aborted = true;
            ClearRetainedData();
            throw CreateAuthenticationFailure();
        }
        catch
        {
            _aborted = true;
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
            if (!_serverFirstReceived || _aborted || _completed ||
                (_serverFinalValidated ? serverData is not null : serverData is null))
            {
                throw CreateAuthenticationFailure();
            }

            if (!_serverFinalValidated)
            {
                ValidateServerFinal(serverData!.Value.Span);
                _serverFinalValidated = true;
            }

            _completed = true;
            return ValueTask.CompletedTask;
        }
        catch (ManageSieveAuthenticationException)
        {
            _aborted = true;
            throw;
        }
        finally
        {
            ClearRetainedData();
        }
    }

    internal void Abort()
    {
        _aborted = true;
        ClearRetainedData();
    }

    internal void ClearRetainedData()
    {
        ClearResponse();
        ClearExpectedServerSignature();
        byte[]? saltToClear = Interlocked.Exchange(ref _salt, null);
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
            if (signature.Length != 32 || _expectedServerSignature is null ||
                !CryptographicOperations.FixedTimeEquals(signature, _expectedServerSignature))
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
            message = _strictUtf8.GetString(data);
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
        if (value.Length is 0 or > 1_368 ||
            !Base64.IsValid(value.AsSpan(), out int decodedLength) ||
            value.Length != ((decodedLength + 2) / 3) * 4 ||
            decodedLength is 0 or > MaximumSaltLength)
        {
            throw CreateAuthenticationFailure();
        }

        return Convert.FromBase64String(value);
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
        byte[]? toClear = Interlocked.Exchange(ref _response, null);
        if (toClear is not null)
        {
            CryptographicOperations.ZeroMemory(toClear);
        }
    }

    private void ClearExpectedServerSignature()
    {
        byte[]? toClear = Interlocked.Exchange(ref _expectedServerSignature, null);
        if (toClear is not null)
        {
            CryptographicOperations.ZeroMemory(toClear);
        }
    }

    private static string EscapeIdentity(string value) =>
        value.Replace("=", "=3D", StringComparison.Ordinal)
            .Replace(",", "=2C", StringComparison.Ordinal);
}
