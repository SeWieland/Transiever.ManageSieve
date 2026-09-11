using System.Globalization;
using System.Text.Json;
using System.Security.Cryptography;
using System.Text;

namespace Transiever.ManageSieve;

public sealed record ManageSieveOAuthBearerError(
    string Status, string? Scope, string? OpenIdConfiguration);

public sealed class ManageSieveOAuthBearerAuthenticator : IManageSieveAuthenticator
{
    private enum State { Created, InitialSent, ErrorResponded, Completed, Aborted }

    private static readonly Encoding StrictUtf8 = new UTF8Encoding(false, true);
    private readonly string _accessToken;
    private readonly string _host;
    private readonly int _port;
    private readonly string _authorizationIdentity;
    private byte[]? _initialResponse;
    private byte[]? _dummyResponse;
    private State _state;

    public ManageSieveOAuthBearerAuthenticator(
        string accessToken,
        string host,
        int port,
        string? authorizationIdentity = null)
    {
        ValidateToken(accessToken);
        ValidateHost(host);
        ArgumentOutOfRangeException.ThrowIfLessThan(port, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(port, 65_535);
        if (authorizationIdentity is not null)
        {
            ValidateUtf8Length(authorizationIdentity, 1_024, nameof(authorizationIdentity));
            if (authorizationIdentity.Contains('\0'))
            {
                throw new ArgumentException(
                    "Authorization identity must not contain NUL.",
                    nameof(authorizationIdentity));
            }
        }

        _accessToken = accessToken;
        _host = host;
        _port = port;
        _authorizationIdentity = authorizationIdentity ?? string.Empty;
    }

    public string Mechanism => "OAUTHBEARER";

    public bool AllowsUnprotectedConnection => false;

    public ManageSieveOAuthBearerError? ServerError { get; private set; }

    public ValueTask<ReadOnlyMemory<byte>?> GetInitialResponseAsync(
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (_state is not State.Created)
        {
            return ValueTask.FromException<ReadOnlyMemory<byte>?>(UsedException());
        }

        string gs2 = string.IsNullOrEmpty(_authorizationIdentity)
            ? "n,,"
            : $"n,a={EscapeAuthorizationIdentity(_authorizationIdentity)},";
        string text = string.Concat(
            gs2, '\u0001', "host=", _host, '\u0001',
            "port=", _port.ToString(CultureInfo.InvariantCulture), '\u0001',
            "auth=Bearer ", _accessToken, '\u0001', '\u0001');
        _initialResponse = StrictUtf8.GetBytes(text);
        _state = State.InitialSent;
        return ValueTask.FromResult<ReadOnlyMemory<byte>?>(_initialResponse);
    }

    public ValueTask<ReadOnlyMemory<byte>> RespondAsync(
        ReadOnlyMemory<byte> challenge,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (_state is not State.InitialSent)
        {
            return ValueTask.FromException<ReadOnlyMemory<byte>>(UsedException());
        }

        try
        {
            if (challenge.Length is < 1 or > 16_384)
            {
                throw new FormatException();
            }

            string json = StrictUtf8.GetString(challenge.Span);
            ManageSieveOAuthBearerError error = ParseError(json);
            ServerError = error;
            _dummyResponse = new byte[] { 0x01 };
            _state = State.ErrorResponded;
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(_dummyResponse);
        }
        catch (Exception exception) when (
            exception is DecoderFallbackException or
            EncoderFallbackException or
            JsonException or
            FormatException)
        {
            return ValueTask.FromException<ReadOnlyMemory<byte>>(InvalidErrorException());
        }
    }

    public ValueTask CompleteAsync(
        ReadOnlyMemory<byte>? serverData,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (serverData is not null || _state is not State.InitialSent)
        {
            return ValueTask.FromException(UsedException());
        }

        ClearResponse();
        _state = State.Completed;
        return ValueTask.CompletedTask;
    }

    public void Abort()
    {
        ClearResponse();
        _state = State.Aborted;
    }

    private ManageSieveOAuthBearerError ParseError(string json)
    {
        using JsonDocument document = JsonDocument.Parse(
            json,
            new JsonDocumentOptions { MaxDepth = 8, CommentHandling = JsonCommentHandling.Disallow });
        if (document.RootElement.ValueKind is not JsonValueKind.Object)
        {
            throw new FormatException();
        }

        string? status = null;
        string? scope = null;
        string? configuration = null;
        bool statusSeen = false;
        bool scopeSeen = false;
        bool configurationSeen = false;
        foreach (JsonProperty property in document.RootElement.EnumerateObject())
        {
            bool allowed = property.Name switch
            {
                "status" => !statusSeen,
                "scope" => !scopeSeen,
                "openid-configuration" => !configurationSeen,
                _ => false
            };
            switch (property.Name)
            {
                case "status":
                    statusSeen = true;
                    if (!allowed) throw new FormatException();
                    status = ReadValue(property.Value, 128, true);
                    break;
                case "scope":
                    scopeSeen = true;
                    if (!allowed) throw new FormatException();
                    scope = ReadValue(property.Value, 4_096, false);
                    break;
                case "openid-configuration":
                    configurationSeen = true;
                    if (!allowed) throw new FormatException();
                    configuration = ReadValue(property.Value, 2_048, false);
                    if (configuration is not null &&
                        (!Uri.TryCreate(configuration, UriKind.Absolute, out Uri? uri) ||
                         !uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase) ||
                         uri.UserInfo.Length != 0 || uri.Fragment.Length != 0))
                    {
                        throw new FormatException();
                    }
                    break;
            }
        }

        if (!statusSeen || status is null)
        {
            throw new FormatException();
        }

        return new ManageSieveOAuthBearerError(status, scope, configuration);
    }

    private string? ReadValue(JsonElement value, int maximumBytes, bool required)
    {
        if (value.ValueKind is not JsonValueKind.String)
        {
            throw new FormatException();
        }

        string? text = value.GetString();
        if (text is null || (required && text.Length == 0) || StrictUtf8.GetByteCount(text) > maximumBytes ||
            text.Contains(_accessToken, StringComparison.Ordinal))
        {
            throw new FormatException();
        }

        return text;
    }

    private static string EscapeAuthorizationIdentity(string value) =>
        value.Replace("=", "=3D").Replace(",", "=2C");

    private static ManageSieveAuthenticationException UsedException() =>
        new("OAUTHBEARER authentication exchange has already been used.");

    private static ManageSieveAuthenticationException InvalidErrorException() =>
        new("OAUTHBEARER authentication failed.");

    private void ClearResponse()
    {
        byte[]? response = Interlocked.Exchange(ref _initialResponse, null);
        if (response is not null)
        {
            CryptographicOperations.ZeroMemory(response);
        }

        response = Interlocked.Exchange(ref _dummyResponse, null);
        if (response is not null)
        {
            CryptographicOperations.ZeroMemory(response);
        }
    }

    private static void ValidateToken(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length is 0 or > 16_384)
        {
            throw new ArgumentException("Access token must be a non-empty b64token of at most 16384 bytes.", nameof(value));
        }

        bool paddingStarted = false;
        bool tokenCharacterSeen = false;
        foreach (char character in value)
        {
            if (character == '=')
            {
                paddingStarted = true;
                continue;
            }

            if (paddingStarted || !IsTokenCharacter(character))
            {
                throw new ArgumentException("Access token must be an RFC 6750 b64token.", nameof(value));
            }

            tokenCharacterSeen = true;
        }

        if (!tokenCharacterSeen)
        {
            throw new ArgumentException("Access token must contain a b64token character.", nameof(value));
        }
    }

    private static bool IsTokenCharacter(char character) =>
        character is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '.' or '_' or '~' or '+' or '/';

    private static void ValidateHost(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length == 0 || value.Length > 255 ||
            value.Any(character => character > 0x7F || char.IsControl(character)))
        {
            throw new ArgumentException(
                "Host must be non-empty ASCII, at most 255 bytes, and contain no control characters.",
                nameof(value));
        }
    }

    private static void ValidateUtf8Length(string value, int maximumBytes, string parameterName)
    {
        int byteCount;
        try
        {
            byteCount = StrictUtf8.GetByteCount(value);
        }
        catch (EncoderFallbackException exception)
        {
            throw new ArgumentException("Value must be valid UTF-8.", parameterName, exception);
        }

        if (byteCount > maximumBytes)
        {
            throw new ArgumentException($"Value must be at most {maximumBytes} UTF-8 bytes.", parameterName);
        }
    }
}
