using System.Buffers;
using System.Buffers.Text;
using System.Security.Cryptography;

namespace Transiever.ManageSieve;

/// <summary>
/// Default ManageSieve protocol client.
/// </summary>
public sealed class ManageSieveClient : IManageSieveClient
{
    private readonly IManageSieveTransportFactory transportFactory;
    private readonly SemaphoreSlim commandLock = new(1, 1);
    private IManageSieveTransport? transport;
    private ManageSieveProtocolReader? reader;
    private bool disposed;

    public ManageSieveClient(ManageSieveClientOptions options)
        : this(options, TcpManageSieveTransportFactory.Instance)
    {
    }

    internal ManageSieveClient(
        ManageSieveClientOptions options,
        IManageSieveTransportFactory transportFactory)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(transportFactory);

        if (string.IsNullOrWhiteSpace(options.Host))
        {
            throw new ArgumentException("A ManageSieve host is required.", nameof(options));
        }

        if (options.Port is <= 0 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "The port must be between 1 and 65535.");
        }

        if (options.ConnectTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "The connect timeout must be positive.");
        }

        if (options.OperationTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "The operation timeout must be positive.");
        }

        Options = options;
        this.transportFactory = transportFactory;
    }

    public ManageSieveClientOptions Options { get; }

    public ManageSieveSessionState State { get; private set; } =
        ManageSieveSessionState.Disconnected;

    public ManageSieveCapabilities? Capabilities { get; private set; }

    public async ValueTask ConnectAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        EnsureState(ManageSieveSessionState.Disconnected);

        using CancellationTokenSource timeout = CreateTimeout(
            Options.ConnectTimeout,
            cancellationToken);

        try
        {
            transport = transportFactory.Create(Options);
            await transport.ConnectAsync(timeout.Token).ConfigureAwait(false);

            if (Options.SecurityMode == ManageSieveSecurityMode.ImplicitTls)
            {
                await transport.UpgradeTlsAsync(Options.Host, timeout.Token).ConfigureAwait(false);
            }

            reader = new ManageSieveProtocolReader(transport.Stream);
            ManageSieveResponse greeting = await reader.ReadResponseAsync(timeout.Token).ConfigureAwait(false);
            ThrowForFailure("CONNECT", greeting);

            Capabilities = ManageSieveProtocolMapper.MapCapabilities(greeting.Data);
            State = transport.IsSecure
                ? ManageSieveSessionState.Secured
                : ManageSieveSessionState.Connected;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            await ResetTransportAsync().ConfigureAwait(false);
            throw new ManageSieveConnectionException(
                $"Connecting to {Options.Host}:{Options.Port} timed out.");
        }
        catch (ManageSieveException)
        {
            await ResetTransportAsync().ConfigureAwait(false);
            throw;
        }
        catch (Exception exception)
        {
            await ResetTransportAsync().ConfigureAwait(false);
            throw new ManageSieveConnectionException(
                $"Could not connect to {Options.Host}:{Options.Port}.",
                exception);
        }
    }

    public ValueTask<ManageSieveCapabilities> RefreshCapabilitiesAsync(
        CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            "CAPABILITY",
            [ManageSieveCommandSerializer.Line("CAPABILITY")],
            response =>
            {
                ManageSieveCapabilities capabilities =
                    ManageSieveProtocolMapper.MapCapabilities(response.Data);
                Capabilities = capabilities;
                return capabilities;
            },
            [ManageSieveSessionState.Connected, ManageSieveSessionState.Secured, ManageSieveSessionState.Authenticated],
            cancellationToken);

    public async ValueTask StartTlsAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        EnsureState(ManageSieveSessionState.Connected);

        if (Options.SecurityMode == ManageSieveSecurityMode.PlainText)
        {
            throw new InvalidOperationException("STARTTLS is disabled by the configured security mode.");
        }

        if (Capabilities?.SupportsStartTls != true)
        {
            throw new ManageSieveProtocolException("The server did not advertise STARTTLS.");
        }

        await commandLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using CancellationTokenSource timeout = CreateTimeout(
                Options.OperationTimeout,
                cancellationToken);
            await WriteAsync([ManageSieveCommandSerializer.Line("STARTTLS")], timeout.Token)
                .ConfigureAwait(false);
            ManageSieveResponse response = await ReadAsync(timeout.Token).ConfigureAwait(false);
            ThrowForFailure("STARTTLS", response);

            await transport!.UpgradeTlsAsync(Options.Host, timeout.Token).ConfigureAwait(false);
            reader = new ManageSieveProtocolReader(transport.Stream);
            State = ManageSieveSessionState.Secured;

            ManageSieveResponse capabilities = await ReadAsync(timeout.Token).ConfigureAwait(false);
            ThrowForFailure("STARTTLS", capabilities);
            Capabilities = ManageSieveProtocolMapper.MapCapabilities(capabilities.Data);
        }
        finally
        {
            commandLock.Release();
        }
    }

    public async ValueTask AuthenticateAsync(
        IManageSieveAuthenticator authenticator,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authenticator);
        ThrowIfDisposed();
        EnsureState(ManageSieveSessionState.Secured, ManageSieveSessionState.Connected);
        string mechanism = authenticator.Mechanism;

        if (State != ManageSieveSessionState.Secured &&
            !authenticator.AllowsUnprotectedConnection)
        {
            throw new InvalidOperationException(
                "The selected SASL mechanism requires a protected connection.");
        }

        if (Capabilities is null ||
            !Capabilities.SaslMechanisms.Contains(mechanism))
        {
            throw new ManageSieveAuthenticationException(
                "The server did not advertise the selected SASL mechanism.");
        }

        await commandLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        bool authenticatorProcessingBegan = false;
        bool authenticatorCallback = false;
        bool bytesWritten = false;
        bool exchangeSynchronized = false;
        CancellationToken operationCancellationToken = default;
        try
        {
            using CancellationTokenSource timeout = CreateTimeout(
                Options.OperationTimeout,
                cancellationToken);
            operationCancellationToken = timeout.Token;
            authenticatorProcessingBegan = true;
            authenticatorCallback = true;
            ReadOnlyMemory<byte>? initial =
                await authenticator.GetInitialResponseAsync(timeout.Token).ConfigureAwait(false);
            authenticatorCallback = false;
            byte[] authenticationFrame = ManageSieveCommandSerializer.Authentication(
                mechanism,
                initial);
            try
            {
                timeout.Token.ThrowIfCancellationRequested();
                bytesWritten = true;
                await WriteAsync([authenticationFrame], timeout.Token).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(authenticationFrame);
            }

            while (true)
            {
                ManageSieveResponse response =
                    await reader!.ReadResponseAsync(timeout.Token, allowContinuation: true)
                        .ConfigureAwait(false);
                if (response.Status == ManageSieveResponseStatus.Ok)
                {
                    byte[]? successData = DecodeSaslSuccessData(response);
                    try
                    {
                        ReadOnlyMemory<byte>? completionData = null;
                        if (successData is not null)
                        {
                            completionData = successData;
                        }

                        authenticatorCallback = true;
                        await authenticator.CompleteAsync(
                            completionData,
                            timeout.Token).ConfigureAwait(false);
                        authenticatorCallback = false;

                        State = ManageSieveSessionState.Authenticated;
                        return;
                    }
                    finally
                    {
                        if (successData is not null)
                        {
                            CryptographicOperations.ZeroMemory(successData);
                        }
                    }
                }

                if (response.Status == ManageSieveResponseStatus.No)
                {
                    exchangeSynchronized = true;
                    throw AuthenticationRejected(response);
                }

                if (response.Status == ManageSieveResponseStatus.Bye)
                {
                    throw new ManageSieveConnectionException(
                        "ManageSieve server closed the connection during authentication.");
                }

                if (response.Data.Count != 1 || response.Data[0].Values.Count != 1)
                {
                    throw new ManageSieveProtocolException(
                        "The server returned an invalid SASL challenge.");
                }

                byte[] encodedChallenge = response.Data[0].Values[0].Bytes.ToArray();
                byte[] challenge;
                try
                {
                    challenge = DecodeSaslData(
                        encodedChallenge,
                        "The server returned an invalid base64 SASL challenge.");
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(encodedChallenge);
                }

                byte[] responseFrame;
                try
                {
                    authenticatorCallback = true;
                    ReadOnlyMemory<byte> answer =
                        await authenticator.RespondAsync(challenge, timeout.Token)
                            .ConfigureAwait(false);
                    authenticatorCallback = false;
                    responseFrame = ManageSieveCommandSerializer.QuotedBase64(answer);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(challenge);
                }

                try
                {
                    await WriteAsync([responseFrame], timeout.Token).ConfigureAwait(false);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(responseFrame);
                }
            }
        }
        catch (Exception exception)
        {
            if (authenticatorProcessingBegan)
            {
                await AbortAuthenticationAsync(
                    authenticator,
                    bytesWritten && !exchangeSynchronized).ConfigureAwait(false);
            }

            if (exception is OperationCanceledException)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                }

                if (operationCancellationToken.IsCancellationRequested)
                {
                    throw new TimeoutException("ManageSieve authentication timed out.");
                }
            }

            if (exchangeSynchronized)
            {
                throw;
            }

            if (authenticatorCallback)
            {
                throw new ManageSieveAuthenticationException(
                    "ManageSieve authenticator failed.");
            }

            throw;
        }
        finally
        {
            commandLock.Release();
        }
    }

    private async ValueTask AbortAuthenticationAsync(
        IManageSieveAuthenticator authenticator,
        bool bytesWritten)
    {
        bool cleanupFailed = false;
        try
        {
            authenticator.Abort();
        }
        catch
        {
            cleanupFailed = true;
        }

        if (bytesWritten || cleanupFailed)
        {
            try
            {
                await ResetTransportAsync().ConfigureAwait(false);
            }
            catch
            {
                cleanupFailed = true;
            }
        }

        if (cleanupFailed)
        {
            throw new ManageSieveAuthenticationException(
                "ManageSieve authentication cleanup failed.");
        }
    }

    private static ManageSieveAuthenticationException AuthenticationRejected(
        ManageSieveResponse response) =>
        new("ManageSieve authentication failed.", response.Code?.Atom);

    private static byte[]? DecodeSaslSuccessData(ManageSieveResponse response)
    {
        if (response.Code is not { } code ||
            !code.Atom.Equals("SASL", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        if (code.Arguments.Count != 1 ||
            code.Arguments[0].Kind is not (
                ManageSieveProtocolValueKind.QuotedString or
                ManageSieveProtocolValueKind.Literal))
        {
            throw new ManageSieveProtocolException(
                "The server returned invalid SASL success data.");
        }

        return DecodeSaslData(
            code.Arguments[0].Bytes.Span,
            "The server returned invalid base64 SASL success data.");
    }

    private static byte[] DecodeSaslData(
        ReadOnlySpan<byte> encoded,
        string errorMessage)
    {
        int padding = encoded.Length switch
        {
            > 1 when encoded[^2..].SequenceEqual("=="u8) => 2,
            > 0 when encoded[^1] == (byte)'=' => 1,
            _ => 0
        };
        int contentLength = encoded.Length - padding;
        bool invalid = encoded.Length % 4 != 0;
        for (int index = 0; !invalid && index < contentLength; index++)
        {
            byte value = encoded[index];
            invalid = value is not (>= (byte)'A' and <= (byte)'Z') and
                not (>= (byte)'a' and <= (byte)'z') and
                not (>= (byte)'0' and <= (byte)'9') and
                not ((byte)'+' or (byte)'/');
        }

        for (int index = contentLength; !invalid && index < encoded.Length; index++)
        {
            invalid = encoded[index] != (byte)'=';
        }

        if (invalid)
        {
            throw new ManageSieveProtocolException(errorMessage);
        }

        byte[] decoded = GC.AllocateUninitializedArray<byte>(
            encoded.Length / 4 * 3 - padding);
        OperationStatus status = Base64.DecodeFromUtf8(
            encoded,
            decoded,
            out int consumed,
            out int written);
        if (status != OperationStatus.Done ||
            consumed != encoded.Length ||
            written != decoded.Length)
        {
            CryptographicOperations.ZeroMemory(decoded);
            throw new ManageSieveProtocolException(errorMessage);
        }

        return decoded;
    }

    public async ValueTask UnauthenticateAsync(CancellationToken cancellationToken = default)
    {
        await ExecuteAsync(
            "UNAUTHENTICATE",
            [ManageSieveCommandSerializer.Line("UNAUTHENTICATE")],
            response =>
            {
                if (response.Data.Count > 0)
                {
                    Capabilities =
                        ManageSieveProtocolMapper.MapCapabilities(response.Data);
                }

                return ManageSieveProtocolMapper.MapResult(response);
            },
            [ManageSieveSessionState.Authenticated],
            cancellationToken).ConfigureAwait(false);
        State = transport!.IsSecure
            ? ManageSieveSessionState.Secured
            : ManageSieveSessionState.Connected;
    }

    public ValueTask<ManageSieveSpaceAvailability> HaveSpaceAsync(
        string scriptName,
        long contentOctetCount,
        CancellationToken cancellationToken = default)
    {
        ValidateScriptName(scriptName);
        ArgumentOutOfRangeException.ThrowIfNegative(contentOctetCount);

        return ExecuteAsync(
            "HAVESPACE",
            [ManageSieveCommandSerializer.Line(
                "HAVESPACE",
                ManageSieveCommandSerializer.Quote(scriptName),
                contentOctetCount.ToString(System.Globalization.CultureInfo.InvariantCulture))],
            response => new ManageSieveSpaceAvailability
            {
                HasSpace = response.Status == ManageSieveResponseStatus.Ok,
                Message = response.Message,
                ResponseCode = response.ResponseCode
            },
            [ManageSieveSessionState.Authenticated],
            cancellationToken,
            throwOnNo: false);
    }

    public ValueTask<IReadOnlyList<ManageSieveScriptInfo>> ListScriptsAsync(
        CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            "LISTSCRIPTS",
            [ManageSieveCommandSerializer.Line("LISTSCRIPTS")],
            response => ManageSieveProtocolMapper.MapScripts(response.Data),
            [ManageSieveSessionState.Authenticated],
            cancellationToken);

    public ValueTask<ManageSieveScript> GetScriptAsync(
        string scriptName,
        CancellationToken cancellationToken = default)
    {
        ValidateScriptName(scriptName);
        return ExecuteAsync(
            "GETSCRIPT",
            [ManageSieveCommandSerializer.Line(
                "GETSCRIPT",
                ManageSieveCommandSerializer.Quote(scriptName))],
            response => ManageSieveProtocolMapper.MapScript(scriptName, response.Data),
            [ManageSieveSessionState.Authenticated],
            cancellationToken);
    }

    public ValueTask<ManageSieveCommandResult> CheckScriptAsync(
        ReadOnlyMemory<byte> content,
        CancellationToken cancellationToken = default) =>
        ExecuteResultAsync(
            "CHECKSCRIPT",
            ManageSieveCommandSerializer.LiteralCommand("CHECKSCRIPT", null, content),
            [ManageSieveSessionState.Authenticated],
            cancellationToken);

    public ValueTask<ManageSieveCommandResult> PutScriptAsync(
        string scriptName,
        ReadOnlyMemory<byte> content,
        CancellationToken cancellationToken = default)
    {
        ValidateScriptName(scriptName);
        return ExecuteResultAsync(
            "PUTSCRIPT",
            ManageSieveCommandSerializer.LiteralCommand("PUTSCRIPT", scriptName, content),
            [ManageSieveSessionState.Authenticated],
            cancellationToken);
    }

    public ValueTask<ManageSieveCommandResult> SetActiveScriptAsync(
        string? scriptName,
        CancellationToken cancellationToken = default)
    {
        if (scriptName is not null)
        {
            ValidateScriptName(scriptName);
        }

        return ExecuteResultAsync(
            "SETACTIVE",
            [ManageSieveCommandSerializer.Line(
                "SETACTIVE",
                ManageSieveCommandSerializer.Quote(scriptName ?? string.Empty))],
            [ManageSieveSessionState.Authenticated],
            cancellationToken);
    }

    public ValueTask<ManageSieveCommandResult> RenameScriptAsync(
        string currentName,
        string newName,
        CancellationToken cancellationToken = default)
    {
        ValidateScriptName(currentName);
        ValidateScriptName(newName);
        return ExecuteResultAsync(
            "RENAMESCRIPT",
            [ManageSieveCommandSerializer.Line(
                "RENAMESCRIPT",
                ManageSieveCommandSerializer.Quote(currentName),
                ManageSieveCommandSerializer.Quote(newName))],
            [ManageSieveSessionState.Authenticated],
            cancellationToken);
    }

    public ValueTask<ManageSieveCommandResult> DeleteScriptAsync(
        string scriptName,
        CancellationToken cancellationToken = default)
    {
        ValidateScriptName(scriptName);
        return ExecuteResultAsync(
            "DELETESCRIPT",
            [ManageSieveCommandSerializer.Line(
                "DELETESCRIPT",
                ManageSieveCommandSerializer.Quote(scriptName))],
            [ManageSieveSessionState.Authenticated],
            cancellationToken);
    }

    public ValueTask<ManageSieveCommandResult> NoOpAsync(
        string? tag = null,
        CancellationToken cancellationToken = default)
    {
        if (tag?.ContainsAny('\r', '\n') == true)
        {
            throw new ArgumentException("A NOOP tag cannot contain a line break.", nameof(tag));
        }

        return ExecuteResultAsync(
            "NOOP",
            tag is null
                ? [ManageSieveCommandSerializer.Line("NOOP")]
                : [ManageSieveCommandSerializer.Line("NOOP", ManageSieveCommandSerializer.Quote(tag))],
            [ManageSieveSessionState.Connected, ManageSieveSessionState.Secured, ManageSieveSessionState.Authenticated],
            cancellationToken);
    }

    public async ValueTask LogoutAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (State is ManageSieveSessionState.Disconnected or ManageSieveSessionState.Closed)
        {
            State = ManageSieveSessionState.Closed;
            return;
        }

        try
        {
            await ExecuteResultAsync(
                "LOGOUT",
                [ManageSieveCommandSerializer.Line("LOGOUT")],
                [ManageSieveSessionState.Connected, ManageSieveSessionState.Secured, ManageSieveSessionState.Authenticated],
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            await ResetTransportAsync().ConfigureAwait(false);
            State = ManageSieveSessionState.Closed;
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (disposed)
        {
            return;
        }

        disposed = true;
        await ResetTransportAsync().ConfigureAwait(false);
        commandLock.Dispose();
        State = ManageSieveSessionState.Closed;
        Capabilities = null;
    }

    private ValueTask<ManageSieveCommandResult> ExecuteResultAsync(
        string command,
        IReadOnlyList<ReadOnlyMemory<byte>> frames,
        IReadOnlyList<ManageSieveSessionState> allowedStates,
        CancellationToken cancellationToken) =>
        ExecuteAsync(
            command,
            frames,
            ManageSieveProtocolMapper.MapResult,
            allowedStates,
            cancellationToken);

    private async ValueTask<T> ExecuteAsync<T>(
        string command,
        IReadOnlyList<ReadOnlyMemory<byte>> frames,
        Func<ManageSieveResponse, T> map,
        IReadOnlyList<ManageSieveSessionState> allowedStates,
        CancellationToken cancellationToken,
        bool throwOnNo = true)
    {
        ThrowIfDisposed();
        EnsureState([.. allowedStates]);
        await commandLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using CancellationTokenSource timeout = CreateTimeout(
                Options.OperationTimeout,
                cancellationToken);
            await WriteAsync(frames, timeout.Token).ConfigureAwait(false);
            ManageSieveResponse response = await ReadAsync(timeout.Token).ConfigureAwait(false);
            if (response.Status == ManageSieveResponseStatus.Bye ||
                (throwOnNo && response.Status == ManageSieveResponseStatus.No))
            {
                ThrowForFailure(command, response);
            }

            return map(response);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException(
                $"ManageSieve command {command} exceeded {Options.OperationTimeout}.");
        }
        finally
        {
            commandLock.Release();
        }
    }

    private async ValueTask WriteAsync(
        IReadOnlyList<ReadOnlyMemory<byte>> frames,
        CancellationToken cancellationToken)
    {
        foreach (ReadOnlyMemory<byte> frame in frames)
        {
            await transport!.Stream.WriteAsync(frame, cancellationToken).ConfigureAwait(false);
        }

        await transport!.Stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private ValueTask<ManageSieveResponse> ReadAsync(CancellationToken cancellationToken) =>
        reader!.ReadResponseAsync(cancellationToken);

    private static void ThrowForFailure(string command, ManageSieveResponse response)
    {
        if (response.Status == ManageSieveResponseStatus.Ok)
        {
            return;
        }

        string message = response.Message ?? $"ManageSieve command {command} failed.";
        if (response.Status == ManageSieveResponseStatus.Bye)
        {
            throw new ManageSieveConnectionException(message);
        }

        throw new ManageSieveCommandException(command, message, response.ResponseCode);
    }

    private static CancellationTokenSource CreateTimeout(
        TimeSpan duration,
        CancellationToken cancellationToken)
    {
        CancellationTokenSource timeout =
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(duration);
        return timeout;
    }

    private void EnsureState(params ManageSieveSessionState[] allowedStates)
    {
        if (!allowedStates.Contains(State))
        {
            throw new InvalidOperationException(
                $"Operation is not valid while the ManageSieve session is {State}.");
        }
    }

    private static void ValidateScriptName(string scriptName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(scriptName);
        if (!scriptName.IsNormalized(System.Text.NormalizationForm.FormC) ||
            scriptName.EnumerateRunes().Any(
                rune => rune.Value is <= 0x1f or 0x7f or >= 0x80 and <= 0x9f
                    or 0x2028 or 0x2029))
        {
            throw new ArgumentException(
                "A script name must be NFC-normalized and cannot contain Unicode control or line-separator characters.",
                nameof(scriptName));
        }
    }

    private async ValueTask ResetTransportAsync()
    {
        IManageSieveTransport? transportToDispose = transport;
        transport = null;
        reader = null;
        Capabilities = null;
        State = ManageSieveSessionState.Disconnected;

        if (transportToDispose is not null)
        {
            await transportToDispose.DisposeAsync().ConfigureAwait(false);
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
    }
}
