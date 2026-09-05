using System.Buffers.Text;
using System.Security.Cryptography;
using Transiever.ManageSieve;

namespace Transiever.ManageSieve.Authentication;

internal enum ManageSieveAuthenticationRecovery
{
    NotStarted,
    DisconnectRequired,
    RejectedReusable,
    Completed
}

internal sealed class ManageSieveAuthenticationExchange
{
    private readonly Stream _stream;
    private readonly ManageSieveProtocolReader _reader;
    private readonly IManageSieveAuthenticator _authenticator;
    private readonly string _mechanism;
    private readonly CancellationToken _cancellationToken;
    private bool _authenticatorProcessingBegan;

    public ManageSieveAuthenticationExchange(
        Stream stream,
        ManageSieveProtocolReader reader,
        IManageSieveAuthenticator authenticator,
        string mechanism,
        CancellationToken cancellationToken)
    {
        _stream = stream;
        _reader = reader;
        _authenticator = authenticator;
        _mechanism = mechanism;
        _cancellationToken = cancellationToken;
    }

    public ManageSieveAuthenticationRecovery Recovery { get; private set; }

    public async ValueTask ExecuteAsync()
    {
        try
        {
            ReadOnlyMemory<byte>? initialResponse = await GetInitialResponseAsync()
                .ConfigureAwait(false);
            await WriteAuthenticationAsync(initialResponse).ConfigureAwait(false);

            while (true)
            {
                ManageSieveResponse response = await _reader.ReadResponseAsync(
                    _cancellationToken,
                    allowAuthenticationChallenge: true).ConfigureAwait(false);
                switch (response.Status)
                {
                    case ManageSieveResponseStatus.Ok:
                        await CompleteAsync(response).ConfigureAwait(false);
                        return;
                    case ManageSieveResponseStatus.No:
                        Recovery = ManageSieveAuthenticationRecovery.RejectedReusable;
                        throw new ManageSieveAuthenticationException(
                            "ManageSieve authentication failed.",
                            response.Code?.Atom);
                    case ManageSieveResponseStatus.Bye:
                        throw new ManageSieveConnectionException(
                            "ManageSieve server closed the connection during authentication.");
                    default:
                        await HandleChallengeAsync(response).ConfigureAwait(false);
                        break;
                }
            }
        }
        catch
        {
            AbortAfterFailure();
            throw;
        }
    }

    private async ValueTask<ReadOnlyMemory<byte>?> GetInitialResponseAsync()
    {
        _authenticatorProcessingBegan = true;
        try
        {
            return await _authenticator.GetInitialResponseAsync(_cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (_cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            throw new ManageSieveAuthenticationException(
                "ManageSieve authenticator failed.");
        }
    }

    private async ValueTask WriteAuthenticationAsync(
        ReadOnlyMemory<byte>? initialResponse)
    {
        byte[] frame = ManageSieveCommandSerializer.Authentication(
            _mechanism,
            initialResponse);
        try
        {
            _cancellationToken.ThrowIfCancellationRequested();
            Recovery = ManageSieveAuthenticationRecovery.DisconnectRequired;
            await _stream.WriteAsync(frame, _cancellationToken).ConfigureAwait(false);
            await _stream.FlushAsync(_cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(frame);
        }
    }

    private async ValueTask HandleChallengeAsync(ManageSieveResponse response)
    {
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
            ReadOnlyMemory<byte> answer;
            try
            {
                answer = await _authenticator.RespondAsync(challenge, _cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (_cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch
            {
                throw new ManageSieveAuthenticationException(
                    "ManageSieve authenticator failed.");
            }

            responseFrame = ManageSieveCommandSerializer.QuotedBase64(answer);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(challenge);
        }

        try
        {
            await _stream.WriteAsync(responseFrame, _cancellationToken).ConfigureAwait(false);
            await _stream.FlushAsync(_cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(responseFrame);
        }
    }

    private async ValueTask CompleteAsync(ManageSieveResponse response)
    {
        byte[]? successData = DecodeSaslSuccessData(response);
        try
        {
            ReadOnlyMemory<byte>? completionData = null;
            if (successData is not null)
            {
                completionData = successData;
            }

            try
            {
                await _authenticator.CompleteAsync(completionData, _cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (_cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch
            {
                throw new ManageSieveAuthenticationException(
                    "ManageSieve authenticator failed.");
            }

        }
        finally
        {
            if (successData is not null)
            {
                CryptographicOperations.ZeroMemory(successData);
            }
        }

        Recovery = ManageSieveAuthenticationRecovery.Completed;
    }

    private void AbortAfterFailure()
    {
        if (!_authenticatorProcessingBegan)
        {
            return;
        }

        _authenticatorProcessingBegan = false;
        try
        {
            _authenticator.Abort();
        }
        catch
        {
            Recovery = ManageSieveAuthenticationRecovery.DisconnectRequired;
            throw new ManageSieveAuthenticationException(
                "ManageSieve authentication cleanup failed.");
        }
    }

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
        if (!Base64.IsValid(encoded, out int decodedLength) ||
            encoded.Length != ((decodedLength + 2) / 3) * 4)
        {
            throw new ManageSieveProtocolException(errorMessage);
        }

        byte[] decoded = GC.AllocateUninitializedArray<byte>(decodedLength);
        Base64.DecodeFromUtf8(encoded, decoded, out _, out _);
        return decoded;
    }
}
