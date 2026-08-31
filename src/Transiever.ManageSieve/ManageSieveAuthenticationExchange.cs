using System.Buffers;
using System.Buffers.Text;
using System.Security.Cryptography;

namespace Transiever.ManageSieve;

internal enum ManageSieveAuthenticationRecovery
{
    NotStarted,
    DisconnectRequired,
    RejectedReusable,
    Completed
}

internal sealed class ManageSieveAuthenticationExchange
{
    private readonly Stream stream;
    private readonly ManageSieveProtocolReader reader;
    private readonly IManageSieveAuthenticator authenticator;
    private readonly string mechanism;
    private readonly CancellationToken cancellationToken;
    private bool authenticatorProcessingBegan;

    public ManageSieveAuthenticationExchange(
        Stream stream,
        ManageSieveProtocolReader reader,
        IManageSieveAuthenticator authenticator,
        string mechanism,
        CancellationToken cancellationToken)
    {
        this.stream = stream;
        this.reader = reader;
        this.authenticator = authenticator;
        this.mechanism = mechanism;
        this.cancellationToken = cancellationToken;
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
                ManageSieveResponse response = await reader.ReadResponseAsync(
                    cancellationToken,
                    allowContinuation: true).ConfigureAwait(false);
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
        authenticatorProcessingBegan = true;
        try
        {
            return await authenticator.GetInitialResponseAsync(cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
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
            mechanism,
            initialResponse);
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            Recovery = ManageSieveAuthenticationRecovery.DisconnectRequired;
            await stream.WriteAsync(frame, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
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
                answer = await authenticator.RespondAsync(challenge, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
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
            await stream.WriteAsync(responseFrame, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
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
                await authenticator.CompleteAsync(completionData, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
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
        if (!authenticatorProcessingBegan)
        {
            return;
        }

        authenticatorProcessingBegan = false;
        try
        {
            authenticator.Abort();
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
}
