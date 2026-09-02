using System.Security.Cryptography;

namespace Transiever.ManageSieve.UnitTest;

internal sealed class ScriptedManageSieveTransport :
    IManageSieveTransport,
    IManageSieveTransportFactory
{
    private readonly ScriptedStream stream;
    private readonly Exception? disposeException;

    public ScriptedManageSieveTransport(
        ReadOnlyMemory<byte> input,
        bool secure = false,
        bool blockAfterInput = false,
        bool failAfterPartialWrite = false,
        int? failAfterPartialWriteNumber = null,
        Exception? disposeException = null)
    {
        stream = new ScriptedStream(
            input,
            blockAfterInput,
            failAfterPartialWriteNumber ?? (failAfterPartialWrite ? 1 : null));
        IsSecure = secure;
        this.disposeException = disposeException;
    }

    public Stream Stream => stream;

    public bool IsSecure { get; private set; }

    public bool IsDisposed { get; private set; }

    public ReadOnlyMemory<byte> Written => stream.Written;

    public IReadOnlyList<ReadOnlyMemory<byte>> OriginalWrites => stream.OriginalWrites;

    public IReadOnlyList<ReadOnlyMemory<byte>> OriginalSensitiveWrites =>
        stream.OriginalWrites;

    public Task WaitForWriteAsync() => stream.WaitForWriteAsync();

    public IManageSieveTransport Create(ManageSieveClientOptions options) => this;

    public ValueTask ConnectAsync(CancellationToken cancellationToken) =>
        ValueTask.CompletedTask;

    public ValueTask UpgradeTlsAsync(
        string targetHost,
        CancellationToken cancellationToken)
    {
        IsSecure = true;
        return ValueTask.CompletedTask;
    }

    public ValueTask DisposeAsync()
    {
        IsDisposed = true;
        stream.Dispose();
        return disposeException is null
            ? ValueTask.CompletedTask
            : ValueTask.FromException(disposeException);
    }

    private sealed class ScriptedStream : Stream
    {
        private readonly MemoryStream input;
        private readonly MemoryStream output = new();
        private readonly bool blockAfterInput;
        private readonly int? failAfterPartialWriteNumber;
        private readonly List<ReadOnlyMemory<byte>> originalWrites = [];
        private readonly TaskCompletionSource writeObserved = new(
            TaskCreationOptions.RunContinuationsAsynchronously);

        public ScriptedStream(
            ReadOnlyMemory<byte> input,
            bool blockAfterInput,
            int? failAfterPartialWriteNumber)
        {
            this.input = new MemoryStream(input.ToArray(), writable: false);
            this.blockAfterInput = blockAfterInput;
            this.failAfterPartialWriteNumber = failAfterPartialWriteNumber;
        }

        public ReadOnlyMemory<byte> Written => output.ToArray();

        public IReadOnlyList<ReadOnlyMemory<byte>> OriginalWrites => originalWrites;

        public Task WaitForWriteAsync() => writeObserved.Task;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override Task FlushAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            int read = await input.ReadAsync(
                buffer[..Math.Min(1, buffer.Length)], cancellationToken);
            if (read > 0 || !blockAfterInput)
            {
                return read;
            }

            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return 0;
        }

        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();

        public override void SetLength(long value) =>
            throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
        {
            originalWrites.Add(new ReadOnlyMemory<byte>(buffer, offset, count));
            output.Write(buffer, offset, count);
            writeObserved.TrySetResult();
        }

        public override ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (failAfterPartialWriteNumber == originalWrites.Count + 1)
            {
                ReadOnlyMemory<byte> partialWrite = buffer[..1];
                originalWrites.Add(partialWrite);
                output.Write(partialWrite.Span);
                writeObserved.TrySetResult();
                return ValueTask.FromException(
                    new IOException("Injected partial write failure."));
            }

            originalWrites.Add(buffer);
            output.Write(buffer.Span);
            writeObserved.TrySetResult();
            return ValueTask.CompletedTask;
        }
    }
}

internal sealed class ScriptedAuthenticator : IManageSieveAuthenticator
{
    private readonly byte[][] responses;
    private readonly List<byte[]> ownedSecretBuffers = [];
    private readonly TaskCompletionSource initialInvoked = new(
        TaskCreationOptions.RunContinuationsAsynchronously);
    private byte[]? initialResponse;
    private int responseIndex;

    public ScriptedAuthenticator(params ReadOnlyMemory<byte>[] responses)
    {
        this.responses = responses.Select(response => response.ToArray()).ToArray();
        ownedSecretBuffers.AddRange(this.responses);
    }

    public string Mechanism => "TEST";

    public bool AllowsUnprotectedConnection { get; init; }

    public List<string> Calls { get; } = [];

    public List<ReadOnlyMemory<byte>> Challenges { get; } = [];

    public List<SaslBufferObservation> ChallengeObservations { get; } = [];

    public IReadOnlyList<ReadOnlyMemory<byte>> OwnedSecretBuffers =>
        [.. ownedSecretBuffers.Select(buffer => (ReadOnlyMemory<byte>)buffer)];

    public byte[]? InitialResponse
    {
        get => initialResponse;
        init
        {
            initialResponse = value?.ToArray();
            if (initialResponse is not null)
            {
                ownedSecretBuffers.Add(initialResponse);
            }
        }
    }

    public bool CompletionDataProvided { get; private set; }

    public ReadOnlyMemory<byte>? CompletionMemory { get; private set; }

    public SaslBufferObservation? CompletionObservation { get; private set; }

    public Exception? CompletionException { get; init; }

    public Exception? InitialException { get; init; }

    public Exception? ResponseException { get; init; }

    public Exception? AbortException { get; init; }

    public bool EchoChallenge { get; init; }

    public bool BlockInitialResponse { get; init; }

    public Action? InitialResponseReturning { get; init; }

    public int AbortCount { get; private set; }

    public Task WaitForInitialAsync() => initialInvoked.Task;

    public void OwnSecret(ReadOnlyMemory<byte> secret) =>
        ownedSecretBuffers.Add(secret.ToArray());

    public async ValueTask<ReadOnlyMemory<byte>?> GetInitialResponseAsync(
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Calls.Add("Initial");
        initialInvoked.TrySetResult();
        if (BlockInitialResponse)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
        }

        if (InitialException is not null)
        {
            throw InitialException;
        }

        InitialResponseReturning?.Invoke();
        if (initialResponse is null)
        {
            return (ReadOnlyMemory<byte>?)null;
        }

        return initialResponse;
    }

    public ValueTask<ReadOnlyMemory<byte>> RespondAsync(
        ReadOnlyMemory<byte> challenge,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Calls.Add("Respond");
        Challenges.Add(challenge);
        ChallengeObservations.Add(SaslConformanceHarness.Observe(challenge.Span));
        if (ResponseException is not null)
        {
            return ValueTask.FromException<ReadOnlyMemory<byte>>(ResponseException);
        }

        ReadOnlyMemory<byte> response = EchoChallenge
            ? challenge
            : responseIndex < responses.Length
                ? responses[responseIndex++]
                : ReadOnlyMemory<byte>.Empty;
        return ValueTask.FromResult(response);
    }

    public ValueTask CompleteAsync(
        ReadOnlyMemory<byte>? serverData,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Calls.Add("Complete");
        CompletionDataProvided = serverData.HasValue;
        CompletionMemory = serverData;
        CompletionObservation = serverData.HasValue
            ? SaslConformanceHarness.Observe(serverData.Value.Span)
            : null;
        ClearOwnedSecrets();
        return CompletionException is null
            ? ValueTask.CompletedTask
            : ValueTask.FromException(CompletionException);
    }

    public void Abort()
    {
        Calls.Add("Abort");
        AbortCount++;
        ClearOwnedSecrets();
        if (AbortException is not null)
        {
            throw AbortException;
        }
    }

    private void ClearOwnedSecrets()
    {
        foreach (byte[] buffer in ownedSecretBuffers)
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }
}

internal readonly record struct SaslBufferObservation(int Length, string Sha256);

internal sealed class SaslConformanceHarness : IAsyncDisposable
{
    public required ManageSieveClient Client { get; init; }

    public required ScriptedManageSieveTransport Transport { get; init; }

    public static SaslBufferObservation Observe(ReadOnlySpan<byte> buffer) =>
        new(buffer.Length, Convert.ToHexString(SHA256.HashData(buffer)));

    public static void AssertTranscriptEqual(
        ReadOnlySpan<byte> expected,
        ReadOnlySpan<byte> actual)
    {
        if (expected.SequenceEqual(actual))
        {
            return;
        }

        int firstDifference = 0;
        int commonLength = Math.Min(expected.Length, actual.Length);
        while (firstDifference < commonLength &&
            expected[firstDifference] == actual[firstDifference])
        {
            firstDifference++;
        }

        Assert.Fail(
            $"Transcript mismatch: expected length {expected.Length}, actual length {actual.Length}, " +
            $"first differing offset {firstDifference}, " +
            $"expected SHA-256 {Convert.ToHexString(SHA256.HashData(expected))}, " +
            $"actual SHA-256 {Convert.ToHexString(SHA256.HashData(actual))}.");
    }

    public static void AssertZeroed(IEnumerable<ReadOnlyMemory<byte>> buffers)
    {
        int bufferIndex = 0;
        foreach (ReadOnlyMemory<byte> buffer in buffers)
        {
            int firstNonZero = buffer.Span.IndexOfAnyExcept((byte)0);
            Assert.True(
                firstNonZero < 0,
                $"Buffer {bufferIndex} was not cleared: length {buffer.Length}, " +
                $"first non-zero offset {firstNonZero}.");
            bufferIndex++;
        }
    }

    public static async ValueTask<SaslConformanceHarness> ConnectAsync(
        ReadOnlyMemory<byte> serverBytes,
        ManageSieveSecurityMode securityMode = ManageSieveSecurityMode.ImplicitTls,
        bool secure = true,
        bool blockAfterInput = false,
        bool failAfterPartialWrite = false,
        int? failAfterPartialWriteNumber = null,
        TimeSpan? operationTimeout = null,
        Exception? disposeException = null)
    {
        TimeSpan timeout = operationTimeout ?? TimeSpan.FromSeconds(30);
        var transport = new ScriptedManageSieveTransport(
            serverBytes,
            secure,
            blockAfterInput,
            failAfterPartialWrite,
            failAfterPartialWriteNumber,
            disposeException);
        var client = new ManageSieveClient(
            new ManageSieveClientOptions
            {
                Host = "sieve.example.com",
                Port = 4190,
                SecurityMode = securityMode,
                ConnectTimeout = timeout,
                OperationTimeout = timeout
            },
            transport);

        await client.ConnectAsync().ConfigureAwait(false);
        return new SaslConformanceHarness
        {
            Client = client,
            Transport = transport
        };
    }

    public ValueTask DisposeAsync() => Client.DisposeAsync();
}
