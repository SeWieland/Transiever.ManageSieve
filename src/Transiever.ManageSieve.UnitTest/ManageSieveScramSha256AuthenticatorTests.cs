using System.Text;
using Transiever.SaslClient;
using static Transiever.ManageSieve.UnitTest.SaslConformanceHarness;

namespace Transiever.ManageSieve.UnitTest;

public sealed class ManageSieveScramSha256AuthenticatorTests
{
    private const string ClientNonce = "rOprNGfwEbeRWgbNEkqO";
    private const string RfcServerNonce =
        ClientNonce + "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
    private const string RfcServerFirst =
        "r=" + RfcServerNonce + ",s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
    private const string RfcServerFirstBase64 =
        "cj1yT3ByTkdmd0ViZVJXZ2JORWtxTyVodllEcFdVYTJSYVRDQWZ1eEZJbGopaE5sRiRrMCxzPVcyMlphSjBTTlk3c29Fc1VFamI2Z1E9PSxpPTQwOTY=";
    private const string RfcServerFinal =
        "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";
    private const string RfcServerFinalBase64 =
        "dj02cnJpVFJCaTIzV3BSUi93dHVwK21NaFVaVW4vZEI1bkxUSlJzamw5NUc0PQ==";
    private const string RfcClientFirstFrame =
        "AUTHENTICATE \"SCRAM-SHA-256\" \"biwsbj11c2VyLHI9ck9wck5HZndFYmVSV2diTkVrcU8=\"\r\n";
    private const string RfcClientFinalFrame =
        "\"Yz1iaXdzLHI9ck9wck5HZndFYmVSV2diTkVrcU8laHZZRHBXVWEyUmFUQ0FmdXhGSWxqKWhObEYkazAscD1kSHpiWmFwV0lrNGpVaE4rVXRlOXl0YWc5empmTUhnc3FtbWl6N0FuZFZRPQ==\"\r\n";
    [Fact]
    public async Task ScramAuthentication_accepts_ok_sasl_final_data_with_exact_frames()
    {
        byte[] responses = Encoding.ASCII.GetBytes(
            "\"SASL\" \"SCRAM-SHA-256\"\r\nOK\r\n" +
            $"\"{RfcServerFirstBase64}\"\r\n" +
            $"OK (SASL \"{RfcServerFinalBase64}\")\r\n");
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(responses);
        var authenticator = new RecordingScramAuthenticator();

        await harness.Client.AuthenticateAsync(
            authenticator, TestContext.Current.CancellationToken);

        Assert.Equal(
            ["GetInitialResponse", "Respond(server-first)", "Complete(server-final)"],
            authenticator.Calls);
        Assert.Equal([Observe(Encoding.UTF8.GetBytes(RfcServerFirst))],
            authenticator.ChallengeObservations);
        Assert.Equal(Observe(Encoding.UTF8.GetBytes(RfcServerFinal)),
            authenticator.CompletionObservation);
        AssertTranscriptEqual(
            Encoding.ASCII.GetBytes(RfcClientFirstFrame + RfcClientFinalFrame),
            harness.Transport.Written.Span);
        AssertZeroed(authenticator.OwnedBuffers);
        Assert.Equal(ManageSieveSessionState.Authenticated, harness.Client.State);
    }

    [Fact]
    public async Task ScramAuthentication_accepts_final_challenge_with_exact_empty_response_frame()
    {
        byte[] responses = Encoding.ASCII.GetBytes(
            "\"SASL\" \"SCRAM-SHA-256\"\r\nOK\r\n" +
            $"\"{RfcServerFirstBase64}\"\r\n" +
            $"\"{RfcServerFinalBase64}\"\r\n" +
            "OK\r\n");
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(responses);
        var authenticator = new RecordingScramAuthenticator();

        await harness.Client.AuthenticateAsync(
            authenticator, TestContext.Current.CancellationToken);

        Assert.Equal(
            [
                "GetInitialResponse",
                "Respond(server-first)",
                "Respond(server-final)",
                "Complete(null)"
            ],
            authenticator.Calls);
        Assert.Equal(
            [
                Observe(Encoding.UTF8.GetBytes(RfcServerFirst)),
                Observe(Encoding.UTF8.GetBytes(RfcServerFinal))
            ],
            authenticator.ChallengeObservations);
        Assert.Null(authenticator.CompletionObservation);
        AssertTranscriptEqual(
            Encoding.ASCII.GetBytes(RfcClientFirstFrame + RfcClientFinalFrame + "\"\"\r\n"),
            harness.Transport.Written.Span);
        AssertZeroed(authenticator.OwnedBuffers);
        Assert.Equal(ManageSieveSessionState.Authenticated, harness.Client.State);
    }

    [Theory]
    [InlineData("server-no", ManageSieveSessionState.Secured, false)]
    [InlineData("server-bye", ManageSieveSessionState.Disconnected, true)]
    [InlineData("post-write-cancellation", ManageSieveSessionState.Disconnected, true)]
    [InlineData("timeout", ManageSieveSessionState.Disconnected, true)]
    [InlineData("malformed-challenge", ManageSieveSessionState.Disconnected, true)]
    [InlineData("authenticator-failure", ManageSieveSessionState.Disconnected, true)]
    [InlineData("completion-failure", ManageSieveSessionState.Disconnected, true)]
    public async Task ScramAuthentication_failure_state_aborts_and_clears_responses(
        string failureCase,
        ManageSieveSessionState expectedState,
        bool expectedDisposed)
    {
        string outcome = failureCase switch
        {
            "server-no" => "NO (AUTHENTICATIONFAILED \"private\") \"private\"\r\n",
            "server-bye" => "BYE \"private\"\r\n",
            "malformed-challenge" => "\"not-base64!\"\r\n",
            "authenticator-failure" => "\"YmFkLXNlcnZlci1maXJzdA==\"\r\n",
            "completion-failure" =>
                $"\"{RfcServerFirstBase64}\"\r\n" +
                "OK (SASL \"dj1BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE9\")\r\n",
            _ => string.Empty
        };
        bool blocks = failureCase is "post-write-cancellation" or "timeout";
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(
                AuthenticationResponses(outcome),
                blockAfterInput: blocks,
                operationTimeout: failureCase == "timeout"
                    ? TimeSpan.FromMilliseconds(50)
                    : null);
        using var cancellation = new CancellationTokenSource();
        var authenticator = new RecordingScramAuthenticator();

        Task authentication = harness.Client.AuthenticateAsync(
            authenticator, cancellation.Token).AsTask();
        if (failureCase == "post-write-cancellation")
        {
            await harness.Transport.WaitForWriteAsync()
                .WaitAsync(TestContext.Current.CancellationToken);
            cancellation.Cancel();
        }

        Exception? failure = await Record.ExceptionAsync(() => authentication);

        Assert.NotNull(failure);
        AssertScramFailureCategory(failureCase, failure);
        Assert.Equal(expectedState, harness.Client.State);
        Assert.Equal(expectedDisposed, harness.Transport.IsDisposed);
        string[] expectedCalls = failureCase switch
        {
            "authenticator-failure" =>
                ["GetInitialResponse", "Respond(server-first)", "Abort"],
            "completion-failure" =>
                [
                    "GetInitialResponse",
                    "Respond(server-first)",
                    "Complete(server-final)",
                    "Abort"
                ],
            _ => ["GetInitialResponse", "Abort"]
        };
        Assert.Equal(expectedCalls, authenticator.Calls);
        AssertZeroed(authenticator.OwnedBuffers);
    }

    [Fact]
    public async Task ScramAuthentication_redacts_actual_generated_secrets()
    {
        const string password = "password-sentinel-601";
        const string salt = "salt-sentinel-602";
        string serverFirst =
            $"r={RfcServerNonce},s={Base64(salt)},i=4096";
        string[] generatedSecrets =
            await CaptureGeneratedSecretRepresentationsAsync(password, serverFirst);
        string outcome =
            $"\"{Base64(serverFirst)}\"\r\n\"{Base64("e=server-error")}\"\r\n";
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(AuthenticationResponses(outcome));
        var authenticator = new RecordingScramAuthenticator(password);

        Exception? failure = await Record.ExceptionAsync(
            () => harness.Client.AuthenticateAsync(
                authenticator, TestContext.Current.CancellationToken).AsTask());

        var exception = Assert.IsType<ManageSieveAuthenticationException>(failure);
        string[] publicSurfaces =
        [
            exception.Message,
            exception.ToString(),
            exception.InnerException?.ToString() ?? string.Empty,
            exception.ResponseCode ?? string.Empty
        ];
        string[] secrets =
        [
            password,
            Base64(password),
            salt,
            Base64(salt),
            .. generatedSecrets
        ];
        foreach (string surface in publicSurfaces)
        {
            foreach (string secret in secrets)
            {
                Assert.DoesNotContain(secret, surface, StringComparison.Ordinal);
            }
        }

        Assert.Equal("ManageSieve authenticator failed.", exception.Message);
        Assert.Null(exception.InnerException);
        Assert.Null(exception.ResponseCode);

        Assert.Equal(ManageSieveSessionState.Disconnected, harness.Client.State);
        AssertZeroed(authenticator.OwnedBuffers);
    }

    [Fact]
    public async Task ScramAuthentication_extra_challenge_after_final_proof_aborts_exchange()
    {
        string outcome =
            $"\"{RfcServerFirstBase64}\"\r\n" +
            $"\"{RfcServerFinalBase64}\"\r\n" +
            $"\"{RfcServerFinalBase64}\"\r\n";
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(AuthenticationResponses(outcome));
        var authenticator = new RecordingScramAuthenticator();

        var exception = await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
            () => harness.Client.AuthenticateAsync(
                authenticator, TestContext.Current.CancellationToken).AsTask());

        Assert.Equal("ManageSieve authenticator failed.", exception.Message);
        Assert.Equal(
            [
                "GetInitialResponse",
                "Respond(server-first)",
                "Respond(server-final)",
                "Respond(server-final)",
                "Abort"
            ],
            authenticator.Calls);
        Assert.Equal(ManageSieveSessionState.Disconnected, harness.Client.State);
        AssertZeroed(authenticator.OwnedBuffers);
    }

    private static byte[] AuthenticationResponses(string outcome) =>
        Encoding.ASCII.GetBytes(
            "\"SASL\" \"SCRAM-SHA-256\"\r\nOK\r\n" + outcome);

    private static async Task<string[]> CaptureGeneratedSecretRepresentationsAsync(
        string password,
        string serverFirst)
    {
        var exchange = new ScramSha256Exchange(
            "user", password, authorizationIdentity: null, ClientNonce);
        try
        {
            await exchange.GetInitialResponseAsync(TestContext.Current.CancellationToken);
            ReadOnlyMemory<byte> response = await exchange.RespondAsync(
                Encoding.UTF8.GetBytes(serverFirst), TestContext.Current.CancellationToken);
            string clientFinal = Encoding.UTF8.GetString(response.Span);
            int proofStart = clientFinal.LastIndexOf(",p=", StringComparison.Ordinal);
            Assert.True(proofStart >= 0);
            string clientProof = clientFinal[(proofStart + 3)..];
            string serverSignature = Convert.ToBase64String(
                exchange.ExpectedServerSignature.Span);
            string serverFinal = $"v={serverSignature}";

            return
            [
                clientProof,
                clientFinal,
                Base64(clientFinal),
                serverSignature,
                serverFinal,
                Base64(serverFinal)
            ];
        }
        finally
        {
            exchange.Abort();
        }
    }

    private static string Base64(string value) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(value));

    private static void AssertScramFailureCategory(string failureCase, Exception failure)
    {
        switch (failureCase)
        {
            case "post-write-cancellation":
                Assert.IsAssignableFrom<OperationCanceledException>(failure);
                break;
            case "timeout":
                Assert.IsType<TimeoutException>(failure);
                Assert.Equal("ManageSieve authentication timed out.", failure.Message);
                break;
            case "server-bye":
                Assert.IsType<ManageSieveConnectionException>(failure);
                break;
            case "malformed-challenge":
                Assert.IsType<ManageSieveProtocolException>(failure);
                break;
            case "server-no":
                var rejection = Assert.IsType<ManageSieveAuthenticationException>(failure);
                Assert.Equal("ManageSieve authentication failed.", rejection.Message);
                Assert.Equal("AUTHENTICATIONFAILED", rejection.ResponseCode);
                break;
            default:
                Assert.IsType<ManageSieveAuthenticationException>(failure);
                Assert.Equal("ManageSieve authenticator failed.", failure.Message);
                break;
        }
    }

    private sealed class RecordingScramAuthenticator : IManageSieveAuthenticator
    {
        private readonly ManageSieveScramSha256Authenticator inner;
        private int responseCount;

        public RecordingScramAuthenticator(string password = "pencil")
        {
            inner = new ManageSieveScramSha256Authenticator(
                new SaslScramSha256Authenticator(
                    "user", password, authorizationIdentity: null,
                    nonceFactory: () => ClientNonce));
        }

        public string Mechanism => inner.Mechanism;

        public List<string> Calls { get; } = [];

        public List<SaslBufferObservation> ChallengeObservations { get; } = [];

        public List<ReadOnlyMemory<byte>> OwnedBuffers { get; } = [];

        public SaslBufferObservation? CompletionObservation { get; private set; }

        public async ValueTask<ReadOnlyMemory<byte>?> GetInitialResponseAsync(
            CancellationToken cancellationToken = default)
        {
            Calls.Add("GetInitialResponse");
            ReadOnlyMemory<byte>? response = await inner.GetInitialResponseAsync(cancellationToken);
            if (response.HasValue)
            {
                OwnedBuffers.Add(response.Value);
            }

            return response;
        }

        public async ValueTask<ReadOnlyMemory<byte>> RespondAsync(
            ReadOnlyMemory<byte> challenge,
            CancellationToken cancellationToken = default)
        {
            Calls.Add(responseCount++ == 0
                ? "Respond(server-first)"
                : "Respond(server-final)");
            ChallengeObservations.Add(Observe(challenge.Span));
            ReadOnlyMemory<byte> response = await inner.RespondAsync(challenge, cancellationToken);
            OwnedBuffers.Add(response);
            return response;
        }

        public async ValueTask CompleteAsync(
            ReadOnlyMemory<byte>? serverData,
            CancellationToken cancellationToken = default)
        {
            Calls.Add(serverData.HasValue ? "Complete(server-final)" : "Complete(null)");
            CompletionObservation = serverData.HasValue ? Observe(serverData.Value.Span) : null;
            await inner.CompleteAsync(serverData, cancellationToken);
        }

        public void Abort()
        {
            Calls.Add("Abort");
            inner.Abort();
        }
    }
}
