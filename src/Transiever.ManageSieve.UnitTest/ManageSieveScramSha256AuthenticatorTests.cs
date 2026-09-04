using System.Text;
using Transiever.ManageSieve.Authentication;
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
    private const string ServerNonce = ClientNonce + "Server";
    private const string AuthenticationFailure = "SCRAM-SHA-256 authentication failed.";

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

    [Fact]
    public async Task ScramAuthentication_duplicate_completion_is_rejected_and_remains_cleared()
    {
        ScramSha256Exchange exchange = await CreateProofSentExchangeAsync();
        await exchange.CompleteAsync(
            Encoding.UTF8.GetBytes(RfcServerFinal), TestContext.Current.CancellationToken);

        ManageSieveAuthenticationException exception =
            await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
                () => exchange.CompleteAsync(
                    Encoding.UTF8.GetBytes(RfcServerFinal),
                    TestContext.Current.CancellationToken).AsTask());

        Assert.Equal(AuthenticationFailure, exception.Message);
        Assert.Empty(exchange.Salt.ToArray());
        Assert.Empty(exchange.ExpectedServerSignature.ToArray());
    }

    [Theory]
    [InlineData("abort")]
    [InlineData("successful-completion")]
    [InlineData("failed-completion")]
    public async Task ScramAuthentication_lifecycle_clears_every_retained_mutable_buffer(
        string lifecycle)
    {
        var exchange = new ScramSha256Exchange(
            "user", "pencil", authorizationIdentity: null, ClientNonce);
        ReadOnlyMemory<byte> initial = Assert.IsType<ReadOnlyMemory<byte>>(
            await exchange.GetInitialResponseAsync(TestContext.Current.CancellationToken));
        ReadOnlyMemory<byte> proof = await exchange.RespondAsync(
            Encoding.UTF8.GetBytes(RfcServerFirst), TestContext.Current.CancellationToken);
        ReadOnlyMemory<byte> salt = exchange.Salt;
        ReadOnlyMemory<byte> signature = exchange.ExpectedServerSignature;

        Assert.True(proof.Span.IndexOfAnyExcept((byte)0) >= 0);
        Assert.True(salt.Span.IndexOfAnyExcept((byte)0) >= 0);
        Assert.True(signature.Span.IndexOfAnyExcept((byte)0) >= 0);

        if (lifecycle == "abort")
        {
            exchange.Abort();
        }
        else
        {
            string final = lifecycle == "successful-completion"
                ? RfcServerFinal
                : "v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
            Exception? failure = await Record.ExceptionAsync(
                () => exchange.CompleteAsync(
                    Encoding.UTF8.GetBytes(final),
                    TestContext.Current.CancellationToken).AsTask());
            if (lifecycle == "failed-completion")
            {
                Assert.IsType<ManageSieveAuthenticationException>(failure);
            }
            else
            {
                Assert.Null(failure);
            }
        }

        AssertZeroed([initial, proof, salt, signature]);
    }

    [Fact]
    public async Task Exposes_scram_sha256_and_emits_client_first_message()
    {
        var authenticator = new ManageSieveScramSha256Authenticator(
            "user", "pencil", authorizationIdentity: null,
            nonceFactory: () => "rOprNGfwEbeRWgbNEkqO");

        Assert.Equal("SCRAM-SHA-256", authenticator.Mechanism);
        Assert.False(authenticator.AllowsUnprotectedConnection);

        ReadOnlyMemory<byte>? initial = await authenticator.GetInitialResponseAsync(
            TestContext.Current.CancellationToken);

        Assert.Equal("n,,n=user,r=rOprNGfwEbeRWgbNEkqO"u8.ToArray(), initial?.ToArray());
    }

    [Fact]
    public async Task ScramAuthentication_proof_binds_escaped_authorization_identity()
    {
        var authenticator = new ManageSieveScramSha256Authenticator(
            "us,er", "pencil", "auth=z,id",
            () => ClientNonce);

        ReadOnlyMemory<byte>? initial = await authenticator.GetInitialResponseAsync(
            TestContext.Current.CancellationToken);
        Assert.Equal(
            "n,a=auth=3Dz=2Cid,n=us=2Cer,r=rOprNGfwEbeRWgbNEkqO"u8.ToArray(),
            initial?.ToArray());

        ReadOnlyMemory<byte> response = await authenticator.RespondAsync(
            Encoding.UTF8.GetBytes(RfcServerFirst), TestContext.Current.CancellationToken);
        Assert.Equal(
            Encoding.UTF8.GetBytes(
                $"c=bixhPWF1dGg9M0R6PTJDaWQs,r={RfcServerNonce},p=zjLyhMiy6yjGzv1j0M7/XkeQbzxfTn5nPqLonAuPQx4="),
            response.ToArray());
        await authenticator.CompleteAsync(
            "v=o9eVJzPc0YzYYbZT0QPeSqyg0sB9Y8V5wKQ06nb/iJA="u8.ToArray(),
            TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task Empty_authorization_identity_is_omitted()
    {
        var authenticator = new ManageSieveScramSha256Authenticator(
            "user", "pencil", string.Empty, () => ClientNonce);

        ReadOnlyMemory<byte>? initial = await authenticator.GetInitialResponseAsync(
            TestContext.Current.CancellationToken);

        Assert.Equal(
            "n,,n=user,r=rOprNGfwEbeRWgbNEkqO"u8.ToArray(),
            initial?.ToArray());
    }

    [Fact]
    public void Accepts_empty_password_and_1024_byte_inputs()
    {
        string value = new('a', 1024);

        var authenticator = new ManageSieveScramSha256Authenticator(value, string.Empty, value,
            () => "nonce");

        Assert.NotNull(authenticator);
    }

    [Fact]
    public void Rejects_null_or_empty_user()
    {
        Assert.Throws<ArgumentNullException>(() => new ManageSieveScramSha256Authenticator(null!, "p"));
        Assert.Throws<ArgumentException>(() => new ManageSieveScramSha256Authenticator(string.Empty, "p"));
    }

    [Fact]
    public void Rejects_non_ascii_control_and_oversized_credentials()
    {
        Assert.Throws<ArgumentException>(() => new ManageSieveScramSha256Authenticator("us\u00e9r", "p"));
        Assert.Throws<ArgumentException>(() => new ManageSieveScramSha256Authenticator("us\n er", "p"));
        Assert.Throws<ArgumentException>(() => new ManageSieveScramSha256Authenticator(new string('a', 1025), "p"));
        Assert.Throws<ArgumentException>(() => new ManageSieveScramSha256Authenticator("u", new string('a', 1025)));
        Assert.Throws<ArgumentException>(() => new ManageSieveScramSha256Authenticator("u", "p", new string('a', 1025)));
    }

    [Fact]
    public void Rejects_invalid_nonce_factory_output()
    {
        Assert.Throws<ArgumentException>(() => new ManageSieveScramSha256Authenticator(
            "u", "p", authorizationIdentity: null, nonceFactory: () => string.Empty));
        Assert.Throws<ArgumentException>(() => new ManageSieveScramSha256Authenticator(
            "u", "p", authorizationIdentity: null, nonceFactory: () => new string('a', 257)));
        Assert.Throws<ArgumentException>(() => new ManageSieveScramSha256Authenticator(
            "u", "p", authorizationIdentity: null, nonceFactory: () => "non,ce"));
    }

    [Fact]
    public async Task Clears_initial_response_when_completion_is_cancelled()
    {
        var authenticator = new ManageSieveScramSha256Authenticator(
            "u", "p", authorizationIdentity: null, nonceFactory: () => "nonce");
        ReadOnlyMemory<byte> response = Assert.IsType<ReadOnlyMemory<byte>>(
            await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken));
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(
            () => authenticator.CompleteAsync(null, cancellation.Token).AsTask());

        Assert.All(response.ToArray(), value => Assert.Equal(0, value));
    }

    [Theory]
    [InlineData("r=" + ServerNonce + ",s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,x=extension")]
    [InlineData("r=" + ServerNonce + ",s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,x=a=b")]
    public async Task ScramServerFirst_accepts_ordered_fields_and_optional_extensions(string message)
    {
        ManageSieveScramSha256Authenticator authenticator = await CreateStartedAuthenticatorAsync();

        ReadOnlyMemory<byte> response = await authenticator.RespondAsync(
            Encoding.UTF8.GetBytes(message), TestContext.Current.CancellationToken);

        AssertClientFinal(response, ServerNonce);
    }

    [Theory]
    [InlineData('a')]
    [InlineData('c')]
    [InlineData('e')]
    [InlineData('n')]
    [InlineData('p')]
    [InlineData('v')]
    public async Task ScramServerFirst_rejects_assigned_attribute_as_extension(char name)
    {
        await AssertRejectedAsync(ServerFirst(extension: $"{name}=value"));
    }

    [Theory]
    [InlineData("s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")]
    [InlineData("r=" + ServerNonce + ",i=4096")]
    [InlineData("r=" + ServerNonce + ",s=W22ZaJ0SNY7soEsUEjb6gQ==")]
    [InlineData("s=W22ZaJ0SNY7soEsUEjb6gQ==,r=" + ServerNonce + ",i=4096")]
    [InlineData("r=" + ServerNonce + ",i=4096,s=W22ZaJ0SNY7soEsUEjb6gQ==")]
    [InlineData("r=" + ServerNonce + ",s=W22ZaJ0SNY7soEsUEjb6gQ==,r=again,i=4096")]
    [InlineData("r=" + ServerNonce + ",s=W22ZaJ0SNY7soEsUEjb6gQ==,s=YQ==,i=4096")]
    [InlineData("r=" + ServerNonce + ",s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,i=4097")]
    [InlineData("m=required,r=" + ServerNonce + ",s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")]
    [InlineData("r=" + ServerNonce + ",s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,")]
    [InlineData("r=" + ServerNonce + ",s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,x=")]
    [InlineData("r=" + ServerNonce + ",s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,xx=value")]
    [InlineData("r=" + ServerNonce + ",s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,x=\0")]
    public async Task ScramServerFirst_rejects_missing_reordered_duplicate_or_invalid_attributes(
        string message)
    {
        await AssertRejectedAsync(Encoding.UTF8.GetBytes(message));
    }

    [Theory]
    [InlineData("r=wrongServer,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")]
    [InlineData("r=" + ClientNonce + ",s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")]
    [InlineData("r=" + ClientNonce + " server,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")]
    [InlineData("r=" + ClientNonce + ",server,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")]
    public async Task ScramBounds_rejects_invalid_server_nonce(string message)
    {
        await AssertRejectedAsync(Encoding.UTF8.GetBytes(message));
    }

    [Fact]
    public async Task ScramBounds_accepts_256_byte_server_nonce_and_rejects_257_bytes()
    {
        string maximumNonce = ClientNonce + new string('a', 256 - ClientNonce.Length);
        ManageSieveScramSha256Authenticator authenticator = await CreateStartedAuthenticatorAsync();

        ReadOnlyMemory<byte> response = await authenticator.RespondAsync(
            ServerFirst(nonce: maximumNonce), TestContext.Current.CancellationToken);

        AssertClientFinal(response, maximumNonce);
        await AssertRejectedAsync(ServerFirst(nonce: maximumNonce + "a"));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(4095)]
    [InlineData(1_000_001)]
    public async Task ScramBounds_rejects_iterations_outside_allowed_range(int iterations)
    {
        await AssertRejectedAsync(ServerFirst(iterations: iterations));
    }

    [Fact]
    public async Task ScramBounds_rejects_overflowing_iterations()
    {
        await AssertRejectedAsync(ServerFirst(iterations: "2147483648"));
    }

    [Theory]
    [InlineData(4096)]
    [InlineData(1_000_000)]
    public async Task ScramBounds_accepts_iteration_boundaries(int iterations)
    {
        ManageSieveScramSha256Authenticator authenticator = await CreateStartedAuthenticatorAsync();

        ReadOnlyMemory<byte> response = await authenticator.RespondAsync(
            ServerFirst(iterations: iterations), TestContext.Current.CancellationToken);

        AssertClientFinal(response, ServerNonce);
    }

    [Theory]
    [InlineData("")]
    [InlineData("YQ")]
    [InlineData("YQ== ")]
    [InlineData("A===")]
    [InlineData("AB==")]
    public async Task ScramBounds_rejects_empty_invalid_or_noncanonical_salt(string salt)
    {
        await AssertRejectedAsync(ServerFirst(salt: salt));
    }

    [Fact]
    public async Task ScramBounds_accepts_1024_byte_salt_and_rejects_1025_bytes()
    {
        ManageSieveScramSha256Authenticator authenticator = await CreateStartedAuthenticatorAsync();
        string maximumSalt = Convert.ToBase64String(new byte[1024]);

        ReadOnlyMemory<byte> response = await authenticator.RespondAsync(
            ServerFirst(salt: maximumSalt), TestContext.Current.CancellationToken);

        AssertClientFinal(response, ServerNonce);
        await AssertRejectedAsync(ServerFirst(salt: Convert.ToBase64String(new byte[1025])));
    }

    [Fact]
    public async Task ScramBounds_accepts_16384_byte_message_and_rejects_larger_or_empty_messages()
    {
        byte[] prefix = ServerFirst(extension: "x=");
        byte[] maximumMessage = [.. prefix, .. Enumerable.Repeat((byte)'a', 16_384 - prefix.Length)];
        ManageSieveScramSha256Authenticator authenticator = await CreateStartedAuthenticatorAsync();

        ReadOnlyMemory<byte> response = await authenticator.RespondAsync(
            maximumMessage, TestContext.Current.CancellationToken);

        AssertClientFinal(response, ServerNonce);
        await AssertRejectedAsync([]);
        await AssertRejectedAsync([.. maximumMessage, (byte)'a']);
    }

    [Fact]
    public async Task ScramServerFirst_rejects_invalid_utf8_without_exposing_input()
    {
        await AssertRejectedAsync([0xff, 0xfe, 0xfd]);
    }

    [Fact]
    public async Task ScramServerFirst_accepts_and_proof_binds_exact_utf8_extension()
    {
        const string serverFirst =
            "r=" + ServerNonce + ",s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,x=é";
        var authenticator = new ManageSieveScramSha256Authenticator(
            "user", "pencil", authorizationIdentity: null, nonceFactory: () => ClientNonce);
        await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken);

        ReadOnlyMemory<byte> response = await authenticator.RespondAsync(
            Encoding.UTF8.GetBytes(serverFirst), TestContext.Current.CancellationToken);

        Assert.Equal(
            Encoding.UTF8.GetBytes(
                $"c=biws,r={ServerNonce},p=W6AWKbhF7tToriNf6+aklK1X01jrmofSWRuZriAkKgw="),
            response.ToArray());
        await authenticator.CompleteAsync(
            "v=Qx9uUGotirsTyGWrdH8yJIaq1VzSsEmVPgi8/1RNRJo="u8.ToArray(),
            TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task ScramServerFinal_accepts_signature_with_optional_extensions()
    {
        ManageSieveScramSha256Authenticator authenticator =
            await CreateProofSentAuthenticatorAsync();

        await authenticator.CompleteAsync(
            "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=,x=extension,y=é"u8.ToArray(),
            TestContext.Current.CancellationToken);
    }

    [Theory]
    [InlineData("v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")]
    [InlineData("x=extension")]
    [InlineData("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=,v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")]
    [InlineData("v=not-base64")]
    [InlineData("v=AB==")]
    [InlineData("v=YQ==")]
    [InlineData("e=server-private-error")]
    public async Task ScramServerFinal_rejects_wrong_missing_duplicate_malformed_or_error(
        string message)
    {
        ManageSieveScramSha256Authenticator authenticator =
            await CreateProofSentAuthenticatorAsync();

        ManageSieveAuthenticationException exception =
            await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
                () => authenticator.CompleteAsync(
                    Encoding.UTF8.GetBytes(message),
                    TestContext.Current.CancellationToken).AsTask());

        Assert.Equal(AuthenticationFailure, exception.Message);
        Assert.Null(exception.InnerException);
        Assert.DoesNotContain(message, exception.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ScramServerFinal_rejects_empty_completion_before_final_challenge()
    {
        ManageSieveScramSha256Authenticator authenticator =
            await CreateProofSentAuthenticatorAsync();

        ManageSieveAuthenticationException exception =
            await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
                () => authenticator.CompleteAsync(
                    null, TestContext.Current.CancellationToken).AsTask());

        Assert.Equal(AuthenticationFailure, exception.Message);
        Assert.Null(exception.InnerException);
    }

    [Theory]
    [InlineData('p')]
    [InlineData('r')]
    [InlineData('s')]
    [InlineData('i')]
    [InlineData('c')]
    [InlineData('n')]
    [InlineData('a')]
    [InlineData('e')]
    [InlineData('m')]
    [InlineData('v')]
    public async Task ScramServerFinal_rejects_reserved_attribute_as_extension(char name)
    {
        ManageSieveScramSha256Authenticator authenticator =
            await CreateProofSentAuthenticatorAsync();

        ManageSieveAuthenticationException exception =
            await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
                () => authenticator.CompleteAsync(
                    Encoding.UTF8.GetBytes(
                        $"v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=,{name}=x"),
                    TestContext.Current.CancellationToken).AsTask());

        Assert.Equal(AuthenticationFailure, exception.Message);
    }

    [Fact]
    public async Task ScramState_duplicate_initial_response_poisons_exchange()
    {
        ManageSieveScramSha256Authenticator authenticator =
            await CreateStartedAuthenticatorAsync();

        await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
            () => authenticator.GetInitialResponseAsync(
                TestContext.Current.CancellationToken).AsTask());

        await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
            () => authenticator.RespondAsync(
                ServerFirst(), TestContext.Current.CancellationToken).AsTask());
    }

    [Fact]
    public async Task ScramState_extra_challenge_poisons_pending_completion()
    {
        ManageSieveScramSha256Authenticator authenticator =
            await CreateProofSentAuthenticatorAsync();
        await authenticator.RespondAsync(
            "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="u8.ToArray(),
            TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
            () => authenticator.RespondAsync(
                "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="u8.ToArray(),
                TestContext.Current.CancellationToken).AsTask());

        await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
            () => authenticator.CompleteAsync(
                null, TestContext.Current.CancellationToken).AsTask());
    }

    [Fact]
    public async Task ScramState_premature_completion_poisons_exchange()
    {
        var authenticator = new ManageSieveScramSha256Authenticator(
            "user", "pencil", authorizationIdentity: null, nonceFactory: () => ClientNonce);

        await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
            () => authenticator.CompleteAsync(
                null, TestContext.Current.CancellationToken).AsTask());

        await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
            () => authenticator.GetInitialResponseAsync(
                TestContext.Current.CancellationToken).AsTask());
    }

    [Fact]
    public async Task ScramServerFirst_rejects_a_second_server_first_message()
    {
        ManageSieveScramSha256Authenticator authenticator = await CreateStartedAuthenticatorAsync();
        await authenticator.RespondAsync(
            ServerFirst(), TestContext.Current.CancellationToken);

        ManageSieveAuthenticationException exception =
            await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
                () => authenticator.RespondAsync(
                    ServerFirst(), TestContext.Current.CancellationToken).AsTask());

        Assert.Equal(AuthenticationFailure, exception.Message);
    }

    private static async Task<ManageSieveScramSha256Authenticator> CreateStartedAuthenticatorAsync()
    {
        var authenticator = new ManageSieveScramSha256Authenticator(
            "user", "pencil", authorizationIdentity: null, nonceFactory: () => ClientNonce);
        await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken);
        return authenticator;
    }

    private static async Task<ManageSieveScramSha256Authenticator> CreateProofSentAuthenticatorAsync()
    {
        const string serverNonce =
            ClientNonce + "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
        ManageSieveScramSha256Authenticator authenticator =
            await CreateStartedAuthenticatorAsync();
        await authenticator.RespondAsync(
            ServerFirst(nonce: serverNonce), TestContext.Current.CancellationToken);
        return authenticator;
    }

    private static async Task<ScramSha256Exchange> CreateProofSentExchangeAsync()
    {
        var exchange = new ScramSha256Exchange(
            "user", "pencil", authorizationIdentity: null, ClientNonce);
        await exchange.GetInitialResponseAsync(TestContext.Current.CancellationToken);
        await exchange.RespondAsync(
            Encoding.UTF8.GetBytes(RfcServerFirst), TestContext.Current.CancellationToken);
        return exchange;
    }

    private static byte[] ServerFirst(
        string salt = "W22ZaJ0SNY7soEsUEjb6gQ==",
        int iterations = 4096,
        string? extension = null,
        string nonce = ServerNonce) =>
        ServerFirst(salt, iterations.ToString(System.Globalization.CultureInfo.InvariantCulture), extension, nonce);

    private static byte[] ServerFirst(string iterations) =>
        ServerFirst("W22ZaJ0SNY7soEsUEjb6gQ==", iterations, extension: null, ServerNonce);

    private static byte[] ServerFirst(
        string salt, string iterations, string? extension, string nonce) =>
        Encoding.UTF8.GetBytes(
            $"r={nonce},s={salt},i={iterations}{(extension is null ? string.Empty : $",{extension}")}");

    private static async Task AssertRejectedAsync(byte[] message)
    {
        ManageSieveScramSha256Authenticator authenticator = await CreateStartedAuthenticatorAsync();

        ManageSieveAuthenticationException exception =
            await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
                () => authenticator.RespondAsync(
                    message, TestContext.Current.CancellationToken).AsTask());

        Assert.Equal(AuthenticationFailure, exception.Message);
        Assert.Null(exception.InnerException);
        if (message.Length > 0)
        {
            Assert.DoesNotContain(
                Encoding.UTF8.GetString(message), exception.ToString(), StringComparison.Ordinal);
        }
    }

    private static void AssertClientFinal(ReadOnlyMemory<byte> response, string nonce)
    {
        string value = Encoding.UTF8.GetString(response.Span);
        string prefix = $"c=biws,r={nonce},p=";
        Assert.StartsWith(prefix, value, StringComparison.Ordinal);
        Assert.Equal(32, Convert.FromBase64String(value[prefix.Length..]).Length);
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
                "user", password, authorizationIdentity: null, nonceFactory: () => ClientNonce);
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
