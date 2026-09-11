using System.Text;
using static Transiever.ManageSieve.UnitTest.SaslConformanceHarness;

namespace Transiever.ManageSieve.UnitTest;

public sealed class ManageSieveOAuthBearerAuthenticatorTests
{
    private const string RfcToken = "vF9dft4qmTc2Nvb3RlckBhbHRhdmlzdGEuY29tCg==";
    private const string RfcInitialBase64 =
        "bixhPXVzZXJAZXhhbXBsZS5jb20sAWhvc3Q9c2VydmVyLmV4YW1wbGUuY29tAXBvcnQ9NDE5MAFhdXRoPUJlYXJlciB2RjlkZnQ0cW1UYzJOdmIzUmxja0JoYkhSaGRtbHpkR0V1WTI5dENnPT0BAQ==";
    private const string ValidErrorBase64 =
        "eyJzdGF0dXMiOiJpbnZhbGlkX3Rva2VuIiwic2NvcGUiOiJleGFtcGxlX3Njb3BlIiwib3BlbmlkLWNvbmZpZ3VyYXRpb24iOiJodHRwczovL2V4YW1wbGUuY29tLy53ZWxsLWtub3duL29wZW5pZC1jb25maWd1cmF0aW9uIn0=";

    [Fact]
    public async Task OAuthBearerAuthentication_success_uses_exact_initial_response_and_completes()
    {
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(
                "\"SASL\" \"OAUTHBEARER\"\r\nOK\r\nOK\r\n"u8.ToArray());
        var authenticator = NewRecordingAuthenticator();

        await harness.Client.AuthenticateAsync(
            authenticator,
            TestContext.Current.CancellationToken);

        Assert.Equal(RfcInitialBytes, authenticator.InitialCopy);
        AssertTranscriptEqual(
            Encoding.ASCII.GetBytes(
                $"AUTHENTICATE \"OAUTHBEARER\" \"{RfcInitialBase64}\"\r\n"),
            harness.Transport.Written.Span);
        Assert.Equal(
            ["GetInitialResponseAsync", "CompleteAsync(null)"],
            authenticator.Calls);
        Assert.Equal(ManageSieveSessionState.Authenticated, harness.Client.State);
        Assert.Null(authenticator.ServerError);
        AssertZeroed(harness.Transport.OriginalSensitiveWrites);
        AssertZeroed([authenticator.InitialMemory!.Value]);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task OAuthBearerAuthentication_writes_complete_initial_frame_for_null_and_empty_authorization_identity(
        string? authorizationIdentity)
    {
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(
                "\"SASL\" \"OAUTHBEARER\"\r\nOK\r\nOK\r\n"u8.ToArray());
        var authenticator = new ManageSieveOAuthBearerAuthenticator(
            RfcToken,
            "server.example.com",
            4190,
            authorizationIdentity);

        await harness.Client.AuthenticateAsync(
            authenticator,
            TestContext.Current.CancellationToken);

        byte[] expectedDecoded =
            "n,,\u0001host=server.example.com\u0001port=4190\u0001auth=Bearer vF9dft4qmTc2Nvb3RlckBhbHRhdmlzdGEuY29tCg==\u0001\u0001"u8.ToArray();
        string expectedEncoded = Convert.ToBase64String(expectedDecoded);
        SaslConformanceHarness.AssertTranscriptEqual(
            Encoding.ASCII.GetBytes(
                $"AUTHENTICATE \"OAUTHBEARER\" \"{expectedEncoded}\"\r\n"),
            harness.Transport.Written.Span);

        string actualEncoded =
            Encoding.ASCII.GetString(harness.Transport.Written.Span).Split('\"')[3];
        Assert.Equal(expectedDecoded, Convert.FromBase64String(actualEncoded));
        Assert.Equal(ManageSieveSessionState.Authenticated, harness.Client.State);
    }

    [Fact]
    public async Task OAuthBearerAuthentication_valid_base64_malformed_json_fails_safely_and_clears_owned_buffers()
    {
        string encodedChallenge =
            Convert.ToBase64String("{\"status\":}"u8.ToArray());
        byte[] responses = Encoding.ASCII.GetBytes(
            "\"SASL\" \"OAUTHBEARER\"\r\nOK\r\n" +
            $"\"{encodedChallenge}\"\r\n");
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(responses);
        var authenticator = NewRecordingAuthenticator();

        ManageSieveAuthenticationException exception =
            await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
                () => harness.Client.AuthenticateAsync(
                    authenticator,
                    TestContext.Current.CancellationToken).AsTask());

        Assert.Equal("ManageSieve authenticator failed.", exception.Message);
        Assert.Null(exception.InnerException);
        Assert.Equal(
            ["GetInitialResponseAsync", "RespondAsync", "Abort"],
            authenticator.Calls);
        Assert.Equal(1, authenticator.AbortCount);
        Assert.Null(authenticator.ServerError);
        Assert.Equal(ManageSieveSessionState.Disconnected, harness.Client.State);
        Assert.Null(harness.Client.Capabilities);
        Assert.True(harness.Transport.IsDisposed);
        AssertZeroed(harness.Transport.OriginalSensitiveWrites);
        AssertZeroed(
            [
                authenticator.InitialMemory!.Value,
                authenticator.ChallengeMemory!.Value
            ]);
    }

    [Fact]
    public async Task OAuthBearerAuthentication_valid_error_writes_dummy_and_preserves_secured_session()
    {
        byte[] responses = Encoding.ASCII.GetBytes(
            "\"IMPLEMENTATION\" \"baseline\"\r\n\"SASL\" \"OAUTHBEARER\"\r\nOK\r\n" +
            $"\"{ValidErrorBase64}\"\r\n" +
            "NO (AUTHENTICATIONFAILED)\r\n");
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(responses);
        var authenticator = NewRecordingAuthenticator();

        ManageSieveAuthenticationException exception =
            await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
                () => harness.Client.AuthenticateAsync(
                    authenticator,
                    TestContext.Current.CancellationToken).AsTask());

        Assert.Equal("ManageSieve authentication failed.", exception.Message);
        Assert.Equal("AUTHENTICATIONFAILED", exception.ResponseCode);
        Assert.Equal(
            new ManageSieveOAuthBearerError(
                "invalid_token",
                "example_scope",
                "https://example.com/.well-known/openid-configuration"),
            authenticator.ServerError);
        Assert.Equal(
            ["GetInitialResponseAsync", "RespondAsync", "Abort"],
            authenticator.Calls);
        Assert.Equal(1, authenticator.AbortCount);
        Assert.Equal(Convert.FromBase64String(ValidErrorBase64), authenticator.ChallengeCopy);
        Assert.Equal(new byte[] { 0x01 }, authenticator.DummyCopy);
        AssertTranscriptEqual(
            Encoding.ASCII.GetBytes(
                $"AUTHENTICATE \"OAUTHBEARER\" \"{RfcInitialBase64}\"\r\n\"AQ==\"\r\n"),
            harness.Transport.Written.Span);
        Assert.Equal(ManageSieveSessionState.Secured, harness.Client.State);
        Assert.Equal("baseline", harness.Client.Capabilities?.Implementation);
        Assert.False(harness.Transport.IsDisposed);
        AssertZeroed(harness.Transport.OriginalSensitiveWrites);
        AssertZeroed(
            [
                authenticator.InitialMemory!.Value,
                authenticator.ChallengeMemory!.Value,
                authenticator.DummyMemory!.Value
            ]);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task OAuthBearerAuthentication_preconditions_preserve_state_without_callbacks_or_wire(
        bool plaintext)
    {
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(
                plaintext
                    ? "\"IMPLEMENTATION\" \"baseline\"\r\n\"SASL\" \"OAUTHBEARER\"\r\nOK\r\n"u8.ToArray()
                    : "\"IMPLEMENTATION\" \"baseline\"\r\n\"SASL\" \"PLAIN\"\r\nOK\r\n"u8.ToArray(),
                plaintext
                    ? ManageSieveSecurityMode.PlainText
                    : ManageSieveSecurityMode.ImplicitTls,
                secure: !plaintext);
        var authenticator = NewRecordingAuthenticator();

        Exception? failure = await Record.ExceptionAsync(
            () => harness.Client.AuthenticateAsync(
                authenticator,
                TestContext.Current.CancellationToken).AsTask());

        if (plaintext)
        {
            Assert.IsType<InvalidOperationException>(failure);
            Assert.Equal(ManageSieveSessionState.Connected, harness.Client.State);
        }
        else
        {
            Assert.IsType<ManageSieveAuthenticationException>(failure);
            Assert.Equal(ManageSieveSessionState.Secured, harness.Client.State);
        }

        Assert.Empty(authenticator.Calls);
        Assert.True(harness.Transport.Written.IsEmpty);
        Assert.Equal("baseline", harness.Client.Capabilities?.Implementation);
        Assert.False(harness.Transport.IsDisposed);
    }

    [Fact]
    public async Task OAuthBearerAuthentication_uses_post_starttls_advertisement()
    {
        byte[] responses = Encoding.ASCII.GetBytes(
            "\"STARTTLS\"\r\n\"SASL\" \"OAUTHBEARER\"\r\nOK\r\n" +
            "OK\r\n" +
            "\"IMPLEMENTATION\" \"protected\"\r\n\"SASL\" \"PLAIN\"\r\nOK\r\n");
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(
                responses,
                ManageSieveSecurityMode.StartTlsRequired,
                secure: false);
        var authenticator = NewRecordingAuthenticator();

        await harness.Client.StartTlsAsync(TestContext.Current.CancellationToken);
        await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
            () => harness.Client.AuthenticateAsync(
                authenticator,
                TestContext.Current.CancellationToken).AsTask());

        Assert.Empty(authenticator.Calls);
        AssertTranscriptEqual("STARTTLS\r\n"u8, harness.Transport.Written.Span);
        Assert.Equal(ManageSieveSessionState.Secured, harness.Client.State);
        Assert.Equal("protected", harness.Client.Capabilities?.Implementation);
        Assert.False(harness.Transport.IsDisposed);
    }

    [Fact]
    public async Task OAuthBearerAuthentication_accepts_mechanism_advertised_only_after_starttls()
    {
        byte[] responses = Encoding.ASCII.GetBytes(
            "\"STARTTLS\"\r\n\"SASL\" \"PLAIN\"\r\nOK\r\n" +
            "OK\r\n" +
            "\"SASL\" \"OAUTHBEARER\"\r\nOK\r\n" +
            "OK\r\n");
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(
                responses,
                ManageSieveSecurityMode.StartTlsRequired,
                secure: false);
        var authenticator = NewRecordingAuthenticator();

        await harness.Client.StartTlsAsync(TestContext.Current.CancellationToken);
        await harness.Client.AuthenticateAsync(
            authenticator,
            TestContext.Current.CancellationToken);

        Assert.Equal(
            ["GetInitialResponseAsync", "CompleteAsync(null)"],
            authenticator.Calls);
        AssertTranscriptEqual(
            Encoding.ASCII.GetBytes(
                $"STARTTLS\r\nAUTHENTICATE \"OAUTHBEARER\" \"{RfcInitialBase64}\"\r\n"),
            harness.Transport.Written.Span);
        Assert.Equal(ManageSieveSessionState.Authenticated, harness.Client.State);
    }

    [Fact]
    public async Task OAuthBearerAuthentication_prewrite_cancellation_leaves_transport_usable()
    {
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(
                "\"SASL\" \"OAUTHBEARER\"\r\nOK\r\nOK\r\n"u8.ToArray());
        var cancelledAuthenticator = NewRecordingAuthenticator();
        using var cancellation = new CancellationTokenSource();
        cancelledAuthenticator.InitialResponseReturning = cancellation.Cancel;

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => harness.Client.AuthenticateAsync(
                cancelledAuthenticator,
                cancellation.Token).AsTask());

        Assert.Equal(
            ["GetInitialResponseAsync", "Abort"],
            cancelledAuthenticator.Calls);
        Assert.Equal(1, cancelledAuthenticator.AbortCount);
        Assert.True(harness.Transport.Written.IsEmpty);
        Assert.Equal(ManageSieveSessionState.Secured, harness.Client.State);
        Assert.False(harness.Transport.IsDisposed);
        AssertZeroed([cancelledAuthenticator.InitialMemory!.Value]);

        var retryAuthenticator = NewRecordingAuthenticator();
        await harness.Client.AuthenticateAsync(
            retryAuthenticator,
            TestContext.Current.CancellationToken);

        Assert.Equal(
            ["GetInitialResponseAsync", "CompleteAsync(null)"],
            retryAuthenticator.Calls);
        Assert.Equal(ManageSieveSessionState.Authenticated, harness.Client.State);
    }

    [Theory]
    [InlineData("server-bye")]
    [InlineData("caller-after-write")]
    [InlineData("timeout-after-write")]
    [InlineData("malformed-challenge")]
    [InlineData("invalid-completion")]
    [InlineData("cleanup-failure")]
    public async Task OAuthBearerAuthentication_indeterminate_failures_disconnect(
        string failureCase)
    {
        string outcome = failureCase switch
        {
            "server-bye" or "cleanup-failure" => "BYE \"unsafe detail\"\r\n",
            "malformed-challenge" => "\"not-base64!\"\r\n",
            "invalid-completion" => "OK (SASL \"c2VydmVyLWZpbmFs\")\r\n",
            _ => string.Empty
        };
        byte[] responses = Encoding.ASCII.GetBytes(
            "\"IMPLEMENTATION\" \"baseline\"\r\n\"SASL\" \"OAUTHBEARER\"\r\nOK\r\n" + outcome);
        bool waitsAfterWrite = failureCase is "caller-after-write" or "timeout-after-write";
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(
                responses,
                blockAfterInput: waitsAfterWrite,
                operationTimeout: failureCase == "timeout-after-write"
                    ? TimeSpan.FromMilliseconds(50)
                    : null);
        var authenticator = NewRecordingAuthenticator();
        authenticator.ThrowOnAbort = failureCase == "cleanup-failure";
        using var cancellation = new CancellationTokenSource();

        Task authentication = harness.Client.AuthenticateAsync(
            authenticator,
            cancellation.Token).AsTask();
        if (failureCase == "caller-after-write")
        {
            await harness.Transport.WaitForWriteAsync()
                .WaitAsync(TestContext.Current.CancellationToken);
            cancellation.Cancel();
        }

        Exception? failure = await Record.ExceptionAsync(() => authentication);

        Assert.NotNull(failure);
        AssertOAuthFailure(failureCase, failure, cancellation.Token);
        Assert.Equal(ManageSieveSessionState.Disconnected, harness.Client.State);
        Assert.Null(harness.Client.Capabilities);
        Assert.True(harness.Transport.IsDisposed);
        Assert.Equal(1, authenticator.AbortCount);
        Assert.Equal(
            failureCase == "invalid-completion"
                ? ["GetInitialResponseAsync", "CompleteAsync(data)", "Abort"]
                : ["GetInitialResponseAsync", "Abort"],
            authenticator.Calls);
        AssertZeroed(harness.Transport.OriginalSensitiveWrites);
        AssertZeroed([authenticator.InitialMemory!.Value]);
        if (authenticator.CompletionMemory is { } completionMemory)
        {
            Assert.Equal("server-final"u8.ToArray(), authenticator.CompletionCopy);
            AssertZeroed([completionMemory]);
        }

        Assert.False(
            Encoding.ASCII.GetString(harness.Transport.Written.Span)
                .Contains("*\r\n", StringComparison.Ordinal));
    }

    [Fact]
    public async Task OAuthBearerAuthentication_diagnostics_redact_raw_and_base64_sentinels()
    {
        const string token = "raw-token-sentinel-701";
        const string challenge = "raw-challenge-sentinel-702";
        string encodedToken = Convert.ToBase64String(Encoding.UTF8.GetBytes(token));
        string encodedChallenge = Convert.ToBase64String(Encoding.UTF8.GetBytes(challenge));
        string error =
            $"{{\"status\":\"invalid_token\",\"raw\":\"{challenge}\",\"encoded\":\"{encodedChallenge}\"}}";
        byte[] responses = Encoding.ASCII.GetBytes(
            "\"IMPLEMENTATION\" \"baseline\"\r\n\"SASL\" \"OAUTHBEARER\"\r\nOK\r\n" +
            $"\"{Convert.ToBase64String(Encoding.UTF8.GetBytes(error))}\"\r\n" +
            $"NO (AUTHENTICATIONFAILED \"{encodedToken}\") \"{token} {challenge} {encodedChallenge}\"\r\n");
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(responses);
        var authenticator = new RecordingOAuthBearerAuthenticator(
            token,
            "server.example.com",
            4190,
            "user@example.com");

        ManageSieveAuthenticationException exception =
            await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
                () => harness.Client.AuthenticateAsync(
                    authenticator,
                    TestContext.Current.CancellationToken).AsTask());

        Assert.Equal("ManageSieve authentication failed.", exception.Message);
        Assert.Null(exception.InnerException);
        Assert.Equal("AUTHENTICATIONFAILED", exception.ResponseCode);
        Assert.Equal(
            new ManageSieveOAuthBearerError("invalid_token", null, null),
            authenticator.ServerError);
        Assert.Equal(ManageSieveSessionState.Secured, harness.Client.State);
        Assert.Equal("baseline", harness.Client.Capabilities?.Implementation);
        string diagnostic = string.Join(
            '\n',
            exception.GetType().FullName,
            exception.Message,
            exception.ToString(),
            exception.InnerException?.ToString() ?? string.Empty,
            exception.ResponseCode,
            harness.Client.State.ToString(),
            harness.Client.Capabilities?.Implementation,
            authenticator.ServerError?.ToString());
        foreach (string sentinel in new[] { token, encodedToken, challenge, encodedChallenge })
        {
            Assert.DoesNotContain(sentinel, diagnostic, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task OAuthBearer_completion_accepts_only_without_server_data_and_rejects_reuse()
    {
        var authenticator = NewAuthenticator();
        await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken);

        await authenticator.CompleteAsync(null, TestContext.Current.CancellationToken);
        await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
            async () => await authenticator.CompleteAsync(null, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task OAuthBearer_completion_rejects_first_non_null_data_without_consuming_exchange()
    {
        var authenticator = NewAuthenticator();
        await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
            async () => await authenticator.CompleteAsync(
                new byte[] { 1 }, TestContext.Current.CancellationToken));
        await authenticator.CompleteAsync(null, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task OAuthBearer_completion_abort_is_idempotent_and_rejects_callbacks()
    {
        var authenticator = NewAuthenticator();
        await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken);
        authenticator.Abort();
        authenticator.Abort();

        await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
            async () => await authenticator.RespondAsync("{}"u8.ToArray(), TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
            async () => await authenticator.CompleteAsync(null, TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
            async () => await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task OAuthBearer_error_rejects_duplicate_response_and_completion_after_error()
    {
        var authenticator = NewAuthenticator();
        await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken);
        ReadOnlyMemory<byte> dummy = await authenticator.RespondAsync(
            "{\"status\":\"ok\"}"u8.ToArray(), TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
            async () => await authenticator.RespondAsync(
                "{\"status\":\"again\"}"u8.ToArray(), TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
            async () => await authenticator.CompleteAsync(null, TestContext.Current.CancellationToken));

        authenticator.Abort();
        Assert.Equal(new byte[] { 0 }, dummy.ToArray());
        Assert.NotNull(authenticator.ServerError);
    }

    [Fact]
    public async Task OAuthBearer_error_rejects_malformed_shapes_bounds_urls_and_reflection()
    {
        string[] invalid =
        [
            "{}", "{\"status\":\"\"}", "{\"status\":null}", "{\"status\":1}",
            "{\"status\":\"ok\",\"status\":\"again\"}", "{\"status\":\"ok\",\"x\":}",
            "{\"status\":\"ok\"} trailing", "[\"status\"]", "{/* comment */\"status\":\"ok\"}",
            "{\"status\":\"ok\",\"openid-configuration\":\"http://example.com\"}",
            "{\"status\":\"ok\",\"openid-configuration\":\"/.well-known/openid-configuration\"}",
            "{\"status\":\"ok\",\"openid-configuration\":\"https://user@example.com\"}",
            "{\"status\":\"ok\",\"openid-configuration\":\"https://example.com/#fragment\"}",
            "{\"status\":\"caller-token\"}",
            "{\"status\":\"ok\",\"scope\":\"caller-token\"}",
            "{\"status\":\"ok\",\"openid-configuration\":\"https://example.com/caller-token\"}",
            "{\"status\":\"ok\",\"scope\":\"one\",\"scope\":\"two\"}",
            "{\"status\":\"ok\",\"openid-configuration\":\"https://a\",\"openid-configuration\":\"https://b\"}",
            $"{{\"status\":\"{new string('a', 129)}\"}}",
            $"{{\"status\":\"ok\",\"scope\":\"{new string('a', 4_097)}\"}}",
            $"{{\"status\":\"ok\",\"openid-configuration\":\"https://example.com/{new string('é', 1_014)}a\"}}",
            "{\"status\":\"ok\",\"nested\":{\"a\":{\"b\":{\"c\":{\"d\":{\"e\":{\"f\":{\"g\":{\"h\":1}}}}}}}}}",
        ];

        foreach (string value in invalid)
        {
            var authenticator = NewAuthenticator();
            await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken);
            ManageSieveAuthenticationException exception =
                await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
                async () => await authenticator.RespondAsync(
                    Encoding.UTF8.GetBytes(value), TestContext.Current.CancellationToken));
            Assert.Equal("OAUTHBEARER authentication failed.", exception.Message);
            Assert.Null(exception.InnerException);
            Assert.Null(authenticator.ServerError);
        }

        var invalidUtf8 = NewAuthenticator();
        await invalidUtf8.GetInitialResponseAsync(TestContext.Current.CancellationToken);
        ManageSieveAuthenticationException invalidUtf8Exception =
            await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
                async () => await invalidUtf8.RespondAsync(
                    new byte[] { (byte)'{', (byte)'"', (byte)'s', (byte)'t', (byte)'a', (byte)'t', (byte)'u', (byte)'s', (byte)'"', (byte)':', (byte)'"', 0xC3, (byte)'"', (byte)'}' },
                    TestContext.Current.CancellationToken));
        Assert.Equal("OAUTHBEARER authentication failed.", invalidUtf8Exception.Message);
        Assert.Null(invalidUtf8Exception.InnerException);
    }

    [Fact]
    public async Task OAuthBearer_error_accepts_exact_multibyte_value_boundaries_and_discards_unknown_fields()
    {
        string status = new('é', 64); // 128 UTF-8 bytes
        string scope = new('é', 2_048); // 4,096 UTF-8 bytes
        string configuration = "https://example.com/" + new string('é', 1_014); // 2,048 UTF-8 bytes
        string json = $"{{\"unknown\":{{\"nested\":[1]}},\"status\":\"{status}\",\"scope\":\"{scope}\",\"openid-configuration\":\"{configuration}\"}}";
        var authenticator = NewAuthenticator();
        await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken);

        ReadOnlyMemory<byte> response = await authenticator.RespondAsync(
            Encoding.UTF8.GetBytes(json), TestContext.Current.CancellationToken);

        Assert.Equal(new byte[] { 1 }, response.ToArray());
        Assert.Equal(status, authenticator.ServerError!.Status);
        Assert.Equal(scope, authenticator.ServerError.Scope);
        Assert.Equal(configuration, authenticator.ServerError.OpenIdConfiguration);
    }

    [Fact]
    public async Task OAuthBearer_error_enforces_decoded_challenge_length_boundaries()
    {
        foreach (int length in new[] { 16_384, 16_385 })
        {
            var authenticator = NewAuthenticator();
            await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken);
            byte[] challenge = ChallengeWithLength(length);
            Func<Task> action = async () => await authenticator.RespondAsync(
                challenge, TestContext.Current.CancellationToken);

            if (length == 16_384)
            {
                Assert.Equal(new byte[] { 1 }, (await authenticator.RespondAsync(
                    challenge, TestContext.Current.CancellationToken)).ToArray());
            }
            else
            {
                await Assert.ThrowsAsync<ManageSieveAuthenticationException>(action);
            }
        }
    }

    private static ManageSieveOAuthBearerAuthenticator NewAuthenticator() =>
        new("caller-token", "host", 1);

    private static RecordingOAuthBearerAuthenticator NewRecordingAuthenticator() =>
        new(RfcToken, "server.example.com", 4190, "user@example.com");

    private static byte[] RfcInitialBytes =>
        "n,a=user@example.com,\u0001host=server.example.com\u0001port=4190\u0001auth=Bearer vF9dft4qmTc2Nvb3RlckBhbHRhdmlzdGEuY29tCg==\u0001\u0001"u8.ToArray();

    private static byte[] ChallengeWithLength(int length)
    {
        const string prefix = "{\"status\":\"ok\",\"unknown\":\"";
        const string suffix = "\"}";
        return Encoding.UTF8.GetBytes(prefix + new string('a', length - Encoding.UTF8.GetByteCount(prefix + suffix)) + suffix);
    }

    private static void AssertOAuthFailure(
        string failureCase,
        Exception failure,
        CancellationToken callerCancellationToken)
    {
        switch (failureCase)
        {
            case "caller-after-write":
                Assert.Equal(
                    callerCancellationToken,
                    Assert.IsAssignableFrom<OperationCanceledException>(failure)
                        .CancellationToken);
                break;
            case "timeout-after-write":
                Assert.Equal(
                    "ManageSieve authentication timed out.",
                    Assert.IsType<TimeoutException>(failure).Message);
                break;
            case "malformed-challenge":
                Assert.IsType<ManageSieveProtocolException>(failure);
                break;
            case "invalid-completion":
                var authenticatorFailure =
                    Assert.IsType<ManageSieveAuthenticationException>(failure);
                Assert.Equal("ManageSieve authenticator failed.", authenticatorFailure.Message);
                Assert.Null(authenticatorFailure.InnerException);
                break;
            case "cleanup-failure":
                var cleanupFailure = Assert.IsType<ManageSieveAuthenticationException>(failure);
                Assert.Equal("ManageSieve authentication cleanup failed.", cleanupFailure.Message);
                Assert.Null(cleanupFailure.InnerException);
                break;
            default:
                Assert.Equal(
                    "ManageSieve server closed the connection during authentication.",
                    Assert.IsType<ManageSieveConnectionException>(failure).Message);
                break;
        }
    }

    private sealed class RecordingOAuthBearerAuthenticator(
        string accessToken,
        string host,
        int port,
        string? authorizationIdentity = null) : IManageSieveAuthenticator
    {
        private readonly ManageSieveOAuthBearerAuthenticator inner =
            new(accessToken, host, port, authorizationIdentity);

        public string Mechanism => inner.Mechanism;

        public bool AllowsUnprotectedConnection => inner.AllowsUnprotectedConnection;

        public ManageSieveOAuthBearerError? ServerError => inner.ServerError;

        public List<string> Calls { get; } = [];

        public int AbortCount { get; private set; }

        public ReadOnlyMemory<byte>? InitialMemory { get; private set; }

        public byte[]? InitialCopy { get; private set; }

        public ReadOnlyMemory<byte>? ChallengeMemory { get; private set; }

        public byte[]? ChallengeCopy { get; private set; }

        public ReadOnlyMemory<byte>? DummyMemory { get; private set; }

        public byte[]? DummyCopy { get; private set; }

        public ReadOnlyMemory<byte>? CompletionMemory { get; private set; }

        public byte[]? CompletionCopy { get; private set; }

        public bool ThrowOnAbort { get; set; }

        public Action? InitialResponseReturning { get; set; }

        public async ValueTask<ReadOnlyMemory<byte>?> GetInitialResponseAsync(
            CancellationToken cancellationToken = default)
        {
            Calls.Add("GetInitialResponseAsync");
            InitialMemory = await inner.GetInitialResponseAsync(cancellationToken);
            InitialCopy = InitialMemory?.ToArray();
            InitialResponseReturning?.Invoke();
            return InitialMemory;
        }

        public async ValueTask<ReadOnlyMemory<byte>> RespondAsync(
            ReadOnlyMemory<byte> challenge,
            CancellationToken cancellationToken = default)
        {
            Calls.Add("RespondAsync");
            ChallengeMemory = challenge;
            ChallengeCopy = challenge.ToArray();
            DummyMemory = await inner.RespondAsync(challenge, cancellationToken);
            DummyCopy = DummyMemory.Value.ToArray();
            return DummyMemory.Value;
        }

        public async ValueTask CompleteAsync(
            ReadOnlyMemory<byte>? serverData,
            CancellationToken cancellationToken = default)
        {
            Calls.Add(serverData is null ? "CompleteAsync(null)" : "CompleteAsync(data)");
            CompletionMemory = serverData;
            CompletionCopy = serverData?.ToArray();
            await inner.CompleteAsync(serverData, cancellationToken);
        }

        public void Abort()
        {
            Calls.Add("Abort");
            AbortCount++;
            inner.Abort();
            if (ThrowOnAbort)
            {
                throw new InvalidOperationException("unsafe cleanup detail");
            }
        }
    }

    [Fact]
    public async Task Initial_response_uses_gs2_escaping_and_strict_utf8()
    {
        var authenticator = new ManageSieveOAuthBearerAuthenticator(
            "token",
            "host.example",
            65535,
            "a,b=é");

        ReadOnlyMemory<byte> response =
            (await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken)).GetValueOrDefault();

        Assert.Equal(
            "n,a=a=2Cb=3Dé,\u0001host=host.example\u0001port=65535\u0001auth=Bearer token\u0001\u0001"u8.ToArray(),
            response.ToArray());
    }

    [Fact]
    public async Task Initial_response_rejects_duplicate_initial_use()
    {
        var authenticator = new ManageSieveOAuthBearerAuthenticator("token", "host", 1);
        await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken);

        ManageSieveAuthenticationException exception = await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
            async () => await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken));

        Assert.Equal("OAUTHBEARER authentication exchange has already been used.", exception.Message);
    }

    [Fact]
    public void Accepts_trailing_padding_and_boundary_token_size()
    {
        Assert.NotNull(new ManageSieveOAuthBearerAuthenticator("abc+/._~-==", "host", 1));
        Assert.NotNull(new ManageSieveOAuthBearerAuthenticator(new string('a', 16_384), "host", 65_535));
    }

    [Fact]
    public void Rejects_null_empty_or_invalid_tokens()
    {
        Assert.Throws<ArgumentNullException>(() => new ManageSieveOAuthBearerAuthenticator(null!, "host", 1));
        Assert.Throws<ArgumentException>(() => new ManageSieveOAuthBearerAuthenticator(string.Empty, "host", 1));
        Assert.Throws<ArgumentException>(() => new ManageSieveOAuthBearerAuthenticator("a=b=c", "host", 1));
        Assert.Throws<ArgumentException>(() => new ManageSieveOAuthBearerAuthenticator("a?b", "host", 1));
        Assert.Throws<ArgumentException>(() => new ManageSieveOAuthBearerAuthenticator(new string('a', 16_385), "host", 1));
    }

    [Fact]
    public void Rejects_padding_only_tokens()
    {
        Assert.Throws<ArgumentException>(() => new ManageSieveOAuthBearerAuthenticator("=", "host", 1));
        Assert.Throws<ArgumentException>(() => new ManageSieveOAuthBearerAuthenticator("==", "host", 1));
    }

    [Fact]
    public void Rejects_invalid_hosts_and_ports()
    {
        Assert.Throws<ArgumentNullException>(() => new ManageSieveOAuthBearerAuthenticator("a", null!, 1));
        Assert.Throws<ArgumentException>(() => new ManageSieveOAuthBearerAuthenticator("a", string.Empty, 1));
        Assert.Throws<ArgumentException>(() => new ManageSieveOAuthBearerAuthenticator("a", "höst.example", 1));
        Assert.Throws<ArgumentException>(() => new ManageSieveOAuthBearerAuthenticator("a", "host\0", 1));
        Assert.Throws<ArgumentException>(() => new ManageSieveOAuthBearerAuthenticator("a", "host\n", 1));
        Assert.Throws<ArgumentException>(() => new ManageSieveOAuthBearerAuthenticator("a", new string('a', 256), 1));
        Assert.Throws<ArgumentException>(() => new ManageSieveOAuthBearerAuthenticator("a", new string('é', 128), 1));
        Assert.Throws<ArgumentOutOfRangeException>(() => new ManageSieveOAuthBearerAuthenticator("a", "host", 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => new ManageSieveOAuthBearerAuthenticator("a", "host", 65_536));
    }

    [Fact]
    public void Accepts_255_byte_ascii_host()
    {
        Assert.NotNull(new ManageSieveOAuthBearerAuthenticator("a", new string('a', 255), 1));
    }

    [Fact]
    public void Rejects_nul_authorization_identity_but_accepts_non_ascii_utf8()
    {
        Assert.NotNull(new ManageSieveOAuthBearerAuthenticator("a", "host", 1));
        Assert.NotNull(new ManageSieveOAuthBearerAuthenticator("a", "host", 1, string.Empty));
        Assert.NotNull(new ManageSieveOAuthBearerAuthenticator("a", "host", 1, "délégation"));
        Assert.NotNull(new ManageSieveOAuthBearerAuthenticator("a", "host", 1, new string('a', 1_024)));
        Assert.Throws<ArgumentException>(() => new ManageSieveOAuthBearerAuthenticator("a", "host", 1, new string('a', 1_025)));
        Assert.Throws<ArgumentException>(() => new ManageSieveOAuthBearerAuthenticator("a", "host", 1, "user\0id"));
        Assert.Throws<ArgumentException>(() => new ManageSieveOAuthBearerAuthenticator("a", "host", 1, "\uD800"));
    }
}
