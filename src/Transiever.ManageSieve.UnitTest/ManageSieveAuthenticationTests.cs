using System.Security.Cryptography;
using System.Text;
using static Transiever.ManageSieve.UnitTest.SaslConformanceHarness;

namespace Transiever.ManageSieve.UnitTest;

public sealed class ManageSieveAuthenticationTests
{
    private static readonly byte[] ScramSha256PlusBinding = Convert.FromHexString(
        "d493933cfb11a10052dbb29ab90ae44ac3294ae370d06ff946c76ebaf4bfedae");
    private const string ScramSha256PlusNonce = "rOprNGfwEbeRWgbNEkqO";
    private const string ScramSha256PlusServerFirstBase64 =
        "cj1yT3ByTkdmd0ViZVJXZ2JORWtxTyVodllEcFdVYTJSYVRDQWZ1eEZJbGopaE5sRiRrMCxzPVcyMlphSjBTTlk3c29Fc1VFamI2Z1E9PSxpPTQwOTY=";
    private const string ScramSha256PlusServerFinal =
        "v=cRUS52qGDweDsewIm6aCNUTa8TgCzWX202cCaOE50JQ=";
    private const string ScramSha256PlusInitialFrame =
        "AUTHENTICATE \"SCRAM-SHA-256-PLUS\" \"cD10bHMtc2VydmVyLWVuZC1wb2ludCwsbj11c2VyLHI9ck9wck5HZndFYmVSV2diTkVrcU8=\"\r\n";
    private const string ScramSha256PlusResponseFrame =
        "\"Yz1jRDEwYkhNdGMyVnlkbVZ5TFdWdVpDMXdiMmx1ZEN3czFKT1RQUHNSb1FCUzI3S2F1UXJrU3NNcFN1TncwRy81UnNkdXV2Uy83YTQ9LHI9ck9wck5HZndFYmVSV2diTkVrcU8laHZZRHBXVWEyUmFUQ0FmdXhGSWxqKWhObEYkazAscD1YZDVBWXJ2bnRtUzNlTTNCdWFTMW5VcUdjQkNFWFg2QUdDQkl2NnNBOGdjPQ==\"\r\n";
    private const string ScramSha256PlusAlteredBindingResponseFrame =
        "\"Yz1jRDEwYkhNdGMyVnlkbVZ5TFdWdVpDMXdiMmx1ZEN3czFaT1RQUHNSb1FCUzI3S2F1UXJrU3NNcFN1TncwRy81UnNkdXV2Uy83YTQ9LHI9ck9wck5HZndFYmVSV2diTkVrcU8laHZZRHBXVWEyUmFUQ0FmdXhGSWxqKWhObEYkazAscD1zQUNiNFFleHUweXU3RnJXNnZyZ1M2Wm85dkhyTm5XZ2w4akJXR25IUGM0PQ==\"\r\n";

    [Fact]
    public async Task ScramSha256PlusLifecycle_fetches_binding_immediately_before_initial_response()
    {
        List<string> trace = [];
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(
                "\"SASL\" \"TEST SCRAM-SHA-256-PLUS\"\r\nOK\r\nOK\r\n"u8.ToArray(),
                tlsServerEndPointBinding: ScramSha256PlusBinding,
                tlsServerEndPointBindingTrace: trace);
        using var cancellation = new CancellationTokenSource();
        var lockHolder = new ScriptedAuthenticator { BlockInitialResponse = true };
        Task heldAuthentication = harness.Client.AuthenticateAsync(
            lockHolder,
            cancellation.Token).AsTask();
        await lockHolder.WaitForInitialAsync()
            .WaitAsync(TestContext.Current.CancellationToken);
        var authenticator = new RecordingChannelBindingLifecycleAuthenticator(trace);

        Task plusAuthentication = harness.Client.AuthenticateAsync(
            authenticator,
            TestContext.Current.CancellationToken).AsTask();

        try
        {
            Assert.Empty(trace);
        }
        finally
        {
            cancellation.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => heldAuthentication);
        }

        await plusAuthentication;

        Assert.Equal(
            ["GetBinding", "SetBinding", "Initial", "Complete"],
            trace);
        Assert.Equal(ScramSha256PlusBinding, authenticator.Binding);
        AssertZeroed(harness.Transport.IssuedTlsServerEndPointBindings.Select(
            binding => (ReadOnlyMemory<byte>)binding));
    }

    [Fact]
    public async Task ScramSha256PlusLifecycle_reports_eligible_and_clears_probe_binding()
    {
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(
                "\"SASL\" \"SCRAM-SHA-256-PLUS\"\r\nOK\r\n"u8.ToArray(),
                tlsServerEndPointBinding: ScramSha256PlusBinding);

        Assert.True(harness.Client.CanUseScramSha256Plus);
        AssertZeroed(harness.Transport.IssuedTlsServerEndPointBindings.Select(
            binding => (ReadOnlyMemory<byte>)binding));
    }

    [Fact]
    public async Task ScramSha256PlusLifecycle_is_ineligible_without_advertisement_or_binding()
    {
        await using SaslConformanceHarness unadvertised =
            await SaslConformanceHarness.ConnectAsync(
                "\"SASL\" \"SCRAM-SHA-256\"\r\nOK\r\n"u8.ToArray(),
                tlsServerEndPointBinding: ScramSha256PlusBinding);
        await using SaslConformanceHarness unavailable =
            await SaslConformanceHarness.ConnectAsync(
                "\"SASL\" \"SCRAM-SHA-256-PLUS\"\r\nOK\r\n"u8.ToArray());
        await using SaslConformanceHarness unsecured =
            await SaslConformanceHarness.ConnectAsync(
                "\"SASL\" \"SCRAM-SHA-256-PLUS\"\r\nOK\r\n"u8.ToArray(),
                ManageSieveSecurityMode.PlainText,
                secure: false,
                tlsServerEndPointBinding: ScramSha256PlusBinding);

        Assert.False(unadvertised.Client.CanUseScramSha256Plus);
        Assert.Empty(unadvertised.Transport.IssuedTlsServerEndPointBindings);
        Assert.False(unavailable.Client.CanUseScramSha256Plus);
        Assert.False(unsecured.Client.CanUseScramSha256Plus);
        Assert.Empty(unsecured.Transport.IssuedTlsServerEndPointBindings);
    }

    [Fact]
    public async Task ScramSha256PlusLifecycle_is_ineligible_when_tls_binding_is_unsupported()
    {
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(
                "\"SASL\" \"SCRAM-SHA-256-PLUS\"\r\nOK\r\n"u8.ToArray(),
                tlsServerEndPointBindingException:
                    new ManageSieveAuthenticationException(
                        "SCRAM-SHA-256-PLUS requires a supported TLS 1.2 channel binding."));

        Assert.False(harness.Client.CanUseScramSha256Plus);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ScramSha256PlusLifecycle_requires_valid_server_proof(bool finalChallenge)
    {
        string outcome = finalChallenge
            ? $"\"{Base64(ScramSha256PlusServerFinal)}\"\r\nOK\r\n"
            : $"OK (SASL \"{Base64(ScramSha256PlusServerFinal)}\")\r\n";
        byte[] responses = Encoding.ASCII.GetBytes(
            "\"SASL\" \"SCRAM-SHA-256-PLUS\"\r\nOK\r\n" +
            $"\"{ScramSha256PlusServerFirstBase64}\"\r\n" +
            outcome);
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(
                responses,
                tlsServerEndPointBinding: ScramSha256PlusBinding);
        var authenticator = CreateScramSha256PlusAuthenticator();

        await harness.Client.AuthenticateAsync(
            authenticator,
            TestContext.Current.CancellationToken);

        string expected = ScramSha256PlusInitialFrame +
            ScramSha256PlusResponseFrame +
            (finalChallenge ? "\"\"\r\n" : string.Empty);
        AssertTranscriptEqual(
            Encoding.ASCII.GetBytes(expected),
            harness.Transport.Written.Span);
        AssertZeroed(harness.Transport.IssuedTlsServerEndPointBindings.Select(
            binding => (ReadOnlyMemory<byte>)binding));
        Assert.Equal(ManageSieveSessionState.Authenticated, harness.Client.State);
        Assert.Throws<ManageSieveAuthenticationException>(
            () => ((IManageSieveChannelBindingAuthenticator)authenticator)
                .SetChannelBinding(ScramSha256PlusBinding));
    }

    [Fact]
    public async Task ScramSha256PlusLifecycle_rejects_one_bit_altered_binding()
    {
        byte[] alteredBinding = [.. ScramSha256PlusBinding];
        alteredBinding[0] ^= 0x01;
        byte[] responses = Encoding.ASCII.GetBytes(
            "\"SASL\" \"SCRAM-SHA-256-PLUS SCRAM-SHA-256\"\r\nOK\r\n" +
            $"\"{ScramSha256PlusServerFirstBase64}\"\r\n" +
            $"OK (SASL \"{Base64(ScramSha256PlusServerFinal)}\")\r\n");
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(
                responses,
                tlsServerEndPointBinding: alteredBinding);

        ManageSieveAuthenticationException exception =
            await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
                () => harness.Client.AuthenticateAsync(
                    CreateScramSha256PlusAuthenticator(),
                    TestContext.Current.CancellationToken).AsTask());

        Assert.Equal("ManageSieve authenticator failed.", exception.Message);
        Assert.Null(exception.InnerException);
        AssertTranscriptEqual(
            Encoding.ASCII.GetBytes(
                ScramSha256PlusInitialFrame +
                ScramSha256PlusAlteredBindingResponseFrame),
            harness.Transport.Written.Span);
        Assert.DoesNotContain(
            "AUTHENTICATE \"SCRAM-SHA-256\"",
            Encoding.ASCII.GetString(harness.Transport.Written.Span),
            StringComparison.Ordinal);
        AssertZeroed(harness.Transport.IssuedTlsServerEndPointBindings.Select(
            binding => (ReadOnlyMemory<byte>)binding));
        Assert.Equal(ManageSieveSessionState.Disconnected, harness.Client.State);
    }

    [Theory]
    [InlineData("completion", "missing")]
    [InlineData("completion", "malformed")]
    [InlineData("completion", "mismatch")]
    [InlineData("challenge", "missing")]
    [InlineData("challenge", "malformed")]
    [InlineData("challenge", "mismatch")]
    public async Task ScramSha256PlusLifecycle_rejects_invalid_server_proof(
        string form,
        string failure)
    {
        string serverFinal = failure switch
        {
            "missing" => string.Empty,
            "malformed" => "v=not-base64",
            _ => "v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        };
        string outcome = form == "challenge"
            ? $"\"{Base64(serverFinal)}\"\r\n"
            : failure == "missing"
                ? "OK\r\n"
                : $"OK (SASL \"{Base64(serverFinal)}\")\r\n";
        byte[] responses = Encoding.ASCII.GetBytes(
            "\"SASL\" \"SCRAM-SHA-256-PLUS\"\r\nOK\r\n" +
            $"\"{ScramSha256PlusServerFirstBase64}\"\r\n" +
            outcome);
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(
                responses,
                tlsServerEndPointBinding: ScramSha256PlusBinding);
        var authenticator = CreateScramSha256PlusAuthenticator();

        await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
            () => harness.Client.AuthenticateAsync(
                authenticator,
                TestContext.Current.CancellationToken).AsTask());

        Assert.StartsWith(
            ScramSha256PlusInitialFrame + ScramSha256PlusResponseFrame,
            Encoding.ASCII.GetString(harness.Transport.Written.Span),
            StringComparison.Ordinal);
        AssertZeroed(harness.Transport.IssuedTlsServerEndPointBindings.Select(
            binding => (ReadOnlyMemory<byte>)binding));
        Assert.Equal(ManageSieveSessionState.Disconnected, harness.Client.State);
        Assert.Throws<ManageSieveAuthenticationException>(
            () => ((IManageSieveChannelBindingAuthenticator)authenticator)
                .SetChannelBinding(ScramSha256PlusBinding));
    }

    [Fact]
    public async Task ScramSha256PlusLifecycle_clears_binding_on_cancellation()
    {
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(
                "\"SASL\" \"SCRAM-SHA-256-PLUS\"\r\nOK\r\n"u8.ToArray(),
                blockAfterInput: true,
                tlsServerEndPointBinding: ScramSha256PlusBinding);
        var authenticator = CreateScramSha256PlusAuthenticator();
        using var cancellation = new CancellationTokenSource();

        Task authentication = harness.Client.AuthenticateAsync(
            authenticator,
            cancellation.Token).AsTask();
        await harness.Transport.WaitForWriteAsync()
            .WaitAsync(TestContext.Current.CancellationToken);
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => authentication);
        AssertZeroed(harness.Transport.IssuedTlsServerEndPointBindings.Select(
            binding => (ReadOnlyMemory<byte>)binding));
        Assert.Throws<ManageSieveAuthenticationException>(
            () => ((IManageSieveChannelBindingAuthenticator)authenticator)
                .SetChannelBinding(ScramSha256PlusBinding));
    }

    [Fact]
    public async Task ScramSha256PlusLifecycle_rejects_unavailable_binding_before_credentials_are_sent()
    {
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(
                "\"SASL\" \"SCRAM-SHA-256-PLUS\"\r\nOK\r\n"u8.ToArray());
        var authenticator = CreateScramSha256PlusAuthenticator();

        await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
            () => harness.Client.AuthenticateAsync(
                authenticator,
                TestContext.Current.CancellationToken).AsTask());
        Assert.True(harness.Transport.Written.IsEmpty);
        Assert.Throws<ManageSieveAuthenticationException>(
            () => ((IManageSieveChannelBindingAuthenticator)authenticator)
                .SetChannelBinding(ScramSha256PlusBinding));
    }

    [Fact]
    public async Task ScramSha256PlusLifecycle_rejects_wrong_binding_name_without_fallback()
    {
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(
                "\"SASL\" \"SCRAM-SHA-256-PLUS\"\r\nOK\r\n"u8.ToArray(),
                tlsServerEndPointBinding: ScramSha256PlusBinding);
        var authenticator = new RecordingChannelBindingLifecycleAuthenticator
        {
            ChannelBindingName = "tls-unique"
        };

        await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
            () => harness.Client.AuthenticateAsync(
                authenticator,
                TestContext.Current.CancellationToken).AsTask());

        Assert.Equal(["Abort"], authenticator.Calls);
        Assert.True(harness.Transport.Written.IsEmpty);
    }

    [Fact]
    public async Task ScramSha256PlusLifecycle_does_not_fallback_to_bare_scram()
    {
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(
                "\"SASL\" \"SCRAM-SHA-256\"\r\nOK\r\n"u8.ToArray(),
                tlsServerEndPointBinding: ScramSha256PlusBinding);

        await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
            () => harness.Client.AuthenticateAsync(
                CreateScramSha256PlusAuthenticator(),
                TestContext.Current.CancellationToken).AsTask());

        Assert.True(harness.Transport.Written.IsEmpty);
        Assert.Empty(harness.Transport.IssuedTlsServerEndPointBindings);
    }

    [Fact]
    public async Task ScramSha256PlusLifecycle_rejects_unprotected_transport_before_wire()
    {
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(
                "\"SASL\" \"SCRAM-SHA-256-PLUS\"\r\nOK\r\n"u8.ToArray(),
                ManageSieveSecurityMode.PlainText,
                secure: false,
                tlsServerEndPointBinding: ScramSha256PlusBinding);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => harness.Client.AuthenticateAsync(
                CreateScramSha256PlusAuthenticator(),
                TestContext.Current.CancellationToken).AsTask());

        Assert.True(harness.Transport.Written.IsEmpty);
        Assert.Empty(harness.Transport.IssuedTlsServerEndPointBindings);
    }

    [Fact]
    public async Task ScramSha256PlusLifecycle_rejects_unsupported_tls_before_wire()
    {
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(
                "\"SASL\" \"SCRAM-SHA-256-PLUS\"\r\nOK\r\n"u8.ToArray(),
                tlsServerEndPointBindingException:
                    new ManageSieveAuthenticationException("unsupported binding"));
        var authenticator = CreateScramSha256PlusAuthenticator();

        await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
            () => harness.Client.AuthenticateAsync(
                authenticator,
                TestContext.Current.CancellationToken).AsTask());
        Assert.True(harness.Transport.Written.IsEmpty);
        Assert.Throws<ManageSieveAuthenticationException>(
            () => ((IManageSieveChannelBindingAuthenticator)authenticator)
                .SetChannelBinding(ScramSha256PlusBinding));
    }

    [Fact]
    public async Task Authentication_defaults_are_compatible_with_legacy_authenticators()
    {
        IManageSieveAuthenticator authenticator = new LegacyAuthenticator();

        Assert.False(authenticator.AllowsUnprotectedConnection);
        await authenticator.CompleteAsync(null, TestContext.Current.CancellationToken);
        authenticator.Abort();
    }

    [Fact]
    public async Task Authentication_preconditions_reject_default_plaintext_before_authenticator_or_wire()
    {
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(
                "\"SASL\" \"TEST\"\r\nOK\r\n"u8.ToArray(),
                ManageSieveSecurityMode.PlainText,
                secure: false);
        var authenticator = new ScriptedAuthenticator();

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => harness.Client.AuthenticateAsync(
                authenticator,
                TestContext.Current.CancellationToken).AsTask());

        Assert.Empty(authenticator.Calls);
        Assert.DoesNotContain("AUTHENTICATE", Encoding.ASCII.GetString(
            harness.Transport.Written.Span));
    }

    [Fact]
    public async Task Authentication_preconditions_allow_explicit_plaintext_opt_in()
    {
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(
                "\"SASL\" \"TEST\"\r\nOK\r\nOK\r\n"u8.ToArray(),
                ManageSieveSecurityMode.PlainText,
                secure: false);
        var authenticator = new ScriptedAuthenticator
        {
            AllowsUnprotectedConnection = true
        };

        await harness.Client.AuthenticateAsync(
            authenticator,
            TestContext.Current.CancellationToken);

        Assert.Equal(["Initial", "Complete"], authenticator.Calls);
        Assert.Contains("AUTHENTICATE \"TEST\"", Encoding.ASCII.GetString(
            harness.Transport.Written.Span));
    }

    [Fact]
    public async Task Authentication_preconditions_reject_unadvertised_mechanism_before_authenticator_or_wire()
    {
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync("OK\r\n"u8.ToArray());
        var authenticator = new ScriptedAuthenticator();

        await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
            () => harness.Client.AuthenticateAsync(
                authenticator,
                TestContext.Current.CancellationToken).AsTask());

        Assert.Empty(authenticator.Calls);
        Assert.DoesNotContain("AUTHENTICATE", Encoding.ASCII.GetString(
            harness.Transport.Written.Span));
    }

    [Fact]
    public async Task Authentication_preconditions_use_capabilities_refreshed_after_starttls()
    {
        byte[] responses = Encoding.ASCII.GetBytes(
            "\"STARTTLS\"\r\n\"SASL\" \"TEST\"\r\nOK\r\n" +
            "OK\r\n" +
            "\"IMPLEMENTATION\" \"after tls\"\r\nOK\r\n");
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(
                responses,
                ManageSieveSecurityMode.StartTlsRequired,
                secure: false);
        var authenticator = new ScriptedAuthenticator();

        await harness.Client.StartTlsAsync(TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
            () => harness.Client.AuthenticateAsync(
                authenticator,
                TestContext.Current.CancellationToken).AsTask());

        Assert.Empty(authenticator.Calls);
        Assert.DoesNotContain("AUTHENTICATE", Encoding.ASCII.GetString(
            harness.Transport.Written.Span));
    }

    [Fact]
    public async Task PlainAuthenticator_RejectsUnsecuredConnection()
    {
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(
                "\"IMPLEMENTATION\" \"test\"\r\n\"SASL\" \"PLAIN\"\r\nOK\r\n"u8.ToArray(),
                ManageSieveSecurityMode.PlainText,
                secure: false);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => harness.Client.AuthenticateAsync(
                new ManageSievePlainAuthenticator("user", "secret"),
                TestContext.Current.CancellationToken).AsTask());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PlainAuthenticator_clears_its_response_at_lifecycle_end(bool abort)
    {
        IManageSieveAuthenticator authenticator =
            new ManageSievePlainAuthenticator("user", "secret");
        ReadOnlyMemory<byte> response = Assert.IsType<ReadOnlyMemory<byte>>(
            await authenticator.GetInitialResponseAsync(
                TestContext.Current.CancellationToken));

        Assert.True(response.Span.IndexOfAnyExcept((byte)0) >= 0);

        if (abort)
        {
            authenticator.Abort();
        }
        else
        {
            await authenticator.CompleteAsync(
                null,
                TestContext.Current.CancellationToken);
        }

        AssertZeroed([response]);
    }

    [Theory]
    [InlineData("", null)]
    [InlineData("c2VydmVyLWZpbmFsLXNlbnRpbmVs", "server-final-sentinel")]
    public async Task Plain_authentication_rejects_unexpected_server_final_data(
        string encodedServerData,
        string? serverData)
    {
        const string password = "plain-password-sentinel";
        byte[] responses = Encoding.ASCII.GetBytes(
            "\"SASL\" \"PLAIN\"\r\nOK\r\n" +
            $"OK (SASL \"{encodedServerData}\")\r\n");
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(responses);
        var authenticator = new RecordingPlainAuthenticator("user", password);

        ManageSieveAuthenticationException exception =
            await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
                () => harness.Client.AuthenticateAsync(
                    authenticator,
                    TestContext.Current.CancellationToken).AsTask());

        Assert.Equal("ManageSieve authenticator failed.", exception.Message);
        Assert.Null(exception.InnerException);
        Assert.Null(exception.ResponseCode);
        string diagnostic = exception.ToString();
        Assert.DoesNotContain(password, diagnostic, StringComparison.Ordinal);
        if (serverData is not null)
        {
            Assert.DoesNotContain(serverData, diagnostic, StringComparison.Ordinal);
            Assert.DoesNotContain(encodedServerData, diagnostic, StringComparison.Ordinal);
        }

        Assert.Equal(["Initial", "Complete", "Abort"], authenticator.Calls);
        Assert.Equal(ManageSieveSessionState.Disconnected, harness.Client.State);
        Assert.Null(harness.Client.Capabilities);
        Assert.True(harness.Transport.IsDisposed);
        Assert.True(authenticator.InitialResponse.HasValue);
        Assert.True(authenticator.CompletionMemory.HasValue);
        AssertZeroed(
            [authenticator.InitialResponse.Value, authenticator.CompletionMemory.Value]);
        AssertZeroed(harness.Transport.OriginalSensitiveWrites);
    }

    [Fact]
    public async Task Authentication_captures_mechanism_once_for_validation_and_frame()
    {
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(
                "\"SASL\" \"TEST\"\r\nOK\r\nOK\r\n"u8.ToArray());
        var authenticator = new StatefulMechanismAuthenticator();

        await harness.Client.AuthenticateAsync(
            authenticator,
            TestContext.Current.CancellationToken);

        Assert.Equal(1, authenticator.MechanismReads);
        AssertTranscriptEqual(
            "AUTHENTICATE \"TEST\"\r\n"u8,
            harness.Transport.Written.Span);
    }

    [Fact]
    public async Task Client_TransitionsThroughTlsAuthenticationAndLogout()
    {
        byte[] responses = Encoding.ASCII.GetBytes(
            "\"IMPLEMENTATION\" \"test\"\r\n" +
            "\"STARTTLS\"\r\n" +
            "\"SASL\" \"PLAIN\"\r\n" +
            "OK\r\n" +
            "OK\r\n" +
            "\"IMPLEMENTATION\" \"test tls\"\r\n" +
            "\"SASL\" \"PLAIN\"\r\n" +
            "OK\r\n" +
            "OK\r\n" +
            "OK\r\n");
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(
                responses,
                ManageSieveSecurityMode.StartTlsRequired,
                secure: false);
        ManageSieveClient client = harness.Client;

        Assert.Equal(ManageSieveSessionState.Connected, client.State);

        await client.StartTlsAsync(TestContext.Current.CancellationToken);
        Assert.Equal(ManageSieveSessionState.Secured, client.State);
        Assert.Equal("test tls", client.Capabilities?.Implementation);

        await client.AuthenticateAsync(
            new ManageSievePlainAuthenticator("user", "secret"),
            TestContext.Current.CancellationToken);
        Assert.Equal(ManageSieveSessionState.Authenticated, client.State);

        await client.LogoutAsync(TestContext.Current.CancellationToken);
        Assert.Equal(ManageSieveSessionState.Closed, client.State);

        AssertTranscriptEqual(
            "STARTTLS\r\nAUTHENTICATE \"PLAIN\" \"AHVzZXIAc2VjcmV0\"\r\nLOGOUT\r\n"u8,
            harness.Transport.Written.Span);
        Assert.Equal("STARTTLS\r\n", Encoding.ASCII.GetString(
            harness.Transport.OriginalWrites[0].Span));
    }

    [Fact]
    public async Task Authentication_ProcessesSaslChallengeAndPreservesCapabilities()
    {
        byte[] responses = Encoding.ASCII.GetBytes(
            "\"IMPLEMENTATION\" \"baseline\"\r\n" +
            "\"SASL\" \"TEST\"\r\nOK\r\n" +
            "\"Y2hhbGxlbmdl\"\r\n" +
            "OK\r\n");
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(responses);
        var authenticator = new ScriptedAuthenticator("response"u8.ToArray());

        await harness.Client.AuthenticateAsync(
            authenticator, TestContext.Current.CancellationToken);

        Assert.Equal(["Initial", "Respond", "Complete"], authenticator.Calls);
        Assert.Equal(
            Observe("challenge"u8),
            authenticator.ChallengeObservations[0]);
        Assert.Equal("baseline", harness.Client.Capabilities?.Implementation);
        AssertTranscriptEqual(
            "AUTHENTICATE \"TEST\"\r\n\"cmVzcG9uc2U=\"\r\n"u8,
            harness.Transport.Written.Span);
        AssertZeroed(harness.Transport.OriginalSensitiveWrites);
        AssertZeroed(authenticator.Challenges);
    }

    [Theory]
    [InlineData(null, "AUTHENTICATE \"TEST\"\r\n")]
    [InlineData("", "AUTHENTICATE \"TEST\" \"\"\r\n")]
    [InlineData("initial", "AUTHENTICATE \"TEST\" \"aW5pdGlhbA==\"\r\n")]
    public async Task Authentication_initial_response_frames_are_exact(
        string? initialResponse,
        string expectedFrame)
    {
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(
                "\"SASL\" \"TEST\"\r\nOK\r\nOK\r\n"u8.ToArray());
        var authenticator = new ScriptedAuthenticator
        {
            InitialResponse = initialResponse is null
                ? null
                : Encoding.ASCII.GetBytes(initialResponse)
        };

        await harness.Client.AuthenticateAsync(
            authenticator,
            TestContext.Current.CancellationToken);

        Assert.Equal(["Initial", "Complete"], authenticator.Calls);
        AssertTranscriptEqual(
            Encoding.ASCII.GetBytes(expectedFrame),
            harness.Transport.Written.Span);
        AssertZeroed(harness.Transport.OriginalSensitiveWrites);
        AssertZeroed(authenticator.OwnedSecretBuffers);
        Assert.Equal(ManageSieveSessionState.Authenticated, harness.Client.State);
    }

    [Theory]
    [InlineData("\"\"\r\nOK\r\n")]
    [InlineData("{0}\r\n\r\nOK\r\n")]
    public async Task Authentication_fragmented_empty_challenge_frame_is_exact(
        string challengeExchange)
    {
        byte[] responses = Encoding.ASCII.GetBytes(
            "\"SASL\" \"TEST\"\r\nOK\r\n" + challengeExchange);
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(responses);
        var authenticator = new ScriptedAuthenticator(ReadOnlyMemory<byte>.Empty);

        await harness.Client.AuthenticateAsync(
            authenticator,
            TestContext.Current.CancellationToken);

        Assert.Equal(["Initial", "Respond", "Complete"], authenticator.Calls);
        Assert.Equal([Observe(ReadOnlySpan<byte>.Empty)], authenticator.ChallengeObservations);
        AssertTranscriptEqual(
            "AUTHENTICATE \"TEST\"\r\n\"\"\r\n"u8,
            harness.Transport.Written.Span);
        AssertZeroed(harness.Transport.OriginalSensitiveWrites);
        AssertZeroed(authenticator.OwnedSecretBuffers);
        AssertZeroed(authenticator.Challenges);
        Assert.Equal(ManageSieveSessionState.Authenticated, harness.Client.State);
    }

    [Fact]
    public async Task Authentication_fragmented_multiple_challenge_frames_are_exact()
    {
        byte[] responses = Encoding.ASCII.GetBytes(
            "\"SASL\" \"TEST\"\r\nOK\r\n" +
            "\"b25l\"\r\n" +
            "{4}\r\ndHdv\r\n" +
            "OK\r\n");
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(responses);
        var authenticator = new ScriptedAuthenticator(
            "client-one"u8.ToArray(),
            "client-two"u8.ToArray());

        await harness.Client.AuthenticateAsync(
            authenticator,
            TestContext.Current.CancellationToken);

        Assert.Equal(
            ["Initial", "Respond", "Respond", "Complete"],
            authenticator.Calls);
        Assert.Equal(
            [Observe("one"u8), Observe("two"u8)],
            authenticator.ChallengeObservations);
        AssertTranscriptEqual(
            "AUTHENTICATE \"TEST\"\r\n\"Y2xpZW50LW9uZQ==\"\r\n\"Y2xpZW50LXR3bw==\"\r\n"u8,
            harness.Transport.Written.Span);
        AssertZeroed(harness.Transport.OriginalSensitiveWrites);
        AssertZeroed(authenticator.OwnedSecretBuffers);
        AssertZeroed(authenticator.Challenges);
        Assert.Equal(ManageSieveSessionState.Authenticated, harness.Client.State);
    }

    [Fact]
    public async Task Authentication_zeroes_owned_buffers_after_success()
    {
        byte[] responses = Encoding.ASCII.GetBytes(
            "\"SASL\" \"TEST\"\r\nOK\r\n" +
            "\"c2VydmVyLWNoYWxsZW5nZQ==\"\r\n" +
            "OK (SASL \"c2VydmVyLXByb29m\")\r\n");
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(responses);
        var authenticator = new ScriptedAuthenticator("client-proof"u8.ToArray())
        {
            InitialResponse = "initial-proof"u8.ToArray()
        };
        authenticator.OwnSecret("derived-secret"u8.ToArray());

        await harness.Client.AuthenticateAsync(
            authenticator,
            TestContext.Current.CancellationToken);

        AssertZeroed(authenticator.OwnedSecretBuffers);
        AssertZeroed(
        [
            .. authenticator.Challenges,
            authenticator.CompletionMemory!.Value
        ]);
        AssertZeroed(harness.Transport.OriginalSensitiveWrites);
        AssertTranscriptEqual(
            "AUTHENTICATE \"TEST\" \"aW5pdGlhbC1wcm9vZg==\"\r\n\"Y2xpZW50LXByb29m\"\r\n"u8,
            harness.Transport.Written.Span);
    }

    [Fact]
    public async Task Authentication_zeroes_owned_buffers_when_completion_throws()
    {
        byte[] responses = Encoding.ASCII.GetBytes(
            "\"SASL\" \"TEST\"\r\nOK\r\n" +
            "\"c2VydmVyLWNoYWxsZW5nZQ==\"\r\n" +
            "OK (SASL \"c2VydmVyLXByb29m\")\r\n");
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(responses);
        var authenticator = new ScriptedAuthenticator("client-proof"u8.ToArray())
        {
            InitialResponse = "initial-proof"u8.ToArray(),
            CompletionException = new InvalidOperationException("unsafe completion failure")
        };
        authenticator.OwnSecret("derived-secret"u8.ToArray());

        await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
            () => harness.Client.AuthenticateAsync(
                authenticator,
                TestContext.Current.CancellationToken).AsTask());

        AssertZeroed(harness.Transport.OriginalSensitiveWrites);
        AssertZeroed(authenticator.OwnedSecretBuffers);
        AssertZeroed(
        [
            .. authenticator.Challenges,
            authenticator.CompletionMemory!.Value
        ]);
        AssertTranscriptEqual(
            "AUTHENTICATE \"TEST\" \"aW5pdGlhbC1wcm9vZg==\"\r\n\"Y2xpZW50LXByb29m\"\r\n"u8,
            harness.Transport.Written.Span);
    }

    [Fact]
    public async Task Authentication_zeroes_challenge_response_frame_when_partial_write_throws()
    {
        byte[] responses = Encoding.ASCII.GetBytes(
            "\"SASL\" \"TEST\"\r\nOK\r\n" +
            "\"Y2hhbGxlbmdl\"\r\n");
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(
                responses,
                failAfterPartialWriteNumber: 2);
        var authenticator = new ScriptedAuthenticator("client-proof"u8.ToArray());

        await Assert.ThrowsAsync<IOException>(
            () => harness.Client.AuthenticateAsync(
                authenticator,
                TestContext.Current.CancellationToken).AsTask());

        Assert.Equal(["Initial", "Respond", "Abort"], authenticator.Calls);
        Assert.Equal(ManageSieveSessionState.Disconnected, harness.Client.State);
        Assert.True(harness.Transport.IsDisposed);
        Assert.Equal(2, harness.Transport.OriginalSensitiveWrites.Count);
        AssertZeroed(harness.Transport.OriginalSensitiveWrites);
        AssertZeroed(authenticator.OwnedSecretBuffers);
        AssertZeroed(authenticator.Challenges);
        AssertTranscriptEqual(
            "AUTHENTICATE \"TEST\"\r\n\""u8,
            harness.Transport.Written.Span);
    }

    [Fact]
    public async Task Authentication_never_mutates_authenticator_owned_memory()
    {
        byte[] initial = "authenticator-initial"u8.ToArray();
        byte[] response = "authenticator-response"u8.ToArray();
        try
        {
            byte[] responses = Encoding.ASCII.GetBytes(
                "\"SASL\" \"TEST\"\r\nOK\r\n" +
                "\"Y2hhbGxlbmdl\"\r\n" +
                "OK\r\n");
            await using SaslConformanceHarness harness =
                await SaslConformanceHarness.ConnectAsync(responses);
            var authenticator = new OwnershipProbeAuthenticator(initial, response);

            await harness.Client.AuthenticateAsync(
                authenticator,
                TestContext.Current.CancellationToken);

            AssertTranscriptEqual("authenticator-initial"u8, initial);
            AssertTranscriptEqual("authenticator-response"u8, response);
            AssertZeroed(harness.Transport.OriginalSensitiveWrites);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(initial);
            CryptographicOperations.ZeroMemory(response);
        }
    }

    [Fact]
    public async Task Authentication_serializes_response_aliased_to_challenge_before_cleanup()
    {
        byte[] responses = Encoding.ASCII.GetBytes(
            "\"SASL\" \"TEST\"\r\nOK\r\n" +
            "\"Y2hhbGxlbmdl\"\r\n" +
            "OK\r\n");
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(responses);
        var authenticator = new ScriptedAuthenticator
        {
            EchoChallenge = true
        };

        await harness.Client.AuthenticateAsync(
            authenticator,
            TestContext.Current.CancellationToken);

        Assert.Equal(["Initial", "Respond", "Complete"], authenticator.Calls);
        AssertTranscriptEqual(
            "AUTHENTICATE \"TEST\"\r\n\"Y2hhbGxlbmdl\"\r\n"u8,
            harness.Transport.Written.Span);
        AssertZeroed(harness.Transport.OriginalSensitiveWrites);
    }

    [Theory]
    [InlineData("OK (SASL \"c2VydmVyLWZpbmFs\")\r\n", "server-final")]
    [InlineData("OK (SASL {16}\r\nc2VydmVyLWZpbmFs)\r\n", "server-final")]
    [InlineData("OK (SASL \"\")\r\n", "")]
    public async Task Authentication_completion_receives_success_data(
        string outcome,
        string expectedData)
    {
        byte[] responses = Encoding.ASCII.GetBytes(
            "\"SASL\" \"TEST\"\r\nOK\r\n" + outcome);
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(responses);
        var authenticator = new ScriptedAuthenticator();

        await harness.Client.AuthenticateAsync(
            authenticator,
            TestContext.Current.CancellationToken);

        Assert.Equal(["Initial", "Complete"], authenticator.Calls);
        Assert.True(authenticator.CompletionDataProvided);
        Assert.Equal(
            Observe(Encoding.ASCII.GetBytes(expectedData)),
            authenticator.CompletionObservation);
        AssertZeroed([authenticator.CompletionMemory!.Value]);
        AssertTranscriptEqual(
            "AUTHENTICATE \"TEST\"\r\n"u8,
            harness.Transport.Written.Span);
        AssertZeroed(harness.Transport.OriginalSensitiveWrites);
        Assert.Equal(ManageSieveSessionState.Authenticated, harness.Client.State);
    }

    [Theory]
    [InlineData("OK\r\n")]
    [InlineData("OK (WARNINGS) \"safe\"\r\n")]
    public async Task Authentication_completion_receives_null_without_Sasl_data(string outcome)
    {
        byte[] responses = Encoding.ASCII.GetBytes(
            "\"SASL\" \"TEST\"\r\nOK\r\n" + outcome);
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(responses);
        var authenticator = new ScriptedAuthenticator();

        await harness.Client.AuthenticateAsync(
            authenticator,
            TestContext.Current.CancellationToken);

        Assert.Equal(["Initial", "Complete"], authenticator.Calls);
        Assert.False(authenticator.CompletionDataProvided);
        Assert.Null(authenticator.CompletionObservation);
        AssertTranscriptEqual(
            "AUTHENTICATE \"TEST\"\r\n"u8,
            harness.Transport.Written.Span);
        AssertZeroed(harness.Transport.OriginalSensitiveWrites);
        Assert.Equal(ManageSieveSessionState.Authenticated, harness.Client.State);
    }

    [Fact]
    public async Task Authentication_completion_follows_final_challenge_and_empty_response()
    {
        byte[] responses = Encoding.ASCII.GetBytes(
            "\"SASL\" \"TEST\"\r\nOK\r\n" +
            "\"c2VydmVyLWZpbmFs\"\r\n" +
            "OK\r\n");
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(responses);
        var authenticator = new ScriptedAuthenticator();

        await harness.Client.AuthenticateAsync(
            authenticator,
            TestContext.Current.CancellationToken);

        Assert.Equal(["Initial", "Respond", "Complete"], authenticator.Calls);
        Assert.Equal(
            Observe("server-final"u8),
            authenticator.ChallengeObservations.Single());
        Assert.False(authenticator.CompletionDataProvided);
        Assert.Null(authenticator.CompletionObservation);
        AssertTranscriptEqual(
            "AUTHENTICATE \"TEST\"\r\n\"\"\r\n"u8,
            harness.Transport.Written.Span);
        AssertZeroed(harness.Transport.OriginalSensitiveWrites);
        AssertZeroed(authenticator.Challenges);
        Assert.Equal(ManageSieveSessionState.Authenticated, harness.Client.State);
    }

    [Theory]
    [InlineData("OK (SASL)\r\n")]
    [InlineData("OK (SASL \"\" \"\")\r\n")]
    [InlineData("OK (SASL c2VydmVyLWZpbmFs)\r\n")]
    [InlineData("OK (SASL \"not-base64\")\r\n")]
    [InlineData("OK (SASL \"YWJjä\")\r\n")]
    public async Task Authentication_completion_rejects_malformed_Sasl_data(string outcome)
    {
        byte[] responses = Encoding.UTF8.GetBytes(
            "\"SASL\" \"TEST\"\r\nOK\r\n" + outcome);
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(responses);
        var authenticator = new ScriptedAuthenticator();

        await Assert.ThrowsAsync<ManageSieveProtocolException>(
            () => harness.Client.AuthenticateAsync(
                authenticator,
                TestContext.Current.CancellationToken).AsTask());

        Assert.Equal(["Initial", "Abort"], authenticator.Calls);
        Assert.Equal(ManageSieveSessionState.Disconnected, harness.Client.State);
        Assert.True(harness.Transport.IsDisposed);
    }

    [Theory]
    [InlineData(
        "\"Y2hh bGxlbmdl\"\r\n",
        "The server returned an invalid base64 SASL challenge.")]
    [InlineData(
        "\"YQ==\" \"Yg==\"\r\n",
        "The server returned an invalid SASL challenge.")]
    [InlineData(
        "Y2hhbGxlbmdl\r\n",
        "The server returned an invalid SASL challenge.")]
    [InlineData(
        " \"Y2hhbGxlbmdl\"\r\n",
        "The server returned an invalid SASL challenge.")]
    [InlineData(
        "\"Y2hhbGxlbmdl\" \r\n",
        "The server returned an invalid SASL challenge.")]
    [InlineData(
        "\"unterminated\r\n",
        "The server returned an invalid SASL challenge.")]
    public async Task Authentication_rejects_malformed_challenge_forms(
        string challenge,
        string expectedMessage)
    {
        byte[] responses = Encoding.ASCII.GetBytes(
            "\"SASL\" \"TEST\"\r\nOK\r\n" + challenge + "OK\r\n");
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(responses);
        var authenticator = new ScriptedAuthenticator();

        ManageSieveProtocolException exception =
            await Assert.ThrowsAsync<ManageSieveProtocolException>(
                () => harness.Client.AuthenticateAsync(
                    authenticator,
                    TestContext.Current.CancellationToken).AsTask());

        Assert.Equal(expectedMessage, exception.Message);
        Assert.Null(exception.InnerException);
        Assert.Equal(["Initial", "Abort"], authenticator.Calls);
        Assert.Equal(ManageSieveSessionState.Disconnected, harness.Client.State);
        Assert.True(harness.Transport.IsDisposed);
        AssertZeroed(harness.Transport.OriginalSensitiveWrites);
    }

    [Fact]
    public async Task Authentication_disposal_failure_still_resets_and_redacts_cleanup()
    {
        const string unsafeDetail = "unsafe-dispose-sentinel";
        byte[] responses = Encoding.ASCII.GetBytes(
            "\"IMPLEMENTATION\" \"baseline\"\r\n\"SASL\" \"TEST\"\r\nOK\r\n" +
            "\"not-base64\"\r\n");
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(
                responses,
                disposeException: new InvalidOperationException(unsafeDetail));
        var authenticator = new ScriptedAuthenticator();

        ManageSieveAuthenticationException exception =
            await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
                () => harness.Client.AuthenticateAsync(
                    authenticator,
                    TestContext.Current.CancellationToken).AsTask());

        Assert.Equal("ManageSieve authentication cleanup failed.", exception.Message);
        Assert.Null(exception.InnerException);
        Assert.DoesNotContain(unsafeDetail, exception.ToString(), StringComparison.Ordinal);
        Assert.Equal(["Initial", "Abort"], authenticator.Calls);
        Assert.Equal(1, authenticator.AbortCount);
        Assert.Equal(ManageSieveSessionState.Disconnected, harness.Client.State);
        Assert.Null(harness.Client.Capabilities);
        Assert.True(harness.Transport.IsDisposed);
        AssertZeroed(harness.Transport.OriginalSensitiveWrites);
    }

    [Fact]
    public async Task Authentication_completion_failure_does_not_authenticate()
    {
        byte[] responses = Encoding.ASCII.GetBytes(
            "\"SASL\" \"TEST\"\r\nOK\r\n" +
            "OK (SASL \"c2VydmVyLWZpbmFs\")\r\n");
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(responses);
        var authenticator = new ScriptedAuthenticator
        {
            CompletionException = new InvalidOperationException("completion failed")
        };

        ManageSieveAuthenticationException exception =
            await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
            () => harness.Client.AuthenticateAsync(
                authenticator,
                TestContext.Current.CancellationToken).AsTask());

        Assert.Equal("ManageSieve authenticator failed.", exception.Message);
        Assert.Null(exception.InnerException);
        Assert.Equal(["Initial", "Complete", "Abort"], authenticator.Calls);
        Assert.Equal(
            Observe("server-final"u8),
            authenticator.CompletionObservation);
        AssertZeroed([authenticator.CompletionMemory!.Value]);
        Assert.Equal(ManageSieveSessionState.Disconnected, harness.Client.State);
        Assert.True(harness.Transport.IsDisposed);
    }

    [Theory]
    [InlineData("caller-before-authenticator", ManageSieveSessionState.Secured, false, 0, true)]
    [InlineData("initial-cancellation", ManageSieveSessionState.Secured, false, 1, true)]
    [InlineData("cancellation-before-write", ManageSieveSessionState.Secured, false, 1, true)]
    [InlineData("authenticator-cancellation", ManageSieveSessionState.Secured, false, 1, true)]
    [InlineData("initial-failure", ManageSieveSessionState.Secured, false, 1, true)]
    [InlineData("server-no", ManageSieveSessionState.Secured, false, 1, true)]
    [InlineData("server-bye", ManageSieveSessionState.Disconnected, true, 1, false)]
    [InlineData("caller-after-write", ManageSieveSessionState.Disconnected, true, 1, false)]
    [InlineData("partial-write-failure", ManageSieveSessionState.Disconnected, true, 1, false)]
    [InlineData("timeout-after-write", ManageSieveSessionState.Disconnected, true, 1, false)]
    [InlineData("malformed-input", ManageSieveSessionState.Disconnected, true, 1, false)]
    [InlineData("response-failure", ManageSieveSessionState.Disconnected, true, 1, false)]
    [InlineData("completion-failure", ManageSieveSessionState.Disconnected, true, 1, false)]
    [InlineData("throwing-abort", ManageSieveSessionState.Disconnected, true, 1, false)]
    public async Task Authentication_failure_state_matches_exchange_synchronization(
        string failureCase,
        ManageSieveSessionState expectedState,
        bool expectedDisposed,
        int expectedAbortCount,
        bool expectedCapabilities)
    {
        string outcome = failureCase switch
        {
            "server-no" => "NO (AUTHENTICATIONFAILED \"unsafe-detail\") \"unsafe prose\"\r\n",
            "server-bye" => "BYE \"unsafe prose\"\r\n",
            "malformed-input" => "\"not-base64!\"\r\n",
            "response-failure" => "\"Y2hhbGxlbmdl\"\r\n",
            "completion-failure" => "OK\r\n",
            _ => string.Empty
        };
        bool blockAfterInput = failureCase is "caller-after-write" or "timeout-after-write";
        TimeSpan? operationTimeout = failureCase == "timeout-after-write"
            ? TimeSpan.FromMilliseconds(50)
            : null;
        byte[] responses = Encoding.ASCII.GetBytes(
            "\"IMPLEMENTATION\" \"baseline\"\r\n\"SASL\" \"TEST\"\r\nOK\r\n" + outcome);
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(
                responses,
                blockAfterInput: blockAfterInput,
                failAfterPartialWrite: failureCase == "partial-write-failure",
                operationTimeout: operationTimeout);
        using var callerCancellation = new CancellationTokenSource();
        var authenticator = new ScriptedAuthenticator
        {
            InitialException = failureCase switch
            {
                "authenticator-cancellation" =>
                    new OperationCanceledException("unsafe authenticator cancellation"),
                "initial-failure" or "throwing-abort" =>
                    new InvalidOperationException("unsafe initial failure"),
                _ => null
            },
            ResponseException = failureCase == "response-failure"
                ? new InvalidOperationException("unsafe response failure")
                : null,
            CompletionException = failureCase == "completion-failure"
                ? new InvalidOperationException("unsafe completion failure")
                : null,
            AbortException = failureCase == "throwing-abort"
                ? new InvalidOperationException("unsafe abort failure")
                : null,
            BlockInitialResponse = failureCase == "initial-cancellation",
            InitialResponseReturning = failureCase == "cancellation-before-write"
                ? callerCancellation.Cancel
                : null
        };
        if (failureCase == "caller-before-authenticator")
        {
            callerCancellation.Cancel();
        }

        Task authentication = harness.Client.AuthenticateAsync(
            authenticator,
            callerCancellation.Token).AsTask();
        if (failureCase == "initial-cancellation")
        {
            await authenticator.WaitForInitialAsync()
                .WaitAsync(TestContext.Current.CancellationToken);
            callerCancellation.Cancel();
        }

        if (failureCase == "caller-after-write")
        {
            await harness.Transport.WaitForWriteAsync()
                .WaitAsync(TestContext.Current.CancellationToken);
            callerCancellation.Cancel();
        }

        Exception? failure = await Record.ExceptionAsync(() => authentication);

        Assert.NotNull(failure);
        AssertFailureCategory(failureCase, failure, callerCancellation.Token);
        Assert.Equal(expectedState, harness.Client.State);
        Assert.Equal(expectedDisposed, harness.Transport.IsDisposed);
        Assert.Equal(expectedAbortCount, authenticator.AbortCount);
        string[] expectedCalls = failureCase switch
        {
            "caller-before-authenticator" => [],
            "response-failure" => ["Initial", "Respond", "Abort"],
            "completion-failure" => ["Initial", "Complete", "Abort"],
            _ => ["Initial", "Abort"]
        };
        Assert.Equal(
            expectedCalls,
            authenticator.Calls);
        Assert.Equal(
            expectedCapabilities ? "baseline" : null,
            harness.Client.Capabilities?.Implementation);
        AssertZeroed(harness.Transport.OriginalSensitiveWrites);
        AssertZeroed(authenticator.OwnedSecretBuffers);
        AssertZeroed(authenticator.Challenges);
        if (authenticator.CompletionMemory is { } completionMemory)
        {
            AssertZeroed([completionMemory]);
        }

        string expectedTranscript = failureCase switch
        {
            "caller-before-authenticator" or
            "initial-cancellation" or
            "cancellation-before-write" or
            "authenticator-cancellation" or
            "initial-failure" or
            "throwing-abort" => string.Empty,
            "partial-write-failure" => "A",
            _ => "AUTHENTICATE \"TEST\"\r\n"
        };
        AssertTranscriptEqual(
            Encoding.ASCII.GetBytes(expectedTranscript),
            harness.Transport.Written.Span);

        Assert.False(
            Encoding.ASCII.GetString(harness.Transport.Written.Span)
                .Contains("*\r\n", StringComparison.Ordinal),
            "Client sent a wire-level SASL cancellation frame.");
    }

    [Theory]
    [InlineData("server-no")]
    [InlineData("server-bye")]
    [InlineData("malformed-challenge")]
    [InlineData("response-failure")]
    [InlineData("completion-failure")]
    public async Task Authentication_redaction_hides_secret_sentinels(string failureCase)
    {
        const string password = "password-sentinel-401";
        const string token = "token-sentinel-402";
        const string challenge = "challenge-sentinel-403";
        const string clientProof = "client-proof-sentinel-404";
        const string serverProof = "server-proof-sentinel-405";
        const string derivedSecret = "derived-secret-sentinel-406";
        string[] secrets =
        [
            password,
            token,
            challenge,
            clientProof,
            serverProof,
            derivedSecret
        ];
        string allSecrets = string.Join(
            ' ',
            secrets.SelectMany(secret => new[] { secret, Base64(secret) }));
        string outcome = failureCase switch
        {
            "server-no" => $"NO (AUTHENTICATIONFAILED \"{Base64(serverProof)}\") \"{allSecrets}\"\r\n",
            "server-bye" => $"BYE \"{allSecrets}\"\r\n",
            "malformed-challenge" => $"\"not-base64 {allSecrets}\"\r\n",
            "response-failure" => $"\"{Base64(challenge)}\"\r\n",
            "completion-failure" => $"OK (SASL \"{Base64(serverProof)}\")\r\n",
            _ => throw new InvalidOperationException("Unknown redaction case.")
        };
        byte[] responses = Encoding.ASCII.GetBytes(
            "\"IMPLEMENTATION\" \"baseline\"\r\n\"SASL\" \"TEST\"\r\nOK\r\n" + outcome);
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(responses);
        var authenticator = new ScriptedAuthenticator
        {
            ResponseException = failureCase == "response-failure"
                ? new ManageSieveProtocolException(allSecrets)
                : null,
            CompletionException = failureCase == "completion-failure"
                ? new InvalidOperationException(allSecrets)
                : null
        };

        Exception? failure = await Record.ExceptionAsync(
            () => harness.Client.AuthenticateAsync(
                authenticator,
                TestContext.Current.CancellationToken).AsTask());

        Assert.NotNull(failure);
        Assert.Null(failure.InnerException);
        string diagnostic = string.Join(
            '\n',
            failure.Message,
            failure.ToString(),
            (failure as ManageSieveAuthenticationException)?.ResponseCode ?? string.Empty,
            harness.Client.State.ToString(),
            harness.Client.Capabilities?.Implementation ?? string.Empty);
        foreach (string secret in secrets)
        {
            Assert.DoesNotContain(secret, diagnostic, StringComparison.Ordinal);
            Assert.DoesNotContain(
                Convert.ToBase64String(Encoding.UTF8.GetBytes(secret)),
                diagnostic,
                StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task Authentication_failure_releases_command_lock_for_next_attempt()
    {
        byte[] responses = Encoding.ASCII.GetBytes(
            "\"IMPLEMENTATION\" \"baseline\"\r\n\"SASL\" \"TEST\"\r\nOK\r\n" +
            "NO\r\n" +
            "OK\r\n");
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(responses);
        var rejectedAuthenticator = new ScriptedAuthenticator();

        await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
            () => harness.Client.AuthenticateAsync(
                rejectedAuthenticator,
                TestContext.Current.CancellationToken).AsTask());

        using CancellationTokenSource timeout =
            CancellationTokenSource.CreateLinkedTokenSource(
                TestContext.Current.CancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(1));
        var acceptedAuthenticator = new ScriptedAuthenticator();
        await harness.Client.AuthenticateAsync(acceptedAuthenticator, timeout.Token);

        Assert.Equal(["Initial", "Abort"], rejectedAuthenticator.Calls);
        Assert.Equal(["Initial", "Complete"], acceptedAuthenticator.Calls);
        Assert.Equal(ManageSieveSessionState.Authenticated, harness.Client.State);
    }

    private static void AssertFailureCategory(
        string failureCase,
        Exception failure,
        CancellationToken callerCancellationToken)
    {
        switch (failureCase)
        {
            case "caller-before-authenticator":
            case "initial-cancellation":
            case "cancellation-before-write":
            case "caller-after-write":
                var cancellation = Assert.IsAssignableFrom<OperationCanceledException>(failure);
                Assert.Equal(callerCancellationToken, cancellation.CancellationToken);
                break;
            case "server-bye":
                Assert.IsType<ManageSieveConnectionException>(failure);
                Assert.Equal("ManageSieve server closed the connection during authentication.", failure.Message);
                break;
            case "timeout-after-write":
                Assert.IsType<TimeoutException>(failure);
                Assert.Equal("ManageSieve authentication timed out.", failure.Message);
                break;
            case "malformed-input":
                Assert.IsType<ManageSieveProtocolException>(failure);
                break;
            case "partial-write-failure":
                Assert.IsType<IOException>(failure);
                break;
            case "throwing-abort":
                Assert.IsType<ManageSieveAuthenticationException>(failure);
                Assert.Equal("ManageSieve authentication cleanup failed.", failure.Message);
                Assert.Null(failure.InnerException);
                break;
            case "server-no":
                var rejection = Assert.IsType<ManageSieveAuthenticationException>(failure);
                Assert.Equal("ManageSieve authentication failed.", rejection.Message);
                Assert.Equal("AUTHENTICATIONFAILED", rejection.ResponseCode);
                break;
            default:
                Assert.IsType<ManageSieveAuthenticationException>(failure);
                Assert.Equal("ManageSieve authenticator failed.", failure.Message);
                Assert.Null(failure.InnerException);
                break;
        }
    }

    private static string Base64(string value) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(value));

    private static ManageSieveScramSha256PlusAuthenticator
        CreateScramSha256PlusAuthenticator() =>
        new(
            "user",
            "pencil",
            authorizationIdentity: null,
            nonceFactory: () => ScramSha256PlusNonce);

    private sealed class RecordingChannelBindingLifecycleAuthenticator(
        List<string>? trace = null) :
        IManageSieveAuthenticator,
        IManageSieveChannelBindingAuthenticator
    {
        public string Mechanism => "SCRAM-SHA-256-PLUS";

        public string ChannelBindingName { get; init; } = "tls-server-end-point";

        public List<string> Calls { get; } = trace ?? [];

        public byte[]? Binding { get; private set; }

        public void SetChannelBinding(ReadOnlyMemory<byte> binding)
        {
            Calls.Add("SetBinding");
            Binding = binding.ToArray();
        }

        public ValueTask<ReadOnlyMemory<byte>?> GetInitialResponseAsync(
            CancellationToken cancellationToken = default)
        {
            Calls.Add("Initial");
            return ValueTask.FromResult<ReadOnlyMemory<byte>?>(null);
        }

        public ValueTask<ReadOnlyMemory<byte>> RespondAsync(
            ReadOnlyMemory<byte> challenge,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(ReadOnlyMemory<byte>.Empty);

        public ValueTask CompleteAsync(
            ReadOnlyMemory<byte>? serverData,
            CancellationToken cancellationToken = default)
        {
            Calls.Add("Complete");
            return ValueTask.CompletedTask;
        }

        public void Abort() => Calls.Add("Abort");
    }

    private sealed class LegacyAuthenticator : IManageSieveAuthenticator
    {
        public string Mechanism => "LEGACY";

        public ValueTask<ReadOnlyMemory<byte>?> GetInitialResponseAsync(
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<ReadOnlyMemory<byte>?>(null);

        public ValueTask<ReadOnlyMemory<byte>> RespondAsync(
            ReadOnlyMemory<byte> challenge,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<ReadOnlyMemory<byte>>(ReadOnlyMemory<byte>.Empty);
    }

    private sealed class StatefulMechanismAuthenticator : IManageSieveAuthenticator
    {
        public int MechanismReads { get; private set; }

        public string Mechanism => MechanismReads++ == 0 ? "TEST" : "CHANGED";

        public ValueTask<ReadOnlyMemory<byte>?> GetInitialResponseAsync(
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<ReadOnlyMemory<byte>?>(null);

        public ValueTask<ReadOnlyMemory<byte>> RespondAsync(
            ReadOnlyMemory<byte> challenge,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(ReadOnlyMemory<byte>.Empty);
    }

    private sealed class OwnershipProbeAuthenticator(
        byte[] initialResponse,
        byte[] challengeResponse) : IManageSieveAuthenticator
    {
        public string Mechanism => "TEST";

        public ValueTask<ReadOnlyMemory<byte>?> GetInitialResponseAsync(
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<ReadOnlyMemory<byte>?>(initialResponse);

        public ValueTask<ReadOnlyMemory<byte>> RespondAsync(
            ReadOnlyMemory<byte> challenge,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<ReadOnlyMemory<byte>>(challengeResponse);
    }

    private sealed class RecordingPlainAuthenticator(
        string userName,
        string password) : IManageSieveAuthenticator
    {
        private readonly ManageSievePlainAuthenticator inner = new(userName, password);

        public string Mechanism => inner.Mechanism;

        public List<string> Calls { get; } = [];

        public ReadOnlyMemory<byte>? InitialResponse { get; private set; }

        public ReadOnlyMemory<byte>? CompletionMemory { get; private set; }

        public async ValueTask<ReadOnlyMemory<byte>?> GetInitialResponseAsync(
            CancellationToken cancellationToken = default)
        {
            Calls.Add("Initial");
            InitialResponse = await inner.GetInitialResponseAsync(cancellationToken);
            return InitialResponse;
        }

        public ValueTask<ReadOnlyMemory<byte>> RespondAsync(
            ReadOnlyMemory<byte> challenge,
            CancellationToken cancellationToken = default)
        {
            Calls.Add("Respond");
            return inner.RespondAsync(challenge, cancellationToken);
        }

        public async ValueTask CompleteAsync(
            ReadOnlyMemory<byte>? serverData,
            CancellationToken cancellationToken = default)
        {
            Calls.Add("Complete");
            CompletionMemory = serverData;
            await inner.CompleteAsync(serverData, cancellationToken);
        }

        public void Abort()
        {
            Calls.Add("Abort");
            inner.Abort();
        }
    }

}
