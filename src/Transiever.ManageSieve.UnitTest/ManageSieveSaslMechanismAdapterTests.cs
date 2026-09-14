using System.Text;
using Transiever.SaslClient;
using static Transiever.ManageSieve.UnitTest.SaslConformanceHarness;

namespace Transiever.ManageSieve.UnitTest;

public sealed class ManageSieveSaslMechanismAdapterTests
{
    private static readonly byte[] Binding = [0x01, 0x02, 0x03, 0x04];

    [Fact]
    public async Task Adapter_runs_neutral_mechanism_through_manage_sieve_exchange()
    {
        string encodedChallenge = Convert.ToBase64String("challenge"u8);
        string encodedFinal = Convert.ToBase64String("final"u8);
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(
                Encoding.ASCII.GetBytes(
                    $"\"SASL\" \"TEST\"\r\nOK\r\n\"{encodedChallenge}\"\r\n" +
                    $"OK (SASL \"{encodedFinal}\")\r\n"));
        var mechanism = new RecordingMechanism();

        await harness.Client.AuthenticateAsync(
            new ManageSieveSaslMechanismAdapter(mechanism),
            TestContext.Current.CancellationToken);

        Assert.Equal(
            ["Initial", "Challenge:challenge", "Complete:final"],
            mechanism.Calls);
        AssertTranscriptEqual(
            "AUTHENTICATE \"TEST\" \"aW5pdGlhbA==\"\r\n\"cmVzcG9uc2U=\"\r\n"u8,
            harness.Transport.Written.Span);
        Assert.Equal(ManageSieveSessionState.Authenticated, harness.Client.State);
    }

    [Fact]
    public async Task Adapter_preserves_package_transport_requirements_before_callbacks()
    {
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(
                "\"SASL\" \"TEST\"\r\nOK\r\n"u8.ToArray(),
                ManageSieveSecurityMode.PlainText,
                secure: false);
        var mechanism = new RecordingMechanism();

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => harness.Client.AuthenticateAsync(
                new ManageSieveSaslMechanismAdapter(mechanism),
                TestContext.Current.CancellationToken).AsTask());

        Assert.Empty(mechanism.Calls);
        Assert.True(harness.Transport.Written.IsEmpty);
    }

    [Fact]
    public async Task Adapter_forwards_attempt_bound_channel_binding_before_initial_response()
    {
        List<string> trace = [];
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(
                "\"SASL\" \"TEST-PLUS\"\r\nOK\r\nOK\r\n"u8.ToArray(),
                tlsServerEndPointBinding: Binding,
                tlsServerEndPointBindingTrace: trace);
        var mechanism = new RecordingChannelBindingMechanism(trace);

        await harness.Client.AuthenticateAsync(
            new ManageSieveSaslMechanismAdapter(mechanism),
            TestContext.Current.CancellationToken);

        Assert.Equal(["GetBinding", "SetBinding", "Initial", "Complete"], trace);
        Assert.Equal(Binding, mechanism.Binding);
        AssertZeroed(harness.Transport.IssuedTlsServerEndPointBindings.Select(
            binding => (ReadOnlyMemory<byte>)binding));
    }

    [Fact]
    public async Task Adapter_translates_package_authentication_failures()
    {
        var adapter = new ManageSieveSaslMechanismAdapter(
            new FailingMechanism());

        ManageSieveAuthenticationException exception =
            await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
                () => adapter.GetInitialResponseAsync(
                    TestContext.Current.CancellationToken).AsTask());

        Assert.Equal("ManageSieve authenticator failed.", exception.Message);
        Assert.Null(exception.InnerException);
        Assert.DoesNotContain("secret", exception.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Adapter_redacts_channel_binding_callback_failures(bool propertyFailure)
    {
        await using SaslConformanceHarness harness =
            await SaslConformanceHarness.ConnectAsync(
                "\"SASL\" \"TEST-PLUS\"\r\nOK\r\n"u8.ToArray(),
                tlsServerEndPointBinding: Binding);
        var mechanism = new FailingChannelBindingMechanism(propertyFailure);

        ManageSieveAuthenticationException exception =
            await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
                () => harness.Client.AuthenticateAsync(
                    new ManageSieveSaslMechanismAdapter(mechanism),
                    TestContext.Current.CancellationToken).AsTask());

        Assert.Equal("ManageSieve authenticator failed.", exception.Message);
        Assert.DoesNotContain("secret", exception.ToString(), StringComparison.Ordinal);
        Assert.Equal(1, mechanism.AbortCount);
        Assert.True(harness.Transport.Written.IsEmpty);
    }

    [Theory]
    [InlineData("mechanism")]
    [InlineData("transport")]
    [InlineData("certificate")]
    public void Adapter_redacts_package_metadata_failures(string member)
    {
        var adapter = new ManageSieveSaslMechanismAdapter(
            new FailingMetadataMechanism(member));

        ManageSieveAuthenticationException exception =
            Assert.Throws<ManageSieveAuthenticationException>(() =>
            {
                _ = member switch
                {
                    "mechanism" => adapter.Mechanism.Length,
                    "transport" => adapter.AllowsUnprotectedConnection ? 1 : 0,
                    _ => adapter.RequiresClientCertificate ? 1 : 0
                };
            });

        Assert.Equal("ManageSieve authenticator failed.", exception.Message);
        Assert.DoesNotContain("secret", exception.ToString(), StringComparison.Ordinal);
    }

    private sealed class RecordingMechanism : ISaslMechanism
    {
        public string Mechanism => "TEST";

        public List<string> Calls { get; } = [];

        public ValueTask<ReadOnlyMemory<byte>?> GetInitialResponseAsync(
            CancellationToken cancellationToken = default)
        {
            Calls.Add("Initial");
            return ValueTask.FromResult<ReadOnlyMemory<byte>?>("initial"u8.ToArray());
        }

        public ValueTask<ReadOnlyMemory<byte>> RespondAsync(
            ReadOnlyMemory<byte> challenge,
            CancellationToken cancellationToken = default)
        {
            Calls.Add($"Challenge:{Encoding.UTF8.GetString(challenge.Span)}");
            return ValueTask.FromResult<ReadOnlyMemory<byte>>("response"u8.ToArray());
        }

        public ValueTask CompleteAsync(
            ReadOnlyMemory<byte>? serverData,
            CancellationToken cancellationToken = default)
        {
            Calls.Add($"Complete:{Encoding.UTF8.GetString(serverData!.Value.Span)}");
            return ValueTask.CompletedTask;
        }
    }

    private sealed class RecordingChannelBindingMechanism(List<string> trace) :
        ISaslMechanism,
        ISaslChannelBindingMechanism
    {
        public string Mechanism => "TEST-PLUS";

        public string ChannelBindingName => "tls-server-end-point";

        public byte[]? Binding { get; private set; }

        public void SetChannelBinding(ReadOnlyMemory<byte> binding)
        {
            trace.Add("SetBinding");
            Binding = binding.ToArray();
        }

        public ValueTask<ReadOnlyMemory<byte>?> GetInitialResponseAsync(
            CancellationToken cancellationToken = default)
        {
            trace.Add("Initial");
            return ValueTask.FromResult<ReadOnlyMemory<byte>?>(null);
        }

        public ValueTask<ReadOnlyMemory<byte>> RespondAsync(
            ReadOnlyMemory<byte> challenge,
            CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException();

        public ValueTask CompleteAsync(
            ReadOnlyMemory<byte>? serverData,
            CancellationToken cancellationToken = default)
        {
            trace.Add("Complete");
            return ValueTask.CompletedTask;
        }
    }

    private sealed class FailingMechanism : ISaslMechanism
    {
        public string Mechanism => "TEST";

        public ValueTask<ReadOnlyMemory<byte>?> GetInitialResponseAsync(
            CancellationToken cancellationToken = default) =>
            ValueTask.FromException<ReadOnlyMemory<byte>?>(
                new SaslAuthenticationException("secret callback details"));

        public ValueTask<ReadOnlyMemory<byte>> RespondAsync(
            ReadOnlyMemory<byte> challenge,
            CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException();
    }

    private sealed class FailingChannelBindingMechanism(bool propertyFailure) :
        ISaslMechanism,
        ISaslChannelBindingMechanism
    {
        public string Mechanism => "TEST-PLUS";

        public string ChannelBindingName => propertyFailure
            ? throw new SaslAuthenticationException("secret property details")
            : "tls-server-end-point";

        public int AbortCount { get; private set; }

        public void SetChannelBinding(ReadOnlyMemory<byte> binding)
        {
            throw new SaslAuthenticationException("secret setter details");
        }

        public ValueTask<ReadOnlyMemory<byte>?> GetInitialResponseAsync(
            CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException();

        public ValueTask<ReadOnlyMemory<byte>> RespondAsync(
            ReadOnlyMemory<byte> challenge,
            CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException();

        public void Abort() => AbortCount++;
    }

    private sealed class FailingMetadataMechanism(string member) : ISaslMechanism
    {
        public string Mechanism => member == "mechanism"
            ? throw new SaslAuthenticationException("secret mechanism details")
            : "TEST";

        public bool AllowsUnprotectedConnection => member == "transport"
            ? throw new SaslAuthenticationException("secret transport details")
            : false;

        public bool RequiresClientCertificate => member == "certificate"
            ? throw new SaslAuthenticationException("secret certificate details")
            : false;

        public ValueTask<ReadOnlyMemory<byte>?> GetInitialResponseAsync(
            CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException();

        public ValueTask<ReadOnlyMemory<byte>> RespondAsync(
            ReadOnlyMemory<byte> challenge,
            CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException();
    }
}
