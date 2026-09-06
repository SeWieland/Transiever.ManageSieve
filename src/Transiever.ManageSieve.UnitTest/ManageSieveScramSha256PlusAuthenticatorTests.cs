namespace Transiever.ManageSieve.UnitTest;

using System.Security.Authentication;
using System.Text;

public sealed class ManageSieveScramSha256PlusAuthenticatorTests
{
    private const string ClientNonce = "rOprNGfwEbeRWgbNEkqO";
    private const string ServerNonce = ClientNonce + "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
    private const string ServerFirst =
        "r=" + ServerNonce + ",s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
    private static readonly byte[] EndpointBinding =
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
         0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    private static readonly byte[] CertificateDer =
        [0x30, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    public static IEnumerable<object[]> SupportedSignatureAlgorithms()
    {
        const string sha256 = "d493933cfb11a10052dbb29ab90ae44ac3294ae370d06ff946c76ebaf4bfedae";
        const string sha384 = "52460ea66bd43d8b7b8a269b46eb59f05041f05efdad9c7181ec23a41621ee6da191fa83d25413464b09c7a84fcfa9a2";
        const string sha512 = "b6b0f2c5a27d5b3bbc7be755860022b52de1c9cfe958b6f30cffff94c5d173a4ef66911c9491ce910ac516988778ae3edc64677d87a35be01b2e7f0f054d7e66";

        foreach (string oid in new[]
        {
            "1.2.840.113549.1.1.4", "1.2.840.113549.2.5",
            "1.3.14.3.2.26", "1.2.840.10040.4.3", "1.2.840.10045.4.1", "1.2.840.113549.1.1.5",
            "2.16.840.1.101.3.4.2.1", "1.2.840.10045.4.3.2", "1.2.840.113549.1.1.11"
        })
        {
            yield return [oid, sha256];
        }

        foreach (string oid in new[]
        {
            "2.16.840.1.101.3.4.2.2", "1.2.840.10045.4.3.3", "1.2.840.113549.1.1.12"
        })
        {
            yield return [oid, sha384];
        }

        foreach (string oid in new[]
        {
            "2.16.840.1.101.3.4.2.3", "1.2.840.10045.4.3.4", "1.2.840.113549.1.1.13"
        })
        {
            yield return [oid, sha512];
        }
    }

    [Theory]
    [MemberData(nameof(SupportedSignatureAlgorithms))]
    public void TlsServerEndPointBinding_maps_signature_algorithm(
        string signatureAlgorithmOid,
        string expectedHex)
    {
        byte[] binding = TcpManageSieveTransport.DeriveTlsServerEndPointBinding(
            SslProtocols.Tls12,
            CertificateDer,
            signatureAlgorithmOid);

        Assert.Equal(Convert.FromHexString(expectedHex), binding);
    }

    [Theory]
    [InlineData(SslProtocols.None, "1.2.840.113549.1.1.11")]
    [InlineData(SslProtocols.Tls13, "1.2.840.113549.1.1.11")]
    [InlineData(SslProtocols.Tls12, null)]
    [InlineData(SslProtocols.Tls12, "1.2.3.4")]
    public void TlsServerEndPointBinding_rejects_unsupported_channel(
        SslProtocols protocol,
        string? signatureAlgorithmOid)
    {
        ManageSieveAuthenticationException exception =
            Assert.Throws<ManageSieveAuthenticationException>(
            () => TcpManageSieveTransport.DeriveTlsServerEndPointBinding(
                protocol,
                CertificateDer,
                signatureAlgorithmOid));

        if (protocol == SslProtocols.Tls13)
        {
            Assert.Equal(
                "SCRAM-SHA-256-PLUS requires a supported TLS 1.2 channel binding.",
                exception.Message);
        }
    }

    [Fact]
    public void TlsServerEndPointBinding_rejects_missing_certificate()
    {
        Assert.Throws<ManageSieveAuthenticationException>(
            () => TcpManageSieveTransport.DeriveTlsServerEndPointBinding(
                SslProtocols.Tls12,
                ReadOnlySpan<byte>.Empty,
                "1.2.840.113549.1.1.11"));
    }

    [Fact]
    public async Task Plus_initial_response_contains_exact_unbound_gs2_header()
    {
        var authenticator = new ManageSieveScramSha256PlusAuthenticator(
            "user", "pencil", authorizationIdentity: null,
            nonceFactory: () => ClientNonce);
        IManageSieveChannelBindingAuthenticator bindingAuthenticator = authenticator;
        bindingAuthenticator.SetChannelBinding(EndpointBinding);

        Assert.Equal(
            "p=tls-server-end-point,,n=user,r=rOprNGfwEbeRWgbNEkqO"u8.ToArray(),
            (await authenticator.GetInitialResponseAsync(
                TestContext.Current.CancellationToken))?.ToArray());
    }

    [Fact]
    public async Task Plus_proof_uses_raw_endpoint_binding_and_escaped_authorization_identity()
    {
        var authenticator = new ManageSieveScramSha256PlusAuthenticator(
            "user", "pencil", "auth=z,id", () => ClientNonce);
        IManageSieveChannelBindingAuthenticator bindingAuthenticator = authenticator;
        bindingAuthenticator.SetChannelBinding(EndpointBinding);

        await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken);
        ReadOnlyMemory<byte> response = await authenticator.RespondAsync(
            Encoding.UTF8.GetBytes(ServerFirst), TestContext.Current.CancellationToken);

        Assert.Equal(
            "c=cD10bHMtc2VydmVyLWVuZC1wb2ludCxhPWF1dGg9M0R6PTJDaWQsABEiM0RVZneImaq7zN3u/w==,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=BBA0e81cyx7GsKJW4dRhCvKNltHFsz7b/3mV1FaFuC8="u8.ToArray(),
            response.ToArray());
    }

    [Fact]
    public async Task Plus_rejects_missing_binding_without_emitting_bare_scram()
    {
        var authenticator = new ManageSieveScramSha256PlusAuthenticator(
            "user", "pencil", authorizationIdentity: null,
            nonceFactory: () => ClientNonce);

        await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
            () => authenticator.GetInitialResponseAsync(
                TestContext.Current.CancellationToken).AsTask());
    }

    [Fact]
    public void Plus_rejects_empty_binding_input()
    {
        var authenticator = new ManageSieveScramSha256PlusAuthenticator(
            "user", "pencil", authorizationIdentity: null,
            nonceFactory: () => ClientNonce);
        IManageSieveChannelBindingAuthenticator bindingAuthenticator = authenticator;

        Assert.Throws<ManageSieveAuthenticationException>(
            () => bindingAuthenticator.SetChannelBinding(ReadOnlyMemory<byte>.Empty));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Plus_rejects_second_binding_input(bool identical)
    {
        var authenticator = new ManageSieveScramSha256PlusAuthenticator(
            "user", "pencil", authorizationIdentity: null,
            nonceFactory: () => ClientNonce);
        IManageSieveChannelBindingAuthenticator bindingAuthenticator = authenticator;

        bindingAuthenticator.SetChannelBinding(EndpointBinding);
        ReadOnlyMemory<byte> secondBinding = identical
            ? EndpointBinding
            : new byte[EndpointBinding.Length + 1];

        Assert.Throws<ManageSieveAuthenticationException>(
            () => bindingAuthenticator.SetChannelBinding(secondBinding));
    }
}
