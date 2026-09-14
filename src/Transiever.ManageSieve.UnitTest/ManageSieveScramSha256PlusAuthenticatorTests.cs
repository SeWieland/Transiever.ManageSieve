namespace Transiever.ManageSieve.UnitTest;

using System.Security.Authentication;

public sealed class ManageSieveScramSha256PlusAuthenticatorTests
{
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

}
