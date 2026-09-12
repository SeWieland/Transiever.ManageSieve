namespace Transiever.ManageSieve.UnitTest;

public sealed class ManageSieveAuthenticatorCompatibilityTests
{
    [Fact]
    public void LegacyAuthenticator_DoesNotRequireClientCertificate()
    {
        IManageSieveAuthenticator authenticator = new LegacyAuthenticator();

        Assert.False(authenticator.RequiresClientCertificate);
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
            ValueTask.FromResult(ReadOnlyMemory<byte>.Empty);
    }
}
