namespace Transiever.ManageSieve.UnitTest;

public sealed class ManageSieveExternalAuthenticatorTests
{
    [Theory]
    [InlineData(null, "")]
    [InlineData("", "")]
    [InlineData("alice@example.com", "616C696365406578616D706C652E636F6D")]
    [InlineData("Jörg", "4AC3B67267")]
    public async Task InitialResponse_UsesExactStrictUtf8(
        string? identity,
        string expectedHex)
    {
        var authenticator = new ManageSieveExternalAuthenticator(identity);

        ReadOnlyMemory<byte>? response = await authenticator.GetInitialResponseAsync(
            TestContext.Current.CancellationToken);

        Assert.Equal("EXTERNAL", authenticator.Mechanism);
        Assert.True(authenticator.RequiresClientCertificate);
        Assert.NotNull(response);
        Assert.Equal(Convert.FromHexString(expectedHex), response.Value.ToArray());
    }

    [Fact]
    public async Task Exchange_RejectsChallengesAndCompletionData()
    {
        var challenge = new ManageSieveExternalAuthenticator();
        await challenge.GetInitialResponseAsync(TestContext.Current.CancellationToken);
        await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
            () => challenge.RespondAsync(
                "challenge"u8.ToArray(),
                TestContext.Current.CancellationToken).AsTask());

        var emptyCompletion = new ManageSieveExternalAuthenticator();
        await emptyCompletion.GetInitialResponseAsync(TestContext.Current.CancellationToken);
        await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
            () => emptyCompletion.CompleteAsync(
                ReadOnlyMemory<byte>.Empty,
                TestContext.Current.CancellationToken).AsTask());

        var dataCompletion = new ManageSieveExternalAuthenticator();
        await dataCompletion.GetInitialResponseAsync(TestContext.Current.CancellationToken);
        await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
            () => dataCompletion.CompleteAsync(
                "data"u8.ToArray(),
                TestContext.Current.CancellationToken).AsTask());
    }

    [Fact]
    public async Task Complete_ClearsResponseAndMakesLifecycleTerminal()
    {
        var authenticator = new ManageSieveExternalAuthenticator("alice@example.com");
        ReadOnlyMemory<byte> response = (await authenticator.GetInitialResponseAsync(
            TestContext.Current.CancellationToken))!.Value;

        await authenticator.CompleteAsync(null, TestContext.Current.CancellationToken);

        Assert.All(response.ToArray(), value => Assert.Equal(0, value));
        await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
            () => authenticator.GetInitialResponseAsync(
                TestContext.Current.CancellationToken).AsTask());
        await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
            () => authenticator.RespondAsync(
                ReadOnlyMemory<byte>.Empty,
                TestContext.Current.CancellationToken).AsTask());
        await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
            () => authenticator.CompleteAsync(
                null,
                TestContext.Current.CancellationToken).AsTask());

        authenticator.Abort();
    }

    [Fact]
    public async Task Abort_ClearsResponseAndDoesNotThrow()
    {
        var authenticator = new ManageSieveExternalAuthenticator("Jörg");
        ReadOnlyMemory<byte> response = (await authenticator.GetInitialResponseAsync(
            TestContext.Current.CancellationToken))!.Value;

        await Assert.ThrowsAsync<ManageSieveAuthenticationException>(
            () => authenticator.GetInitialResponseAsync(
                TestContext.Current.CancellationToken).AsTask());

        authenticator.Abort();

        Assert.All(response.ToArray(), value => Assert.Equal(0, value));
    }
}
