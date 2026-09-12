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
    public async Task Identity_Uses1024Utf8OctetBoundary()
    {
        var authenticator = new ManageSieveExternalAuthenticator(new string('é', 512));

        ReadOnlyMemory<byte>? response = await authenticator.GetInitialResponseAsync(
            TestContext.Current.CancellationToken);
        string tooLong = new string('é', 512) + "a";
        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => new ManageSieveExternalAuthenticator(tooLong));

        Assert.Equal(1024, response?.Length);
        Assert.DoesNotContain(tooLong, exception.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("nul\0identity")]
    public void Identity_RejectsInvalidTextWithoutEchoingIt(string identity)
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => new ManageSieveExternalAuthenticator(identity));

        Assert.DoesNotContain(identity, exception.ToString(), StringComparison.Ordinal);
        Assert.Null(exception.InnerException);
    }

    [Fact]
    public void Identity_RejectsInvalidUtf16WithoutInnerException()
    {
        string identity = new('\uD800', 1);

        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => new ManageSieveExternalAuthenticator(identity));

        Assert.Null(exception.InnerException);
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
