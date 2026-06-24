using global::Transiever.ManageSieve;
using System.Diagnostics;
using Xunit.Sdk;

namespace Transiever.ManageSieve.IntegrationTest;

[CollectionDefinition(Name)]
public sealed class DovecotCollection : ICollectionFixture<DovecotFixture>
{
    public const string Name = "Disposable Dovecot";
}

[Collection(DovecotCollection.Name)]
public sealed class ManageSieveIntegrationTests(DovecotFixture fixture)
{
    [DockerFact]
    public async Task CompleteProtocolSurface_RoundTripsAgainstDovecot()
    {
        SkipWhenDockerIsUnavailable();
        string first = $"transiever-{Guid.NewGuid():N}";
        string renamed = $"{first}-renamed";
        byte[] content = "# Transiever integration test\r\nkeep;\r\n"u8.ToArray();

        await using ManageSieveClient client = fixture.CreateClient();
        await client.ConnectAsync();
        Assert.True(client.Capabilities?.SupportsStartTls);

        await client.StartTlsAsync();
        Assert.Equal(ManageSieveSessionState.Secured, client.State);

        await client.AuthenticateAsync(
            new ManageSievePlainAuthenticator(
                "transiever",
                "transiever-password"));
        Assert.Equal(ManageSieveSessionState.Authenticated, client.State);

        try
        {
            ManageSieveCapabilities capabilities =
                await client.RefreshCapabilitiesAsync();
            Assert.Contains("PLAIN", capabilities.SaslMechanisms);

            Assert.True((await client.HaveSpaceAsync(first, content.Length)).HasSpace);
            Assert.NotNull(await client.CheckScriptAsync(content));
            await client.PutScriptAsync(first, content);

            IReadOnlyList<ManageSieveScriptInfo> scripts =
                await client.ListScriptsAsync();
            Assert.Contains(scripts, script => script.Name == first && !script.IsActive);

            ManageSieveScript downloaded = await client.GetScriptAsync(first);
            Assert.Equal(content, downloaded.Content.ToArray());

            await client.SetActiveScriptAsync(first);
            Assert.Contains(
                await client.ListScriptsAsync(),
                script => script.Name == first && script.IsActive);

            await client.SetActiveScriptAsync(null);
            await client.RenameScriptAsync(first, renamed);
            Assert.Equal(content, (await client.GetScriptAsync(renamed)).Content.ToArray());

            await client.DeleteScriptAsync(renamed);
            await Assert.ThrowsAsync<ManageSieveCommandException>(
                () => client.GetScriptAsync(renamed).AsTask());

            Assert.NotNull(await client.NoOpAsync("integration"));
            await client.UnauthenticateAsync();
            Assert.Equal(ManageSieveSessionState.Secured, client.State);
        }
        finally
        {
            await CleanupAsync(client, first, renamed);
        }

        await client.LogoutAsync();
    }

    private void SkipWhenDockerIsUnavailable()
    {
        if (fixture.UnavailableReason is not null)
        {
            throw new XunitException(fixture.UnavailableReason);
        }
    }

    private static async Task CleanupAsync(
        ManageSieveClient client,
        params string[] names)
    {
        if (client.State != ManageSieveSessionState.Authenticated)
        {
            return;
        }

        IReadOnlyList<ManageSieveScriptInfo> scripts = await client.ListScriptsAsync();
        foreach (string name in names)
        {
            if (scripts.Any(script => script.Name == name))
            {
                if (scripts.Any(script => script.Name == name && script.IsActive))
                {
                    await client.SetActiveScriptAsync(null);
                }

                await client.DeleteScriptAsync(name);
            }
        }
    }
}

internal sealed class DockerFactAttribute : FactAttribute
{
    public DockerFactAttribute()
    {
        try
        {
            using var process = Process.Start(
                new ProcessStartInfo
                {
                    FileName = "docker",
                    Arguments = "version --format {{.Server.Version}}",
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false
                });
            if (process is null ||
                !process.WaitForExit(5_000) ||
                process.ExitCode != 0)
            {
                Skip = "Docker-backed ManageSieve tests require a running Docker daemon.";
            }
        }
        catch
        {
            Skip = "Docker-backed ManageSieve tests require the Docker CLI and a running daemon.";
        }
    }
}
