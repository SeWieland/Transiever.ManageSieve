using global::Transiever.ManageSieve;
using System.Security.Cryptography;
using Xunit.Sdk;

namespace Transiever.ManageSieve.LiveTest;

public sealed class ManageSieveLiveTests
{
    [LiveFact]
    public async Task ReadOnlyProtocolSurface()
    {
        LiveConfiguration configuration = LiveConfiguration.Load(writeRequired: false);
        await using IManageSieveClient client = await ConnectAsync(configuration);

        ManageSieveCapabilities capabilities = await client.RefreshCapabilitiesAsync();
        IReadOnlyList<ManageSieveScriptInfo> scripts = await client.ListScriptsAsync();
        foreach (ManageSieveScriptInfo script in scripts)
        {
            Assert.Equal(
                script.Name,
                (await client.GetScriptAsync(script.Name)).Name);
        }

        byte[] harmless = "# Transiever live read-only validation\r\nkeep;\r\n"u8.ToArray();
        Assert.NotNull(await client.CheckScriptAsync(harmless));
        Assert.NotNull(
            await client.HaveSpaceAsync(
                $"transiever-test-{Guid.NewGuid():N}",
                harmless.Length));
        Assert.NotNull(await client.NoOpAsync("transiever-live-read-only"));
        Assert.NotNull(capabilities);
    }

    [LiveFact(writes: true)]
    public async Task GuardedWriteSurface_DoesNotTouchExistingScripts()
    {
        LiveConfiguration configuration = LiveConfiguration.Load(writeRequired: true);
        await using IManageSieveClient client = await ConnectAsync(configuration);
        IReadOnlyList<ScriptSnapshot> initial = await SnapshotAsync(client);
        HashSet<string> initialNames =
            initial.Select(script => script.Name).ToHashSet(StringComparer.Ordinal);
        string first = $"transiever-test-{Guid.NewGuid():N}";
        string renamed = $"{first}-renamed";
        HashSet<string> owned = [first, renamed];
        List<string> cleanupFailures = [];
        byte[] harmless = "# Transiever owned live test script\r\nkeep;\r\n"u8.ToArray();

        try
        {
            Assert.DoesNotContain(first, initialNames);
            Assert.DoesNotContain(renamed, initialNames);
            await client.CheckScriptAsync(harmless);
            await client.PutScriptAsync(first, harmless);
            await client.RenameScriptAsync(first, renamed);
            Assert.Equal(harmless, (await client.GetScriptAsync(renamed)).Content.ToArray());
            await client.DeleteScriptAsync(renamed);
        }
        finally
        {
            try
            {
                IReadOnlyList<ManageSieveScriptInfo> current =
                    await client.ListScriptsAsync();
                foreach (string name in owned)
                {
                    if (!initialNames.Contains(name) &&
                        current.Any(script => script.Name == name && !script.IsActive))
                    {
                        try
                        {
                            await client.DeleteScriptAsync(name);
                        }
                        catch (Exception exception)
                        {
                            cleanupFailures.Add($"{name}: {exception.Message}");
                        }
                    }
                    else if (!initialNames.Contains(name) &&
                        current.Any(script => script.Name == name && script.IsActive))
                    {
                        cleanupFailures.Add(
                            $"{name}: temporary script is active; automatic cleanup refused");
                    }
                }
            }
            catch (Exception exception)
            {
                cleanupFailures.Add($"Could not list scripts during cleanup: {exception.Message}");
            }

            if (cleanupFailures.Count > 0)
            {
                throw new XunitException(
                    "Live-test cleanup failed. Inspect and manually remove only these exact temporary names: " +
                    string.Join("; ", cleanupFailures));
            }
        }

        IReadOnlyList<ScriptSnapshot> after = await SnapshotAsync(client);
        Assert.Equal(initial.OrderBy(item => item.Name), after.OrderBy(item => item.Name));
    }

    private static async Task<IManageSieveClient> ConnectAsync(
        LiveConfiguration configuration)
    {
        IManageSieveClient client = new ManageSieveClientFactory().CreateClient(
            new ManageSieveClientOptions
            {
                Host = configuration.Host,
                Port = configuration.Port,
                SecurityMode = configuration.SecurityMode
            });
        await client.ConnectAsync();
        if (configuration.SecurityMode == ManageSieveSecurityMode.StartTlsRequired)
        {
            await client.StartTlsAsync();
        }

        await client.AuthenticateAsync(
            new ManageSievePlainAuthenticator(
                configuration.UserName,
                configuration.Password));
        return client;
    }

    private static async Task<IReadOnlyList<ScriptSnapshot>> SnapshotAsync(
        IManageSieveClient client)
    {
        IReadOnlyList<ManageSieveScriptInfo> scripts = await client.ListScriptsAsync();
        var snapshots = new List<ScriptSnapshot>(scripts.Count);
        foreach (ManageSieveScriptInfo script in scripts)
        {
            ManageSieveScript content = await client.GetScriptAsync(script.Name);
            snapshots.Add(
                new ScriptSnapshot(
                    script.Name,
                    script.IsActive,
                    Convert.ToHexString(SHA256.HashData(content.Content.Span))));
        }

        return snapshots;
    }

    private sealed record ScriptSnapshot(string Name, bool IsActive, string ContentHash);

    private sealed record LiveConfiguration(
        string Host,
        int Port,
        string UserName,
        string Password,
        ManageSieveSecurityMode SecurityMode)
    {
        public static LiveConfiguration Load(bool writeRequired)
        {
            string host = Required("TRANSIEVER_LIVE_HOST");
            string userName = Required("TRANSIEVER_LIVE_USERNAME");
            string password = Required("TRANSIEVER_LIVE_PASSWORD");
            int port = int.TryParse(
                Environment.GetEnvironmentVariable("TRANSIEVER_LIVE_PORT"),
                out int configuredPort)
                ? configuredPort
                : ManageSieveClientOptions.DefaultPort;
            ManageSieveSecurityMode securityMode = Enum.TryParse(
                Environment.GetEnvironmentVariable("TRANSIEVER_LIVE_SECURITY_MODE"),
                ignoreCase: true,
                out ManageSieveSecurityMode configuredMode)
                ? configuredMode
                : ManageSieveSecurityMode.StartTlsRequired;

            return new LiveConfiguration(
                host,
                port,
                userName,
                password,
                securityMode);
        }

        private static string Required(string name) =>
            Environment.GetEnvironmentVariable(name) is { Length: > 0 } value
                ? value
                : throw new XunitException(
                    $"Environment variable {name} is required for live tests.");
    }
}

internal sealed class LiveFactAttribute : FactAttribute
{
    public LiveFactAttribute(bool writes = false)
    {
        if (!Enabled("TRANSIEVER_LIVE_TESTS"))
        {
            Skip = "Set TRANSIEVER_LIVE_TESTS=true to enable live-provider tests.";
        }
        else if (writes && !Enabled("TRANSIEVER_LIVE_WRITES"))
        {
            Skip = "Set TRANSIEVER_LIVE_WRITES=true to enable guarded live write tests.";
        }
    }

    private static bool Enabled(string name) =>
        bool.TryParse(Environment.GetEnvironmentVariable(name), out bool enabled) &&
        enabled;
}
