using System.Text;
using Transiever.ManageSieve;
using Transiever.ManageSieve.Cli;

namespace Transiever.ManageSieve.Cli.UnitTest;

public sealed class ManageSieveCliApplicationTests
{
    [Fact]
    public async Task CapabilitiesConnectsWithoutAuthentication()
    {
        var client = new FakeManageSieveClient
        {
            CapabilitiesResult = new ManageSieveCapabilities
            {
                Implementation = "Dovecot",
                ProtocolVersion = "1.0",
                SaslMechanisms = new HashSet<string>(["PLAIN"]),
                SieveExtensions = new HashSet<string>(["fileinto"]),
                NotificationMethods = new HashSet<string>(["mailto"]),
                Additional = new Dictionary<string, string?>
                {
                    ["XTEST"] = "value"
                }
            }
        };
        TestApplication app = CreateApplication(client);

        int exitCode = await app.Application.RunAsync(
            CommandLineOptions.Parse(["capabilities"]));

        Assert.Equal(0, exitCode);
        Assert.True(client.Connected);
        Assert.True(client.StartTlsCalled);
        Assert.False(client.Authenticated);
        Assert.Contains("Implementation: Dovecot", app.TextOutput);
        Assert.Contains("SASL mechanisms: PLAIN", app.TextOutput);
    }

    [Fact]
    public async Task ListPrintsScriptsAndAuthenticates()
    {
        var client = new FakeManageSieveClient
        {
            Scripts =
            [
                new ManageSieveScriptInfo("one", false),
                new ManageSieveScriptInfo("two", true)
            ]
        };
        TestApplication app = CreateApplication(client);

        int exitCode = await app.Application.RunAsync(
            CommandLineOptions.Parse(["list"]));

        Assert.Equal(0, exitCode);
        Assert.True(client.Authenticated);
        Assert.Contains("  one", app.TextOutput);
        Assert.Contains("* two", app.TextOutput);
    }

    [Fact]
    public async Task GetWritesRawBytesToStandardOutput()
    {
        byte[] content = [0, 1, 13, 10, 195, 164];
        var client = new FakeManageSieveClient
        {
            Script = new ManageSieveScript("active", content)
        };
        TestApplication app = CreateApplication(client);

        int exitCode = await app.Application.RunAsync(
            CommandLineOptions.Parse(["get", "active"]));

        Assert.Equal(0, exitCode);
        Assert.Equal(content, app.RawOutput.ToArray());
    }

    [Fact]
    public async Task GetWritesExactBytesToFile()
    {
        byte[] content = Encoding.UTF8.GetBytes("# ä\r\nkeep;\r\n");
        var client = new FakeManageSieveClient
        {
            Script = new ManageSieveScript("active", content)
        };
        string outputFile = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid()}.sieve");
        TestApplication app = CreateApplication(client);

        try
        {
            int exitCode = await app.Application.RunAsync(
                CommandLineOptions.Parse(
                    ["get", "active", "--output", outputFile]));

            Assert.Equal(0, exitCode);
            Assert.Equal(content, await File.ReadAllBytesAsync(outputFile));
        }
        finally
        {
            if (File.Exists(outputFile))
            {
                File.Delete(outputFile);
            }
        }
    }

    [Fact]
    public async Task CheckReadsExactBytesFromFile()
    {
        byte[] content = [0, 1, 13, 10, 195, 164];
        string inputFile = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid()}.sieve");
        await File.WriteAllBytesAsync(inputFile, content);
        var client = new FakeManageSieveClient();
        TestApplication app = CreateApplication(client);

        try
        {
            int exitCode = await app.Application.RunAsync(
                CommandLineOptions.Parse(["check", "--file", inputFile]));

            Assert.Equal(0, exitCode);
            Assert.Equal(content, client.CheckedContent);
            Assert.Contains("Script is valid.", app.TextOutput);
        }
        finally
        {
            File.Delete(inputFile);
        }
    }

    [Fact]
    public async Task PutUploadsExactBytesAndActivatesWhenRequested()
    {
        byte[] content = Encoding.UTF8.GetBytes("# candidate\r\nkeep;\r\n");
        string inputFile = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid()}.sieve");
        await File.WriteAllBytesAsync(inputFile, content);
        var client = new FakeManageSieveClient();
        TestApplication app = CreateApplication(client);

        try
        {
            int exitCode = await app.Application.RunAsync(
                CommandLineOptions.Parse(
                    ["put", "candidate", "--file", inputFile, "--activate"]));

            Assert.Equal(0, exitCode);
            Assert.Equal("candidate", client.PutScriptName);
            Assert.Equal(content, client.PutContent);
            Assert.Equal("candidate", client.ActiveScriptName);
        }
        finally
        {
            File.Delete(inputFile);
        }
    }

    [Theory]
    [InlineData("activate", "active")]
    [InlineData("delete", "old")]
    public async Task ScriptNameCommandsCallExpectedOperation(
        string command,
        string scriptName)
    {
        var client = new FakeManageSieveClient();
        TestApplication app = CreateApplication(client);

        int exitCode = await app.Application.RunAsync(
            CommandLineOptions.Parse([command, scriptName]));

        Assert.Equal(0, exitCode);
        if (command == "activate")
        {
            Assert.Equal(scriptName, client.ActiveScriptName);
        }
        else
        {
            Assert.Equal(scriptName, client.DeletedScriptName);
        }
    }

    [Fact]
    public async Task DeactivateClearsActiveScript()
    {
        var client = new FakeManageSieveClient();
        TestApplication app = CreateApplication(client);

        int exitCode = await app.Application.RunAsync(
            CommandLineOptions.Parse(["deactivate"]));

        Assert.Equal(0, exitCode);
        Assert.Null(client.ActiveScriptName);
        Assert.True(client.SetActiveCalled);
    }

    private static TestApplication CreateApplication(
        FakeManageSieveClient client)
    {
        var rawOutput = new MemoryStream();
        var textBuffer = new StringWriter();
        var provider = new StaticSieveServerConfigurationProvider();
        var application = new ManageSieveCliApplication(
            new FakeManageSieveClientFactory(client),
            provider,
            rawOutput,
            textBuffer);
        return new TestApplication(application, rawOutput, textBuffer);
    }

    private sealed record TestApplication(
        ManageSieveCliApplication Application,
        MemoryStream RawOutput,
        StringWriter TextWriter)
    {
        public string TextOutput => TextWriter.ToString();
    }

    private sealed class StaticSieveServerConfigurationProvider
        : ISieveServerConfigurationProvider
    {
        public ManageSieveClientOptions GetConnectionOptions(
            CommandLineOptions options) =>
            new()
            {
                Host = "sieve.example.com",
                SecurityMode = ManageSieveSecurityMode.StartTlsRequired
            };

        public SieveServerConfiguration GetAuthenticatedConfiguration(
            CommandLineOptions options) =>
            new(
                GetConnectionOptions(options),
                "user@example.com",
                "secret");
    }

    private sealed class FakeManageSieveClientFactory(
        FakeManageSieveClient client) : IManageSieveClientFactory
    {
        public IManageSieveClient CreateClient(
            ManageSieveClientOptions options)
        {
            client.OptionsValue = options;
            return client;
        }
    }

    private sealed class FakeManageSieveClient : IManageSieveClient
    {
        public ManageSieveClientOptions OptionsValue { get; set; } =
            new() { Host = "sieve.example.com" };

        public bool Connected { get; private set; }

        public bool StartTlsCalled { get; private set; }

        public bool Authenticated { get; private set; }

        public bool SetActiveCalled { get; private set; }

        public byte[]? CheckedContent { get; private set; }

        public string? PutScriptName { get; private set; }

        public byte[]? PutContent { get; private set; }

        public string? ActiveScriptName { get; private set; }

        public string? DeletedScriptName { get; private set; }

        public ManageSieveCapabilities CapabilitiesResult { get; set; } = new();

        public IReadOnlyList<ManageSieveScriptInfo> Scripts { get; set; } = [];

        public ManageSieveScript Script { get; set; } =
            new("active", ReadOnlyMemory<byte>.Empty);

        public ManageSieveClientOptions Options => OptionsValue;

        public ManageSieveSessionState State =>
            Authenticated
                ? ManageSieveSessionState.Authenticated
                : ManageSieveSessionState.Connected;

        public ManageSieveCapabilities? Capabilities => CapabilitiesResult;

        public ValueTask ConnectAsync(
            CancellationToken cancellationToken = default)
        {
            Connected = true;
            return ValueTask.CompletedTask;
        }

        public ValueTask<ManageSieveCapabilities> RefreshCapabilitiesAsync(
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(CapabilitiesResult);

        public ValueTask StartTlsAsync(
            CancellationToken cancellationToken = default)
        {
            StartTlsCalled = true;
            return ValueTask.CompletedTask;
        }

        public ValueTask AuthenticateAsync(
            IManageSieveAuthenticator authenticator,
            CancellationToken cancellationToken = default)
        {
            Authenticated = true;
            return ValueTask.CompletedTask;
        }

        public ValueTask UnauthenticateAsync(
            CancellationToken cancellationToken = default) =>
            ValueTask.CompletedTask;

        public ValueTask<ManageSieveSpaceAvailability> HaveSpaceAsync(
            string scriptName,
            long contentOctetCount,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(
                new ManageSieveSpaceAvailability { HasSpace = true });

        public ValueTask<IReadOnlyList<ManageSieveScriptInfo>> ListScriptsAsync(
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(Scripts);

        public ValueTask<ManageSieveScript> GetScriptAsync(
            string scriptName,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(Script);

        public ValueTask<ManageSieveCommandResult> CheckScriptAsync(
            ReadOnlyMemory<byte> content,
            CancellationToken cancellationToken = default)
        {
            CheckedContent = content.ToArray();
            return ValueTask.FromResult(new ManageSieveCommandResult());
        }

        public ValueTask<ManageSieveCommandResult> PutScriptAsync(
            string scriptName,
            ReadOnlyMemory<byte> content,
            CancellationToken cancellationToken = default)
        {
            PutScriptName = scriptName;
            PutContent = content.ToArray();
            return ValueTask.FromResult(new ManageSieveCommandResult());
        }

        public ValueTask<ManageSieveCommandResult> SetActiveScriptAsync(
            string? scriptName,
            CancellationToken cancellationToken = default)
        {
            SetActiveCalled = true;
            ActiveScriptName = scriptName;
            return ValueTask.FromResult(new ManageSieveCommandResult());
        }

        public ValueTask<ManageSieveCommandResult> RenameScriptAsync(
            string currentName,
            string newName,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(new ManageSieveCommandResult());

        public ValueTask<ManageSieveCommandResult> DeleteScriptAsync(
            string scriptName,
            CancellationToken cancellationToken = default)
        {
            DeletedScriptName = scriptName;
            return ValueTask.FromResult(new ManageSieveCommandResult());
        }

        public ValueTask<ManageSieveCommandResult> NoOpAsync(
            string? tag = null,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(new ManageSieveCommandResult());

        public ValueTask LogoutAsync(
            CancellationToken cancellationToken = default) =>
            ValueTask.CompletedTask;

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
