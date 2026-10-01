using System.Net;
using System.Net.Http.Json;
using System.Threading.Channels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using SentinelAI.Agent;
using SentinelAI.Contracts.Heartbeat;
using SentinelAI.Core;
using SentinelAI.Core.Persistence;

Ensure(typeof(SentinelAI.Agent.Program).Assembly.GetName().Name == "SentinelAI.Agent",
    "The Agent project did not produce the expected assembly.");
Ensure(typeof(SentinelAI.Agent.Program).Assembly.EntryPoint is not null,
    "The Agent assembly must be executable.");

var testDirectory = Path.Combine(Path.GetTempPath(), $"sentinelai-agent-tests-{Guid.NewGuid():N}");
Directory.CreateDirectory(testDirectory);

try
{
    await VerifyRetryAndStableIdentityAsync(Path.Combine(testDirectory, "retry"));
    await VerifyAgentToCoreAsync(Path.Combine(testDirectory, "end-to-end"));
    Console.WriteLine("Agent heartbeat tests passed.");
}
finally
{
    Directory.Delete(testDirectory, recursive: true);
}

static async Task VerifyRetryAndStableIdentityAsync(string dataDirectory)
{
    Guid initialId;
    var handler = new RecordingHeartbeatHandler(failuresBeforeSuccess: 2);
    using (var agent = BuildAgent(dataDirectory, "http://127.0.0.1:5000", handler,
               heartbeatInterval: "00:00:00.200", retryDelay: "00:00:00.050"))
    {
        await agent.StartAsync();
        try
        {
            var requests = new List<HeartbeatObservation>();
            for (var i = 0; i < 4; i++)
            {
                requests.Add(await handler.Requests.Reader.ReadAsync()
                    .AsTask().WaitAsync(TimeSpan.FromSeconds(10)));
            }

            initialId = requests[0].InstallationId;
            Ensure(requests.All(request => request.Method == HttpMethod.Post),
                "The Agent did not send POST heartbeats.");
            Ensure(requests.All(request => request.Path == "/api/agent/heartbeat"),
                "The Agent sent a heartbeat to the wrong API path.");
            Ensure(initialId != Guid.Empty, "The Agent sent an empty installation ID.");
            Ensure(requests.All(request => request.InstallationId == initialId),
                "The Agent changed its installation ID during retries.");
            Ensure(!agent.Services.GetRequiredService<IHostApplicationLifetime>()
                    .ApplicationStopping.IsCancellationRequested,
                "Temporary Core failures stopped the Agent host.");

            var identityFile = Path.Combine(dataDirectory, "installation-id");
            Ensure(File.Exists(identityFile), "The Agent did not persist its installation ID.");
            Ensure(Guid.TryParse(await File.ReadAllTextAsync(identityFile), out var persistedId)
                   && persistedId == initialId,
                "The persisted installation ID differs from the heartbeat ID.");
        }
        finally
        {
            await StopPromptlyAsync(agent);
        }
    }

    var restartHandler = new RecordingHeartbeatHandler();
    using (var restartedAgent = BuildAgent(dataDirectory, "http://127.0.0.1:5000", restartHandler,
               heartbeatInterval: "00:05:00", retryDelay: "00:00:00.050"))
    {
        await restartedAgent.StartAsync();
        try
        {
            var request = await restartHandler.Requests.Reader.ReadAsync()
                .AsTask().WaitAsync(TimeSpan.FromSeconds(10));
            Ensure(request.InstallationId == initialId,
                "The Agent changed its installation ID after restart.");
        }
        finally
        {
            // The next heartbeat is five minutes away; stopping must cancel that wait.
            await StopPromptlyAsync(restartedAgent);
        }
    }
}

static async Task VerifyAgentToCoreAsync(string testDirectory)
{
    var originalUsername = Environment.GetEnvironmentVariable("SENTINELAI_BOOTSTRAP_USERNAME");
    var originalPassword = Environment.GetEnvironmentVariable("SENTINELAI_BOOTSTRAP_PASSWORD");
    var coreDirectory = Path.Combine(testDirectory, "core");
    var agentDirectory = Path.Combine(testDirectory, "agent");

    try
    {
        Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_USERNAME", $"test-admin-{Guid.NewGuid():N}");
        Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_PASSWORD", $"Test-Only-{Guid.NewGuid():N}!");

        await using var core = CoreHost.Build(["--SentinelAI:DataDirectory", coreDirectory]);
        core.Urls.Clear();
        core.Urls.Add("http://127.0.0.1:0");
        await core.StartAsync();
        try
        {
            Ensure(core.Urls.Count == 1 && !core.Urls.Single().EndsWith(":0", StringComparison.Ordinal),
                "Core did not bind to an ephemeral loopback port.");

            using var agent = BuildAgent(agentDirectory, core.Urls.Single(),
                heartbeatInterval: "00:00:00.500", retryDelay: "00:00:00.100");
            await agent.StartAsync();
            try
            {
                var installationId = await WaitForInstallationIdAsync(
                    Path.Combine(agentDirectory, "installation-id"));
                var devices = core.Services.GetRequiredService<DeviceStore>();
                var firstRecord = await WaitForDeviceAsync(devices, installationId);
                Ensure(firstRecord.HealthStatus == DeviceHealthStatus.Reporting,
                    "Core did not report a healthy device after the Agent heartbeat.");
                Ensure(firstRecord.EnrollmentStatus == "unverified",
                    "A heartbeat unexpectedly enrolled the device.");
                Ensure(firstRecord.LastSeenUtc.Offset == TimeSpan.Zero,
                    "Core did not store the Agent heartbeat time in UTC.");

                await WaitForLaterHeartbeatAsync(devices, installationId, firstRecord.LastSeenUtc);
            }
            finally
            {
                await StopPromptlyAsync(agent);
            }
        }
        finally
        {
            await core.StopAsync();
        }
    }
    finally
    {
        Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_USERNAME", originalUsername);
        Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_PASSWORD", originalPassword);
    }
}

static IHost BuildAgent(string dataDirectory, string coreUrl,
    HttpMessageHandler? handler = null,
    string heartbeatInterval = "00:00:00.200",
    string retryDelay = "00:00:00.050")
{
    var builder = AgentHost.CreateBuilder([]);
    builder.Configuration["Agent:CoreUrl"] = coreUrl;
    builder.Configuration["Agent:DataDirectory"] = dataDirectory;
    builder.Configuration["Agent:HeartbeatInterval"] = heartbeatInterval;
    builder.Configuration["Agent:RetryDelay"] = retryDelay;
    builder.Configuration["Agent:MaxRetryDelay"] = "00:00:00.200";

    if (handler is not null)
    {
        builder.Services.RemoveAll<HttpClient>();
        builder.Services.AddSingleton(new HttpClient(handler));
    }

    return builder.Build();
}

static async Task<Guid> WaitForInstallationIdAsync(string path)
{
    var deadline = DateTime.UtcNow.AddSeconds(10);
    while (DateTime.UtcNow < deadline)
    {
        if (File.Exists(path) && Guid.TryParse(await File.ReadAllTextAsync(path), out var installationId))
        {
            return installationId;
        }

        await Task.Delay(50);
    }

    throw new Exception("The Agent did not create an installation ID.");
}

static async Task<DeviceRecord> WaitForDeviceAsync(DeviceStore devices, Guid installationId)
{
    var deadline = DateTime.UtcNow.AddSeconds(10);
    while (DateTime.UtcNow < deadline)
    {
        var device = await devices.FindByInstallationIdAsync(installationId);
        if (device is not null)
        {
            return device;
        }

        await Task.Delay(50);
    }

    throw new Exception("The Agent heartbeat did not create a Core device record.");
}

static async Task WaitForLaterHeartbeatAsync(DeviceStore devices, Guid installationId,
    DateTimeOffset firstSeenUtc)
{
    var deadline = DateTime.UtcNow.AddSeconds(10);
    while (DateTime.UtcNow < deadline)
    {
        var device = await devices.FindByInstallationIdAsync(installationId);
        if (device?.LastSeenUtc > firstSeenUtc)
        {
            return;
        }

        await Task.Delay(50);
    }

    throw new Exception("Repeated Agent heartbeats did not update Core last_seen.");
}

static async Task StopPromptlyAsync(IHost host)
{
    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
    await host.StopAsync(timeout.Token).WaitAsync(TimeSpan.FromSeconds(3));
}

static void Ensure(bool condition, string message)
{
    if (!condition)
    {
        throw new Exception(message);
    }
}

internal sealed record HeartbeatObservation(Guid InstallationId, HttpMethod Method, string Path);

internal sealed class RecordingHeartbeatHandler(int failuresBeforeSuccess = 0) : HttpMessageHandler
{
    private int _attempts;

    public Channel<HeartbeatObservation> Requests { get; } = Channel.CreateUnbounded<HeartbeatObservation>();

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var heartbeat = await (request.Content?.ReadFromJsonAsync<HeartbeatRequest>(cancellationToken)
            ?? throw new Exception("The Agent sent no heartbeat body."));
        if (heartbeat is null)
        {
            throw new Exception("The Agent sent an empty heartbeat body.");
        }

        Requests.Writer.TryWrite(new HeartbeatObservation(
            heartbeat.InstallationId, request.Method, request.RequestUri?.AbsolutePath ?? string.Empty));

        var attempt = Interlocked.Increment(ref _attempts);
        if (attempt == 1 && failuresBeforeSuccess > 0)
        {
            throw new HttpRequestException("Simulated Core connection outage.");
        }

        if (attempt <= failuresBeforeSuccess)
        {
            return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
        }

        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = JsonContent.Create(new HeartbeatResponse(
                heartbeat.InstallationId, DateTimeOffset.UtcNow, DeviceHealthStatus.Reporting))
        };
    }
}
