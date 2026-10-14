using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text.Json;
using System.Threading.Channels;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32;
using SentinelAI.Agent;
using SentinelAI.Contracts.Enrollment;
using SentinelAI.Contracts.Inventory;
using SentinelAI.Contracts.SecurityEvents;
using SentinelAI.Core;
using SentinelAI.Core.Persistence;

internal static class PostureMonitorTests
{
    internal static readonly SecurityPostureInventory Secure = new(true, true, true,
        new WindowsSecurityConfiguration(UacEnabled: true, AdminConsentPromptBehavior: 5, RdpEnabled: false,
            Smb1ServerEnabled: false, SmbInsecureGuestLogonsAllowed: false, AutomaticAdminLogonEnabled: false,
            LsaProtectionEnabled: true, AutomaticUpdatesDisabled: false));

    private static readonly SecurityPostureInventory PublicFirewallDisabled = Secure with { PublicFirewallEnabled = false };

    public static async Task RunAsync(string testDirectory)
    {
        VerifyConfigurationBounds();
        VerifyWatchedLocationsMatchCollection();
        await VerifyCoalescedDetectionAsync();
        await VerifyNotificationStormIsBoundedAsync();
        await VerifyRevertAndDuplicateSuppressionAsync();
        await VerifySingleSlotSpacingAndRetryAsync();
        await VerifyPeriodicVerificationFallbackAsync();
        await VerifyMonitoringFailuresAreContainedAsync();
        await VerifyPromptDeliveryOutageAndRestartAsync(Path.Combine(testDirectory, "agent-core"));
        if (OperatingSystem.IsWindows())
        {
            await VerifyRegistryNotificationsAsync();
            await VerifyNativeRegistryDeliveryAsync(Path.Combine(testDirectory, "native-registry"));
        }
    }

    private static void VerifyConfigurationBounds()
    {
        var defaults = AgentOptions.FromConfiguration(new ConfigurationBuilder().Build());
        Ensure(defaults.PostureCheckInterval == TimeSpan.FromMinutes(5) &&
               defaults.PostureSettleDelay == TimeSpan.FromSeconds(2) &&
               defaults.PostureDeliveryInterval == TimeSpan.FromSeconds(30),
            "Posture monitoring defaults changed without documentation.");
        foreach (var (key, value) in new[]
                 {
                     ("Agent:PostureCheckInterval", "00:00:00.500"), ("Agent:PostureCheckInterval", "06:00:01"),
                     ("Agent:PostureSettleDelay", "00:00:00.050"), ("Agent:PostureSettleDelay", "00:01:01"),
                     ("Agent:PostureDeliveryInterval", "00:00:00.500"), ("Agent:PostureDeliveryInterval", "01:00:01"),
                     ("Agent:PostureSettleDelay", "0"), ("Agent:PostureCheckInterval", "not-a-time")
                 })
        {
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?> { [key] = value }).Build();
            try
            {
                AgentOptions.FromConfiguration(configuration);
                throw new Exception($"The Agent accepted an unbounded posture setting {key}={value}.");
            }
            catch (InvalidOperationException)
            {
            }
        }
    }

    private static void VerifyWatchedLocationsMatchCollection()
    {
        var probed = new HashSet<string>(StringComparer.Ordinal);
        WindowsSecurityConfigurationCollector.CollectPosture((key, _) =>
        {
            probed.Add(key);
            return null;
        });
        var watched = WindowsSecurityConfigurationCollector.ConfigurationKeyPaths;
        Ensure(watched.Count == probed.Count && probed.SetEquals(watched),
            "Posture monitoring does not watch exactly the registry keys used by the deterministic rules.");
    }

    private static async Task VerifyCoalescedDetectionAsync()
    {
        var reader = new MutablePostureReader(Secure);
        using var source = new ManualPostureChangeSource();
        using var monitor = CreateMonitor(reader, source, checkInterval: TimeSpan.FromHours(1),
            settleDelay: TimeSpan.FromMilliseconds(150), deliveryInterval: TimeSpan.FromMilliseconds(200));
        await monitor.StartAsync(CancellationToken.None);
        try
        {
            await WaitUntilAsync(() => monitor.Verifications >= 1, "The monitor did not read initial posture.");
            Ensure(monitor.PendingDeliveryUtc is not null,
                "A posture that Core never acknowledged was not pending delivery.");
            monitor.RecordDelivered(Report(Secure));
            Ensure(monitor.PendingDeliveryUtc is null && !monitor.IsDeliveryDue(DateTimeOffset.UtcNow.AddHours(1)),
                "An acknowledged unchanged posture remained pending.");

            var verifications = monitor.Verifications;
            var reads = reader.Reads;
            var changed = monitor.ChangeDetected;
            var stopwatch = Stopwatch.StartNew();
            reader.Current = PublicFirewallDisabled;
            for (var i = 0; i < 1_000; i++)
            {
                source.Notify();
            }

            await changed.WaitAsync(TimeSpan.FromSeconds(10));
            Ensure(stopwatch.Elapsed < TimeSpan.FromSeconds(5),
                "A notified posture change was not detected within seconds.");
            await Task.Delay(TimeSpan.FromMilliseconds(500));
            Ensure(monitor.Verifications - verifications == 1 && reader.Reads - reads == 1,
                "A burst of 1,000 notifications was not coalesced into one bounded posture read.");
            await WaitUntilAsync(() => monitor.IsDeliveryDue(DateTimeOffset.UtcNow),
                "A detected posture change did not become due for delivery.");
        }
        finally
        {
            await monitor.StopAsync(CancellationToken.None);
        }
    }

    private static async Task VerifyNotificationStormIsBoundedAsync()
    {
        var reader = new MutablePostureReader(Secure);
        using var source = new ManualPostureChangeSource();
        using var monitor = CreateMonitor(reader, source, checkInterval: TimeSpan.FromHours(1),
            settleDelay: TimeSpan.FromMilliseconds(100), deliveryInterval: TimeSpan.FromMilliseconds(100));
        await monitor.StartAsync(CancellationToken.None);
        try
        {
            await WaitUntilAsync(() => monitor.Verifications >= 1, "The monitor did not read initial posture.");
            monitor.RecordDelivered(Report(Secure));
            var reads = reader.Reads;
            var changed = monitor.ChangeDetected;
            var storm = Stopwatch.StartNew();
            var notifications = 0;
            while (storm.Elapsed < TimeSpan.FromSeconds(2))
            {
                source.Notify();
                notifications++;
                await Task.Delay(2);
            }

            await Task.Delay(TimeSpan.FromMilliseconds(300));
            var stormReads = reader.Reads - reads;
            // A continuous storm is read about once per five settle delays (500 ms); allow
            // scheduler gaps on slow runners while remaining far below the notification count.
            Ensure(notifications > 50 && stormReads is >= 1 and <= 10,
                $"A continuous notification storm caused unbounded posture reads ({stormReads} for {notifications}).");
            Ensure(!changed.IsCompleted && monitor.PendingDeliveryUtc is null,
                "Duplicate notifications for an unchanged posture requested an inventory delivery.");
        }
        finally
        {
            await monitor.StopAsync(CancellationToken.None);
        }
    }

    private static async Task VerifyRevertAndDuplicateSuppressionAsync()
    {
        var reader = new MutablePostureReader(Secure);
        using var source = new ManualPostureChangeSource();
        using var monitor = CreateMonitor(reader, source, checkInterval: TimeSpan.FromHours(1),
            settleDelay: TimeSpan.FromMilliseconds(100), deliveryInterval: TimeSpan.FromMilliseconds(100));
        await monitor.StartAsync(CancellationToken.None);
        try
        {
            await WaitUntilAsync(() => monitor.Verifications >= 1, "The monitor did not read initial posture.");
            monitor.RecordDelivered(Report(Secure));

            var changed = monitor.ChangeDetected;
            reader.Current = PublicFirewallDisabled;
            source.Notify();
            await changed.WaitAsync(TimeSpan.FromSeconds(10));

            var verifications = monitor.Verifications;
            reader.Current = Secure;
            source.Notify();
            await WaitUntilAsync(() => monitor.Verifications > verifications, "The monitor ignored a reverted change.");
            Ensure(monitor.PendingDeliveryUtc is null,
                "A change reverted to the acknowledged posture before delivery was still sent.");

            monitor.RecordDelivered(Report(PublicFirewallDisabled));
            verifications = monitor.Verifications;
            changed = monitor.ChangeDetected;
            reader.Current = PublicFirewallDisabled;
            source.Notify();
            await WaitUntilAsync(() => monitor.Verifications > verifications, "The monitor ignored a notification.");
            Ensure(monitor.PendingDeliveryUtc is null && !changed.IsCompleted,
                "A posture identical to Core's latest acknowledgement was delivered again.");

            // A read made after an upload was collected remains pending.
            reader.Current = Secure;
            source.Notify();
            await WaitUntilAsync(() => monitor.PendingDeliveryUtc is not null, "A new change was not detected.");
            monitor.RecordDelivered(Report(PublicFirewallDisabled, DateTimeOffset.UtcNow.AddMinutes(-1)));
            Ensure(monitor.PendingDeliveryUtc is not null,
                "An older upload cleared a newer pending posture change.");
        }
        finally
        {
            await monitor.StopAsync(CancellationToken.None);
        }
    }

    private static async Task VerifySingleSlotSpacingAndRetryAsync()
    {
        var reader = new MutablePostureReader(Secure);
        using var source = new ManualPostureChangeSource();
        using var monitor = CreateMonitor(reader, source, checkInterval: TimeSpan.FromHours(1),
            settleDelay: TimeSpan.FromMilliseconds(100), deliveryInterval: TimeSpan.FromSeconds(3));
        await monitor.StartAsync(CancellationToken.None);
        try
        {
            await WaitUntilAsync(() => monitor.Verifications >= 1, "The monitor did not read initial posture.");
            var deliveredUtc = DateTimeOffset.UtcNow;
            monitor.RecordDelivered(Report(Secure));
            reader.Current = PublicFirewallDisabled;
            source.Notify();
            await WaitUntilAsync(() => monitor.PendingDeliveryUtc is not null, "A posture change was not detected.");
            var dueUtc = monitor.PendingDeliveryUtc!.Value;
            Ensure(dueUtc >= deliveredUtc.AddSeconds(3) && dueUtc <= DateTimeOffset.UtcNow.AddSeconds(3) &&
                   !monitor.IsDeliveryDue(dueUtc.AddMilliseconds(-1)) && monitor.IsDeliveryDue(dueUtc),
                "Change-triggered deliveries were not spaced by the configured minimum interval.");

            var failedUtc = DateTimeOffset.UtcNow;
            monitor.RecordDeliveryFailed();
            var retryUtc = monitor.PendingDeliveryUtc!.Value;
            Ensure(retryUtc >= failedUtc + PostureMonitor.DeliveryRetryDelay &&
                   retryUtc <= DateTimeOffset.UtcNow + PostureMonitor.DeliveryRetryDelay &&
                   !monitor.IsDeliveryDue(DateTimeOffset.UtcNow.AddMinutes(4)),
                "A failed change delivery did not keep the bounded five-minute retry.");

            // Further changes replace the one pending observation rather than queueing.
            foreach (var posture in new[]
                     {
                         Secure with { DomainFirewallEnabled = false },
                         Secure with { Configuration = Secure.Configuration! with { UacEnabled = false } }
                     })
            {
                var verifications = monitor.Verifications;
                reader.Current = posture;
                source.Notify();
                await WaitUntilAsync(() => monitor.Verifications > verifications, "A later change was not read.");
                Ensure(monitor.PendingDeliveryUtc == retryUtc,
                    "A later change reset the bounded retry or created another pending delivery.");
            }
        }
        finally
        {
            await monitor.StopAsync(CancellationToken.None);
        }
    }

    private static async Task VerifyPeriodicVerificationFallbackAsync()
    {
        var reader = new MutablePostureReader(Secure);
        using var source = new ManualPostureChangeSource(available: false);
        using var monitor = CreateMonitor(reader, source, checkInterval: TimeSpan.FromMilliseconds(300),
            settleDelay: TimeSpan.FromMilliseconds(100), deliveryInterval: TimeSpan.FromMilliseconds(100));
        await monitor.StartAsync(CancellationToken.None);
        try
        {
            await WaitUntilAsync(() => monitor.Verifications >= 1, "The monitor did not read initial posture.");
            monitor.RecordDelivered(Report(Secure));
            var changed = monitor.ChangeDetected;
            reader.Current = PublicFirewallDisabled;
            await changed.WaitAsync(TimeSpan.FromSeconds(10));
            Ensure(source.Arms >= 2, "Periodic verification did not retry change notification registration.");
        }
        finally
        {
            await monitor.StopAsync(CancellationToken.None);
        }
    }

    private static async Task VerifyMonitoringFailuresAreContainedAsync()
    {
        var reader = new MutablePostureReader(Secure) { FailuresRemaining = 2 };
        using var source = new ManualPostureChangeSource { ThrowOnArm = true };
        using var monitor = CreateMonitor(reader, source, checkInterval: TimeSpan.FromSeconds(1),
            settleDelay: TimeSpan.FromMilliseconds(100), deliveryInterval: TimeSpan.FromMilliseconds(100));
        await monitor.StartAsync(CancellationToken.None);
        try
        {
            await WaitUntilAsync(() => reader.Reads >= 3, "The monitor stopped after posture read failures.");
            Ensure(monitor.ExecuteTask is { IsCompleted: false },
                "A posture monitoring failure stopped the monitor.");
            await WaitUntilAsync(() => monitor.PendingDeliveryUtc is not null,
                "The monitor did not recover after transient read and registration failures.");
        }
        finally
        {
            await monitor.StopAsync(CancellationToken.None);
        }
    }

    private static async Task VerifyPromptDeliveryOutageAndRestartAsync(string testDirectory)
    {
        await using var core = await CoreFixture.StartAsync(Path.Combine(testDirectory, "core"));
        var agentDirectory = Path.Combine(testDirectory, "agent");
        var reader = new MutablePostureReader(Secure);
        using var source = new ManualPostureChangeSource();
        using var link = new CoreLinkHandler();
        using var httpClient = new HttpClient(link, disposeHandler: false);
        var token = await core.IssueEnrollmentTokenAsync();
        var inventories = core.Services.GetRequiredService<InventoryStore>();
        Guid endpointId;
        PostureMonitor monitor;

        using (var agent = BuildMonitoredAgent(agentDirectory, core.Url, httpClient, reader, source, token))
        {
            await agent.StartAsync();
            try
            {
                monitor = agent.Services.GetRequiredService<PostureMonitor>();
                endpointId = await WaitForEndpointReceiptAsync(agentDirectory);
                await WaitForCorePostureAsync(inventories, endpointId, Secure, "The initial inventory was not delivered.");
                Ensure(link.InventoryAccepted == 1, "The initial inventory was uploaded more than once.");
                Ensure(await core.FindingIdsAsync(endpointId) is { Count: 0 },
                    "A secure synthetic posture produced findings.");
                await Task.Delay(TimeSpan.FromSeconds(1.2)); // Respect the configured delivery spacing.

                // Heartbeats are five minutes apart; only the posture change can explain prompt delivery.
                var uploads = link.InventoryAccepted;
                var stopwatch = Stopwatch.StartNew();
                reader.Current = PublicFirewallDisabled;
                source.Notify();
                await WaitForCorePostureAsync(inventories, endpointId, PublicFirewallDisabled,
                    "A security setting change was not reflected in Core.");
                // Heartbeats are not counted: Core may answer a heartbeat whose commit overlaps a
                // concurrent read with a transient 500, which the Agent retries with backoff.
                Ensure(stopwatch.Elapsed < TimeSpan.FromSeconds(10) && link.InventoryAccepted == uploads + 1,
                    $"A security setting change took {stopwatch.Elapsed} or did not upload exactly once.");
                Console.WriteLine(
                    $"Posture change reflected in Core after {stopwatch.ElapsedMilliseconds} ms (heartbeat interval 5 minutes).");
                Ensure((await core.FindingIdsAsync(endpointId)).SequenceEqual(["SA-FW-003"]),
                    "Current findings did not reflect the promptly delivered posture.");
                var alert = await core.FindTrackedAlertAsync(endpointId, "SA-FW-003")
                    ?? throw new Exception("The promptly delivered posture did not update tracked alerts.");
                Ensure(alert.Status == "open", "The new posture finding was not tracked as open.");
                var risk = await core.Services.GetRequiredService<RiskReadStore>().FindAsync(endpointId)
                    ?? throw new Exception("Core returned no endpoint risk.");
                Ensure(risk.Risk.Score > 0 && risk.Alerts.Any(item => item.RuleId == "SA-FW-003"),
                    "Risk did not reflect the promptly delivered posture on the next read.");

                // Bursts of duplicate notifications for an unchanged posture upload nothing.
                var accepted = link.InventoryAccepted;
                var verifications = monitor.Verifications;
                for (var i = 0; i < 500; i++)
                {
                    source.Notify();
                }

                await Task.Delay(TimeSpan.FromSeconds(1.5));
                Ensure(link.InventoryAccepted == accepted && link.InventoryAttempts == accepted &&
                       monitor.Verifications - verifications is >= 1 and <= 2,
                    "Duplicate notification bursts created unbounded posture work or uploads.");

                // A burst carrying one real change produces exactly one upload.
                var bothDisabled = PublicFirewallDisabled with { DomainFirewallEnabled = false };
                reader.Current = bothDisabled;
                for (var i = 0; i < 500; i++)
                {
                    source.Notify();
                }

                await WaitForCorePostureAsync(inventories, endpointId, bothDisabled, "A burst change was not delivered.");
                await Task.Delay(TimeSpan.FromSeconds(1.5));
                Ensure(link.InventoryAccepted == accepted + 1,
                    "One coalesced burst of changes uploaded more than one inventory.");

                // Restoring the setting clears current findings but, as before, never resolves alerts.
                await Task.Delay(TimeSpan.FromSeconds(1.2));
                reader.Current = Secure;
                source.Notify();
                await WaitForCorePostureAsync(inventories, endpointId, Secure, "A restored setting was not reflected.");
                Ensure(await core.FindingIdsAsync(endpointId) is { Count: 0 } &&
                       (await core.FindTrackedAlertAsync(endpointId, "SA-FW-003"))?.Status == "open",
                    "Deterministic finding or tracked-alert meaning changed with prompt delivery.");

                // Core outage: changes coalesce into one pending delivery; the Agent keeps running.
                link.Outage = true;
                var outageAttempts = link.InventoryAttempts;
                var outageHeartbeats = link.Heartbeats;
                var outageStarted = Stopwatch.StartNew();
                var outagePostures = new[]
                {
                    Secure with { PublicFirewallEnabled = false },
                    Secure with { Configuration = Secure.Configuration! with { Smb1ServerEnabled = true } },
                    Secure with { Configuration = Secure.Configuration! with { UacEnabled = false } }
                };
                foreach (var posture in outagePostures)
                {
                    reader.Current = posture;
                    source.Notify();
                    await Task.Delay(TimeSpan.FromMilliseconds(500));
                }

                var outageElapsed = outageStarted.Elapsed;
                var lifetime = agent.Services.GetRequiredService<IHostApplicationLifetime>();
                Ensure(!lifetime.ApplicationStopping.IsCancellationRequested && !monitor.ExecuteTask!.IsCompleted,
                    "Temporary Core unavailability stopped the Agent or its posture monitor.");
                Ensure(link.InventoryAttempts == outageAttempts,
                    "The Agent attempted inventory uploads while heartbeats could not reach Core.");
                // Backoff: 50 ms doubling to the 200 ms maximum bounds attempts by elapsed time.
                var maximumAttempts = (int)(outageElapsed.TotalMilliseconds / 200) + 6;
                Ensure(link.Heartbeats - outageHeartbeats is >= 1 && link.Heartbeats - outageHeartbeats <= maximumAttempts,
                    $"Outage retries were not bounded by backoff ({link.Heartbeats - outageHeartbeats}).");
                Ensure((await inventories.FindLatestAsync(endpointId))?.SecurityPosture == Secure,
                    "Core changed during a simulated outage.");

                link.Outage = false;
                await WaitForCorePostureAsync(inventories, endpointId, outagePostures[^1],
                    "The pending posture change was not delivered after Core recovered.");
                await Task.Delay(TimeSpan.FromSeconds(1.5));
                Ensure(link.InventoryAttempts == outageAttempts + 1 &&
                       (await core.FindingIdsAsync(endpointId)).SequenceEqual(["SA-UAC-001"]),
                    "Outage changes were queued instead of delivering the one latest observation.");

                // Core rejecting inventory leaves one pending delivery with the bounded retry delay.
                await Task.Delay(TimeSpan.FromSeconds(1.2));
                link.RejectInventory = true;
                var rejectedAttempts = link.InventoryAttempts;
                reader.Current = Secure;
                source.Notify();
                await WaitUntilAsync(() => link.InventoryAttempts > rejectedAttempts,
                    "A posture change was not attempted after a reachable heartbeat.");
                await Task.Delay(TimeSpan.FromSeconds(1.5));
                Ensure(link.InventoryAttempts == rejectedAttempts + 1 &&
                       monitor.PendingDeliveryUtc > DateTimeOffset.UtcNow.AddMinutes(4) &&
                       !lifetime.ApplicationStopping.IsCancellationRequested,
                    "A rejected change delivery was retried without the bounded delay or stopped the Agent.");
            }
            finally
            {
                await StopPromptlyAsync(agent);
            }
        }

        // Restart: nothing is persisted for retries; the reconciliation upload after restart
        // reflects a change made while the Agent was stopped.
        link.RejectInventory = false;
        var persistedFiles = ListFiles(agentDirectory);
        var whileStopped = Secure with { Configuration = Secure.Configuration! with { AutomaticAdminLogonEnabled = true } };
        reader.Current = whileStopped;
        using (var restarted = BuildMonitoredAgent(agentDirectory, core.Url, httpClient, reader, source, null))
        {
            var stopwatch = Stopwatch.StartNew();
            await restarted.StartAsync();
            try
            {
                await WaitForCorePostureAsync(inventories, endpointId, whileStopped,
                    "A change made while the Agent was stopped was not reconciled after restart.");
                Ensure(stopwatch.Elapsed < TimeSpan.FromSeconds(10) &&
                       (await core.FindingIdsAsync(endpointId)).SequenceEqual(["SA-LOGON-001"]),
                    "Restart reconciliation did not promptly produce the current finding.");
                Ensure(ListFiles(agentDirectory).SequenceEqual(persistedFiles),
                    "Posture monitoring persisted retry or queue state on disk.");
            }
            finally
            {
                await StopPromptlyAsync(restarted);
            }
        }
    }

    [SupportedOSPlatform("windows")]
    private static async Task VerifyRegistryNotificationsAsync()
    {
        var root = $@"Software\SentinelAI-Tests\posture-{Guid.NewGuid():N}";
        using var hive = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
        hive.CreateSubKey(root + @"\Existing").Dispose();
        try
        {
            var signals = Channel.CreateUnbounded<bool>();
            void OnChange() => signals.Writer.TryWrite(true);
            var source = new RegistryPostureChangeSource(RegistryHive.CurrentUser, RegistryView.Default,
                [root + @"\Existing", root + @"\Missing\Nested"]);
            try
            {
                Ensure(source.Arm(OnChange) && source.Arm(OnChange),
                    "Registry notifications could not watch an existing key and an absent key's ancestor.");
                await ExpectNoSignalAsync(signals, "Re-registering notifications raised a spurious change.");

                using (var key = hive.OpenSubKey(root + @"\Existing", writable: true)!)
                {
                    key.SetValue("EnableFirewall", 0, RegistryValueKind.DWord);
                }

                await ExpectSignalAsync(signals, "A registry value change raised no notification.");

                Ensure(source.Arm(OnChange), "Registry notifications could not be re-armed.");
                Drain(signals);
                using (var created = hive.CreateSubKey(root + @"\Missing\Nested"))
                {
                    created.SetValue("EnableFirewall", 1, RegistryValueKind.DWord);
                }

                await ExpectSignalAsync(signals, "Creating an absent monitored key raised no notification.");

                Ensure(source.Arm(OnChange), "A newly created monitored key could not be watched.");
                Drain(signals);
                using (var key = hive.OpenSubKey(root + @"\Missing\Nested", writable: true)!)
                {
                    key.SetValue("EnableFirewall", 0, RegistryValueKind.DWord);
                }

                await ExpectSignalAsync(signals, "A value change on a newly created key raised no notification.");
            }
            finally
            {
                source.Dispose();
            }

            Drain(signals);
            using (var key = hive.OpenSubKey(root + @"\Existing", writable: true)!)
            {
                key.SetValue("EnableFirewall", 1, RegistryValueKind.DWord);
            }

            await ExpectNoSignalAsync(signals, "A disposed registry source still raised notifications.");
        }
        finally
        {
            hive.DeleteSubKeyTree(root, throwOnMissingSubKey: false);
        }
    }

    [SupportedOSPlatform("windows")]
    private static async Task VerifyNativeRegistryDeliveryAsync(string testDirectory)
    {
        // Redirect the real collector and notifications to a private HKCU copy of the monitored
        // keys: actual Windows notifications and parsing, without changing machine policy.
        var root = $@"Software\SentinelAI-Tests\posture-{Guid.NewGuid():N}";
        const string LocalPublic = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile";
        const string PolicyPublic = @"SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile";
        using var hive = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
        foreach (var profile in new[] { "DomainProfile", "StandardProfile", "PublicProfile" })
        {
            using var key = hive.CreateSubKey(
                $@"{root}\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{profile}");
            key.SetValue("EnableFirewall", 1, RegistryValueKind.DWord);
        }

        hive.CreateSubKey(root + @"\SOFTWARE\Policies\Microsoft").Dispose();
        try
        {
            await using var core = await CoreFixture.StartAsync(Path.Combine(testDirectory, "core"));
            var agentDirectory = Path.Combine(testDirectory, "agent");
            var reader = new RedirectedRegistryPostureReader(root);
            using var source = new RegistryPostureChangeSource(RegistryHive.CurrentUser, RegistryView.Default,
                WindowsSecurityConfigurationCollector.ConfigurationKeyPaths.Select(path => root + "\\" + path));
            using var link = new CoreLinkHandler();
            using var httpClient = new HttpClient(link, disposeHandler: false);
            var inventories = core.Services.GetRequiredService<InventoryStore>();
            using var agent = BuildMonitoredAgent(agentDirectory, core.Url, httpClient, reader, source,
                await core.IssueEnrollmentTokenAsync());
            await agent.StartAsync();
            try
            {
                var endpointId = await WaitForEndpointReceiptAsync(agentDirectory);
                await WaitForCoreAsync(inventories, endpointId, report => report.SecurityPosture.PublicFirewallEnabled == true,
                    "The native initial inventory was not delivered.");
                await Task.Delay(TimeSpan.FromSeconds(1.2));

                var stopwatch = Stopwatch.StartNew();
                using (var key = hive.OpenSubKey($@"{root}\{LocalPublic}", writable: true)!)
                {
                    key.SetValue("EnableFirewall", 0, RegistryValueKind.DWord);
                }

                await WaitForCoreAsync(inventories, endpointId, report => report.SecurityPosture.PublicFirewallEnabled == false,
                    "A native registry change was not reflected in Core.");
                Ensure(stopwatch.Elapsed < TimeSpan.FromSeconds(10) &&
                       (await core.FindTrackedAlertAsync(endpointId, "SA-FW-003"))?.Status == "open",
                    $"A native registry change took {stopwatch.Elapsed} or created no tracked alert.");
                Console.WriteLine($"Native registry posture change reflected in Core after {stopwatch.ElapsedMilliseconds} ms.");

                // Creating an absent policy key is noticed through its watched ancestor.
                await Task.Delay(TimeSpan.FromSeconds(1.2));
                stopwatch.Restart();
                using (var policy = hive.CreateSubKey($@"{root}\{PolicyPublic}"))
                {
                    policy.SetValue("EnableFirewall", 1, RegistryValueKind.DWord);
                }

                await WaitForCoreAsync(inventories, endpointId, report => report.SecurityPosture.PublicFirewallEnabled == true,
                    "A newly created firewall policy was not reflected in Core.");
                Ensure(stopwatch.Elapsed < TimeSpan.FromSeconds(10),
                    $"A newly created policy key took {stopwatch.Elapsed} to reach Core.");
            }
            finally
            {
                await StopPromptlyAsync(agent);
            }
        }
        finally
        {
            hive.DeleteSubKeyTree(root, throwOnMissingSubKey: false);
        }
    }

    /// <summary>
    /// Elevated, opt-in acceptance against the production Agent composition and the real
    /// HKLM allowlist. LSA protection is changed because RunAsPPL is applied only at boot;
    /// the original value is restored before exit.
    /// </summary>
    public static async Task RunNativeAcceptanceAsync(string testDirectory)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new Exception("Native posture acceptance requires Windows.");
        }

        await RunElevatedLsaAcceptanceAsync(testDirectory);
    }

    [SupportedOSPlatform("windows")]
    private static async Task RunElevatedLsaAcceptanceAsync(string testDirectory)
    {
        using (var identity = WindowsIdentity.GetCurrent())
        {
            Ensure(new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator),
                "Native posture acceptance must run elevated.");
        }

        const string LsaPath = @"SYSTEM\CurrentControlSet\Control\Lsa";
        using var hive = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var lsa = hive.OpenSubKey(LsaPath, writable: true)
            ?? throw new Exception("The LSA configuration key is unavailable.");
        var originalValue = lsa.GetValue("RunAsPPL", null, RegistryValueOptions.DoNotExpandEnvironmentNames);
        var originalKind = originalValue is null ? RegistryValueKind.Unknown : lsa.GetValueKind("RunAsPPL");
        try
        {
            await using var core = await CoreFixture.StartAsync(Path.Combine(testDirectory, "core"));
            var agentDirectory = Path.Combine(testDirectory, "agent");
            var inventories = core.Services.GetRequiredService<InventoryStore>();
            var builder = AgentHost.CreateBuilder([]);
            builder.Configuration["Agent:CoreUrl"] = core.Url;
            builder.Configuration["Agent:DataDirectory"] = agentDirectory;
            builder.Configuration["Agent:HeartbeatInterval"] = "00:05:00";
            builder.Configuration["Agent:EnrollmentToken"] = await core.IssueEnrollmentTokenAsync();
            builder.Configuration["Agent:CoreCertificateSha256"] = null;
            // Production posture reader, HKLM change source and default monitoring intervals; no event channels.
            builder.Services.RemoveAll<IEventLogAccess>();
            builder.Services.AddSingleton<IEventLogAccess>(new NoEventLogAccess());
            using var agent = builder.Build();
            Ensure(agent.Services.GetRequiredService<IPostureChangeSource>() is RegistryPostureChangeSource &&
                   agent.Services.GetRequiredService<ISecurityPostureReader>() is SecurityPostureReader,
                "Native acceptance did not use the production posture composition.");
            await agent.StartAsync();
            try
            {
                var endpointId = await WaitForEndpointReceiptAsync(agentDirectory);
                lsa.SetValue("RunAsPPL", 1, RegistryValueKind.DWord);
                await WaitForCoreAsync(inventories, endpointId,
                    report => report.SecurityPosture.Configuration?.LsaProtectionEnabled == true,
                    "The baseline LSA protection setting was not reflected in Core.", TimeSpan.FromSeconds(60), 250);
                // Default spacing is 30 seconds between change-triggered uploads.
                await Task.Delay(TimeSpan.FromSeconds(31));

                var stopwatch = Stopwatch.StartNew();
                lsa.SetValue("RunAsPPL", 0, RegistryValueKind.DWord);
                await WaitForCoreAsync(inventories, endpointId,
                    report => report.SecurityPosture.Configuration?.LsaProtectionEnabled == false,
                    "Disabling LSA protection was not reflected in Core.", TimeSpan.FromSeconds(45), 250);
                var latency = stopwatch.Elapsed;
                Ensure((await core.FindingIdsAsync(endpointId)).Contains("SA-LSA-001") &&
                       (await core.FindTrackedAlertAsync(endpointId, "SA-LSA-001"))?.Status == "open",
                    "The native LSA protection change did not produce the SA-LSA-001 alert.");
                // Two-second settle plus heartbeat; allows the default 5 s retry if Core answers 500.
                Ensure(latency < TimeSpan.FromSeconds(30),
                    $"The native LSA protection change took {latency} with default monitoring settings.");
                Console.WriteLine(
                    $"Native posture acceptance: HKLM RunAsPPL change reflected as SA-LSA-001 after {latency.TotalMilliseconds:F0} ms.");
            }
            finally
            {
                await StopPromptlyAsync(agent);
            }
        }
        finally
        {
            if (originalValue is null)
            {
                lsa.DeleteValue("RunAsPPL", throwOnMissingValue: false);
            }
            else
            {
                lsa.SetValue("RunAsPPL", originalValue, originalKind);
            }
        }

        Console.WriteLine("Native posture acceptance passed.");
    }

    private static PostureMonitor CreateMonitor(ISecurityPostureReader reader, IPostureChangeSource source,
        TimeSpan checkInterval, TimeSpan settleDelay, TimeSpan deliveryInterval) =>
        new(new AgentOptions(new Uri("http://127.0.0.1:5000"), Path.GetTempPath(), TimeSpan.FromSeconds(30),
                TimeSpan.FromSeconds(5), TimeSpan.FromMinutes(1), null, null)
            {
                PostureCheckInterval = checkInterval,
                PostureSettleDelay = settleDelay,
                PostureDeliveryInterval = deliveryInterval
            },
            reader, source, NullLogger<PostureMonitor>.Instance);

    private static InventoryReport Report(SecurityPostureInventory posture, DateTimeOffset? collectedUtc = null) =>
        new(Guid.NewGuid(), collectedUtc ?? DateTimeOffset.UtcNow, "1.0.0", "test-host", "Windows 11 Pro", "10.0.26100",
            "X64", new CpuInventory(null, 4), null, [], posture);

    private static IHost BuildMonitoredAgent(string dataDirectory, string coreUrl, HttpClient httpClient,
        ISecurityPostureReader reader, IPostureChangeSource source, string? enrollmentToken)
    {
        var builder = AgentHost.CreateBuilder([]);
        builder.Configuration["Agent:CoreUrl"] = coreUrl;
        builder.Configuration["Agent:DataDirectory"] = dataDirectory;
        builder.Configuration["Agent:HeartbeatInterval"] = "00:05:00";
        builder.Configuration["Agent:RetryDelay"] = "00:00:00.050";
        builder.Configuration["Agent:MaxRetryDelay"] = "00:00:00.200";
        builder.Configuration["Agent:PostureCheckInterval"] = "01:00:00";
        builder.Configuration["Agent:PostureSettleDelay"] = "00:00:00.100";
        builder.Configuration["Agent:PostureDeliveryInterval"] = "00:00:01";
        builder.Configuration["Agent:EnrollmentToken"] = enrollmentToken;
        builder.Configuration["Agent:CoreCertificateSha256"] = null;
        builder.Services.RemoveAll<HttpClient>();
        builder.Services.AddSingleton(httpClient);
        builder.Services.RemoveAll<ISecurityPostureReader>();
        builder.Services.AddSingleton(reader);
        builder.Services.RemoveAll<IPostureChangeSource>();
        builder.Services.AddSingleton(source);
        builder.Services.RemoveAll<IEventLogAccess>();
        builder.Services.AddSingleton<IEventLogAccess>(new NoEventLogAccess());
        return builder.Build();
    }

    private static async Task<Guid> WaitForEndpointReceiptAsync(string agentDirectory)
    {
        var path = Path.Combine(agentDirectory, "endpoint-id");
        Guid endpointId = default;
        await WaitUntilAsync(() => File.Exists(path) && Guid.TryParse(File.ReadAllText(path), out endpointId),
            "The Agent did not enroll.");
        return endpointId;
    }

    private static Task WaitForCorePostureAsync(InventoryStore inventories, Guid endpointId,
        SecurityPostureInventory expected, string message) =>
        WaitForCoreAsync(inventories, endpointId, report => report.SecurityPosture == expected, message);

    // Polling reads Core's database; a modest interval limits contention with Agent writes.
    private static async Task WaitForCoreAsync(InventoryStore inventories, Guid endpointId,
        Func<InventoryReport, bool> condition, string message, TimeSpan? timeout = null,
        int pollMilliseconds = 100)
    {
        var deadline = DateTime.UtcNow + (timeout ?? TimeSpan.FromSeconds(10));
        while (DateTime.UtcNow < deadline)
        {
            if (await inventories.FindLatestAsync(endpointId) is { } report && condition(report))
            {
                return;
            }

            await Task.Delay(pollMilliseconds);
        }

        throw new Exception(message);
    }

    private static async Task WaitUntilAsync(Func<bool> condition, string message)
    {
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (DateTime.UtcNow < deadline)
        {
            if (condition())
            {
                return;
            }

            await Task.Delay(10);
        }

        throw new Exception(message);
    }

    private static async Task ExpectSignalAsync(Channel<bool> signals, string message)
    {
        try
        {
            await signals.Reader.ReadAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        }
        catch (TimeoutException)
        {
            throw new Exception(message);
        }
    }

    private static async Task ExpectNoSignalAsync(Channel<bool> signals, string message)
    {
        await Task.Delay(TimeSpan.FromMilliseconds(500));
        Ensure(!signals.Reader.TryRead(out _), message);
    }

    private static void Drain(Channel<bool> signals)
    {
        while (signals.Reader.TryRead(out _))
        {
        }
    }

    private static string[] ListFiles(string directory) => Directory
        .EnumerateFileSystemEntries(directory, "*", SearchOption.AllDirectories)
        .Select(path => Path.GetRelativePath(directory, path))
        .Order(StringComparer.Ordinal)
        .ToArray();

    private static async Task StopPromptlyAsync(IHost host)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        await host.StopAsync(timeout.Token).WaitAsync(TimeSpan.FromSeconds(5));
    }

    private static void Ensure(bool condition, string message)
    {
        if (!condition)
        {
            throw new Exception(message);
        }
    }

    internal sealed class CoreFixture : IAsyncDisposable
    {
        private readonly WebApplication _core;
        private readonly HttpClient _client;
        private readonly string _accessToken;

        private CoreFixture(WebApplication core, HttpClient client, string accessToken)
        {
            _core = core;
            _client = client;
            _accessToken = accessToken;
        }

        public string Url => _core.Urls.Single();
        public IServiceProvider Services => _core.Services;

        public static async Task<CoreFixture> StartAsync(string dataDirectory)
        {
            var originalUsername = Environment.GetEnvironmentVariable("SENTINELAI_BOOTSTRAP_USERNAME");
            var originalPassword = Environment.GetEnvironmentVariable("SENTINELAI_BOOTSTRAP_PASSWORD");
            var username = $"test-admin-{Guid.NewGuid():N}";
            var password = $"Test-Only-{Guid.NewGuid():N}!";
            WebApplication core;
            try
            {
                Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_USERNAME", username);
                Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_PASSWORD", password);
                core = CoreHost.Build(["--SentinelAI:DataDirectory", dataDirectory]);
                core.Urls.Clear();
                core.Urls.Add("http://127.0.0.1:0");
                await core.StartAsync();
            }
            finally
            {
                Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_USERNAME", originalUsername);
                Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_PASSWORD", originalPassword);
            }

            var client = new HttpClient(new HttpClientHandler { UseProxy = false })
            {
                BaseAddress = new Uri(core.Urls.Single())
            };
            using var login = await client.PostAsJsonAsync("/api/auth/login", new { username, password });
            Ensure(login.StatusCode == HttpStatusCode.OK, "The test administrator could not sign in.");
            using var body = JsonDocument.Parse(await login.Content.ReadAsStringAsync());
            var accessToken = body.RootElement.GetProperty("accessToken").GetString()
                ?? throw new Exception("The administrator login returned no token.");
            return new CoreFixture(core, client, accessToken);
        }

        public async Task<string> IssueEnrollmentTokenAsync()
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, "/api/admin/enrollment-tokens");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _accessToken);
            using var response = await _client.SendAsync(request);
            Ensure(response.StatusCode == HttpStatusCode.OK, "Core did not issue an enrollment token.");
            return (await response.Content.ReadFromJsonAsync<EnrollmentTokenResponse>())?.Token
                ?? throw new Exception("Core returned no enrollment token.");
        }

        /// <summary>Current findings through the administrator API, evaluated from Core's latest inventory.</summary>
        public async Task<List<string>> FindingIdsAsync(Guid endpointId)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, $"/api/admin/devices/{endpointId:D}/alerts");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _accessToken);
            using var response = await _client.SendAsync(request);
            Ensure(response.StatusCode == HttpStatusCode.OK, "Core did not return current findings.");
            using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            return body.RootElement.GetProperty("alerts").EnumerateArray()
                .Select(alert => alert.GetProperty("ruleId").GetString()!)
                .ToList();
        }

        public async Task<AlertListItem?> FindTrackedAlertAsync(Guid endpointId, string ruleId)
        {
            var page = await Services.GetRequiredService<AlertStore>()
                .ListAsync(null, null, 0, 100, endpointId: endpointId);
            return page.Alerts.SingleOrDefault(alert => alert.RuleId == ruleId);
        }

        /// <summary>Event source status through the administrator route: states, counters and gap metadata only.</summary>
        public async Task<SecurityEventSourcesView> EventSourcesAsync(Guid endpointId)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, $"/api/admin/devices/{endpointId:D}/event-sources");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _accessToken);
            using var response = await _client.SendAsync(request);
            Ensure(response.StatusCode == HttpStatusCode.OK && response.Headers.CacheControl?.NoStore == true,
                "Core did not return the event source status.");
            return await response.Content.ReadFromJsonAsync<SecurityEventSourcesView>()
                ?? throw new Exception("Core returned no event source status.");
        }

        public async ValueTask DisposeAsync()
        {
            _client.Dispose();
            await _core.StopAsync();
            await _core.DisposeAsync();
        }
    }
}

internal sealed class MutablePostureReader(SecurityPostureInventory posture) : ISecurityPostureReader
{
    private readonly object _gate = new();
    private SecurityPostureInventory _posture = posture;
    private long _reads;

    public int FailuresRemaining { get; set; }

    public SecurityPostureInventory Current
    {
        get
        {
            lock (_gate)
            {
                return _posture;
            }
        }
        set
        {
            lock (_gate)
            {
                _posture = value;
            }
        }
    }

    public long Reads => Interlocked.Read(ref _reads);

    public SecurityPostureInventory Read()
    {
        Interlocked.Increment(ref _reads);
        lock (_gate)
        {
            if (FailuresRemaining > 0)
            {
                FailuresRemaining--;
                throw new InvalidOperationException("Simulated posture read failure.");
            }

            return _posture;
        }
    }
}

internal sealed class ManualPostureChangeSource(bool available = true) : IPostureChangeSource
{
    private Action? _onChange;
    private int _arms;

    public bool ThrowOnArm { get; set; }
    public int Arms => Volatile.Read(ref _arms);

    public bool Arm(Action onChange)
    {
        Interlocked.Increment(ref _arms);
        if (ThrowOnArm)
        {
            ThrowOnArm = false;
            throw new System.ComponentModel.Win32Exception(5, "Simulated registration failure.");
        }

        Volatile.Write(ref _onChange, onChange);
        return available;
    }

    public void Notify() => Volatile.Read(ref _onChange)?.Invoke();

    public void Dispose() => Volatile.Write(ref _onChange, null);
}

[SupportedOSPlatform("windows")]
internal sealed class RedirectedRegistryPostureReader(string root) : ISecurityPostureReader
{
    public SecurityPostureInventory Read() => WindowsSecurityConfigurationCollector.CollectPosture((keyPath, valueName) =>
    {
        using var hive = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
        using var key = hive.OpenSubKey(root + "\\" + keyPath);
        return key?.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
    });
}

/// <summary>Real Core transport with switchable outage/rejection and request counts.</summary>
internal sealed class CoreLinkHandler() : DelegatingHandler(new HttpClientHandler { UseProxy = false })
{
    private const string SecurityEventsPath = "/api/agent/security-events";
    private int _heartbeats;
    private int _inventoryAttempts;
    private int _inventoryAccepted;
    private int _eventAttempts;
    private int _eventBatchesAccepted;
    private int _eventsInAcceptedBatches;
    private int _eventDuplicates;
    private int _maxEventsInBatch;
    private int _maxEventBodyBytes;
    private int _incompatibleEvents;
    private int _loseNextEventAcknowledgement;
    private volatile bool _outage;
    private volatile bool _rejectInventory;
    private volatile bool _failEvents;

    public bool Outage { get => _outage; set => _outage = value; }
    public bool RejectInventory { get => _rejectInventory; set => _rejectInventory = value; }
    public int Heartbeats => Volatile.Read(ref _heartbeats);
    public int InventoryAttempts => Volatile.Read(ref _inventoryAttempts);
    public int InventoryAccepted => Volatile.Read(ref _inventoryAccepted);

    /// <summary>Security event batches are answered 503 without reaching Core.</summary>
    public bool FailEvents { get => _failEvents; set => _failEvents = value; }

    /// <summary>Security event batches are answered with this status without reaching Core.</summary>
    public HttpStatusCode? IncompatibleEvents
    {
        get
        {
            var status = Volatile.Read(ref _incompatibleEvents);
            return status == 0 ? null : (HttpStatusCode)status;
        }
        set => Volatile.Write(ref _incompatibleEvents, (int?)value ?? 0);
    }

    /// <summary>The next batch carrying events is committed by Core, but its acknowledgement is lost in transport.</summary>
    public bool LoseNextEventAcknowledgement
    {
        get => Volatile.Read(ref _loseNextEventAcknowledgement) != 0;
        set => Volatile.Write(ref _loseNextEventAcknowledgement, value ? 1 : 0);
    }

    public int EventAttempts => Volatile.Read(ref _eventAttempts);
    // Batches and their events that Core answered with success, whether or not the Agent saw the answer.
    public int EventBatchesAccepted => Volatile.Read(ref _eventBatchesAccepted);
    public int EventsInAcceptedBatches => Volatile.Read(ref _eventsInAcceptedBatches);
    // Sum of the duplicates counts in Core's success answers.
    public int EventDuplicates => Volatile.Read(ref _eventDuplicates);
    public int MaxEventsInBatch => Volatile.Read(ref _maxEventsInBatch);
    public int MaxEventBodyBytes => Volatile.Read(ref _maxEventBodyBytes);

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var path = request.RequestUri?.AbsolutePath;
        var inventory = path == "/api/agent/inventory";
        var events = path == SecurityEventsPath;
        if (path == "/api/agent/heartbeat")
        {
            Interlocked.Increment(ref _heartbeats);
        }

        if (inventory)
        {
            Interlocked.Increment(ref _inventoryAttempts);
        }

        if (events)
        {
            Interlocked.Increment(ref _eventAttempts);
        }

        if (Outage)
        {
            throw new HttpRequestException("Simulated Core outage.");
        }

        if (inventory && RejectInventory)
        {
            return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
        }

        if (inventory && !OperatingSystem.IsWindows())
        {
            // Rules intentionally ignore non-Windows inventory. Present the synthetic report
            // from a portable test host as Windows so the unchanged rules evaluate it.
            var report = await request.Content!.ReadFromJsonAsync<InventoryReport>(cancellationToken)
                ?? throw new Exception("The Agent sent an empty inventory.");
            request.Content = JsonContent.Create(report with { OsName = "Windows 11 Pro" });
        }

        var eventCount = 0;
        if (events)
        {
            // Measure the exact body, then send the same bytes with the original content headers.
            var original = request.Content!;
            var body = await original.ReadAsByteArrayAsync(cancellationToken);
            var buffered = new ByteArrayContent(body);
            foreach (var header in original.Headers)
            {
                if (!string.Equals(header.Key, "Content-Length", StringComparison.OrdinalIgnoreCase))
                {
                    buffered.Headers.TryAddWithoutValidation(header.Key, header.Value);
                }
            }

            request.Content = buffered;
            original.Dispose();
            eventCount = JsonSerializer.Deserialize<SecurityEventBatch>(body, SecurityEventContract.Json)?.Events.Count
                ?? throw new Exception("The Agent sent an empty security event batch.");
            Raise(ref _maxEventsInBatch, eventCount);
            Raise(ref _maxEventBodyBytes, body.Length);
            if (FailEvents)
            {
                return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
            }

            if (IncompatibleEvents is { } status)
            {
                return new HttpResponseMessage(status);
            }
        }

        var response = await base.SendAsync(request, cancellationToken);
        if (inventory && response.IsSuccessStatusCode)
        {
            Interlocked.Increment(ref _inventoryAccepted);
        }

        if (events && response.IsSuccessStatusCode)
        {
            // Buffered, so the Agent still reads the same answer.
            var result = JsonSerializer.Deserialize<SecurityEventBatchResult>(
                await response.Content.ReadAsByteArrayAsync(cancellationToken), SecurityEventContract.Json);
            Interlocked.Increment(ref _eventBatchesAccepted);
            Interlocked.Add(ref _eventsInAcceptedBatches, eventCount);
            Interlocked.Add(ref _eventDuplicates, result?.Duplicates ?? 0);
        }

        if (events && eventCount > 0 && Interlocked.Exchange(ref _loseNextEventAcknowledgement, 0) != 0)
        {
            response.Dispose();
            throw new HttpRequestException("Simulated lost acknowledgement.");
        }

        return response;
    }

    private static void Raise(ref int maximum, int value)
    {
        var current = Volatile.Read(ref maximum);
        while (value > current)
        {
            var seen = Interlocked.CompareExchange(ref maximum, value, current);
            if (seen == current)
            {
                return;
            }

            current = seen;
        }
    }
}
