using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Contracts.Notifications;
using SentinelAI.Core.Backups;
using SentinelAI.Core.Notifications;
using SentinelAI.Core.Persistence;
using SentinelAI.Rules;

internal static class NotificationStoreTests
{
    internal static async Task RunAsync()
    {
        var directory = Path.Combine(Path.GetTempPath(), "sentinelai-notifications-" + Guid.NewGuid().ToString("N"));
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        { ["SentinelAI:DataDirectory"] = directory }).Build();
        var admins = new AdminStore(configuration, new PasswordHasher<AdminRecord>(), NullLogger<AdminStore>.Instance);
        var time = new TestTime();
        using var protection = new TestProtection();
        var store = new NotificationStore(admins, time, protection);
        var alerts = new AlertStore(admins, store, time);
        var endpoint = Guid.NewGuid(); var installation = Guid.NewGuid();
        var oldEndpoint = Guid.NewGuid(); var oldInstallation = Guid.NewGuid();
        var checks = 0;
        void Check(bool value, string description)
        { if (!value) throw new InvalidOperationException(description); checks++; }
        SqliteConnection Connection() => new(new SqliteConnectionStringBuilder
        { DataSource = admins.DatabasePath, Mode = SqliteOpenMode.ReadWrite, ForeignKeys = true, Pooling = false }.ToString());
        async Task SqlAsync(string sql, params (string Name, object Value)[] parameters)
        {
            await using var connection = Connection(); await connection.OpenAsync(); await using var command = connection.CreateCommand();
            command.CommandText = sql; foreach (var (name, value) in parameters) command.Parameters.AddWithValue(name, value);
            await command.ExecuteNonQueryAsync();
        }
        async Task ObserveAsync(string rule, string severity = "critical", bool commit = true)
        {
            time.Advance(TimeSpan.FromTicks(1));
            await using var connection = Connection(); await connection.OpenAsync(); using var transaction = connection.BeginTransaction();
            await alerts.RecordObservedAsync(connection, transaction, new SecurityAlert(rule, "synthetic title", severity,
                "synthetic arbitrary reason is not sent", [RuleEvidence.Text("synthetic", "private evidence")], endpoint, time.GetUtcNow(), "synthetic action"),
                "synthetic-machine", CancellationToken.None);
            if (commit) transaction.Commit();
        }
        async Task DirectAsync(string kind = "criticalAlertNew", Guid? id = null)
        {
            await using var connection = Connection(); await connection.OpenAsync(); using var transaction = connection.BeginTransaction();
            await store.RecordCriticalAsync(connection, transaction, id ?? Guid.NewGuid(), endpoint, "synthetic-machine", "SYNTHETIC", kind, CancellationToken.None);
            transaction.Commit();
        }
        async Task ResolveAsync(string rule)
        {
            var item = (await alerts.ListAsync(null, null, 0, 100)).Alerts.Single(item => item.RuleId == rule);
            await alerts.UpdateStatusAsync(item.AlertId, "resolved", item.Version, "synthetic-admin");
        }
        NotificationPolicyWrite Write(NotificationPolicy policy, bool webhook = false, bool email = false, string? url = null, string? secret = null, string? password = null) =>
            new(policy.Version, true, false, 15, 5, webhook, url, secret, false, false, email, email ? "smtp.example.com" : null, 587,
                email ? "synthetic-user" : null, password, false, email ? "from@example.com" : null, email ? "to@example.com" : null);
        try
        {
            await admins.InitializeWithCredentialsAsync("synthetic-admin", "Synthetic-Only-Password-17!");
            await new DeviceStore(admins).InitializeAsync(); await new EnrollmentStore(admins).InitializeAsync();
            await alerts.InitializeAsync(); await new InventoryStore(admins, alerts, RuleEngine.CreateDefault()).InitializeAsync();
            foreach (var (id, install, seen) in new[]
            {
                (endpoint,installation,time.GetUtcNow().UtcTicks),
                (oldEndpoint,oldInstallation,time.GetUtcNow().AddDays(-1).UtcTicks)
            })
                await SqlAsync("""
                    INSERT INTO EndpointEnrollments(InstallationId,EndpointId,CoreInstallationId,OrganizationId,CredentialHash)
                        SELECT $install,$endpoint,CoreInstallationId,OrganizationId,$hash FROM CoreIdentity;
                    INSERT INTO Devices VALUES($install,$seen,'reporting','enrolled');
                    """, ("$install", install.ToString("D")), ("$endpoint", id.ToString("D")), ("$hash", RandomNumberGenerator.GetBytes(32)), ("$seen", seen));
            await ObserveAsync("PRE-UPGRADE");
            await store.InitializeAsync(); await store.ObserveMonitoringAsync();
            Check((await store.ListAsync(0, 100)).Total == 0, "Upgrade backfill or offline baseline flooded the notification center.");
            var policy = await store.GetPolicyAsync();
            Check(policy.Version == 1 && !policy.EmailEnabled && !policy.WebhookEnabled && policy.CriticalAlerts && policy.MonitoringChanges,
                "External notifications were enabled by default or local categories were disabled.");
            await ObserveAsync("ROLLED-BACK", commit: false);
            Check((await store.ListAsync(0, 100)).Total == 0 && !(await alerts.ListAsync(null, null, 0, 100)).Alerts.Any(x => x.RuleId == "ROLLED-BACK"),
                "A rolled-back alert transaction leaked a notification or alert.");
            await ObserveAsync("NEW"); await ObserveAsync("NEW");
            Check((await store.ListAsync(0, 100)).Items.Count(x => x.Kind == "criticalAlertNew") == 1, "Repeated critical observations created a storm.");
            await ObserveAsync("ESCALATION", "high"); await ObserveAsync("ESCALATION");
            Check((await store.ListAsync(0, 100)).Items.Count(x => x.Kind == "criticalAlertEscalated") == 1, "High-to-critical escalation was not persisted.");
            await ResolveAsync("NEW"); await ObserveAsync("NEW");
            var reopened = (await store.ListAsync(0, 100)).Items.Single(x => x.Kind == "criticalAlertReopened");
            Check(await store.MarkReadAsync(reopened.NotificationId), "An existing notification could not be marked read.");
            var read = (await store.ListAsync(0, 100)).Items.Single(x => x.NotificationId == reopened.NotificationId).ReadUtc;
            Check(await store.MarkReadAsync(reopened.NotificationId) && (await store.ListAsync(0, 100)).Items.Single(x => x.NotificationId == reopened.NotificationId).ReadUtc == read,
                "Mark-read was not idempotent.");
            time.Advance(TimeSpan.FromMinutes(4)); await ResolveAsync("NEW"); await ObserveAsync("NEW");
            reopened = (await store.ListAsync(0, 100)).Items.Single(x => x.Kind == "criticalAlertReopened");
            Check(reopened.Occurrences == 2 && reopened.ReadUtc is null, "Grouping lost count or failed to restore unread state.");
            time.Advance(TimeSpan.FromMinutes(1)); await ResolveAsync("NEW"); await ObserveAsync("NEW");
            Check((await store.ListAsync(0, 100)).Items.Count(x => x.Kind == "criticalAlertReopened") == 2,
                "The fixed group window slid forward after a repeated transition.");
            var page = await store.ListAsync(1, 1);
            Check(page.Items.Count == 1 && page.Total == 4 && page.Offset == 1 && page.Limit == 1, "Notification paging lost stable totals or bounds.");
            Check(!await store.MarkReadAsync(Guid.NewGuid()), "A missing notification was marked read.");
            foreach (var (offset, limit) in new[] { (-1, 1), (0, 0), (0, 101), (100001, 1) })
            {
                try { _ = await store.ListAsync(offset, limit); throw new InvalidOperationException("Paging accepted an invalid bound."); }
                catch (ArgumentOutOfRangeException) { checks++; }
            }
            time.Advance(TimeSpan.FromMinutes(10)); await store.ObserveMonitoringAsync(); await store.ObserveMonitoringAsync();
            Check((await store.ListAsync(0, 100)).Items.Count(x => x.Kind == "monitoringOffline") == 1, "Offline threshold or durable transition deduplication failed.");
            store = new NotificationStore(admins, time, protection); await store.InitializeAsync(); await store.ObserveMonitoringAsync();
            Check((await store.ListAsync(0, 100)).Items.Count(x => x.Kind == "monitoringOffline") == 1, "Restart duplicated offline transitions.");
            await SqlAsync("UPDATE Devices SET LastSeenUtcTicks=$now WHERE InstallationId=$install;", ("$now", time.GetUtcNow().UtcTicks), ("$install", installation.ToString("D")));
            await store.ObserveMonitoringAsync(); await store.ObserveMonitoringAsync();
            Check((await store.ListAsync(0, 100)).Items.Count(x => x.Kind == "monitoringRecovered") == 1, "Monitoring recovery did not fire exactly once.");
            Check((await store.DeliveriesAsync(0, 100)).Total == 0, "Disabled channels queued external delivery work.");
            var laterEndpoint = Guid.NewGuid(); var laterInstallation = Guid.NewGuid();
            await SqlAsync("""
                INSERT INTO EndpointEnrollments(InstallationId,EndpointId,CoreInstallationId,OrganizationId,CredentialHash)
                    SELECT $install,$endpoint,CoreInstallationId,OrganizationId,$hash FROM CoreIdentity;
                INSERT INTO Devices VALUES($install,$seen,'reporting','enrolled');
                """, ("$install", laterInstallation.ToString("D")), ("$endpoint", laterEndpoint.ToString("D")),
                ("$hash", RandomNumberGenerator.GetBytes(32)), ("$seen", time.GetUtcNow().AddMinutes(-15).UtcTicks));
            await store.ObserveMonitoringAsync();
            Check((await store.ListAsync(0, 100)).Items.Any(x => x.EndpointId == laterEndpoint && x.Kind == "monitoringOffline"),
                "A new endpoint that missed its first monitoring scan never notified its offline transition.");

            const string url = "https://hooks.example.com/private/synthetic-token?access=synthetic-query-secret";
            const string secret = "synthetic-webhook-signing-secret";
            const string password = "Synthetic-SMTP-Password!";
            policy = (await store.UpdatePolicyAsync(Write(await store.GetPolicyAsync(), true, true, url, secret, password)))!;
            Check(policy.HasWebhookDestination && policy.HasWebhookSecret && policy.HasSmtpPassword && policy.WebhookOrigin == "https://hooks.example.com",
                "Protected destination or secret-presence metadata was not saved.");
            var publicJson = JsonSerializer.Serialize(policy);
            Check(!publicJson.Contains("synthetic-token") && !publicJson.Contains(secret) && !publicJson.Contains(password) && !publicJson.Contains("access="),
                "A settings response exposed a protected URL or secret.");
            using (var destination = await store.GetDestinationAsync(policy.Version, "webhook", CancellationToken.None))
                Check(destination?.WebhookUri?.OriginalString == url && Encoding.UTF8.GetString(destination.WebhookSecret!) == secret, "Protected webhook values did not round-trip.");
            using (var destination = await store.GetDestinationAsync(policy.Version, "email", CancellationToken.None))
                Check(destination?.SmtpHost == "smtp.example.com" && Encoding.UTF8.GetString(destination.SmtpPassword!) == password, "Protected SMTP password did not round-trip.");
            await using (var connection = Connection())
            {
                await connection.OpenAsync(); await using var query = connection.CreateCommand();
                query.CommandText = "SELECT ProtectedWebhookUrl,ProtectedWebhookSecret,ProtectedSmtpPassword FROM NotificationPolicy;";
                await using var reader = await query.ExecuteReaderAsync(); await reader.ReadAsync();
                foreach (var (index, plain) in new[] { (0, url), (1, secret), (2, password) })
                    Check(!((byte[])reader[index]).AsSpan().SequenceEqual(Encoding.UTF8.GetBytes(plain)), "SQLite stored an unprotected credential.");
            }
            var stale = Write(policy);
            policy = (await store.UpdatePolicyAsync(Write(policy, true, true)))!;
            Check(policy.HasWebhookDestination && policy.HasWebhookSecret && policy.HasSmtpPassword, "Null write-only values erased credentials instead of retaining them.");
            Check(await store.UpdatePolicyAsync(stale) is null, "Stale policy version overwrote newer settings.");
            foreach (var invalid in new[]
            {
                Write(policy) with { OfflineMinutes=4 },Write(policy) with { GroupMinutes=61 },Write(policy) with { SmtpPort=25 },
                Write(policy) with { WebhookUrl="https://127.0.0.1/private" },Write(policy) with { WebhookSecret="too-short" },
                Write(policy) with { SmtpPassword="1234567" },Write(policy) with { SmtpPassword=new string('ą',257) },
                Write(policy) with { WebhookUrl=url,ClearWebhookDestination=true }
            })
            {
                try { await store.UpdatePolicyAsync(invalid); throw new InvalidOperationException("Invalid policy was accepted."); }
                catch (ArgumentException) { checks++; }
            }
            // Only one fake external channel is needed for retry behavior. No fixture contacts a socket.
            policy = (await store.UpdatePolicyAsync(Write(policy, true)))!;
            await DirectAsync();
            Check(await store.ClaimAsync() is null, "An outbox delivery escaped the fixed grouping window.");
            var fake = new FakeSender(); var worker = new NotificationWorker(store, fake, time, NullLogger<NotificationWorker>.Instance);
            time.Advance(TimeSpan.FromMinutes(5)); await worker.ProcessOnceAsync();
            var deliveries = await store.DeliveriesAsync(0, 100);
            Check(fake.Payloads.Count == 1 && deliveries.Items.Single().State == "retry" && deliveries.Items.Single().Attempts == 1, "A transient failure was not durably queued for retry.");
            await worker.ProcessOnceAsync(); Check(fake.Payloads.Count == 1, "Retry ignored backoff.");
            foreach (var seconds in new[] { 15, 60, 300, 300 }) { time.Advance(TimeSpan.FromSeconds(seconds)); await worker.ProcessOnceAsync(); }
            deliveries = await store.DeliveriesAsync(0, 100);
            Check(fake.Payloads.Count == 5 && deliveries.Items.Single().State == "failed" && deliveries.Items.Single().Attempts == 5,
                "Retry count exceeded five attempts or failed to become terminal.");
            Check(fake.Payloads.Select(x => x.NotificationId).Distinct().Count() == 1 && fake.Payloads.Distinct().Count() == 1,
                "At-least-once retries changed their idempotency key or payload.");
            var payloadJson = JsonSerializer.Serialize(fake.Payloads[0]);
            Check(!payloadJson.Contains("synthetic-machine") && !payloadJson.Contains("private evidence") && !payloadJson.Contains("arbitrary reason"),
                "External payload included endpoint names, evidence, or arbitrary finding text.");
            await DirectAsync(); time.Advance(TimeSpan.FromMinutes(5));
            var leased = (await store.ClaimAsync())!;
            Check(await store.ClaimAsync() is null, "A live attempt was reclaimed before its bounded transport could finish.");
            await using (var blocker = Connection())
            {
                await blocker.OpenAsync(); using var locked = blocker.BeginTransaction(deferred: false);
                try { await store.CompleteAsync(leased, new(true, false, "delivered")); throw new InvalidOperationException("A locked completion unexpectedly committed."); }
                catch (SqliteException error) when (error.SqliteErrorCode == 5) { checks++; }
            }
            time.Advance(TimeSpan.FromSeconds(59));
            Check(await store.ClaimAsync() is null, "Lease recovery overlapped a possibly active attempt.");
            time.Advance(TimeSpan.FromSeconds(1));
            var reclaimed = (await store.ClaimAsync())!;
            Check(reclaimed.DeliveryId == leased.DeliveryId && reclaimed.Attempts == 2 && reclaimed.Payload == leased.Payload,
                "A failed completion stranded sending work until process restart.");
            await store.CompleteAsync(leased, new(true, false, "delivered"));
            Check((await store.DeliveriesAsync(0, 100)).Items.Single(x => x.DeliveryId == leased.DeliveryId).State == "sending",
                "A stale completion overwrote a reclaimed attempt.");
            await store.CompleteAsync(reclaimed, new(true, false, "delivered"));
            await DirectAsync(); time.Advance(TimeSpan.FromMinutes(5));
            var interrupted = (await store.ClaimAsync())!;
            store = new NotificationStore(admins, time, protection); await store.InitializeAsync();
            var retried = (await store.ClaimAsync())!;
            Check(retried.DeliveryId == interrupted.DeliveryId && retried.Attempts == 2 && retried.Payload == interrupted.Payload,
                "A sending delivery was lost or changed identity after restart.");
            policy = (await store.UpdatePolicyAsync(Write(await store.GetPolicyAsync(), true)))!;
            await store.CompleteAsync(retried, new(true, false, "delivered"));
            Check((await store.DeliveriesAsync(0, 100)).Items.Single(x => x.DeliveryId == retried.DeliveryId).State == "cancelled",
                "A stale in-flight result resurrected delivery after a policy change.");
            await DirectAsync(); time.Advance(TimeSpan.FromMinutes(5));
            var blockedSender = new BlockingSender();
            using (var activeWorker = new NotificationWorker(store, blockedSender, time, NullLogger<NotificationWorker>.Instance))
            {
                await activeWorker.StartAsync(CancellationToken.None);
                await blockedSender.Started.Task.WaitAsync(TimeSpan.FromSeconds(10));
                policy = (await store.UpdatePolicyAsync(Write(await store.GetPolicyAsync(), true)))!;
                await blockedSender.Cancelled.Task.WaitAsync(TimeSpan.FromSeconds(10));
                using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                await activeWorker.StopAsync(stop.Token);
            }
            Check((await store.DeliveriesAsync(0, 100)).Items.Single(x => x.NotificationId == blockedSender.NotificationId).State == "cancelled",
                "A policy change failed to cancel an in-flight worker attempt.");

            policy = (await store.UpdatePolicyAsync(Write(await store.GetPolicyAsync(), true) with { MonitoringChanges = true }))!;
            await DirectAsync(); time.Advance(TimeSpan.FromMinutes(5));
            var monitoredEndpoint = Guid.NewGuid(); var monitoredInstallation = Guid.NewGuid();
            await SqlAsync("""
                INSERT INTO EndpointEnrollments(InstallationId,EndpointId,CoreInstallationId,OrganizationId,CredentialHash)
                    SELECT $install,$endpoint,CoreInstallationId,OrganizationId,$hash FROM CoreIdentity;
                INSERT INTO Devices VALUES($install,$seen,'reporting','enrolled');
                """, ("$install", monitoredInstallation.ToString("D")), ("$endpoint", monitoredEndpoint.ToString("D")),
                ("$hash", RandomNumberGenerator.GetBytes(32)), ("$seen", time.GetUtcNow().AddMinutes(-15).AddSeconds(1).UtcTicks));
            await store.ObserveMonitoringAsync();
            var slowSender = new BlockingSender();
            using (var activeWorker = new NotificationWorker(store, slowSender, time, NullLogger<NotificationWorker>.Instance))
            {
                async Task WaitForMonitoringAsync(string kind)
                {
                    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                    while (!(await store.ListAsync(0, 100)).Items.Any(x => x.EndpointId == monitoredEndpoint && x.Kind == kind))
                        await Task.Delay(10, timeout.Token);
                }

                await activeWorker.StartAsync(CancellationToken.None);
                try
                {
                    await slowSender.Started.Task.WaitAsync(TimeSpan.FromSeconds(10));
                    time.Advance(TimeSpan.FromSeconds(15));
                    await WaitForMonitoringAsync("monitoringOffline");
                    await SqlAsync("UPDATE Devices SET LastSeenUtcTicks=$now WHERE InstallationId=$install;",
                        ("$now", time.GetUtcNow().UtcTicks), ("$install", monitoredInstallation.ToString("D")));
                    time.Advance(TimeSpan.FromSeconds(15));
                    await WaitForMonitoringAsync("monitoringRecovered");
                    var transitions = (await store.ListAsync(0, 100)).Items.Where(x => x.EndpointId == monitoredEndpoint).ToArray();
                    Check(transitions.Count(x => x.Kind == "monitoringOffline") == 1 && transitions.Count(x => x.Kind == "monitoringRecovered") == 1 &&
                        slowSender.Calls == 1 && !slowSender.Cancelled.Task.IsCompleted,
                        "A blocked external send delayed local monitoring transitions or caused concurrent delivery attempts.");
                }
                finally
                {
                    using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                    await activeWorker.StopAsync(stop.Token);
                }
            }
            await DirectAsync();
            await using (var connection = Connection())
            {
                await connection.OpenAsync(); using var transaction = connection.BeginTransaction();
                await NotificationStore.SuppressAfterRecoveryAsync(connection, transaction, CancellationToken.None); transaction.Commit();
            }
            policy = await store.GetPolicyAsync();
            Check(!policy.WebhookEnabled && !policy.EmailEnabled && !policy.HasWebhookDestination && !policy.HasWebhookSecret && !policy.HasSmtpPassword,
                "Recovery reactivated external sending or retained protected credentials.");
            Check((await store.DeliveriesAsync(0, 100)).Items.All(x => x.State is "failed" or "cancelled" or "succeeded"), "Recovery retained pending delivery work.");
            Check(await store.ClaimAsync() is null, "Recovery allowed an old snapshot to resend notifications.");
            await using (var connection = Connection())
            {
                await connection.OpenAsync(); using var transaction = connection.BeginTransaction();
                // Old archives without optional tables are still supported.
                foreach (var table in new[] { "NotificationDeliveries", "NotificationPolicy", "NotificationMonitoringState", "NotificationRuntime" })
                { await using var drop = connection.CreateCommand(); drop.Transaction = transaction; drop.CommandText = "DROP TABLE " + table; await drop.ExecuteNonQueryAsync(); }
                await NotificationStore.SuppressAfterRecoveryAsync(connection, transaction, CancellationToken.None); transaction.Commit(); checks++;
            }
            await store.InitializeAsync();
            policy = (await store.UpdatePolicyAsync(Write(await store.GetPolicyAsync(), true, url: url, secret: secret)))!;
            policy = (await store.UpdatePolicyAsync(Write(policy) with { ClearWebhookDestination = true, ClearWebhookSecret = true, ClearSmtpPassword = true }))!;
            Check(!policy.HasWebhookDestination && !policy.HasWebhookSecret && !policy.HasSmtpPassword, "Explicit clear flags retained credentials.");
            await DirectAsync();
            time.Advance(TimeSpan.FromDays(31)); await store.PruneAsync();
            Check((await store.ListAsync(0, 100)).Total == 0 && (await store.DeliveriesAsync(0, 100)).Total == 0, "Thirty-day retention left notifications or orphaned deliveries.");
            await SqlAsync("""
                WITH RECURSIVE numbers(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM numbers WHERE n<10000)
                INSERT INTO Notifications SELECT '00000000-0000-0000-0000-'||printf('%012d',n),'criticalAlertNew',$endpoint,$name,NULL,$rule,
                    'critical',1,$now,$now,NULL,'synthetic-'||n,$due FROM numbers;
                """, ("$endpoint", endpoint.ToString("D")), ("$name", new string('ą', 128)), ("$rule", new string('ą', 128)),
                ("$now", time.GetUtcNow().AddTicks(-1).UtcTicks), ("$due", time.GetUtcNow().AddMinutes(5).UtcTicks));
            await DirectAsync();
            var bounded = await store.ListAsync(0, 100);
            Check(bounded.Total == 10000 && bounded.Items.Count == 100 &&
                JsonSerializer.SerializeToUtf8Bytes(bounded, new JsonSerializerOptions(JsonSerializerDefaults.Web)).Length <= NotificationContract.MaximumResponseBytes,
                "Notification retention cap or maximum encoded response size was exceeded.");
            time.Advance(TimeSpan.FromDays(31)); await store.PruneAsync();
            Check((await store.ListAsync(0, 1)).Total == 9500, "Retention cleanup did not bound each sweep to 500 expired notifications.");
            for (var index = 0; index < 19; index++) await store.PruneAsync();
            Check((await store.ListAsync(0, 1)).Total == 0, "Bounded retention sweeps failed to drain expired notifications.");
            if (OperatingSystem.IsWindows())
            {
                var production = new WindowsNotificationCredentialProtection(); var plain = Encoding.UTF8.GetBytes(secret);
                var ciphertext = production.Protect(plain); var decrypted = production.Unprotect(ciphertext);
                Check(plain.AsSpan().SequenceEqual(decrypted) && !plain.AsSpan().SequenceEqual(ciphertext), "Production DPAPI did not round-trip synthetic notification credentials.");
                CryptographicOperations.ZeroMemory(decrypted);
                var other = new WindowsBackupKeyProtection().Protect(plain);
                try { var wrong = production.Unprotect(other); CryptographicOperations.ZeroMemory(wrong); throw new InvalidOperationException("Notification DPAPI accepted another feature's entropy."); }
                catch (CryptographicException) { checks++; }
                CryptographicOperations.ZeroMemory(plain);
            }
        }
        finally { SqliteConnection.ClearAllPools(); if (Directory.Exists(directory)) Directory.Delete(directory, true); }
        Console.WriteLine($"Notification store tests passed ({checks} checks: transactions, grouping, monitoring, paging, secrets, policy CAS, retries, restart, recovery, retention).");
    }

    private sealed class TestTime : TimeProvider
    {
        private readonly object _gate = new();
        private readonly HashSet<ManualTimer> _timers = [];
        private DateTimeOffset _now = new(2026, 11, 17, 12, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() { lock (_gate) return _now; }
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            var timer = new ManualTimer(this, callback, state);
            timer.Change(dueTime, period); return timer;
        }
        internal void Advance(TimeSpan delta)
        {
            List<ManualTimer> ready;
            lock (_gate)
            {
                _now += delta;
                ready = _timers.Where(timer => timer.Due(_now.UtcTicks)).ToList();
            }
            foreach (var timer in ready) timer.Fire();
        }

        private sealed class ManualTimer(TestTime owner, TimerCallback callback, object? state) : ITimer
        {
            private long _next = long.MaxValue;
            private long _period;
            private bool _disposed;
            public bool Change(TimeSpan dueTime, TimeSpan period)
            {
                lock (owner._gate)
                {
                    if (_disposed) return false;
                    _next = dueTime == Timeout.InfiniteTimeSpan ? long.MaxValue : owner._now.UtcTicks + dueTime.Ticks;
                    _period = period.Ticks;
                    owner._timers.Add(this); return true;
                }
            }
            internal bool Due(long now)
            {
                if (_disposed || _next > now) return false;
                _next = _period > 0 ? _next + ((now - _next) / _period + 1) * _period : long.MaxValue;
                return true;
            }
            internal void Fire()
            {
                lock (owner._gate) { if (_disposed) return; }
                callback(state);
            }
            public void Dispose() { lock (owner._gate) { _disposed = true; owner._timers.Remove(this); } }
            public ValueTask DisposeAsync() { Dispose(); return ValueTask.CompletedTask; }
        }
    }
    private sealed class FakeSender : INotificationSender
    {
        internal List<NotificationPayload> Payloads { get; } = [];
        public Task<NotificationSendResult> SendAsync(NotificationPayload payload, NotificationDestination destination, CancellationToken cancellationToken)
        { cancellationToken.ThrowIfCancellationRequested(); Payloads.Add(payload); return Task.FromResult(new NotificationSendResult(false, true, "syntheticFailure")); }
    }
    private sealed class BlockingSender : INotificationSender
    {
        private int _calls;
        internal TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Cancelled { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal Guid NotificationId { get; private set; }
        internal int Calls => Volatile.Read(ref _calls);
        public async Task<NotificationSendResult> SendAsync(NotificationPayload payload, NotificationDestination destination, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _calls);
            NotificationId = payload.NotificationId; Started.TrySetResult();
            try { await Task.Delay(Timeout.Infinite, cancellationToken); }
            catch (OperationCanceledException) { Cancelled.TrySetResult(); throw; }
            return new(false, false, "syntheticFailure");
        }
    }
    private sealed class TestProtection : INotificationCredentialProtection, IDisposable
    {
        private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);
        public bool IsSupported => true;
        public byte[] Protect(ReadOnlySpan<byte> value)
        {
            var bytes = new byte[28 + value.Length]; RandomNumberGenerator.Fill(bytes.AsSpan(0, 12));
            using var aes = new AesGcm(_key, 16); aes.Encrypt(bytes.AsSpan(0, 12), value, bytes.AsSpan(28), bytes.AsSpan(12, 16)); return bytes;
        }
        public byte[] Unprotect(ReadOnlySpan<byte> value)
        {
            var plain = new byte[value.Length - 28]; using var aes = new AesGcm(_key, 16);
            aes.Decrypt(value[..12], value[28..], value.Slice(12, 16), plain); return plain;
        }
        public void Dispose() => CryptographicOperations.ZeroMemory(_key);
    }
}
