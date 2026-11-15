using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SentinelAI.Contracts.Enrollment;
using SentinelAI.Contracts.Heartbeat;
using SentinelAI.Core;
using SentinelAI.Core.Persistence;

internal static class HeartbeatConcurrencyTests
{
    public static async Task RunAsync()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"sentinelai-heartbeat-lock-tests-{Guid.NewGuid():N}");
        try
        {
            await using var app = CoreHost.Build(["--SentinelAI:DataDirectory=" + directory],
                configureBuilder: builder => builder.Logging.ClearProviders());
            app.Urls.Clear();
            app.Urls.Add("http://127.0.0.1:0");
            await app.StartAsync();
            using var client = new HttpClient(new HttpClientHandler { UseProxy = false })
            {
                BaseAddress = new Uri(app.Urls.Single()), Timeout = TimeSpan.FromSeconds(15)
            };
            var devices = app.Services.GetRequiredService<DeviceStore>();
            var database = app.Services.GetRequiredService<AdminStore>().DatabasePath;
            var enrollments = app.Services.GetRequiredService<EnrollmentStore>();
            var legacyId = Guid.NewGuid();
            var enrolledId = Guid.NewGuid();
            var token = await enrollments.IssueTokenAsync();
            var enrollment = (await enrollments.TryEnrollAsync(new EnrollmentRequest(enrolledId, token.Token))).Response
                ?? throw new InvalidOperationException("The synthetic heartbeat endpoint could not enroll.");

            // This regression deliberately exercises SQLite's existing rollback journal,
            // where a reader can coexist with a writer but prevent its commit.
            await using (var connection = await OpenAsync(database))
            {
                using var journal = connection.CreateCommand();
                journal.CommandText = "PRAGMA journal_mode;";
                Check(string.Equals((string?)await journal.ExecuteScalarAsync(), "delete", StringComparison.OrdinalIgnoreCase),
                    "The heartbeat lock regression requires the default rollback journal.");
            }
            await devices.RecordHeartbeatAsync(legacyId);
            await devices.RecordEnrolledHeartbeatAsync(enrolledId);
            await VerifyReaderAndOtherWriterAsync(devices, database, legacyId, enrolled: false);
            await VerifyReaderAndOtherWriterAsync(devices, database, enrolledId, enrolled: true);
            await VerifyCancellationAsync(devices, database, atCommit: false);
            await VerifyCancellationAsync(devices, database, atCommit: true);
            await VerifyHttpConcurrencyAsync(client, devices, database, legacyId, enrolledId, enrollment);
            await app.StopAsync();
            Console.WriteLine("Heartbeat concurrency tests passed (reader/other writer overlap, monotonicity, cancellation/rollback, authenticated HTTP concurrency).");
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    private static async Task VerifyReaderAndOtherWriterAsync(DeviceStore devices, string database,
        Guid installationId, bool enrolled)
    {
        // A future stored timestamp also proves a delayed/older write cannot move last-seen backwards.
        var future = DateTimeOffset.UtcNow.AddHours(1);
        await using (var seed = await OpenAsync(database))
        {
            using var command = seed.CreateCommand();
            command.CommandText = "UPDATE Devices SET LastSeenUtcTicks = $ticks WHERE InstallationId = $id;";
            command.Parameters.AddWithValue("$ticks", future.UtcTicks);
            command.Parameters.AddWithValue("$id", installationId.ToString("D"));
            await command.ExecuteNonQueryAsync();
        }
        await using var readerConnection = await OpenAsync(database);
        using var reader = await HoldReaderAsync(readerConnection);
        await using var otherWriterConnection = await OpenAsync(database);
        using var otherWriter = otherWriterConnection.BeginTransaction(deferred: false);
        using var started = new ManualResetEventSlim();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var heartbeat = StartDedicated(async () =>
        {
            started.Set();
            return enrolled
                ? await devices.RecordEnrolledHeartbeatAsync(installationId, deadline.Token)
                : await devices.RecordHeartbeatAsync(installationId, deadline.Token);
        });
        Check(started.Wait(TimeSpan.FromSeconds(5)), "The heartbeat worker did not start.");
        // It must first contend with an independent writer, then commit past a reader.
        await Task.Delay(1100);
        Check(!heartbeat.IsCompleted, "The heartbeat did not wait for the independent writer.");
        otherWriter.Rollback();
        var observedWriteLock = false;
        try
        {
            observedWriteLock = await ObserveWriterAsync(database, heartbeat);
        }
        finally
        {
            reader.Rollback();
        }
        var result = await heartbeat.WaitAsync(TimeSpan.FromSeconds(5));
        Check(observedWriteLock, "The heartbeat did not wait at the reader-blocked commit.");
        Check(result is not null && result.LastSeenUtc == future && result.HealthStatus == DeviceHealthStatus.Reporting &&
              result.EnrollmentStatus == (enrolled ? DeviceEnrollmentStatus.Enrolled : DeviceEnrollmentStatus.Unverified),
            "A contended heartbeat lost its monotonic timestamp, health or enrollment status.");
        Check(await devices.FindByInstallationIdAsync(installationId) == result,
            "The heartbeat returned before its exact result was committed.");
    }

    private static async Task VerifyCancellationAsync(DeviceStore devices, string database, bool atCommit)
    {
        var installationId = Guid.NewGuid();
        await using var blockerConnection = await OpenAsync(database);
        using var blocker = atCommit
            ? await HoldReaderAsync(blockerConnection)
            : blockerConnection.BeginTransaction(deferred: false);
        using var started = new ManualResetEventSlim();
        using var cancellation = new CancellationTokenSource();
        var heartbeat = StartDedicated(() =>
        {
            started.Set();
            return devices.RecordEnrolledHeartbeatAsync(installationId, cancellation.Token);
        });
        Check(started.Wait(TimeSpan.FromSeconds(5)), "The cancellable heartbeat worker did not start.");
        try
        {
            if (atCommit)
                Check(await ObserveWriterAsync(database, heartbeat), "The cancellation test did not reach a blocked commit.");
            else
                await Task.Delay(100); // Allow BEGIN's native busy wait to start while the writer remains held.
            var elapsed = Stopwatch.StartNew();
            cancellation.Cancel();
            try
            {
                await heartbeat.WaitAsync(TimeSpan.FromSeconds(5));
                throw new InvalidOperationException("A heartbeat ignored cancellation while the database remained locked.");
            }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
            {
                Check(elapsed.Elapsed < TimeSpan.FromSeconds(5), "Heartbeat cancellation waited for the full SQLite timeout.");
            }
        }
        finally
        {
            cancellation.Cancel();
            blocker.Rollback();
            // Finish ownership of the connection before disposing the fixture on a failed assertion.
            try { await heartbeat.WaitAsync(TimeSpan.FromSeconds(5)); }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { }
        }
        Check(await devices.FindByInstallationIdAsync(installationId) is null,
            "A cancelled heartbeat left an uncommitted write persisted.");
        Check((await devices.RecordEnrolledHeartbeatAsync(installationId)).EnrollmentStatus == DeviceEnrollmentStatus.Enrolled,
            "A cancelled heartbeat retained a SQLite lock after rollback.");
    }

    private static async Task VerifyHttpConcurrencyAsync(HttpClient client, DeviceStore devices, string database,
        Guid legacyId, Guid enrolledId, EnrollmentResponse enrollment)
    {
        using (var anonymous = await client.PostAsJsonAsync("/api/agent/heartbeat", new HeartbeatRequest(enrolledId)))
            Check(anonymous.StatusCode == HttpStatusCode.Unauthorized, "A legacy heartbeat overwrote an enrolled device.");
        var before = await devices.FindByInstallationIdAsync(enrolledId);
        await using var readerConnection = await OpenAsync(database);
        using var reader = await HoldReaderAsync(readerConnection);
        var requests = Enumerable.Range(0, 12).Select(async index =>
        {
            var installationId = index % 2 == 0 ? legacyId : enrolledId;
            using var request = new HttpRequestMessage(HttpMethod.Post, "/api/agent/heartbeat")
            {
                Content = JsonContent.Create(new HeartbeatRequest(installationId))
            };
            if (installationId == enrolledId)
                request.Headers.Authorization = new AuthenticationHeaderValue("SentinelAgent", $"{enrollment.EndpointId:D}.{enrollment.AgentCredential}");
            using var response = await client.SendAsync(request);
            Check(response.StatusCode == HttpStatusCode.OK, "A concurrent heartbeat failed at the HTTP boundary: " + response.StatusCode);
            return await response.Content.ReadFromJsonAsync<HeartbeatResponse>()
                ?? throw new InvalidOperationException("A concurrent heartbeat returned no result.");
        }).ToArray();
        var all = Task.WhenAll(requests);
        try
        {
            Check(await ObserveWriterAsync(database, all), "HTTP heartbeats did not overlap the held database reader.");
        }
        finally { reader.Rollback(); }
        var results = await all.WaitAsync(TimeSpan.FromSeconds(10));
        foreach (var installationId in new[] { legacyId, enrolledId })
        {
            var saved = await devices.FindByInstallationIdAsync(installationId);
            Check(saved is not null && saved.LastSeenUtc == results.Where(result => result.InstallationId == installationId).Max(result => result.LastSeenUtc),
                "Concurrent HTTP heartbeats did not persist the latest acknowledged timestamp.");
        }
        Check((await devices.FindByInstallationIdAsync(enrolledId))!.LastSeenUtc >= before!.LastSeenUtc,
            "Concurrent enrolled heartbeats moved last-seen backwards.");
    }

    private static async Task<SqliteTransaction> HoldReaderAsync(SqliteConnection connection)
    {
        var transaction = connection.BeginTransaction(deferred: true);
        try
        {
            using var query = connection.CreateCommand();
            query.Transaction = transaction;
            query.CommandText = "SELECT COUNT(*) FROM Devices;";
            await query.ExecuteScalarAsync();
            return transaction;
        }
        catch { transaction.Dispose(); throw; }
    }

    private static async Task<bool> ObserveWriterAsync(string database, Task heartbeat)
    {
        await using var probe = await OpenAsync(database);
        var elapsed = Stopwatch.StartNew();
        while (!heartbeat.IsCompleted && elapsed.Elapsed < TimeSpan.FromSeconds(5))
        {
            try
            {
                using var transaction = probe.BeginTransaction(deferred: false);
                transaction.Rollback();
            }
            catch (SqliteException exception) when (exception.SqliteErrorCode == 5)
            {
                return true; // A real competing write lock, rather than a timing assumption.
            }
            await Task.Delay(10);
        }
        return false;
    }

    private static async Task<SqliteConnection> OpenAsync(string database)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = database, Mode = SqliteOpenMode.ReadWrite, DefaultTimeout = 1, Pooling = false
        }.ToString());
        await connection.OpenAsync();
        return connection;
    }

    private static Task<T> StartDedicated<T>(Func<Task<T>> action) => Task.Factory.StartNew(action,
        CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default).Unwrap();

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }
}
