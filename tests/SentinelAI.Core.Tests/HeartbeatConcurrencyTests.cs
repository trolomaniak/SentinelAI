using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Data.Sqlite;
using SentinelAI.Contracts.Enrollment;
using SentinelAI.Contracts.Heartbeat;
using SentinelAI.Contracts.Inventory;
using SentinelAI.Core;
using SentinelAI.Core.Persistence;

static class HeartbeatConcurrencyTests
{
    private const int Iterations = 100;

    public static async Task VerifyAsync()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"sentinelai-heartbeat-tests-{Guid.NewGuid():N}");
        try
        {
            await using var app = CoreHost.Build([$"--SentinelAI:DataDirectory={directory}"],
                builder => builder.Logging.ClearProviders());
            app.Urls.Clear();
            app.Urls.Add("http://127.0.0.1:0");
            await app.StartAsync();
            var databasePath = app.Services.GetRequiredService<AdminStore>().DatabasePath;
            var devices = app.Services.GetRequiredService<DeviceStore>();
            var inventories = app.Services.GetRequiredService<InventoryStore>();
            var enrollments = app.Services.GetRequiredService<EnrollmentStore>();

            var enrolledInstallationId = Guid.NewGuid();
            var token = await enrollments.IssueTokenAsync();
            var enrollment = await enrollments.TryEnrollAsync(
                new EnrollmentRequest(enrolledInstallationId, token.Token));
            Check(enrollment is { Outcome: EnrollmentOutcome.Enrolled, Response: not null },
                "The synthetic heartbeat test Agent could not enroll.");
            var endpointId = enrollment.Response!.EndpointId;
            await inventories.RecordLatestAsync(new InventoryReport(endpointId, DateTimeOffset.UtcNow, "0.1.0-test",
                "synthetic-heartbeat-endpoint", "Windows 11", "10.0.26200.0", "X64", new("Synthetic CPU", 4),
                null, [], new(true, true, true)));
            var unverifiedInstallationId = Guid.NewGuid();

            // A read transaction (dashboard list/export, report or risk read) holds its shared lock for its whole
            // duration; the heartbeat must wait for it to finish instead of failing when it commits.
            var held = await WhileReaderHoldsDatabaseAsync(databasePath,
                () => devices.RecordEnrolledHeartbeatAsync(enrolledInstallationId), "An enrolled heartbeat");
            Check(held.EnrollmentStatus == DeviceEnrollmentStatus.Enrolled &&
                  held.HealthStatus == DeviceHealthStatus.Reporting,
                "An enrolled heartbeat recorded under reader contention returned the wrong state.");
            var heldUnverified = await WhileReaderHoldsDatabaseAsync(databasePath,
                () => devices.RecordHeartbeatAsync(unverifiedInstallationId), "An unverified heartbeat");
            Check(heldUnverified?.EnrollmentStatus == DeviceEnrollmentStatus.Unverified,
                "An unverified heartbeat recorded under reader contention returned the wrong state.");

            using var stop = new CancellationTokenSource();
            var reads = 0L;
            // Microsoft.Data.Sqlite completes "async" calls synchronously, so readers need their own threads.
            var readers = Enumerable.Range(0, 2).Select(_ => Task.Run(async () =>
            {
                while (!stop.IsCancellationRequested)
                {
                    Check(await inventories.FindLatestAsync(endpointId) is not null &&
                          await devices.FindByInstallationIdAsync(enrolledInstallationId) is not null,
                        "A concurrent reader lost the enrolled endpoint.");
                    Interlocked.Increment(ref reads);
                }
            })).ToArray();

            DeviceRecord enrolled = held;
            DeviceRecord? unverified = heldUnverified;
            long concurrentReads;
            try
            {
                var started = DateTimeOffset.UtcNow;
                while (Interlocked.Read(ref reads) == 0 && !readers.Any(reader => reader.IsCompleted))
                {
                    Check(DateTimeOffset.UtcNow - started < TimeSpan.FromSeconds(30),
                        "The concurrent readers did not start.");
                    await Task.Delay(10);
                }

                var readsBeforeWrites = Interlocked.Read(ref reads);
                await Task.Run(async () =>
                {
                    for (var iteration = 0; iteration < Iterations; iteration++)
                    {
                        // Leave readers time to take shared locks between heartbeats, as periodic Agents do.
                        await Task.Delay(1);
                        var nextEnrolled = await devices.RecordEnrolledHeartbeatAsync(enrolledInstallationId);
                        Check(nextEnrolled.EnrollmentStatus == DeviceEnrollmentStatus.Enrolled &&
                              nextEnrolled.LastSeenUtc >= enrolled.LastSeenUtc,
                            "A concurrent enrolled heartbeat returned the wrong state.");
                        enrolled = nextEnrolled;
                        var nextUnverified = await devices.RecordHeartbeatAsync(unverifiedInstallationId);
                        Check(nextUnverified?.EnrollmentStatus == DeviceEnrollmentStatus.Unverified &&
                              nextUnverified.LastSeenUtc >= unverified!.LastSeenUtc,
                            "A concurrent unverified heartbeat returned the wrong state.");
                        unverified = nextUnverified;
                    }
                }).WaitAsync(TimeSpan.FromMinutes(2));
                concurrentReads = Interlocked.Read(ref reads) - readsBeforeWrites;
            }
            finally
            {
                stop.Cancel();
                // Release reader connections before cleanup; reader failures are observed below.
                await Task.WhenAny(Task.WhenAll(readers), Task.Delay(TimeSpan.FromMinutes(1)));
            }

            await Task.WhenAll(readers).WaitAsync(TimeSpan.FromSeconds(1));
            Check(concurrentReads > 0, "No reads overlapped the concurrent heartbeats.");
            Check(await devices.FindByInstallationIdAsync(enrolledInstallationId) == enrolled &&
                  await devices.FindByInstallationIdAsync(unverifiedInstallationId) == unverified,
                "The persisted heartbeats differ from the last returned heartbeats.");
            Check(await devices.CountAsync() == 2, "Concurrent heartbeats duplicated devices.");
            // Enrollment still wins over the legacy unauthenticated path after concurrent writes.
            Check(await devices.RecordHeartbeatAsync(enrolledInstallationId) is null,
                "A legacy heartbeat updated an enrolled device.");

            await app.StopAsync();
            Console.WriteLine($"Heartbeat concurrency tests passed (held read transaction, {Iterations} " +
                $"enrolled/unverified pairs, {concurrentReads} concurrent reads).");
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    private static async Task<T> WhileReaderHoldsDatabaseAsync<T>(
        string databasePath, Func<Task<T>> write, string description)
    {
        await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = false
        }.ToString());
        await connection.OpenAsync();
        Task<T> pending;
        using (var transaction = connection.BeginTransaction(deferred: true))
        {
            await using (var read = connection.CreateCommand())
            {
                read.Transaction = transaction;
                read.CommandText = "SELECT COUNT(*) FROM Devices;";
                await read.ExecuteScalarAsync();
            }

            pending = Task.Run(write);
            await Task.Delay(TimeSpan.FromMilliseconds(500));
            if (pending.IsFaulted)
            {
                throw new InvalidOperationException(
                    $"{description} failed while another connection held a read transaction.",
                    pending.Exception?.GetBaseException());
            }

            transaction.Commit();
        }

        return await pending.WaitAsync(TimeSpan.FromSeconds(20));
    }

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }
}
