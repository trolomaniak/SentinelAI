using SentinelAI.Contracts.EndpointTelemetry;

namespace SentinelAI.Agent;

/// <summary>
/// Reads one telemetry section each. Implementations return a section with its availability and may throw;
/// <see cref="EndpointTelemetryCollector"/> turns a failure into an Unknown section of the matching availability.
/// </summary>
public interface IEndpointTelemetrySource
{
    BitLockerTelemetry ReadBitLocker();
    AntivirusTelemetry ReadAntivirus();
    DefenderTelemetry ReadDefender();
    LocalAdministratorsTelemetry ReadLocalAdministrators();
    WindowsUpdateTelemetry ReadWindowsUpdate(DateTimeOffset collectedUtc);
    PendingRebootTelemetry ReadPendingReboot();
    SecurityServicesTelemetry ReadServices();
    InstalledSoftwareTelemetry ReadSoftware();
}

/// <summary>Non-Windows hosts provide none of the Windows sources.</summary>
public sealed class UnsupportedEndpointTelemetrySource : IEndpointTelemetrySource
{
    private const string Unsupported = TelemetryAvailability.Unsupported;
    public BitLockerTelemetry ReadBitLocker() => new(Unsupported);
    public AntivirusTelemetry ReadAntivirus() => new(Unsupported);
    public DefenderTelemetry ReadDefender() => new(Unsupported);
    public LocalAdministratorsTelemetry ReadLocalAdministrators() => new(Unsupported);
    public WindowsUpdateTelemetry ReadWindowsUpdate(DateTimeOffset collectedUtc) => new(Unsupported, Unsupported);
    public PendingRebootTelemetry ReadPendingReboot() => new(Unsupported);
    public SecurityServicesTelemetry ReadServices() => new(Unsupported);
    public InstalledSoftwareTelemetry ReadSoftware() => new(Unsupported);
}

/// <summary>
/// Collects one report. Each section is read on its own dedicated thread, and the whole collection waits at most
/// <see cref="Deadline"/>. A section that does not finish in time is reported Unavailable; its thread is kept rather
/// than abandoned and replaced, so a hung platform source occupies at most one thread per section until it returns.
/// A section that throws, or returns values the contract rejects, is reported without values.
/// </summary>
public sealed class EndpointTelemetryCollector
{
    public static readonly TimeSpan DefaultDeadline = TimeSpan.FromSeconds(30);

    private readonly IEndpointTelemetrySource _source;
    private readonly TimeProvider _time;
    private readonly Task?[] _pending = new Task?[8];
    private readonly object _gate = new();

    public EndpointTelemetryCollector(IEndpointTelemetrySource source, TimeProvider time, TimeSpan? deadline = null)
    {
        _source = source ?? throw new ArgumentNullException(nameof(source));
        _time = time ?? throw new ArgumentNullException(nameof(time));
        Deadline = deadline ?? DefaultDeadline;
        if (Deadline <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(deadline));
    }

    public TimeSpan Deadline { get; }

    /// <summary>Sections still running after an earlier deadline; they are reported Unavailable until they return.</summary>
    public int LingeringSections
    {
        get
        {
            lock (_gate)
            {
                return _pending.Count(task => task is { IsCompleted: false });
            }
        }
    }

    public async Task<EndpointTelemetryReport> CollectAsync(Guid endpointId, CancellationToken cancellationToken)
    {
        if (endpointId == Guid.Empty) throw new ArgumentException("An endpoint ID is required.", nameof(endpointId));
        var collectedUtc = _time.GetUtcNow().ToUniversalTime();
        const string unavailable = TelemetryAvailability.Unavailable;
        var bitLocker = Start(0, _source.ReadBitLocker, a => new BitLockerTelemetry(a));
        var antivirus = Start(1, _source.ReadAntivirus, a => new AntivirusTelemetry(a));
        var defender = Start(2, _source.ReadDefender, a => new DefenderTelemetry(a));
        var administrators = Start(3, _source.ReadLocalAdministrators, a => new LocalAdministratorsTelemetry(a));
        var update = Start(4, () => _source.ReadWindowsUpdate(collectedUtc), a => new WindowsUpdateTelemetry(a, a));
        var reboot = Start(5, _source.ReadPendingReboot, a => new PendingRebootTelemetry(a));
        var services = Start(6, _source.ReadServices, a => new SecurityServicesTelemetry(a));
        var software = Start(7, _source.ReadSoftware, a => new InstalledSoftwareTelemetry(a));
        Task[] all = [bitLocker, antivirus, defender, administrators, update, reboot, services, software];

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var deadline = Task.Delay(Deadline, _time, timeout.Token);
        await Task.WhenAny(Task.WhenAll(all), deadline).ConfigureAwait(false);
        await timeout.CancelAsync().ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();

        return new EndpointTelemetryReport(EndpointTelemetryContract.CurrentSchemaVersion, endpointId, collectedUtc,
            Result(bitLocker, new BitLockerTelemetry(unavailable), EndpointTelemetryContract.IsValid),
            Result(antivirus, new AntivirusTelemetry(unavailable), EndpointTelemetryContract.IsValid),
            Result(defender, new DefenderTelemetry(unavailable), EndpointTelemetryContract.IsValid),
            Result(administrators, new LocalAdministratorsTelemetry(unavailable), EndpointTelemetryContract.IsValid),
            Result(update, new WindowsUpdateTelemetry(unavailable, unavailable),
                section => EndpointTelemetryContract.IsValid(section, collectedUtc)),
            Result(reboot, new PendingRebootTelemetry(unavailable), EndpointTelemetryContract.IsValid),
            Result(services, new SecurityServicesTelemetry(unavailable), EndpointTelemetryContract.IsValid),
            Result(software, new InstalledSoftwareTelemetry(unavailable), EndpointTelemetryContract.IsValid));
    }

    private Task<T?> Start<T>(int slot, Func<T> read, Func<string, T> failed) where T : class
    {
        lock (_gate)
        {
            if (_pending[slot] is { IsCompleted: false })
            {
                // The previous read of this section has not returned; never start a second one.
                return Task.FromResult<T?>(null);
            }

            var task = Task.Factory.StartNew<T?>(() =>
            {
                try
                {
                    return read();
                }
                catch (Exception exception)
                {
                    return failed(EndpointTelemetryNormalizer.Classify(exception));
                }
            }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
            _pending[slot] = task;
            return task;
        }
    }

    private static T Result<T>(Task<T?> task, T unavailable, Func<T, bool> isValid) where T : class =>
        task.IsCompletedSuccessfully && task.Result is { } section && isValid(section) ? section : unavailable;
}
