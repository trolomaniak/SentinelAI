using System.Text;
using System.Text.Json;
using SentinelAI.Contracts.SecurityEvents;
using SentinelAI.Hosting;

namespace SentinelAI.Agent;

/// <summary>An acknowledged scanned-through record number and, when known, its creation time.</summary>
public readonly record struct EventCheckpoint(long RecordId, long? AnchorUtcTicks);

/// <summary>
/// Loaded checkpoints; channels without one start coverage at the tail for <paramref name="Cause"/>
/// (a coverage cause from <see cref="SecurityEventCoverageCauses"/>).
/// </summary>
public sealed record EventCheckpointLoad(IReadOnlyDictionary<string, EventCheckpoint> Checkpoints, string Cause);

/// <summary>
/// Per-channel event positions in one small private file. It holds only channel names, record
/// numbers, ticks and the endpoint ID: no event data, no bookmark XML and no secrets.
/// </summary>
public sealed class EventCheckpointStore(AgentOptions options)
{
    public const string Format = "sentinelai-event-checkpoints-v1";
    public const int MaxBytes = 4096;
    private const int MaxSweep = 16;
    private const UnixFileMode DirectoryMode =
        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private const UnixFileMode StateFileMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
    private long _writes;

    public string StatePath => Path.Combine(options.DataDirectory, "event-checkpoints");

    /// <summary>Completed checkpoint writes, exposed for bounded-work checks.</summary>
    public long Writes => Interlocked.Read(ref _writes);

    /// <summary>Never throws for content problems: anything invalid restarts coverage on every channel.</summary>
    public async Task<EventCheckpointLoad> LoadAsync(Guid endpointId, CancellationToken cancellationToken = default)
    {
        try
        {
            PilotHostConfiguration.RejectLinks(StatePath);
            SweepTemporaryFiles();
            if (!File.Exists(StatePath)) return Empty(SecurityEventCoverageCauses.NoCheckpoint);

            byte[] bytes;
            await using (var stream = new FileStream(StatePath, FileMode.Open, FileAccess.Read, FileShare.None))
            {
                if (stream.Length is < 1 or > MaxBytes) return Empty(SecurityEventCoverageCauses.CheckpointInvalid);
                bytes = new byte[stream.Length];
                await stream.ReadExactlyAsync(bytes, cancellationToken);
                if (stream.ReadByte() != -1) return Empty(SecurityEventCoverageCauses.CheckpointInvalid);
            }

            _ = StrictUtf8.GetString(bytes);
            using var document = JsonDocument.Parse(bytes,
                new JsonDocumentOptions { MaxDepth = 4, AllowDuplicateProperties = false });
            return Parse(document.RootElement, endpointId) ?? Empty(SecurityEventCoverageCauses.CheckpointInvalid);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            // A link, an IO error or malformed content: coverage restarts and the change is reported.
            return Empty(SecurityEventCoverageCauses.CheckpointInvalid);
        }
    }

    public async Task SaveAsync(Guid endpointId, IReadOnlyList<(string Channel, EventCheckpoint Checkpoint)> channels,
        CancellationToken cancellationToken = default)
    {
        EnsurePrivateDirectory();
        PilotHostConfiguration.RejectLinks(StatePath);
        var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("format", Format);
            writer.WriteString("endpointId", endpointId.ToString("D"));
            writer.WriteStartArray("channels");
            foreach (var channel in SecurityEventChannels.All)
            {
                foreach (var (name, checkpoint) in channels)
                {
                    if (name != channel) continue;
                    writer.WriteStartObject();
                    writer.WriteString("channel", name);
                    writer.WriteNumber("recordId", checkpoint.RecordId);
                    if (checkpoint.AnchorUtcTicks is { } ticks) writer.WriteNumber("anchorUtcTicks", ticks);
                    else writer.WriteNull("anchorUtcTicks");
                    writer.WriteEndObject();
                }
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
        }

        if (buffer.Length > MaxBytes) throw new InvalidDataException("The event checkpoint exceeds its size bound.");
        var temporaryPath = Path.Combine(options.DataDirectory, $".event-checkpoints.{Guid.NewGuid():N}.tmp");
        try
        {
            var streamOptions = new FileStreamOptions
            {
                Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None,
                Options = FileOptions.Asynchronous
            };
            if (!OperatingSystem.IsWindows()) streamOptions.UnixCreateMode = StateFileMode;
            await using (var stream = new FileStream(temporaryPath, streamOptions))
            {
                await stream.WriteAsync(buffer.GetBuffer().AsMemory(0, (int)buffer.Length), cancellationToken);
                await stream.FlushAsync(cancellationToken);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporaryPath, StatePath, overwrite: true);
            Interlocked.Increment(ref _writes);
        }
        finally
        {
            if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
        }
    }

    private static EventCheckpointLoad? Parse(JsonElement root, Guid endpointId)
    {
        if (root.ValueKind != JsonValueKind.Object || !HasExactly(root, "format", "endpointId", "channels") ||
            root.GetProperty("format").ValueKind != JsonValueKind.String ||
            root.GetProperty("format").GetString() != Format ||
            root.GetProperty("endpointId").ValueKind != JsonValueKind.String ||
            !Guid.TryParseExact(root.GetProperty("endpointId").GetString(), "D", out var storedEndpoint) ||
            root.GetProperty("channels") is not { ValueKind: JsonValueKind.Array } entries ||
            entries.GetArrayLength() > SecurityEventContract.MaxSourcesPerBatch)
            return null;

        var checkpoints = new Dictionary<string, EventCheckpoint>(StringComparer.Ordinal);
        foreach (var entry in entries.EnumerateArray())
        {
            if (entry.ValueKind != JsonValueKind.Object || !HasExactly(entry, "channel", "recordId", "anchorUtcTicks") ||
                entry.GetProperty("channel") is not { ValueKind: JsonValueKind.String } channelElement ||
                channelElement.GetString() is not { } channel ||
                !SecurityEventChannels.All.Contains(channel, StringComparer.Ordinal) || checkpoints.ContainsKey(channel) ||
                entry.GetProperty("recordId") is not { ValueKind: JsonValueKind.Number } recordElement ||
                !recordElement.TryGetInt64(out var recordId) || recordId < 0)
                return null;

            long? anchor = null;
            var anchorElement = entry.GetProperty("anchorUtcTicks");
            if (anchorElement.ValueKind != JsonValueKind.Null)
            {
                if (anchorElement.ValueKind != JsonValueKind.Number || !anchorElement.TryGetInt64(out var ticks) ||
                    ticks < DateTime.UnixEpoch.Ticks || ticks > DateTime.MaxValue.Ticks || recordId == 0)
                    return null;
                anchor = ticks;
            }

            checkpoints.Add(channel, new EventCheckpoint(recordId, anchor));
        }

        // Another endpoint's positions must not replay its history into this enrollment.
        return storedEndpoint != endpointId
            ? Empty(SecurityEventCoverageCauses.EndpointChanged)
            : new EventCheckpointLoad(checkpoints, SecurityEventCoverageCauses.NoCheckpoint);
    }

    private static bool HasExactly(JsonElement element, params string[] names)
    {
        var count = 0;
        foreach (var property in element.EnumerateObject())
        {
            if (!names.Contains(property.Name, StringComparer.Ordinal)) return false;
            count++;
        }

        return count == names.Length;
    }

    private static EventCheckpointLoad Empty(string cause) =>
        new(new Dictionary<string, EventCheckpoint>(StringComparer.Ordinal), cause);

    private void SweepTemporaryFiles()
    {
        // Temporary files orphaned by a crash between create and rename; bounded per load.
        if (!Directory.Exists(options.DataDirectory)) return;
        foreach (var path in Directory.EnumerateFiles(options.DataDirectory, ".event-checkpoints.*.tmp").Take(MaxSweep))
        {
            try
            {
                var file = new FileInfo(path);
                if (file.Name.StartsWith(".event-checkpoints.", StringComparison.Ordinal) &&
                    file.Name.EndsWith(".tmp", StringComparison.Ordinal) && file.LinkTarget is null &&
                    (file.Attributes & FileAttributes.ReparsePoint) == 0)
                    file.Delete();
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
            }
        }
    }

    private void EnsurePrivateDirectory()
    {
        if (OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(options.DataDirectory);
            return;
        }

        Directory.CreateDirectory(options.DataDirectory, DirectoryMode);
        if (new DirectoryInfo(options.DataDirectory).LinkTarget is not null)
        {
            throw new InvalidDataException("The Agent data directory cannot be a symbolic link.");
        }

        File.SetUnixFileMode(options.DataDirectory, DirectoryMode);
    }
}
