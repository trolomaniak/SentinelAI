namespace SentinelAI.Agent;

// Portable seam between the security event pipeline and the Windows event log. Values that
// cross it are only string, long, Guid, null or EventFieldValue.Oversize.

/// <summary>Channel metadata from one Describe call; no event content.</summary>
public sealed record ChannelExtent(long? OldestRecordId, long? NewestRecordId, long? MaximumSizeBytes, bool? Enabled);

public readonly record struct EventRecordHeader(long? RecordId, string? Provider, int EventId, int Version,
    int? Level, DateTimeOffset? TimeCreatedUtc);

/// <summary>Marks a field value that exceeded the portable string bound; its text never crosses the seam.</summary>
public sealed class EventFieldValue
{
    public static readonly EventFieldValue Oversize = new();

    private EventFieldValue()
    {
    }

    public override string ToString() => nameof(Oversize);
}

/// <summary>The channel cannot be read: <c>accessDenied</c> or <c>notFound</c>, with the HResult only.</summary>
public sealed class EventChannelUnavailableException(string state, int errorCode)
    : Exception("The event channel is unavailable.")
{
    public string State { get; } = state;
    public int ErrorCode { get; } = errorCode;
}

public interface IEventLogAccess : IDisposable
{
    /// <summary>False means the pipeline stays idle: no reads, no checkpoint file and no traffic.</summary>
    bool IsSupported { get; }

    /// <summary>Catalog channels in catalog order.</summary>
    IReadOnlyList<string> Channels { get; }

    /// <summary>Channel metadata only.</summary>
    ChannelExtent Describe(string channel);

    /// <summary>The newest record of the channel (unfiltered reverse read of one record), or null when empty.</summary>
    EventRecordHeader? ReadNewest(string channel);

    /// <summary>
    /// Ascending catalog query that also selects <paramref name="after"/> (when given) and
    /// <paramref name="through"/>. When <paramref name="after"/> is given the cursor is positioned
    /// on that record. Precondition: oldest &lt;= after &lt;= newest of the last Describe.
    /// </summary>
    IEventRecordCursor Open(string channel, long? after, long through, bool forceFallback = false);

    /// <summary>Cancels a read in progress, if any; never throws.</summary>
    void CancelPending();
}

public interface IEventRecordCursor : IDisposable
{
    /// <summary>The bookmark seek was not used; the query filters by record number instead.</summary>
    bool UsedFallback { get; }

    /// <summary>False at the end of the result set; never reads past it.</summary>
    bool TryNext(out EventRecordHeader header);

    /// <summary>Renders the named fields of the current record, in field order.</summary>
    IReadOnlyList<object?> ReadFields(EventFieldSet fields);
}

/// <summary>Used where the Windows event log does not exist; the pipeline stays idle.</summary>
public sealed class NoEventLogAccess : IEventLogAccess
{
    public bool IsSupported => false;
    public IReadOnlyList<string> Channels => [];
    public ChannelExtent Describe(string channel) => throw Unsupported();
    public EventRecordHeader? ReadNewest(string channel) => throw Unsupported();
    public IEventRecordCursor Open(string channel, long? after, long through, bool forceFallback = false) =>
        throw Unsupported();
    public void CancelPending()
    {
    }

    public void Dispose()
    {
    }

    private static InvalidOperationException Unsupported() =>
        new("Security event collection is unavailable on this platform.");
}
