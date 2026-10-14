using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Runtime.Versioning;
using System.Security.Principal;
using SentinelAI.Contracts.SecurityEvents;

namespace SentinelAI.Agent;

/// <summary>
/// Reads catalog channels with filtered, polled <see cref="EventLogReader"/> queries. Construction makes
/// no native calls; every call runs synchronously on the pipeline's loop thread and reads only named
/// allowlist fields through property selectors. Channels outside the catalog are refused.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsEventLogAccess(SecurityEventCatalog catalog, TimeSpan? configurationRefresh = null)
    : IEventLogAccess
{
    public static readonly TimeSpan ReadTimeout = TimeSpan.FromSeconds(10);
    private const int BatchSize = 64;

    private readonly TimeSpan _configurationRefresh = configurationRefresh ?? TimeSpan.FromMinutes(5);
    private readonly object _gate = new();
    private readonly Dictionary<EventFieldSet, EventLogPropertySelector> _selectors = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<string, (long ReadAt, long? MaximumBytes, bool? Enabled)> _configuration =
        new(StringComparer.Ordinal);
    private EventLogReader? _pending;
    private bool _disposed;

    public bool IsSupported => true;
    public IReadOnlyList<string> Channels => catalog.ChannelNames;

    public ChannelExtent Describe(string channel)
    {
        EnsureChannel(channel);
        return Mapped(() =>
        {
            var information = EventLogSession.GlobalSession.GetLogInformation(channel, PathType.LogName);
            var oldest = information.OldestRecordNumber;
            var newest = information.RecordCount is > 0 && oldest is { } first ? first + information.RecordCount - 1 : null;
            var (maximumBytes, enabled) = Configuration(channel);
            return new ChannelExtent(oldest, newest, maximumBytes, enabled);
        });
    }

    public EventRecordHeader? ReadNewest(string channel)
    {
        EnsureChannel(channel);
        return Mapped(() =>
        {
            var reader = Track(new EventLogReader(new EventLogQuery(channel, PathType.LogName) { ReverseDirection = true }));
            try
            {
                using var record = reader.ReadEvent(ReadTimeout);
                return record is null ? (EventRecordHeader?)null : Header(record);
            }
            finally
            {
                Release(reader);
            }
        });
    }

    public IEventRecordCursor Open(string channel, long? after, long through, bool forceFallback = false)
    {
        EnsureChannel(channel);
        return Mapped<IEventRecordCursor>(() =>
        {
            if (after is { } anchor && !forceFallback)
            {
                var reader = CreateReader(channel, catalog.BuildXPath(channel, after, through, minimum: null));
                try
                {
                    // Offset 0 from a bookmark on a record that the query selects by construction.
                    reader.Seek(new EventBookmark(Bookmark(channel, anchor)), 0);
                    return new Cursor(this, reader, usedFallback: false);
                }
                catch (EventLogException exception) when (exception is not EventLogNotFoundException)
                {
                    Release(reader);
                }
                catch
                {
                    Release(reader);
                    throw;
                }
            }

            var fallback = CreateReader(channel, catalog.BuildXPath(channel, after, through, minimum: after));
            return new Cursor(this, fallback, usedFallback: after is not null);
        });
    }

    public void CancelPending()
    {
        lock (_gate)
        {
            try
            {
                _pending?.CancelReading();
            }
            catch (Exception)
            {
                // Best effort: a reader that already finished cannot be cancelled.
            }
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            foreach (var selector in _selectors.Values) selector.Dispose();
            _selectors.Clear();
        }
    }

    /// <summary>
    /// Converts a rendered native value to a portable one: SIDs to their string form, integral values to
    /// long, strings up to the bound (longer ones become Oversize) and GUIDs; anything else is null.
    /// </summary>
    public static object? ToPortable(object? value) => value switch
    {
        null => null,
        SecurityIdentifier sid => sid.Value,
        string text => text.Length > SecurityEventNormalizer.MaxFieldChars ? EventFieldValue.Oversize : text,
        sbyte number => (long)number,
        byte number => (long)number,
        short number => (long)number,
        ushort number => (long)number,
        int number => (long)number,
        uint number => (long)number,
        long number => number,
        ulong number => number > long.MaxValue ? null : (long)number,
        Guid guid => guid,
        _ => null
    };

    private static EventRecordHeader Header(EventRecord record) => new(
        record.RecordId,
        record.ProviderName,
        record.Id,
        record.Version ?? 0,
        record.Level,
        record.TimeCreated is { } created ? new DateTimeOffset(created.ToUniversalTime(), TimeSpan.Zero) : null);

    private static string Bookmark(string channel, long recordId) =>
        $"<BookmarkList><Bookmark Channel='{channel}' RecordId='{recordId.ToString(CultureInfo.InvariantCulture)}' IsCurrent='true'/></BookmarkList>";

    private static T Mapped<T>(Func<T> action)
    {
        try
        {
            return action();
        }
        catch (UnauthorizedAccessException exception)
        {
            throw new EventChannelUnavailableException(SecurityEventSourceStates.AccessDenied, exception.HResult);
        }
        catch (EventLogNotFoundException exception)
        {
            throw new EventChannelUnavailableException(SecurityEventSourceStates.NotFound, exception.HResult);
        }
    }

    private void EnsureChannel(string channel)
    {
        // Defence in depth: only compiled catalog channels are ever queried.
        if (!catalog.ChannelNames.Contains(channel, StringComparer.Ordinal))
            throw new ArgumentException("The channel is not in the security event catalog.", nameof(channel));
    }

    private (long? MaximumBytes, bool? Enabled) Configuration(string channel)
    {
        lock (_gate)
        {
            if (_configuration.TryGetValue(channel, out var cached) &&
                Environment.TickCount64 - cached.ReadAt < (long)_configurationRefresh.TotalMilliseconds)
                return (cached.MaximumBytes, cached.Enabled);
        }

        (long? MaximumBytes, bool? Enabled) values;
        try
        {
            using var configuration = new EventLogConfiguration(channel);
            values = (configuration.MaximumSizeInBytes, configuration.IsEnabled);
        }
        catch (Exception)
        {
            // Size and enablement are informational; collection does not depend on them.
            values = (null, null);
        }

        lock (_gate)
        {
            _configuration[channel] = (Environment.TickCount64, values.MaximumBytes, values.Enabled);
        }

        return values;
    }

    private EventLogReader CreateReader(string channel, string xpath) =>
        Track(new EventLogReader(new EventLogQuery(channel, PathType.LogName, xpath)) { BatchSize = BatchSize });

    private EventLogReader Track(EventLogReader reader)
    {
        lock (_gate)
        {
            _pending = reader;
        }

        return reader;
    }

    private void Release(EventLogReader reader)
    {
        // Disposing under the lock keeps CancelPending from reaching a disposed handle.
        lock (_gate)
        {
            if (ReferenceEquals(_pending, reader)) _pending = null;
            reader.Dispose();
        }
    }

    private EventLogPropertySelector Selector(EventFieldSet fields)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (!_selectors.TryGetValue(fields, out var selector))
            {
                selector = new EventLogPropertySelector(fields.Fields.Select(field => field.Path));
                _selectors.Add(fields, selector);
            }

            return selector;
        }
    }

    private sealed class Cursor(WindowsEventLogAccess owner, EventLogReader reader, bool usedFallback) : IEventRecordCursor
    {
        private EventRecord? _current;
        private bool _endOfResults;

        public bool UsedFallback => usedFallback;

        public bool TryNext(out EventRecordHeader header)
        {
            _current?.Dispose();
            _current = null;
            header = default;
            if (_endOfResults) return false;
            var record = Mapped(() => reader.ReadEvent(ReadTimeout));
            if (record is null)
            {
                // The reader throws if asked again after the end of its results.
                _endOfResults = true;
                return false;
            }

            _current = record;
            header = Header(record);
            return true;
        }

        public IReadOnlyList<object?> ReadFields(EventFieldSet fields)
        {
            if (_current is not EventLogRecord record) throw new InvalidOperationException("No current event record.");
            if (fields.Fields.Count == 0) return [];
            return record.GetPropertyValues(owner.Selector(fields)).Select(ToPortable).ToArray();
        }

        public void Dispose()
        {
            _current?.Dispose();
            _current = null;
            owner.Release(reader);
        }
    }
}
