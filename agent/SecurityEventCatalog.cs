using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using SentinelAI.Contracts.SecurityEvents;

namespace SentinelAI.Agent;

/// <summary>One named event field. Only these selectors are ever rendered.</summary>
public sealed record EventField(string Name, string Path, int SinceVersion)
{
    public static EventField Data(string name, int sinceVersion = 0) =>
        new(name, $"Event/EventData/Data[@Name='{name}']", sinceVersion);
}

/// <summary>A fixed field list rendered together; its identity keys the native selector cache.</summary>
public sealed class EventFieldSet(IReadOnlyList<EventField> fields)
{
    public IReadOnlyList<EventField> Fields { get; } = fields;
}

/// <summary>
/// A collected selection. <paramref name="Level"/> is a server-side filter; <paramref name="Predicate"/>
/// fields are rendered first and evaluated only in managed code.
/// </summary>
public sealed record SecurityEventDefinition(string Channel, string Provider, int EventId, string Kind, byte? Level,
    EventFieldSet? Predicate, EventFieldSet Fields);

public sealed record SecurityEventChannelDefinition(string Channel, IReadOnlyList<SecurityEventDefinition> Definitions);

/// <summary>
/// The compiled allowlist. Configuration can never widen it: the production catalog is static and
/// the server query is generated only from its constants and invariant-formatted record numbers.
/// </summary>
public sealed class SecurityEventCatalog
{
    private static readonly Regex ProviderPattern = new("^[A-Za-z0-9 ._-]+$",
        RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));

    private readonly Dictionary<string, SecurityEventChannelDefinition> _channels;
    private readonly Dictionary<string, string> _groups;

    private SecurityEventCatalog(IReadOnlyList<SecurityEventChannelDefinition> channels)
    {
        Channels = channels;
        ChannelNames = channels.Select(channel => channel.Channel).ToArray();
        _channels = channels.ToDictionary(channel => channel.Channel, StringComparer.Ordinal);
        _groups = channels.ToDictionary(channel => channel.Channel, channel => BuildGroups(channel.Definitions),
            StringComparer.Ordinal);
    }

    public static SecurityEventCatalog Production { get; } = Create(
    [
        new(SecurityEventChannels.Security,
        [
            new(SecurityEventChannels.Security, SecurityEventProviders.SecurityAuditing, 4624,
                SecurityEventKinds.LogonSucceeded, null, Set(EventField.Data("LogonType")),
                Set(EventField.Data("TargetUserSid"), EventField.Data("IpAddress"), EventField.Data("ElevatedToken", 2))),
            new(SecurityEventChannels.Security, SecurityEventProviders.SecurityAuditing, 4625,
                SecurityEventKinds.LogonFailed, null, null,
                Set(EventField.Data("LogonType"), EventField.Data("TargetUserSid"), EventField.Data("IpAddress"),
                    EventField.Data("Status"), EventField.Data("SubStatus"))),
            new(SecurityEventChannels.Security, SecurityEventProviders.SecurityAuditing, 4698,
                SecurityEventKinds.ScheduledTaskCreated, null, null,
                Set(EventField.Data("TaskName"), EventField.Data("SubjectUserSid"))),
            new(SecurityEventChannels.Security, SecurityEventProviders.Eventlog, 1102,
                SecurityEventKinds.LogCleared, null, null, Set())
        ]),
        new(SecurityEventChannels.System,
        [
            new(SecurityEventChannels.System, SecurityEventProviders.ServiceControlManager, 7045,
                SecurityEventKinds.ServiceInstalled, null, null,
                Set(EventField.Data("ServiceName"), EventField.Data("ImagePath"), EventField.Data("ServiceType"),
                    EventField.Data("StartType"), EventField.Data("AccountName"))),
            new(SecurityEventChannels.System, SecurityEventProviders.ServiceControlManager, 7040,
                SecurityEventKinds.ProtectionServiceStartTypeChanged, null, Set(EventField.Data("param4")),
                Set(EventField.Data("param3"))),
            new(SecurityEventChannels.System, SecurityEventProviders.Eventlog, 104,
                SecurityEventKinds.LogCleared, null, null,
                Set(new EventField("Channel", "Event/UserData/LogFileCleared/Channel", 0)))
        ]),
        new(SecurityEventChannels.PowerShell,
        [
            new(SecurityEventChannels.PowerShell, SecurityEventProviders.PowerShell, 4104,
                SecurityEventKinds.ScriptBlockFlagged, 3, Set(EventField.Data("MessageNumber", 1)),
                Set(EventField.Data("ScriptBlockId", 1), EventField.Data("MessageTotal", 1)))
        ]),
        new(SecurityEventChannels.Defender,
        [
            Defender(1116, SecurityEventKinds.MalwareDetected, MalwareFields()),
            Defender(1117, SecurityEventKinds.MalwareActionTaken, MalwareFields("Action ID")),
            Defender(1118, SecurityEventKinds.MalwareActionFailed, MalwareFields("Action ID", "Error Code")),
            Defender(1119, SecurityEventKinds.MalwareActionFailed, MalwareFields("Action ID", "Error Code")),
            Defender(5001, SecurityEventKinds.ProtectionDisabled, Set()),
            Defender(5010, SecurityEventKinds.ProtectionDisabled, Set()),
            Defender(5012, SecurityEventKinds.ProtectionDisabled, Set()),
            Defender(5007, SecurityEventKinds.DefenderSettingChanged,
                Set(EventField.Data("Old Value"), EventField.Data("New Value")))
        ])
    ]);

    public IReadOnlyList<SecurityEventChannelDefinition> Channels { get; }
    public IReadOnlyList<string> ChannelNames { get; }

    /// <summary>Validates and compiles a catalog; test catalogs exercise adapter mechanics only.</summary>
    public static SecurityEventCatalog Create(IReadOnlyList<SecurityEventChannelDefinition> channels)
    {
        ArgumentNullException.ThrowIfNull(channels);
        if (channels.Count is 0 or > SecurityEventContract.MaxSourcesPerBatch)
            throw new ArgumentException("A catalog needs one to eight channels.", nameof(channels));
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var channel in channels)
        {
            // Channel names are embedded in synthesized bookmark XML and the checkpoint file.
            if (channel?.Channel is not { Length: > 0 and <= 255 } name || !names.Add(name) ||
                name.Any(character => character is '\'' or '"' or '&' or '<' or '>' || char.IsControl(character)) ||
                channel.Definitions is not { Count: > 0 })
                throw new ArgumentException("A catalog channel is invalid.", nameof(channels));
            var selections = new HashSet<(string, int)>();
            foreach (var definition in channel.Definitions)
            {
                if (definition is null || definition.Channel != name || !ProviderPattern.IsMatch(definition.Provider) ||
                    definition.EventId is < 0 or > 65535 || string.IsNullOrEmpty(definition.Kind) ||
                    definition.Fields is null ||
                    !selections.Add((definition.Provider.ToUpperInvariant(), definition.EventId)))
                    throw new ArgumentException("A catalog selection is invalid.", nameof(channels));
            }
        }

        return new SecurityEventCatalog(channels);
    }

    /// <summary>The selection for a record header; providers compare case-insensitively.</summary>
    public SecurityEventDefinition? Find(string channel, string? provider, int eventId, int? level)
    {
        if (provider is null || !_channels.TryGetValue(channel, out var definitions)) return null;
        foreach (var definition in definitions.Definitions)
        {
            if (definition.EventId == eventId &&
                string.Equals(definition.Provider, provider, StringComparison.OrdinalIgnoreCase) &&
                (definition.Level is null || definition.Level == level))
                return definition;
        }

        return null;
    }

    /// <summary>The managed equivalent of the generated server filter (without record-number terms).</summary>
    public bool MatchesHeader(string channel, string? provider, int eventId, int? level) =>
        Find(channel, provider, eventId, level) is not null;

    /// <summary>
    /// The server query: the channel's selections, plus <paramref name="anchor"/> and
    /// <paramref name="through"/> as explicit record-number members, so a seek target is always in the
    /// result set. <paramref name="minimum"/> adds a record-number floor for the no-seek fallback.
    /// </summary>
    public string BuildXPath(string channel, long? anchor, long through, long? minimum)
    {
        if (!_groups.TryGetValue(channel, out var groups))
            throw new ArgumentException("The channel is not in the catalog.", nameof(channel));
        if (anchor is < 0 || through < 0 || minimum is < 0)
            throw new ArgumentOutOfRangeException(nameof(through), "Record numbers cannot be negative.");

        var members = new StringBuilder();
        if (anchor is { } anchorId) members.Append(" or EventRecordID=").Append(anchorId.ToString(CultureInfo.InvariantCulture));
        members.Append(" or EventRecordID=").Append(through.ToString(CultureInfo.InvariantCulture));
        return minimum is { } floor
            ? $"*[System[(({groups}){members}) and EventRecordID>={floor.ToString(CultureInfo.InvariantCulture)}]]"
            : $"*[System[{groups}{members}]]";
    }

    private static string BuildGroups(IReadOnlyList<SecurityEventDefinition> definitions)
    {
        // One group per (provider, level) in catalog order, event IDs ascending.
        var groups = new List<(string Provider, byte? Level, SortedSet<int> Ids)>();
        foreach (var definition in definitions)
        {
            var index = groups.FindIndex(group => group.Level == definition.Level &&
                string.Equals(group.Provider, definition.Provider, StringComparison.OrdinalIgnoreCase));
            if (index < 0)
            {
                groups.Add((definition.Provider, definition.Level, []));
                index = groups.Count - 1;
            }

            groups[index].Ids.Add(definition.EventId);
        }

        return string.Join(" or ", groups.Select(group =>
        {
            var ids = string.Join(" or ", group.Ids.Select(id => "EventID=" + id.ToString(CultureInfo.InvariantCulture)));
            if (group.Ids.Count > 1) ids = "(" + ids + ")";
            var level = group.Level is { } value ? " and Level=" + value.ToString(CultureInfo.InvariantCulture) : string.Empty;
            return $"(Provider[@Name='{group.Provider}'] and {ids}{level})";
        }));
    }

    private static EventFieldSet Set(params EventField[] fields) => new(fields);

    private static EventFieldSet MalwareFields(params string[] extra) =>
        Set([.. new[] { "Detection ID", "Threat ID", "Threat Name", "Severity ID", "Category ID" }
            .Concat(extra).Select(name => EventField.Data(name))]);

    private static SecurityEventDefinition Defender(int eventId, string kind, EventFieldSet fields) =>
        new(SecurityEventChannels.Defender, SecurityEventProviders.Defender, eventId, kind, null, null, fields);
}
