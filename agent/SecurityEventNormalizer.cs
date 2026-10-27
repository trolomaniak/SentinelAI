using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using SentinelAI.Contracts.SecurityEvents;

namespace SentinelAI.Agent;

public enum NormalizationOutcome { Selected, NotSelected, Unparsed, Oversize }

public readonly record struct NormalizationResult(NormalizationOutcome Outcome, SecurityEventObservation? Observation,
    int Size, int FieldsDiscarded);

/// <summary>
/// Converts rendered allowlist fields into typed observations. Pure and portable; it never throws on
/// data. An absent value (null, empty or "-") becomes null; a present value that fails conversion or
/// validation becomes null and is counted, and the observation is still emitted, so an odd or oversized
/// value can never suppress an event. Free-text inputs are derived, never copied.
/// </summary>
public static class SecurityEventNormalizer
{
    /// <summary>Longest string the adapter passes through; longer values arrive as Oversize.</summary>
    public const int MaxFieldChars = 1024;
    private const long MaxUInt32 = 0xFFFFFFFF;
    private const string AnonymousSid = "S-1-0-0";

    /// <summary>Evaluates the managed predicate of a selection; false means the record is not collected.</summary>
    public static bool PassesPredicate(SecurityEventDefinition definition, IReadOnlyList<object?>? values,
        out int fieldsDiscarded)
    {
        var predicate = new FieldValues(definition.Predicate, values);
        var passes = Predicate(definition, predicate, out _);
        fieldsDiscarded = predicate.Discarded;
        return passes;
    }

    /// <param name="serviceText">The SCM texts to recognize; English when null.</param>
    public static NormalizationResult Normalize(SecurityEventDefinition definition, EventRecordHeader header,
        IReadOnlyList<object?>? predicateValues, IReadOnlyList<object?>? fieldValues,
        ServiceControlManagerText? serviceText = null)
    {
        serviceText ??= ServiceControlManagerText.English;
        var predicate = new FieldValues(definition.Predicate, predicateValues);
        if (!Predicate(definition, predicate, out var carried))
            return new(NormalizationOutcome.NotSelected, null, 0, predicate.Discarded);
        if (header.RecordId is not { } recordId || header.TimeCreatedUtc is not { } timeCreated)
            return new(NormalizationOutcome.Unparsed, null, 0, predicate.Discarded);

        var fields = new FieldValues(definition.Fields, fieldValues);
        var observation = new SecurityEventObservation(definition.Channel, definition.Provider, definition.EventId,
            header.Version, header.Level, recordId, timeCreated.ToUniversalTime(), definition.Kind);
        switch (definition.Kind)
        {
            case SecurityEventKinds.LogonSucceeded:
                observation = observation with
                {
                    Logon = new LogonEvent((int?)(long?)carried, Sid(fields["TargetUserSid"], ref fields.Discarded),
                        Ip(fields["IpAddress"], ref fields.Discarded), null, null,
                        ElevatedToken(fields["ElevatedToken"], ref fields.Discarded))
                };
                break;
            case SecurityEventKinds.LogonFailed:
                observation = observation with
                {
                    Logon = new LogonEvent((int?)Int(fields["LogonType"], 0, 15, ref fields.Discarded),
                        Sid(fields["TargetUserSid"], ref fields.Discarded), Ip(fields["IpAddress"], ref fields.Discarded),
                        NtStatus(fields["Status"], ref fields.Discarded), NtStatus(fields["SubStatus"], ref fields.Discarded),
                        null)
                };
                break;
            case SecurityEventKinds.ScheduledTaskCreated:
                observation = observation with
                {
                    ScheduledTask = new ScheduledTaskEvent(Text(fields["TaskName"], 256, ref fields.Discarded),
                        Sid(fields["SubjectUserSid"], ref fields.Discarded))
                };
                break;
            case SecurityEventKinds.LogCleared:
                // A clear recorded in the cleared channel itself (Security 1102) names no channel field.
                observation = observation with
                {
                    LogCleared = new LogClearedEvent(fields.Has("Channel")
                        ? Text(fields["Channel"], 256, ref fields.Discarded)
                        : definition.Channel)
                };
                break;
            case SecurityEventKinds.ServiceInstalled:
                var image = ServiceImagePath.Derive(fields["ImagePath"]);
                if (image.Discarded) fields.Discarded++;
                observation = observation with
                {
                    ServiceInstall = new ServiceInstallEvent(Text(fields["ServiceName"], 256, ref fields.Discarded),
                        image.FileName, image.Location, ServiceType(fields["ServiceType"], serviceText, ref fields.Discarded),
                        StartType(fields["StartType"], serviceText, ref fields.Discarded),
                        AccountKind(fields["AccountName"], ref fields.Discarded))
                };
                break;
            case SecurityEventKinds.ProtectionServiceStartTypeChanged:
                observation = observation with
                {
                    ServiceStartType = new ServiceStartTypeEvent((string?)carried,
                        StartType(fields["param3"], serviceText, ref fields.Discarded))
                };
                break;
            case SecurityEventKinds.ScriptBlockFlagged:
                observation = observation with
                {
                    ScriptBlock = new ScriptBlockEvent(Guid(fields["ScriptBlockId"], ref fields.Discarded),
                        (int?)Int(fields["MessageTotal"], 1, 10000, ref fields.Discarded))
                };
                break;
            case SecurityEventKinds.MalwareDetected:
            case SecurityEventKinds.MalwareActionTaken:
            case SecurityEventKinds.MalwareActionFailed:
                var acted = definition.Kind != SecurityEventKinds.MalwareDetected;
                observation = observation with
                {
                    Malware = new MalwareEvent(Guid(fields["Detection ID"], ref fields.Discarded),
                        Int(fields["Threat ID"], 0, long.MaxValue, ref fields.Discarded),
                        Text(fields["Threat Name"], 256, ref fields.Discarded),
                        (int?)Int(fields["Severity ID"], 0, 255, ref fields.Discarded),
                        (int?)Int(fields["Category ID"], 0, 255, ref fields.Discarded),
                        acted ? (int?)Int(fields["Action ID"], 0, 255, ref fields.Discarded) : null,
                        definition.Kind == SecurityEventKinds.MalwareActionFailed
                            ? NtStatus(fields["Error Code"], ref fields.Discarded)
                            : null)
                };
                break;
            case SecurityEventKinds.DefenderSettingChanged:
                var setting = DefenderSettingClassifier.Classify(fields["Old Value"], fields["New Value"]);
                fields.Discarded += setting.Discarded;
                observation = observation with { DefenderSetting = new DefenderSettingEvent(setting.Area, setting.Change) };
                break;
            case SecurityEventKinds.ProtectionDisabled:
                break;
            default:
                return new(NormalizationOutcome.Unparsed, null, 0, predicate.Discarded + fields.Discarded);
        }

        var discarded = predicate.Discarded + fields.Discarded;
        // Final check with the same validator Core applies; anything else is a normalizer bug path.
        if (SecurityEventContract.Classify(observation) != SecurityEventItemValidity.Valid)
        {
            return new(SecurityEventContract.MeasureBytes(observation) > SecurityEventContract.MaxObservationBytes
                ? NormalizationOutcome.Oversize
                : NormalizationOutcome.Unparsed, null, 0, discarded);
        }

        return new(NormalizationOutcome.Selected, observation, SecurityEventContract.MeasureBytes(observation), discarded);
    }

    /// <summary>Accepts a long or an invariant decimal or 0x hexadecimal string within the range.</summary>
    public static long? Int(object? value, long minimum, long maximum, ref int discarded)
    {
        if (IsAbsent(value)) return null;
        if (Integer(value) is { } parsed && parsed >= minimum && parsed <= maximum) return parsed;
        discarded++;
        return null;
    }

    /// <summary>An NTSTATUS-style code as an unsigned 32-bit value; signed renderings are masked.</summary>
    public static long? NtStatus(object? value, ref int discarded)
    {
        if (IsAbsent(value)) return null;
        switch (Integer(value))
        {
            case >= int.MinValue and <= -1 and var negative:
                return negative & MaxUInt32;
            case >= 0 and <= MaxUInt32 and var code:
                return code;
            default:
                discarded++;
                return null;
        }
    }

    public static Guid? Guid(object? value, ref int discarded)
    {
        if (IsAbsent(value)) return null;
        switch (value)
        {
            case System.Guid guid when guid == System.Guid.Empty:
                return null;
            case System.Guid guid:
                return guid;
            case string text when System.Guid.TryParseExact(text.Trim(), "D", out var parsed) ||
                                  System.Guid.TryParseExact(text.Trim(), "B", out parsed):
                return parsed;
            default:
                discarded++;
                return null;
        }
    }

    /// <summary>A SID string; the anonymous/null SID is treated as absent.</summary>
    public static string? Sid(object? value, ref int discarded)
    {
        if (IsAbsent(value)) return null;
        if (value is string text)
        {
            text = text.Trim();
            if (text == AnonymousSid) return null;
            if (SecurityEventContract.IsValidSid(text)) return text;
        }

        discarded++;
        return null;
    }

    /// <summary>A canonical IP address: IPv4-mapped addresses become IPv4 and scope IDs are cleared.</summary>
    public static string? Ip(object? value, ref int discarded)
    {
        if (IsAbsent(value)) return null;
        if (value is string text && text.Length <= MaxFieldChars && IPAddress.TryParse(text.Trim(), out var address))
        {
            if (address.AddressFamily == AddressFamily.InterNetworkV6)
            {
                address.ScopeId = 0;
                if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
            }

            var canonical = address.ToString();
            if (SecurityEventContract.IsCanonicalIp(canonical)) return canonical;
        }

        discarded++;
        return null;
    }

    public static string? Text(object? value, int maximum, ref int discarded)
    {
        if (IsAbsent(value)) return null;
        if (value is string text && SecurityEventContract.IsBoundedText(text.Trim(), maximum)) return text.Trim();
        discarded++;
        return null;
    }

    public static string? AccountKind(object? value, ref int discarded)
    {
        if (IsAbsent(value)) return null;
        if (value is not string text)
        {
            discarded++;
            return null;
        }

        return text.Trim().ToUpperInvariant() switch
        {
            "LOCALSYSTEM" or @".\LOCALSYSTEM" or @"NT AUTHORITY\SYSTEM" => ServiceAccountKinds.LocalSystem,
            @"NT AUTHORITY\LOCALSERVICE" or @"NT AUTHORITY\LOCAL SERVICE" => ServiceAccountKinds.LocalService,
            @"NT AUTHORITY\NETWORKSERVICE" or @"NT AUTHORITY\NETWORK SERVICE" => ServiceAccountKinds.NetworkService,
            var account when account.StartsWith(@"NT SERVICE\", StringComparison.Ordinal) => ServiceAccountKinds.VirtualAccount,
            _ => ServiceAccountKinds.OtherAccount
        };
    }

    /// <summary>SCM service-type text in any loaded display language.</summary>
    public static string? ServiceType(object? value, ServiceControlManagerText text, ref int discarded)
    {
        if (IsAbsent(value)) return null;
        var type = value is string name ? text.ServiceType(name) : null;
        if (type is null) discarded++;
        return type;
    }

    /// <summary>SCM start-type text in any loaded display language, or its numeric value.</summary>
    public static string? StartType(object? value, ServiceControlManagerText text, ref int discarded)
    {
        if (IsAbsent(value)) return null;
        var type = (value is string name ? text.StartType(name) : null) ??
                   (Integer(value) is long number and >= 0 and <= 4 ? ServiceStartTypes.All[(int)number] : null);
        if (type is null) discarded++;
        return type;
    }

    public static bool? ElevatedToken(object? value, ref int discarded)
    {
        if (IsAbsent(value)) return null;
        switch ((value as string)?.Trim())
        {
            case "%%1842":
                return true;
            case "%%1843":
                return false;
            default:
                discarded++;
                return null;
        }
    }

    internal static bool IsAbsent(object? value) =>
        value is null || value is string text && text.AsSpan().Trim() is "" or "-";

    private static long? Integer(object? value)
    {
        switch (value)
        {
            case long number:
                return number;
            case string text:
                var trimmed = text.Trim();
                if (trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                {
                    return trimmed.Length is > 2 and <= 18 &&
                           ulong.TryParse(trimmed.AsSpan(2), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture,
                               out var hex) && hex <= long.MaxValue
                        ? (long)hex
                        : null;
                }

                return long.TryParse(trimmed, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var decimalValue)
                    ? decimalValue
                    : null;
            default:
                return null;
        }
    }

    private static bool Predicate(SecurityEventDefinition definition, FieldValues predicate, out object? carried)
    {
        carried = null;
        switch (definition.Kind)
        {
            case SecurityEventKinds.LogonSucceeded:
                // Interactive (2), remote interactive/RDP (10) and cached interactive (11) logons only.
                carried = Int(predicate["LogonType"], 0, 15, ref predicate.Discarded);
                return carried is 2L or 10L or 11L;
            case SecurityEventKinds.ScriptBlockFlagged:
                // Only the first part of a multi-part script block is reported.
                return Int(predicate["MessageNumber"], 1, 10000, ref predicate.Discarded) == 1;
            case SecurityEventKinds.ProtectionServiceStartTypeChanged:
                var service = Text(predicate["param4"], 256, ref predicate.Discarded);
                carried = ProtectedServices.All.FirstOrDefault(name =>
                    string.Equals(name, service, StringComparison.OrdinalIgnoreCase));
                return carried is not null;
            default:
                return definition.Predicate is null;
        }
    }

    /// <summary>Values rendered for a field set, by name. A failed render counts every field once.</summary>
    private sealed class FieldValues
    {
        private readonly EventFieldSet? _set;
        private readonly IReadOnlyList<object?>? _values;
        public int Discarded;

        public FieldValues(EventFieldSet? set, IReadOnlyList<object?>? values)
        {
            _set = set;
            _values = values;
            if (set is { Fields.Count: > 0 } && (values is null || values.Count != set.Fields.Count))
            {
                _values = null;
                Discarded = set.Fields.Count;
            }
        }

        public bool Has(string name) => _set?.Fields.Any(field => field.Name == name) == true;

        public object? this[string name]
        {
            get
            {
                if (_set is null || _values is null) return null;
                for (var index = 0; index < _set.Fields.Count; index++)
                {
                    if (_set.Fields[index].Name == name) return _values[index];
                }

                return null;
            }
        }
    }
}

public readonly record struct ServiceImage(string? FileName, string? Location, bool Discarded);

/// <summary>
/// Reduces a 7045 ImagePath to its leaf file name and a location class. Arguments and directories
/// are never kept; the raw value is held only transiently in memory.
/// </summary>
public static class ServiceImagePath
{
    private static readonly Regex BareName = new("^[A-Za-z0-9._-]{1,64}$",
        RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));

    public static ServiceImage Derive(object? imagePath)
    {
        if (SecurityEventNormalizer.IsAbsent(imagePath)) return new(null, null, false);
        if (imagePath is not string raw) return new(null, null, true);

        var text = raw.Trim();
        string path;
        if (text[0] == '"')
        {
            var end = text.IndexOf('"', 1);
            if (end < 0) return new(null, null, true);
            path = text[1..end];
        }
        else if (ExecutablePrefix(text) is { } prefix)
        {
            path = prefix;
        }
        else
        {
            var token = text.Split((char[]?)null, 2, StringSplitOptions.RemoveEmptyEntries)[0];
            return IsMatch(BareName, token) ? new(token, null, false) : new(null, null, true);
        }

        var normalized = Normalize(path);
        var fileName = normalized[(normalized.LastIndexOf('\\') + 1)..];
        var validName = SecurityEventContract.IsBoundedText(fileName, 128) &&
                        fileName.IndexOfAny(['\\', '/', ':', '*', '?', '"', '<', '>', '|']) < 0;
        return new(validName ? fileName : null, Location(normalized), !validName);
    }

    private static string? ExecutablePrefix(string text)
    {
        // The shortest prefix ending in .exe or .sys that is followed by the end, whitespace or a quote.
        for (var index = 0; index + 4 <= text.Length; index++)
        {
            if (string.Compare(text, index, ".exe", 0, 4, StringComparison.OrdinalIgnoreCase) != 0 &&
                string.Compare(text, index, ".sys", 0, 4, StringComparison.OrdinalIgnoreCase) != 0)
                continue;
            var end = index + 4;
            if (end == text.Length || char.IsWhiteSpace(text[end]) || text[end] == '"') return text[..end];
        }

        return null;
    }

    private static string Normalize(string path)
    {
        var normalized = path.Replace('/', '\\');
        if (normalized.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) normalized = @"\\" + normalized[8..];
        else if (normalized.StartsWith(@"\??\", StringComparison.Ordinal) ||
                 normalized.StartsWith(@"\\?\", StringComparison.Ordinal)) normalized = normalized[4..];
        if (normalized.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            normalized = @"%SystemRoot%\" + normalized[12..];
        else if (normalized.StartsWith(@"System32\", StringComparison.OrdinalIgnoreCase) ||
                 normalized.StartsWith(@"SysWOW64\", StringComparison.OrdinalIgnoreCase))
            normalized = @"%SystemRoot%\System32\" + normalized[9..];
        return normalized;
    }

    private static string? Location(string path)
    {
        if (path.StartsWith(@"\\", StringComparison.Ordinal)) return ServiceImageLocations.Network;
        var drive = path.Length >= 3 && char.IsAsciiLetter(path[0]) && path[1] == ':' && path[2] == '\\';
        // Dot segments could make a path claim a trusted prefix it does not resolve to.
        if (path.Split('\\').Any(segment => segment is "." or "..")) return drive ? ServiceImageLocations.Other : null;
        var rest = drive ? path[3..] : string.Empty;
        if (drive && StartsWith(rest, @"Windows\Temp\") || StartsWith(path, @"%SystemRoot%\Temp\") ||
            StartsWith(path, @"%windir%\Temp\"))
            return ServiceImageLocations.Temp;
        if (drive && StartsWith(rest, @"Windows\") || StartsWith(path, @"%SystemRoot%\") || StartsWith(path, @"%windir%\"))
            return ServiceImageLocations.Windows;
        if (!drive) return null;
        if (StartsWith(rest, @"Program Files\") || StartsWith(rest, @"Program Files (x86)\"))
            return ServiceImageLocations.ProgramFiles;
        if (StartsWith(rest, @"ProgramData\")) return ServiceImageLocations.ProgramData;
        if (StartsWith(rest, @"Users\"))
        {
            return rest.Contains(@"\AppData\Local\Temp\", StringComparison.OrdinalIgnoreCase)
                ? ServiceImageLocations.Temp
                : ServiceImageLocations.UserProfile;
        }

        return ServiceImageLocations.Other;
    }

    private static bool StartsWith(string value, string prefix) =>
        value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);

    private static bool IsMatch(Regex pattern, string value)
    {
        try
        {
            return pattern.IsMatch(value);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }
}

public readonly record struct DefenderSetting(string? Area, string? Change, int Discarded);

/// <summary>Classifies a 5007 configuration change by registry area; raw values are never kept.</summary>
public static class DefenderSettingClassifier
{
    private static readonly (string Prefix, string Area)[] Areas =
    [
        (@"Exclusions\Paths", DefenderSettingAreas.ExclusionPath),
        (@"Exclusions\Processes", DefenderSettingAreas.ExclusionProcess),
        (@"Exclusions\Extensions", DefenderSettingAreas.ExclusionExtension),
        (@"Exclusions\IpAddresses", DefenderSettingAreas.ExclusionIpAddress),
        ("Real-Time Protection", DefenderSettingAreas.RealTimeProtection),
        (@"Features\TamperProtection", DefenderSettingAreas.TamperProtection)
    ];

    public static DefenderSetting Classify(object? oldValue, object? newValue)
    {
        var discarded = 0;
        var oldPresent = Present(oldValue, ref discarded);
        var newPresent = Present(newValue, ref discarded);
        if (!oldPresent && !newPresent) return new(null, null, discarded);

        var change = oldPresent && newPresent ? DefenderSettingChanges.Modified
            : newPresent ? DefenderSettingChanges.Added
            : DefenderSettingChanges.Removed;
        if ((newPresent ? newValue : oldValue) is not string value)
        {
            // An oversized value still records the change, but its area cannot be read.
            discarded++;
            return new(null, change, discarded);
        }

        var marker = value.IndexOf(@"\Windows Defender\", StringComparison.OrdinalIgnoreCase);
        var remainder = marker < 0 ? string.Empty : value[(marker + @"\Windows Defender\".Length)..];
        var area = marker < 0
            ? DefenderSettingAreas.Other
            : Areas.FirstOrDefault(entry => remainder.StartsWith(entry.Prefix, StringComparison.OrdinalIgnoreCase)).Area
              ?? DefenderSettingAreas.Other;
        return new(area, change, discarded);
    }

    private static bool Present(object? value, ref int discarded)
    {
        if (SecurityEventNormalizer.IsAbsent(value)) return false;
        if (value is string || ReferenceEquals(value, EventFieldValue.Oversize)) return true;
        discarded++;
        return false;
    }
}
