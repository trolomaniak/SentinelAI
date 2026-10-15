using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SentinelAI.Contracts.EndpointTelemetry;
using SentinelAI.Contracts.Inventory;
using SentinelAI.Contracts.SecurityEvents;

namespace SentinelAI.Desktop.Foundation;

public sealed partial class HttpAuthenticationClient
{
    private const int MaximumDeviceListBytes = 8 * 1024 * 1024;
    private const int MaximumDeviceDetailBytes = 256 * 1024;
    private const int MaximumDevices = 10_000;
    private const int MaximumDeviceDisks = 64;

    public Task<DeviceReadResult<IReadOnlyList<DeviceSummary>>> GetDevicesAsync(CancellationToken cancellationToken) =>
        ReadDeviceResourceAsync("api/admin/devices", MaximumDeviceListBytes, ParseDeviceList, allowNotFound: false, cancellationToken);

    public Task<DeviceReadResult<EndpointDetail>> GetDeviceDetailAsync(Guid endpointId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (endpointId == Guid.Empty)
        {
            lock (_gate)
            {
                if (_disposed || _token is null) return Task.FromResult(new DeviceReadResult<EndpointDetail>(DeviceReadOutcome.Unauthenticated));
                if (_time.GetUtcNow() >= _expiresAt)
                {
                    ResetGenerationLocked();
                    return Task.FromResult(new DeviceReadResult<EndpointDetail>(DeviceReadOutcome.Unauthenticated));
                }
                return Task.FromResult(new DeviceReadResult<EndpointDetail>(DeviceReadOutcome.NotFound));
            }
        }
        return ReadDeviceResourceAsync("api/admin/devices/" + endpointId.ToString("D"), MaximumDeviceDetailBytes,
            root => ParseEndpointDetail(root, endpointId), allowNotFound: true, cancellationToken);
    }

    private async Task<DeviceReadResult<T>> ReadDeviceResourceAsync<T>(string path, int maximumBytes,
        Func<JsonElement, T> parse, bool allowNotFound, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Operation operation;
        byte[] token;
        lock (_gate)
        {
            if (_disposed || _token is null) return new(DeviceReadOutcome.Unauthenticated);
            if (_time.GetUtcNow() >= _expiresAt)
            {
                ResetGenerationLocked();
                return new(DeviceReadOutcome.Unauthenticated);
            }
            operation = new Operation(_generation,
                CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _generationCancellation.Token));
            token = _token.ToArray();
        }
        using (operation)
        {
            operation.Cancellation.CancelAfter(TimeSpan.FromSeconds(10));
            DeviceReadResult<T> result;
            try
            {
                result = await RequestDeviceResourceAsync(path, maximumBytes, parse, allowNotFound, token, operation.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                cancellationToken.ThrowIfCancellationRequested();
                result = new(DeviceReadOutcome.Unavailable);
            }
            catch (DeviceReadTooLargeException) { result = new(DeviceReadOutcome.TooLarge); }
            catch (Exception exception) when (exception is InvalidResponseException or JsonException or FormatException or OverflowException)
            {
                result = new(DeviceReadOutcome.InvalidResponse);
            }
            catch (Exception)
            {
                cancellationToken.ThrowIfCancellationRequested();
                result = new(DeviceReadOutcome.Unavailable);
            }
            finally { CryptographicOperations.ZeroMemory(token); }
            cancellationToken.ThrowIfCancellationRequested();
            lock (_gate)
            {
                // Old requests can neither publish data nor invalidate a newly
                // authenticated session after sign-out, expiry or reconnect.
                if (_disposed || operation.Generation != _generation || _token is null)
                    return new(DeviceReadOutcome.Unauthenticated);
                if (_time.GetUtcNow() >= _expiresAt)
                {
                    ResetGenerationLocked();
                    return new(DeviceReadOutcome.Unauthenticated);
                }
                if (result.Outcome is DeviceReadOutcome.Unauthenticated or DeviceReadOutcome.UntrustedConnection)
                    ResetGenerationLocked();
                return result;
            }
        }
    }

    private async Task<DeviceReadResult<T>> RequestDeviceResourceAsync<T>(string path, int maximumBytes,
        Func<JsonElement, T> parse, bool allowNotFound, byte[] token, CancellationToken cancellationToken)
    {
        if (!await _trust.IsTrustedAsync(_origin, cancellationToken).ConfigureAwait(false))
            return new(DeviceReadOutcome.UntrustedConnection);
        cancellationToken.ThrowIfCancellationRequested();
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(_origin, path));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Encoding.ASCII.GetString(token));
        try
        {
            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (response.StatusCode == HttpStatusCode.Unauthorized) return new(DeviceReadOutcome.Unauthenticated);
            if (allowNotFound && response.StatusCode == HttpStatusCode.NotFound) return new(DeviceReadOutcome.NotFound);
            if (response.StatusCode is HttpStatusCode.RequestEntityTooLarge or HttpStatusCode.UnprocessableEntity)
                return new(DeviceReadOutcome.TooLarge);
            if (response.StatusCode != HttpStatusCode.OK) return new(DeviceReadOutcome.Unavailable);
            if (!string.Equals(response.Content.Headers.ContentType?.MediaType, "application/json", StringComparison.OrdinalIgnoreCase))
                throw new InvalidResponseException();
            if (response.Content.Headers.ContentLength > maximumBytes) throw new DeviceReadTooLargeException();
            var buffer = new byte[maximumBytes + 1];
            try
            {
                using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
                var length = 0;
                while (length < buffer.Length)
                {
                    var count = await stream.ReadAsync(buffer.AsMemory(length), cancellationToken).ConfigureAwait(false);
                    if (count == 0) break;
                    length += count;
                }
                cancellationToken.ThrowIfCancellationRequested();
                if (length > maximumBytes) throw new DeviceReadTooLargeException();
                using var json = JsonDocument.Parse(buffer.AsMemory(0, length), new JsonDocumentOptions { MaxDepth = 6 });
                var value = parse(json.RootElement);
                cancellationToken.ThrowIfCancellationRequested();
                return new(DeviceReadOutcome.Success, value);
            }
            finally { CryptographicOperations.ZeroMemory(buffer); }
        }
        finally { request.Headers.Authorization = null; }
    }

    private static IReadOnlyList<DeviceSummary> ParseDeviceList(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Array) throw new InvalidResponseException();
        if (root.GetArrayLength() > MaximumDevices) throw new DeviceReadTooLargeException();
        var devices = new List<DeviceSummary>(root.GetArrayLength());
        var identities = new HashSet<Guid>();
        foreach (var element in root.EnumerateArray())
        {
            var device = ParseDeviceSummary(element);
            if (!identities.Add(device.EndpointId)) throw new InvalidResponseException();
            devices.Add(device);
        }
        return devices.AsReadOnly();
    }

    private static DeviceSummary ParseDeviceSummary(JsonElement root)
    {
        var fields = ReadProperties(root, ["endpointId", "name", "operatingSystem", "healthState", "lastSeenUtc", "agentVersion", "securityPostureSummary", "inventoryCollectedUtc"]);
        if (!fields.TryGetValue("endpointId", out var endpoint) || endpoint.ValueKind != JsonValueKind.String ||
            !Guid.TryParseExact(endpoint.GetString(), "D", out var endpointId) || endpointId == Guid.Empty) throw new InvalidResponseException();
        var health = OptionalDeviceText(fields, "healthState", 32);
        if (health is not ("healthy" or "warning" or "offline")) health = "unknown";
        var firewall = OptionalDeviceText(fields, "securityPostureSummary", 256);
        if (firewall is not ("Firewall enabled on all profiles" or "Firewall disabled on one or more profiles")) firewall = "Firewall status unknown";
        return new DeviceSummary(endpointId, OptionalDeviceText(fields, "name", 255) ?? "Unknown",
            OptionalDeviceText(fields, "operatingSystem", 512), health, OptionalDeviceDate(fields, "lastSeenUtc"),
            OptionalDeviceText(fields, "agentVersion", 64), firewall, OptionalDeviceDate(fields, "inventoryCollectedUtc"));
    }

    private static EndpointDetail ParseEndpointDetail(JsonElement root, Guid expectedEndpointId)
    {
        var fields = ReadProperties(root, ["device", "inventoryCollectedUtc", "osVersion", "architecture", "cpu", "installedRamBytes", "disks", "securityPosture", "osName", "securityTelemetry"]);
        if (!fields.TryGetValue("device", out var deviceElement)) throw new InvalidResponseException();
        var device = ParseDeviceSummary(deviceElement);
        if (device.EndpointId != expectedEndpointId) throw new InvalidResponseException();
        CpuInventory? cpu = null;
        if (PresentObject(fields, "cpu", out var cpuElement))
        {
            var cpuFields = ReadProperties(cpuElement, ["model", "logicalProcessorCount"]);
            var count = OptionalDeviceInteger(cpuFields, "logicalProcessorCount", 1, 1024);
            if (count is null) throw new InvalidResponseException();
            cpu = new CpuInventory(OptionalDeviceText(cpuFields, "model", 256), (int)count.Value);
        }
        var disks = new List<DiskInventory>();
        if (fields.TryGetValue("disks", out var diskElement) && diskElement.ValueKind != JsonValueKind.Null)
        {
            if (diskElement.ValueKind != JsonValueKind.Array) throw new InvalidResponseException();
            if (diskElement.GetArrayLength() > MaximumDeviceDisks) throw new DeviceReadTooLargeException();
            foreach (var disk in diskElement.EnumerateArray())
            {
                var diskFields = ReadProperties(disk, ["name", "totalBytes", "availableBytes"]);
                var total = OptionalDeviceInteger(diskFields, "totalBytes", 1, long.MaxValue);
                var available = OptionalDeviceInteger(diskFields, "availableBytes", 0, long.MaxValue);
                var name = OptionalDeviceText(diskFields, "name", 256);
                if (name is null || total is null || available is null || available > total) throw new InvalidResponseException();
                disks.Add(new DiskInventory(name, total.Value, available.Value));
            }
        }
        SecurityPostureInventory? posture = null;
        if (PresentObject(fields, "securityPosture", out var postureElement))
        {
            var postureFields = ReadProperties(postureElement, ["domainFirewallEnabled", "privateFirewallEnabled", "publicFirewallEnabled", "configuration"]);
            WindowsSecurityConfiguration? configuration = null;
            if (PresentObject(postureFields, "configuration", out var configurationElement))
            {
                var settings = ReadProperties(configurationElement, ["uacEnabled", "adminConsentPromptBehavior", "rdpEnabled", "rdpNetworkLevelAuthenticationRequired", "rdpSecurityLayer", "rdpMinimumEncryptionLevel", "smb1ServerEnabled", "smbInsecureGuestLogonsAllowed", "automaticAdminLogonEnabled", "lsaProtectionEnabled", "automaticUpdatesDisabled"]);
                configuration = new WindowsSecurityConfiguration(OptionalDeviceBoolean(settings, "uacEnabled"),
                    (int?)OptionalDeviceInteger(settings, "adminConsentPromptBehavior", 0, 5), OptionalDeviceBoolean(settings, "rdpEnabled"),
                    OptionalDeviceBoolean(settings, "rdpNetworkLevelAuthenticationRequired"), (int?)OptionalDeviceInteger(settings, "rdpSecurityLayer", 0, 2),
                    (int?)OptionalDeviceInteger(settings, "rdpMinimumEncryptionLevel", 1, 4), OptionalDeviceBoolean(settings, "smb1ServerEnabled"),
                    OptionalDeviceBoolean(settings, "smbInsecureGuestLogonsAllowed"), OptionalDeviceBoolean(settings, "automaticAdminLogonEnabled"),
                    OptionalDeviceBoolean(settings, "lsaProtectionEnabled"), OptionalDeviceBoolean(settings, "automaticUpdatesDisabled"));
            }
            posture = new SecurityPostureInventory(OptionalDeviceBoolean(postureFields, "domainFirewallEnabled"),
                OptionalDeviceBoolean(postureFields, "privateFirewallEnabled"), OptionalDeviceBoolean(postureFields, "publicFirewallEnabled"), configuration);
        }
        return new EndpointDetail(device, OptionalDeviceDate(fields, "inventoryCollectedUtc"), OptionalDeviceText(fields, "osVersion", 192),
            OptionalDeviceText(fields, "architecture", 32), cpu, OptionalDeviceInteger(fields, "installedRamBytes", 1, long.MaxValue),
            disks.AsReadOnly(), posture, OptionalDeviceText(fields, "osName", 128), ParseTelemetry(fields));
    }

    /// <summary>
    /// Parses Core's optional telemetry projection. Types, bounds and section consistency are strict; a vocabulary value
    /// this Desktop does not know is shown as Unknown, and an unknown schema version is not shown at all.
    /// </summary>
    private static EndpointTelemetryDetail? ParseTelemetry(Dictionary<string, JsonElement> fields)
    {
        if (!PresentObject(fields, "securityTelemetry", out var element)) return null;
        var telemetry = ReadProperties(element, ["schemaVersion", "collectedUtc", "receivedUtc", "bitLocker", "antivirus", "defender", "localAdministrators", "windowsUpdate", "pendingReboot", "services", "software"]);
        if (OptionalDeviceInteger(telemetry, "schemaVersion", 1, int.MaxValue) is not { } version) throw new InvalidResponseException();
        if (version != EndpointTelemetryContract.CurrentSchemaVersion) return null;
        var collectedUtc = OptionalDeviceDate(telemetry, "collectedUtc") ?? throw new InvalidResponseException();
        var receivedUtc = OptionalDeviceDate(telemetry, "receivedUtc") ?? throw new InvalidResponseException();

        var section = TelemetrySection(telemetry, "bitLocker", ["availability", "protectionStatus", "conversionStatus"]);
        var bitLocker = new BitLockerTelemetry(TelemetryAvailabilityOf(section, "availability"),
            TelemetryVocabulary(section, "protectionStatus", BitLockerProtectionStates.All),
            TelemetryVocabulary(section, "conversionStatus", BitLockerConversionStates.All));

        section = TelemetrySection(telemetry, "antivirus", ["availability", "securityCenterHealth"]);
        var antivirus = new AntivirusTelemetry(TelemetryAvailabilityOf(section, "availability"),
            TelemetryVocabulary(section, "securityCenterHealth", SecurityCenterHealthStates.All));

        section = TelemetrySection(telemetry, "defender", ["availability", "runningMode", "antivirusEnabled", "realTimeProtectionEnabled", "tamperProtectionEnabled", "signatureAgeDays"]);
        var defender = new DefenderTelemetry(TelemetryAvailabilityOf(section, "availability"),
            TelemetryVocabulary(section, "runningMode", DefenderRunningModes.All), OptionalDeviceBoolean(section, "antivirusEnabled"),
            OptionalDeviceBoolean(section, "realTimeProtectionEnabled"), OptionalDeviceBoolean(section, "tamperProtectionEnabled"),
            (int?)OptionalDeviceInteger(section, "signatureAgeDays", 0, EndpointTelemetryContract.MaxSignatureAgeDays));

        section = TelemetrySection(telemetry, "localAdministrators", ["availability", "memberCount", "members"]);
        List<LocalAdministratorMember>? members = null;
        if (section.TryGetValue("members", out var memberElement) && memberElement.ValueKind != JsonValueKind.Null)
        {
            if (memberElement.ValueKind != JsonValueKind.Array) throw new InvalidResponseException();
            if (memberElement.GetArrayLength() > EndpointTelemetryContract.MaxAdministratorMembers) throw new DeviceReadTooLargeException();
            members = [];
            foreach (var item in memberElement.EnumerateArray())
            {
                var member = ReadProperties(item, ["sid", "scope", "accountType"]);
                var sid = OptionalDeviceText(member, "sid", 184);
                if (!SecurityEventContract.IsValidSid(sid)) throw new InvalidResponseException();
                members.Add(new LocalAdministratorMember(sid!, TelemetryVocabulary(member, "scope", AdministratorScopes.All),
                    TelemetryVocabulary(member, "accountType", AdministratorAccountTypes.All)));
            }
        }
        var administrators = new LocalAdministratorsTelemetry(TelemetryAvailabilityOf(section, "availability"),
            (int?)OptionalDeviceInteger(section, "memberCount", 0, EndpointTelemetryContract.MaxAdministratorMemberCount),
            members?.AsReadOnly());

        section = TelemetrySection(telemetry, "windowsUpdate", ["policyAvailability", "resultsAvailability", "automaticUpdatesPolicy", "managedUpdateServer", "lastSuccessfulSearchUtc", "lastSuccessfulInstallationUtc"]);
        var update = new WindowsUpdateTelemetry(TelemetryAvailabilityOf(section, "policyAvailability"),
            TelemetryAvailabilityOf(section, "resultsAvailability"),
            TelemetryVocabulary(section, "automaticUpdatesPolicy", AutomaticUpdatesPolicies.All),
            OptionalDeviceBoolean(section, "managedUpdateServer"), OptionalDeviceDate(section, "lastSuccessfulSearchUtc"),
            OptionalDeviceDate(section, "lastSuccessfulInstallationUtc"));

        section = TelemetrySection(telemetry, "pendingReboot", ["availability", "componentBasedServicing", "windowsUpdate", "pendingFileRenameOperations"]);
        var reboot = new PendingRebootTelemetry(TelemetryAvailabilityOf(section, "availability"),
            OptionalDeviceBoolean(section, "componentBasedServicing"), OptionalDeviceBoolean(section, "windowsUpdate"),
            OptionalDeviceBoolean(section, "pendingFileRenameOperations"));

        section = TelemetrySection(telemetry, "services", ["availability", "items"]);
        List<SecurityServiceObservation>? services = null;
        if (section.TryGetValue("items", out var serviceElement) && serviceElement.ValueKind != JsonValueKind.Null)
        {
            if (serviceElement.ValueKind != JsonValueKind.Array) throw new InvalidResponseException();
            if (serviceElement.GetArrayLength() > EndpointTelemetryContract.MonitoredServices.Count) throw new DeviceReadTooLargeException();
            services = [];
            foreach (var item in serviceElement.EnumerateArray())
            {
                var service = ReadProperties(item, ["name", "state", "startType"]);
                var name = OptionalDeviceText(service, "name", 64);
                if (name is null || !EndpointTelemetryContract.MonitoredServices.Contains(name, StringComparer.Ordinal))
                    throw new InvalidResponseException();
                services.Add(new SecurityServiceObservation(name, TelemetryVocabulary(service, "state", ServiceRunStates.All),
                    TelemetryVocabulary(service, "startType", ServiceStartTypes.All)));
            }
        }
        var serviceTelemetry = new SecurityServicesTelemetry(TelemetryAvailabilityOf(section, "availability"), services?.AsReadOnly());

        section = TelemetrySection(telemetry, "software", ["availability", "totalCount", "reportedCount", "truncated", "skippedCount"]);
        var software = new InstalledSoftwareSummary(TelemetryAvailabilityOf(section, "availability"),
            (int?)OptionalDeviceInteger(section, "totalCount", 0, EndpointTelemetryContract.MaxSoftwareTotal),
            (int?)OptionalDeviceInteger(section, "reportedCount", 0, EndpointTelemetryContract.MaxSoftwareItems),
            OptionalDeviceBoolean(section, "truncated") ?? throw new InvalidResponseException(),
            (int?)OptionalDeviceInteger(section, "skippedCount", 0, EndpointTelemetryContract.MaxSoftwareTotal) ?? throw new InvalidResponseException());
        var softwareConsistent = software.Availability == TelemetryAvailability.Collected
            ? software is { TotalCount: { } total, ReportedCount: { } reported } && reported <= total && software.Truncated == reported < total
            : software is { TotalCount: null, ReportedCount: null, Truncated: false, SkippedCount: 0 };

        if (!softwareConsistent || !EndpointTelemetryContract.IsValid(bitLocker) || !EndpointTelemetryContract.IsValid(antivirus) ||
            !EndpointTelemetryContract.IsValid(defender) || !EndpointTelemetryContract.IsValid(administrators) ||
            !EndpointTelemetryContract.IsValid(update, collectedUtc) || !EndpointTelemetryContract.IsValid(reboot) ||
            !EndpointTelemetryContract.IsValid(serviceTelemetry))
            throw new InvalidResponseException();
        return new EndpointTelemetryDetail(collectedUtc, receivedUtc, bitLocker, antivirus, defender, administrators, update,
            reboot, serviceTelemetry, software);
    }

    private static Dictionary<string, JsonElement> TelemetrySection(Dictionary<string, JsonElement> fields, string name, string[] allowed) =>
        PresentObject(fields, name, out var element) ? ReadProperties(element, allowed) : throw new InvalidResponseException();

    private static string TelemetryAvailabilityOf(Dictionary<string, JsonElement> fields, string name) =>
        OptionalDeviceText(fields, name, 32) is { } availability && TelemetryAvailability.All.Contains(availability, StringComparer.Ordinal)
            ? availability
            : throw new InvalidResponseException();

    private static string? TelemetryVocabulary(Dictionary<string, JsonElement> fields, string name, IReadOnlyList<string> vocabulary) =>
        OptionalDeviceText(fields, name, 64) is { } value && vocabulary.Contains(value, StringComparer.Ordinal) ? value : null;

    private static bool PresentObject(Dictionary<string, JsonElement> fields, string name, out JsonElement value)
    {
        if (!fields.TryGetValue(name, out value) || value.ValueKind == JsonValueKind.Null) return false;
        if (value.ValueKind != JsonValueKind.Object) throw new InvalidResponseException();
        return true;
    }

    private static string? OptionalDeviceText(Dictionary<string, JsonElement> fields, string name, int limit)
    {
        if (!fields.TryGetValue(name, out var value) || value.ValueKind == JsonValueKind.Null) return null;
        if (value.ValueKind != JsonValueKind.String) throw new InvalidResponseException();
        var text = value.GetString()!;
        if (text.Length > limit || text.Any(char.IsControl)) throw new InvalidResponseException();
        return string.IsNullOrWhiteSpace(text) ? null : text;
    }

    private static DateTimeOffset? OptionalDeviceDate(Dictionary<string, JsonElement> fields, string name)
    {
        if (!fields.TryGetValue(name, out var value) || value.ValueKind == JsonValueKind.Null) return null;
        if (value.ValueKind != JsonValueKind.String || !value.TryGetDateTimeOffset(out var date) || date.Offset != TimeSpan.Zero)
            throw new InvalidResponseException();
        return date;
    }

    private static long? OptionalDeviceInteger(Dictionary<string, JsonElement> fields, string name, long minimum, long maximum)
    {
        if (!fields.TryGetValue(name, out var value) || value.ValueKind == JsonValueKind.Null) return null;
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt64(out var number) || number < minimum || number > maximum)
            throw new InvalidResponseException();
        return number;
    }

    private static bool? OptionalDeviceBoolean(Dictionary<string, JsonElement> fields, string name)
    {
        if (!fields.TryGetValue(name, out var value) || value.ValueKind == JsonValueKind.Null) return null;
        return value.ValueKind switch { JsonValueKind.True => true, JsonValueKind.False => false, _ => throw new InvalidResponseException() };
    }

    private sealed class DeviceReadTooLargeException : Exception;
}
