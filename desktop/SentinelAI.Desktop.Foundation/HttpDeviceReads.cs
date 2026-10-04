using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SentinelAI.Contracts.Inventory;

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
        var fields = ReadProperties(root, ["device", "inventoryCollectedUtc", "osVersion", "architecture", "cpu", "installedRamBytes", "disks", "securityPosture", "osName"]);
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
            disks.AsReadOnly(), posture, OptionalDeviceText(fields, "osName", 128));
    }

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
