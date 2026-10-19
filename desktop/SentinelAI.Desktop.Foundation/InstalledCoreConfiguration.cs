using System.Text.Json;
using System.Text.RegularExpressions;

namespace SentinelAI.Desktop.Foundation;

// The fixed Core configuration Setup writes: the loopback origin and data directory, plus Core's
// local-network port and certificate pin on a central installation (MVP-1). Anything else is untrusted.
public static class InstalledCoreConfiguration
{
    public const string LocalNetworkPort = "5443";

    public static bool IsExpected(JsonElement root, string origin, string dataDirectory)
    {
        if (!TryExactObject(root, out var settings, "urls", "SentinelAI") ||
            !TryString(settings["urls"], out var urls) || !string.Equals(urls, origin, StringComparison.Ordinal)) return false;
        var core = settings["SentinelAI"];
        var central = core.ValueKind == JsonValueKind.Object && core.TryGetProperty("LocalNetworkPort", out _);
        if (!(central
                ? TryExactObject(core, out var data, "DataDirectory", "LocalNetworkPort", "LocalNetworkCertificateSha256")
                : TryExactObject(core, out data, "DataDirectory")) ||
            !TryString(data["DataDirectory"], out var directory) || !string.Equals(directory, dataDirectory, StringComparison.OrdinalIgnoreCase)) return false;
        return !central ||
               TryString(data["LocalNetworkPort"], out var port) && port == LocalNetworkPort &&
               TryString(data["LocalNetworkCertificateSha256"], out var pin) && Regex.IsMatch(pin, @"\A[0-9A-F]{64}\z");
    }

    private static bool TryExactObject(JsonElement element, out Dictionary<string, JsonElement> result, params string[] names)
    {
        result = new Dictionary<string, JsonElement>(StringComparer.OrdinalIgnoreCase);
        if (element.ValueKind != JsonValueKind.Object) return false;
        foreach (var property in element.EnumerateObject())
            if (!names.Contains(property.Name, StringComparer.Ordinal) || !result.TryAdd(property.Name, property.Value)) return false;
        return result.Count == names.Length;
    }

    private static bool TryString(JsonElement element, out string value)
    {
        value = element.ValueKind == JsonValueKind.String ? element.GetString()! : string.Empty;
        return element.ValueKind == JsonValueKind.String;
    }
}
