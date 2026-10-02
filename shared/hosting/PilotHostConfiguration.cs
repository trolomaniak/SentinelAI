using System.Text.Json;

namespace SentinelAI.Hosting;

// Linked into the two hosts: the pilot configuration has no hosting or package dependency.
internal sealed record PilotHostConfiguration(string[] Arguments, Dictionary<string, string?>? Values)
{
    private const int MaximumBytes = 16 * 1024;
    private static readonly HashSet<string> AgentKeys = new(StringComparer.Ordinal)
    {
        "CoreUrl", "DataDirectory", "CoreCertificateSha256", "HeartbeatInterval",
        "RetryDelay", "MaxRetryDelay", "EnrollmentTokenFile"
    };

    public static PilotHostConfiguration Read(string[] arguments, bool agent)
    {
        if (!arguments.Any(argument => argument == "--config" || argument.StartsWith("--config=", StringComparison.Ordinal)))
            return new(arguments, null);
        if (arguments.Length != 2 || arguments[0] != "--config")
            throw Invalid();

        var path = arguments[1];
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path)) throw Invalid();
        RejectLinks(path);
        if (!OperatingSystem.IsWindows() &&
            (File.GetUnixFileMode(path) & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) != 0)
            throw Invalid();

        byte[] bytes;
        using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            if (stream.Length is <= 0 or > MaximumBytes) throw Invalid();
            bytes = new byte[checked((int)stream.Length)];
            stream.ReadExactly(bytes);
            if (stream.ReadByte() != -1) throw Invalid();
        }

        try
        {
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 3 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) throw Invalid();
            var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
            var roots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var property in root.EnumerateObject())
            {
                if (!roots.Add(property.Name)) throw Invalid();
                if (!agent && property.Name == "urls")
                {
                    var url = ReadString(property.Value);
                    if (!Uri.TryCreate(url, UriKind.Absolute, out var origin) ||
                        origin.Scheme != Uri.UriSchemeHttp || !origin.IsLoopback ||
                        origin.AbsolutePath != "/" || origin.Port < 1 ||
                        !string.IsNullOrEmpty(origin.UserInfo) ||
                        !string.IsNullOrEmpty(origin.Query) || !string.IsNullOrEmpty(origin.Fragment)) throw Invalid();
                    values.Add("urls", url);
                }
                else if (property.Name == (agent ? "Agent" : "SentinelAI") && property.Value.ValueKind == JsonValueKind.Object)
                {
                    var members = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    foreach (var member in property.Value.EnumerateObject())
                    {
                        if (!members.Add(member.Name) ||
                            (agent ? !AgentKeys.Contains(member.Name) : member.Name != "DataDirectory")) throw Invalid();
                        var value = ReadString(member.Value);
                        if (member.Name is "DataDirectory" or "EnrollmentTokenFile")
                        {
                            if (!Path.IsPathFullyQualified(value) || Path.GetFullPath(value) == Path.GetPathRoot(value)) throw Invalid();
                            RejectLinks(value);
                        }
                        values.Add(property.Name + ":" + member.Name, value);
                    }
                }
                else throw Invalid();
            }

            if (agent ? !values.ContainsKey("Agent:CoreUrl") || !values.ContainsKey("Agent:DataDirectory")
                      : !values.ContainsKey("urls") || !values.ContainsKey("SentinelAI:DataDirectory")) throw Invalid();
            return new([], values);
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException or ArgumentException)
        {
            throw Invalid();
        }
    }

    public static void RejectLinks(string path)
    {
        var current = Path.GetFullPath(path);
        while (current is not null)
        {
            var file = new FileInfo(current);
            var directory = new DirectoryInfo(current);
            if (file.LinkTarget is not null || directory.LinkTarget is not null ||
                ((File.Exists(current) || Directory.Exists(current)) &&
                 (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)) throw Invalid();
            current = Path.GetDirectoryName(current);
        }
    }

    private static string ReadString(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.String) throw Invalid();
        var value = element.GetString();
        if (string.IsNullOrWhiteSpace(value) || value.Length > 4096 || value.Any(char.IsControl)) throw Invalid();
        return value;
    }

    private static InvalidOperationException Invalid() =>
        new("The pilot configuration must be a supported nonsecret configuration at an absolute regular-file path.");
}
