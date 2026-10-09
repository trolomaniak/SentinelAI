using System.Text.Json;
using System.Text.RegularExpressions;

namespace SentinelAI.Setup.Foundation;

public sealed record SetupMetadata(string KeyId, string Version, string Channel, string PayloadSha256, long PayloadLength)
{
    public static SetupMetadata Parse(ReadOnlyMemory<byte> input)
    {
        if (input.Length is <= 0 or > 4096) throw new InvalidDataException("Invalid setup metadata.");
        using var document = JsonDocument.Parse(input, new JsonDocumentOptions { MaxDepth = 2 });
        if (document.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Invalid setup metadata.");
        var fields = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        string[] names = ["keyId", "version", "channel", "environment", "payloadSha256", "payloadLength"];
        foreach (var field in document.RootElement.EnumerateObject())
            if (!names.Contains(field.Name, StringComparer.Ordinal) || !fields.TryAdd(field.Name, field.Value)) throw new InvalidDataException("Invalid setup metadata.");
        if (fields.Count != names.Length) throw new InvalidDataException("Incomplete setup metadata.");
        string Text(string name) => fields[name].ValueKind == JsonValueKind.String ? fields[name].GetString()! : throw new InvalidDataException("Invalid setup metadata.");
        var key = Text("keyId"); var version = Text("version"); var channel = Text("channel"); var hash = Text("payloadSha256");
        if (!Regex.IsMatch(key, "\\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\\z", RegexOptions.CultureInvariant) ||
            !Regex.IsMatch(version, "\\A[0-9]{1,9}\\.[0-9]{1,9}\\.[0-9]{1,9}\\z", RegexOptions.CultureInvariant) ||
            channel is not ("stable" or "pilot" or "beta") || Text("environment") != "development" ||
            !Regex.IsMatch(hash, "\\A[0-9a-f]{64}\\z", RegexOptions.CultureInvariant) ||
            fields["payloadLength"].ValueKind != JsonValueKind.Number || !fields["payloadLength"].TryGetInt64(out var length) || length is <= 0 or > SetupPayload.MaximumCompressedBytes)
            throw new InvalidDataException("Unsupported setup metadata.");
        return new(key, version, channel, hash, length);
    }
}
