using System.Text.Json;

namespace SentinelAI.Updates;

/// <summary>Bounded code-package version metadata; authority comes from the enclosing signed deployment manifest.</summary>
public static class DeploymentPackageVersion
{
    public const string FileName = "deployment-version.json";
    public const string Format = "sentinelai-deployment-v1";
    public const int MaximumDocumentBytes = 1024;

    public static string Read(ReadOnlyMemory<byte> document)
    {
        if (document.Length is < 1 or > MaximumDocumentBytes) throw new InvalidDataException("Invalid deployment version metadata.");
        try
        {
            using var json = JsonDocument.Parse(document, new JsonDocumentOptions { MaxDepth = 2 });
            if (json.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Invalid deployment version metadata.");
            var fields = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
            foreach (var field in json.RootElement.EnumerateObject())
                if (field.Name is not ("format" or "version") || !fields.TryAdd(field.Name, field.Value)) throw new InvalidDataException("Invalid deployment version metadata.");
            if (fields.Count != 2 || fields["format"].ValueKind != JsonValueKind.String || fields["format"].GetString() != Format ||
                fields["version"].ValueKind != JsonValueKind.String || !UpdateManifestFormat.TryVersion(fields["version"].GetString(), out _))
                throw new InvalidDataException("Invalid deployment version metadata.");
            return fields["version"].GetString()!;
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException)
        {
            throw new InvalidDataException("Invalid deployment version metadata.");
        }
    }
}
