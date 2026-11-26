using System.Text.Json;
using SentinelAI.Contracts.EndpointTelemetry;
using SentinelAI.Contracts.SecurityEvents;
using SentinelAI.Contracts.SoftwareCatalog;

namespace SentinelAI.Desktop.Foundation;

public interface ISoftwareCatalogClient
{
    Task<DeviceReadResult<SoftwareCatalogPage>> GetSoftwareCatalogAsync(string query, int offset, int limit, CancellationToken cancellationToken);
    Task<DeviceReadResult<SoftwareInstallationsPage>> GetSoftwareInstallationsAsync(string productId, int offset, int limit, CancellationToken cancellationToken);
    Task<DeviceReadResult<SoftwareChangesPage>> GetSoftwareChangesAsync(string? productId, int offset, int limit, CancellationToken cancellationToken);
}

public sealed partial class HttpAuthenticationClient : ISoftwareCatalogClient
{
    private const string SoftwareCatalogPath = "api/admin/software-catalog";

    public Task<DeviceReadResult<SoftwareCatalogPage>> GetSoftwareCatalogAsync(string query, int offset, int limit,
        CancellationToken cancellationToken)
    {
        if (query.Length != 0 && !SecurityEventContract.IsBoundedText(query, SoftwareCatalogContract.MaximumQueryLength))
            return Task.FromResult(new DeviceReadResult<SoftwareCatalogPage>(DeviceReadOutcome.InvalidResponse));
        var path = SoftwareCatalogPath + SoftwarePageQuery(offset, limit);
        if (query.Length > 0) path += "&q=" + Uri.EscapeDataString(query);
        return ReadDeviceResourceAsync(path, SoftwareCatalogContract.MaximumResponseBytes,
            root => ParseSoftwareCatalog(root, offset, limit), allowNotFound: false, cancellationToken);
    }

    public Task<DeviceReadResult<SoftwareInstallationsPage>> GetSoftwareInstallationsAsync(string productId, int offset, int limit,
        CancellationToken cancellationToken) => ReadDeviceResourceAsync(
        $"{SoftwareCatalogPath}/{RequireSoftwareProductId(productId)}/installations" + SoftwarePageQuery(offset, limit),
        SoftwareCatalogContract.MaximumResponseBytes, root => ParseSoftwareInstallations(root, productId, offset, limit),
        allowNotFound: false, cancellationToken);

    public Task<DeviceReadResult<SoftwareChangesPage>> GetSoftwareChangesAsync(string? productId, int offset, int limit,
        CancellationToken cancellationToken)
    {
        var path = SoftwareCatalogPath + "/changes" + SoftwarePageQuery(offset, limit);
        if (productId is not null) path += "&productId=" + RequireSoftwareProductId(productId);
        return ReadDeviceResourceAsync(path, SoftwareCatalogContract.MaximumResponseBytes,
            root => ParseSoftwareChanges(root, productId, offset, limit), allowNotFound: false, cancellationToken);
    }

    private static string SoftwarePageQuery(int offset, int limit)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(offset);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(offset, SoftwareCatalogContract.MaximumOffset);
        ArgumentOutOfRangeException.ThrowIfLessThan(limit, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(limit, SoftwareCatalogContract.MaxPageSize);
        return FormattableString.Invariant($"?offset={offset}&limit={limit}");
    }

    private static SoftwareCatalogPage ParseSoftwareCatalog(JsonElement root, int offset, int limit)
    {
        var fields = CoverageFields(root, "generatedUtc", "total", "offset", "limit", "coverage", "items");
        var coverage = ParseSoftwareCoverage(fields["coverage"]);
        var total = SoftwareCount(fields, "total");
        var items = SoftwarePageItems(fields, total, offset, limit).Select(element => ParseSoftwareProduct(element, coverage)).ToArray();
        if (items.Length != items.Select(item => item.ProductId).Distinct(StringComparer.Ordinal).Count()) throw new InvalidResponseException();
        return new(CoverageDate(fields, "generatedUtc"), total, offset, limit, coverage, Array.AsReadOnly(items));
    }

    private static SoftwareCatalogCoverage ParseSoftwareCoverage(JsonElement root)
    {
        var fields = CoverageFields(root, "activeEndpoints", "completeEndpoints", "partialEndpoints", "unavailableEndpoints",
            "missingEndpoints", "staleEndpoints");
        var active = SoftwareCount(fields, "activeEndpoints");
        var complete = SoftwareCount(fields, "completeEndpoints");
        var partial = SoftwareCount(fields, "partialEndpoints");
        var unavailable = SoftwareCount(fields, "unavailableEndpoints");
        var missing = SoftwareCount(fields, "missingEndpoints");
        var stale = SoftwareCount(fields, "staleEndpoints");
        if ((long)complete + partial + unavailable + missing != active || stale > (long)complete + partial) throw new InvalidResponseException();
        return new(active, complete, partial, unavailable, missing, stale);
    }

    private static SoftwareProduct ParseSoftwareProduct(JsonElement root, SoftwareCatalogCoverage coverage)
    {
        var fields = CoverageFields(root, "productId", "name", "publisher", "endpointCount", "variantCount");
        return new(ParseSoftwareProductId(fields, "productId"), SoftwareName(fields), SoftwarePublisher(fields),
            CoverageNumber(fields, "endpointCount", 1, coverage.CompleteEndpoints + coverage.PartialEndpoints),
            CoverageNumber(fields, "variantCount", 1, int.MaxValue));
    }

    private static SoftwareInstallationsPage ParseSoftwareInstallations(JsonElement root, string productId, int offset, int limit)
    {
        var fields = CoverageFields(root, "productId", "generatedUtc", "total", "offset", "limit", "items");
        if (ParseSoftwareProductId(fields, "productId") != productId) throw new InvalidResponseException();
        var total = SoftwareCount(fields, "total");
        var items = SoftwarePageItems(fields, total, offset, limit).Select(ParseSoftwareInstallation).ToArray();
        if (items.Length != items.Select(item => (item.EndpointId, item.Version, item.Architecture)).Distinct().Count())
            throw new InvalidResponseException();
        return new(productId, CoverageDate(fields, "generatedUtc"), total, offset, limit, Array.AsReadOnly(items));
    }

    private static SoftwareInstallation ParseSoftwareInstallation(JsonElement root)
    {
        var fields = CoverageFields(root, "endpointId", "endpointName", "version", "architecture", "collectedUtc", "partial", "stale");
        var variant = ParseSoftwareVariantFields(fields);
        return new(CoverageId(fields), RequiredSoftwareText(fields, "endpointName", 256), variant.Version, variant.Architecture,
            CoverageDate(fields, "collectedUtc"), CoverageBoolean(fields, "partial"), CoverageBoolean(fields, "stale"));
    }

    private static SoftwareChangesPage ParseSoftwareChanges(JsonElement root, string? productId, int offset, int limit)
    {
        var fields = CoverageFields(root, "productId", "generatedUtc", "total", "offset", "limit", "items");
        var scope = fields["productId"].ValueKind == JsonValueKind.Null ? null : ParseSoftwareProductId(fields, "productId");
        if (scope != productId) throw new InvalidResponseException();
        var total = CoverageNumber(fields, "total", 0, SoftwareCatalogContract.MaximumChanges);
        var items = SoftwarePageItems(fields, total, offset, limit).Select(ParseSoftwareChange).ToArray();
        var identities = items.Select(item => (item.EndpointId, item.ProductId, item.CollectedUtc));
        if (items.Length != identities.Distinct().Count() || productId is not null && items.Any(item => item.ProductId != productId))
            throw new InvalidResponseException();
        return new(scope, CoverageDate(fields, "generatedUtc"), total, offset, limit, Array.AsReadOnly(items));
    }

    private static SoftwareChange ParseSoftwareChange(JsonElement root)
    {
        var fields = CoverageFields(root, "endpointId", "endpointName", "productId", "name", "publisher", "kind",
            "previousCollectedUtc", "collectedUtc", "beforeCount", "afterCount", "before", "after");
        var collected = CoverageDate(fields, "collectedUtc");
        var previous = CoverageDate(fields, "previousCollectedUtc");
        var kind = CoverageChoice(fields, "kind", [.. SoftwareCatalogContract.ChangeKinds]);
        var beforeCount = CoverageNumber(fields, "beforeCount", 0, EndpointTelemetryContract.MaxSoftwareItems);
        var afterCount = CoverageNumber(fields, "afterCount", 0, EndpointTelemetryContract.MaxSoftwareItems);
        if (previous >= collected || (beforeCount == 0) != (kind == "appeared") || (afterCount == 0) != (kind == "disappeared"))
            throw new InvalidResponseException();
        return new(CoverageId(fields), RequiredSoftwareText(fields, "endpointName", 256), ParseSoftwareProductId(fields, "productId"),
            SoftwareName(fields), SoftwarePublisher(fields), kind, previous, collected, beforeCount, afterCount,
            ParseSoftwareVariants(fields["before"], beforeCount), ParseSoftwareVariants(fields["after"], afterCount));
    }

    private static IReadOnlyList<SoftwareVariant> ParseSoftwareVariants(JsonElement element, int count)
    {
        var items = CoverageArray(element, Math.Min(SoftwareCatalogContract.MaximumChangeVariants, count))
            .Select(variant => ParseSoftwareVariantFields(CoverageFields(variant, "version", "architecture"))).ToArray();
        if (items.Length != items.Distinct().Count()) throw new InvalidResponseException();
        return Array.AsReadOnly(items);
    }

    private static SoftwareVariant ParseSoftwareVariantFields(Dictionary<string, JsonElement> fields) => new(
        NullableSoftwareText(fields, "version", EndpointTelemetryContract.MaxSoftwareVersionLength),
        fields["architecture"].ValueKind == JsonValueKind.Null ? null : CoverageChoice(fields, "architecture", [.. SoftwareArchitectures.All]));

    private static JsonElement.ArrayEnumerator SoftwarePageItems(Dictionary<string, JsonElement> fields, int total, int offset, int limit)
    {
        if (CoverageNumber(fields, "offset", 0, SoftwareCatalogContract.MaximumOffset) != offset ||
            CoverageNumber(fields, "limit", 1, SoftwareCatalogContract.MaxPageSize) != limit) throw new InvalidResponseException();
        return CoverageArray(fields["items"], Math.Min(limit, Math.Max(0, total - offset)));
    }

    private static int SoftwareCount(Dictionary<string, JsonElement> fields, string name) => CoverageNumber(fields, name, 0, int.MaxValue);
    private static string SoftwareName(Dictionary<string, JsonElement> fields) => RequiredSoftwareText(fields, "name", EndpointTelemetryContract.MaxSoftwareNameLength);
    private static string? SoftwarePublisher(Dictionary<string, JsonElement> fields) => NullableSoftwareText(fields, "publisher", EndpointTelemetryContract.MaxSoftwarePublisherLength);
    private static string? NullableSoftwareText(Dictionary<string, JsonElement> fields, string name, int maximum) =>
        fields[name].ValueKind == JsonValueKind.Null ? null : RequiredSoftwareText(fields, name, maximum);
    private static string RequiredSoftwareText(Dictionary<string, JsonElement> fields, string name, int maximum) =>
        fields[name].ValueKind == JsonValueKind.String && fields[name].GetString() is { } value && SecurityEventContract.IsBoundedText(value, maximum)
            ? value : throw new InvalidResponseException();

    private static string ParseSoftwareProductId(Dictionary<string, JsonElement> fields, string name) =>
        fields[name].ValueKind == JsonValueKind.String && fields[name].GetString() is { } id && SoftwareCatalogContract.IsProductId(id)
            ? id : throw new InvalidResponseException();

    private static string RequireSoftwareProductId(string value) => SoftwareCatalogContract.IsProductId(value)
        ? value : throw new ArgumentException("A software product identifier is required.", nameof(value));
}
