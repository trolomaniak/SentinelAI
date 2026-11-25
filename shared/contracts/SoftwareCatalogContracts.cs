namespace SentinelAI.Contracts.SoftwareCatalog;

public static class SoftwareCatalogContract
{
    public const int DefaultPageSize = 25;
    public const int MaxPageSize = 50;
    public const int MaximumOffset = int.MaxValue - MaxPageSize;
    public const int MaximumQueryLength = 128;
    public const int MaximumChangeVariants = 12;
    public const int MaximumChanges = 25_000;
    public const int StaleAfterHours = 3;
    public const int RetentionDays = 90;
    public const int MaximumResponseBytes = 1024 * 1024;
    public static IReadOnlyList<string> ChangeKinds { get; } = Array.AsReadOnly(new[] { "appeared", "disappeared", "variantsChanged" });

    public static bool IsProductId(string? value) => value is { Length: 64 } &&
        value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');
}

public sealed record SoftwareVariant(string? Version, string? Architecture);

public sealed record SoftwareCatalogCoverage(int ActiveEndpoints, int CompleteEndpoints, int PartialEndpoints,
    int UnavailableEndpoints, int MissingEndpoints, int StaleEndpoints);

public sealed record SoftwareProduct(string ProductId, string Name, string? Publisher, int EndpointCount, int VariantCount);

public sealed record SoftwareCatalogPage(DateTimeOffset GeneratedUtc, int Total, int Offset, int Limit,
    SoftwareCatalogCoverage Coverage, IReadOnlyList<SoftwareProduct> Items);

public sealed record SoftwareInstallation(Guid EndpointId, string EndpointName, string? Version, string? Architecture,
    DateTimeOffset CollectedUtc, bool Partial, bool Stale);

public sealed record SoftwareInstallationsPage(string ProductId, DateTimeOffset GeneratedUtc, int Total, int Offset, int Limit,
    IReadOnlyList<SoftwareInstallation> Items);

public sealed record SoftwareChange(Guid EndpointId, string EndpointName, string ProductId, string Name, string? Publisher,
    string Kind, DateTimeOffset PreviousCollectedUtc, DateTimeOffset CollectedUtc, int BeforeCount, int AfterCount,
    IReadOnlyList<SoftwareVariant> Before, IReadOnlyList<SoftwareVariant> After);

public sealed record SoftwareChangesPage(string? ProductId, DateTimeOffset GeneratedUtc, int Total, int Offset, int Limit,
    IReadOnlyList<SoftwareChange> Items);
