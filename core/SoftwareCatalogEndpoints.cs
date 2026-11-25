using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SentinelAI.Contracts.SecurityEvents;
using SentinelAI.Contracts.SoftwareCatalog;
using SentinelAI.Core.Persistence;

namespace SentinelAI.Core;

internal static class SoftwareCatalogEndpoints
{
    internal const string Route = "/api/admin/software-catalog";

    internal static void MapSoftwareCatalogEndpoints(this WebApplication app)
    {
        var group = app.MapGroup(Route).RequireAuthorization();
        group.MapGet("", (HttpContext context, SoftwareCatalogReadStore catalog, CancellationToken cancellationToken) =>
        {
            var query = context.Request.Query;
            if (!TryReadPage(query, "q", out var offset, out var limit) || !TryReadSearch(query, out var search))
                return Task.FromResult(Results.BadRequest());
            return ReadAsync(app.Logger, () => catalog.ReadProductsAsync(search, offset, limit, cancellationToken));
        });

        group.MapGet("/{productId}/installations", (string productId, HttpContext context, SoftwareCatalogReadStore catalog,
            CancellationToken cancellationToken) =>
        {
            if (!SoftwareCatalogContract.IsProductId(productId) ||
                !TryReadPage(context.Request.Query, null, out var offset, out var limit))
                return Task.FromResult(Results.BadRequest());
            return ReadAsync(app.Logger, () => catalog.ReadInstallationsAsync(productId, offset, limit, cancellationToken));
        });

        group.MapGet("/changes", (HttpContext context, SoftwareCatalogReadStore catalog, CancellationToken cancellationToken) =>
        {
            var query = context.Request.Query;
            if (!TryReadPage(query, "productId", out var offset, out var limit)) return Task.FromResult(Results.BadRequest());
            var productId = query.TryGetValue("productId", out var values) ? values[0] : null;
            if (values.Count == 1 && !SoftwareCatalogContract.IsProductId(productId)) return Task.FromResult(Results.BadRequest());
            return ReadAsync(app.Logger, () => catalog.ReadChangesAsync(productId, offset, limit, cancellationToken));
        });
    }

    private static bool TryReadSearch(IQueryCollection query, out string search)
    {
        search = string.Empty;
        if (!query.TryGetValue("q", out var values)) return true;
        // Validate the original string as well as the trimmed query so a control character is never silently accepted.
        var value = values[0] ?? string.Empty;
        if (!SecurityEventContract.IsBoundedText("[" + value + "]", SoftwareCatalogContract.MaximumQueryLength + 2)) return false;
        search = value.Trim();
        return true;
    }

    private static bool TryReadPage(IQueryCollection query, string? filter, out int offset, out int limit)
    {
        offset = 0;
        limit = SoftwareCatalogContract.DefaultPageSize;
        foreach (var (key, values) in query)
        {
            if (values.Count != 1) return false;
            if (key == filter) continue;
            if (!int.TryParse(values[0], NumberStyles.None, CultureInfo.InvariantCulture, out var value)) return false;
            switch (key)
            {
                case "offset" when value <= SoftwareCatalogContract.MaximumOffset: offset = value; break;
                case "limit" when value is >= 1 and <= SoftwareCatalogContract.MaxPageSize: limit = value; break;
                default: return false;
            }
        }
        return true;
    }

    private static async Task<IResult> ReadAsync<T>(ILogger logger, Func<Task<T>> read)
    {
        try
        {
            return Results.Ok(await read());
        }
        catch (Exception error) when (error is SqliteException or JsonException or InvalidDataException or FormatException or
                                      OverflowException or ArgumentOutOfRangeException)
        {
            logger.LogWarning("Software catalog read failed ({ErrorType}).", error.GetType().Name);
            return Results.StatusCode(StatusCodes.Status500InternalServerError);
        }
    }
}
