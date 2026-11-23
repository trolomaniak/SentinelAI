using System.Globalization;
using SentinelAI.Contracts.Monitoring;
using SentinelAI.Core.Persistence;

namespace SentinelAI.Core;

internal static class MonitoringCoverageEndpoints
{
    public const string Route = "/api/admin/monitoring-coverage";
    private const int DefaultLimit = 50;

    internal static void MapMonitoringCoverageEndpoints(this WebApplication app)
    {
        var group = app.MapGroup(Route).RequireAuthorization();
        group.MapGet("", async (HttpContext context, MonitoringCoverageReadStore coverage, CancellationToken cancellationToken) =>
        {
            var query = context.Request.Query;
            if (!TryPage(query, out var offset, out var limit)) return Results.BadRequest();
            var issuesOnly = false;
            if (query.TryGetValue("issuesOnly", out var issues))
            {
                if (issues.Count != 1 || issues[0] is not ("true" or "false")) return Results.BadRequest();
                issuesOnly = issues[0] == "true";
            }
            return Results.Ok(await coverage.ListAsync(offset, limit, issuesOnly, cancellationToken));
        });

        group.MapGet("/{endpointId:guid}", async (Guid endpointId, MonitoringCoverageReadStore coverage, CancellationToken cancellationToken) =>
        {
            var detail = await coverage.FindAsync(endpointId, cancellationToken);
            return detail is null ? Results.NotFound() : Results.Ok(detail);
        });

        group.MapGet("/{endpointId:guid}/gaps", async (Guid endpointId, HttpContext context, MonitoringCoverageReadStore coverage,
            CancellationToken cancellationToken) =>
        {
            if (!TryPage(context.Request.Query, out var offset, out var limit)) return Results.BadRequest();
            var page = await coverage.ListGapsAsync(endpointId, offset, limit, cancellationToken);
            return page is null ? Results.NotFound() : Results.Ok(page);
        });
    }

    private static bool TryPage(IQueryCollection query, out int offset, out int limit)
    {
        limit = DefaultLimit;
        return TryInteger(query, "offset", 0, out offset) && TryInteger(query, "limit", DefaultLimit, out limit) &&
            offset is >= 0 and <= MonitoringCoverageContract.MaximumOffset &&
            limit is >= 1 and <= MonitoringCoverageContract.MaximumPageSize;
    }

    private static bool TryInteger(IQueryCollection query, string name, int fallback, out int value)
    {
        value = fallback;
        return !query.TryGetValue(name, out var parameter) ||
            parameter.Count == 1 && int.TryParse(parameter[0], NumberStyles.None, CultureInfo.InvariantCulture, out value);
    }
}
