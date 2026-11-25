using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SentinelAI.Contracts.RiskHistory;

namespace SentinelAI.Core.History;

internal static class RiskHistoryEndpoints
{
    internal const string Route = "/api/admin/risk-history";

    internal static void MapRiskHistoryEndpoints(this WebApplication app)
    {
        var group = app.MapGroup(Route).RequireAuthorization();
        group.MapGet("", (HttpContext context, RiskHistoryStore history, CancellationToken cancellationToken) =>
            ReadAsync(app.Logger, history, null, context.Request.Query, cancellationToken));
        group.MapGet("/{endpointId:guid}", (Guid endpointId, HttpContext context, RiskHistoryStore history, CancellationToken cancellationToken) =>
            ReadAsync(app.Logger, history, endpointId, context.Request.Query, cancellationToken));
    }

    private static async Task<IResult> ReadAsync(ILogger logger, RiskHistoryStore history, Guid? endpointId,
        IQueryCollection query, CancellationToken cancellationToken)
    {
        var hours = 168;
        if (endpointId == Guid.Empty || (query.Count != 0 &&
            (query.Count != 1 || !query.TryGetValue("hours", out var values) || values.Count != 1 ||
            !int.TryParse(values[0], NumberStyles.None, CultureInfo.InvariantCulture, out hours) ||
            !RiskHistoryContract.PeriodHours.Contains(hours))))
            return Results.BadRequest();

        try
        {
            return Results.Ok(await history.ReadAsync(endpointId, hours, cancellationToken));
        }
        catch (Exception error) when (error is SqliteException or JsonException or InvalidDataException or FormatException or ArgumentOutOfRangeException)
        {
            logger.LogWarning("Risk history read failed ({ErrorType}).", error.GetType().Name);
            return Results.StatusCode(StatusCodes.Status500InternalServerError);
        }
    }
}
