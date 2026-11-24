using System.Text.Json;
using Microsoft.Data.Sqlite;
using SentinelAI.Core.Persistence;

namespace SentinelAI.Core;

internal static class OperationsOverviewEndpoints
{
    public const string Route = "/api/admin/overview";

    internal static void MapOperationsOverviewEndpoints(this WebApplication app)
    {
        app.MapGet(Route, async (OperationsOverviewReadStore overview, CancellationToken cancellationToken) =>
        {
            try
            {
                return Results.Ok(await overview.ReadAsync(cancellationToken));
            }
            catch (Exception error) when (error is SqliteException or JsonException or InvalidDataException or FormatException)
            {
                app.Logger.LogWarning("Operations overview read failed ({ErrorType}).", error.GetType().Name);
                return Results.StatusCode(StatusCodes.Status500InternalServerError);
            }
        }).RequireAuthorization();
    }
}
