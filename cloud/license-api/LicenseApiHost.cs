using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace SentinelAI.LicenseApi;

public static class LicenseApiHost
{
    private const int MaximumRequestBytes = 4096;

    public static WebApplication Build(string[] args, Action<WebApplicationBuilder>? configureBuilder = null)
    {
        var builder = WebApplication.CreateBuilder(args);
        if (string.IsNullOrWhiteSpace(builder.Configuration["urls"]))
        {
            builder.WebHost.UseUrls("http://127.0.0.1:5100");
        }
        builder.WebHost.ConfigureKestrel(options => options.Limits.MaxRequestBodySize = MaximumRequestBytes);
        builder.Logging.ClearProviders();
        builder.Logging.AddJsonConsole();

        var settings = LicenseApiOptions.Load(builder.Configuration);
        var issuer = new LeaseIssuer(settings); // Required key validation must fail at startup, not on the first request.
        builder.Services.AddSingleton(settings);
        builder.Services.AddSingleton<LeaseIssuer>(_ => issuer);
        builder.Services.TryAddSingleton<TimeProvider>(TimeProvider.System);
        builder.Services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.AddPolicy("lease", context => RateLimitPartition.GetFixedWindowLimiter(
                context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = 30,
                    Window = TimeSpan.FromMinutes(1),
                    QueueLimit = 0,
                    AutoReplenishment = true
                }));
        });
        configureBuilder?.Invoke(builder);
        WebApplication app;
        try
        {
            app = builder.Build();
        }
        catch
        {
            issuer.Dispose();
            throw;
        }
        _ = app.Services.GetRequiredService<LeaseIssuer>();
        app.Use(async (context, next) =>
        {
            context.Response.Headers.CacheControl = "no-store";
            context.Response.Headers["X-Content-Type-Options"] = "nosniff";
            if (!context.Request.IsHttps && (context.Connection.RemoteIpAddress is null
                || !IPAddress.IsLoopback(context.Connection.RemoteIpAddress)))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return;
            }
            await next(context);
        });
        app.UseRouting();
        app.UseRateLimiter();
        app.MapPost("/api/licenses/lease", IssueLeaseAsync).RequireRateLimiting("lease");
        return app;
    }

    private static async Task<IResult> IssueLeaseAsync(HttpContext context, LicenseApiOptions options,
        LeaseIssuer issuer, TimeProvider clock)
    {
        if (!context.Request.HasJsonContentType())
        {
            return Results.StatusCode(StatusCodes.Status415UnsupportedMediaType);
        }
        if (context.Request.ContentLength > MaximumRequestBytes)
        {
            return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
        }
        var buffer = new byte[MaximumRequestBytes + 1];
        var length = 0;
        try
        {
            while (length < buffer.Length)
            {
                var read = await context.Request.Body.ReadAsync(buffer.AsMemory(length), context.RequestAborted);
                if (read == 0) break;
                length += read;
            }
        }
        catch (BadHttpRequestException)
        {
            return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
        }
        if (length > MaximumRequestBytes)
        {
            return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
        }

        Guid organizationId;
        Guid installationId;
        try
        {
            using var json = JsonDocument.Parse(buffer.AsMemory(0, length), new JsonDocumentOptions { MaxDepth = 8 });
            var root = json.RootElement;
            if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Count() != 2
                || !root.TryGetProperty("organizationId", out var organization)
                || !root.TryGetProperty("installationId", out var installation)
                || organization.ValueKind != JsonValueKind.String || !organization.TryGetGuid(out organizationId)
                || installation.ValueKind != JsonValueKind.String || !installation.TryGetGuid(out installationId)
                || organizationId == Guid.Empty || installationId == Guid.Empty)
            {
                return Results.BadRequest();
            }
        }
        catch (JsonException)
        {
            return Results.BadRequest();
        }

        var authorization = context.Request.Headers.Authorization;
        if (authorization.Count != 1 || !authorization[0]!.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return Results.Unauthorized();
        }
        var credential = authorization[0]![7..];
        if (credential.Length != 43 || !credential.All(character =>
            char.IsAsciiLetterOrDigit(character) || character is '_' or '-'))
        {
            return Results.Unauthorized();
        }
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(credential));
        LicenseEntitlement? matched = null;
        foreach (var grant in options.Entitlements)
        {
            var credentialMatches = CryptographicOperations.FixedTimeEquals(digest, grant.CredentialDigest);
            if (credentialMatches && grant.OrganizationId == organizationId && grant.InstallationId == installationId)
            {
                matched = grant;
            }
        }
        if (matched is null)
        {
            return Results.Unauthorized();
        }
        return Results.Ok(issuer.Issue(matched, clock.GetUtcNow()));
    }
}
