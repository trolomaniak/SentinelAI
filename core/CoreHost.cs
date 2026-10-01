using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using SentinelAI.Contracts.Heartbeat;
using SentinelAI.Core.Persistence;

namespace SentinelAI.Core;

public static class CoreHost
{
    public static WebApplication Build(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        // An explicit URL or Kestrel configuration can enable HTTPS or another interface.
        // Without one, the local API is reachable only from this machine.
        if (string.IsNullOrWhiteSpace(builder.Configuration["urls"]))
        {
            builder.WebHost.UseUrls("http://127.0.0.1:5000");
        }

        builder.Logging.ClearProviders();
        builder.Logging.AddJsonConsole();

        builder.Services.Configure<PasswordHasherOptions>(options =>
        {
            options.IterationCount = 310_000;
        });
        builder.Services.AddSingleton<IPasswordHasher<AdminRecord>, PasswordHasher<AdminRecord>>();
        builder.Services.AddSingleton<AdminStore>();
        builder.Services.AddSingleton<DeviceStore>();
        builder.Services.AddHostedService<AdminInitializationService>();

        builder.Services.AddDataProtection()
            .UseEphemeralDataProtectionProvider()
            .AddKeyManagementOptions(options => options.XmlRepository = new InMemoryKeyRepository());
        builder.Services.AddAuthentication(BearerTokenDefaults.AuthenticationScheme)
            .AddBearerToken(options =>
            {
                options.BearerTokenExpiration = TimeSpan.FromMinutes(15);
                options.RefreshTokenExpiration = TimeSpan.FromMinutes(15);
            });
        builder.Services.AddAuthorization();
        builder.Services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.AddFixedWindowLimiter("login", policy =>
            {
                policy.PermitLimit = 5;
                policy.Window = TimeSpan.FromMinutes(1);
                policy.QueueLimit = 0;
            });
            options.AddFixedWindowLimiter("heartbeat", policy =>
            {
                policy.PermitLimit = 30;
                policy.Window = TimeSpan.FromMinutes(1);
                policy.QueueLimit = 0;
            });
        });

        var app = builder.Build();
        var fallbackAdmin = new AdminRecord(string.Empty, string.Empty);
        var fallbackHash = app.Services.GetRequiredService<IPasswordHasher<AdminRecord>>()
            .HashPassword(fallbackAdmin, Convert.ToHexString(RandomNumberGenerator.GetBytes(32)));

        app.UseRouting();
        app.UseRateLimiter();
        app.UseAuthentication();
        app.UseAuthorization();

        app.MapGet("/api/health", () => Results.Ok(new { status = "healthy" }))
            .AllowAnonymous();

        app.MapPost("/api/agent/heartbeat", async (
                HeartbeatRequest? request,
                HttpContext context,
                DeviceStore devices,
                CancellationToken cancellationToken) =>
            {
                var remoteAddress = context.Connection.RemoteIpAddress;
                if (remoteAddress is null ||
                    !IPAddress.IsLoopback(remoteAddress) &&
                    !(remoteAddress.IsIPv4MappedToIPv6 && IPAddress.IsLoopback(remoteAddress.MapToIPv4())))
                {
                    return Results.StatusCode(StatusCodes.Status403Forbidden);
                }

                if (request is null || request.InstallationId == Guid.Empty)
                {
                    return Results.BadRequest();
                }

                var device = await devices.RecordHeartbeatAsync(request.InstallationId, cancellationToken);
                return Results.Ok(new HeartbeatResponse(
                    device.InstallationId,
                    device.LastSeenUtc,
                    device.HealthStatus));
            })
            .AllowAnonymous()
            .RequireRateLimiting("heartbeat");

        app.MapPost("/api/auth/login", async (
                LoginRequest? request,
                AdminStore admins,
                IPasswordHasher<AdminRecord> passwordHasher,
                HttpContext context,
                CancellationToken cancellationToken) =>
            {
                var admin = await admins.FindByUsernameAsync(request?.Username ?? string.Empty, cancellationToken);
                var password = request?.Password ?? string.Empty;
                var verification = passwordHasher.VerifyHashedPassword(
                    admin ?? fallbackAdmin,
                    admin?.PasswordHash ?? fallbackHash,
                    password);
                if (admin is null || string.IsNullOrEmpty(password) || verification == PasswordVerificationResult.Failed)
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    return;
                }

                var identity = new ClaimsIdentity(
                    [new Claim(ClaimTypes.NameIdentifier, admin.Username), new Claim(ClaimTypes.Name, admin.Username)],
                    BearerTokenDefaults.AuthenticationScheme);
                await context.SignInAsync(
                    BearerTokenDefaults.AuthenticationScheme,
                    new ClaimsPrincipal(identity));
            })
            .AllowAnonymous()
            .RequireRateLimiting("login");

        app.MapGet("/api/admin/me", (ClaimsPrincipal user) =>
                Results.Ok(new { username = user.Identity?.Name, role = "administrator" }))
            .RequireAuthorization();

        return app;
    }

    private sealed record LoginRequest(string? Username, string? Password);
}
