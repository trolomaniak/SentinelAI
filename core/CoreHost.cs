using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.FileProviders;
using SentinelAI.Contracts.Enrollment;
using SentinelAI.Contracts.Heartbeat;
using SentinelAI.Contracts.Inventory;
using SentinelAI.Core.Persistence;
using SentinelAI.Rules;

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
        builder.Services.AddSingleton<DeviceReadStore>();
        builder.Services.AddSingleton<EnrollmentStore>();
        builder.Services.AddSingleton<InventoryStore>();
        builder.Services.AddSingleton(RuleEngine.CreateDefault());
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
            options.AddPolicy("heartbeat", context => RateLimitPartition.GetFixedWindowLimiter(
                context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = 30,
                    Window = TimeSpan.FromMinutes(1),
                    QueueLimit = 0,
                    AutoReplenishment = true
                }));
            options.AddPolicy("enrollment", context => RateLimitPartition.GetFixedWindowLimiter(
                context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = 20,
                    Window = TimeSpan.FromMinutes(1),
                    QueueLimit = 0,
                    AutoReplenishment = true
                }));
            options.AddPolicy("inventory", context => RateLimitPartition.GetFixedWindowLimiter(
                context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = 30,
                    Window = TimeSpan.FromMinutes(1),
                    QueueLimit = 0,
                    AutoReplenishment = true
                }));
        });

        var app = builder.Build();
        var fallbackAdmin = new AdminRecord(string.Empty, string.Empty);
        var fallbackHash = app.Services.GetRequiredService<IPasswordHasher<AdminRecord>>()
            .HashPassword(fallbackAdmin, Convert.ToHexString(RandomNumberGenerator.GetBytes(32)));

        var dashboardDirectory = Path.Combine(AppContext.BaseDirectory, "dashboard");
        if (Directory.Exists(dashboardDirectory))
        {
            var dashboardFiles = new PhysicalFileProvider(dashboardDirectory);
            app.Lifetime.ApplicationStopped.Register(dashboardFiles.Dispose);
            app.UseDefaultFiles(new DefaultFilesOptions { FileProvider = dashboardFiles });
            app.UseStaticFiles(new StaticFileOptions
            {
                FileProvider = dashboardFiles,
                OnPrepareResponse = context =>
                {
                    context.Context.Response.Headers["Content-Security-Policy"] =
                        "default-src 'self'; script-src 'self'; style-src 'self'; " +
                        "img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";
                    context.Context.Response.Headers["X-Content-Type-Options"] = "nosniff";
                }
            });
        }

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
                EnrollmentStore enrollments,
                CancellationToken cancellationToken) =>
            {
                if (request is null || request.InstallationId == Guid.Empty)
                {
                    return Results.BadRequest();
                }

                DeviceRecord? device;
                var authorization = context.Request.Headers.Authorization.ToString();
                if (!string.IsNullOrEmpty(authorization))
                {
                    if (!IsLocalOrHttps(context))
                    {
                        return Results.StatusCode(StatusCodes.Status403Forbidden);
                    }

                    if (!TryReadAgentCredential(authorization, out var endpointId, out var credential) ||
                        !await enrollments.AuthenticateAsync(
                            request.InstallationId, endpointId, credential, cancellationToken))
                    {
                        return Results.Unauthorized();
                    }

                    device = await devices.RecordEnrolledHeartbeatAsync(request.InstallationId, cancellationToken);
                }
                else
                {
                    if (!IsLoopback(context.Connection.RemoteIpAddress))
                    {
                        return Results.StatusCode(StatusCodes.Status403Forbidden);
                    }

                    device = await devices.RecordHeartbeatAsync(request.InstallationId, cancellationToken);
                    if (device is null)
                    {
                        return Results.Unauthorized();
                    }
                }

                return Results.Ok(new HeartbeatResponse(
                    device.InstallationId,
                    device.LastSeenUtc,
                    device.HealthStatus));
            })
            .AllowAnonymous()
            .RequireRateLimiting("heartbeat");

        app.MapPost("/api/agent/enroll", async (
                EnrollmentRequest? request,
                HttpContext context,
                EnrollmentStore enrollments,
                CancellationToken cancellationToken) =>
            {
                context.Response.Headers.CacheControl = "no-store";
                if (!IsLocalOrHttps(context))
                {
                    return Results.StatusCode(StatusCodes.Status403Forbidden);
                }

                if (request is null || request.InstallationId == Guid.Empty)
                {
                    return Results.BadRequest();
                }

                var attempt = await enrollments.TryEnrollAsync(request, cancellationToken);
                return attempt.Outcome switch
                {
                    EnrollmentOutcome.Enrolled => Results.Ok(attempt.Response),
                    EnrollmentOutcome.AlreadyEnrolled => Results.Conflict(),
                    _ => Results.Unauthorized()
                };
            })
            .AllowAnonymous()
            .RequireRateLimiting("enrollment");

        app.MapPost("/api/agent/inventory", async (
                InventoryReport? report,
                HttpContext context,
                InventoryStore inventories,
                EnrollmentStore enrollments,
                CancellationToken cancellationToken) =>
            {
                if (!IsLocalOrHttps(context))
                {
                    return Results.StatusCode(StatusCodes.Status403Forbidden);
                }

                if (!IsValidInventory(report))
                {
                    return Results.BadRequest();
                }

                var authorization = context.Request.Headers.Authorization.ToString();
                if (!TryReadAgentCredential(authorization, out var endpointId, out var credential) ||
                    endpointId != report!.EndpointId)
                {
                    return Results.Unauthorized();
                }

                if (!await enrollments.AuthenticateEndpointAsync(
                        endpointId, credential, cancellationToken))
                {
                    return Results.Unauthorized();
                }

                await inventories.RecordLatestAsync(report, cancellationToken);
                return Results.NoContent();
            })
            .AllowAnonymous()
            .RequireRateLimiting("inventory")
            .WithMetadata(new RequestSizeLimitAttribute(16 * 1024));

        app.MapPost("/api/auth/login", async (
                LoginRequest? request,
                AdminStore admins,
                IPasswordHasher<AdminRecord> passwordHasher,
                HttpContext context,
                CancellationToken cancellationToken) =>
            {
                context.Response.Headers.CacheControl = "no-store";
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

        app.MapGet("/api/admin/devices", async (
                HttpContext context,
                DeviceReadStore devices,
                CancellationToken cancellationToken) =>
            {
                context.Response.Headers.CacheControl = "no-store";
                if (!IsLocalOrHttps(context))
                {
                    return Results.StatusCode(StatusCodes.Status403Forbidden);
                }

                return Results.Ok(await devices.ListAsync(cancellationToken));
            })
            .RequireAuthorization();

        app.MapGet("/api/admin/devices/{endpointId:guid}", async (
                Guid endpointId,
                HttpContext context,
                DeviceReadStore devices,
                CancellationToken cancellationToken) =>
            {
                context.Response.Headers.CacheControl = "no-store";
                if (!IsLocalOrHttps(context))
                {
                    return Results.StatusCode(StatusCodes.Status403Forbidden);
                }

                var device = await devices.FindAsync(endpointId, cancellationToken);
                return device is null ? Results.NotFound() : Results.Ok(device);
            })
            .RequireAuthorization();

        app.MapGet("/api/admin/devices/{endpointId:guid}/alerts", async (
                Guid endpointId,
                HttpContext context,
                DeviceReadStore devices,
                InventoryStore inventories,
                RuleEngine rules,
                CancellationToken cancellationToken) =>
            {
                context.Response.Headers.CacheControl = "no-store";
                if (!IsLocalOrHttps(context))
                {
                    return Results.StatusCode(StatusCodes.Status403Forbidden);
                }

                if (await devices.FindAsync(endpointId, cancellationToken) is null)
                {
                    return Results.NotFound();
                }

                var inventory = await inventories.FindLatestAsync(endpointId, cancellationToken);
                // Derive current findings from the newest accepted snapshot. Keeping the
                // observation time makes stale data visible and repeat reads deterministic.
                return Results.Ok(new
                {
                    endpointId,
                    observedUtc = inventory?.CollectedUtc,
                    alerts = inventory is null
                        ? Array.Empty<SecurityAlert>()
                        : rules.Evaluate(EndpointState.FromInventory(inventory))
                });
            })
            .RequireAuthorization();

        app.MapPost("/api/admin/enrollment-tokens", async (
                HttpContext context,
                EnrollmentStore enrollments,
                CancellationToken cancellationToken) =>
            {
                context.Response.Headers.CacheControl = "no-store";
                if (!IsLocalOrHttps(context))
                {
                    return Results.StatusCode(StatusCodes.Status403Forbidden);
                }

                return Results.Ok(await enrollments.IssueTokenAsync(cancellationToken: cancellationToken));
            })
            .RequireAuthorization();

        return app;
    }

    private sealed record LoginRequest(string? Username, string? Password);

    private static bool IsValidInventory(InventoryReport? report)
    {
        if (report is null || report.EndpointId == Guid.Empty ||
            report.CollectedUtc.Offset != TimeSpan.Zero ||
            report.CollectedUtc <= DateTimeOffset.UnixEpoch ||
            report.CollectedUtc > DateTimeOffset.UtcNow.AddMinutes(5) ||
            !IsValidText(report.AgentVersion, 64) ||
            !IsValidText(report.Hostname, 255) ||
            !IsValidText(report.OsName, 128) ||
            !IsValidText(report.OsVersion, 128) ||
            !IsValidText(report.Architecture, 32) ||
            report.Cpu is null ||
            report.Cpu.LogicalProcessorCount is < 1 or > 1024 ||
            report.Cpu.Model is not null && !IsValidText(report.Cpu.Model, 256) ||
            report.InstalledRamBytes is <= 0 ||
            report.Disks is null or { Count: > 32 } ||
            report.SecurityPosture is null)
        {
            return false;
        }

        var configuration = report.SecurityPosture.Configuration;
        if (configuration is not null &&
            (configuration.AdminConsentPromptBehavior is < 0 or > 5 ||
             configuration.RdpSecurityLayer is < 0 or > 2 ||
             configuration.RdpMinimumEncryptionLevel is < 1 or > 4))
        {
            return false;
        }

        return report.Disks.All(disk =>
            disk is not null &&
            IsValidText(disk.Name, 256) &&
            disk.TotalBytes > 0 &&
            disk.AvailableBytes >= 0 &&
            disk.AvailableBytes <= disk.TotalBytes);
    }

    private static bool IsValidText(string? value, int maxLength) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= maxLength &&
        !value.Any(char.IsControl);

    private static bool IsLocalOrHttps(HttpContext context) =>
        context.Request.IsHttps || IsLoopback(context.Connection.RemoteIpAddress);

    private static bool IsLoopback(IPAddress? address) =>
        address is not null &&
        (IPAddress.IsLoopback(address) ||
         address.IsIPv4MappedToIPv6 && IPAddress.IsLoopback(address.MapToIPv4()));

    private static bool TryReadAgentCredential(
        string authorization,
        out Guid endpointId,
        out string credential)
    {
        endpointId = Guid.Empty;
        credential = string.Empty;
        if (!AuthenticationHeaderValue.TryParse(authorization, out var header) ||
            !string.Equals(header.Scheme, "SentinelAgent", StringComparison.OrdinalIgnoreCase) ||
            header.Parameter is null)
        {
            return false;
        }

        var separator = header.Parameter.IndexOf('.');
        if (separator < 0 ||
            !Guid.TryParseExact(header.Parameter.AsSpan(0, separator), "D", out endpointId))
        {
            return false;
        }

        credential = header.Parameter[(separator + 1)..];
        return credential.Length == 64;
    }
}
