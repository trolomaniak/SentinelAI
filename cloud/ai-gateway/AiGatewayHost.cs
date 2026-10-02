using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SentinelAI.Contracts.Ai;

namespace SentinelAI.AiGateway;

public static class AiGatewayHost
{
    private static readonly JsonSerializerOptions WireJson = new(JsonSerializerDefaults.Web);

    public static WebApplication Build(string[] args, Action<WebApplicationBuilder>? configureBuilder = null)
    {
        var builder = WebApplication.CreateBuilder(args);
        builder.Logging.ClearProviders();
        builder.Logging.AddJsonConsole();
        configureBuilder?.Invoke(builder);
        if (string.IsNullOrWhiteSpace(builder.Configuration["urls"]))
        {
            builder.WebHost.UseUrls("http://127.0.0.1:5200");
        }
        builder.WebHost.ConfigureKestrel(options => options.Limits.MaxRequestBodySize = AiContract.MaximumRequestBytes);
        // Only the gateway process reads this secret; never bind it from client requests or general configuration.
        var providerKey = Environment.GetEnvironmentVariable("SENTINELAI_AI_PROVIDER_API_KEY");
        var settings = AiGatewayOptions.Load(builder.Configuration, !string.IsNullOrWhiteSpace(providerKey));
        builder.Services.AddSingleton(settings);
        builder.Services.TryAddSingleton<IAiExplanationProvider>(_ => new OpenAiExplanationProvider(settings, providerKey));
        builder.Services.AddSingleton<ProviderSlots>();
        builder.Services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
                RateLimitPartition.GetFixedWindowLimiter(context.Connection.RemoteIpAddress?.ToString() ?? "unknown", _ =>
                    new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = 30,
                        Window = TimeSpan.FromMinutes(1),
                        QueueLimit = 0,
                        AutoReplenishment = true
                    }));
            options.AddFixedWindowLimiter("client", limiter =>
            {
                // This gateway currently accepts one configured Core credential, so this is its shared client budget.
                limiter.PermitLimit = 12;
                limiter.Window = TimeSpan.FromMinutes(1);
                limiter.QueueLimit = 0;
                limiter.AutoReplenishment = true;
            });
        });
        var app = builder.Build();
        app.Use(async (context, next) =>
        {
            context.Response.Headers.CacheControl = "no-store";
            context.Response.Headers["X-Content-Type-Options"] = "nosniff";
            if (!context.Request.IsHttps && (context.Connection.RemoteIpAddress is null ||
                !IPAddress.IsLoopback(context.Connection.RemoteIpAddress)))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return;
            }
            if (!Authenticate(context, settings))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return;
            }
            await next(context);
        });
        app.UseRouting();
        app.UseRateLimiter();
        app.MapPost("/api/ai/alerts/explain", ExplainAsync).RequireRateLimiting("client");
        return app;
    }

    private static bool Authenticate(HttpContext context, AiGatewayOptions settings)
    {
        var authorization = context.Request.Headers.Authorization;
        if (authorization.Count != 1 || authorization[0] is not { } header ||
            !header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) return false;
        var credential = header[7..];
        if (credential.Length != 43 || !credential.All(character =>
            char.IsAsciiLetterOrDigit(character) || character is '_' or '-')) return false;
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(credential));
        return CryptographicOperations.FixedTimeEquals(digest, settings.ClientCredentialDigest);
    }

    private static async Task<IResult> ExplainAsync(HttpContext context, AiGatewayOptions settings,
        IAiExplanationProvider provider, ProviderSlots slots)
    {
        if (!context.Request.HasJsonContentType()) return Results.StatusCode(StatusCodes.Status415UnsupportedMediaType);
        if (context.Request.ContentLength > AiContract.MaximumRequestBytes)
            return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
        var buffer = new byte[AiContract.MaximumRequestBytes + 1];
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
        catch (OperationCanceledException)
        {
            return Results.StatusCode(StatusCodes.Status408RequestTimeout);
        }
        if (length > AiContract.MaximumRequestBytes) return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
        AiAlertContext? alert;
        try
        {
            using var json = JsonDocument.Parse(buffer.AsMemory(0, length), new JsonDocumentOptions { MaxDepth = 8 });
            if (!AiContract.TryReadContext(json.RootElement, out alert) || alert is null) return Results.BadRequest();
        }
        catch (JsonException)
        {
            return Results.BadRequest();
        }
        if (!await slots.Semaphore.WaitAsync(0, context.RequestAborted))
            return Results.StatusCode(StatusCodes.Status429TooManyRequests);
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted);
            timeout.CancelAfter(settings.Timeout);
            var analysis = await provider.ExplainAsync(alert, timeout.Token).WaitAsync(timeout.Token);
            if (!AiContract.IsValidAnalysis(analysis)) return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
            var body = JsonSerializer.SerializeToUtf8Bytes(new AiExplanationResponse(AiContract.AssistiveLabel, analysis!), WireJson);
            if (body.Length > AiContract.MaximumResponseBytes) return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
            return Results.Bytes(body, "application/json");
        }
        catch (Exception)
        {
            // Provider exceptions and content are intentionally never echoed or logged; monitoring is independent.
            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
        }
        finally
        {
            slots.Semaphore.Release();
        }
    }

    private sealed class ProviderSlots : IDisposable
    {
        public SemaphoreSlim Semaphore { get; } = new(4, 4);
        public void Dispose() => Semaphore.Dispose();
    }
}
