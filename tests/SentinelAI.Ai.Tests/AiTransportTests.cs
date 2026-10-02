using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using SentinelAI.AiGateway;
using SentinelAI.Contracts.Ai;
using SentinelAI.Core;

static class AiTransportTests
{
    internal static async Task RunAsync()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"sentinelai-ai-transport-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var credentialPath = Path.Combine(directory, "gateway-credential");
            await File.WriteAllTextAsync(credentialPath, Test.GatewayCredential);
            if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(credentialPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            var coreOptions = AiOptions.Load(new ConfigurationBuilder().AddInMemoryCollection(
                new Dictionary<string, string?>
                {
                    ["SentinelAI:Ai:GatewayUrl"] = "http://127.0.0.1:1",
                    ["SentinelAI:Ai:GatewayCredentialPath"] = credentialPath,
                    ["SentinelAI:Ai:TimeoutSeconds"] = "1"
                }).Build());
            await GatewayClientAsync(coreOptions);
            var providerOptions = AiGatewayOptions.Load(new ConfigurationBuilder().AddInMemoryCollection(
                new Dictionary<string, string?>
                {
                    ["SentinelAI:AiGateway:ClientCredentialSha256"] = Test.GatewayDigest,
                    ["SentinelAI:AiGateway:Model"] = "synthetic-test-model",
                    ["SentinelAI:AiGateway:TimeoutSeconds"] = "1"
                }).Build(), providerKeyPresent: true);
            await ProviderAsync(providerOptions);
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    private static async Task GatewayClientAsync(AiOptions options)
    {
        var valid = JsonSerializer.Serialize(new AiExplanationResponse(AiContract.AssistiveLabel, Test.Analysis()), Test.Json);
        var handler = new StubHandler(async (request, cancellationToken) =>
        {
            Test.Ensure(request.Method == HttpMethod.Post
                && request.RequestUri?.ToString() == "http://127.0.0.1:1/api/ai/alerts/explain",
                "Core's AI transport used a caller-selected method or destination.");
            Test.Ensure(request.Headers.Authorization?.Scheme == "Bearer"
                && request.Headers.Authorization.Parameter == Test.GatewayCredential,
                "Core's AI transport did not authenticate only to the configured gateway.");
            Test.Ensure(request.Headers.Accept.Any(value => value.MediaType == "application/json"),
                "Core's AI transport did not request structured JSON.");
            using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(cancellationToken));
            Test.Ensure(AiContract.TryReadContext(body.RootElement, out _)
                && !body.RootElement.GetRawText().Contains(Test.GatewayCredential, StringComparison.Ordinal),
                "Core's AI transport sent an invalid context or embedded its credential in telemetry.");
            return Reply(valid);
        });
        using (var http = new HttpClient(handler))
        using (var client = new AiGatewayClient(options, http))
            Test.Ensure((await client.ExplainAsync(Test.Context(), CancellationToken.None))?.Label == AiContract.AssistiveLabel,
                "Core's AI transport did not accept a valid structured gateway response.");

        var extra = JsonSerializer.SerializeToNode(new AiExplanationResponse(AiContract.AssistiveLabel, Test.Analysis()), Test.Json)!.AsObject();
        extra["actions"] = new JsonArray("deleteFile", "isolateHost", "disableAccount");
        var duplicate = valid.Replace("\"label\":", "\"label\":\"AI assistive analysis\",\"label\":", StringComparison.Ordinal);
        foreach (var invalid in new[] { "not JSON", "null", "{}", extra.ToJsonString(), duplicate,
            valid.Replace(AiContract.AssistiveLabel, "Deterministic result", StringComparison.Ordinal),
            JsonSerializer.Serialize(new AiExplanationResponse(AiContract.AssistiveLabel,
                Test.Analysis() with { Confidence = "absolute" }), Test.Json), new string('x', AiContract.MaximumResponseBytes + 1) })
        {
            using var http = new HttpClient(new StubHandler((_, _) => Task.FromResult(Reply(invalid))));
            using var client = new AiGatewayClient(options, http);
            Test.Ensure(await client.ExplainAsync(Test.Context(), CancellationToken.None) is null,
                "Core's AI transport accepted an invalid, duplicated, action-bearing, or oversized response.");
        }
        foreach (var status in new[] { HttpStatusCode.Unauthorized, HttpStatusCode.BadGateway, HttpStatusCode.Redirect })
        {
            using var http = new HttpClient(new StubHandler((_, _) => Task.FromResult(Reply(valid, status))));
            using var client = new AiGatewayClient(options, http);
            Test.Ensure(await client.ExplainAsync(Test.Context(), CancellationToken.None) is null,
                "Core's AI transport accepted an unauthorized/error/redirect response.");
        }
        using (var http = new HttpClient(new StubHandler((_, _) => Task.FromResult(Reply(valid, mediaType: "text/plain")))))
        using (var client = new AiGatewayClient(options, http))
            Test.Ensure(await client.ExplainAsync(Test.Context(), CancellationToken.None) is null,
                "Core's AI transport accepted a non-JSON gateway response.");
        using (var http = new HttpClient(new StubHandler((_, _) => Task.FromResult(UnknownLengthReply(AiContract.MaximumResponseBytes + 1)))))
        using (var client = new AiGatewayClient(options, http))
            Test.Ensure(await client.ExplainAsync(Test.Context(), CancellationToken.None) is null,
                "Core's AI transport did not bound a response without Content-Length.");
        using (var http = new HttpClient(new StubHandler((_, _) => throw new HttpRequestException("synthetic-gateway-secret"))))
        using (var client = new AiGatewayClient(options, http))
            Test.Ensure(await client.ExplainAsync(Test.Context(), CancellationToken.None) is null,
                "Core's AI transport did not contain a network failure.");
        using (var http = new HttpClient(new StubHandler(async (_, cancellationToken) =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return Reply(valid);
        })))
        using (var client = new AiGatewayClient(options, http))
            Test.Ensure(await client.ExplainAsync(Test.Context(), CancellationToken.None) is null,
                "Core's AI transport did not bound an unavailable gateway.");
        using (var http = new HttpClient(new StubHandler((_, _) => Task.FromResult(Reply(valid)))))
        using (var client = new AiGatewayClient(options, http))
        using (var canceled = new CancellationTokenSource())
        {
            canceled.Cancel();
            await ExpectCancellationAsync(() => client.ExplainAsync(Test.Context(), canceled.Token));
        }
    }

    private static async Task ProviderAsync(AiGatewayOptions options)
    {
        const string providerKey = "synthetic-provider-key-for-tests";
        var analysis = JsonSerializer.Serialize(Test.Analysis(), Test.Json);
        var valid = ProviderReply(analysis);
        var handler = new StubHandler(async (request, cancellationToken) =>
        {
            Test.Ensure(request.Method == HttpMethod.Post
                && request.RequestUri?.ToString() == "https://api.openai.com/v1/chat/completions",
                "The model adapter used a context-selected provider destination.");
            Test.Ensure(request.Headers.Authorization?.Scheme == "Bearer"
                && request.Headers.Authorization.Parameter == providerKey,
                "The gateway did not restrict its provider credential to provider authorization.");
            var rawBody = await request.Content!.ReadAsStringAsync(cancellationToken);
            Test.Ensure(!rawBody.Contains(providerKey, StringComparison.Ordinal), "The model request embedded its provider key in content.");
            using var body = JsonDocument.Parse(rawBody);
            var root = body.RootElement;
            Test.Ensure(root.GetProperty("model").GetString() == "synthetic-test-model"
                && !root.TryGetProperty("tools", out _) && !root.TryGetProperty("functions", out _),
                "The model adapter changed configuration or enabled executable tools.");
            Test.Ensure(root.GetProperty("max_completion_tokens").GetInt32() == 4096
                && root.GetProperty("store").ValueKind == JsonValueKind.False,
                "The model adapter omitted its token budget or requested provider content storage.");
            var messages = root.GetProperty("messages");
            Test.Ensure(messages.GetArrayLength() == 2 && messages[0].GetProperty("role").GetString() == "system"
                && messages[1].GetProperty("role").GetString() == "user", "Model instructions and context were not separated.");
            var system = messages[0].GetProperty("content").GetString()!;
            Test.Ensure(system.Contains("data", StringComparison.OrdinalIgnoreCase)
                && system.Contains("instruction", StringComparison.OrdinalIgnoreCase)
                && system.Contains("deterministic", StringComparison.OrdinalIgnoreCase),
                "The model prompt omitted input-data and deterministic-detection guardrails.");
            using var context = JsonDocument.Parse(messages[1].GetProperty("content").GetString()!);
            Test.Ensure(AiContract.TryReadContext(context.RootElement, out var parsed)
                && parsed?.RuleId == Test.Context().RuleId, "The provider did not receive the minimized JSON context as data.");
            var format = root.GetProperty("response_format");
            var schema = format.GetProperty("json_schema");
            Test.Ensure(format.GetProperty("type").GetString() == "json_schema"
                && schema.GetProperty("strict").GetBoolean()
                && schema.GetProperty("schema").GetProperty("additionalProperties").ValueKind == JsonValueKind.False,
                "The model adapter did not require a strict structured response.");
            return Reply(valid);
        });
        using (var http = new HttpClient(handler))
        using (var provider = new OpenAiExplanationProvider(options, providerKey, http))
            Test.Ensure((await provider.ExplainAsync(Test.Context(), CancellationToken.None))?.Explanation == Test.Analysis().Explanation,
                "The model adapter did not accept a valid completed analysis.");

        var extra = JsonSerializer.SerializeToNode(Test.Analysis(), Test.Json)!.AsObject();
        extra["actions"] = new JsonArray("deleteFile", "isolateHost", "disableAccount");
        var duplicate = analysis.Replace("\"confidence\":", "\"confidence\":\"medium\",\"confidence\":", StringComparison.Ordinal);
        var refusal = JsonSerializer.Serialize(new
        {
            choices = new[] { new { finish_reason = "stop", message = new { content = analysis, refusal = "Refused" } } }
        });
        var multiple = JsonSerializer.Serialize(new
        {
            choices = new[]
            {
                new { finish_reason = "stop", message = new { content = analysis } },
                new { finish_reason = "stop", message = new { content = analysis } }
            }
        });
        var toolCall = JsonSerializer.Serialize(new
        {
            choices = new[] { new { finish_reason = "stop", message = new { content = analysis, tool_calls = new[] { new { name = "deleteFile" } } } } }
        });
        var functionCall = JsonSerializer.Serialize(new
        {
            choices = new[] { new { finish_reason = "stop", message = new { content = analysis, function_call = new { name = "isolateHost" } } } }
        });
        foreach (var invalid in new[] { "not JSON", "null", "{}", ProviderReply("not JSON"),
            ProviderReply(extra.ToJsonString()), ProviderReply(duplicate), ProviderReply(analysis, "length"),
            refusal, multiple, toolCall, functionCall, new string('x', 65537) })
        {
            using var http = new HttpClient(new StubHandler((_, _) => Task.FromResult(Reply(invalid))));
            using var provider = new OpenAiExplanationProvider(options, providerKey, http);
            Test.Ensure(await provider.ExplainAsync(Test.Context(), CancellationToken.None) is null,
                "The provider accepted malformed, truncated, refused, ambiguous, action-bearing, or oversized output.");
        }
        foreach (var status in new[] { HttpStatusCode.Unauthorized, HttpStatusCode.TooManyRequests,
            HttpStatusCode.ServiceUnavailable, HttpStatusCode.Redirect })
        {
            using var http = new HttpClient(new StubHandler((_, _) => Task.FromResult(Reply(valid, status))));
            using var provider = new OpenAiExplanationProvider(options, providerKey, http);
            Test.Ensure(await provider.ExplainAsync(Test.Context(), CancellationToken.None) is null,
                "The provider accepted a failed or redirect response.");
        }
        using (var http = new HttpClient(new StubHandler((_, _) => Task.FromResult(Reply(valid, mediaType: "text/plain")))))
        using (var provider = new OpenAiExplanationProvider(options, providerKey, http))
            Test.Ensure(await provider.ExplainAsync(Test.Context(), CancellationToken.None) is null,
                "The provider accepted a non-JSON response.");
        using (var http = new HttpClient(new StubHandler((_, _) => Task.FromResult(UnknownLengthReply(65537)))))
        using (var provider = new OpenAiExplanationProvider(options, providerKey, http))
            Test.Ensure(await provider.ExplainAsync(Test.Context(), CancellationToken.None) is null,
                "The provider did not bound a response without Content-Length.");
        using (var http = new HttpClient(new StubHandler(async (_, cancellationToken) =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return Reply(valid);
        })))
        using (var provider = new OpenAiExplanationProvider(options, providerKey, http))
            Test.Ensure(await provider.ExplainAsync(Test.Context(), CancellationToken.None) is null,
                "The provider request timeout was not bounded.");
        var unconfiguredHandler = new StubHandler((_, _) => throw new InvalidOperationException("No provider call is permitted."));
        using (var http = new HttpClient(unconfiguredHandler))
        using (var provider = new OpenAiExplanationProvider(options, null, http))
            Test.Ensure(await provider.ExplainAsync(Test.Context(), CancellationToken.None) is null,
                "An unconfigured provider attempted an external call.");
    }

    private static string ProviderReply(string analysis, string finishReason = "stop") => JsonSerializer.Serialize(new
    {
        choices = new[] { new { finish_reason = finishReason, message = new { content = analysis } } }
    });

    private static HttpResponseMessage Reply(string body, HttpStatusCode status = HttpStatusCode.OK,
        string mediaType = "application/json") => new(status)
        { Content = new StringContent(body, Encoding.UTF8, mediaType) };

    private static HttpResponseMessage UnknownLengthReply(int size)
    {
        var content = new UnknownLengthContent(Encoding.UTF8.GetBytes(new string('x', size)));
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        return new HttpResponseMessage(HttpStatusCode.OK) { Content = content };
    }

    private static async Task ExpectCancellationAsync(Func<Task<AiExplanationResponse?>> action)
    {
        try { await action(); }
        catch (OperationCanceledException) { Test.Ensure(true, "Caller cancellation is preserved."); return; }
        Test.Ensure(false, "Core's AI transport swallowed caller cancellation.");
    }
}

sealed class StubHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> respond) : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
        respond(request, cancellationToken);
}

sealed class UnknownLengthContent(byte[] contents) : HttpContent
{
    protected override bool TryComputeLength(out long length) { length = 0; return false; }
    protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
        stream.WriteAsync(contents).AsTask();
    protected override Task<Stream> CreateContentReadStreamAsync() =>
        Task.FromResult<Stream>(new MemoryStream(contents, writable: false));
}
