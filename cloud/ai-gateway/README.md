# SentinelAI AI Gateway

TASK-012 adds one separate .NET 10 cloud service: `POST /api/ai/alerts/explain` explains a selected configuration alert. Core sends the minimized shared `SentinelAI.Contracts.Ai` context, and the gateway returns `label: "AI assistive analysis"` plus a strictly validated analysis. Local detections, alert status, monitoring, and remediation remain independent. Suggested steps require a human to review and perform them.

## Configuration and startup

The default development listener is `http://127.0.0.1:5200`. Remote callers must use HTTPS with normal certificate verification. Use a separate randomly generated 32-byte Core-to-gateway credential encoded as unpadded base64url (43 characters), and configure only its SHA-256 hexadecimal digest in the gateway:

- `SentinelAI:AiGateway:ClientCredentialSha256`: required 64-character SHA-256 hexadecimal digest of the credential string.
- `SentinelAI:AiGateway:Model`: explicit provider model supporting Chat Completions and strict structured JSON output; required when a provider key is configured. There is no default model.
- `SentinelAI:AiGateway:TimeoutSeconds`: whole request deadline, default 20, allowed 1–60 seconds.
- `SENTINELAI_AI_PROVIDER_API_KEY`: provider key injected into the gateway process through cloud secret configuration. Never set this in Core, Agent, dashboard, tracked source, request bodies, or logs.

ASP.NET Core environment variable keys use double underscores, for example `SentinelAI__AiGateway__ClientCredentialSha256`. Unknown gateway configuration fields fail startup. Start from the repository root with `dotnet run --project cloud/ai-gateway/SentinelAI.AiGateway.csproj`; provision the credential digest before startup. Provider credentials can remain absent for local development: authorized requests return a generic `503` while local alert functionality continues. No live provider call is required to run the synthetic tests.

## Boundaries and behavior

The endpoint accepts one authenticated Core client using a fixed-time SHA-256 digest comparison. Context is limited to the 13 current built-in configuration rules, each rule's explicitly allowed Boolean/integer evidence, normalized severity, platform `windows`, and coarse observation freshness. Exact fields are required and duplicate/unknown properties fail validation. No device, organization, account, hostname, address, log history, inventory dump, event timestamp, or arbitrary text is accepted. Core supplies context from stored alert evidence; dashboard callers cannot override it.

Requests are at most 4 KiB, including streamed bodies. Responses are at most 32 KiB; provider replies are read with a 64 KiB limit. All gateway responses carry `Cache-Control: no-store`. Authenticated traffic is limited to 30 requests per minute per source IP and 12 per minute for the configured Core credential. A maximum of four provider requests run concurrently; excess calls return `429` immediately. Provider calls use one bounded deadline and no automatic retries.

The production adapter sends one HTTPS request to the fixed `https://api.openai.com/v1/chat/completions` origin, with redirects and cookies disabled and normal TLS verification. Configure cloud network access to `api.openai.com` only if provider operation is needed. The provider key goes exclusively in the authorization header to this origin. Separate system instructions treat all context as data, require assistive output, preserve deterministic findings, and prohibit actions. Strict JSON schema requests have six exact analysis fields, bounded strings/lists, and low/medium/high confidence. Provider-side output is capped at 4,096 completion tokens and explicit `store: false`; operators must separately understand their provider's retention policy.

Tool execution is never configured. Refusals, tool/function calls, truncated/malformed/oversized responses, duplicate fields, transport errors, timeouts, and unavailable providers produce a generic `503` without returning provider body or exception details. The gateway does not persist alert context or AI output. Output has no authority to update deterministic detections or automatically delete files, isolate hosts, or disable accounts.

`AiGatewayHost.Build` accepts a builder callback and `IAiExplanationProvider` can be injected for synthetic loopback integration tests. `OpenAiExplanationProvider` accepts an optional test `HttpClient` so its real adapter can be checked with an in-memory HTTP handler and development credentials without external access.
