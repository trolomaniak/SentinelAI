# Cloud AI v1: selected-alert explanation

TASK-012 adds one assistive feature: explain a selected stored alert and suggest investigation/remediation for administrator review. Flow: native Desktop → Core → minimized structured context → separate SentinelAI AI Gateway → model provider → validated structured analysis → Core → Desktop. Desktop is the supported production interface; the dashboard retains its equivalent flow only for development/diagnostic compatibility. AI does not change deterministic findings, scores, incident status or endpoint configuration and has no remediation executor or model tools.

## Data and trust boundaries

Desktop and the diagnostic dashboard send only the selected alert ID. Core projects the allowlisted evidence for that stored alert's supported built-in rule. Outbound context contains rule ID, severity, boolean/integer configuration evidence, `windows` platform and a coarse recent/stale/unknown observation label. Hostnames, endpoint/organization/installation IDs, users, addresses, titles, reasons, actions, history, exact timestamps, raw logs and arbitrary string evidence are excluded. Unsupported rules or invalid relevant evidence are not sent. The gateway independently validates the same strict schema; unknown/duplicate properties and instruction strings are rejected.

Provider system instructions are separate from JSON incident data. Incident content is data, never instruction. The model has no tools and returns a fixed schema: explanation, why it matters, recommended investigation, suggested remediation, qualitative confidence and uncertainty. Responses are strictly validated and bounded at gateway and Core. Confidence is a model assessment, not a calibrated detection probability. AI text is displayed literally under **AI assistive analysis**. It cannot override detections or automatically delete files, isolate hosts or disable accounts; administrators review suggestions and any operational action separately.

The provider key is read only by the gateway from `SENTINELAI_AI_PROVIDER_API_KEY`. Core references the shared wire contract and authenticates to its fixed gateway with a separate client credential. Agent, Desktop and the diagnostic dashboard receive neither credential. AI context/results are not persisted or intentionally logged. Deployment must review the chosen provider account's retention/data settings before sending real telemetry.

## Configuration

`cloud/ai-gateway/SentinelAI.AiGateway.csproj` is a separate .NET 10 host, defaulting to loopback port 5200. Settings under `SentinelAI:AiGateway`:

| Setting | Meaning |
| --- | --- |
| `ClientCredentialSha256` | Required SHA-256 hex digest of the separate Core-to-gateway credential |
| `Model` | Explicit model supporting Chat Completions structured JSON schema; required when the provider key is set, with no implicit model choice |
| `TimeoutSeconds` | Provider timeout, 1–60 seconds; default 20 |

Supply the provider key securely to the gateway process only. The adapter uses the fixed verified HTTPS destination `https://api.openai.com/v1/chat/completions`, disables redirects, bounds output/body size and does not automatically retry paid calls. Production egress belongs to the gateway environment. A missing provider key returns unavailable (`503`), without a fake analysis or effect on monitoring. Tests use synthetic provider HTTP responses and generated development authentication, never production keys or customer telemetry.

Core settings under `SentinelAI:Ai`:

| Setting | Meaning |
| --- | --- |
| `GatewayUrl` | Fixed HTTPS origin; loopback HTTP for isolated development; never selected by Desktop or the diagnostic dashboard |
| `GatewayCredentialPath` | Absolute private file containing exactly 43 base64url characters (random 256-bit credential), without a newline |
| `TimeoutSeconds` | Complete gateway request timeout, 1–60 seconds; default 15 |

Absent Core AI settings disable cloud requests. Provision the credential's digest on the gateway; keep raw credentials out of source, arguments, logs and shared artifacts. Unix files must be private to the account; Windows requires operator-provisioned account-restricted ACLs. Do not configure a provider key on Core. New cloud AI requires a currently permitted signed `cloud_ai` feature; Safe Mode preserves local alerts while withholding this cloud feature.

## API and failures

- Gateway `POST /api/ai/alerts/explain` requires its separate bearer, secure transport outside loopback, strict bounded context and rate/concurrency limits.
- Core `POST /api/admin/alerts/{alertId}/explanation` requires an administrator token, secure transport, a supported stored alert and `cloud_ai` entitlement. It accepts no body/context/destination overrides and is rate limited.
- Responses are uncached. Success contains `label: "AI assistive analysis"` and structured `analysis`, with no credentials or provider error bodies.
- Configuration, timeout, network and malformed-response failures produce generic unavailable results. Desktop permits another explicit request while local details and status controls continue working; it never retries automatically. The diagnostic dashboard retains its manual retry flow. Sign-out, navigation and stale responses cannot restore obsolete AI content.

No chat, autonomous response, raw-log upload, new detection, billing, model training pipeline or additional cloud feature is introduced.
