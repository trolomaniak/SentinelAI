using System.Collections.ObjectModel;
using System.Text.Json;

namespace SentinelAI.Contracts.Ai;

public sealed record AiEvidence(string Field, JsonElement Value);
public sealed record AiAlertContext(string RuleId, string Severity, IReadOnlyList<AiEvidence> Evidence,
    string EndpointPlatform, string ObservationFreshness);
public sealed record AiExplanation(string Explanation, string WhyItMatters,
    IReadOnlyList<string> RecommendedInvestigation, IReadOnlyList<string> SuggestedRemediation,
    string Confidence, string Uncertainty);
public sealed record AiExplanationResponse(string Label, AiExplanation Analysis);

/// <summary>A deliberately small wire contract: no identifiers, log text, or executable actions.</summary>
public static class AiContract
{
    public const string AssistiveLabel = "AI assistive analysis";
    public const int MaximumRequestBytes = 4096;
    public const int MaximumResponseBytes = 32768;
    private const string Configuration = "securityPosture.configuration.";
    private static readonly IReadOnlyDictionary<string, IReadOnlyDictionary<string, JsonValueKind>> EvidenceFields =
        new ReadOnlyDictionary<string, IReadOnlyDictionary<string, JsonValueKind>>(
            new Dictionary<string, IReadOnlyDictionary<string, JsonValueKind>>(StringComparer.Ordinal)
            {
                ["SA-FW-001"] = Fields(("securityPosture.domainFirewallEnabled", JsonValueKind.True)),
                ["SA-FW-002"] = Fields(("securityPosture.privateFirewallEnabled", JsonValueKind.True)),
                ["SA-FW-003"] = Fields(("securityPosture.publicFirewallEnabled", JsonValueKind.True)),
                ["SA-UAC-001"] = Fields((Configuration + "uacEnabled", JsonValueKind.True)),
                ["SA-UAC-002"] = Fields((Configuration + "uacEnabled", JsonValueKind.True),
                    (Configuration + "adminConsentPromptBehavior", JsonValueKind.Number)),
                ["SA-RDP-001"] = Fields((Configuration + "rdpEnabled", JsonValueKind.True),
                    (Configuration + "rdpNetworkLevelAuthenticationRequired", JsonValueKind.True)),
                ["SA-RDP-002"] = Fields((Configuration + "rdpEnabled", JsonValueKind.True),
                    (Configuration + "rdpSecurityLayer", JsonValueKind.Number)),
                ["SA-RDP-003"] = Fields((Configuration + "rdpEnabled", JsonValueKind.True),
                    (Configuration + "rdpSecurityLayer", JsonValueKind.Number),
                    (Configuration + "rdpMinimumEncryptionLevel", JsonValueKind.Number)),
                ["SA-SMB-001"] = Fields((Configuration + "smb1ServerEnabled", JsonValueKind.True)),
                ["SA-SMB-002"] = Fields((Configuration + "smbInsecureGuestLogonsAllowed", JsonValueKind.True)),
                ["SA-LOGON-001"] = Fields((Configuration + "automaticAdminLogonEnabled", JsonValueKind.True)),
                ["SA-LSA-001"] = Fields((Configuration + "lsaProtectionEnabled", JsonValueKind.True)),
                ["SA-UPDATE-001"] = Fields((Configuration + "automaticUpdatesDisabled", JsonValueKind.True))
            });

    public static IReadOnlyDictionary<string, JsonValueKind>? GetEvidenceFields(string ruleId) =>
        EvidenceFields.TryGetValue(ruleId, out var fields) ? fields : null;

    public static bool IsValidContext(AiAlertContext? context)
    {
        if (context is null || string.IsNullOrEmpty(context.RuleId) ||
            GetEvidenceFields(context.RuleId) is not { } fields ||
            context.Severity is not ("info" or "low" or "medium" or "high" or "critical") ||
            context.EndpointPlatform != "windows" || context.ObservationFreshness is not ("recent" or "stale" or "unknown") ||
            context.Evidence is null || context.Evidence.Count != fields.Count) return false;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var evidence in context.Evidence)
        {
            if (evidence is null || string.IsNullOrEmpty(evidence.Field) || !seen.Add(evidence.Field) ||
                !fields.TryGetValue(evidence.Field, out var kind)) return false;
            if (kind == JsonValueKind.True && evidence.Value.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) return false;
            if (kind == JsonValueKind.Number && (evidence.Value.ValueKind != JsonValueKind.Number ||
                !evidence.Value.TryGetInt32(out var integer) || integer is < 0 or > 5)) return false;
        }
        return true;
    }

    public static bool TryReadContext(JsonElement root, out AiAlertContext? context)
    {
        context = null;
        if (!ExactFields(root, "ruleId", "severity", "evidence", "endpointPlatform", "observationFreshness") ||
            root.GetProperty("evidence") is not { ValueKind: JsonValueKind.Array } array || array.GetArrayLength() > 3) return false;
        var evidence = new List<AiEvidence>();
        foreach (var item in array.EnumerateArray())
        {
            if (!ExactFields(item, "field", "value") || Text(item.GetProperty("field")) is not { } field) return false;
            evidence.Add(new(field, item.GetProperty("value").Clone()));
        }
        var parsed = new AiAlertContext(Text(root.GetProperty("ruleId")) ?? "", Text(root.GetProperty("severity")) ?? "",
            evidence.AsReadOnly(), Text(root.GetProperty("endpointPlatform")) ?? "", Text(root.GetProperty("observationFreshness")) ?? "");
        if (!IsValidContext(parsed)) return false;
        context = parsed;
        return true;
    }

    public static bool IsValidAnalysis(AiExplanation? analysis) => analysis is not null &&
        BoundedText(analysis.Explanation, 2048) && BoundedText(analysis.WhyItMatters, 1024) &&
        BoundedSteps(analysis.RecommendedInvestigation) && BoundedSteps(analysis.SuggestedRemediation) &&
        analysis.Confidence is "low" or "medium" or "high" && BoundedText(analysis.Uncertainty, 1024);

    public static bool TryReadAnalysis(JsonElement root, out AiExplanation? analysis)
    {
        analysis = null;
        if (!ExactFields(root, "explanation", "whyItMatters", "recommendedInvestigation", "suggestedRemediation", "confidence", "uncertainty") ||
            !ReadSteps(root.GetProperty("recommendedInvestigation"), out var investigation) ||
            !ReadSteps(root.GetProperty("suggestedRemediation"), out var remediation)) return false;
        var parsed = new AiExplanation(Text(root.GetProperty("explanation")) ?? "", Text(root.GetProperty("whyItMatters")) ?? "",
            investigation, remediation, Text(root.GetProperty("confidence")) ?? "", Text(root.GetProperty("uncertainty")) ?? "");
        if (!IsValidAnalysis(parsed)) return false;
        analysis = parsed;
        return true;
    }

    public static bool TryReadResponse(JsonElement root, out AiExplanationResponse? response)
    {
        response = null;
        if (!ExactFields(root, "label", "analysis") || Text(root.GetProperty("label")) != AssistiveLabel ||
            !TryReadAnalysis(root.GetProperty("analysis"), out var analysis) || analysis is null) return false;
        response = new(AssistiveLabel, analysis);
        return true;
    }

    private static IReadOnlyDictionary<string, JsonValueKind> Fields(params (string Field, JsonValueKind Kind)[] fields) =>
        new ReadOnlyDictionary<string, JsonValueKind>(fields.ToDictionary(field => field.Field, field => field.Kind, StringComparer.Ordinal));
    private static string? Text(JsonElement value) => value.ValueKind == JsonValueKind.String ? value.GetString() : null;
    private static bool ExactFields(JsonElement value, params string[] names)
    {
        if (value.ValueKind != JsonValueKind.Object) return false;
        var expected = new HashSet<string>(names, StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject()) if (!expected.Remove(property.Name)) return false;
        return expected.Count == 0;
    }
    private static bool BoundedText(string? text, int limit) => !string.IsNullOrWhiteSpace(text) && text.Length <= limit &&
        !text.Any(character => char.IsControl(character) && character is not ('\n' or '\r' or '\t'));
    private static bool BoundedSteps(IReadOnlyList<string>? steps) => steps is { Count: >= 1 and <= 8 } && steps.All(step => BoundedText(step, 512));
    private static bool ReadSteps(JsonElement value, out IReadOnlyList<string> steps)
    {
        steps = Array.Empty<string>();
        if (value.ValueKind != JsonValueKind.Array || value.GetArrayLength() is < 1 or > 8) return false;
        var list = value.EnumerateArray().Select(item => Text(item) ?? "").ToArray();
        if (!BoundedSteps(list)) return false;
        steps = Array.AsReadOnly(list);
        return true;
    }
}
