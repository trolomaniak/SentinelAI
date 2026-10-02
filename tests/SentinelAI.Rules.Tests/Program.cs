using System.Text.Json;
using SentinelAI.Contracts.Inventory;
using SentinelAI.Rules;

var engine = RuleEngine.CreateDefault();
var endpointId = Guid.Parse("fe2b1c17-95d3-40b4-8e24-ed7a66b46443");
var timestamp = new DateTimeOffset(2026, 1, 10, 9, 30, 0, TimeSpan.Zero);
var unknown = new EndpointState(endpointId, timestamp, true, new SecurityPostureInventory(null, null, null));

EndpointState Configuration(WindowsSecurityConfiguration configuration) =>
    unknown with { SecurityPosture = new SecurityPostureInventory(null, null, null, configuration) };

var cases = new RuleCase[]
{
    new("Domain firewall", "SA-FW-001", unknown with { SecurityPosture = new(false, null, null) },
        unknown with { SecurityPosture = new(true, null, null) }, "domainFirewallEnabled", false),
    new("Private firewall", "SA-FW-002", unknown with { SecurityPosture = new(null, false, null) },
        unknown with { SecurityPosture = new(null, true, null) }, "privateFirewallEnabled", false),
    new("Public firewall", "SA-FW-003", unknown with { SecurityPosture = new(null, null, false) },
        unknown with { SecurityPosture = new(null, null, true) }, "publicFirewallEnabled", false),
    new("UAC disabled", "SA-UAC-001", Configuration(new(UacEnabled: false)),
        Configuration(new(UacEnabled: true)), "uacEnabled", false),
    new("UAC elevation without consent", "SA-UAC-002", Configuration(new(UacEnabled: true, AdminConsentPromptBehavior: 0)),
        Configuration(new(UacEnabled: true, AdminConsentPromptBehavior: 2)), "adminConsentPromptBehavior", 0),
    new("RDP without NLA", "SA-RDP-001", Configuration(new(RdpEnabled: true, RdpNetworkLevelAuthenticationRequired: false)),
        Configuration(new(RdpEnabled: true, RdpNetworkLevelAuthenticationRequired: true)),
        "rdpNetworkLevelAuthenticationRequired", false),
    new("RDP legacy security", "SA-RDP-002", Configuration(new(RdpEnabled: true, RdpSecurityLayer: 0)),
        Configuration(new(RdpEnabled: true, RdpSecurityLayer: 2)), "rdpSecurityLayer", 0),
    new("RDP low encryption", "SA-RDP-003", Configuration(new(RdpEnabled: true, RdpSecurityLayer: 1, RdpMinimumEncryptionLevel: 1)),
        Configuration(new(RdpEnabled: true, RdpSecurityLayer: 1, RdpMinimumEncryptionLevel: 3)), "rdpMinimumEncryptionLevel", 1),
    new("SMB1 server", "SA-SMB-001", Configuration(new(Smb1ServerEnabled: true)),
        Configuration(new(Smb1ServerEnabled: false)), "smb1ServerEnabled", true),
    new("SMB insecure guest logon", "SA-SMB-002", Configuration(new(SmbInsecureGuestLogonsAllowed: true)),
        Configuration(new(SmbInsecureGuestLogonsAllowed: false)), "smbInsecureGuestLogonsAllowed", true),
    new("Automatic Windows logon", "SA-LOGON-001", Configuration(new(AutomaticAdminLogonEnabled: true)),
        Configuration(new(AutomaticAdminLogonEnabled: false)), "automaticAdminLogonEnabled", true),
    new("LSA protection disabled", "SA-LSA-001", Configuration(new(LsaProtectionEnabled: false)),
        Configuration(new(LsaProtectionEnabled: true)), "lsaProtectionEnabled", false),
    new("Automatic updates disabled", "SA-UPDATE-001", Configuration(new(AutomaticUpdatesDisabled: true)),
        Configuration(new(AutomaticUpdatesDisabled: false)), "automaticUpdatesDisabled", true)
};

Ensure(engine.Rules.Count == cases.Length && engine.Rules.Count >= 10,
    "Every default rule must have a test case and at least ten default rules must exist.");
Ensure(engine.Rules.Select(rule => rule.Id).Distinct(StringComparer.Ordinal).Count() == engine.Rules.Count,
    "Default rule IDs must be unique.");
Ensure(engine.Evaluate(unknown).Count == 0, "Missing telemetry must not create detections.");
Ensure(engine.Evaluate(unknown with { SecurityPosture = new(null, null, null, new()) }).Count == 0,
    "Unknown configuration values must not create detections.");

var exercisedIds = new HashSet<string>(StringComparer.Ordinal);
var jsonOptions = new JsonSerializerOptions(JsonSerializerDefaults.Web);
foreach (var test in cases)
{
    var alerts = engine.Evaluate(test.Trigger);
    Ensure(alerts.Count == 1, $"{test.Name}: the isolated risky condition must trigger exactly one rule.");
    var alert = alerts.Single();
    Ensure(alert.RuleId == test.RuleId, $"{test.Name}: the stable rule ID must identify this detection.");
    Ensure(exercisedIds.Add(alert.RuleId), $"{test.Name}: each isolated condition must exercise a different rule.");
    var rule = engine.Rules.Single(candidate => candidate.Id == alert.RuleId);
    Ensure(rule.Evaluate(test.Trigger) is not null, $"{test.Name}: the rule must be individually evaluable.");
    Ensure(rule.Evaluate(test.Normal) is null && engine.Evaluate(test.Normal).Count == 0,
        $"{test.Name}: normal configuration must not alert.");
    Ensure(rule.Evaluate(unknown) is null, $"{test.Name}: absent telemetry must not alert.");
    Ensure(rule.Evaluate(test.Trigger with { IsWindows = false }) is null &&
           engine.Evaluate(test.Trigger with { IsWindows = false }).Count == 0,
        $"{test.Name}: Windows rules must not apply to non-Windows endpoints.");
    Ensure(!string.IsNullOrWhiteSpace(alert.RuleId) && alert.RuleId == rule.Id &&
           !string.IsNullOrWhiteSpace(alert.Title) && alert.Title == rule.Title &&
           alert.Severity == rule.Severity &&
           new[] { "low", "medium", "high", "critical" }.Contains(alert.Severity, StringComparer.OrdinalIgnoreCase) &&
           !string.IsNullOrWhiteSpace(alert.Reason) && !string.IsNullOrWhiteSpace(alert.RecommendedAction),
        $"{test.Name}: alert metadata must be meaningful and match its rule.");
    Ensure(alert.EndpointId == endpointId && alert.Timestamp == timestamp,
        $"{test.Name}: alert identity and time must come from the normalized state.");
    Ensure(alert.Evidence.Count > 0 && alert.Evidence.All(item => !string.IsNullOrWhiteSpace(item.Field)),
        $"{test.Name}: structured field evidence must be present.");
    var matchingEvidence = alert.Evidence.Where(item =>
        item.Field.Equals(test.EvidenceField, StringComparison.Ordinal) ||
        item.Field.EndsWith($".{test.EvidenceField}", StringComparison.Ordinal)).ToArray();
    Ensure(matchingEvidence.Length == 1, $"{test.Name}: evidence must identify the observed configuration field.");
    VerifyTypedValue(matchingEvidence.Single().Value, test.ExpectedValue, test.Name);

    var serialized = JsonSerializer.Serialize(alert, jsonOptions);
    var roundTrip = JsonSerializer.Deserialize<SecurityAlert>(serialized, jsonOptions)!;
    Ensure(roundTrip.RuleId == alert.RuleId && roundTrip.EndpointId == endpointId &&
           roundTrip.Timestamp == timestamp && roundTrip.Evidence.Count == alert.Evidence.Count,
        $"{test.Name}: structured alerts must survive JSON serialization.");
    using var document = JsonDocument.Parse(serialized);
    Ensure(document.RootElement.GetProperty("reason").GetString() == alert.Reason &&
           document.RootElement.GetProperty("recommendedAction").GetString() == alert.RecommendedAction,
        $"{test.Name}: reason and recommended action must be included in serialized alerts.");
    Ensure(serialized == JsonSerializer.Serialize(engine.Evaluate(test.Trigger).Single(), jsonOptions),
        $"{test.Name}: evaluating unchanged state must produce deterministic alerts.");
}
Ensure(exercisedIds.SetEquals(engine.Rules.Select(rule => rule.Id)),
    "Every default rule must have trigger, normal, unknown, and non-Windows coverage.");

VerifyPrerequisites();
VerifyMultipleAlerts();
VerifyInventoryNormalization();
VerifyCustomRules();
Console.WriteLine($"Rules tests passed ({cases.Length} rules, normal/unknown/platform guards, typed alerts, determinism).");

void VerifyPrerequisites()
{
    foreach (var enabled in new bool?[] { false, null })
    {
        var rdp = Configuration(new(RdpEnabled: enabled, RdpNetworkLevelAuthenticationRequired: false,
            RdpSecurityLayer: 0, RdpMinimumEncryptionLevel: 1));
        Ensure(engine.Evaluate(rdp).Count == 0,
            "Risky RDP settings must not alert unless RDP is explicitly enabled.");
    }
    Ensure(engine.Evaluate(Configuration(new(AdminConsentPromptBehavior: 0))).Count == 0,
        "Missing UAC state must not trigger a consent-prompt detection.");
    var disabledUac = engine.Evaluate(Configuration(new(UacEnabled: false, AdminConsentPromptBehavior: 0)));
    var onlyDisabledUac = engine.Evaluate(Configuration(new(UacEnabled: false)));
    Ensure(disabledUac.Count == 1 && disabledUac.Single().RuleId == onlyDisabledUac.Single().RuleId,
        "Disabled UAC must trigger its own rule, without a redundant prompt-configuration alert.");
    foreach (var consent in new[] { 1, 2, 3, 4, 5 })
        Ensure(engine.Evaluate(Configuration(new(UacEnabled: true, AdminConsentPromptBehavior: consent))).Count == 0,
            "Consent modes that request approval must not be reported as no-prompt elevation.");
    Ensure(engine.Evaluate(Configuration(new(RdpEnabled: true, RdpSecurityLayer: 1,
        RdpMinimumEncryptionLevel: 2))).Count == 0,
        "Negotiated RDP security and client-compatible encryption must not trigger legacy/low-setting rules.");
    foreach (var layer in new int?[] { null, 2 })
        Ensure(engine.Evaluate(Configuration(new(RdpEnabled: true, RdpSecurityLayer: layer,
            RdpMinimumEncryptionLevel: 1))).Count == 0,
            "Low RDP encryption must not alert when TLS is required or the security layer is unknown.");
    foreach (var layer in new[] { 0, 1 })
    {
        var lowEncryption = engine.Evaluate(Configuration(new(RdpEnabled: true, RdpSecurityLayer: layer,
            RdpMinimumEncryptionLevel: 1))).Single(alert => alert.RuleId == "SA-RDP-003");
        var evidence = lowEncryption.Evidence.Single(item => item.Field.EndsWith(".rdpSecurityLayer", StringComparison.Ordinal));
        VerifyTypedValue(evidence.Value, layer, "RDP low encryption security-layer prerequisite");
    }
}

void VerifyMultipleAlerts()
{
    var allRisky = unknown with
    {
        SecurityPosture = new(false, false, false, new(UacEnabled: false, AdminConsentPromptBehavior: 0,
            RdpEnabled: true, RdpNetworkLevelAuthenticationRequired: false, RdpSecurityLayer: 0,
            RdpMinimumEncryptionLevel: 1, Smb1ServerEnabled: true, SmbInsecureGuestLogonsAllowed: true,
            AutomaticAdminLogonEnabled: true, LsaProtectionEnabled: false, AutomaticUpdatesDisabled: true))
    };
    var alerts = engine.Evaluate(allRisky);
    Ensure(alerts.Count == cases.Length - 1 && alerts.Select(alert => alert.RuleId).Distinct().Count() == alerts.Count,
        "Independent risky settings must create all applicable alerts, without duplicate IDs.");
    Ensure(JsonSerializer.Serialize(alerts, jsonOptions) == JsonSerializer.Serialize(engine.Evaluate(allRisky), jsonOptions),
        "Multiple alerts must have deterministic values and ordering.");
    Ensure(engine.Evaluate(allRisky with { IsWindows = false }).Count == 0,
        "A non-Windows endpoint must not produce Windows configuration detections.");
    var selectedEngine = new RuleEngine([engine.Rules.Single(rule => rule.Id == "SA-FW-001")]);
    Ensure(selectedEngine.Evaluate(allRisky).Select(alert => alert.RuleId).SequenceEqual(new[] { "SA-FW-001" }),
        "A caller must be able to evaluate a selected rule without enabling the entire default rule set.");
}

void VerifyInventoryNormalization()
{
    var posture = cases.First().Trigger.SecurityPosture;
    var inventory = new InventoryReport(endpointId, timestamp, "test-agent", "synthetic-host", "Windows", "10.0",
        "X64", new(null, 4), null, [], posture);
    var state = EndpointState.FromInventory(inventory);
    Ensure(state.EndpointId == endpointId && state.Timestamp == timestamp && state.IsWindows &&
           state.SecurityPosture == posture,
        "Inventory normalization must retain endpoint, collection time, platform and observed configuration.");
    Ensure(engine.Evaluate(state).Count == 1,
        "Normalized inventory must be evaluable through the reusable engine.");
    foreach (var osName in new[] { "Windows", "windows", "Windows 10", "Windows 11", "Microsoft Windows", "Microsoft Windows 11" })
        Ensure(EndpointState.FromInventory(inventory with { OsName = osName }).IsWindows,
            $"Inventory normalization must recognize a supported Windows OS name: {osName}.");
    foreach (var osName in new[] { "Linux", "Windowsish", "WindowsMalware", "Microsoft Windowsish", "" })
    {
        var nonWindows = EndpointState.FromInventory(inventory with { OsName = osName });
        Ensure(!nonWindows.IsWindows && engine.Evaluate(nonWindows).Count == 0,
            $"Inventory normalization must reject a non-Windows or lookalike OS name: {osName}.");
    }
}

void VerifyCustomRules()
{
    IEndpointRule[] suppliedRules = [new SyntheticRule("test-first"), new SyntheticRule("test-second")];
    var customEngine = new RuleEngine(suppliedRules);
    suppliedRules[0] = new SyntheticRule("test-replaced");
    var customAlerts = customEngine.Evaluate(unknown);
    Ensure(customAlerts.Select(alert => alert.RuleId).SequenceEqual(new[] { "test-first", "test-second" }),
        "The reusable engine must accept external rules in a stable order and snapshot its rule collection.");
    Ensure(customAlerts.All(alert => alert.EndpointId == endpointId && alert.Timestamp == timestamp),
        "External rule evaluation must receive the normalized endpoint snapshot.");
}

static void VerifyTypedValue(JsonElement value, object expected, string name)
{
    if (expected is bool boolean)
        Ensure(value.ValueKind == (boolean ? JsonValueKind.True : JsonValueKind.False) && value.GetBoolean() == boolean,
            $"{name}: boolean evidence must remain typed, rather than formatted text.");
    else if (expected is int integer)
        Ensure(value.ValueKind == JsonValueKind.Number && value.GetInt32() == integer,
            $"{name}: numeric evidence must remain typed, rather than formatted text.");
    else
        throw new InvalidOperationException("Unsupported test evidence type.");
}

static void Ensure(bool condition, string message)
{
    if (!condition)
        throw new InvalidOperationException(message);
}

internal sealed record RuleCase(string Name, string RuleId, EndpointState Trigger, EndpointState Normal,
    string EvidenceField, object ExpectedValue);

internal sealed class SyntheticRule(string id) : IEndpointRule
{
    public string Id { get; } = id;
    public string Title => "Synthetic extension rule";
    public string Severity => "low";

    public SecurityAlert? Evaluate(EndpointState state) => new(Id, Title, Severity,
        "Synthetic test rule ran.", [RuleEvidence.Boolean("test.observed", true)],
        state.EndpointId, state.Timestamp, "No action; synthetic test only.");
}
