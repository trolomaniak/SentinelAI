using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Unicode;
using SentinelAI.Contracts.Ai;
using SentinelAI.Localization;

namespace SentinelAI.Core.Reports;

/// <summary>Standalone deterministic HTML in the installation language. Every dynamic value is encoded and all assets are local.</summary>
public static class SecurityReportRenderer
{
    public static string Render(SecurityReport report, UiLanguage language = UiLanguage.English)
    {
        ArgumentNullException.ThrowIfNull(report);
        return new Page(language).Render(report);
    }

    /// <summary>
    /// One report. Fixed texts are translated by their exact English text, as in Desktop; identifiers stay as Core stores them
    /// (rule IDs, inventory and coverage states, criticality and exposure labels, evidence fields and typed values).
    /// </summary>
    private sealed class Page(UiLanguage language)
    {
        // Polish letters stay readable in the saved file; HTML-sensitive characters are always encoded.
        private static readonly HtmlEncoder PolishEncoder =
            HtmlEncoder.Create(UnicodeRanges.BasicLatin, UnicodeRanges.Latin1Supplement, UnicodeRanges.LatinExtendedA);
        private readonly StringBuilder _html = new(32768);
        private readonly HtmlEncoder _encoder = language == UiLanguage.English ? HtmlEncoder.Default : PolishEncoder;

        private string T(string english) => Localizer.Translate(english, language);
        private string F(string englishFormat, params object?[] arguments) => Localizer.Format(englishFormat, language, arguments);

        public string Render(SecurityReport report)
        {
            _html.Append("""
                <!doctype html>
                <html lang="
                """).Append(UiLanguages.Code(language)).Append("""
                "><head><meta charset="utf-8">
                <meta name="viewport" content="width=device-width,initial-scale=1">
                <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; object-src 'none'; base-uri 'none'; frame-src 'none'; form-action 'none'">
                <title>
                """);
            Text(T("SentinelAI local security report"));
            _html.Append("""
                </title>
                <style>
                :root{color-scheme:light}body{font-family:system-ui,sans-serif;max-width:1120px;margin:2rem auto;padding:0 1rem;color:#17212e;background:#fff;line-height:1.5}h1{font-size:2rem}h2{margin-top:2rem;border-bottom:2px solid #dbe2ea;padding-bottom:.4rem}h3{margin-bottom:.4rem}.notice{background:#edf3fa;border-left:4px solid #345d86;padding:1rem}.muted{color:#43566b}table{border-collapse:collapse;width:100%;margin:1rem 0;font-size:.9rem}th,td{border:1px solid #cad5e0;padding:.5rem;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#edf3fa}dl{display:grid;grid-template-columns:minmax(12rem,1fr) 2fr;gap:.3rem 1rem}dt{font-weight:600}dd{margin:0;overflow-wrap:anywhere}.incident{border:1px solid #cad5e0;padding:1rem;margin:1rem 0;break-inside:avoid}code{overflow-wrap:anywhere}li{margin:.5rem 0}@media print{body{margin:0;max-width:none;font-size:10pt}h2{break-after:avoid}thead{display:table-header-group}.incident{break-inside:auto}}
                </style></head><body><main><h1>
                """);
            Text(T("SentinelAI local security report"));
            _html.Append("</h1>");
            _html.Append("<dl>");
            Definition(T("Reporting period (inclusive UTC dates)"), F("{0} through {1}", Date(report.Period.From), Date(report.Period.To)));
            Definition(T("Generated / current state evaluated at (UTC)"), Utc(report.GeneratedAtUtc));
            Definition(T("Source"), T("Stored local SentinelAI data; deterministic policy and rules; no cloud AI required."));
            _html.Append("</dl><p class=\"notice\">");
            Text(T(SecurityReport.ChronologyCaution));
            _html.Append("</p>");

            Heading(T("Management summary"));
            _html.Append("<dl>");
            Definition(T("Organization risk score (security prioritization)"), $"{Number(report.OrganizationRisk.Score)} / 100");
            Definition(T("Score method"), T(report.OrganizationRisk.Method));
            Definition(T("Enrolled endpoints in current snapshot"), Number(report.OrganizationRisk.EndpointCount));
            Definition(T("Endpoints tied at highest current risk"), Number(report.OrganizationRisk.HighestRiskEndpointCount));
            Definition(T("Retained alerts associated with selected period"), Number(report.Activity.AssociatedAlertCount));
            Definition(T("New retained alerts first observed during period"), Number(report.Activity.NewAlertCount));
            Definition(T("Distinct alerts with a resolved transition during period"), Number(report.Activity.ResolvedAlertCount));
            Definition(T("Score trend"), T(SecurityReport.UnavailableTrend));
            _html.Append("</dl>");
            Paragraph(T(report.OrganizationRisk.Explanation));
            Paragraph(T("Higher scores prioritize recorded configuration risks. A zero score does not establish endpoint safety. Unknown or stale observations can conceal risks. Accepted and Investigating do not reduce remaining risk; Resolved changes the current score contribution but does not itself remediate an endpoint."));
            if (report.Endpoints.Count == 0)
                Paragraph(T("No enrolled endpoints are stored. No endpoint security assurance can be made from this empty fleet."));

            Heading(T("Retained activity in the selected UTC period"));
            Paragraph(T("Associated alerts have a retained first observation, retained latest observation, or stored status transition inside the selected interval. Severity below is the latest stored severity, not a historical severity snapshot. Resolved counts include alerts later reopened and count each alert once, even if resolved repeatedly."));
            StartTable(T("Latest severity"), T("Period-associated retained alerts"), T("New retained alerts"));
            foreach (var count in report.Activity.SeverityCounts)
                Row(Severity(count.Severity), Number(count.AssociatedAlerts), Number(count.NewAlerts));
            EndTable();

            Heading(T("Current endpoint health and risk"));
            Paragraph(T("Health uses the latest stored heartbeat at generation: Healthy up to 2 minutes; Warning over 2 through 5 minutes; Offline over 5 minutes; Unknown without a heartbeat. This is reporting freshness, not historical uptime or endpoint safety."));
            StartTable(T("Healthy"), T("Warning"), T("Offline"), T("Unknown"));
            Row(Number(report.Health.Healthy), Number(report.Health.Warning), Number(report.Health.Offline), Number(report.Health.Unknown));
            EndTable();
            _html.Append("<dl>");
            Definition(T("Missing inventories"), Number(report.Endpoints.Count(endpoint => endpoint.CurrentRisk.Coverage.InventoryState == "missing")));
            Definition(T("Stale inventories"), Number(report.Endpoints.Count(endpoint => endpoint.CurrentRisk.Coverage.InventoryState == "stale")));
            Definition(T("Future-dated inventories"), Number(report.Endpoints.Count(endpoint => endpoint.CurrentRisk.Coverage.InventoryState == "future")));
            Definition(T("Unknown supported-rule coverage"), Number(report.Endpoints.Count(endpoint => endpoint.CurrentRisk.Coverage.SignalCoverage == "unknown")));
            Definition(T("Partial supported-rule coverage"), Number(report.Endpoints.Count(endpoint => endpoint.CurrentRisk.Coverage.SignalCoverage == "partial")));
            Definition(T("Inventory freshness expectation"), F("Within {0} hours", Number(report.InventoryFreshForHours)));
            _html.Append("</dl>");
            Paragraph(T("Coverage counts only the 13 supported Windows configuration rules. Missing or unknown signals receive no score; complete supported-rule coverage does not establish overall endpoint protection. Criticality and exposure are operator declarations or explicit policy defaults, not inferred Internet exposure."));
            var endpoints = report.Endpoints.OrderByDescending(endpoint => endpoint.CurrentRisk.Risk.Score)
                .ThenByDescending(endpoint => endpoint.CurrentRisk.Risk.RawScore).ThenBy(endpoint => endpoint.EndpointId).ToArray();
            Paragraph(F("Showing {0} of {1} endpoints. Management counts and scores use all retained records admitted by report capacity; detail is limited to 200 items per section.",
                Number(Math.Min(endpoints.Length, SecurityReport.DetailedItemLimit)), Number(endpoints.Length)));
            StartTable(T("Endpoint / ID"), T("Current reporting health / last heartbeat UTC"), T("Current risk / raw points"), T("Latest inventory UTC"), T("Coverage"), T("Criticality / exposure assumptions"));
            foreach (var endpoint in endpoints.Take(SecurityReport.DetailedItemLimit))
            {
                var risk = endpoint.CurrentRisk;
                Row($"{endpoint.EndpointName} / {endpoint.EndpointId:D}", $"{Health(endpoint.Health)} / {Utc(endpoint.LastSeenUtc)}",
                    F("{0} / 100; raw {1}", Number(risk.Risk.Score), Number(risk.Risk.RawScore)), Utc(risk.InventoryCollectedUtc),
                    F("{0}; {1}; {2} of {3} known", risk.Coverage.InventoryState, risk.Coverage.SignalCoverage, Number(risk.Coverage.KnownRuleSignals), Number(risk.Coverage.TotalRuleSignals)),
                    $"{risk.Risk.Context.AssetCriticality} ({risk.Risk.Context.AssetCriticalitySource}) / {risk.Risk.Context.Exposure} ({risk.Risk.Context.ExposureSource})");
            }
            EndTable();

            IncidentSection(T("Critical/high incidents associated with the period"),
                report.PeriodIncidents.Where(incident => incident.Severity is "critical" or "high").ToArray(),
                T("No critical or high retained incidents are associated with this period; missing observations remain unknown."));
            IncidentSection(T("Incidents resolved during the period"),
                report.PeriodIncidents.Where(incident => incident.ResolutionsInPeriod > 0).ToArray(),
                T("No retained alert has a stored resolved transition inside this period."));
            IncidentSection(T("Current major security posture findings"), report.MajorPostureFindings,
                T("No tracked unresolved configuration findings are stored. This does not establish endpoint safety."));

            Heading(T("Recommended priority actions"));
            Paragraph(T("Deterministic local recommendations prioritize current unresolved findings by severity, current risk contribution, and rule ID, followed by telemetry gaps. Review compatibility and approved policy before making changes. This report performs no remediation."));
            if (report.PriorityActions.Count == 0)
                Paragraph(T("Continue approved monitoring and validate coverage; absence of a recommended finding does not establish safety."));
            else
            {
                _html.Append("<ol>");
                foreach (var action in report.PriorityActions)
                {
                    _html.Append("<li><strong>");
                    Text(F("{0} / {1} — {2} endpoint(s)", Priority(action.Priority), action.RuleId, Number(action.AffectedEndpointCount)));
                    _html.Append("</strong>: ");
                    Text(T(action.Action));
                    _html.Append("<br>");
                    Text(F("{0} Current summed alert contribution: {1} points.", T(action.Reason), Number(action.CurrentRiskContribution)));
                    _html.Append("</li>");
                }
                _html.Append("</ol>");
            }

            Heading(T("Current deterministic scoring policy"));
            _html.Append("<dl>");
            Definition(T("Policy version"), report.Policy.Version);
            Definition(T("Final score cap"), Number(report.Policy.MaximumScore));
            Definition(T("Confidence default evidence weight"), Number(report.Policy.DefaultConfidence));
            Definition(T("Full age weight"), F("Through {0} days: 1", Number(report.Policy.FreshForDays)));
            Definition(T("Aging age weight"), F("Over {0} through {1} days: {2}", Number(report.Policy.FreshForDays), Number(report.Policy.AgingForDays), Number(report.Policy.AgingMultiplier)));
            Definition(T("Older observation weight"), Number(report.Policy.OldMultiplier));
            Definition(T("Correlation bonus"), F("{0} per extra distinct correlated group; base cap {1}", Number(report.Policy.CorrelationPointsPerExtraGroup), Number(report.Policy.MaximumCorrelationBaseBonus)));
            _html.Append("</dl>");
            StartTable(T("Severity"), T("Base points"));
            foreach (var severity in new[] { "critical", "high", "medium", "low", "info" })
                Row(Severity(severity), Number(report.Policy.SeverityPoints[severity]));
            EndTable();
            Paragraph(T("Risk uses current policy, severity, configured confidence weight, asset criticality, exposure, observation age and current status, plus bounded correlation of configuration findings confirmed by the latest inventory, of endpoint telemetry findings confirmed by the latest telemetry report and of fresh runtime event detections. Confidence is not statistical probability. Age discounts do not prove remediation. Endpoint raw points and incident contributions are shown before the final score cap; correlation is additional to individual alert contributions. The organization score is the highest endpoint score, not a fleet average. Decimal values and timestamps use invariant formatting and UTC."));
            Paragraph(T("The report contains selected endpoint identities and typed security configuration evidence. Authentication credentials, tokens, signing material, status actors and arbitrary raw evidence are excluded."));
            _html.Append("</main></body></html>");
            return _html.ToString();
        }

        private void IncidentSection(string title, IReadOnlyList<ReportIncident> incidents, string empty)
        {
            Heading(title);
            if (incidents.Count == 0) { Paragraph(empty); return; }
            Paragraph(F("Showing {0} of {1} incidents. Management counts and scores use all retained records admitted by report capacity; detail is limited to 200 items per section.",
                Number(Math.Min(incidents.Count, SecurityReport.DetailedItemLimit)), Number(incidents.Count)));
            foreach (var incident in incidents.Take(SecurityReport.DetailedItemLimit))
            {
                _html.Append("<article class=\"incident\"><h3>");
                Text($"{Severity(incident.Severity)} — {T(incident.Title)}");
                _html.Append("</h3><dl>");
                Definition(T("Endpoint / ID"), $"{incident.EndpointName} / {incident.EndpointId:D}");
                Definition(T("Alert / rule"), $"{incident.AlertId:D} / {incident.RuleId}");
                Definition(T("Current stored status"), Status(incident.CurrentStatus));
                Definition(T("Current alert risk contribution"), Number(incident.CurrentRiskContribution));
                Definition(T("Retained first observation (UTC)"), Utc(incident.FirstObservedUtc));
                Definition(T("Latest stored technical evidence observed at (UTC)"), Utc(incident.LastObservedUtc));
                Definition(T("Period association"), F("First observation: {0}; latest observation: {1}; stored status transitions: {2}",
                    YesNo(incident.FirstObservedInPeriod), YesNo(incident.LastObservedInPeriod), Number(incident.StatusChangesInPeriod)));
                Definition(T("Resolved transitions inside selected period"), Number(incident.ResolutionsInPeriod));
                if (incident.LatestResolutionInPeriodUtc is not null)
                    Definition(T("Latest resolved transition inside period (UTC)"), Utc(incident.LatestResolutionInPeriodUtc));
                if (incident.ReopenedAfterPeriodResolution)
                    Definition(T("Later reopen"), T("Reopened after a resolved transition in the selected period; current status above is authoritative."));
                _html.Append("</dl>");
                Paragraph(T(incident.Reason));
                Paragraph(T("Technical evidence below is the latest stored positive observation. It is not evidence captured at each period transition and does not establish current effective runtime protection."));
                var allowed = AiContract.GetEvidenceFields(incident.RuleId);
                var evidence = incident.Evidence.Where(item => allowed is not null &&
                    allowed.TryGetValue(item.Field, out var kind) &&
                    ((kind == JsonValueKind.True && item.Value.ValueKind is JsonValueKind.True or JsonValueKind.False) ||
                     (kind == JsonValueKind.Number && item.Value.ValueKind == JsonValueKind.Number &&
                      item.Value.TryGetInt32(out var integer) && integer is >= 0 and <= 5)))
                    .OrderBy(item => item.Field, StringComparer.Ordinal).ToArray();
                if (evidence.Length == 0) Paragraph(T("Supported typed evidence is unavailable; arbitrary or malformed evidence is excluded."));
                else
                {
                    StartTable(T("Observed configuration field"), T("Typed value"));
                    foreach (var item in evidence)
                        Row(item.Field, item.Value.ValueKind == JsonValueKind.Number ? Number(item.Value.GetInt32())
                            : item.Value.GetBoolean() ? "true" : "false");
                    EndTable();
                }
                Paragraph(F("Recommended action: {0}", T(incident.RecommendedAction)));
                _html.Append("</article>");
            }
        }

        // Stored values that Desktop also shows translated; English keeps Core's own words.
        private string Severity(string value) => language == UiLanguage.English ? value : value switch
        {
            "critical" => T("Critical"), "high" => T("High"), "medium" => T("Medium"), "low" => T("Low"), "info" => T("Info"),
            _ => value
        };
        private string Status(string value) => language == UiLanguage.English ? value : value switch
        {
            "open" => T("Open"), "investigating" => T("Investigating"), "accepted" => T("Accepted"), "resolved" => T("Resolved"),
            _ => value
        };
        private string Health(string value) => language == UiLanguage.English ? value : value switch
        {
            "healthy" => T("Healthy"), "warning" => T("Warning"), "offline" => T("Offline"), "unknown" => T("Unknown"),
            _ => value
        };
        private string Priority(string value) => language == UiLanguage.English ? value : value switch
        {
            "coverage" => T("Coverage"), "health" => T("Reporting health"),
            _ => Severity(value)
        };
        private string YesNo(bool value) => value ? T("yes") : T("no");
        private string Utc(DateTimeOffset? value) =>
            value?.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture) ?? T("Not reported");

        private void Heading(string title) { _html.Append("<h2>"); Text(title); _html.Append("</h2>"); }
        private void Paragraph(string value) { _html.Append("<p>"); Text(value); _html.Append("</p>"); }
        private void Definition(string name, string value)
        {
            _html.Append("<dt>"); Text(name); _html.Append("</dt><dd>"); Text(value); _html.Append("</dd>");
        }
        private void StartTable(params string[] headings)
        {
            _html.Append("<table><thead><tr>");
            foreach (var heading in headings) { _html.Append("<th scope=\"col\">"); Text(heading); _html.Append("</th>"); }
            _html.Append("</tr></thead><tbody>");
        }
        private void Row(params string[] values)
        {
            _html.Append("<tr>");
            foreach (var value in values) { _html.Append("<td>"); Text(value); _html.Append("</td>"); }
            _html.Append("</tr>");
        }
        private void EndTable() => _html.Append("</tbody></table>");
        private void Text(string value) => _html.Append(_encoder.Encode(value));
        private static string Date(DateOnly value) => value.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        private static string Number(IFormattable value) => value.ToString(null, CultureInfo.InvariantCulture);
    }
}
