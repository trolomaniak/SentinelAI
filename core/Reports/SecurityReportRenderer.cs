using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using SentinelAI.Contracts.Ai;

namespace SentinelAI.Core.Reports;

/// <summary>Standalone deterministic HTML. Every dynamic value is encoded and all assets are local.</summary>
public static class SecurityReportRenderer
{
    public static string Render(SecurityReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        var html = new StringBuilder(32768);
        html.Append("""
            <!doctype html>
            <html lang="en"><head><meta charset="utf-8">
            <meta name="viewport" content="width=device-width,initial-scale=1">
            <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; object-src 'none'; base-uri 'none'; frame-src 'none'; form-action 'none'">
            <title>SentinelAI local security report</title>
            <style>
            :root{color-scheme:light}body{font-family:system-ui,sans-serif;max-width:1120px;margin:2rem auto;padding:0 1rem;color:#17212e;background:#fff;line-height:1.5}h1{font-size:2rem}h2{margin-top:2rem;border-bottom:2px solid #dbe2ea;padding-bottom:.4rem}h3{margin-bottom:.4rem}.notice{background:#edf3fa;border-left:4px solid #345d86;padding:1rem}.muted{color:#43566b}table{border-collapse:collapse;width:100%;margin:1rem 0;font-size:.9rem}th,td{border:1px solid #cad5e0;padding:.5rem;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#edf3fa}dl{display:grid;grid-template-columns:minmax(12rem,1fr) 2fr;gap:.3rem 1rem}dt{font-weight:600}dd{margin:0;overflow-wrap:anywhere}.incident{border:1px solid #cad5e0;padding:1rem;margin:1rem 0;break-inside:avoid}code{overflow-wrap:anywhere}li{margin:.5rem 0}@media print{body{margin:0;max-width:none;font-size:10pt}h2{break-after:avoid}thead{display:table-header-group}.incident{break-inside:auto}}
            </style></head><body><main><h1>SentinelAI local security report</h1>
            """);
        html.Append("<dl>");
        Definition(html, "Reporting period (inclusive UTC dates)", $"{Date(report.Period.From)} through {Date(report.Period.To)}");
        Definition(html, "Generated / current state evaluated at (UTC)", Utc(report.GeneratedAtUtc));
        Definition(html, "Source", "Stored local SentinelAI data; deterministic policy and rules; no cloud AI required.");
        html.Append("</dl><p class=\"notice\">");
        Text(html, SecurityReport.ChronologyCaution);
        html.Append("</p>");

        Heading(html, "Management summary");
        html.Append("<dl>");
        Definition(html, "Organization risk score (security prioritization)", $"{Number(report.OrganizationRisk.Score)} / 100");
        Definition(html, "Score method", report.OrganizationRisk.Method);
        Definition(html, "Enrolled endpoints in current snapshot", Number(report.OrganizationRisk.EndpointCount));
        Definition(html, "Endpoints tied at highest current risk", Number(report.OrganizationRisk.HighestRiskEndpointCount));
        Definition(html, "Retained alerts associated with selected period", Number(report.Activity.AssociatedAlertCount));
        Definition(html, "New retained alerts first observed during period", Number(report.Activity.NewAlertCount));
        Definition(html, "Distinct alerts with a resolved transition during period", Number(report.Activity.ResolvedAlertCount));
        Definition(html, "Score trend", SecurityReport.UnavailableTrend);
        html.Append("</dl>");
        Paragraph(html, report.OrganizationRisk.Explanation);
        Paragraph(html, "Higher scores prioritize recorded configuration risks. A zero score does not establish endpoint safety. " +
            "Unknown or stale observations can conceal risks. Accepted and Investigating do not reduce remaining risk; " +
            "Resolved changes the current score contribution but does not itself remediate an endpoint.");
        if (report.Endpoints.Count == 0)
            Paragraph(html, "No enrolled endpoints are stored. No endpoint security assurance can be made from this empty fleet.");

        Heading(html, "Retained activity in the selected UTC period");
        Paragraph(html, "Associated alerts have a retained first observation, retained latest observation, or stored status transition " +
            "inside the selected interval. Severity below is the latest stored severity, not a historical severity snapshot. " +
            "Resolved counts include alerts later reopened and count each alert once, even if resolved repeatedly.");
        StartTable(html, "Latest severity", "Period-associated retained alerts", "New retained alerts");
        foreach (var count in report.Activity.SeverityCounts)
            Row(html, count.Severity, Number(count.AssociatedAlerts), Number(count.NewAlerts));
        EndTable(html);

        Heading(html, "Current endpoint health and risk");
        Paragraph(html, "Health uses the latest stored heartbeat at generation: Healthy up to 2 minutes; Warning over 2 through 5 minutes; " +
            "Offline over 5 minutes; Unknown without a heartbeat. This is reporting freshness, not historical uptime or endpoint safety.");
        StartTable(html, "Healthy", "Warning", "Offline", "Unknown");
        Row(html, Number(report.Health.Healthy), Number(report.Health.Warning), Number(report.Health.Offline), Number(report.Health.Unknown));
        EndTable(html);
        html.Append("<dl>");
        Definition(html, "Missing inventories", Number(report.Endpoints.Count(endpoint => endpoint.CurrentRisk.Coverage.InventoryState == "missing")));
        Definition(html, "Stale inventories", Number(report.Endpoints.Count(endpoint => endpoint.CurrentRisk.Coverage.InventoryState == "stale")));
        Definition(html, "Future-dated inventories", Number(report.Endpoints.Count(endpoint => endpoint.CurrentRisk.Coverage.InventoryState == "future")));
        Definition(html, "Unknown supported-rule coverage", Number(report.Endpoints.Count(endpoint => endpoint.CurrentRisk.Coverage.SignalCoverage == "unknown")));
        Definition(html, "Partial supported-rule coverage", Number(report.Endpoints.Count(endpoint => endpoint.CurrentRisk.Coverage.SignalCoverage == "partial")));
        Definition(html, "Inventory freshness expectation", $"Within {Number(report.InventoryFreshForHours)} hours");
        html.Append("</dl>");
        Paragraph(html, "Coverage counts only the 13 supported Windows configuration rules. Missing or unknown signals receive no score; " +
            "complete supported-rule coverage does not establish overall endpoint protection. Criticality and exposure are operator declarations " +
            "or explicit policy defaults, not inferred Internet exposure.");
        var endpoints = report.Endpoints.OrderByDescending(endpoint => endpoint.CurrentRisk.Risk.Score)
            .ThenByDescending(endpoint => endpoint.CurrentRisk.Risk.RawScore).ThenBy(endpoint => endpoint.EndpointId).ToArray();
        LimitNotice(html, endpoints.Length, "endpoints");
        StartTable(html, "Endpoint / ID", "Current reporting health / last heartbeat UTC", "Current risk / raw points", "Latest inventory UTC", "Coverage", "Criticality / exposure assumptions");
        foreach (var endpoint in endpoints.Take(SecurityReport.DetailedItemLimit))
        {
            var risk = endpoint.CurrentRisk;
            Row(html, $"{endpoint.EndpointName} / {endpoint.EndpointId:D}", $"{endpoint.Health} / {Utc(endpoint.LastSeenUtc)}",
                $"{Number(risk.Risk.Score)} / 100; raw {Number(risk.Risk.RawScore)}", Utc(risk.InventoryCollectedUtc),
                $"{risk.Coverage.InventoryState}; {risk.Coverage.SignalCoverage}; {Number(risk.Coverage.KnownRuleSignals)} of {Number(risk.Coverage.TotalRuleSignals)} known",
                $"{risk.Risk.Context.AssetCriticality} ({risk.Risk.Context.AssetCriticalitySource}) / {risk.Risk.Context.Exposure} ({risk.Risk.Context.ExposureSource})");
        }
        EndTable(html);

        IncidentSection(html, "Critical/high incidents associated with the period",
            report.PeriodIncidents.Where(incident => incident.Severity is "critical" or "high").ToArray(),
            "No critical or high retained incidents are associated with this period; missing observations remain unknown.");
        IncidentSection(html, "Incidents resolved during the period",
            report.PeriodIncidents.Where(incident => incident.ResolutionsInPeriod > 0).ToArray(),
            "No retained alert has a stored resolved transition inside this period.");
        IncidentSection(html, "Current major security posture findings", report.MajorPostureFindings,
            "No tracked unresolved configuration findings are stored. This does not establish endpoint safety.");

        Heading(html, "Recommended priority actions");
        Paragraph(html, "Deterministic local recommendations prioritize current unresolved findings by severity, current risk contribution, " +
            "and rule ID, followed by telemetry gaps. Review compatibility and approved policy before making changes. This report performs no remediation.");
        if (report.PriorityActions.Count == 0)
            Paragraph(html, "Continue approved monitoring and validate coverage; absence of a recommended finding does not establish safety.");
        else
        {
            html.Append("<ol>");
            foreach (var action in report.PriorityActions)
            {
                html.Append("<li><strong>");
                Text(html, $"{action.Priority} / {action.RuleId} — {Number(action.AffectedEndpointCount)} endpoint(s)");
                html.Append("</strong>: ");
                Text(html, action.Action);
                html.Append("<br>");
                Text(html, $"{action.Reason} Current summed alert contribution: {Number(action.CurrentRiskContribution)} points.");
                html.Append("</li>");
            }
            html.Append("</ol>");
        }

        Heading(html, "Current deterministic scoring policy");
        html.Append("<dl>");
        Definition(html, "Policy version", report.Policy.Version);
        Definition(html, "Final score cap", Number(report.Policy.MaximumScore));
        Definition(html, "Confidence default evidence weight", Number(report.Policy.DefaultConfidence));
        Definition(html, "Full age weight", $"Through {Number(report.Policy.FreshForDays)} days: 1");
        Definition(html, "Aging age weight", $"Over {Number(report.Policy.FreshForDays)} through {Number(report.Policy.AgingForDays)} days: {Number(report.Policy.AgingMultiplier)}");
        Definition(html, "Older observation weight", Number(report.Policy.OldMultiplier));
        Definition(html, "Correlation bonus", $"{Number(report.Policy.CorrelationPointsPerExtraGroup)} per extra distinct confirmed group; base cap {Number(report.Policy.MaximumCorrelationBaseBonus)}");
        html.Append("</dl>");
        StartTable(html, "Severity", "Base points");
        foreach (var severity in new[] { "critical", "high", "medium", "low", "info" })
            Row(html, severity, Number(report.Policy.SeverityPoints[severity]));
        EndTable(html);
        Paragraph(html, "Risk uses current policy, severity, configured confidence weight, asset criticality, exposure, observation age and current status, " +
            "plus bounded correlation confirmed by the latest inventory. Confidence is not statistical probability. Age discounts do not prove remediation. " +
            "Endpoint raw points and incident contributions are shown before the final score cap; correlation is additional to individual alert contributions. " +
            "The organization score is the highest endpoint score, not a fleet average. Decimal values and timestamps use invariant formatting and UTC.");
        Paragraph(html, "The report contains selected endpoint identities and typed security configuration evidence. " +
            "Authentication credentials, tokens, signing material, status actors and arbitrary raw evidence are excluded.");
        html.Append("</main></body></html>");
        return html.ToString();
    }

    private static void IncidentSection(StringBuilder html, string title, IReadOnlyList<ReportIncident> incidents, string empty)
    {
        Heading(html, title);
        if (incidents.Count == 0) { Paragraph(html, empty); return; }
        LimitNotice(html, incidents.Count, "incidents");
        foreach (var incident in incidents.Take(SecurityReport.DetailedItemLimit))
        {
            html.Append("<article class=\"incident\"><h3>");
            Text(html, $"{incident.Severity} — {incident.Title}");
            html.Append("</h3><dl>");
            Definition(html, "Endpoint / ID", $"{incident.EndpointName} / {incident.EndpointId:D}");
            Definition(html, "Alert / rule", $"{incident.AlertId:D} / {incident.RuleId}");
            Definition(html, "Current stored status", incident.CurrentStatus);
            Definition(html, "Current alert risk contribution", Number(incident.CurrentRiskContribution));
            Definition(html, "Retained first observation (UTC)", Utc(incident.FirstObservedUtc));
            Definition(html, "Latest stored technical evidence observed at (UTC)", Utc(incident.LastObservedUtc));
            Definition(html, "Period association", $"First observation: {YesNo(incident.FirstObservedInPeriod)}; latest observation: {YesNo(incident.LastObservedInPeriod)}; stored status transitions: {Number(incident.StatusChangesInPeriod)}");
            Definition(html, "Resolved transitions inside selected period", Number(incident.ResolutionsInPeriod));
            if (incident.LatestResolutionInPeriodUtc is not null)
                Definition(html, "Latest resolved transition inside period (UTC)", Utc(incident.LatestResolutionInPeriodUtc));
            if (incident.ReopenedAfterPeriodResolution)
                Definition(html, "Later reopen", "Reopened after a resolved transition in the selected period; current status above is authoritative.");
            html.Append("</dl>");
            Paragraph(html, incident.Reason);
            Paragraph(html, "Technical evidence below is the latest stored positive observation. It is not evidence captured at each period transition and does not establish current effective runtime protection.");
            var allowed = AiContract.GetEvidenceFields(incident.RuleId);
            var evidence = incident.Evidence.Where(item => allowed is not null &&
                allowed.TryGetValue(item.Field, out var kind) &&
                ((kind == JsonValueKind.True && item.Value.ValueKind is JsonValueKind.True or JsonValueKind.False) ||
                 (kind == JsonValueKind.Number && item.Value.ValueKind == JsonValueKind.Number &&
                  item.Value.TryGetInt32(out var integer) && integer is >= 0 and <= 5)))
                .OrderBy(item => item.Field, StringComparer.Ordinal).ToArray();
            if (evidence.Length == 0) Paragraph(html, "Supported typed evidence is unavailable; arbitrary or malformed evidence is excluded.");
            else
            {
                StartTable(html, "Observed configuration field", "Typed value");
                foreach (var item in evidence)
                    Row(html, item.Field, item.Value.ValueKind == JsonValueKind.Number ? Number(item.Value.GetInt32())
                        : item.Value.GetBoolean() ? "true" : "false");
                EndTable(html);
            }
            Paragraph(html, $"Recommended action: {incident.RecommendedAction}");
            html.Append("</article>");
        }
    }

    private static void LimitNotice(StringBuilder html, int total, string kind) => Paragraph(html,
        $"Showing {Number(Math.Min(total, SecurityReport.DetailedItemLimit))} of {Number(total)} {kind}. " +
        "Management counts and scores use all retained records admitted by report capacity; detail is limited to 200 items per section.");
    private static void Heading(StringBuilder html, string title) { html.Append("<h2>"); Text(html, title); html.Append("</h2>"); }
    private static void Paragraph(StringBuilder html, string value) { html.Append("<p>"); Text(html, value); html.Append("</p>"); }
    private static void Definition(StringBuilder html, string name, string value)
    {
        html.Append("<dt>"); Text(html, name); html.Append("</dt><dd>"); Text(html, value); html.Append("</dd>");
    }
    private static void StartTable(StringBuilder html, params string[] headings)
    {
        html.Append("<table><thead><tr>");
        foreach (var heading in headings) { html.Append("<th scope=\"col\">"); Text(html, heading); html.Append("</th>"); }
        html.Append("</tr></thead><tbody>");
    }
    private static void Row(StringBuilder html, params string[] values)
    {
        html.Append("<tr>");
        foreach (var value in values) { html.Append("<td>"); Text(html, value); html.Append("</td>"); }
        html.Append("</tr>");
    }
    private static void EndTable(StringBuilder html) => html.Append("</tbody></table>");
    private static void Text(StringBuilder html, string value) => html.Append(HtmlEncoder.Default.Encode(value));
    private static string Date(DateOnly value) => value.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
    private static string Utc(DateTimeOffset? value) => value?.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture) ?? "Not reported";
    private static string Number(IFormattable value) => value.ToString(null, CultureInfo.InvariantCulture);
    private static string YesNo(bool value) => value ? "yes" : "no";
}
