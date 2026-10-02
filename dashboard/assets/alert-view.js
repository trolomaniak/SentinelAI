const severityLabels = {
  info: "Information",
  low: "Low",
  medium: "Medium",
  high: "High",
  critical: "Critical",
};

export const alertStatuses = {
  open: "Open",
  investigating: "Investigating",
  resolved: "Resolved",
  accepted: "Accepted",
};

export function severityPresentation(severity) {
  return Object.hasOwn(severityLabels, severity)
    ? { label: severityLabels[severity], className: `severity-${severity}` }
    : { label: "Unknown", className: "health-unknown" };
}

export function alertStatusPresentation(status) {
  return Object.hasOwn(alertStatuses, status)
    ? { label: alertStatuses[status], className: `alert-${status}` }
    : { label: "Unknown", className: "health-unknown" };
}

export function alertListPath(severity, status, offset, limit = 50) {
  const query = new URLSearchParams();
  if (Object.hasOwn(severityLabels, severity)) query.set("severity", severity);
  if (Object.hasOwn(alertStatuses, status)) query.set("status", status);
  query.set("offset", String(offset));
  query.set("limit", String(limit));
  return `/api/admin/alerts?${query}`;
}

export function formatEvidence(value) {
  if (value == null) return "Unknown";
  if (typeof value === "boolean" || typeof value === "number" || typeof value === "string") return String(value);
  return "Unsupported value";
}
