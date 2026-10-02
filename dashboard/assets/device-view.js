const endpointIdPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const healthLabels = {
  healthy: "Healthy",
  warning: "Warning",
  offline: "Offline",
  unknown: "Unknown",
};

export function healthPresentation(state) {
  return Object.hasOwn(healthLabels, state)
    ? { label: healthLabels[state], className: `health-${state}` }
    : { label: healthLabels.unknown, className: "health-unknown" };
}

export function routeFromHash(hash) {
  if (!hash || hash === "#" || hash === "#/devices") return { kind: "list" };
  const match = /^#\/devices\/(.+)$/i.exec(hash);
  return match && endpointIdPattern.test(match[1])
    ? { kind: "detail", endpointId: match[1].toLowerCase() }
    : { kind: "invalid" };
}

export function isTrustedDashboardOrigin(location) {
  const hostname = location.hostname.toLowerCase();
  return location.protocol === "https:" ||
    (location.protocol === "http:" &&
      ["localhost", "127.0.0.1", "::1", "[::1]"].includes(hostname));
}

export function formatTimestamp(value, missing = "Never reported") {
  if (!value) return missing;
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? "Unknown"
    : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

export function formatBytes(value) {
  if (!Number.isFinite(value) || value < 0) return "Not reported";
  if (value < 1024) return `${value} B`;
  const units = ["KB", "MB", "GB", "TB", "PB"];
  let amount = value;
  let unit = -1;
  do {
    amount /= 1024;
    unit += 1;
  } while (amount >= 1024 && unit < units.length - 1);
  return `${new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 }).format(amount)} ${units[unit]}`;
}

export function firewallLabel(value) {
  return value === true ? "Enabled" : value === false ? "Disabled" : "Unknown";
}
