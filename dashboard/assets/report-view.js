const dayMilliseconds = 24 * 60 * 60 * 1000;

function utcDate(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value) || value.startsWith("0000-")) return null;
  const date = new Date(`${value}T00:00:00.000Z`);
  return Number.isNaN(date.getTime()) || date.toISOString().slice(0, 10) !== value ? null : date;
}

export function previousUtcMonth(now = new Date()) {
  const end = new Date(0);
  end.setUTCFullYear(now.getUTCFullYear(), now.getUTCMonth(), 0);
  const start = new Date(0);
  start.setUTCFullYear(end.getUTCFullYear(), end.getUTCMonth(), 1);
  return { from: start.toISOString().slice(0, 10), to: end.toISOString().slice(0, 10) };
}

export function reportRangeError(from, to) {
  const start = utcDate(from);
  const end = utcDate(to);
  if (!start || !end) return "Enter both UTC dates in YYYY-MM-DD format.";
  if (to === "9999-12-31") return "Choose a To date before 9999-12-31.";
  if (end < start) return "The To date must be on or after the From date.";
  if ((end - start) / dayMilliseconds + 1 > 366) return "Choose a date range of at most 366 inclusive UTC days.";
  return null;
}

export function reportPath(from, to) {
  return `/api/admin/reports/security?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`;
}
