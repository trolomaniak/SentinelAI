import {
  firewallLabel,
  formatBytes,
  formatTimestamp,
  healthPresentation,
  isTrustedDashboardOrigin,
  routeFromHash,
} from "./device-view.js";
import {
  alertListPath,
  alertStatuses,
  alertStatusPresentation,
  formatEvidence,
  severityPresentation,
} from "./alert-view.js";

const loginView = document.querySelector("#login-view");
const devicesView = document.querySelector("#devices-view");
const detailView = document.querySelector("#detail-view");
const loginForm = document.querySelector("#login-form");
const loginMessage = document.querySelector("#login-message");
const signOutButton = document.querySelector("#sign-out");
const devicesStatus = document.querySelector("#devices-status");
const devicesContent = document.querySelector("#devices-content");
const detailStatus = document.querySelector("#detail-status");
const detailContent = document.querySelector("#detail-content");
const alertsView = document.querySelector("#alerts-view");
const alertDetailView = document.querySelector("#alert-detail-view");
const alertsStatus = document.querySelector("#alerts-status");
const alertsContent = document.querySelector("#alerts-content");
const alertDetailStatus = document.querySelector("#alert-detail-status");
const alertDetailContent = document.querySelector("#alert-detail-content");
const severityFilter = document.querySelector("#severity-filter");
const statusFilter = document.querySelector("#status-filter");
const pagination = document.querySelector("#alerts-pagination");
const previousPage = document.querySelector("#alerts-previous");
const nextPage = document.querySelector("#alerts-next");
const trustedOrigin = isTrustedDashboardOrigin(window.location);

let accessToken = null;
let navigationVersion = 0;
let alertOffset = 0;
const alertPageSize = 50;

class ApiError extends Error {
  constructor(status) {
    super(`Core returned HTTP ${status}`);
    this.status = status;
  }
}

class SessionExpired extends Error {}

function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function setView(name) {
  loginView.hidden = name !== "login";
  devicesView.hidden = name !== "devices";
  detailView.hidden = name !== "detail";
  alertsView.hidden = name !== "alerts";
  alertDetailView.hidden = name !== "alert-detail";
  signOutButton.hidden = !accessToken;
  document.querySelector("#workspace-nav").hidden = !accessToken;
  document.querySelector("#devices-nav").setAttribute("aria-current", ["devices", "detail"].includes(name) ? "page" : "false");
  document.querySelector("#alerts-nav").setAttribute("aria-current", ["alerts", "alert-detail"].includes(name) ? "page" : "false");
  document.title = `${["alerts", "alert-detail"].includes(name) ? "Alerts" : name === "login" ? "Sign in" : "Devices"} · SentinelAI`;
}

function showLogin(message = trustedOrigin ? "" : "Open Core with HTTPS to sign in from another computer.") {
  setView("login");
  loginMessage.textContent = message;
  loginMessage.hidden = !message;
}

function expireSession() {
  accessToken = null;
  navigationVersion += 1;
  devicesContent.replaceChildren();
  detailContent.replaceChildren();
  alertsContent.replaceChildren();
  alertDetailContent.replaceChildren();
  showLogin("Your session ended. Sign in again to continue.");
}

async function requestCore(path, method = "GET", body) {
  const requestedToken = accessToken;
  const response = await fetch(path, {
    method,
    headers: { Authorization: `Bearer ${requestedToken}`, ...(body ? { "Content-Type": "application/json" } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {}),
    cache: "no-store",
    credentials: "omit",
  });
  if (response.status === 401) {
    if (requestedToken === accessToken) expireSession();
    throw new SessionExpired();
  }
  if (!response.ok) throw new ApiError(response.status);
  return response.json();
}

function getFromCore(path) {
  return requestCore(path);
}

function renderStatusBadge(state) {
  const presentation = healthPresentation(state);
  return node("span", `status-badge ${presentation.className}`, presentation.label);
}

function renderTime(value, missing = "Never reported") {
  const formatted = formatTimestamp(value, missing);
  if (!value || formatted === "Unknown") return node("span", "muted", formatted);
  const element = node("time", null, formatted);
  element.dateTime = value;
  return element;
}

function renderStatePanel(title, description, retry) {
  const panel = node("div", "panel state-panel");
  panel.append(node("h2", null, title), node("p", null, description));
  if (retry) {
    const button = node("button", "button button-secondary", "Try again");
    button.type = "button";
    button.addEventListener("click", retry);
    panel.append(button);
  }
  return panel;
}

function renderDeviceTable(devices) {
  const wrapper = node("div", "panel table-wrap");
  const table = node("table", "device-table");
  const caption = node("caption", "visually-hidden", "Enrolled devices and their latest state");
  const thead = node("thead");
  const header = node("tr");
  for (const label of ["Endpoint", "Operating system", "Health", "Last seen", "Agent", "Last reported firewall settings"]) {
    const cell = node("th", null, label);
    cell.scope = "col";
    header.append(cell);
  }
  thead.append(header);
  const tbody = node("tbody");
  for (const device of devices) {
    const row = node("tr");
    const nameCell = node("td");
    const link = node("a", "device-name", device.name || "Unnamed endpoint");
    link.href = `#/devices/${encodeURIComponent(device.endpointId)}`;
    nameCell.append(link);
    row.append(nameCell);
    row.append(node("td", "secondary-cell", device.operatingSystem || "Not reported"));
    const healthCell = node("td");
    healthCell.append(renderStatusBadge(device.healthState));
    row.append(healthCell);
    const seenCell = node("td", "secondary-cell");
    seenCell.append(renderTime(device.lastSeenUtc));
    row.append(seenCell);
    row.append(node("td", "secondary-cell", device.agentVersion || "Not reported"));
    row.append(node("td", "secondary-cell", device.securityPostureSummary || "Unknown"));
    tbody.append(row);
  }
  table.append(caption, thead, tbody);
  wrapper.append(table);
  return wrapper;
}

async function loadDevices() {
  const version = ++navigationVersion;
  setView("devices");
  devicesStatus.textContent = "Loading devices…";
  devicesContent.replaceChildren();
  try {
    const devices = await getFromCore("/api/admin/devices");
    if (version !== navigationVersion || !accessToken) return;
    if (!Array.isArray(devices)) throw new Error("Invalid device response");
    if (devices.length === 0) {
      devicesStatus.textContent = "No enrolled devices";
      devicesContent.append(renderStatePanel(
        "No devices yet",
        "Enrolled endpoints will appear here after they connect to Core.",
        loadDevices,
      ));
      return;
    }
    devicesStatus.textContent = `${devices.length} enrolled ${devices.length === 1 ? "device" : "devices"}`;
    devicesContent.append(renderDeviceTable(devices));
  } catch (error) {
    if (error instanceof SessionExpired || version !== navigationVersion) return;
    devicesStatus.textContent = "Could not load devices";
    devicesContent.append(renderStatePanel(
      "Devices are unavailable",
      "Core could not return the device list. Check the connection and try again.",
      loadDevices,
    ));
  }
}

function factGrid(facts) {
  const grid = node("dl", "fact-grid");
  for (const [label, value] of facts) {
    const item = node("div");
    item.append(node("dt", null, label));
    const description = node("dd");
    description.append(value instanceof Node ? value : document.createTextNode(value));
    item.append(description);
    grid.append(item);
  }
  return grid;
}

function detailPanel(title, content) {
  const panel = node("section", "panel detail-panel");
  panel.append(node("h2", null, title), content);
  return panel;
}

function renderDetail(detail) {
  const device = detail.device;
  const header = node("div", "detail-heading");
  header.append(node("h1", null, device.name || "Unnamed endpoint"), renderStatusBadge(device.healthState));
  header.querySelector("h1").id = "detail-heading";
  detailContent.append(header, node("p", "lead", "Latest information reported to SentinelAI Core."));

  const grid = node("div", "detail-grid");
  grid.append(detailPanel("Device status", factGrid([
    ["Health", healthPresentation(device.healthState).label],
    ["Last seen", renderTime(device.lastSeenUtc)],
    ["Operating system", device.operatingSystem || "Not reported"],
    ["OS version", detail.osVersion || "Not reported"],
    ["Agent version", device.agentVersion || "Not reported"],
    ["Inventory collected", renderTime(detail.inventoryCollectedUtc, "Not received")],
  ])));

  const cpu = detail.cpu;
  grid.append(detailPanel("System inventory", factGrid([
    ["Architecture", detail.architecture || "Not reported"],
    ["Processor", cpu?.model || "Not reported"],
    ["Logical processors", cpu?.logicalProcessorCount == null ? "Not reported" : String(cpu.logicalProcessorCount)],
    ["Installed RAM", formatBytes(detail.installedRamBytes)],
  ])));

  const posture = detail.securityPosture;
  grid.append(detailPanel("Last reported firewall settings", factGrid([
    ["Summary", device.securityPostureSummary || "Firewall status unknown"],
    ["Domain profile", firewallLabel(posture?.domainFirewallEnabled)],
    ["Private profile", firewallLabel(posture?.privateFirewallEnabled)],
    ["Public profile", firewallLabel(posture?.publicFirewallEnabled)],
  ])));

  const disks = Array.isArray(detail.disks) ? detail.disks : [];
  const diskContent = disks.length ? node("ul", "stack-list") : node("p", "muted", "No fixed-disk information reported.");
  for (const disk of disks) {
    const item = node("li");
    item.append(node("strong", null, disk.name || "Local disk"));
    item.append(node("span", "value", `${formatBytes(disk.availableBytes)} free of ${formatBytes(disk.totalBytes)}`));
    diskContent.append(item);
  }
  grid.append(detailPanel("Local disks", diskContent));
  detailContent.append(grid);
}

async function loadDetail(endpointId) {
  const version = ++navigationVersion;
  setView("detail");
  detailStatus.textContent = "Loading device details…";
  detailContent.replaceChildren();
  try {
    const detail = await getFromCore(`/api/admin/devices/${endpointId}`);
    if (version !== navigationVersion || !accessToken) return;
    if (!detail?.device) throw new Error("Invalid detail response");
    detailStatus.textContent = "";
    renderDetail(detail);
  } catch (error) {
    if (error instanceof SessionExpired || version !== navigationVersion) return;
    const missing = error instanceof ApiError && error.status === 404;
    detailStatus.textContent = missing ? "Device not found" : "Could not load device details";
    detailContent.append(renderStatePanel(
      missing ? "Device not found" : "Device details are unavailable",
      missing
        ? "This endpoint may have been removed or the link is incorrect."
        : "Core could not return this endpoint. Check the connection and try again.",
      missing ? null : () => loadDetail(endpointId),
    ));
  }
}

function renderAlertBadge(value, presentation) {
  const badge = presentation(value);
  return node("span", `status-badge ${badge.className}`, badge.label);
}

function renderEndpointLink(alert) {
  const text = alert.endpointName || "Unnamed endpoint";
  if (routeFromHash(`#/devices/${alert.endpointId}`).kind !== "detail") return node("span", null, text);
  const link = node("a", "device-name", text);
  link.href = `#/devices/${alert.endpointId}`;
  return link;
}

function renderAlertTable(alerts) {
  const wrapper = node("div", "panel table-wrap");
  const table = node("table", "device-table alert-table");
  const thead = node("thead");
  const header = node("tr");
  for (const label of ["Alert", "Endpoint", "Severity", "Status", "First observed", "Last observed"]) {
    const cell = node("th", null, label);
    cell.scope = "col";
    header.append(cell);
  }
  thead.append(header);
  const tbody = node("tbody");
  for (const alert of alerts) {
    const row = node("tr");
    const titleCell = node("td");
    const title = node("a", "alert-title", alert.title || "Untitled alert");
    if (routeFromHash(`#/alerts/${alert.alertId}`).kind === "alert-detail") title.href = `#/alerts/${alert.alertId}`;
    titleCell.append(title, node("span", "rule-id", alert.ruleId || "Unknown rule"));
    const endpointCell = node("td");
    endpointCell.append(renderEndpointLink(alert));
    const severityCell = node("td");
    severityCell.append(renderAlertBadge(alert.severity, severityPresentation));
    const statusCell = node("td");
    statusCell.append(renderAlertBadge(alert.status, alertStatusPresentation));
    const firstCell = node("td", "secondary-cell");
    firstCell.append(renderTime(alert.firstObservedUtc, "Unknown"));
    const lastCell = node("td", "secondary-cell");
    lastCell.append(renderTime(alert.lastObservedUtc, "Unknown"));
    row.append(titleCell, endpointCell, severityCell, statusCell, firstCell, lastCell);
    tbody.append(row);
  }
  table.append(node("caption", "visually-hidden", "Detected security alerts and their review status"), thead, tbody);
  wrapper.append(table);
  return wrapper;
}

async function loadAlerts() {
  const version = ++navigationVersion;
  setView("alerts");
  alertsStatus.textContent = "Loading alerts…";
  alertsContent.replaceChildren();
  pagination.hidden = true;
  previousPage.disabled = true;
  nextPage.disabled = true;
  try {
    const page = await getFromCore(alertListPath(severityFilter.value, statusFilter.value, alertOffset, alertPageSize));
    if (version !== navigationVersion || !accessToken) return;
    if (!Array.isArray(page?.alerts) || !Number.isInteger(page.total) || !Number.isInteger(page.offset) || !Number.isInteger(page.limit)) {
      throw new Error("Invalid alerts response");
    }
    alertOffset = page.offset;
    if (!page.alerts.length) {
      alertsStatus.textContent = "No matching alerts";
      alertsContent.append(renderStatePanel(
        "No matching alerts",
        "No findings match these filters. An empty list does not establish that an endpoint is protected; some settings may be unknown or unsupported.",
        loadAlerts,
      ));
    } else {
      alertsStatus.textContent = `${page.offset + 1}–${page.offset + page.alerts.length} of ${page.total} ${page.total === 1 ? "alert" : "alerts"}`;
      alertsContent.append(renderAlertTable(page.alerts));
    }
    previousPage.disabled = page.offset === 0;
    nextPage.disabled = page.offset + page.limit >= page.total;
    pagination.hidden = previousPage.disabled && nextPage.disabled;
  } catch (error) {
    if (error instanceof SessionExpired || version !== navigationVersion) return;
    alertsStatus.textContent = "Could not load alerts";
    alertsContent.append(renderStatePanel("Alerts are unavailable", "Core could not return alerts. Check the connection and try again.", loadAlerts));
  }
}

function renderEvidence(evidence) {
  if (!Array.isArray(evidence) || !evidence.length) return node("p", "muted", "No evidence was recorded.");
  const table = node("table", "evidence-table");
  const header = node("tr");
  for (const label of ["Observed field", "Reported value"]) {
    const cell = node("th", null, label);
    cell.scope = "col";
    header.append(cell);
  }
  const thead = node("thead");
  thead.append(header);
  const tbody = node("tbody");
  for (const observation of evidence) {
    const row = node("tr");
    row.append(node("td", null, observation.field || "Unknown field"), node("td", null, formatEvidence(observation.value)));
    tbody.append(row);
  }
  table.append(thead, tbody);
  return table;
}

function renderStatusHistory(history) {
  if (!Array.isArray(history) || !history.length) return node("p", "muted", "No status history was recorded.");
  const list = node("ol", "history-list");
  for (const transition of history) {
    const item = node("li");
    const current = alertStatusPresentation(transition.status).label;
    const previous = transition.previousStatus ? alertStatusPresentation(transition.previousStatus).label : null;
    item.append(node("strong", null, previous ? `${previous} → ${current}` : current));
    item.append(node("span", "history-meta", transition.changedBy || "Core"), renderTime(transition.changedUtc, "Unknown"));
    list.append(item);
  }
  return list;
}

function renderAlertDetail(alert, feedback = "") {
  alertDetailContent.replaceChildren();
  const header = node("div", "detail-heading");
  const title = node("h1", null, alert.title || "Untitled alert");
  title.id = "alert-detail-heading";
  header.append(title, renderAlertBadge(alert.severity, severityPresentation), renderAlertBadge(alert.status, alertStatusPresentation));
  alertDetailContent.append(header, node("p", "lead", "A recorded finding from reported configuration. Evidence reflects the last matching observation, not a live protection check."));

  const grid = node("div", "detail-grid");
  grid.append(detailPanel("What happened?", node("p", "alert-copy", alert.title || "Untitled alert")));
  grid.append(detailPanel("Why is it risky?", node("p", "alert-copy", alert.reason || "No reason was recorded.")));
  grid.append(detailPanel("Which endpoint?", factGrid([
    ["Endpoint", renderEndpointLink(alert)],
    ["Endpoint ID", alert.endpointId || "Unknown"],
    ["Rule", alert.ruleId || "Unknown"],
    ["Severity", severityPresentation(alert.severity).label],
  ])));
  grid.append(detailPanel("What should the administrator do?", node("p", "alert-copy", alert.recommendedAction || "No recommended action was recorded.")));
  const evidencePanel = detailPanel("What evidence supports it?", renderEvidence(alert.evidence));
  evidencePanel.className += " wide-panel";
  grid.append(evidencePanel);
  grid.append(detailPanel("Observation times", factGrid([
    ["First observed", renderTime(alert.firstObservedUtc, "Unknown")],
    ["Last observed", renderTime(alert.lastObservedUtc, "Unknown")],
    ["Stored in Core", renderTime(alert.createdUtc, "Unknown")],
    ["Last updated", renderTime(alert.updatedUtc, "Unknown")],
    ["Status changed", renderTime(alert.statusChangedUtc, "Unknown")],
  ])));

  const form = node("form", "alert-status-form");
  form.id = "alert-status-form";
  const label = node("label", null, "Review status");
  label.htmlFor = "alert-status-select";
  const select = node("select");
  select.id = "alert-status-select";
  for (const [value, text] of Object.entries(alertStatuses)) {
    const option = node("option", null, text);
    option.value = value;
    select.append(option);
  }
  select.value = alert.status;
  const save = node("button", "button button-primary", "Save status");
  save.id = "save-alert-status";
  save.type = "submit";
  save.disabled = true;
  select.addEventListener("change", () => { save.disabled = select.value === alert.status; });
  const message = node("p", "status-feedback", feedback);
  message.id = "alert-status-message";
  message.setAttribute("role", "status");
  message.setAttribute("aria-live", "polite");
  message.hidden = !feedback;
  form.append(label, select, save, node("p", "helper-text", "Changing status records your review; it does not change endpoint configuration. Resolved alerts may reopen after a newer risky observation. Accepted alerts remain accepted when the risk is reported again."), message);
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    if (!save.disabled) saveAlertStatus(alert, select, save, message);
  });
  grid.append(detailPanel("Administrator review", form));
  const history = detailPanel("Status history", renderStatusHistory(alert.statusHistory));
  if (alert.statusHistoryCount > (alert.statusHistory?.length || 0)) {
    history.append(node("p", "helper-text", `Showing the latest ${alert.statusHistory.length} of ${alert.statusHistoryCount} status changes.`));
  }
  history.className += " wide-panel";
  grid.append(history);
  alertDetailContent.append(grid);
}

async function saveAlertStatus(alert, select, save, message) {
  const version = navigationVersion;
  const requestedStatus = select.value;
  save.disabled = true;
  select.disabled = true;
  message.hidden = false;
  message.textContent = "Saving status…";
  try {
    const updated = await requestCore(`/api/admin/alerts/${alert.alertId}/status`, "PUT", { status: requestedStatus, expectedVersion: alert.version });
    if (version !== navigationVersion || !accessToken) return;
    renderAlertDetail(updated, `Status saved: ${alertStatusPresentation(updated.status).label}.`);
  } catch (error) {
    if (error instanceof SessionExpired || version !== navigationVersion || !accessToken) return;
    if (error instanceof ApiError && error.status === 409) {
      try {
        const current = await getFromCore(`/api/admin/alerts/${alert.alertId}`);
        if (version !== navigationVersion || !accessToken) return;
        renderAlertDetail(current, `This alert changed while you were reviewing it. Current status: ${alertStatusPresentation(current.status).label}. Your change to ${alertStatusPresentation(requestedStatus).label} was not saved. Review the latest evidence and choose a status again.`);
        return;
      } catch (reloadError) {
        if (reloadError instanceof SessionExpired || version !== navigationVersion || !accessToken) return;
        message.textContent = "This alert changed and your status was not saved. Reload the alert before trying again.";
        // The old version is stale. Only a fresh detail request can safely enable another save.
        const retry = node("button", "button button-secondary", "Reload alert");
        retry.type = "button";
        retry.addEventListener("click", () => loadAlertDetail(alert.alertId));
        message.append(retry);
        return;
      }
    }
    if (error instanceof ApiError && error.status === 404) {
      alertDetailStatus.textContent = "Alert not found";
      alertDetailContent.replaceChildren(renderStatePanel("Alert not found", "This alert may have been removed. Return to the alert list."));
      return;
    }
    message.textContent = error instanceof ApiError && error.status === 400
      ? "Core did not accept this status. Reload the alert and try again."
      : "Could not save status. Your change is still selected; check the connection and try again.";
    save.disabled = false;
    select.disabled = false;
  }
}

async function loadAlertDetail(alertId) {
  const version = ++navigationVersion;
  setView("alert-detail");
  alertDetailStatus.textContent = "Loading alert details…";
  alertDetailContent.replaceChildren();
  try {
    const alert = await getFromCore(`/api/admin/alerts/${alertId}`);
    if (version !== navigationVersion || !accessToken) return;
    if (!alert?.alertId || !Number.isInteger(alert.version)) throw new Error("Invalid alert response");
    alertDetailStatus.textContent = "";
    renderAlertDetail(alert);
  } catch (error) {
    if (error instanceof SessionExpired || version !== navigationVersion) return;
    const missing = error instanceof ApiError && error.status === 404;
    alertDetailStatus.textContent = missing ? "Alert not found" : "Could not load alert details";
    alertDetailContent.append(renderStatePanel(
      missing ? "Alert not found" : "Alert details are unavailable",
      missing ? "This alert may have been removed or the link is incorrect." : "Core could not return this alert. Check the connection and try again.",
      missing ? null : () => loadAlertDetail(alertId),
    ));
  }
}

function loadRoute() {
  if (!accessToken) {
    showLogin();
    return;
  }
  const route = routeFromHash(window.location.hash);
  if (route.kind === "list") {
    loadDevices();
  } else if (route.kind === "detail") {
    loadDetail(route.endpointId);
  } else if (route.kind === "alerts") {
    loadAlerts();
  } else if (route.kind === "alert-detail") {
    loadAlertDetail(route.alertId);
  } else {
    navigationVersion += 1;
    setView("detail");
    detailStatus.textContent = "Invalid link";
    detailContent.replaceChildren(renderStatePanel(
      "Invalid link",
      "Open a device or alert from its list to view details.",
    ));
  }
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!trustedOrigin) return;
  const submit = document.querySelector("#login-submit");
  const passwordInput = document.querySelector("#password");
  submit.disabled = true;
  loginMessage.hidden = true;
  try {
    const response = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: document.querySelector("#username").value,
        password: passwordInput.value,
      }),
      cache: "no-store",
      credentials: "omit",
    });
    if (!response.ok) {
      throw new ApiError(response.status);
    }
    const result = await response.json();
    if (typeof result.accessToken !== "string" || !result.accessToken) throw new Error("Missing access token");
    accessToken = result.accessToken;
    loadRoute();
  } catch (error) {
    showLogin(error instanceof ApiError && error.status === 401
      ? "Username or password was not accepted."
      : error instanceof ApiError && error.status === 429
        ? "Too many attempts. Wait a minute and try again."
        : "Could not sign in. Check the Core connection and try again.");
  } finally {
    passwordInput.value = "";
    submit.disabled = false;
  }
});

signOutButton.addEventListener("click", () => {
  accessToken = null;
  navigationVersion += 1;
  devicesContent.replaceChildren();
  detailContent.replaceChildren();
  alertsContent.replaceChildren();
  alertDetailContent.replaceChildren();
  window.location.hash = "#/devices";
  showLogin("Signed out.");
});

document.querySelector("#refresh-devices").addEventListener("click", loadDevices);
document.querySelector("#refresh-alerts").addEventListener("click", loadAlerts);
document.querySelector("#alert-filters").addEventListener("submit", (event) => {
  event.preventDefault();
  alertOffset = 0;
  loadAlerts();
});
previousPage.addEventListener("click", () => {
  if (previousPage.disabled) return;
  alertOffset = Math.max(0, alertOffset - alertPageSize);
  loadAlerts();
});
nextPage.addEventListener("click", () => {
  if (nextPage.disabled) return;
  alertOffset += alertPageSize;
  loadAlerts();
});
document.querySelector(".skip-link").addEventListener("click", (event) => {
  event.preventDefault();
  document.querySelector("#main").focus();
});
document.querySelector("#main").tabIndex = -1;
window.addEventListener("hashchange", loadRoute);

if (!trustedOrigin) {
  loginForm.querySelectorAll("input, button").forEach((control) => { control.disabled = true; });
  showLogin("Open Core with HTTPS to sign in from another computer.");
} else {
  showLogin();
}
