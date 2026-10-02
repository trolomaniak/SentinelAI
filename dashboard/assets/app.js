import {
  firewallLabel,
  formatBytes,
  formatTimestamp,
  healthPresentation,
  isTrustedDashboardOrigin,
  routeFromHash,
} from "./device-view.js";

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
const trustedOrigin = isTrustedDashboardOrigin(window.location);

let accessToken = null;
let navigationVersion = 0;

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
  signOutButton.hidden = !accessToken;
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
  showLogin("Your session ended. Sign in again to continue.");
}

async function getFromCore(path) {
  const response = await fetch(path, {
    headers: { Authorization: `Bearer ${accessToken}` },
    cache: "no-store",
    credentials: "omit",
  });
  if (response.status === 401) {
    expireSession();
    throw new SessionExpired();
  }
  if (!response.ok) throw new ApiError(response.status);
  return response.json();
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
  } else {
    navigationVersion += 1;
    setView("detail");
    detailStatus.textContent = "Invalid device link";
    detailContent.replaceChildren(renderStatePanel(
      "Invalid device link",
      "Open a device from the list to view its details.",
    ));
  }
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
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
  window.location.hash = "#/devices";
  showLogin("Signed out.");
});

document.querySelector("#refresh-devices").addEventListener("click", loadDevices);
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
