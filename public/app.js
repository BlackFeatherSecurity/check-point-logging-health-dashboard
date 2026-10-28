const loginForm = document.querySelector("#loginForm");
const loginCard = document.querySelector("#loginCard");
const workspace = document.querySelector("#workspace");
const loginStatus = document.querySelector("#loginStatus");
const firewallList = document.querySelector("#firewallList");
const tableWrap = document.querySelector("#tableWrap");
const serverSummary = document.querySelector("#serverSummary");
const serverSummaryTotal = document.querySelector("#serverSummaryTotal");
const logServerChart = document.querySelector("#logServerChart");
const changeSummary = document.querySelector("#changeSummary");
const changeSummaryText = document.querySelector("#changeSummaryText");
const scanTiming = document.querySelector("#scanTiming");
const changeList = document.querySelector("#changeList");
const attentionPanel = document.querySelector("#attentionPanel");
const attentionText = document.querySelector("#attentionText");
const attentionList = document.querySelector("#attentionList");
const firewallSearch = document.querySelector("#firewallSearch");
const firewallFilter = document.querySelector("#firewallFilter");
const exportButton = document.querySelector("#exportButton");
const managementType = document.querySelector("#managementType");
const domainField = document.querySelector("#domainField");
const domainInput = document.querySelector("#domain");
const allDomainsNote = document.querySelector("#allDomainsNote");
const domainColumn = document.querySelector("#domainColumn");
const loadingState = document.querySelector("#loadingState");
const subtitle = document.querySelector("#statusSubtitle");
const connectionLabel = document.querySelector("#connectionLabel");
let sessionId = "";
let latestRows = [];
let latestCheckedAt = "";
let allDomainMode = false;

function updateManagementType() {
  const isMds = managementType.value === "mds" || managementType.value === "mds-all";
  const isAllDomains = managementType.value === "mds-all";
  domainField.classList.toggle("hidden", !isMds || isAllDomains);
  allDomainsNote.classList.toggle("hidden", !isAllDomains);
  domainInput.required = isMds && !isAllDomains;
  if (!isMds || isAllDomains) domainInput.value = "";
}

function firewallLabel(row) {
  return row.domain ? `${row.domain} / ${row.name}` : row.name;
}

async function api(path, body) {
  const response = await fetch(path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || `Request failed (${response.status}).`);
  return result;
}

function statusLabel(runtime) {
  const state = runtime?.state || "unknown";
  if (state === "connected") return "Connected";
  if (state === "disconnected") return "Disconnected";
  if (state === "not checked") return "Not checked";
  if (state === "unavailable") return "Unavailable";
  return "Needs review";
}

function listText(values) {
  return values?.length ? values.join(", ") : "—";
}

function cell(value, className = "") {
  const td = document.createElement("td");
  if (className) td.className = className;
  td.textContent = value || "—";
  return td;
}

function locationLabel(row) {
  if (row.local) return "Local";
  if (row.destinations?.length) return "Off-box";
  return "Not configured";
}

function needsAttention(row) {
  return row.local || !row.destinations?.length || ["disconnected", "unavailable", "unknown"].includes(row.runtime?.state);
}

function renderAttention(rows) {
  const flagged = rows.filter(needsAttention);
  attentionPanel.classList.toggle("hidden", !flagged.length);
  attentionList.replaceChildren();
  if (!flagged.length) return;
  attentionText.textContent = `${flagged.length} firewall${flagged.length === 1 ? "" : "s"} ${flagged.length === 1 ? "needs" : "need"} review.`;
  for (const row of flagged) {
    const item = document.createElement("li");
    const name = document.createElement("strong");
    const reason = document.createElement("span");
    name.textContent = firewallLabel(row);
    reason.textContent = row.local ? "Local logging enabled" : !row.destinations?.length ? "No remote log server configured" : statusLabel(row.runtime);
    item.append(name, reason);
    attentionList.append(item);
  }
}

function appendDomainFailures(failures = []) {
  for (const failure of failures) {
    const item = document.createElement("li");
    const name = document.createElement("strong");
    const reason = document.createElement("span");
    name.textContent = failure.domain;
    reason.textContent = `Domain scan failed: ${failure.error}`;
    item.append(name, reason);
    attentionList.append(item);
  }
}

function filteredRows() {
  const query = firewallSearch.value.trim().toLowerCase();
  return latestRows.filter((row) => {
    const haystack = [row.domain, row.name, row.type, row.primary, ...(row.secondary || []), ...(row.backup || []), row.runtime?.destination].join(" ").toLowerCase();
    const matchesQuery = !query || haystack.includes(query);
    const filter = firewallFilter.value;
    const matchesFilter = filter === "all" || (filter === "attention" && needsAttention(row)) || (filter === "off-box" && !row.local && row.destinations?.length) || (filter === "local" && row.local);
    return matchesQuery && matchesFilter;
  });
}

function csvEscape(value) {
  const text = String(value ?? "");
  return /[",\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

function exportCsv() {
  const rows = filteredRows();
  const headings = ["Domain", "Firewall", "Type", "Primary log server", "Secondary log servers", "Backup log servers", "Current destination", "Logging location", "Connection state", "Checked at"];
  const lines = [headings, ...rows.map((row) => [row.domain, row.name, row.type, row.primary, (row.secondary || []).join("; "), (row.backup || []).join("; "), row.runtime?.destination, locationLabel(row), statusLabel(row.runtime), latestCheckedAt])]
    .map((row) => row.map(csvEscape).join(","));
  const blob = new Blob([`${lines.join("\n")}\n`], { type: "text/csv;charset=utf-8" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `check-point-logging-${new Date(latestCheckedAt || Date.now()).toISOString().slice(0, 10)}.csv`;
  link.click();
  URL.revokeObjectURL(link.href);
}

function renderLogServerChart(servers, firewallCount) {
  logServerChart.replaceChildren();
  serverSummary.classList.toggle("hidden", !servers?.length);
  if (!servers?.length) return;
  serverSummaryTotal.textContent = `${servers.length} configured log server${servers.length === 1 ? "" : "s"}`;
  const maximum = Math.max(firewallCount, 1);
  for (const server of servers) {
    const item = document.createElement("article");
    item.className = "server-bar";
    const heading = document.createElement("div");
    heading.className = "server-bar-heading";
    const name = document.createElement("strong");
    const count = document.createElement("span");
    name.textContent = server.name;
    count.textContent = `${server.activeFirewalls} active firewall${server.activeFirewalls === 1 ? "" : "s"}`;
    heading.append(name, count);
    const track = document.createElement("div");
    track.className = "bar-track";
    track.setAttribute("role", "img");
    track.setAttribute("aria-label", `${server.name}: ${server.activeFirewalls} active of ${server.configuredFirewalls} configured firewall connections`);
    const fill = document.createElement("span");
    fill.className = "bar-fill";
    fill.style.width = `${Math.max((server.activeFirewalls / maximum) * 100, server.activeFirewalls ? 8 : 0)}%`;
    track.append(fill);
    const footnote = document.createElement("p");
    footnote.textContent = `${server.configuredFirewalls} firewall${server.configuredFirewalls === 1 ? "" : "s"} configured`;
    item.append(heading, track, footnote);
    logServerChart.append(item);
  }
}

function fieldLabel(field) {
  return ({ local: "local logging", primary: "primary destination", secondary: "secondary destinations", backup: "backup destinations", destination: "current destination", runtimeState: "connection state", mode: "logging location" })[field] || field;
}

function renderHistory(result) {
  const history = result.history || { baseline: true, changes: [] };
  changeSummary.classList.remove("hidden");
  changeList.replaceChildren();
  scanTiming.textContent = `Scan ${Math.max(1, Math.round((result.scanDurationMs || 0) / 1000))}s`;
  if (history.baseline) {
    changeSummaryText.textContent = "Baseline saved. Future scans will flag logging changes here.";
    return;
  }
  if (!history.changes?.length) {
    changeSummaryText.textContent = `No logging changes since ${new Date(history.previousCheckedAt).toLocaleString()}.`;
    return;
  }
  changeSummaryText.textContent = `${history.changes.length} logging change${history.changes.length === 1 ? "" : "s"} since ${new Date(history.previousCheckedAt).toLocaleString()}.`;
  for (const change of history.changes) {
    const item = document.createElement("li");
    const name = document.createElement("strong");
    const detail = document.createElement("span");
    name.textContent = change.firewall;
    detail.textContent = change.kind === "changed" ? `Changed: ${change.fields.map(fieldLabel).join(", ")}` : change.fields.join(", ");
    item.append(name, detail);
    changeList.append(item);
  }
}

function render(rows) {
  firewallList.replaceChildren();
  tableWrap.hidden = !rows.length;
  if (!rows.length) {
    loadingState.textContent = "No firewall objects were returned by this Management Server.";
    loadingState.hidden = false;
    return;
  }
  loadingState.hidden = true;
  for (const row of rows) {
    const tr = document.createElement("tr");
    if (allDomainMode) tr.append(cell(row.domain));
    const firewall = document.createElement("th");
    firewall.scope = "row";
    const name = document.createElement("strong");
    const type = document.createElement("span");
    name.textContent = row.name;
    type.className = "firewall-type";
    type.textContent = row.type.replaceAll("-", " ");
    firewall.append(name, type);
    tr.append(firewall);
    tr.append(cell(row.primary));
    tr.append(cell(listText(row.secondary)));
    tr.append(cell(listText(row.backup)));
    tr.append(cell(row.runtime?.destination || (row.runtime?.state === "connected" ? "Connected; target not identified" : "—")));
    const location = document.createElement("td");
    const locationBadge = document.createElement("span");
    locationBadge.className = `mode-badge ${row.local ? "local" : row.destinations?.length ? "off-box" : "unknown"}`;
    locationBadge.textContent = locationLabel(row);
    location.append(locationBadge);
    tr.append(location);
    const connection = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = `runtime-badge ${row.runtime?.state || "unknown"}`;
    badge.textContent = statusLabel(row.runtime);
    connection.append(badge);
    if (row.runtime?.detail) {
      const detail = document.createElement("span");
      detail.className = "connection-detail";
      detail.textContent = row.runtime.detail;
      connection.append(detail);
    }
    if (row.runtime?.raw) {
      const details = document.createElement("details");
      const summary = document.createElement("summary");
      summary.textContent = "View gateway response";
      const pre = document.createElement("pre");
      pre.textContent = row.runtime.raw;
      details.append(summary, pre);
      connection.append(details);
    }
    tr.append(connection);
    firewallList.append(tr);
  }
}

async function refresh() {
  if (!sessionId) return;
  const button = document.querySelector("#refreshButton");
  button.disabled = true;
  button.textContent = "Checking…";
  loadingState.hidden = false;
  loadingState.textContent = "Reading Management configuration and gateway connection status…";
  try {
    const result = await api("/api/logging-status", { sessionId, includeRuntime: document.querySelector("#runtimeToggle").checked, allDomains: allDomainMode });
    latestRows = result.firewalls;
    latestCheckedAt = result.checkedAt;
    allDomainMode = Boolean(result.domains?.length) && allDomainMode;
    domainColumn.hidden = !allDomainMode;
    const rows = filteredRows();
    const domainSummary = allDomainMode ? ` across ${result.domains.length} domain${result.domains.length === 1 ? "" : "s"}` : "";
    subtitle.textContent = `${rows.length === result.count ? "" : `${rows.length} of `}${result.count} firewall${result.count === 1 ? "" : "s"}${domainSummary} checked · ${new Date(result.checkedAt).toLocaleString()}`;
    exportButton.disabled = !rows.length;
    renderAttention(result.firewalls);
    if (result.domainFailures?.length) {
      attentionPanel.classList.remove("hidden");
      attentionText.textContent = `${result.domainFailures.length} MDS domain${result.domainFailures.length === 1 ? "" : "s"} could not be scanned.`;
      appendDomainFailures(result.domainFailures);
    }
    renderHistory(result);
    renderLogServerChart(result.logServers, result.count);
    render(rows);
  } catch (error) {
    loadingState.hidden = false;
    loadingState.textContent = error.message;
    serverSummary.classList.add("hidden");
    logServerChart.replaceChildren();
    changeSummary.classList.add("hidden");
    changeList.replaceChildren();
    attentionPanel.classList.add("hidden");
    attentionList.replaceChildren();
    firewallList.replaceChildren();
  } finally {
    button.disabled = false;
    button.textContent = "Refresh status";
  }
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = loginForm.querySelector('button[type="submit"]');
  button.disabled = true;
  loginStatus.textContent = "Creating a temporary Management API session…";
  try {
    const fields = new FormData(loginForm);
    const selectedType = fields.get("managementType");
    const isMds = selectedType === "mds" || selectedType === "mds-all";
    const isAllDomains = selectedType === "mds-all";
    const result = await api("/api/login", {
      host: fields.get("host"), port: fields.get("port"), username: fields.get("username"), password: fields.get("password"),
      ignoreTls: fields.get("ignoreTls") === "on", largeEnvironmentMode: fields.get("largeEnvironmentMode") === "on",
      mdsMode: isMds, mdsScan: isMds, allDomains: isAllDomains, domain: isMds && !isAllDomains ? fields.get("domain") : ""
    });
    sessionId = result.sessionId;
    allDomainMode = Boolean(result.allDomains);
    domainColumn.hidden = !allDomainMode;
    const scope = result.allDomains ? "MDS / all domains" : result.mdsMode ? `MDS / ${result.domain}` : "";
    connectionLabel.textContent = `CONNECTED · ${result.user}${scope ? ` · ${scope}` : ""}${result.largeEnvironmentMode ? " · throttled" : ""}`;
    loginCard.classList.add("hidden");
    workspace.classList.remove("hidden");
    await refresh();
  } catch (error) {
    loginStatus.textContent = error.message;
  } finally { button.disabled = false; }
});

document.querySelector("#refreshButton").addEventListener("click", refresh);
document.querySelector("#runtimeToggle").addEventListener("change", refresh);
document.querySelector("#logoutButton").addEventListener("click", async () => {
  if (sessionId) { try { await api("/api/logout", { sessionId }); } catch {} }
  sessionId = "";
  allDomainMode = false;
  domainColumn.hidden = true;
  workspace.classList.add("hidden");
  loginCard.classList.remove("hidden");
  loginStatus.textContent = "Logged out. Credentials and API session have been discarded.";
  firewallList.replaceChildren();
  latestRows = [];
  latestCheckedAt = "";
  exportButton.disabled = true;
  serverSummary.classList.add("hidden");
  logServerChart.replaceChildren();
  changeSummary.classList.add("hidden");
  changeList.replaceChildren();
  attentionPanel.classList.add("hidden");
  attentionList.replaceChildren();
});

function applyFilters() {
  if (!latestRows.length) return;
  const rows = filteredRows();
  subtitle.textContent = `${rows.length === latestRows.length ? "" : `${rows.length} of `}${latestRows.length} firewall${latestRows.length === 1 ? "" : "s"} shown · ${new Date(latestCheckedAt).toLocaleString()}`;
  exportButton.disabled = !rows.length;
  render(rows);
}

firewallSearch.addEventListener("input", applyFilters);
firewallFilter.addEventListener("change", applyFilters);
exportButton.addEventListener("click", exportCsv);
managementType.addEventListener("change", updateManagementType);
updateManagementType();
