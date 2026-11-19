const loginForm = document.querySelector("#loginForm");
const loginCard = document.querySelector("#loginCard");
const workspace = document.querySelector("#workspace");
const loginStatus = document.querySelector("#loginStatus");
const firewallList = document.querySelector("#firewallList");
const tableWrap = document.querySelector("#tableWrap");
const tableScrollHint = document.querySelector("#tableScrollHint");
const tableScrollLeft = document.querySelector("#tableScrollLeft");
const tableScrollRight = document.querySelector("#tableScrollRight");
const serverSummary = document.querySelector("#serverSummary");
const serverSummaryTotal = document.querySelector("#serverSummaryTotal");
const logServerChart = document.querySelector("#logServerChart");
const changeSummary = document.querySelector("#changeSummary");
const changeSummaryText = document.querySelector("#changeSummaryText");
const scanTiming = document.querySelector("#scanTiming");
const changeList = document.querySelector("#changeList");
const attentionPanel = document.querySelector("#attentionPanel");
const attentionLink = document.querySelector("#attentionLink");
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
const domainFilter = document.querySelector("#domainFilter");
const destinationFilter = document.querySelector("#destinationFilter");
const scanNavigation = document.querySelector("#scanNavigation");
const managementSummary = document.querySelector("#managementSummary");
const managementSubtitle = document.querySelector("#managementSubtitle");
const scopeList = document.querySelector("#scopeList");
const serverLink = document.querySelector("#serverLink");
const fleetEmpty = document.querySelector("#fleetEmpty");
const fleetTable = document.querySelector("#firewallTable");
const viewButtons = [...document.querySelectorAll("button[data-view]")];
const resultColumns = [...fleetTable.querySelectorAll("thead th")].slice(1);
const runtimeToggle = document.querySelector("#runtimeToggle");
const refreshButton = document.querySelector("#refreshButton");
const logoutButton = document.querySelector("#logoutButton");
const workspaceTitle = document.querySelector("#workspaceTitle");
const loadingState = document.querySelector("#loadingState");
const subtitle = document.querySelector("#statusSubtitle");
const connectionLabel = document.querySelector("#connectionLabel");
const fleetHome = document.querySelector("#fleetHome");
const serverDetail = document.querySelector("#serverDetail");
const serverDetailTitle = document.querySelector("#serverDetailTitle");
const serverDetailMeta = document.querySelector("#serverDetailMeta");
const serverDetailContent = document.querySelector("#serverDetailContent");
const serverDetailStatus = document.querySelector("#serverDetailStatus");
const managementHealth = document.querySelector("#managementHealth");
const schedulePanel = document.querySelector("#scanSchedule");
const scheduleLink = document.querySelector("#scheduleLink");
const scheduleForm = document.querySelector("#scheduleForm");
const scheduleStatus = document.querySelector("#scheduleStatus");
const scheduleAlerts = document.querySelector("#scheduleAlerts");
const stopSchedule = document.querySelector("#stopSchedule");
let sessionId = "";
let latestRows = [];
let latestCheckedAt = "";
let allDomainMode = false;
let activeView = "overview";
let managementScope = "";
let managementHost = "";
let latestDomainCount = 0;
let latestIncludedRuntime = false;
let scanning = false;
let latestServerReports = [];
let schedulePolling;
let scheduleRequest = false;

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

function syncTableOverflowHint() {
  const maxScroll = Math.max(0, tableWrap.scrollWidth - tableWrap.clientWidth);
  const overflowing = !tableWrap.hidden && maxScroll > 1;
  tableScrollHint.hidden = !overflowing;
  tableScrollLeft.disabled = !overflowing || tableWrap.scrollLeft <= 1;
  tableScrollRight.disabled = !overflowing || tableWrap.scrollLeft >= maxScroll - 1;
}

function scrollTableColumns(direction) {
  tableWrap.scrollBy({ left: direction * Math.max(320, Math.round(tableWrap.clientWidth * 0.75)), behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "instant" : "smooth" });
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

function isTimeAttention(row) {
  return ["ntp-off", "drift", "drift-critical", "unavailable"].includes(row.time?.state);
}

function isRouteAttention(row) {
  return ["mismatch", "unavailable"].includes(row.routes?.state);
}

function routeLabel(routes) {
  if (routes?.state === "matched") return "Matched";
  if (routes?.state === "mismatch") return "Mismatch";
  if (routes?.state === "not-applicable") return "Not a cluster";
  if (routes?.state === "not checked") return "Not checked";
  if (routes?.state === "unavailable") return "Unavailable";
  return routes?.label || "Needs review";
}

function timeLabel(time) {
  const state = time?.state || "not checked";
  if (state === "synced") return "NTP active · synced";
  if (state === "ntp-active") return "NTP active";
  if (state === "drift") return time?.ntpEnabled === true ? "NTP active · drift" : "Clock drift";
  if (state === "drift-critical") return time?.ntpEnabled === true ? "NTP active · clock drift" : "Clock drift";
  if (state === "ntp-off") return "NTP off";
  if (state === "not-supported") return "Not supported";
  if (state === "not checked") return "Not checked";
  if (state === "unavailable") return "Unavailable";
  return time?.label || "Needs review";
}

function offsetLabel(offsetMs) {
  if (typeof offsetMs !== "number" || !Number.isFinite(offsetMs)) return "Comparison unavailable";
  const absolute = Math.abs(offsetMs);
  const sign = offsetMs >= 0 ? "+" : "−";
  if (absolute < 1000) return `${sign}${Math.round(absolute)}ms`;
  if (absolute < 60000) return `${sign}${(absolute / 1000).toFixed(1)}s`;
  const minutes = Math.floor(absolute / 60000);
  const seconds = Math.round((absolute % 60000) / 1000);
  return `${sign}${String(minutes).padStart(2, "0")}m ${String(seconds).padStart(2, "0")}s`;
}

function utcLabel(epoch) {
  return epoch ? new Date(epoch).toISOString().replace(".000Z", "Z") : "Not returned";
}

function timeEvidenceCell(row) {
  const time = document.createElement("td");
  time.className = "time-column";
  const badge = document.createElement("span");
  badge.className = `time-badge ${row.time?.state || "unknown"}`;
  badge.textContent = timeLabel(row.time);
  time.append(badge);

  // The firewall clock is deliberately visible without expanding a detail
  // panel.  If NTP is off or cannot be confirmed, an operator sees the
  // actual gateway time immediately—not a vague diagnostic adjective.
  if (row.time?.firewallEpoch) {
    const clock = document.createElement("span");
    clock.className = "time-clock";
    clock.textContent = `Firewall UTC ${utcLabel(row.time.firewallEpoch)}`;
    time.append(clock);
  }
  if (typeof row.time?.offsetMs === "number") {
    const comparison = document.createElement("span");
    comparison.className = "time-comparison";
    comparison.textContent = `Vs. log server ${offsetLabel(row.time.offsetMs)}`;
    time.append(comparison);
  } else if (row.time?.comparisonError) {
    const comparison = document.createElement("span");
    comparison.className = "time-comparison time-comparison-warning";
    comparison.textContent = "Log-server clock comparison unavailable";
    time.append(comparison);
  }
  if (row.time?.detail) {
    const detail = document.createElement("span");
    detail.className = "connection-detail overview-detail";
    detail.textContent = row.time.detail;
    time.append(detail);
  }
  if (row.time && row.time.state !== "not checked") {
    const details = document.createElement("details");
    const summary = document.createElement("summary");
    summary.textContent = "View NTP and clock evidence";
    const evidence = document.createElement("dl");
    evidence.className = "time-evidence";
    const entries = [
      ["NTP active", row.time.ntpEnabled === null || row.time.ntpEnabled === undefined ? "Not reported" : row.time.ntpEnabled ? "Yes" : "No"],
      ["NTP peer/source", row.time.peer || "Not reported"],
      ["Firewall time (UTC)", utcLabel(row.time.firewallEpoch)],
      ["Active log server", row.time.logServer || "Not identified"],
      ["Log-server time (UTC)", utcLabel(row.time.logServerEpoch)],
      ["Firewall minus log server", offsetLabel(row.time.offsetMs)],
      ["Comparison status", row.time.comparisonError ? `Unavailable: ${row.time.comparisonError}` : row.time.logServerEpoch ? "Measured" : "Not available"]
    ];
    for (const [term, value] of entries) {
      const dt = document.createElement("dt");
      const dd = document.createElement("dd");
      dt.textContent = term;
      dd.textContent = value;
      evidence.append(dt, dd);
    }
    details.append(summary, evidence);
    if (row.time.raw) {
      const pre = document.createElement("pre");
      pre.textContent = row.time.raw;
      details.append(pre);
    }
    time.append(details);
  }
  return time;
}

function attentionReasons(row) {
  const reasons = [];
  if (row.local) reasons.push("Local logging enabled");
  if (!row.destinations?.length) reasons.push("No remote log server configured");
  if (row.configurationError) reasons.push(row.configurationError);
  if (["disconnected", "unavailable", "unknown", "reported"].includes(row.runtime?.state)) {
    reasons.push(`Connection: ${statusLabel(row.runtime)}`);
  }
  if (isTimeAttention(row)) {
    const offset = typeof row.time.offsetMs === "number" ? ` (${offsetLabel(row.time.offsetMs)})` : "";
    reasons.push(`Time health: ${timeLabel(row.time)}${offset}`);
  }
  if (isRouteAttention(row)) reasons.push(`Cluster routes: ${routeLabel(row.routes)}`);
  return reasons;
}

function renderAttention(rows, failures = []) {
  const flagged = rows.map(row => ({ row, reasons: attentionReasons(row) })).filter(item => item.reasons.length);
  attentionLink.hidden = !flagged.length && !failures.length;
  attentionPanel.classList.toggle("hidden", attentionLink.hidden);
  attentionList.replaceChildren();
  const counts = [];
  if (flagged.length) counts.push(`${flagged.length} ${flagged.length === 1 ? "firewall" : "firewalls"} flagged`);
  if (failures.length) counts.push(`${failures.length} ${failures.length === 1 ? "domain" : "domains"} could not be scanned`);
  attentionText.textContent = counts.join(" · ");
  for (const { row, reasons } of flagged) {
    const item = document.createElement("li");
    const name = document.createElement("strong");
    const reason = document.createElement("span");
    name.textContent = firewallLabel(row);
    reason.textContent = reasons.join(" · ");
    item.append(name, reason);
    attentionList.append(item);
  }
  appendDomainFailures(failures);
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
  const domain = domainFilter.value;
  const destination = destinationFilter.value;
  const filter = firewallFilter.value;
  return latestRows.filter((row) => {
    if (domain && row.domain !== domain) return false;
    if (destination && !row.destinations?.includes(destination) &&
        !(row.runtime?.state === "connected" && row.runtime.destination === destination) &&
        !latestServerReports.some(report => report.name === destination &&
          (!row.domain || report.domain === row.domain) &&
          report.dependencies.some(gateway => gateway.id === (row.uid || row.name)))) return false;
    const haystack = [row.domain, row.name, row.type, row.deviceFamily, row.probe?.label, row.primary, ...(row.secondary || []), ...(row.backup || []), row.runtime?.destination, timeLabel(row.time), row.time?.peer, row.time?.logServer, routeLabel(row.routes), ...(row.routes?.members || [])].join(" ").toLowerCase();
    const matchesQuery = !query || haystack.includes(query);
    const matchesFilter = filter === "all" || (filter === "attention" && attentionReasons(row).length) || (filter === "off-box" && !row.local && row.destinations?.length) || (filter === "local" && row.local);
    return matchesQuery && matchesFilter;
  });
}

function csvEscape(value) {
  const raw = String(value ?? "");
  const numeric = /^[+-]?\d+(?:\.\d+)?(?:ms|s)?$/.test(raw);
  const text = !numeric && /^\s*[=+\-@]|^[\t\r\n]/.test(raw) ? `'${raw}` : raw;
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

function exportCsv() {
  const rows = filteredRows();
  const headings = ["Domain", "Firewall", "Object type", "Device family", "Runtime probe", "Primary log server", "Secondary log servers", "Backup log servers", "Current destination", "Logging location", "Connection state", "Time health", "NTP enabled", "NTP peer", "Firewall time UTC", "Log-server time UTC", "Offset", "Cluster route health", "Cluster member route counts", "Checked at"];
  const lines = [headings, ...rows.map((row) => [row.domain, row.name, row.type, row.deviceFamily, row.probe?.label, row.primary, (row.secondary || []).join("; "), (row.backup || []).join("; "), row.runtime?.destination, locationLabel(row), statusLabel(row.runtime), timeLabel(row.time), row.time?.ntpEnabled === null || row.time?.ntpEnabled === undefined ? "Not reported" : row.time.ntpEnabled ? "Yes" : "No", row.time?.peer, utcLabel(row.time?.firewallEpoch), utcLabel(row.time?.logServerEpoch), offsetLabel(row.time?.offsetMs), routeLabel(row.routes), Object.entries(row.routes?.counts || {}).map(([member, count]) => `${member}: ${count}`).join("; "), latestCheckedAt])]
    .map((row) => row.map(csvEscape).join(","));
  const blob = new Blob([`${lines.join("\n")}\n`], { type: "text/csv;charset=utf-8" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `check-point-logging-${new Date(latestCheckedAt || Date.now()).toISOString().slice(0, 10)}.csv`;
  link.click();
  URL.revokeObjectURL(link.href);
}

function replaceOptions(select, values) {
  const previous = select.value;
  select.replaceChildren(select.options[0], ...values.map(value => new Option(value, value)));
  if (values.includes(previous)) select.value = previous;
}

function showMatchingFirewalls(select, value, view, domain = "") {
  firewallSearch.value = "";
  firewallFilter.value = "all";
  domainFilter.value = [...domainFilter.options].some(option => option.value === domain) ? domain : "";
  destinationFilter.value = "";
  select.value = value;
  setView(view);
  applyFilters();
  document.querySelector("#firewallTitle").focus();
}

function drillDownButton(select, value, view) {
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = "View firewalls";
  button.setAttribute("aria-label", `View firewalls for ${value}`);
  button.addEventListener("click", () => showMatchingFirewalls(select, value, view));
  return button;
}

function renderLogServerChart(servers = [], includeRuntime) {
  logServerChart.replaceChildren();
  const reports = latestServerReports.length ? latestServerReports : servers;
  serverSummary.classList.toggle("hidden", !reports.length);
  serverLink.hidden = !reports.length;
  const destinations = [...new Set([...reports, ...servers].map(server => server.name))].sort();
  replaceOptions(destinationFilter, destinations);
  document.querySelector("#destinationFilterField").hidden = !reports.length;
  serverSummaryTotal.textContent = `${reports.length} ${reports.length === 1 ? "destination" : "destinations"}`;

  for (const server of reports) {
    const item = document.createElement("div");
    item.className = "coverage-row";
    const name = document.createElement("strong");
    name.textContent = server.domain ? `${server.name} · ${server.domain}` : server.name;
    const counts = document.createElement("p");
    counts.className = "coverage-counts";
    const configured = server.dependencies?.filter(gateway => gateway.roles.length).length ?? server.configuredFirewalls;
    const active = server.dependencies?.filter(gateway => gateway.observed).length ?? server.activeFirewalls;
    counts.textContent = `${configured} configured · ${includeRuntime ? `${active} active` : "Live checks skipped"}`;
    if (server.key) {
      const link = document.createElement("a");
      link.className = "detail-link";
      link.href = serverRoute(server);
      link.textContent = "View health";
      link.setAttribute("aria-label", `View health for ${name.textContent}`);
      item.append(name, counts, link);
    } else {
      item.append(name, counts, drillDownButton(destinationFilter, server.name, "logging"));
    }
    logServerChart.append(item);
  }
}

function renderManagementScope(result) {
  const domains = result.domains || [];
  const failures = new Map((result.domainFailures || []).map(failure => [failure.domain, failure.error]));
  replaceOptions(domainFilter, domains.map(domain => domain.name));
  document.querySelector("#domainFilterField").hidden = !domains.length;
  managementSummary.classList.remove("hidden");
  managementSubtitle.textContent = `${managementScope} · ${managementHost}`;
  scopeList.replaceChildren();
  renderManagementHealth(result);
  if (!domains.length) return;

  const counts = new Map();
  for (const row of result.firewalls) counts.set(row.domain, (counts.get(row.domain) || 0) + 1);
  for (const domain of domains) {
    const item = document.createElement("div");
    item.className = "scope-row";
    const name = document.createElement("strong");
    name.textContent = domain.name;
    const summary = document.createElement("p");
    const count = counts.get(domain.name) || 0;
    item.toggleAttribute("data-failed", failures.has(domain.name));
    summary.textContent = failures.has(domain.name) ? failures.get(domain.name) : `${count} ${count === 1 ? "firewall" : "firewalls"} scanned`;
    item.append(name, summary);
    if (count) item.append(drillDownButton(domainFilter, domain.name, "overview"));
    scopeList.append(item);
  }
}

function textElement(tag, content, className = "") {
  const element = document.createElement(tag);
  element.textContent = content;
  if (className) element.className = className;
  return element;
}

function evidenceList(entries) {
  const list = document.createElement("dl");
  list.className = "health-evidence";
  for (const [label, value] of entries) list.append(textElement("dt", label), textElement("dd", value));
  return list;
}

function formattedDate(value) {
  const date = new Date(value);
  return value && Number.isFinite(date.getTime()) ? date.toLocaleString() : "Not reported";
}

function rawEvidence(title, raw) {
  const details = document.createElement("details");
  details.className = "health-raw";
  details.append(textElement("summary", title), textElement("pre", raw));
  return details;
}

function renderManagementHealth(result) {
  managementHealth.replaceChildren();
  if (!result.management) return;
  const endpoint = result.managementEndpoint || result.management[0];
  const endpointEvidence = endpoint
    ? `Reachable · ${endpoint.inventoryMs} ms · ${formattedDate(endpoint.checkedAt)}`
    : "Could not verify Management API reachability.";
  managementHealth.append(evidenceList([["Management API", endpointEvidence]]));
  const states = {
    "not-configured": "HA not configured",
    "no-peer-reported": "No HA peer reported",
    unavailable: "HA unavailable",
    synchronized: "Synchronized",
    "not-synchronized": "Not synchronized",
    reported: "Peer roles reported"
  };
  for (const management of result.management) {
    const section = document.createElement("section");
    section.className = "health-subsection";
    section.append(textElement("h3", management.domain ? `HA · ${management.domain}` : "Management HA"));
    section.append(textElement("p", states[management.ha.state] || "Unavailable"));
    if (management.ha.detail) section.append(textElement("p", management.ha.detail, "muted-text"));
    for (const peer of management.ha.peers) {
      section.append(evidenceList([
        [peer.name || peer.ip || "Peer", [peer.role, peer.sync, peer.managementServer].filter(Boolean).join(" · ") || "Status unavailable"],
        ["Last successful sync", formattedDate(peer.lastSync)]
      ]));
    }
    managementHealth.append(section);
  }
}

function serverRoute(server) {
  return `#log-server=${encodeURIComponent(JSON.stringify([server.domain, server.key]))}`;
}

function volumeLabel(volume) {
  return volume ? `${(volume.availableKiB / 1048576).toFixed(1)} GiB free of ${(volume.totalKiB / 1048576).toFixed(1)} GiB (${volume.percentFree.toFixed(1)}%) · ${volume.mount}`
    : "Unavailable";
}

function renderServerDetail(report) {
  serverDetailTitle.textContent = report?.name || "Log server unavailable";
  serverDetailMeta.textContent = report
    ? `${report.domain || "Security Management Server"} · ${report.version ? `${report.version} · ` : ""}Checked ${formattedDate(report.checkedAt)}`
    : "Run a scan in the appropriate Management scope to view this destination.";
  serverDetailContent.replaceChildren();
  if (!report) return;
  if (report.configurationError) serverDetailContent.append(textElement("p", report.configurationError, "muted-text"));
  if (report.probeError) serverDetailContent.append(textElement("p", report.probeError, "muted-text"));
  const overview = document.createElement("div");
  overview.className = "server-health-grid";
  const storage = document.createElement("section");
  storage.append(textElement("h3", "Storage and indexing"), evidenceList([
    ["Log volume", report.probeState === "not-checked" ? "Not checked" : volumeLabel(report.volumes.log)],
    ["Index volume", report.probeState === "not-checked" ? "Not checked" : volumeLabel(report.volumes.index)],
    ["Indexing mode", { enabled: "Enabled", disabled: "Disabled", unavailable: "Unavailable" }[report.indexingMode]],
    ["Indexer status", report.indexer]
  ]));
  const thresholds = document.createElement("section");
  thresholds.append(textElement("h3", "Configured free-space thresholds"), evidenceList(report.thresholds.map(threshold => [
    threshold.label, threshold.enabled === false ? "Disabled" : threshold.enabled && threshold.value !== null && threshold.metric
      ? `${threshold.value}${threshold.metric === "percent" ? "%" : " MiB"} free` : "Unavailable"
  ])));
  for (const finding of report.storageFindings || []) {
    thresholds.append(textElement("p", `${finding.label} · ${finding.state === "approaching" ? "Approaching threshold" : "At or below threshold"}`, "threshold-finding"));
  }
  overview.append(storage, thresholds);
  serverDetailContent.append(overview);
  if (report.raw) serverDetailContent.append(rawEvidence("View log-server probe response", report.raw));
  serverDetailContent.append(textElement("h3", "Dependent gateways"));
  if (!report.dependencies.length) {
    serverDetailContent.append(textElement("p", "No gateways in this scan reference this server.", "muted-text"));
    return;
  }
  serverDetailContent.append(evidenceList(report.dependencies.map(gateway => [
    gateway.name, [...gateway.roles, gateway.observed ? "Reported active destination" : ""].filter(Boolean).join(" · ")
  ])));
  const link = textElement("a", "Open filtered firewall view", "detail-link");
  link.href = "#firewallTitle";
  link.addEventListener("click", event => {
    event.preventDefault();
    location.hash = "#firewallTitle";
    showMatchingFirewalls(destinationFilter, report.name, "logging", report.domain);
  });
  serverDetailContent.append(link);
}

function syncServerPage(moveFocus = false) {
  const opening = location.hash.startsWith("#log-server=");
  const wasOpen = !serverDetail.classList.contains("hidden");
  fleetHome.hidden = opening;
  serverDetail.classList.toggle("hidden", !opening);
  if (opening) {
    renderServerDetail(latestServerReports.find(report => serverRoute(report) === location.hash));
    if (moveFocus && sessionId) serverDetailTitle.focus();
  } else if (wasOpen && moveFocus) {
    const target = document.getElementById(location.hash.slice(1)) || workspaceTitle;
    if (!target.hasAttribute("tabindex")) target.tabIndex = -1;
    target.focus();
    target.scrollIntoView({ block: "start" });
  }
}

function renderMemberHealth(members) {
  const details = document.createElement("details");
  details.append(textElement("summary", "View member logging and clocks"));
  for (const member of members) {
    const section = document.createElement("section");
    section.className = "health-subsection";
    const destination = member.runtime.observedDestination;
    section.append(textElement("h3", member.name), evidenceList([
      ["Cluster state", member.role || "Not reported"],
      ["Logging", [statusLabel(member.runtime), destination].filter(Boolean).join(" · ")],
      ["NTP", timeLabel(member.time)],
      ["Member UTC", utcLabel(member.time.firewallEpoch)],
      ["NTP peer", member.time.peer || "Not reported"]
    ]));
    if (member.runtime.detail) section.append(textElement("p", member.runtime.detail, "muted-text"));
    if (member.runtime.raw) section.append(rawEvidence("View member logging response", member.runtime.raw));
    if (member.time.raw) section.append(rawEvidence("View member time response", member.time.raw));
    if (member.stateEvidence) section.append(rawEvidence("View cluster-state response", member.stateEvidence));
    details.append(section);
  }
  return details;
}

function renderSchedule(schedule) {
  schedulePanel.classList.toggle("hidden", !schedule.enabled);
  scheduleLink.hidden = !schedule.enabled;
  for (const control of scheduleForm.elements) {
    if (control !== stopSchedule) control.disabled = schedule.active;
  }
  stopSchedule.hidden = !schedule.active;
  const details = [];
  if (schedule.active) {
    if (schedule.running) details.push("Scheduled scan running.");
    else if (schedule.nextAt) details.push(`Next scan ${formattedDate(schedule.nextAt)}.`);
    details.push(`Ends ${formattedDate(schedule.expiresAt)}.`);
  } else {
    details.push(schedule.expiresAt ? "Schedule ended." : "No schedule is active.");
  }
  if (schedule.lastSuccess) details.push(`Last complete scan ${formattedDate(schedule.lastSuccess)}.`);
  if (schedule.error) details.push(schedule.error);
  scheduleStatus.textContent = details.join(" ");
  scheduleAlerts.replaceChildren();
  for (const alert of schedule.alerts || []) {
    const item = document.createElement("li");
    item.append(
      textElement("strong", `${alert.type} · ${alert.domain} / ${alert.target}`),
      textElement("span", `${alert.evidence} Last successful check ${formattedDate(alert.checkedAt)}.`)
    );
    scheduleAlerts.append(item);
  }
}

async function updateSchedule(action = "status", options = {}) {
  if (!sessionId || scheduleRequest === "start" || scheduleRequest === "stop" || (action === "status" && scheduleRequest)) return;
  const requestedSession = sessionId;
  scheduleRequest = action;
  try {
    const result = await api(`/api/schedules/${action}`, { sessionId, ...options });
    if (requestedSession === sessionId && scheduleRequest === action) renderSchedule(result);
  } catch (error) {
    if (requestedSession === sessionId && scheduleRequest === action &&
        (action !== "status" || !schedulePanel.classList.contains("hidden"))) {
      scheduleStatus.textContent = error.message;
    }
  } finally {
    if (scheduleRequest === action) scheduleRequest = false;
  }
}

function fieldLabel(field) {
  return ({ local: "local logging", primary: "primary destination", secondary: "secondary destinations", backup: "backup destinations", destination: "current destination", runtimeState: "connection state", timeState: "time health", ntpEnabled: "NTP enablement", timeOffsetMs: "clock offset", routeState: "cluster route health", mode: "logging location" })[field] || field;
}

function renderHistory(result) {
  const history = result.history || { baseline: true, changes: [] };
  changeSummary.classList.remove("hidden");
  changeList.replaceChildren();
  scanTiming.textContent = `Scan ${Math.max(1, Math.round((result.scanDurationMs || 0) / 1000))}s`;
  if (history.partial) {
    changeSummaryText.textContent = "One or more domains could not be scanned. Change comparison will resume after a complete scan.";
    return;
  }
  if (history.unavailable) {
    changeSummaryText.textContent = "Scan history is unavailable. Current results are shown.";
    return;
  }
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
  tableScrollHint.hidden = true;
  fleetEmpty.hidden = Boolean(rows.length);
  if (!rows.length) {
    fleetEmpty.textContent = latestRows.length
      ? "No firewalls match the current filters."
      : "The scan returned no firewall objects.";
    return;
  }
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
    tr.append(cell(row.deviceFamily || "Unknown device family"));
    tr.append(timeEvidenceCell(row));
    const probe = document.createElement("td");
    const probeLabel = document.createElement("span");
    probeLabel.className = `probe-badge ${row.probe?.id || "unknown"}`;
    probeLabel.textContent = row.probe?.label || "No runtime probe";
    probe.append(probeLabel);
    if (row.probe?.command) {
      const command = document.createElement("code");
      command.className = "probe-command";
      command.textContent = row.probe.command;
      probe.append(command);
    }
    tr.append(probe);
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
    connection.className = "evidence-column";
    const badge = document.createElement("span");
    badge.className = `runtime-badge ${row.runtime?.state || "unknown"}`;
    badge.textContent = statusLabel(row.runtime);
    connection.append(badge);
    if (row.runtime?.detail) {
      const detail = document.createElement("span");
      detail.className = "connection-detail overview-detail";
      detail.textContent = row.runtime.detail;
      connection.append(detail);
    }
    if (row.runtime?.raw) {
      const details = document.createElement("details");
      details.className = "overview-detail";
      const summary = document.createElement("summary");
      summary.textContent = "View gateway response";
      const pre = document.createElement("pre");
      pre.textContent = row.runtime.raw;
      details.append(summary, pre);
      connection.append(details);
    }
    tr.append(connection);
    const routes = document.createElement("td");
    routes.className = "evidence-column";
    const routeBadge = document.createElement("span");
    routeBadge.className = `route-badge ${row.routes?.state || "unknown"}`;
    routeBadge.textContent = routeLabel(row.routes);
    routes.append(routeBadge);
    if (row.routes?.detail) {
      const detail = document.createElement("span");
      detail.className = "connection-detail overview-detail";
      detail.textContent = row.routes.detail;
      routes.append(detail);
    }
    if (row.routes?.state === "matched" || row.routes?.state === "mismatch") {
      const details = document.createElement("details");
      details.className = "overview-detail";
      const summary = document.createElement("summary");
      summary.textContent = "View route comparison";
      const evidence = document.createElement("dl");
      evidence.className = "time-evidence";
      for (const member of row.routes.members || []) {
        const term = document.createElement("dt");
        const value = document.createElement("dd");
        term.textContent = member;
        value.textContent = `${row.routes.counts?.[member] ?? 0} normalized routes`;
        evidence.append(term, value);
      }
      details.append(summary, evidence);
      if (row.routes?.state === "mismatch") {
        for (const member of row.routes.members || []) {
          const difference = row.routes.differences?.[member];
          if (!difference) continue;
          const pre = document.createElement("pre");
          pre.textContent = `${member} only:\n${difference.only.join("\n") || "—"}\n\nMissing versus ${row.routes.baseline}:\n${difference.missing.join("\n") || "—"}`;
          details.append(pre);
        }
      }
      routes.append(details);
    }
    if (row.memberHealth?.length) routes.append(renderMemberHealth(row.memberHealth));
    tr.append(routes);
    for (const [index, column] of resultColumns.entries()) {
      const td = tr.cells[index + Number(allDomainMode)];
      if (column.dataset.views) td.dataset.views = column.dataset.views;
    }
    firewallList.append(tr);
  }
  syncViewColumns();
}

function syncViewColumns() {
  fleetTable.dataset.view = activeView;
  for (const column of fleetTable.querySelectorAll("[data-views]")) {
    column.hidden = activeView !== "all" && !column.dataset.views.split(" ").includes(activeView);
  }
  requestAnimationFrame(syncTableOverflowHint);
}

function setView(view) {
  activeView = view;
  for (const button of viewButtons) button.setAttribute("aria-pressed", String(button.dataset.view === view));
  tableWrap.scrollLeft = 0;
  syncViewColumns();
}

async function refresh() {
  if (!sessionId || scanning) return;
  const requestedSession = sessionId;
  const includeRuntime = runtimeToggle.checked;
  scanning = true;
  refreshButton.disabled = true;
  runtimeToggle.disabled = true;
  refreshButton.textContent = "Scanning…";
  loadingState.hidden = false;
  serverDetailStatus.textContent = "Refreshing server health…";
  serverDetailStatus.removeAttribute("data-error");
  loadingState.removeAttribute("data-error");
  loadingState.textContent = includeRuntime
    ? "Reading Management configuration and live gateway health…"
    : "Reading Management configuration…";
  try {
    const result = await api("/api/logging-status", { sessionId: requestedSession, includeRuntime, allDomains: allDomainMode });
    if (sessionId !== requestedSession) return;
    latestRows = result.firewalls;
    latestCheckedAt = result.checkedAt;
    latestDomainCount = result.domains?.length || 0;
    latestIncludedRuntime = includeRuntime;
    domainColumn.hidden = !allDomainMode;
    renderAttention(result.firewalls, result.domainFailures);
    renderHistory(result);
    renderManagementScope(result);
    latestServerReports = result.logServerHealth || [];
    renderLogServerChart(result.logServers, includeRuntime);
    syncServerPage();
    scanNavigation.hidden = false;
    loadingState.hidden = true;
    serverDetailStatus.textContent = "";
    applyFilters();
  } catch (error) {
    if (sessionId !== requestedSession) return;
    loadingState.hidden = false;
    loadingState.setAttribute("data-error", "");
    serverDetailStatus.setAttribute("data-error", "");
    serverDetailStatus.textContent = latestCheckedAt ? "Refresh failed. Showing the last completed scan." : error.message;
    if (latestCheckedAt && !managementSummary.classList.contains("hidden")) {
      const stale = textElement("p", "Latest scan failed. The evidence below is from the previous scan.", "threshold-finding");
      stale.id = "managementStale";
      document.querySelector("#managementStale")?.remove();
      managementHealth.prepend(stale);
    }
    loadingState.textContent = latestCheckedAt ? `Refresh failed. Showing the last completed scan. ${error.message}` : error.message;
  } finally {
    if (sessionId === requestedSession) {
      scanning = false;
      refreshButton.disabled = false;
      runtimeToggle.disabled = false;
      refreshButton.textContent = "Refresh scan";
    }
  }
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = loginForm.querySelector('button[type="submit"]');
  button.disabled = true;
  loginStatus.removeAttribute("data-error");
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
    managementScope = isAllDomains ? "MDS / all domains" : isMds ? `MDS / ${result.domain || fields.get("domain")}` : "Security Management Server";
    managementHost = result.baseUrl ? new URL(result.baseUrl).host : String(fields.get("host") || "").trim();
    connectionLabel.textContent = `Connected · ${managementHost} · ${result.user}${result.largeEnvironmentMode ? " · Large environment mode" : ""}`;
    loginForm.elements.password.value = "";
    loginCard.classList.add("hidden");
    workspace.classList.remove("hidden");
    workspaceTitle.focus();
    void refresh();
    void updateSchedule();
    schedulePolling = setInterval(updateSchedule, 15000);
  } catch (error) {
    loginStatus.setAttribute("data-error", "");
    loginStatus.textContent = error.message;
  } finally { button.disabled = false; }
});

refreshButton.addEventListener("click", refresh);
runtimeToggle.addEventListener("change", refresh);
logoutButton.addEventListener("click", async () => {
  const previousSession = sessionId;
  sessionId = "";
  scanning = false;
  allDomainMode = false;
  latestDomainCount = 0;
  latestRows = [];
  latestServerReports = [];
  latestCheckedAt = "";
  clearInterval(schedulePolling);
  if (location.hash.startsWith("#log-server=")) window.history.replaceState(null, "", window.location.pathname);
  syncServerPage();
  schedulePanel.classList.add("hidden");
  scheduleLink.hidden = true;
  scheduleAlerts.replaceChildren();
  serverDetailStatus.textContent = "";
  domainColumn.hidden = true;
  workspace.classList.add("hidden");
  loginCard.classList.remove("hidden");
  loginStatus.textContent = "Closing session…";
  loginForm.elements.host.focus();
  firewallList.replaceChildren();
  firewallSearch.value = "";
  firewallFilter.value = "all";
  replaceOptions(domainFilter, []);
  replaceOptions(destinationFilter, []);
  document.querySelector("#domainFilterField").hidden = true;
  document.querySelector("#destinationFilterField").hidden = true;
  exportButton.disabled = true;
  scanNavigation.hidden = true;
  tableWrap.hidden = true;
  fleetEmpty.hidden = true;
  tableScrollHint.hidden = true;
  setView("overview");
  subtitle.textContent = "Waiting for scan results.";
  scopeList.replaceChildren();
  managementSummary.classList.add("hidden");
  serverSummary.classList.add("hidden");
  logServerChart.replaceChildren();
  changeSummary.classList.add("hidden");
  changeList.replaceChildren();
  attentionPanel.classList.add("hidden");
  attentionList.replaceChildren();
  const connect = loginForm.querySelector('button[type="submit"]');
  connect.disabled = true;
  try {
    if (previousSession) await api("/api/logout", { sessionId: previousSession });
    loginStatus.textContent = "Logged out.";
  } catch (error) {
    loginStatus.setAttribute("data-error", "");
    loginStatus.textContent = `The dashboard disconnected, but Management logout could not be confirmed. ${error.message}`;
  } finally {
    connect.disabled = false;
  }
});

function applyFilters() {
  if (!latestCheckedAt) return;
  const rows = filteredRows();
  const count = latestRows.length;
  const scope = latestDomainCount ? ` · ${latestDomainCount} ${latestDomainCount === 1 ? "domain" : "domains"} in scope` : "";
  const mode = latestIncludedRuntime ? "" : " · Configuration only";
  subtitle.textContent = `${rows.length === count ? "" : `${rows.length} of `}${count} ${count === 1 ? "firewall" : "firewalls"}${scope}${mode} · ${new Date(latestCheckedAt).toLocaleString()}`;
  exportButton.disabled = !rows.length;
  render(rows);
}

firewallSearch.addEventListener("input", applyFilters);
firewallFilter.addEventListener("change", applyFilters);
domainFilter.addEventListener("change", applyFilters);
destinationFilter.addEventListener("change", applyFilters);
for (const button of viewButtons) button.addEventListener("click", () => setView(button.dataset.view));
exportButton.addEventListener("click", exportCsv);
window.addEventListener("hashchange", () => syncServerPage(true));
scheduleForm.addEventListener("submit", event => {
  event.preventDefault();
  const fields = new FormData(scheduleForm);
  void updateSchedule("start", { interval: Number(fields.get("interval")), horizon: fields.get("horizon") });
});
stopSchedule.addEventListener("click", () => void updateSchedule("stop"));
managementType.addEventListener("change", updateManagementType);
window.addEventListener("resize", syncTableOverflowHint);
tableWrap.addEventListener("scroll", syncTableOverflowHint, { passive: true });
tableScrollLeft.addEventListener("click", () => scrollTableColumns(-1));
tableScrollRight.addEventListener("click", () => scrollTableColumns(1));
updateManagementType();
