import test from "node:test";
import assert from "node:assert/strict";
import { collectLoggingStatus, loggingStatusInternals } from "../src/workflows/logging-status.js";
import {
  collectIndexedFreshness, collectManagementHealth, monitoringPreset, parseLogServerProbe
} from "../src/workflows/infrastructure-health.js";
import { ScanScheduler, updateAlerts } from "../src/scan-scheduler.js";

const diskHeader = "Filesystem 1024-blocks Used Available Capacity Mounted on";
const diskProbe = [
  "__LOG_VOLUME__", diskHeader, "/dev/log 1000000 870000 130000 87% /var/log",
  "__INDEX_VOLUME__", diskHeader, "/dev/index 2000000 1200000 800000 60% /var/index",
  "__INDEXER__", "Indexer Status: Running"
].join("\n");
const noIndexVolume = [
  "__LOG_VOLUME__", diskHeader, "/dev/log 1000000 870000 130000 87% /var/log",
  "__INDEX_VOLUME__", "df: index directory not found", "__INDEXER__", "Unknown flavor", "__INDEXER_FAILED__"
].join("\n");
const memberProbe = (role, ntp) => [
  "__LOG_CONNECTION__", "|192.0.2.11|0|Log-Server Connected|",
  "__CLOCK__", "__TIME_EPOCH__=1735689600", `__NTP_ACTIVE__=${ntp}`, "__NTP_CURRENT__=ntp.example.net",
  "__CLUSTER_STATE__", `2 (local) 192.0.2.20 0% ${role} Member`
].join("\n");
const executions = (targets, output) => ({
  taskSummary: [{ executions: targets.map(target => ({ target, output: typeof output === "function" ? output(target) : output })) }]
});

test("server probes preserve separate volumes, missing paths, and disabled indexing", () => {
  const results = parseLogServerProbe(diskProbe, "enabled");
  assert.equal(results.volumes.log.percentFree, 13);
  assert.equal(results.volumes.index.availableKiB, 800000);
  assert.equal(results.volumes.index.mount, "/var/index");
  assert.equal(results.indexer, "Running");
  const missing = parseLogServerProbe(noIndexVolume, "enabled");
  assert.equal(missing.volumes.index, null);
  assert.equal(missing.indexer, "Unavailable");
  assert.equal(parseLogServerProbe(noIndexVolume, "disabled").indexer, "Disabled in configuration");
  assert.equal(parseLogServerProbe("__INDEXER__\nUpdates and Logs Indexed Rate: 16", "enabled").indexer,
    "Indexing activity observed");
  assert.equal(parseLogServerProbe("__INDEXER__\nUpdates and Logs Indexed Rate: 0\nUpdates and Logs Indexed Rate (10min): 188", "enabled").indexer,
    "No indexing activity in this sample");
  assert.match(monitoringPreset("log-server-storage"), /df -Pk/);
  assert.match(monitoringPreset("cluster-member-logging-health"), /cphaprob state/);
  assert.equal(loggingStatusInternals.ntpFromOutput("__NTP_ACTIVE__=Invalid command: show ntp active").enabled, null);
});

test("live scan collects Management, log-server, and cluster member evidence through fixed targets", async () => {
  const calls = [];
  const sessions = {
    async list() {
      return [
        { uid: "cluster", type: "simple-cluster", name: "cluster-a" },
        { uid: "log", type: "CpmiHostCkp", name: "log-a", "ipv4-address": "192.0.2.11" },
        { uid: "unused", type: "checkpoint-host", name: "unused" },
        { uid: "host", type: "host", name: "external" }
      ];
    },
    async command(_id, command, body) {
      if (command === "show-simple-cluster") return {
        "send-logs-to-server": [{ uid: "log", name: "log-a" }],
        "send-logs-to-backup-server": ["external"],
        "cluster-members": [{ name: "member-a" }, { name: "member-b" }]
      };
      if (command === "show-checkpoint-host") return body.uid === "log" ? {
        os: "Gaia",
        "management-blades": { "logging-and-status": true },
        "logs-settings": {
          "enable-log-indexing": true,
          "alert-when-free-disk-space-below": true,
          "alert-when-free-disk-space-below-threshold": 10,
          "alert-when-free-disk-space-below-metrics": "percent",
          "stop-logging-when-free-disk-space-below": false
        }
      } : { "management-blades": { "logging-and-status": false } };
      if (command === "show-ha-status") return {
        servers: [{ "ip-address": "192.0.2.41", "ha-state": "standby", "sync-state": "Sync Error" }],
        "successfully-synced": false
      };
      assert.fail(`Unexpected command ${command}`);
    },
    async runScript(_id, body) {
      const script = body["script-name"];
      calls.push({ script, targets: body.targets });
      switch (script) {
        case "check-log-connection-gaia":
          return executions(body.targets, "|192.0.2.11|0|Log-Server Connected|\n|192.0.2.12|1|Log-Server Not Connected|");
        case "check-time-health-gaia":
        case "check-active-log-server-time":
          return executions(body.targets, "__TIME_EPOCH__=1735689600\n__NTP_ACTIVE__=Yes");
        case "check-cluster-routes":
          return executions(body.targets, "0.0.0.0/0 via 192.0.2.1 eth0");
        case "check-cluster-member-health":
          return executions(body.targets, target => target === "member-a" ? memberProbe("ACTIVE(!)", "Yes") : memberProbe("STANDBY", "No"));
        case "check-log-server-storage":
          return executions(body.targets, diskProbe);
        default:
          assert.fail(`Unexpected preset ${script}`);
      }
    }
  };
  const result = await collectLoggingStatus({ sessions, sessionId: "session", domain: "Branch", includeInfrastructure: true });
  const server = result.logServerHealth.find(report => report.key === "log");
  assert.equal(result.management[0].reachability, "reachable");
  assert.equal(result.management[0].ha.state, "not-synchronized");
  assert.equal(result.management[0].ha.peers[0].role, "standby");
  assert.equal(server.indexingMode, "enabled");
  assert.equal(server.storageFindings[0].state, "approaching");
  assert.equal(server.dependencies[0].observed, true);
  assert.deepEqual(server.dependencies[0].roles, ["Primary"]);
  assert.deepEqual(calls.find(call => call.script === "check-log-server-storage").targets, ["log-a"]);
  assert.deepEqual(calls.find(call => call.script === "check-cluster-member-health").targets, ["member-a", "member-b"]);
  assert.equal(result.logServerHealth.find(report => report.name === "external").confirmed, false);
  const cluster = result.firewalls[0];
  assert.equal(cluster.runtime.observedDestination, "192.0.2.11");
  assert.equal(cluster.routes.state, "matched");
  assert.equal(cluster.memberHealth[0].role, "ACTIVE(!)");
  assert.equal(cluster.memberHealth[1].role, "STANDBY");
  assert.equal(cluster.memberHealth[1].time.state, "ntp-off");
  assert.equal(loggingStatusInternals.parseRuntime("Log connection: connected", "", ["log-a"]).observedDestination, "");
  assert.equal(loggingStatusInternals.parseRuntime(
    "tcp 0 0 192.0.2.5:30000 192.0.2.11:257 SYN_SENT fw", "", [], loggingStatusInternals.DEVICE_PROFILES.smb
  ).state, "disconnected");

  calls.length = 0;
  const configuration = await collectLoggingStatus({ sessions, sessionId: "session", includeInfrastructure: true, includeRuntime: false });
  assert.deepEqual(calls, []);
  assert.equal(configuration.logServerHealth.find(report => report.key === "log").probeState, "not-checked");
  assert.equal(configuration.firewalls[0].memberHealth, undefined);
});

test("Management reports System Data synchronization without inventing peer details", async () => {
  const sessions = {
    async command(id, command, query, context) {
      assert.deepEqual([id, command, query, context], ["session", "show-ha-status", {}, "system-data"]);
      return { "successfully-synced": true, "domain-type": "mds" };
    }
  };
  const result = await collectManagementHealth({ sessions, sessionId: "session", context: "system-data", domain: "System Data" });
  assert.deepEqual(result.ha, { state: "synchronized", peers: [] });
});

test("a standalone SMS reports HA unconfigured and unrelated failures stay unavailable", async () => {
  const sessions = { async command() { throw new Error("Operation is not allowed - High Availability is not configured on this system!"); } };
  assert.equal((await collectManagementHealth({ sessions, sessionId: "session" })).ha.state, "not-configured");
  sessions.command = async () => { throw new Error("Permission denied"); };
  assert.equal((await collectManagementHealth({ sessions, sessionId: "session" })).ha.state, "unavailable");
});

test("freshness queries are read-only, scoped, and distinguish zero logs from a denied or uncertain query", async () => {
  const replies = [
    { "logs-count": 1, logs: [{ time: "17:00" }] },
    { "logs-count": 0, logs: [] },
    { "logs-count": 0, incidents: { warning: true } }
  ];
  const report = {
    name: "log-a", confirmed: true, indexingMode: "enabled", aliases: ["log-a", "192.0.2.11"],
    dependencies: [
      { name: "cluster", members: ["member-a", "member-b"], roles: ["Primary"] },
      { name: "gateway-b", roles: [], observed: true },
      { name: "gateway-c", roles: ["Primary"] },
      { name: "gateway-d", roles: ["Backup"] }
    ]
  };
  const requests = [];
  const sessions = {
    async command(id, command, query, context) {
      assert.deepEqual([id, command, context], ["session", "show-logs", "primary"]);
      requests.push(query["new-query"]);
      return replies.shift();
    }
  };
  await collectIndexedFreshness({ sessions, sessionId: "session", context: "primary", horizon: "last-hour", reports: [report] });
  assert.equal(requests.length, 3);
  assert.equal(requests[0].filter, 'origin:"cluster" OR origin:"member-a" OR origin:"member-b"');
  assert.deepEqual(requests[0]["log-servers"], ["192.0.2.11"]);
  assert.deepEqual(report.dependencies.map(item => item.freshness), ["recent", "quiet", "unavailable", undefined]);
});

const evidence = () => ({ destinations: new Map(), freshness: new Map(), storage: new Set() });
const sample = (checkedAt, { destination = "main-log", freshness = "recent", low = false, failed = false } = {}) => ({
  checkedAt, management: [{ domain: "Domain A" }],
  domainFailures: failed ? [{ domain: "Domain A" }] : [],
  firewalls: failed ? [] : [{ uid: "a", name: "gw-a", domain: "Domain A", runtime: { state: "connected", observedDestination: destination } }],
  logServerHealth: failed ? [] : [{
    key: "main", domain: "Domain A", name: "main-log", aliases: ["main-log"],
    dependencies: [{ id: "a", name: "gw-a", freshness }, { id: "b", name: "gw-b", freshness }],
    storageFindings: low ? [{ key: "alert", label: "Low-space alert", unit: "percent", free: 13, threshold: 10, state: "approaching" }] : []
  }]
});

test("alerts require prior evidence and consecutive successful checks after partial scans", () => {
  const state = evidence();
  assert.deepEqual(updateAlerts(state, sample("first"), "last-hour"), []);
  const fault = { destination: "backup-log", freshness: "quiet", low: true };
  assert.deepEqual(updateAlerts(state, sample("second", fault), "last-hour"), []);
  assert.deepEqual(updateAlerts(state, sample("partial", { failed: true }), "last-hour"), []);
  assert.deepEqual(updateAlerts(state, sample("third", fault), "last-hour"), []);
  const alerts = updateAlerts(state, sample("fourth", fault), "last-hour");
  assert.deepEqual(alerts.map(alert => alert.type), ["Destination changed", "Multiple gateways went quiet", "Low log-volume headroom"]);
  assert.ok(alerts.every(alert => alert.domain === "Domain A" && alert.checkedAt === "fourth"));
  assert.deepEqual(updateAlerts(state, sample("recovered"), "last-hour"), []);
});

test("a disabled scheduler refuses a job and an active job records scans, isolates sessions, and stops", async () => {
  assert.throws(() => new ScanScheduler({ scan: async () => {} }).start("session", 15, "last-hour"), /disabled/);
  let now = 100;
  let callback;
  let scans = 0;
  const scheduler = new ScanScheduler({
    enabled: true, now: () => now,
    setTimer(fn, delay) { callback = fn; return { delay }; },
    clearTimer() { callback = null; },
    async scan(id, horizon) {
      assert.deepEqual([id, horizon], ["owner", "last-hour"]);
      scans++;
      return sample("first");
    }
  });
  assert.throws(() => scheduler.start("owner", 1, "last-hour"), /supported/);
  scheduler.start("owner", 15, "last-hour");
  assert.throws(() => scheduler.start("owner", 15, "last-hour"), /Stop/);
  assert.equal(scheduler.status("other").active, false);
  callback();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(scans, 1);
  assert.equal(scheduler.status("owner").lastSuccess, "first");
  assert.equal(scheduler.status("owner").nextAt, now + 15 * 60_000);
  scheduler.stop("owner");
  assert.equal(callback, null);
  assert.equal(scheduler.status("owner").active, false);
});
