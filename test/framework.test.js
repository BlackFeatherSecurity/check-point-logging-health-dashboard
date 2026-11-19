import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { apiUrl, normalizeBaseUrl } from "../src/check-point-client.js";
import { SessionManager } from "../src/session-manager.js";
import { collectAllDomainLoggingStatus, collectLoggingStatus, loggingStatusInternals } from "../src/workflows/logging-status.js";
import { HistoryStore, historyInternals } from "../src/history-store.js";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

test("log-status workflow separates configured destinations from read-only runtime status", async () => {
  const calls = [];
  const sessions = {
    async list() {
      return [{
        name: "gateway-a", type: "simple-gateway", uid: "a",
        "save-logs-locally": true,
        "send-logs-to-server": [{ name: "log-primary" }],
        "send-logs-to-backup-server": [{ name: "log-backup" }]
      },
      { name: "host-not-firewall", type: "host" },
      { name: "management-or-log-host", type: "checkpoint-host" }];
    },
    async runScript(_sessionId, body) {
      calls.push(body);
      return { taskSummary: [{ executions: [{ target: "gateway-a", output: "Log connection: connected" }] }] };
    },
    async command(_sessionId, command) {
      assert.equal(command, "show-simple-gateway");
      return {
        "save-logs-locally": true,
        "send-logs-to-server": [{ name: "log-primary" }],
        "send-logs-to-backup-server": [{ name: "log-backup" }]
      };
    }
  };
  const status = await collectLoggingStatus({ sessions, sessionId: "sid", context: "primary", includeRuntime: true });
  assert.equal(status.count, 1);
  assert.deepEqual(status.firewalls[0].destinations, ["log-primary", "log-backup"]);
  assert.equal(status.firewalls[0].primary, "log-primary");
  assert.deepEqual(status.firewalls[0].secondary, []);
  assert.equal(status.firewalls[0].mode, "local");
  assert.equal(status.firewalls[0].runtime.state, "connected");
  assert.equal(status.firewalls[0].runtime.destination, "log-primary");
  assert.equal(status.firewalls[0].deviceFamily, "Gaia gateway / cluster");
  assert.equal(status.firewalls[0].probe.id, "gaia");
  assert.deepEqual(status.logServers, [
    { name: "log-primary", configuredFirewalls: 1, activeFirewalls: 1 },
    { name: "log-backup", configuredFirewalls: 1, activeFirewalls: 0 }
  ]);
  assert.equal(calls[0].script, "cpstat -f log_connection fw");
  assert.deepEqual(calls[0].targets, ["gateway-a"]);
  assert.match(calls[1].script, /__TIME_EPOCH__/);
  assert.equal(loggingStatusInternals.parseRuntime("connection failed").state, "disconnected");
  assert.equal(
    loggingStatusInternals.parseRuntime("Log Servers Connections\n| 192.0.2.20 | Connected |", "", ["log-primary"]).destination,
    "log-primary"
  );
});

test("logging workflow selects the SMB probe only from full Management object signals", async () => {
  const calls = [];
  const sessions = {
    async list() { return [{ name: "spark-1", type: "simple-gateway", uid: "spark" }, { name: "maestro-1", type: "cloudguard-gateway", uid: "maestro" }]; },
    async command(_id, command, body) {
      if (body.uid === "spark") return { type: "simple-gateway", "allow-smb": true, "send-logs-to-server": [{ name: "log-smb" }] };
      assert.equal(command, "show-simple-gateway");
      return { type: "cloudguard-gateway", hardware: "Maestro Orchestrator", "send-logs-to-server": [{ name: "log-maestro" }] };
    },
    async runScript(_id, body) {
      calls.push(body);
      return { taskSummary: [{ executions: [{ target: "spark-1", output: "tcp 0 0 10.0.0.5:46000 192.0.2.30:257 ESTABLISHED fw" }] }] };
    }
  };
  const status = await collectLoggingStatus({ sessions, sessionId: "sid", includeRuntime: true });
  const spark = status.firewalls.find((row) => row.name === "spark-1");
  const maestro = status.firewalls.find((row) => row.name === "maestro-1");
  assert.equal(spark.probe.id, "smb");
  assert.equal(spark.runtime.state, "connected");
  assert.equal(spark.runtime.destination, "log-smb");
  assert.match(calls[0].script, /netstat -tnp/);
  assert.equal(maestro.probe.id, "unknown");
  assert.equal(maestro.runtime.state, "unknown");
  assert.equal(calls.length, 2, "unknown platforms never receive a fallback command");
  assert.equal(loggingStatusInternals.parseRuntime("NO_FW_LOG_CONNECTION", "", ["log-smb"], loggingStatusInternals.DEVICE_PROFILES.smb).state, "disconnected");
});

test("time health uses Gaia NTP status and measures the active configured log server", async () => {
  const sessions = {
    async list() {
      return [
        { name: "gateway-a", type: "simple-gateway", uid: "a" },
        { name: "central-log", type: "checkpoint-host", uid: "log" }
      ];
    },
    async command(_id, command) {
      assert.equal(command, "show-simple-gateway");
      return { "send-logs-to-server": [{ name: "central-log" }] };
    },
    async runScript(_id, body) {
      if (body["script-name"] === "check-log-connection-gaia") {
        return { taskSummary: [{ executions: [{ target: "gateway-a", output: "Log connection: connected" }] }] };
      }
      if (body["script-name"] === "check-time-health-gaia") {
        return { taskSummary: [{ executions: [{ target: "gateway-a", output: "__TIME_EPOCH__=1735689601\n__NTP_ACTIVE__=Yes\n__NTP_CURRENT__=ntp.example.net" }] }] };
      }
      assert.equal(body["script-name"], "check-active-log-server-time");
      assert.deepEqual(body.targets, ["central-log"]);
      return { taskSummary: [{ executions: [{ target: "central-log", output: "__TIME_EPOCH__=1735689600" }] }] };
    }
  };
  const result = await collectLoggingStatus({ sessions, sessionId: "sid", includeRuntime: true });
  const time = result.firewalls[0].time;
  assert.equal(time.state, "synced");
  assert.equal(time.ntpEnabled, true);
  assert.equal(time.peer, "ntp.example.net");
  assert.equal(time.logServer, "central-log");
  assert.equal(time.offsetMs, 1000);
  assert.equal(loggingStatusInternals.evaluateTimeHealth({ profile: loggingStatusInternals.DEVICE_PROFILES.gaia, firewallEpoch: 1000, logServerEpoch: 302000, ntpEnabled: true }).state, "drift-critical");
  assert.equal(loggingStatusInternals.evaluateTimeHealth({ profile: loggingStatusInternals.DEVICE_PROFILES.gaia, firewallEpoch: 1000, ntpEnabled: false }).state, "ntp-off");
});

test("time health keeps gateway NTP and UTC evidence when the log-server comparison fails", async () => {
  const sessions = {
    async list() {
      return [
        { name: "gateway-a", type: "simple-gateway", uid: "a" },
        { name: "central-log", type: "checkpoint-host", uid: "log" }
      ];
    },
    async command() { return { "send-logs-to-server": [{ name: "central-log" }] }; },
    async runScript(_id, body) {
      if (body["script-name"] === "check-log-connection-gaia") {
        return { taskSummary: [{ executions: [{ target: "gateway-a", output: "Log connection: connected" }] }] };
      }
      if (body["script-name"] === "check-time-health-gaia") {
        return { taskSummary: [{ executions: [{ target: "gateway-a", output: "__TIME_EPOCH__=1735689601\n__NTP_ACTIVE__=active: true\n__NTP_CURRENT__=ntp.example.net" }] }] };
      }
      assert.equal(body["script-name"], "check-active-log-server-time");
      return { taskSummary: [{ executions: [{ target: "central-log", error: "Permission denied for this target" }] }] };
    }
  };
  const result = await collectLoggingStatus({ sessions, sessionId: "sid", includeRuntime: true });
  const time = result.firewalls[0].time;
  assert.equal(time.state, "ntp-active");
  assert.equal(time.ntpEnabled, true);
  assert.equal(time.firewallEpoch, 1735689601000);
  assert.equal(time.logServer, "central-log");
  assert.match(time.comparisonError, /Permission denied/);
});

test("NTP and gateway clock evidence are first-class table information", async () => {
  const [html, app] = await Promise.all([
    readFile(new URL("../public/index.html", import.meta.url), "utf8"),
    readFile(new URL("../public/app.js", import.meta.url), "utf8")
  ]);
  assert.match(html, /NTP &amp; time[\s\S]*Runtime probe/);
  assert.match(html, /NTP is recommended/);
  assert.match(app, /Firewall UTC/);
  assert.match(app, /View NTP and clock evidence/);
});

test("cluster route health compares normalized route tables member by member", async () => {
  const sessions = {
    async list() { return [{ name: "cluster-a", type: "simple-cluster", uid: "cluster" }]; },
    async command(_id, command) {
      assert.equal(command, "show-simple-cluster");
      return { members: [{ name: "member-a" }, { name: "member-b" }], "send-logs-to-server": [{ name: "central-log" }] };
    },
    async runScript(_id, body) {
      if (body["script-name"] === "check-log-connection-gaia") return { taskSummary: [{ executions: [{ target: "cluster-a", output: "Log connection: connected" }] }] };
      if (body["script-name"] === "check-time-health-gaia") return { taskSummary: [{ executions: [{ target: "cluster-a", output: "__TIME_EPOCH__=1735689600\n__NTP_ACTIVE__=Yes\n__NTP_CURRENT__=ntp.example.net" }] }] };
      assert.equal(body["script-name"], "check-cluster-routes");
      assert.match(body.script, /show route all/);
      return { taskSummary: [{ executions: [
        { target: "member-a", output: "Destination Gateway\n10.0.0.0/24 via 192.0.2.1 eth1\n0.0.0.0/0 via 192.0.2.254 eth0" },
        { target: "member-b", output: "Destination Gateway\n10.0.0.0/24 via 192.0.2.1 eth1\n0.0.0.0/0 via 192.0.2.253 eth0" }
      ] }] };
    }
  };
  const result = await collectLoggingStatus({ sessions, sessionId: "sid", includeRuntime: true });
  const routes = result.firewalls[0].routes;
  assert.equal(routes.state, "mismatch");
  assert.deepEqual(routes.counts, { "member-a": 2, "member-b": 2 });
  assert.match(routes.differences["member-b"].only[0], /192\.0\.2\.253/);
  assert.deepEqual(loggingStatusInternals.routeLines("Flags\n10.0.0.0/24    via 192.0.2.1\nlocal 192.0.2.10 dev eth0"), ["10.0.0.0/24 via 192.0.2.1"]);
});

test("all-domain MDS logging collection keeps firewall domains separate and logs out child sessions", async () => {
  const closed = [];
  const sessions = {
    describe() { return { allDomains: true, mdsMode: true, domains: [{ name: "Domain-A" }, { name: "Domain-B" }] }; },
    async openDomainSession(_id, domain) { return domain; },
    async logout(id) { closed.push(id); },
    async list(sessionId) { return [{ name: `${sessionId}-fw`, type: "simple-gateway", uid: `${sessionId}-uid` }]; },
    async command(_id, command) {
      assert.equal(command, "show-simple-gateway");
      return { "send-logs-to-server": [{ name: "central-log" }] };
    },
    async runScript(_id, body) {
      return { taskSummary: [{ executions: body.targets.map((target) => ({ target, output: "Log connection: connected" })) }] };
    }
  };
  const result = await collectAllDomainLoggingStatus({ sessions, sessionId: "root", includeRuntime: true });
  assert.equal(result.count, 2);
  assert.deepEqual(result.firewalls.map((row) => row.domain), ["Domain-A", "Domain-B"]);
  assert.deepEqual(closed, ["Domain-A", "Domain-B"]);
  assert.deepEqual(result.domainFailures, []);
});

test("scan history reports only meaningful firewall logging changes", () => {
  const previous = [{ name: "gateway-a", local: false, primary: "log-a", secondary: [], backup: [], destination: "log-a", runtimeState: "connected", mode: "off-box" }];
  const current = [
    { ...previous[0], runtimeState: "disconnected" },
    { name: "gateway-b", local: true, primary: "", secondary: [], backup: [], destination: "", runtimeState: "unknown", mode: "local" }
  ];
  assert.deepEqual(historyInternals.changesBetween(previous, current), [
    { firewall: "gateway-a", kind: "changed", fields: ["runtimeState"] },
    { firewall: "gateway-b", kind: "added", fields: ["firewall discovered"] }
  ]);
});

test("scan history isolates scopes, skips partial scans, and serializes writes", async () => {
  const directory = await mkdtemp(join(tmpdir(), "logging-history-"));
  try {
    await writeFile(join(directory, "scan-history.json"), JSON.stringify({
      snapshots: [{ checkedAt: "legacy", firewalls: [{ name: "legacy-firewall" }] }]
    }));
    const history = new HistoryStore({ directory });
    const snapshot = (checkedAt, name) => ({ checkedAt, firewalls: [{ name }] });
    const [initial, other] = await Promise.all([
      history.record(snapshot("first", "gate-a"), "scope-a"),
      history.record(snapshot("other", "gate-b"), "scope-b")
    ]);
    assert.equal(initial.baseline, true);
    assert.equal(other.baseline, true);
    assert.equal((await history.record({
      ...snapshot("partial", "gate-b"),
      domainFailures: [{ domain: "datacenter" }]
    }, "scope-a")).partial, true);
    const resumed = await history.record(snapshot("resumed", "gate-a"), "scope-a");
    assert.equal(resumed.previousCheckedAt, "first");
    assert.deepEqual(resumed.changes, []);
    const persisted = new HistoryStore({ directory });
    assert.equal((await persisted.record(snapshot("again", "gate-b"), "scope-b")).previousCheckedAt, "other");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("self-signed certificates default on while explicit TLS verification is preserved for every management type", async () => {
  const html = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
  assert.match(html, /<input\b[^>]*name="ignoreTls"[^>]*\bchecked\b/);
  class TlsClient {
    constructor(options) { Object.assign(this, options); }
    withSid(sid) { return new TlsClient({ ...this, sid }); }
    async command() { return { sid: "test-sid" }; }
  }
  for (const mode of [{}, { smart1Cloud: true }, { mdsMode: true, domain: "Domain-A" }]) {
    for (const ignoreTls of [undefined, true, false]) {
      const sessions = new SessionManager({ clientFactory: options => new TlsClient(options) });
      const login = await sessions.login({ host: "example.com", username: "admin", password: "test", ...mode, ...(ignoreTls === undefined ? {} : { ignoreTls }) });
      for (const [context, state] of Object.entries(login.contexts)) {
        if (state.available) assert.equal(sessions.client(login.sessionId, context).rejectUnauthorized, ignoreTls === false);
      }
      await sessions.logout(login.sessionId);
    }
  }
});


test("explicit version URLs preserve SMS and Smart-1 Cloud paths", () => {
  assert.equal(apiUrl({ baseUrl: "https://mgmt.example.com" }, "show-hosts", "v2.2").pathname, "/web_api/v2.2/show-hosts");
  assert.equal(apiUrl({ baseUrl: "https://tenant.example.com/context/web_api", smart1Cloud: true }, "show-hosts", "v2.1").pathname, "/context/web_api/v2.1/show-hosts");
  assert.throws(() => apiUrl({ baseUrl: "https://mgmt.example.com" }, "show-hosts", "../../"), /Invalid/);
});

test("context capability negotiation rejects unsupported versions and pins script task polls", async () => {
  const calls = [];
  class VersionClient {
    constructor(options) { Object.assign(this, options); }
    withSid(sid) { return new VersionClient({ ...this, sid }); }
    async command(command, body, version) {
      calls.push({ command, version, sid: this.sid });
      if (command === "login") return { sid: body.domain || "primary" };
      if (command === "show-api-versions") return { "supported-versions": this.sid === "Global" ? ["2.1"] : ["2.1","2.2"], "current-version": "2.2" };
      if (command === "run-script") return { tasks: [{ "task-id": "id" }] };
      if (command === "show-task") return { tasks: [{ "task-details": [{ responseMessage: Buffer.from("done").toString("base64") }] }] };
      return {};
    }
  }
  const sessions = new SessionManager({ clientFactory: o=>new VersionClient(o), largeEnvironmentApiConcurrency: 1 });
  const login = await sessions.login({ host:"mds.example.com", username:"admin", password:"test", mdsMode:true, largeEnvironmentMode:true });
  await sessions.command(login.sessionId, "show-hosts", {}, "primary", "v2.2");
  await assert.rejects(sessions.command(login.sessionId, "show-hosts", {}, "global", "v2.2"), /not verified/);
  await sessions.runScript(login.sessionId, { script:"echo done", targets:["gateway"] }, "primary", "v2.2");
  assert.equal(calls.find(c=>c.command==="show-task").version, "v2.2");
  assert.equal(calls.filter(c=>c.command==="show-hosts").length, 1);
});

test("capability detection failure leaves login and unversioned framework calls available", async () => {
  class Client {
    constructor(o) { Object.assign(this,o); }
    withSid(sid) { return new Client({...this,sid}); }
    async command(command) {
      if(command==="login") return {sid:"sid"};
      if(command==="show-api-versions") throw new Error("Unavailable");
      return {ok:true};
    }
  }
  const sessions=new SessionManager({clientFactory:o=>new Client(o)});
  const login=await sessions.login({host:"sms.example.com",username:"admin",password:"test"});
  assert.match((await sessions.capabilities(login.sessionId)).error,/Unavailable/);
  assert.equal((await sessions.command(login.sessionId,"show-hosts")).ok,true);
  await assert.rejects(sessions.command(login.sessionId,"show-hosts",{},"primary","v2.2"),/not verified/);
});


test("normalizes SMS and Smart-1 Cloud API URLs", () => {
  assert.equal(normalizeBaseUrl("mgmt.example.com", "443"), "https://mgmt.example.com");
  assert.equal(
    normalizeBaseUrl("https://tenant.maas.checkpoint.com/customer/abc", "", { smart1Cloud: true }),
    "https://tenant.maas.checkpoint.com/customer/abc/web_api"
  );
  assert.equal(
    apiUrl({ baseUrl: "https://mgmt.example.com", smart1Cloud: false }, "show-hosts").pathname,
    "/web_api/show-hosts"
  );
});

test("creates MDS contexts, runs commands, polls run-script, and logs out", async (t) => {
  const requests = [];
  let loginCount = 0;
  let taskPolls = 0;
  class MockClient {
    constructor(options) {
      Object.assign(this, options);
    }
    withSid(sid) {
      return new MockClient({ ...this, sid });
    }
    async command(command, body = {}) {
      requests.push({ command, body, sid: this.sid || "" });
      let result;
      if (command === "login") result = { sid: `sid-${++loginCount}` };
      else if (command === "show-hosts") result = { objects: [{ name: "host-a" }], total: 1 };
      else if (command === "run-script") result = { tasks: [{ "task-id": "task-1" }] };
      else if (command === "show-task") {
        taskPolls += 1;
        result = taskPolls < 2
          ? { tasks: [{ "task-details": [] }] }
          : { tasks: [{ "task-details": [{ statusDescription: "R81.20" }] }] };
      } else result = { message: "OK" };
      return result;
    }
    async list(command, body = {}) {
      return (await this.command(command, body)).objects;
    }
  }

  const sessions = new SessionManager({
    taskPollAttempts: 3,
    taskPollIntervalMs: 1,
    clientFactory: (options) => new MockClient(options)
  });
  const connected = await sessions.login({
    host: "https://mds.example.com",
    authMode: "password",
    username: "admin",
    password: "secret",
    mdsMode: true,
    domain: "Domain-A"
  });

  assert.deepEqual(
    Object.fromEntries(Object.entries(connected.contexts).map(([key, value]) => [key, value.available])),
    { primary: true, mds: true, global: true, "system-data": true }
  );
  assert.equal(connected.largeEnvironmentMode, false);
  assert.equal(requests.filter(({ command }) => command === "login").length, 4);
  assert.equal(requests.find(({ body }) => body.domain === "Global").body.password, "secret");

  const objects = await sessions.list(connected.sessionId, "show-hosts", {}, "global");
  assert.equal(objects[0].name, "host-a");
  assert.equal(requests.find(({ command }) => command === "show-hosts").sid, "sid-3");

  const script = await sessions.runScript(connected.sessionId, {
    "script-name": "test",
    script: "show version",
    targets: ["gw"]
  }, "mds");
  assert.equal(script.output, "R81.20");
  assert.deepEqual(script.taskSummary, [{
    id: "",
    name: "run-script",
    status: "unknown",
    progress: null,
    startedAt: "",
    lastUpdatedAt: "",
    targets: [],
    output: "",
    statusDescription: "R81.20",
    errors: [],
    executions: [{ target: "", status: "", message: "R81.20", output: "", error: "" }]
  }]);
  assert.equal(requests.find(({ command }) => command === "run-script").sid, "sid-2");
  assert.equal(taskPolls, 2);

  const logout = await sessions.logout(connected.sessionId);
  assert.equal(logout.closedContexts, 4);
  assert.throws(() => sessions.get(connected.sessionId), /Session not found/);
});

test("large-environment mode applies separate API and run-script throttles", async () => {
  let activeApi = 0;
  let maxActiveApi = 0;
  let activeScripts = 0;
  let maxActiveScripts = 0;

  class ThrottleClient {
    constructor(options) { Object.assign(this, options); }
    withSid(sid) { return new ThrottleClient({ ...this, sid }); }
    async command(command) {
      if (command === "login") return { sid: "large-sid" };
      if (command === "logout") return { message: "OK" };
      const isScript = command === "run-script";
      if (isScript) {
        activeScripts += 1;
        maxActiveScripts = Math.max(maxActiveScripts, activeScripts);
      } else {
        activeApi += 1;
        maxActiveApi = Math.max(maxActiveApi, activeApi);
      }
      await new Promise((resolve) => setTimeout(resolve, 5));
      if (isScript) {
        activeScripts -= 1;
        return { tasks: [{ "task-details": [{ statusDescription: "done" }] }] };
      }
      activeApi -= 1;
      return { ok: true };
    }
  }

  const sessions = new SessionManager({
    largeEnvironmentApiConcurrency: 2,
    largeEnvironmentRunScriptConcurrency: 1,
    clientFactory: (options) => new ThrottleClient(options)
  });
  const connected = await sessions.login({
    host: "https://large.example.com",
    authMode: "password",
    username: "admin",
    password: "secret",
    largeEnvironmentMode: true
  });

  await Promise.all(Array.from({ length: 6 }, () =>
    sessions.command(connected.sessionId, "show-hosts")
  ));
  await Promise.all(Array.from({ length: 3 }, () =>
    sessions.runScript(connected.sessionId, { script: "show version", targets: ["gw"] })
  ));

  assert.equal(connected.largeEnvironmentMode, true);
  assert.equal(maxActiveApi, 2);
  assert.equal(maxActiveScripts, 1);
});

test("run-script keeps decoded output and errors attached to their gateway targets", async () => {
  class ScriptClient {
    constructor(options) { Object.assign(this, options); }
    withSid(sid) { return new ScriptClient({ ...this, sid }); }
    async command(command) {
      if (command === "login") return { sid: "script-sid" };
      if (command === "logout") return { ok: true };
      if (command === "run-script") return {
        tasks: [{
          "task-id": "task-output-1",
          "task-name": "run-script",
          status: "succeeded",
          "progress-percentage": 100,
          "task-details": [
            { gatewayName: "gw-east", responseMessage: Buffer.from("east output").toString("base64") },
            { gatewayName: "gw-west", responseError: "SSH connection failed" }
          ]
        }]
      };
      return {};
    }
  }
  const sessions = new SessionManager({ clientFactory: (options) => new ScriptClient(options) });
  const connected = await sessions.login({ host: "mgmt.example.com", authMode: "api-key", apiKey: "key" });
  const result = await sessions.runScript(connected.sessionId, { script: "cplp list", targets: ["gw-east", "gw-west"] });

  assert.equal(result.output, "east output");
  assert.deepEqual(result.taskSummary[0].targets, ["gw-east", "gw-west"]);
  assert.deepEqual(result.taskSummary[0].executions, [
    { target: "gw-east", status: "", message: "", output: "east output", error: "" },
    { target: "gw-west", status: "", message: "", output: "", error: "SSH connection failed" }
  ]);
});

test("run-script keeps outputs from every task when one target finishes earlier", async () => {
  const polls = [];
  class SplitTaskClient {
    constructor(options) { Object.assign(this, options); }
    withSid(sid) { return new SplitTaskClient({ ...this, sid }); }
    async command(command, body) {
      if (command === "login") return { sid: "split-session" };
      if (command === "run-script") return { tasks: [{ "task-id": "early" }, { "task-id": "late" }] };
      assert.equal(command, "show-task");
      const id = body["task-id"];
      polls.push(id);
      if (id === "late" && polls.filter(value => value === id).length === 1) {
        return { tasks: [{ "task-id": id, status: "in progress" }] };
      }
      return { tasks: [{
        "task-id": id,
        status: "succeeded",
        "task-details": [{ gatewayName: id, responseMessage: Buffer.from(`output for ${id}`).toString("base64") }]
      }] };
    }
  }
  const sessions = new SessionManager({ clientFactory: options => new SplitTaskClient(options), taskPollIntervalMs: 1 });
  const { sessionId } = await sessions.login({ host: "example.com", username: "user", password: "fixture" });
  const report = await sessions.runScript(sessionId, { targets: ["early", "late"], script: "date -u" });
  assert.deepEqual(report.taskSummary.map(task => task.executions[0].target), ["early", "late"]);
  assert.deepEqual(polls, ["early", "late", "late"]);
});
