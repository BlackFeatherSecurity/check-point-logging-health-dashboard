import test from "node:test";
import assert from "node:assert/strict";
import { loggingStatusInternals } from "../src/workflows/logging-status.js";
import { historyInternals } from "../src/history-store.js";

test("logging status treats any local logging setting as local", () => {
  const status = loggingStatusInternals.configuredStatus({
    "send-logs-to-server": [{ name: "Log-A" }],
    "send-logs-to-backup-server": [{ name: "Log-B" }],
    "save-logs-locally": true
  });
  assert.equal(status.mode, "local");
  assert.equal(status.primary, "Log-A");
  assert.deepEqual(status.backup, ["Log-B"]);
});

test("runtime output correlates a single configured remote destination", () => {
  const result = loggingStatusInternals.parseRuntime(
    "Log connection: Connected to 192.0.2.5",
    "",
    ["Central-Log"]
  );
  assert.equal(result.state, "connected");
  assert.equal(result.destination, "Central-Log");
});

test("SMB and unknown device families use the fixed allowlist", () => {
  const smb = loggingStatusInternals.deviceProfile({ type: "simple-gateway", "allow-smb": true });
  const unknown = loggingStatusInternals.deviceProfile({ type: "cloudguard-gateway", hardware: "Maestro Orchestrator" });
  assert.equal(smb.id, "smb");
  assert.match(smb.script, /netstat -tnp/);
  assert.equal(unknown.id, "unknown");
  assert.equal(loggingStatusInternals.parseRuntime("NO_FW_LOG_CONNECTION", "", ["Central-Log"], smb).state, "disconnected");
});

test("history records only meaningful firewall state deltas", () => {
  const before = [{ name: "gw-a", local: false, primary: "Log-A", secondary: [], backup: [], destination: "Log-A", runtimeState: "connected", mode: "off-box" }];
  const after = [{ ...before[0], local: true, mode: "local" }];
  const changes = historyInternals.changesBetween(before, after);
  assert.equal(changes.length, 1);
  assert.deepEqual(changes[0].fields, ["local", "mode"]);
});
