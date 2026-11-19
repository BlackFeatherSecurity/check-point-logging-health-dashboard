import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash, randomUUID } from "node:crypto";
import { SessionManager } from "./session-manager.js";
import { collectAllDomainLoggingStatus, collectLoggingStatus } from "./workflows/logging-status.js";
import { HistoryStore } from "./history-store.js";
import { ScanScheduler } from "./scan-scheduler.js";

const HOST = process.env.HOST || "127.0.0.1";
const PORT = Number(process.env.PORT || 3000);
const PUBLIC_DIR = fileURLToPath(new URL("../public/", import.meta.url));
const sessions = new SessionManager({
  runScriptConcurrency: Number(process.env.RUN_SCRIPT_CONCURRENCY || 8),
  largeEnvironmentRunScriptConcurrency: Number(process.env.LARGE_ENV_RUN_SCRIPT_CONCURRENCY || 3),
  largeEnvironmentApiConcurrency: Number(process.env.LARGE_ENV_API_CONCURRENCY || 10),
  taskPollAttempts: Number(process.env.TASK_POLL_ATTEMPTS || 20),
  taskPollIntervalMs: Number(process.env.TASK_POLL_INTERVAL_MS || 1000),
  largeEnvironmentTaskPollIntervalMs: Number(process.env.LARGE_ENV_TASK_POLL_INTERVAL_MS || 1250),
  logger: process.env.CP_API_LOGGING
    ? (entry) => console.log(JSON.stringify({ time: new Date().toISOString(), ...entry }))
    : null
});
const history = new HistoryStore();

const activeScans = new Set();
const validatedScans = new Set();

async function withScanLock(id, run) {
  if (activeScans.has(id)) throw new Error("A scan is already in progress for this session.");
  activeScans.add(id);
  try {
    return await run();
  } finally {
    activeScans.delete(id);
  }
}

async function scanEnvironment(id, options = {}, owner = id) {
  const scope = sessions.describe(id);
  const includeRuntime = options.includeRuntime !== false;
  const includeInfrastructure = true;
  const context = options.context || "primary";
  const scanOptions = {
    sessions, sessionId: id, includeRuntime, includeInfrastructure, freshnessHorizon: options.freshnessHorizon
  };
  const result = scope.allDomains
    ? await collectAllDomainLoggingStatus(scanOptions)
    : await collectLoggingStatus({ ...scanOptions, context, managementDomain: scope.domain });
  const ownerScope = sessions.describe(owner);
  if (owner === id && includeRuntime && !result.domainFailures?.length) {
    validatedScans.add(id);
  }
  const historyScope = createHash("sha256").update(JSON.stringify([
    scope.baseUrl, scope.user === "API Key" ? ownerScope.sessionId : scope.user,
    scope.domain, scope.allDomains ? "all-domains" : context, includeRuntime
  ])).digest("hex");
  try {
    result.history = await history.record(result, historyScope);
  } catch {
    result.history = { unavailable: true, changes: [] };
  }
  return result;
}

const scheduler = new ScanScheduler({
  enabled: process.env.ENABLE_SCHEDULED_SCANS === "true",
  scan: (owner, horizon) => withScanLock(owner, async () => {
    const temporary = await sessions.openScanSession(owner);
    try {
      return await scanEnvironment(temporary.sessionId, { freshnessHorizon: horizon }, owner);
    } finally {
      await sessions.logout(temporary.sessionId);
    }
  })
});

const contentTypes = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8"
};

function sendJson(res, statusCode, value) {
  const body = JSON.stringify(value, null, 2);
  res.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store"
  });
  res.end(body);
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 2_000_000) {
        reject(new Error("Request body is too large."));
        req.destroy();
      }
    });
    req.on("end", () => {
      try { resolve(body ? JSON.parse(body) : {}); }
      catch { reject(new Error("Request body must be valid JSON.")); }
    });
    req.on("error", reject);
  });
}

async function handleApi(req, res) {
  const requestId = randomUUID().slice(0, 8);
  try {
    if (req.url === "/api/health" && req.method === "GET") {
      sendJson(res, 200, { ok: true, requestId, serverTime: new Date().toISOString() });
      return;
    }
    if (req.method !== "POST") {
      sendJson(res, 405, { error: "Method not allowed.", requestId });
      return;
    }
    const body = await readJson(req);
    let result;
    switch (req.url) {
      case "/api/login":
        result = await sessions.login(body);
        break;
      case "/api/session":
        result = sessions.describe(body.sessionId);
        break;
      case "/api/logging-status":
        result = await withScanLock(body.sessionId, () => scanEnvironment(body.sessionId, body));
        break;
      case "/api/schedules/status":
        sessions.describe(body.sessionId);
        result = scheduler.status(body.sessionId);
        break;
      case "/api/schedules/start":
        sessions.describe(body.sessionId);
        if (!validatedScans.has(body.sessionId)) throw new Error("Complete a live scan before starting a schedule.");
        result = scheduler.start(body.sessionId, body.interval, body.horizon);
        break;
      case "/api/schedules/stop":
        sessions.describe(body.sessionId);
        result = scheduler.stop(body.sessionId);
        break;
      case "/api/logout":
        scheduler.stop(body.sessionId);
        validatedScans.delete(body.sessionId);
        result = await sessions.logout(body.sessionId);
        break;
      default:
        sendJson(res, 404, { error: "API route not found.", requestId });
        return;
    }
    sendJson(res, 200, { requestId, ...result });
  } catch (error) {
    sendJson(res, error.statusCode === 401 || error.statusCode === 403 ? 401 : 400, {
      requestId,
      error: error.message,
      command: error.command,
      phase: error.phase,
      statusCode: error.statusCode,
      response: error.response
    });
  }
}

async function serveStatic(req, res) {
  const pathname = new URL(req.url, "http://localhost").pathname;
  const relative = pathname === "/" ? "index.html" : pathname.slice(1);
  const path = normalize(join(PUBLIC_DIR, relative));
  if (!path.startsWith(PUBLIC_DIR)) {
    res.writeHead(403).end("Forbidden");
    return;
  }
  try {
    const file = await readFile(path);
    res.writeHead(200, {
      "content-type": contentTypes[extname(path)] || "application/octet-stream",
      "cache-control": "no-cache"
    });
    res.end(file);
  } catch {
    res.writeHead(404).end("Not found");
  }
}

export const server = createServer((req, res) => {
  if (req.url.startsWith("/api/")) void handleApi(req, res);
  else void serveStatic(req, res);
});

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  server.listen(PORT, HOST, () => {
    console.log(`Check Point Logging Health Dashboard listening at http://${HOST}:${PORT}`);
  });
}
