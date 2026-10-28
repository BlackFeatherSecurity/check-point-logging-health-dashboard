import { randomUUID } from "node:crypto";
import { CheckPointClient, normalizeBaseUrl } from "./check-point-client.js";

const CONTEXTS = new Set(["primary", "mds", "global", "system-data"]);

function enabled(value) {
  return value === true || value === "true" || value === "on";
}

function activeDomain(domain = {}) {
  if (domain.active === false) return false;
  if (domain.active === true) return true;
  const servers = Array.isArray(domain.servers) ? domain.servers : [];
  return !servers.length || servers.some((server) => (
    server?.active === true || /active/i.test(String(server?.status || server?.state || server?.role || ""))
  ));
}

function loginBody(payload, domain) {
  const authMode = payload.authMode === "api-key" ? "api-key" : "password";
  const body = {};
  if (authMode === "api-key") {
    if (!payload.apiKey) throw new Error("API key is required.");
    body["api-key"] = String(payload.apiKey);
  } else {
    if (!payload.username) throw new Error("Username is required.");
    if (!payload.password) throw new Error("Password is required.");
    body.user = String(payload.username);
    body.password = String(payload.password);
  }
  if (domain) body.domain = String(domain);
  return body;
}

function taskIds(result) {
  return [...new Set((result?.tasks || [])
    .map((task) => task?.["task-id"] || task?.taskId || task?.uid)
    .filter(Boolean))];
}

function decodeResponseMessage(value) {
  if (!value) return "";
  try { return Buffer.from(String(value), "base64").toString("utf8").trim(); } catch { return ""; }
}

function taskSummary(result) {
  return (result?.tasks || []).map((task) => {
    const details = task?.["task-details"] || task?.taskDetails || [];
    const executions = details.map((detail) => ({
      target: detail?.gatewayName || detail?.["gateway-name"] || "",
      status: detail?.status || detail?.statusCode || detail?.["status-code"] || "",
      message: String(detail?.statusDescription || detail?.["status-description"] || ""),
      output: decodeResponseMessage(detail?.responseMessage || detail?.["response-message"]),
      error: String(detail?.responseError || detail?.["response-error"] || "")
    }));
    const output = executions
      .map((execution) => execution.output)
      .filter(Boolean)
      .join("\n");
    return {
      id: task?.["task-id"] || task?.taskId || task?.uid || "",
      name: task?.["task-name"] || task?.taskName || task?.name || "run-script",
      status: task?.status || "unknown",
      progress: task?.["progress-percentage"] ?? task?.progressPercentage ?? null,
      startedAt: task?.["start-time"] || task?.startTime || "",
      lastUpdatedAt: task?.["last-update-time"] || task?.lastUpdateTime || "",
      targets: executions.map((execution) => execution.target).filter(Boolean),
      output,
      statusDescription: executions
        .map((execution) => execution.message)
        .filter(Boolean)
        .join("\n"),
      errors: executions
        .map((execution) => execution.error)
        .filter(Boolean),
      executions
    };
  });
}

function taskOutput(result) {
  const tasks = taskSummary(result);
  const messages = tasks.map((task) => task.output).filter(Boolean);
  if (messages.length) return messages.join("\n");
  return tasks.map((task) => task.statusDescription).filter(Boolean).join("\n");
}

function scriptResult(result) {
  return { result, output: taskOutput(result), taskSummary: taskSummary(result) };
}

function createLimiter(limit) {
  let active = 0;
  const queue = [];
  const next = () => {
    if (active >= limit || queue.length === 0) return;
    const { work, resolve, reject } = queue.shift();
    active += 1;
    Promise.resolve().then(work).then(resolve, reject).finally(() => {
      active -= 1;
      next();
    });
  };
  return (work) => new Promise((resolve, reject) => {
    queue.push({ work, resolve, reject });
    next();
  });
}

export class SessionManager {
  constructor({
    logger = null,
    runScriptConcurrency = 8,
    largeEnvironmentRunScriptConcurrency = 3,
    largeEnvironmentApiConcurrency = 10,
    taskPollAttempts = 20,
    taskPollIntervalMs = 1000,
    largeEnvironmentTaskPollIntervalMs = 1250,
    clientFactory = (options) => new CheckPointClient(options)
  } = {}) {
    this.sessions = new Map();
    this.logger = logger;
    this.taskPollAttempts = taskPollAttempts;
    this.taskPollIntervalMs = taskPollIntervalMs;
    this.largeEnvironmentTaskPollIntervalMs = largeEnvironmentTaskPollIntervalMs;
    this.clientFactory = clientFactory;
    this.runQueued = createLimiter(runScriptConcurrency);
    this.largeEnvironmentRunQueued = createLimiter(largeEnvironmentRunScriptConcurrency);
    this.largeEnvironmentApiQueued = createLimiter(largeEnvironmentApiConcurrency);
  }

  async login(payload) {
    const smart1Cloud = enabled(payload.smart1Cloud);
    const allDomains = enabled(payload.allDomains);
    const mdsMode = allDomains || enabled(payload.mdsMode) || enabled(payload.mdsScan);
    const largeEnvironmentMode = enabled(payload.largeEnvironmentMode);
    if (allDomains && smart1Cloud) throw new Error("All-domain scanning requires a Multi-Domain Server, not Smart-1 Cloud.");
    if (allDomains && payload.domain) throw new Error("Do not select a single domain when scanning all MDS domains.");
    const baseUrl = normalizeBaseUrl(payload.host, payload.port, { smart1Cloud });
    const baseClient = this.clientFactory({
      baseUrl,
      smart1Cloud,
      rejectUnauthorized: payload.ignoreTls === undefined ? false : !enabled(payload.ignoreTls),
      logger: this.logger
    });
    const primaryLogin = await baseClient.command("login", loginBody(payload, payload.domain));
    if (!primaryLogin.sid) throw new Error(primaryLogin.message || "Login did not return a session ID.");

    const sids = { primary: primaryLogin.sid, mds: "", global: "", "system-data": "" };
    const contextErrors = {};
    const optionalLogin = async (context, domain) => {
      try {
        const result = await baseClient.command("login", loginBody(payload, domain));
        if (!result.sid) throw new Error(`${domain} login did not return a session ID.`);
        sids[context] = result.sid;
      } catch (error) {
        contextErrors[context] = error.message;
      }
    };

    if (mdsMode) {
      if (payload.domain) await optionalLogin("mds", "");
      else sids.mds = primaryLogin.sid;
      await optionalLogin("global", "Global");
    }
    await optionalLogin("system-data", "System Data");

    const id = randomUUID();
    const session = {
      id,
      baseClient,
      sids,
      contextErrors,
      smart1Cloud,
      mdsMode,
      allDomains,
      largeEnvironmentMode,
      domain: String(payload.domain || ""),
      managementObjectName: String(payload.managementObjectName || ""),
      auth: {
        authMode: payload.authMode === "api-key" ? "api-key" : "password",
        username: String(payload.username || ""),
        password: String(payload.password || ""),
        apiKey: String(payload.apiKey || "")
      },
      domains: [],
      user: payload.authMode === "api-key" ? "API Key" : String(payload.username),
      createdAt: new Date().toISOString()
    };
    this.sessions.set(id, session);
    if (allDomains) {
      session.domains = await this.discoverDomains(id);
      if (!session.domains.length) {
        await this.logout(id);
        throw new Error("No active MDS domains were available to this administrator.");
      }
    }
    return this.describe(session);
  }

  async discoverDomains(id) {
    const session = this.get(id);
    if (!session.mdsMode) throw new Error("Domain discovery requires an MDS session.");
    const domains = await this.list(id, "show-domains", {}, "mds");
    return domains
      .filter((domain) => domain?.name && activeDomain(domain))
      .map((domain) => ({ name: String(domain.name), uid: String(domain.uid || "") }))
      .sort((left, right) => left.name.localeCompare(right.name));
  }

  async openDomainSession(id, domain) {
    const root = this.get(id);
    if (!root.allDomains) throw new Error("A separate domain session is only available during an all-domain MDS scan.");
    const domainName = String(domain || "").trim();
    if (!domainName) throw new Error("A domain name is required.");
    const result = await root.baseClient.command("login", loginBody(root.auth, domainName));
    if (!result.sid) throw new Error(`${domainName} login did not return a session ID.`);
    const childId = randomUUID();
    this.sessions.set(childId, {
      ...root,
      id: childId,
      allDomains: false,
      domain: domainName,
      sids: { primary: result.sid, mds: "", global: "", "system-data": "" },
      contextErrors: {},
      capabilities: {}
    });
    return childId;
  }

  get(id) {
    const session = this.sessions.get(id);
    if (!session) throw new Error("Session not found. Log in again.");
    return session;
  }

  async capabilities(id, context = "primary") {
    const session = this.get(id);
    session.capabilities ||= {};
    if (session.capabilities[context]) return session.capabilities[context];
    try {
      const result = await this.command(id, "show-api-versions", {}, context);
      const normalize = (value) => {
        const version = `v${String(value).replace(/^v/, "")}`;
        return /^v\d+(?:\.\d+){0,2}$/.test(version) ? version : "";
      };
      const supported = (Array.isArray(result["supported-versions"]) ? result["supported-versions"] : []).map(normalize).filter(Boolean);
      if (!supported.length) throw new Error("Server did not advertise supported API versions.");
      return session.capabilities[context] = { supported, current: normalize(result["current-version"]), error: "" };
    } catch (error) { return { supported: [], current: "", error: error.message }; }
  }

  async validateVersion(id, context, version) {
    if (!version) return;
    const capability = await this.capabilities(id, context);
    if (!capability.supported.includes(version)) throw new Error(`API ${version} is not verified as supported in this context.`);
  }

  client(id, context = "primary") {
    if (!CONTEXTS.has(context)) throw new Error(`Unknown session context: ${context}.`);
    const session = this.get(id);
    const sid = session.sids[context];
    if (!sid) throw new Error(session.contextErrors[context] || `${context} session is not available.`);
    return session.baseClient.withSid(sid);
  }

  describe(sessionOrId) {
    const session = typeof sessionOrId === "string" ? this.get(sessionOrId) : sessionOrId;
    return {
      sessionId: session.id,
      user: session.user,
      baseUrl: session.baseClient.baseUrl,
      smart1Cloud: session.smart1Cloud,
      mdsMode: session.mdsMode,
      allDomains: session.allDomains,
      largeEnvironmentMode: session.largeEnvironmentMode,
      domain: session.domain,
      domains: session.domains.map((domain) => ({ name: domain.name, uid: domain.uid })),
      managementObjectName: session.managementObjectName,
      contexts: Object.fromEntries(Object.entries(session.sids).map(([name, sid]) => [name, {
        available: Boolean(sid),
        error: session.contextErrors[name] || ""
      }]))
    };
  }

  command(id, command, body = {}, context = "primary", apiVersion = "") {
    if (!command || !/^[a-z0-9][a-z0-9-]*$/i.test(command)) throw new Error("A valid API command is required.");
    const session = this.get(id);
    const work = () => this.client(id, context).command(command, body, apiVersion);
    const dispatch = () => session.largeEnvironmentMode ? this.largeEnvironmentApiQueued(work) : work();
    return apiVersion ? this.validateVersion(id, context, apiVersion).then(dispatch) : dispatch();
  }

  list(id, command, body = {}, context = "primary") {
    const session = this.get(id);
    const work = () => this.client(id, context).list(command, body);
    return session.largeEnvironmentMode ? this.largeEnvironmentApiQueued(work) : work();
  }

  runScript(id, body, context = "primary", apiVersion = "") {
    const session = this.get(id);
    const queue = session.largeEnvironmentMode ? this.largeEnvironmentRunQueued : this.runQueued;
    return queue(async () => {
      await this.validateVersion(id, context, apiVersion);
      const client = this.client(id, context);
      const initial = await client.command("run-script", body, apiVersion);
      if (taskOutput(initial)) return scriptResult(initial);
      const ids = taskIds(initial);
      if (ids.length === 0) return scriptResult(initial);

      let lastResult = initial;
      for (let attempt = 0; attempt < this.taskPollAttempts; attempt += 1) {
        const results = await Promise.all(ids.map((taskId) => client.command("show-task", {
          "task-id": taskId,
          "details-level": "full"
        }, apiVersion)));
        lastResult = results[0] || lastResult;
        const completed = results.find((result) => taskOutput(result));
        if (completed) return scriptResult(completed);
        if (attempt < this.taskPollAttempts - 1) {
          const interval = session.largeEnvironmentMode
            ? this.largeEnvironmentTaskPollIntervalMs
            : this.taskPollIntervalMs;
          await new Promise((resolve) => setTimeout(resolve, interval));
        }
      }
      return scriptResult(lastResult);
    });
  }

  async logout(id) {
    const session = this.get(id);
    const uniqueSids = [...new Set(Object.values(session.sids).filter(Boolean))];
    const results = await Promise.allSettled(uniqueSids.map((sid) => session.baseClient.withSid(sid).command("logout")));
    this.sessions.delete(id);
    return { ok: true, closedContexts: uniqueSids.length, failures: results.filter((item) => item.status === "rejected").length };
  }
}
