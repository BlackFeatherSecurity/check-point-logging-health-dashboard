import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

const MAX_SNAPSHOTS = 100;

function compactRow(row) {
  return {
    domain: row.domain || "",
    name: row.name,
    type: row.type,
    local: Boolean(row.local),
    primary: row.primary || "",
    secondary: [...(row.secondary || [])],
    backup: [...(row.backup || [])],
    destination: row.runtime?.destination || "",
    runtimeState: row.runtime?.state || "unknown",
    mode: row.mode || "not configured"
  };
}

function rowKey(row) {
  return `${row.domain || ""}\u0000${row.name}`;
}

function changesBetween(previous = [], current = []) {
  const oldRows = new Map(previous.map((row) => [rowKey(row), row]));
  const newRows = new Map(current.map((row) => [rowKey(row), row]));
  const changes = [];
  for (const [key, row] of newRows) {
    const old = oldRows.get(key);
    const firewall = row.domain ? `${row.domain} / ${row.name}` : row.name;
    if (!old) {
      changes.push({ firewall, kind: "added", fields: ["firewall discovered"] });
      continue;
    }
    const fields = [];
    for (const key of ["local", "primary", "secondary", "backup", "destination", "runtimeState", "mode"]) {
      if (JSON.stringify(old[key]) !== JSON.stringify(row[key])) fields.push(key);
    }
    if (fields.length) changes.push({ firewall, kind: "changed", fields });
  }
  for (const [key, row] of oldRows) {
    if (!newRows.has(key)) changes.push({ firewall: row.domain ? `${row.domain} / ${row.name}` : row.name, kind: "removed", fields: ["firewall no longer returned"] });
  }
  return changes;
}

export class HistoryStore {
  constructor({ directory = process.env.HISTORY_DIR || "/tmp/check-point-log-status", filename = "scan-history.json" } = {}) {
    this.path = join(directory, filename);
    this.ready = null;
  }

  async load() {
    if (!this.ready) {
      this.ready = (async () => {
        await mkdir(dirname(this.path), { recursive: true });
        try {
          const parsed = JSON.parse(await readFile(this.path, "utf8"));
          return Array.isArray(parsed.snapshots) ? parsed : { snapshots: [] };
        } catch (error) {
          if (error.code === "ENOENT") return { snapshots: [] };
          throw new Error("Could not read saved scan history.");
        }
      })();
    }
    return this.ready;
  }

  async record(result) {
    const history = await this.load();
    const rows = result.firewalls.map(compactRow);
    const previous = history.snapshots.at(-1);
    const changes = previous ? changesBetween(previous.firewalls, rows) : [];
    const snapshot = { checkedAt: result.checkedAt, firewalls: rows };
    history.snapshots = [...history.snapshots, snapshot].slice(-MAX_SNAPSHOTS);
    const temporary = `${this.path}.${process.pid}.tmp`;
    await writeFile(temporary, JSON.stringify(history), { mode: 0o600 });
    await rename(temporary, this.path);
    return {
      baseline: !previous,
      previousCheckedAt: previous?.checkedAt || "",
      changes,
      retainedScans: history.snapshots.length
    };
  }
}

export const historyInternals = { compactRow, changesBetween };
