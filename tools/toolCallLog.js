// Shared tool-call diagnostic log: records every tool invocation (success
// or failure) with enough detail for the assistant — or the user, via chat
// — to answer "what went wrong and why" after the fact, instead of that
// detail evaporating the moment a single chat turn ends. Framework-agnostic
// like cyberNews.js/threatIntel.js — the host owns its own SQLite
// connection (via better-sqlite3) and passes it in as `db` to every
// function here, including `ensureSchema(db)` which the host calls once
// from its own db.js.
//
// This is what actually makes "self-diagnose why tool calls fail" possible:
// without a persistent record, an error only ever lives in the ephemeral
// tool-result message for that one turn — paraphrased or dropped entirely
// by the model's reply, and unrecoverable afterward. Every call is logged
// centrally at the single executeTool() choke point (see each host's
// lib/tools/registry.js), so nothing needs to opt in individually.

const MAX_ARGS_LEN = 500; // truncate large args (e.g. long pcap paths/queries) before storing
const MAX_ERROR_LEN = 1000;
const DEFAULT_LIMIT = 20;

/** Creates the tool_call_log table (+ indexes) if not already present. */
function ensureSchema(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS tool_call_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      args TEXT,
      success INTEGER NOT NULL,
      error TEXT,
      duration_ms INTEGER,
      conversation_id TEXT,
      created_at REAL NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_tool_call_log_created_at ON tool_call_log (created_at);
    CREATE INDEX IF NOT EXISTS idx_tool_call_log_name ON tool_call_log (name);
  `);
}

function truncate(str, max) {
  if (!str) return str;
  return str.length > max ? `${str.slice(0, max)}…` : str;
}

function safeStringifyArgs(args) {
  try {
    return truncate(JSON.stringify(args), MAX_ARGS_LEN);
  } catch {
    return null;
  }
}

function safeParseArgs(str) {
  if (!str) return null;
  try {
    return JSON.parse(str);
  } catch {
    return str; // was truncated mid-JSON — return as raw text rather than losing it
  }
}

function formatRow(row) {
  return {
    id: row.id,
    name: row.name,
    args: safeParseArgs(row.args),
    success: Boolean(row.success),
    error: row.error || null,
    duration_ms: row.duration_ms,
    conversation_id: row.conversation_id,
    at: new Date(row.created_at).toISOString(),
  };
}

/**
 * Records one tool invocation's outcome. Never throws — a logging hiccup
 * (e.g. a disk-full SQLite error) must never take down the actual tool
 * call it's trying to record.
 */
function logToolCall(db, { name, args, success, error, durationMs, conversationId }) {
  try {
    db.prepare(
      `INSERT INTO tool_call_log (name, args, success, error, duration_ms, conversation_id, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).run(
      name,
      safeStringifyArgs(args),
      success ? 1 : 0,
      error ? truncate(String(error), MAX_ERROR_LEN) : null,
      durationMs != null ? Math.round(durationMs) : null,
      conversationId || null,
      Date.now()
    );
  } catch (err) {
    console.error("[tool-call-log] failed to record entry:", err.message);
  }
}

function buildWhere({ toolName, sinceMs, onlyFailures }) {
  const clauses = [];
  const params = [];
  if (onlyFailures) clauses.push("success = 0");
  if (toolName) {
    clauses.push("name = ?");
    params.push(toolName);
  }
  if (sinceMs) {
    clauses.push("created_at >= ?");
    params.push(sinceMs);
  }
  return { where: clauses.length ? clauses.join(" AND ") : "1=1", params };
}

/** Recent tool calls, most recent first. Pass onlyFailures:true to only see failures. */
function getRecentCalls(db, { limit, toolName, sinceMs, onlyFailures } = {}) {
  const { where, params } = buildWhere({ toolName, sinceMs, onlyFailures });
  const rows = db
    .prepare(
      `SELECT id, name, args, success, error, duration_ms, conversation_id, created_at
       FROM tool_call_log WHERE ${where}
       ORDER BY id DESC LIMIT ?`
    )
    .all(...params, limit || DEFAULT_LIMIT);
  return rows.map(formatRow);
}

/** Per-tool call/failure counts over a time window — surfaces what's actually been breaking. */
function getFailureSummary(db, { sinceMs } = {}) {
  const params = [];
  let where = "1=1";
  if (sinceMs) {
    where += " AND created_at >= ?";
    params.push(sinceMs);
  }
  return db
    .prepare(
      `SELECT name,
              COUNT(*) AS total,
              SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) AS failures
       FROM tool_call_log WHERE ${where}
       GROUP BY name
       HAVING failures > 0
       ORDER BY failures DESC`
    )
    .all(...params);
}

const toolDefinitions = {
  diagnose_tool_calls: {
    name: "diagnose_tool_calls",
    description:
      "Look at the actual recorded history of recent tool calls — real " +
      "successes and failures, with real error messages and timing — to " +
      "self-diagnose what went wrong and why, instead of guessing. Use this " +
      "whenever the user asks why a tool call failed, why something " +
      "'didn't work', or asks you to check your own reliability/logs. " +
      "Always quote the actual recorded error text back to the user rather " +
      "than paraphrasing it away, and if the same tool keeps failing with " +
      "the same error, say so explicitly instead of listing each one flatly.",
    parameters: {
      type: "object",
      properties: {
        tool_name: {
          type: "string",
          description:
            "Optional: only look at calls to this specific tool (e.g. 'port_scan').",
        },
        only_failures: {
          type: "boolean",
          description:
            "If true (default), only return failed calls. Set false to also " +
            "see recent successes for context/comparison.",
        },
        hours: {
          type: "number",
          description: "How far back to look, in hours. Default 24.",
        },
        limit: {
          type: "number",
          description: "Max entries to return. Default 20.",
        },
      },
      required: [],
    },
  },
};

function describeToolCall(name, args) {
  if (name === "diagnose_tool_calls") {
    return args.tool_name
      ? `check recent tool-call history for "${args.tool_name}"`
      : "check recent tool-call history to self-diagnose failures";
  }
  return null;
}

module.exports = {
  ensureSchema,
  logToolCall,
  getRecentCalls,
  getFailureSummary,
  toolDefinitions,
  describeToolCall,
};
