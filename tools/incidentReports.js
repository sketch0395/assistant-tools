// Incident report library + live incident tracking: companion to
// playbooks.js. Where playbooks.js is the reference library of *what to
// do*, this module is where a completed record of *what actually
// happened* during a real incident gets built and stored — for playbooks
// marked requires_report: true (see playbooks.js), or any time the user
// asks for a written report.
//
// Two halves, same shape as playbooks.js's draft/library split:
//   - incident_reports: the saved library of finished reports (browsable,
//     searchable, exportable — same pattern as playbooks/threatIntel).
//   - incident_report_drafts: one in-progress "live incident" per
//     conversation, built up entry by entry (steps taken, findings,
//     actions, lessons) as the incident unfolds, then compiled into a
//     single Markdown report and saved when the incident is resolved.
//
// Framework-agnostic like the other tools/*.js modules here: the host
// owns its own SQLite connection and passes it in as `db`.
const MAX_SEARCH_RESULTS = 5;
const MAX_LIST_RESULTS = 200;
const ENTRY_TYPES = ["step", "finding", "action", "lesson"];

function ensureSchema(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS incident_reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      category TEXT,
      playbook_title TEXT,
      tags TEXT,
      content TEXT NOT NULL,
      created_at REAL,
      updated_at REAL
    );
    CREATE VIRTUAL TABLE IF NOT EXISTS incident_reports_fts USING fts5(
      title, content, tags,
      content='incident_reports', content_rowid='id'
    );
    CREATE TRIGGER IF NOT EXISTS incident_reports_ai AFTER INSERT ON incident_reports BEGIN
      INSERT INTO incident_reports_fts(rowid, title, content, tags)
      VALUES (new.id, new.title, new.content, new.tags);
    END;
    CREATE TRIGGER IF NOT EXISTS incident_reports_ad AFTER DELETE ON incident_reports BEGIN
      INSERT INTO incident_reports_fts(incident_reports_fts, rowid, title, content, tags)
      VALUES ('delete', old.id, old.title, old.content, old.tags);
    END;
    CREATE TRIGGER IF NOT EXISTS incident_reports_au AFTER UPDATE ON incident_reports BEGIN
      INSERT INTO incident_reports_fts(incident_reports_fts, rowid, title, content, tags)
      VALUES ('delete', old.id, old.title, old.content, old.tags);
      INSERT INTO incident_reports_fts(rowid, title, content, tags)
      VALUES (new.id, new.title, new.content, new.tags);
    END;
    CREATE TABLE IF NOT EXISTS incident_report_drafts (
      conversation_id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      category TEXT,
      playbook_title TEXT,
      summary TEXT NOT NULL DEFAULT '',
      entries TEXT NOT NULL DEFAULT '[]',
      started_at REAL,
      updated_at REAL
    );
  `);
}

/** Adds a finished report directly (manual entry, or the result of finalizeIncidentReport). */
function addIncidentReport(db, { title, category, playbookTitle, tags, content } = {}) {
  const t = String(title || "").trim();
  const c = String(content || "").trim();
  if (!t) throw new Error("title is required");
  if (!c) throw new Error("content is required");
  const cat = String(category || "").trim();
  const pbTitle = String(playbookTitle || "").trim();
  const tagsStr = Array.isArray(tags) ? tags.join(", ") : String(tags || "").trim();
  const now = Date.now();
  const info = db
    .prepare(
      `INSERT INTO incident_reports (title, category, playbook_title, tags, content, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    )
    .run(t, cat, pbTitle, tagsStr, c, now, now);
  return {
    id: info.lastInsertRowid,
    title: t,
    category: cat,
    playbook_title: pbTitle,
    tags: tagsStr,
    content: c,
  };
}

/** Lists saved incident reports, most recent first. */
function listIncidentReports(db, category = null) {
  if (category) {
    return db
      .prepare(`SELECT * FROM incident_reports WHERE category = ? ORDER BY created_at DESC`)
      .all(category);
  }
  return db
    .prepare(`SELECT * FROM incident_reports ORDER BY created_at DESC LIMIT ?`)
    .all(MAX_LIST_RESULTS);
}

function listIncidentReportCategories(db) {
  return db
    .prepare(
      `SELECT DISTINCT category FROM incident_reports WHERE category IS NOT NULL AND category != '' ORDER BY category`
    )
    .all()
    .map((r) => r.category);
}

/** Updates a saved report. Returns the updated row, or null if not found. */
function updateIncidentReport(db, id, { title, category, playbookTitle, tags, content } = {}) {
  const existing = db.prepare(`SELECT * FROM incident_reports WHERE id = ?`).get(id);
  if (!existing) return null;
  const t = title !== undefined ? String(title || "").trim() : existing.title;
  const c = content !== undefined ? String(content || "").trim() : existing.content;
  const cat = category !== undefined ? String(category || "").trim() : existing.category;
  const pbTitle =
    playbookTitle !== undefined ? String(playbookTitle || "").trim() : existing.playbook_title;
  const tagsStr =
    tags !== undefined
      ? Array.isArray(tags)
        ? tags.join(", ")
        : String(tags || "").trim()
      : existing.tags;
  if (!t) throw new Error("title is required");
  if (!c) throw new Error("content is required");
  db.prepare(
    `UPDATE incident_reports SET title = ?, category = ?, playbook_title = ?, tags = ?, content = ?, updated_at = ? WHERE id = ?`
  ).run(t, cat, pbTitle, tagsStr, c, Date.now(), id);
  return { id, title: t, category: cat, playbook_title: pbTitle, tags: tagsStr, content: c };
}

function deleteIncidentReport(db, id) {
  const info = db.prepare(`DELETE FROM incident_reports WHERE id = ?`).run(id);
  return info.changes > 0;
}

/** Full-text search over saved incident reports — used by lookup_incident_report. */
function searchIncidentReports(db, query, limit = MAX_SEARCH_RESULTS) {
  const q = String(query || "").trim();
  if (!q) return [];
  const ftsQuery = q
    .split(/\s+/)
    .filter(Boolean)
    .map((word) => `"${word.replace(/"/g, '""')}"`)
    .join(" OR ");
  if (!ftsQuery) return [];
  try {
    return db
      .prepare(
        `SELECT r.id, r.title, r.category, r.playbook_title, r.content, r.tags, r.created_at
         FROM incident_reports_fts f
         JOIN incident_reports r ON r.id = f.rowid
         WHERE incident_reports_fts MATCH ?
         ORDER BY bm25(incident_reports_fts)
         LIMIT ?`
      )
      .all(ftsQuery, Math.min(Number(limit) || MAX_SEARCH_RESULTS, 20));
  } catch {
    const like = `%${q}%`;
    return db
      .prepare(
        `SELECT id, title, category, playbook_title, content, tags, created_at FROM incident_reports
         WHERE title LIKE ? OR content LIKE ? OR tags LIKE ?
         ORDER BY created_at DESC LIMIT ?`
      )
      .all(like, like, like, Math.min(Number(limit) || MAX_SEARCH_RESULTS, 20));
  }
}

// --- Live incident tracking ---------------------------------------------
// One in-progress "incident report draft" per conversation — entries are
// appended as the incident unfolds (steps taken, findings, actions,
// lessons learned) instead of trying to reconstruct the whole thing from
// memory at the end. Same pattern as playbook_drafts in playbooks.js.

function getIncidentReportDraft(db, conversationId) {
  if (!conversationId) return null;
  const row = db
    .prepare(`SELECT * FROM incident_report_drafts WHERE conversation_id = ?`)
    .get(conversationId);
  if (!row) return null;
  return {
    title: row.title,
    category: row.category,
    playbookTitle: row.playbook_title,
    summary: row.summary,
    entries: JSON.parse(row.entries || "[]"),
    startedAt: row.started_at,
  };
}

/** Starts (or restarts) incident tracking for this conversation. */
function startIncidentReport(
  db,
  conversationId,
  { title, category, playbookTitle, summary } = {}
) {
  if (!conversationId) throw new Error("conversationId is required");
  const t = String(title || "").trim();
  if (!t) throw new Error("title is required");
  const cat = String(category || "").trim();
  const pbTitle = String(playbookTitle || "").trim();
  const summaryStr = String(summary || "").trim();
  const now = Date.now();
  db.prepare(
    `INSERT INTO incident_report_drafts
       (conversation_id, title, category, playbook_title, summary, entries, started_at, updated_at)
     VALUES (?, ?, ?, ?, ?, '[]', ?, ?)
     ON CONFLICT(conversation_id) DO UPDATE SET
       title = excluded.title, category = excluded.category,
       playbook_title = excluded.playbook_title, summary = excluded.summary,
       entries = '[]', started_at = excluded.started_at, updated_at = excluded.updated_at`
  ).run(conversationId, t, cat, pbTitle, summaryStr, now, now);
  return {
    title: t,
    category: cat,
    playbookTitle: pbTitle,
    summary: summaryStr,
    entries: [],
    startedAt: now,
  };
}

/** Appends one entry (a step taken, a finding, an action, or a lesson learned) to the tracked incident. */
function logIncidentEntry(db, conversationId, { type, text, owner } = {}) {
  const draft = getIncidentReportDraft(db, conversationId);
  if (!draft) {
    throw new Error(
      "No incident is currently being tracked for this conversation — call start_incident_report first."
    );
  }
  const ty = ENTRY_TYPES.includes(type) ? type : null;
  if (!ty) {
    throw new Error(`type must be one of: ${ENTRY_TYPES.join(", ")}`);
  }
  const txt = String(text || "").trim();
  if (!txt) throw new Error("text is required");
  const entry = { type: ty, text: txt, at: Date.now() };
  if (owner) entry.owner = String(owner).trim();
  const entries = [...draft.entries, entry];
  db.prepare(
    `UPDATE incident_report_drafts SET entries = ?, updated_at = ? WHERE conversation_id = ?`
  ).run(JSON.stringify(entries), Date.now(), conversationId);
  return { ...draft, entries };
}

/** Abandons the in-progress incident tracking for this conversation without saving a report. */
function discardIncidentReport(db, conversationId) {
  const info = db
    .prepare(`DELETE FROM incident_report_drafts WHERE conversation_id = ?`)
    .run(conversationId);
  return info.changes > 0;
}

function formatTime(ms) {
  try {
    return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
  } catch {
    return String(ms);
  }
}

/** Renders the tracked incident (summary + entries) into the final Markdown report body. */
function renderIncidentReportContent(draft) {
  const steps = draft.entries.filter((e) => e.type === "step");
  const findings = draft.entries.filter((e) => e.type === "finding");
  const actions = draft.entries.filter((e) => e.type === "action");
  const lessons = draft.entries.filter((e) => e.type === "lesson");

  const lines = [];
  if (draft.playbookTitle) lines.push(`**Playbook followed:** ${draft.playbookTitle}`);
  if (draft.category) lines.push(`**Category:** ${draft.category}`);
  if (draft.startedAt) lines.push(`**Started:** ${formatTime(draft.startedAt)}`);
  lines.push(`**Completed:** ${formatTime(Date.now())}`);
  lines.push("");

  lines.push("## Incident Summary");
  lines.push(draft.summary || "_No summary recorded._");
  lines.push("");

  lines.push("## Timeline");
  if (draft.entries.length === 0) {
    lines.push("_No entries recorded._");
  } else {
    for (const e of draft.entries) {
      const ownerPart = e.owner ? ` (${e.owner})` : "";
      lines.push(`- [${formatTime(e.at)}] **${e.type}**${ownerPart}: ${e.text}`);
    }
  }
  lines.push("");

  lines.push("## Steps Taken");
  lines.push(
    steps.length ? steps.map((e, i) => `${i + 1}. ${e.text}`).join("\n") : "_None recorded._"
  );
  lines.push("");

  lines.push("## Findings");
  lines.push(findings.length ? findings.map((e) => `- ${e.text}`).join("\n") : "_None recorded._");
  lines.push("");

  lines.push("## Actions Taken");
  lines.push(
    actions.length
      ? actions.map((e) => `- ${e.text}${e.owner ? ` — ${e.owner}` : ""}`).join("\n")
      : "_None recorded._"
  );
  lines.push("");

  lines.push("## Lessons Learned");
  lines.push(lessons.length ? lessons.map((e) => `- ${e.text}`).join("\n") : "_None recorded._");
  lines.push("");

  return lines.join("\n").trim();
}

/**
 * Completes the tracked incident for this conversation, compiles it into a
 * full Markdown report, saves it to the incident_reports library, and
 * clears the draft. Returns the saved report row.
 */
function finalizeIncidentReport(db, conversationId, { tags } = {}) {
  const draft = getIncidentReportDraft(db, conversationId);
  if (!draft) {
    throw new Error(
      "No incident is currently being tracked for this conversation — call start_incident_report first."
    );
  }
  const content = renderIncidentReportContent(draft);
  const entry = addIncidentReport(db, {
    title: draft.title,
    category: draft.category,
    playbookTitle: draft.playbookTitle,
    tags,
    content,
  });
  discardIncidentReport(db, conversationId);
  return entry;
}

// --- Markdown import/export ----------------------------------------------
// Same shape as playbooks.js's export helpers, so the Incident Reports
// page can reuse the same download-as-.md-or-.zip UI pattern.

function escapeFrontmatterValue(v) {
  const s = String(v ?? "");
  if (/[:#\n]/.test(s) || s !== s.trim()) {
    return `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
  }
  return s;
}

function reportToMarkdown(entry) {
  const lines = [
    "---",
    `title: ${escapeFrontmatterValue(entry.title)}`,
    `category: ${escapeFrontmatterValue(entry.category || "")}`,
    `playbook_title: ${escapeFrontmatterValue(entry.playbook_title || "")}`,
    `tags: ${escapeFrontmatterValue(entry.tags || "")}`,
    "---",
    "",
    `# ${entry.title}`,
    "",
    String(entry.content || "").trim(),
    "",
  ];
  return lines.join("\n");
}

function reportFilename(entry) {
  const slug = (s) =>
    String(s || "")
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "") || "untitled";
  const datePart = entry.created_at
    ? new Date(entry.created_at).toISOString().slice(0, 10)
    : "";
  return `${datePart ? `${datePart}__` : ""}${slug(entry.title)}.md`;
}

function unescapeFrontmatterValue(v) {
  const s = String(v ?? "").trim();
  if (s.startsWith('"') && s.endsWith('"')) {
    return s.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, "\\");
  }
  return s;
}

/**
 * Parses a Markdown file back into { title, category, playbookTitle, tags,
 * content }, for restoring/importing a previously exported report (or any
 * .md file with a similar frontmatter shape). Falls back to `fallbackTitle`
 * (e.g. derived from the uploaded filename) if there's no frontmatter.
 */
function parseReportMarkdown(text, fallbackTitle = "Untitled Report") {
  const raw = String(text || "").replace(/\r\n/g, "\n");
  let body = raw;
  const meta = {};
  const fmMatch = raw.match(/^---\n([\s\S]*?)\n---\n?/);
  if (fmMatch) {
    body = raw.slice(fmMatch[0].length);
    for (const line of fmMatch[1].split("\n")) {
      const m = line.match(/^([A-Za-z_][\w-]*)\s*:\s*(.*)$/);
      if (m) meta[m[1].toLowerCase()] = unescapeFrontmatterValue(m[2]);
    }
  }
  body = body.replace(/^\s*#\s+.+\n+/, "");
  const title = String(meta.title || fallbackTitle || "Untitled Report").trim();
  const category = String(meta.category || "").trim();
  const playbookTitle = String(meta.playbook_title || "").trim();
  const tags = String(meta.tags || "").trim();
  const content = body.trim();
  return { title, category, playbookTitle, tags, content };
}

const toolDefinitions = {
  start_incident_report: {
    name: "start_incident_report",
    description:
      "Begin tracking a real, currently-active security incident for " +
      "reporting purposes. Call this right after lookup_playbook returns " +
      "a matching playbook with requires_report: true — do this " +
      "proactively, don't wait to be asked. Can also be used any time " +
      "the user asks you to track/document/report on an incident, even " +
      "without a matching playbook. Starts (or restarts, discarding any " +
      "unfinished tracking) fresh tracking for THIS conversation. After " +
      "this, call log_incident_entry as things happen during the " +
      "incident, then finish_incident_report once it's resolved.",
    parameters: {
      type: "object",
      properties: {
        title: {
          type: "string",
          description:
            "Short descriptive title for this specific incident, e.g. " +
            "'Ransomware — Finance Workstation FIN-042'.",
        },
        category: {
          type: "string",
          description: "Incident type, e.g. 'ransomware', 'phishing', 'account_compromise'.",
        },
        playbook_title: {
          type: "string",
          description: "Title of the playbook being followed for this incident, if any.",
        },
        summary: {
          type: "string",
          description: "Brief initial description of what's happening / how it was detected.",
        },
      },
      required: ["title"],
    },
  },
  log_incident_entry: {
    name: "log_incident_entry",
    description:
      "Record one thing that happened during the incident currently " +
      "being tracked for this conversation (started with " +
      "start_incident_report). Call this as things happen, one entry at " +
      "a time — don't wait and try to reconstruct everything at the end. " +
      "Use it for each playbook step actually carried out, each finding/ " +
      "piece of evidence uncovered, each containment/remediation action " +
      "taken, and any lessons learned noted along the way.",
    parameters: {
      type: "object",
      properties: {
        type: {
          type: "string",
          enum: ENTRY_TYPES,
          description:
            "'step' = a playbook step that was carried out, 'finding' = " +
            "evidence/observation (e.g. an IOC, a log entry), 'action' = " +
            "a containment/remediation action taken, 'lesson' = a lesson " +
            "learned or follow-up item.",
        },
        text: {
          type: "string",
          description: "One clear, self-contained sentence describing this entry.",
        },
        owner: {
          type: "string",
          description: "Optional — who did this (mainly useful for 'action' entries).",
        },
      },
      required: ["type", "text"],
    },
  },
  view_incident_report_draft: {
    name: "view_incident_report_draft",
    description:
      "Show everything recorded so far for the incident currently being " +
      "tracked in this conversation (summary and all logged entries). " +
      "Use this if the user asks to review/recap progress before " +
      "continuing or finishing.",
    parameters: { type: "object", properties: {} },
  },
  finish_incident_report: {
    name: "finish_incident_report",
    description:
      "Complete the incident currently being tracked for this " +
      "conversation, compile everything recorded into a full incident " +
      "report (summary, timeline, steps taken, findings, actions taken, " +
      "lessons learned), and save it to the incident report library. " +
      "Call this proactively once the incident is resolved / all " +
      "playbook steps are done — don't wait to be asked if the playbook " +
      "required a report. The tracking is cleared after this succeeds.",
    parameters: {
      type: "object",
      properties: {
        tags: {
          type: "string",
          description: "Optional comma-separated keywords to help future search.",
        },
      },
    },
  },
  discard_incident_report: {
    name: "discard_incident_report",
    description:
      "Abandon incident tracking for this conversation without saving a " +
      "report — use this only if the user explicitly says the incident " +
      "tracking should be scrapped (e.g. it was a false alarm).",
    parameters: { type: "object", properties: {} },
  },
  lookup_incident_report: {
    name: "lookup_incident_report",
    description:
      "Search past saved incident reports — useful for checking how a " +
      "similar past incident was handled, what the root cause and " +
      "remediation were, or pulling up history when the user asks 'have " +
      "we seen this before' / 'what happened last time'.",
    parameters: {
      type: "object",
      properties: {
        query: {
          type: "string",
          description: "Keyword(s) describing the incident to search past reports for.",
        },
        limit: {
          type: "number",
          description: "Max reports to return (default 5).",
        },
      },
      required: ["query"],
    },
  },
};

// start_incident_report/log_incident_entry/view/discard only touch an
// unpersisted per-conversation draft — safe to run without confirmation,
// same reasoning as the playbook draft tools. finish_incident_report
// writes a real, permanent report, so it goes through the normal
// confirm/deny flow.
const CONFIRM_REQUIRED_TOOLS = ["finish_incident_report"];

function describeToolCall(name, args) {
  switch (name) {
    case "start_incident_report":
      return `start tracking an incident report: "${args.title}"`;
    case "log_incident_entry":
      return `log an incident ${args.type}`;
    case "view_incident_report_draft":
      return `review the incident report tracked so far`;
    case "finish_incident_report":
      return `complete and save the incident report`;
    case "discard_incident_report":
      return `discard the in-progress incident tracking`;
    case "lookup_incident_report":
      return `look up past incident reports for "${args.query}"`;
    default:
      return undefined;
  }
}

module.exports = {
  ensureSchema,
  addIncidentReport,
  listIncidentReports,
  listIncidentReportCategories,
  updateIncidentReport,
  deleteIncidentReport,
  searchIncidentReports,
  getIncidentReportDraft,
  startIncidentReport,
  logIncidentEntry,
  discardIncidentReport,
  finalizeIncidentReport,
  reportToMarkdown,
  reportFilename,
  parseReportMarkdown,
  toolDefinitions,
  CONFIRM_REQUIRED_TOOLS,
  describeToolCall,
};
