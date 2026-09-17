// Shared cyber incident response playbook library: curated, growing
// runbooks an assistant can follow when a real security incident is
// called out — "we have a phishing email", "ransomware just hit a
// machine", "we think we've been breached" — instead of improvising from
// general knowledge alone. Same shape/pattern as threatIntel.js (a
// reference library), but playbooks are meant to be *followed step by
// step* during an active incident rather than just cited.
//
// Framework-agnostic like notes.js/threatIntel.js: the host owns its own
// SQLite connection (via better-sqlite3) and passes it in as `db` to every
// function here, including `ensureSchema(db)` which the host calls once
// from its own db.js alongside its other CREATE TABLE statements.
//
// Full-text search (SQLite FTS5) over title/content/tags — good enough for
// structured runbooks, not free-form documents, and needs no embedding
// model or vector store.
const MAX_SEARCH_RESULTS = 5;
const MAX_LIST_RESULTS = 200;

/** Creates the playbooks table + FTS5 index/triggers if not already present. */
function ensureSchema(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS playbooks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      category TEXT NOT NULL,
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      tags TEXT,
      created_at REAL,
      updated_at REAL
    );
    CREATE VIRTUAL TABLE IF NOT EXISTS playbooks_fts USING fts5(
      title, content, tags,
      content='playbooks', content_rowid='id'
    );
    CREATE TRIGGER IF NOT EXISTS playbooks_ai AFTER INSERT ON playbooks BEGIN
      INSERT INTO playbooks_fts(rowid, title, content, tags)
      VALUES (new.id, new.title, new.content, new.tags);
    END;
    CREATE TRIGGER IF NOT EXISTS playbooks_ad AFTER DELETE ON playbooks BEGIN
      INSERT INTO playbooks_fts(playbooks_fts, rowid, title, content, tags)
      VALUES ('delete', old.id, old.title, old.content, old.tags);
    END;
    CREATE TRIGGER IF NOT EXISTS playbooks_au AFTER UPDATE ON playbooks BEGIN
      INSERT INTO playbooks_fts(playbooks_fts, rowid, title, content, tags)
      VALUES ('delete', old.id, old.title, old.content, old.tags);
      INSERT INTO playbooks_fts(rowid, title, content, tags)
      VALUES (new.id, new.title, new.content, new.tags);
    END;
  `);
}

/** Adds a new playbook. Returns the created row. */
function addPlaybook(db, { category, title, content, tags } = {}) {
  const cat = String(category || "").trim();
  const t = String(title || "").trim();
  const c = String(content || "").trim();
  if (!cat) throw new Error("category is required");
  if (!t) throw new Error("title is required");
  if (!c) throw new Error("content is required");
  const tagsStr = Array.isArray(tags) ? tags.join(", ") : String(tags || "").trim();
  const now = Date.now();
  const info = db
    .prepare(
      `INSERT INTO playbooks (category, title, content, tags, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`
    )
    .run(cat, t, c, tagsStr, now, now);
  return { id: info.lastInsertRowid, category: cat, title: t, content: c, tags: tagsStr };
}

/** Lists every playbook, optionally filtered by category, most recent first. */
function listPlaybooks(db, category = null) {
  if (category) {
    return db
      .prepare(`SELECT * FROM playbooks WHERE category = ? ORDER BY title`)
      .all(category);
  }
  return db
    .prepare(`SELECT * FROM playbooks ORDER BY category, title LIMIT ?`)
    .all(MAX_LIST_RESULTS);
}

/** Distinct categories currently in use, for grouping in an admin panel. */
function listPlaybookCategories(db) {
  return db
    .prepare(`SELECT DISTINCT category FROM playbooks ORDER BY category`)
    .all()
    .map((r) => r.category);
}

/** Updates a playbook's content/title/category/tags. Returns the updated row, or null if not found. */
function updatePlaybook(db, id, { category, title, content, tags } = {}) {
  const existing = db.prepare(`SELECT * FROM playbooks WHERE id = ?`).get(id);
  if (!existing) return null;
  const cat = category !== undefined ? String(category || "").trim() : existing.category;
  const t = title !== undefined ? String(title || "").trim() : existing.title;
  const c = content !== undefined ? String(content || "").trim() : existing.content;
  const tagsStr =
    tags !== undefined
      ? Array.isArray(tags)
        ? tags.join(", ")
        : String(tags || "").trim()
      : existing.tags;
  if (!cat) throw new Error("category is required");
  if (!t) throw new Error("title is required");
  if (!c) throw new Error("content is required");
  db.prepare(
    `UPDATE playbooks SET category = ?, title = ?, content = ?, tags = ?, updated_at = ? WHERE id = ?`
  ).run(cat, t, c, tagsStr, Date.now(), id);
  return { id, category: cat, title: t, content: c, tags: tagsStr };
}

/** Deletes a playbook by id. Returns true if a row was removed. */
function deletePlaybook(db, id) {
  const info = db.prepare(`DELETE FROM playbooks WHERE id = ?`).run(id);
  return info.changes > 0;
}

/**
 * Full-text search over the playbook library — used by the
 * lookup_playbook tool. Returns the matching rows (category, title,
 * content, tags), best matches first.
 */
function searchPlaybooks(db, query, limit = MAX_SEARCH_RESULTS) {
  const q = String(query || "").trim();
  if (!q) return [];
  // FTS5 special characters (", *, etc.) in free-text queries can throw a
  // syntax error — quote each token and OR them together so any word in the
  // query can match, robust to punctuation/typos in what the model sends.
  const ftsQuery = q
    .split(/\s+/)
    .filter(Boolean)
    .map((word) => `"${word.replace(/"/g, '""')}"`)
    .join(" OR ");
  if (!ftsQuery) return [];
  try {
    return db
      .prepare(
        `SELECT p.id, p.category, p.title, p.content, p.tags
         FROM playbooks_fts f
         JOIN playbooks p ON p.id = f.rowid
         WHERE playbooks_fts MATCH ?
         ORDER BY bm25(playbooks_fts)
         LIMIT ?`
      )
      .all(ftsQuery, Math.min(Number(limit) || MAX_SEARCH_RESULTS, 20));
  } catch {
    // Fall back to a plain substring scan if the FTS query still fails for
    // some reason — better a slower match than an error surfaced to the model.
    const like = `%${q}%`;
    return db
      .prepare(
        `SELECT id, category, title, content, tags FROM playbooks
         WHERE title LIKE ? OR content LIKE ? OR tags LIKE ?
         ORDER BY title LIMIT ?`
      )
      .all(like, like, like, Math.min(Number(limit) || MAX_SEARCH_RESULTS, 20));
  }
}

const toolDefinitions = {
  lookup_playbook: {
    name: "lookup_playbook",
    description:
      "Search the curated cyber incident response playbook library — " +
      "step-by-step runbooks the user has written or transcribed for " +
      "handling specific kinds of security incidents (e.g. phishing " +
      "report, ransomware detection, suspected account compromise, data " +
      "exfiltration, malware infection). ALWAYS call this the moment an " +
      "active or suspected incident is described, or the user explicitly " +
      "asks 'what's the playbook for X' / 'do we have a runbook for this' " +
      "— before improvising your own response steps. If a matching " +
      "playbook is found, follow it: walk the user through its steps in " +
      "order, in your own words, don't just paste it verbatim. If nothing " +
      "matches, say so plainly and fall back to general incident-response " +
      "best practice.",
    parameters: {
      type: "object",
      properties: {
        query: {
          type: "string",
          description:
            "What kind of incident this is, e.g. 'phishing email', " +
            "'ransomware', 'compromised account', 'data breach', " +
            "'malware on endpoint', or a keyword from the situation " +
            "being described.",
        },
        limit: {
          type: "number",
          description: "Max playbooks to return (default 5).",
        },
      },
      required: ["query"],
    },
  },
  add_playbook: {
    name: "add_playbook",
    description:
      "Add a new incident response playbook/runbook to the library (the " +
      "user may call it a 'playbook', 'runbook', 'IR plan', 'response " +
      "plan', or similar — treat all of those as this tool). Use this " +
      "whenever the user asks you to save, write down, or transcribe a " +
      "playbook for handling a specific type of security incident. Write " +
      "the content as clear, ordered steps (numbered list) so it can be " +
      "followed directly during a real incident — this will be shown " +
      "back and read aloud step by step later, not just cited.",
    parameters: {
      type: "object",
      properties: {
        category: {
          type: "string",
          description:
            "Short grouping label for the incident type, e.g. " +
            "'phishing', 'ransomware', 'account_compromise', " +
            "'data_exfiltration', 'malware' — reuse an existing category " +
            "if it fits, otherwise make a concise new one.",
        },
        title: {
          type: "string",
          description:
            "Short title for the playbook, e.g. 'Suspected Phishing Email — Employee Report'.",
        },
        content: {
          type: "string",
          description:
            "The playbook steps, as a numbered/ordered list covering " +
            "detection, containment, eradication, recovery, and " +
            "follow-up/lessons-learned as applicable.",
        },
        tags: {
          type: "string",
          description: "Optional comma-separated keywords to help future search.",
        },
      },
      required: ["category", "title", "content"],
    },
  },
};

// add_playbook mutates state and should go through the normal confirm/deny
// flow (like create_note/add_threat_intel); lookup_playbook is read-only.
const CONFIRM_REQUIRED_TOOLS = ["add_playbook"];

function describeToolCall(name, args) {
  switch (name) {
    case "lookup_playbook":
      return `look up an incident playbook for "${args.query}"`;
    case "add_playbook":
      return `add "${args.title}" to the playbook library (${args.category})`;
    default:
      return undefined;
  }
}

module.exports = {
  ensureSchema,
  addPlaybook,
  listPlaybooks,
  listPlaybookCategories,
  updatePlaybook,
  deletePlaybook,
  searchPlaybooks,
  toolDefinitions,
  CONFIRM_REQUIRED_TOOLS,
  describeToolCall,
};
