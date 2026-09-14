// Shared cyber threat intelligence reference library: a small, curated,
// growing knowledge base an assistant can reference when acting as a
// security/forensics analyst — kill chain phases, ATT&CK-style
// techniques, IOCs, mitigations, etc. — instead of relying purely on the
// model's own (unsourced, sometimes stale) training knowledge.
//
// Framework-agnostic like notes.js/files.js: the host owns its own SQLite
// connection (via better-sqlite3) and passes it in as `db` to every
// function here, including `ensureSchema(db)` which the host calls once
// from its own db.js alongside its other CREATE TABLE statements — this
// keeps the schema itself (not just the query logic) as a single source
// of truth instead of copy-pasted SQL drifting between hosts.
//
// Full-text search (SQLite FTS5) over title/content/tags — good enough
// for structured reference entries, not free-form documents, and needs no
// embedding model or vector store.
const MAX_SEARCH_RESULTS = 8;
const MAX_LIST_RESULTS = 200;

/** Creates the threat_intel table + FTS5 index/triggers if not already present. */
function ensureSchema(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS threat_intel (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      category TEXT NOT NULL,
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      tags TEXT,
      created_at REAL
    );
    CREATE VIRTUAL TABLE IF NOT EXISTS threat_intel_fts USING fts5(
      title, content, tags,
      content='threat_intel', content_rowid='id'
    );
    CREATE TRIGGER IF NOT EXISTS threat_intel_ai AFTER INSERT ON threat_intel BEGIN
      INSERT INTO threat_intel_fts(rowid, title, content, tags)
      VALUES (new.id, new.title, new.content, new.tags);
    END;
    CREATE TRIGGER IF NOT EXISTS threat_intel_ad AFTER DELETE ON threat_intel BEGIN
      INSERT INTO threat_intel_fts(threat_intel_fts, rowid, title, content, tags)
      VALUES ('delete', old.id, old.title, old.content, old.tags);
    END;
    CREATE TRIGGER IF NOT EXISTS threat_intel_au AFTER UPDATE ON threat_intel BEGIN
      INSERT INTO threat_intel_fts(threat_intel_fts, rowid, title, content, tags)
      VALUES ('delete', old.id, old.title, old.content, old.tags);
      INSERT INTO threat_intel_fts(rowid, title, content, tags)
      VALUES (new.id, new.title, new.content, new.tags);
    END;
  `);
}

/** Adds a new reference entry. Returns the created row. */
function addThreatIntel(db, { category, title, content, tags } = {}) {
  const cat = String(category || "").trim();
  const t = String(title || "").trim();
  const c = String(content || "").trim();
  if (!cat) throw new Error("category is required");
  if (!t) throw new Error("title is required");
  if (!c) throw new Error("content is required");
  const tagsStr = Array.isArray(tags) ? tags.join(", ") : String(tags || "").trim();
  const info = db
    .prepare(
      `INSERT INTO threat_intel (category, title, content, tags, created_at) VALUES (?, ?, ?, ?, ?)`
    )
    .run(cat, t, c, tagsStr, Date.now());
  return { id: info.lastInsertRowid, category: cat, title: t, content: c, tags: tagsStr };
}

/** Lists every reference entry, optionally filtered by category, most recent first. */
function listThreatIntel(db, category = null) {
  if (category) {
    return db
      .prepare(
        `SELECT * FROM threat_intel WHERE category = ? ORDER BY created_at DESC LIMIT ?`
      )
      .all(category, MAX_LIST_RESULTS);
  }
  return db
    .prepare(`SELECT * FROM threat_intel ORDER BY category, created_at DESC LIMIT ?`)
    .all(MAX_LIST_RESULTS);
}

/** Distinct categories currently in use, for grouping in an admin panel. */
function listThreatIntelCategories(db) {
  return db
    .prepare(`SELECT DISTINCT category FROM threat_intel ORDER BY category`)
    .all()
    .map((r) => r.category);
}

/** Deletes a reference entry by id. Returns true if a row was removed. */
function deleteThreatIntel(db, id) {
  const info = db.prepare(`DELETE FROM threat_intel WHERE id = ?`).run(id);
  return info.changes > 0;
}

/**
 * Full-text search over the reference library — used by the
 * lookup_threat_intel tool. Returns the matching rows (category, title,
 * content, tags), best matches first.
 */
function searchThreatIntel(db, query, limit = MAX_SEARCH_RESULTS) {
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
        `SELECT t.id, t.category, t.title, t.content, t.tags
         FROM threat_intel_fts f
         JOIN threat_intel t ON t.id = f.rowid
         WHERE threat_intel_fts MATCH ?
         ORDER BY bm25(threat_intel_fts)
         LIMIT ?`
      )
      .all(ftsQuery, Math.min(Number(limit) || MAX_SEARCH_RESULTS, 25));
  } catch {
    // Fall back to a plain substring scan if the FTS query still fails for
    // some reason — better a slower match than an error surfaced to the model.
    const like = `%${q}%`;
    return db
      .prepare(
        `SELECT id, category, title, content, tags FROM threat_intel
         WHERE title LIKE ? OR content LIKE ? OR tags LIKE ?
         ORDER BY created_at DESC LIMIT ?`
      )
      .all(like, like, like, Math.min(Number(limit) || MAX_SEARCH_RESULTS, 25));
  }
}

const toolDefinitions = {
  lookup_threat_intel: {
    name: "lookup_threat_intel",
    description:
      "Search the curated cyber threat intelligence reference library — " +
      "cyber kill chain phases, attack techniques/tactics, IOCs, " +
      "mitigations, and other security reference material the user has " +
      "added. Use this whenever discussing an attack, incident, malware " +
      "behavior, or asked to map something to the kill chain/a framework, " +
      "so you can cite real curated reference content instead of relying " +
      "only on your own general knowledge. Returns the best-matching " +
      "entries (category, title, content) — synthesize an answer from " +
      "them in your own words, don't just dump them raw.",
    parameters: {
      type: "object",
      properties: {
        query: {
          type: "string",
          description:
            "What to search for, e.g. 'reconnaissance', 'lateral movement', " +
            "'command and control', a technique name, or a keyword.",
        },
        limit: {
          type: "number",
          description: "Max entries to return (default 8).",
        },
      },
      required: ["query"],
    },
  },
  add_threat_intel: {
    name: "add_threat_intel",
    description:
      "Add a new entry to the curated cyber threat intelligence reference " +
      "library (also called the threat intel library, threat " +
      "intelligence database, or similar by the user — this is the tool " +
      "for all of those). Use this whenever the user asks you to save, " +
      "add, remember, log, or record something into that library — e.g. " +
      "a kill chain phase, an attack technique/tactic, an IOC, a " +
      "mitigation, or any other security reference fact worth keeping on " +
      "hand for future lookup_threat_intel searches. Write the content " +
      "clearly and self-contained, as it will be shown back verbatim " +
      "later.",
    parameters: {
      type: "object",
      properties: {
        category: {
          type: "string",
          description:
            "Short grouping label, e.g. 'kill_chain', 'attack_technique', " +
            "'ioc', 'mitigation' — reuse an existing category if it fits, " +
            "otherwise make a concise new one.",
        },
        title: {
          type: "string",
          description: "Short title for the entry, e.g. 'Reconnaissance'.",
        },
        content: {
          type: "string",
          description: "The reference content/description/details to save.",
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

// add_threat_intel mutates state and should go through the normal
// confirm/deny flow (like create_note); lookup_threat_intel is read-only.
const CONFIRM_REQUIRED_TOOLS = ["add_threat_intel"];

function describeToolCall(name, args) {
  switch (name) {
    case "lookup_threat_intel":
      return `look up threat intel on "${args.query}"`;
    case "add_threat_intel":
      return `add "${args.title}" to the threat intel library (${args.category})`;
    default:
      return undefined;
  }
}

module.exports = {
  ensureSchema,
  addThreatIntel,
  listThreatIntel,
  listThreatIntelCategories,
  deleteThreatIntel,
  searchThreatIntel,
  toolDefinitions,
  CONFIRM_REQUIRED_TOOLS,
  describeToolCall,
};
