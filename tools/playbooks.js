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
    CREATE TABLE IF NOT EXISTS playbook_drafts (
      conversation_id TEXT PRIMARY KEY,
      category TEXT NOT NULL,
      title TEXT NOT NULL,
      tags TEXT NOT NULL DEFAULT '',
      steps TEXT NOT NULL DEFAULT '[]',
      updated_at REAL
    );
  `);
  // Added after the tables above already existed in deployed databases —
  // CREATE TABLE IF NOT EXISTS won't retrofit a new column onto an
  // existing table, so add it defensively and ignore the "duplicate
  // column" error on databases that already have it.
  for (const table of ["playbooks", "playbook_drafts"]) {
    try {
      db.exec(`ALTER TABLE ${table} ADD COLUMN requires_report INTEGER NOT NULL DEFAULT 0`);
    } catch {
      // already has the column
    }
  }
}

/** Adds a new playbook. Returns the created row. */
function addPlaybook(db, { category, title, content, tags, requiresReport } = {}) {
  const cat = String(category || "").trim();
  const t = String(title || "").trim();
  const c = String(content || "").trim();
  if (!cat) throw new Error("category is required");
  if (!t) throw new Error("title is required");
  if (!c) throw new Error("content is required");
  const tagsStr = Array.isArray(tags) ? tags.join(", ") : String(tags || "").trim();
  const reqReport = requiresReport ? 1 : 0;
  const now = Date.now();
  const info = db
    .prepare(
      `INSERT INTO playbooks (category, title, content, tags, requires_report, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`
    )
    .run(cat, t, c, tagsStr, reqReport, now, now);
  return {
    id: info.lastInsertRowid,
    category: cat,
    title: t,
    content: c,
    tags: tagsStr,
    requires_report: reqReport,
  };
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

/** Updates a playbook's content/title/category/tags/requiresReport. Returns the updated row, or null if not found. */
function updatePlaybook(db, id, { category, title, content, tags, requiresReport } = {}) {
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
  const reqReport =
    requiresReport !== undefined ? (requiresReport ? 1 : 0) : existing.requires_report;
  if (!cat) throw new Error("category is required");
  if (!t) throw new Error("title is required");
  if (!c) throw new Error("content is required");
  db.prepare(
    `UPDATE playbooks SET category = ?, title = ?, content = ?, tags = ?, requires_report = ?, updated_at = ? WHERE id = ?`
  ).run(cat, t, c, tagsStr, reqReport, Date.now(), id);
  return { id, category: cat, title: t, content: c, tags: tagsStr, requires_report: reqReport };
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

// --- Conversational drafting -------------------------------------------
// Lets the assistant build up a playbook incrementally while talking it
// through with the user in chat — one draft per conversation (rather than
// trusting the model to silently reconstruct the whole thing from context
// at the end), so state survives long conversations and each step is
// durably recorded the moment it's described instead of only living in
// the model's own recollection of the chat so far.

function getPlaybookDraft(db, conversationId) {
  if (!conversationId) return null;
  const row = db
    .prepare(`SELECT * FROM playbook_drafts WHERE conversation_id = ?`)
    .get(conversationId);
  if (!row) return null;
  return {
    category: row.category,
    title: row.title,
    tags: row.tags,
    steps: JSON.parse(row.steps || "[]"),
    requiresReport: !!row.requires_report,
  };
}

/** Starts (or restarts) a playbook draft scoped to this conversation. */
function startPlaybookDraft(db, conversationId, { category, title, requiresReport } = {}) {
  if (!conversationId) throw new Error("conversationId is required");
  const cat = String(category || "").trim();
  const t = String(title || "").trim();
  if (!cat) throw new Error("category is required");
  if (!t) throw new Error("title is required");
  const reqReport = requiresReport ? 1 : 0;
  db.prepare(
    `INSERT INTO playbook_drafts (conversation_id, category, title, tags, steps, requires_report, updated_at)
     VALUES (?, ?, ?, '', '[]', ?, ?)
     ON CONFLICT(conversation_id) DO UPDATE SET
       category = excluded.category, title = excluded.title,
       tags = '', steps = '[]', requires_report = excluded.requires_report,
       updated_at = excluded.updated_at`
  ).run(conversationId, cat, t, reqReport, Date.now());
  return { category: cat, title: t, tags: "", steps: [], requiresReport: !!reqReport };
}

/** Appends one step (optionally under a named section) to the in-progress draft for this conversation. */
function addPlaybookDraftStep(db, conversationId, stepInput) {
  const draft = getPlaybookDraft(db, conversationId);
  if (!draft) {
    throw new Error(
      "No playbook draft in progress for this conversation — call start_playbook_draft first."
    );
  }
  const { step, section } =
    typeof stepInput === "string" ? { step: stepInput, section: "" } : stepInput || {};
  const s = String(step || "").trim();
  if (!s) throw new Error("step is required");
  const sec = String(section || "").trim();
  const steps = [...draft.steps, { section: sec, text: s }];
  db.prepare(
    `UPDATE playbook_drafts SET steps = ?, updated_at = ? WHERE conversation_id = ?`
  ).run(JSON.stringify(steps), Date.now(), conversationId);
  return { ...draft, steps };
}

/** Clears the in-progress draft for this conversation without saving it. */
function discardPlaybookDraft(db, conversationId) {
  const info = db
    .prepare(`DELETE FROM playbook_drafts WHERE conversation_id = ?`)
    .run(conversationId);
  return info.changes > 0;
}

/**
 * Turns the accumulated draft steps into a real, saved playbook (via
 * addPlaybook) and clears the draft. Steps recorded under the same named
 * section (see addPlaybookDraftStep) are grouped and numbered together
 * under a "## Section Title" heading, in the order each section was first
 * used; steps with no section are numbered as one plain list, exactly
 * like before named sections existed.
 */
function renderDraftContent(steps) {
  const groups = [];
  for (const raw of steps) {
    const { section, text } = typeof raw === "string" ? { section: "", text: raw } : raw || {};
    const sec = String(section || "").trim();
    let group = groups.find((g) => g.section === sec);
    if (!group) {
      group = { section: sec, items: [] };
      groups.push(group);
    }
    group.items.push(String(text || ""));
  }
  // Put any unsectioned steps first (mirrors splitPlaybookSections' own
  // "preamble" handling — content before the first heading), so mixing
  // sectioned and unsectioned steps in one draft doesn't accidentally
  // swallow the unsectioned ones into whatever section happens to be last.
  groups.sort((a, b) => (a.section ? 1 : 0) - (b.section ? 1 : 0));
  const sections = groups.map((g) => ({
    title: g.section,
    content: g.items.map((t, i) => `${i + 1}. ${t}`).join("\n"),
  }));
  return joinPlaybookSections(sections);
}

function finalizePlaybookDraft(db, conversationId, { tags } = {}) {
  const draft = getPlaybookDraft(db, conversationId);
  if (!draft) {
    throw new Error(
      "No playbook draft in progress for this conversation — call start_playbook_draft first."
    );
  }
  if (draft.steps.length === 0) {
    throw new Error("This draft has no steps yet — add at least one before finishing it.");
  }
  const content = renderDraftContent(draft.steps);
  const tagsStr =
    tags !== undefined
      ? Array.isArray(tags)
        ? tags.join(", ")
        : String(tags || "").trim()
      : draft.tags;
  const entry = addPlaybook(db, {
    category: draft.category,
    title: draft.title,
    content,
    tags: tagsStr,
    requiresReport: draft.requiresReport,
  });
  discardPlaybookDraft(db, conversationId);
  return entry;
}

// --- Markdown import/export ---------------------------------------------
// Lets a playbook be handed off as a single portable .md file (or a folder
// of them, zipped) — for backing up the library, editing steps in a real
// editor/Obsidian, sharing one playbook with someone else, or restoring
// from a previous export. Round-trips category/title/tags via a small
// YAML-ish frontmatter block so nothing is lost going out and back in.

function escapeFrontmatterValue(v) {
  const s = String(v ?? "");
  // Quote if it has anything that would break a naive "key: value" line.
  if (/[:#\n]/.test(s) || s !== s.trim()) {
    return `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
  }
  return s;
}

function unescapeFrontmatterValue(v) {
  const s = String(v ?? "").trim();
  if (s.startsWith('"') && s.endsWith('"')) {
    return s.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, "\\");
  }
  return s;
}

/** Renders one playbook as a single Markdown file with a frontmatter header. */
function playbookToMarkdown(entry) {
  const lines = [
    "---",
    `title: ${escapeFrontmatterValue(entry.title)}`,
    `category: ${escapeFrontmatterValue(entry.category)}`,
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

/**
 * Parses a Markdown file back into { title, category, tags, content }.
 * Reads title/category/tags from frontmatter if present, falling back to
 * `fallbackTitle` (e.g. derived from the uploaded filename) and an
 * "uncategorized" bucket so an import never hard-fails just because the
 * file wasn't originally exported from here.
 */
function parsePlaybookMarkdown(text, fallbackTitle = "Untitled Playbook") {
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
  // Strip a single leading "# Title" heading from the body if present —
  // it's redundant with the frontmatter title / just a copy of it.
  body = body.replace(/^\s*#\s+.+\n+/, "");
  const title = String(meta.title || fallbackTitle || "Untitled Playbook").trim();
  const category = String(meta.category || "uncategorized").trim() || "uncategorized";
  const tags = String(meta.tags || "").trim();
  const content = body.trim();
  return { title, category, tags, content };
}

/** Safe-ish filename (no path separators/odd characters) for one exported playbook. */
function playbookFilename(entry) {
  const slug = (s) =>
    String(s || "")
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "") || "untitled";
  return `${slug(entry.category)}__${slug(entry.title)}.md`;
}

// --- Structured sections ---------------------------------------------------
// Playbooks are still stored as one plain `content` string (no schema
// change needed, and it stays a single field for search/export/the model
// to read) — but the writing/editing UI presents it broken into named
// sections (e.g. the standard incident-response phases), using Markdown
// "## Section Title" headings as the delimiter. splitPlaybookSections /
// joinPlaybookSections convert between that flat string and a
// [{ title, content }] array, entirely losslessly for content that
// already follows the convention. Content with no "## " headings at all
// (older freeform playbooks, or anything imported from elsewhere) comes
// back as a single untitled section so nothing is lost or misrepresented.

const DEFAULT_PLAYBOOK_SECTIONS = [
  "Preparation",
  "Identification",
  "Containment",
  "Remediation",
  "Recovery",
  "Aftermath",
];

function splitPlaybookSections(content) {
  const text = String(content || "").replace(/\r\n/g, "\n").trim();
  if (!text) return [{ title: "", content: "" }];
  const headingRe = /^##\s+(.+?)\s*$/gm;
  const matches = [...text.matchAll(headingRe)];
  if (matches.length === 0) return [{ title: "", content: text }];
  const sections = [];
  // Anything before the first "## " heading (rare, but don't drop it).
  const preamble = text.slice(0, matches[0].index).trim();
  if (preamble) sections.push({ title: "", content: preamble });
  for (let i = 0; i < matches.length; i++) {
    const start = matches[i].index + matches[i][0].length;
    const end = i + 1 < matches.length ? matches[i + 1].index : text.length;
    sections.push({
      title: matches[i][1].trim(),
      content: text.slice(start, end).trim(),
    });
  }
  return sections;
}

function joinPlaybookSections(sections) {
  const list = Array.isArray(sections) ? sections : [];
  return list
    .map((s) => {
      const title = String(s?.title || "").trim();
      const body = String(s?.content || "").trim();
      if (!title && !body) return "";
      return title ? `## ${title}\n\n${body}` : body;
    })
    .filter(Boolean)
    .join("\n\n");
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
      "asks to 'run' a playbook/runbook (e.g. 'run playbook " +
      "ransomware: Ransomware Response', 'run the phishing playbook') — " +
      "before improvising your own response steps. If a matching " +
      "playbook is found, RUN it: call start_incident_report right away " +
      "(don't wait to be asked, and regardless of requires_report — " +
      "always track a playbook run so findings aren't lost), then walk " +
      "the user through the playbook's steps in order in your own words " +
      "(don't just paste it verbatim), calling log_incident_entry for " +
      "each step/finding/action as it actually happens. IMPORTANT: " +
      "running a playbook uses start_incident_report/log_incident_entry/" +
      "finish_incident_report — it NEVER uses start_playbook_draft/" +
      "add_playbook_step/finish_playbook_draft, which are a completely " +
      "separate set of tools for AUTHORING a brand-new playbook to save " +
      "to the library, not for executing one that already exists. If " +
      "nothing matches, say so plainly and fall back to general " +
      "incident-response best practice. When the user says to close " +
      "out/wrap up/finish the playbook, call finish_incident_report — " +
      "this is especially important (do it proactively, don't wait to " +
      "be asked) when the playbook has requires_report: true.",
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
            "The playbook steps, broken into named sections using " +
            "Markdown '## Section Title' headings — one heading per " +
            "phase, e.g. '## Preparation', '## Identification', " +
            "'## Containment', '## Remediation', '## Recovery', " +
            "'## Aftermath' (use whichever of these apply, add custom " +
            "section names if a phase doesn't fit, and skip phases with " +
            "nothing to say). Each section's body should be a clear, " +
            "ordered/numbered list of concrete steps to follow during a " +
            "real incident, not just a description.",
        },
        tags: {
          type: "string",
          description: "Optional comma-separated keywords to help future search.",
        },
        requires_report: {
          type: "boolean",
          description:
            "Set true if incidents handled with this playbook should end " +
            "in a written incident report (significant incidents like " +
            "ransomware, breach, data exfiltration). Set false for quick " +
            "procedures that don't warrant one (e.g. 'lost badge'). " +
            "Defaults to false if omitted.",
        },
      },
      required: ["category", "title", "content"],
    },
  },
  start_playbook_draft: {
    name: "start_playbook_draft",
    description:
      "Begin building a new incident response playbook interactively, " +
      "one step at a time, while talking it through with the user in " +
      "chat — use this instead of add_playbook when the user wants to " +
      "walk you through a process conversationally rather than dictate " +
      "the whole thing at once (e.g. 'let's build a playbook for " +
      "ransomware, step one is...'). Starts (or restarts, discarding any " +
      "unfinished draft) a fresh draft for THIS conversation. After this, " +
      "call add_playbook_step for each step as the user describes it, " +
      "then finish_playbook_draft once they say it's complete. ONLY use " +
      "this to author a brand-new playbook definition for the library. " +
      "Do NOT use this (or add_playbook_step/finish_playbook_draft) when " +
      "the user is actually RUNNING/executing an existing playbook found " +
      "via lookup_playbook during a real or simulated incident — that " +
      "case uses the entirely separate start_incident_report/" +
      "log_incident_entry/finish_incident_report tools instead.",
    parameters: {
      type: "object",
      properties: {
        category: {
          type: "string",
          description:
            "Short grouping label for the incident type, e.g. " +
            "'phishing', 'ransomware', 'account_compromise'.",
        },
        title: {
          type: "string",
          description: "Short title for the playbook being built.",
        },
        requires_report: {
          type: "boolean",
          description:
            "Set true if incidents handled with this playbook should end " +
            "in a written incident report (significant incidents like " +
            "ransomware, breach, data exfiltration). Defaults to false.",
        },
      },
      required: ["category", "title"],
    },
  },
  add_playbook_step: {
    name: "add_playbook_step",
    description:
      "Append one step to the playbook draft currently being built for " +
      "this conversation (started with start_playbook_draft). Call this " +
      "once per step as the user describes it in the conversation — " +
      "don't wait and try to reconstruct all the steps at the end. " +
      "Rephrase what they said into one clear, actionable step; don't " +
      "just copy their raw sentence if it's rambling. Briefly confirm " +
      "back what you recorded so they can correct it if needed. If the " +
      "user is walking through this by incident-response phase (e.g. " +
      "'step one is preparation...', 'next is identification...'), pass " +
      "that phase as `section` so steps get grouped under it in the " +
      "final playbook — typical phases are Preparation, Identification, " +
      "Containment, Remediation, Recovery, and Aftermath, but use " +
      "whatever section name fits what the user said, or omit it for a " +
      "flat unsectioned list.",
    parameters: {
      type: "object",
      properties: {
        step: {
          type: "string",
          description: "One clear, self-contained action for this step.",
        },
        section: {
          type: "string",
          description:
            "Optional phase/section this step belongs to (e.g. " +
            "'Preparation', 'Identification', 'Containment', " +
            "'Remediation', 'Recovery', 'Aftermath', or a custom name). " +
            "Steps sharing the same section are grouped together under " +
            "that heading in the final playbook. Omit for an unsectioned " +
            "flat list.",
        },
      },
      required: ["step"],
    },
  },
  // NOTE: start_playbook_draft/add_playbook_step/view_playbook_draft/
  // finish_playbook_draft/discard_playbook_draft only ever author a new
  // playbook DEFINITION for the library. Actually running/executing an
  // existing playbook during an incident is a different job entirely and
  // uses start_incident_report/log_incident_entry/finish_incident_report
  // from incidentReports.js instead — see lookup_playbook's description.
  view_playbook_draft: {
    name: "view_playbook_draft",
    description:
      "Show the playbook draft currently being built for this " +
      "conversation (its category, title, and steps recorded so far). " +
      "Use this if the user asks to review, recap, or hear the steps so " +
      "far before continuing or finishing.",
    parameters: { type: "object", properties: {} },
  },
  finish_playbook_draft: {
    name: "finish_playbook_draft",
    description:
      "Complete the in-progress playbook draft for this conversation and " +
      "save it as a real playbook in the library (equivalent to " +
      "add_playbook, but using the steps already recorded via " +
      "add_playbook_step instead of one big block of content). Call this " +
      "once the user confirms they're done describing steps. The draft " +
      "is cleared after this succeeds. This saves a playbook DEFINITION " +
      "to the library — it is unrelated to closing out a live playbook " +
      "run; for that, use finish_incident_report instead.",
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
  discard_playbook_draft: {
    name: "discard_playbook_draft",
    description:
      "Abandon the in-progress playbook draft for this conversation " +
      "without saving it — use this if the user decides not to finish it " +
      "or wants to start over from scratch.",
    parameters: { type: "object", properties: {} },
  },
};

// add_playbook/finish_playbook_draft both persist a real playbook and
// should go through the normal confirm/deny flow (like create_note/
// add_threat_intel); everything else here is read-only or scoped to an
// unpersisted draft, so it's safe to run without confirmation.
const CONFIRM_REQUIRED_TOOLS = ["add_playbook", "finish_playbook_draft"];

function describeToolCall(name, args) {
  switch (name) {
    case "lookup_playbook":
      return `look up an incident playbook for "${args.query}"`;
    case "add_playbook":
      return `add "${args.title}" to the playbook library (${args.category})`;
    case "start_playbook_draft":
      return `start drafting a playbook: "${args.title}" (${args.category})`;
    case "add_playbook_step":
      return args.section
        ? `add a step under "${args.section}" to the in-progress playbook draft`
        : `add a step to the in-progress playbook draft`;
    case "view_playbook_draft":
      return `review the in-progress playbook draft`;
    case "finish_playbook_draft":
      return `save the in-progress playbook draft to the library`;
    case "discard_playbook_draft":
      return `discard the in-progress playbook draft`;
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
  getPlaybookDraft,
  startPlaybookDraft,
  addPlaybookDraftStep,
  discardPlaybookDraft,
  finalizePlaybookDraft,
  playbookToMarkdown,
  parsePlaybookMarkdown,
  playbookFilename,
  DEFAULT_PLAYBOOK_SECTIONS,
  splitPlaybookSections,
  joinPlaybookSections,
  toolDefinitions,
  CONFIRM_REQUIRED_TOOLS,
  describeToolCall,
};
