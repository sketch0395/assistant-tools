"use strict";

// create_note: writes/appends/replaces markdown (.md) note files under a
// configurable notes directory. Framework-agnostic — the host project
// injects its own filesystem sandboxing check and HTTP helpers instead of
// this module assuming any particular project's conventions.
//
// Usage (host project's tools-agent):
//
//   const notesTool = require("../shared/tools/notes");
//   notesTool.registerRoutes(router, {
//     notesDir: NOTES_DIR,
//     isAllowed,
//     send,
//     readJsonBody,
//   });
//
// `isAllowed(path)` must return a boolean — used to sandbox NOTES_DIR the
// same way every other filesystem-touching tool in the host project is
// sandboxed. `send(res, status, body)` and `readJsonBody(req)` may be the
// host's existing HTTP helpers (see lain's tools-agent/lib/http.js for a
// reference implementation), or omitted to use the small built-in
// fallbacks below.

const fs = require("node:fs");
const path = require("node:path");

function defaultSend(res, status, body) {
  const json = JSON.stringify(body);
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(json);
}

function defaultReadJsonBody(req) {
  return new Promise((resolve) => {
    let raw = "";
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", () => {
      try {
        resolve(JSON.parse(raw || "{}"));
      } catch {
        resolve({});
      }
    });
  });
}

// Turns an arbitrary title into a safe, filesystem-friendly base filename —
// no path separators or traversal sequences can survive this, so the
// resulting path is always a direct child of notesDir.
function slugifyTitle(title) {
  const slug = String(title || "note")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 60);
  return slug || "note";
}

// Small/fast models occasionally emit a literal backslash-n (two chars)
// instead of a real newline inside JSON string content, which then shows
// up as visible "\n" text in the saved note. Normalize that away.
function sanitizeNoteContent(content) {
  if (typeof content !== "string") return content;
  return content.replace(/\\n/g, "\n").replace(/\\t/g, "\t");
}

// isAllowed and notesDir must be supplied by the caller — see file header.
function createNote(title, content, mode, { notesDir, isAllowed }) {
  content = sanitizeNoteContent(content);
  if (typeof isAllowed === "function" && !isAllowed(notesDir)) {
    throw new Error(
      `Notes directory (${notesDir}) is not inside an allowed root. ` +
        `Adjust your host project's allowed-roots config or notes-dir setting.`
    );
  }
  fs.mkdirSync(notesDir, { recursive: true });

  const slug = slugifyTitle(title);
  const baseFilename = `${slug}.md`;
  const basePath = path.join(notesDir, baseFilename);
  const baseExists = fs.existsSync(basePath);

  // append/replace only apply to an existing note with this exact title —
  // if none exists yet, fall through to normal "create" behavior below.
  if (mode === "append" && baseExists) {
    fs.appendFileSync(basePath, `\n${content || ""}\n`, "utf8");
    return { path: basePath, filename: baseFilename, mode: "appended" };
  }
  if (mode === "replace" && baseExists) {
    const body = title ? `# ${title}\n\n${content || ""}\n` : `${content || ""}\n`;
    fs.writeFileSync(basePath, body, "utf8");
    return { path: basePath, filename: baseFilename, mode: "replaced" };
  }

  // "create" (or append/replace with no existing note to target): always
  // makes a new file, auto-incrementing the name instead of overwriting.
  let filename = baseFilename;
  let fullPath = basePath;
  let n = 2;
  while (fs.existsSync(fullPath)) {
    filename = `${slug}-${n}.md`;
    fullPath = path.join(notesDir, filename);
    n++;
  }

  const body = title ? `# ${title}\n\n${content || ""}\n` : `${content || ""}\n`;
  fs.writeFileSync(fullPath, body, "utf8");
  return { path: fullPath, filename, mode: "created" };
}

// Tool definition fragment for LLM function-calling — host projects can
// spread/reuse this instead of retyping the same schema by hand. This is
// the canonical, battle-tested description (refined from real usage
// across projects) — host projects should prefer requiring this over
// writing their own, and if a host-specific detail is needed (e.g. "on
// the user's laptop"), append it rather than rewriting the whole thing,
// so fixes/improvements made here don't have to be re-discovered per
// project.
const toolDefinition = {
  name: "create_note",
  description:
    "Create a new note, append to an existing note, or replace an existing " +
    "note's content. Notes are saved as markdown (.md) files. Use this when " +
    "the user asks to write something down, save a summary/list as a file, " +
    "or add to an existing note by title — as opposed to remembering a " +
    "short durable fact. Matching an existing note for append/replace mode " +
    "is by exact title.",
  parameters: {
    type: "object",
    properties: {
      title: {
        type: "string",
        description:
          "Note title — used as the file name (sanitized) and as a " +
          "top-level heading in the file. Also used to find an existing " +
          "note for append/replace mode.",
      },
      content: { type: "string", description: "The note's body content, in markdown." },
      mode: {
        type: "string",
        enum: ["create", "append", "replace"],
        description:
          "'create' (default) always makes a brand-new, distinct note — use " +
          "when the user wants a new note even if a similarly-titled one " +
          "exists. 'append' adds this content to the end of the existing " +
          "note with this exact title (e.g. 'add X to my grocery list'). " +
          "'replace' overwrites the entire content of the existing note " +
          "with this exact title.",
      },
    },
    required: ["title"],
  },
};

// router: object with a `.post(path, handler)` method (see lain's
// tools-agent/lib/http.js createRouter() for a reference implementation).
// opts: { notesDir, isAllowed, send, readJsonBody } — see file header.
function registerRoutes(router, opts = {}) {
  const { notesDir, isAllowed } = opts;
  const send = opts.send || defaultSend;
  const readJsonBody = opts.readJsonBody || defaultReadJsonBody;

  if (!notesDir) {
    throw new Error("notes tool: registerRoutes() requires opts.notesDir");
  }

  router.post("/note", async (req, res) => {
    try {
      const { title, content, mode } = await readJsonBody(req);
      if (!content && !title) {
        return send(res, 400, { error: "title or content is required" });
      }
      if (mode && !["create", "append", "replace"].includes(mode)) {
        return send(res, 400, { error: "mode must be create, append, or replace" });
      }
      send(res, 200, createNote(title, content, mode || "create", { notesDir, isAllowed }));
    } catch (err) {
      send(res, 500, { error: err.message });
    }
  });
}

module.exports = { createNote, slugifyTitle, sanitizeNoteContent, registerRoutes, toolDefinition };
