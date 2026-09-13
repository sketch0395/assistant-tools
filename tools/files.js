"use strict";

// find_files / search_files / read_file / list_directory / summarize_directory:
// read-only filesystem browsing tools shared by every host project's
// tools-agent, plus the LLM-facing tool definitions/dispatch helpers so a
// host's own lib/tools.js doesn't have to hand-write (and let drift) the
// same schema and URL-building logic per project.
//
// Framework-agnostic — the host project injects its own path-resolution/
// sandboxing helpers and HTTP helpers instead of this module assuming any
// particular project's conventions.
//
// Usage (host project's tools-agent server):
//
//   const filesTool = require("../shared/tools/files");
//   filesTool.registerRoutes(router, {
//     allowedRoots: ALLOWED_ROOTS,
//     isAllowed,
//     resolveAllowedPath,
//     walk,
//     looksBinary,
//     skipDirs: SKIP_DIRS,
//     binaryExtensions: BINARY_EXTENSIONS,
//     maxFileScanBytes: MAX_FILE_SCAN_BYTES,
//     send,
//   });
//
// `isAllowed`, `resolveAllowedPath`, `walk`, and `looksBinary` should be the
// host's existing tools-agent/lib/paths.js helpers — this module doesn't
// reimplement path-resolution or sandboxing itself, on purpose, so a host
// project's own security invariants are never bypassed by a shared-code
// change.
//
// Usage (host project's own chat app, e.g. lib/tools.js):
//
//   const filesTool = require("../tools-agent/shared/tools/files");
//   // spread into your own tool-definitions array:
//   ...Object.values(filesTool.toolDefinitions).map((fn) => ({ type: "function", function: fn })),
//   // merge into your confirm-required set:
//   ...filesTool.CONFIRM_REQUIRED_TOOLS,
//   // try the shared describe/dispatch first, fall back to host-specific tools:
//   filesTool.describeToolCall(name, args) ?? myOwnDescribe(name, args);
//   filesTool.buildRequest(name, args) // -> { method, path, searchParams } | null

const fs = require("node:fs");
const path = require("node:path");

function defaultSend(res, status, body) {
  const json = JSON.stringify(body);
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(json);
}

function findFiles(query, root, limit, { walk }) {
  const results = [];
  const q = query.toLowerCase();
  walk(
    root,
    (file) => {
      if (results.length >= limit) return;
      if (path.basename(file).toLowerCase().includes(q)) {
        results.push(file);
      }
    },
    { stopEarly: () => results.length >= limit }
  );
  return results;
}

function searchFiles(query, root, limit, { walk, maxFileScanBytes }) {
  const results = [];
  const q = query.toLowerCase();
  walk(
    root,
    (file) => {
      if (results.length >= limit) return;
      let stat;
      try {
        stat = fs.statSync(file);
      } catch {
        return;
      }
      if (stat.size > maxFileScanBytes) return;
      let content;
      try {
        content = fs.readFileSync(file, "utf8");
      } catch {
        return; // likely binary or unreadable
      }
      const idx = content.toLowerCase().indexOf(q);
      if (idx !== -1) {
        const start = Math.max(0, idx - 60);
        const snippet = content
          .slice(start, idx + q.length + 60)
          .replace(/\s+/g, " ")
          .trim();
        results.push({ file, snippet });
      }
    },
    { stopEarly: () => results.length >= limit }
  );
  return results;
}

function readFileSafe(targetPath, maxBytes) {
  const buf = fs.readFileSync(targetPath);
  const truncated = buf.length > maxBytes;
  return {
    content: buf.subarray(0, maxBytes).toString("utf8"),
    truncated,
    size: buf.length,
  };
}

// Non-recursive listing of a directory's immediate contents — lets a
// model see what's actually in e.g. ~/Downloads before deciding what to
// read or summarize.
function listDirectory(root, limit, { skipDirs }) {
  const entries = fs.readdirSync(root, { withFileTypes: true });
  const items = [];
  for (const entry of entries) {
    if (entry.isDirectory() && skipDirs.has(entry.name)) continue;
    const full = path.join(root, entry.name);
    let stat;
    try {
      stat = fs.statSync(full);
    } catch {
      continue;
    }
    items.push({
      name: entry.name,
      type: entry.isDirectory() ? "dir" : "file",
      size: entry.isDirectory() ? null : stat.size,
      modified: stat.mtime.toISOString(),
    });
  }
  // Most-recently-modified first — usually what you want for "what's in Downloads".
  items.sort((a, b) => new Date(b.modified) - new Date(a.modified));
  return items.slice(0, limit);
}

// Batch-reads the (text) files directly inside a directory, for
// summarization. Non-recursive, skips known-binary extensions and anything
// that looks binary on inspection, and stops once either the file count or
// total byte budget is hit so a big folder can't blow out the model's context.
function readDirectory(
  root,
  { limit, maxBytesPerFile, maxTotalBytes },
  { binaryExtensions, maxFileScanBytes, looksBinary }
) {
  const entries = fs.readdirSync(root, { withFileTypes: true }).filter((e) => e.isFile());

  const withStats = entries
    .map((e) => {
      const full = path.join(root, e.name);
      let stat;
      try {
        stat = fs.statSync(full);
      } catch {
        return null;
      }
      return { name: e.name, path: full, size: stat.size, modified: stat.mtime };
    })
    .filter(Boolean)
    .sort((a, b) => b.modified - a.modified);

  const results = [];
  let totalBytes = 0;

  for (const item of withStats) {
    if (results.length >= limit) break;

    const ext = path.extname(item.name).toLowerCase();
    if (binaryExtensions.has(ext)) {
      results.push({ name: item.name, size: item.size, skipped: "binary file type" });
      continue;
    }
    if (item.size > maxFileScanBytes) {
      results.push({ name: item.name, size: item.size, skipped: "file too large" });
      continue;
    }
    if (totalBytes >= maxTotalBytes) {
      results.push({ name: item.name, size: item.size, skipped: "byte budget reached" });
      continue;
    }

    let buf;
    try {
      buf = fs.readFileSync(item.path);
    } catch {
      results.push({ name: item.name, size: item.size, skipped: "unreadable" });
      continue;
    }
    if (looksBinary(buf)) {
      results.push({ name: item.name, size: item.size, skipped: "binary content" });
      continue;
    }

    const remainingBudget = maxTotalBytes - totalBytes;
    const cap = Math.min(maxBytesPerFile, remainingBudget);
    const truncated = buf.length > cap;
    const content = buf.subarray(0, cap).toString("utf8");
    totalBytes += content.length;

    results.push({ name: item.name, size: item.size, content, truncated });
  }

  return results;
}

function registerRoutes(router, opts = {}) {
  const {
    allowedRoots,
    isAllowed,
    resolveAllowedPath,
    walk,
    looksBinary,
    skipDirs,
    binaryExtensions,
    maxFileScanBytes,
  } = opts;
  const send = opts.send || defaultSend;

  if (!allowedRoots || !isAllowed || !resolveAllowedPath || !walk) {
    throw new Error(
      "files tool: registerRoutes() requires opts.allowedRoots/isAllowed/resolveAllowedPath/walk"
    );
  }

  // A model that guesses an out-of-bounds root (e.g. "/") gets a bare 403
  // with no way to recover on its own. Including the actual allowed
  // root(s) lets it self-correct — retry with no root (defaults to the
  // first allowed root) or an absolute path under one of these — instead
  // of giving up and asking the user for more context.
  function rootNotAllowedError() {
    return {
      error: "root not allowed",
      hint:
        `That path is outside the directories you're allowed to access. ` +
        `Omit "root" to default to ${allowedRoots[0]}, or use an absolute ` +
        `path under one of: ${allowedRoots.join(", ")}.`,
    };
  }

  function pathNotAllowedError() {
    return {
      error: "path not allowed",
      hint:
        `That path is outside the directories you're allowed to access. ` +
        `Use an absolute path under one of: ${allowedRoots.join(", ")}.`,
    };
  }

  router.any("/find", (req, res, url) => {
    const query = url.searchParams.get("q") || "";
    const rootArg = url.searchParams.get("root");
    const limit = Math.min(Number(url.searchParams.get("limit")) || 30, 100);
    if (!query) return send(res, 400, { error: "q is required" });
    const root = rootArg ? resolveAllowedPath(rootArg) : allowedRoots[0];
    if (!root || !isAllowed(root)) return send(res, 403, rootNotAllowedError());
    return send(res, 200, { results: findFiles(query, root, limit, { walk }) });
  });

  router.any("/search", (req, res, url) => {
    const query = url.searchParams.get("q") || "";
    const rootArg = url.searchParams.get("root");
    const limit = Math.min(Number(url.searchParams.get("limit")) || 20, 50);
    if (!query) return send(res, 400, { error: "q is required" });
    const root = rootArg ? resolveAllowedPath(rootArg) : allowedRoots[0];
    if (!root || !isAllowed(root)) return send(res, 403, rootNotAllowedError());
    return send(res, 200, {
      results: searchFiles(query, root, limit, { walk, maxFileScanBytes }),
    });
  });

  router.any("/read", (req, res, url) => {
    const p = url.searchParams.get("path") || "";
    const maxBytes = Math.min(Number(url.searchParams.get("max")) || 20000, 100000);
    if (!p) return send(res, 400, { error: "path is required" });
    const resolved = resolveAllowedPath(p);
    if (!resolved || !isAllowed(resolved)) return send(res, 403, pathNotAllowedError());
    const stat = fs.statSync(resolved);
    if (!stat.isFile()) return send(res, 400, { error: "not a file" });
    return send(res, 200, readFileSafe(resolved, maxBytes));
  });

  router.any("/list", (req, res, url) => {
    const rootArg = url.searchParams.get("root");
    const limit = Math.min(Number(url.searchParams.get("limit")) || 100, 500);
    const root = rootArg ? resolveAllowedPath(rootArg) : allowedRoots[0];
    if (!root || !isAllowed(root)) return send(res, 403, rootNotAllowedError());
    const stat = fs.statSync(root);
    if (!stat.isDirectory()) return send(res, 400, { error: "not a directory" });
    return send(res, 200, { root, entries: listDirectory(root, limit, { skipDirs }) });
  });

  router.any("/read-dir", (req, res, url) => {
    const rootArg = url.searchParams.get("root");
    const limit = Math.min(Number(url.searchParams.get("limit")) || 10, 25);
    const maxBytesPerFile = Math.min(
      Number(url.searchParams.get("maxBytesPerFile")) || 6000,
      30000
    );
    const maxTotalBytes = Math.min(
      Number(url.searchParams.get("maxTotalBytes")) || 30000,
      100000
    );
    const root = rootArg ? resolveAllowedPath(rootArg) : allowedRoots[0];
    if (!root || !isAllowed(root)) return send(res, 403, rootNotAllowedError());
    const stat = fs.statSync(root);
    if (!stat.isDirectory()) return send(res, 400, { error: "not a directory" });
    return send(res, 200, {
      root,
      files: readDirectory(
        root,
        { limit, maxBytesPerFile, maxTotalBytes },
        { binaryExtensions, maxFileScanBytes, looksBinary }
      ),
    });
  });
}

// LLM-facing tool definitions (JSON-schema fragments) for the routes
// above — host projects spread these into their own tool-definitions
// array instead of retyping the same schema by hand.
const toolDefinitions = {
  find_files: {
    name: "find_files",
    description:
      "Find files on the user's laptop by (partial) file name, within directories the user has allowed.",
    parameters: {
      type: "object",
      properties: {
        query: {
          type: "string",
          description: "Substring to match against file names.",
        },
        root: {
          type: "string",
          description:
            "Optional directory to search under (defaults to the user's home directory).",
        },
        limit: {
          type: "number",
          description: "Max results to return (default 30).",
        },
      },
      required: ["query"],
    },
  },
  search_files: {
    name: "search_files",
    description:
      "Search file contents for a substring on the user's laptop, within directories the user has allowed.",
    parameters: {
      type: "object",
      properties: {
        query: { type: "string", description: "Text to search for inside files." },
        root: { type: "string", description: "Optional directory to search under." },
        limit: { type: "number", description: "Max matches to return (default 20)." },
      },
      required: ["query"],
    },
  },
  read_file: {
    name: "read_file",
    description:
      "Read the contents of a specific text file on the user's laptop (truncated if large).",
    parameters: {
      type: "object",
      properties: {
        path: { type: "string", description: "Absolute path to the file." },
        max_bytes: {
          type: "number",
          description: "Max bytes to read (default 20000).",
        },
      },
      required: ["path"],
    },
  },
  list_directory: {
    name: "list_directory",
    description:
      "List the immediate contents (files and subfolders) of a directory on the " +
      "user's machine, within directories the user has allowed. Use this to see " +
      "what's actually in a folder (e.g. Downloads) before deciding what to read " +
      "or summarize.",
    parameters: {
      type: "object",
      properties: {
        root: {
          type: "string",
          description:
            "Directory to list, e.g. '~/Downloads' or an absolute path (defaults " +
            "to the user's home directory).",
        },
        limit: {
          type: "number",
          description: "Max entries to return (default 100).",
        },
      },
      required: [],
    },
  },
  summarize_directory: {
    name: "summarize_directory",
    description:
      "Read the text files directly inside a directory (not subfolders) so you " +
      "can summarize them for the user — e.g. 'summarize the files in my " +
      "Downloads folder'. Binary files (images, PDFs, archives, etc.) are " +
      "automatically skipped and listed as skipped rather than read. After " +
      "calling this, write an actual summary in your own words — don't just " +
      "dump the raw file contents back at the user.",
    parameters: {
      type: "object",
      properties: {
        root: {
          type: "string",
          description:
            "Directory whose files to read, e.g. '~/Downloads' or an absolute path.",
        },
        limit: {
          type: "number",
          description: "Max number of files to read (default 10, max 25).",
        },
      },
      required: ["root"],
    },
  },
};

// These tools always require an explicit Allow/Deny before running (they
// read the user's filesystem) — host projects should merge this into
// their own confirm-required set.
const CONFIRM_REQUIRED_TOOLS = Object.keys(toolDefinitions);

// Human-readable one-liner describing a tool call, for confirmation
// prompts + history. Returns undefined for names this module doesn't own,
// so the host can fall back to its own switch for host-specific tools.
function describeToolCall(name, args) {
  switch (name) {
    case "find_files":
      return `find files named like "${args.query}"${args.root ? ` under ${args.root}` : ""}`;
    case "search_files":
      return `search file contents for "${args.query}"${
        args.root ? ` under ${args.root}` : ""
      }`;
    case "read_file":
      return `read the file ${args.path}`;
    case "list_directory":
      return `list the contents of ${args.root || "your home directory"}`;
    case "summarize_directory":
      return `read and summarize the files in ${args.root}`;
    default:
      return undefined;
  }
}

// Builds the { method, path, searchParams } needed to call one of this
// module's routes on the tools-agent — the host prepends its own
// TOOLS_URL, adds its auth header, and performs the actual fetch (keeping
// timeout/error-handling conventions under the host's control). Returns
// null for names this module doesn't own, so the host can fall back to
// its own dispatch for host-specific tools.
function buildRequest(name, rawArgs) {
  const args = rawArgs || {};
  switch (name) {
    case "find_files": {
      const searchParams = new URLSearchParams({ q: args.query || "" });
      if (args.root) searchParams.set("root", args.root);
      if (args.limit) searchParams.set("limit", String(args.limit));
      return { method: "GET", path: "/find", searchParams };
    }
    case "search_files": {
      const searchParams = new URLSearchParams({ q: args.query || "" });
      if (args.root) searchParams.set("root", args.root);
      if (args.limit) searchParams.set("limit", String(args.limit));
      return { method: "GET", path: "/search", searchParams };
    }
    case "read_file": {
      const searchParams = new URLSearchParams({ path: args.path || "" });
      if (args.max_bytes) searchParams.set("max", String(args.max_bytes));
      return { method: "GET", path: "/read", searchParams };
    }
    case "list_directory": {
      const searchParams = new URLSearchParams();
      if (args.root) searchParams.set("root", args.root);
      if (args.limit) searchParams.set("limit", String(args.limit));
      return { method: "GET", path: "/list", searchParams };
    }
    case "summarize_directory": {
      const searchParams = new URLSearchParams({ root: args.root || "" });
      if (args.limit) searchParams.set("limit", String(args.limit));
      return { method: "GET", path: "/read-dir", searchParams };
    }
    default:
      return null;
  }
}

module.exports = {
  findFiles,
  searchFiles,
  readFileSafe,
  listDirectory,
  readDirectory,
  registerRoutes,
  toolDefinitions,
  CONFIRM_REQUIRED_TOOLS,
  describeToolCall,
  buildRequest,
};
