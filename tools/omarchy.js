"use strict";

// Omarchy Linux desktop integration: status, theme list/set, creating
// custom themes (from raw colors.toml, a background image/URL, or
// auto-extracted from a local image's dominant colors), and a generic
// passthrough for any `omarchy <args...>` command. Framework-agnostic
// like notes.js/files.js — the host project injects its own filesystem-
// sandboxing helpers (`resolveInputPath`/`isAllowed`, used for background
// images) and HTTP helpers via opts; state/theme directory paths below
// are standard Omarchy conventions (not project-specific), so they're not
// injected.
//
// Usage (host project's tools-agent):
//
//   const omarchyTool = require("../shared/tools/omarchy");
//   omarchyTool.registerRoutes(router, { send, readJsonBody, resolveInputPath, isAllowed });

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync, spawn } = require("node:child_process");
const imageColorsTool = require("./imageColors");

const OMARCHY_STATE_DIR = path.join(os.homedir(), ".local/state/omarchy/current");

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


function hyprctlJson(args) {
  try {
    const out = execFileSync("hyprctl", ["-j", ...args], {
      encoding: "utf8",
      timeout: 5000,
    });
    return JSON.parse(out);
  } catch {
    return null;
  }
}

function omarchyStatus() {
  let theme = "unknown";
  try {
    theme = fs.readFileSync(path.join(OMARCHY_STATE_DIR, "theme.name"), "utf8").trim();
  } catch {
    // best-effort only
  }

  const activeWorkspace = hyprctlJson(["activeworkspace"]);
  const clients = hyprctlJson(["clients"]) || [];
  const monitors = hyprctlJson(["monitors"]) || [];
  const activeClient = hyprctlJson(["activewindow"]);

  return {
    theme,
    activeWorkspace: activeWorkspace
      ? { id: activeWorkspace.id, name: activeWorkspace.name, monitor: activeWorkspace.monitor }
      : null,
    activeWindow: activeClient
      ? { class: activeClient.class, title: activeClient.title }
      : null,
    monitors: monitors.map((m) => ({
      name: m.name,
      activeWorkspace: m.activeWorkspace && m.activeWorkspace.name,
      focused: Boolean(m.focused),
    })),
    windowCount: clients.length,
  };
}

function omarchyThemeList() {
  const out = execFileSync("omarchy-theme-list", [], {
    encoding: "utf8",
    timeout: 5000,
  });
  return out
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
}

function omarchySetTheme(themeName) {
  // Validate against the actual installed theme list first, so we only ever
  // pass a known-good value to execFile (no shell involved either way, but
  // this also gives a clean error instead of omarchy-theme-set's own).
  const available = omarchyThemeList();
  if (!available.includes(themeName)) {
    throw new Error(`Unknown theme "${themeName}". Available: ${available.join(", ")}`);
  }
  execFileSync("omarchy-theme-set", [themeName], { timeout: 10000 });
  return { theme: themeName };
}

const OMARCHY_THEMES_DIR = path.join(os.homedir(), ".config", "omarchy", "themes");

// Matches the skill's guidance: "Unsure if command exists? Run `omarchy
// commands`" — exposed as its own read-only, no-confirmation tool so the
// LLM can self-discover what's available instead of guessing at
// arguments for omarchy_command.
function omarchyListCommands() {
  const out = execFileSync("omarchy", ["commands", "--json"], {
    encoding: "utf8",
    timeout: 8000,
  });
  try {
    return JSON.parse(out);
  } catch {
    // Fall back to the plain-text listing if --json isn't supported by
    // this Omarchy version.
    return { raw: out };
  }
}

// Generic, synchronous passthrough for any `omarchy <args...>` invocation
// (theme/font/refresh/restart/toggle/bar/plugin/hook/reminder/capture/
// launch/system lock, etc.) — everything the skill documents as a "stock
// omarchy command". Deliberately NOT restricted to an allowlist of
// subcommands: `execFile` passes `args` straight to the kernel as an
// argv array (no shell is ever involved), so there's no injection surface
// regardless of content, and the caller (lib/tools.js) always requires
// explicit user Allow/Deny confirmation before invoking this, showing the
// literal command about to run. Only suitable for commands that finish
// quickly and don't need interactive stdin (e.g. NOT `omarchy setup ...`
// wizards) — use omarchyCommandBackground for slow ones (update, install,
// pkg add, theme install, reinstall).
function omarchyCommand(argv, { timeoutMs = 20000 } = {}) {
  if (!Array.isArray(argv) || argv.length === 0 || argv.some((a) => typeof a !== "string")) {
    throw new Error("argv must be a non-empty array of strings, e.g. [\"theme\", \"set\", \"catppuccin\"]");
  }
  const commandLabel = `omarchy ${argv.join(" ")}`;
  try {
    const stdout = execFileSync("omarchy", argv, {
      encoding: "utf8",
      timeout: timeoutMs,
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { command: commandLabel, stdout: stdout.trim() };
  } catch (err) {
    if (err.signal === "SIGTERM" || err.killed) {
      throw new Error(
        `\`${commandLabel}\` timed out after ${timeoutMs}ms — it may be waiting on ` +
          "interactive input (unsupported here) or is slow; try omarchy_command_background instead."
      );
    }
    const stderr = (err.stderr || "").toString().trim();
    throw new Error(stderr || `\`${commandLabel}\` failed (exit ${err.status ?? "?"})`);
  }
}

// For slow/long-running omarchy commands (system update, package installs,
// theme install from a git repo, full config reinstall) that would
// otherwise block the HTTP request past any reasonable timeout. Mirrors
// lib/update.js's approach: spawn detached, redirect output to a log file
// in the OS temp dir, return immediately. The caller can check back later
// by asking to read the log file (via the existing read_file tool) if
// they want to see progress/output.
function omarchyCommandBackground(argv) {
  if (!Array.isArray(argv) || argv.length === 0 || argv.some((a) => typeof a !== "string")) {
    throw new Error("argv must be a non-empty array of strings, e.g. [\"update\"]");
  }
  const commandLabel = `omarchy ${argv.join(" ")}`;
  const logPath = path.join(os.tmpdir(), `omarchy-cmd-${Date.now()}.log`);
  const logFd = fs.openSync(logPath, "a");
  const child = spawn("omarchy", argv, {
    detached: true,
    stdio: ["ignore", logFd, logFd],
  });
  child.unref();
  return { started: true, command: commandLabel, logFile: logPath };
}

// name must be a plain slug — no path separators or traversal — since it
// becomes a directory name directly under ~/.config/omarchy/themes/.
const THEME_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9 ._-]{0,63}$/;

// omarchy-theme-set derives the directory it looks for by lowercasing the
// name it's given and turning spaces into dashes (see
// /usr/share/omarchy/bin/omarchy-theme-set: `tr '[:upper:]' '[:lower:]' | tr
// ' ' '-'`) — e.g. `omarchy theme set "Lain"` looks for a directory literally
// named "lain", not "Lain". If we created the theme directory using whatever
// case/spacing the user or model happened to type, applying it later would
// fail with "Theme '...' does not exist" on a case-sensitive filesystem even
// though the directory is right there. Normalizing the directory name up
// front (at creation time) keeps it consistent with what every future
// `omarchy theme set <name>` invocation will actually go looking for.
function normalizeThemeName(name) {
  return String(name).trim().toLowerCase().replace(/\s+/g, "-");
}

function omarchyThemeDir(name) {
  if (!THEME_NAME_RE.test(name)) {
    throw new Error(
      "Invalid theme name — use letters, numbers, spaces, '.', '_', '-' only (no slashes)."
    );
  }
  const normalized = normalizeThemeName(name);
  const dir = path.resolve(OMARCHY_THEMES_DIR, normalized);
  if (path.dirname(dir) !== OMARCHY_THEMES_DIR) {
    throw new Error("Invalid theme name.");
  }
  return { dir, name: normalized };
}

// Creates (or overlays onto) a custom theme under ~/.config/omarchy/themes/
// per theming.md: a directory containing at minimum a colors.toml, plus
// optionally a background image — either downloaded from a public URL
// (backgroundUrl) or copied straight from a local file already on this
// machine (backgroundPath, e.g. something the user saved to ~/Downloads —
// no hosting required, it's read through the same allowed-roots sandbox as
// every other file-path tool). Never touches /usr/share/omarchy/ (stock
// themes) — this only ever writes into the user's own config dir. If
// `apply` is set, switches to the new theme immediately afterward via the
// same validated omarchySetTheme path.
async function omarchyCreateTheme(
  { name, colorsToml, backgroundUrl, backgroundPath, apply },
  pathOpts = {}
) {
  if (!name) throw new Error("name is required");
  const { dir, name: normalizedName } = omarchyThemeDir(name);
  fs.mkdirSync(dir, { recursive: true });

  const written = [];
  if (colorsToml) {
    const colorsPath = path.join(dir, "colors.toml");
    fs.writeFileSync(colorsPath, colorsToml, "utf8");
    written.push("colors.toml");
  }

  if (backgroundPath) {
    const resolved = imageColorsTool.resolveImagePath(backgroundPath, pathOpts);
    const bgDir = path.join(dir, "backgrounds");
    fs.mkdirSync(bgDir, { recursive: true });
    const ext = path.extname(resolved) || ".jpg";
    const bgPath = path.join(bgDir, `background${ext}`);
    fs.copyFileSync(resolved, bgPath);
    written.push(`backgrounds/background${ext}`);
  } else if (backgroundUrl) {
    const bgDir = path.join(dir, "backgrounds");
    fs.mkdirSync(bgDir, { recursive: true });
    const res = await fetch(backgroundUrl, { signal: AbortSignal.timeout(15000) });
    if (!res.ok) {
      throw new Error(`Failed to download background (HTTP ${res.status}): ${backgroundUrl}`);
    }
    const contentType = res.headers.get("content-type") || "";
    const ext =
      (contentType.includes("png") && ".png") ||
      (contentType.includes("webp") && ".webp") ||
      (contentType.includes("gif") && ".gif") ||
      ".jpg";
    const bgPath = path.join(bgDir, `background${ext}`);
    const buf = Buffer.from(await res.arrayBuffer());
    fs.writeFileSync(bgPath, buf);
    written.push(`backgrounds/background${ext}`);
  }

  let applied = false;
  if (apply) {
    execFileSync("omarchy-theme-set", [normalizedName], { timeout: 10000 });
    applied = true;
  }

  return { theme: normalizedName, dir, written, applied };
}

// One-shot "make a theme out of this picture": extracts a dominant-color
// palette from a local image file (no public URL needed), auto-generates a
// full colors.toml from it, creates the theme with that same image as its
// background, and optionally applies it immediately.
async function omarchyCreateThemeFromImage({ name, imagePath, apply, count }, pathOpts = {}) {
  if (!name) throw new Error("name is required");
  if (!imagePath) throw new Error("imagePath is required");
  const generated = imageColorsTool.themeFromImage(imagePath, { count, ...pathOpts });
  const result = await omarchyCreateTheme(
    {
      name,
      colorsToml: generated.colorsToml,
      backgroundPath: generated.imagePath,
      apply,
    },
    pathOpts
  );
  return { ...result, colors: generated.colors, palette: generated.palette };
}

function registerRoutes(router, opts = {}) {
  const send = opts.send || defaultSend;
  const readJsonBody = opts.readJsonBody || defaultReadJsonBody;
  const pathOpts = { resolveInputPath: opts.resolveInputPath, isAllowed: opts.isAllowed };

  router.get("/omarchy/status", (req, res) => send(res, 200, omarchyStatus()));

  router.get("/omarchy/themes", (req, res) =>
    send(res, 200, { themes: omarchyThemeList() })
  );

  router.get("/omarchy/commands", (req, res) => {
    try {
      send(res, 200, omarchyListCommands());
    } catch (err) {
      send(res, 500, { error: err.message });
    }
  });

  router.post("/omarchy/theme", async (req, res) => {
    const { theme } = await readJsonBody(req);
    if (!theme) return send(res, 400, { error: "theme is required" });
    try {
      send(res, 200, omarchySetTheme(theme));
    } catch (err) {
      send(res, 500, { error: err.message });
    }
  });

  router.post("/omarchy/theme/create", async (req, res) => {
    const body = await readJsonBody(req);
    if (!body.name) return send(res, 400, { error: "name is required" });
    try {
      send(res, 200, await omarchyCreateTheme(body, pathOpts));
    } catch (err) {
      send(res, 500, { error: err.message });
    }
  });

  router.post("/omarchy/image/colors", async (req, res) => {
    const { path: imagePath, count } = await readJsonBody(req);
    if (!imagePath) return send(res, 400, { error: "path is required" });
    try {
      send(res, 200, imageColorsTool.extractImageColors(imagePath, { count, ...pathOpts }));
    } catch (err) {
      send(res, 500, { error: err.message });
    }
  });

  router.post("/omarchy/theme/from-image", async (req, res) => {
    const body = await readJsonBody(req);
    if (!body.name) return send(res, 400, { error: "name is required" });
    if (!body.imagePath) return send(res, 400, { error: "imagePath is required" });
    try {
      send(res, 200, await omarchyCreateThemeFromImage(body, pathOpts));
    } catch (err) {
      send(res, 500, { error: err.message });
    }
  });

  router.post("/omarchy/command", async (req, res) => {
    const { argv } = await readJsonBody(req);
    try {
      send(res, 200, omarchyCommand(argv));
    } catch (err) {
      send(res, 500, { error: err.message });
    }
  });

  router.post("/omarchy/command/background", async (req, res) => {
    const { argv } = await readJsonBody(req);
    try {
      send(res, 200, omarchyCommandBackground(argv));
    } catch (err) {
      send(res, 500, { error: err.message });
    }
  });
}

module.exports = {
  hyprctlJson,
  omarchyStatus,
  omarchyThemeList,
  omarchySetTheme,
  omarchyListCommands,
  omarchyCommand,
  omarchyCommandBackground,
  omarchyCreateTheme,
  omarchyCreateThemeFromImage,
  registerRoutes,
};

