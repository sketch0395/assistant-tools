"use strict";

// Self-update tool: kicks off scripts/update.sh (git pull + resync tools
// agent + rebuild/restart the app's Docker container) as a detached
// background process, so it can finish restarting the tools-agent itself
// without killing this HTTP response mid-flight. Framework-agnostic — the
// host project injects its own repo directory, product name (for error
// messages), and HTTP helpers via opts.
//
// Usage (host project's tools-agent):
//
//   const updateTool = require("../shared/tools/update");
//   updateTool.registerRoutes(router, {
//     repoDir: REPO_DIR,
//     repoDirEnvVar: "LAIN_REPO_DIR",
//     productName: "Lain",
//     send,
//   });

const os = require("node:os");
const fs = require("node:fs");
const path = require("node:path");
const { spawn } = require("node:child_process");

function defaultSend(res, status, body) {
  const json = JSON.stringify(body);
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(json);
}

function requireRepoDir(repoDir, repoDirEnvVar) {
  if (!repoDir) {
    throw new Error(
      `${repoDirEnvVar || "the repo dir"} is not configured on the tools agent — re-run ` +
        "scripts/setup-tools-agent.sh to set it."
    );
  }
  if (!fs.existsSync(path.join(repoDir, ".git"))) {
    throw new Error(`${repoDirEnvVar || "REPO_DIR"} (${repoDir}) doesn't look like a git repo.`);
  }
}

// opts: { repoDir, repoDirEnvVar, productName }
function startUpdate({ repoDir, repoDirEnvVar, productName } = {}) {
  requireRepoDir(repoDir, repoDirEnvVar);
  const scriptPath = path.join(repoDir, "scripts", "update.sh");
  if (!fs.existsSync(scriptPath)) {
    throw new Error("scripts/update.sh not found in the repo — pull the latest changes first.");
  }
  const logPath = path.join(
    os.tmpdir(),
    `${(productName || "assistant").toLowerCase()}-update-${Date.now()}.log`
  );
  const logFd = fs.openSync(logPath, "a");
  const child = spawn("bash", [scriptPath], {
    cwd: repoDir,
    detached: true,
    stdio: ["ignore", logFd, logFd],
  });
  child.unref();
  return { started: true, logFile: logPath };
}

function registerRoutes(router, opts = {}) {
  const send = opts.send || defaultSend;
  const { repoDir, repoDirEnvVar, productName } = opts;
  router.post("/update", (req, res) => {
    try {
      send(res, 200, startUpdate({ repoDir, repoDirEnvVar, productName }));
    } catch (err) {
      send(res, 500, { error: err.message });
    }
  });
}

module.exports = { requireRepoDir, startUpdate, registerRoutes };
