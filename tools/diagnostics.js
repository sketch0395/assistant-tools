"use strict";

// system_diagnostics: basic host health info (hostname, platform, uptime,
// load average, CPU count, memory, disk usage). Framework-agnostic — no
// config deps at all, so the host project only needs to inject an HTTP
// `send` helper (or omit it to use the small built-in fallback below).
//
// Usage (host project's tools-agent):
//
//   const diagnosticsTool = require("../shared/tools/diagnostics");
//   diagnosticsTool.registerRoutes(router, { send });

const os = require("node:os");
const { execFileSync } = require("node:child_process");

function defaultSend(res, status, body) {
  const json = JSON.stringify(body);
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(json);
}

function diagnostics() {
  let disk = "unavailable";
  try {
    disk = execFileSync("df", ["-h"], { encoding: "utf8", timeout: 5000 });
  } catch {
    // best-effort only
  }
  return {
    hostname: os.hostname(),
    platform: os.platform(),
    uptimeSeconds: Math.round(os.uptime()),
    loadavg: os.loadavg(),
    cpuCount: os.cpus().length,
    totalMemMB: Math.round(os.totalmem() / 1024 / 1024),
    freeMemMB: Math.round(os.freemem() / 1024 / 1024),
    disk,
  };
}

function registerRoutes(router, opts = {}) {
  const send = opts.send || defaultSend;
  router.any("/diagnostics", (req, res) => send(res, 200, diagnostics()));
}

module.exports = { diagnostics, registerRoutes };
