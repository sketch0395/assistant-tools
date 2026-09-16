"use strict";

// Desktop notifications via notify-send. Framework-agnostic — the host
// project injects its own app name (e.g. "Lain" or "Asuna") instead of
// this module hardcoding one.
//
// Usage (host project's tools-agent):
//
//   const notifyTool = require("../shared/tools/notify");
//   notifyTool.registerRoutes(router, { send, readJsonBody, appName: "Lain" });

const { execFileSync } = require("node:child_process");

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

// Best-effort desktop notification via notify-send. Fixed binary, args are
// passed as separate execFile arguments (no shell), so there's no
// injection risk even though title/body typically come from reminders.
// `appName` (e.g. "Lain"/"Asuna") is a fixed, host-supplied string — used
// as both the --app-name and the fallback title if none is given.
function notify(title, body, appName) {
  const name = appName || "Assistant";
  execFileSync("notify-send", [`--app-name=${name}`, title || name, body || ""], {
    timeout: 5000,
  });
}

function registerRoutes(router, opts = {}) {
  const send = opts.send || defaultSend;
  const readJsonBody = opts.readJsonBody || defaultReadJsonBody;
  const appName = opts.appName;

  router.post("/notify", async (req, res) => {
    try {
      const { title, body } = await readJsonBody(req);
      notify(title, body, appName);
      send(res, 200, { ok: true });
    } catch (err) {
      send(res, 500, { error: err.message });
    }
  });
}

module.exports = { notify, registerRoutes };
