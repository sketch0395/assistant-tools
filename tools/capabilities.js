"use strict";

// One narrow, explicitly-scoped privilege-elevation action: granting
// tcpdump the packet-capture capabilities it needs for capture_packets to
// work without running the whole agent as root. This is intentionally NOT
// a general "run sudo command" endpoint — it only ever runs one fixed
// command with fixed arguments. Framework-agnostic — the host project
// injects its own HTTP helpers via opts.
//
// Security notes:
//   - The password is read once from the request body, piped directly to
//     `sudo -S` over stdin, and never written to a variable that outlives
//     this function, logged, echoed back in a response, or persisted
//     anywhere (not in the request log, not on disk).
//   - This is deliberately NOT wired up as an LLM-callable tool — it's
//     only reachable via a dedicated, non-chat UI flow in the host app,
//     so a user's sudo password never enters the model's context or the
//     conversation history.
//   - Still requires the normal bearer-token auth like every other
//     endpoint on this agent.
//
// Usage (host project's tools-agent):
//
//   const capabilitiesTool = require("../shared/tools/capabilities");
//   capabilitiesTool.registerRoutes(router, { send, readJsonBody });

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

function resolveBinaryPath(bin) {
  try {
    return execFileSync("which", [bin], { encoding: "utf8", timeout: 3000 }).trim();
  } catch {
    return null;
  }
}

// Runs `sudo -S setcap cap_net_raw,cap_net_admin+eip <tcpdump path>`,
// feeding `password` to sudo's stdin rather than passing it as an argument
// (which would leak it via `ps`/process listings).
function grantTcpdumpCapturePermission(password) {
  if (!password || typeof password !== "string") {
    throw new Error("password is required");
  }
  const tcpdumpPath = resolveBinaryPath("tcpdump");
  if (!tcpdumpPath) {
    throw new Error("tcpdump isn't installed — install it first, then try again.");
  }

  try {
    execFileSync(
      "sudo",
      ["-S", "-p", "", "setcap", "cap_net_raw,cap_net_admin+eip", tcpdumpPath],
      {
        input: `${password}\n`,
        timeout: 10000,
        stdio: ["pipe", "pipe", "pipe"],
      }
    );
  } catch (err) {
    const stderr = (err.stderr || "").toString();
    if (/incorrect password|sorry, try again/i.test(stderr)) {
      throw new Error("Incorrect password.");
    }
    if (/not in the sudoers|may not run sudo/i.test(stderr)) {
      throw new Error("This user isn't allowed to run sudo on this machine.");
    }
    if (/a password is required|no tty present/i.test(stderr)) {
      throw new Error(
        "sudo here requires an interactive terminal (tty) and refused the piped " +
          "password — this usually means a `requiretty` setting in /etc/sudoers. " +
          `Run \`sudo setcap cap_net_raw,cap_net_admin+eip ${tcpdumpPath}\` yourself ` +
          "in a terminal instead."
      );
    }
    throw new Error("Failed to grant capture permission — check the agent's logs.");
  }

  return { ok: true, path: tcpdumpPath };
}

function registerRoutes(router, opts = {}) {
  const send = opts.send || defaultSend;
  const readJsonBody = opts.readJsonBody || defaultReadJsonBody;
  router.post("/grant-capture-permission", async (req, res) => {
    const body = await readJsonBody(req);
    try {
      const result = grantTcpdumpCapturePermission(body.password);
      send(res, 200, result);
    } catch (err) {
      send(res, 400, { error: err.message });
    }
  });
}

module.exports = { grantTcpdumpCapturePermission, registerRoutes };
