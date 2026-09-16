"use strict";

// Network diagnostic tools: ping, DNS lookup, traceroute, whois, a basic
// TCP port scan/service check, a LAN device scan, and a speed test.
// Framework-agnostic like notes.js/files.js — no filesystem/config deps
// at all, so the host project only needs to inject an HTTP `send` helper
// (or omit it to use the small built-in fallback below).
//
// None of these are path-restricted (they don't read the filesystem) —
// but every external command runs via execFile with a fixed binary and
// argument array (no shell, no string interpolation), and the target
// itself is validated before being handed to any binary, so there's no
// way to smuggle extra flags in via a hostname like "-oProxyCommand=...".
//
// These are meant to run on the tools-agent (the user's own laptop)
// rather than inside a Docker container, so "local network" actually
// means the user's LAN — not whatever network namespace the container
// happens to be attached to. That's a host-project deployment choice,
// not something enforced by this module.
//
// Usage (host project's tools-agent):
//
//   const networkTool = require("../shared/tools/network");
//   networkTool.registerRoutes(router, { send });

const dns = require("node:dns");
const net = require("node:net");
const os = require("node:os");
const { execFile, execFileSync } = require("node:child_process");
const { promisify } = require("node:util");

const execFileAsync = promisify(execFile);

function defaultSend(res, status, body) {
  const json = JSON.stringify(body);
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(json);
}

const PING_TIMEOUT_MS = 15000;
const TRACEROUTE_TIMEOUT_MS = 30000;
const WHOIS_TIMEOUT_MS = 15000;
const MAX_PING_COUNT = 10;
const MAX_TRACEROUTE_HOPS = 30;
const MAX_PORT_SCAN_PORTS = 256;
const PORT_SCAN_CONNECT_TIMEOUT_MS = 800;
const PORT_SCAN_CONCURRENCY = 32;
const MAX_LAN_SCAN_HOSTS = 254; // a /24, the common home-network size
const LAN_SWEEP_CONCURRENCY = 32;
const LAN_SWEEP_PING_TIMEOUT_S = 1;
const LAN_REVERSE_DNS_TIMEOUT_MS = 1500;
const SPEED_TEST_DOWNLOAD_BYTES = 25_000_000; // 25MB
const SPEED_TEST_UPLOAD_BYTES = 5_000_000; // 5MB
const SPEED_TEST_TIMEOUT_MS = 30000;
const CHECK_PORT_CONNECT_TIMEOUT_MS = 2000;
const CHECK_PORT_BANNER_TIMEOUT_MS = 1000;

// Common ports -> service name, purely for a friendlier check_port result
// (not used for anything security-sensitive).
const WELL_KNOWN_PORTS = {
  20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
  80: "http", 110: "pop3", 123: "ntp", 143: "imap", 161: "snmp", 389: "ldap",
  443: "https", 445: "smb", 465: "smtps", 587: "smtp-submission",
  631: "ipp", 993: "imaps", 995: "pop3s", 1433: "mssql", 1883: "mqtt",
  2049: "nfs", 3000: "http-alt", 3306: "mysql", 3389: "rdp", 5000: "http-alt",
  5432: "postgres", 5900: "vnc", 6379: "redis", 8000: "http-alt",
  8080: "http-alt", 8443: "https-alt", 8888: "http-alt", 9000: "http-alt",
  9200: "elasticsearch", 27017: "mongodb",
};

// A conservative allowlist for hostnames/IPs handed to execFile'd binaries.
// Blocks anything that could look like a flag (leading "-") or contain
// shell-metacharacter-adjacent junk, without needing a full RFC-1123
// validator — execFile already prevents shell injection, this is just
// about not letting a hostname be misread as an extra CLI flag.
const HOST_PATTERN = /^[a-zA-Z0-9](?:[a-zA-Z0-9.:_-]{0,253}[a-zA-Z0-9])?$/;

function assertValidHost(host) {
  const h = String(host || "").trim();
  if (!h) throw new Error("host is required");
  if (!HOST_PATTERN.test(h)) throw new Error("invalid host/IP");
  return h;
}

function commandAvailable(bin) {
  try {
    execFileSync("which", [bin], { timeout: 3000, stdio: ["ignore", "ignore", "ignore"] });
    return true;
  } catch {
    return false;
  }
}

// --- ping ------------------------------------------------------------------

function pingHost(host, count) {
  const target = assertValidHost(host);
  const n = Math.min(Math.max(Number(count) || 4, 1), MAX_PING_COUNT);
  let out;
  try {
    out = execFileSync("ping", ["-c", String(n), "-W", "2", target], {
      encoding: "utf8",
      timeout: PING_TIMEOUT_MS,
    });
  } catch (err) {
    // ping exits non-zero on 100% packet loss but still writes useful
    // output to stdout — surface that instead of just "command failed".
    out = err.stdout || "";
    if (!out) throw new Error(err.message);
  }
  const lossMatch = out.match(/(\d+(?:\.\d+)?)% packet loss/);
  const rttMatch = out.match(/= ([\d.]+)\/([\d.]+)\/([\d.]+)\/([\d.]+)/);
  return {
    host: target,
    raw: out.trim(),
    packetLossPercent: lossMatch ? Number(lossMatch[1]) : null,
    rttMs: rttMatch
      ? { min: Number(rttMatch[1]), avg: Number(rttMatch[2]), max: Number(rttMatch[3]), mdev: Number(rttMatch[4]) }
      : null,
  };
}

// --- DNS lookup --------------------------------------------------------------

async function dnsLookup(host) {
  const target = assertValidHost(host);
  const isIp = net.isIP(target) !== 0;

  if (isIp) {
    const hostnames = await dns.promises.reverse(target).catch(() => []);
    return { query: target, type: "PTR", hostnames };
  }

  const [a, aaaa, mx, txt, cname] = await Promise.all([
    dns.promises.resolve4(target).catch(() => []),
    dns.promises.resolve6(target).catch(() => []),
    dns.promises.resolveMx(target).catch(() => []),
    dns.promises.resolveTxt(target).catch(() => []),
    dns.promises.resolveCname(target).catch(() => []),
  ]);
  return { query: target, a, aaaa, mx, txt: txt.map((t) => t.join("")), cname };
}

// --- traceroute (via tracepath — no root required) --------------------------

function tracerouteHost(host, maxHops) {
  const target = assertValidHost(host);
  if (!commandAvailable("tracepath")) {
    throw new Error("tracepath is not installed on the tools-agent host");
  }
  const hops = Math.min(Math.max(Number(maxHops) || 20, 1), MAX_TRACEROUTE_HOPS);
  let out;
  try {
    out = execFileSync("tracepath", ["-m", String(hops), target], {
      encoding: "utf8",
      timeout: TRACEROUTE_TIMEOUT_MS,
    });
  } catch (err) {
    out = err.stdout || "";
    if (!out) throw new Error(err.message);
  }
  const hopLines = out
    .trim()
    .split("\n")
    .filter((l) => /^\s*\d+[?:]/.test(l))
    .map((l) => l.trim());
  return { host: target, hops: hopLines, raw: out.trim() };
}

// --- whois -------------------------------------------------------------------

function whoisLookup(query) {
  const target = assertValidHost(query);
  if (!commandAvailable("whois")) {
    throw new Error("whois is not installed on the tools-agent host");
  }
  const out = execFileSync("whois", [target], {
    encoding: "utf8",
    timeout: WHOIS_TIMEOUT_MS,
    maxBuffer: 2 * 1024 * 1024,
  });
  // Whois records vary wildly by registrar; just trim obvious legal
  // boilerplate/blank padding and cap length rather than trying to
  // parse every registrar's format.
  const trimmed = out
    .split("\n")
    .filter((l) => !/^%|^#/.test(l.trim()))
    .join("\n")
    .trim();
  return { query: target, raw: trimmed.slice(0, 8000) };
}

// --- port scan (plain TCP connect scan, no nmap dependency) -----------------

function parsePortList(portsArg) {
  const ports = new Set();
  const raw = String(portsArg || "").trim();
  if (!raw) return [80, 443, 22, 21, 25, 3306, 5432, 6379, 8080, 8443];
  for (const part of raw.split(",")) {
    const p = part.trim();
    const rangeMatch = p.match(/^(\d+)-(\d+)$/);
    if (rangeMatch) {
      const start = Number(rangeMatch[1]);
      const end = Number(rangeMatch[2]);
      for (let i = start; i <= end; i++) ports.add(i);
    } else if (/^\d+$/.test(p)) {
      ports.add(Number(p));
    }
  }
  return [...ports].filter((p) => p >= 1 && p <= 65535);
}

function checkPort(host, port) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;
    const finish = (state) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ port, state });
    };
    socket.setTimeout(PORT_SCAN_CONNECT_TIMEOUT_MS);
    socket.once("connect", () => finish("open"));
    socket.once("timeout", () => finish("filtered"));
    socket.once("error", () => finish("closed"));
    socket.connect(port, host);
  });
}

async function portScan(host, portsArg) {
  const target = assertValidHost(host);
  let ports = parsePortList(portsArg);
  if (ports.length > MAX_PORT_SCAN_PORTS) {
    throw new Error(`too many ports requested (max ${MAX_PORT_SCAN_PORTS})`);
  }
  const results = [];
  for (let i = 0; i < ports.length; i += PORT_SCAN_CONCURRENCY) {
    const batch = ports.slice(i, i + PORT_SCAN_CONCURRENCY);
    const batchResults = await Promise.all(batch.map((p) => checkPort(target, p)));
    results.push(...batchResults);
  }
  results.sort((a, b) => a.port - b.port);
  return {
    host: target,
    scanned: results.length,
    open: results.filter((r) => r.state === "open").map((r) => r.port),
    results,
  };
}

// --- check a single port/service (like portScan's checkPort, but also ---
// --- grabs a banner if the service offers one, and names the service) ---

function checkPortWithBanner(host, port) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;
    let banner = "";
    const finish = (state) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ port, state, banner: banner || null });
    };
    socket.setTimeout(CHECK_PORT_CONNECT_TIMEOUT_MS);
    socket.once("connect", () => {
      // Some services (SSH, SMTP, FTP) greet immediately on connect; give
      // it a brief window to speak first before we give up on a banner.
      // Drop the connect-phase timeout listener first — otherwise it's
      // still attached and would wrongly report "filtered" once the new,
      // shorter banner timeout below fires.
      socket.removeAllListeners("timeout");
      socket.setTimeout(CHECK_PORT_BANNER_TIMEOUT_MS);
      socket.once("data", (chunk) => {
        banner = chunk.toString("utf8", 0, Math.min(chunk.length, 200)).trim();
        finish("open");
      });
      socket.once("timeout", () => finish("open")); // connected, just silent
    });
    socket.once("timeout", () => finish("filtered"));
    socket.once("error", () => finish("closed"));
    socket.connect(port, host);
  });
}

async function checkPortService(host, portArg) {
  const target = assertValidHost(host);
  const port = Number(portArg);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("a single valid port (1-65535) is required");
  }
  const result = await checkPortWithBanner(target, port);
  return {
    host: target,
    port,
    service: WELL_KNOWN_PORTS[port] || "unknown",
    ...result,
  };
}

// --- LAN device scan (ping sweep + ARP/neighbor table, no arp-scan/nmap) ---

// Figures out the /24 to scan: an explicit "a.b.c.0/24" (or bare
// "a.b.c.0") argument, or auto-detected from the first non-internal IPv4
// interface. Deliberately only ever supports /24 (254 hosts) — plenty for
// a home LAN, and keeps a "scan the network" request from ever turning
// into scanning something much bigger by mistake.
function resolveScanSubnet(subnetArg) {
  const raw = String(subnetArg || "").trim();
  if (raw) {
    const base = raw.split("/")[0];
    const octets = base.split(".");
    if (octets.length !== 4 || octets.some((o) => !/^\d{1,3}$/.test(o) || Number(o) > 255)) {
      throw new Error("subnet must look like e.g. 192.168.1.0/24 or 192.168.1.0");
    }
    return octets.slice(0, 3).join(".");
  }
  for (const ifaces of Object.values(os.networkInterfaces())) {
    for (const iface of ifaces || []) {
      if (iface.family === "IPv4" && !iface.internal) {
        return iface.address.split(".").slice(0, 3).join(".");
      }
    }
  }
  throw new Error("couldn't auto-detect a local IPv4 network — pass subnet explicitly");
}

// Sends one best-effort ping to every host in the /24 (concurrency-
// limited) purely to populate the OS's ARP/neighbor table — we don't use
// the ping results themselves, since plenty of devices block ICMP but
// still show up in `ip neigh` once they've replied to an ARP request.
async function pingSweep(base) {
  const ips = [];
  for (let i = 1; i <= MAX_LAN_SCAN_HOSTS; i++) ips.push(`${base}.${i}`);
  for (let i = 0; i < ips.length; i += LAN_SWEEP_CONCURRENCY) {
    const batch = ips.slice(i, i + LAN_SWEEP_CONCURRENCY);
    await Promise.all(
      batch.map((ip) =>
        execFileAsync("ping", ["-c", "1", "-W", String(LAN_SWEEP_PING_TIMEOUT_S), ip], {
          timeout: (LAN_SWEEP_PING_TIMEOUT_S + 1) * 1000,
        }).catch(() => {})
      )
    );
  }
}

async function readNeighborTable(base) {
  let out;
  try {
    out = execFileSync("ip", ["neigh", "show"], { encoding: "utf8", timeout: 5000 });
  } catch (err) {
    throw new Error(`couldn't read the neighbor table: ${err.message}`);
  }
  return out
    .split("\n")
    .map((line) => {
      const m = line.match(/^(\S+)\s+dev\s+(\S+)\s+lladdr\s+(\S+)\s+(\S+)/);
      if (!m) return null;
      const [, ip, iface, mac, state] = m;
      if (!ip.startsWith(`${base}.`)) return null;
      if (!["REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT"].includes(state)) return null;
      return { ip, iface, mac, state };
    })
    .filter(Boolean);
}

async function lanDeviceScan(subnetArg) {
  const base = resolveScanSubnet(subnetArg);
  await pingSweep(base);
  const devices = await readNeighborTable(base);
  await Promise.all(
    devices.map(async (d) => {
      try {
        const hostnames = await Promise.race([
          dns.promises.reverse(d.ip),
          new Promise((_, reject) =>
            setTimeout(() => reject(new Error("timeout")), LAN_REVERSE_DNS_TIMEOUT_MS)
          ),
        ]);
        d.hostname = hostnames[0] || null;
      } catch {
        d.hostname = null;
      }
    })
  );
  devices.sort((a, b) => Number(a.ip.split(".")[3]) - Number(b.ip.split(".")[3]));
  return { subnet: `${base}.0/24`, deviceCount: devices.length, devices };
}

// --- speed test (download/upload throughput via Cloudflare's public, ---
// --- no-auth speed-test endpoints — no local iperf/speedtest-cli needed) ---

async function speedTest() {
  const downloadUrl = `https://speed.cloudflare.com/__down?bytes=${SPEED_TEST_DOWNLOAD_BYTES}`;
  const t0 = Date.now();
  const downRes = await fetch(downloadUrl, { signal: AbortSignal.timeout(SPEED_TEST_TIMEOUT_MS) });
  if (!downRes.ok) throw new Error(`speed-test download failed: HTTP ${downRes.status}`);
  const downBuf = await downRes.arrayBuffer();
  const downSeconds = (Date.now() - t0) / 1000;
  const downloadMbps = (downBuf.byteLength * 8) / downSeconds / 1_000_000;

  const uploadBody = Buffer.alloc(SPEED_TEST_UPLOAD_BYTES, 0);
  const t1 = Date.now();
  const upRes = await fetch("https://speed.cloudflare.com/__up", {
    method: "POST",
    body: uploadBody,
    signal: AbortSignal.timeout(SPEED_TEST_TIMEOUT_MS),
  });
  if (!upRes.ok) throw new Error(`speed-test upload failed: HTTP ${upRes.status}`);
  await upRes.arrayBuffer().catch(() => {});
  const upSeconds = (Date.now() - t1) / 1000;
  const uploadMbps = (uploadBody.byteLength * 8) / upSeconds / 1_000_000;

  return {
    downloadMbps: Math.round(downloadMbps * 10) / 10,
    uploadMbps: Math.round(uploadMbps * 10) / 10,
    downloadBytes: downBuf.byteLength,
    uploadBytes: uploadBody.byteLength,
  };
}

function registerRoutes(router, opts = {}) {
  const send = opts.send || defaultSend;

  router.any("/ping", (req, res, url) => {
    const host = url.searchParams.get("host") || "";
    const count = url.searchParams.get("count");
    try {
      return send(res, 200, pingHost(host, count));
    } catch (err) {
      return send(res, 400, { error: err.message });
    }
  });

  router.any("/dns-lookup", (req, res, url) => {
    const host = url.searchParams.get("host") || "";
    return dnsLookup(host)
      .then((result) => send(res, 200, result))
      .catch((err) => send(res, 400, { error: err.message }));
  });

  router.any("/traceroute", (req, res, url) => {
    const host = url.searchParams.get("host") || "";
    const maxHops = url.searchParams.get("maxHops");
    try {
      return send(res, 200, tracerouteHost(host, maxHops));
    } catch (err) {
      return send(res, 400, { error: err.message });
    }
  });

  router.any("/whois", (req, res, url) => {
    const query = url.searchParams.get("query") || "";
    try {
      return send(res, 200, whoisLookup(query));
    } catch (err) {
      return send(res, 400, { error: err.message });
    }
  });

  router.any("/port-scan", (req, res, url) => {
    const host = url.searchParams.get("host") || "";
    const ports = url.searchParams.get("ports") || "";
    return portScan(host, ports)
      .then((result) => send(res, 200, result))
      .catch((err) => send(res, 400, { error: err.message }));
  });

  router.any("/check-port", (req, res, url) => {
    const host = url.searchParams.get("host") || "";
    const port = url.searchParams.get("port") || "";
    return checkPortService(host, port)
      .then((result) => send(res, 200, result))
      .catch((err) => send(res, 400, { error: err.message }));
  });

  router.any("/lan-scan", (req, res, url) => {
    const subnet = url.searchParams.get("subnet") || "";
    return lanDeviceScan(subnet)
      .then((result) => send(res, 200, result))
      .catch((err) => send(res, 400, { error: err.message }));
  });

  router.any("/speed-test", (req, res) => {
    return speedTest()
      .then((result) => send(res, 200, result))
      .catch((err) => send(res, 400, { error: err.message }));
  });
}

module.exports = {
  pingHost,
  dnsLookup,
  tracerouteHost,
  whoisLookup,
  portScan,
  checkPortService,
  lanDeviceScan,
  speedTest,
  registerRoutes,
};
