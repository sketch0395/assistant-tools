"use strict";

// App-side network diagnostics/lookups: Ollama-compatible tool schemas that
// dispatch to the host project's laptop tools agent (ping/dns/traceroute/
// whois/port-scan/lan-scan/speed-test), plus Shodan lookups (a direct API
// call, independent of the laptop agent). This is the client/schema layer
// used by each host project's Next.js app (lib/tools/network.js) — NOT the
// same thing as tools/network.js in this repo, which is the tools-agent
// SERVER's own implementation of ping/traceroute/etc.
//
// Framework-agnostic like tools/threatIntel.js — the host project injects
// its own httpClient (fetchToolsAgent) and shodan adapter functions via the
// third `deps` argument to execute(), since the tools-agent URL/token env
// var names and the Shodan API key wiring are host-specific config, not
// something this module should know about directly.
//
// Usage (host project's lib/tools/network.js):
//
//   const sharedNetwork = require("../../tools-agent/shared/app-tools/network");
//   export const { CONFIRM_REQUIRED_TOOLS, CATEGORY_KEYWORDS, NAMES } = sharedNetwork;
//   export function getDefinitions(flags) {
//     return sharedNetwork.getDefinitions({ ...flags, shodanConfigured: shodanConfigured() });
//   }
//   export const describe = sharedNetwork.describe;
//   export function execute(name, args) {
//     return sharedNetwork.execute(name, args, {
//       fetchToolsAgent,
//       shodan: { shodanHostLookup, shodanSearch, shodanDnsLookup, shodanAccountInfo },
//     });
//   }

const shodanTool = require("../tools/shodan");

const CONFIRM_REQUIRED_TOOLS = new Set([
  "ping_host",
  "dns_lookup",
  "traceroute_host",
  "whois_lookup",
  "port_scan",
  "check_port",
  "lan_device_scan",
  "speed_test",
  ...shodanTool.CONFIRM_REQUIRED_TOOLS,
]);

const CATEGORY_KEYWORDS = [
  "ping", "dns", "resolve", "domain", "ip address", "traceroute",
  "trace route", "whois", "port", "lan", "local network", "network",
  "speed test", "bandwidth", "internet speed", "mbps", "shodan", "subnet",
  "wifi", "router", "reachable", "latency", "device",
];

// Hashing/pcap/strings can take a while on large files, and traceroute/
// whois/port-scan spend real wall-clock time waiting on the network — give
// all of these more room than the default 10s budget used by quick lookups.
const SLOW_TOOLS = new Set([
  "ping_host",
  "traceroute_host",
  "whois_lookup",
  "port_scan",
  "check_port",
  "lan_device_scan",
  "speed_test",
]);

const PING_HOST_DEF = {
  type: "function",
  function: {
    name: "ping_host",
    description:
      "Ping a host or IP (from the user's laptop) to check reachability and " +
      "latency — e.g. 'is my router up?' or 'ping google.com'.",
    parameters: {
      type: "object",
      properties: {
        host: { type: "string", description: "Hostname or IP to ping." },
        count: { type: "number", description: "Number of pings to send (default 4, max 10)." },
      },
      required: ["host"],
    },
  },
};

const DNS_LOOKUP_DEF = {
  type: "function",
  function: {
    name: "dns_lookup",
    description:
      "Resolve a hostname to its DNS records (A, AAAA, MX, TXT, CNAME) or, given " +
      "an IP, do a reverse (PTR) lookup — e.g. 'what IP does example.com resolve " +
      "to?' or 'what's the MX record for this domain?'.",
    parameters: {
      type: "object",
      properties: {
        host: { type: "string", description: "Hostname or IP to look up." },
      },
      required: ["host"],
    },
  },
};

const TRACEROUTE_HOST_DEF = {
  type: "function",
  function: {
    name: "traceroute_host",
    description:
      "Trace the network path (hop by hop) from the user's laptop to a host or " +
      "IP — useful for diagnosing where a connection is slow or failing.",
    parameters: {
      type: "object",
      properties: {
        host: { type: "string", description: "Hostname or IP to trace to." },
        max_hops: {
          type: "number",
          description: "Maximum number of hops to trace (default 20, max 30).",
        },
      },
      required: ["host"],
    },
  },
};

const WHOIS_LOOKUP_DEF = {
  type: "function",
  function: {
    name: "whois_lookup",
    description:
      "Look up WHOIS registration info for a domain or IP address (registrar, " +
      "owning organization, registration/expiry dates, name servers).",
    parameters: {
      type: "object",
      properties: {
        query: { type: "string", description: "Domain name or IP to look up." },
      },
      required: ["query"],
    },
  },
};

const PORT_SCAN_DEF = {
  type: "function",
  function: {
    name: "port_scan",
    description:
      "Scan a host or IP on the user's local network for open TCP ports — e.g. " +
      "'what ports are open on my NAS?' or 'check if port 22 is open on " +
      "192.168.1.50'. Defaults to a handful of common ports if none are given; " +
      "accepts specific ports and/or ranges (max 256 ports per scan).",
    parameters: {
      type: "object",
      properties: {
        host: { type: "string", description: "Hostname or IP to scan." },
        ports: {
          type: "string",
          description:
            "Comma-separated ports and/or ranges, e.g. '22,80,443' or " +
            "'1-1024'. Omit to scan a default set of common ports.",
        },
      },
      required: ["host"],
    },
  },
};

const CHECK_PORT_DEF = {
  type: "function",
  function: {
    name: "check_port",
    description:
      "Check whether a single specific port is open on a host — e.g. 'is port " +
      "22 open on my server?' or 'is my web server (port 80) up on " +
      "192.168.1.50?'. Identifies the well-known service name for that port " +
      "and grabs a short banner if the service offers one on connect (e.g. " +
      "SSH). For checking many ports at once, use port_scan instead.",
    parameters: {
      type: "object",
      properties: {
        host: { type: "string", description: "Hostname or IP to check." },
        port: { type: "number", description: "The single port to check (1-65535)." },
      },
      required: ["host", "port"],
    },
  },
};

const LAN_DEVICE_SCAN_DEF = {
  type: "function",
  function: {
    name: "lan_device_scan",
    description:
      "Discover devices currently on the user's local network (LAN) — IP, MAC " +
      "address, and hostname where resolvable — e.g. 'what devices are on my " +
      "network?' or 'find my NAS's IP address'. Auto-detects the local /24 " +
      "subnet unless one is given. Takes several seconds (does a ping sweep, " +
      "then reads the ARP/neighbor table, which also catches devices that " +
      "block ICMP ping but have otherwise been seen on the network).",
    parameters: {
      type: "object",
      properties: {
        subnet: {
          type: "string",
          description:
            "Optional /24 subnet to scan, e.g. '192.168.1.0'. Omit to " +
            "auto-detect the laptop's own local network.",
        },
      },
      required: [],
    },
  },
};

const SPEED_TEST_DEF = {
  type: "function",
  function: {
    name: "speed_test",
    description:
      "Run an internet speed test from the user's laptop (download/upload " +
      "throughput in Mbps) — e.g. 'check my internet speed' or 'how's my " +
      "bandwidth right now?'. Takes roughly 5-15 seconds.",
    parameters: { type: "object", properties: {}, required: [] },
  },
};

/** Tool definitions in this category — laptop-agent tools need toolsConfigured, Shodan tools just need a SHODAN_API_KEY. */
function getDefinitions({ toolsConfigured, shodanConfigured }) {
  const defs = [];
  if (toolsConfigured) {
    defs.push(
      PING_HOST_DEF,
      DNS_LOOKUP_DEF,
      TRACEROUTE_HOST_DEF,
      WHOIS_LOOKUP_DEF,
      PORT_SCAN_DEF,
      CHECK_PORT_DEF,
      LAN_DEVICE_SCAN_DEF,
      SPEED_TEST_DEF
    );
  }
  if (shodanConfigured) {
    defs.push(
      ...Object.values(shodanTool.toolDefinitions).map((fn) => ({
        type: "function",
        function: fn,
      }))
    );
  }
  return defs;
}

function describe(name, args) {
  switch (name) {
    case "ping_host":
      return `ping ${args.host}`;
    case "dns_lookup":
      return `look up DNS records for ${args.host}`;
    case "traceroute_host":
      return `trace the network route to ${args.host}`;
    case "whois_lookup":
      return `look up WHOIS info for ${args.query}`;
    case "port_scan":
      return `scan ${args.host} for open ports${args.ports ? ` (${args.ports})` : ""}`;
    case "check_port":
      return `check if port ${args.port} is open on ${args.host}`;
    case "lan_device_scan":
      return `scan your local network for devices${args.subnet ? ` (${args.subnet})` : ""}`;
    case "speed_test":
      return "run an internet speed test";
    default:
      return shodanTool.describeToolCall(name, args) || undefined;
  }
}

/**
 * @param {string} name
 * @param {object} args
 * @param {object} deps
 * @param {function} deps.fetchToolsAgent - host's lib/tools/httpClient.js fetchToolsAgent
 * @param {object} deps.shodan - host's lib/shodan.js: { shodanHostLookup, shodanSearch, shodanDnsLookup, shodanAccountInfo }
 */
async function execute(name, args, deps = {}) {
  const { fetchToolsAgent, shodan = {} } = deps;
  switch (name) {
    case "shodan_host_lookup":
      return shodan.shodanHostLookup(args.ip);
    case "shodan_search":
      return shodan.shodanSearch(args.query, { limit: args.limit });
    case "shodan_dns_lookup":
      return shodan.shodanDnsLookup(args.hostnames);
    case "shodan_account_info":
      return shodan.shodanAccountInfo();
    case "ping_host":
      return fetchToolsAgent(
        "/ping",
        { host: args.host, count: args.count },
        { timeoutMs: SLOW_TOOLS.has(name) ? 120000 : 10000 }
      );
    case "dns_lookup":
      return fetchToolsAgent("/dns-lookup", { host: args.host });
    case "traceroute_host":
      return fetchToolsAgent(
        "/traceroute",
        { host: args.host, maxHops: args.max_hops },
        { timeoutMs: 120000 }
      );
    case "whois_lookup":
      return fetchToolsAgent("/whois", { query: args.query }, { timeoutMs: 120000 });
    case "port_scan":
      return fetchToolsAgent(
        "/port-scan",
        { host: args.host, ports: args.ports },
        { timeoutMs: 120000 }
      );
    case "check_port":
      return fetchToolsAgent(
        "/check-port",
        { host: args.host, port: args.port },
        { timeoutMs: 120000 }
      );
    case "lan_device_scan":
      return fetchToolsAgent(
        "/lan-scan",
        { subnet: args.subnet },
        { timeoutMs: 120000 }
      );
    case "speed_test":
      return fetchToolsAgent("/speed-test", {}, { timeoutMs: 120000 });
    default:
      return undefined;
  }
}

const NAMES = new Set([
  "ping_host",
  "dns_lookup",
  "traceroute_host",
  "whois_lookup",
  "port_scan",
  "check_port",
  "lan_device_scan",
  "speed_test",
  "shodan_host_lookup",
  "shodan_search",
  "shodan_dns_lookup",
  "shodan_account_info",
]);

module.exports = {
  CONFIRM_REQUIRED_TOOLS,
  CATEGORY_KEYWORDS,
  getDefinitions,
  describe,
  execute,
  NAMES,
};
