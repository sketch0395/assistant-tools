"use strict";

// App-side laptop/system forensics: Ollama-compatible tool schemas that
// dispatch to the host project's laptop tools agent (files, processes,
// logs, packet captures). This is the client/schema layer used by each
// host project's Next.js app (lib/tools/forensics.js) — NOT the same thing
// as tools/forensics.js in this repo, which is the tools-agent SERVER's
// own implementation.
//
// Framework-agnostic like tools/threatIntel.js — the host project injects
// its own httpClient functions via the third `deps` argument to execute(),
// since the tools-agent URL/token env var names are host-specific config.
//
// Usage (host project's lib/tools/forensics.js):
//
//   const sharedForensics = require("../../tools-agent/shared/app-tools/forensics");
//   export const { CONFIRM_REQUIRED_TOOLS, CATEGORY_KEYWORDS, NAMES } = sharedForensics;
//   export const getDefinitions = sharedForensics.getDefinitions;
//   export const describe = sharedForensics.describe;
//   export function execute(name, args) {
//     return sharedForensics.execute(name, args, {
//       fetchToolsAgent, fetchToolsAgentRaw, postToolsAgent,
//     });
//   }

const filesTool = require("../tools/files");

const CONFIRM_REQUIRED_TOOLS = new Set([
  "system_diagnostics",
  ...filesTool.CONFIRM_REQUIRED_TOOLS,
  "hash_file",
  "file_metadata",
  "extract_strings",
  "list_processes",
  "network_connections",
  "search_logs",
  "recent_file_activity",
  "login_history",
  "analyze_pcap",
  "capture_packets",
]);

const CATEGORY_KEYWORDS = [
  "hash", "checksum", "sha256", "sha-256", "md5", "metadata", "permissions",
  "extract strings", "strings from", "process list", "running process",
  "processes", "network connections", "active connections", "search logs",
  "log file", "logs for", "recent file", "file activity", "login history",
  "logged in", "pcap", "packet capture", "capture packets", "wireshark",
  "find file", "search file", "read file", "list directory", "folder",
  "directory", "disk usage", "cpu load", "memory usage", "uptime",
  "system diagnostics", "diagnostics",
];

const SYSTEM_DIAGNOSTICS_DEF = {
  type: "function",
  function: {
    name: "system_diagnostics",
    description:
      "Get diagnostics for the user's laptop: CPU load, memory usage, disk usage, uptime, hostname.",
    parameters: { type: "object", properties: {}, required: [] },
  },
};

const HASH_FILE_DEF = {
  type: "function",
  function: {
    name: "hash_file",
    description:
      "Compute cryptographic hashes (MD5/SHA1/SHA256) of a file on the user's " +
      "laptop — for integrity verification, identifying known files, or comparing " +
      "against a hash database.",
    parameters: {
      type: "object",
      properties: {
        path: { type: "string", description: "Path to the file to hash." },
        algorithms: {
          type: "string",
          description:
            "Comma-separated algorithms to compute (default 'md5,sha1,sha256'). " +
            "Any Node.js crypto digest name works, e.g. 'sha512'.",
        },
      },
      required: ["path"],
    },
  },
};

const FILE_METADATA_DEF = {
  type: "function",
  function: {
    name: "file_metadata",
    description:
      "Get forensic metadata for a file on the user's laptop: size, " +
      "created/modified/accessed/metadata-changed timestamps, permissions, MIME " +
      "type, and (for images) EXIF data if available.",
    parameters: {
      type: "object",
      properties: {
        path: { type: "string", description: "Path to the file to inspect." },
      },
      required: ["path"],
    },
  },
};

const EXTRACT_STRINGS_DEF = {
  type: "function",
  function: {
    name: "extract_strings",
    description:
      "Extract printable text strings from a binary or unknown file on the user's " +
      "laptop (like the Unix 'strings' command) — useful for spotting URLs, " +
      "commands, credentials, or other readable artifacts embedded in a binary.",
    parameters: {
      type: "object",
      properties: {
        path: { type: "string", description: "Path to the file to scan." },
        min_length: {
          type: "number",
          description: "Minimum string length to report (default 4).",
        },
        limit: {
          type: "number",
          description: "Max strings to return (default 200, max 2000).",
        },
      },
      required: ["path"],
    },
  },
};

const LIST_PROCESSES_DEF = {
  type: "function",
  function: {
    name: "list_processes",
    description:
      "List running processes on the user's laptop (pid, user, CPU%, memory%, " +
      "elapsed time, command) — sorted by CPU or memory usage.",
    parameters: {
      type: "object",
      properties: {
        limit: { type: "number", description: "Max processes to return (default 20)." },
        sort_by: {
          type: "string",
          enum: ["cpu", "mem"],
          description: "Sort by CPU or memory usage (default 'cpu').",
        },
      },
      required: [],
    },
  },
};

const NETWORK_CONNECTIONS_DEF = {
  type: "function",
  function: {
    name: "network_connections",
    description:
      "List active/listening network connections on the user's laptop (protocol, " +
      "local/remote address, state, owning process) — useful for spotting " +
      "unexpected outbound connections or open ports.",
    parameters: {
      type: "object",
      properties: {
        limit: { type: "number", description: "Max connections to return (default 50)." },
      },
      required: [],
    },
  },
};

const SEARCH_LOGS_DEF = {
  type: "function",
  function: {
    name: "search_logs",
    description:
      "Search the user's laptop system logs (journalctl) for a pattern, optionally " +
      "since a given time — useful for investigating suspicious activity, errors, " +
      "or a timeline of events.",
    parameters: {
      type: "object",
      properties: {
        query: {
          type: "string",
          description: "Text/regex pattern to search log messages for (optional).",
        },
        since: {
          type: "string",
          description:
            "How far back to search, in journalctl --since format, e.g. " +
            "'2026-09-12 00:00:00', '1 hour ago', 'yesterday'.",
        },
        limit: { type: "number", description: "Max log lines to return (default 50)." },
      },
      required: [],
    },
  },
};

const RECENT_FILE_ACTIVITY_DEF = {
  type: "function",
  function: {
    name: "recent_file_activity",
    description:
      "Find files modified within the last N hours under a directory on the " +
      "user's laptop — useful for building a timeline of recent activity (e.g. " +
      "'what changed in the last day?').",
    parameters: {
      type: "object",
      properties: {
        root: {
          type: "string",
          description: "Directory to scan (defaults to the user's home directory).",
        },
        since_hours: {
          type: "number",
          description: "How many hours back to look (default 24).",
        },
        limit: { type: "number", description: "Max files to return (default 50)." },
      },
      required: [],
    },
  },
};

const LOGIN_HISTORY_DEF = {
  type: "function",
  function: {
    name: "login_history",
    description:
      "Show recent login history and who is currently logged into the user's " +
      "laptop — useful for spotting unexpected access.",
    parameters: {
      type: "object",
      properties: {
        limit: { type: "number", description: "Max login records to return (default 20)." },
      },
      required: [],
    },
  },
};

const ANALYZE_PCAP_DEF = {
  type: "function",
  function: {
    name: "analyze_pcap",
    description:
      "Analyze a network packet capture file (.pcap/.pcapng/.cap) on the user's " +
      "laptop: samples up to `limit` packets and reports protocol counts, top " +
      "talkers (most active hosts), and a sample of the raw packet lines. This " +
      "is a sample-based summary, not a full-file analysis, for large captures.",
    parameters: {
      type: "object",
      properties: {
        path: { type: "string", description: "Path to the pcap file." },
        limit: {
          type: "number",
          description: "Max packets to sample (default 500, max 5000).",
        },
      },
      required: ["path"],
    },
  },
};

const CAPTURE_PACKETS_DEF = {
  type: "function",
  function: {
    name: "capture_packets",
    description:
      "Capture live network traffic on the user's laptop and report protocol " +
      "counts, top talkers, and sample packet lines — e.g. 'capture some " +
      "traffic and tell me what's talking to the internet right now' or " +
      "'run a pcap for 5 minutes'. Captures up to ~25s run immediately and " +
      "you get the summary right away. Longer captures (minutes, up to 30) " +
      "run in the background instead — you'll get an immediate 'started' " +
      "acknowledgement to tell the user, and a desktop notification is sent " +
      "automatically when it finishes (you don't need to do anything else " +
      "or call analyze_pcap yourself; the user will be notified). The " +
      "capture is always saved as a .pcap file (to ~/Documents/pcaps/ by " +
      "default, or save_path if given) so it's never lost — pass " +
      "no_save: true only if the user explicitly doesn't want it kept. " +
      "Requires the tools agent's tcpdump to have packet-capture " +
      "permissions (setup-tools-agent.sh grants this); if not, it'll return a " +
      "clear error explaining how to fix that. Only call this when the user " +
      "actually wants a live capture — use analyze_pcap instead for an " +
      "existing .pcap file.",
    parameters: {
      type: "object",
      properties: {
        duration: {
          type: "number",
          description:
            "How many seconds to capture for (default 10, max 1800 = 30 " +
            "minutes). Convert minutes to seconds, e.g. '5 minutes' -> 300. " +
            "Anything over ~25s automatically runs in the background.",
        },
        limit: {
          type: "number",
          description:
            "Stop early once this many packets are captured (default 100 " +
            "for short captures, higher automatically for background ones, " +
            "max 1,000,000).",
        },
        interface: {
          type: "string",
          description:
            "Network interface to capture on, e.g. 'eth0', 'wlan0' (default 'any', " +
            "meaning all interfaces).",
        },
        filter: {
          type: "string",
          description:
            "Optional BPF filter to narrow the capture, e.g. 'tcp port 443', " +
            "'host 8.8.8.8', 'udp'.",
        },
        save_path: {
          type: "string",
          description:
            "Where to save the raw capture as a .pcap file for later analysis " +
            "(e.g. with analyze_pcap), within directories the user has allowed. " +
            "Defaults to a timestamped file under ~/Documents/pcaps/ if not " +
            "given — the capture is saved either way. Any missing folders in " +
            "the path are created automatically, e.g. " +
            "'~/Documents/pcaps/capture1.pcap' creates the pcaps folder if it " +
            "doesn't exist yet. '.pcap' is appended if the name doesn't already " +
            "end in a recognized pcap extension.",
        },
        no_save: {
          type: "boolean",
          description:
            "Set true to skip saving entirely and only get the in-memory " +
            "summary — only do this if the user explicitly says not to save it.",
        },
      },
      required: [],
    },
  },
};

/** Tool definitions in this category — entirely gated on the laptop tools agent being configured. */
function getDefinitions({ toolsConfigured }) {
  if (!toolsConfigured) return [];
  return [
    SYSTEM_DIAGNOSTICS_DEF,
    // find_files/search_files/read_file/list_directory/summarize_directory
    // definitions live in the shared assistant-tools submodule
    // (tools-agent/shared/tools/files.js) so they stay in sync with other
    // projects that use the same tools — see that file for descriptions.
    ...Object.values(filesTool.toolDefinitions).map((fn) => ({
      type: "function",
      function: fn,
    })),
    HASH_FILE_DEF,
    FILE_METADATA_DEF,
    EXTRACT_STRINGS_DEF,
    LIST_PROCESSES_DEF,
    NETWORK_CONNECTIONS_DEF,
    SEARCH_LOGS_DEF,
    RECENT_FILE_ACTIVITY_DEF,
    LOGIN_HISTORY_DEF,
    ANALYZE_PCAP_DEF,
    CAPTURE_PACKETS_DEF,
  ];
}

function describe(name, args) {
  const shared = filesTool.describeToolCall(name, args);
  if (shared) return shared;
  switch (name) {
    case "system_diagnostics":
      return "check your laptop's system diagnostics (CPU, memory, disk, uptime)";
    case "hash_file":
      return `compute hashes for ${args.path}`;
    case "file_metadata":
      return `check metadata for ${args.path}`;
    case "extract_strings":
      return `extract text strings from ${args.path}`;
    case "list_processes":
      return `list running processes${args.sort_by ? ` (sorted by ${args.sort_by})` : ""}`;
    case "network_connections":
      return "list active network connections";
    case "search_logs":
      return args.query
        ? `search system logs for "${args.query}"${args.since ? ` since ${args.since}` : ""}`
        : `check recent system logs${args.since ? ` since ${args.since}` : ""}`;
    case "recent_file_activity":
      return `find files modified in the last ${args.since_hours || 24}h${
        args.root ? ` under ${args.root}` : ""
      }`;
    case "login_history":
      return "check login history and who's currently logged in";
    case "analyze_pcap":
      return `analyze the packet capture ${args.path}`;
    case "capture_packets":
      return `capture live network traffic for ${args.duration || 10}s${
        args.filter ? ` (filter: ${args.filter})` : ""
      }`;
    default:
      return undefined;
  }
}

const SLOW_TOOLS = new Set(["hash_file", "analyze_pcap", "extract_strings"]);

/**
 * @param {string} name
 * @param {object} args
 * @param {object} deps
 * @param {function} deps.fetchToolsAgent
 * @param {function} deps.fetchToolsAgentRaw
 * @param {function} deps.postToolsAgent
 */
async function execute(name, args, deps = {}) {
  const { fetchToolsAgent, fetchToolsAgentRaw, postToolsAgent } = deps;

  // find_files/search_files/read_file/list_directory/summarize_directory are
  // dispatched via the shared assistant-tools module so their request shape
  // can't drift from the tool definitions above.
  const sharedReq = filesTool.buildRequest(name, args);
  if (sharedReq) {
    return fetchToolsAgentRaw(`${sharedReq.path}?${sharedReq.searchParams}`);
  }

  const timeoutMs = SLOW_TOOLS.has(name) ? 120000 : 10000;

  switch (name) {
    case "system_diagnostics":
      return fetchToolsAgent("/diagnostics", {}, { timeoutMs });
    case "hash_file":
      return fetchToolsAgent(
        "/hash",
        { path: args.path, algorithms: args.algorithms },
        { timeoutMs }
      );
    case "file_metadata":
      return fetchToolsAgent("/metadata", { path: args.path }, { timeoutMs });
    case "extract_strings":
      return fetchToolsAgent(
        "/strings",
        { path: args.path, minLength: args.min_length, limit: args.limit },
        { timeoutMs }
      );
    case "list_processes":
      return fetchToolsAgent(
        "/processes",
        { limit: args.limit, sortBy: args.sort_by },
        { timeoutMs }
      );
    case "network_connections":
      return fetchToolsAgent("/connections", { limit: args.limit }, { timeoutMs });
    case "search_logs":
      return fetchToolsAgent(
        "/logs",
        { q: args.query, since: args.since, limit: args.limit },
        { timeoutMs }
      );
    case "recent_file_activity":
      return fetchToolsAgent(
        "/recent-activity",
        { root: args.root, sinceHours: args.since_hours, limit: args.limit },
        { timeoutMs }
      );
    case "login_history":
      return fetchToolsAgent("/login-history", { limit: args.limit }, { timeoutMs });
    case "analyze_pcap":
      return fetchToolsAgent("/pcap", { path: args.path, limit: args.limit }, { timeoutMs });
    case "capture_packets": {
      // The agent itself decides sync vs. background based on duration
      // (anything over ~25s responds immediately with a "started"
      // acknowledgement instead of blocking) — so this client-side wait
      // only ever needs to cover a short synchronous capture, never the
      // full requested duration.
      const CAPTURE_SYNC_MAX_SECONDS = 25;
      const durationMs =
        Math.min(Math.max(Number(args.duration) || 10, 1), CAPTURE_SYNC_MAX_SECONDS) * 1000;
      return postToolsAgent(
        "/capture",
        {
          duration: args.duration,
          limit: args.limit,
          interface: args.interface,
          filter: args.filter,
          savePath: args.no_save ? false : args.save_path,
        },
        { timeoutMs: durationMs + 30000 }
      );
    }
    default:
      return undefined;
  }
}

const NAMES = new Set([
  "system_diagnostics",
  "hash_file",
  "file_metadata",
  "extract_strings",
  "list_processes",
  "network_connections",
  "search_logs",
  "recent_file_activity",
  "login_history",
  "analyze_pcap",
  "capture_packets",
  "find_files",
  "search_files",
  "read_file",
  "list_directory",
  "summarize_directory",
]);

module.exports = {
  CONFIRM_REQUIRED_TOOLS,
  CATEGORY_KEYWORDS,
  getDefinitions,
  describe,
  execute,
  NAMES,
};
