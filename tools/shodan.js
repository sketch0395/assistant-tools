// Shared Shodan.io integration: lets an assistant look up what's publicly
// exposed about an IP/host, run Shodan search queries, resolve hostnames,
// and check the configured account's API quota. Framework-agnostic like
// webFetch.js — no database, just an API key supplied by the host app
// (env var), so Lain/Asuna (or anything else) can share this without
// drifting apart on request shape, error handling, or tool wording.

const API_BASE = "https://api.shodan.io";
const FETCH_TIMEOUT_MS = 15000;
// Keep responses prompt-friendly — a raw Shodan host record can include
// dozens of full banners; cap how many we forward per lookup/search.
const MAX_SEARCH_RESULTS = 20;
const MAX_BANNER_CHARS = 2000;

async function shodanFetch(apiKey, path, params = {}) {
  if (!apiKey) {
    throw new Error(
      "Shodan isn't configured (no API key set) — this tool is unavailable."
    );
  }
  const url = new URL(API_BASE + path);
  url.searchParams.set("key", apiKey);
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") url.searchParams.set(k, v);
  }

  let res;
  try {
    res = await fetch(url.toString(), {
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
  } catch (err) {
    throw new Error(`Shodan request failed: ${err.message || err}`);
  }

  const text = await res.text();
  let body;
  try {
    body = text ? JSON.parse(text) : {};
  } catch {
    body = { raw: text };
  }

  if (!res.ok) {
    const msg = body?.error || body?.raw || `HTTP ${res.status}`;
    throw new Error(`Shodan error: ${msg}`);
  }
  return body;
}

/** Looks up everything Shodan knows about a single IP address. */
async function shodanHostLookup(apiKey, ip, opts = {}) {
  const target = String(ip || "").trim();
  if (!target) throw new Error("ip is required");

  const data = await shodanFetch(apiKey, `/shodan/host/${encodeURIComponent(target)}`, {
    minify: opts.minify ? "true" : undefined,
  });

  const services = Array.isArray(data.data)
    ? data.data.map((svc) => ({
        port: svc.port,
        transport: svc.transport,
        product: svc.product,
        version: svc.version,
        cpe: svc.cpe,
        timestamp: svc.timestamp,
        banner:
          typeof svc.data === "string"
            ? svc.data.slice(0, MAX_BANNER_CHARS)
            : undefined,
        vulns: svc.vulns ? Object.keys(svc.vulns) : undefined,
      }))
    : [];

  return {
    ip: data.ip_str || target,
    organization: data.org,
    isp: data.isp,
    asn: data.asn,
    country: data.country_name,
    city: data.city,
    hostnames: data.hostnames || [],
    domains: data.domains || [],
    operating_system: data.os,
    open_ports: data.ports || services.map((s) => s.port),
    last_update: data.last_update,
    vulns: data.vulns || [],
    tags: data.tags || [],
    services,
  };
}

/** Runs a Shodan search query (Shodan's own query syntax, e.g. "apache country:US"). */
async function shodanSearch(apiKey, query, opts = {}) {
  const q = String(query || "").trim();
  if (!q) throw new Error("query is required");

  const data = await shodanFetch(apiKey, "/shodan/host/search", {
    query: q,
    page: opts.page,
  });

  const matches = Array.isArray(data.matches) ? data.matches : [];
  const limited = matches.slice(0, opts.limit || MAX_SEARCH_RESULTS);

  return {
    query: q,
    total_results: data.total ?? matches.length,
    returned: limited.length,
    results: limited.map((m) => ({
      ip: m.ip_str,
      port: m.port,
      organization: m.org,
      hostnames: m.hostnames || [],
      country: m.location?.country_name,
      product: m.product,
      timestamp: m.timestamp,
      banner:
        typeof m.data === "string" ? m.data.slice(0, MAX_BANNER_CHARS) : undefined,
    })),
  };
}

/** Resolves one or more hostnames to IP addresses via Shodan's DNS API. */
async function shodanDnsLookup(apiKey, hostnames) {
  const list = Array.isArray(hostnames) ? hostnames : [hostnames];
  const cleaned = list.map((h) => String(h || "").trim()).filter(Boolean);
  if (!cleaned.length) throw new Error("hostnames is required");

  const data = await shodanFetch(apiKey, "/dns/resolve", {
    hostnames: cleaned.join(","),
  });
  return { resolved: data };
}

/** Returns the configured API key's plan/quota info. */
async function shodanAccountInfo(apiKey) {
  const data = await shodanFetch(apiKey, "/api-info");
  return {
    plan: data.plan,
    query_credits: data.query_credits,
    scan_credits: data.scan_credits,
    https: data.https,
    unlocked: data.unlocked,
  };
}

const toolDefinitions = {
  shodan_host_lookup: {
    name: "shodan_host_lookup",
    description:
      "Look up everything Shodan.io knows about a public IP address: " +
      "open ports, running services/banners, known vulnerabilities " +
      "(CVEs), hostnames, organization, and location. Use this when the " +
      "user asks what's exposed on an IP, wants recon on a host, or is " +
      "investigating whether something is publicly reachable. Only works " +
      "for IPs Shodan has actually scanned — private/internal IPs won't " +
      "have data. Consider chaining with add_threat_intel to save " +
      "notable findings (e.g. an exposed/vulnerable service).",
    parameters: {
      type: "object",
      properties: {
        ip: { type: "string", description: "The IP address to look up." },
      },
      required: ["ip"],
    },
  },
  shodan_search: {
    name: "shodan_search",
    description:
      "Search Shodan.io's index of internet-connected devices using its " +
      "query syntax (e.g. \"apache country:US\", \"port:3389 os:Windows\", " +
      "\"product:MongoDB\"). Use this for broader recon/exposure research " +
      "— finding instances of a vulnerable product, checking what's " +
      "exposed for an organization (\"org:Acme Corp\"), etc. Each search " +
      "consumes Shodan query credits, so don't call this repeatedly for " +
      "the same thing.",
    parameters: {
      type: "object",
      properties: {
        query: {
          type: "string",
          description: "Shodan search query string.",
        },
        limit: {
          type: "number",
          description: "Max results to return (default 20, max 20).",
        },
      },
      required: ["query"],
    },
  },
  shodan_dns_lookup: {
    name: "shodan_dns_lookup",
    description:
      "Resolve one or more hostnames to IP addresses via Shodan's DNS " +
      "API. Use this before shodan_host_lookup when the user gives you a " +
      "domain name instead of an IP.",
    parameters: {
      type: "object",
      properties: {
        hostnames: {
          type: "array",
          items: { type: "string" },
          description: "One or more hostnames to resolve.",
        },
      },
      required: ["hostnames"],
    },
  },
  shodan_account_info: {
    name: "shodan_account_info",
    description:
      "Check the configured Shodan API key's plan and remaining query/scan " +
      "credits. Use this if a search/lookup fails or the user asks about " +
      "Shodan usage/quota.",
    parameters: { type: "object", properties: {} },
  },
};

// Read-only external lookups, same rationale as fetch_web_page/get_cyber_news.
const CONFIRM_REQUIRED_TOOLS = [];

function describeToolCall(name, args) {
  switch (name) {
    case "shodan_host_lookup":
      return `look up ${args.ip} on Shodan`;
    case "shodan_search":
      return `search Shodan for "${args.query}"`;
    case "shodan_dns_lookup":
      return `resolve ${[].concat(args.hostnames).join(", ")} via Shodan DNS`;
    case "shodan_account_info":
      return "check Shodan account/quota info";
    default:
      return undefined;
  }
}

module.exports = {
  shodanHostLookup,
  shodanSearch,
  shodanDnsLookup,
  shodanAccountInfo,
  toolDefinitions,
  CONFIRM_REQUIRED_TOOLS,
  describeToolCall,
};
