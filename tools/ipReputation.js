// Shared IP reputation integration via AbuseIPDB — complements Shodan
// (which shows what's *exposed* on an IP) with what's actually been
// *reported* about it (spam, brute-force, scanning, botnet activity,
// etc). Get a free API key at https://www.abuseipdb.com/register.
//
// Framework-agnostic like shodan.js — host app injects the API key
// (env var), no database needed.

const API_BASE = "https://api.abuseipdb.com/api/v2";
const FETCH_TIMEOUT_MS = 15000;
const DEFAULT_MAX_AGE_DAYS = 90;

async function abuseIpdbFetch(apiKey, path, params = {}) {
  if (!apiKey) {
    throw new Error(
      "AbuseIPDB isn't configured (no API key set) — this tool is unavailable."
    );
  }
  const url = new URL(API_BASE + path);
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") url.searchParams.set(k, v);
  }

  let res;
  try {
    res = await fetch(url.toString(), {
      headers: { Key: apiKey, Accept: "application/json" },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
  } catch (err) {
    throw new Error(`AbuseIPDB request failed: ${err.message || err}`);
  }

  const text = await res.text();
  let body;
  try {
    body = text ? JSON.parse(text) : {};
  } catch {
    body = { raw: text };
  }

  if (!res.ok) {
    const msg = body?.errors?.[0]?.detail || body?.raw || `HTTP ${res.status}`;
    throw new Error(`AbuseIPDB error: ${msg}`);
  }
  return body;
}

/** Checks an IP's abuse reports/confidence score via AbuseIPDB. */
async function checkIpReputation(apiKey, ip, opts = {}) {
  const target = String(ip || "").trim();
  if (!target) throw new Error("ip is required");

  const data = await abuseIpdbFetch(apiKey, "/check", {
    ipAddress: target,
    maxAgeInDays: opts.max_age_days || DEFAULT_MAX_AGE_DAYS,
    verbose: opts.verbose ? "" : undefined,
  });
  const d = data.data || {};

  const reports = Array.isArray(d.reports)
    ? d.reports.slice(0, 10).map((r) => ({
        reported_at: r.reportedAt,
        comment: r.comment,
        categories: r.categories,
      }))
    : undefined;

  return {
    ip: d.ipAddress || target,
    is_public: d.isPublic,
    ip_version: d.ipVersion,
    abuse_confidence_score: d.abuseConfidenceScore,
    country_code: d.countryCode,
    usage_type: d.usageType,
    isp: d.isp,
    domain: d.domain,
    hostnames: d.hostnames || [],
    is_tor: d.isTor,
    total_reports: d.totalReports,
    num_distinct_reporters: d.numDistinctUsers,
    last_reported_at: d.lastReportedAt,
    recent_reports: reports,
  };
}

const toolDefinitions = {
  check_ip_reputation: {
    name: "check_ip_reputation",
    description:
      "Check an IP address's abuse reports and confidence score via " +
      "AbuseIPDB — a community-reported database of spam, brute-force " +
      "login attempts, port scanning, botnet activity, and other abusive " +
      "behavior. Use this when investigating whether an IP seen in logs, " +
      "a connection, or an alert is a known-bad actor. Complements " +
      "shodan_host_lookup (which shows what's exposed ON the IP, not " +
      "what it's been reported doing) — use both together for a full " +
      "picture during an investigation. abuse_confidence_score is 0-100; " +
      "anything above ~25 with multiple reports is worth flagging, above " +
      "75 is a strong signal. Consider chaining with add_threat_intel to " +
      "save a notable finding.",
    parameters: {
      type: "object",
      properties: {
        ip: { type: "string", description: "The IP address to check." },
        max_age_days: {
          type: "number",
          description: "Only count reports within this many days (default 90).",
        },
        verbose: {
          type: "boolean",
          description: "Include recent individual abuse reports (comments/categories), not just the score.",
        },
      },
      required: ["ip"],
    },
  },
};

// Read-only external lookup, same rationale as shodan_host_lookup.
const CONFIRM_REQUIRED_TOOLS = [];

function describeToolCall(name, args) {
  switch (name) {
    case "check_ip_reputation":
      return `check ${args.ip}'s abuse reports on AbuseIPDB`;
    default:
      return undefined;
  }
}

module.exports = {
  checkIpReputation,
  toolDefinitions,
  CONFIRM_REQUIRED_TOOLS,
  describeToolCall,
};
