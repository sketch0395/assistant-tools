// Shared malware distribution lookup via URLhaus (abuse.ch) — a feed of
// known malware distribution URLs/hosts and the payloads (files) served
// from them. Complements check_url_legitimacy (phishing/scam-focused:
// VirusTotal + urlscan.io + domain age/homograph checks) with a dedicated
// "is this a known malware drop site" signal, and complements
// check_file_hash (VirusTotal) with a second, independent source for
// file reputation.
//
// As of 2025, abuse.ch requires a free Auth-Key (register at
// https://auth.abuse.ch/) sent as the `Auth-Key` header on every request —
// the host must inject it via injectApiKey-style pattern like shodan.js.

const API_BASE = "https://urlhaus-api.abuse.ch/v1";
const FETCH_TIMEOUT_MS = 15000;
const MAX_URLS = 10;

async function urlhausFetch(apiKey, path, formParams = {}) {
  if (!apiKey) {
    throw new Error(
      "URLhaus requires a free Auth-Key (register at https://auth.abuse.ch/) " +
        "— set URLHAUS_AUTH_KEY."
    );
  }
  const body = new URLSearchParams();
  for (const [k, v] of Object.entries(formParams)) {
    if (v !== undefined && v !== null && v !== "") body.set(k, v);
  }

  let res;
  try {
    res = await fetch(API_BASE + path, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Auth-Key": apiKey,
      },
      body,
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
  } catch (err) {
    throw new Error(`URLhaus request failed: ${err.message || err}`);
  }

  const text = await res.text();
  let json;
  try {
    json = text ? JSON.parse(text) : {};
  } catch {
    throw new Error(`URLhaus returned an unexpected response: ${text.slice(0, 200)}`);
  }
  return json;
}

function summarizeUrlEntry(u) {
  return {
    url: u.url,
    url_status: u.url_status,
    date_added: u.date_added,
    threat: u.threat,
    tags: u.tags || [],
    reporter: u.reporter,
    urlhaus_reference: u.urlhaus_reference,
    payload: u.payloads?.[0]
      ? {
          filename: u.payloads[0].filename,
          file_type: u.payloads[0].file_type,
          signature: u.payloads[0].signature,
          md5: u.payloads[0].response_md5,
          sha256: u.payloads[0].response_sha256,
        }
      : undefined,
  };
}

/** Checks a specific URL against URLhaus's database of malware distribution URLs. */
async function checkUrl(apiKey, targetUrl) {
  const url = String(targetUrl || "").trim();
  if (!url) throw new Error("url is required");
  const data = await urlhausFetch(apiKey, "/url/", { url });
  if (data.query_status !== "ok") {
    return { url, found: false, status: data.query_status };
  }
  return { url, found: true, ...summarizeUrlEntry(data) };
}

/** Checks a host (domain or IP) for any malware URLs URLhaus has seen hosted on it. */
async function checkHost(apiKey, hostOrIp) {
  const host = String(hostOrIp || "").trim();
  if (!host) throw new Error("host is required");
  const data = await urlhausFetch(apiKey, "/host/", { host });
  if (data.query_status !== "ok") {
    return { host, found: false, status: data.query_status };
  }
  const urls = Array.isArray(data.urls) ? data.urls.slice(0, MAX_URLS) : [];
  return {
    host,
    found: true,
    first_seen: data.firstseen,
    url_count: data.url_count,
    urls: urls.map(summarizeUrlEntry),
  };
}

/** Checks a file hash (MD5 or SHA256) against payloads URLhaus has seen distributed. */
async function checkPayloadHash(apiKey, hash) {
  const h = String(hash || "").trim().toLowerCase();
  if (!h) throw new Error("hash is required");
  const param = h.length === 32 ? "md5_hash" : h.length === 64 ? "sha256_hash" : null;
  if (!param) throw new Error("hash must be an MD5 (32 hex chars) or SHA256 (64 hex chars) hash");

  const data = await urlhausFetch(apiKey, "/payload/", { [param]: h });
  if (data.query_status !== "ok") {
    return { hash: h, found: false, status: data.query_status };
  }
  return {
    hash: h,
    found: true,
    file_type: data.file_type,
    file_size: data.file_size,
    signature: data.signature,
    first_seen: data.firstseen,
    last_seen: data.lastseen,
    md5: data.md5_hash,
    sha256: data.sha256_hash,
    virustotal: data.virustotal?.result
      ? { result: data.virustotal.result, percent: data.virustotal.percent, link: data.virustotal.link }
      : undefined,
    urls: Array.isArray(data.urls)
      ? data.urls.slice(0, MAX_URLS).map((u) => ({ url: u.url, url_status: u.url_status }))
      : [],
  };
}

const toolDefinitions = {
  check_urlhaus: {
    name: "check_urlhaus",
    description:
      "Check a URL, host (domain/IP), or file hash (MD5/SHA256) against " +
      "URLhaus (abuse.ch) — a free (registration required), community-fed " +
      "database of known malware distribution URLs and the payloads " +
      "served from them. " +
      "Give exactly ONE of url/host/hash. Use `url` for a specific link " +
      "someone received, `host` to check whether a domain/IP has ever " +
      "hosted malware, and `hash` to check whether a specific file (by " +
      "its MD5/SHA256) is a known malware payload. This is a different, " +
      "free, independent signal from check_url_legitimacy (phishing/scam " +
      "focus via VirusTotal+urlscan) and check_file_hash (VirusTotal) — " +
      "worth checking alongside those for a fuller picture, not instead " +
      "of them. found: false just means URLhaus has no record — not " +
      "proof something is safe.",
    parameters: {
      type: "object",
      properties: {
        url: { type: "string", description: "A specific URL to check." },
        host: { type: "string", description: "A domain or IP to check." },
        hash: { type: "string", description: "An MD5 or SHA256 file hash to check." },
      },
    },
  },
};

// Read-only external lookup, same rationale as shodan_host_lookup.
const CONFIRM_REQUIRED_TOOLS = [];

function describeToolCall(name, args) {
  switch (name) {
    case "check_urlhaus":
      if (args.url) return `check ${args.url} against URLhaus`;
      if (args.host) return `check ${args.host} against URLhaus`;
      if (args.hash) return `check hash ${args.hash} against URLhaus`;
      return "check URLhaus";
    default:
      return undefined;
  }
}

module.exports = {
  checkUrl,
  checkHost,
  checkPayloadHash,
  toolDefinitions,
  CONFIRM_REQUIRED_TOOLS,
  describeToolCall,
};
