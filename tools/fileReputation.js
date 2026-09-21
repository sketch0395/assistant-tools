// Shared file hash reputation via VirusTotal's /files endpoint —
// complements urlProvenance.js (which checks URLs/domains) with a lookup
// for a specific file, by hash, against VT's ~70-engine multi-scanner
// database. Reuses the same VIRUSTOTAL_API_KEY the host app already has
// configured for check_url_legitimacy.
//
// Framework-agnostic like shodan.js/urlProvenance.js — host app injects
// the API key (env var), no database needed.

const API_BASE = "https://www.virustotal.com/api/v3";
const FETCH_TIMEOUT_MS = 15000;
const MAX_ENGINE_DETECTIONS = 15;

async function vtFetch(apiKey, path) {
  if (!apiKey) {
    throw new Error(
      "VirusTotal isn't configured (no API key set) — this tool is unavailable."
    );
  }
  let res;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      headers: { "x-apikey": apiKey },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
  } catch (err) {
    throw new Error(`VirusTotal request failed: ${err.message || err}`);
  }
  const text = await res.text();
  let body;
  try {
    body = text ? JSON.parse(text) : {};
  } catch {
    body = { raw: text };
  }
  if (res.status === 404) return null;
  if (!res.ok) {
    const msg = body?.error?.message || body?.raw || `HTTP ${res.status}`;
    throw new Error(`VirusTotal error: ${msg}`);
  }
  return body;
}

/** Looks up a file's reputation on VirusTotal by its MD5/SHA1/SHA256 hash. */
async function checkFileHash(apiKey, hash) {
  const h = String(hash || "").trim().toLowerCase();
  if (!/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/.test(h)) {
    throw new Error("hash must be a valid MD5 (32), SHA1 (40), or SHA256 (64) hex hash");
  }

  const data = await vtFetch(apiKey, `/files/${h}`);
  if (!data) {
    return {
      hash: h,
      found: false,
      message:
        "VirusTotal has no record of this hash — this does NOT mean the file is safe, " +
        "just that it hasn't been submitted/scanned there before.",
    };
  }

  const attrs = data.data?.attributes || {};
  const stats = attrs.last_analysis_stats || {};
  const results = attrs.last_analysis_results || {};
  const detections = Object.entries(results)
    .filter(([, r]) => r.category === "malicious" || r.category === "suspicious")
    .slice(0, MAX_ENGINE_DETECTIONS)
    .map(([engine, r]) => ({ engine, category: r.category, result: r.result }));

  return {
    hash: h,
    found: true,
    meaningful_name: attrs.meaningful_name,
    names: (attrs.names || []).slice(0, 10),
    type_description: attrs.type_description,
    size: attrs.size,
    md5: attrs.md5,
    sha1: attrs.sha1,
    sha256: attrs.sha256,
    first_submission_date: attrs.first_submission_date,
    last_analysis_date: attrs.last_analysis_date,
    reputation: attrs.reputation,
    tags: attrs.tags || [],
    detection_stats: {
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      undetected: stats.undetected || 0,
      harmless: stats.harmless || 0,
      total_engines:
        (stats.malicious || 0) +
        (stats.suspicious || 0) +
        (stats.undetected || 0) +
        (stats.harmless || 0),
    },
    flagged_by: detections,
    permalink: `https://www.virustotal.com/gui/file/${attrs.sha256 || h}`,
  };
}

const toolDefinitions = {
  check_file_hash: {
    name: "check_file_hash",
    description:
      "Look up a file's reputation on VirusTotal by its hash (MD5, " +
      "SHA1, or SHA256) — how many of ~70 antivirus/security engines " +
      "flag it as malicious/suspicious, what it's commonly named, file " +
      "type, and reputation score. Use this whenever investigating a " +
      "suspicious file found on disk (pair with hash_file to compute " +
      "the hash first if you only have a path) or a hash mentioned in a " +
      "report/IOC. found: false means VT has no record — NOT proof the " +
      "file is safe, just that it's never been submitted/scanned there. " +
      "Also consider check_urlhaus with the same hash for a second, " +
      "independent signal. Chain with add_threat_intel to save a " +
      "notable malicious finding.",
    parameters: {
      type: "object",
      properties: {
        hash: {
          type: "string",
          description: "The file's MD5, SHA1, or SHA256 hash.",
        },
      },
      required: ["hash"],
    },
  },
};

// Read-only external lookup, same rationale as check_url_legitimacy.
const CONFIRM_REQUIRED_TOOLS = [];

function describeToolCall(name, args) {
  switch (name) {
    case "check_file_hash":
      return `check hash ${args.hash} on VirusTotal`;
    default:
      return undefined;
  }
}

module.exports = {
  checkFileHash,
  toolDefinitions,
  CONFIRM_REQUIRED_TOOLS,
  describeToolCall,
};
