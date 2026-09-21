// Shared CVE lookup integration: queries the NIST National Vulnerability
// Database (NVD) REST API for known vulnerability details — either a
// specific CVE ID, or a keyword search (e.g. "any CVEs affecting OpenSSH
// 9.6?"). No API key required (NVD's API is free/public), but an optional
// key raises the rate limit from 5 requests/30s to 50/30s — see
// https://nvd.nist.gov/developers/request-an-api-key.
//
// Framework-agnostic like shodan.js/urlProvenance.js — the host app injects
// an optional API key (env var), no database needed.

const API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const FETCH_TIMEOUT_MS = 15000;
const MAX_SEARCH_RESULTS = 10;
const MAX_DESCRIPTION_CHARS = 1000;
const MAX_REFERENCES = 5;

async function nvdFetch(apiKey, params = {}) {
  const url = new URL(API_BASE);
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") url.searchParams.set(k, v);
  }

  const headers = {};
  if (apiKey) headers.apiKey = apiKey;

  let res;
  try {
    res = await fetch(url.toString(), {
      headers,
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
  } catch (err) {
    throw new Error(`NVD request failed: ${err.message || err}`);
  }

  const text = await res.text();
  let body;
  try {
    body = text ? JSON.parse(text) : {};
  } catch {
    body = { raw: text };
  }

  if (!res.ok) {
    if (res.status === 403 || res.status === 429) {
      throw new Error(
        "NVD rate limit hit (5 requests/30s without an API key) — wait a " +
          "moment and try again, or set NVD_API_KEY for a higher limit."
      );
    }
    const msg = body?.message || body?.raw || `HTTP ${res.status}`;
    throw new Error(`NVD error: ${msg}`);
  }
  return body;
}

/** Picks the best available CVSS score/severity/vector across v3.1 > v3.0 > v2. */
function bestCvssMetric(metrics = {}) {
  const pick = (arr) => (Array.isArray(arr) && arr.length ? arr[0] : null);
  const v31 = pick(metrics.cvssMetricV31);
  const v30 = pick(metrics.cvssMetricV30);
  const v2 = pick(metrics.cvssMetricV2);
  const m = v31 || v30 || v2;
  if (!m) return null;
  return {
    version: m.cvssData?.version,
    base_score: m.cvssData?.baseScore,
    base_severity: m.cvssData?.baseSeverity || m.baseSeverity,
    vector: m.cvssData?.vectorString,
    exploitability_score: m.exploitabilityScore,
    impact_score: m.impactScore,
  };
}

function summarizeVulnerability(vuln) {
  const cve = vuln.cve || vuln;
  const descriptions = Array.isArray(cve.descriptions) ? cve.descriptions : [];
  const enDescription =
    descriptions.find((d) => d.lang === "en")?.value || descriptions[0]?.value || "";
  const weaknesses = Array.isArray(cve.weaknesses)
    ? cve.weaknesses
        .flatMap((w) => (Array.isArray(w.description) ? w.description : []))
        .map((d) => d.value)
        .filter(Boolean)
    : [];
  const references = Array.isArray(cve.references)
    ? cve.references.slice(0, MAX_REFERENCES).map((r) => r.url)
    : [];

  return {
    id: cve.id,
    published: cve.published,
    last_modified: cve.lastModified,
    vuln_status: cve.vulnStatus,
    description: enDescription.slice(0, MAX_DESCRIPTION_CHARS),
    cvss: bestCvssMetric(cve.metrics),
    cwe: [...new Set(weaknesses)],
    references,
  };
}

/** Looks up a single CVE by its ID (e.g. "CVE-2021-44228"). */
async function lookupCve(apiKey, cveId) {
  const id = String(cveId || "").trim().toUpperCase();
  if (!/^CVE-\d{4}-\d{4,}$/.test(id)) {
    throw new Error("cve_id must look like 'CVE-YYYY-NNNN' (e.g. CVE-2021-44228)");
  }
  const data = await nvdFetch(apiKey, { cveId: id });
  const vulns = Array.isArray(data.vulnerabilities) ? data.vulnerabilities : [];
  if (!vulns.length) {
    return { found: false, id, message: `${id} was not found in the NVD.` };
  }
  return { found: true, ...summarizeVulnerability(vulns[0]) };
}

/** Searches recent/known CVEs by keyword (product name, vendor, etc). */
async function searchCves(apiKey, keyword, opts = {}) {
  const kw = String(keyword || "").trim();
  if (!kw) throw new Error("keyword is required");
  const limit = Math.min(Number(opts.limit) || MAX_SEARCH_RESULTS, MAX_SEARCH_RESULTS);

  const params = { keywordSearch: kw, resultsPerPage: limit };
  if (opts.exact_match) params.keywordExactMatch = "";

  const data = await nvdFetch(apiKey, params);
  const vulns = Array.isArray(data.vulnerabilities) ? data.vulnerabilities : [];
  return {
    keyword: kw,
    total_results: data.totalResults ?? vulns.length,
    returned: vulns.length,
    results: vulns.map(summarizeVulnerability),
  };
}

const toolDefinitions = {
  lookup_cve: {
    name: "lookup_cve",
    description:
      "Look up full details on a specific CVE by its ID (e.g. " +
      "'CVE-2021-44228' for Log4Shell) from the official NIST National " +
      "Vulnerability Database — description, CVSS score/severity/vector, " +
      "CWE weakness type(s), and reference links. Use this instead of " +
      "relying on your own training knowledge whenever a specific CVE ID " +
      "is mentioned, since your knowledge of CVEs may be outdated or " +
      "incomplete — always cite what this returns rather than guessing.",
    parameters: {
      type: "object",
      properties: {
        cve_id: {
          type: "string",
          description: "The CVE identifier, e.g. 'CVE-2021-44228'.",
        },
      },
      required: ["cve_id"],
    },
  },
  search_cves: {
    name: "search_cves",
    description:
      "Search the NIST National Vulnerability Database by keyword — a " +
      "product/vendor name, technology, or short phrase (e.g. 'OpenSSH', " +
      "'Fortinet FortiOS', 'Log4j') — to find known CVEs affecting it. " +
      "Use this when the user asks 'are there any known vulnerabilities " +
      "in X' / 'what CVEs affect X' without already knowing a specific " +
      "CVE ID. Results are NOT necessarily sorted by severity or " +
      "recency — skim the returned CVSS scores/dates yourself before " +
      "summarizing which ones matter most.",
    parameters: {
      type: "object",
      properties: {
        keyword: {
          type: "string",
          description: "Product, vendor, or technology name to search for.",
        },
        limit: {
          type: "number",
          description: "Max results to return (default 10, max 10).",
        },
        exact_match: {
          type: "boolean",
          description: "Require the exact keyword phrase rather than a fuzzy match.",
        },
      },
      required: ["keyword"],
    },
  },
};

// Read-only external lookups, same rationale as shodan.js/webFetch.js.
const CONFIRM_REQUIRED_TOOLS = [];

function describeToolCall(name, args) {
  switch (name) {
    case "lookup_cve":
      return `look up ${args.cve_id} in the NVD`;
    case "search_cves":
      return `search the NVD for CVEs matching "${args.keyword}"`;
    default:
      return undefined;
  }
}

module.exports = {
  lookupCve,
  searchCves,
  toolDefinitions,
  CONFIRM_REQUIRED_TOOLS,
  describeToolCall,
};
