"use strict";

// Website provenance / legitimacy checker: given a URL (including
// shortened ones), this:
//   1. Follows redirects to find where it actually leads (shortened URLs,
//      tracking links, etc.), without ever downloading/executing the
//      destination's content — HEAD/GET only, headers ignored beyond
//      status + Location.
//   2. Flags Unicode/punycode tricks in the hostname (homograph attacks —
//      e.g. a Cyrillic "а" standing in for a Latin "a").
//   3. Checks how long the domain has been registered via RDAP (the
//      modern, HTTPS-based replacement for the `whois` protocol — no
//      local `whois` binary or laptop agent needed, so this works
//      entirely from inside the host's own sandboxed server/container).
//   4. Cross-references VirusTotal's community detections for the URL.
//   5. Submits/searches urlscan.io, which actually renders the page in a
//      real (sandboxed, urlscan-hosted) browser and reports what it saw —
//      final IP/ASN/server, TLS certificate age, and a malicious/phishing
//      verdict. This is the closest thing to "actually visiting it" while
//      keeping the visit itself off of the user's/host's own network.
//
// Framework-agnostic like shodan.js — no database, just an API key
// supplied by the host app (env var), so Lain/Asuna (or anything else)
// can share this without drifting apart on request shape, error
// handling, or tool wording.

const REDIRECT_TIMEOUT_MS = 10000;
const MAX_REDIRECTS = 8;
const RDAP_TIMEOUT_MS = 8000;
const VT_TIMEOUT_MS = 15000;
const VT_POLL_ATTEMPTS = 3;
const VT_POLL_DELAY_MS = 3000;
const URLSCAN_TIMEOUT_MS = 15000;
const URLSCAN_POLL_ATTEMPTS = 6;
const URLSCAN_POLL_DELAY_MS = 5000;
const URLSCAN_SEARCH_MAX_AGE_DAYS = 7;
const YOUNG_DOMAIN_DAYS = 90;
const USER_AGENT = "Mozilla/5.0 (compatible; url-provenance-check/1.0)";

function toUrlSafeBase64(str) {
  return Buffer.from(str)
    .toString("base64")
    .replace(/=+$/, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function normalizeUrl(input) {
  const raw = String(input || "").trim();
  if (!raw) throw new Error("url is required");
  // Default to https:// if no scheme was given (e.g. "bit.ly/abc123").
  const withScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(raw) ? raw : `https://${raw}`;
  return new URL(withScheme); // throws on malformed input
}

// Common two-label public suffixes (ccSLDs) where the registrable domain is
// "label.suffix.tld" rather than just "suffix.tld" — e.g. "bbc.co.uk", not
// "co.uk". Not an exhaustive public-suffix-list replacement, but covers the
// vast majority of real-world cases without pulling in a new dependency.
const TWO_LABEL_SUFFIXES = new Set([
  "co.uk", "org.uk", "gov.uk", "ac.uk", "sch.uk", "me.uk", "net.uk", "ltd.uk", "plc.uk",
  "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
  "com.au", "net.au", "org.au", "edu.au", "gov.au",
  "co.nz", "net.nz", "org.nz", "govt.nz",
  "com.br", "net.br", "org.br", "gov.br",
  "co.in", "net.in", "org.in", "gov.in", "co.za", "org.za", "gov.za",
  "com.cn", "net.cn", "org.cn", "gov.cn",
  "com.mx", "com.tr", "com.sg", "com.hk", "co.kr", "com.tw",
]);

// Reduce a hostname to its registrable domain (eTLD+1-ish), e.g.
// "docs.google.com" -> "google.com", "www.bbc.co.uk" -> "bbc.co.uk".
// RDAP/whois records exist per-registered-domain, not per-subdomain, so
// looking up a subdomain directly returns "not found" even when the
// domain is long-established.
function getRegistrableDomain(hostname) {
  const labels = hostname.toLowerCase().split(".").filter(Boolean);
  if (labels.length <= 2) return labels.join(".");
  const lastTwo = labels.slice(-2).join(".");
  const take = TWO_LABEL_SUFFIXES.has(lastTwo) ? 3 : 2;
  return labels.slice(-take).join(".");
}

// --- 1. Redirect resolution (shortened URLs, tracking links) ---------------

async function followRedirects(startUrl) {
  const chain = [startUrl.toString()];
  let current = startUrl;
  for (let i = 0; i < MAX_REDIRECTS; i++) {
    let res;
    const fetchOpts = {
      redirect: "manual",
      signal: AbortSignal.timeout(REDIRECT_TIMEOUT_MS),
      headers: { "User-Agent": USER_AGENT },
    };
    try {
      res = await fetch(current, { ...fetchOpts, method: "HEAD" });
    } catch {
      // Some servers reject HEAD outright — retry once with GET.
      try {
        res = await fetch(current, { ...fetchOpts, method: "GET" });
      } catch (err) {
        throw new Error(`couldn't reach ${current}: ${err.message || err}`);
      }
    }
    if (res.status >= 300 && res.status < 400 && res.headers.get("location")) {
      const next = new URL(res.headers.get("location"), current);
      chain.push(next.toString());
      current = next;
      continue;
    }
    return { finalUrl: current, statusCode: res.status, chain, redirected: chain.length > 1 };
  }
  return {
    finalUrl: current,
    statusCode: null,
    chain,
    redirected: true,
    note: `stopped after ${MAX_REDIRECTS} redirects — possible redirect loop`,
  };
}

// --- 2. Unicode/punycode homograph check ------------------------------------

function analyzeHostname(hostname) {
  const labels = hostname.split(".");
  const isPunycode = labels.some((l) => l.toLowerCase().startsWith("xn--"));
  let decodedUnicode = null;
  if (isPunycode) {
    try {
      const punycode = require("node:punycode");
      decodedUnicode = labels.map((l) => (l.toLowerCase().startsWith("xn--") ? punycode.toUnicode(l) : l)).join(".");
    } catch {
      decodedUnicode = null;
    }
  }
  // The WHATWG URL parser already IDNA-encodes any raw Unicode hostname
  // into its ASCII/punycode form, so by the time we get here `hostname`
  // itself won't contain raw non-ASCII characters — punycode presence is
  // the actual signal that this is (or claims to be) an internationalized
  // domain name, worth a second look before trusting it visually.
  return {
    hostname,
    isPunycode,
    decodedUnicode,
    note: isPunycode
      ? "This domain uses punycode (internationalized domain name) encoding — " +
        "confirm the decoded form is the domain you expect before trusting it; " +
        "lookalike characters from other scripts are a common phishing trick."
      : null,
  };
}

// --- 3. Domain age via RDAP (no whois binary/laptop agent needed) ----------

async function checkDomainAge(domain) {
  let res;
  try {
    res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      signal: AbortSignal.timeout(RDAP_TIMEOUT_MS),
      headers: { Accept: "application/rdap+json", "User-Agent": USER_AGENT },
    });
  } catch (err) {
    return { available: false, reason: `RDAP lookup failed: ${err.message || err}` };
  }
  if (!res.ok) {
    return {
      available: false,
      reason: res.status === 404 ? "no RDAP record found for this domain" : `RDAP HTTP ${res.status}`,
    };
  }
  let data;
  try {
    data = await res.json();
  } catch {
    return { available: false, reason: "RDAP response wasn't valid JSON" };
  }
  const events = Array.isArray(data.events) ? data.events : [];
  const registration = events.find((e) => e.eventAction === "registration");
  if (!registration || !registration.eventDate) {
    return { available: false, reason: "RDAP record has no registration date" };
  }
  const registeredOn = new Date(registration.eventDate);
  const ageDays = Math.floor((Date.now() - registeredOn.getTime()) / 86400000);
  return {
    available: true,
    registeredOn: registeredOn.toISOString(),
    ageDays,
    isYoung: ageDays < YOUNG_DOMAIN_DAYS,
  };
}

// --- 4. VirusTotal community detections -------------------------------------

async function vtFetch(apiKey, path, opts = {}) {
  const res = await fetch(`https://www.virustotal.com/api/v3${path}`, {
    ...opts,
    headers: { "x-apikey": apiKey, ...(opts.headers || {}) },
    signal: AbortSignal.timeout(VT_TIMEOUT_MS),
  });
  const text = await res.text();
  let body;
  try {
    body = text ? JSON.parse(text) : {};
  } catch {
    body = { raw: text };
  }
  return { ok: res.ok, status: res.status, body };
}

function summarizeStats(stats) {
  if (!stats) return null;
  return {
    malicious: stats.malicious || 0,
    suspicious: stats.suspicious || 0,
    harmless: stats.harmless || 0,
    undetected: stats.undetected || 0,
    timeout: stats.timeout || 0,
  };
}

async function virusTotalReport(apiKey, targetUrl) {
  if (!apiKey) {
    return { available: false, reason: "VirusTotal isn't configured (no API key set)." };
  }
  try {
    return await virusTotalReportInner(apiKey, targetUrl);
  } catch (err) {
    return { available: false, reason: `VirusTotal lookup failed: ${err.message || err}` };
  }
}

async function virusTotalReportInner(apiKey, targetUrl) {
  const urlId = toUrlSafeBase64(targetUrl);

  // Fast path: someone else may have already scanned this exact URL.
  const existing = await vtFetch(apiKey, `/urls/${urlId}`);
  if (existing.ok) {
    const attrs = existing.body?.data?.attributes || {};
    return {
      available: true,
      stats: summarizeStats(attrs.last_analysis_stats),
      lastAnalysisDate: attrs.last_analysis_date
        ? new Date(attrs.last_analysis_date * 1000).toISOString()
        : null,
      permalink: `https://www.virustotal.com/gui/url/${urlId}`,
    };
  }
  if (existing.status === 429) {
    return { available: false, reason: "VirusTotal rate limit hit — try again shortly." };
  }
  if (existing.status !== 404) {
    return { available: false, reason: `VirusTotal error: HTTP ${existing.status}` };
  }

  // Not previously scanned — submit it, then poll briefly for a result.
  const submitted = await vtFetch(apiKey, "/urls", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ url: targetUrl }).toString(),
  });
  if (!submitted.ok) {
    if (submitted.status === 429) {
      return { available: false, reason: "VirusTotal rate limit hit — try again shortly." };
    }
    return { available: false, reason: `VirusTotal submission failed: HTTP ${submitted.status}` };
  }
  const analysisId = submitted.body?.data?.id;
  if (!analysisId) {
    return { available: false, reason: "VirusTotal submission didn't return an analysis id." };
  }

  for (let i = 0; i < VT_POLL_ATTEMPTS; i++) {
    await new Promise((resolve) => setTimeout(resolve, VT_POLL_DELAY_MS));
    const analysis = await vtFetch(apiKey, `/analyses/${analysisId}`);
    if (analysis.ok && analysis.body?.data?.attributes?.status === "completed") {
      return {
        available: true,
        stats: summarizeStats(analysis.body.data.attributes.stats),
        lastAnalysisDate: new Date().toISOString(),
        permalink: `https://www.virustotal.com/gui/url/${urlId}`,
        freshlySubmitted: true,
      };
    }
  }
  return {
    available: false,
    reason:
      "VirusTotal scan was just submitted and is still processing — ask again in a " +
      "minute or two for results.",
    permalink: `https://www.virustotal.com/gui/url/${urlId}`,
  };
}

// --- 5. urlscan.io — actually renders the page in a sandboxed browser ------

async function urlscanFetch(apiKey, path, opts = {}) {
  const headers = { ...(opts.headers || {}) };
  if (apiKey) headers["API-Key"] = apiKey;
  const res = await fetch(`https://urlscan.io${path}`, {
    ...opts,
    headers,
    signal: AbortSignal.timeout(URLSCAN_TIMEOUT_MS),
  });
  const text = await res.text();
  let body;
  try {
    body = text ? JSON.parse(text) : {};
  } catch {
    body = { raw: text };
  }
  return { ok: res.ok, status: res.status, body };
}

function summarizeUrlscanResult(result, { freshlySubmitted } = {}) {
  const page = result.page || {};
  const verdicts = result.verdicts || {};
  const overall = verdicts.overall || {};
  return {
    available: true,
    uuid: result.task?.uuid || null,
    permalink: result.task?.reportURL || (result.task?.uuid ? `https://urlscan.io/result/${result.task.uuid}/` : null),
    screenshot: result.task?.screenshotURL || null,
    malicious: Boolean(overall.malicious),
    score: typeof overall.score === "number" ? overall.score : null,
    categories: overall.categories || [],
    brands: overall.brands || [],
    finalUrl: page.url || null,
    ip: page.ip || null,
    country: page.country || null,
    server: page.server || null,
    asn: page.asn || null,
    asnName: page.asnname || null,
    tlsIssuer: page.tlsIssuer || null,
    tlsAgeDays: typeof page.tlsAgeDays === "number" ? page.tlsAgeDays : null,
    scanDate: result.task?.time || null,
    freshlySubmitted: Boolean(freshlySubmitted),
  };
}

function normalizeForCompare(u) {
  return String(u || "").replace(/\/+$/, "").toLowerCase();
}

async function urlscanReport(apiKey, targetUrl) {
  if (!apiKey) {
    return { available: false, reason: "urlscan.io isn't configured (no API key set)." };
  }
  try {
    return await urlscanReportInner(apiKey, targetUrl);
  } catch (err) {
    return { available: false, reason: `urlscan.io lookup failed: ${err.message || err}` };
  }
}

async function urlscanReportInner(apiKey, targetUrl) {
  // Fast path: search for a recent existing scan of this exact URL first —
  // free (doesn't count against submission quota) and instant. "page.url"
  // is a tokenized text field (fuzzy), so search by domain instead and
  // filter for an exact URL match client-side rather than trusting
  // relevance-sorted fuzzy hits.
  const targetHostname = new URL(targetUrl).hostname;
  const search = await urlscanFetch(
    apiKey,
    `/api/v1/search/?q=${encodeURIComponent(`page.domain:"${targetHostname}"`)}&size=10`
  );
  if (search.ok && Array.isArray(search.body?.results)) {
    const normalizedTarget = normalizeForCompare(targetUrl);
    const hit = search.body.results.find((r) => {
      const ageDays = r.task?.time ? Math.floor((Date.now() - new Date(r.task.time).getTime()) / 86400000) : null;
      if (ageDays !== null && ageDays > URLSCAN_SEARCH_MAX_AGE_DAYS) return false;
      return (
        normalizeForCompare(r.page?.url) === normalizedTarget || normalizeForCompare(r.task?.url) === normalizedTarget
      );
    });
    if (hit) {
      const resultRes = await urlscanFetch(apiKey, `/api/v1/result/${hit._id}/`);
      if (resultRes.ok) return summarizeUrlscanResult(resultRes.body);
    }
  } else if (search.status === 429) {
    return { available: false, reason: "urlscan.io rate limit hit — try again shortly." };
  }

  // No recent exact-match scan found — submit one. Unlisted: not on the
  // public front-page/search, but still gets a real sandboxed-browser visit.
  const submitted = await urlscanFetch(apiKey, "/api/v1/scan/", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: targetUrl, visibility: "unlisted" }),
  });
  if (!submitted.ok) {
    if (submitted.status === 429) {
      return { available: false, reason: "urlscan.io rate limit hit — try again shortly." };
    }
    return {
      available: false,
      reason: `urlscan.io submission failed: ${submitted.body?.message || `HTTP ${submitted.status}`}`,
    };
  }
  const uuid = submitted.body?.uuid;
  if (!uuid) {
    return { available: false, reason: "urlscan.io submission didn't return a scan id." };
  }

  // Result endpoint 404s until the scan finishes — the docs suggest an
  // initial wait before polling, then a few retries.
  await new Promise((resolve) => setTimeout(resolve, URLSCAN_POLL_DELAY_MS));
  for (let i = 0; i < URLSCAN_POLL_ATTEMPTS; i++) {
    const resultRes = await urlscanFetch(apiKey, `/api/v1/result/${uuid}/`);
    if (resultRes.ok) return summarizeUrlscanResult(resultRes.body, { freshlySubmitted: true });
    if (resultRes.status === 410) {
      return { available: false, reason: "urlscan.io deleted this scan result before it could be read." };
    }
    await new Promise((resolve) => setTimeout(resolve, URLSCAN_POLL_DELAY_MS));
  }
  return {
    available: false,
    reason: "urlscan.io scan was just submitted and is still processing — ask again in a minute for results.",
    permalink: `https://urlscan.io/result/${uuid}/`,
  };
}

// --- Orchestration -----------------------------------------------------------

function buildVerdict({ hostnameCheck, domainAge, vt, urlscan }) {
  const reasons = [];
  let verdict = "insufficient data";

  if (vt.available && vt.stats?.malicious > 0) {
    verdict = "likely malicious";
    reasons.push(`VirusTotal: ${vt.stats.malicious} security vendor(s) flagged this URL as malicious.`);
  } else if (vt.available && vt.stats?.suspicious > 0) {
    verdict = "suspicious";
    reasons.push(`VirusTotal: ${vt.stats.suspicious} security vendor(s) flagged this URL as suspicious.`);
  }

  if (urlscan.available && urlscan.malicious) {
    verdict = "likely malicious";
    reasons.push(
      `urlscan.io flagged this page as malicious` +
        (urlscan.categories?.length ? ` (${urlscan.categories.join(", ")})` : "") +
        (urlscan.brands?.length ? `, impersonating: ${urlscan.brands.join(", ")}` : "") +
        "."
    );
  }

  if (domainAge.available && domainAge.isYoung) {
    if (verdict === "insufficient data") verdict = "suspicious";
    reasons.push(
      `Domain was registered only ${domainAge.ageDays} day(s) ago (< ${YOUNG_DOMAIN_DAYS}-day threshold) — ` +
        "newly-registered domains are disproportionately used for scams/phishing."
    );
  }

  if (hostnameCheck.isPunycode) {
    if (verdict === "insufficient data") verdict = "suspicious";
    reasons.push(hostnameCheck.note);
  }

  if (verdict === "insufficient data") {
    const vtClean = vt.available && (vt.stats?.harmless ?? 0) > 0;
    const urlscanClean = urlscan.available && !urlscan.malicious;
    const domainEstablished = domainAge.available && !domainAge.isYoung;
    if ((vtClean || urlscanClean) && domainEstablished) {
      verdict = "likely legitimate";
      const signals = [];
      if (vtClean) signals.push("no VirusTotal vendors flagged it");
      if (urlscanClean) signals.push("urlscan.io's sandboxed render found nothing malicious");
      reasons.push(
        `${signals.join(" and ")}, and the domain has been registered for ${domainAge.ageDays} day(s).`
      );
    } else {
      reasons.push(
        "Not enough signal from VirusTotal/urlscan.io/RDAP to reach a confident verdict — use your own judgment."
      );
    }
  }

  return { verdict, reasons };
}

async function checkUrlLegitimacy(keys, inputUrl) {
  const { virusTotalApiKey = "", urlscanApiKey = "" } = typeof keys === "string" ? { virusTotalApiKey: keys } : keys || {};
  const parsed = normalizeUrl(inputUrl);
  const redirectResult = await followRedirects(parsed);
  const finalUrl = redirectResult.finalUrl instanceof URL ? redirectResult.finalUrl : new URL(redirectResult.finalUrl);
  const hostnameCheck = analyzeHostname(finalUrl.hostname);
  const domainForRdap = getRegistrableDomain(finalUrl.hostname);
  const finalUrlStr = redirectResult.finalUrl.toString ? redirectResult.finalUrl.toString() : String(redirectResult.finalUrl);

  const [domainAge, vt, urlscan] = await Promise.all([
    checkDomainAge(domainForRdap),
    virusTotalReport(virusTotalApiKey, finalUrlStr),
    urlscanReport(urlscanApiKey, finalUrlStr),
  ]);

  const { verdict, reasons } = buildVerdict({ hostnameCheck, domainAge, vt, urlscan });

  return {
    inputUrl: parsed.toString(),
    finalUrl: finalUrl.toString(),
    redirected: redirectResult.redirected,
    redirectChain: redirectResult.chain,
    hostname: hostnameCheck,
    domainAge,
    virusTotal: vt,
    urlscan,
    verdict,
    reasons,
  };
}

const toolDefinition = {
  name: "check_url_legitimacy",
  description:
    "Check whether a URL/website is legitimate or likely a scam/phishing/malware " +
    "link, before visiting or trusting it. Follows shortened-URL redirect chains " +
    "to find the real destination (without downloading/executing its content), " +
    "flags Unicode/punycode homograph tricks in the domain name, checks how long " +
    "the domain has been registered (very new domains are a red flag), cross-" +
    "references VirusTotal's community detections, and (via urlscan.io) has the " +
    "page actually rendered in a real, sandboxed browser to catch phishing/brand " +
    "impersonation and report its true IP/server/TLS certificate. Use this " +
    "whenever the user shares a suspicious link, a shortened URL (bit.ly, " +
    "tinyurl, etc.), or asks 'is this site safe/legit'.",
  parameters: {
    type: "object",
    properties: {
      url: {
        type: "string",
        description: "The URL to check — may be a shortened URL, may omit the scheme (e.g. \"bit.ly/abc123\").",
      },
    },
    required: ["url"],
  },
};

// Read-only lookup (never downloads/executes the destination's actual
// content, just headers + reputation APIs) — same rationale as
// fetch_web_page/get_cyber_news/shodan_host_lookup.
const CONFIRM_REQUIRED_TOOLS = [];

function describeToolCall(name, args) {
  if (name === "check_url_legitimacy") return `check whether "${args.url}" is a legitimate site`;
  return undefined;
}

module.exports = {
  checkUrlLegitimacy,
  followRedirects,
  analyzeHostname,
  checkDomainAge,
  virusTotalReport,
  urlscanReport,
  toolDefinition,
  CONFIRM_REQUIRED_TOOLS,
  describeToolCall,
};
