// Shared cybersecurity news aggregator: fetches configured RSS/Atom feeds
// (e.g. Krebs on Security, The Hacker News, BleepingComputer) that the user
// adds via chat, and returns matching articles. Framework-agnostic like
// notes.js/threatIntel.js — the host owns its own SQLite connection (via
// better-sqlite3) and passes it in as `db` to every function here,
// including `ensureSchema(db)` which the host calls once from its own
// db.js, keeping the schema itself a single source of truth.
//
// Sources are just name/url pairs persisted in the `cyber_news_sources`
// table. A standing "watch" phrase — the user's instructions on what to
// look for (e.g. "ransomware, zero-days, CVEs affecting Linux") — is
// stored as a single string in the host's key/value `settings` table.
// get_cyber_news uses an explicit topic argument if given, otherwise falls
// back to that stored watch phrase, otherwise returns the latest items
// unfiltered.

const WATCH_TERMS_KEY = "cyber_news_watch_terms";
const FETCH_TIMEOUT_MS = 10000;
const MAX_ITEMS_PER_SOURCE = 15;
const DEFAULT_LIMIT = 15;

/** Creates the cyber_news_sources table if not already present. */
function ensureSchema(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS cyber_news_sources (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      url TEXT NOT NULL UNIQUE,
      created_at REAL
    );
  `);
}

function decodeEntities(str) {
  return str
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&#39;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/&nbsp;/g, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function firstMatch(block, re) {
  const m = block.match(re);
  return m ? decodeEntities(m[1]) : "";
}

/** Parses RSS <item> or Atom <entry> blocks into a normalized {title, link, summary, date} list. */
function parseFeedItems(xml) {
  const isAtom = /<feed[\s>]/i.test(xml) && !/<rss[\s>]/i.test(xml);
  const blocks = isAtom
    ? [...xml.matchAll(/<entry>([\s\S]*?)<\/entry>/g)].map((m) => m[1])
    : [...xml.matchAll(/<item>([\s\S]*?)<\/item>/g)].map((m) => m[1]);

  return blocks
    .map((block) => {
      const title = firstMatch(block, /<title[^>]*>([\s\S]*?)<\/title>/);
      let link = firstMatch(block, /<link[^>]*>([\s\S]*?)<\/link>/);
      if (!link) {
        // Atom links are often self-closing with an href attribute instead
        // of text content: <link href="..." />
        const hrefMatch = block.match(/<link[^>]*href="([^"]+)"/);
        if (hrefMatch) link = hrefMatch[1];
      }
      const summary =
        firstMatch(block, /<description>([\s\S]*?)<\/description>/) ||
        firstMatch(block, /<summary[^>]*>([\s\S]*?)<\/summary>/) ||
        firstMatch(block, /<content[^>]*>([\s\S]*?)<\/content>/);
      const dateStr =
        firstMatch(block, /<pubDate>([\s\S]*?)<\/pubDate>/) ||
        firstMatch(block, /<published>([\s\S]*?)<\/published>/) ||
        firstMatch(block, /<updated>([\s\S]*?)<\/updated>/);
      const date = dateStr ? new Date(dateStr) : null;
      return {
        title,
        link: link.trim(),
        summary: summary.slice(0, 400),
        date: date && !isNaN(date.getTime()) ? date : null,
      };
    })
    .filter((item) => item.title && item.link)
    .slice(0, MAX_ITEMS_PER_SOURCE);
}

async function fetchOneSource(source) {
  try {
    const res = await fetch(source.url, {
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      headers: {
        // Some sources (BleepingComputer, SecurityWeek, etc.) sit behind
        // bot-detection that blocks generic/"compatible" user agents but
        // allows a normal-looking browser UA through.
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
          "(KHTML, like Gecko) Chrome/120.0 Safari/537.36",
        Accept: "application/rss+xml, application/xml, text/xml, */*",
      },
    });
    if (!res.ok) throw new Error(`responded with ${res.status}`);
    const text = await res.text();
    const items = parseFeedItems(text);
    return items.map((item) => ({ ...item, source: source.name }));
  } catch (err) {
    return { error: `${source.name}: ${err.message}`, source: source.name };
  }
}

/** Adds a new cybersecurity news source. Returns the created row. */
function addCyberNewsSource(db, name, url) {
  const n = String(name || "").trim();
  const u = String(url || "").trim();
  if (!n) throw new Error("name is required");
  if (!u) throw new Error("url is required");
  let parsed;
  try {
    parsed = new URL(u);
  } catch {
    throw new Error(`"${u}" isn't a valid URL`);
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("Only http:// and https:// URLs are supported");
  }
  const info = db
    .prepare(
      `INSERT INTO cyber_news_sources (name, url, created_at) VALUES (?, ?, ?)
       ON CONFLICT(url) DO UPDATE SET name = excluded.name`
    )
    .run(n, parsed.toString(), Date.now());
  return { id: info.lastInsertRowid, name: n, url: parsed.toString() };
}

/** Lists all configured cybersecurity news sources, oldest first. */
function listCyberNewsSources(db) {
  return db.prepare(`SELECT id, name, url FROM cyber_news_sources ORDER BY id`).all();
}

/** Removes a source by exact name or url (case-insensitive). Returns true if one was removed. */
function removeCyberNewsSource(db, nameOrUrl) {
  const q = String(nameOrUrl || "").trim().toLowerCase();
  if (!q) throw new Error("name_or_url is required");
  const info = db
    .prepare(`DELETE FROM cyber_news_sources WHERE lower(name) = ? OR lower(url) = ?`)
    .run(q, q);
  return info.changes > 0;
}

/** Stores the user's standing "what to look for" instructions (topics/keywords) as free text. */
function setCyberNewsWatchTerms(db, text) {
  const t = String(text || "").trim();
  db.prepare(
    `INSERT INTO settings (key, value) VALUES (?, ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value`
  ).run(WATCH_TERMS_KEY, t);
  return t;
}

/** Returns the stored watch terms, or "" if none set yet. */
function getCyberNewsWatchTerms(db) {
  const row = db.prepare(`SELECT value FROM settings WHERE key = ?`).get(WATCH_TERMS_KEY);
  return row ? row.value : "";
}

function matchesKeywords(item, keywords) {
  if (!keywords.length) return true;
  const haystack = `${item.title} ${item.summary}`.toLowerCase();
  return keywords.some((k) => haystack.includes(k));
}

/**
 * Fetches all configured sources in parallel, optionally filters by topic
 * (falls back to the stored watch terms if no topic is passed), and
 * returns the most recent matching items across all sources.
 */
async function fetchCyberNews(db, { topic, limit } = {}) {
  const sources = listCyberNewsSources(db);
  if (sources.length === 0) {
    return {
      items: [],
      errors: [],
      message:
        "No cybersecurity news sources are configured yet — add one with add_cyber_news_source.",
    };
  }

  const effectiveTopic = topic && topic.trim() ? topic.trim() : getCyberNewsWatchTerms(db);
  const keywords = effectiveTopic
    ? effectiveTopic
        .split(/[,;\n]+/)
        .map((k) => k.trim().toLowerCase())
        .filter(Boolean)
    : [];

  const results = await Promise.all(sources.map(fetchOneSource));
  const errors = results.filter((r) => !Array.isArray(r)).map((r) => r.error);
  const allItems = results.filter(Array.isArray).flat();

  const filtered = keywords.length
    ? allItems.filter((item) => matchesKeywords(item, keywords))
    : allItems;
  filtered.sort((a, b) => {
    if (a.date && b.date) return b.date - a.date;
    if (a.date) return -1;
    if (b.date) return 1;
    return 0;
  });

  return {
    items: filtered.slice(0, limit || DEFAULT_LIMIT).map((item) => ({
      source: item.source,
      title: item.title,
      link: item.link,
      summary: item.summary,
      published: item.date ? item.date.toISOString() : null,
    })),
    errors,
    filteredBy: keywords.length ? effectiveTopic : null,
  };
}

const toolDefinitions = {
  get_cyber_news: {
    name: "get_cyber_news",
    description:
      "Fetch recent articles from the user's configured cybersecurity news " +
      "sources (added via add_cyber_news_source). Filters results by topic " +
      "if given, otherwise by the standing 'what to look for' watch terms " +
      "set via set_cyber_news_watch_terms, otherwise returns the latest " +
      "items unfiltered. Use this whenever the user asks for security news, " +
      "threat intel headlines, or to check their configured feeds.",
    parameters: {
      type: "object",
      properties: {
        topic: {
          type: "string",
          description:
            "Optional comma-separated keywords/topics to filter this lookup by " +
            "(e.g. 'ransomware, zero-day, CVE'). Overrides the stored watch terms.",
        },
        limit: {
          type: "number",
          description: "Max articles to return (default 15).",
        },
      },
      required: [],
    },
  },
  add_cyber_news_source: {
    name: "add_cyber_news_source",
    description:
      "Add a cybersecurity news source (an RSS/Atom feed URL, e.g. Krebs on " +
      "Security, The Hacker News, BleepingComputer) that get_cyber_news will " +
      "pull from. Use when the user gives you a site/feed URL to start " +
      "tracking for security news.",
    parameters: {
      type: "object",
      properties: {
        name: {
          type: "string",
          description: "Short label for the source, e.g. 'Krebs on Security'.",
        },
        url: {
          type: "string",
          description: "The feed or page http(s) URL to pull articles from.",
        },
      },
      required: ["name", "url"],
    },
  },
  list_cyber_news_sources: {
    name: "list_cyber_news_sources",
    description: "List the currently configured cybersecurity news sources.",
    parameters: { type: "object", properties: {}, required: [] },
  },
  remove_cyber_news_source: {
    name: "remove_cyber_news_source",
    description: "Remove a configured cybersecurity news source by its exact name or URL.",
    parameters: {
      type: "object",
      properties: {
        name_or_url: {
          type: "string",
          description: "The source's exact name or URL, as shown by list_cyber_news_sources.",
        },
      },
      required: ["name_or_url"],
    },
  },
  set_cyber_news_watch_terms: {
    name: "set_cyber_news_watch_terms",
    description:
      "Save the user's standing instructions on what to look for in " +
      "cybersecurity news (topics/keywords, e.g. 'ransomware, zero-days, " +
      "CVEs affecting Linux, phishing campaigns'). get_cyber_news uses these " +
      "automatically when no explicit topic is given. Use when the user " +
      "tells you what kinds of security news to watch for or filter on.",
    parameters: {
      type: "object",
      properties: {
        watch_terms: {
          type: "string",
          description: "Comma-separated topics/keywords to watch for, in the user's own words.",
        },
      },
      required: ["watch_terms"],
    },
  },
};

// Mutating tools require explicit confirmation; get_cyber_news/
// list_cyber_news_sources are read-only and execute immediately.
const CONFIRM_REQUIRED_TOOLS = [
  "add_cyber_news_source",
  "remove_cyber_news_source",
  "set_cyber_news_watch_terms",
];

function describeToolCall(name, args) {
  switch (name) {
    case "get_cyber_news":
      return args.topic
        ? `get cybersecurity news about "${args.topic}"`
        : "get the latest cybersecurity news from your configured sources";
    case "add_cyber_news_source":
      return `add "${args.name}" (${args.url}) as a cybersecurity news source`;
    case "list_cyber_news_sources":
      return "list your configured cybersecurity news sources";
    case "remove_cyber_news_source":
      return `remove the cybersecurity news source "${args.name_or_url}"`;
    case "set_cyber_news_watch_terms":
      return `set cybersecurity news watch terms to "${args.watch_terms}"`;
    default:
      return null;
  }
}

module.exports = {
  ensureSchema,
  addCyberNewsSource,
  listCyberNewsSources,
  removeCyberNewsSource,
  setCyberNewsWatchTerms,
  getCyberNewsWatchTerms,
  fetchCyberNews,
  toolDefinitions,
  CONFIRM_REQUIRED_TOOLS,
  describeToolCall,
};
