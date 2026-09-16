# assistant-tools

Shared, framework-agnostic tool modules for self-hosted LLM assistant
projects (e.g. [Lain](https://github.com/sketch0395/lain), Asuna, and
future ones). Each project consumes this repo as a **git submodule** and
opts in to whichever tools it wants — nothing is forced on every project,
and updates are pulled deliberately, not automatically.

## Why this exists

Multiple assistant projects ended up with near-identical tool code
(e.g. a `create_note` tool) copy-pasted and hand-adapted between repos.
That drifts over time — a bug fix or improvement in one project's copy
doesn't make it to the others. This repo is the single source of truth
for tool *logic*; each project still owns its own HTTP plumbing, auth,
and filesystem sandboxing config.

## Design

Every module under `tools/` is a plain Node.js file with **no
dependencies on any specific project's conventions**. Instead of reading
config/env vars itself, each module exports a `registerRoutes(router, opts)`
function and expects the host project to inject whatever it needs
(directories, sandboxing checks, HTTP helpers) as `opts`. See the header
comment in each tool file for its exact contract — `tools/notes.js` is the
reference example.

Modules may also export a `toolDefinition` — the JSON-schema fragment an
LLM needs for function-calling — so host projects can reuse it directly
instead of retyping the same schema in their own `lib/tools.js`.

## Using this in a project (git submodule)

```sh
# from the root of your project (e.g. lain/)
git submodule add https://github.com/sketch0395/assistant-tools.git tools-agent/shared
git submodule update --init --recursive
```

Then, in your own tools-agent, require whichever modules you want and
wire up their required `opts`:

```js
const notesTool = require("./shared/tools/notes");
notesTool.registerRoutes(router, {
  notesDir: NOTES_DIR,   // your project's own config
  isAllowed,             // your project's own sandboxing check
  send,                  // optional: your project's own HTTP helpers
  readJsonBody,          // (falls back to small built-ins if omitted)
});
```

### Pulling in updates

Submodules are pinned to a specific commit, so updates are opt-in:

```sh
cd tools-agent/shared
git pull origin main
cd ../..
git add tools-agent/shared
git commit -m "Update shared tools submodule"
```

## Available tools

| Tool(s)                                                                 | File                    | Description                                                                 |
|--------------------------------------------------------------------------|-------------------------|------------------------------------------------------------------------------|
| `create_note`                                                             | `tools/notes.js`        | Create/append/replace a markdown note file.                                  |
| `find_files`, `search_files`, `read_file`, `list_directory`, `summarize_directory` | `tools/files.js` | Read-only filesystem browsing/searching.                                     |
| `get_cyber_news`, source management                                      | `tools/cyberNews.js`    | Cybersecurity RSS/Atom news aggregator (DB-backed; host injects its own connection). |
| `add_threat_intel`, related lookups                                      | `tools/threatIntel.js`  | Threat-intel notes storage (DB-backed; host injects its own connection).     |
| `fetch_web_page`                                                          | `tools/webFetch.js`     | Fetch and summarize a web page.                                              |
| `shodan_host_lookup`, `shodan_search`, `shodan_dns_lookup`, `shodan_account_info` | `tools/shodan.js` | Shodan.io recon/exposure lookups (host injects its own API key).            |
| `ping_host`, `dns_lookup`, `traceroute_host`, `whois_lookup`, `port_scan`, `check_port`, `lan_device_scan`, `speed_test` | `tools/network.js` | Network diagnostics (runs on the tools-agent host/laptop, not in a container). |
| `system_diagnostics`                                                      | `tools/diagnostics.js`  | Host health snapshot (uptime, load, memory, disk).                          |
| hash/metadata/strings/pcap, processes, connections, logs, login history, packet capture | `tools/forensics.js` | Digital-forensics-style tools (path-restricted where filesystem-based).      |
| Omarchy status/theme list/set/create (incl. from-image), generic `omarchy <args>` passthrough | `tools/omarchy.js` | Omarchy Linux desktop integration.                                          |
| `extract_image_colors` (and theme-from-image support)                    | `tools/imageColors.js`  | Dominant-color palette extraction from a local image.                       |
| desktop notifications (internal — used by reminders, not LLM-callable)   | `tools/notify.js`       | notify-send wrapper; host supplies its own app name.                        |
| self-update (internal — e.g. `update_lain`/`update_asuna`)                | `tools/update.js`       | Kicks off the host project's own `scripts/update.sh`.                        |
| grant tcpdump capture capability (internal, non-LLM, UI-triggered only)  | `tools/capabilities.js` | One narrow, explicitly-scoped `sudo setcap` action for packet capture.       |


## Adding a new shared tool

1. Add `tools/<name>.js`, exporting `registerRoutes(router, opts)` (and
   optionally `toolDefinition`). Keep it dependency-free from any one
   project's config/env vars — accept everything it needs via `opts`.
2. Document its `opts` contract in a header comment, following
   `tools/notes.js` as the template.
3. Add a row to the table above.
4. Bump the submodule in whichever projects should pick it up.

## License

MIT — see [LICENSE](./LICENSE).
