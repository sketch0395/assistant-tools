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

| Tool        | File               | Description                                              |
|-------------|--------------------|-----------------------------------------------------------|
| `create_note` | `tools/notes.js` | Create/append/replace a markdown note file.               |

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
