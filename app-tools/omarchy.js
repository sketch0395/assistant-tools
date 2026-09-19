"use strict";

// App-side Omarchy desktop control: Ollama-compatible tool schemas that
// dispatch to the host project's laptop tools agent (themes, commands,
// backgrounds). This is the client/schema layer used by each host
// project's Next.js app (lib/tools/omarchy.js) — NOT the same thing as
// tools/omarchy.js in this repo, which is the tools-agent SERVER's own
// implementation.
//
// Framework-agnostic like tools/threatIntel.js — the host project injects
// its own httpClient functions via the third `deps` argument to execute(),
// since the tools-agent URL/token env var names are host-specific config.
//
// Usage (host project's lib/tools/omarchy.js):
//
//   const sharedOmarchy = require("../../tools-agent/shared/app-tools/omarchy");
//   export const { CONFIRM_REQUIRED_TOOLS, CATEGORY_KEYWORDS, NAMES } = sharedOmarchy;
//   export const getDefinitions = sharedOmarchy.getDefinitions;
//   export const describe = sharedOmarchy.describe;
//   export function execute(name, args) {
//     return sharedOmarchy.execute(name, args, { fetchToolsAgent, postToolsAgent });
//   }

const CONFIRM_REQUIRED_TOOLS = new Set([
  "omarchy_status",
  "list_omarchy_themes",
  "set_omarchy_theme",
  "omarchy_command",
  "omarchy_command_background",
  "create_omarchy_theme",
  "create_omarchy_theme_from_image",
]);

const CATEGORY_KEYWORDS = [
  "omarchy", "theme", "hyprland", "wallpaper", "background image",
  "desktop", "workspace", "window rule", "bar layout", "hyprctl",
  "colors.toml", "extract colors", "color palette", "refresh shell",
];

const OMARCHY_STATUS_DEF = {
  type: "function",
  function: {
    name: "omarchy_status",
    description:
      "Get the user's Omarchy desktop status: current theme, active window, " +
      "active workspace, and connected monitors.",
    parameters: { type: "object", properties: {}, required: [] },
  },
};

const LIST_OMARCHY_THEMES_DEF = {
  type: "function",
  function: {
    name: "list_omarchy_themes",
    description: "List the Omarchy themes currently installed on the user's laptop.",
    parameters: { type: "object", properties: {}, required: [] },
  },
};

const SET_OMARCHY_THEME_DEF = {
  type: "function",
  function: {
    name: "set_omarchy_theme",
    description:
      "Switch the user's Omarchy desktop to a different installed theme (changes " +
      "colors, background, terminal/app theming system-wide). Use list_omarchy_themes " +
      "first if unsure of the exact theme name.",
    parameters: {
      type: "object",
      properties: {
        theme: {
          type: "string",
          description: "Exact theme name, e.g. 'Tokyo Night' or 'Gundam Barbatos'.",
        },
      },
      required: ["theme"],
    },
  },
};

const LIST_OMARCHY_COMMANDS_DEF = {
  type: "function",
  function: {
    name: "list_omarchy_commands",
    description:
      "List every `omarchy <group> <action>` command the user's installed " +
      "Omarchy version supports (machine-readable: binary, route, summary, " +
      "args, aliases). Read-only and safe — call this first whenever you're " +
      "unsure if something is possible with Omarchy or what the exact " +
      "command/arguments are, instead of guessing.",
    parameters: { type: "object", properties: {}, required: [] },
  },
};

const OMARCHY_COMMAND_DEF = {
  type: "function",
  function: {
    name: "omarchy_command",
    description:
      "Run any fast, non-interactive `omarchy <args...>` command on the user's " +
      "machine — theme/font changes, `refresh`/`restart` a component, " +
      "`toggle` a feature (e.g. nightlight), bar layout (`bar move ...`), " +
      "plugin/hook management, `reminder`, screenshots/recordings " +
      "(`capture ...`), `launch` an app, `system lock`, `version`, or " +
      "`debug --no-sudo --print`. Pass the command's arguments (everything " +
      "after `omarchy`) as an array of strings, e.g. [\"toggle\", " +
      "\"nightlight\"] or [\"theme\", \"set\", \"catppuccin\"]. Don't use " +
      "this for slow operations (system update, package installs, " +
      "installing a theme from a repo, full reinstall) — use " +
      "omarchy_command_background instead, or for anything requiring " +
      "interactive input (e.g. `omarchy setup ...` wizards), which isn't " +
      "supported here.",
    parameters: {
      type: "object",
      properties: {
        argv: {
          type: "array",
          items: { type: "string" },
          description:
            "The command's arguments as separate strings, in order, exactly as " +
            "you'd type them after `omarchy` (don't include 'omarchy' itself).",
        },
      },
      required: ["argv"],
    },
  },
};

const OMARCHY_COMMAND_BACKGROUND_DEF = {
  type: "function",
  function: {
    name: "omarchy_command_background",
    description:
      "Like omarchy_command, but for slow/long-running operations that " +
      "shouldn't block: `update` (full system update), `pkg add`/`install` " +
      "(package installs), `theme install <url>` (clone a theme from a git " +
      "repo), or `reinstall` (full config reinstall). Starts the command " +
      "detached and returns immediately with a log file path the user can " +
      "check progress in later (e.g. via read_file).",
    parameters: {
      type: "object",
      properties: {
        argv: {
          type: "array",
          items: { type: "string" },
          description: "The command's arguments, e.g. [\"update\"] or [\"pkg\", \"add\", \"neofetch\"].",
        },
      },
      required: ["argv"],
    },
  },
};

const CREATE_OMARCHY_THEME_DEF = {
  type: "function",
  function: {
    name: "create_omarchy_theme",
    description:
      "Create a brand-new custom Omarchy theme under the user's own " +
      "~/.config/omarchy/themes/<name>/ (never touches the read-only stock " +
      "themes under /usr/share/omarchy/). Writes a colors.toml you provide " +
      "(match the structure of an existing theme's colors.toml — check one " +
      "via read_file if unsure of the exact keys). For the background image, " +
      "use background_path if the user already has the image saved locally " +
      "(e.g. in ~/Downloads or ~/Pictures) — it's copied directly, no hosting " +
      "needed — or background_url to download one from the web instead. " +
      "Optionally applies the new theme immediately. If the user wants a " +
      "theme built FROM the colors in a picture (rather than colors you " +
      "compose yourself), use create_omarchy_theme_from_image instead — it " +
      "does the color extraction for you.",
    parameters: {
      type: "object",
      properties: {
        name: {
          type: "string",
          description: "Theme name (becomes the directory name) — letters/numbers/spaces/-/_ only.",
        },
        colors_toml: {
          type: "string",
          description: "Full contents to write as this theme's colors.toml.",
        },
        background_path: {
          type: "string",
          description: "Optional local file path of an image already saved on the user's machine, copied in as the background.",
        },
        background_url: {
          type: "string",
          description: "Optional URL of a background image to download into the theme (use background_path instead if the user already saved it locally).",
        },
        apply: {
          type: "boolean",
          description: "If true, switch to this theme immediately after creating it.",
        },
      },
      required: ["name"],
    },
  },
};

const EXTRACT_IMAGE_COLORS_DEF = {
  type: "function",
  function: {
    name: "extract_image_colors",
    description:
      "Analyze a local image file and extract its dominant color palette " +
      "(hex codes, sorted by how much of the image each color covers). " +
      "Read-only — use this to preview what colors would come out of a " +
      "picture, or to build a colors.toml yourself with fine-grained " +
      "control. For just turning a picture straight into a full working " +
      "theme in one step, use create_omarchy_theme_from_image instead.",
    parameters: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Local path to the image file (e.g. ~/Downloads/photo.jpg).",
        },
        count: {
          type: "integer",
          description: "How many distinct colors to extract (default 12, range 4-32).",
        },
      },
      required: ["path"],
    },
  },
};

const CREATE_OMARCHY_THEME_FROM_IMAGE_DEF = {
  type: "function",
  function: {
    name: "create_omarchy_theme_from_image",
    description:
      "The one-step version of 'make a theme out of this picture': reads a " +
      "local image file the user already has saved (no public URL needed), " +
      "automatically extracts its dominant colors, builds a full Omarchy " +
      "colors.toml from them (background/foreground/accent/8 named colors, " +
      "picking a sensible light/dark mode from the image itself), creates " +
      "the theme with that same image as its background, and optionally " +
      "applies it immediately. Use this whenever the user wants a theme " +
      "generated from a photo/wallpaper/character art rather than hand-" +
      "specifying colors.",
    parameters: {
      type: "object",
      properties: {
        name: {
          type: "string",
          description: "Theme name (becomes the directory name) — letters/numbers/spaces/-/_ only.",
        },
        image_path: {
          type: "string",
          description: "Local path to the image to build the theme from (e.g. ~/Downloads/wallpaper.png).",
        },
        apply: {
          type: "boolean",
          description: "If true, switch to this theme immediately after creating it.",
        },
      },
      required: ["name", "image_path"],
    },
  },
};

/** Tool definitions in this category — entirely gated on the laptop tools agent being configured. */
function getDefinitions({ toolsConfigured }) {
  if (!toolsConfigured) return [];
  return [
    OMARCHY_STATUS_DEF,
    LIST_OMARCHY_THEMES_DEF,
    SET_OMARCHY_THEME_DEF,
    LIST_OMARCHY_COMMANDS_DEF,
    OMARCHY_COMMAND_DEF,
    OMARCHY_COMMAND_BACKGROUND_DEF,
    CREATE_OMARCHY_THEME_DEF,
    EXTRACT_IMAGE_COLORS_DEF,
    CREATE_OMARCHY_THEME_FROM_IMAGE_DEF,
  ];
}

function describe(name, args) {
  switch (name) {
    case "omarchy_status":
      return "check your Omarchy desktop status (theme, active window, workspace)";
    case "list_omarchy_themes":
      return "list your installed Omarchy themes";
    case "set_omarchy_theme":
      return `switch your Omarchy theme to "${args.theme}"`;
    case "list_omarchy_commands":
      return "list every available Omarchy command";
    case "omarchy_command":
      return `run \`omarchy ${(args.argv || []).join(" ")}\``;
    case "omarchy_command_background":
      return `run \`omarchy ${(args.argv || []).join(" ")}\` in the background (this may take a while)`;
    case "create_omarchy_theme":
      return `create a new Omarchy theme "${args.name}"${args.apply ? " and apply it" : ""}`;
    case "extract_image_colors":
      return `extract the color palette from "${args.path}"`;
    case "create_omarchy_theme_from_image":
      return `create a new Omarchy theme "${args.name}" from the colors in "${args.image_path}"${args.apply ? " and apply it" : ""}`;
    default:
      return undefined;
  }
}

/**
 * @param {string} name
 * @param {object} args
 * @param {object} deps
 * @param {function} deps.fetchToolsAgent
 * @param {function} deps.postToolsAgent
 */
async function execute(name, args, deps = {}) {
  const { fetchToolsAgent, postToolsAgent } = deps;
  switch (name) {
    case "omarchy_status":
      return fetchToolsAgent("/omarchy/status");
    case "list_omarchy_themes":
      return fetchToolsAgent("/omarchy/themes");
    case "set_omarchy_theme":
      return postToolsAgent("/omarchy/theme", { theme: args.theme }, { timeoutMs: 15000 });
    case "list_omarchy_commands":
      return fetchToolsAgent("/omarchy/commands");
    case "omarchy_command":
      return postToolsAgent("/omarchy/command", { argv: args.argv }, { timeoutMs: 25000 });
    case "omarchy_command_background":
      return postToolsAgent(
        "/omarchy/command/background",
        { argv: args.argv },
        { timeoutMs: 15000 }
      );
    case "create_omarchy_theme":
      return postToolsAgent(
        "/omarchy/theme/create",
        {
          name: args.name,
          colorsToml: args.colors_toml,
          backgroundPath: args.background_path,
          backgroundUrl: args.background_url,
          apply: args.apply,
        },
        { timeoutMs: 30000 }
      );
    case "extract_image_colors":
      return postToolsAgent(
        "/omarchy/image/colors",
        { path: args.path, count: args.count },
        { timeoutMs: 20000 }
      );
    case "create_omarchy_theme_from_image":
      return postToolsAgent(
        "/omarchy/theme/from-image",
        { name: args.name, imagePath: args.image_path, apply: args.apply },
        { timeoutMs: 30000 }
      );
    default:
      return undefined;
  }
}

const NAMES = new Set([
  "omarchy_status",
  "list_omarchy_themes",
  "set_omarchy_theme",
  "list_omarchy_commands",
  "omarchy_command",
  "omarchy_command_background",
  "create_omarchy_theme",
  "extract_image_colors",
  "create_omarchy_theme_from_image",
]);

module.exports = {
  CONFIRM_REQUIRED_TOOLS,
  CATEGORY_KEYWORDS,
  getDefinitions,
  describe,
  execute,
  NAMES,
};
