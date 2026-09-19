"use strict";

// App-side "diagnostics" tool: lets the assistant (and, through it, the
// user) look at the real recorded history of tool-call successes/failures
// instead of guessing why something didn't work. Every tool call across
// every other category gets logged centrally at the executeTool() choke
// point in the host project's lib/tools/registry.js — this module just
// exposes that log via a read-only tool.
//
// The host project injects its own getRecentToolCalls (its lib/toolCallLog.js
// adapter, which wraps tools-agent/shared/tools/toolCallLog.js with its own
// getDb()) via the third `deps` argument to execute(), since DB access is
// host-specific.
//
// Usage (host project's lib/tools/diagnostics.js):
//
//   const sharedDiagnostics = require("../../tools-agent/shared/app-tools/diagnostics");
//   export const { CONFIRM_REQUIRED_TOOLS, CATEGORY_KEYWORDS, NAMES } = sharedDiagnostics;
//   export const getDefinitions = sharedDiagnostics.getDefinitions;
//   export const describe = sharedDiagnostics.describe;
//   export function execute(name, args) {
//     return sharedDiagnostics.execute(name, args, { getRecentToolCalls });
//   }

const toolCallLogTool = require("../tools/toolCallLog");

const CONFIRM_REQUIRED_TOOLS = new Set(); // read-only, executes immediately
const CATEGORY_KEYWORDS = []; // always-included (see ALWAYS_INCLUDE_TOOLS in registry.js), no keyword gating needed

const DIAGNOSE_TOOL_CALLS_DEF = {
  type: "function",
  function: toolCallLogTool.toolDefinitions.diagnose_tool_calls,
};

function getDefinitions() {
  return [DIAGNOSE_TOOL_CALLS_DEF];
}

function describe(name, args) {
  return toolCallLogTool.describeToolCall(name, args);
}

/**
 * @param {string} name
 * @param {object} args
 * @param {object} deps
 * @param {function} deps.getRecentToolCalls - host's lib/toolCallLog.js adapter
 */
function execute(name, args, deps = {}) {
  const { getRecentToolCalls } = deps;
  if (name !== "diagnose_tool_calls") return undefined;
  const hours = Number(args.hours) > 0 ? Number(args.hours) : 24;
  const sinceMs = Date.now() - hours * 60 * 60 * 1000;
  const onlyFailures = args.only_failures !== false;
  const limit = Number(args.limit) > 0 ? Number(args.limit) : 20;
  const calls = getRecentToolCalls({
    toolName: args.tool_name || undefined,
    sinceMs,
    onlyFailures,
    limit,
  });
  return {
    window_hours: hours,
    only_failures: onlyFailures,
    count: calls.length,
    calls,
    message: calls.length
      ? undefined
      : onlyFailures
      ? `No failed tool calls recorded in the last ${hours} hour(s)${
          args.tool_name ? ` for "${args.tool_name}"` : ""
        }.`
      : `No tool calls recorded in the last ${hours} hour(s)${
          args.tool_name ? ` for "${args.tool_name}"` : ""
        }.`,
  };
}

const NAMES = new Set(["diagnose_tool_calls"]);

module.exports = {
  CONFIRM_REQUIRED_TOOLS,
  CATEGORY_KEYWORDS,
  getDefinitions,
  describe,
  execute,
  NAMES,
};
