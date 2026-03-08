const DEFAULT_CONFIG = {
  backendUrl: "http://127.0.0.1:8000/api",
  blockOnWarn: false,
  failClosed: false,
  inspectToolResults: true,
  contentMaxChars: 12000,
  fileReadTools: ["read"],
  fileWriteTools: ["write", "apply_patch"],
  shellTools: ["exec", "shell", "system.run"],
  httpTools: ["browser", "web_fetch", "fetch_url"],
  contentInspectionTools: ["browser", "web_fetch", "fetch_url", "read"],
  ignoredTools: ["session_status"],
};

const CONFIG_SCHEMA = {
  type: "object",
  additionalProperties: false,
  properties: {
    backendUrl: { type: "string" },
    blockOnWarn: { type: "boolean" },
    failClosed: { type: "boolean" },
    inspectToolResults: { type: "boolean" },
    contentMaxChars: { type: "integer", minimum: 256, maximum: 20000 },
    fileReadTools: { type: "array", items: { type: "string" } },
    fileWriteTools: { type: "array", items: { type: "string" } },
    shellTools: { type: "array", items: { type: "string" } },
    httpTools: { type: "array", items: { type: "string" } },
    contentInspectionTools: { type: "array", items: { type: "string" } },
    ignoredTools: { type: "array", items: { type: "string" } },
  },
};

function asStringArray(value, fallback) {
  if (!Array.isArray(value)) {
    return [...fallback];
  }
  return value.filter((item) => typeof item === "string" && item.trim()).map((item) => item.trim());
}

export function normalizePluginConfig(raw = {}) {
  return {
    backendUrl:
      typeof raw.backendUrl === "string" && raw.backendUrl.trim()
        ? raw.backendUrl.replace(/\/+$/, "")
        : DEFAULT_CONFIG.backendUrl,
    blockOnWarn: Boolean(raw.blockOnWarn),
    failClosed: Boolean(raw.failClosed),
    inspectToolResults:
      typeof raw.inspectToolResults === "boolean"
        ? raw.inspectToolResults
        : DEFAULT_CONFIG.inspectToolResults,
    contentMaxChars:
      typeof raw.contentMaxChars === "number" && Number.isFinite(raw.contentMaxChars)
        ? Math.min(Math.max(Math.trunc(raw.contentMaxChars), 256), 20000)
        : DEFAULT_CONFIG.contentMaxChars,
    fileReadTools: asStringArray(raw.fileReadTools, DEFAULT_CONFIG.fileReadTools),
    fileWriteTools: asStringArray(raw.fileWriteTools, DEFAULT_CONFIG.fileWriteTools),
    shellTools: asStringArray(raw.shellTools, DEFAULT_CONFIG.shellTools),
    httpTools: asStringArray(raw.httpTools, DEFAULT_CONFIG.httpTools),
    contentInspectionTools: asStringArray(
      raw.contentInspectionTools,
      DEFAULT_CONFIG.contentInspectionTools,
    ),
    ignoredTools: asStringArray(raw.ignoredTools, DEFAULT_CONFIG.ignoredTools),
  };
}

function normalizeName(value) {
  return String(value || "").trim().toLowerCase();
}

export function matchesConfiguredTool(toolName, configuredNames) {
  const normalized = normalizeName(toolName);
  return configuredNames.some((candidate) => normalizeName(candidate) === normalized);
}

function firstString(params, keys) {
  for (const key of keys) {
    const value = params?.[key];
    if (typeof value === "string" && value.trim()) {
      return value.trim();
    }
  }
  return undefined;
}

function summarizeParams(params) {
  const keys = Object.keys(params || {});
  return keys.length ? `Tool params: ${keys.join(", ")}` : "OpenClaw tool call";
}

export function inferRuntimeEvent(toolName, params, ctx, pluginConfig) {
  if (matchesConfiguredTool(toolName, pluginConfig.ignoredTools)) {
    return null;
  }

  const actor = ctx?.agentId || ctx?.agentName || "openclaw";
  const sessionId = ctx?.sessionKey || ctx?.sessionId || undefined;
  const provenance = "openclaw-plugin";
  const metadata = {
    tool_name: String(toolName || ""),
  };

  if (matchesConfiguredTool(toolName, pluginConfig.fileReadTools)) {
    const target = firstString(params, ["path", "filePath", "file", "target"]);
    return target
      ? {
          session_id: sessionId,
          event_type: "file_read",
          actor,
          task: firstString(params, ["purpose", "prompt", "query", "instruction"]) || summarizeParams(params),
          target_resource: target,
          provenance,
          metadata,
        }
      : null;
  }

  if (matchesConfiguredTool(toolName, pluginConfig.fileWriteTools)) {
    const target = firstString(params, ["path", "filePath", "file", "target"]);
    return target
      ? {
          session_id: sessionId,
          event_type: "file_write",
          actor,
          task: firstString(params, ["purpose", "prompt", "query", "instruction"]) || summarizeParams(params),
          target_resource: target,
          provenance,
          metadata,
        }
      : null;
  }

  if (matchesConfiguredTool(toolName, pluginConfig.shellTools)) {
    const command =
      firstString(params, ["command", "cmd"]) ||
      (Array.isArray(params?.argv) ? params.argv.join(" ") : undefined);
    return command
      ? {
          session_id: sessionId,
          event_type: "shell_exec",
          actor,
          task: firstString(params, ["purpose", "prompt", "query", "instruction"]) || summarizeParams(params),
          target_resource: command,
          provenance,
          command,
          metadata,
        }
      : null;
  }

  if (matchesConfiguredTool(toolName, pluginConfig.httpTools)) {
    const url = firstString(params, ["url", "href", "target"]);
    return url
      ? {
          session_id: sessionId,
          event_type: "http_request",
          actor,
          task: firstString(params, ["purpose", "prompt", "query", "instruction"]) || summarizeParams(params),
          target_resource: url,
          provenance,
          url,
          payload_excerpt: firstString(params, ["body", "payload", "content", "text"]),
          metadata,
        }
      : null;
  }

  return null;
}

export function shouldInspectToolResult(toolName, pluginConfig) {
  return matchesConfiguredTool(toolName, pluginConfig.contentInspectionTools);
}

export function extractTextForInspection(result, maxChars) {
  if (typeof result === "string") {
    return result.slice(0, maxChars);
  }

  if (result && typeof result === "object") {
    if (typeof result.text === "string") {
      return result.text.slice(0, maxChars);
    }
    if (typeof result.output_text === "string") {
      return result.output_text.slice(0, maxChars);
    }
    if (Array.isArray(result.content)) {
      const text = result.content
        .map((item) => {
          if (typeof item === "string") {
            return item;
          }
          if (item && typeof item === "object" && typeof item.text === "string") {
            return item.text;
          }
          return "";
        })
        .filter(Boolean)
        .join("\n");
      if (text) {
        return text.slice(0, maxChars);
      }
    }
  }

  return undefined;
}

async function requestJson(url, init) {
  const response = await fetch(url, {
    ...init,
    headers: {
      "content-type": "application/json",
      ...(init?.headers || {}),
    },
  });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json();
}

async function checkBackendHealth(pluginConfig) {
  const healthUrl = pluginConfig.backendUrl.endsWith("/api")
    ? pluginConfig.backendUrl.replace(/\/api$/, "/healthz")
    : `${pluginConfig.backendUrl}/healthz`;
  const response = await fetch(healthUrl);
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
}

function log(logger, level, message, extra) {
  if (logger && typeof logger[level] === "function") {
    logger[level](message, extra);
    return;
  }
  const suffix = extra ? ` ${JSON.stringify(extra)}` : "";
  if (level === "error") {
    console.error(`[clawshield] ${message}${suffix}`);
  } else {
    console.log(`[clawshield] ${message}${suffix}`);
  }
}

function formatReasons(reasons) {
  if (!Array.isArray(reasons) || reasons.length === 0) {
    return "ClawShield denied the action.";
  }
  return reasons.join(" ");
}

async function evaluateRuntimeEvent(pluginConfig, payload) {
  return requestJson(`${pluginConfig.backendUrl}/evaluate-event`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

async function checkContent(pluginConfig, payload) {
  return requestJson(`${pluginConfig.backendUrl}/check-content`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

async function scanSkill(pluginConfig, path) {
  return requestJson(`${pluginConfig.backendUrl}/scan-skill`, {
    method: "POST",
    body: JSON.stringify({ path }),
  });
}

function installCliCommands(api, pluginConfig) {
  api.registerCli(
    ({ program }) => {
      const clawshield = program.command("clawshield").description("ClawShield plugin helpers");

      clawshield
        .command("doctor")
        .description("Check that the local ClawShield backend is reachable")
        .action(async () => {
          await checkBackendHealth(pluginConfig);
          console.log(`ClawShield backend reachable at ${pluginConfig.backendUrl}`);
        });

      clawshield
        .command("scan-skill <path>")
        .description("Scan a skill directory or single skill file with ClawShield")
        .action(async (path) => {
          const result = await scanSkill(pluginConfig, path);
          console.log(`Recommendation: ${String(result.recommendation).toUpperCase()}`);
          console.log(`Score: ${result.score}`);
          for (const finding of result.findings || []) {
            console.log(`- ${finding.severity}: ${finding.title} [${finding.file_path}]`);
          }
          if (result.recommendation === "block") {
            process.exitCode = 2;
          }
        });

      clawshield
        .command("status")
        .description("Print current ClawShield plugin configuration")
        .action(() => {
          console.log(
            JSON.stringify(
              {
                backendUrl: pluginConfig.backendUrl,
                blockOnWarn: pluginConfig.blockOnWarn,
                failClosed: pluginConfig.failClosed,
                inspectToolResults: pluginConfig.inspectToolResults,
              },
              null,
              2,
            ),
          );
        });
    },
    { commands: ["clawshield"] },
  );
}

function installSlashCommand(api, pluginConfig) {
  api.registerCommand({
    name: "clawshield-status",
    description: "Show ClawShield plugin status",
    handler: () => ({
      text: `ClawShield plugin active. backend=${pluginConfig.backendUrl} blockOnWarn=${pluginConfig.blockOnWarn} failClosed=${pluginConfig.failClosed}`,
    }),
  });
}

function installGatewayMethod(api, pluginConfig) {
  api.registerGatewayMethod("clawshield.status", ({ respond }) => {
    respond(true, {
      ok: true,
      plugin: "clawshield",
      backendUrl: pluginConfig.backendUrl,
      blockOnWarn: pluginConfig.blockOnWarn,
      failClosed: pluginConfig.failClosed,
      inspectToolResults: pluginConfig.inspectToolResults,
    });
  });
}

function installToolHooks(api, pluginConfig) {
  api.on("before_tool_call", async (event, ctx) => {
    const payload = inferRuntimeEvent(event.toolName, event.params, ctx, pluginConfig);
    if (!payload) {
      return;
    }

    try {
      const result = await evaluateRuntimeEvent(pluginConfig, payload);
      const shouldBlock = result.decision === "block" || (result.decision === "warn" && pluginConfig.blockOnWarn);
      if (shouldBlock) {
        return {
          block: true,
          blockReason: formatReasons(result.reasons),
        };
      }
      if (result.decision === "warn") {
        log(api.logger, "warn", "ClawShield warned on tool call", {
          toolName: event.toolName,
          reasons: result.reasons,
        });
      }
      return;
    } catch (error) {
      log(api.logger, "error", "ClawShield backend call failed before tool execution", {
        toolName: event.toolName,
        error: String(error),
      });
      if (pluginConfig.failClosed) {
        return {
          block: true,
          blockReason: "ClawShield backend was unavailable and failClosed is enabled.",
        };
      }
      return;
    }
  });

  api.on("after_tool_call", async (event, ctx) => {
    if (!pluginConfig.inspectToolResults || !shouldInspectToolResult(event.toolName, pluginConfig)) {
      return;
    }
    const text = extractTextForInspection(event.result, pluginConfig.contentMaxChars);
    if (!text) {
      return;
    }

    try {
      const contentResult = await checkContent(pluginConfig, {
        text,
        session_id: ctx?.sessionKey,
        source: `openclaw-tool:${event.toolName}`,
      });
      if (contentResult.injection_score >= 35) {
        log(api.logger, "warn", "ClawShield detected suspicious tool output", {
          toolName: event.toolName,
          injectionScore: contentResult.injection_score,
          matchedPatterns: contentResult.matched_patterns,
        });
      }
    } catch (error) {
      log(api.logger, "error", "ClawShield backend call failed while inspecting tool output", {
        toolName: event.toolName,
        error: String(error),
      });
    }
  });
}

export function createPlugin() {
  return {
    id: "clawshield",
    name: "ClawShield",
    description: "Runtime guardrails for OpenClaw tool calls backed by the local ClawShield service.",
    configSchema: CONFIG_SCHEMA,
    register(api) {
      const pluginConfig = normalizePluginConfig(api.pluginConfig || {});
      installCliCommands(api, pluginConfig);
      installSlashCommand(api, pluginConfig);
      installGatewayMethod(api, pluginConfig);
      installToolHooks(api, pluginConfig);
      log(api.logger, "info", "ClawShield OpenClaw plugin loaded", {
        backendUrl: pluginConfig.backendUrl,
        blockOnWarn: pluginConfig.blockOnWarn,
        failClosed: pluginConfig.failClosed,
      });
    },
  };
}

const plugin = createPlugin();

export default plugin;
