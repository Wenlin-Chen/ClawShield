# ClawShield OpenClaw Plugin

This package is the OpenClaw-native plugin for `ClawShield`.

It follows OpenClaw's plugin model and lifecycle hooks so OpenClaw can call the
local `ClawShield` backend before risky tool execution and after text-bearing
tool output.

## What it intercepts

- `before_tool_call`: maps configured OpenClaw tool names into
  `POST /api/evaluate-event`
- `after_tool_call`: inspects text-heavy tool output with
  `POST /api/check-content`
- `openclaw clawshield scan-skill <path>`: sends a local skill path to
  `POST /api/scan-skill`

## Install from this repo

```bash
openclaw plugins install ./openclaw-plugin
```

Then restart the OpenClaw Gateway so it reloads the plugin registry.

## Configure

Add config under `plugins.entries.clawshield.config` in your OpenClaw Gateway
config.

`backendUrl` may be either the API root (`http://127.0.0.1:8000/api`) or the
backend root (`http://127.0.0.1:8000`). The plugin normalizes it to `/api`.

Example:

```json
{
  "plugins": {
    "entries": {
      "clawshield": {
        "enabled": true,
        "config": {
          "backendUrl": "http://127.0.0.1:8000/api",
          "blockOnWarn": false,
          "failClosed": true,
          "inspectToolResults": true,
          "unclassifiedToolPolicy": "block"
        }
      }
    }
  }
}
```

## Recommended mapping

Match these lists to the tool names your OpenClaw install exposes:

```json
{
  "fileReadTools": ["read", "fs.read"],
  "fileWriteTools": ["write", "edit", "apply_patch"],
  "shellTools": ["exec", "bash", "process"],
  "httpTools": ["browser", "web_fetch", "web_search"],
  "contentInspectionTools": ["browser", "web_fetch", "web_search", "read"],
  "ignoredTools": ["session_status"],
  "unclassifiedToolPolicy": "block"
}
```

Name matching is case-insensitive.

## Included commands

- `openclaw clawshield doctor`
- `openclaw clawshield scan-skill <path>`
- `openclaw clawshield status`
- `/clawshield-status`

## Notes

- This plugin is the preferred OpenClaw integration path.
- `failClosed` defaults to `true`, so backend outages block protected tool
  execution unless you explicitly change that setting.
- Skill scanning is exposed as an OpenClaw CLI helper because the official
  OpenClaw docs used for this repo document tool lifecycle hooks, but not a
  dedicated skill-install lifecycle hook.
- Tool-name mapping is configurable so you can adapt it to your OpenClaw tool
  inventory without changing code.
- Tools that are not classified or ignored in the plugin config are blocked by
  default so they do not silently bypass enforcement.
- Backend security rules are customized separately from plugin config. To add or
  tune rules, edit the backend rule sources documented in
  [`docs/policy-reference.md`](../docs/policy-reference.md), then restart the
  backend.
