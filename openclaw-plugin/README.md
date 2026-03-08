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
          "failClosed": false,
          "inspectToolResults": true
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
  "fileWriteTools": ["write", "apply_patch", "fs.write"],
  "shellTools": ["exec", "shell", "system.run"],
  "httpTools": ["browser", "web_fetch", "fetch_url"],
  "contentInspectionTools": ["browser", "web_fetch", "fetch_url", "read"]
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
- Skill scanning is exposed as an OpenClaw CLI helper because the official
  OpenClaw docs used for this repo document tool lifecycle hooks, but not a
  dedicated skill-install lifecycle hook.
- Tool-name mapping is configurable so you can adapt it to your OpenClaw tool
  inventory without changing code.
- Backend security rules are customized separately from plugin config. To add or
  tune rules, edit the backend rule sources documented in
  [`docs/policy-reference.md`](../docs/policy-reference.md), then restart the
  backend.
