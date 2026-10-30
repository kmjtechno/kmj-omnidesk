# Zed IDE + KMJ CodeBridge (OmniDesk)

> **Connection status is not release status.** This document configures a remote MCP server for the **Zed Agent**, not a local shell or a production authorization bypass.

## 1. Open this repository in Zed

On the owner's approved development computer, open a trusted checkout of `kmjtechno/kmj-omnidesk` in Zed. The repository contains `.zed/settings.json` with only this credential-free remote MCP entry:

```json
{
  "context_servers": {
    "kmj-codebridge": {
      "url": "https://kmjtechno.com/mcp"
    }
  }
}
```

Zed can load project-level settings. Review any workspace trust prompt; only trust workspaces you control. Never commit access tokens, OAuth cookies, signing material or personal credentials into `.zed/settings.json`.

If another Zed setup already provides a CodeBridge server, avoid creating duplicate servers. Use **Settings → AI → MCP Servers** to review `kmj-codebridge`; if the project setting is not loaded, use **Add Server → Add Remote Server**, name it `kmj-codebridge`, and enter the HTTPS URL above. To edit your local/global settings, use the Command Palette action `zed: open settings file` and merge the `context_servers` entry rather than replacing existing settings.

Reference: https://zed.dev/docs/ai/mcp

## 2. Sign in and authorize the exact project

1. In Zed's MCP Servers view, inspect the connection indicator. Green / **Server is active** means the MCP server is reachable, **not** that any project is authorized.
2. If prompted, complete the **standard OAuth browser flow**. Do not paste bearer tokens, passwords, personal access tokens or cookies into project files or chat.
3. In KMJ Main Platform / CodeBridge, approve **the intended device and the exact `kmj-omnidesk` project**, with the correct repository root. A different project's grant (including `kmj-main-platform` or `kmj-codebridge`) does not authorize this one.
4. Verify that the agent can call `list_devices`, then check `connection_overview` for the exact chosen device and `kmj-omnidesk`. If it reports `ACCOUNT_PROJECT_GRANT_MISSING`, `ACCOUNT_GRANT_MISSING`, `OFFLINE`, or `UNKNOWN_TOOL`, stop and resolve the actual grant/runtime issue. Do not infer success from a green UI indicator.

The desktop agent must be online with a separately approved project root. Do **not** connect via a retired/offline device, widen another project's root, disable OAuth, bypass owner consent, or grant unrestricted shell access as a workaround.

## 3. Read-only smoke test from Zed Agent

Open Agent Panel and ask:

> Use KMJ CodeBridge only. List my authorized devices/projects and confirm an online, explicitly granted `kmj-omnidesk` project. Read `README.md` and `ROADMAP.yaml` inside that project's authorized root; report Git branch/commit, dirty state and any missing gate. Do not write, run commands, claim release readiness, or access unrelated projects.

**Pass:** server active, OAuth complete, project grant present, actual read-only file content and Git identity independently verified. **Blocked:** one or more steps cannot be confirmed; report which precise step failed.

## 4. Resume engineering after verified access

- Use a separate feature branch/worktree, preserve the approved KMJ visual design and existing changes, and obtain guarded SHA-pinned writes.
- Continue `ROADMAP.yaml` from evidence-backed milestones. Prioritize M4 real-network test instrumentation, M5 encrypted relay evidence, M9 cross-service licensing integration, security/release gates and Windows native QA as dependencies permit.
- Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings` and `cargo test --workspace --all-targets --all-features` using approved project quality gates. Also require exact-head Windows CI for native installers and shell behavior.
- **Do not** manufacture REALNET-60 observations or hardware/DPI results. An unsigned installer is not a commercial release. Keep `purchase_enabled_now: false` until protected signing, physical-network evidence, cross-service validation and independent M14 signoff all pass.
- Main Platform owns billing/licensing, not screen/audio/session data traffic. Preserve fail-closed authorization and zero-additional-paid-spend policy.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| MCP server entry missing | Open the correct trusted workspace; inspect `.zed/settings.json` and Settings → AI → MCP Servers |
| Red / disconnected indicator | Check the canonical HTTPS endpoint, gateway/service health and Zed network access |
| OAuth prompt fails | Verify supported OAuth redirects and server/client compatibility; do not embed credentials in Git |
| Green server but no OmniDesk tools | Ask `list_devices` and `connection_overview`; request a separate device/project authorization |
| Existing `kmj-codebridge` project only | That scope is insufficient: approve `kmj-omnidesk` separately |
| Files cannot be edited or quality gate unavailable | Inspect configured project permissions and gate profiles; do not bypass policy |
| Tests green but product not publishable | Follow `ROADMAP.yaml` and the real evidence checklist in issue #89 |

Zed supports remote MCP via `context_servers` and standard OAuth: https://zed.dev/docs/ai/mcp .
CodeBridge gateway onboarding: https://github.com/kmjtechno/kmj-codebridge/blob/main/docs/AI-CLIENT-QUICKSTART.md .
