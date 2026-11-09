# Changelog

## 1.3.0

- Added Power-scoped `mcp.json` files for the exact MCP endpoints supplied by the user.
- Mapped Darknet to Threat Intelligence; REMnux and REMnux Docs to Static Analysis; Ghidra and Radare2 to Reverse Engineering; x64dbg to Dynamic Analysis.
- Added environment-variable placeholders for all authentication headers; no secret values are stored in the repository.
- Added optional macOS scripts to set/clear secrets in the launchd user session without writing them to files.
- Set `security-analyst` to `includeMcpJson: false` and `includePowers: true`.
- Added workspace overrides to disable the six same-named global MCP entries only within this workspace.
- Explicitly marked Procmon as pending because it was absent from the supplied MCP configuration.
- Documented rotation of credentials exposed in the conversation.

## 1.2.0

- Restored four native Kiro Power packages under `powers/` with valid `plugin.json` manifests.
- Moved CTI, file analysis, reverse engineering and dynamic analysis Skills into their relevant Power packages.
- Kept five general Skills in `.kiro/skills/` so the base project context remains small.
- Enabled `includePowers` for the coordinator agent.
- Preserved deterministic ingestion, SHA-256 validation, JSON case tracking and SQLite deduplication.

## 1.1.0

- Removed native Power packages in favor of workspace Skills.
- Kept one workspace agent and deterministic case tracking.

## 1.0.0

- Initial deterministic ingestion, extraction and case tracking pipeline.
