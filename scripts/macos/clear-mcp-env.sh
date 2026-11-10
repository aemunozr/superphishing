#!/bin/bash
# Remove MCP secrets from the current macOS launchd user session.
set -euo pipefail
for name in \
  DARKNET_MCP_TOKEN \
  REMNUX_MCP_TOKEN \
  GHIDRA_MCP_BASIC_AUTH \
  RADARE2_MCP_TOKEN \
  X64DBG_MCP_BASIC_AUTH
do
  launchctl unsetenv "$name"
  printf 'Eliminada de launchd: %s\n' "$name"
done
printf '%s\n' 'Cierra Kiro completamente y vuelve a abrirlo para que deje de heredarlas.'
