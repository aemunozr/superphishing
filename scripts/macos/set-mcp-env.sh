#!/bin/bash
# Set MCP secrets in the current macOS launchd user session without saving them to disk.
# Run this script in Terminal, then fully quit and reopen Kiro.
set -euo pipefail

set_secret() {
  local name="$1"
  local label="$2"
  local value=""
  printf '%s' "$label: "
  IFS= read -r -s value
  printf '\n'
  if [[ -z "$value" ]]; then
    printf 'No se configuró %s: valor vacío.\n' "$name" >&2
    return 1
  fi
  launchctl setenv "$name" "$value"
  unset value
  printf 'Configurada: %s\n' "$name"
}

printf '%s\n' 'Introduce las credenciales ROTADAS. Los valores no se guardan en archivos.'
printf '%s\n' 'Bearer: pega solo el token, sin el prefijo Bearer.'
printf '%s\n' 'Basic: pega el Base64 de usuario:contraseña, sin el prefijo Basic.'
printf '\n'

set_secret "DARKNET_MCP_TOKEN" "Darknet Bearer token"
set_secret "REMNUX_MCP_TOKEN" "REMnux Bearer token"
set_secret "GHIDRA_MCP_BASIC_AUTH" "Ghidra Basic auth (Base64 usuario:contraseña)"
set_secret "RADARE2_MCP_TOKEN" "Radare2 Bearer token"
set_secret "X64DBG_MCP_BASIC_AUTH" "x64dbg Basic auth (Base64 usuario:contraseña)"

printf '\n%s\n' 'Variables configuradas en launchd para esta sesión de usuario.'
printf '%s\n' 'Cierra Kiro completamente (Cmd+Q) y vuelve a abrirlo para que herede el entorno.'
printf '%s\n' 'En Kiro, aprueba estos nombres en Settings → Mcp Approved Env Vars.'
