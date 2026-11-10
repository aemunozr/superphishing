# Credenciales MCP de los Powers

Los `mcp.json` de los Powers contienen únicamente placeholders `${VARIABLE}`. No guardan tokens ni contraseñas.

| Variable | Servidor | Formato esperado |
|---|---|---|
| `DARKNET_MCP_TOKEN` | Darknet | Token Bearer, sin `Bearer ` |
| `REMNUX_MCP_TOKEN` | REMnux | Token Bearer, sin `Bearer ` |
| `GHIDRA_MCP_BASIC_AUTH` | Ghidra | Base64 de `usuario:contraseña`, sin `Basic ` |
| `RADARE2_MCP_TOKEN` | Radare2 | Token Bearer, sin `Bearer ` |
| `X64DBG_MCP_BASIC_AUTH` | x64dbg | Base64 de `usuario:contraseña`, sin `Basic ` |

Base64 es codificación reversible, no cifrado. No compartas su contenido como si fuera inocuo.

## macOS: configurar sin escribir secretos a archivos

Kiro expande variables de entorno aprobadas en los headers MCP. Un archivo `.env` dentro del proyecto no se carga automáticamente.

1. Rota las credenciales que se compartieron accidentalmente en una conversación. Usa credenciales nuevas.
2. Abre Terminal en la raíz del proyecto y ejecuta:

   ```bash
   bash scripts/macos/set-mcp-env.sh
   ```

3. Introduce los cinco valores cuando el script los solicite. La entrada es oculta; el script los coloca en el entorno de `launchd` de tu sesión macOS y no los escribe en archivos ni los imprime.
4. Cierra Kiro completamente con `Cmd+Q` y vuelve a abrirlo para que herede las variables.
5. En Kiro, abre Settings, busca **Mcp Approved Env Vars** y aprueba exactamente los cinco nombres de la tabla.
6. Importa los Powers locales desde sus carpetas (solo una vez) y comprueba la conexión al activar cada Power.

El entorno de `launchd` queda disponible para procesos de tu sesión de usuario. No uses este método en una cuenta macOS compartida o no confiable. Cuando termines, puedes retirar las variables de la sesión con:

```bash
bash scripts/macos/clear-mcp-env.sh
```

Después de limpiar, cierra y vuelve a abrir Kiro. Para volver a usar los Powers deberás configurar las variables otra vez.

## Validación

- Si un Power no conecta, confirma que la variable correspondiente está definida y aprobada.
- Revisa el estado del servidor en Kiro después de activar el Power.
- No pegues tokens en prompts, logs, capturas ni archivos versionados.
- Se recomienda usar credenciales Basic distintas para Ghidra y x64dbg si el servicio lo permite.

## Procmon

Procmon no aparece en el `mcp.json` que se revisó. Por ahora no se configura ni se anuncia como disponible dentro del Power dinámico.
