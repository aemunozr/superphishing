# Exposure Hunting Power

Incluye la Skill `exposure-assessment` y los MCP de CrowdStrike Falcon y Cisco Secure Access. Responde a una sola pregunta: **¿quién de la organización tuvo contacto con los IOC maliciosos confirmados?** Se usa una vez por campaña y solo en modo lectura.

## Instalación

1. Quita `falcon-mcp` y `cisco-secure-access` del `~/.kiro/settings/mcp.json` global. Así solo se cargan cuando el Power está activo, que es lo que ahorra créditos.
2. Copia `mcp.json.example` como `mcp.json` y ajusta la ruta del `.env` de Falcon.
3. En el `.env` de Falcon (fuera del repositorio), además de `FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET` y `FALCON_BASE_URL`:
   - `FALCON_MCP_READ_ONLY=true`: solo registra herramientas de lectura.
   - `FALCON_MCP_DYNAMIC=true`: expone 3 herramientas de descubrimiento en vez de unas 200.
   - `FALCON_MCP_MODULES=detections,hosts,intel,ngsiem`.
4. Cisco: `CISCO_SA_MCP_TOKEN` como variable de entorno aprobada. El servidor community no tiene modo de solo lectura documentado; la Skill prohíbe sus herramientas de escritura.
5. Importa la carpeta desde **Powers → Add Custom Power → Import power from a folder**.

Referencias: [configuración de falcon-mcp](https://developer.crowdstrike.com/falcon-mcp/getting-started/configuration/), [modo dinámico](https://developer.crowdstrike.com/falcon-mcp/usage/dynamic-mode/).
