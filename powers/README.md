# Powers nativos del proyecto

El repositorio incluye cuatro Powers nativos independientes. Cada uno contiene `plugin.json`, `mcp.json` y una Skill especializada:

- `threat-intelligence/` → IOC y CTI con Darknet.
- `static-analysis/` → análisis estático con REMnux y documentación REMnux.
- `reverse-engineering/` → Ghidra y Radare2.
- `dynamic-analysis/` → x64dbg. Procmon queda pendiente de recibir su configuración real.
- `exposure-hunting/` → exposición interna con CrowdStrike Falcon (NG-SIEM, detecciones, intel) y Cisco Secure Access, en solo lectura y una vez por campaña. Ver su README: los MCP deben salir del `mcp.json` global.

Importa cada carpeta una sola vez desde **Powers → Add Custom Power → Import power from a folder**. Kiro administra las conexiones MCP asociadas al Power y las activa/desactiva con este. No se instalan herramientas del sistema ni servidores nuevos.

Las credenciales se referencian mediante variables de entorno aprobadas; nunca se guardan dentro de este repositorio. Consulta `docs/MCP-ENVIRONMENT.md`.
