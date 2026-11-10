# Dynamic Analysis Power

Incluye la Skill `dynamic-analysis` y una conexión MCP propia con x64dbg. Procmon no aparece en el `mcp.json` recibido y no se declara como conectado; se añadirá cuando se disponga de su endpoint y autenticación reales.

Credencial: `X64DBG_MCP_BASIC_AUTH` (Base64 de `usuario:contraseña`, sin el prefijo `Basic `). Base64 es codificación reversible, no cifrado. No guardar secretos en este directorio.

El análisis dinámico exige autorización explícita por muestra y laboratorio aislado y desechable.
