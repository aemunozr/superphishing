---
inclusion: always
---
# Estado conocido de fuentes MCP

Revisado el 2026-11-12. Si una fuente de esta lista vuelve a funcionar, actualiza este archivo.

No las consultes; registra la limitación en el informe y sigue:

- `darknet` → URLhaus y ThreatFox (abuse.ch): `401 Unauthorized`, falta `ABUSECH_AUTH_KEY`.
- `darknet` → `phishing_check` (PhishTank): `403` por desafío Cloudflare.
- `darknet` → AbuseIPDB, Pulsedive, HIBP, IntelX, Hudson Rock, Hybrid Analysis: sin clave configurada.
- `exposure-hunting` → `cisco-secure-access`: el servidor no expone herramientas.

Funcionan:

- `darknet`: `otx_domain`, `otx_hash` (suele devolver 0 pulsos, señal débil), `greynoise_check`, CIRCL, Tor.
- `static-analysis` → `remnux` (Docker por HTTP). Las tools solo ven el host REMnux: `upload_from_host` no acepta rutas de la estación. Los adjuntos de riesgo llegan por `engine/remnux_stage.py` (en la ingesta); su ruta está en `extracted/remnux_stage.json` → `mcp_path`. La sesión puede caducar (`Server not initialized`): reintenta una vez tras reactivar el Power.
- `darknet`: la sesión puede caducar (`Session not found`). Si falla tras reactivar el Power, usa `extracted/reputation.json` y GTI, y regístralo como limitación.
- `exposure-hunting` → `falcon-mcp`, solo lectura (NG-SIEM, detecciones, intel).
- `threat-intelligence` → `gti-agentic`, reservado a escalados o campañas.

Reputación VirusTotal: la da `engine/reputation.py` en `extracted/reputation.json`. Léela antes de cualquier consulta MCP.
