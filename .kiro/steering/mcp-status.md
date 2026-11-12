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
- `static-analysis` → `remnux` (Docker por HTTP). `upload_from_host` solo acepta rutas absolutas del propio host REMnux, no rutas de Windows.
- `exposure-hunting` → `falcon-mcp`, solo lectura (NG-SIEM, detecciones, intel).
- `threat-intelligence` → `gti-agentic`, reservado a escalados o campañas.

Reputación VirusTotal: la da `engine/reputation.py` en `extracted/reputation.json`. Léela antes de cualquier consulta MCP.
