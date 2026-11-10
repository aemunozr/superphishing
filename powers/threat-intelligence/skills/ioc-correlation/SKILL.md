---
name: "ioc-correlation"
description: "Normaliza, deduplica y correlaciona dominios, subdominios, URLs, IPs, emails, hashes, certificados y otros IOC con evidencias del caso y fuentes CTI autorizadas."
---

# Correlación de IOC y CTI

0a. Orden de fuentes, de más barata a más cara: `extracted/reputation.json` (VirusTotal, sin coste de agente) → Falcon Intel `falcon_search_indicators` (una llamada con todos los IOC, si el Power `exposure-hunting` está activo) → darknet (OTX/abuse.ch) → GTI, como máximo una vez por campaña. No consultes una fuente más cara si las anteriores ya responden la pregunta.
0. Si existe `extracted/reputation.json` (VirusTotal API v3, solo lectura, generado por `engine/reputation.py`), úsalo como primera fuente y no repitas esas consultas por MCP. Si falta o tiene IOC `pending`, indica al usuario que ejecute `engine/reputation.py`. Usa el MCP `gti-agentic` solo para escalar casos de severidad alta o campañas: pide únicamente una consulta, sin enviar nada a escanear, con el IOC mínimo y una respuesta de 10 líneas como máximo. Registra la conclusión en `findings.json`.
1. Lee únicamente los JSON pertinentes: `urls.json`, `ips.json`, `domains.json`, `attachments.json` y hallazgos previos. Conserva valor original, normalizado, fuente y relación con el artefacto.
2. Considera, si aparecen en evidencia, dominios/subdominios, URLs, IPv4/IPv6, email, hashes, nombres/rutas, certificados, User-Agent, mutex, claves de registro, endpoints y campañas. No inventes valores ausentes.
3. Prioriza IOC de contexto: destinos realmente enlazados, dominios de remitente, IPs en headers relevantes y hashes de adjuntos. No consultes listas completas indiscriminadamente.
4. Deduplica por tipo/valor/fuente y evita transformar cada URL en muchos IOC redundantes sin utilidad analítica.
5. Descubre solo herramientas CTI disponibles en los MCP ya conectados a Kiro. Consulta fuentes autorizadas; registra fuente exacta, resultado, fecha/ventana y limitaciones. No afirmes haber usado VirusTotal, MISP, Shodan u otra fuente sin consulta real.
6. No transmitas adjuntos, cuerpos completos, datos personales, credenciales ni secretos a servicios externos. Comparte solamente el indicador mínimo necesario.
7. Trata reputación como contexto, no como prueba. Un IOC limpio/ausente no demuestra legitimidad; una coincidencia aislada no prueba malicia. Considera falsos positivos, datos envejecidos, CDN, hosting compartido, DNS público y servicios legítimos abusados.
8. Clasifica cada IOC según evidencia: malicioso, sospechoso, intermediario, servicio legítimo abusado, suplantación, benigno o no concluyente. Justifica confianza y contradicciones.
9. Recomienda bloqueo, búsqueda retroactiva o monitorización; nunca ejecutes acciones de remediación sobre sistemas.
