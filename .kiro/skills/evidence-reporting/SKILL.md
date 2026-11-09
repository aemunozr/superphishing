---
name: "evidence-reporting"
description: "Actualiza el tracking JSON del expediente, consolida hallazgos y redacta un informe proporcional a las evidencias disponibles."
---

# Tracking e informe

1. Lee `analysis/state.json` y `analysis/findings.json` del caso activo. `case.json` es el manifiesto de ingestión y no debe modificarse.
2. Después de cada etapa, actualiza solo la entrada correspondiente en `analysis/state.json`: `status`, `input_fingerprint`, `note`, `updated_utc`, `started_utc`, `completed_utc` y `authorization_reference` cuando corresponda.
3. Estados permitidos: `pending`, `running`, `completed`, `skipped`, `not_applicable`, `failed`. Para `skipped`/`failed`, escribe una razón breve. No marques `completed` sin resultado observado.
4. Usa exactamente el fingerprint correspondiente de `case.json`: `triage`, `url_analysis`, `ioc_analysis`, `static_analysis`, `reverse_engineering` o `dynamic_analysis`. No calcules hashes con el LLM.
5. Si una etapa está `completed` con el mismo fingerprint, reutiliza el resultado. Si el fingerprint cambió, no reemplaces evidencia: requiere expediente/revisión nueva.
6. Registra hallazgos en `analysis/findings.json`, con campos: `id`, `category`, `title`, `observation`, `interpretation`, `source`, `evidence_ref`, `confidence`, `severity`, `indicator`, `created_utc`. Mantén `observation` e `interpretation` separados. Deduplica por categoría + título + evidencia_ref + indicador.
7. Guarda detalles extensos en el artefacto original de la herramienta, cuando exista; en `findings.json` guarda una síntesis breve y la referencia. No copies dumps, blobs ni cuerpos completos.
8. El veredicto debe ser uno de: `phishing`, `malware`, `fraud`, `suspicious`, `spam`, `legitimate`, `inconclusive`. Severidad: `critical`, `high`, `medium`, `low`, `none`, `unknown`. Confianza: `high`, `medium`, `low`, `unknown`.
9. Finaliza solo cuando triage y todas las ramas aplicables estén resueltas. Actualiza `verdict`, `severity`, `confidence`, `finalized=true` y `updated_utc` en `state.json`; después genera `report/final-report.md` desde los hallazgos persistidos.
10. El informe estándar es conciso: resumen, alcance, evidencias principales, veredicto, limitaciones y recomendaciones. Añade secciones técnicas de URL, archivo, IOC o MITRE ATT&CK solo si existen evidencias suficientes.
11. No releas el correo completo para redactar el informe. Usa `summary.json`, resultados específicos y referencias a evidencias.
