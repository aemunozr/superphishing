---
name: "evidence-reporting"
description: "Actualiza el tracking JSON del expediente, consolida hallazgos y redacta un informe proporcional a las evidencias disponibles."
---

# Tracking e informe

1. Lee `analysis/state.json` y `analysis/findings.json` del caso activo antes de escribirlos. Conserva los hallazgos existentes: añade, corrige o deduplica, pero no reemplaces el archivo sin haberlo leído. `case.json` es el manifiesto de ingestión y no debe modificarse.
2. Después de cada etapa, actualiza solo la entrada correspondiente en `analysis/state.json` con ediciones puntuales, no reescribiendo el archivo entero: `status`, `input_fingerprint`, `note`, `updated_utc`, `started_utc`, `completed_utc` y `authorization_reference` cuando corresponda. La etapa `report` no tiene fingerprint en `case.json`: deja `input_fingerprint` vacío.
3. Estados permitidos: `pending`, `running`, `completed`, `skipped`, `not_applicable`, `failed`. Para `skipped`/`failed`, escribe una razón breve. No marques `completed` sin resultado observado.
4. Usa exactamente el fingerprint correspondiente de `case.json`: `triage`, `url_analysis`, `ioc_analysis`, `static_analysis`, `reverse_engineering` o `dynamic_analysis`. No calcules hashes con el LLM.
5. Si una etapa está `completed` con el mismo fingerprint, reutiliza el resultado. Si el fingerprint cambió, no reemplaces evidencia: requiere expediente/revisión nueva.
6. Registra hallazgos en `analysis/findings.json`, con campos: `id`, `category`, `title`, `observation`, `interpretation`, `source`, `evidence_ref`, `confidence`, `severity`, `indicator`, `created_utc`. Mantén `observation` e `interpretation` separados. Deduplica por categoría + título + evidencia_ref + indicador.
7. Guarda detalles extensos en el artefacto original de la herramienta, cuando exista; en `findings.json` guarda una síntesis breve y la referencia. No copies dumps, blobs ni cuerpos completos.
8. El veredicto debe ser uno de: `phishing`, `malware`, `fraud`, `suspicious`, `spam`, `legitimate`, `inconclusive`. Severidad: `critical`, `high`, `medium`, `low`, `none`, `unknown`. Confianza: `high`, `medium`, `low`, `unknown`.
9. Finaliza solo cuando triage y todas las ramas aplicables estén resueltas. Actualiza `verdict`, `severity`, `confidence`, `finalized=true`, `finalized_utc` y `updated_utc` en `state.json`; después genera `report/final-report.md` desde los hallazgos persistidos.
   - Si quedan comprobaciones que el pipeline no puede resolver (confirmación de negocio, sandbox, exposición interna), finaliza igualmente y regístralas en `pending_verifications`: una lista de objetos `{item, owner, impact_if_negative}`. Repite la lista en la sección "Verificaciones pendientes" del informe. Un caso solo está cerrado del todo con `pending_verifications` vacío. Ver `docs/TRACKING.md`.
9b. Mínimos según el veredicto:
   - `phishing`, `fraud` o `malware`: cadena de redirección obtenida con el probe de `url-analysis` (o el motivo concreto por el que no se pudo seguir: sin enlaces clicables, REMnux caído, `antibot_gate`, `login_page`; "prohibido por regla" no es un motivo válido), reputación de los destinos, correlación de campaña, exposición interna (hallazgo `exposure` propio o referenciado) o su ausencia registrada en `pending_verifications`, y tabla de IOC para bloqueo.
   - `spam` o `legitimate`: autenticación, motivo del veredicto y recomendación.
   - Severidad de hallazgo informativo: `none`, no `informational`. Cada hallazgo lleva `title` y `created_utc`.
10. El informe estándar es conciso: resumen, alcance, evidencias principales, veredicto, limitaciones y recomendaciones. Añade secciones técnicas de URL, archivo, IOC o MITRE ATT&CK solo si existen evidencias suficientes.
11. No releas el correo completo para redactar el informe. Usa `summary.json`, resultados específicos y referencias a evidencias.
