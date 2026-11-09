# Tracking de casos

## Identidad y deduplicación

- Un MSG equivale a un expediente.
- `case_id` identifica el expediente; SHA-256 del MSG evita importaciones repetidas.
- SQLite (`storage/cases.db`) indexa casos y sirve a la ingestión para detectar duplicados.

## Fuente de verdad del análisis

`case.json` es el manifiesto inmutable de ingestión. El seguimiento que actualiza Kiro está en `analysis/state.json`; los hallazgos se registran en `analysis/findings.json`.

Estados permitidos: `pending`, `running`, `completed`, `skipped`, `not_applicable`, `failed`.

Etapas: `ingestion`, `extraction`, `triage`, `url_analysis`, `ioc_analysis`, `static_analysis`, `reverse_engineering`, `dynamic_analysis`, `report`.

## Fingerprints e idempotencia

`case.json` contiene fingerprints SHA-256 para las ramas analíticas. Antes de ejecutar una rama, el agente comprueba el estado y fingerprint. Si el estado es `completed` para el mismo fingerprint, reutiliza el resultado. Si el material de entrada cambió, no sobrescribe evidencia: se crea un caso/revisión nuevo.

El agente actualiza solo `analysis/state.json` y `analysis/findings.json`; nunca modifica originales, EML, adjuntos, extracción o `case.json`.

## Hallazgos

Cada hallazgo incluye categoría, observación, interpretación, fuente, referencia de evidencia, confianza, severidad e indicador opcional. Los detalles extensos permanecen en el artefacto original de la herramienta. El JSON contiene una síntesis breve y referencia, no dumps ni cuerpos completos.

## Informe

El agente genera `report/final-report.md` cuando triage y todas las ramas aplicables estén resueltas. Debe incluir herramientas realmente invocadas, etapas omitidas, evidencia contraria y limitaciones.

## Dinámica

Una rama dinámica no pasa de `not_applicable`/`pending` a `running` sin autorización explícita del usuario para esa muestra y confirmación de un laboratorio aislado y desechable. La referencia de autorización queda registrada en `analysis/state.json`.
