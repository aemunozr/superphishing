---
name: "triage"
description: "Clasifica el expediente ya preparado, determina alcance y decide las ramas de análisis necesarias sin volver a extraer datos ni activar herramientas irrelevantes."
---

# Triage por etapas

1. Lee primero `case.json`, `summary.json` y `analysis/state.json`. No vuelvas a parsear MSG/EML ni recalcular IOC.
2. Identifica qué evidencia existe y qué objetivo analítico responde el expediente. Separa datos observados, inferencias y no verificados.
3. Razona sobre JSON local primero. Consultas externas/read-only solo si están autorizadas y aportan una respuesta material.
4. Decide ramas según evidencia: `url_analysis` para URLs; `ioc_analysis` para dominios/IPs/hashes contextuales; `static_analysis` para adjuntos; `reverse_engineering` solo para binarios que necesiten desensamblado; `dynamic_analysis` solo después de análisis estático insuficiente y con autorización específica más laboratorio aislado confirmado.
5. Marca `not_applicable` o `skipped` con una nota breve cuando una rama no aporte valor. No ejecutes herramientas por el mero hecho de que exista una Skill.
6. Descubre herramientas MCP solo de la especialidad seleccionada. Lee únicamente descripciones/esquemas de las candidatas; no enumeres todos los servidores ni todas las herramientas en cada caso.
7. Antes de cada rama, comprueba su estado y `input_fingerprint` en `analysis/state.json`; el valor de referencia debe coincidir con `case.json` → `fingerprints`. Reutiliza etapas `completed`; si cambió el material de entrada, no sobrescribas evidencia: solicita un caso/revisión nuevo.
8. Usa exactamente estos fingerprints de `case.json`: `triage` → `fingerprints.triage`; `url_analysis` → `fingerprints.url_analysis`; `ioc_analysis` → `fingerprints.ioc_analysis`; `static_analysis` → `fingerprints.static_analysis`; `reverse_engineering` → `fingerprints.reverse_engineering`; `dynamic_analysis` → `fingerprints.dynamic_analysis`. No calcules huellas con el LLM.
9. Actualiza la etapa `triage` en `analysis/state.json` con el fingerprint existente y una nota breve que explique qué ramas aplican. Para ramas omitidas, registra `not_applicable` o `skipped` con una razón breve.
10. Veredicto preliminar: usa solo el vocabulario de `evidence-reporting` (`phishing`, `malware`, `fraud`, `suspicious`, `spam`, `legitimate`, `inconclusive`). Nunca `likely_*`. La duda se expresa con `confidence`.
11. Campaña: antes de abrir ramas, busca en `cases/**/summary.json` y `cases/**/extracted/urls.json` (los expedientes se agrupan en `cases/AAAA/MM/DD/`; los antiguos están directamente en `cases/`) el mismo host o patrón de URL, el mismo remitente, el mismo Message-ID o un asunto similar en los últimos 7 días. Si ya hay un caso cerrado de la misma campaña, anótalo en la nota del triage, reutiliza sus hallazgos (cadena, reputación, exposición) y analiza solo lo nuevo.
   - Cierre abreviado: si el caso es un duplicado de plantilla (mismo remitente o Message-ID y mismo patrón de URL que un caso cerrado), no repitas consultas MCP ni el probe. Registra un hallazgo `campaign` que cite el caso principal, uno por cada diferencia observada (URL, remitente, autenticación) y un informe corto que remita al principal.
   - Mismo Message-ID que otro expediente indica el mismo correo reportado por varias personas: veredicto idéntico salvo evidencia nueva.
12. Exposición: si el veredicto es `phishing`, `fraud` o `malware` y hay IOC de red de destino confirmados, indica en la nota que aplica `exposure-assessment` (Power `exposure-hunting`, una vez por campaña, dentro de `ioc_analysis`).

## Selección de profundidad

- Básica: razonamiento sobre `summary.json`, headers y extractos relevantes.
- Técnica: consulta selectiva de reputación/CTI o análisis estático cuando existe un indicador que lo justifica.
- Profunda: Ghidra o dinámica únicamente cuando los resultados previos dejan una pregunta importante sin resolver.

El objetivo es agotar la evidencia disponible con el menor número de llamadas LLM y MCP, no maximizar la cantidad de herramientas ejecutadas.
