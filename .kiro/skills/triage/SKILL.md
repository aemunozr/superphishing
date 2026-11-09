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

## Selección de profundidad

- Básica: razonamiento sobre `summary.json`, headers y extractos relevantes.
- Técnica: consulta selectiva de reputación/CTI o análisis estático cuando existe un indicador que lo justifica.
- Profunda: Ghidra o dinámica únicamente cuando los resultados previos dejan una pregunta importante sin resolver.

El objetivo es agotar la evidencia disponible con el menor número de llamadas LLM y MCP, no maximizar la cantidad de herramientas ejecutadas.
