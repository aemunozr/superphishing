---
name: "mcp-tool-discovery"
description: "Localiza de forma selectiva las herramientas MCP existentes para una tarea concreta, sin enumerar todos los servidores ni cargar descripciones irrelevantes."
---

# Descubrimiento MCP selectivo

1. Decide primero la capacidad requerida a partir del expediente. No inspecciones todos los servidores ni todas las herramientas.
2. Usa la búsqueda de herramientas MCP de Kiro, si está disponible, con 2–4 términos específicos de la tarea. Lee solo las descripciones/esquemas de las 1–3 candidatas más relevantes.
3. Mapa funcional: Darknet → CTI/IOC; REMnux → análisis estático; Ghidra y Radare2 → ingeniería inversa; x64dbg → análisis dinámico. Procmon no está configurado en este proyecto. Estos son roles esperados, no nombres de herramientas: usa únicamente nombres reales anunciados por los MCP del Power activado.
4. Comprueba entradas, salidas, límites y efectos antes de invocar. Distingue lectura local, consulta de red, descarga, ejecución/depuración y modificación.
5. Prioriza operaciones de lectura y análisis estático. Trata `run`, `execute`, `debug`, `fetch`, `download`, `open`, `write` y `delete` como potencialmente activas hasta verificar su descripción.
6. No inventes herramientas, parámetros, rutas, resultados ni capacidades. La conexión del servidor no demuestra que la herramienta o el laboratorio subyacente funcione.
7. Si una herramienta no existe o falla, registra la limitación y continúa con capacidades reales. No repitas descubrimiento en la misma etapa sin una razón material.
8. No hagas un inventario global por caso ni cargues salidas completas de herramientas cuando baste con una síntesis y referencias.
