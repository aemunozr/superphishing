---
name: "reverse-engineering"
description: "Realiza análisis estático de binarios con Ghidra y/o Radare2: arquitectura, entry point, imports, strings, funciones, llamadas y referencias cruzadas."
---

# Ingeniería inversa estática

1. Confirma expediente, SHA-256, tipo real y arquitectura. Verifica que la muestra corresponde al hash del manifiesto; nunca alteres el original.
2. Usa solo las herramientas MCP reales de Ghidra y/o Radare2 que estén disponibles en el Power. Descubre únicamente las funciones necesarias para importar/consultar la muestra y el proyecto; no enumeres el servidor completo.
3. Prioriza entry point, imports, strings relevantes, funciones relacionadas con red/archivos/procesos, persistencia, criptografía, empaquetado y referencias cruzadas cuando exista motivo.
4. Limita la consulta a funciones, direcciones y referencias que respondan la pregunta; evita exportar decompilados completos al contexto.
5. Distingue el análisis en el desensamblador de ejecutar el binario. No ejecutes la muestra ni escribas sobre el original.
6. No declares malware por un import, una cadena o una función aislada. Busca contexto y flujo de control.
7. Registra SHA-256, herramienta realmente usada, función/dirección, evidencia observada, hipótesis, confianza y limitaciones.
