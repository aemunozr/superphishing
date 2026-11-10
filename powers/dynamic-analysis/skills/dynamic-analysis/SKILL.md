---
name: "dynamic-analysis"
description: "Planifica y analiza comportamiento dinámico con x64dbg únicamente (Procmon queda pendiente de configurar) y solo tras autorización explícita por muestra y confirmación de un laboratorio aislado y desechable."
---

# Análisis dinámico controlado

1. No actives esta Skill por la mera presencia de un adjunto. Debe existir una pregunta material que el análisis estático no resolvió.
2. Antes de cualquier ejecución, exige autorización explícita y específica para el caso/muestra y confirma un laboratorio aislado, desechable, sin credenciales reales y con controles de red/compartición adecuados.
3. Si falta cualquier requisito, no ejecutes. Registra la etapa como `skipped` con la razón.
4. Identifica solo herramientas reales anunciadas por el MCP x64dbg. No supongas que Procmon está conectado: no aparece en la configuración proporcionada. No uses Bash ni comandos del sistema, no desactives controles ni amplíes alcance.
5. Define objetivo, proceso, red permitida, artefactos, snapshot/restauración y condiciones de parada. No conectes infraestructura maliciosa real desde redes productivas.
6. Registra eventos realmente observados: proceso/padre, ruta, operación, timestamp, resultado y referencia a captura/log.
7. Distingue observación de hipótesis. Si una tool falla o no se invoca, decláralo.
8. Registra autorización de forma trazable en `authorization_reference`; nunca la infieras de una autorización genérica para analizar correo.
