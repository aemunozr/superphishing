# Investigación escalonada de URLs y cadenas

Usar esta referencia únicamente cuando el triage detecte una URL o cadena relevante. No ejecutar todas las fases por defecto.

## Etapa 1 — Evidencia del correo
- Recuperar URL exacta, texto visible, ubicación HTML, hostname y mensaje de origen desde JSON.
- Identificar acortadores, punycode, IP literal, credenciales embebidas y codificaciones múltiples.
- No abrir URL ni ejecutar JavaScript.

## Etapa 2 — Análisis sintáctico y de infraestructura
- Normalizar para parsing sin sustituir el valor original.
- Separar dominio registrable, subdominios, ruta, query y fragmento.
- Usar solo datos locales o fuentes pasivas autorizadas; evitar consultas redundantes.

## Etapa 3 — Reputación y correlación pasiva
- Consultar únicamente fuentes reales disponibles. Registrar proveedor, fecha, indicador, resultado y limitación.
- Un resultado limpio/no encontrado no demuestra legitimidad; una detección aislada no prueba el caso completo.

## Etapa 4 — Redirecciones observadas
- Solo si la consulta externa está autorizada y el destino está dentro del alcance.
- Revalidar cada salto; bloquear loopback, redes privadas, link-local, metadata y destinos internos.
- Registrar URL de cada salto, código, timestamp, método y fuente. No inferir saltos desde parámetros o HTML.
- Si se comparan perfiles de cliente/User-Agent, usar únicamente perfiles de prueba autorizados y fijos; nunca rotarlos para evadir anti-bot, autenticación, WAF o rate limits.
- Un 403, 404, challenge, timeout o DNS failure no demuestra evasión ni malicia.

## Etapa 5 — Contenido de destino y cadenas de entrega
- Inspeccionar únicamente evidencia obtenida de forma autorizada y segura. No descargar ni ejecutar payloads automáticamente.
- Si el correo/adjunto contiene referencias a `.lnk`, `mshta`, PowerShell, scripts o protocolos especiales, trátalas como cadenas estáticas: identifica argumentos, destinos, archivos referenciados y etapas potenciales sin ejecutar.
- Vincular cada etapa con su fuente y hash cuando exista. Distinguir claramente una cadena hipotética de una cadena observada.

## Cierre
Detener el análisis cuando la evidencia sea suficiente para responder la pregunta. No hacer crawling, fuzzing, enumeración de directorios, evasión ni pruebas indiscriminadas.
