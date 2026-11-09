---
name: "url-analysis"
description: "Investiga URLs extraídas: esquema, hostname, Punycode, credenciales, IP literal, parámetros, redirecciones observadas y reputación autorizada."
---

# Investigación de URLs

1. Usa `extracted/urls.json`; conserva `value` exacto como original y usa `normalized_for_parsing` solo para parsear. No vuelvas a extraer ni deduplicar si el parser ya lo hizo.
2. Analiza esquema, hostname, puerto, usuario/contraseña embebidos, IP literal, Punycode/IDN, dominio registrable, subdominios engañosos, ruta, parámetros, acortadores y codificación repetida.
3. Compara texto visible y destino HTML. Señala discrepancias de marca/dominio, sin atribuir intención únicamente por similitud visual.
4. No abras URLs ni realices DNS/HTTP automáticamente. La consulta externa requiere alcance autorizado. No envíes cookies, tokens, credenciales, cuerpo completo ni datos personales a servicios externos.
5. Bloquea localhost, loopback, RFC1918, IPv6 privado, link-local, dominios internos y endpoints de metadata. Revalida cada salto antes de seguir redirecciones; no eludas autenticación, anti-bot, WAF ni rate limits.
6. Distingue análisis sintáctico, reputación, resolución DNS, petición HTTP y navegación. Registra solo saltos y códigos realmente observados con fuente y timestamp disponible.
7. Un 403/404, timeout, DNS failure, challenge o certificado válido no demuestra por sí mismo malicia ni legitimidad.
8. Correlaciona URL, hostname, IP y correo de origen. Evita repetir consultas al mismo IOC/fuente/ventana temporal. Registra fuente, resultado, fecha y limitaciones.
