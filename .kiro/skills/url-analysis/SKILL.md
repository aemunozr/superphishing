---
name: "url-analysis"
description: "Investiga URLs extraídas: análisis sintáctico, seguimiento controlado de redirecciones en REMnux, descargables y reputación autorizada."
---

# Investigación de URLs

1. Usa `extracted/urls.json`. Conserva `value` exacto como original y usa `normalized_for_parsing` solo para parsear. No vuelvas a extraer ni a deduplicar.
2. Análisis sintáctico: esquema, hostname, puerto, credenciales embebidas, IP literal, Punycode/IDN, dominio registrable, subdominios engañosos, ruta, parámetros, acortadores y codificación repetida. Compara el texto visible con el destino.
3. Correlación de campaña antes de gastar llamadas: busca el mismo host o patrón en `cases/*/extracted/urls.json` y en los `findings.json` de otros casos. Si otro caso ya resolvió ese mismo enlace o destino, reutiliza su cadena y su reputación, cítalo y no vuelvas a seguirlo.

## Seguimiento de redirecciones (solo `phishing` o `suspicious` en el triage)

4. Sigue **solo enlaces clicables** (fuentes `html:a.href`, `html:form.action`, `body_text`). Nunca imágenes ni píxeles. Máximo 5 enlaces distintos por caso.
5. **Siempre desde REMnux** (`run_tool` del Power `static-analysis`), nunca desde la red corporativa. Antes, quita de la URL los parámetros que identifican a la víctima (`_token`, `token`, `_uid`, `uid`, `mid`, `email`, `e`, `u`, `recipient`).
6. Ejecuta **una sola llamada por enlace** con este probe, sustituyendo `<URL>` y `<CASE>`. Sigue respuestas 3xx, meta refresh y `location`/`location.replace` con URL literal. Para en IP privada o local, en error o a los 15 saltos. Devuelve una línea por salto:

```bash
U='<URL>'; D=/home/remnux/files/samples/probe_<CASE>; mkdir -p "$D"; UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36'; for i in $(seq 1 15); do H=$(echo "$U" | sed -E 's#^https?://([^/:?]+).*#\1#'); if getent ahosts "$H" | awk '{print $1}' | grep -qE '^(0\.|10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|::1$|f[cd]|fe80)'; then echo "$i BLOCKED_PRIVATE $H"; break; fi; F="$D/hop$i"; R=$(curl -sS --max-time 20 --max-filesize 26214400 --proto =https,http -A "$UA" -o "$F" -w '%{http_code}|%{content_type}|%{redirect_url}|%{size_download}' "$U" 2>&1) || { echo "$i ERR $U $R"; break; }; IFS='|' read -r CODE CT NEXT SIZE <<< "$R"; echo "$i $CODE ${U%%\?*} ct=$CT size=$SIZE sha256=$(sha256sum "$F" | cut -c1-64) magic=$(file -b "$F" | cut -c1-50)"; if [ -z "$NEXT" ] && grep -qiE '<html|<!doctype' "$F"; then NEXT=$(grep -oiE "(http-equiv=.refresh[^>]*url=|location(\.href)? *= *|location\.(replace|assign)\()['\"][^'\"]+" "$F" | head -1 | sed -E "s/.*['\"]//"); [ -n "$NEXT" ] && echo "$i HTML_REDIRECT $NEXT"; fi; [ -z "$NEXT" ] && break; case "$NEXT" in http*) U="$NEXT";; /*) U="$(echo "$U" | grep -oE '^https?://[^/]+')$NEXT";; *) U="${U%/*}/$NEXT";; esac; done
```

7. **No eludas** filtros anti-bot, CAPTCHA, login, WAF ni rate limits: no envíes formularios, tokens ni POST de validación, y no ejecutes JavaScript. Si la cadena termina en uno de ellos, regístralo como `antibot_gate` o `login_page`. El contenido posterior queda en `pending_verifications` (sandbox con navegador).

## Descargables

8. Un salto es **descargable** si su `magic` no es HTML/texto (PE, ZIP/RAR/7z, ISO/IMG, OLE/Office, PDF, LNK, JS/VBS/HTA/script, APK, MSI) o si `ct` no es `text/*`. En ese caso, en el mismo REMnux y sin transferir nada:
   - `analyze_file` con `depth: "quick"` sobre `probe_<CASE>/hopN`. Usa `standard` solo si quick marca algo.
   - Registra en `findings.json` el SHA-256, el tipo, el tamaño, la URL de origen y el resultado resumido. No copies la salida completa.
   - Si es PE/ELF y quick no basta, deriva a `reverse-engineering`. Nunca a `dynamic-analysis` sin autorización.
9. Limpieza: al terminar, `rm -rf /home/remnux/files/samples/probe_<CASE>`. La evidencia queda en los hashes registrados.

## Registro y reputación

10. Registra cada salto (código, host y URL sin query) con la hora y la fuente `REMnux curl`. Pasa los hosts nuevos de la cadena a `ioc-correlation`. Usa primero `extracted/reputation.json` o VirusTotal, y GTI solo una vez por campaña.
11. Un 403/404, timeout, fallo DNS, challenge o certificado válido no prueba por sí solo ni malicia ni legitimidad.
12. No envíes cookies, credenciales, cuerpos ni datos personales a servicios externos.
