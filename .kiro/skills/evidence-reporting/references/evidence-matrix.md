# Matriz de interpretación de evidencia

Esta matriz guía el razonamiento; no es una puntuación automática.

| Señal | Puede respaldar | No demuestra por sí sola |
|---|---|---|
| SPF/DKIM/DMARC fallido | Inconsistencia de autenticación | Phishing: puede haber errores de configuración o reenvío |
| Reply-To distinto de From | Cambio de canal de respuesta | Suplantación maliciosa sin contexto |
| URL con dominio confusable | Riesgo de suplantación | Destino activo o entrega de malware |
| Ejecutable o macro | Capacidad de ejecutar código | Que sea malicioso |
| Ofuscación/empaquetado | Dificultad de inspección y motivo para profundizar | Intención maliciosa sin más evidencia |
| Reputación positiva | Señal externa contextual | Que el objeto/caso completo sea malicioso o que no haya falsos positivos |
| HTTP 403/404, timeout, challenge | Resultado puntual | Evasión, malicia o estado permanente del recurso |
| Coincidencia con marca | Posible imitación | Phishing sin validar dominio, contexto y conducta |
| Sin IOC detectados | No se encontraron IOC en el alcance revisado | Que el objeto sea seguro |

## Regla de decisión

- `phishing`, `malware` o `fraud`: evidencia convergente suficiente, con hechos decisivos explicados.
- `suspicious`: señales relevantes, pero falta confirmación o hay contradicción.
- `inconclusive`: datos ausentes, inaccesibles o ambiguos impiden una conclusión responsable.
- `legitimate`: evidencia consistente dentro del alcance; no es garantía universal.
- `spam`: correo no solicitado sin evidencia suficiente de phishing, fraude o malware.
