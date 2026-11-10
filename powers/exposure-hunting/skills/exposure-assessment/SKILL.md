---
name: "exposure-assessment"
description: "Mide la exposición interna (equipos y usuarios que contactaron IOC maliciosos confirmados) con Falcon NG-SIEM y Cisco Secure Access, en solo lectura y una vez por campaña."
---

# Evaluación de exposición

## Cuándo

1. Solo si el veredicto es `phishing`, `fraud` o `malware` y existen IOC de red **confirmados**: dominios o IP de destino de la cadena de redirección (Skill `url-analysis`), hosts de descarga o hashes detectados. Nunca con dominios de remitente legítimos comprometidos, plataformas masivas (`share.google`, `gmail.com`, `googleusercontent.com`) ni infraestructura propia.
2. **Una vez por campaña.** Antes de consultar, busca en `cases/*/analysis/findings.json` un hallazgo `category: "exposure"` con los mismos IOC y una ventana que cubra la actual. Si existe y tiene menos de 24 h, cítalo y no consultes.
3. Máximo 10 IOC por consulta. Agrúpalos todos en una sola llamada.

## Solo lectura (obligatorio)

4. Prohibido: crear, editar o borrar listas de destino, reglas de acceso, IOC, exclusiones, políticas, casos o detecciones; contener hosts; iniciar sesiones RTR; ejecutar workflows. Se **recomiendan** acciones, nunca se ejecutan.
5. Falcon trabaja en modo dinámico (`FALCON_MCP_DYNAMIC=true`). Busca el esquema solo de la herramienta que vayas a usar (`falcon_search_tools`) y no listes el inventario completo.

## Consultas fijas

Ventana: desde 24 h antes del primer envío de la campaña hasta ahora. Formato ISO 8601 UTC.

6. **Falcon NG-SIEM, DNS por equipo** (una llamada, salida agregada):

```
#event_simpleName=DnsRequest DomainName=/(^|\.)(<dom1>|<dom2>|<dom3>)$/i
| groupBy([DomainName, ComputerName], function=[count(), min(@timestamp, as=first_seen), max(@timestamp, as=last_seen)])
| sort(_count, order=desc) | head(20)
```

   Escapa los puntos de los dominios (`htxklyq\.com`). Revisa `job.parsed_query` en la respuesta. Si `job` indica que no escaneó eventos, el resultado es **no concluyente**, no "sin exposición".

7. **Falcon NG-SIEM, conexiones a IP** (solo si hay IP confirmadas):

```
#event_simpleName=NetworkConnectIP4 RemoteAddressIP4=/^(<ip1>|<ip2>)$/
| groupBy([RemoteAddressIP4, ComputerName], function=[count(), min(@timestamp, as=first_seen)]) | head(20)
```

8. **Falcon Intel y detecciones** (solo si las consultas 6 o 7 devuelven equipos): `falcon_search_indicators` con `indicator:['<ioc1>','<ioc2>']` y `falcon_search_detections` filtrado por los `ComputerName` afectados y la ventana. Pide `limit` ≤ 10.
9. **Cisco Secure Access, estado de bloqueo:** `search_domain_across_lists` por cada dominio de destino (salida corta). Opcional: `investigate_domain` para conocer su categorización. No uses `get_activity*`, `get_top_*` ni `get_summaries_*`: no filtran por dominio y devuelven mucho volumen.

## Registro

10. Un hallazgo por campaña en `findings.json` del caso activo:
    - `category: "exposure"` y `title`.
    - `observation`: número de equipos y consultas, top 5 de `ComputerName` con primera y última vez, y estado de bloqueo en Cisco.
    - `interpretation`.
    - `source`: herramientas usadas.
    - `evidence_ref`: ventana y consulta.
    - `confidence`, `severity` e `indicator`: la lista de IOC.
    - No incluyas usuarios ni datos personales que no sean necesarios.
11. En los demás casos de la campaña, añade un hallazgo `exposure` que solo **referencie** al principal (`evidence_ref: "CASE-…:F<n>"`), sin repetir la consulta.
12. Interpretación:
    - **0 equipos con eventos escaneados:** sin exposición observada en la telemetría de Falcon. Los equipos sin sensor o fuera de la red no están cubiertos.
    - **Equipos con resolución DNS:** posible clic. Recomienda revisar ese equipo y al usuario, y restablecer credenciales si hubo acceso a un login.
    - **Dominio no bloqueado en Cisco:** recomienda añadirlo a la lista de bloqueo. Lo hace el operador, no el agente.
13. Si un MCP no está disponible, registra la exposición como `pending_verifications` (ver `evidence-reporting`) con el motivo. No la des por descartada.
