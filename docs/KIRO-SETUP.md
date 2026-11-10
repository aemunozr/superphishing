# Abrir y configurar el proyecto en Kiro

## 1. Abrir el proyecto

1. Descomprime el ZIP.
2. En Kiro selecciona **File → Open Folder** y abre `security-analysis-pipeline`.
3. Selecciona el agente `security-analyst`.
4. Kiro descubre las Skills generales del workspace. Sus nombres y descripciones se cargan inicialmente; el contenido completo de cada Skill se carga cuando resulta relevante.

## 2. Importar los cuatro Powers locales (una sola vez)

Las carpetas Power permanecen dentro de este mismo proyecto. En Kiro:

1. Abre el panel **Powers**.
2. Selecciona **Add Custom Power → Import power from a folder**.
3. Importa `powers/threat-intelligence`.
4. Repite con `powers/static-analysis`, `powers/reverse-engineering` y `powers/dynamic-analysis`.

Esto registra los cuatro Powers personalizados en Kiro. No instala binarios, herramientas de análisis, paquetes de sistema ni servidores nuevos. Kiro administra los MCP declarados en el `mcp.json` de cada Power y los activa/desactiva junto con el Power.

## 3. Distribución de MCP por Power

| Power | MCP declarados | Variable(s) |
|---|---|---|
| `threat-intelligence` | Darknet | `DARKNET_MCP_TOKEN` |
| `static-analysis` | REMnux + REMnux Docs | `REMNUX_MCP_TOKEN` |
| `reverse-engineering` | Ghidra + Radare2 | `GHIDRA_MCP_BASIC_AUTH`, `RADARE2_MCP_TOKEN` |
| `dynamic-analysis` | x64dbg | `X64DBG_MCP_BASIC_AUTH` |

Los servidores son los endpoints que compartiste. Los `mcp.json` de los Powers conservan los endpoints, pero reemplazan los secretos por variables de entorno. Kiro namespacia los nombres de los servidores Power para evitar colisiones con MCP globales.

**Procmon no está configurado** porque no aparece en el JSON recibido. No se inventa endpoint ni autenticación.

## 4. Credenciales

Las credenciales que se pegaron en la conversación deben considerarse expuestas y rotarse antes del uso. No están incluidas en el proyecto.

En macOS, desde la raíz del proyecto ejecuta:

```bash
bash scripts/macos/set-mcp-env.sh
```

Introduce las credenciales nuevas cuando se soliciten. El script no las guarda en archivos ni las muestra. Después:

1. Cierra Kiro con `Cmd+Q` y vuelve a abrirlo.
2. En Settings busca **Mcp Approved Env Vars** y aprueba los cinco nombres indicados en `docs/MCP-ENVIRONMENT.md`.
3. Activa cada Power y comprueba su servidor en Kiro.

El script usa `launchctl` para definir las variables en el entorno de tu sesión macOS; cualquier proceso de esa sesión podría heredarlas. No lo uses en una cuenta compartida. Para retirarlas:

```bash
bash scripts/macos/clear-mcp-env.sh
```

Kiro no lee automáticamente `.env`; `.env.example` es solo una referencia de nombres.

## 5. Evitar servidores globales duplicados

`.kiro/settings/mcp.json` contiene overrides `disabled: true` para los seis nombres que aparecían en tu configuración global: `remnux`, `remnux-docs`, `ghidra`, `radare2`, `darknet` y `x64dbg`. Esto deshabilita esas copias globales solo dentro de este workspace; no altera el archivo global ni otros proyectos.

El agente `security-analyst` tiene `includeMcpJson: false` e `includePowers: true`: no incorpora el inventario MCP global al agente y puede utilizar los Powers instalados. Cada Power declara únicamente los servidores de su especialidad.

## 6. Permisos

- El agente no tiene acceso a Shell.
- Solo puede escribir el estado, los hallazgos y el informe del expediente activo.
- Originales, EML, adjuntos, extracción, manifiesto, motor, configuración y Powers permanecen protegidos.
- El análisis dinámico exige autorización explícita para la muestra y confirmación de un laboratorio aislado y desechable.

## 7. Preparar un caso

Si el colector ya generó MSG, EML, `metadata.json` y `READY`:

```bash
.venv/bin/python engine/import_messages.py /ruta/a/descargas --recursive --ready-only
```

Para un MSG individual:

```bash
.venv/bin/python engine/ingest_msg.py /ruta/al/correo.msg
```

El motor se ejecuta dentro del venv del proyecto; `extract-msg` es necesario para convertir un MSG cuando no existe un EML verificado del colector:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

Si el EML y el MSG coinciden con los hashes declarados por el colector, se reutiliza el EML sin volver a convertir.
