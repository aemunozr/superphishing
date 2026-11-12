# Arquitectura

## Principio

**Determinístico primero; IA solo para interpretar, correlacionar y decidir.**

El diagrama de componentes y despliegue está en la sección **Arquitectura** del `README.md`. Este muestra el recorrido de un correo.

```mermaid
flowchart TD
    A["Buzón de reportes<br/>Microsoft Graph, solo lectura"]
    A -->|"graph_import.py<br/>timer systemd, incremental"| B
    A -->|"revision.py<br/>manual, por fechas"| B
    B["Adjunto .msg<br/>el contenedor solo aporta metadatos"]
    L["MSG local / carpeta READY"]
    B --> C
    L --> C
    subgraph ENG["Python engine · sin LLM · la única red es la descarga desde Graph"]
        C["MSG original + SHA-256"]
        C --> D["EML verificado reutilizado si existe<br/>o MSG → EML con extract-msg"]
        D --> E["headers · body · URLs · IPs ·<br/>dominios · adjuntos"]
        E --> F["summary.json · case.json · fingerprints"]
    end
    F --> G[("Expediente cases/CASE-...<br/>+ índice SQLite")]
    G -.->|"reputation.py<br/>VirusTotal, solo GET"| RP["extracted/reputation.json"]
    HK["Hook READY"] -->|"caso no finalizado"| H
    subgraph AGT["Kiro security-analyst · shell denegado"]
        S["Steering<br/>reglas · vocabulario · mcp-status"]
        H["Triage + correlación de campaña"]
        AB["Cierre abreviado<br/>duplicado de plantilla"]
        I["5 Skills generales del workspace"]
        P["5 Powers con Skills especializadas<br/>bajo demanda"]
        J["MCP de cada Power<br/>se omiten los no disponibles"]
        U["Probe de URLs en REMnux<br/>solo phishing/suspicious"]
        K["Tracking en state.json / findings.json<br/>lectura previa, edición puntual"]
        S -.-> H
        H -->|"campaña ya cerrada"| AB
        H -->|"caso nuevo"| I --> P --> J --> K
        J --> U --> K
        AB --> K
    end
    G --> H
    RP --> H
    K --> R["Informe Markdown<br/>report/final-report.md"]
```

## Responsabilidades

- `engine/`: parsing, normalización, hashes, extracción, importación y registro determinístico.
- `engine/graph_import.py` y `engine/revision.py`: colector de Microsoft Graph (sondeo incremental y revisión por fechas).
- `deploy/ubuntu/`: servicio y timer systemd, `install.sh` y plantilla de credenciales para el servidor.
- `.kiro/agents/`: un agente coordinador con permisos restringidos.
- `.kiro/skills/`: cinco Skills generales: triage, email, URL, descubrimiento MCP e informe.
- `powers/`: cinco paquetes Kiro nativos con `plugin.json`, una Skill especializada, `mcp.json.example` versionado con placeholders `${VARIABLE}` y un `mcp.json` local con credenciales (en `.gitignore`).
- `.kiro/steering/security-analysis.md`: reglas globales, vocabulario fijo, excepción de URLs para REMnux y reglas de lotes.
- `.kiro/steering/mcp-status.md`: fuentes MCP que hoy no se deben consultar y fuentes operativas.
- `.kiro/hooks/analizar-expediente-nuevo.json`: delega en `security-analyst` cada expediente nuevo no finalizado.
- `.kiro/settings/mcp.json` (local): deshabilita únicamente las copias globales de los seis servidores recibidos para evitar conexiones duplicadas en este workspace.
- `analysis/state.json`: tracking mutable de etapas y fingerprints.
- `analysis/findings.json`: hallazgos breves con referencias.
- `storage/cases.db`: índice SQLite determinístico.

## Powers y servidores

| Power | Skill | MCP incluidos |
|---|---|---|
| `threat-intelligence` | `ioc-correlation` | Darknet, GTI agentic |
| `static-analysis` | `file-analysis` | REMnux, REMnux Docs |
| `reverse-engineering` | `reverse-engineering` | Ghidra, Radare2 |
| `dynamic-analysis` | `dynamic-analysis` | x64dbg |
| `exposure-hunting` | `exposure-assessment` | CrowdStrike Falcon, Cisco Secure Access (solo lectura) |

Procmon queda pendiente porque no aparece en la configuración recibida. No se simula ni se inventa su conexión.

Los Powers empaquetan sus configuraciones MCP en `mcp.json`. Kiro administra y namespacia esas conexiones. En el repositorio solo se versiona `mcp.json.example`, con placeholders `${VARIABLE}` en todas las cabeceras de autenticación; los tests lo validan para que nunca entre un secreto literal.

El agente usa `includePowers: true` y `includeMcpJson: false`. El `mcp.json` del workspace deshabilita las definiciones globales con los mismos nombres, pero no altera el archivo global del usuario ni otros proyectos.

## Ruta de análisis

1. `ingestion` y `extraction`: motor Python sin IA.
2. `triage`: siempre. Incluye la correlación de campaña; un duplicado de plantilla de un caso cerrado va a cierre abreviado.
3. `url_analysis`: solo si hay URLs. Análisis sintáctico siempre; probe de redirecciones en REMnux solo en casos `phishing` o `suspicious`.
4. `ioc_analysis`: solo si existen IOC contextuales.
5. `static_analysis`: si hay adjuntos.
6. `reverse_engineering`: solo si existe binario que lo justifique.
7. `dynamic_analysis`: solo tras análisis estático insuficiente, autorización específica y laboratorio aislado confirmado.
8. `report`: desde los hallazgos y referencias persistidos.

No todas las ramas se ejecutan en todos los casos. `not_applicable` y `skipped` son estados válidos.
