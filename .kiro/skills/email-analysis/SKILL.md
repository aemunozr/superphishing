---
name: "email-analysis"
description: "Analiza headers, autenticación SPF/DKIM/DMARC/ARC, cadena Received, remitente, contenido MIME/HTML y señales de ingeniería social en un correo ya normalizado."
---

# Análisis de correo

1. Lee `summary.json` y `extracted/headers.json` primero. Abre `msg_properties.json`, `body.json` o el EML solo cuando falte un dato material; el MSG original es evidencia primaria.
2. Distingue headers originales expuestos por el parser de headers reconstruidos desde el EML. No presentes la conversión MSG→EML como copia forense exacta.
3. Revisa From, Reply-To, Return-Path, Sender, Message-ID, Date, Received y dominios DKIM cuando existan. Evalúa saltos Received y límites de confianza; un header por sí solo puede ser falsificado o añadido por una infraestructura intermedia.
4. Interpreta SPF, DKIM, DMARC y ARC únicamente cuando haya resultados explícitos y el dominio evaluado esté identificado. Ausencia de header no significa fail; un pass no prueba que el contenido sea legítimo.
5. Compara dominios visibles, Reply-To, Return-Path y firma; una diferencia es una pista, no una conclusión automática. Considera reenvíos, gateways y listas de distribución.
6. Resume la petición y busca presión, urgencia, suplantación, pagos/cambios bancarios, robo de credenciales, solicitudes de información sensible y adjuntos inesperados.
7. Para HTML, usa la extracción existente: anchors, href/src/action/formaction, formularios, iframes, recursos externos y diferencias entre texto visible y destino. No ejecutes JavaScript, macros ni formularios.
8. Enumera adjuntos mediante `attachments.json`; tipo declarado y tipo real pueden diferir. Deriva el análisis de archivo a la Skill `file-analysis`.
9. Registra señales a favor y en contra, referencia exacta al artefacto y limitaciones. No concluyas phishing por una sola anomalía o mala redacción.
