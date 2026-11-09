# Casos de prueba

1. **Correo con URL y adjunto:** extrae indicadores localmente; triage aplica email, URL, CTI y análisis estático según evidencia.
2. **Correo sin URL ni adjunto:** omite ramas no aplicables y no activa MCP de malware.
3. **URL única:** se investiga sin ejecutar análisis de archivos.
4. **Adjunto PDF/Office/script:** análisis estático primero; no ejecución de contenido.
5. **Binario PE/ELF:** análisis estático y, si aporta valor, Ghidra.
6. **Dinámica:** permanece omitida salvo autorización explícita y laboratorio aislado confirmado.
7. **Mismo MSG:** segunda importación se detecta por SHA-256.
8. **EML del colector con hashes válidos:** se reutiliza; no se convierte de nuevo.
9. **EML con hash inválido o metadata inconsistente:** no se confía en el EML; MSG original se conserva y el caso se detiene o se convierte localmente según la disponibilidad de `extract-msg`.
10. **Interrupción:** el análisis retoma desde `analysis/state.json` sin repetir etapas completadas con el mismo fingerprint.
