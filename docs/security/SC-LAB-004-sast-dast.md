# SC-LAB-004: Análisis de Seguridad Estático y Dinámico (SAST + DAST)

- **Proyecto:** SecureCampus Security Lab
- **Curso:** Desarrollo Seguro
- **Fecha:** Septiembre 2026
- **Alumno:** Ricardo Lugo Chavira

---

## 1. Pregunta guía
**¿Qué puede descubrir una herramienta al analizar el código fuente y qué puede descubrir al interactuar con una aplicación en ejecución?**  
El análisis de código fuente (SAST) descubre debilidades estructurales internas como consultas SQL concatenadas, funciones deprecadas, falta de sanitización y secretos expuestos sin requerir el despliegue del sistema. La interacción en ejecución (DAST) descubre fallos observables en tiempo real desde el exterior, como Cross-Site Scripting (XSS) reflejado, cabeceras HTTP de seguridad ausentes y respuestas indebidas del servidor frente a peticiones anómalas.

---

## 2. Parte A · SAST con Semgrep (app.py)

### 2.1 Análisis humano inicial
- **¿Qué dato controla el usuario?:** El texto ingresado mediante la instrucción interactiva `input("Nombre del estudiante: ")`, almacenado en la variable `nombre`.
- **¿A dónde llega ese dato?:** Pasa como argumento a la función `buscar_estudiante(nombre)` y se concatena directamente dentro de la cadena de consulta SQL ejecutada por `cursor.execute(consulta)`.
- **¿Qué riesgo observas?:** Inyección SQL (SQLi / CWE-89). Al concatenar sin sanitizar, un atacante puede alterar la sintaxis de la consulta (por ejemplo, con `' OR '1'='1`) para evadir filtros o extraer la base de datos completa.
- **¿Qué control propondrías?:** Uso estricto de consultas parametrizadas (sentencias preparadas) utilizando el marcador `?` nativo de SQLite (`cursor.execute("... WHERE nombre = ?", (nombre,))`).

### 2.2 Ejecución formal de Semgrep
```bash
docker run --rm -v "${PWD}:/src" semgrep/semgrep semgrep scan --config auto /src/src