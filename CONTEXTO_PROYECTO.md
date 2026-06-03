# cPacleanS — Contexto del Proyecto

## Objetivo principal
Herramienta de escritorio para Windows que permite limpiar malware de copias de seguridad generadas desde cPanel, de forma segura, automatica y eficiente.

## Problema que resuelve
Cuando un servidor web es infectado con malware, el administrador necesita:
1. Descargar el backup completo de cPanel
2. Identificar todos los archivos maliciosos (shells, backdoors, inyecciones, spam)
3. Limpiar los archivos sin romper el sitio web
4. Restaurar los archivos core de WordPress/Moodle/Joomla/Laravel
5. Generar un reporte para el cliente
6. Re-empaquetar el backup limpio para subirlo a una nueva instalacion de cPanel

## Arquitectura
- **Lenguaje**: Python 3.11+
- **GUI**: CustomTkinter (dark mode)
- **Rendimiento**: multiprocessing (usa todos los CPUs)
- **Empaquetado**: PyInstaller (ejecutable unico)
- **Instalador**: Inno Setup (instalador Windows)
- **Reportes**: HTML (Jinja2) + PDF (fpdf2)

## Modulos
```
src/
  config/settings.py      — Configuracion global, modos de limpieza
  core/extractor.py       — Extraccion de backups (.tar.gz, .zip)
  core/engine.py          — Motor de escaneo multiprocessing
  core/cms_restorer.py    — Restauracion CMS desde repos oficiales
  core/packager.py        — Generacion .tar.gz / copia de archivos
  scanners/php_scanner.py — Deteccion PHP (shells, backdoors, ofuscacion)
  scanners/database_scanner.py — Deteccion en dumps MySQL
  scanners/email_scanner.py    — Phishing, adjuntos, reinfeccion
  scanners/cms_scanner.py      — WordPress, Joomla, Moodle, Laravel
  scanners/yara_scanner.py     — Reglas YARA avanzadas
  api/virustotal.py       — Integracion VirusTotal API v3
  report/generator.py     — Reportes HTML + PDF
  gui/app.py              — Interfaz grafica completa
```

## Modos de operacion
1. **Solo Escaneo** — genera reporte sin tocar archivos
2. **Normal** — solo malware confirmado a cuarentena (copia original guardada)
3. **Intermedio** — confirmados + alta severidad a cuarentena
4. **Estricto** — todos los sospechosos eliminados

## CMS soportados
- WordPress (core, plugins, temas desde wordpress.org — solo activos segun DB)
- Moodle (deteccion de version, limpieza por patrones)
- Joomla (deteccion, config, uploads)
- Laravel (deteccion, .env, storage)
- Softaculous (deteccion)

## Integraciones
- **VirusTotal API v3**: modo rapido (confirmar hashes) o profundo (upload archivos)
- **WordPress.org API**: descarga de core, plugins, temas limpios
- **YARA**: reglas de deteccion avanzada (cuando esta instalado)

## Repositorio
https://github.com/sotadev-agency/proyectos-ia.git

## Stack de desarrollo
- Python 3.11+ (Windows)
- CustomTkinter 5.2+
- PyInstaller 6.x
- Inno Setup 6.x
- fpdf2 para PDF
- Jinja2 para HTML
- requests para APIs
