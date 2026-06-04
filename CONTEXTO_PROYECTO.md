# cPacleanS v2.3.0 — Contexto del Proyecto para Claude Code

> **Leer este archivo completo antes de cualquier modificacion.**
> Su proposito es permitir que nuevas sesiones de Claude Code comprendan el proyecto sin dañar archivos core.

---

## 1. Que es este proyecto

**cPacleanS** es una herramienta de escritorio para Windows que escanea y limpia malware de backups cPanel (.tar.gz, .zip). Esta dirigida a administradores de servidores web que necesitan sanear sitios infectados antes de restaurarlos.

- **Version actual:** 2.3.0
- **Lenguaje:** Python 3.11+
- **Plataforma:** Windows 10/11 64-bit
- **Entrada:** Archivo de backup cPanel (`.tar.gz`, `.zip`, `.tar`, `.gz`)
- **Salida:** Reporte HTML + PDF, archivos en cuarentena, core CMS restaurado, .tar.gz limpio
- **Repositorio:** https://github.com/sotadev-agency/proyectos-ia.git

---

## 2. Arquitectura general

```
limpiador_malware/
├── main.py                        ← Punto de entrada (lanza la GUI)
├── src/
│   ├── config/settings.py         ← Constantes globales, tablas protegidas, marcadores CMS
│   ├── core/
│   │   ├── engine.py              ← Motor multiprocessing (CORE — leer antes de tocar)
│   │   ├── extractor.py           ← Extraccion de backups cPanel
│   │   ├── path_filter.py         ← Filtro whitelist/blacklist modo "Solo contenido critico"
│   │   ├── cms_restorer.py        ← Restaura core CMS (WP, Joomla, Moodle, OJS, Laravel)
│   │   ├── cms_plugin_cleaner.py  ← Separa/elimina/reinstala plugins y temas por modo (v2.3.0)
│   │   └── packager.py            ← Empaqueta backup limpio (.tar.gz completo o parcial cPanel)
│   ├── scanners/
│   │   ├── php_scanner.py         ← PHP, JS, .htaccess (principal detector)
│   │   ├── cms_scanner.py         ← WordPress, Joomla, Moodle, Laravel
│   │   ├── database_scanner.py    ← Dumps MySQL/SQL (.sql, .sql.gz, .sql.bz2)
│   │   ├── email_scanner.py       ← Phishing, reinfeccion
│   │   └── yara_scanner.py        ← Reglas YARA avanzadas (opcional)
│   ├── cleaners/
│   │   └── db_cleaner.py          ← Limpieza BD por fila con tablas protegidas (v2.3.0)
│   ├── utils/
│   │   ├── php_serializer.py      ← Parser serializacion PHP para BD (v2.3.0)
│   │   └── db_utils.py            ← Deteccion prefijos, lectura streaming SQL (v2.3.0)
│   ├── api/virustotal.py          ← VirusTotal API v3
│   ├── report/generator.py        ← Reportes HTML (Jinja2) y PDF (fpdf2)
│   ├── gui/app.py                 ← Interfaz grafica CustomTkinter
│   └── signatures/malware_rules.yar ← Reglas YARA
├── installer/setup.iss            ← Script Inno Setup para instalador
├── build.py                       ← Script de compilacion PyInstaller
├── requirements.txt               ← Dependencias Python
└── reportes/                      ← Reportes generados (no incluir en commits)
```

---

## 3. Archivos CORE — no modificar sin entender su contrato

### `src/config/settings.py`
Define las constantes que usa todo el sistema:
```python
APP_VERSION = "2.3.0"
SCAN_MODE_ONLY = "scan_only"
CLEAN_MODE_NORMAL = "normal"
CLEAN_MODE_INTERMEDIATE = "intermediate"
CLEAN_MODE_STRICT = "strict"
CPANEL_PROTECTED_DIRS   # dirs cPanel nunca cuarentenados (etc, userdata, dns, cp)
WP_CORE_ROOT_FILES      # archivos raiz del core de WordPress
CMS_PROTECTED_TABLES    # tablas BD por CMS que nunca se eliminan completas (v2.3.0)
CMS_DETECTION_MARKERS   # marcadores file+dir para deteccion robusta de CMS (v2.3.0)
```
Configuracion de usuario en: `%APPDATA%\cPacleanS\config.json`

---

### `src/core/engine.py`
**Motor multiprocessing — el archivo mas critico.**

Contiene:
- `Finding` (dataclass): un hallazgo individual de malware
- `ScanResult` (dataclass): resultado agregado de todo el escaneo
- `ScanEngine`: orquestador del pool de procesos
- `CONFIRMED_MALWARE_CATEGORIES`: categorias que se auto-limpian en modo Normal

**Contrato de `ScanResult`:**
```python
@dataclass
class ScanResult:
    total_files_scanned: int
    total_threats_found: int
    total_cleaned: int
    scan_duration_seconds: float
    findings: list[Finding]
    summary_by_severity: dict
    summary_by_category: dict
    cms_detected: list
    virustotal_hits: list
    scan_errors: list
    quarantine_dir: str
    cms_restore_log: list       # [{type, cms, message}] de CMSRestorer
    clean_mode_used: str
    workers_used: int
    critical_only_mode: bool    # v2.2.0
    omitted_paths_count: int    # v2.2.0
    plugins_temas_log: list     # v2.2.3 — [{cms, type, name, version, original_path, action, is_active, reinstalled}]
    db_interventions_log: list  # v2.3.0 — [{file, table, prefix, cms, type, detail, action}]
    db_prefixes: dict           # v2.3.0 — {cms: prefix} detectados dinamicamente
```

---

### `src/core/cms_plugin_cleaner.py` ← reescrito en v2.3.0
**Flujo correcto para TODOS los modos:**

1. Leer BD del CMS → detectar prefijo real → identificar plugins/temas ACTIVOS
2. Mover TODOS los plugins/temas a cuarentena (Normal/Intermedio) o eliminar (Estricto)
3. Descargar desde repo oficial SOLO los que estan activos segun BD (WordPress.org API)
4. Instalar version limpia en la copia de trabajo

`CMSPluginCleaner(extract_dir, quarantine_dir, clean_mode, progress_callback, db_paths)`

- `.process(cms_detected: list) -> dict` — punto de entrada
- `.removal_log` — lista de dicts con `{cms, type, name, version, original_path, action, is_active, reinstalled}`
- `.get_detected_prefixes() -> dict` — prefijos detectados por CMS

**Reinstalacion automatica:**
- WordPress: API wordpress.org (plugins + temas) — completa
- Joomla/Moodle/OJS: no hay API equivalente — genera nota de reinstalacion manual

---

### `src/cleaners/db_cleaner.py` ← nuevo en v2.3.0
**Limpia dumps SQL eliminando filas maliciosas con proteccion de tablas.**

`DBCleaner(extract_dir, cms_detected, prefixes, clean_mode, progress_callback)`

- `.process(sql_files: list) -> list` — retorna lista de intervenciones
- `.interventions` — log de todas las acciones realizadas

**Reglas de proteccion:**
- Tablas protegidas (CMS_PROTECTED_TABLES): solo DELETE de filas con malware CRITICO CONFIRMADO
- Tablas de codigo propio (sin CMS): misma proteccion que tablas protegidas
- Tablas no protegidas: reglas normales segun modo de limpieza
- Filas sospechosas (no criticas): marcadas para revision manual, sin modificar

---

### `src/utils/php_serializer.py` ← nuevo en v2.3.0
Parser de serializacion PHP para extraer datos de campos BD.
- `unserialize_php(data)` — usa phpserialize (pip) con fallback regex
- `extract_active_plugins_wp(serialized)` — extrae slugs de active_plugins

### `src/utils/db_utils.py` ← nuevo en v2.3.0
- `iter_sql_lines(file_path)` — streaming .sql/.sql.gz/.sql.bz2
- `detect_prefix_from_config(cms, cms_root)` — lee wp-config.php, configuration.php, etc.
- `detect_prefix_from_dump(sql_path, cms)` — fallback: busca CREATE TABLE en dump
- `read_active_from_dump(sql_path, cms, prefix)` — extrae plugins/temas activos del dump

---

## 4. Flujo de datos completo

```
backup.tar.gz
    │
    ▼
BackupExtractor.extract()
    │ → BackupInfo { total_files, cms_detected[], structure{} }
    │ → Directorio temporal extraido
    │ → Deteccion CMS robusta (CMS_DETECTION_MARKERS: file + dir + extras)
    ▼
ScanEngine.scan_directory()
    │ → ProcessPoolExecutor → N workers → _worker_scan_batch()
    │ → Soporta .sql.gz y .sql.bz2 (extensiones compuestas)
    │ → Finding[] clasificados
    ▼
VirusTotalClient.check_files()      (opcional, si API key configurada)
    │ → VTResult[] para top-10 archivos criticos
    ▼
CMSRestorer.restore_all()           (opcional, si "Restaurar CMS" activo)
    │ → Descarga core limpio de WP/Joomla/Moodle/OJS
    │ → Rebuild completo de dirs core infectados (solo CORE, no plugins)
    ▼
ScanEngine.clean_findings()
    │ → setup_quarantine() crea estructura de cuarentena
    │ → mueve/elimina hallazgos segun modo
    │ → clean_zero_byte_files()
    ▼
[NUEVO v2.3.0] Deteccion de prefijos BD
    │ → detect_prefix_from_config() o detect_prefix_from_dump()
    │ → Resultado → ScanResult.db_prefixes
    ▼
[NUEVO v2.3.0] DBCleaner.process()
    │ → Lee dumps SQL con streaming
    │ → Tablas protegidas: solo filas criticas confirmadas
    │ → Tablas propias: misma proteccion
    │ → Resultado → ScanResult.db_interventions_log
    ▼
CMSPluginCleaner.process()
    │ → Lee BD para detectar activos (via db_utils + php_serializer)
    │ → Mueve/elimina TODOS los plugins/temas
    │ → Descarga e instala version limpia de los ACTIVOS (WP.org API)
    │ → Resultado → ScanResult.plugins_temas_log
    ▼
ReportGenerator.generate()
    │ → HTML con seccion Intervenciones BD + Plugins reinstalados
    │ → PDF con mismas secciones
    │ → Solo muestra CMS realmente detectados (fix Moodle fantasma)
    ▼
PackagingDialog (opcional, post-limpieza)
    │ → create_targz() / create_cpanel_partial_targz() / copy_clean_files()
```

---

## 5. CMS soportados

| CMS | Deteccion | Restauracion core | Plugins/temas | Reinstalacion auto |
|-----|-----------|-------------------|---------------|-------------------|
| WordPress | Robusta (wp-config.php + wp-includes/) | Desde wordpress.org | Todos a cuarentena, activos reinstalados | Si (WP.org API) |
| Joomla | Robusta (configuration.php + administrator/) | Dirs core desde joomla.org | Todos a cuarentena | No (nota manual) |
| Moodle | Robusta (config.php + lib/moodlelib.php) | Dirs core desde moodle.org | Todos a cuarentena | No (nota manual) |
| OJS | Robusta (config.inc.php + lib/pkp/) | Dirs core desde GitHub | Todos a cuarentena | No (nota manual) |
| Laravel | Deteccion basica | No aplica — avisa `composer install` | N/A | N/A |

---

## 6. Dependencias clave

```
customtkinter>=5.2.0    # GUI dark mode
yara-python>=4.3.0      # Opcional — si no esta instalado, YaraScanner devuelve []
requests>=2.31.0        # APIs (VirusTotal, WordPress.org, Joomla, Moodle, OJS)
jinja2>=3.1.2           # Templates HTML para reportes
fpdf2>=2.8.0            # Generacion PDF
chardet>=5.2.0          # Deteccion de encoding de archivos
python-magic-bin>=0.4.14 # Deteccion de tipo MIME (Windows)
psutil>=5.9.0           # Info de sistema (CPUs disponibles)
phpserialize>=1.3       # Parser serializacion PHP para BD (v2.3.0)
pyinstaller>=6.0.0      # Solo para compilar el ejecutable
```

---

## 7. Historial de versiones resumido

| Version | Cambios principales |
|---------|---------------------|
| 2.0.0 | Migracion a multiprocessing, cuarentena segura, reportes PDF |
| 2.0.1 | Log visual por fases, escaneo de reinfeccion, modo VT deep, bloqueo de controles UI |
| 2.1.0 | Fix truncate filenames, limpieza archivos 0KB, separacion plugins premium/sospechosos, rutas relativas en reporte |
| 2.2.0 | Modo "Solo contenido critico", restauracion Joomla/Moodle/Laravel, 48 plugins maliciosos, boton validar API key VT |
| 2.2.1 | Fix: doble llamada redundante en php_scanner; Fix: API yara-python ≥4.3; Fix: spec agrega collect_all(fpdf) |
| 2.2.2 | Fix critico: path_filter usaba ruta absoluta; cPanel core preservation; Full rebuild CMS; OJS soporte |
| 2.2.3 | CMSPluginCleaner: separa/elimina plugins/temas; BackupPackager.create_cpanel_partial_targz(); seccion plugins en HTML+PDF |
| **2.3.0** | **BD: parser SQL robusto (.sql.bz2), prefijos dinamicos, tablas protegidas, limpieza por fila. Plugins: lee activos desde BD, reinstala desde WP.org. Reportes: seccion BD, solo CMS detectados. Fix: Moodle fantasma en deteccion** |

---

## 8. Nuevos archivos v2.3.0

- `src/utils/__init__.py` — modulo utilidades
- `src/utils/php_serializer.py` — parser serializacion PHP
- `src/utils/db_utils.py` — streaming SQL, deteccion prefijos, lectura activos BD
- `src/cleaners/__init__.py` — modulo limpiadores
- `src/cleaners/db_cleaner.py` — limpieza BD con tablas protegidas

---

## 9. Reglas de seguridad del codigo

- La cuarentena SIEMPRE guarda copia original antes de mover o eliminar (excepto modo `strict`)
- El modo `scan_only` nunca toca archivos bajo ninguna circunstancia
- NUNCA eliminar tablas completas de BD — solo filas con malware CRITICO CONFIRMADO
- Tablas de codigo propio (sin CMS) tienen misma proteccion que tablas protegidas
- Los dirs de configuracion cPanel nunca se cuarentenan — ver `CPANEL_PROTECTED_DIRS`
- Deteccion de CMS requiere file + dir + extras (CMS_DETECTION_MARKERS) para evitar falsos positivos
- Prefijos de BD se detectan desde config del CMS o como fallback desde el dump SQL

---

## 10. Proximas mejoras identificadas (backlog)

- [ ] Descargar y reinstalar plugins de Joomla (no hay API como WP.org)
- [ ] Descargar y reinstalar plugins de Moodle (moodle.org sin API directa)
- [ ] Omitir descarga de plugins en CMSRestorer cuando CMSPluginCleaner va a manejarlos
- [ ] Modo "Solo contenido critico": deteccion dinamica de addon domains
- [ ] Exportar lista de archivos omitidos por el filtro critico a CSV
- [ ] Panel de configuracion de workers en la GUI
