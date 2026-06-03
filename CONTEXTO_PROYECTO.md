# cPacleanS v2.1.0 — Contexto del Proyecto para Claude Code

> **Leer este archivo completo antes de cualquier modificación.**
> Su propósito es permitir que nuevas sesiones de Claude Code comprendan el proyecto sin dañar archivos core.

---

## 1. Qué es este proyecto

**cPacleanS** es una herramienta de escritorio para Windows que escanea y limpia malware de backups cPanel (.tar.gz, .zip). Está dirigida a administradores de servidores web que necesitan sanear sitios infectados antes de restaurarlos.

- **Versión actual:** 2.2.0
- **Lenguaje:** Python 3.11+
- **Plataforma:** Windows 10/11 64-bit
- **Entrada:** Archivo de backup cPanel (`.tar.gz`, `.zip`, `.tar`, `.gz`)
- **Salida:** Reporte HTML + PDF, archivos en cuarentena, core CMS restaurado
- **Repositorio:** https://github.com/sotadev-agency/proyectos-ia.git

---

## 2. Arquitectura general

```
limpiador_malware/
├── main.py                        ← Punto de entrada (lanza la GUI)
├── src/
│   ├── config/settings.py         ← Constantes globales y configuración
│   ├── core/
│   │   ├── engine.py              ← Motor multiprocessing (CORE — leer antes de tocar)
│   │   ├── extractor.py           ← Extracción de backups cPanel
│   │   ├── path_filter.py         ← Filtro whitelist/blacklist modo "Solo contenido crítico"
│   │   ├── cms_restorer.py        ← Restaura core CMS (WP, Joomla, Moodle, Laravel)
│   │   └── packager.py            ← Empaqueta backup limpio en .tar.gz
│   ├── scanners/
│   │   ├── php_scanner.py         ← PHP, JS, .htaccess (principal detector)
│   │   ├── cms_scanner.py         ← WordPress, Joomla, Moodle, Laravel
│   │   ├── database_scanner.py    ← Dumps MySQL/SQL
│   │   ├── email_scanner.py       ← Phishing, reinfección
│   │   └── yara_scanner.py        ← Reglas YARA avanzadas (opcional)
│   ├── api/virustotal.py          ← VirusTotal API v3
│   ├── report/generator.py        ← Reportes HTML (Jinja2) y PDF (fpdf2)
│   ├── gui/app.py                 ← Interfaz gráfica CustomTkinter
│   └── signatures/malware_rules.yar ← Reglas YARA
├── installer/setup.iss            ← Script Inno Setup para instalador
├── build.py                       ← Script de compilación PyInstaller
├── requirements.txt               ← Dependencias Python
└── reportes/                      ← Reportes generados (no incluir en commits)
```

---

## 3. Archivos CORE — no modificar sin entender su contrato

Estos archivos tienen contratos internos que otros módulos dependen. Un cambio incorrecto rompe toda la cadena:

### `src/config/settings.py`
Define las constantes que usa todo el sistema:
```python
APP_VERSION = "2.1.0"           # Actualizar solo al subir versión
SCAN_MODE_ONLY = "scan_only"
CLEAN_MODE_NORMAL = "normal"
CLEAN_MODE_INTERMEDIATE = "intermediate"
CLEAN_MODE_STRICT = "strict"

CONFIRMED_MALWARE_CATEGORIES    # Definido en engine.py — ver sección 4
```
Configuración de usuario en: `%APPDATA%\cPacleanS\config.json`

### `src/core/engine.py`
**Motor multiprocessing — el archivo más crítico.**

Contiene:
- `Finding` (dataclass): un hallazgo individual de malware
- `ScanResult` (dataclass): resultado agregado de todo el escaneo
- `ScanEngine`: orquestador del pool de procesos
- `CONFIRMED_MALWARE_CATEGORIES`: categorías que se auto-limpian en modo Normal

**Patrón de multiprocessing que NO se debe cambiar:**
```python
# Cada worker inicializa sus propios scanners UNA sola vez
_worker_scanners = None
def _worker_init(scanner_classes): ...
def _worker_scan_batch(file_batch): ...  # llama scanner.scan(path) en cada uno
```
Los scanners deben ser serializables (sin locks, sin handles externos en `__init__`).

**Contrato de `Finding`:**
```python
@dataclass
class Finding:
    file_path: str          # Ruta absoluta al archivo
    line_number: int = 0
    severity: str = "medium"  # critical | high | medium | low | info
    category: str = ""        # Ver CONFIRMED_MALWARE_CATEGORIES
    description: str = ""
    matched_pattern: str = ""
    context: str = ""
    cleaned: bool = False
    sha256: str = ""
    confirmed_malware: bool = False   # True = se limpia automáticamente
```

**Modos de limpieza:**
| Modo | Qué limpia |
|------|-----------|
| `scan_only` | Nada. Solo genera reporte. |
| `normal` | Solo `confirmed_malware=True` |
| `intermediate` | Confirmados + severidad high/critical |
| `strict` | Todo lo sospechoso |

**Cuarentena:** Siempre copia el original antes de mover. Estructura:
```
cuarentena_YYYYMMDD_HHMMSS/
  originales_intactos/      ← copia exacta del archivo original
  amenazas_removidas/       ← archivos movidos desde el backup
  archivos_0kb/             ← archivos vacíos (restos de infección)
```

### `src/gui/app.py`
La GUI importa y orquesta todo el flujo. No tiene lógica de negocio propia.

**Flujo de 6 fases en hilo separado (`_run_scan_thread`):**
1. Extracción del backup → `BackupExtractor`
2. Escaneo multiprocessing → `ScanEngine`
3. Verificación VirusTotal → `VirusTotalClient` (opcional, si hay API key)
4. Restauración CMS → `CMSRestorer` (si checkbox activo)
5. Limpieza/cuarentena → `ScanEngine.clean_findings()`
6. Generación de reportes → `ReportGenerator`

**Control de UI durante escaneo:**
- `_lock_ui()` / `_unlock_ui()`: deshabilita/habilita controles
- `_append_log(msg)`: añade línea al log visual (thread-safe)
- `_update_progress(pct)`: actualiza barra de progreso 0-100

---

## 4. Contrato de los Scanners

Todos los scanners en `src/scanners/` siguen la misma interfaz:
```python
class XyzScanner:
    def scan(self, file_path: str) -> list[dict]:
        """
        Analiza un archivo. Devuelve lista de dicts con este esquema:
        {
            "file_path": str,
            "line_number": int,
            "severity": "critical" | "high" | "medium" | "low" | "info",
            "category": str,        # debe estar en CONFIRMED_MALWARE_CATEGORIES si es auto-limpiable
            "description": str,
            "matched_pattern": str,
            "context": str,         # fragmento de código para el reporte
            "confirmed_malware": bool,
        }
        Devuelve [] si el archivo es limpio o no aplica.
        """
```

**Para agregar un nuevo scanner:**
1. Crear `src/scanners/nuevo_scanner.py` con la clase siguiendo el contrato
2. Importarlo en `src/gui/app.py` y añadirlo a `SCANNER_CLASSES`
3. No tocar `engine.py` — el pool lo usa automáticamente

**`CONFIRMED_MALWARE_CATEGORIES`** — Categorías que activan limpieza en modo Normal:
```python
{
    "webshell", "backdoor", "cryptominer", "dropper",
    "cms_upload_php", "cms_htaccess_override", "cms_index_hijack",
    "cms_ini_injection", "double_extension",
    "malicious_attachment",
    "htaccess_redirect", "htaccess_handler", "htaccess_php",
}
```
Para agregar una categoría nueva como "auto-limpiable", añadirla a este set en `engine.py`.

---

## 5. CMS soportados

| CMS | Detección | Restauración core | Restauración plugins |
|-----|-----------|-------------------|----------------------|
| WordPress | Completa | Desde wordpress.org | Solo plugins **activos** (leídos del dump SQL) |
| Joomla | Completa | Desde downloads.joomla.org (dirs core: libraries, includes, layouts, language) | No implementada |
| Moodle | Completa | Desde download.moodle.org (dirs core: lib, mod, admin, auth…) | No implementada |
| Laravel | Detección básica | No aplica (app custom) — avisa composer install manual | N/A |
| Softaculous | Detección | No implementada | No implementada |

**La restauración de WordPress** lee `active_plugins` y `template` del dump SQL antes de descargar nada. No restaura plugins inactivos ni temas desactivados.

---

## 6. Flujo de datos completo

```
backup.tar.gz
    │
    ▼
BackupExtractor.extract()
    │ → BackupInfo { total_files, cms_detected[], structure{} }
    │ → Directorio temporal extraído
    ▼
ScanEngine.scan_directory()
    │ → ProcessPoolExecutor → N workers → _worker_scan_batch()
    │ → cada worker: [PHPScanner, DatabaseScanner, EmailScanner, CMSScanner, YaraScanner]
    │ → Finding[] clasificados
    ▼
VirusTotalClient.check_files()      (opcional)
    │ → VTResult[] para top-10 archivos críticos
    ▼
CMSRestorer.restore_all()           (opcional, si restore_cms_core=True)
    │ → Descarga core limpio de WordPress.org
    │ → Reemplaza wp-admin/, wp-includes/, plugins activos
    ▼
ScanEngine.clean_findings()
    │ → setup_quarantine() crea estructura de cuarentena
    │ → mueve/elimina según modo
    │ → separate_premium_suspicious() segrega plugins no verificables
    ▼
ReportGenerator.generate_html() + generate_pdf()
    │ → reportes/cpacleans_report_YYYYMMDD_HHMMSS.html
    │ → reportes/cpacleans_report_YYYYMMDD_HHMMSS.pdf
    ▼
BackupPackager.package()            (opcional, generate_targz=True)
    → backup_limpio.tar.gz listo para reimportar en cPanel
```

---

## 7. Rendimiento y limitaciones conocidas

**Rendimiento real medido:**
| Backup | Archivos | Tiempo | Workers |
|--------|----------|--------|---------|
| 50 MB | 3.075 | ~58 s | 5 |
| 354 MB | 22.472 | ~35 s | 5 |
| 1.2 GB | 52.013 | ~15 min | 5 |

**Límites de archivo en scanners:**
- `php_scanner`: omite archivos > 5 MB y archivos binarios (detecta `\x00`)
- `database_scanner`: máximo 500 hallazgos por archivo SQL
- `yara_scanner`: omite archivos > 10 MB, timeout 30 s por archivo

**Limitaciones actuales v2.2.0:**
- Restauración de plugins/temas solo funciona para **WordPress** (Joomla y Moodle restauran core pero no extensiones)
- Restauración de **Laravel**: no aplica (aplicación custom) — la herramienta detecta la versión y advierte ejecutar `composer install` manualmente
- Lista de plugins maliciosos: 48 entradas en `cms_scanner.py` — puede ampliarse añadiendo a `KNOWN_MALICIOUS_PLUGINS`

---

## 8. Dependencias clave

```
customtkinter>=5.2.0    # GUI dark mode — no reemplazar por tkinter estándar
yara-python>=4.3.0      # Opcional — si no está instalado, YaraScanner devuelve []
requests>=2.31.0        # APIs (VirusTotal, WordPress.org)
jinja2>=3.1.2           # Templates HTML para reportes
fpdf2>=2.8.0            # Generación PDF
chardet>=5.2.0          # Detección de encoding de archivos
python-magic-bin>=0.4.14 # Detección de tipo MIME (Windows)
psutil>=5.9.0           # Info de sistema (CPUs disponibles)
pyinstaller>=6.0.0      # Solo para compilar el ejecutable
```

---

## 9. Cómo compilar y distribuir

```bash
# Instalar dependencias
pip install -r requirements.txt

# Ejecutar en desarrollo
python main.py

# Compilar ejecutable (.exe)
python build.py
# o directamente:
pyinstaller cPacleanS.spec

# El instalador se genera con Inno Setup usando installer/setup.iss
```

---

## 10. Reglas de seguridad del código

- La cuarentena SIEMPRE guarda copia original antes de mover o eliminar
- El modo `scan_only` nunca toca archivos bajo ninguna circunstancia
- `confirmed_malware=True` solo se asigna cuando la categoría está en `CONFIRMED_MALWARE_CATEGORIES` AND la severidad es high/critical, O cuando hay múltiples patrones (≥3 hits, injection + obfuscation)
- No se eliminan archivos de plugins/temas premium (se segregan a carpeta separada para revisión manual)
- Los archivos de logs de cuarentena (`quarantine_log.json`) se preservan siempre

---

## 11. Convenciones del código

- Docstrings cortos en una línea por módulo/clase, sin bloques extensos
- Logging visual vía callbacks (`progress_callback`, `log_callback`) — no `print()` en módulos core
- Los errores de archivos individuales se capturan y se añaden a `scan_errors[]`, sin detener el escaneo
- Rutas Windows largas (>260 chars): usar prefijo `\\?\` en `extractor.py`
- Encoding de archivos: intentar UTF-8, fallback a latin-1, fallback a ignore

---

## 12. Historial de versiones resumido

| Versión | Cambios principales |
|---------|---------------------|
| 2.0.0 | Migración a multiprocessing, cuarentena segura, reportes PDF |
| 2.0.1 | Log visual por fases, escaneo de reinfección, modo VT deep, bloqueo de controles UI |
| 2.1.0 | Fix truncate filenames, limpieza archivos 0KB, separación plugins premium/sospechosos, rutas relativas en reporte |
| 2.2.0 | Modo "Solo contenido crítico" (whitelist/blacklist rutas cPanel), restauración Joomla/Moodle/Laravel, 48 plugins maliciosos, botón validar API key VT |

---

## 13. Próximas mejoras identificadas (backlog)

- [ ] Restauración de plugins/extensiones para Joomla (Joomla Extensions Directory API no existe como WP — requiere scraping o lista manual)
- [ ] Restauración de plugins para Moodle (moodle.org no tiene API de descarga como WP)
- [ ] Modo "Solo contenido crítico": detección dinámica de nombres de addon domains sin conocerlos de antemano
- [ ] Panel de configuración de workers (actualmente solo via config.json)
- [ ] Exportar lista de archivos omitidos por el filtro crítico a CSV
