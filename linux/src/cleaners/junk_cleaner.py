"""JunkCleaner v2.6.0 — elimina archivos residuales en instalaciones CMS.

Ejecutar DESPUES de CMSPluginCleaner — limpia directorios preservados
(uploads, etc.) que no son gestionados por CMSFullWiper.
"""
import os
import shutil
import re
from pathlib import Path
from typing import Callable

from ..config.settings import (
    SCAN_MODE_ONLY, CLEAN_MODE_STRICT,
    CMS_DETECTION_MARKERS,
)

# Extensiones PHP que NUNCA son legitimas en uploads
_PHP_EXTS = frozenset([".php", ".php5", ".php7", ".phtml", ".phar"])

# Extensiones de imagen validas
_IMAGE_EXTS = frozenset([".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".ico"])

# Archivos .txt legitimamente presentes en el root de WP
_WP_ROOT_TXT = frozenset([
    "readme.txt", "license.txt", "readme.html",
])

# ── v3.2: residuos que NO cumplen función vital (cuarentena en cualquier webroot) ──

# Copias de seguridad / temporales de editores dejadas en el servidor
_BACKUP_EXTS = frozenset([
    ".bak", ".old", ".orig", ".save", ".saved", ".swp", ".swo",
    ".tmp", ".temp", ".copy", ".backup", ".bk", ".previous", ".prev", ".~",
])
# Sufijos al final del nombre (antes de la ext real): index.php.bak, wp-config.php~
_BACKUP_NAME_RE = re.compile(
    r"(~$|\.(bak|old|orig|save|saved|copy|backup|bk|previous|prev)$|"
    r"\.(php|js|css|html?|inc|sql|conf|ini|env)\.(bak|old|orig|save|copy|backup|txt|_?[0-9]+)$|"
    r"[ _-]cop(?:y|ia)([ _-]?[0-9]+)?\.(php|js|css|html?|inc|sql|conf|ini|env|zip|tar|gz)$|"
    r"\.(php|js|html?)\.(suspected|disabled|infected|quarantine))",
    re.IGNORECASE)

# Archivos comprimidos y volcados de BD olvidados en el webroot (riesgo de fuga)
_ARCHIVE_EXTS = frozenset([
    ".zip", ".tar", ".tar.gz", ".tgz", ".rar", ".7z", ".gz", ".bz2",
])
_DUMP_EXTS = frozenset([".sql", ".sql.gz", ".sql.zip", ".dump", ".mysql"])

# Basura de sistema operativo / editores
_OS_JUNK = frozenset([
    ".ds_store", "thumbs.db", "desktop.ini", ".spotlight-v100",
    ".trashes", "._.ds_store", ".fseventsd", "ehthumbs.db",
])

# Archivos PHP de diagnóstico / instaladores residuales (no vitales, riesgo expuesto)
_DIAGNOSTIC_PHP = frozenset([
    "phpinfo.php", "info.php", "i.php", "test.php", "tests.php",
    "phptest.php", "php.php", "1.php", "2.php", "3.php", "temp.php",
    "adminer.php", "adminer.php.txt", "pma.php", "dbtest.php",
    "install.php.bak", "setup.php.bak", "wp-config.php.bak",
    "wp-config.bak", "wp-config.old", "wp-config.txt", "wp-config.save",
    "phpmyadmin.php", "sql.php", "mysql.php", "db.php.bak",
])

# Directorios que NO se exploran para residuos (dependencias/core legítimos)
_SKIP_DIRS = frozenset([
    "node_modules", "vendor", "wp-admin", "wp-includes",
    ".git", ".svn", ".hg", "__pycache__", ".quarantine",
    "cuarentena", "cache", "upgrade",
])

# Carpetas ocultas / de respaldo que NO pertenecen al webroot legítimo y son
# frecuentes como artefactos de malware o residuos de servidores comprometidos.
_SUSPICIOUS_DIRS = frozenset([
    ".backup", ".tmb", ".old", ".tmp", ".bak", ".saved",
    ".trash", ".disabled", ".hidden", ".x", ".data",
    ".quarantine2", ".htpasswd_backup", ".restore",
])

# Regex para detectar nombres de archivo PHP con componente aleatoria / ofuscada.
# Ejemplos: 6tzrlwycdcyfhk9m86tCdefault.php, a1b2c3d4e5.php, xyz123abc456.php
# Patrón: 8+ chars de mezcla alfanumérica sin consonante/vocal legible + ext .php
_RANDOM_PHP_RE = re.compile(
    r'^(?:'
    r'[a-z0-9]{3,}[0-9]{2,}[a-z]{2,}[0-9]{1,}[a-z0-9]*'   # dígitos intercalados: 6tz...86t
    r'|[a-f0-9]{16,}'                                          # hex puro
    r'|[a-z0-9]{12,}'                                          # 12+ alfanumérico sin guiones/palabras
    r')(?:default|main|config|admin|index|core|wp|base|cache|log|tmp|temp)?'
    r'\.php(?:5|7)?$',
    re.IGNORECASE,
)

# Palabras que hacen legítimo un nombre (plugins, temas, proyectos propios)
_LEGIT_INDICATORS = frozenset([
    "woocommerce", "contact", "akismet", "yoast", "jetpack", "elementor",
    "gutenberg", "classic", "hello", "twentytwenty", "twentyone", "twentytwo",
    "twentythree", "loader", "autoload", "bootstrap", "functions",
])

# Intentar importar magic para MIME detection
try:
    import magic
    _MAGIC_AVAILABLE = True
except ImportError:
    _MAGIC_AVAILABLE = False


class JunkCleaner:
    """Limpia archivos residuales en dirs preservados de CMS."""

    def __init__(self, extract_dir: str, quarantine_dir: str,
                 clean_mode: str, progress_callback: Callable = None):
        self.extract_dir = Path(extract_dir)
        self.quarantine_dir = Path(quarantine_dir)
        self.clean_mode = clean_mode
        self.progress_callback = progress_callback or (lambda *a: None)
        self._junk_dir = self.quarantine_dir / "archivos_residuales"

    def process(self, cms_detected: list) -> list:
        """Escanea y limpia residuos. Retorna lista de dicts con resultados."""
        results = []
        self._handled = set()  # rutas ya procesadas (evita duplicados entre barridos)

        for cms in cms_detected:
            roots = self._find_cms_roots(cms)
            for root in roots:
                if cms == "wordpress":
                    results.extend(self._scan_wp_junk(root, cms))
                elif cms == "joomla":
                    results.extend(self._scan_joomla_junk(root, cms))
                # Moodle/OJS: sus uploads estan fuera del tree (moodledata), menos junk

        # v3.2: barrido global de residuos no vitales en todos los webroots
        # (backups, dumps, archivos de diagnóstico, basura de OS, carpetas vacías).
        # Funciona también para proyectos de código propio sin CMS detectado.
        results.extend(self._scan_residuals_global(cms_detected))

        if results:
            total = len(results)
            acted = sum(1 for r in results if r["action"] != "logged_only")
            self.progress_callback("status",
                f"[JUNK] {total} residuos encontrados, {acted} procesados")

        return results

    # ─────────────────────── v3.2: residuos globales ───────────────────────

    def _find_webroots(self, cms_detected: list) -> list:
        """Localiza las raíces web a barrer: todos los public_html + raíces CMS.
        Si no hay ninguno, cae al propio extract_dir (proyecto suelto)."""
        roots = []
        seen = set()

        def _add(p: Path):
            try:
                rp = p.resolve()
            except OSError:
                rp = p
            key = str(rp).lower()
            if key not in seen and p.exists() and p.is_dir():
                seen.add(key)
                roots.append(p)

        for r, dirs, _files in os.walk(self.extract_dir):
            for d in list(dirs):
                if d.lower() == "public_html":
                    _add(Path(r) / d)
        for cms in cms_detected:
            for cr in self._find_cms_roots(cms):
                _add(cr)
        if not roots:
            _add(self.extract_dir)
        return roots

    def _scan_residuals_global(self, cms_detected: list) -> list:
        """Barre los webroots buscando archivos y carpetas residuales no vitales."""
        results = []
        webroots = self._find_webroots(cms_detected)
        for webroot in webroots:
            for root, dirs, files in os.walk(webroot, topdown=True):
                # podar directorios que no se exploran (dependencias/core/cuarentena)
                dirs[:] = [d for d in dirs if d.lower() not in _SKIP_DIRS]
                root_path = Path(root)

                # Detectar carpetas sospechosas antes de explorar su contenido
                suspicious_subdirs = [d for d in dirs if d.lower() in _SUSPICIOUS_DIRS]
                for sd in suspicious_subdirs:
                    dir_path = root_path / sd
                    dstr = str(dir_path)
                    if dstr not in self._handled and dir_path.exists():
                        self._handled.add(dstr)
                        results.append(self._handle_suspicious_dir(dir_path, "suspicious_dir"))
                        dirs.remove(sd)  # no explorar internamente, ya está en cuarentena

                for fname in files:
                    fpath = root_path / fname
                    spath = str(fpath)
                    if spath in self._handled or not fpath.exists():
                        continue
                    category = self._classify_residual(fpath, webroot)
                    if category:
                        self._handled.add(spath)
                        results.append(self._handle_residual(fpath, category))
            # carpetas vacías (tras mover archivos)
            results.extend(self._quarantine_empty_dirs(webroot))
        return results

    def _handle_suspicious_dir(self, dir_path: Path, category: str) -> dict:
        """Mueve o elimina una carpeta sospechosa completa preservando la ruta relativa."""
        try:
            rel_path = str(dir_path.relative_to(self.extract_dir))
        except ValueError:
            rel_path = str(dir_path)

        entry = {"path": rel_path, "cms": "-", "category": category, "action": "logged_only"}

        if self.clean_mode == SCAN_MODE_ONLY:
            return entry

        if self.clean_mode == CLEAN_MODE_STRICT:
            try:
                shutil.rmtree(str(dir_path), ignore_errors=True)
                entry["action"] = "deleted"
            except (OSError, PermissionError):
                pass
            return entry

        # normal/intermediate: mover a cuarentena
        try:
            dest = self._junk_dir / rel_path
            dest.parent.mkdir(parents=True, exist_ok=True)
            if dest.exists():
                import time as _t
                dest = dest.parent / f"{dest.name}_{int(_t.time())}"
            shutil.move(str(dir_path), str(dest))
            entry["action"] = "quarantined"
        except (OSError, PermissionError, shutil.Error):
            pass
        return entry

    def _classify_residual(self, fpath: Path, webroot: Path) -> str:
        """Clasifica un archivo como residuo no vital, o '' si es legítimo."""
        name = fpath.name
        name_lower = name.lower()
        suffix = fpath.suffix.lower()
        # nombre compuesto para extensiones dobles (.tar.gz, .sql.gz)
        lower_full = name_lower

        # 1. Basura de sistema operativo / editores
        if name_lower in _OS_JUNK:
            return "os_junk"

        # 2. PHP de diagnóstico / instaladores residuales
        if name_lower in _DIAGNOSTIC_PHP:
            return "diagnostic_php"

        # 3. Volcados de BD expuestos en el webroot
        if any(lower_full.endswith(e) for e in _DUMP_EXTS):
            return "db_dump_exposed"

        # 4. Archivos comprimidos olvidados en el webroot
        if any(lower_full.endswith(e) for e in _ARCHIVE_EXTS):
            return "archive_exposed"

        # 5. Copias de seguridad / temporales de editores
        if suffix in _BACKUP_EXTS or _BACKUP_NAME_RE.search(name):
            return "backup_leftover"

        # 6. PHP con nombre aleatorio/ofuscado (no pertenece a ningún CMS ni proyecto legítimo)
        # Ej: 6tzrlwycdcyfhk9m86tCdefault.php, a1b2c3d4e5f6.php
        if suffix == ".php" and _RANDOM_PHP_RE.match(name_lower):
            # Excluir si el nombre contiene una palabra reconocible de plugin/tema
            if not any(ind in name_lower for ind in _LEGIT_INDICATORS):
                return "obfuscated_php"

        return ""

    def _quarantine_empty_dirs(self, webroot: Path) -> list:
        """Elimina/cuarentena directorios vacíos residuales (de abajo hacia arriba)."""
        results = []
        if self.clean_mode == SCAN_MODE_ONLY:
            return results
        try:
            all_dirs = [Path(r) / d for r, ds, _ in os.walk(webroot)
                        for d in ds if d.lower() not in _SKIP_DIRS]
        except (OSError, PermissionError):
            return results
        # procesar primero los más profundos
        for d in sorted(all_dirs, key=lambda p: len(p.parts), reverse=True):
            try:
                if d.exists() and d.is_dir() and not any(d.iterdir()):
                    try:
                        rel = str(d.relative_to(self.extract_dir))
                    except ValueError:
                        rel = str(d)
                    d.rmdir()
                    results.append({
                        "path": rel, "cms": "-", "category": "empty_dir",
                        "action": "deleted",
                    })
            except (OSError, PermissionError):
                pass
        return results

    def _handle_residual(self, fpath: Path, category: str) -> dict:
        """Cuarentena (o elimina en strict) un residuo preservando su ruta relativa
        para evitar colisiones de nombres."""
        try:
            rel_path = str(fpath.relative_to(self.extract_dir))
        except ValueError:
            rel_path = str(fpath)

        entry = {"path": rel_path, "cms": "-", "category": category,
                 "action": "logged_only"}

        if self.clean_mode == SCAN_MODE_ONLY:
            return entry

        if self.clean_mode == CLEAN_MODE_STRICT:
            try:
                os.remove(str(fpath))
                entry["action"] = "deleted"
            except (OSError, PermissionError):
                pass
            return entry

        # normal / intermediate: mover a cuarentena preservando estructura
        try:
            dest = self._junk_dir / rel_path
            dest.parent.mkdir(parents=True, exist_ok=True)
            if dest.exists():
                stem, suf = dest.stem, dest.suffix
                counter = 1
                while dest.exists():
                    dest = dest.parent / f"{stem}_{counter}{suf}"
                    counter += 1
            shutil.move(str(fpath), str(dest))
            entry["action"] = "quarantined"
        except (OSError, PermissionError, shutil.Error):
            pass
        return entry

    def _find_cms_roots(self, cms: str) -> list:
        markers = CMS_DETECTION_MARKERS.get(cms)
        if not markers:
            return []
        req_file = markers["file"]
        req_dir = markers["dir"]
        roots = []
        for root, dirs, files in os.walk(self.extract_dir):
            if req_file in files and req_dir in dirs:
                rp = Path(root)
                if cms == "moodle" and not (rp / "lib" / "moodlelib.php").exists():
                    continue
                if cms == "ojs" and not (rp / "lib" / "pkp").exists():
                    continue
                roots.append(rp)
        return roots

    def _scan_wp_junk(self, wp_root: Path, cms: str) -> list:
        """Escanea junk en una instalacion WordPress."""
        results = []
        uploads = wp_root / "wp-content" / "uploads"

        if uploads.exists():
            # 1. Recopilar index.php inyectados en subdirs de uploads
            # (WP solo tiene uno en la raiz de uploads/)
            injected_index = set()
            for root, dirs, files in os.walk(uploads):
                if "index.php" in files:
                    idx_path = Path(root) / "index.php"
                    # El de la raiz de uploads/ es legitimo
                    if idx_path.parent == uploads:
                        continue
                    injected_index.add(str(idx_path))
                    results.append(self._handle_junk(
                        idx_path, "injected_index_php", cms))

            # 2. PHP en uploads — NUNCA legitimo (excepto los ya contados como injected)
            for php_file in self._find_by_extensions(uploads, _PHP_EXTS):
                if str(php_file) in injected_index:
                    continue
                # El index.php raiz de uploads es legitimo
                if php_file.name == "index.php" and php_file.parent == uploads:
                    continue
                results.append(self._handle_junk(
                    php_file, "orphan_php_uploads", cms))

            # 3. Imagenes rotas / falsas en uploads
            for img_file in self._find_by_extensions(uploads, _IMAGE_EXTS):
                if self._is_broken_image(img_file):
                    results.append(self._handle_junk(
                        img_file, "broken_image", cms))

        # 4. Archivos .log en la instalacion WP
        for log_file in self._find_by_extensions(wp_root, frozenset([".log", ".logs"])):
            results.append(self._handle_junk(log_file, "log_file", cms))

        # 5. Archivos .txt en rutas no estandar
        for txt_file in self._find_by_extensions(wp_root, frozenset([".txt"])):
            name_lower = txt_file.name.lower()
            # Excluir archivos txt conocidos en root
            if name_lower in _WP_ROOT_TXT and txt_file.parent == wp_root:
                continue
            # Excluir readme/license dentro de plugins/themes (legitimos)
            rel = str(txt_file.relative_to(wp_root)).replace("\\", "/").lower()
            if any(seg in rel for seg in ("/plugins/", "/themes/", "/vendor/")):
                continue
            # Solo reportar txt fuera de rutas estandar
            if "/uploads/" in rel:
                results.append(self._handle_junk(txt_file, "orphan_txt", cms))

        return results

    def _scan_joomla_junk(self, joomla_root: Path, cms: str) -> list:
        """Escanea junk en una instalacion Joomla."""
        results = []
        images_dir = joomla_root / "images"
        media_dir = joomla_root / "media"

        for upload_dir in [images_dir, media_dir]:
            if not upload_dir.exists():
                continue
            # PHP en dirs de uploads Joomla
            for php_file in self._find_by_extensions(upload_dir, _PHP_EXTS):
                results.append(self._handle_junk(
                    php_file, "orphan_php_uploads", cms))
            # Imagenes rotas
            for img_file in self._find_by_extensions(upload_dir, _IMAGE_EXTS):
                if self._is_broken_image(img_file):
                    results.append(self._handle_junk(
                        img_file, "broken_image", cms))

        # Logs
        for log_file in self._find_by_extensions(joomla_root, frozenset([".log"])):
            results.append(self._handle_junk(log_file, "log_file", cms))

        return results

    def _find_by_extensions(self, directory: Path, extensions: frozenset):
        """Genera archivos con las extensiones dadas."""
        try:
            for root, dirs, files in os.walk(directory):
                for fname in files:
                    if any(fname.lower().endswith(ext) for ext in extensions):
                        yield Path(root) / fname
        except (OSError, PermissionError):
            pass

    def _is_broken_image(self, file_path: Path) -> bool:
        """True si extension es imagen pero MIME no coincide, o archivo 0 bytes."""
        try:
            size = file_path.stat().st_size
            if size == 0:
                return True
        except OSError:
            return False

        if not _MAGIC_AVAILABLE:
            # Sin python-magic, solo detectar 0-byte
            return False

        try:
            mime = magic.from_file(str(file_path), mime=True)
            if not mime:
                return True
            # MIME debe empezar con "image/" para archivos de imagen
            if not mime.startswith("image/"):
                return True
        except Exception:
            pass

        return False

    def _handle_junk(self, file_path: Path, category: str, cms: str) -> dict:
        """Procesa un archivo junk segun el clean_mode."""
        try:
            rel_path = str(file_path.relative_to(self.extract_dir))
        except ValueError:
            rel_path = str(file_path)

        entry = {
            "path": rel_path,
            "cms": cms,
            "category": category,
            "action": "logged_only",
        }

        if self.clean_mode == SCAN_MODE_ONLY:
            return entry

        # always policy: orphan_php_uploads, injected_index_php
        # by_mode policy: log_file, orphan_txt, broken_image
        always_remove = category in ("orphan_php_uploads", "injected_index_php")

        if self.clean_mode == CLEAN_MODE_STRICT:
            # Strict: eliminar todo
            try:
                os.remove(str(file_path))
                entry["action"] = "deleted"
            except (OSError, PermissionError):
                pass
        elif always_remove or self.clean_mode in ("normal", "intermediate"):
            # Normal/Intermediate: cuarentena
            if always_remove or category in ("broken_image",):
                try:
                    self._junk_dir.mkdir(parents=True, exist_ok=True)
                    dest = self._junk_dir / file_path.name
                    counter = 0
                    while dest.exists():
                        counter += 1
                        dest = self._junk_dir / f"{file_path.stem}_{counter}{file_path.suffix}"
                    shutil.move(str(file_path), str(dest))
                    entry["action"] = "quarantined"
                except (OSError, PermissionError, shutil.Error):
                    pass
            else:
                # by_mode items in normal: just log (less aggressive for logs/txt)
                pass

        return entry
