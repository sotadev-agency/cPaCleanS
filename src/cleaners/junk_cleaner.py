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

        for cms in cms_detected:
            roots = self._find_cms_roots(cms)
            for root in roots:
                if cms == "wordpress":
                    results.extend(self._scan_wp_junk(root, cms))
                elif cms == "joomla":
                    results.extend(self._scan_joomla_junk(root, cms))
                # Moodle/OJS: sus uploads estan fuera del tree (moodledata), menos junk

        if results:
            total = len(results)
            acted = sum(1 for r in results if r["action"] != "logged_only")
            self.progress_callback("status",
                f"[JUNK] {total} residuos encontrados, {acted} procesados")

        return results

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
