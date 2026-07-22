"""CMSFullWiper v2.6.0 — elimina todos los archivos CMS conocidos antes de reinstalar.

Ejecutar ANTES de CMSRestorer y CMSPluginCleaner.
No es cuarentena — los archivos se borran porque seran reemplazados
por versiones limpias desde repos oficiales.
"""
import os
import shutil
from pathlib import Path
from typing import Callable

from ..config.settings import (
    CPANEL_PROTECTED_DIRS, WP_CORE_ROOT_FILES,
    SCAN_MODE_ONLY, CMS_DETECTION_MARKERS,
)


class CMSFullWiper:
    """Wipe completo de archivos CMS antes de reinstalacion limpia."""

    # Archivos de configuracion/conexion — NUNCA eliminar
    PRESERVE_FILES = {
        "wordpress": frozenset(["wp-config.php"]),
        "joomla":    frozenset(["configuration.php"]),
        "moodle":    frozenset(["config.php"]),
        "ojs":       frozenset(["config.inc.php"]),
    }

    # Directorios de contenido de usuario WP — NUNCA eliminar
    PRESERVE_DIRS_WP = frozenset([
        "wp-content/uploads",
        "wp-content/cache",
        "wp-content/upgrade",
    ])

    # Directorios core WP a eliminar
    WP_WIPE_DIRS = ["wp-admin", "wp-includes",
                    "wp-content/themes", "wp-content/plugins",
                    "wp-content/mu-plugins"]

    # Directorios core Joomla a eliminar
    JOOMLA_WIPE_DIRS = [
        "administrator", "components", "modules", "plugins",
        "libraries", "includes", "layouts", "language", "api",
        "templates", "cli", "media",
    ]

    # Directorios core Moodle a eliminar
    MOODLE_WIPE_DIRS = [
        "lib", "admin", "auth", "availability", "backup", "badges",
        "cache", "calendar", "cohort", "comment", "completion",
        "course", "enrol", "filter", "grade", "group", "h5p",
        "login", "media", "message", "my", "notes", "pix",
        "portfolio", "question", "rating", "report", "repository",
        "rss", "search", "tag", "user", "webservice",
        "mod", "blocks", "local", "theme",
    ]

    # Directorios core OJS a eliminar
    OJS_WIPE_DIRS = [
        "classes", "controllers", "pages", "templates",
        "lib", "tools", "dbscripts",
    ]

    def __init__(self, extract_dir: str, cms_detected: list,
                 clean_mode: str = "normal",
                 progress_callback: Callable = None):
        self.extract_dir = Path(extract_dir)
        self.cms_detected = cms_detected
        self.clean_mode = clean_mode
        self.progress_callback = progress_callback or (lambda *a: None)

    def wipe(self) -> dict:
        """Elimina archivos CMS conocidos. Retorna dict con stats por CMS.
        En SCAN_MODE_ONLY retorna zeros sin tocar nada."""
        result = {}
        if self.clean_mode == SCAN_MODE_ONLY:
            for cms in self.cms_detected:
                result[cms] = {"files_removed": 0, "dirs_removed": 0, "preserved": []}
            return result

        for cms in self.cms_detected:
            try:
                if cms == "wordpress":
                    roots = self._find_roots(cms)
                    stats = {"files_removed": 0, "dirs_removed": 0, "preserved": []}
                    for root in roots:
                        s = self._wipe_wordpress(root)
                        stats["files_removed"] += s["files_removed"]
                        stats["dirs_removed"] += s["dirs_removed"]
                        stats["preserved"].extend(s["preserved"])
                    result[cms] = stats
                elif cms == "joomla":
                    roots = self._find_roots(cms)
                    stats = {"files_removed": 0, "dirs_removed": 0, "preserved": []}
                    for root in roots:
                        s = self._wipe_generic(root, self.JOOMLA_WIPE_DIRS, cms)
                        stats["files_removed"] += s["files_removed"]
                        stats["dirs_removed"] += s["dirs_removed"]
                        stats["preserved"].extend(s["preserved"])
                    result[cms] = stats
                elif cms == "moodle":
                    roots = self._find_roots(cms)
                    stats = {"files_removed": 0, "dirs_removed": 0, "preserved": []}
                    for root in roots:
                        s = self._wipe_generic(root, self.MOODLE_WIPE_DIRS, cms)
                        stats["files_removed"] += s["files_removed"]
                        stats["dirs_removed"] += s["dirs_removed"]
                        stats["preserved"].extend(s["preserved"])
                    result[cms] = stats
                elif cms == "ojs":
                    roots = self._find_roots(cms)
                    stats = {"files_removed": 0, "dirs_removed": 0, "preserved": []}
                    for root in roots:
                        s = self._wipe_generic(root, self.OJS_WIPE_DIRS, cms)
                        stats["files_removed"] += s["files_removed"]
                        stats["dirs_removed"] += s["dirs_removed"]
                        stats["preserved"].extend(s["preserved"])
                    result[cms] = stats
                else:
                    result[cms] = {"files_removed": 0, "dirs_removed": 0, "preserved": []}
            except Exception as e:
                result[cms] = {"files_removed": 0, "dirs_removed": 0,
                               "preserved": [], "error": str(e)}

        return result

    def _find_roots(self, cms: str) -> list:
        """Localiza raices CMS en el extract_dir."""
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

    def _is_cpanel_protected(self, file_path: Path) -> bool:
        """True si la ruta esta bajo dirs protegidos de cPanel."""
        try:
            rel = file_path.relative_to(self.extract_dir)
            top_parts = {p.lower() for p in rel.parts[:3]}
            return bool(top_parts & CPANEL_PROTECTED_DIRS)
        except ValueError:
            return False

    def _wipe_wordpress(self, wp_root: Path) -> dict:
        """Wipe WP: elimina dirs core, plugins, temas y PHP raiz.
        Preserva wp-config.php y uploads/cache."""
        stats = {"files_removed": 0, "dirs_removed": 0, "preserved": []}
        preserve = self.PRESERVE_FILES.get("wordpress", frozenset())

        self.progress_callback("status",
            f"[WIPER] WordPress: limpiando {wp_root.name}...")

        # Eliminar directorios core
        for dirname in self.WP_WIPE_DIRS:
            target = wp_root / dirname
            if not target.exists():
                continue
            if self._is_cpanel_protected(target):
                stats["preserved"].append(str(target))
                continue
            try:
                file_count = sum(1 for _ in target.rglob("*") if _.is_file())
                shutil.rmtree(str(target))
                stats["files_removed"] += file_count
                stats["dirs_removed"] += 1
            except (OSError, PermissionError, shutil.Error):
                pass

        # Eliminar PHP raiz (excepto wp-config.php)
        for item in wp_root.iterdir():
            if not item.is_file():
                continue
            if item.name.lower() in preserve:
                stats["preserved"].append(str(item))
                continue
            if self._is_cpanel_protected(item):
                stats["preserved"].append(str(item))
                continue
            name_lower = item.name.lower()
            # Eliminar archivos core PHP y .htaccess raiz
            is_core_root = name_lower in {f.lower() for f in WP_CORE_ROOT_FILES}
            is_php = name_lower.endswith((".php", ".php5", ".php7", ".phtml"))
            if is_core_root or is_php:
                try:
                    item.unlink()
                    stats["files_removed"] += 1
                except (OSError, PermissionError):
                    pass

        # Eliminar wp-content/index.php si existe
        wpc_index = wp_root / "wp-content" / "index.php"
        if wpc_index.exists():
            try:
                wpc_index.unlink()
                stats["files_removed"] += 1
            except (OSError, PermissionError):
                pass

        return stats

    def _wipe_generic(self, cms_root: Path, wipe_dirs: list, cms: str) -> dict:
        """Wipe generico para Joomla/Moodle/OJS: elimina dirs core listados."""
        stats = {"files_removed": 0, "dirs_removed": 0, "preserved": []}
        preserve = self.PRESERVE_FILES.get(cms, frozenset())

        self.progress_callback("status",
            f"[WIPER] {cms.upper()}: limpiando {cms_root.name}...")

        for dirname in wipe_dirs:
            target = cms_root / dirname
            if not target.exists():
                continue
            if self._is_cpanel_protected(target):
                stats["preserved"].append(str(target))
                continue
            try:
                file_count = sum(1 for _ in target.rglob("*") if _.is_file())
                shutil.rmtree(str(target))
                stats["files_removed"] += file_count
                stats["dirs_removed"] += 1
            except (OSError, PermissionError, shutil.Error):
                pass

        # Eliminar PHP raiz (excepto config)
        for item in cms_root.iterdir():
            if not item.is_file():
                continue
            if item.name.lower() in {p.lower() for p in preserve}:
                stats["preserved"].append(str(item))
                continue
            if item.name.lower().endswith((".php", ".php5", ".php7", ".phtml")):
                if self._is_cpanel_protected(item):
                    stats["preserved"].append(str(item))
                    continue
                try:
                    item.unlink()
                    stats["files_removed"] += 1
                except (OSError, PermissionError):
                    pass

        return stats
