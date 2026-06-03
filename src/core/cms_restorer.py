"""Restaurador de CMS — descarga versiones limpias, solo plugins/temas activos."""
import os
import re
import json
import shutil
import zipfile
import tempfile
import hashlib
from pathlib import Path
from typing import Callable

import requests

WP_VERSION_API = "https://api.wordpress.org/core/version-check/1.7/"
WP_DOWNLOAD = "https://downloads.wordpress.org/release/wordpress-{version}.zip"
WP_PLUGIN_API = "https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]={slug}"
WP_THEME_API = "https://api.wordpress.org/themes/info/1.2/?action=theme_information&request[slug]={slug}"

TIMEOUT = 60


class CMSRestorer:
    def __init__(self, extract_dir: str, progress_callback: Callable = None):
        self.extract_dir = Path(extract_dir)
        self.progress_callback = progress_callback or (lambda *a: None)
        self.log = []
        self._cache_dir = Path(tempfile.gettempdir()) / "cpacleans_cache"
        self._cache_dir.mkdir(parents=True, exist_ok=True)

    def restore_all(self, cms_list: list, backup_info=None) -> list:
        for cms in cms_list:
            try:
                if cms == "wordpress":
                    self._restore_wordpress(backup_info)
                elif cms == "moodle":
                    self._restore_moodle()
            except Exception as e:
                self.log.append({"type": "error", "cms": cms, "message": f"Error general: {e}"})
        return self.log

    # ───────────── WordPress ─────────────

    def _restore_wordpress(self, backup_info=None):
        self.progress_callback("status", "Restaurando WordPress core...")
        wp_roots = self._find_wp_roots()

        # Leer plugins/temas activos desde los dumps SQL
        active_plugins = set()
        active_theme = ""
        if backup_info and backup_info.structure.get("databases"):
            for db_path in backup_info.structure["databases"]:
                ap, at = self._read_wp_active_from_sql(db_path)
                active_plugins.update(ap)
                if at:
                    active_theme = at

        for wp_root in wp_roots:
            version = self._detect_wp_version(wp_root)
            if not version:
                self.log.append({"type": "warning", "cms": "wordpress", "message": f"No se detecto version WP"})
                continue

            self.log.append({"type": "info", "cms": "wordpress", "message": f"WordPress {version} detectado"})

            clean_dir = self._download_wp_core(version)
            if clean_dir:
                replaced = self._replace_core_files(wp_root, clean_dir, ["wp-admin", "wp-includes"])
                self.log.append({"type": "success", "cms": "wordpress", "message": f"Core restaurado: {replaced} archivos"})

            self._restore_wp_plugins(wp_root, active_plugins)
            self._restore_wp_themes(wp_root, active_theme)

    def _read_wp_active_from_sql(self, sql_path: str) -> tuple:
        """Lee plugins activos y tema activo desde un dump SQL de WordPress."""
        active_plugins = set()
        active_theme = ""

        try:
            import gzip
            if sql_path.endswith(".gz"):
                opener = lambda: gzip.open(sql_path, "rt", encoding="utf-8", errors="replace")
            else:
                opener = lambda: open(sql_path, "r", encoding="utf-8", errors="replace")

            with opener() as f:
                for line in f:
                    if len(line) > 500_000:
                        continue

                    # Buscar active_plugins en wp_options
                    if "active_plugins" in line:
                        # Extraer slugs de plugins del serialized PHP array
                        for m in re.finditer(r'["\']([^"\']+/[^"\']+\.php)["\']', line):
                            slug = m.group(1).split("/")[0]
                            active_plugins.add(slug)

                    # Buscar template (tema activo) en wp_options
                    if "'template'" in line or '"template"' in line:
                        m = re.search(r"'template'\s*,\s*'([^']+)'", line)
                        if not m:
                            m = re.search(r'"template"\s*,\s*"([^"]+)"', line)
                        if m:
                            active_theme = m.group(1)

        except (OSError, Exception):
            pass

        return active_plugins, active_theme

    def _find_wp_roots(self) -> list:
        roots = []
        for root, dirs, files in os.walk(self.extract_dir):
            if "wp-config.php" in files and "wp-includes" in dirs:
                roots.append(Path(root))
        return roots

    def _detect_wp_version(self, wp_root: Path) -> str:
        version_file = wp_root / "wp-includes" / "version.php"
        if not version_file.exists():
            return ""
        try:
            content = version_file.read_text(encoding="utf-8", errors="replace")
            match = re.search(r"\$wp_version\s*=\s*['\"]([^'\"]+)['\"]", content)
            return match.group(1) if match else ""
        except OSError:
            return ""

    def _download_wp_core(self, version: str) -> Path:
        cache_file = self._cache_dir / f"wordpress-{version}.zip"
        extract_to = self._cache_dir / f"wordpress-{version}"

        if extract_to.exists() and (extract_to / "wordpress" / "wp-includes").exists():
            return extract_to / "wordpress"

        url = WP_DOWNLOAD.format(version=version)
        self.progress_callback("status", f"Descargando WordPress {version}...")

        try:
            if not cache_file.exists():
                resp = requests.get(url, timeout=TIMEOUT, stream=True)
                if resp.status_code != 200:
                    self.log.append({"type": "error", "cms": "wordpress", "message": f"Error descargando WP {version}: HTTP {resp.status_code}"})
                    return None
                with open(str(cache_file), "wb") as f:
                    for chunk in resp.iter_content(chunk_size=65536):
                        f.write(chunk)

            extract_to.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(str(cache_file), "r") as zf:
                zf.extractall(str(extract_to))
            return extract_to / "wordpress"
        except (requests.RequestException, zipfile.BadZipFile, OSError) as e:
            self.log.append({"type": "error", "cms": "wordpress", "message": f"Error descargando WP: {e}"})
            return None

    def _replace_core_files(self, site_root: Path, clean_root: Path, dirs: list) -> int:
        replaced = 0
        for dirname in dirs:
            site_dir = site_root / dirname
            clean_dir = clean_root / dirname
            if not clean_dir.exists() or not site_dir.exists():
                continue
            for root, _, files in os.walk(clean_dir):
                rel = Path(root).relative_to(clean_root)
                site_target_dir = site_root / rel
                for fname in files:
                    clean_file = Path(root) / fname
                    site_file = site_target_dir / fname
                    if site_file.exists():
                        if self._file_hash(str(clean_file)) != self._file_hash(str(site_file)):
                            try:
                                shutil.copy2(str(clean_file), str(site_file))
                                replaced += 1
                            except (OSError, PermissionError):
                                pass
                    else:
                        try:
                            site_target_dir.mkdir(parents=True, exist_ok=True)
                            shutil.copy2(str(clean_file), str(site_file))
                            replaced += 1
                        except (OSError, PermissionError):
                            pass
        return replaced

    def _restore_wp_plugins(self, wp_root: Path, active_plugins: set):
        plugins_dir = wp_root / "wp-content" / "plugins"
        if not plugins_dir.exists():
            return

        for plugin_dir in plugins_dir.iterdir():
            if not plugin_dir.is_dir():
                continue

            slug = plugin_dir.name

            # Obs. 6: Solo restaurar plugins activos
            if active_plugins and slug not in active_plugins:
                self.log.append({"type": "info", "cms": "wordpress",
                               "message": f"Plugin '{slug}' inactivo, omitido"})
                continue

            self.progress_callback("status", f"Plugin: {slug}...")

            try:
                url = WP_PLUGIN_API.format(slug=slug)
                resp = requests.get(url, timeout=15)

                if resp.status_code == 200:
                    data = resp.json()
                    if isinstance(data, dict) and "download_link" in data:
                        dl_url = data["download_link"]
                        version = data.get("version", "?")
                        clean_plugin = self._download_and_extract(slug, dl_url, "plugin")
                        if clean_plugin:
                            replaced = self._replace_plugin_files(plugin_dir, clean_plugin)
                            self.log.append({"type": "success", "cms": "wordpress",
                                           "message": f"Plugin '{slug}' v{version}: {replaced} archivos"})
                        continue

                self.log.append({"type": "warning", "cms": "wordpress",
                               "message": f"Plugin '{slug}' no en WordPress.org (premium/custom)"})
            except (requests.RequestException, json.JSONDecodeError, ValueError):
                self.log.append({"type": "warning", "cms": "wordpress",
                               "message": f"Plugin '{slug}': no se pudo verificar"})

    def _restore_wp_themes(self, wp_root: Path, active_theme: str):
        themes_dir = wp_root / "wp-content" / "themes"
        if not themes_dir.exists():
            return

        for theme_dir in themes_dir.iterdir():
            if not theme_dir.is_dir():
                continue

            slug = theme_dir.name

            # Obs. 6: Solo restaurar tema activo
            if active_theme and slug != active_theme:
                self.log.append({"type": "info", "cms": "wordpress",
                               "message": f"Tema '{slug}' inactivo, omitido"})
                continue

            self.progress_callback("status", f"Tema: {slug}...")

            try:
                url = WP_THEME_API.format(slug=slug)
                resp = requests.get(url, timeout=15)

                if resp.status_code == 200:
                    data = resp.json()
                    if isinstance(data, dict) and "download_link" in data:
                        dl_url = data["download_link"]
                        version = data.get("version", "?")
                        clean_theme = self._download_and_extract(slug, dl_url, "theme")
                        if clean_theme:
                            replaced = self._replace_plugin_files(theme_dir, clean_theme)
                            self.log.append({"type": "success", "cms": "wordpress",
                                           "message": f"Tema '{slug}' v{version}: {replaced} archivos"})
                        continue

                self.log.append({"type": "warning", "cms": "wordpress",
                               "message": f"Tema '{slug}' no en WordPress.org (premium — limpiado con patrones pero sin verificar integridad)"})
            except (requests.RequestException, json.JSONDecodeError, ValueError):
                self.log.append({"type": "warning", "cms": "wordpress",
                               "message": f"Tema '{slug}': no se pudo verificar"})

    def _download_and_extract(self, slug: str, url: str, kind: str) -> Path:
        cache_file = self._cache_dir / f"wp-{kind}-{slug}.zip"
        extract_to = self._cache_dir / f"wp-{kind}-{slug}"

        if extract_to.exists() and any(extract_to.iterdir()):
            for d in extract_to.iterdir():
                if d.is_dir():
                    return d
            return extract_to

        try:
            if not cache_file.exists():
                resp = requests.get(url, timeout=TIMEOUT, stream=True)
                if resp.status_code != 200:
                    return None
                with open(str(cache_file), "wb") as f:
                    for chunk in resp.iter_content(chunk_size=65536):
                        f.write(chunk)

            extract_to.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(str(cache_file), "r") as zf:
                zf.extractall(str(extract_to))

            for d in extract_to.iterdir():
                if d.is_dir():
                    return d
            return extract_to
        except (requests.RequestException, zipfile.BadZipFile, OSError):
            return None

    def _replace_plugin_files(self, target_dir: Path, clean_dir: Path) -> int:
        replaced = 0
        for root, _, files in os.walk(clean_dir):
            rel = Path(root).relative_to(clean_dir)
            target = target_dir / rel
            for fname in files:
                clean_file = Path(root) / fname
                site_file = target / fname
                if site_file.exists():
                    if self._file_hash(str(clean_file)) != self._file_hash(str(site_file)):
                        try:
                            shutil.copy2(str(clean_file), str(site_file))
                            replaced += 1
                        except (OSError, PermissionError):
                            pass
        return replaced

    # ───────────── Moodle ─────────────

    def _restore_moodle(self):
        self.progress_callback("status", "Verificando Moodle...")
        for root, dirs, files in os.walk(self.extract_dir):
            if "config.php" in files and "mod" in dirs and "lib" in dirs:
                version = self._detect_moodle_version(Path(root))
                if version:
                    self.log.append({"type": "info", "cms": "moodle", "message": f"Moodle {version} detectado"})
                self.log.append({"type": "warning", "cms": "moodle",
                               "message": "Restauracion de Moodle: limpieza con patrones aplicada, descarga manual recomendada desde moodle.org"})
                break

    def _detect_moodle_version(self, moodle_root: Path) -> str:
        version_file = moodle_root / "version.php"
        if not version_file.exists():
            return ""
        try:
            content = version_file.read_text(encoding="utf-8", errors="replace")
            match = re.search(r"\$release\s*=\s*['\"]([^'\"]+)['\"]", content)
            return match.group(1) if match else ""
        except OSError:
            return ""

    @staticmethod
    def _file_hash(path: str) -> str:
        sha = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    sha.update(chunk)
            return sha.hexdigest()
        except (OSError, PermissionError):
            return ""
