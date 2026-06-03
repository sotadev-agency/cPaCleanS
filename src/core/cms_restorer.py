"""Restaurador de CMS — descarga versiones limpias desde repositorios oficiales.

Soporta: WordPress (core + plugins/temas activos), Joomla (core), Moodle (core), Laravel (deteccion).
Solo restaura lo que hay en la DB o lo que corresponde al core oficial; no toca personalizaciones.
"""
import os
import re
import json
import shutil
import zipfile
import tarfile
import tempfile
import hashlib
from pathlib import Path
from typing import Callable

import requests

# ── WordPress ──
WP_DOWNLOAD = "https://downloads.wordpress.org/release/wordpress-{version}.zip"
WP_PLUGIN_API = "https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]={slug}"
WP_THEME_API = "https://api.wordpress.org/themes/info/1.2/?action=theme_information&request[slug]={slug}"

# ── Joomla ──
# URL oficial: https://downloads.joomla.org/cms/joomla5/5-1-4/Joomla_5.1.4-Stable-Full_Package.zip
JOOMLA_DOWNLOAD = "https://downloads.joomla.org/cms/joomla{major}/{version_dashed}/Joomla_{version}-Stable-Full_Package.zip"
JOOMLA_DOWNLOAD_GH = "https://github.com/joomla/joomla-cms/releases/download/{version}/Joomla_{version}-Stable-Full_Package.zip"
JOOMLA_CORE_DIRS = ["libraries", "includes", "layouts", "language", "api"]
JOOMLA_ADMIN_SAFE_DIRS = ["includes", "language", "manifests"]  # dentro de administrator/

# ── Moodle ──
# URL oficial: https://download.moodle.org/download.php/direct/stable403/moodle-4.3.3.tgz
MOODLE_DOWNLOAD = "https://download.moodle.org/download.php/direct/{branch}/moodle-{version}.tgz"
MOODLE_CORE_DIRS = [
    "lib", "mod", "admin", "auth", "calendar", "course",
    "enrol", "filter", "grade", "group", "login", "message",
    "my", "notes", "pix", "question", "report", "search",
    "tag", "user", "webservice", "availability", "backup",
    "badges", "cache", "cohort", "comment", "completion",
    "h5p", "media", "portfolio", "rating", "repository",
]

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
                elif cms == "joomla":
                    self._restore_joomla()
                elif cms == "moodle":
                    self._restore_moodle()
                elif cms == "laravel":
                    self._restore_laravel()
            except Exception as e:
                self.log.append({"type": "error", "cms": cms, "message": f"Error general: {e}"})
        return self.log

    # ─────────────────────────── WordPress ───────────────────────────

    def _restore_wordpress(self, backup_info=None):
        self.progress_callback("status", "Restaurando WordPress core...")
        wp_roots = self._find_wp_roots()

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
                self.log.append({"type": "warning", "cms": "wordpress", "message": "No se detecto version WP"})
                continue

            self.log.append({"type": "info", "cms": "wordpress", "message": f"WordPress {version} detectado"})

            clean_dir = self._download_wp_core(version)
            if clean_dir:
                replaced = self._replace_core_files(wp_root, clean_dir, ["wp-admin", "wp-includes"])
                self.log.append({"type": "success", "cms": "wordpress", "message": f"Core restaurado: {replaced} archivos"})

            self._restore_wp_plugins(wp_root, active_plugins)
            self._restore_wp_themes(wp_root, active_theme)

    def _read_wp_active_from_sql(self, sql_path: str) -> tuple:
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
                    if "active_plugins" in line:
                        for m in re.finditer(r'["\']([^"\']+/[^"\']+\.php)["\']', line):
                            slug = m.group(1).split("/")[0]
                            active_plugins.add(slug)
                    if "'template'" in line or '"template"' in line:
                        m = re.search(r"'template'\s*,\s*'([^']+)'", line)
                        if not m:
                            m = re.search(r'"template"\s*,\s*"([^"]+)"', line)
                        if m:
                            active_theme = m.group(1)
        except Exception:
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

    def _restore_wp_plugins(self, wp_root: Path, active_plugins: set):
        plugins_dir = wp_root / "wp-content" / "plugins"
        if not plugins_dir.exists():
            return

        for plugin_dir in plugins_dir.iterdir():
            if not plugin_dir.is_dir():
                continue
            slug = plugin_dir.name
            if active_plugins and slug not in active_plugins:
                self.log.append({"type": "info", "cms": "wordpress", "message": f"Plugin '{slug}' inactivo, omitido"})
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
            if active_theme and slug != active_theme:
                self.log.append({"type": "info", "cms": "wordpress", "message": f"Tema '{slug}' inactivo, omitido"})
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
                               "message": f"Tema '{slug}' no en WordPress.org (premium)"})
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

    # ─────────────────────────── Joomla ───────────────────────────

    def _restore_joomla(self):
        self.progress_callback("status", "Restaurando Joomla core...")
        joomla_roots = self._find_joomla_roots()
        if not joomla_roots:
            self.log.append({"type": "warning", "cms": "joomla",
                           "message": "No se encontro directorio raiz de Joomla"})
            return

        for joomla_root in joomla_roots:
            version = self._detect_joomla_version(joomla_root)
            if not version:
                self.log.append({"type": "warning", "cms": "joomla",
                               "message": "No se pudo detectar version de Joomla"})
                continue

            self.log.append({"type": "info", "cms": "joomla", "message": f"Joomla {version} detectado"})
            clean_dir = self._download_joomla_core(version)
            if not clean_dir:
                continue

            # Reemplazar directorios de core seguros
            total_replaced = self._replace_core_files(joomla_root, clean_dir, JOOMLA_CORE_DIRS)

            # Subdirectorios de administrador que son solo core
            admin_clean = clean_dir / "administrator"
            admin_site = joomla_root / "administrator"
            if admin_clean.exists() and admin_site.exists():
                for sub in JOOMLA_ADMIN_SAFE_DIRS:
                    total_replaced += self._replace_core_files(admin_site, admin_clean, [sub])

            self.log.append({"type": "success", "cms": "joomla",
                           "message": f"Core restaurado: {total_replaced} archivos"})

    def _find_joomla_roots(self) -> list:
        roots = []
        for root, dirs, files in os.walk(self.extract_dir):
            if "configuration.php" in files and ("administrator" in dirs or "components" in dirs):
                roots.append(Path(root))
        return roots

    def _detect_joomla_version(self, joomla_root: Path) -> str:
        # Metodo 1: XML manifest (Joomla 4+/5+)
        xml_file = joomla_root / "administrator" / "manifests" / "files" / "joomla.xml"
        if xml_file.exists():
            try:
                content = xml_file.read_text(encoding="utf-8", errors="replace")
                m = re.search(r"<version>([^<]+)</version>", content)
                if m:
                    return m.group(1).strip()
            except OSError:
                pass

        # Metodo 2: version.php (Joomla 3.x y anteriores)
        for ver_path in [
            joomla_root / "libraries" / "cms" / "version" / "version.php",
            joomla_root / "includes" / "version.php",
            joomla_root / "libraries" / "joomla" / "version.php",
        ]:
            if ver_path.exists():
                try:
                    content = ver_path.read_text(encoding="utf-8", errors="replace")
                    # Joomla 3.x: define('JVERSION', '3.10.12')
                    m = re.search(r"define\s*\(\s*['\"]JVERSION['\"]\s*,\s*['\"]([^'\"]+)['\"]", content)
                    if m:
                        return m.group(1).strip()
                    # Joomla 4+: const MAJOR_VERSION = 4; MINOR_VERSION = 3; PATCH_VERSION = 7
                    major_m = re.search(r"(?:const\s+|define\s*\(['\"])MAJOR_VERSION\s*[=,]\s*(\d+)", content)
                    minor_m = re.search(r"(?:const\s+|define\s*\(['\"])MINOR_VERSION\s*[=,]\s*(\d+)", content)
                    patch_m = re.search(r"(?:const\s+|define\s*\(['\"])PATCH_VERSION\s*[=,]\s*(\d+)", content)
                    if major_m and minor_m and patch_m:
                        return f"{major_m.group(1)}.{minor_m.group(1)}.{patch_m.group(1)}"
                except OSError:
                    pass
        return ""

    def _download_joomla_core(self, version: str) -> Path:
        cache_file = self._cache_dir / f"joomla-{version}.zip"
        extract_to = self._cache_dir / f"joomla-{version}"

        if extract_to.exists() and any(extract_to.iterdir()):
            for d in extract_to.iterdir():
                if d.is_dir() and (d / "libraries").exists():
                    return d
            if (extract_to / "libraries").exists():
                return extract_to

        parts = version.split(".")
        major = parts[0] if parts else "4"
        version_dashed = version.replace(".", "-")

        # URL principal: downloads.joomla.org
        url = JOOMLA_DOWNLOAD.format(major=major, version_dashed=version_dashed, version=version)
        self.progress_callback("status", f"Descargando Joomla {version}...")

        try:
            if not cache_file.exists():
                resp = requests.get(url, timeout=TIMEOUT, stream=True)
                if resp.status_code != 200:
                    # Fallback: GitHub releases
                    gh_url = JOOMLA_DOWNLOAD_GH.format(version=version)
                    resp = requests.get(gh_url, timeout=TIMEOUT, stream=True)
                    if resp.status_code != 200:
                        self.log.append({"type": "error", "cms": "joomla",
                                       "message": f"Error descargando Joomla {version}: HTTP {resp.status_code}"})
                        return None
                with open(str(cache_file), "wb") as f:
                    for chunk in resp.iter_content(chunk_size=65536):
                        f.write(chunk)

            extract_to.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(str(cache_file), "r") as zf:
                zf.extractall(str(extract_to))

            # Algunos paquetes extraen en subcarpeta, otros directamente
            if (extract_to / "libraries").exists():
                return extract_to
            for d in extract_to.iterdir():
                if d.is_dir() and (d / "libraries").exists():
                    return d
            return extract_to
        except (requests.RequestException, zipfile.BadZipFile, OSError) as e:
            self.log.append({"type": "error", "cms": "joomla", "message": f"Error descargando Joomla: {e}"})
            if cache_file.exists():
                try:
                    cache_file.unlink()
                except OSError:
                    pass
            return None

    # ─────────────────────────── Moodle ───────────────────────────

    def _restore_moodle(self):
        self.progress_callback("status", "Restaurando Moodle core...")
        moodle_roots = self._find_moodle_roots()
        if not moodle_roots:
            self.log.append({"type": "warning", "cms": "moodle",
                           "message": "No se encontro directorio raiz de Moodle"})
            return

        for moodle_root in moodle_roots:
            version = self._detect_moodle_version(moodle_root)
            if not version:
                self.log.append({"type": "warning", "cms": "moodle",
                               "message": "No se pudo detectar version de Moodle"})
                continue

            self.log.append({"type": "info", "cms": "moodle", "message": f"Moodle {version} detectado"})
            clean_dir = self._download_moodle_core(version)
            if not clean_dir:
                continue

            total_replaced = self._replace_core_files(moodle_root, clean_dir, MOODLE_CORE_DIRS)
            self.log.append({"type": "success", "cms": "moodle",
                           "message": f"Core restaurado: {total_replaced} archivos"})

    def _find_moodle_roots(self) -> list:
        roots = []
        for root, dirs, files in os.walk(self.extract_dir):
            if "config.php" in files and "lib" in dirs and ("mod" in dirs or "admin" in dirs):
                moodle_lib = Path(root) / "lib" / "moodlelib.php"
                if moodle_lib.exists():
                    roots.append(Path(root))
        return roots

    def _detect_moodle_version(self, moodle_root: Path) -> str:
        version_file = moodle_root / "version.php"
        if not version_file.exists():
            return ""
        try:
            content = version_file.read_text(encoding="utf-8", errors="replace")
            # $release = '4.3.3 (Build: 20231120)' o '4.3.3+'
            m = re.search(r"\$release\s*=\s*['\"]([0-9]+\.[0-9]+\.?[0-9]*)", content)
            if m:
                return m.group(1).strip()
            # Formato alternativo: $MOODLE_RELEASE = '4.3'
            m = re.search(r"\$MOODLE_RELEASE\s*=\s*['\"]([^'\"]+)['\"]", content, re.IGNORECASE)
            if m:
                return m.group(1).strip()
        except OSError:
            pass
        return ""

    def _download_moodle_core(self, version: str) -> Path:
        """Descarga y extrae Moodle desde el mirror oficial."""
        parts = version.split(".")
        try:
            major = int(parts[0])
            minor = int(parts[1]) if len(parts) > 1 else 0
        except (ValueError, IndexError):
            major, minor = 4, 0
        branch = f"stable{major}{minor:02d}"  # 4.3 → stable403, 4.10 → stable410

        cache_file = self._cache_dir / f"moodle-{version}.tgz"
        extract_to = self._cache_dir / f"moodle-{version}"

        if extract_to.exists() and (extract_to / "moodle" / "lib").exists():
            return extract_to / "moodle"

        url = MOODLE_DOWNLOAD.format(branch=branch, version=version)
        self.progress_callback("status", f"Descargando Moodle {version}...")

        try:
            if not cache_file.exists():
                resp = requests.get(url, timeout=TIMEOUT, stream=True, allow_redirects=True)
                if resp.status_code != 200:
                    self.log.append({"type": "error", "cms": "moodle",
                                   "message": f"Error descargando Moodle {version}: HTTP {resp.status_code}"})
                    return None
                with open(str(cache_file), "wb") as f:
                    for chunk in resp.iter_content(chunk_size=65536):
                        f.write(chunk)

            extract_to.mkdir(parents=True, exist_ok=True)
            with tarfile.open(str(cache_file), "r:gz") as tar:
                tar.extractall(str(extract_to))

            moodle_dir = extract_to / "moodle"
            if moodle_dir.exists() and (moodle_dir / "lib").exists():
                return moodle_dir
            # Algunas versiones extraen con nombre diferente
            for d in extract_to.iterdir():
                if d.is_dir() and (d / "lib" / "moodlelib.php").exists():
                    return d
            return extract_to
        except Exception as e:
            self.log.append({"type": "error", "cms": "moodle", "message": f"Error descargando Moodle: {e}"})
            if cache_file.exists():
                try:
                    cache_file.unlink()
                except OSError:
                    pass
            return None

    # ─────────────────────────── Laravel ───────────────────────────

    def _restore_laravel(self):
        """Laravel: detecta version y advierte restauracion manual via composer."""
        self.progress_callback("status", "Verificando Laravel...")
        found = False
        for root, dirs, files in os.walk(self.extract_dir):
            if "artisan" in files and "composer.json" in files:
                found = True
                version = self._detect_laravel_version(Path(root))
                msg = f"Laravel {version} detectado" if version else "Laravel detectado"
                self.log.append({"type": "info", "cms": "laravel", "message": msg})
                self.log.append({"type": "warning", "cms": "laravel",
                               "message": "Restauracion automatica de vendor/ no disponible — ejecutar 'composer install --no-dev' manualmente en el directorio raiz"})
                self.log.append({"type": "info", "cms": "laravel",
                               "message": "Archivos de app/ y routes/ escaneados con patrones maliciosos (php_scanner)"})
                break

        if not found:
            self.log.append({"type": "warning", "cms": "laravel",
                           "message": "No se encontro directorio raiz de Laravel (artisan + composer.json)"})

    def _detect_laravel_version(self, laravel_root: Path) -> str:
        composer_file = laravel_root / "composer.json"
        if not composer_file.exists():
            return ""
        try:
            data = json.loads(composer_file.read_text(encoding="utf-8", errors="replace"))
            require = data.get("require", {})
            version = require.get("laravel/framework", "")
            if version:
                # Limpiar operadores de restriccion: ^10.0, ~10, >=10
                clean = re.sub(r"[^0-9.]", "", version.split(",")[0]).strip(".")
                return clean if clean else version
            return data.get("version", "")
        except Exception:
            return ""

    # ─────────────────────────── Utilidades compartidas ───────────────────────────

    def _replace_core_files(self, site_root: Path, clean_root: Path, dirs: list) -> int:
        """Reemplaza archivos de core en site_root con los de clean_root, solo si el hash difiere."""
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
