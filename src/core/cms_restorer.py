"""Restaurador de CMS — descarga core limpio y hace rebuild completo.

v2.2.2: Estrategia "full rebuild":
  - Elimina completamente los directorios core del CMS infectado
  - Descarga version limpia desde el repositorio oficial
  - Conserva SOLO los archivos del USUARIO: config BD, uploads, .htaccess
  - Garantiza que el .tar.gz final sea restaurable en WHM sin errores post-restore

CMS soportados:
  WordPress  — rebuild completo (core + plugins/temas activos desde DB)
  Joomla     — rebuild de dirs core seguros
  Moodle     — rebuild de dirs core
  Laravel    — deteccion + aviso composer install
  OJS        — deteccion + rebuild dirs core
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

# Directorios core de WP a hacer rebuild completo
WP_CORE_DIRS = ["wp-admin", "wp-includes"]

# Archivos PHP raiz de WP que son core (no del usuario)
WP_CORE_ROOT_FILES = [
    "index.php", "wp-activate.php", "wp-blog-header.php",
    "wp-comments-post.php", "wp-cron.php", "wp-links-opml.php",
    "wp-load.php", "wp-login.php", "wp-mail.php", "wp-settings.php",
    "wp-signup.php", "wp-trackback.php", "xmlrpc.php",
]

# ── Joomla ──
JOOMLA_DOWNLOAD = "https://downloads.joomla.org/cms/joomla{major}/{version_dashed}/Joomla_{version}-Stable-Full_Package.zip"
JOOMLA_DOWNLOAD_GH = "https://github.com/joomla/joomla-cms/releases/download/{version}/Joomla_{version}-Stable-Full_Package.zip"
# Dirs de solo core (sin extensiones de usuario) — rebuild completo seguro
JOOMLA_CORE_DIRS = ["libraries", "includes", "layouts", "language", "api"]
JOOMLA_ADMIN_CORE_DIRS = ["includes", "language", "manifests"]  # dentro de administrator/

# ── Moodle ──
MOODLE_DOWNLOAD = "https://download.moodle.org/download.php/direct/{branch}/moodle-{version}.tgz"
# Dirs claramente core de Moodle (excluye mod/, blocks/, local/ que pueden tener plugins de usuario)
MOODLE_CORE_DIRS = [
    "lib", "admin", "auth", "availability", "backup", "badges",
    "cache", "calendar", "cohort", "comment", "completion",
    "course", "enrol", "filter", "grade", "group", "h5p",
    "login", "media", "message", "my", "notes", "pix",
    "portfolio", "question", "rating", "report", "repository",
    "rss", "search", "tag", "user", "webservice",
]

# ── OJS (Open Journal Systems) ──
OJS_DOWNLOAD_GH = "https://github.com/pkp/ojs/releases/download/{tag}/{archive}"
OJS_CORE_DIRS = ["classes", "controllers", "pages", "templates", "lib", "tools", "dbscripts"]

TIMEOUT = 90


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
                elif cms == "ojs":
                    self._restore_ojs()
            except Exception as e:
                self.log.append({"type": "error", "cms": cms, "message": f"Error general: {e}"})
        return self.log

    # ─────────────────────────── WordPress ───────────────────────────

    def _restore_wordpress(self, backup_info=None):
        """Rebuild completo: elimina dirs core infectados, instala core limpio, conserva wp-content y wp-config."""
        self.progress_callback("status", "Restaurando WordPress (rebuild completo)...")
        wp_roots = self._find_wp_roots()
        if not wp_roots:
            self.log.append({"type": "warning", "cms": "wordpress", "message": "No se encontro instalacion de WordPress"})
            return

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
                self.log.append({"type": "warning", "cms": "wordpress", "message": f"Version WP no detectada en {wp_root.name}"})
                continue

            self.log.append({"type": "info", "cms": "wordpress", "message": f"WordPress {version} en {wp_root.name}"})
            clean_dir = self._download_wp_core(version)
            if not clean_dir:
                continue

            # ── Rebuild completo de directorios core ──
            rebuilt_files = self._full_rebuild_dirs(wp_root, clean_dir, WP_CORE_DIRS, cms_key="wordpress")

            # ── Rebuild de archivos PHP raiz (index.php, wp-login.php, etc.) ──
            rebuilt_root = self._rebuild_root_php_files(wp_root, clean_dir, WP_CORE_ROOT_FILES)

            total = rebuilt_files + rebuilt_root
            self.log.append({"type": "success", "cms": "wordpress",
                           "message": f"Core rebuildeado: {total} archivos ({len(WP_CORE_DIRS)} dirs + {rebuilt_root} archivos raiz)"})

            # ── Restaurar plugins y temas activos desde WordPress.org ──
            self._restore_wp_plugins(wp_root, active_plugins)
            self._restore_wp_themes(wp_root, active_theme)

    def _rebuild_root_php_files(self, site_root: Path, clean_root: Path, file_list: list) -> int:
        """Reemplaza archivos PHP raiz del core (no toca wp-config.php ni .htaccess)."""
        count = 0
        for fname in file_list:
            clean_file = clean_root / fname
            site_file = site_root / fname
            if not clean_file.exists():
                continue
            try:
                shutil.copy2(str(clean_file), str(site_file))
                count += 1
            except (OSError, PermissionError):
                pass
        return count

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
                    self.log.append({"type": "error", "cms": "wordpress", "message": f"HTTP {resp.status_code} descargando WP {version}"})
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
            if cache_file.exists():
                try:
                    cache_file.unlink()
                except OSError:
                    pass
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
                        version = data.get("version", "?")
                        clean_plugin = self._download_and_extract_zip(slug, data["download_link"], "plugin")
                        if clean_plugin:
                            rebuilt = self._full_rebuild_dirs(plugin_dir, clean_plugin, ["."], cms_key="wordpress")
                            self.log.append({"type": "success", "cms": "wordpress",
                                           "message": f"Plugin '{slug}' v{version}: {rebuilt} archivos"})
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
                        version = data.get("version", "?")
                        clean_theme = self._download_and_extract_zip(slug, data["download_link"], "theme")
                        if clean_theme:
                            rebuilt = self._full_rebuild_dirs(theme_dir, clean_theme, ["."], cms_key="wordpress")
                            self.log.append({"type": "success", "cms": "wordpress",
                                           "message": f"Tema '{slug}' v{version}: {rebuilt} archivos"})
                        continue
                self.log.append({"type": "warning", "cms": "wordpress",
                               "message": f"Tema '{slug}' no en WordPress.org (premium)"})
            except (requests.RequestException, json.JSONDecodeError, ValueError):
                self.log.append({"type": "warning", "cms": "wordpress",
                               "message": f"Tema '{slug}': no se pudo verificar"})

    def _download_and_extract_zip(self, slug: str, url: str, kind: str) -> Path:
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
        self.progress_callback("status", "Restaurando Joomla core (rebuild completo)...")
        joomla_roots = self._find_joomla_roots()
        if not joomla_roots:
            self.log.append({"type": "warning", "cms": "joomla", "message": "No se encontro directorio raiz de Joomla"})
            return

        for joomla_root in joomla_roots:
            version = self._detect_joomla_version(joomla_root)
            if not version:
                self.log.append({"type": "warning", "cms": "joomla", "message": "Version Joomla no detectada"})
                continue

            self.log.append({"type": "info", "cms": "joomla", "message": f"Joomla {version} detectado"})
            clean_dir = self._download_joomla_core(version)
            if not clean_dir:
                continue

            # Rebuild de directorios core seguros (sin extensiones de usuario)
            total = self._full_rebuild_dirs(joomla_root, clean_dir, JOOMLA_CORE_DIRS, cms_key="joomla")

            # Rebuild de subdirectorios core de administrator/
            admin_clean = clean_dir / "administrator"
            admin_site = joomla_root / "administrator"
            if admin_clean.exists() and admin_site.exists():
                total += self._full_rebuild_dirs(admin_site, admin_clean, JOOMLA_ADMIN_CORE_DIRS, cms_key="joomla")

            self.log.append({"type": "success", "cms": "joomla", "message": f"Core rebuildeado: {total} archivos"})

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

        # Metodo 2: version.php (Joomla 3.x)
        for ver_path in [
            joomla_root / "libraries" / "cms" / "version" / "version.php",
            joomla_root / "includes" / "version.php",
        ]:
            if ver_path.exists():
                try:
                    content = ver_path.read_text(encoding="utf-8", errors="replace")
                    m = re.search(r"define\s*\(\s*['\"]JVERSION['\"]\s*,\s*['\"]([^'\"]+)['\"]", content)
                    if m:
                        return m.group(1).strip()
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

        if extract_to.exists() and any(p.name == "libraries" for p in extract_to.iterdir() if p.is_dir()):
            return extract_to
        # Puede estar un nivel abajo
        if extract_to.exists():
            for d in extract_to.iterdir():
                if d.is_dir() and (d / "libraries").exists():
                    return d

        parts = version.split(".")
        major = parts[0] if parts else "4"
        version_dashed = version.replace(".", "-")
        url = JOOMLA_DOWNLOAD.format(major=major, version_dashed=version_dashed, version=version)
        self.progress_callback("status", f"Descargando Joomla {version}...")

        try:
            if not cache_file.exists():
                resp = requests.get(url, timeout=TIMEOUT, stream=True)
                if resp.status_code != 200:
                    gh_url = JOOMLA_DOWNLOAD_GH.format(version=version)
                    resp = requests.get(gh_url, timeout=TIMEOUT, stream=True)
                    if resp.status_code != 200:
                        self.log.append({"type": "error", "cms": "joomla",
                                       "message": f"HTTP {resp.status_code} descargando Joomla {version}"})
                        return None
                with open(str(cache_file), "wb") as f:
                    for chunk in resp.iter_content(chunk_size=65536):
                        f.write(chunk)

            extract_to.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(str(cache_file), "r") as zf:
                zf.extractall(str(extract_to))

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
        self.progress_callback("status", "Restaurando Moodle core (rebuild completo)...")
        moodle_roots = self._find_moodle_roots()
        if not moodle_roots:
            self.log.append({"type": "warning", "cms": "moodle", "message": "No se encontro directorio raiz de Moodle"})
            return

        for moodle_root in moodle_roots:
            version = self._detect_moodle_version(moodle_root)
            if not version:
                self.log.append({"type": "warning", "cms": "moodle", "message": "Version Moodle no detectada"})
                continue

            self.log.append({"type": "info", "cms": "moodle", "message": f"Moodle {version} detectado"})
            clean_dir = self._download_moodle_core(version)
            if not clean_dir:
                continue

            total = self._full_rebuild_dirs(moodle_root, clean_dir, MOODLE_CORE_DIRS, cms_key="moodle")
            self.log.append({"type": "success", "cms": "moodle", "message": f"Core rebuildeado: {total} archivos"})

    def _find_moodle_roots(self) -> list:
        roots = []
        for root, dirs, files in os.walk(self.extract_dir):
            if "config.php" in files and "lib" in dirs and ("mod" in dirs or "admin" in dirs):
                if (Path(root) / "lib" / "moodlelib.php").exists():
                    roots.append(Path(root))
        return roots

    def _detect_moodle_version(self, moodle_root: Path) -> str:
        version_file = moodle_root / "version.php"
        if not version_file.exists():
            return ""
        try:
            content = version_file.read_text(encoding="utf-8", errors="replace")
            m = re.search(r"\$release\s*=\s*['\"]([0-9]+\.[0-9]+\.?[0-9]*)", content)
            if m:
                return m.group(1).strip()
        except OSError:
            pass
        return ""

    def _download_moodle_core(self, version: str) -> Path:
        parts = version.split(".")
        try:
            major = int(parts[0])
            minor = int(parts[1]) if len(parts) > 1 else 0
        except (ValueError, IndexError):
            major, minor = 4, 0
        branch = f"stable{major}{minor:02d}"

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
                                   "message": f"HTTP {resp.status_code} descargando Moodle {version}"})
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
        self.progress_callback("status", "Verificando Laravel...")
        found = False
        for root, dirs, files in os.walk(self.extract_dir):
            if "artisan" in files and "composer.json" in files:
                found = True
                version = self._detect_laravel_version(Path(root))
                msg = f"Laravel {version} detectado" if version else "Laravel detectado"
                self.log.append({"type": "info", "cms": "laravel", "message": msg})
                self.log.append({"type": "warning", "cms": "laravel",
                               "message": "Restauracion de vendor/ requiere: composer install --no-dev (ejecutar manualmente en el directorio raiz)"})
                break
        if not found:
            self.log.append({"type": "warning", "cms": "laravel",
                           "message": "No se encontro instalacion de Laravel (artisan + composer.json)"})

    def _detect_laravel_version(self, laravel_root: Path) -> str:
        try:
            data = json.loads((laravel_root / "composer.json").read_text(encoding="utf-8", errors="replace"))
            version = data.get("require", {}).get("laravel/framework", "")
            if version:
                return re.sub(r"[^0-9.]", "", version.split(",")[0]).strip(".")
            return data.get("version", "")
        except Exception:
            return ""

    # ─────────────────────────── OJS (Open Journal Systems) ───────────────────────────

    def _restore_ojs(self):
        self.progress_callback("status", "Restaurando OJS core (rebuild completo)...")
        ojs_roots = self._find_ojs_roots()
        if not ojs_roots:
            self.log.append({"type": "warning", "cms": "ojs", "message": "No se encontro instalacion de OJS"})
            return

        for ojs_root in ojs_roots:
            version = self._detect_ojs_version(ojs_root)
            if not version:
                self.log.append({"type": "warning", "cms": "ojs", "message": "Version OJS no detectada"})
                continue

            self.log.append({"type": "info", "cms": "ojs", "message": f"OJS {version} detectado"})
            clean_dir = self._download_ojs_core(version)
            if not clean_dir:
                continue

            total = self._full_rebuild_dirs(ojs_root, clean_dir, OJS_CORE_DIRS, cms_key="ojs")
            self.log.append({"type": "success", "cms": "ojs",
                           "message": f"Core rebuildeado: {total} archivos (conservado: config.inc.php, public/)"})

    def _find_ojs_roots(self) -> list:
        roots = []
        for root, dirs, files in os.walk(self.extract_dir):
            # OJS tiene config.inc.php + lib/pkp/ (PKP library) + classes/
            if "config.inc.php" in files and "lib" in dirs and "classes" in dirs:
                pkp_lib = Path(root) / "lib" / "pkp"
                if pkp_lib.exists():
                    roots.append(Path(root))
        return roots

    def _detect_ojs_version(self, ojs_root: Path) -> str:
        # Metodo 1: desde config.inc.php comentario de version
        config_file = ojs_root / "config.inc.php"
        if config_file.exists():
            try:
                content = config_file.read_text(encoding="utf-8", errors="replace")
                m = re.search(r"Open Journal Systems\s+([0-9]+\.[0-9]+\.[0-9]+)", content)
                if m:
                    return m.group(1).strip()
            except OSError:
                pass

        # Metodo 2: desde dbscripts/xml/ojs_schema.xml
        schema_file = ojs_root / "dbscripts" / "xml" / "ojs_schema.xml"
        if schema_file.exists():
            try:
                content = schema_file.read_text(encoding="utf-8", errors="replace")
                m = re.search(r'version="([0-9]+\.[0-9]+\.[0-9]+)', content)
                if m:
                    return m.group(1).strip()
            except OSError:
                pass

        # Metodo 3: desde lib/pkp/classes/core/PKPApplication.php
        pkp_app = ojs_root / "lib" / "pkp" / "classes" / "core" / "PKPApplication.php"
        if pkp_app.exists():
            try:
                content = pkp_app.read_text(encoding="utf-8", errors="replace")
                m = re.search(r"MAJOR_VERSION\s*=\s*(\d+).*?MINOR_VERSION\s*=\s*(\d+).*?REVISION\s*=\s*(\d+)",
                              content, re.DOTALL)
                if m:
                    return f"{m.group(1)}.{m.group(2)}.{m.group(3)}"
            except OSError:
                pass
        return ""

    def _download_ojs_core(self, version: str) -> Path:
        """Descarga OJS desde GitHub releases PKP.
        Tags: ojs-3-3-0-17 -> archivo: ojs-3_3_0-17.tar.gz
        """
        # Convertir version X.Y.Z a formato del tag (X-Y-Z) y archivo (X_Y_Z)
        ver_parts = version.replace("-", ".").split(".")
        if len(ver_parts) < 3:
            self.log.append({"type": "error", "cms": "ojs",
                           "message": f"Version OJS no valida para descarga: {version}"})
            return None

        tag = "ojs-" + "-".join(ver_parts)
        archive_ver = "_".join(ver_parts)
        archive = f"ojs-{archive_ver}.tar.gz"

        cache_file = self._cache_dir / f"ojs-{archive_ver}.tar.gz"
        extract_to = self._cache_dir / f"ojs-{archive_ver}"

        if extract_to.exists() and (extract_to / "ojs" / "classes").exists():
            return extract_to / "ojs"

        url = OJS_DOWNLOAD_GH.format(tag=tag, archive=archive)
        self.progress_callback("status", f"Descargando OJS {version}...")

        try:
            if not cache_file.exists():
                resp = requests.get(url, timeout=TIMEOUT, stream=True, allow_redirects=True)
                if resp.status_code != 200:
                    self.log.append({"type": "error", "cms": "ojs",
                                   "message": f"HTTP {resp.status_code} descargando OJS {version}. Instalar manualmente desde pkp.sfu.ca"})
                    return None
                with open(str(cache_file), "wb") as f:
                    for chunk in resp.iter_content(chunk_size=65536):
                        f.write(chunk)

            extract_to.mkdir(parents=True, exist_ok=True)
            with tarfile.open(str(cache_file), "r:gz") as tar:
                tar.extractall(str(extract_to))

            ojs_dir = extract_to / "ojs"
            if ojs_dir.exists() and (ojs_dir / "classes").exists():
                return ojs_dir
            for d in extract_to.iterdir():
                if d.is_dir() and (d / "classes").exists() and (d / "lib").exists():
                    return d
            return extract_to
        except Exception as e:
            self.log.append({"type": "error", "cms": "ojs", "message": f"Error descargando OJS: {e}"})
            if cache_file.exists():
                try:
                    cache_file.unlink()
                except OSError:
                    pass
            return None

    # ─────────────────────────── Utilidades compartidas ───────────────────────────

    def _full_rebuild_dirs(self, site_root: Path, clean_root: Path, dirs: list, cms_key: str = "cms") -> int:
        """Full rebuild: elimina el directorio existente y copia el limpio.
        Mas agresivo que replace_core_files — garantiza que no queden archivos infectados
        que el malware haya AGREGADO al core (no solo modificado).
        """
        total_files = 0
        for dirname in dirs:
            # Caso especial: "." indica el propio directorio raiz (para plugins/themes)
            if dirname == ".":
                src_dir = clean_root
                dst_dir = site_root
            else:
                src_dir = clean_root / dirname
                dst_dir = site_root / dirname

            if not src_dir.exists():
                continue

            # Eliminar existente
            if dst_dir.exists() and dirname != ".":
                try:
                    shutil.rmtree(str(dst_dir))
                except (OSError, PermissionError) as e:
                    self.log.append({"type": "warning", "cms": cms_key,
                                   "message": f"No se pudo eliminar {dirname}: {e}"})
                    continue

            # Copiar limpio
            try:
                if dirname == ".":
                    # Copiar archivos individuales en lugar de reemplazar el dir raiz
                    copied = 0
                    for item in src_dir.iterdir():
                        if item.is_file():
                            try:
                                shutil.copy2(str(item), str(dst_dir / item.name))
                                copied += 1
                            except (OSError, PermissionError):
                                pass
                    total_files += copied
                else:
                    shutil.copytree(str(src_dir), str(dst_dir))
                    total_files += sum(1 for f in src_dir.rglob("*") if f.is_file())
            except (OSError, PermissionError, shutil.Error) as e:
                self.log.append({"type": "warning", "cms": cms_key,
                               "message": f"Error copiando {dirname}: {e}"})
        return total_files

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
