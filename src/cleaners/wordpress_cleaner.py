"""WordPressCleaner v2.6.6 — limpieza profunda y restauracion completa de WordPress.

Resuelve los problemas de la cadena wipe -> restore:
  1. Detecta version WP y tema activo ANTES del wipe (pre_wipe_detect)
  2. Post-wipe: limpia residuos no criticos, instala core limpio,
     instala tema activo, garantiza dirs de wp-content

Ejecutar:
  - pre_wipe_detect() ANTES de CMSFullWiper.wipe()
  - post_wipe_clean() DESPUES del wipe, ANTES del restorer general
"""
import os
import re
import shutil
import zipfile
import tempfile
from pathlib import Path
from typing import Callable

import requests

from ..config.settings import (
    SCAN_MODE_ONLY, CMS_DETECTION_MARKERS,
)

# Archivos WP raiz no criticos que deben eliminarse en limpieza profunda
_WP_ROOT_JUNK = frozenset([
    "error_log", "licence.txt", "license.txt", "readme.html",
    "xmlrpc.php.disabled", "wp-config-sample.php",
])

# Archivos no criticos en wp-content que deben eliminarse
_WPCONTENT_JUNK = frozenset([
    "maintenance.php", "hello.php", "error_log",
    "readme.md", "readme.txt", "readme.html",
])

# Archivos que NUNCA se eliminan
_NEVER_DELETE = frozenset([
    "wp-config.php", ".htaccess", "wp-config-sample.php",
])

# Subdirs obligatorios de wp-content que deben existir post-limpieza
_WPCONTENT_REQUIRED_DIRS = ["languages", "plugins", "themes", "uploads"]

# URLs API WordPress.org
_WP_CORE_DOWNLOAD = "https://downloads.wordpress.org/release/wordpress-{version}.zip"
_WP_THEME_API = "https://api.wordpress.org/themes/info/1.2/?action=theme_information&request[slug]={slug}"
_WP_VERSION_API = "https://api.wordpress.org/core/version-check/1.7/"

TIMEOUT = 90


class WordPressCleaner:
    """Limpieza profunda y restauracion completa de instalaciones WordPress."""

    def __init__(self, extract_dir: str, quarantine_dir: str,
                 clean_mode: str = "normal", backup_info=None,
                 progress_callback: Callable = None):
        self.extract_dir = Path(extract_dir)
        self.quarantine_dir = Path(quarantine_dir)
        self.clean_mode = clean_mode
        self.backup_info = backup_info
        self.progress_callback = progress_callback or (lambda *a: None)
        self.log: list[dict] = []
        self._cache_dir = Path(tempfile.gettempdir()) / "cpacleans_cache"
        self._cache_dir.mkdir(parents=True, exist_ok=True)

    # ─────────────────────────────────────────────────────────────
    # PRE-WIPE: detectar info antes de que el wiper borre todo
    # ─────────────────────────────────────────────────────────────

    def pre_wipe_detect(self) -> dict:
        """Detecta version WP, tema activo y plugins activos ANTES del wipe.

        v2.6.3 Bug #1: Prioriza lectura de BD sobre filesystem. La BD contiene
        el estado real de activacion; el filesystem solo refleja archivos presentes.

        Retorna dict con la info cacheada para usar en post_wipe_clean().
        """
        wp_roots = self._find_wp_roots()
        if not wp_roots:
            return {}

        info = {
            "wp_roots": [str(r) for r in wp_roots],
            "versions": {},
            "active_themes": {},
            "active_plugins": {},
        }

        # ── v2.6.3: Leer BD PRIMERO — es la fuente autoritativa ──
        if self.backup_info and hasattr(self.backup_info, "structure"):
            db_paths = self.backup_info.structure.get("databases", [])
            for db_path in db_paths:
                plugins, theme = self._read_wp_active_from_sql(db_path)
                for wp_root in wp_roots:
                    root_key = str(wp_root)
                    # BD tiene prioridad: sobreescribe cualquier valor previo
                    if theme:
                        info["active_themes"][root_key] = theme
                    if plugins:
                        info["active_plugins"].setdefault(root_key, set()).update(plugins)

        for wp_root in wp_roots:
            root_key = str(wp_root)

            # Version desde version.php (todavia existe pre-wipe)
            version = self._detect_wp_version(wp_root)
            if version:
                info["versions"][root_key] = version

            # v2.6.3: Filesystem como FALLBACK si BD no dio tema
            if root_key not in info["active_themes"]:
                active_theme = self._detect_active_theme_from_fs(wp_root)
                if active_theme:
                    info["active_themes"][root_key] = active_theme

        # Convertir sets a listas para serializar
        for k, v in info["active_plugins"].items():
            if isinstance(v, set):
                info["active_plugins"][k] = list(v)

        themes_found = list(info["active_themes"].values())
        plugins_total = sum(len(v) for v in info["active_plugins"].values())
        self.progress_callback("status",
            f"[WP] Pre-wipe: {len(wp_roots)} instalaciones, "
            f"versiones: {list(info['versions'].values())}, "
            f"tema: {themes_found}, plugins activos: {plugins_total}")

        return info

    def pre_wipe_separate_addons(self) -> list:
        """Mueve plugins y temas a quarantine/cms_components/ ANTES del wipe.

        v2.6.3 Bug #3: El orden correcto es:
          a) limpiar archivos de malware  (clean_findings — ya ejecutado)
          b) mover plugins+temas a cuarentena  ← ESTE METODO
          c) wipe del core
          d) instalar core + plugins + tema desde wordpress.org

        No ejecuta en SCAN_MODE_ONLY (no modifica nada).
        Retorna lista de addons movidos para el reporte.
        """
        if self.clean_mode == SCAN_MODE_ONLY:
            return []

        wp_roots = [str(r) for r in self._find_wp_roots()]
        if not wp_roots:
            return []

        from ..quarantine.manager import QuarantineManager
        qm = QuarantineManager(
            str(self.quarantine_dir),
            progress_callback=self.progress_callback,
        )
        return qm.move_wp_addons_to_quarantine(wp_roots)

    # ─────────────────────────────────────────────────────────────
    # POST-WIPE: limpieza profunda + instalacion core + tema
    # ─────────────────────────────────────────────────────────────

    def post_wipe_clean(self, wp_info: dict, do_install: bool = True) -> dict:
        """Ejecutar DESPUES del wipe. Usa info cacheada de pre_wipe_detect().

        v2.6.6 — `do_install=False` deja esta operacion en SOLO LIMPIEZA:
        garantiza dirs, limpia residuos y carpetas vacias, pero NO descarga ni
        instala core/plugins/temas. La reinstalacion es exclusiva de la fase 5.

        Orden de operaciones (con do_install=True):
        1. Garantizar dirs wp-content/{languages,plugins,themes,uploads}
        2. Descargar e instalar core WP limpio
        3. Instalar plugins activos disponibles en wordpress.org
        4. Instalar tema activo limpio desde wordpress.org
        5. Limpieza profunda de residuos no criticos (todos los modos)
        6. Limpiar carpetas vacias y residuos en wp-content

        Los plugins premium o no disponibles se registran como 'manual_required'.
        Retorna dict con stats de la operacion.
        """
        if self.clean_mode == SCAN_MODE_ONLY:
            return {"status": "scan_only", "cleaned": 0, "core_installed": False}

        stats = {
            "core_installed": False,
            "core_version": "",
            "theme_installed": False,
            "theme_slug": "",
            "plugins_installed": 0,
            "plugins_manual": 0,
            "cleaned_files": 0,
            "cleaned_empty_dirs": 0,
            "dirs_ensured": 0,
        }

        wp_roots = [Path(r) for r in wp_info.get("wp_roots", [])]
        if not wp_roots:
            wp_roots = self._find_wp_roots()

        # Preparar restorer de plugins (solo si se va a instalar)
        restorer = None
        if do_install:
            from ..restore.cms_restore import WPAddonRestorer
            restorer = WPAddonRestorer(
                clean_mode=self.clean_mode,
                cache_dir=str(self._cache_dir),
                progress_callback=self.progress_callback,
            )

        for wp_root in wp_roots:
            root_key = str(wp_root)

            # 1. Garantizar dirs wp-content
            ensured = self._ensure_wpcontent_dirs(wp_root)
            stats["dirs_ensured"] += ensured

            # 2-4. Instalacion de core/plugins/tema — SOLO si do_install (v2.6.6:
            # en fase 4 do_install=False; la reinstalacion vive en la fase 5)
            if do_install:
                # 2. Instalar core WP limpio
                version = wp_info.get("versions", {}).get(root_key, "")
                if not version:
                    version = self._detect_wp_version(wp_root)
                if not version:
                    version = self._get_latest_wp_version()

                if version:
                    installed = self._install_wp_core(wp_root, version)
                    if installed:
                        stats["core_installed"] = True
                        stats["core_version"] = version

                # 3. Instalar plugins activos desde wordpress.org
                active_plugins = wp_info.get("active_plugins", {}).get(root_key, [])
                if active_plugins:
                    plugin_result = restorer.install_active_plugins(wp_root, active_plugins)
                    stats["plugins_installed"] += len(plugin_result["installed"])
                    stats["plugins_manual"] += len(plugin_result["manual"])

                    # Registrar instalados en log
                    for p in plugin_result["installed"]:
                        self.log.append({
                            "type": "success", "cms": "wordpress",
                            "message": f"Plugin '{p['slug']}' v{p['version']} instalado desde wordpress.org",
                        })
                    # Registrar manuales en log (para seccion del reporte)
                    for p in plugin_result["manual"]:
                        self.log.append({
                            "type": "manual_required",
                            "cms": "wordpress",
                            "name": p["slug"],
                            "version": wp_info.get("_plugin_versions", {}).get(p["slug"], "desconocida"),
                            "reason": p["reason"],
                            "message": (
                                f"Plugin '{p['slug']}' requiere instalacion manual "
                                f"— {p['reason']}"
                            ),
                        })

                # 4. Instalar tema activo limpio
                theme_slug = wp_info.get("active_themes", {}).get(root_key, "")
                if theme_slug:
                    theme_ok = self._install_theme(wp_root, theme_slug)
                    if theme_ok:
                        stats["theme_installed"] = True
                        stats["theme_slug"] = theme_slug

            # 5. Limpieza profunda de residuos — todos los modos no-scan
            # Tambien limpia subdirectorios (no solo raiz de wp-content)
            cleaned = self._deep_clean_residuals(wp_root)
            stats["cleaned_files"] += cleaned

            # 6. Limpiar carpetas vacias y residuos en wp-content
            empty_cleaned = self._clean_empty_dirs(wp_root)
            stats["cleaned_empty_dirs"] += empty_cleaned

            # 7. Garantizar dirs wp-content de nuevo (por si la limpieza los borro)
            self._ensure_wpcontent_dirs(wp_root)

        self.progress_callback("status",
            f"[WP] Post-wipe: core={'OK' if stats['core_installed'] else 'N/A'} "
            f"v{stats['core_version']}, tema={stats['theme_slug'] or 'N/A'}, "
            f"plugins={stats['plugins_installed']} instalados "
            f"{stats['plugins_manual']} manuales, "
            f"residuos={stats['cleaned_files']}")

        return stats

    # ─────────────────────────────────────────────────────────────
    # Deteccion
    # ─────────────────────────────────────────────────────────────

    def _find_wp_roots(self) -> list[Path]:
        """Localiza raices WP en el extract_dir."""
        markers = CMS_DETECTION_MARKERS.get("wordpress")
        if not markers:
            return []
        roots = []
        for root, dirs, files in os.walk(self.extract_dir):
            if markers["file"] in files and markers["dir"] in dirs:
                roots.append(Path(root))
        return roots

    def _detect_wp_version(self, wp_root: Path) -> str:
        """Detecta version WP desde version.php."""
        version_file = wp_root / "wp-includes" / "version.php"
        if not version_file.exists():
            return ""
        try:
            content = version_file.read_text(encoding="utf-8", errors="replace")
            match = re.search(r"\$wp_version\s*=\s*['\"]([^'\"]+)['\"]", content)
            return match.group(1) if match else ""
        except OSError:
            return ""

    def _detect_active_theme_from_fs(self, wp_root: Path) -> str:
        """Detecta tema activo mirando cual tiene el style.css mas reciente."""
        themes_dir = wp_root / "wp-content" / "themes"
        if not themes_dir.exists():
            return ""
        best_slug = ""
        best_mtime = 0
        try:
            for theme_dir in themes_dir.iterdir():
                if not theme_dir.is_dir():
                    continue
                style = theme_dir / "style.css"
                if style.exists():
                    try:
                        mtime = style.stat().st_mtime
                        if mtime > best_mtime:
                            best_mtime = mtime
                            best_slug = theme_dir.name
                    except OSError:
                        pass
        except OSError:
            pass
        return best_slug

    def _read_wp_active_from_sql(self, sql_path: str) -> tuple:
        """Lee plugins y tema activo desde dump SQL."""
        active_plugins = set()
        active_theme = ""
        try:
            import gzip as _gzip
            if sql_path.endswith(".gz"):
                opener = lambda: _gzip.open(sql_path, "rt",
                                            encoding="utf-8", errors="replace")
            else:
                opener = lambda: open(sql_path, "r",
                                      encoding="utf-8", errors="replace")
            with opener() as f:
                for line in f:
                    if len(line) > 500_000:
                        continue
                    if "active_plugins" in line:
                        for m in re.finditer(
                                r'["\']([^"\']+/[^"\']+\.php)["\']', line):
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

    def _get_latest_wp_version(self) -> str:
        """Consulta api.wordpress.org para la version estable mas reciente."""
        try:
            resp = requests.get(_WP_VERSION_API, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                offers = data.get("offers", [])
                if offers:
                    return offers[0].get("version", "")
        except Exception:
            pass
        return ""

    # ─────────────────────────────────────────────────────────────
    # Instalacion core WP
    # ─────────────────────────────────────────────────────────────

    def _install_wp_core(self, wp_root: Path, version: str) -> bool:
        """Descarga WP core y lo instala en wp_root."""
        clean_dir = self._download_wp_core(version)
        if not clean_dir:
            return False

        self.progress_callback("status",
            f"[WP] Instalando core WordPress {version}...")

        # Copiar wp-admin/ y wp-includes/
        for core_dir in ["wp-admin", "wp-includes"]:
            src = clean_dir / core_dir
            dst = wp_root / core_dir
            if not src.exists():
                continue
            try:
                if dst.exists():
                    shutil.rmtree(str(dst))
                shutil.copytree(str(src), str(dst))
            except (OSError, PermissionError, shutil.Error) as e:
                self.log.append({"type": "error", "cms": "wordpress",
                                 "message": f"Error copiando {core_dir}: {e}"})

        # Copiar archivos PHP raiz (excepto wp-config.php)
        _skip_root = frozenset({
            "wp-config.php", "wp-config-sample.php",
            "readme.html", "license.txt", "licence.txt", ".maintenance",
        })
        root_copied = 0
        try:
            for item in clean_dir.iterdir():
                if not item.is_file():
                    continue
                if item.name.lower() in _skip_root:
                    continue
                try:
                    shutil.copy2(str(item), str(wp_root / item.name))
                    root_copied += 1
                except (OSError, PermissionError):
                    pass
        except OSError:
            pass

        self.log.append({
            "type": "success", "cms": "wordpress",
            "message": f"Core WP {version} instalado: wp-admin, wp-includes, "
                       f"{root_copied} archivos raiz"
        })
        return True

    def _download_wp_core(self, version: str) -> Path:
        """Descarga y extrae WP core. Retorna path al dir wordpress/."""
        cache_file = self._cache_dir / f"wordpress-{version}.zip"
        extract_to = self._cache_dir / f"wordpress-{version}"

        if extract_to.exists() and (extract_to / "wordpress" / "wp-includes").exists():
            return extract_to / "wordpress"

        url = _WP_CORE_DOWNLOAD.format(version=version)
        self.progress_callback("status", f"[WP] Descargando WordPress {version}...")

        try:
            if not cache_file.exists():
                resp = requests.get(url, timeout=TIMEOUT, stream=True)
                if resp.status_code != 200:
                    self.log.append({
                        "type": "error", "cms": "wordpress",
                        "message": f"HTTP {resp.status_code} descargando WP {version}"
                    })
                    return None
                with open(str(cache_file), "wb") as f:
                    for chunk in resp.iter_content(chunk_size=65536):
                        f.write(chunk)

            extract_to.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(str(cache_file), "r") as zf:
                zf.extractall(str(extract_to))
            return extract_to / "wordpress"
        except (requests.RequestException, zipfile.BadZipFile, OSError) as e:
            self.log.append({
                "type": "error", "cms": "wordpress",
                "message": f"Error descargando WP: {e}"
            })
            if cache_file.exists():
                try:
                    cache_file.unlink()
                except OSError:
                    pass
            return None

    # ─────────────────────────────────────────────────────────────
    # Instalacion de tema activo
    # ─────────────────────────────────────────────────────────────

    def _install_theme(self, wp_root: Path, theme_slug: str) -> bool:
        """Descarga e instala tema activo desde wordpress.org."""
        if not theme_slug:
            return False

        self.progress_callback("status",
            f"[WP] Descargando tema '{theme_slug}'...")

        try:
            resp = requests.get(
                _WP_THEME_API.format(slug=theme_slug), timeout=15)
            if resp.status_code != 200:
                self.log.append({
                    "type": "warning", "cms": "wordpress",
                    "message": f"Tema '{theme_slug}' no encontrado en wordpress.org "
                               f"(premium/custom)"
                })
                return False

            data = resp.json()
            if not isinstance(data, dict) or "download_link" not in data:
                self.log.append({
                    "type": "warning", "cms": "wordpress",
                    "message": f"Tema '{theme_slug}' sin enlace de descarga"
                })
                return False

            download_url = data["download_link"]
            version = data.get("version", "?")

            # Descargar zip
            cache_file = self._cache_dir / f"wp-theme-{theme_slug}.zip"
            extract_to = self._cache_dir / f"wp-theme-{theme_slug}"

            if not (extract_to.exists() and any(extract_to.iterdir())):
                if not cache_file.exists():
                    dl = requests.get(download_url, timeout=TIMEOUT, stream=True)
                    if dl.status_code != 200:
                        return False
                    with open(str(cache_file), "wb") as f:
                        for chunk in dl.iter_content(chunk_size=65536):
                            f.write(chunk)

                extract_to.mkdir(parents=True, exist_ok=True)
                with zipfile.ZipFile(str(cache_file), "r") as zf:
                    zf.extractall(str(extract_to))

            # Localizar dir del tema en el zip extraido
            theme_src = None
            for d in extract_to.iterdir():
                if d.is_dir():
                    theme_src = d
                    break
            if not theme_src:
                theme_src = extract_to

            # Instalar en wp-content/themes/
            themes_dir = wp_root / "wp-content" / "themes"
            themes_dir.mkdir(parents=True, exist_ok=True)
            dst = themes_dir / theme_slug

            if dst.exists():
                shutil.rmtree(str(dst))
            shutil.copytree(str(theme_src), str(dst))

            file_count = sum(1 for _ in dst.rglob("*") if _.is_file())
            self.log.append({
                "type": "success", "cms": "wordpress",
                "message": f"Tema '{theme_slug}' v{version} instalado: "
                           f"{file_count} archivos"
            })
            return True

        except (requests.RequestException, zipfile.BadZipFile, OSError) as e:
            self.log.append({
                "type": "warning", "cms": "wordpress",
                "message": f"Error instalando tema '{theme_slug}': {e}"
            })
            return False

    # ─────────────────────────────────────────────────────────────
    # Limpieza profunda de residuos
    # ─────────────────────────────────────────────────────────────

    def _deep_clean_residuals(self, wp_root: Path) -> int:
        """Elimina archivos no criticos que el wiper estandar no cubre.

        v2.6.3 Bug #2: Ampliado para limpiar _WPCONTENT_JUNK en TODOS los
        subdirectorios de wp-content (no solo en la raiz). Cubre casos como
        error_log, hello.php e index.php no-funcionales en cualquier subdirectorio.
        """
        cleaned = 0
        junk_dir = self.quarantine_dir / "wp_residuales"

        # 1. Archivos junk en raiz WP
        for item in self._safe_iterdir(wp_root):
            if not item.is_file():
                continue
            name_lower = item.name.lower()
            if name_lower in _WP_ROOT_JUNK:
                cleaned += self._remove_or_quarantine(item, junk_dir)

        # 2. Archivos junk en wp-content/ (raiz Y subdirectorios — v2.6.3)
        wpc = wp_root / "wp-content"
        if wpc.exists():
            # 2a. Raiz de wp-content: junk conocido + PHP no-funcionales
            for item in self._safe_iterdir(wpc):
                if not item.is_file():
                    continue
                name_lower = item.name.lower()
                if name_lower in _WPCONTENT_JUNK:
                    cleaned += self._remove_or_quarantine(item, junk_dir)
                elif name_lower.endswith(".php") and name_lower not in (
                        "index.php", "advanced-cache.php", "object-cache.php",
                        "db.php", "sunrise.php", "blog-deleted.php",
                        "blog-inactive.php", "blog-suspended.php",
                ):
                    # v2.6.2+2.6.3: Solo remover PHP sin codigo ejecutable
                    try:
                        from ..scanners.php_scanner import is_php_functional
                        php_content = item.read_text(encoding="utf-8", errors="replace")
                        if not is_php_functional(php_content):
                            cleaned += self._remove_or_quarantine(item, junk_dir)
                    except (OSError, ImportError):
                        pass

            # 2b. v2.6.3: subdirs de wp-content — junk conocido
            # v2.6.8 Bug #2: NO tocar plugins/ ni themes/ — los procesa por completo
            #  CMSPluginCleaner (separar + reinstalar). Aqui solo uploads, languages,
            #  cache, mu-plugins y carpetas no reconocidas.
            for dirpath, dirnames, filenames in os.walk(wpc):
                dp = Path(dirpath)
                if dp == wpc:
                    continue  # La raiz ya fue procesada en 2a
                try:
                    top_seg = dp.relative_to(wpc).parts[0].lower()
                except (ValueError, IndexError):
                    top_seg = ""
                if top_seg in ("plugins", "themes"):
                    continue  # gestionado por CMSPluginCleaner
                is_safe_htaccess_dir = any(
                    dp == wpc / d for d in ("uploads", "cache", "upgrade")
                )
                for fname in filenames:
                    fpath = dp / fname
                    fl = fname.lower()
                    # Junk conocido en cualquier subdir
                    if fl in _WPCONTENT_JUNK:
                        cleaned += self._remove_or_quarantine(fpath, junk_dir)
                    elif fl == ".htaccess" and not is_safe_htaccess_dir:
                        siblings = [f for f in filenames if f.lower() != ".htaccess"]
                        if not siblings and not dirnames:
                            cleaned += self._remove_or_quarantine(fpath, junk_dir)

        # 3. v2.6.4: index.php "silence is golden" en subdirectorios de wp-content
        # Los dirs obligatorios (plugins/, themes/, languages/, uploads/) NECESITAN
        # su propio index.php de proteccion; los demas subdirs no.
        _silence_pattern = re.compile(
            r'^\s*<\?php\s*\n?\s*//\s*Silence\s+is\s+golden\.?\s*$',
            re.IGNORECASE | re.DOTALL,
        )
        _protected_top = {wpc / d for d in _WPCONTENT_REQUIRED_DIRS}
        if wpc.exists():
            for dirpath, _dirs, filenames in os.walk(wpc):
                dp = Path(dirpath)
                if dp in _protected_top:
                    continue  # conservar index.php de proteccion en dirs obligatorios
                if "index.php" not in [f.lower() for f in filenames]:
                    continue
                fpath = dp / "index.php"
                try:
                    content = fpath.read_text(encoding="utf-8", errors="replace")
                    if _silence_pattern.match(content) or (
                        len(content.strip()) <= 50
                        and "silence" in content.lower()
                    ):
                        cleaned += self._remove_or_quarantine(fpath, junk_dir)
                except OSError:
                    pass

        # 4. error_log en raiz de wp-admin, wp-includes (post-restauracion)
        for core_dir in ["wp-admin", "wp-includes"]:
            elog = wp_root / core_dir / "error_log"
            if elog.exists():
                cleaned += self._remove_or_quarantine(elog, junk_dir)

        return cleaned

    def _clean_empty_dirs(self, wp_root: Path) -> int:
        """Elimina carpetas vacias o que solo contienen .htaccess/error_log."""
        cleaned = 0
        wpc = wp_root / "wp-content"
        if not wpc.exists():
            return 0

        # Recorrer bottom-up para que se limpien dirs anidados
        dirs_to_check = []
        for dirpath, dirnames, filenames in os.walk(wpc, topdown=False):
            dp = Path(dirpath)
            # No eliminar dirs obligatorios
            try:
                rel = dp.relative_to(wpc)
                if str(rel) in _WPCONTENT_REQUIRED_DIRS or dp == wpc:
                    continue
            except ValueError:
                continue
            dirs_to_check.append(dp)

        for dp in dirs_to_check:
            if not dp.exists():
                continue
            try:
                contents = list(dp.iterdir())
                # Dir vacio
                if not contents:
                    dp.rmdir()
                    cleaned += 1
                    continue
                # Dir con solo archivos residuales
                all_junk = all(
                    item.is_file() and item.name.lower() in
                    ("error_log", ".htaccess", "index.php", "index.html")
                    for item in contents
                )
                if all_junk and len(contents) <= 2:
                    # v2.6.2: Verificar que index.php no tiene codigo ejecutable real.
                    # Un index.php funcional (con codigo real) indica dir con contenido
                    # relevante — conservar. Un stub "silence is golden" → eliminar dir.
                    is_silence = True
                    for item in contents:
                        if item.name.lower() == "index.php":
                            try:
                                from ..scanners.php_scanner import is_php_functional
                                text = item.read_text(
                                    encoding="utf-8", errors="replace")
                                if is_php_functional(text):
                                    is_silence = False
                            except (OSError, ImportError):
                                pass
                    if is_silence:
                        shutil.rmtree(str(dp), ignore_errors=True)
                        cleaned += 1
            except (OSError, PermissionError):
                pass

        return cleaned

    # ─────────────────────────────────────────────────────────────
    # Garantizar dirs wp-content
    # ─────────────────────────────────────────────────────────────

    def _ensure_wpcontent_dirs(self, wp_root: Path) -> int:
        """Crea languages/, plugins/, themes/, uploads/ si no existen.
        Tambien crea un index.php vacio de proteccion en cada uno.
        """
        wpc = wp_root / "wp-content"
        wpc.mkdir(parents=True, exist_ok=True)
        created = 0

        # index.php en wp-content si no existe
        wpc_index = wpc / "index.php"
        if not wpc_index.exists():
            try:
                wpc_index.write_text(
                    "<?php\n// Silence is golden.\n",
                    encoding="utf-8")
            except OSError:
                pass

        for dirname in _WPCONTENT_REQUIRED_DIRS:
            d = wpc / dirname
            if not d.exists():
                try:
                    d.mkdir(parents=True, exist_ok=True)
                    # Crear index.php proteccion
                    idx = d / "index.php"
                    idx.write_text(
                        "<?php\n// Silence is golden.\n",
                        encoding="utf-8")
                    created += 1
                except OSError:
                    pass

        return created

    # ─────────────────────────────────────────────────────────────
    # Utilidades
    # ─────────────────────────────────────────────────────────────

    def _remove_or_quarantine(self, file_path: Path, junk_dir: Path) -> int:
        """Mueve a cuarentena en modo normal/intermediate, elimina en strict."""
        if self.clean_mode == SCAN_MODE_ONLY:
            return 0
        try:
            if self.clean_mode == "strict":
                file_path.unlink()
            else:
                junk_dir.mkdir(parents=True, exist_ok=True)
                dest = junk_dir / file_path.name
                counter = 0
                while dest.exists():
                    counter += 1
                    dest = junk_dir / f"{file_path.stem}_{counter}{file_path.suffix}"
                shutil.move(str(file_path), str(dest))
            return 1
        except (OSError, PermissionError, shutil.Error):
            return 0

    @staticmethod
    def _safe_iterdir(path: Path):
        """iterdir con proteccion contra errores de permisos."""
        try:
            yield from path.iterdir()
        except (OSError, PermissionError):
            return
