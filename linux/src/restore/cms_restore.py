"""WPAddonRestorer v2.6.3 — instala plugins y temas activos desde WordPress.org post-wipe.

Resuelve Bug #1 (v2.6.3): lee active_plugins y template desde wp_options en el dump SQL
y los instala desde wordpress.org; registra los premium/no disponibles como manuales.

Responsabilidades:
  - Leer active_plugins y template desde dump SQL (prioridad sobre filesystem)
  - Descargar e instalar cada plugin desde api.wordpress.org/plugins
  - Registrar los plugins no disponibles (premium/cerrados) para instalacion manual

No modifica el sistema de archivos en SCAN_MODE_ONLY.
"""
import re
import gzip
import shutil
import zipfile
import tempfile
from pathlib import Path
from typing import Callable

import requests

from ..config.settings import SCAN_MODE_ONLY

# ── API endpoints WordPress.org ──
_WP_PLUGIN_API = (
    "https://api.wordpress.org/plugins/info/1.2/"
    "?action=plugin_information&request[slug]={slug}&request[fields][download_link]=1"
)
_WP_THEME_API = (
    "https://api.wordpress.org/themes/info/1.2/"
    "?action=theme_information&request[slug]={slug}"
)

# Limite de plugins a instalar automaticamente por instalacion WP
_MAX_AUTO_PLUGINS = 35
# Timeout de descarga por plugin
_DOWNLOAD_TIMEOUT = 90


class WPAddonRestorer:
    """Instala plugins y temas activos de WordPress desde repositorios oficiales.

    Uso tipico:
        restorer = WPAddonRestorer(clean_mode, cache_dir, progress_callback)
        result = restorer.install_active_plugins(wp_root, active_slugs)
        # result = {"installed": [...], "manual": [...]}
    """

    def __init__(self, clean_mode: str = "normal",
                 cache_dir: str = None,
                 progress_callback: Callable = None):
        self.clean_mode = clean_mode
        self.progress_callback = progress_callback or (lambda *a: None)
        self._cache_dir = Path(cache_dir) if cache_dir else (
            Path(tempfile.gettempdir()) / "cpacleans_cache"
        )
        self._cache_dir.mkdir(parents=True, exist_ok=True)

    # ─────────────────────────────── Lectura desde BD ─────────────────────────

    def read_active_from_db(self, db_paths: list) -> dict:
        """Lee active_plugins y template desde dumps SQL.

        v2.6.3: Prioriza BD sobre deteccion de filesystem — mas fiable ya que
        la BD contiene el estado real de activacion, no solo los archivos presentes.

        Returns:
            {
                "active_plugins": ["contact-form-7", "woocommerce", ...],
                "active_theme": "twentytwenty",
            }
        """
        active_plugins: set = set()
        active_theme = ""

        for db_path in db_paths:
            try:
                plugins, theme = self._parse_wp_options(db_path)
                active_plugins.update(plugins)
                if theme and not active_theme:
                    active_theme = theme
            except Exception:
                pass

        return {
            "active_plugins": sorted(active_plugins),
            "active_theme": active_theme,
        }

    def _parse_wp_options(self, db_path: str) -> tuple:
        """Parsea active_plugins y template desde un dump SQL."""
        active_plugins: set = set()
        active_theme = ""

        try:
            if db_path.endswith(".gz"):
                opener = lambda: gzip.open(db_path, "rt",
                                           encoding="utf-8", errors="replace")
            else:
                opener = lambda: open(db_path, "r",
                                      encoding="utf-8", errors="replace")

            with opener() as f:
                for line in f:
                    if len(line) > 500_000:
                        continue

                    # active_plugins: serialized PHP array con "slug/file.php"
                    if "active_plugins" in line:
                        for m in re.finditer(
                                r'["\']([a-zA-Z0-9_\-]+/[^"\']+\.php)["\']', line):
                            slug = m.group(1).split("/")[0].strip().lower()
                            if slug and len(slug) <= 80:
                                active_plugins.add(slug)

                    # template: nombre del tema activo
                    if not active_theme:
                        if "'template'" in line or '"template"' in line:
                            m = re.search(r"'template'\s*,\s*'([^']+)'", line)
                            if not m:
                                m = re.search(r'"template"\s*,\s*"([^"]+)"', line)
                            if m:
                                active_theme = m.group(1).strip()

        except Exception:
            pass

        return active_plugins, active_theme

    # ─────────────────────────────── Instalacion de plugins ───────────────────

    def install_active_plugins(self, wp_root: Path, active_slugs: list) -> dict:
        """Descarga e instala plugins activos desde wordpress.org.

        Los plugins no disponibles (premium, cerrados, errores) se omiten
        y se registran como "manual_required" para el reporte.

        Args:
            wp_root: Raiz de instalacion WordPress
            active_slugs: Lista de slugs de plugins activos (e.g. ["contact-form-7", ...])

        Returns:
            {
                "installed": [{"slug": ..., "version": ...}, ...],
                "manual":    [{"slug": ..., "reason": ...}, ...],
            }
        """
        if self.clean_mode == SCAN_MODE_ONLY:
            return {"installed": [], "manual": []}

        installed = []
        manual = []

        # Limitar para evitar tiempos excesivos
        slugs_to_try = [s for s in active_slugs if s][:_MAX_AUTO_PLUGINS]

        self.progress_callback("status",
            f"[WP] Instalando {len(slugs_to_try)} plugins activos desde wordpress.org...")

        for slug in slugs_to_try:
            slug = slug.strip().lower()
            if not slug or not re.match(r'^[a-zA-Z0-9_\-]+$', slug):
                continue

            self.progress_callback("status", f"[WP] Plugin: {slug}...")
            result = self._install_one_plugin(wp_root, slug)

            if isinstance(result, dict):
                installed.append(result)
            else:
                # result es el motivo del fallo
                manual.append({"slug": slug, "reason": result})

        n_installed = len(installed)
        n_manual = len(manual)
        self.progress_callback("status",
            f"[WP] Plugins: {n_installed} instalados, "
            f"{n_manual} requieren instalacion manual")

        return {"installed": installed, "manual": manual}

    def _install_one_plugin(self, wp_root: Path, slug: str):
        """Instala un plugin desde WP.org.

        Returns:
            dict {"slug": ..., "version": ...} si exitoso
            str  motivo del fallo si no disponible
        """
        try:
            # Consultar API para obtener download_link
            resp = requests.get(
                _WP_PLUGIN_API.format(slug=slug),
                timeout=15,
            )
            if resp.status_code != 200:
                return "error HTTP al consultar WP.org"

            data = resp.json()
            if not data or data.get("error") or not data.get("download_link"):
                return "no disponible en wordpress.org (posiblemente premium o cerrado)"

            download_url = data["download_link"]
            version = str(data.get("version", "?"))

            # Descargar + extraer (con cache para re-runs)
            plugin_dir = self._download_and_extract_plugin(slug, version, download_url)
            if not plugin_dir:
                return "error al descargar o extraer"

            # Instalar en wp-content/plugins/
            plugins_dir = wp_root / "wp-content" / "plugins"
            plugins_dir.mkdir(parents=True, exist_ok=True)
            dst = plugins_dir / slug

            if dst.exists():
                shutil.rmtree(str(dst), ignore_errors=True)
            shutil.copytree(str(plugin_dir), str(dst))

            file_count = sum(1 for _ in dst.rglob("*") if _.is_file())
            self.progress_callback("status",
                f"[WP] Plugin '{slug}' v{version} instalado ({file_count} archivos)")

            return {"slug": slug, "version": version}

        except (requests.RequestException, zipfile.BadZipFile,
                OSError, shutil.Error) as e:
            return f"error: {e}"

    def _download_and_extract_plugin(self, slug: str, version: str,
                                     download_url: str) -> Path:
        """Descarga y extrae el zip del plugin. Usa cache si disponible.

        Returns:
            Path al directorio del plugin (slug/) dentro del zip extraido.
            None si falla.
        """
        cache_zip = self._cache_dir / f"wp-plugin-{slug}-{version}.zip"
        cache_dir = self._cache_dir / f"wp-plugin-{slug}-{version}"

        # Usar cache si ya fue extraido
        if cache_dir.exists() and any(cache_dir.iterdir()):
            extracted = self._locate_plugin_dir(cache_dir, slug)
            if extracted:
                return extracted

        # v2.6.8: lista de URLs — link de la API + fallback directo de WP.org
        urls = []
        if download_url:
            urls.append(download_url)
        urls.append(f"https://downloads.wordpress.org/plugin/{slug}.zip")
        urls.append(f"https://downloads.wordpress.org/plugin/{slug}.{version}.zip")

        for try_url in urls:
            try:
                if cache_zip.exists():
                    try:
                        cache_zip.unlink()
                    except OSError:
                        pass
                dl = requests.get(try_url, timeout=_DOWNLOAD_TIMEOUT, stream=True)
                if dl.status_code != 200:
                    continue
                with open(str(cache_zip), "wb") as f:
                    for chunk in dl.iter_content(chunk_size=65536):
                        f.write(chunk)

                if cache_dir.exists():
                    shutil.rmtree(str(cache_dir), ignore_errors=True)
                cache_dir.mkdir(parents=True, exist_ok=True)
                with zipfile.ZipFile(str(cache_zip), "r") as zf:
                    zf.extractall(str(cache_dir))

                located = self._locate_plugin_dir(cache_dir, slug)
                if located and any(located.rglob("*")):
                    return located
            except (requests.RequestException, zipfile.BadZipFile, OSError):
                continue
        return None

    @staticmethod
    def _locate_plugin_dir(extract_dir: Path, slug: str) -> Path:
        """Localiza el directorio del plugin dentro del zip extraido.

        Los zips de WP.org extraen a {slug}/ directamente.
        """
        # Primero intentar con el slug exacto
        exact = extract_dir / slug
        if exact.is_dir():
            return exact
        # Cualquier subdirectorio
        for d in extract_dir.iterdir():
            if d.is_dir():
                return d
        return None
