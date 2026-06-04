"""Separador de plugins y temas de CMS — v2.3.0.

Flujo por modo (Normal, Intermedio, Estricto):
  1. Leer BD del CMS -> detectar prefijo real -> identificar plugins/temas ACTIVOS
  2. Mover TODOS los plugins/temas a cuarentena (Normal/Intermedio) o eliminar (Estricto)
  3. Descargar desde repo oficial SOLO los que estan activos segun BD
  4. Instalar version limpia en la copia de trabajo
"""
import os
import re
import json
import shutil
import zipfile
import tempfile
from pathlib import Path
from typing import Callable

import requests

from ..utils.db_utils import (
    detect_prefix_from_config, detect_prefix_from_dump, read_active_from_dump,
)

TIMEOUT = 60

WP_PLUGIN_API = "https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]={slug}"
WP_THEME_API = "https://api.wordpress.org/themes/info/1.2/?action=theme_information&request[slug]={slug}"

CMS_ADDON_PATHS = {
    "wordpress": [
        ("plugin", "wp-content/plugins"),
        ("theme",  "wp-content/themes"),
    ],
    "joomla": [
        ("component", "components"),
        ("module",    "modules"),
        ("plugin",    "plugins"),
        ("template",  "templates"),
    ],
    "moodle": [
        ("mod",    "mod"),
        ("theme",  "theme"),
        ("local",  "local"),
        ("block",  "blocks"),
    ],
    "ojs": [
        ("plugin",     "plugins"),
        ("pkp_plugin", "lib/pkp/plugins"),
    ],
}

_CMS_ROOT_MARKERS = {
    "wordpress": ("wp-config.php",   "wp-includes"),
    "joomla":    ("configuration.php", "administrator"),
    "moodle":    ("config.php",       "lib"),
    "ojs":       ("config.inc.php",   "lib"),
}


# -- Deteccion de version por tipo de extension --

def _version_wp_plugin(plugin_dir: Path) -> str:
    candidates = [plugin_dir / f"{plugin_dir.name}.php"]
    candidates += list(plugin_dir.glob("*.php"))
    for f in candidates:
        if not f.exists():
            continue
        try:
            snippet = f.read_text(encoding="utf-8", errors="replace")[:4096]
            m = re.search(r"^(?:Version|Plugin Version)\s*:\s*([0-9][^\r\n,;]*)",
                          snippet, re.IGNORECASE | re.MULTILINE)
            if m:
                return m.group(1).strip()
        except OSError:
            pass
    return ""


def _version_wp_theme(theme_dir: Path) -> str:
    style = theme_dir / "style.css"
    if not style.exists():
        return ""
    try:
        snippet = style.read_text(encoding="utf-8", errors="replace")[:3072]
        m = re.search(r"^Version\s*:\s*([0-9][^\r\n,;]*)", snippet,
                      re.IGNORECASE | re.MULTILINE)
        return m.group(1).strip() if m else ""
    except OSError:
        return ""


def _version_joomla_ext(ext_dir: Path) -> str:
    for xml_file in ext_dir.glob("*.xml"):
        try:
            content = xml_file.read_text(encoding="utf-8", errors="replace")[:4096]
            m = re.search(r"<version>\s*([^<\s]+)\s*</version>", content)
            if m:
                return m.group(1).strip()
        except OSError:
            pass
    return ""


def _version_moodle_mod(mod_dir: Path) -> str:
    ver_file = mod_dir / "version.php"
    if not ver_file.exists():
        return ""
    try:
        content = ver_file.read_text(encoding="utf-8", errors="replace")[:2048]
        m = re.search(r"\$release\s*=\s*['\"]([^'\"]+)['\"]", content, re.IGNORECASE)
        if m:
            return m.group(1).strip()
        m = re.search(r"\$version\s*=\s*([0-9]{8,})", content)
        if m:
            return m.group(1)
    except OSError:
        pass
    return ""


def _version_ojs_plugin(plugin_dir: Path) -> str:
    ver_file = plugin_dir / "version.xml"
    if not ver_file.exists():
        return ""
    try:
        content = ver_file.read_text(encoding="utf-8", errors="replace")[:2048]
        m = re.search(r"<release>\s*([^<\s]+)\s*</release>", content)
        return m.group(1).strip() if m else ""
    except OSError:
        return ""


_VERSION_DETECTORS = {
    "wordpress": {"plugin": _version_wp_plugin, "theme": _version_wp_theme},
    "joomla":    {t: _version_joomla_ext for t in ("component", "module", "plugin", "template")},
    "moodle":    {t: _version_moodle_mod for t in ("mod", "theme", "local", "block")},
    "ojs":       {"plugin": _version_ojs_plugin, "pkp_plugin": _version_ojs_plugin},
}


class CMSPluginCleaner:
    """Separa o elimina todos los plugins/temas de los CMS detectados,
    luego reinstala desde repos oficiales SOLO los que estaban activos."""

    def __init__(self, extract_dir: str, quarantine_dir: str, clean_mode: str,
                 progress_callback: Callable = None,
                 db_paths: list = None):
        self.extract_dir  = Path(extract_dir)
        self.quarantine_dir = Path(quarantine_dir)
        self.clean_mode   = clean_mode
        self.progress_callback = progress_callback or (lambda *a: None)
        self.db_paths = db_paths or []
        self.removal_log: list[dict] = []
        self._cache_dir = Path(tempfile.gettempdir()) / "cpacleans_cache"
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._detected_prefixes: dict[str, str] = {}

    # -- API publica --

    def process(self, cms_detected: list) -> dict:
        """Procesa todos los CMS detectados. Retorna conteos por CMS."""
        dest_base = self.quarantine_dir / "plugins_temas"
        dest_base.mkdir(parents=True, exist_ok=True)

        counts = {"total": 0, "by_cms": {}}
        for cms in cms_detected:
            if cms not in CMS_ADDON_PATHS:
                continue

            roots = self._find_cms_roots(cms)
            if not roots:
                continue

            active = self._detect_active_addons(cms, roots)
            n = self._process_cms(cms, dest_base, roots, active)
            counts["by_cms"][cms] = n
            counts["total"] += n

        if self.removal_log:
            self._write_reinstall_guide(dest_base)

        return counts

    def get_detected_prefixes(self) -> dict:
        return self._detected_prefixes.copy()

    # -- Deteccion de activos desde BD --

    def _detect_active_addons(self, cms: str, roots: list) -> dict:
        """Lee la BD para identificar plugins/temas ACTIVOS."""
        active = {"plugins": set(), "theme": "", "templates": set(), "components": set()}

        for root in roots:
            prefix = detect_prefix_from_config(cms, str(root))
            if prefix:
                self._detected_prefixes[cms] = prefix
                self.progress_callback("status",
                    f"[{cms.upper()}] Prefijo detectado desde config: {prefix}")
                break

        if cms not in self._detected_prefixes:
            for db_path in self.db_paths:
                prefix = detect_prefix_from_dump(db_path, cms)
                if prefix:
                    self._detected_prefixes[cms] = prefix
                    self.progress_callback("status",
                        f"[{cms.upper()}] Prefijo detectado desde dump: {prefix}")
                    break

        prefix = self._detected_prefixes.get(cms, "")
        if not prefix:
            self.progress_callback("status",
                f"[{cms.upper()}] Prefijo no detectado, usando default")
            return active

        for db_path in self.db_paths:
            try:
                result = read_active_from_dump(db_path, cms, prefix)
                active["plugins"].update(result.get("plugins", set()))
                if result.get("theme") and not active["theme"]:
                    active["theme"] = result["theme"]
                active["templates"].update(result.get("templates", set()))
                active["components"].update(result.get("components", set()))
            except Exception:
                pass

        total_active = len(active["plugins"]) + (1 if active["theme"] else 0)
        if total_active:
            self.progress_callback("status",
                f"[{cms.upper()}] {total_active} extensiones activas detectadas en BD")

        return active

    # -- Procesamiento de CMS --

    def _process_cms(self, cms: str, dest_base: Path, roots: list, active: dict) -> int:
        count = 0
        for root in roots:
            for addon_type, rel_path in CMS_ADDON_PATHS[cms]:
                addon_dir = root
                for segment in rel_path.split("/"):
                    addon_dir = addon_dir / segment
                if addon_dir.exists():
                    count += self._process_addon_dir(cms, addon_type, addon_dir,
                                                      dest_base, active)
        return count

    def _find_cms_roots(self, cms: str) -> list:
        if cms not in _CMS_ROOT_MARKERS:
            return []
        required_file, required_dir = _CMS_ROOT_MARKERS[cms]
        roots = []
        for root, dirs, files in os.walk(self.extract_dir):
            if required_file in files and required_dir in dirs:
                rp = Path(root)
                if cms == "moodle" and not (rp / "lib" / "moodlelib.php").exists():
                    continue
                if cms == "ojs" and not (rp / "lib" / "pkp").exists():
                    continue
                roots.append(rp)
        return roots

    def _process_addon_dir(self, cms: str, addon_type: str,
                           addon_dir: Path, dest_base: Path, active: dict) -> int:
        try:
            items = [p for p in addon_dir.iterdir() if p.is_dir()]
        except (OSError, PermissionError):
            return 0

        count = 0
        detector = _VERSION_DETECTORS.get(cms, {}).get(addon_type)

        is_active_set = self._get_active_set(cms, addon_type, active)

        for item in items:
            version = detector(item) if detector else ""
            slug = item.name
            is_active = slug in is_active_set if is_active_set else True

            entry = {
                "cms":           cms,
                "type":          addon_type,
                "name":          slug,
                "version":       version or "desconocida",
                "original_path": str(item),
                "is_active":     is_active,
            }
            self.progress_callback("status", f"[{cms.upper()}] {addon_type}: {slug}...")

            # Paso 2: Mover TODO a cuarentena o eliminar
            if self.clean_mode == "strict":
                try:
                    shutil.rmtree(str(item))
                    entry["action"] = "eliminado"
                    count += 1
                except (OSError, PermissionError, shutil.Error) as e:
                    entry["action"] = f"error: {e}"
            else:
                dest_dir = dest_base / cms / addon_type
                dest_dir.mkdir(parents=True, exist_ok=True)
                dest = dest_dir / slug
                if dest.exists():
                    dest = dest_dir / f"{slug}_dup"
                try:
                    shutil.move(str(item), str(dest))
                    entry["action"] = "cuarentena"
                    entry["quarantine_path"] = str(dest)
                    count += 1
                except (OSError, PermissionError, shutil.Error) as e:
                    entry["action"] = f"error: {e}"

            self.removal_log.append(entry)

            # Paso 3-4: Reinstalar activos desde repo oficial
            if is_active and entry.get("action") in ("cuarentena", "eliminado"):
                reinstalled = self._reinstall_from_repo(cms, addon_type, slug,
                                                         addon_dir, version)
                entry["reinstalled"] = reinstalled
                if reinstalled:
                    entry["reinstalled_version"] = reinstalled.get("version", "")

        return count

    def _get_active_set(self, cms: str, addon_type: str, active: dict) -> set:
        """Retorna el set de slugs activos para un tipo de addon."""
        if cms == "wordpress":
            if addon_type == "plugin":
                return active.get("plugins", set())
            elif addon_type == "theme":
                t = active.get("theme", "")
                return {t} if t else set()
        elif cms == "joomla":
            if addon_type == "plugin":
                return active.get("plugins", set())
            elif addon_type == "template":
                return active.get("templates", set())
            elif addon_type == "component":
                return active.get("components", set())
        elif cms == "moodle":
            return active.get("plugins", set())
        elif cms == "ojs":
            return active.get("plugins", set())
        return set()

    # -- Reinstalacion desde repos oficiales --

    def _reinstall_from_repo(self, cms: str, addon_type: str, slug: str,
                              addon_dir: Path, original_version: str) -> dict:
        """Descarga e instala version limpia desde repo oficial. Solo WordPress soportado."""
        if cms == "wordpress":
            return self._reinstall_wp(addon_type, slug, addon_dir, original_version)

        entry = {"slug": slug, "status": "manual_required",
                 "reason": f"No hay API de descarga automatica para {cms.upper()}"}
        self.progress_callback("status",
            f"[{cms.upper()}] {slug}: reinstalacion manual requerida")
        return entry

    def _reinstall_wp(self, addon_type: str, slug: str, addon_dir: Path,
                       original_version: str) -> dict:
        """Descarga plugin/tema de WordPress.org e instala en la ruta original."""
        if addon_type == "plugin":
            api_url = WP_PLUGIN_API.format(slug=slug)
        elif addon_type == "theme":
            api_url = WP_THEME_API.format(slug=slug)
        else:
            return {}

        try:
            resp = requests.get(api_url, timeout=15)
            if resp.status_code != 200:
                self.progress_callback("status",
                    f"[WP] {slug}: no encontrado en WordPress.org (premium/custom)")
                return {"slug": slug, "status": "not_in_repo"}

            data = resp.json()
            if not isinstance(data, dict) or "download_link" not in data:
                return {"slug": slug, "status": "not_in_repo"}

            download_url = data["download_link"]
            repo_version = data.get("version", "?")

            self.progress_callback("status",
                f"[WP] Descargando {slug} v{repo_version}...")

            clean_dir = self._download_and_extract_zip(slug, download_url, addon_type)
            if not clean_dir:
                return {"slug": slug, "status": "download_failed"}

            target = addon_dir / slug
            target.mkdir(parents=True, exist_ok=True)

            copied = 0
            for src_file in clean_dir.rglob("*"):
                if src_file.is_file():
                    rel = src_file.relative_to(clean_dir)
                    dst = target / rel
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    try:
                        shutil.copy2(str(src_file), str(dst))
                        copied += 1
                    except (OSError, PermissionError):
                        pass

            self.progress_callback("status",
                f"[WP] {slug}: reinstalado ({copied} archivos, {original_version} -> {repo_version})")

            return {
                "slug": slug,
                "status": "reinstalled",
                "version": repo_version,
                "original_version": original_version,
                "files": copied,
            }

        except (requests.RequestException, json.JSONDecodeError, ValueError) as e:
            self.progress_callback("status", f"[WP] {slug}: error descargando — {e}")
            return {"slug": slug, "status": "error", "error": str(e)}

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

    # -- Guia de reinstalacion --

    def _write_reinstall_guide(self, dest_base: Path):
        lines = [
            "=== cPacleanS v2.3.0 — Plugins y Temas Removidos ===",
            "",
            "IMPORTANTE: Reinstalar SOLO desde repositorios oficiales del CMS.",
            "No reutilizar los archivos originales — pueden contener malware.",
            "",
        ]

        by_cms: dict[str, list] = {}
        for e in self.removal_log:
            by_cms.setdefault(e["cms"], []).append(e)

        for cms, entries in by_cms.items():
            prefix = self._detected_prefixes.get(cms, "")
            lines.append(f"=== {cms.upper()} (prefijo: {prefix or 'N/A'}) ===")
            lines.append("")

            active = [e for e in entries if e.get("is_active")]
            inactive = [e for e in entries if not e.get("is_active")]

            if active:
                lines.append("  --- ACTIVOS (reinstalados desde repo oficial) ---")
                for e in active:
                    ver = f" v{e['version']}" if e["version"] != "desconocida" else ""
                    ri = e.get("reinstalled", {})
                    if ri and ri.get("status") == "reinstalled":
                        new_ver = ri.get("version", "?")
                        lines.append(f"  [OK] [{e['type']}] {e['name']}{ver} -> v{new_ver} (reinstalado)")
                    elif ri and ri.get("status") == "not_in_repo":
                        lines.append(f"  [!] [{e['type']}] {e['name']}{ver} -> NO en repo oficial (reinstalar manual)")
                        if cms == "wordpress":
                            if e["type"] == "plugin":
                                lines.append(f"         Buscar: https://wordpress.org/plugins/{e['name']}/")
                            elif e["type"] == "theme":
                                lines.append(f"         Buscar: https://wordpress.org/themes/{e['name']}/")
                    elif ri and ri.get("status") == "manual_required":
                        lines.append(f"  [!] [{e['type']}] {e['name']}{ver} -> reinstalacion manual requerida")
                    else:
                        lines.append(f"  [{e['type']}] {e['name']}{ver} -> {e.get('action', '?')}")
                lines.append("")

            if inactive:
                lines.append("  --- INACTIVOS (removidos, no reinstalados) ---")
                for e in inactive:
                    ver = f" v{e['version']}" if e["version"] != "desconocida" else ""
                    lines.append(f"  [-] [{e['type']}] {e['name']}{ver} -> {e.get('action', '?')}")
                lines.append("")

        guide_path = dest_base / "REINSTALAR_PLUGINS.txt"
        try:
            guide_path.write_text("\n".join(lines), encoding="utf-8")
        except (OSError, PermissionError):
            pass
