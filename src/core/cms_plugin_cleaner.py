"""Separador de plugins y temas de CMS — v2.2.3.

Plugins y temas son el vector de infeccion #1 en backups comprometidos.
Este módulo los extrae o elimina según el modo de limpieza para que el
usuario los reinstale desde repositorios oficiales del CMS.

Comportamiento por modo:
  Normal / Intermedio : mueve a cuarentena/plugins_temas/ (excluidos del .tar.gz final)
  Estricto            : elimina completamente, sin respaldo
"""
import os
import re
import shutil
from pathlib import Path
from typing import Callable


# Rutas de extensiones por CMS — (tipo, ruta_relativa_a_raiz_cms)
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

# Marcadores para ubicar la raiz de cada CMS
_CMS_ROOT_MARKERS = {
    "wordpress": ("wp-config.php",   "wp-includes"),
    "joomla":    ("configuration.php", "administrator"),
    "moodle":    ("config.php",       "lib"),
    "ojs":       ("config.inc.php",   "lib"),
}


# ── Detección de versión por tipo de extensión ──────────────────────────────

def _version_wp_plugin(plugin_dir: Path) -> str:
    """Lee la Version del comentario de cabecera del plugin principal."""
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


# ── Clase principal ──────────────────────────────────────────────────────────

class CMSPluginCleaner:
    """Separa o elimina todos los plugins/temas de los CMS detectados.

    Genera un log detallado (name, version, original_path, action) que el
    usuario puede usar como lista de reinstalación desde repos oficiales.
    """

    def __init__(self, extract_dir: str, quarantine_dir: str, clean_mode: str,
                 progress_callback: Callable = None):
        self.extract_dir  = Path(extract_dir)
        self.quarantine_dir = Path(quarantine_dir)
        self.clean_mode   = clean_mode
        self.progress_callback = progress_callback or (lambda *a: None)
        self.removal_log: list[dict] = []

    # ── API pública ──────────────────────────────────────────────────────────

    def process(self, cms_detected: list) -> dict:
        """Procesa todos los CMS detectados. Retorna conteos por CMS."""
        dest_base = self.quarantine_dir / "plugins_temas"
        dest_base.mkdir(parents=True, exist_ok=True)

        counts = {"total": 0, "by_cms": {}}
        for cms in cms_detected:
            if cms in CMS_ADDON_PATHS:
                n = self._process_cms(cms, dest_base)
                counts["by_cms"][cms] = n
                counts["total"] += n

        if self.removal_log:
            self._write_reinstall_guide(dest_base)

        return counts

    # ── Lógica interna ───────────────────────────────────────────────────────

    def _process_cms(self, cms: str, dest_base: Path) -> int:
        roots = self._find_cms_roots(cms)
        count = 0
        for root in roots:
            for addon_type, rel_path in CMS_ADDON_PATHS[cms]:
                addon_dir = root
                for segment in rel_path.split("/"):
                    addon_dir = addon_dir / segment
                if addon_dir.exists():
                    count += self._process_addon_dir(cms, addon_type, addon_dir, dest_base)
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
                           addon_dir: Path, dest_base: Path) -> int:
        try:
            items = [p for p in addon_dir.iterdir() if p.is_dir()]
        except (OSError, PermissionError):
            return 0

        count = 0
        detector = _VERSION_DETECTORS.get(cms, {}).get(addon_type)

        for item in items:
            version = detector(item) if detector else ""
            entry = {
                "cms":           cms,
                "type":          addon_type,
                "name":          item.name,
                "version":       version or "desconocida",
                "original_path": str(item),
            }
            self.progress_callback("status", f"[{cms.upper()}] {addon_type}: {item.name}...")

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
                dest = dest_dir / item.name
                if dest.exists():
                    dest = dest_dir / f"{item.name}_dup"
                try:
                    shutil.move(str(item), str(dest))
                    entry["action"] = "cuarentena"
                    entry["quarantine_path"] = str(dest)
                    count += 1
                except (OSError, PermissionError, shutil.Error) as e:
                    entry["action"] = f"error: {e}"

            self.removal_log.append(entry)

        return count

    def _write_reinstall_guide(self, dest_base: Path):
        """Escribe REINSTALAR_PLUGINS.txt en la carpeta de cuarentena."""
        lines = [
            "=== cPacleanS — Plugins y Temas Removidos ===",
            "",
            "IMPORTANTE: Reinstalar SOLO desde repositorios oficiales del CMS.",
            "No reutilizar los archivos originales — pueden contener malware.",
            "",
        ]

        by_cms: dict[str, list] = {}
        for e in self.removal_log:
            by_cms.setdefault(e["cms"], []).append(e)

        for cms, entries in by_cms.items():
            lines.append(f"=== {cms.upper()} ===")
            for e in entries:
                ver = f" v{e['version']}" if e["version"] != "desconocida" else ""
                lines.append(f"  [{e['type']}] {e['name']}{ver}  ->  {e['action']}")
                if cms == "wordpress":
                    if e["type"] == "plugin":
                        lines.append(f"         Repo: https://wordpress.org/plugins/{e['name']}/")
                    elif e["type"] == "theme":
                        lines.append(f"         Repo: https://wordpress.org/themes/{e['name']}/")
            lines.append("")

        guide_path = dest_base / "REINSTALAR_PLUGINS.txt"
        try:
            guide_path.write_text("\n".join(lines), encoding="utf-8")
        except (OSError, PermissionError):
            pass
