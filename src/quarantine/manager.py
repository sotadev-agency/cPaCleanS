"""QuarantineManager v2.6.6 — estructura unificada de cuarentena.

Resuelve Bug #2 (v2.6.2): elimina la duplicacion entre plugins_temas y
plugins_temas_separados unificando todo en cms_components/{cms}/{type}/.
Resuelve Bug #3 (v2.6.2): aislamiento de backups antes del escaneo.

Estructura cuarentena_TIMESTAMP/:
  originales_intactos/   — copias antes de limpiar (engine.clean_findings)
  amenazas_removidas/    — archivos de malware movidos
  archivos_0kb/          — archivos vacios (engine.clean_zero_byte_files)
  cms_components/        — plugins/temas por CMS (CMSPluginCleaner)
    {cms}/
      plugins/ | themes/ | components/ | modules/ | ...
  backups/               — backups aislados pre-escaneo (Bug #3)
    homedir/             — softaculous_backups, cpanelbackups
    wp_uploads/          — UpdraftPlus, BackWPup, Duplicator, etc.
    wp_backup_files/     — archivos .zip/.tar.gz dentro de dirs de backup
  archivos_residuales/   — junk (JunkCleaner)
  wp_residuales/         — residuos WP (WordPressCleaner)
"""
import os
import re
import shutil
from pathlib import Path
from typing import Callable


# Nombres exactos de dirs en homedir cPanel que son almacenamiento de backups cPanel
_HOMEDIR_BACKUP_DIRS = frozenset([
    "softaculous_backups",
    "cpanelbackups",
])

# Patrones de nombre de dirs de backup de plugins WP (en uploads/ o wp-content/ raiz)
_WP_BACKUP_DIR_PATTERNS = [
    re.compile(r'^updraftplus$', re.IGNORECASE),
    re.compile(r'^backwpup', re.IGNORECASE),
    re.compile(r'^duplicator(?:-pro)?$', re.IGNORECASE),
    re.compile(r'^wp-clone$', re.IGNORECASE),
    re.compile(r'^all-in-one-wp-migration$', re.IGNORECASE),
    re.compile(r'^backups?$', re.IGNORECASE),
    re.compile(r'^(?:site|db|full)[_-]?backup', re.IGNORECASE),
    re.compile(r'^wp.+backup', re.IGNORECASE),
]

# Extensiones de archivos de backup (se aíslan si están dentro de dirs de backup)
_BACKUP_FILE_EXTS = frozenset([".zip", ".tar", ".tgz"])


class QuarantineManager:
    """Gestor centralizado de la estructura de cuarentena v2.6.2.

    Uso:
        qm = QuarantineManager(quarantine_dir, progress_callback)
        qm.setup()                              # crea dirs base
        path = qm.cms_component_dir("wordpress", "plugins")  # cms_components/wordpress/plugins/
        log  = qm.isolate_backups(extract_dir)  # aísla backups pre-scan
    """

    FIXED_DIRS = [
        "originales_intactos",
        "amenazas_removidas",
        "archivos_0kb",
        "cms_components",
        "backups",
        "archivos_residuales",
        "wp_residuales",
    ]

    def __init__(self, quarantine_dir: str,
                 progress_callback: Callable = None):
        self.root = Path(quarantine_dir)
        self.progress_callback = progress_callback or (lambda *a: None)

    # ─────────────────────────────── Estructura ───────────────────────────────

    def setup(self):
        """Crea la estructura de directorios base. Idempotente."""
        self.root.mkdir(parents=True, exist_ok=True)
        for d in self.FIXED_DIRS:
            (self.root / d).mkdir(parents=True, exist_ok=True)

    def cms_component_dir(self, cms: str, component_type: str) -> Path:
        """Retorna (y crea si necesario) cms_components/{cms}/{component_type}/.

        Args:
            cms: 'wordpress', 'joomla', 'moodle', 'ojs', etc.
            component_type: 'plugins', 'themes', 'components', 'modules', etc.
        """
        d = self.root / "cms_components" / cms / component_type
        d.mkdir(parents=True, exist_ok=True)
        return d

    def backups_dir(self, subdir: str = "") -> Path:
        """Retorna (y crea) backups/{subdir}/ dentro de la cuarentena."""
        d = (self.root / "backups" / subdir) if subdir else (self.root / "backups")
        d.mkdir(parents=True, exist_ok=True)
        return d

    # ─────────────────────────────── Backup Isolation ─────────────────────────

    def isolate_backups(self, extract_dir: str) -> list:
        """Mueve dirs y archivos de backup a quarantine/backups/ ANTES del escaneo.

        Los backups del usuario no son malware. Aislarlos pre-scan evita:
        - Que el scanner PHP procese archivos .zip de backup (costoso e innecesario)
        - Que aparezcan como amenazas en el reporte
        - Que sean eliminados por el cleaner principal

        Detecta:
        1. softaculous_backups/, cpanelbackups/ en homedir cPanel
        2. UpdraftPlus, BackWPup, Duplicator, etc. en wp-content/uploads/
        3. Archivos .zip/.tar.gz dentro de dirs de backup en wp-content

        Retorna lista de dicts con {path, name, type, action} para el reporte.
        """
        log = []
        extract = Path(extract_dir)

        # ── 1. Homedir cPanel: dirs conocidos de backup ──
        homedir = self._find_homedir(extract)
        if homedir:
            for item in self._safe_iterdir(homedir):
                if item.name.lower() in _HOMEDIR_BACKUP_DIRS:
                    dest = self.backups_dir("homedir")
                    if self._move_item(item, dest):
                        log.append({
                            "path": self._rel(item, extract),
                            "name": item.name,
                            "type": "homedir_backup",
                            "action": "aislado",
                        })
                        self.progress_callback("status",
                            f"[BACKUP] Aislado: {item.name} (cPanel backup)")

        # ── 2. WordPress wp-content: dirs de plugins de backup ──
        for wp_root in self._find_wp_roots(extract):
            wpc = wp_root / "wp-content"
            if not wpc.exists():
                continue

            # 2a. uploads/: UpdraftPlus, BackWPup, Duplicator, wp-clone, etc.
            uploads = wpc / "uploads"
            if uploads.exists():
                for item in self._safe_iterdir(uploads):
                    if item.is_dir() and self._is_backup_dir_name(item.name):
                        dest = self.backups_dir("wp_uploads")
                        if self._move_item(item, dest):
                            log.append({
                                "path": self._rel(item, extract),
                                "name": item.name,
                                "type": "wp_backup_dir",
                                "action": "aislado",
                            })
                            self.progress_callback("status",
                                f"[BACKUP] Aislado: uploads/{item.name}")

            # 2b. Archivos .zip/.tar.gz dentro de rutas de backup conocidas
            try:
                for fp in wpc.rglob("*"):
                    if not fp.is_file():
                        continue
                    name_lower = fp.name.lower()
                    is_backup_ext = (
                        name_lower.endswith(".tar.gz") or
                        name_lower.endswith(".tgz") or
                        fp.suffix.lower() in _BACKUP_FILE_EXTS
                    )
                    if not is_backup_ext:
                        continue
                    # Solo aislar si la ruta pasa por un dir de backup conocido
                    try:
                        rel_parts = list(fp.relative_to(wpc).parts[:-1])
                    except ValueError:
                        continue
                    if any(self._is_backup_dir_name(p) for p in rel_parts):
                        dest = self.backups_dir("wp_backup_files")
                        if self._move_item(fp, dest):
                            log.append({
                                "path": self._rel(fp, extract),
                                "name": fp.name,
                                "type": "wp_backup_file",
                                "action": "aislado",
                            })
            except (OSError, PermissionError):
                pass

        if log:
            self.progress_callback("status",
                f"[BACKUP] {len(log)} elementos aislados en quarantine/backups/")

        return log

    # ─────────────────── CMS Addon Separation (v2.6.3) ───────────────────────

    def move_wp_addons_to_quarantine(self, wp_roots: list) -> list:
        """Mueve plugins y temas de todas las instalaciones WP a cms_components/.

        v2.6.3: Los addons se separan ANTES del wipe+restore para:
        - Preservar una copia original (incluso si ya fue limpiada de malware)
        - Poder auditar que plugins son premium (necesitan instalacion manual)
        - Dejar plugins/ y themes/ vacios para que post_wipe_clean instale versiones limpias

        Args:
            wp_roots: Lista de rutas (str o Path) a raices WordPress.

        Returns:
            Lista de dicts {slug, addon_type, version, action} por addon movido.
        """
        log = []
        for wp_root in wp_roots:
            wpc = Path(wp_root) / "wp-content"
            domain_label = self._domain_label(Path(wp_root))
            for addon_type in ("plugins", "themes"):
                src_dir = wpc / addon_type
                if not src_dir.exists():
                    continue
                # v2.6.6 Mejora #5: nombrar la carpeta con el dominio de origen.
                # plugins -> plugins_<dominio>, themes -> theme_<dominio> (singular).
                base = "plugins" if addon_type == "plugins" else "theme"
                folder = f"{base}_{domain_label}"
                dest_dir = self.root / "cms_components" / "wordpress" / folder
                dest_dir.mkdir(parents=True, exist_ok=True)
                for item in self._safe_iterdir(src_dir):
                    if not item.is_dir():
                        continue
                    # Leer version antes de mover
                    version = self._get_addon_version(item, addon_type)
                    if self._move_item(item, dest_dir):
                        log.append({
                            "slug": item.name,
                            "addon_type": addon_type[:-1],  # "plugin" o "theme"
                            "version": version,
                            "domain": domain_label,
                            "quarantine_folder": folder,
                            "action": "moved_pre_wipe",
                        })
        if log:
            plugins_n = sum(1 for e in log if e["addon_type"] == "plugin")
            themes_n = sum(1 for e in log if e["addon_type"] == "theme")
            self.progress_callback("status",
                f"[CMS] Pre-wipe: {plugins_n} plugins y {themes_n} temas "
                f"movidos a cms_components/wordpress/")
        return log

    @staticmethod
    def _domain_label(wp_root: Path) -> str:
        """v2.6.6: Deriva una etiqueta de dominio desde la ruta de la instalacion WP.

        Ejemplos:
          .../homedir/public_html            -> "public_html"
          .../homedir/domains/dominio.com/.. -> "dominio_com"
          .../sub.dominio.com/public_html    -> "sub_dominio_com"
        """
        parts = list(wp_root.parts)
        # 1) Preferir un segmento con forma de dominio (contiene un punto)
        for seg in reversed(parts):
            low = seg.lower()
            if low in ("public_html", "www", "htdocs", "wp-content"):
                continue
            if "." in seg and not seg.startswith("."):
                return seg.replace(".", "_").lower()
        # 2) Carpeta web estandar
        for seg in reversed(parts):
            if seg.lower() in ("public_html", "www", "htdocs"):
                return seg.lower()
        # 3) Fallback: ultimo segmento significativo
        return (parts[-1].lower() if parts else "sitio").replace(".", "_")

    @staticmethod
    def _get_addon_version(addon_dir: Path, addon_type: str) -> str:
        """Lee la version de un plugin o tema desde su archivo principal.

        Plugins: busca 'Version: x.y.z' en archivos PHP del directorio.
        Temas: busca 'Version: x.y.z' en style.css.
        """
        if addon_type == "themes":
            style = addon_dir / "style.css"
            if style.exists():
                try:
                    content = style.read_text(encoding="utf-8", errors="replace")[:2048]
                    m = re.search(r'^Version:\s*(.+)$', content,
                                  re.MULTILINE | re.IGNORECASE)
                    if m:
                        return m.group(1).strip()[:30]
                except OSError:
                    pass
        else:
            # Plugins: intentar archivo con nombre del directorio primero
            try:
                for php_file in addon_dir.glob("*.php"):
                    try:
                        content = php_file.read_text(
                            encoding="utf-8", errors="replace")[:4096]
                        m = re.search(r'^\s*\*?\s*Version:\s*(.+)$', content,
                                      re.MULTILINE | re.IGNORECASE)
                        if m:
                            return m.group(1).strip()[:30]
                    except OSError:
                        continue
            except OSError:
                pass
        return "desconocida"

    # ─────────────────────────────── Helpers ──────────────────────────────────

    @staticmethod
    def _is_backup_dir_name(name: str) -> bool:
        """True si el nombre del directorio coincide con un patron de backup conocido."""
        return any(p.search(name) for p in _WP_BACKUP_DIR_PATTERNS)

    def _find_homedir(self, extract: Path) -> Path:
        """Localiza el directorio homedir dentro del extract."""
        if (extract / "homedir").is_dir():
            return extract / "homedir"
        for d in self._safe_iterdir(extract):
            if d.is_dir() and (d / "homedir").is_dir():
                return d / "homedir"
        return None

    def _find_wp_roots(self, extract: Path) -> list:
        """Localiza raices WordPress (contienen wp-config.php y wp-includes/)."""
        roots = []
        try:
            for root, dirs, files in os.walk(str(extract)):
                if "wp-config.php" in files and "wp-includes" in dirs:
                    roots.append(Path(root))
        except (OSError, PermissionError):
            pass
        return roots

    def _move_item(self, src: Path, dest_dir: Path) -> bool:
        """Mueve src a dest_dir/. Maneja colisiones de nombre. Retorna True si exitoso."""
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / src.name
        counter = 0
        while dest.exists():
            counter += 1
            if src.is_file():
                stem = src.stem
                # Manejar doble extension: .tar.gz
                if stem.endswith(".tar"):
                    stem = stem[:-4]
                    suffix = ".tar.gz"
                else:
                    suffix = src.suffix
                dest = dest_dir / f"{stem}_{counter}{suffix}"
            else:
                dest = dest_dir / f"{src.name}_{counter}"
        try:
            shutil.move(str(src), str(dest))
            return True
        except (OSError, PermissionError, shutil.Error):
            return False

    @staticmethod
    def _safe_iterdir(path: Path):
        """Itera sobre path.iterdir() ignorando errores de permisos."""
        try:
            yield from path.iterdir()
        except (OSError, PermissionError):
            return

    @staticmethod
    def _rel(path: Path, base: Path) -> str:
        """Ruta relativa de path respecto a base, o ruta absoluta si falla."""
        try:
            return str(path.relative_to(base))
        except ValueError:
            return str(path)
