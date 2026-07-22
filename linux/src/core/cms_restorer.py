"""Restaurador de CMS — descarga core limpio y hace rebuild completo.

v2.6.6: Fase 5 reinstala TODOS los plugins instalados (activos + inactivos), leyendo
los slugs de las carpetas separadas pre-wipe en cuarentena; identificacion de activos
movida aqui; usa la version detectada pre-wipe para instalar el core.

v2.6.5: Bug fix en _restore_wp_plugins/_restore_wp_themes — distingue "no en WP.org"
de "falló la descarga"; reintentar con cache limpio antes de reportar error.

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
    "wp-config-sample.php",
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
    def __init__(self, extract_dir: str, progress_callback: Callable = None,
                 quarantine_dir: str = None, wp_versions: dict = None):
        self.extract_dir = Path(extract_dir)
        self.progress_callback = progress_callback or (lambda *a: None)
        self.log = []
        self._cache_dir = Path(tempfile.gettempdir()) / "cpacleans_cache"
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        # v2.6.6: cuarentena (para leer plugins separados pre-wipe) y versiones
        # detectadas pre-wipe (version.php se borra en el wipe).
        self.quarantine_dir = Path(quarantine_dir) if quarantine_dir else None
        self.wp_versions = wp_versions or {}

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
        """Rebuild completo: instala core limpio y reinstala TODOS los plugins/temas.

        v2.6.6:
          - Mejora #4: la identificacion de plugins/tema activos ocurre AQUI (fase 5),
            no en fase 4.
          - Bug #1: reinstala TODOS los plugins instalados (activos e inactivos),
            no solo los activos. El set se construye uniendo los activos de la BD con
            los slugs de las carpetas separadas pre-wipe en cuarentena.
          - El core se instala con la version detectada pre-wipe (version.php ya fue
            borrado por el wipe).
        """
        self.progress_callback("status", "Restaurando WordPress (rebuild completo)...")
        wp_roots = self._find_wp_roots()
        if not wp_roots:
            self.log.append({"type": "warning", "cms": "wordpress", "message": "No se encontro instalacion de WordPress"})
            return

        # ── Mejora #4: detectar plugins/tema activos desde los dumps SQL (fase 5) ──
        active_plugins = set()
        active_theme = ""
        if backup_info and backup_info.structure.get("databases"):
            for db_path in backup_info.structure["databases"]:
                ap, at = self._read_wp_active_from_sql(db_path)
                active_plugins.update(ap)
                if at:
                    active_theme = at

        # ── Bug #1: TODOS los plugins instalados (activos + inactivos) ──
        # Los plugins separados pre-wipe estan en cuarentena; sus nombres de carpeta
        # son el conjunto real de plugins instalados en el sitio.
        quarantined = self._gather_quarantined_slugs("plugins")
        all_plugins = set(active_plugins) | quarantined
        quarantined_themes = self._gather_quarantined_slugs("theme")

        if all_plugins:
            self.log.append({"type": "info", "cms": "wordpress",
                "message": f"Plugins a reinstalar: {len(all_plugins)} "
                           f"({len(active_plugins)} activos en BD, {len(quarantined)} en cuarentena)"})

        for wp_root in wp_roots:
            # v2.6.6: version pre-wipe (version.php fue borrado por el wipe)
            version = self.wp_versions.get(str(wp_root)) or self._detect_wp_version(wp_root)
            if not version:
                version = self._get_latest_wp_version()
            if not version:
                self.log.append({"type": "warning", "cms": "wordpress", "message": f"Version WP no detectada en {wp_root.name}"})
                continue

            self.log.append({"type": "info", "cms": "wordpress", "message": f"WordPress {version} en {wp_root.name}"})
            clean_dir = self._download_wp_core(version)
            if not clean_dir:
                # Fallback: intentar con la última versión estable de WordPress.org
                latest = self._get_latest_wp_version()
                if latest and latest != version:
                    self.log.append({"type": "warning", "cms": "wordpress",
                        "message": f"No se pudo descargar WP {version}; usando última estable {latest}"})
                    clean_dir = self._download_wp_core(latest)
                if not clean_dir:
                    self.log.append({"type": "error", "cms": "wordpress",
                        "message": f"No se pudo descargar el core limpio de WordPress.org — "
                                   f"core NO reemplazado en {wp_root.name}"})
                    continue

            # ── v3.0.3: REEMPLAZO TOTAL del core (no sobreescritura) ──
            # Se elimina TODO el core de WordPress en la raíz (wp-admin, wp-includes,
            # todos los .php raíz y cualquier archivo/carpeta que no sea contenido de
            # usuario) y se instala íntegro el core limpio descargado de WordPress.org.
            # Se conserva ÚNICAMENTE wp-content/, wp-config.php (+ .htaccess/.user.ini).
            # I/O tolerante a rutas largas de Windows (prefijo \\?\) para que ningún
            # archivo profundo (p.ej. wp-includes/php-ai-client/...) quede sin reponer.
            removed, copied = self._replace_wp_core(wp_root, clean_dir)
            self.log.append({"type": "success", "cms": "wordpress",
                "message": f"Core REEMPLAZADO por versión limpia de WordPress.org: "
                           f"{removed} elementos antiguos eliminados, {copied} archivos limpios instalados"})

            # ── Reinstalar TODOS los plugins y el/los tema(s) desde WordPress.org ──
            installed_plugins = self._restore_wp_plugins(wp_root, all_plugins) or set()
            theme_set = set(quarantined_themes)
            if active_theme:
                theme_set.add(active_theme)
            installed_themes = self._restore_wp_themes(wp_root, theme_set, active_theme) or set()

            # ── v3.2 Bug #3: garantizar que el sitio nunca quede sin tema.
            #    Si el tema activo era premium/no estaba en WP.org y no se pudo
            #    reinstalar, se copia el tema por defecto incluido en el core limpio. ──
            default_theme = self._ensure_default_theme(wp_root, clean_dir, active_theme)
            if default_theme:
                installed_themes.add(default_theme)

            # ── v3.0.2 Issue #5: el resultado final SOLO debe contener addons
            #    reinstalados desde el repositorio oficial. Cualquier carpeta antigua
            #    de plugin/tema que haya sobrevivido al wipe (p.ej. por rutas largas
            #    en Windows) se elimina para no dejar versiones posiblemente infectadas. ──
            self._enforce_repo_addons(wp_root, installed_plugins, installed_themes)

    def _gather_quarantined_slugs(self, base: str) -> set:
        """v2.6.6: Lee los slugs de las carpetas separadas pre-wipe en cuarentena.

        base: 'plugins' o 'theme' (prefijo de las carpetas cms_components/wordpress/).
        Estructura: cms_components/wordpress/{base}_<dominio>/<slug>/.
        """
        slugs = set()
        if not self.quarantine_dir:
            return slugs
        cms_base = self.quarantine_dir / "cms_components" / "wordpress"
        if not cms_base.exists():
            return slugs
        try:
            for folder in cms_base.iterdir():
                if not folder.is_dir():
                    continue
                fname = folder.name.lower()
                # plugins_<dominio> / theme_<dominio>; tambien acepta legacy plugins/themes
                if fname == base or fname.startswith(f"{base}_") or (
                        base == "theme" and (fname == "themes" or fname.startswith("themes_"))):
                    for item in folder.iterdir():
                        if item.is_dir():
                            slugs.add(item.name)
        except (OSError, PermissionError):
            pass
        return slugs

    def _get_latest_wp_version(self) -> str:
        """v2.6.6: ultima version estable de WordPress (fallback de core)."""
        try:
            resp = requests.get(
                "https://api.wordpress.org/core/version-check/1.7/", timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                offers = data.get("offers", [])
                if offers and isinstance(offers, list):
                    return offers[0].get("current", "")
        except (requests.RequestException, json.JSONDecodeError, ValueError, KeyError):
            pass
        return ""

    def _enforce_repo_addons(self, wp_root: Path, allowed_plugins: set, allowed_themes: set):
        """v3.0.2 Issue #5: garantiza que wp-content/plugins y wp-content/themes
        contengan ÚNICAMENTE los addons reinstalados desde el repositorio oficial.

        Cualquier carpeta de plugin/tema que sobreviviera al wipe (p.ej. porque el
        move/rmtree falló por rutas largas en Windows) y NO esté en el set reinstalado
        se mueve a cuarentena (o se elimina) — evita dejar versiones antiguas que
        pueden estar infectadas. Aplica en todos los modos salvo solo-escaneo (esta
        función solo se invoca durante la restauración, que no corre en scan-only)."""
        mapping = [("plugins", {s.lower() for s in (allowed_plugins or set())}),
                   ("themes", {s.lower() for s in (allowed_themes or set())})]
        for sub, allowed_lower in mapping:
            d = wp_root / "wp-content" / sub
            if not d.exists():
                continue
            try:
                entries = [x for x in d.iterdir() if x.is_dir()]
            except (OSError, PermissionError):
                continue
            for item in entries:
                if item.name.lower() in allowed_lower:
                    continue  # recién instalado desde repo → conservar
                # superviviente antiguo no reinstalable → remover por seguridad
                moved = self._quarantine_old_addon(item, sub)
                self.log.append({
                    "type": "warning", "cms": "wordpress",
                    "message": (
                        f"{'Plugin' if sub == 'plugins' else 'Tema'} '{item.name}' no se "
                        f"reinstaló desde repositorio oficial; "
                        f"{'movido a cuarentena' if moved else 'eliminado'} del resultado "
                        f"(posible versión antigua/infectada — reinstalar manualmente)"),
                })

    def _quarantine_old_addon(self, addon_dir: Path, sub: str) -> bool:
        """Mueve un addon antiguo a cuarentena (cms_components/wordpress/eliminados_no_repo/)
        o lo elimina si no hay cuarentena. Robusto ante rutas largas en Windows.
        Retorna True si se preservó en cuarentena, False si solo se eliminó/borró."""
        if self.quarantine_dir:
            dest_base = (self.quarantine_dir / "cms_components" / "wordpress"
                         / "eliminados_no_repo" / sub)
            try:
                dest_base.mkdir(parents=True, exist_ok=True)
                dest = dest_base / addon_dir.name
                counter = 0
                while dest.exists():
                    counter += 1
                    dest = dest_base / f"{addon_dir.name}_{counter}"
                shutil.move(str(addon_dir), str(dest))
                return True
            except (OSError, PermissionError, shutil.Error):
                # fallback: eliminar (robusto ante rutas largas en Windows)
                pass
        self._robust_rmtree(addon_dir)
        return False

    # ───────────────── I/O tolerante a rutas largas en Windows ─────────────────

    @staticmethod
    def _winlong(p) -> str:
        """Devuelve la ruta absoluta con prefijo \\\\?\\ en Windows (elimina el
        límite de 260 chars). En otros SO devuelve la ruta absoluta normal."""
        ap = os.path.abspath(str(p))
        if os.name == "nt" and not ap.startswith("\\\\?\\"):
            if ap.startswith("\\\\"):           # ruta UNC
                return "\\\\?\\UNC\\" + ap[2:]
            return "\\\\?\\" + ap
        return ap

    @classmethod
    def _robust_rmtree(cls, path):
        """rmtree tolerante a rutas largas (prefijo \\\\?\\). Reintenta sin prefijo."""
        shutil.rmtree(cls._winlong(path), ignore_errors=True)
        if Path(path).exists():
            shutil.rmtree(str(path), ignore_errors=True)

    @classmethod
    def _robust_unlink(cls, path):
        """Elimina un archivo tolerando rutas largas."""
        for target in (cls._winlong(path), str(path)):
            try:
                os.remove(target)
                return
            except FileNotFoundError:
                return
            except (OSError, PermissionError):
                continue

    @classmethod
    def _robust_copytree(cls, src, dst) -> int:
        """Copia recursiva tolerante a rutas largas (recorre y escribe con prefijo
        \\\\?\\ para alcanzar archivos profundos). Retorna nº de archivos copiados."""
        count = 0
        src_long = cls._winlong(src)
        for root, _dirs, files in os.walk(src_long):
            rel = os.path.relpath(root, src_long)
            target_dir = Path(dst) if rel == "." else Path(dst) / rel
            try:
                os.makedirs(cls._winlong(target_dir), exist_ok=True)
            except (OSError, PermissionError):
                pass
            for f in files:
                s = os.path.join(root, f)
                d = cls._winlong(Path(target_dir) / f)
                try:
                    shutil.copy2(s, d)
                    count += 1
                except (OSError, PermissionError, shutil.Error):
                    pass
        return count

    @classmethod
    def _robust_copy(cls, src, dst) -> bool:
        """Copia un archivo tolerando rutas largas, creando el directorio padre."""
        try:
            os.makedirs(cls._winlong(Path(dst).parent), exist_ok=True)
            shutil.copy2(cls._winlong(src), cls._winlong(dst))
            return True
        except (OSError, PermissionError, shutil.Error):
            return False

    @staticmethod
    def _safe_iter(path: Path):
        try:
            yield from path.iterdir()
        except (OSError, PermissionError):
            return

    # Contenido de usuario / config que se PRESERVA al reemplazar el core.
    # El zip oficial de WordPress no incluye estos, así que nunca se pisan;
    # se listan para no eliminarlos al limpiar la raíz.
    _CORE_PRESERVE = frozenset({"wp-content", "wp-config.php", ".htaccess", ".user.ini"})

    def _replace_wp_core(self, wp_root: Path, clean_dir: Path) -> tuple:
        """v3.0.3: Reemplaza por completo el core de WordPress.

        1) Elimina TODO en la raíz salvo wp-content/, wp-config.php, .htaccess y
           .user.ini (el core NO se sobreescribe archivo a archivo: se borra entero).
        2) Copia el core limpio descargado de WordPress.org (wp-admin, wp-includes,
           todos los .php raíz). El wp-content del zip NO se copia para no pisar el
           contenido del usuario; solo se repone su scaffold (index.php + languages/).

        Retorna (elementos_eliminados, archivos_copiados).
        """
        removed = 0
        # 1) Limpiar la raíz (todo lo que no sea contenido de usuario)
        for item in self._safe_iter(wp_root):
            if item.name.lower() in self._CORE_PRESERVE:
                continue
            try:
                if item.is_dir() and not item.is_symlink():
                    self._robust_rmtree(item)
                else:
                    self._robust_unlink(item)
                removed += 1
            except (OSError, PermissionError):
                pass

        # 2) Instalar el core limpio íntegro (salvo wp-content del zip)
        copied = 0
        for item in self._safe_iter(clean_dir):
            if item.name.lower() == "wp-content":
                continue  # no pisar contenido de usuario
            dst = wp_root / item.name
            if item.is_dir():
                copied += self._robust_copytree(item, dst)
            else:
                if self._robust_copy(item, dst):
                    copied += 1

        # 3) Reponer scaffold de wp-content (index.php de protección + languages/)
        copied += self._restore_wpcontent_scaffold(wp_root, clean_dir)
        return removed, copied

    def _restore_wpcontent_scaffold(self, wp_root: Path, clean_root: Path) -> int:
        """v3.2+: repone archivos y directorios core de wp-content que el wipe elimina
        y el rebuild de wp-admin/wp-includes no repone.
        Incluye: index.php de protección, directorio languages/ del core."""
        count = 0
        wp_content = wp_root / "wp-content"
        clean_wpc = clean_root / "wp-content"
        if not clean_wpc.exists():
            return 0

        # Archivos de protección individuales (silence is golden)
        targets = [
            (clean_wpc / "index.php", wp_content / "index.php"),
            (clean_wpc / "plugins" / "index.php", wp_content / "plugins" / "index.php"),
            (clean_wpc / "themes" / "index.php", wp_content / "themes" / "index.php"),
            (clean_wpc / "upgrade" / "index.php", wp_content / "upgrade" / "index.php"),
        ]
        for src, dst in targets:
            if not src.exists():
                continue
            try:
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(str(src), str(dst))  # sobreescribir siempre
                count += 1
            except (OSError, PermissionError):
                pass

        # Restaurar directorio core languages/ (traducciones del sistema WordPress)
        src_lang = clean_wpc / "languages"
        dst_lang = wp_content / "languages"
        if src_lang.exists():
            try:
                if not dst_lang.exists():
                    shutil.copytree(str(src_lang), str(dst_lang))
                    count += sum(1 for f in src_lang.rglob("*") if f.is_file())
                else:
                    # Solo copiar archivos core del paquete limpio que falten
                    for src_f in src_lang.rglob("*"):
                        if src_f.is_file():
                            rel = src_f.relative_to(src_lang)
                            dst_f = dst_lang / rel
                            if not dst_f.exists():
                                try:
                                    dst_f.parent.mkdir(parents=True, exist_ok=True)
                                    shutil.copy2(str(src_f), str(dst_f))
                                    count += 1
                                except (OSError, PermissionError):
                                    pass
            except (OSError, PermissionError, shutil.Error):
                pass

        return count

    def _ensure_default_theme(self, wp_root: Path, clean_root: Path, active_theme: str = "") -> str:
        """v3.2: garantiza que exista al menos un tema instalado. Si el tema activo
        no quedó instalado (premium/no en WP.org) y no hay ningún otro tema, copia
        el tema por defecto incluido en el core limpio (twentytwenty*).

        Retorna el slug del tema por defecto instalado (o '' si no instaló ninguno).
        """
        themes_dir = wp_root / "wp-content" / "themes"
        clean_themes = clean_root / "wp-content" / "themes"

        # ¿El tema activo ya está instalado con contenido real?
        if active_theme:
            at = themes_dir / active_theme
            if at.is_dir() and at.exists() and any(at.rglob("*.php")):
                return ""

        # ¿Existe ya algún tema válido (con style.css)?
        if themes_dir.exists():
            for d in themes_dir.iterdir():
                if d.is_dir() and (d / "style.css").exists():
                    return ""

        if not clean_themes.exists():
            return ""
        # Copiar el tema por defecto del core (el más reciente twentytwenty*)
        defaults = sorted(
            [d for d in clean_themes.iterdir()
             if d.is_dir() and d.name.startswith("twenty")],
            reverse=True)
        if not defaults:
            defaults = [d for d in clean_themes.iterdir() if d.is_dir()]
        if not defaults:
            return ""
        src_theme = defaults[0]
        dst_theme = themes_dir / src_theme.name
        try:
            themes_dir.mkdir(parents=True, exist_ok=True)
            if dst_theme.exists():
                shutil.rmtree(str(dst_theme), ignore_errors=True)
            shutil.copytree(str(src_theme), str(dst_theme))
            self.log.append({"type": "warning", "cms": "wordpress",
                "message": f"Tema activo '{active_theme or '?'}' no disponible en WP.org; "
                           f"instalado tema por defecto '{src_theme.name}' para que el sitio cargue"})
            return src_theme.name
        except (OSError, PermissionError, shutil.Error):
            pass
        return ""

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
        """v2.6.7 Bug #1: la fase 5 corre DESPUES del wipe, que elimina wp-includes/.
        Por eso NO se puede exigir wp-includes para detectar la raiz. Una instalacion
        WP se identifica por wp-config.php (preservado) o por wp-content/ (preservado y
        re-garantizado en fase 4). Asi la reinstalacion de core/plugins/temas funciona.
        """
        roots = []
        seen = set()
        for root, dirs, files in os.walk(self.extract_dir):
            is_wp = (
                "wp-config.php" in files
                or "wp-content" in dirs
                or "wp-includes" in dirs
                or "wp-login.php" in files
            )
            if is_wp and root not in seen:
                # Evitar duplicar subdirectorios: si wp-content es el match, la raiz
                # es el padre que contiene wp-config/wp-content, no wp-content mismo.
                rp = Path(root)
                if rp.name in ("wp-content", "wp-includes", "wp-admin"):
                    continue
                roots.append(rp)
                seen.add(root)
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

    def _restore_wp_plugins(self, wp_root: Path, active_plugins: set) -> set:
        """Reinstala plugins desde WordPress.org. Retorna el set de slugs que
        quedaron efectivamente instalados (para enforcement posterior)."""
        installed: set = set()
        plugins_dir = wp_root / "wp-content" / "plugins"
        if not plugins_dir.exists():
            plugins_dir.mkdir(parents=True, exist_ok=True)

        # v2.6.4: usar active_plugins directamente — el directorio puede estar
        # vacio si CMSPluginCleaner ya movio los plugins a cuarentena antes
        if not active_plugins:
            return installed
        slugs = list(active_plugins)

        total = len(slugs)
        from concurrent.futures import ThreadPoolExecutor, as_completed as _ac

        def _restore_one(slug):
            try:
                resp = requests.get(WP_PLUGIN_API.format(slug=slug), timeout=15)
                if resp.status_code != 200:
                    return {"type": "warning", "cms": "wordpress",
                            "message": f"Plugin '{slug}': API respondio {resp.status_code}"}
                data = resp.json()
                if not isinstance(data, dict) or "download_link" not in data:
                    # WP.org confirma que no existe (premium, custom, o retirado)
                    return {"type": "warning", "cms": "wordpress",
                            "message": f"Plugin '{slug}' no en WordPress.org (premium/custom)"}
                version = data.get("version", "?")
                clean = self._download_and_extract_zip(slug, data["download_link"], "plugin")
                if not clean:
                    # Reintento con cache limpio
                    for p in (self._cache_dir / f"wp-plugin-{slug}.zip",
                              self._cache_dir / f"wp-plugin-{slug}"):
                        if p.exists():
                            try:
                                shutil.rmtree(str(p)) if p.is_dir() else p.unlink()
                            except OSError:
                                pass
                    clean = self._download_and_extract_zip(slug, data["download_link"], "plugin")
                if clean:
                    n = self._full_rebuild_dirs(plugins_dir / slug, clean, ["."], cms_key="wordpress")
                    return {"type": "success", "cms": "wordpress",
                            "message": f"Plugin '{slug}' v{version}: {n} archivos"}
                return {"type": "error", "cms": "wordpress",
                        "message": f"Plugin '{slug}' v{version} en WP.org pero fallo la descarga"}
            except (requests.RequestException, json.JSONDecodeError, ValueError) as e:
                return {"type": "warning", "cms": "wordpress",
                        "message": f"Plugin '{slug}': error de conexion ({type(e).__name__})"}

        with ThreadPoolExecutor(max_workers=4) as pool:
            futs = {pool.submit(_restore_one, s): s for s in slugs}
            done = 0
            for fut in _ac(futs):
                done += 1
                self.progress_callback("status", f"Descargando plugin {done} de {total}...")
                slug = futs[fut]
                entry = fut.result()
                if entry:
                    self.log.append(entry)
                    if entry.get("type") == "success":
                        installed.add(slug)
        return installed

    def _restore_wp_themes(self, wp_root: Path, theme_slugs, active_theme: str = "") -> set:
        """Reinstala temas desde WordPress.org. Retorna el set de slugs instalados."""
        installed: set = set()
        themes_dir = wp_root / "wp-content" / "themes"
        if not themes_dir.exists():
            themes_dir.mkdir(parents=True, exist_ok=True)

        # v2.6.6: reinstalar todos los temas separados (set) + el activo
        if isinstance(theme_slugs, str):
            theme_slugs = {theme_slugs} if theme_slugs else set()
        slugs = sorted(s for s in theme_slugs if s)
        if active_theme and active_theme not in slugs:
            slugs.append(active_theme)
        if not slugs:
            return installed

        total = len(slugs)
        from concurrent.futures import ThreadPoolExecutor, as_completed as _ac

        def _restore_one(slug):
            try:
                resp = requests.get(WP_THEME_API.format(slug=slug), timeout=15)
                if resp.status_code != 200:
                    return {"type": "warning", "cms": "wordpress",
                            "message": f"Tema '{slug}': API respondio {resp.status_code}"}
                data = resp.json()
                if not isinstance(data, dict) or "download_link" not in data:
                    return {"type": "warning", "cms": "wordpress",
                            "message": f"Tema '{slug}' no en WordPress.org (premium/custom)"}
                version = data.get("version", "?")
                clean = self._download_and_extract_zip(slug, data["download_link"], "theme")
                if not clean:
                    for p in (self._cache_dir / f"wp-theme-{slug}.zip",
                              self._cache_dir / f"wp-theme-{slug}"):
                        if p.exists():
                            try:
                                shutil.rmtree(str(p)) if p.is_dir() else p.unlink()
                            except OSError:
                                pass
                    clean = self._download_and_extract_zip(slug, data["download_link"], "theme")
                if clean:
                    n = self._full_rebuild_dirs(themes_dir / slug, clean, ["."], cms_key="wordpress")
                    return {"type": "success", "cms": "wordpress",
                            "message": f"Tema '{slug}' v{version}: {n} archivos"}
                return {"type": "error", "cms": "wordpress",
                        "message": f"Tema '{slug}' v{version} en WP.org pero fallo la descarga"}
            except (requests.RequestException, json.JSONDecodeError, ValueError) as e:
                return {"type": "warning", "cms": "wordpress",
                        "message": f"Tema '{slug}': error de conexion ({type(e).__name__})"}

        with ThreadPoolExecutor(max_workers=4) as pool:
            futs = {pool.submit(_restore_one, s): s for s in slugs}
            done = 0
            for fut in _ac(futs):
                done += 1
                self.progress_callback("status", f"Descargando tema {done} de {total}...")
                slug = futs[fut]
                entry = fut.result()
                if entry:
                    self.log.append(entry)
                    if entry.get("type") == "success":
                        installed.add(slug)
        return installed

    def _download_and_extract_zip(self, slug: str, url: str, kind: str) -> Path:
        cache_file = self._cache_dir / f"wp-{kind}-{slug}.zip"
        extract_to = self._cache_dir / f"wp-{kind}-{slug}"

        # v2.6.8: solo reutilizar cache si tiene contenido real (un dir con archivos)
        cached = self._pick_addon_dir(extract_to, slug)
        if cached and any(cached.rglob("*")):
            return cached

        # v2.6.8 Bug #1: lista de URLs a probar — API + fallback directo de WP.org
        urls = []
        if url:
            urls.append(url)
        kind_path = "plugin" if kind == "plugin" else "theme"
        urls.append(f"https://downloads.wordpress.org/{kind_path}/{slug}.zip")
        urls.append(f"https://downloads.wordpress.org/{kind_path}/{slug}.latest-stable.zip")

        for try_url in urls:
            try:
                # descarga limpia (sin reutilizar zip parcial previo)
                if cache_file.exists():
                    try:
                        cache_file.unlink()
                    except OSError:
                        pass
                resp = requests.get(try_url, timeout=TIMEOUT, stream=True)
                if resp.status_code != 200:
                    continue
                with open(str(cache_file), "wb") as f:
                    for chunk in resp.iter_content(chunk_size=65536):
                        f.write(chunk)

                if extract_to.exists():
                    shutil.rmtree(str(extract_to), ignore_errors=True)
                extract_to.mkdir(parents=True, exist_ok=True)
                with zipfile.ZipFile(str(cache_file), "r") as zf:
                    zf.extractall(str(extract_to))

                got = self._pick_addon_dir(extract_to, slug)
                if got and any(got.rglob("*")):
                    return got
            except (requests.RequestException, zipfile.BadZipFile, OSError):
                continue
        return None

    @staticmethod
    def _pick_addon_dir(extract_to: Path, slug: str) -> Path:
        """Devuelve el directorio real del addon dentro del zip extraido.
        Prefiere la carpeta con el nombre del slug; si no, el primer subdir; si
        no hay subdirs pero si archivos, el propio extract_to."""
        if not extract_to.exists():
            return None
        exact = extract_to / slug
        if exact.is_dir():
            return exact
        subdirs = [d for d in extract_to.iterdir() if d.is_dir()]
        if len(subdirs) == 1:
            return subdirs[0]
        if subdirs:
            return subdirs[0]
        if any(extract_to.iterdir()):
            return extract_to
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
        """Full rebuild: elimina por completo cada directorio destino y lo repone con
        la versión limpia. Garantiza que no queden archivos infectados que el malware
        haya AGREGADO al core (no solo modificado).

        v3.0.3: I/O tolerante a rutas largas de Windows (prefijo \\\\?\\) tanto al borrar
        como al copiar. Se usa también para reinstalar plugins/temas (dirname=".") cuyos
        árboles profundos (p.ej. vendor/elementor/...) antes fallaban silenciosamente.
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

            # Eliminar destino existente por completo (robusto ante rutas largas)
            if dst_dir.exists():
                self._robust_rmtree(dst_dir)

            # Copiar limpio (robusto ante rutas largas)
            n = self._robust_copytree(src_dir, dst_dir)
            total_files += n
            if n == 0:
                self.log.append({"type": "warning", "cms": cms_key,
                               "message": f"Sin archivos copiados al reponer '{dirname}'"})
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
