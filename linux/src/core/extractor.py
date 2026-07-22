"""Extractor de backups cPanel (tar.gz, zip, gzip) — robusto ante rutas largas y errores."""
import os
import re
import tarfile
import zipfile
import gzip
import shutil
import tempfile
from pathlib import Path
from dataclasses import dataclass, field


def _long_path(p: str) -> str:
    """Prefijo \\\\?\\ para soportar rutas >260 chars en Windows."""
    if os.name == "nt" and not p.startswith("\\\\?\\"):
        absp = os.path.abspath(p)
        if not absp.startswith("\\\\?\\"):
            return "\\\\?\\" + absp
    return p


@dataclass
class BackupInfo:
    path: str
    extract_dir: str
    total_files: int = 0
    total_size_mb: float = 0.0
    cpanel_user: str = ""
    has_mysql: bool = False
    has_email: bool = False
    has_homedir: bool = False
    cms_detected: list = field(default_factory=list)
    structure: dict = field(default_factory=dict)
    extraction_errors: list = field(default_factory=list)
    main_domain: str = ""
    all_domains: list = field(default_factory=list)


class ExtractionCancelled(Exception):
    """La extraccion fue interrumpida por el usuario."""


class BackupExtractor:
    CPANEL_MARKERS = {
        "mysql": ["mysql", "mysql.sql", "backup/mysql"],
        "email": ["mail", "etc/", "homedir/mail"],
        "homedir": ["homedir", "public_html"],
    }

    # Rutas que indican backup cPanel válido
    _VALID_CPANEL_PATHS = frozenset({
        "homedir", "public_html", "mysql", "mail", "etc",
        "userdata", "ssl", "bandwidth", "logs",
    })

    def __init__(self, backup_path: str, progress_callback=None):
        self.backup_path = Path(backup_path)
        self.progress_callback = progress_callback or (lambda *a: None)
        self.extract_dir = None
        self._errors = []
        self._cancelled = False

    def cancel(self):
        """Marca la extraccion para que se interrumpa lo antes posible."""
        self._cancelled = True

    @classmethod
    def validate(cls, backup_path: str) -> dict:
        """v3.1: Valida que el archivo es un backup cPanel reconocible antes de extraer.

        Retorna {"valid": True/False, "reason": "...", "file_count": N, "has_homedir": bool}
        Lanza ValueError si el archivo no existe o el formato no es soportado.
        """
        bp = Path(backup_path)
        if not bp.exists():
            raise ValueError(f"Archivo no encontrado: {backup_path}")

        name = bp.name.lower()
        result = {"valid": False, "reason": "", "file_count": 0, "has_homedir": False}

        try:
            if name.endswith((".tar.gz", ".tgz")):
                with tarfile.open(str(bp), "r:gz") as tar:
                    members = tar.getnames()
                    result["file_count"] = len(members)
                    # Revisar hasta 500 entradas para detectar estructura cPanel
                    sample = members[:500]
                    top_dirs = set()
                    second_dirs = set()
                    for m in sample:
                        parts = m.replace("\\", "/").lstrip("/").split("/")
                        if len(parts) >= 2:
                            top_dirs.add(parts[0].lower())
                            second_dirs.add(parts[1].lower())
                        elif len(parts) == 1 and parts[0]:
                            top_dirs.add(parts[0].lower())
                    matches = top_dirs & cls._VALID_CPANEL_PATHS
                    nested = not matches and bool(second_dirs & cls._VALID_CPANEL_PATHS)
                    if nested:
                        matches = second_dirs & cls._VALID_CPANEL_PATHS
                    result["has_homedir"] = bool(
                        {"homedir", "public_html"} & top_dirs or
                        {"homedir", "public_html"} & second_dirs
                    )
                    if matches:
                        result["valid"] = True
                        label = "anidada — " if nested else ""
                        result["reason"] = f"Estructura cPanel detectada ({label}{', '.join(sorted(matches))})"
                    else:
                        result["reason"] = (
                            "No se detectó estructura cPanel (homedir, public_html, mysql, etc.). "
                            "Puede ser un backup de otro sistema o estar vacío."
                        )
            elif name.endswith(".zip"):
                with zipfile.ZipFile(str(bp), "r") as zf:
                    members = zf.namelist()
                    result["file_count"] = len(members)
                    sample500 = members[:500]
                    top_dirs = {m.replace("\\", "/").split("/")[0].lower() for m in sample500}
                    second_dirs = {
                        m.replace("\\", "/").split("/")[1].lower()
                        for m in sample500 if len(m.replace("\\", "/").split("/")) >= 2
                    }
                    matches = top_dirs & cls._VALID_CPANEL_PATHS
                    if not matches:
                        matches = second_dirs & cls._VALID_CPANEL_PATHS
                    result["has_homedir"] = bool(
                        {"homedir", "public_html"} & top_dirs or
                        {"homedir", "public_html"} & second_dirs
                    )
                    result["valid"] = bool(matches)
                    result["reason"] = (
                        f"Estructura ZIP cPanel: {', '.join(sorted(matches))}" if matches
                        else "No se detectó estructura cPanel en el ZIP."
                    )
            elif name.endswith(".gz"):
                result["valid"] = True
                result["reason"] = "Archivo .gz — sin validación de estructura interna"
            else:
                raise ValueError(f"Formato no soportado: {name}")
        except (tarfile.TarError, zipfile.BadZipFile) as e:
            raise ValueError(f"Archivo corrupto o no es un backup válido: {e}") from e

        return result

    def extract(self, destination=None):
        if destination:
            self.extract_dir = Path(destination)
            self.extract_dir.mkdir(parents=True, exist_ok=True)
        else:
            base_tmp = Path(tempfile.gettempdir()) / "malclean"
            base_tmp.mkdir(parents=True, exist_ok=True)
            self.extract_dir = Path(tempfile.mkdtemp(prefix="scan_", dir=str(base_tmp)))

        name = self.backup_path.name.lower()

        if name.endswith(".tar.gz") or name.endswith(".tgz"):
            self._extract_targz()
        elif name.endswith(".tar"):
            self._extract_tar()
        elif name.endswith(".zip"):
            self._extract_zip()
        elif name.endswith(".gz"):
            self._extract_gz()
        else:
            raise ValueError(f"Formato no soportado: {name}")

        if self._cancelled:
            raise ExtractionCancelled("Extraccion cancelada por el usuario")

        return self._analyze_structure()

    def _extract_member_safe(self, tar, member, dest):
        """Extrae un miembro con manejo robusto de errores."""
        try:
            target = os.path.join(str(dest), member.name)
            if len(target) > 250 and os.name == "nt":
                parent = os.path.dirname(target)
                long_parent = _long_path(parent)
                os.makedirs(long_parent, exist_ok=True)
                if member.isfile():
                    long_target = _long_path(target)
                    fobj = tar.extractfile(member)
                    if fobj:
                        with open(long_target, "wb") as out:
                            shutil.copyfileobj(fobj, out)
                        return True
                elif member.isdir():
                    os.makedirs(_long_path(target), exist_ok=True)
                    return True
                return True
            else:
                tar.extract(member, dest, filter="data")
                return True
        except (OSError, tarfile.TarError, PermissionError, UnicodeDecodeError) as e:
            self._errors.append(f"{member.name}: {e}")
            return False

    def _extract_targz(self):
        self.progress_callback("status", "Extrayendo archivo tar.gz...")
        with tarfile.open(str(self.backup_path), "r:gz") as tar:
            members = tar.getmembers()
            total = len(members)
            for i, member in enumerate(members):
                if self._cancelled:
                    return
                if self._is_safe_path(member.name):
                    self._extract_member_safe(tar, member, self.extract_dir)
                pct = int((i + 1) / total * 100) if total else 0
                if i % 200 == 0:
                    self.progress_callback("progress", pct)

    def _extract_tar(self):
        self.progress_callback("status", "Extrayendo archivo tar...")
        with tarfile.open(str(self.backup_path), "r:") as tar:
            members = tar.getmembers()
            total = len(members)
            for i, member in enumerate(members):
                if self._cancelled:
                    return
                if self._is_safe_path(member.name):
                    self._extract_member_safe(tar, member, self.extract_dir)
                pct = int((i + 1) / total * 100) if total else 0
                if i % 200 == 0:
                    self.progress_callback("progress", pct)

    def _extract_zip(self):
        self.progress_callback("status", "Extrayendo archivo zip...")
        with zipfile.ZipFile(str(self.backup_path), "r") as zf:
            members = zf.namelist()
            total = len(members)
            for i, name in enumerate(members):
                if self._cancelled:
                    return
                if self._is_safe_path(name):
                    try:
                        zf.extract(name, str(self.extract_dir))
                    except (OSError, zipfile.BadZipFile, PermissionError) as e:
                        self._errors.append(f"{name}: {e}")
                pct = int((i + 1) / total * 100) if total else 0
                if i % 200 == 0:
                    self.progress_callback("progress", pct)

    def _extract_gz(self):
        self.progress_callback("status", "Extrayendo archivo gzip...")
        out_name = self.backup_path.stem
        out_path = self.extract_dir / out_name
        with gzip.open(str(self.backup_path), "rb") as gz_in:
            with open(str(out_path), "wb") as f_out:
                shutil.copyfileobj(gz_in, f_out)

    def _is_safe_path(self, path: str) -> bool:
        if ".." in path or path.startswith("/") or path.startswith("\\"):
            clean = path.lstrip("/\\").replace("..", "")
            if not clean:
                return False
        try:
            resolved = (self.extract_dir / path).resolve()
            return str(resolved).startswith(str(self.extract_dir.resolve()))
        except (OSError, ValueError):
            return False

    def _analyze_structure(self) -> BackupInfo:
        info = BackupInfo(
            path=str(self.backup_path),
            extract_dir=str(self.extract_dir),
            extraction_errors=self._errors.copy(),
        )

        total_size = 0
        total_files = 0
        structure = {"databases": [], "emails": [], "websites": [], "configs": []}

        for root, dirs, files in os.walk(self.extract_dir):
            try:
                rel_root = Path(root).relative_to(self.extract_dir)
            except ValueError:
                continue
            rel_str = str(rel_root).replace("\\", "/").lower()

            if any(m in rel_str for m in self.CPANEL_MARKERS["mysql"]):
                info.has_mysql = True
                for f in files:
                    if f.endswith((".sql", ".sql.gz")):
                        structure["databases"].append(str(Path(root) / f))

            if any(m in rel_str for m in self.CPANEL_MARKERS["email"]):
                info.has_email = True
                for f in files:
                    if f.endswith((".eml", ".mbox")) or "cur" in rel_str or "new" in rel_str:
                        structure["emails"].append(str(Path(root) / f))

            if any(m in rel_str for m in self.CPANEL_MARKERS["homedir"]):
                info.has_homedir = True

            for f in files:
                fp = Path(root) / f
                total_files += 1
                try:
                    total_size += fp.stat().st_size
                except OSError:
                    pass

            self._detect_cms(root, files, info, structure)

        if not info.cpanel_user:
            try:
                for d in self.extract_dir.iterdir():
                    if d.is_dir() and d.name not in (".", ".."):
                        info.cpanel_user = d.name
                        break
            except OSError:
                pass

        info.total_files = total_files
        info.total_size_mb = round(total_size / (1024 * 1024), 2)
        info.structure = structure
        self._detect_domains(info)
        return info

    def _detect_domains(self, info: BackupInfo):
        """Detecta el dominio principal del hosting y todos los dominios.

        Orden de prioridad (de más a menos autoritativo):
          1. userdata/main de cPanel  -> main_domain, addon/parked/sub domains
          2. Directorios homedir/etc/<dominio> (cuentas de correo por dominio)
          3. siteurl/home de wp_options en los dumps SQL
          4. cpanel_user como último recurso
        """
        main_domain = ""
        domains = []
        seen = set()

        # Dominio real: etiquetas + TLD alfabético 2-24. Rechaza nombres de BD,
        # 'public_html', rutas y prefijos de tabla aunque tengan puntos.
        _dom_re = re.compile(
            r'^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$')
        _non_domain = {"public_html", "www", "htdocs", "localhost",
                       "wp-content", "homedir", "localhost.localdomain"}

        def _add(d):
            d = (d or "").strip().strip("'\"").lower()
            d = d.split("://")[-1].split("/")[0].split(":")[0]
            if d.startswith("www."):
                d = d[4:]
            if (d and d not in seen and d not in _non_domain
                    and not d.replace(".", "").isdigit()
                    and _dom_re.match(d)):
                seen.add(d)
                domains.append(d)
                return True
            return False

        # 1. userdata/main (formato YAML simple de cPanel)
        main_files = []
        for root, dirs, files in os.walk(self.extract_dir):
            rel = str(Path(root).relative_to(self.extract_dir)).replace("\\", "/").lower()
            if rel.endswith("userdata") or "/userdata" in f"/{rel}":
                if "main" in files:
                    main_files.append(Path(root) / "main")
        for mf in main_files:
            try:
                txt = mf.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            m = re.search(r"^\s*main_domain:\s*(\S+)", txt, re.MULTILINE)
            if m and not main_domain:
                cand = m.group(1).strip().strip("'\"")
                if _add(cand):
                    main_domain = domains[-1]
            # addon/parked/sub: claves "dominio: ..." y entradas de lista
            for dm in re.findall(r"^\s*-?\s*([a-z0-9][a-z0-9.\-]+\.[a-z]{2,}):", txt, re.MULTILINE):
                _add(dm)

        # 2. homedir/etc/<dominio>
        for root, dirs, files in os.walk(self.extract_dir):
            rel = str(Path(root).relative_to(self.extract_dir)).replace("\\", "/").lower()
            if rel.endswith("/etc") or rel.endswith("homedir/etc") or rel.endswith("etc"):
                for d in dirs:
                    _add(d)

        # 3. wp_options siteurl/home (solo si aún no hay dominio principal)
        if not main_domain:
            for db_path in info.structure.get("databases", []):
                dom = self._domain_from_sql(db_path)
                if dom and _add(dom):
                    main_domain = domains[-1]
                    break

        # 4. fallback
        if not main_domain:
            if domains:
                main_domain = domains[0]
            elif info.cpanel_user and "." in info.cpanel_user:
                main_domain = info.cpanel_user
                domains.append(info.cpanel_user)

        info.main_domain = main_domain
        info.all_domains = domains

    @staticmethod
    def _domain_from_sql(db_path: str) -> str:
        """Extrae el dominio de siteurl/home en wp_options de un dump SQL."""
        try:
            with open(db_path, "r", encoding="utf-8", errors="replace") as f:
                head = f.read(2_000_000)  # primeras ~2MB suelen contener wp_options
        except OSError:
            return ""
        m = re.search(
            r"'(?:siteurl|home)',\s*'(https?://[^']+)'", head, re.IGNORECASE)
        if m:
            url = m.group(1)
            host = url.split("://")[-1].split("/")[0]
            return host
        return ""

    def _detect_cms(self, root, files, info, structure):
        from ..config.settings import CMS_DETECTION_MARKERS
        root_path = Path(root)
        dirs_here = set()
        try:
            dirs_here = {d.name for d in root_path.iterdir() if d.is_dir()}
        except (OSError, PermissionError):
            pass

        for cms_name, markers in CMS_DETECTION_MARKERS.items():
            if cms_name in info.cms_detected:
                continue
            req_file = markers.get("file", "")
            req_dir = markers.get("dir", "")
            if req_file not in files:
                continue
            if req_dir and req_dir not in dirs_here:
                continue
            extra_file = markers.get("extra_file", "")
            if extra_file and not (root_path / extra_file).exists():
                continue
            extra_dir = markers.get("extra_dir", "")
            if extra_dir and not (root_path / extra_dir).exists():
                continue
            info.cms_detected.append(cms_name)
            if str(root) not in structure["websites"]:
                structure["websites"].append(str(root))

        from ..config.settings import DEFAULT_CONFIG
        for cms_name in ("laravel", "softaculous"):
            if cms_name in info.cms_detected:
                continue
            markers = DEFAULT_CONFIG["cms_patterns"].get(cms_name, [])
            for marker in markers:
                if marker in files:
                    info.cms_detected.append(cms_name)
                    if str(root) not in structure["websites"]:
                        structure["websites"].append(str(root))
                    break

    def cleanup(self):
        if self.extract_dir and self.extract_dir.exists():
            if "malclean" in str(self.extract_dir):
                shutil.rmtree(str(self.extract_dir), ignore_errors=True)
