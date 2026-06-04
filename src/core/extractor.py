"""Extractor de backups cPanel (tar.gz, zip, gzip) — robusto ante rutas largas y errores."""
import os
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


class BackupExtractor:
    CPANEL_MARKERS = {
        "mysql": ["mysql", "mysql.sql", "backup/mysql"],
        "email": ["mail", "etc/", "homedir/mail"],
        "homedir": ["homedir", "public_html"],
    }

    def __init__(self, backup_path: str, progress_callback=None):
        self.backup_path = Path(backup_path)
        self.progress_callback = progress_callback or (lambda *a: None)
        self.extract_dir = None
        self._errors = []

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
        return info

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
