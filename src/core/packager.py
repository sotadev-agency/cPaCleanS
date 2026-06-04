"""Empaquetador — genera .tar.gz listo para importar en cPanel."""
import os
import tarfile
import shutil
from pathlib import Path
from typing import Callable

# Directorios cPanel considerados "contenido critico" restaurable en WHM
_CPANEL_CRITICAL_DIRS  = {"mysql", "homedir", "userdata", "cp", "mail", "etc"}
_CPANEL_CRITICAL_FILES = {"mysql.sql", "mysql.sql.gz"}


class BackupPackager:
    def __init__(self, progress_callback: Callable = None):
        self.progress_callback = progress_callback or (lambda *a: None)

    def create_cpanel_partial_targz(self, extract_dir: str, backup_info=None,
                                    output_path: str = None) -> str:
        """Crea .tar.gz parcial compatible con el importador de cPanel/WHM.

        Incluye solo: mysql/, homedir/ (con mail/), userdata/, cp/
        Excluye logs, ssl, bandwidth y otros dirs que WHM recrea al restaurar.
        La estructura generada es importable en WHM > Restore a Full Backup.
        """
        source = Path(extract_dir)
        if output_path is None:
            output_path = str(source.parent / f"{source.name}-critico.tar.gz")

        cpanel_root  = self._find_cpanel_backup_root(source)
        cpanel_user  = (backup_info.cpanel_user
                        if backup_info and getattr(backup_info, "cpanel_user", "")
                        else cpanel_root.name)

        items_to_pack = []
        try:
            for item in cpanel_root.iterdir():
                name_lc = item.name.lower()
                if item.is_dir() and name_lc in _CPANEL_CRITICAL_DIRS:
                    items_to_pack.append(item)
                elif item.is_file() and name_lc in _CPANEL_CRITICAL_FILES:
                    items_to_pack.append(item)
        except (OSError, PermissionError):
            pass

        if not items_to_pack:
            # Fallback: empaquetar todo (backup con estructura inesperada)
            return self.create_targz(extract_dir, output_path)

        self.progress_callback("status",
            f"Backup parcial cPanel: {len(items_to_pack)} dirs criticos ({cpanel_user})...")

        with tarfile.open(output_path, "w:gz", compresslevel=6) as tar:
            for i, item in enumerate(items_to_pack):
                try:
                    arcname = os.path.join(cpanel_user, item.name)
                    tar.add(str(item), arcname=arcname)
                except (OSError, PermissionError, tarfile.TarError):
                    pass
                pct = int((i + 1) / len(items_to_pack) * 100)
                self.progress_callback("progress", pct)

        size_mb = round(Path(output_path).stat().st_size / (1024 * 1024), 2)
        self.progress_callback("status", f"Backup parcial generado: {size_mb} MB")
        return output_path

    def _find_cpanel_backup_root(self, extract_dir: Path) -> Path:
        """Localiza el directorio que contiene mysql/, homedir/, etc."""
        cpanel_dirs = {"mysql", "homedir", "userdata", "cp"}
        if any((extract_dir / d).exists() for d in cpanel_dirs):
            return extract_dir
        try:
            for d in extract_dir.iterdir():
                if d.is_dir() and any((d / cd).exists() for cd in cpanel_dirs):
                    return d
        except (OSError, PermissionError):
            pass
        return extract_dir

    def create_targz(self, source_dir: str, output_path: str = None) -> str:
        source = Path(source_dir)
        if output_path is None:
            output_path = str(source.parent / f"{source.name}-limpio.tar.gz")

        self.progress_callback("status", "Generando archivo .tar.gz...")

        all_files = []
        for root, dirs, files in os.walk(source):
            for f in files:
                all_files.append(os.path.join(root, f))

        total = len(all_files)
        self.progress_callback("status", f"Comprimiendo {total} archivos...")

        with tarfile.open(output_path, "w:gz", compresslevel=6) as tar:
            for i, fp in enumerate(all_files):
                try:
                    arcname = os.path.relpath(fp, source)
                    tar.add(fp, arcname=arcname)
                except (OSError, PermissionError, ValueError):
                    pass

                if i % 500 == 0 or i == total - 1:
                    pct = int((i + 1) / total * 100) if total else 100
                    self.progress_callback("progress", pct)

        size_mb = round(Path(output_path).stat().st_size / (1024 * 1024), 2)
        self.progress_callback("status", f"Archivo generado: {size_mb} MB")
        return output_path

    def copy_clean_files(self, source_dir: str, dest_dir: str) -> int:
        source = Path(source_dir)
        dest = Path(dest_dir)
        dest.mkdir(parents=True, exist_ok=True)

        self.progress_callback("status", f"Copiando archivos limpios a {dest}...")

        copied = 0
        for root, dirs, files in os.walk(source):
            rel = Path(root).relative_to(source)
            target_dir = dest / rel
            target_dir.mkdir(parents=True, exist_ok=True)

            for f in files:
                src_file = Path(root) / f
                dst_file = target_dir / f
                try:
                    shutil.copy2(str(src_file), str(dst_file))
                    copied += 1
                except (OSError, PermissionError):
                    pass

            if copied % 500 == 0:
                self.progress_callback("status", f"Copiados: {copied} archivos...")

        self.progress_callback("status", f"Completado: {copied} archivos copiados")
        return copied
