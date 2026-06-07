"""Empaquetador — genera .tar.gz listo para importar en cPanel.

v2.6.0: Nuevo create_critical_mode_output() genera paquetes separados
compatible con la herramienta de Backup de cPanel:
  - homedir_backup.tar.gz (rutas relativas desde homedir)
  - databases/*.sql.gz (cada BD como gzip directo)
"""
import os
import re
import gzip
import tarfile
import shutil
import time
from pathlib import Path
from typing import Callable

from ..config.settings import HOMEDIR_EXCLUDE_DIRS

# Directorios cPanel considerados "contenido critico" restaurable en WHM
_CPANEL_CRITICAL_DIRS  = {"mysql", "homedir", "userdata", "cp", "mail", "etc"}
_CPANEL_CRITICAL_FILES = {"mysql.sql", "mysql.sql.gz"}

# Directorios a incluir en el homedir backup critico
_HOMEDIR_INCLUDE_DIRS = {
    "public_html", "www", "mail", "etc", "domains",
    "maildir", ".cpanel", ".htpasswds",
}


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

    # ── v2.6.0: Critical mode output ──

    def create_critical_mode_output(self, extract_dir: str, sql_files: list,
                                     output_base_dir: str, domain: str = "sitio",
                                     progress_callback: Callable = None) -> dict:
        """Genera paquetes separados compatibles con cPanel Backup Restore.
        - homedir_backup.tar.gz: rutas relativas desde homedir
        - databases/*.sql.gz: cada BD como gzip directo
        """
        cb = progress_callback or self.progress_callback
        ts = time.strftime("%Y%m%d_%H%M%S")
        output_folder = Path(output_base_dir) / f"cpacleans_{domain}_{ts}"
        output_folder.mkdir(parents=True, exist_ok=True)

        source = Path(extract_dir)
        cpanel_root = self._find_cpanel_backup_root(source)
        homedir = cpanel_root / "homedir"

        result = {
            "homedir_tar": "",
            "databases": [],
            "quarantine_dir": "",
            "included_count": 0,
            "excluded_count": 0,
            "output_folder": str(output_folder),
        }

        # 1. Detectar rutas criticas en homedir
        if homedir.exists():
            cb("status", "Detectando rutas criticas del homedir...")
            included_paths = self._detect_critical_paths(homedir)

            # Generar homedir_backup.tar.gz
            homedir_tar = str(output_folder / "homedir_backup.tar.gz")
            included_count = 0
            cb("status", f"Empaquetando homedir ({len(included_paths)} dirs)...")

            with tarfile.open(homedir_tar, "w:gz", compresslevel=6) as tar:
                for rel_path in included_paths:
                    full = homedir / rel_path
                    if not full.exists():
                        continue
                    try:
                        tar.add(str(full), arcname=rel_path)
                        if full.is_file():
                            included_count += 1
                        else:
                            included_count += sum(1 for _ in full.rglob("*")
                                                  if _.is_file())
                    except (OSError, PermissionError, tarfile.TarError):
                        pass

            result["homedir_tar"] = homedir_tar
            result["included_count"] = included_count

            # Mover excluidos a cuarentena
            quarantine_dir = str(output_folder / "cuarentena")
            excluded = self._move_to_critical_quarantine(
                homedir, included_paths, quarantine_dir)
            result["quarantine_dir"] = quarantine_dir
            result["excluded_count"] = excluded

        # 2. Empaquetar bases de datos como .sql.gz individuales
        if sql_files:
            db_dir = output_folder / "databases"
            db_dir.mkdir(parents=True, exist_ok=True)
            db_paths = self._package_databases_gz(sql_files, str(db_dir))
            result["databases"] = db_paths
            cb("status", f"BDs empaquetadas: {len(db_paths)} archivos .sql.gz")

        cb("status", f"Paquete critico generado en {output_folder.name}")
        return result

    def _detect_critical_paths(self, homedir: Path) -> list:
        """Retorna lista de rutas relativas desde homedir a incluir."""
        paths = []
        try:
            for item in homedir.iterdir():
                name_lower = item.name.lower()
                # Incluir dirs conocidos
                if name_lower in _HOMEDIR_INCLUDE_DIRS:
                    paths.append(item.name)
                    continue
                # Excluir dirs no deseados
                if name_lower in HOMEDIR_EXCLUDE_DIRS:
                    continue
                # Detectar addon domains / subdominios
                if item.is_dir():
                    # Patron subdominio: sub.dominio.com/
                    if "." in item.name and not item.name.startswith("."):
                        # Verificar que tiene contenido web
                        has_web = any(
                            (item / f).exists()
                            for f in ("index.php", "index.html", "wp-config.php",
                                      "public_html", "configuration.php")
                        )
                        if has_web:
                            paths.append(item.name)
                            continue
                    # Dir con public_html interno (addon domain)
                    if (item / "public_html").exists():
                        paths.append(item.name)
                        continue
                # Incluir archivos sueltos importantes en homedir root
                elif item.is_file():
                    if name_lower in (".htaccess", ".bash_profile", ".bashrc"):
                        paths.append(item.name)
        except (OSError, PermissionError):
            pass

        return paths

    def _package_databases_gz(self, sql_files: list, db_output_dir: str) -> list:
        """Comprime cada SQL limpio a .sql.gz individual."""
        results = []
        for sql_path in sql_files:
            fp = Path(sql_path)
            if not fp.exists():
                continue

            # Detectar nombre BD desde comentario del dump
            db_name = fp.stem  # fallback: nombre del archivo
            try:
                with open(sql_path, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        if line.startswith("--"):
                            m = re.search(r'Database:\s*`?(\w+)`?', line)
                            if m:
                                db_name = m.group(1)
                                break
                        if not line.startswith("-") and not line.startswith("/"):
                            break
            except (OSError, PermissionError):
                pass

            out_path = Path(db_output_dir) / f"{db_name}.sql.gz"
            try:
                with open(sql_path, "rb") as src:
                    with gzip.open(str(out_path), "wb", compresslevel=6) as dst:
                        shutil.copyfileobj(src, dst)
                results.append(str(out_path))
            except (OSError, PermissionError):
                pass

        return results

    def _move_to_critical_quarantine(self, homedir: Path,
                                      included_paths: list,
                                      quarantine_dir: str) -> int:
        """Copia a cuarentena archivos de homedir no incluidos en el backup."""
        included_set = {p.lower() for p in included_paths}
        quarantine = Path(quarantine_dir)
        quarantine.mkdir(parents=True, exist_ok=True)
        count = 0

        try:
            for item in homedir.iterdir():
                if item.name.lower() in included_set:
                    continue
                # No mover dirs ya excluidos conocidos (virtfs, cagefs)
                name_lower = item.name.lower()
                if name_lower in HOMEDIR_EXCLUDE_DIRS:
                    continue
                try:
                    dest = quarantine / item.name
                    if item.is_dir():
                        if not dest.exists():
                            shutil.copytree(str(item), str(dest))
                            file_count = sum(1 for _ in dest.rglob("*")
                                            if _.is_file())
                            count += file_count
                    elif item.is_file():
                        shutil.copy2(str(item), str(dest))
                        count += 1
                except (OSError, PermissionError, shutil.Error):
                    pass
        except (OSError, PermissionError):
            pass

        return count

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
