"""Empaquetador — genera .tar.gz listo para importar en cPanel."""
import os
import tarfile
import shutil
from pathlib import Path
from typing import Callable


class BackupPackager:
    def __init__(self, progress_callback: Callable = None):
        self.progress_callback = progress_callback or (lambda *a: None)

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
