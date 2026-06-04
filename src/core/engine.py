"""Motor de escaneo de alto rendimiento — pool de procesos con scanners persistentes."""
import os
import re
import time
import hashlib
import shutil
import multiprocessing
from pathlib import Path
from dataclasses import dataclass, field
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from typing import Callable

from ..config.settings import (
    load_config, CLEAN_MODE_NORMAL, CLEAN_MODE_INTERMEDIATE, CLEAN_MODE_STRICT,
    CPANEL_PROTECTED_DIRS,
)

CONFIRMED_MALWARE_CATEGORIES = {
    "webshell", "backdoor", "cryptominer", "dropper",
    "cms_upload_php", "cms_htaccess_override", "cms_index_hijack",
    "cms_ini_injection", "double_extension",
    "malicious_attachment",
    "htaccess_redirect", "htaccess_handler", "htaccess_php",
}


@dataclass
class Finding:
    file_path: str
    line_number: int = 0
    severity: str = "medium"
    category: str = ""
    description: str = ""
    matched_pattern: str = ""
    context: str = ""
    cleaned: bool = False
    sha256: str = ""
    confirmed_malware: bool = False


@dataclass
class ScanResult:
    total_files_scanned: int = 0
    total_threats_found: int = 0
    total_cleaned: int = 0
    scan_duration_seconds: float = 0.0
    findings: list = field(default_factory=list)
    summary_by_severity: dict = field(default_factory=dict)
    summary_by_category: dict = field(default_factory=dict)
    cms_detected: list = field(default_factory=list)
    virustotal_hits: list = field(default_factory=list)
    scan_errors: list = field(default_factory=list)
    quarantine_dir: str = ""
    cms_restore_log: list = field(default_factory=list)
    clean_mode_used: str = ""
    workers_used: int = 0
    # v2.2.0 — filtro de rutas criticas
    critical_only_mode: bool = False
    omitted_paths_count: int = 0
    # v2.2.3 — log de plugins/temas separados
    plugins_temas_log: list = field(default_factory=list)


# --- Multiprocessing worker con scanners persistentes por proceso ---
_worker_scanners = None


def _worker_init(scanner_classes):
    global _worker_scanners
    _worker_scanners = [cls() for cls in scanner_classes]


def _worker_scan_batch(file_batch):
    """Escanea un lote de archivos con scanners ya instanciados."""
    results = []
    for file_path in file_batch:
        file_findings = []
        for scanner in _worker_scanners:
            try:
                r = scanner.scan(file_path)
                if r:
                    file_findings.extend(r)
            except Exception:
                pass
        if file_findings:
            results.extend(file_findings)
    return results


class ScanEngine:
    def __init__(self, progress_callback: Callable = None):
        self.config = load_config()
        self.progress_callback = progress_callback or (lambda *a: None)
        self.scanner_classes = []
        self.result = ScanResult()
        self._cancelled = False
        self._extract_dir = ""  # guardado en scan_directory para uso en clean_findings

    def register_scanner_class(self, scanner_class):
        self.scanner_classes.append(scanner_class)

    def cancel(self):
        self._cancelled = True

    def scan_directory(self, directory: str, backup_info=None, critical_only: bool = False) -> ScanResult:
        start_time = time.time()
        directory = Path(directory)

        if backup_info:
            self.result.cms_detected = backup_info.cms_detected

        self._extract_dir = str(directory)
        self.result.critical_only_mode = critical_only
        files_to_scan, omitted = self._collect_files(directory, critical_only=critical_only)
        self.result.omitted_paths_count = omitted
        total = len(files_to_scan)
        workers = min(self.config.get("scan_workers", 4), multiprocessing.cpu_count(), 16)
        self.result.workers_used = workers

        status_msg = f"Escaneando {total} archivos con {workers} workers..."
        if critical_only and omitted:
            status_msg += f" ({omitted} rutas de sistema omitidas)"
        self.progress_callback("status", status_msg)

        batch_size = max(50, total // (workers * 4))
        batches = [files_to_scan[i:i + batch_size] for i in range(0, total, batch_size)]

        try:
            self._scan_multiprocess(batches, total, workers)
        except Exception:
            self.progress_callback("status", "Fallback a threading...")
            self._scan_threaded(files_to_scan, total)

        self._classify_findings()

        self.result.total_files_scanned = total
        self.result.total_threats_found = len(self.result.findings)
        self.result.scan_duration_seconds = round(time.time() - start_time, 2)
        self._build_summaries()
        return self.result

    def _classify_findings(self):
        for f in self.result.findings:
            f.confirmed_malware = (
                f.category in CONFIRMED_MALWARE_CATEGORIES
                and f.severity in ("critical", "high")
            )

        hits_per_file = {}
        for f in self.result.findings:
            fp = f.file_path
            if fp not in hits_per_file:
                hits_per_file[fp] = {"categories": set(), "severities": set(), "count": 0}
            hits_per_file[fp]["categories"].add(f.category)
            hits_per_file[fp]["severities"].add(f.severity)
            hits_per_file[fp]["count"] += 1

        for f in self.result.findings:
            if f.confirmed_malware:
                continue
            info = hits_per_file.get(f.file_path)
            if not info:
                continue
            cats = info["categories"]
            has_exec = cats & {"injection", "webshell", "backdoor"}
            has_obfusc = cats & {"obfuscation"}
            high_sev = "critical" in info["severities"] or "high" in info["severities"]
            if has_exec and has_obfusc and high_sev and info["count"] >= 3:
                f.confirmed_malware = True

    def _scan_multiprocess(self, batches, total, workers):
        processed = 0
        with ProcessPoolExecutor(
            max_workers=workers,
            initializer=_worker_init,
            initargs=(self.scanner_classes,)
        ) as executor:
            futures = {executor.submit(_worker_scan_batch, batch): len(batch) for batch in batches}

            for future in as_completed(futures):
                if self._cancelled:
                    executor.shutdown(wait=False, cancel_futures=True)
                    break

                batch_size = futures[future]
                processed += batch_size
                pct = min(100, int(processed / total * 100))
                self.progress_callback("progress", pct)

                try:
                    findings = future.result(timeout=120)
                    if findings:
                        self.result.findings.extend(findings)
                except Exception as e:
                    self.result.scan_errors.append(f"Batch error: {e}")

    def _scan_threaded(self, files, total):
        scanners = [cls() for cls in self.scanner_classes]
        scanned = 0

        with ThreadPoolExecutor(max_workers=min(8, multiprocessing.cpu_count())) as executor:
            def scan_one(fp):
                results = []
                for s in scanners:
                    try:
                        r = s.scan(fp)
                        if r:
                            results.extend(r)
                    except Exception:
                        pass
                return results

            futures = {executor.submit(scan_one, fp): fp for fp in files}
            for future in as_completed(futures):
                scanned += 1
                if scanned % 100 == 0:
                    self.progress_callback("progress", int(scanned / total * 100))
                try:
                    findings = future.result(timeout=60)
                    if findings:
                        self.result.findings.extend(findings)
                except Exception:
                    pass

    def _collect_files(self, directory: Path, critical_only: bool = False) -> tuple:
        """Recopila archivos a escanear. Retorna (archivos, omitidos)."""
        all_extensions = set()
        for exts in self.config["scan_extensions"].values():
            all_extensions.update(exts)

        max_size = self.config["max_file_size_mb"] * 1024 * 1024
        files = []

        important_names = {
            ".htaccess", ".env", "wp-config.php", "configuration.php",
            "config.php", ".user.ini", "php.ini", "index.php",
        }

        for root, _, filenames in os.walk(directory):
            for fname in filenames:
                fp = Path(root) / fname
                ext = fp.suffix.lower()
                name_lower = fname.lower()

                should_scan = (
                    ext in all_extensions
                    or name_lower in important_names
                    or name_lower.startswith(".")
                )

                if should_scan:
                    try:
                        sz = fp.stat().st_size
                        if 0 < sz <= max_size:
                            files.append(str(fp))
                    except OSError:
                        pass

        if critical_only:
            from .path_filter import filter_files
            return filter_files(files, critical_only=True, base_dir=str(directory))

        return files, 0

    def setup_quarantine(self, base_dir: str) -> str:
        ts = time.strftime("%Y%m%d_%H%M%S")
        qdir = Path(base_dir) / f"cuarentena_{ts}"
        qdir.mkdir(parents=True, exist_ok=True)
        (qdir / "originales_intactos").mkdir(exist_ok=True)
        (qdir / "amenazas_removidas").mkdir(exist_ok=True)
        (qdir / "archivos_0kb").mkdir(exist_ok=True)
        (qdir / "plugins_temas_separados" / "premium").mkdir(parents=True, exist_ok=True)
        (qdir / "plugins_temas_separados" / "sospechosos").mkdir(parents=True, exist_ok=True)
        self.result.quarantine_dir = str(qdir)
        return str(qdir)

    def clean_findings(self, quarantine_base: str, mode: str = CLEAN_MODE_NORMAL) -> int:
        self.result.clean_mode_used = mode

        qdir = self.setup_quarantine(quarantine_base)
        originals_dir = Path(qdir) / "originales_intactos"
        removed_dir = Path(qdir) / "amenazas_removidas"

        cleaned = 0
        already_processed = set()

        for finding in self.result.findings:
            fp = Path(finding.file_path)
            if str(fp) in already_processed or not fp.exists():
                if str(fp) in already_processed:
                    finding.cleaned = True
                continue

            should_clean = False
            if mode == CLEAN_MODE_STRICT:
                should_clean = True
            elif mode == CLEAN_MODE_INTERMEDIATE:
                should_clean = finding.confirmed_malware or finding.severity in ("critical", "high")
            elif mode == CLEAN_MODE_NORMAL:
                should_clean = finding.confirmed_malware

            if not should_clean:
                continue

            # Nunca cuarentenar archivos core de cPanel necesarios para restore en WHM
            if self._is_cpanel_protected(str(fp)):
                self.progress_callback("status", f"[PROTEGIDO cPanel] {fp.name} — no cuarentenado")
                continue

            try:
                safe_name = fp.name
                counter = 0
                dest_orig = originals_dir / safe_name
                dest_removed = removed_dir / safe_name
                while dest_orig.exists():
                    counter += 1
                    dest_orig = originals_dir / f"{fp.stem}_{counter}{fp.suffix}"
                    dest_removed = removed_dir / f"{fp.stem}_{counter}{fp.suffix}"

                shutil.copy2(str(fp), str(dest_orig))
                if mode == CLEAN_MODE_STRICT:
                    os.remove(str(fp))
                else:
                    shutil.move(str(fp), str(dest_removed))
                finding.cleaned = True
                already_processed.add(str(fp))
                cleaned += 1
            except (OSError, PermissionError, shutil.Error):
                pass

        self.result.total_cleaned = cleaned
        return cleaned

    def _is_cpanel_protected(self, file_path: str) -> bool:
        """Retorna True si el archivo es core de cPanel y NO debe ser cuarentenado.
        Evalua solo los primeros 3 segmentos de la ruta relativa al extract_dir."""
        if not self._extract_dir:
            return False
        try:
            rel = Path(file_path).relative_to(self._extract_dir)
            top_parts = {p.lower() for p in rel.parts[:3]}
            return bool(top_parts & CPANEL_PROTECTED_DIRS)
        except ValueError:
            return False

    def clean_zero_byte_files(self, extract_dir: str, mode: str = CLEAN_MODE_NORMAL) -> int:
        """Mueve o elimina archivos de 0 bytes que generan basura."""
        if not self.result.quarantine_dir:
            return 0
        zero_dir = Path(self.result.quarantine_dir) / "archivos_0kb"
        count = 0
        for root, dirs, files in os.walk(extract_dir):
            for fname in files:
                fp = Path(root) / fname
                try:
                    if fp.stat().st_size == 0:
                        if mode == CLEAN_MODE_STRICT:
                            os.remove(str(fp))
                        else:
                            dest = zero_dir / f"{fname}_{count}"
                            shutil.move(str(fp), str(dest))
                        count += 1
                except (OSError, PermissionError):
                    pass
        return count

    def separate_premium_suspicious(self, extract_dir: str, cms_restore_log: list) -> dict:
        """Separa plugins/temas premium y sospechosos fuera del backup limpio."""
        if not self.result.quarantine_dir:
            return {"premium": 0, "suspicious": 0}
        sep_dir = Path(self.result.quarantine_dir) / "plugins_temas_separados"
        premium_dir = sep_dir / "premium"
        suspicious_dir = sep_dir / "sospechosos"

        premium_slugs = set()
        for entry in cms_restore_log:
            if entry.get("type") == "warning" and "no en WordPress.org" in entry.get("message", ""):
                slug = ""
                msg = entry["message"]
                if "'" in msg:
                    slug = msg.split("'")[1]
                if slug:
                    premium_slugs.add(slug)

        counts = {"premium": 0, "suspicious": 0}

        wp_dirs = []
        for root, dirs, files in os.walk(extract_dir):
            if "wp-content" in dirs:
                wp_dirs.append(Path(root) / "wp-content")

        for wp_content in wp_dirs:
            for subdir_name in ("plugins", "themes"):
                subdir = wp_content / subdir_name
                if not subdir.exists():
                    continue
                for item in subdir.iterdir():
                    if not item.is_dir():
                        continue
                    slug = item.name
                    is_suspicious = bool(re.match(r'^[a-z]{2,4}\d{2,}', slug)) or len(slug) > 40
                    if slug in premium_slugs:
                        try:
                            dest = premium_dir / f"{subdir_name}_{slug}"
                            if not dest.exists():
                                shutil.copytree(str(item), str(dest))
                                shutil.rmtree(str(item))
                                counts["premium"] += 1
                        except (OSError, PermissionError, shutil.Error):
                            pass
                    elif is_suspicious:
                        try:
                            dest = suspicious_dir / f"{subdir_name}_{slug}"
                            if not dest.exists():
                                shutil.copytree(str(item), str(dest))
                                shutil.rmtree(str(item))
                                counts["suspicious"] += 1
                        except (OSError, PermissionError, shutil.Error):
                            pass
        return counts

    def _build_summaries(self):
        by_sev = {}
        by_cat = {}
        for f in self.result.findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
            by_cat[f.category] = by_cat.get(f.category, 0) + 1
        self.result.summary_by_severity = by_sev
        self.result.summary_by_category = by_cat

    @staticmethod
    def file_hash(file_path: str) -> str:
        sha = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    sha.update(chunk)
            return sha.hexdigest()
        except (OSError, PermissionError):
            return ""
