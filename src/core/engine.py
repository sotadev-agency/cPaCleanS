"""Motor de escaneo de alto rendimiento — pool de procesos con scanners persistentes."""
import os
import re
import math
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
    CPANEL_PROTECTED_DIRS, CONFIG_DIR, WP_TRUSTED_SLUGS,
)

CONFIRMED_MALWARE_CATEGORIES = {
    "webshell", "backdoor", "cryptominer", "dropper",
    "cms_upload_php", "cms_htaccess_override", "cms_index_hijack",
    "cms_ini_injection", "double_extension",
    "malicious_attachment",
    "htaccess_redirect", "htaccess_handler", "htaccess_php",
    "mailer_backdoor",  # v2.6.5: cfg.php con SPAM relay / phishing
    "userini_php",      # v3.1: auto_prepend/append en .user.ini
}

# v2.6.6: Drop-ins legitimos de WordPress que pueden vivir en wp-content/ (raiz).
# Cualquier OTRO .php en wp-content (fuera de plugins/ y themes/) se cuarentena.
_WPCONTENT_CORE_PHP = frozenset({
    "index.php",            # stub "silence is golden" de proteccion
    "advanced-cache.php",   # drop-in de cache
    "object-cache.php",     # drop-in de object cache
    "db.php",               # drop-in de base de datos
    "sunrise.php",          # drop-in multisite
    "blog-deleted.php", "blog-inactive.php", "blog-suspended.php",
})

# v2.6.6: subdirectorios de wp-content cuyo .php gestiona el flujo separar+reinstalar
# (NO se tocan en clean_findings — se mueven completos a cuarentena pre-wipe y se
#  reinstalan limpios en fase 5; los premium se conservan en cuarentena).
_WPCONTENT_ADDON_DIRS = frozenset({"plugins", "themes"})


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
    confidence_score: int = 0


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
    # v2.3.0 — intervenciones en BD (filas eliminadas/sospechosas)
    db_interventions_log: list = field(default_factory=list)
    # v2.3.0 — prefijos de tablas detectados por CMS
    db_prefixes: dict = field(default_factory=dict)
    # v2.6.0 — archivos residuales eliminados
    junk_files_log: list = field(default_factory=list)
    # v2.6.0 — posts SPAM eliminados de BD WordPress
    spam_posts_log: list = field(default_factory=list)
    # v2.6.0 — resultado del wipe CMS
    wipe_result: dict = field(default_factory=dict)
    # v2.6.0 — manifiesto del empaquetado modo critico
    critical_output_manifest: dict = field(default_factory=dict)
    # v2.6.2 — backups aislados ANTES del escaneo (no son amenazas)
    backups_isolated_log: list = field(default_factory=list)
    # v2.6.6 — versiones WP detectadas pre-wipe (version.php se borra en el wipe;
    # se consumen en fase 5 para instalar el core correcto). {wp_root: version}
    wp_versions_prewipe: dict = field(default_factory=dict)
    # v2.6.7 — endurecimiento de BD y reporte
    db_cron_log: list = field(default_factory=list)        # eventos cron inseguros
    db_users_log: list = field(default_factory=list)       # usuarios limpiados
    generated_passwords: dict = field(default_factory=dict)  # contrasenas generadas
    db_very_infected: bool = False
    # v3.1 — indicadores de compromiso extraídos de findings
    iocs: dict = field(default_factory=dict)   # {"ips": [...], "urls": [...], "domains": [...]}


# --- Multiprocessing worker con scanners persistentes por proceso ---
_worker_scanners = None
_worker_cache = None


def _file_sha256(file_path):
    sha = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha.update(chunk)
        return sha.hexdigest()
    except (OSError, PermissionError):
        return ""


def _worker_init(scanner_classes, cache_db_path=None):
    global _worker_scanners, _worker_cache
    _worker_scanners = [cls() for cls in scanner_classes]
    if cache_db_path:
        try:
            from ..utils.hash_cache import HashCache
            _worker_cache = HashCache(cache_db_path)
        except Exception:
            _worker_cache = None
    else:
        _worker_cache = None


def _worker_scan_batch(file_batch):
    """Escanea un lote de archivos con scanners ya instanciados.
    v2.5.0: integra cache SHA256 — archivos identicos no se re-escanean."""
    results = []
    for file_path in file_batch:
        file_hash = ""
        # Cache lookup
        if _worker_cache:
            file_hash = _file_sha256(file_path)
            if file_hash:
                cached = _worker_cache.get(file_hash)
                if cached and cached["scan_result"] is not None:
                    for fd in cached["scan_result"]:
                        fd["file_path"] = file_path
                        fd["sha256"] = file_hash
                        results.append(Finding(**fd))
                    continue

        file_findings = []
        for scanner in _worker_scanners:
            try:
                r = scanner.scan(file_path)
                if r:
                    file_findings.extend(r)
            except Exception:
                pass

        if file_hash:
            for f in file_findings:
                f.sha256 = file_hash

        # Cache store
        if _worker_cache and file_hash:
            cache_data = [
                {"line_number": f.line_number, "severity": f.severity,
                 "category": f.category, "description": f.description,
                 "matched_pattern": f.matched_pattern, "context": f.context}
                for f in file_findings
            ] if file_findings else []
            _worker_cache.put(file_hash, cache_data)

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
        self._cache_db_path = str(CONFIG_DIR / "scan_cache.db")

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

    SEVERITY_WEIGHTS = {"critical": 40, "high": 25, "medium": 10, "low": 5, "info": 0}

    def _classify_findings(self):
        """Scoring de confianza 0-100 por finding.
        Threshold configurable determina confirmed_malware."""
        threshold = self.config.get("confidence_threshold", 70)

        hits_per_file = {}
        for f in self.result.findings:
            hits_per_file[f.file_path] = hits_per_file.get(f.file_path, 0) + 1

        entropy_cache = {}
        for f in self.result.findings:
            fp = f.file_path
            score = self.SEVERITY_WEIGHTS.get(f.severity, 0)

            if f.category in CONFIRMED_MALWARE_CATEGORIES:
                score += 15

            if fp not in entropy_cache:
                entropy_cache[fp] = self._file_entropy(fp)
            if entropy_cache[fp] > 6.0:
                score += 10

            count = hits_per_file.get(fp, 0)
            if count >= 3:
                score += 10 + (count - 3) * 5

            fp_norm = fp.replace("\\", "/").lower()
            if self._in_trusted_plugin(fp_norm):
                score -= 20
            if self._in_testing_dir(fp_norm):
                score -= 15

            f.confidence_score = max(0, min(100, score))
            f.confirmed_malware = f.confidence_score >= threshold

    @staticmethod
    def _file_entropy(file_path):
        try:
            with open(file_path, "rb") as f:
                data = f.read(65536)
            if not data:
                return 0.0
            freq = [0] * 256
            for b in data:
                freq[b] += 1
            length = len(data)
            return -sum(
                (c / length) * math.log2(c / length)
                for c in freq if c > 0
            )
        except (OSError, PermissionError):
            return 0.0

    @staticmethod
    def _in_trusted_plugin(fp_norm):
        for seg in ("plugins", "themes"):
            marker = f"/wp-content/{seg}/"
            idx = fp_norm.find(marker)
            if idx >= 0:
                slug = fp_norm[idx + len(marker):].split("/")[0]
                if slug in WP_TRUSTED_SLUGS:
                    return True
        return False

    @staticmethod
    def _in_testing_dir(fp_norm):
        return any(d in fp_norm for d in
                   ("/vendor/", "/node_modules/", "/tests/", "/test/", "/phpunit/", "/.git/"))

    def _scan_multiprocess(self, batches, total, workers):
        processed = 0
        with ProcessPoolExecutor(
            max_workers=workers,
            initializer=_worker_init,
            initargs=(self.scanner_classes, self._cache_db_path)
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
        """Recopila archivos via os.scandir recursivo (mas rapido que os.walk).
        Filtra extensiones y dirs excluidos durante el recorrido."""
        all_extensions = set()
        for exts in self.config["scan_extensions"].values():
            all_extensions.update(exts)

        max_size = self.config["max_file_size_mb"] * 1024 * 1024

        important_names = {
            ".htaccess", ".env", "wp-config.php", "configuration.php",
            "config.php", ".user.ini", "php.ini", "index.php",
        }

        compound_extensions = {e for e in all_extensions if e.count(".") > 1}
        excluded_dirs = {d.lower() for d in self.config.get("excluded_dirs", [])}

        files = []

        def _recurse(path):
            try:
                with os.scandir(path) as it:
                    for entry in it:
                        if entry.is_dir(follow_symlinks=False):
                            if entry.name.lower() not in excluded_dirs:
                                _recurse(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            name_lower = entry.name.lower()
                            ext = os.path.splitext(name_lower)[1]
                            has_compound = any(name_lower.endswith(ce) for ce in compound_extensions)
                            if (ext in all_extensions or has_compound
                                    or name_lower in important_names
                                    or name_lower.startswith(".")):
                                try:
                                    sz = entry.stat().st_size
                                    if 0 < sz <= max_size:
                                        files.append(entry.path)
                                except OSError:
                                    pass
            except (OSError, PermissionError):
                pass

        _recurse(str(directory))

        if critical_only:
            from .path_filter import filter_files
            return filter_files(files, critical_only=True, base_dir=str(directory))

        return files, 0

    def setup_quarantine(self, base_dir: str) -> str:
        """Crea (o reutiliza) la estructura de cuarentena.

        v2.6.2: Si quarantine_dir ya fue configurado por pre_scan_quarantine_setup(),
        reutiliza el directorio existente en lugar de crear uno nuevo con otro timestamp.
        Estructura unificada: originales_intactos/, amenazas_removidas/, archivos_0kb/,
        cms_components/ (era plugins_temas + plugins_temas_separados), backups/.
        """
        # Reutilizar si ya fue configurado (e.g., por pre_scan_quarantine_setup)
        if self.result.quarantine_dir:
            qdir = Path(self.result.quarantine_dir)
            if qdir.exists():
                # Asegurar subdirs requeridos
                for d in ("originales_intactos", "amenazas_removidas",
                          "archivos_0kb", "cms_components", "backups"):
                    (qdir / d).mkdir(exist_ok=True)
                return str(qdir)

        ts = time.strftime("%Y%m%d_%H%M%S")
        qdir = Path(base_dir) / f"cuarentena_{ts}"
        qdir.mkdir(parents=True, exist_ok=True)
        (qdir / "originales_intactos").mkdir(exist_ok=True)
        (qdir / "amenazas_removidas").mkdir(exist_ok=True)
        (qdir / "archivos_0kb").mkdir(exist_ok=True)
        # v2.6.2: estructura unificada — elimina plugins_temas_separados duplicado
        (qdir / "cms_components").mkdir(exist_ok=True)
        (qdir / "backups").mkdir(exist_ok=True)
        self.result.quarantine_dir = str(qdir)
        return str(qdir)

    def pre_scan_quarantine_setup(self, base_dir: str) -> str:
        """v2.6.2: Configura la cuarentena ANTES del escaneo.

        Permite aislar backups pre-scan sin requerir que el scan haya terminado.
        Llama a setup_quarantine() con la misma logica pero con nombre semantico.
        """
        return self.setup_quarantine(base_dir)

    def isolate_backups_pre_scan(self, extract_dir: str) -> list:
        """v2.6.2: Aísla dirs y archivos de backup ANTES del escaneo principal.

        Requiere que pre_scan_quarantine_setup() haya sido llamado antes.
        Los backups no son malware — se mueven a quarantine/backups/ para:
        - Evitar que el scanner PHP los analice innecesariamente
        - Mantenerlos disponibles para el usuario post-limpieza
        - No contabilizarlos como amenazas en el reporte

        Retorna lista de dicts {path, name, type, action} para el reporte.
        """
        if not self.result.quarantine_dir:
            return []
        from ..quarantine.manager import QuarantineManager
        qm = QuarantineManager(
            self.result.quarantine_dir,
            progress_callback=self.progress_callback,
        )
        log = qm.isolate_backups(extract_dir)
        self.result.backups_isolated_log = log
        return log

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

            if self._quarantine_or_delete(fp, originals_dir, removed_dir, mode):
                finding.cleaned = True
                already_processed.add(str(fp))
                cleaned += 1

        # v2.6.6 Mejora #1: mover/eliminar TODOS los .md hallados en la limpieza
        cleaned += self._sweep_markdown(originals_dir, removed_dir, mode, already_processed)

        # v2.6.6 Mejora #2: .php no-core dentro de wp-content (y todo .php en uploads/)
        cleaned += self._sweep_wpcontent_php(originals_dir, removed_dir, mode, already_processed)

        self.result.total_cleaned = cleaned
        return cleaned

    def _quarantine_or_delete(self, fp: Path, originals_dir: Path,
                              removed_dir: Path, mode: str) -> bool:
        """Copia el original a originales_intactos y mueve a amenazas_removidas
        (modo normal/intermedio) o elimina (estricto). Retorna True si tuvo exito.

        Nunca toca archivos core de cPanel necesarios para restore en WHM.
        """
        if not fp.exists():
            return False
        if self._is_cpanel_protected(str(fp)):
            self.progress_callback("status", f"[PROTEGIDO cPanel] {fp.name} — no cuarentenado")
            return False
        try:
            counter = 0
            dest_orig = originals_dir / fp.name
            dest_removed = removed_dir / fp.name
            while dest_orig.exists():
                counter += 1
                dest_orig = originals_dir / f"{fp.stem}_{counter}{fp.suffix}"
                dest_removed = removed_dir / f"{fp.stem}_{counter}{fp.suffix}"

            shutil.copy2(str(fp), str(dest_orig))
            if mode == CLEAN_MODE_STRICT:
                os.remove(str(fp))
            else:
                shutil.move(str(fp), str(dest_removed))
            return True
        except (OSError, PermissionError, shutil.Error):
            return False

    def _sweep_markdown(self, originals_dir: Path, removed_dir: Path,
                        mode: str, already_processed: set) -> int:
        """v2.6.6: cuarentena/elimina todos los archivos .md del extract_dir."""
        if not self._extract_dir:
            return 0
        count = 0
        for root, dirs, files in os.walk(self._extract_dir):
            for fname in files:
                if fname.lower().endswith(".md"):
                    fp = Path(root) / fname
                    if str(fp) in already_processed:
                        continue
                    if self._quarantine_or_delete(fp, originals_dir, removed_dir, mode):
                        already_processed.add(str(fp))
                        count += 1
        if count:
            self.progress_callback("status", f"Archivos .md removidos: {count}")
        return count

    def _sweep_wpcontent_php(self, originals_dir: Path, removed_dir: Path,
                             mode: str, already_processed: set) -> int:
        """v2.6.8 Bug #2: mover a cuarentena/eliminar .php sospechoso dentro de
        wp-content, PERO NO de plugins/ ni themes/ — esas carpetas las procesa por
        completo CMSPluginCleaner (separar + reinstalar limpio desde WP.org).

        Reglas:
          - plugins/ y themes/ (y todo su arbol): NO se tocan aqui.
          - wp-content/ raiz: .php que no sea drop-in core de WordPress.
          - uploads/ y subcarpetas: cualquier .php (jamas legitimo en uploads).
          - resto de subdirs (mu-plugins, languages, cache, carpetas no
            reconocidas...): cualquier .php salvo el index.php de proteccion.

        En modo normal/intermedio se mueve a cuarentena (recuperable); en estricto
        se elimina.
        """
        if not self._extract_dir:
            return 0
        count = 0
        for root, dirs, files in os.walk(self._extract_dir):
            rp = Path(root)
            if rp.name != "wp-content":
                continue
            # Recorrer el arbol completo de wp-content
            for sub_root, sub_dirs, sub_files in os.walk(rp):
                srp = Path(sub_root)
                rel_parts = srp.relative_to(rp).parts
                top = rel_parts[0].lower() if rel_parts else ""
                # NO tocar plugins/ ni themes/ (CMSPluginCleaner los gestiona)
                if top in _WPCONTENT_ADDON_DIRS:
                    continue
                in_uploads = top == "uploads"
                at_root = (srp == rp)
                for fname in sub_files:
                    if not fname.lower().endswith(".php"):
                        continue
                    fp = srp / fname
                    if str(fp) in already_processed:
                        continue
                    if in_uploads:
                        should = True  # uploads: ningun .php es legitimo
                    elif at_root:
                        should = fname.lower() not in _WPCONTENT_CORE_PHP
                    else:
                        # subdirs (mu-plugins, languages, cache, no reconocidas):
                        # cualquier .php salvo el index.php de proteccion
                        should = fname.lower() != "index.php"
                    if should and self._quarantine_or_delete(fp, originals_dir, removed_dir, mode):
                        already_processed.add(str(fp))
                        count += 1
        if count:
            self.progress_callback("status", f"PHP no-core en wp-content removidos: {count}")
        return count

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
        """Separa plugins/temas premium y sospechosos fuera del backup limpio.

        v2.6.2: Usa cms_components/wordpress/premium/ y cms_components/wordpress/sospechosos/
        en lugar de la estructura duplicada plugins_temas_separados/.
        """
        if not self.result.quarantine_dir:
            return {"premium": 0, "suspicious": 0}
        # v2.6.2: estructura unificada bajo cms_components/
        cms_base = Path(self.result.quarantine_dir) / "cms_components" / "wordpress"
        premium_dir = cms_base / "premium"
        suspicious_dir = cms_base / "sospechosos"
        premium_dir.mkdir(parents=True, exist_ok=True)
        suspicious_dir.mkdir(parents=True, exist_ok=True)

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

    def extract_iocs(self) -> dict:
        """v3.1: Extrae indicadores de compromiso (IPs, URLs, dominios) de los findings confirmados."""
        import re as _re
        _ip = _re.compile(r'\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}\b')
        _url = _re.compile(r'https?://[^\s\'"<>{}\[\]]{10,120}', _re.IGNORECASE)
        _dom = _re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
            r'+(?:com|net|org|io|ru|cn|tk|xyz|top|info|biz|cc|pw|su|ws|me|co|online)\b',
            _re.IGNORECASE,
        )
        _PRIVATE = ('127.', '10.', '192.168.', '172.16.', '172.17.',
                    '172.18.', '172.19.', '172.20.', '0.0.0.0', '255.')
        _SAFE_DOMS = frozenset({
            'wordpress.org', 'wp.com', 'github.com', 'php.net', 'google.com',
            'googleapis.com', 'jquery.com', 'jquery.org', 'bootstrapcdn.com',
            'cloudflare.com', 'cloudfront.net', 'amazonaws.com', 'paypal.com',
        })

        ips, urls, domains = set(), set(), set()
        for f in self.result.findings:
            if not f.confirmed_malware:
                continue
            text = f"{f.context} {f.matched_pattern} {f.description}"
            ips.update(_ip.findall(text))
            urls.update(_url.findall(text))
            domains.update(_dom.findall(text.lower()))

        public_ips = sorted(ip for ip in ips if not any(ip.startswith(p) for p in _PRIVATE))
        clean_urls = sorted(urls)[:50]
        clean_doms = sorted(
            d for d in domains
            if d not in _SAFE_DOMS and not any(s in d for s in _SAFE_DOMS)
        )[:30]

        self.result.iocs = {"ips": public_ips, "urls": clean_urls, "domains": clean_doms}
        return self.result.iocs

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
