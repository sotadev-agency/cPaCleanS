"""Interfaz grafica de cPacleanS v2.5 — scoring, cache, log de fases, bloqueo de controles y cancelacion segura."""
import os
import re
import sys
import threading
import webbrowser
import multiprocessing
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk

from ..config.settings import (
    load_config, save_config, APP_NAME, APP_VERSION,
    SCAN_MODE_ONLY, CLEAN_MODE_NORMAL, CLEAN_MODE_INTERMEDIATE, CLEAN_MODE_STRICT,
)
from ..core.extractor import BackupExtractor
from ..core.engine import ScanEngine
from ..scanners.php_scanner import PHPScanner
from ..scanners.database_scanner import DatabaseScanner
from ..scanners.email_scanner import EmailScanner
from ..scanners.cms_scanner import CMSScanner
from ..scanners.yara_scanner import YaraScanner
from ..api.virustotal import VirusTotalClient
from ..report.generator import ReportGenerator
from ..core.cms_restorer import CMSRestorer
from ..core.packager import BackupPackager
from ..core.cms_plugin_cleaner import CMSPluginCleaner
from ..core.cms_full_wiper import CMSFullWiper
from ..cleaners.db_cleaner import DBCleaner
from ..cleaners.junk_cleaner import JunkCleaner
from ..cleaners.wordpress_cleaner import WordPressCleaner
from ..utils.db_utils import detect_prefix_from_config, detect_prefix_from_dump

SCANNER_CLASSES = [PHPScanner, DatabaseScanner, EmailScanner, CMSScanner, YaraScanner]

MODE_LABELS = {
    SCAN_MODE_ONLY: "Solo Escaneo (reporte sin modificar archivos)",
    CLEAN_MODE_NORMAL: "Normal (solo malware confirmado a cuarentena)",
    CLEAN_MODE_INTERMEDIATE: "Intermedio (confirmados + alta severidad a cuarentena)",
    CLEAN_MODE_STRICT: "Estricto (todos los sospechosos eliminados)",
}


class CpacleanSApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.config = load_config()
        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry("1050x780")
        self.minsize(900, 650)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self._scan_thread = None
        self._engine = None
        self._backup_info = None
        self._scan_result = None
        self._report_path = None
        self._pdf_path = None
        self._is_running = False
        self._critical_only = False  # capturado antes de lanzar el hilo

        self._build_ui()

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        # === Header ===
        header = ctk.CTkFrame(self, fg_color="#1a1a2e", corner_radius=10)
        header.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 4))

        ctk.CTkLabel(header, text=f"  {APP_NAME}",
                     font=ctk.CTkFont(size=24, weight="bold"),
                     text_color="#00d4ff").pack(side="left", padx=12, pady=8)
        ctk.CTkLabel(header, text=f"v{APP_VERSION}",
                     font=ctk.CTkFont(size=11), text_color="#6c7293").pack(side="left")
        ctk.CTkLabel(header, text=f"CPUs: {multiprocessing.cpu_count()}",
                     font=ctk.CTkFont(size=10), text_color="#4a5568").pack(side="left", padx=20)
        ctk.CTkButton(header, text="Config", width=70, command=self._open_settings,
                      fg_color="#2a2a4a", hover_color="#3a3a5a",
                      font=ctk.CTkFont(size=11)).pack(side="right", padx=12, pady=8)

        # === Panel de archivo + modo ===
        controls = ctk.CTkFrame(self, fg_color="#1a1a2e", corner_radius=10)
        controls.grid(row=1, column=0, sticky="ew", padx=12, pady=4)
        controls.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(controls, text="Backup:", font=ctk.CTkFont(size=12)).grid(row=0, column=0, padx=8, pady=6)
        self.file_entry = ctk.CTkEntry(controls, placeholder_text="Archivo .tar.gz, .zip o .gz de cPanel...")
        self.file_entry.grid(row=0, column=1, sticky="ew", padx=4, pady=6)
        self.browse_btn = ctk.CTkButton(controls, text="Explorar", width=80, command=self._browse_file,
                      fg_color="#0f3460", hover_color="#1a4f8a", font=ctk.CTkFont(size=11))
        self.browse_btn.grid(row=0, column=2, padx=4, pady=6)

        ctk.CTkLabel(controls, text="Modo:", font=ctk.CTkFont(size=12)).grid(row=1, column=0, padx=8, pady=6)
        self.mode_var = ctk.StringVar(value=SCAN_MODE_ONLY)
        mode_frame = ctk.CTkFrame(controls, fg_color="transparent")
        mode_frame.grid(row=1, column=1, columnspan=2, sticky="ew", padx=4, pady=4)
        self._mode_radios = []
        for mode_key, mode_label in MODE_LABELS.items():
            rb = ctk.CTkRadioButton(mode_frame, text=mode_label, variable=self.mode_var, value=mode_key,
                font=ctk.CTkFont(size=11), radiobutton_width=16, radiobutton_height=16)
            rb.pack(anchor="w", padx=8, pady=1)
            self._mode_radios.append(rb)

        # === Opciones ===
        opts = ctk.CTkFrame(self, fg_color="#1a1a2e", corner_radius=10)
        opts.grid(row=2, column=0, sticky="ew", padx=12, pady=4)

        self.restore_cms_var = ctk.BooleanVar(value=True)
        self.chk_restore = ctk.CTkCheckBox(opts, text="Restaurar CMS desde repos oficiales",
                        variable=self.restore_cms_var, font=ctk.CTkFont(size=11))
        self.chk_restore.pack(side="left", padx=12, pady=6)

        self.gen_pdf_var = ctk.BooleanVar(value=True)
        self.chk_pdf = ctk.CTkCheckBox(opts, text="Generar PDF para cliente",
                        variable=self.gen_pdf_var, font=ctk.CTkFont(size=11))
        self.chk_pdf.pack(side="left", padx=12, pady=6)

        self.critical_only_var = ctk.BooleanVar(value=False)
        self.chk_critical = ctk.CTkCheckBox(
            opts,
            text="Solo contenido critico\n(public_html, mail, SQL)",
            variable=self.critical_only_var,
            font=ctk.CTkFont(size=10),
            text_color="#33b5e5",
        )
        self.chk_critical.pack(side="left", padx=12, pady=6)

        self.cancel_btn = ctk.CTkButton(opts, text="CANCELAR", width=110, command=self._cancel_scan,
                                         state="disabled", fg_color="#cc3300", hover_color="#ff4400",
                                         font=ctk.CTkFont(size=13, weight="bold"))
        self.cancel_btn.pack(side="right", padx=6, pady=6)

        self.scan_btn = ctk.CTkButton(opts, text="INICIAR", width=140, command=self._start_scan,
                                       fg_color="#00a86b", hover_color="#00c878",
                                       font=ctk.CTkFont(size=15, weight="bold"))
        self.scan_btn.pack(side="right", padx=6, pady=6)

        # === Panel central ===
        center = ctk.CTkFrame(self, fg_color="#0d0d1a", corner_radius=10)
        center.grid(row=3, column=0, sticky="nsew", padx=12, pady=4)
        center.grid_columnconfigure(0, weight=1)
        center.grid_rowconfigure(1, weight=1)

        pf = ctk.CTkFrame(center, fg_color="transparent")
        pf.grid(row=0, column=0, sticky="ew", padx=10, pady=(8, 0))
        pf.grid_columnconfigure(0, weight=1)
        self.progress_bar = ctk.CTkProgressBar(pf, height=8)
        self.progress_bar.grid(row=0, column=0, sticky="ew")
        self.progress_bar.set(0)
        self.status_label = ctk.CTkLabel(pf, text="Listo", font=ctk.CTkFont(size=11), text_color="#8892b0")
        self.status_label.grid(row=1, column=0, sticky="w", pady=(2, 0))

        self.log_text = ctk.CTkTextbox(center, font=ctk.CTkFont(family="Consolas", size=11),
                                        fg_color="#0a0a14", text_color="#c0c0c0",
                                        border_width=0, corner_radius=8)
        self.log_text.grid(row=1, column=0, sticky="nsew", padx=10, pady=8)

        # === Barra inferior ===
        bottom = ctk.CTkFrame(self, fg_color="#1a1a2e", corner_radius=10)
        bottom.grid(row=4, column=0, sticky="ew", padx=12, pady=(4, 12))

        self.report_btn = ctk.CTkButton(bottom, text="Ver Reporte HTML", width=130,
                                         command=self._open_report, state="disabled",
                                         fg_color="#0f3460", font=ctk.CTkFont(size=11))
        self.report_btn.pack(side="left", padx=8, pady=8)
        self.pdf_btn = ctk.CTkButton(bottom, text="Ver PDF", width=80,
                                      command=self._open_pdf, state="disabled",
                                      fg_color="#0f3460", font=ctk.CTkFont(size=11))
        self.pdf_btn.pack(side="left", padx=4, pady=8)

        self.summary_label = ctk.CTkLabel(bottom, text="",
                                           font=ctk.CTkFont(size=12, weight="bold"), text_color="#00d4ff")
        self.summary_label.pack(side="right", padx=8, pady=8)

    # ---- Control de estado: bloquear/desbloquear toda la UI ----
    def _lock_ui(self):
        self._is_running = True
        self.scan_btn.configure(state="disabled")
        self.browse_btn.configure(state="disabled")
        self.file_entry.configure(state="disabled")
        self.chk_restore.configure(state="disabled")
        self.chk_pdf.configure(state="disabled")
        self.chk_critical.configure(state="disabled")
        for rb in self._mode_radios:
            rb.configure(state="disabled")
        self.report_btn.configure(state="disabled")
        self.pdf_btn.configure(state="disabled")
        self.cancel_btn.configure(state="normal")

    def _unlock_ui(self):
        self._is_running = False
        self.scan_btn.configure(state="normal")
        self.browse_btn.configure(state="normal")
        self.file_entry.configure(state="normal")
        self.chk_restore.configure(state="normal")
        self.chk_pdf.configure(state="normal")
        self.chk_critical.configure(state="normal")
        for rb in self._mode_radios:
            rb.configure(state="normal")
        self.cancel_btn.configure(state="disabled")

    def _browse_file(self):
        path = filedialog.askopenfilename(
            title="Seleccionar Backup cPanel",
            filetypes=[("Backups", "*.tar.gz *.tgz *.zip *.gz *.tar"), ("Todos", "*.*")])
        if path:
            self.file_entry.delete(0, "end")
            self.file_entry.insert(0, path)

    def _log(self, msg: str):
        self.log_text.insert("end", msg + "\n")
        self.log_text.see("end")

    def _log_phase(self, num, title):
        self._log(f"\n{'─'*50}")
        self._log(f"  FASE {num}: {title}")
        self._log(f"{'─'*50}")

    def _log_result(self, msg):
        self._log(f"  >> {msg}")

    def _log_detail(self, msg):
        self._log(f"     {msg}")

    def _update_progress(self, t, v):
        if t == "progress":
            self.progress_bar.set(v / 100)
        elif t == "status":
            self.status_label.configure(text=str(v))

    def _start_scan(self):
        if self._is_running:
            return
        backup_path = self.file_entry.get().strip()
        if not backup_path or not Path(backup_path).exists():
            messagebox.showerror("Error", "Seleccione un archivo de backup valido.")
            return

        # Capturar opciones antes de bloquear la UI (seguro desde el hilo principal)
        self._critical_only = self.critical_only_var.get()

        self._lock_ui()
        self.log_text.delete("1.0", "end")
        self.progress_bar.set(0)
        self._report_path = None
        self._pdf_path = None
        self.summary_label.configure(text="")

        self._scan_thread = threading.Thread(target=self._run_scan, args=(backup_path,), daemon=True)
        self._scan_thread.start()

    def _run_scan(self, backup_path: str):
        try:
            mode = self.mode_var.get()
            is_clean = mode != SCAN_MODE_ONLY
            clean_mode = mode if is_clean else None

            critical_only = self._critical_only
            self._safe_log(f"  {APP_NAME} v{APP_VERSION} | {MODE_LABELS.get(mode, mode)}")
            self._safe_log(f"  {multiprocessing.cpu_count()} CPUs | Backup: {Path(backup_path).name}")
            if critical_only:
                self._safe_log("  [MODO CRITICO] Solo public_html, mail y SQL seran escaneados")

            # ── FASE 1 ──
            self._safe_phase(1, "Extraccion del backup")
            self._safe_status("Extrayendo backup...")
            extractor = BackupExtractor(backup_path,
                progress_callback=lambda t, v: self.after(0, lambda: self._update_progress(t, v)))
            self._backup_info = extractor.extract()
            info = self._backup_info

            self._safe_result(f"Extraido: {info.total_files} archivos, {info.total_size_mb} MB")
            self._safe_detail(f"Usuario cPanel: {info.cpanel_user or 'N/A'}")
            self._safe_detail(f"MySQL: {'Si' if info.has_mysql else 'No'} | Email: {'Si' if info.has_email else 'No'}")
            if info.cms_detected:
                self._safe_detail(f"CMS detectados: {', '.join(c.upper() for c in info.cms_detected)}")
            if info.extraction_errors:
                self._safe_detail(f"Advertencias: {len(info.extraction_errors)} archivos con rutas largas (omitidos)")

            # ── FASE 2 ──
            self._safe_phase(2, "Escaneo de malware (multiprocessing)")
            self._safe_status("Escaneando archivos...")
            engine = ScanEngine(
                progress_callback=lambda t, v: self.after(0, lambda: self._update_progress(t, v)))
            self._engine = engine
            for cls in SCANNER_CLASSES:
                engine.register_scanner_class(cls)
            result = engine.scan_directory(info.extract_dir, backup_info=info, critical_only=critical_only)
            self._scan_result = result

            confirmed = sum(1 for f in result.findings if f.confirmed_malware)
            suspect = result.total_threats_found - confirmed
            self._safe_result(f"{result.total_files_scanned} archivos en {result.scan_duration_seconds}s ({result.workers_used} workers)")
            if result.omitted_paths_count:
                self._safe_detail(f"Modo critico: {result.omitted_paths_count} archivos de sistema omitidos (logs, ssl, ips, etc.)")
            self._safe_result(f"Detecciones: {result.total_threats_found} total")
            self._safe_detail(f"CONFIRMADOS (malware real): {confirmed}")
            self._safe_detail(f"Sospechosos (solo reporte): {suspect}")
            for sev in ["critical", "high", "medium", "low"]:
                c = result.summary_by_severity.get(sev, 0)
                if c:
                    self._safe_detail(f"{sev.upper()}: {c}")
            if result.scan_errors:
                self._safe_detail(f"Errores de lectura: {len(result.scan_errors)}")

            # ── FASE 3 ──
            vt_key = self.config.get("virustotal_api_key", "")
            if vt_key and result.findings:
                self._safe_phase(3, "Verificacion VirusTotal")
                self._safe_status("Consultando VirusTotal...")
                critical_files = list(set(
                    f.file_path for f in result.findings
                    if f.severity == "critical" and Path(f.file_path).suffix.lower() in (".php", ".js")
                ))[:10]
                if critical_files:
                    vt = VirusTotalClient(vt_key)
                    vt_mode = self.config.get("vt_mode", "confirm")
                    if vt_mode == "deep":
                        self._safe_detail("Modo profundo: subiendo archivos a VT...")
                        vt_results = []
                        for fp in critical_files[:5]:
                            r = vt.check_hash(fp)
                            if not r.detected and not r.error:
                                r = vt.upload_and_scan(fp)
                            vt_results.append(r)
                    else:
                        vt_results = vt.batch_check(critical_files)
                    hits = [r for r in vt_results if r.detected]
                    result.virustotal_hits = hits
                    self._safe_result(f"VirusTotal ({vt_mode}): {len(hits)} detecciones en {len(critical_files)} archivos")

            # ── FASE 4 ──
            if is_clean:
                self._safe_phase(4, f"Limpieza ({clean_mode})")
                self._safe_status(f"Limpiando modo {clean_mode}...")
                quarantine_base = str(Path(backup_path).parent)
                cleaned = engine.clean_findings(quarantine_base, mode=clean_mode)
                self._safe_result(f"Malware en cuarentena: {cleaned} archivos")

                # Archivos 0KB
                zero_count = engine.clean_zero_byte_files(info.extract_dir, mode=clean_mode)
                if zero_count:
                    self._safe_result(f"Archivos 0KB removidos: {zero_count}")

                # v2.6.1: Pre-wipe WP detection (antes de borrar version.php)
                wp_info = {}
                if info.cms_detected and "wordpress" in info.cms_detected:
                    self._safe_status("Pre-wipe: detectando version WP y tema activo...")
                    wp_cleaner = WordPressCleaner(
                        extract_dir=info.extract_dir,
                        quarantine_dir=result.quarantine_dir or str(Path(backup_path).parent / "cuarentena"),
                        clean_mode=clean_mode,
                        backup_info=info,
                        progress_callback=lambda t, v: self.after(0, lambda: self._update_progress(t, v)),
                    )
                    wp_info = wp_cleaner.pre_wipe_detect()
                    if wp_info.get("versions"):
                        for rk, ver in wp_info["versions"].items():
                            self._safe_detail(f"[WP] Version detectada: {ver}")
                    if wp_info.get("active_themes"):
                        for rk, theme in wp_info["active_themes"].items():
                            self._safe_detail(f"[WP] Tema activo: {theme}")

                # v2.6.0: WIPE completo de CMS antes de restaurar
                if info.cms_detected:
                    self._safe_status("Wipe CMS: eliminando archivos infectados...")
                    wiper = CMSFullWiper(
                        extract_dir=info.extract_dir,
                        cms_detected=info.cms_detected,
                        clean_mode=clean_mode,
                        progress_callback=lambda t, v: self.after(0, lambda: self._update_progress(t, v)),
                    )
                    wipe_result = wiper.wipe()
                    result.wipe_result = wipe_result
                    for cms_name, stats in wipe_result.items():
                        files_rm = stats.get("files_removed", 0)
                        dirs_rm = stats.get("dirs_removed", 0)
                        if files_rm or dirs_rm:
                            self._safe_result(f"[WIPER] {cms_name.upper()}: {files_rm} archivos, {dirs_rm} dirs eliminados")
                        preserved = stats.get("preserved", [])
                        if preserved:
                            self._safe_detail(f"Preservados: {len(preserved)} archivos/dirs")

                # v2.6.1: Post-wipe WP cleanup (core + tema + residuos)
                if wp_info and "wordpress" in info.cms_detected:
                    self._safe_status("Post-wipe: instalando core WP y tema activo...")
                    wp_cleaner = WordPressCleaner(
                        extract_dir=info.extract_dir,
                        quarantine_dir=result.quarantine_dir or str(Path(backup_path).parent / "cuarentena"),
                        clean_mode=clean_mode,
                        backup_info=info,
                        progress_callback=lambda t, v: self.after(0, lambda: self._update_progress(t, v)),
                    )
                    wp_stats = wp_cleaner.post_wipe_clean(wp_info)
                    # Agregar log de WP cleaner al restore log
                    result.cms_restore_log = result.cms_restore_log or []
                    result.cms_restore_log.extend(wp_cleaner.log)
                    if wp_stats.get("core_installed"):
                        self._safe_result(f"[WP] Core {wp_stats['core_version']} instalado")
                    if wp_stats.get("theme_installed"):
                        self._safe_result(f"[WP] Tema '{wp_stats['theme_slug']}' instalado")
                    if wp_stats.get("cleaned_files"):
                        self._safe_detail(f"[WP] Residuos limpiados: {wp_stats['cleaned_files']}")
                    if wp_stats.get("cleaned_empty_dirs"):
                        self._safe_detail(f"[WP] Carpetas vacias eliminadas: {wp_stats['cleaned_empty_dirs']}")
                    if wp_stats.get("dirs_ensured"):
                        self._safe_detail(f"[WP] Dirs wp-content creados: {wp_stats['dirs_ensured']}")

            # ── FASE 5: Restauracion CMS (post-wipe) ──
            if self.restore_cms_var.get() and info.cms_detected and is_clean:
                self._safe_phase(5, "Restauracion de CMS")
                self._safe_status("Restaurando desde repositorios oficiales...")
                restorer = CMSRestorer(info.extract_dir,
                    progress_callback=lambda t, v: self.after(0, lambda: self._update_progress(t, v)))
                restore_log = restorer.restore_all(info.cms_detected, backup_info=info)
                result.cms_restore_log = restore_log
                ok = sum(1 for e in restore_log if e["type"] == "success")
                warn = sum(1 for e in restore_log if e["type"] == "warning")
                self._safe_result(f"CMS: {ok} restaurados, {warn} advertencias")
                for entry in restore_log:
                    if entry["type"] in ("success", "error"):
                        icon = "[OK]" if entry["type"] == "success" else "[X]"
                        self._safe_detail(f"{icon} {entry['message'][:90]}")

            # ── FASE 5b: Plugins/Temas + JunkCleaner + DBCleaner ──
            if is_clean:
                # Detectar prefijos de BD para CMS
                db_paths = info.structure.get("databases", [])
                detected_prefixes = {}
                if info.cms_detected and db_paths:
                    from ..core.cms_plugin_cleaner import _CMS_ROOT_MARKERS
                    for cms_name in info.cms_detected:
                        if cms_name not in _CMS_ROOT_MARKERS:
                            continue
                        for website_root in info.structure.get("websites", []):
                            prefix = detect_prefix_from_config(cms_name, website_root)
                            if prefix:
                                detected_prefixes[cms_name] = prefix
                                self._safe_detail(f"[{cms_name.upper()}] Prefijo BD: {prefix}")
                                break
                        if cms_name not in detected_prefixes:
                            for dp in db_paths:
                                prefix = detect_prefix_from_dump(dp, cms_name)
                                if prefix:
                                    detected_prefixes[cms_name] = prefix
                                    self._safe_detail(f"[{cms_name.upper()}] Prefijo BD (dump): {prefix}")
                                    break
                    result.db_prefixes = detected_prefixes

                # Plugins/temas con filtro de reputacion v2.6.0
                if info.cms_detected and result.quarantine_dir:
                    plugin_cleaner = CMSPluginCleaner(
                        extract_dir=info.extract_dir,
                        quarantine_dir=result.quarantine_dir,
                        clean_mode=clean_mode,
                        progress_callback=lambda t, v: self.after(0, lambda: self._update_progress(t, v)),
                        db_paths=db_paths,
                    )
                    pt_counts = plugin_cleaner.process(info.cms_detected)
                    result.plugins_temas_log = plugin_cleaner.removal_log
                    if not result.db_prefixes:
                        result.db_prefixes = plugin_cleaner.get_detected_prefixes()
                    if pt_counts["total"] > 0:
                        action_word = "eliminados" if clean_mode == "strict" else "en cuarentena"
                        self._safe_result(f"Plugins/temas {action_word}: {pt_counts['total']}")
                        for cms, n in pt_counts["by_cms"].items():
                            if n:
                                self._safe_detail(f"{cms.upper()}: {n} extensiones")
                        reinstalled = sum(1 for e in plugin_cleaner.removal_log
                                          if e.get("reinstalled", {}).get("status") == "reinstalled")
                        not_in_repo = sum(1 for e in plugin_cleaner.removal_log
                                          if e.get("reinstalled", {}).get("status") == "not_in_repo")
                        skipped = sum(1 for e in plugin_cleaner.removal_log
                                      if e.get("reinstalled", {}).get("status") == "not_reinstalled")
                        if reinstalled:
                            self._safe_detail(f"Reinstalados desde repo oficial: {reinstalled}")
                        if not_in_repo:
                            self._safe_detail(f"No en repo oficial (reinstalar manual): {not_in_repo}")
                        if skipped:
                            self._safe_detail(f"No reinstalados (filtro reputacion): {skipped}")
                        if clean_mode != "strict":
                            self._safe_detail("Ver REINSTALAR_PLUGINS.txt en cuarentena/plugins_temas/")

                # v2.6.0: JunkCleaner — archivos residuales
                if info.cms_detected and result.quarantine_dir:
                    self._safe_status("Limpiando archivos residuales...")
                    junk_cleaner = JunkCleaner(
                        extract_dir=info.extract_dir,
                        quarantine_dir=result.quarantine_dir,
                        clean_mode=clean_mode,
                        progress_callback=lambda t, v: self.after(0, lambda: self._update_progress(t, v)),
                    )
                    junk_log = junk_cleaner.process(info.cms_detected)
                    result.junk_files_log = junk_log
                    if junk_log:
                        acted = sum(1 for j in junk_log if j["action"] != "logged_only")
                        self._safe_result(f"Archivos residuales: {len(junk_log)} encontrados, {acted} procesados")

                # Limpieza de BD (filas maliciosas + SPAM v2.6.0)
                if db_paths and info.cms_detected and result.quarantine_dir:
                    self._safe_status("Limpiando base de datos...")
                    db_cleaner = DBCleaner(
                        extract_dir=info.extract_dir,
                        cms_detected=info.cms_detected,
                        prefixes=detected_prefixes,
                        clean_mode=clean_mode,
                        progress_callback=lambda t, v: self.after(0, lambda: self._update_progress(t, v)),
                    )
                    db_interventions = db_cleaner.process(db_paths)
                    result.db_interventions_log = db_interventions

                    # Separar spam posts del log general
                    spam_posts = [i for i in db_interventions if i.get("type") == "spam_post"]
                    result.spam_posts_log = spam_posts
                    non_spam = [i for i in db_interventions if i.get("type") != "spam_post"]

                    if non_spam:
                        deleted = sum(1 for i in non_spam if "deleted" in i.get("type", "") or "removed" in i.get("type", ""))
                        suspicious = sum(1 for i in non_spam if i.get("type") == "suspicious")
                        self._safe_result(f"BD: {deleted} filas eliminadas, {suspicious} sospechosas")
                    if spam_posts:
                        spam_deleted = sum(1 for s in spam_posts if s.get("action") == "deleted")
                        self._safe_result(f"Posts SPAM: {len(spam_posts)} detectados, {spam_deleted} eliminados")

                self._safe_detail(f"Cuarentena: {result.quarantine_dir}")

            # ── FASE 6 ──
            phase_n = 6 if is_clean else 3
            self._safe_phase(phase_n, "Generacion de reportes")
            self._safe_status("Generando reportes...")
            report_dir = Path(backup_path).parent / "reportes"
            gen = ReportGenerator(str(report_dir))
            self._report_path = gen.generate(result, backup_path)
            self._safe_result(f"HTML: {Path(self._report_path).name}")

            if self.gen_pdf_var.get():
                try:
                    self._pdf_path = gen.generate_pdf(result, backup_path)
                    self._safe_result(f"PDF: {Path(self._pdf_path).name}")
                except Exception as e:
                    self._safe_detail(f"PDF no generado: {e}")

            # ── FASE 7 ──
            if is_clean:
                _info = info
                _crit = critical_only
                self.after(0, lambda: self._ask_packaging(_info, backup_path, _crit))
            else:
                self._safe_log(f"\n{'='*50}")
                self._safe_log(f"  ESCANEO COMPLETADO")
                self._safe_log(f"{'='*50}")

            self.after(0, self._scan_finished)

        except Exception as e:
            self._safe_log(f"\n  ERROR: {e}")
            self._safe_status(f"Error: {e}")
            self.after(0, self._unlock_ui)

    def _ask_packaging(self, backup_info, backup_path, critical_only=False):
        PackagingDialog(self, backup_info.extract_dir, backup_path,
                        backup_info=backup_info, critical_only=critical_only,
                        log_cb=self._safe_result, detail_cb=self._safe_detail,
                        status_cb=self._safe_status, progress_cb=lambda t, v: self.after(0, lambda: self._update_progress(t, v)),
                        finish_cb=self._finish_packaging)

    def _do_package_targz(self, extract_dir, out_path):
        try:
            packager = BackupPackager(
                progress_callback=lambda t, v: self.after(0, lambda: self._update_progress(t, v)))
            out_path = str(out_path)
            result_path = packager.create_targz(extract_dir, out_path)
            size = round(Path(result_path).stat().st_size / (1024 * 1024), 1)
            self._safe_result(f"Archivo .tar.gz: {Path(result_path).name} ({size} MB)")
        except Exception as e:
            self._safe_detail(f"Error empaquetando: {e}")
        self.after(0, self._finish_packaging)

    def _do_package_cpanel_partial(self, extract_dir, backup_info, out_path):
        try:
            packager = BackupPackager(
                progress_callback=lambda t, v: self.after(0, lambda: self._update_progress(t, v)))
            result_path = packager.create_cpanel_partial_targz(extract_dir, backup_info, str(out_path))
            size = round(Path(result_path).stat().st_size / (1024 * 1024), 1)
            self._safe_result(f"Backup parcial cPanel: {Path(result_path).name} ({size} MB)")
            self._safe_detail("Importable en WHM > Backup > Restore a Full Backup")
        except Exception as e:
            self._safe_detail(f"Error generando backup parcial: {e}")
        self.after(0, self._finish_packaging)

    def _do_package_critical_mode(self, extract_dir, backup_info, name):
        """v2.6.0: Genera paquetes separados compatibles con cPanel Backup Restore."""
        try:
            packager = BackupPackager(
                progress_callback=lambda t, v: self.after(0, lambda: self._update_progress(t, v)))
            output_base = str(Path(self._backup_info.path if hasattr(self._backup_info, 'path') else '').parent
                             or Path.cwd())
            if backup_info:
                output_base = str(Path(backup_info.path).parent)

            # Obtener SQL files del backup_info
            sql_files = backup_info.structure.get("databases", []) if backup_info else []
            domain = name or "sitio"

            result = packager.create_critical_mode_output(
                extract_dir, sql_files, output_base, domain)

            if result.get("homedir_tar"):
                size = round(Path(result["homedir_tar"]).stat().st_size / (1024 * 1024), 1)
                self._safe_result(f"homedir_backup.tar.gz: {size} MB ({result['included_count']} archivos)")
            if result.get("databases"):
                self._safe_result(f"Bases de datos: {len(result['databases'])} archivos .sql.gz")
            if result.get("excluded_count"):
                self._safe_result(f"Cuarentena: {result['excluded_count']} archivos excluidos")

            # Instrucciones de importacion
            self._safe_log("")
            self._safe_log("  PASOS PARA RESTAURAR EN CPANEL:")
            self._safe_log("  " + "-" * 46)
            self._safe_log("  [1] Restaurar directorio home:")
            self._safe_log("      cPanel > Backup > Restore > Home Directory Backup")
            self._safe_log(f"      Archivo: homedir_backup.tar.gz")
            self._safe_log("")
            self._safe_log("  [2] Restaurar bases de datos (una por una):")
            self._safe_log("      cPanel > Backup > Restore > MySQL Database Backup")
            if result.get("databases"):
                for db_path in result["databases"]:
                    self._safe_log(f"      - {Path(db_path).name}")
            self._safe_log("")
            self._safe_log("  [3] Archivos excluidos en: cuarentena/")

            if self._scan_result:
                self._scan_result.critical_output_manifest = result

        except Exception as e:
            self._safe_detail(f"Error generando paquete critico: {e}")
        self.after(0, self._finish_packaging)

    def _do_copy_files(self, extract_dir, dest):
        try:
            packager = BackupPackager(
                progress_callback=lambda t, v: self.after(0, lambda: self._update_progress(t, v)))
            copied = packager.copy_clean_files(extract_dir, dest)
            self._safe_result(f"{copied} archivos copiados a {dest}")
        except Exception as e:
            self._safe_detail(f"Error copiando: {e}")
        self.after(0, self._finish_packaging)

    def _finish_packaging(self):
        self._safe_log(f"\n{'='*50}")
        self._safe_log(f"  PROCESO COMPLETADO")
        self._safe_log(f"{'='*50}")

    # ---- Log helpers thread-safe ----
    def _safe_log(self, msg):
        self.after(0, lambda: self._log(msg))

    def _safe_phase(self, num, title):
        self.after(0, lambda: self._log_phase(num, title))

    def _safe_result(self, msg):
        self.after(0, lambda: self._log_result(msg))

    def _safe_detail(self, msg):
        self.after(0, lambda: self._log_detail(msg))

    def _safe_status(self, msg):
        self.after(0, lambda: self._update_progress("status", msg))

    def _scan_finished(self):
        self._unlock_ui()
        self.progress_bar.set(1.0)

        if self._report_path:
            self.report_btn.configure(state="normal")
        if self._pdf_path:
            self.pdf_btn.configure(state="normal")

        if self._scan_result:
            confirmed = sum(1 for f in self._scan_result.findings if f.confirmed_malware)
            t = self._scan_result.total_threats_found
            c = self._scan_result.total_cleaned
            if c > 0:
                self.summary_label.configure(text=f"{c} cuarentena / {confirmed} confirmados / {t} total", text_color="#00d4ff")
            elif t > 0:
                self.summary_label.configure(text=f"{confirmed} confirmados / {t} total detectados", text_color="#ff8800")
            else:
                self.summary_label.configure(text="Sin amenazas", text_color="#00C851")
        self._update_progress("status", "Completado")

    def _open_report(self):
        if self._report_path and Path(self._report_path).exists():
            webbrowser.open(f"file:///{self._report_path}")

    def _open_pdf(self):
        if self._pdf_path and Path(self._pdf_path).exists():
            os.startfile(self._pdf_path)

    def _cancel_scan(self):
        if self._engine:
            self._engine.cancel()
            self._log("\n  >> Cancelado por el usuario")
            self._update_progress("status", "Cancelado")
            self._unlock_ui()

    def _open_settings(self):
        if not self._is_running:
            SettingsWindow(self, self.config)


class PackagingDialog(ctk.CTkToplevel):
    """Dialogo para elegir nombre y formato del archivo limpio."""
    def __init__(self, parent, extract_dir, backup_path,
                 log_cb, detail_cb, status_cb, progress_cb, finish_cb,
                 backup_info=None, critical_only=False):
        super().__init__(parent)
        self.extract_dir  = extract_dir
        self.backup_path  = backup_path
        self.backup_info  = backup_info
        self.critical_only = critical_only
        self.log_cb       = log_cb
        self.detail_cb    = detail_cb
        self.status_cb    = status_cb
        self.progress_cb  = progress_cb
        self.finish_cb    = finish_cb
        self.parent_app   = parent

        self.title("Empaquetar resultado")
        height = 340 if critical_only else 280
        self.geometry(f"580x{height}")
        self.transient(parent)
        self.grab_set()

        default_name = re.sub(r'\.(tar\.gz|tgz|tar|zip|gz)$', '',
                               Path(backup_path).name, flags=re.IGNORECASE) + "-limpio"

        frame = ctk.CTkFrame(self, fg_color="#1a1a2e", corner_radius=10)
        frame.pack(fill="both", expand=True, padx=12, pady=12)

        ctk.CTkLabel(frame, text="Limpieza completada", font=ctk.CTkFont(size=15, weight="bold"),
                     text_color="#00d4ff").pack(pady=(12, 8))

        ctk.CTkLabel(frame, text="Nombre del archivo de salida:", anchor="w",
                     font=ctk.CTkFont(size=11)).pack(padx=16, anchor="w")
        self.name_entry = ctk.CTkEntry(frame, width=440, placeholder_text=default_name)
        self.name_entry.pack(padx=16, pady=(0, 8))
        self.name_entry.insert(0, default_name)

        ctk.CTkLabel(frame, text="Formato de salida:", anchor="w",
                     font=ctk.CTkFont(size=11)).pack(padx=16, anchor="w", pady=(4, 0))

        btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
        btn_frame.pack(pady=8)

        ctk.CTkButton(btn_frame, text="Generar .tar.gz\n(completo, para cPanel)", width=170, height=50,
                      command=self._do_targz, fg_color="#00a86b", hover_color="#00c878",
                      font=ctk.CTkFont(size=12)).pack(side="left", padx=6)
        ctk.CTkButton(btn_frame, text="Copiar a carpeta", width=130, height=50,
                      command=self._do_copy, fg_color="#0f3460", hover_color="#1a4f8a",
                      font=ctk.CTkFont(size=12)).pack(side="left", padx=6)
        ctk.CTkButton(btn_frame, text="Solo reportes", width=110, height=50,
                      command=self._do_skip, fg_color="#555", hover_color="#777",
                      font=ctk.CTkFont(size=12)).pack(side="left", padx=6)

        if critical_only:
            ctk.CTkLabel(frame,
                text="Modo Solo Contenido Critico activo:",
                anchor="w", font=ctk.CTkFont(size=11), text_color="#33b5e5",
            ).pack(padx=16, anchor="w", pady=(10, 2))
            btn_frame2 = ctk.CTkFrame(frame, fg_color="transparent")
            btn_frame2.pack(pady=4)
            ctk.CTkButton(
                btn_frame2,
                text="Backup parcial cPanel\n(SQL + homedir + mail)",
                width=200, height=50,
                command=self._do_cpanel_partial,
                fg_color="#1a4f8a", hover_color="#1e5fa0",
                font=ctk.CTkFont(size=12),
            ).pack(side="left", padx=6)
            ctk.CTkLabel(
                btn_frame2,
                text="Importable directo\nen WHM > Restore",
                font=ctk.CTkFont(size=10), text_color="#8892b0",
            ).pack(side="left", padx=8)

    def _get_name(self):
        name = self.name_entry.get().strip()
        return name if name else Path(self.backup_path).name.split(".")[0] + "-limpio"

    def _do_targz(self):
        name = self._get_name()
        out_path = Path(self.backup_path).parent / f"{name}.tar.gz"
        self.destroy()
        threading.Thread(target=self.parent_app._do_package_targz,
                         args=(self.extract_dir, out_path), daemon=True).start()

    def _do_cpanel_partial(self):
        name = self._get_name() + "-critico"
        self.destroy()
        # v2.6.0: Usar create_critical_mode_output para paquetes compatibles cPanel
        threading.Thread(target=self.parent_app._do_package_critical_mode,
                         args=(self.extract_dir, self.backup_info, name),
                         daemon=True).start()

    def _do_copy(self):
        self.destroy()
        dest = filedialog.askdirectory(title="Seleccione carpeta destino")
        if dest:
            threading.Thread(target=self.parent_app._do_copy_files,
                             args=(self.extract_dir, dest), daemon=True).start()
        else:
            self.finish_cb()

    def _do_skip(self):
        self.destroy()
        self.finish_cb()


class SettingsWindow(ctk.CTkToplevel):
    def __init__(self, parent, config):
        super().__init__(parent)
        self.config = config
        self.title("Configuracion cPacleanS")
        self.geometry("560x780")
        self.transient(parent)
        self.grab_set()
        self._build()

    def _build(self):
        frame = ctk.CTkScrollableFrame(self, fg_color="#1a1a2e", corner_radius=10)
        frame.pack(fill="both", expand=True, padx=12, pady=12)
        ctk.CTkLabel(frame, text="Configuracion", font=ctk.CTkFont(size=16, weight="bold"),
                     text_color="#00d4ff").pack(pady=(8, 12))

        # ── VirusTotal ──
        ctk.CTkLabel(frame, text="VirusTotal API Key:", anchor="w",
                     font=ctk.CTkFont(size=12, weight="bold")).pack(padx=16, anchor="w")
        ctk.CTkLabel(frame, text="Gratuita: 500 consultas/dia, 4/min — suficiente para confirmar detecciones",
                     font=ctk.CTkFont(size=10), text_color="#8892b0", wraplength=480).pack(padx=16, anchor="w")
        ctk.CTkLabel(frame, text="Premium: sin limites, analisis profundo con upload de archivos sospechosos",
                     font=ctk.CTkFont(size=10), text_color="#8892b0", wraplength=480).pack(padx=16, anchor="w")
        self.vt_entry = ctk.CTkEntry(frame, width=460, show="*", placeholder_text="Obtener en virustotal.com > Perfil > API key")
        self.vt_entry.pack(padx=16, pady=(4, 2))
        if self.config.get("virustotal_api_key"):
            self.vt_entry.insert(0, self.config["virustotal_api_key"])

        vt_btn_row = ctk.CTkFrame(frame, fg_color="transparent")
        vt_btn_row.pack(padx=16, anchor="w", pady=(2, 8))
        ctk.CTkButton(vt_btn_row, text="Mostrar/ocultar", width=120,
                      command=self._toggle_vt_visibility,
                      fg_color="#2a2a4a", hover_color="#3a3a5a",
                      font=ctk.CTkFont(size=10)).pack(side="left", padx=(0, 6))
        ctk.CTkButton(vt_btn_row, text="Validar key →", width=110,
                      command=self._validate_vt_key,
                      fg_color="#0f3460", hover_color="#1a4f8a",
                      font=ctk.CTkFont(size=10)).pack(side="left", padx=(0, 8))
        self.vt_status = ctk.CTkLabel(vt_btn_row, text="",
                                       font=ctk.CTkFont(size=10), text_color="#8892b0")
        self.vt_status.pack(side="left")

        self.vt_mode_var = ctk.StringVar(value=self.config.get("vt_mode", "confirm"))
        vt_frame = ctk.CTkFrame(frame, fg_color="transparent")
        vt_frame.pack(padx=16, anchor="w", pady=(0, 10))
        ctk.CTkRadioButton(vt_frame, text="Solo confirmar (rapido, consulta hashes)",
                           variable=self.vt_mode_var, value="confirm",
                           font=ctk.CTkFont(size=10)).pack(anchor="w")
        ctk.CTkRadioButton(vt_frame, text="Profundo (sube archivos sospechosos a VT para analisis completo)",
                           variable=self.vt_mode_var, value="deep",
                           font=ctk.CTkFont(size=10)).pack(anchor="w")

        # ── Rendimiento ──
        ctk.CTkLabel(frame, text="Rendimiento:", anchor="w",
                     font=ctk.CTkFont(size=12, weight="bold")).pack(padx=16, anchor="w", pady=(6, 0))

        ctk.CTkLabel(frame, text="Tamano maximo de archivo a escanear (MB):", anchor="w",
                     font=ctk.CTkFont(size=10)).pack(padx=16, anchor="w")
        self.size_entry = ctk.CTkEntry(frame, width=80)
        self.size_entry.pack(padx=16, anchor="w", pady=(0, 6))
        self.size_entry.insert(0, str(self.config.get("max_file_size_mb", 50)))

        max_cpu = multiprocessing.cpu_count()
        ctk.CTkLabel(frame, text=f"Workers de escaneo (CPUs disponibles: {max_cpu}):", anchor="w",
                     font=ctk.CTkFont(size=10)).pack(padx=16, anchor="w")
        self.workers_slider = ctk.CTkSlider(frame, from_=1, to=max_cpu, number_of_steps=max(1, max_cpu - 1), width=300)
        self.workers_slider.pack(padx=16, anchor="w", pady=(0, 2))
        self.workers_slider.set(self.config.get("scan_workers", max(1, max_cpu - 1)))
        self.workers_label = ctk.CTkLabel(frame, text=f"{int(self.workers_slider.get())} workers",
                                           font=ctk.CTkFont(size=10), text_color="#8892b0")
        self.workers_label.pack(padx=16, anchor="w", pady=(0, 8))
        self.workers_slider.configure(command=lambda v: self.workers_label.configure(text=f"{int(v)} workers"))

        # ── Scoring ──
        ctk.CTkLabel(frame, text="Scoring:", anchor="w",
                     font=ctk.CTkFont(size=12, weight="bold")).pack(padx=16, anchor="w", pady=(6, 0))
        ctk.CTkLabel(frame, text="Threshold de confirmacion (score >= threshold = malware confirmado):",
                     font=ctk.CTkFont(size=10)).pack(padx=16, anchor="w")
        self.threshold_slider = ctk.CTkSlider(frame, from_=20, to=95, number_of_steps=15, width=300)
        self.threshold_slider.pack(padx=16, anchor="w", pady=(0, 2))
        self.threshold_slider.set(self.config.get("confidence_threshold", 70))
        self.threshold_label = ctk.CTkLabel(frame,
            text=f"Threshold: {int(self.threshold_slider.get())}  (>=70 estricto, >=50 permisivo)",
            font=ctk.CTkFont(size=10), text_color="#8892b0")
        self.threshold_label.pack(padx=16, anchor="w", pady=(0, 8))
        self.threshold_slider.configure(
            command=lambda v: self.threshold_label.configure(
                text=f"Threshold: {int(v)}  (>=70 estricto, >=50 permisivo)"))

        # ── Filtrado ──
        ctk.CTkLabel(frame, text="Filtrado:", anchor="w",
                     font=ctk.CTkFont(size=12, weight="bold")).pack(padx=16, anchor="w", pady=(6, 0))
        ctk.CTkLabel(frame, text="Directorios excluidos del escaneo (separados por coma):",
                     font=ctk.CTkFont(size=10)).pack(padx=16, anchor="w")
        self.excluded_entry = ctk.CTkEntry(frame, width=460,
                     placeholder_text="vendor, node_modules, .git, tests, test, phpunit")
        self.excluded_entry.pack(padx=16, anchor="w", pady=(0, 8))
        current_excluded = ", ".join(self.config.get("excluded_dirs", []))
        if current_excluded:
            self.excluded_entry.insert(0, current_excluded)

        # ── Cache ──
        ctk.CTkLabel(frame, text="Cache de escaneo:", anchor="w",
                     font=ctk.CTkFont(size=12, weight="bold")).pack(padx=16, anchor="w", pady=(6, 0))
        cache_row = ctk.CTkFrame(frame, fg_color="transparent")
        cache_row.pack(padx=16, anchor="w", pady=(0, 8))
        self.cache_stats_label = ctk.CTkLabel(cache_row, text="Cargando...",
                     font=ctk.CTkFont(size=10), text_color="#8892b0")
        self.cache_stats_label.pack(side="left", padx=(0, 12))
        ctk.CTkButton(cache_row, text="Limpiar cache", width=110,
                      command=self._clear_cache,
                      fg_color="#cc3300", hover_color="#ff4400",
                      font=ctk.CTkFont(size=10)).pack(side="left")
        self._refresh_cache_stats()

        # ── CMS ──
        ctk.CTkLabel(frame, text="CMS:", anchor="w",
                     font=ctk.CTkFont(size=12, weight="bold")).pack(padx=16, anchor="w", pady=(6, 0))
        self.restore_var = ctk.BooleanVar(value=self.config.get("restore_cms_core", True))
        ctk.CTkCheckBox(frame, text="Restaurar core/plugins/temas desde repositorios oficiales",
                        variable=self.restore_var, font=ctk.CTkFont(size=10)).pack(padx=16, anchor="w", pady=(0, 12))

        # ── Botones ──
        bf = ctk.CTkFrame(frame, fg_color="transparent")
        bf.pack(pady=8)
        ctk.CTkButton(bf, text="Guardar", width=110, command=self._save, fg_color="#00a86b").pack(side="left", padx=8)
        ctk.CTkButton(bf, text="Cancelar", width=110, command=self.destroy, fg_color="#555").pack(side="left", padx=8)

    def _toggle_vt_visibility(self):
        current = self.vt_entry.cget("show")
        self.vt_entry.configure(show="" if current == "*" else "*")

    def _validate_vt_key(self):
        import threading as _threading
        key = self.vt_entry.get().strip()
        if not key:
            self.vt_status.configure(text="Ingresa una key primero", text_color="#ffbb33")
            return
        self.vt_status.configure(text="Validando...", text_color="#8892b0")
        self.update()

        def do_check():
            try:
                import requests as _req
                # Consulta el hash de EICAR — siempre presente en VT
                resp = _req.get(
                    "https://www.virustotal.com/api/v3/files/"
                    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                    headers={"x-apikey": key},
                    timeout=12,
                )
                if resp.status_code == 200:
                    msg, color = "✓ Key valida", "#00C851"
                elif resp.status_code == 401:
                    msg, color = "✗ Key invalida (401)", "#ff4444"
                elif resp.status_code == 429:
                    msg, color = "✓ Valida (limite por minuto)", "#ffbb33"
                else:
                    msg, color = f"⚠ HTTP {resp.status_code}", "#ffbb33"
            except Exception as e:
                msg, color = f"✗ {str(e)[:32]}", "#ff4444"
            self.after(0, lambda: self.vt_status.configure(text=msg, text_color=color))

        _threading.Thread(target=do_check, daemon=True).start()

    def _save(self):
        self.config["virustotal_api_key"] = self.vt_entry.get().strip()
        self.config["vt_mode"] = self.vt_mode_var.get()
        try:
            self.config["max_file_size_mb"] = int(self.size_entry.get())
        except ValueError:
            pass
        self.config["scan_workers"] = int(self.workers_slider.get())
        self.config["confidence_threshold"] = int(self.threshold_slider.get())
        excluded_raw = self.excluded_entry.get().strip()
        self.config["excluded_dirs"] = [d.strip() for d in excluded_raw.split(",") if d.strip()] if excluded_raw else []
        self.config["restore_cms_core"] = self.restore_var.get()
        save_config(self.config)
        self.destroy()

    def _refresh_cache_stats(self):
        try:
            from ..utils.hash_cache import HashCache
            stats = HashCache().stats()
            self.cache_stats_label.configure(
                text=f"{stats['count']} archivos en cache, {stats['size_mb']} MB")
        except Exception:
            self.cache_stats_label.configure(text="Cache no disponible")

    def _clear_cache(self):
        try:
            from ..utils.hash_cache import HashCache
            HashCache().clear()
            self._refresh_cache_stats()
        except Exception:
            pass
