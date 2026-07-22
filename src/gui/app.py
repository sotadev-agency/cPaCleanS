"""Interfaz gráfica de cPacleanS v3.0.2 — diseño profesional con tracker de fases."""
import os
import re
import threading
import traceback
import webbrowser
import multiprocessing
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk

from ..config.settings import (
    load_config, save_config, APP_NAME, APP_VERSION,
    SCAN_MODE_ONLY, CLEAN_MODE_NORMAL, CLEAN_MODE_INTERMEDIATE, CLEAN_MODE_STRICT,
)
from ..core.extractor import BackupExtractor, ExtractionCancelled
from ..core.engine import ScanEngine
from ..scanners.php_scanner import PHPScanner
from ..scanners.database_scanner import DatabaseScanner
from ..scanners.email_scanner import EmailScanner
from ..scanners.cms_scanner import CMSScanner
from ..scanners.yara_scanner import YaraScanner
from ..scanners.executable_scanner import ExecutableScanner
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

SCANNER_CLASSES = [PHPScanner, DatabaseScanner, EmailScanner, CMSScanner, YaraScanner, ExecutableScanner]

MODE_LABELS = {
    SCAN_MODE_ONLY:          "Solo Escaneo",
    CLEAN_MODE_NORMAL:       "Normal",
    CLEAN_MODE_INTERMEDIATE: "Intermedio",
    CLEAN_MODE_STRICT:       "Estricto",
}
MODE_HINTS = {
    SCAN_MODE_ONLY:          "reporte sin modificar archivos",
    CLEAN_MODE_NORMAL:       "solo malware confirmado → cuarentena",
    CLEAN_MODE_INTERMEDIATE: "confirmados + alta severidad → cuarentena",
    CLEAN_MODE_STRICT:       "todos los sospechosos eliminados",
}

# ── Paleta de colores (tema "security tool" oscuro) ──
BG_MAIN  = "#0d1117"
BG_PANEL = "#161b22"
BG_CARD  = "#21262d"
BORDER   = "#30363d"
T_PRI    = "#e6edf3"
T_MUT    = "#8b949e"
BLUE     = "#58a6ff"
GREEN    = "#3fb950"
YELLOW   = "#d29922"
RED      = "#f85149"
ORANGE   = "#ffa657"
CYAN     = "#79c0ff"

PHASES = [
    (0, "Validar backup"),
    (1, "Extraer backup"),
    (2, "Pre-scan"),
    (3, "Escaneo"),
    (4, "Enriquecimiento"),
    (5, "Limpieza"),
    (6, "Restaurar CMS"),
    (7, "Base de datos"),
    (8, "Reportes"),
    (9, "Empaquetar"),
]

# Peso relativo de cada fase sobre el total del proceso (suma ≈ 100)
PHASE_WEIGHTS = {
    0: 0.5,   # Validar: instantáneo
    1: 10.0,  # Extraer: proporcional al tamaño
    2: 1.0,   # Pre-scan: cuarentena rápida
    3: 35.0,  # Escaneo: la fase más larga
    4: 5.0,   # Enriquecimiento: VT + IoC
    5: 8.0,   # Limpieza: mover archivos
    6: 25.0,  # Restaurar CMS: descarga de repos
    7: 8.0,   # BD + junk
    8: 3.0,   # Reportes
    9: 4.5,   # Empaquetar
}


class CpacleanSApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.config = load_config()
        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry("1150x800")
        self.minsize(960, 680)
        self._center_on_screen(1150, 800)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.configure(fg_color=BG_MAIN)

        self._scan_thread = None
        self._engine = None
        self._extractor = None
        self._backup_info = None
        self._scan_result = None
        self._report_path = None
        self._pdf_path = None
        self._json_path = None
        self._is_running = False
        self._critical_only = False

        # Phase tracker widgets
        self._phase_icons  = {}
        self._phase_labels = {}

        # Timing / progreso global
        self._scan_start_time = 0.0
        self._current_phase = -1
        self._phase_start_time = 0.0
        self._phase_progress = 0  # 0-100 dentro de la fase actual

        self._build_ui()

    # ─────────────────────────── UI BUILDER ───────────────────────────────

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        self._build_header()
        self._build_file_row()
        self._build_center()
        self._build_bottom()

    def _build_header(self):
        hdr = ctk.CTkFrame(self, fg_color=BG_PANEL, corner_radius=0, border_width=0)
        hdr.grid(row=0, column=0, sticky="ew")

        inner = ctk.CTkFrame(hdr, fg_color="transparent")
        inner.pack(fill="x", padx=16, pady=8)

        # Logo + title
        logo = ctk.CTkLabel(inner, text="◈", font=ctk.CTkFont(size=22, weight="bold"),
                            text_color=BLUE)
        logo.pack(side="left")
        ctk.CTkLabel(inner, text=f"  {APP_NAME}",
                     font=ctk.CTkFont(size=20, weight="bold"),
                     text_color=T_PRI).pack(side="left")
        ctk.CTkLabel(inner, text=f"  v{APP_VERSION}",
                     font=ctk.CTkFont(size=11), text_color=T_MUT).pack(side="left")
        ctk.CTkLabel(inner, text=f"  •  {multiprocessing.cpu_count()} CPUs",
                     font=ctk.CTkFont(size=10), text_color=T_MUT).pack(side="left")

        # Right buttons
        ctk.CTkButton(inner, text="⚙  Config", width=90, height=30,
                      command=self._open_settings,
                      fg_color=BG_CARD, hover_color=BORDER,
                      text_color=T_PRI, border_color=BORDER, border_width=1,
                      font=ctk.CTkFont(size=11)).pack(side="right", padx=4)

        # Separator line
        sep = ctk.CTkFrame(hdr, height=1, fg_color=BORDER)
        sep.pack(fill="x")

    def _build_file_row(self):
        row = ctk.CTkFrame(self, fg_color=BG_PANEL, corner_radius=0)
        row.grid(row=1, column=0, sticky="ew")

        sep_top = ctk.CTkFrame(row, height=1, fg_color=BORDER)
        sep_top.pack(fill="x")

        inner = ctk.CTkFrame(row, fg_color="transparent")
        inner.pack(fill="x", padx=16, pady=10)
        inner.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(inner, text="Backup:", font=ctk.CTkFont(size=12, weight="bold"),
                     text_color=T_MUT, width=60, anchor="w").grid(row=0, column=0, padx=(0, 8))

        self.file_entry = ctk.CTkEntry(
            inner,
            placeholder_text="Seleccione archivo .tar.gz, .tgz, .zip de cPanel...",
            fg_color=BG_CARD, border_color=BORDER, text_color=T_PRI,
            placeholder_text_color=T_MUT, font=ctk.CTkFont(size=11),
        )
        self.file_entry.grid(row=0, column=1, sticky="ew", padx=(0, 8))

        self.browse_btn = ctk.CTkButton(
            inner, text="Examinar", width=90, height=32,
            command=self._browse_file,
            fg_color=BG_CARD, hover_color=BORDER,
            text_color=BLUE, border_color=BORDER, border_width=1,
            font=ctk.CTkFont(size=11),
        )
        self.browse_btn.grid(row=0, column=2)

        sep_bot = ctk.CTkFrame(row, height=1, fg_color=BORDER)
        sep_bot.pack(fill="x")

    def _build_center(self):
        center = ctk.CTkFrame(self, fg_color=BG_MAIN, corner_radius=0)
        center.grid(row=2, column=0, sticky="nsew")
        center.grid_columnconfigure(1, weight=1)
        center.grid_rowconfigure(0, weight=1)

        # ── Left sidebar ──
        sidebar = ctk.CTkFrame(center, fg_color=BG_PANEL, corner_radius=0,
                               width=220, border_width=0)
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)

        sep_r = ctk.CTkFrame(center, width=1, fg_color=BORDER, corner_radius=0)
        sep_r.grid(row=0, column=0, sticky="nse")

        self._build_sidebar(sidebar)

        # ── Main log area ──
        log_frame = ctk.CTkFrame(center, fg_color=BG_MAIN, corner_radius=0)
        log_frame.grid(row=0, column=1, sticky="nsew")
        log_frame.grid_rowconfigure(0, weight=1)
        log_frame.grid_columnconfigure(0, weight=1)

        self.log_text = ctk.CTkTextbox(
            log_frame,
            font=ctk.CTkFont(family="Consolas", size=11),
            fg_color=BG_MAIN,
            text_color=T_PRI,
            border_width=0,
            corner_radius=0,
            scrollbar_button_color=BG_CARD,
            scrollbar_button_hover_color=BORDER,
        )
        self.log_text.grid(row=0, column=0, sticky="nsew", padx=(12, 4), pady=8)
        self.log_text.tag_config("phase",   foreground=CYAN)
        self.log_text.tag_config("result",  foreground=GREEN)
        self.log_text.tag_config("detail",  foreground=T_MUT)
        self.log_text.tag_config("error",   foreground=RED)
        self.log_text.tag_config("warning", foreground=YELLOW)
        self.log_text.tag_config("info",    foreground=BLUE)

    def _build_sidebar(self, parent):
        scroll = ctk.CTkScrollableFrame(parent, fg_color="transparent",
                                        scrollbar_button_color=BG_CARD,
                                        scrollbar_button_hover_color=BORDER)
        scroll.pack(fill="both", expand=True, padx=0, pady=0)

        # ── PROCESO ──
        self._sb_section(scroll, "PROCESO")
        for phase_num, phase_name in PHASES:
            row = ctk.CTkFrame(scroll, fg_color="transparent")
            row.pack(fill="x", padx=10, pady=1)

            icon = ctk.CTkLabel(row, text="○", width=18,
                                font=ctk.CTkFont(size=12, weight="bold"),
                                text_color=T_MUT)
            icon.pack(side="left")
            lbl = ctk.CTkLabel(row, text=f" {phase_name}",
                               font=ctk.CTkFont(size=10),
                               text_color=T_MUT, anchor="w")
            lbl.pack(side="left", fill="x", expand=True)

            self._phase_icons[phase_num] = icon
            self._phase_labels[phase_num] = lbl

        self._sb_separator(scroll)

        # ── MODO ──
        self._sb_section(scroll, "MODO")
        self.mode_var = ctk.StringVar(value=SCAN_MODE_ONLY)
        self._mode_radios = []
        for mode_key, mode_label in MODE_LABELS.items():
            hint = MODE_HINTS.get(mode_key, "")
            rb_frame = ctk.CTkFrame(scroll, fg_color="transparent")
            rb_frame.pack(fill="x", padx=10, pady=1)
            rb = ctk.CTkRadioButton(
                rb_frame, text=mode_label, variable=self.mode_var, value=mode_key,
                font=ctk.CTkFont(size=11), text_color=T_PRI,
                radiobutton_width=14, radiobutton_height=14,
                fg_color=BLUE, hover_color=CYAN,
            )
            rb.pack(anchor="w")
            ctk.CTkLabel(rb_frame, text=f"  {hint}",
                         font=ctk.CTkFont(size=9), text_color=T_MUT,
                         anchor="w").pack(anchor="w", padx=20)
            self._mode_radios.append(rb)

        self._sb_separator(scroll)

        # ── OPCIONES ──
        self._sb_section(scroll, "OPCIONES")
        chk_kw = dict(font=ctk.CTkFont(size=11), text_color=T_PRI,
                      fg_color=BLUE, hover_color=CYAN,
                      checkmark_color="#0d1117")

        self.restore_cms_var = ctk.BooleanVar(value=True)
        self.chk_restore = ctk.CTkCheckBox(scroll, text="Restaurar CMS",
                                            variable=self.restore_cms_var, **chk_kw)
        self.chk_restore.pack(anchor="w", padx=14, pady=2)

        self.gen_pdf_var = ctk.BooleanVar(value=True)
        self.chk_pdf = ctk.CTkCheckBox(scroll, text="Generar PDF",
                                        variable=self.gen_pdf_var, **chk_kw)
        self.chk_pdf.pack(anchor="w", padx=14, pady=2)

        self.gen_json_var = ctk.BooleanVar(value=True)
        self.chk_json = ctk.CTkCheckBox(scroll, text="Exportar JSON",
                                         variable=self.gen_json_var, **chk_kw)
        self.chk_json.pack(anchor="w", padx=14, pady=2)

        self.critical_only_var = ctk.BooleanVar(value=False)
        self.chk_critical = ctk.CTkCheckBox(scroll, text="Solo contenido crítico",
                                             variable=self.critical_only_var, **chk_kw)
        self.chk_critical.pack(anchor="w", padx=14, pady=2)

        self._sb_separator(scroll)

        # ── BOTONES ──
        self.scan_btn = ctk.CTkButton(
            scroll, text="▶  INICIAR", height=36,
            command=self._start_scan,
            fg_color=GREEN, hover_color="#2ea043",
            text_color="#0d1117", font=ctk.CTkFont(size=13, weight="bold"),
            corner_radius=6,
        )
        self.scan_btn.pack(fill="x", padx=10, pady=(4, 3))

        self.cancel_btn = ctk.CTkButton(
            scroll, text="■  CANCELAR", height=32,
            command=self._cancel_scan, state="disabled",
            fg_color=BG_CARD, hover_color=RED,
            text_color=RED, border_color=RED, border_width=1,
            font=ctk.CTkFont(size=11, weight="bold"),
            corner_radius=6,
        )
        self.cancel_btn.pack(fill="x", padx=10, pady=(0, 8))

    def _sb_section(self, parent, title):
        ctk.CTkLabel(parent, text=title,
                     font=ctk.CTkFont(size=9, weight="bold"),
                     text_color=T_MUT, anchor="w").pack(fill="x", padx=12, pady=(10, 2))

    def _sb_separator(self, parent):
        ctk.CTkFrame(parent, height=1, fg_color=BORDER).pack(fill="x", padx=10, pady=4)

    def _build_bottom(self):
        bottom = ctk.CTkFrame(self, fg_color=BG_PANEL, corner_radius=0)
        bottom.grid(row=3, column=0, sticky="ew")

        sep = ctk.CTkFrame(bottom, height=1, fg_color=BORDER)
        sep.pack(fill="x")

        # Progress bar
        pb_frame = ctk.CTkFrame(bottom, fg_color="transparent")
        pb_frame.pack(fill="x", padx=16, pady=(8, 0))

        self.progress_bar = ctk.CTkProgressBar(pb_frame, height=5,
                                               fg_color=BG_CARD,
                                               progress_color=BLUE)
        self.progress_bar.pack(fill="x")
        self.progress_bar.set(0)

        # Fila de ETA / porcentaje de fase
        eta_row = ctk.CTkFrame(bottom, fg_color="transparent")
        eta_row.pack(fill="x", padx=16, pady=(2, 0))

        self.eta_label = ctk.CTkLabel(eta_row, text="",
                                       font=ctk.CTkFont(family="Consolas", size=9),
                                       text_color=T_MUT, anchor="w")
        self.eta_label.pack(side="left")

        # Status + metrics + buttons
        meta_row = ctk.CTkFrame(bottom, fg_color="transparent")
        meta_row.pack(fill="x", padx=16, pady=(2, 8))

        self.status_label = ctk.CTkLabel(meta_row, text="Listo",
                                          font=ctk.CTkFont(size=10),
                                          text_color=T_MUT, anchor="w")
        self.status_label.pack(side="left")

        # Report buttons (right-aligned)
        self.json_btn = ctk.CTkButton(meta_row, text="JSON", width=62, height=26,
                                       command=self._open_json, state="disabled",
                                       fg_color=BG_CARD, hover_color=BORDER,
                                       text_color=YELLOW, border_color=BORDER, border_width=1,
                                       font=ctk.CTkFont(size=10))
        self.json_btn.pack(side="right", padx=2)

        self.pdf_btn = ctk.CTkButton(meta_row, text="PDF", width=62, height=26,
                                      command=self._open_pdf, state="disabled",
                                      fg_color=BG_CARD, hover_color=BORDER,
                                      text_color=ORANGE, border_color=BORDER, border_width=1,
                                      font=ctk.CTkFont(size=10))
        self.pdf_btn.pack(side="right", padx=2)

        self.report_btn = ctk.CTkButton(meta_row, text="HTML", width=62, height=26,
                                         command=self._open_report, state="disabled",
                                         fg_color=BG_CARD, hover_color=BORDER,
                                         text_color=BLUE, border_color=BORDER, border_width=1,
                                         font=ctk.CTkFont(size=10))
        self.report_btn.pack(side="right", padx=2)

        # Metric badges
        badges = ctk.CTkFrame(meta_row, fg_color="transparent")
        badges.pack(side="right", padx=12)

        self._badge_crit = self._make_badge(badges, "● 0 crít", RED)
        self._badge_high = self._make_badge(badges, "● 0 altos", ORANGE)
        self._badge_med  = self._make_badge(badges, "● 0 med", YELLOW)
        self._badge_low  = self._make_badge(badges, "● 0 bajos", GREEN)

    def _make_badge(self, parent, text, color):
        lbl = ctk.CTkLabel(parent, text=text, font=ctk.CTkFont(size=10),
                            text_color=color)
        lbl.pack(side="left", padx=6)
        return lbl

    # ─────────────────────────── PHASE TRACKER ────────────────────────────

    def _set_phase(self, num: int, status: str):
        """Actualiza el indicador de fase en el sidebar. Llama desde hilo de scan."""
        import time as _t
        icon_map = {
            "pending": ("○", T_MUT),
            "running": ("▶", CYAN),
            "done":    ("✓", GREEN),
            "error":   ("✗", RED),
            "skip":    ("–", T_MUT),
        }
        icon, color = icon_map.get(status, ("○", T_MUT))
        if status == "running":
            self._current_phase = num
            self._phase_start_time = _t.time()
            self._phase_progress = 0
        self.after(0, lambda i=num, ic=icon, cl=color: self._update_phase_widget(i, ic, cl))
        self.after(0, self._refresh_eta)

    def _update_phase_widget(self, num, icon, color):
        if num in self._phase_icons:
            self._phase_icons[num].configure(text=icon, text_color=color)
        if num in self._phase_labels:
            self._phase_labels[num].configure(
                text_color=color if color != T_MUT else T_MUT
            )

    def _reset_phases(self):
        for num in self._phase_icons:
            self._update_phase_widget(num, "○", T_MUT)

    # ─────────────────────────── LOCK / UNLOCK ────────────────────────────

    def _lock_ui(self):
        self._is_running = True
        widgets = [
            self.scan_btn, self.browse_btn, self.file_entry,
            self.chk_restore, self.chk_pdf, self.chk_json, self.chk_critical,
        ]
        for w in widgets:
            w.configure(state="disabled")
        for rb in self._mode_radios:
            rb.configure(state="disabled")
        self.report_btn.configure(state="disabled")
        self.pdf_btn.configure(state="disabled")
        self.json_btn.configure(state="disabled")
        self.cancel_btn.configure(state="normal")

    def _unlock_ui(self):
        self._is_running = False
        widgets = [
            self.scan_btn, self.browse_btn, self.file_entry,
            self.chk_restore, self.chk_pdf, self.chk_json, self.chk_critical,
        ]
        for w in widgets:
            w.configure(state="normal")
        for rb in self._mode_radios:
            rb.configure(state="normal")
        self.cancel_btn.configure(state="disabled")

    # ─────────────────────────── FILE BROWSER ─────────────────────────────

    def _browse_file(self):
        path = filedialog.askopenfilename(
            title="Seleccionar Backup cPanel",
            filetypes=[("Backups", "*.tar.gz *.tgz *.zip *.gz *.tar"), ("Todos", "*.*")])
        if path:
            self.file_entry.delete(0, "end")
            self.file_entry.insert(0, path)

    # ─────────────────────────── LOG HELPERS ──────────────────────────────

    def _log(self, msg: str, tag: str = ""):
        self.log_text.insert("end", msg + "\n", tag)
        self.log_text.see("end")

    def _log_phase(self, num, title):
        self._log(f"\n{'─' * 52}", "detail")
        self._log(f"  FASE {num}: {title}", "phase")
        self._log(f"{'─' * 52}", "detail")

    def _log_result(self, msg):
        self._log(f"  >> {msg}", "result")

    def _log_detail(self, msg):
        self._log(f"     {msg}", "detail")

    def _log_warn(self, msg):
        self._log(f"  ⚠  {msg}", "warning")

    def _log_error(self, msg):
        self._log(f"  ✗  {msg}", "error")

    # Thread-safe wrappers
    def _safe_log(self, msg, tag=""):
        self.after(0, lambda: self._log(msg, tag))

    def _safe_phase(self, num, title):
        self.after(0, lambda: self._log_phase(num, title))

    def _safe_result(self, msg):
        self.after(0, lambda: self._log_result(msg))

    def _safe_detail(self, msg):
        self.after(0, lambda: self._log_detail(msg))

    def _safe_warn(self, msg):
        self.after(0, lambda: self._log_warn(msg))

    def _safe_status(self, msg):
        self.after(0, lambda: self.status_label.configure(text=str(msg)))

    def _safe_error(self, msg):
        self.after(0, lambda: self._log(msg, "error"))

    def _update_progress(self, t, v):
        if t == "progress":
            self._phase_progress = int(v)
            self.progress_bar.set(v / 100)
            self._refresh_eta()
        elif t == "status":
            self.status_label.configure(text=str(v))

    def _tick_eta(self):
        """Ticker de 1 s que mantiene vivo el ETA aunque la fase no emita progreso.
        Las fases 4-8 solo emiten 'status' (sin 'progress'); sin este ticker el
        tiempo transcurrido quedaría congelado y el estimado nunca se recalcularía."""
        if not self._is_running:
            return
        self._refresh_eta()
        # reprogramar cada segundo mientras el escaneo siga corriendo
        self.after(1000, self._tick_eta)

    def _refresh_eta(self):
        """Actualiza el label de porcentaje global y tiempo estimado."""
        import time as _t
        if not self._is_running or self._current_phase < 0:
            self.eta_label.configure(text="")
            return

        # % global completado: suma de pesos de fases anteriores + fracción de la actual.
        # Para fases sin señal de progreso granular, interpola por tiempo dentro de
        # la fase usando una duración típica estimada, así el % nunca se estanca.
        completed_weight = sum(
            w for p, w in PHASE_WEIGHTS.items() if p < self._current_phase
        )
        current_weight = PHASE_WEIGHTS.get(self._current_phase, 0)
        total_weight = sum(PHASE_WEIGHTS.values()) or 1.0

        phase_frac = self._phase_progress / 100.0
        # Si la fase no reporta progreso (sigue en 0) pero lleva tiempo corriendo,
        # interpola suavemente hacia ~90% según el tiempo en la fase (evita "0%" fijo).
        if self._phase_progress <= 0 and self._phase_start_time:
            in_phase = max(0.0, _t.time() - self._phase_start_time)
            # curva asintótica: se acerca a 0.9 sin superarlo (no sabemos el real)
            phase_frac = min(0.9, in_phase / (in_phase + 20.0))

        global_pct = (completed_weight + current_weight * phase_frac) / total_weight * 100
        global_pct = min(99.0, max(0.0, global_pct))

        # Tiempo transcurrido y estimación
        elapsed = _t.time() - self._scan_start_time
        elapsed_str = self._fmt_seconds(int(elapsed))

        # Mostrar "calculando" solo los primeros segundos; luego siempre un estimado.
        if elapsed >= 4.0 and global_pct >= 1.0:
            total_est = elapsed / (global_pct / 100.0)
            remaining = max(0, total_est - elapsed)
            eta_str = f"~{self._fmt_seconds(int(remaining))} restantes"
        else:
            eta_str = "estimando tiempo…"

        phase_name = PHASES[self._current_phase][1] if self._current_phase < len(PHASES) else ""
        label = (
            f"Fase {self._current_phase + 1}/10 [{phase_name}]"
            f"  —  {global_pct:.0f}% completado"
            f"  —  {elapsed_str} transcurrido"
            f"  —  {eta_str}"
        )
        self.eta_label.configure(text=label)

    @staticmethod
    def _fmt_seconds(secs: int) -> str:
        if secs < 60:
            return f"{secs}s"
        elif secs < 3600:
            return f"{secs // 60}min {secs % 60}s"
        else:
            h = secs // 3600
            m = (secs % 3600) // 60
            return f"{h}h {m}min"

    def _update_badges(self, result):
        s = result.summary_by_severity
        self._badge_crit.configure(text=f"● {s.get('critical', 0)} crít")
        self._badge_high.configure(text=f"● {s.get('high', 0)} altos")
        self._badge_med.configure(text=f"● {s.get('medium', 0)} med")
        self._badge_low.configure(text=f"● {s.get('low', 0)} bajos")

    # ─────────────────────────── MAIN SCAN FLOW ───────────────────────────

    def _start_scan(self):
        if self._is_running:
            return
        backup_path = self.file_entry.get().strip()
        if not backup_path or not Path(backup_path).exists():
            messagebox.showerror("Error", "Seleccione un archivo de backup válido.")
            return

        import time as _t
        self._critical_only = self.critical_only_var.get()
        self._lock_ui()
        self._reset_phases()
        self.log_text.delete("1.0", "end")
        self.progress_bar.set(0)
        self.eta_label.configure(text="")
        self._report_path = None
        self._pdf_path = None
        self._json_path = None
        self._scan_start_time = _t.time()
        self._current_phase = -1
        self._phase_progress = 0
        for b in (self._badge_crit, self._badge_high, self._badge_med, self._badge_low):
            pass  # badges keep last scan values until new scan starts

        self._scan_thread = threading.Thread(
            target=self._run_scan, args=(backup_path,), daemon=True)
        self._scan_thread.start()
        self._tick_eta()  # arrancar ticker de tiempo estimado (1 s)

    def _run_scan(self, backup_path: str):
        try:
            mode = self.mode_var.get()
            is_clean = mode != SCAN_MODE_ONLY
            clean_mode = mode if is_clean else None
            critical_only = self._critical_only

            self._safe_log(f"  {APP_NAME} v{APP_VERSION}  |  {multiprocessing.cpu_count()} CPUs", "info")
            self._safe_log(f"  Modo: {MODE_LABELS.get(mode, mode)} — {MODE_HINTS.get(mode, '')}", "detail")
            self._safe_log(f"  Backup: {Path(backup_path).name}", "detail")
            if critical_only:
                self._safe_log("  [MODO CRITICO] Solo public_html, mail y SQL serán escaneados", "warning")

            # ── FASE 0: VALIDAR BACKUP ──────────────────────────────────────
            self._set_phase(0, "running")
            self._safe_phase(0, "Validar backup")
            self._safe_status("Validando backup...")
            try:
                val = BackupExtractor.validate(backup_path)
                self._safe_result(f"Archivo: {Path(backup_path).name} ({round(Path(backup_path).stat().st_size / 1024 / 1024, 1)} MB)")
                self._safe_detail(val["reason"])
                if not val["valid"]:
                    self._safe_warn("No parece un backup cPanel estándar — se continúa de todos modos")
                self._set_phase(0, "done")
            except ValueError as ve:
                self._safe_error(f"Validación fallida: {ve}")
                self._set_phase(0, "error")
                self.after(0, self._unlock_ui)
                return

            # ── FASE 1: EXTRAER BACKUP ──────────────────────────────────────
            self._set_phase(1, "running")
            self._safe_phase(1, "Extraer backup")
            self._safe_status("Extrayendo backup...")
            extractor = BackupExtractor(backup_path,
                progress_callback=lambda t, v: self.after(0, lambda: self._update_progress(t, v)))
            self._extractor = extractor
            try:
                self._backup_info = extractor.extract()
            except ExtractionCancelled:
                self._safe_warn("Extraccion cancelada por el usuario")
                self._set_phase(1, "error")
                self.after(0, self._unlock_ui)
                return
            info = self._backup_info
            self._safe_result(f"Extraído: {info.total_files} archivos, {info.total_size_mb} MB")
            self._safe_detail(f"Usuario cPanel: {info.cpanel_user or 'N/A'}")
            if info.main_domain:
                self._safe_detail(f"Dominio principal: {info.main_domain}"
                                  + (f" (+{len(info.all_domains) - 1} más)" if len(info.all_domains) > 1 else ""))
            self._safe_detail(f"MySQL: {'Sí' if info.has_mysql else 'No'}  |  Email: {'Sí' if info.has_email else 'No'}")
            if info.cms_detected:
                self._safe_detail(f"CMS detectados: {', '.join(c.upper() for c in info.cms_detected)}")
            if info.extraction_errors:
                self._safe_detail(f"Advertencias: {len(info.extraction_errors)} archivos con rutas largas (omitidos)")
            self._set_phase(1, "done")

            # ── FASE 2: PRE-SCAN ────────────────────────────────────────────
            self._set_phase(2, "running")
            self._safe_phase(2, "Pre-scan")
            engine = ScanEngine(
                progress_callback=lambda t, v: self.after(0, lambda: self._update_progress(t, v)))
            self._engine = engine
            for cls in SCANNER_CLASSES:
                engine.register_scanner_class(cls)

            if is_clean:
                self._safe_status("Configurando cuarentena...")
                engine.pre_scan_quarantine_setup(str(Path(backup_path).parent))
                backup_log = engine.isolate_backups_pre_scan(info.extract_dir)
                if backup_log:
                    self._safe_result(f"Backups aislados pre-scan: {len(backup_log)}")
                    for b in backup_log[:4]:
                        self._safe_detail(f"  {b['name']} ({b['type']})")
                    if len(backup_log) > 4:
                        self._safe_detail(f"  ... y {len(backup_log) - 4} más")
            self._set_phase(2, "done")

            # ── FASE 3: ESCANEO ─────────────────────────────────────────────
            self._set_phase(3, "running")
            self._safe_phase(3, "Escaneo de malware (multiprocessing)")
            self._safe_status("Escaneando archivos...")
            result = engine.scan_directory(info.extract_dir, backup_info=info, critical_only=critical_only)
            result.main_domain = info.main_domain
            result.all_domains = list(info.all_domains)
            self._scan_result = result

            confirmed = sum(1 for f in result.findings if f.confirmed_malware)
            suspect = result.total_threats_found - confirmed
            self._safe_result(f"{result.total_files_scanned} archivos en {result.scan_duration_seconds}s ({result.workers_used} workers)")
            if result.omitted_paths_count:
                self._safe_detail(f"Modo crítico: {result.omitted_paths_count} archivos de sistema omitidos")
            self._safe_result(f"Detecciones: {result.total_threats_found} total")
            self._safe_detail(f"CONFIRMADOS (malware real): {confirmed}")
            self._safe_detail(f"Sospechosos (solo reporte): {suspect}")
            for sev in ("critical", "high", "medium", "low"):
                c = result.summary_by_severity.get(sev, 0)
                if c:
                    self._safe_detail(f"{sev.upper()}: {c}")
            if result.scan_errors:
                self._safe_detail(f"Errores de lectura: {len(result.scan_errors)}")
            self.after(0, lambda: self._update_badges(result))
            self._set_phase(3, "done")

            # ── FASE 4: ENRIQUECIMIENTO (VT + IoC) ─────────────────────────
            self._set_phase(4, "running")
            self._safe_phase(4, "Enriquecimiento")

            # 4a: VirusTotal
            vt_key = self.config.get("virustotal_api_key", "")
            if vt_key and result.findings:
                self._safe_status("Consultando VirusTotal...")
                critical_files = list(set(
                    f.file_path for f in result.findings
                    if f.severity == "critical" and Path(f.file_path).suffix.lower() in (".php", ".js")
                ))[:10]
                if critical_files:
                    vt = VirusTotalClient(vt_key)
                    vt_mode = self.config.get("vt_mode", "confirm")
                    if vt_mode == "deep":
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
                    self._safe_result(f"VirusTotal: {len(hits)} detecciones en {len(critical_files)} archivos")
                    for h in hits[:5]:
                        self._safe_detail(f"  {Path(h.file_path).name}: {h.detection_count}/{h.total_engines} motores")
            else:
                if not vt_key:
                    self._safe_detail("VirusTotal no configurado (opcional — ver Config)")

            # 4b: Extracción de IoC
            self._safe_status("Extrayendo indicadores de compromiso...")
            iocs = engine.extract_iocs()
            if iocs.get("ips") or iocs.get("urls") or iocs.get("domains"):
                self._safe_result(f"IoC extraídos: {len(iocs.get('ips', []))} IPs, "
                                  f"{len(iocs.get('domains', []))} dominios, "
                                  f"{len(iocs.get('urls', []))} URLs")
                for ip in iocs.get("ips", [])[:5]:
                    self._safe_detail(f"  IP: {ip}")
                for d in iocs.get("domains", [])[:5]:
                    self._safe_detail(f"  Dominio: {d}")
            else:
                self._safe_detail("Sin IoC de red encontrados en findings confirmados")
            self._set_phase(4, "done")

            # ── FASE 5: LIMPIEZA ────────────────────────────────────────────
            if is_clean:
                self._set_phase(5, "running")
                self._safe_phase(5, f"Limpieza ({clean_mode})")
                quarantine_base = str(Path(backup_path).parent)

                self._safe_status(f"Limpiando archivos maliciosos (modo {clean_mode})...")
                cleaned = engine.clean_findings(quarantine_base, mode=clean_mode)
                self._safe_result(f"Malware en cuarentena: {cleaned} archivos")

                zero_count = engine.clean_zero_byte_files(info.extract_dir, mode=clean_mode)
                if zero_count:
                    self._safe_result(f"Archivos 0KB removidos: {zero_count}")

                self._safe_detail(f"Cuarentena: {result.quarantine_dir}")
                self._set_phase(5, "done")
            else:
                self._set_phase(5, "skip")

            # ── FASE 6: RESTAURAR CMS ───────────────────────────────────────
            if is_clean and info.cms_detected:
                self._set_phase(6, "running")
                self._safe_phase(6, "Restaurar CMS")
                quarantine_base = str(Path(backup_path).parent)

                # Pre-wipe: detectar versión WP antes de borrar wp-includes
                wp_info = {}
                wp_cleaner_ref = None
                if "wordpress" in info.cms_detected:
                    self._safe_status("Pre-wipe: detectando versión WP...")
                    wp_cleaner_ref = WordPressCleaner(
                        extract_dir=info.extract_dir,
                        quarantine_dir=result.quarantine_dir or str(Path(backup_path).parent / "cuarentena"),
                        clean_mode=clean_mode,
                        backup_info=info,
                        progress_callback=lambda t, v: self.after(0, lambda: self._update_progress(t, v)),
                    )
                    wp_info = wp_cleaner_ref.pre_wipe_detect()
                    result.wp_versions_prewipe = dict(wp_info.get("versions", {}))
                    for rk, ver in wp_info.get("versions", {}).items():
                        self._safe_detail(f"[WP] Versión detectada pre-wipe: {ver}")

                # Separar plugins/temas antes del wipe
                if wp_info and "wordpress" in info.cms_detected:
                    self._safe_status("Pre-wipe: separando plugins y temas...")
                    sep_log = wp_cleaner_ref.pre_wipe_separate_addons()
                    if sep_log:
                        plugins_sep = sum(1 for e in sep_log if e["addon_type"] == "plugin")
                        themes_sep = sum(1 for e in sep_log if e["addon_type"] == "theme")
                        self._safe_result(f"[WP] Separados: {plugins_sep} plugins, {themes_sep} temas")
                        result.plugins_temas_log = result.plugins_temas_log or []
                        for e in sep_log:
                            result.plugins_temas_log.append({
                                "cms": "wordpress", "type": e["addon_type"],
                                "name": e["slug"], "version": e["version"],
                                "is_active": False, "action": "cuarentena", "reinstalled": None,
                            })

                # Wipe completo del CMS
                self._safe_status("Wipe CMS: eliminando core infectado...")
                wiper = CMSFullWiper(
                    extract_dir=info.extract_dir,
                    cms_detected=info.cms_detected,
                    clean_mode=clean_mode,
                    progress_callback=lambda t, v: self.after(0, lambda: self._update_progress(t, v)),
                )
                wipe_result = wiper.wipe()
                result.wipe_result = wipe_result
                for cms_name, wstats in wipe_result.items():
                    files_rm = wstats.get("files_removed", 0)
                    dirs_rm = wstats.get("dirs_removed", 0)
                    if files_rm or dirs_rm:
                        self._safe_result(f"[WIPER] {cms_name.upper()}: {files_rm} archivos, {dirs_rm} dirs eliminados")

                # Post-wipe: limpiar residuos de wp-content
                if wp_info and "wordpress" in info.cms_detected:
                    self._safe_status("Post-wipe: limpiando residuos wp-content...")
                    wp_cleaner2 = WordPressCleaner(
                        extract_dir=info.extract_dir,
                        quarantine_dir=result.quarantine_dir or str(Path(backup_path).parent / "cuarentena"),
                        clean_mode=clean_mode,
                        backup_info=info,
                        progress_callback=lambda t, v: self.after(0, lambda: self._update_progress(t, v)),
                    )
                    wp_stats = wp_cleaner2.post_wipe_clean(wp_info, do_install=False)
                    result.cms_restore_log = result.cms_restore_log or []
                    result.cms_restore_log.extend(wp_cleaner2.log)
                    if wp_stats.get("cleaned_files"):
                        self._safe_detail(f"[WP] Residuos limpiados: {wp_stats['cleaned_files']}")

                # Reinstalar desde repos oficiales
                if self.restore_cms_var.get():
                    self._safe_status("Restaurando desde repositorios oficiales...")
                    restorer = CMSRestorer(info.extract_dir,
                        progress_callback=lambda t, v: self.after(0, lambda: self._update_progress(t, v)),
                        quarantine_dir=result.quarantine_dir,
                        wp_versions=result.wp_versions_prewipe)
                    restore_log = restorer.restore_all(info.cms_detected, backup_info=info)
                    result.cms_restore_log = restore_log
                    ok = sum(1 for e in restore_log if e["type"] == "success")
                    warn = sum(1 for e in restore_log if e["type"] == "warning")
                    self._safe_result(f"CMS: {ok} restaurados, {warn} advertencias")
                    for entry in restore_log:
                        if entry["type"] in ("success", "error"):
                            icon = "[OK]" if entry["type"] == "success" else "[X]"
                            self._safe_detail(f"{icon} {entry['message'][:90]}")

                self._set_phase(6, "done")
            else:
                self._set_phase(6, "skip")

            # ── FASE 7: BASE DE DATOS / JUNK ────────────────────────────────
            if is_clean:
                self._set_phase(7, "running")
                self._safe_phase(7, "Base de datos y archivos residuales")

                db_paths = info.structure.get("databases", [])
                detected_prefixes = {}

                # Detectar prefijos de BD
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

                # CMSPluginCleaner (excluye WordPress — ya gestionado en fase 6)
                cms_for_cleaner = [c for c in info.cms_detected if c != "wordpress"]
                if cms_for_cleaner and result.quarantine_dir:
                    plugin_cleaner = CMSPluginCleaner(
                        extract_dir=info.extract_dir,
                        quarantine_dir=result.quarantine_dir,
                        clean_mode=clean_mode,
                        progress_callback=lambda t, v: self.after(0, lambda: self._update_progress(t, v)),
                        db_paths=db_paths,
                    )
                    pt_counts = plugin_cleaner.process(cms_for_cleaner)
                    result.plugins_temas_log = (result.plugins_temas_log or [])
                    result.plugins_temas_log.extend(plugin_cleaner.removal_log)
                    if not result.db_prefixes:
                        result.db_prefixes = plugin_cleaner.get_detected_prefixes()
                    if pt_counts["total"] > 0:
                        self._safe_result(f"Plugins/temas procesados: {pt_counts['total']}")

                # JunkCleaner — v3.2: corre también sin CMS (proyectos de código propio)
                if result.quarantine_dir:
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
                        by_cat = {}
                        for j in junk_log:
                            by_cat[j["category"]] = by_cat.get(j["category"], 0) + 1
                        self._safe_result(f"Residuales: {len(junk_log)} encontrados, {acted} procesados")
                        for cat, n in sorted(by_cat.items(), key=lambda x: -x[1])[:6]:
                            self._safe_detail(f"  {cat}: {n}")

                # DBCleaner
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
                    result.db_cron_log = db_cleaner.cron_log
                    result.db_users_log = db_cleaner.users_log
                    result.generated_passwords = db_cleaner.generated_passwords
                    result.db_very_infected = db_cleaner.db_very_infected

                    spam_posts = [i for i in db_interventions if i.get("type") == "spam_post"]
                    result.spam_posts_log = spam_posts
                    non_spam = [i for i in db_interventions if i.get("type") != "spam_post"]

                    if non_spam:
                        deleted = sum(1 for i in non_spam if "deleted" in i.get("type", "") or "removed" in i.get("type", ""))
                        suspicious = sum(1 for i in non_spam if i.get("type") == "suspicious")
                        self._safe_result(f"BD: {deleted} filas eliminadas, {suspicious} sospechosas")
                    if db_cleaner.cron_log:
                        self._safe_result(f"BD: {len(db_cleaner.cron_log)} cron maliciosos neutralizados")
                    if db_cleaner.users_log:
                        removed_u = sum(1 for u in db_cleaner.users_log if "eliminado" in u.get("action", ""))
                        self._safe_result(f"BD: {removed_u} usuarios peligrosos eliminados")
                    if spam_posts:
                        spam_del = sum(1 for s in spam_posts if s.get("action") == "deleted")
                        self._safe_result(f"Posts SPAM: {len(spam_posts)} detectados, {spam_del} eliminados")

                self._set_phase(7, "done")
            else:
                self._set_phase(7, "skip")

            # ── FASE 8: REPORTES ────────────────────────────────────────────
            self._set_phase(8, "running")
            phase_n = 8 if is_clean else 4
            self._safe_phase(phase_n, "Generación de reportes")
            self._safe_status("Generando reportes...")

            report_dir = Path(backup_path).parent / "reportes"
            gen = ReportGenerator(str(report_dir))

            # HTML
            self._report_path = gen.generate(result, backup_path)
            self._safe_result(f"HTML: {Path(self._report_path).name}")

            # PDF
            if self.gen_pdf_var.get():
                try:
                    self._pdf_path = gen.generate_pdf(result, backup_path)
                    self._safe_result(f"PDF: {Path(self._pdf_path).name}")
                except Exception as e:
                    self._safe_warn(f"PDF no generado: {e}")

            # JSON
            if self.gen_json_var.get():
                try:
                    self._json_path = gen.generate_json(result, backup_path)
                    self._safe_result(f"JSON: {Path(self._json_path).name}")
                except Exception as e:
                    self._safe_warn(f"JSON no generado: {e}")

            self._set_phase(8, "done")

            # ── FASE 9: EMPAQUETAR ──────────────────────────────────────────
            if is_clean:
                self._set_phase(9, "running")
                _info = info
                _crit = critical_only
                self.after(0, lambda: self._ask_packaging(_info, backup_path, _crit))
            else:
                self._set_phase(9, "skip")
                self._safe_log(f"\n{'═' * 52}", "phase")
                self._safe_log("  ESCANEO COMPLETADO", "info")
                self._safe_log(f"{'═' * 52}", "phase")

            self.after(0, self._scan_finished)

        except Exception as e:
            self._safe_log(f"\n  ERROR: {e}\n{traceback.format_exc()}", "error")
            self._safe_status(f"Error: {e}")
            self.after(0, self._unlock_ui)

    # ─────────────────────────── SCAN FINISHED ────────────────────────────

    def _scan_finished(self):
        self._unlock_ui()
        self.progress_bar.set(1.0)
        self._current_phase = -1
        self.eta_label.configure(text="")

        if self._report_path:
            self.report_btn.configure(state="normal")
        if self._pdf_path:
            self.pdf_btn.configure(state="normal")
        if self._json_path:
            self.json_btn.configure(state="normal")

        if self._scan_result:
            confirmed = sum(1 for f in self._scan_result.findings if f.confirmed_malware)
            t = self._scan_result.total_threats_found
            c = self._scan_result.total_cleaned
            if c > 0:
                self.status_label.configure(
                    text=f"Completado — {c} cuarentena / {confirmed} confirmados / {t} total",
                    text_color=GREEN)
            elif t > 0:
                self.status_label.configure(
                    text=f"Completado — {confirmed} confirmados / {t} total detectados",
                    text_color=ORANGE)
            else:
                self.status_label.configure(text="Completado — Sin amenazas detectadas",
                                             text_color=GREEN)
        else:
            self.status_label.configure(text="Completado", text_color=T_MUT)

    # ─────────────────────────── REPORT OPENERS ───────────────────────────

    def _open_report(self):
        if self._report_path and Path(self._report_path).exists():
            webbrowser.open(f"file:///{self._report_path}")

    def _open_pdf(self):
        if self._pdf_path and Path(self._pdf_path).exists():
            os.startfile(self._pdf_path)

    def _open_json(self):
        if self._json_path and Path(self._json_path).exists():
            os.startfile(self._json_path)

    # ─────────────────────────── CANCEL ───────────────────────────────────

    def _center_on_screen(self, w, h):
        """Centra la ventana en el monitor primario. Evita que la app abra fuera
        de pantalla si el gestor de ventanas restaura una geometria antigua."""
        try:
            self.update_idletasks()
            sw = self.winfo_screenwidth()
            sh = self.winfo_screenheight()
            x = max(0, (sw - w) // 2)
            y = max(0, (sh - h) // 2)
            self.geometry(f"{w}x{h}+{x}+{y}")
        except Exception:
            pass

    def _cancel_scan(self):
        if getattr(self, "_extractor", None):
            self._extractor.cancel()
        if self._engine:
            self._engine.cancel()
        self._log("\n  >> Cancelado por el usuario", "warning")
        self.status_label.configure(text="Cancelado", text_color=YELLOW)
        self._unlock_ui()

    # ─────────────────────────── PACKAGING ────────────────────────────────

    def _ask_packaging(self, backup_info, backup_path, critical_only=False):
        PackagingDialog(self, backup_info.extract_dir, backup_path,
                        backup_info=backup_info, critical_only=critical_only,
                        log_cb=self._safe_result, detail_cb=self._safe_detail,
                        status_cb=self._safe_status,
                        progress_cb=lambda t, v: self.after(0, lambda: self._update_progress(t, v)),
                        finish_cb=self._finish_packaging)

    def _do_package_targz(self, extract_dir, out_path):
        try:
            packager = BackupPackager(
                progress_callback=lambda t, v: self.after(0, lambda: self._update_progress(t, v)))
            result_path = packager.create_targz(extract_dir, str(out_path))
            size = round(Path(result_path).stat().st_size / (1024 * 1024), 1)
            self._safe_result(f"Archivo .tar.gz: {Path(result_path).name} ({size} MB)")
        except Exception as e:
            self._safe_warn(f"Error empaquetando: {e}")
        self.after(0, self._finish_packaging)

    def _do_package_cpanel_partial(self, extract_dir, backup_info, out_path):
        try:
            packager = BackupPackager(
                progress_callback=lambda t, v: self.after(0, lambda: self._update_progress(t, v)))
            result_path = packager.create_cpanel_partial_targz(extract_dir, backup_info, str(out_path))
            size = round(Path(result_path).stat().st_size / (1024 * 1024), 1)
            self._safe_result(f"Backup parcial cPanel: {Path(result_path).name} ({size} MB)")
            self._safe_detail("Importable en WHM > Backup > Restore > Full Backup")
        except Exception as e:
            self._safe_warn(f"Error generando backup parcial: {e}")
        self.after(0, self._finish_packaging)

    def _do_package_critical_mode(self, extract_dir, backup_info, name):
        try:
            packager = BackupPackager(
                progress_callback=lambda t, v: self.after(0, lambda: self._update_progress(t, v)))
            output_base = str(Path(extract_dir).parent)
            sql_files = backup_info.structure.get("databases", []) if backup_info else []
            domain = name or "sitio"
            existing_q = None
            if self._scan_result and getattr(self._scan_result, "quarantine_dir", ""):
                existing_q = self._scan_result.quarantine_dir
            result = packager.create_critical_mode_output(
                extract_dir, sql_files, output_base, domain, quarantine_dir=existing_q)
            if result.get("homedir_tar"):
                size = round(Path(result["homedir_tar"]).stat().st_size / (1024 * 1024), 1)
                self._safe_result(f"homedir_backup.tar.gz: {size} MB ({result['included_count']} archivos)")
            if result.get("databases"):
                self._safe_result(f"Bases de datos: {len(result['databases'])} archivos .sql.gz")
            self._safe_log("\n  PASOS PARA RESTAURAR EN CPANEL:", "info")
            self._safe_log("  [1] cPanel > Backup > Restore > Home Directory Backup", "detail")
            self._safe_log("  [2] cPanel > Backup > Restore > MySQL Database Backup", "detail")
            if self._scan_result:
                self._scan_result.critical_output_manifest = result
        except Exception as e:
            self._safe_warn(f"Error generando paquete crítico: {e}")
        self.after(0, self._finish_packaging)

    def _do_copy_files(self, extract_dir, dest):
        try:
            packager = BackupPackager(
                progress_callback=lambda t, v: self.after(0, lambda: self._update_progress(t, v)))
            copied = packager.copy_clean_files(extract_dir, dest)
            self._safe_result(f"{copied} archivos copiados a {dest}")
        except Exception as e:
            self._safe_warn(f"Error copiando: {e}")
        self.after(0, self._finish_packaging)

    def _finish_packaging(self):
        self._set_phase(9, "done")
        self._safe_log(f"\n{'═' * 52}", "phase")
        self._safe_log("  PROCESO COMPLETADO", "info")
        self._safe_log(f"{'═' * 52}", "phase")

    # ─────────────────────────── SETTINGS ─────────────────────────────────

    def _open_settings(self):
        if not self._is_running:
            SettingsWindow(self, self.config)


# ══════════════════════════════════════════════════════════════════════════
#  PACKAGING DIALOG
# ══════════════════════════════════════════════════════════════════════════

class PackagingDialog(ctk.CTkToplevel):
    def __init__(self, parent, extract_dir, backup_path,
                 log_cb, detail_cb, status_cb, progress_cb, finish_cb,
                 backup_info=None, critical_only=False):
        super().__init__(parent)
        self.extract_dir   = extract_dir
        self.backup_path   = backup_path
        self.backup_info   = backup_info
        self.critical_only = critical_only
        self.log_cb        = log_cb
        self.detail_cb     = detail_cb
        self.status_cb     = status_cb
        self.progress_cb   = progress_cb
        self.finish_cb     = finish_cb
        self.parent_app    = parent

        self.title("Empaquetar resultado limpio")
        height = 360 if critical_only else 290
        self.geometry(f"600x{height}")
        self.configure(fg_color=BG_MAIN)
        self.transient(parent)
        self.grab_set()

        default_name = re.sub(r'\.(tar\.gz|tgz|tar|zip|gz)$', '',
                               Path(backup_path).name, flags=re.IGNORECASE) + "-limpio"

        frame = ctk.CTkFrame(self, fg_color=BG_PANEL, corner_radius=8)
        frame.pack(fill="both", expand=True, padx=12, pady=12)

        ctk.CTkLabel(frame, text="✓  Limpieza completada",
                     font=ctk.CTkFont(size=15, weight="bold"),
                     text_color=GREEN).pack(pady=(16, 8))

        ctk.CTkLabel(frame, text="Nombre del archivo de salida:",
                     font=ctk.CTkFont(size=11), text_color=T_MUT,
                     anchor="w").pack(padx=20, anchor="w")
        self.name_entry = ctk.CTkEntry(frame, width=460,
                                        fg_color=BG_CARD, border_color=BORDER,
                                        text_color=T_PRI, placeholder_text=default_name,
                                        font=ctk.CTkFont(size=11))
        self.name_entry.pack(padx=20, pady=(0, 12))
        self.name_entry.insert(0, default_name)

        ctk.CTkLabel(frame, text="Formato de salida:",
                     font=ctk.CTkFont(size=11), text_color=T_MUT,
                     anchor="w").pack(padx=20, anchor="w", pady=(0, 6))

        btn_f = ctk.CTkFrame(frame, fg_color="transparent")
        btn_f.pack(pady=4)

        ctk.CTkButton(btn_f, text="Generar .tar.gz\n(completo, para cPanel)", width=180, height=52,
                      command=self._do_targz, fg_color=GREEN, hover_color="#2ea043",
                      text_color="#0d1117", font=ctk.CTkFont(size=11, weight="bold"),
                      corner_radius=6).pack(side="left", padx=6)
        ctk.CTkButton(btn_f, text="Copiar a carpeta", width=130, height=52,
                      command=self._do_copy, fg_color=BG_CARD, hover_color=BORDER,
                      text_color=BLUE, border_color=BORDER, border_width=1,
                      font=ctk.CTkFont(size=11), corner_radius=6).pack(side="left", padx=6)
        ctk.CTkButton(btn_f, text="Solo reportes", width=110, height=52,
                      command=self._do_skip, fg_color=BG_CARD, hover_color=BORDER,
                      text_color=T_MUT, border_color=BORDER, border_width=1,
                      font=ctk.CTkFont(size=11), corner_radius=6).pack(side="left", padx=6)

        if critical_only:
            ctk.CTkFrame(frame, height=1, fg_color=BORDER).pack(fill="x", padx=20, pady=10)
            ctk.CTkLabel(frame, text="Modo Solo Contenido Crítico:",
                         anchor="w", font=ctk.CTkFont(size=11), text_color=CYAN).pack(padx=20, anchor="w")
            btn_f2 = ctk.CTkFrame(frame, fg_color="transparent")
            btn_f2.pack(pady=6)
            ctk.CTkButton(btn_f2, text="Backup parcial cPanel\n(SQL + homedir + mail)",
                          width=210, height=52, command=self._do_cpanel_partial,
                          fg_color=BLUE, hover_color=CYAN,
                          text_color="#0d1117", font=ctk.CTkFont(size=11, weight="bold"),
                          corner_radius=6).pack(side="left", padx=6)
            ctk.CTkLabel(btn_f2, text="Importable directo\nen WHM > Restore",
                         font=ctk.CTkFont(size=10), text_color=T_MUT).pack(side="left", padx=8)

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


# ══════════════════════════════════════════════════════════════════════════
#  SETTINGS WINDOW
# ══════════════════════════════════════════════════════════════════════════

class SettingsWindow(ctk.CTkToplevel):
    def __init__(self, parent, config):
        super().__init__(parent)
        self.config = config
        self.title("Configuración — cPaCleanS")
        self.geometry("580x800")
        self.configure(fg_color=BG_MAIN)
        self.transient(parent)
        self.grab_set()
        self._build()

    def _build(self):
        frame = ctk.CTkScrollableFrame(self, fg_color=BG_PANEL, corner_radius=8,
                                        scrollbar_button_color=BG_CARD,
                                        scrollbar_button_hover_color=BORDER)
        frame.pack(fill="both", expand=True, padx=12, pady=12)

        ctk.CTkLabel(frame, text="Configuración",
                     font=ctk.CTkFont(size=16, weight="bold"),
                     text_color=T_PRI).pack(pady=(8, 16))

        # ── VirusTotal ──
        self._section(frame, "VirusTotal API")
        ctk.CTkLabel(frame, text="Gratuita: 500 consultas/día, 4/min\nPremium: sin límites, análisis profundo con upload",
                     font=ctk.CTkFont(size=10), text_color=T_MUT, justify="left",
                     wraplength=490).pack(padx=16, anchor="w")

        self.vt_entry = ctk.CTkEntry(frame, width=480, show="*",
                                      placeholder_text="Obtener en virustotal.com > Perfil > API key",
                                      fg_color=BG_CARD, border_color=BORDER, text_color=T_PRI)
        self.vt_entry.pack(padx=16, pady=(6, 2))
        if self.config.get("virustotal_api_key"):
            self.vt_entry.insert(0, self.config["virustotal_api_key"])

        vt_row = ctk.CTkFrame(frame, fg_color="transparent")
        vt_row.pack(padx=16, anchor="w", pady=(2, 8))
        ctk.CTkButton(vt_row, text="Mostrar/ocultar", width=120, height=28,
                      command=self._toggle_vt, fg_color=BG_CARD, hover_color=BORDER,
                      text_color=T_MUT, border_color=BORDER, border_width=1,
                      font=ctk.CTkFont(size=10)).pack(side="left", padx=(0, 6))
        ctk.CTkButton(vt_row, text="Validar key →", width=110, height=28,
                      command=self._validate_vt, fg_color=BG_CARD, hover_color=BORDER,
                      text_color=BLUE, border_color=BORDER, border_width=1,
                      font=ctk.CTkFont(size=10)).pack(side="left", padx=(0, 8))
        self.vt_status = ctk.CTkLabel(vt_row, text="", font=ctk.CTkFont(size=10), text_color=T_MUT)
        self.vt_status.pack(side="left")

        self.vt_mode_var = ctk.StringVar(value=self.config.get("vt_mode", "confirm"))
        vt_mf = ctk.CTkFrame(frame, fg_color="transparent")
        vt_mf.pack(padx=16, anchor="w", pady=(0, 12))
        ctk.CTkRadioButton(vt_mf, text="Solo confirmar (rápido, consulta hashes)",
                           variable=self.vt_mode_var, value="confirm",
                           font=ctk.CTkFont(size=10), text_color=T_PRI,
                           fg_color=BLUE).pack(anchor="w")
        ctk.CTkRadioButton(vt_mf, text="Profundo (sube archivos sospechosos — más lento)",
                           variable=self.vt_mode_var, value="deep",
                           font=ctk.CTkFont(size=10), text_color=T_PRI,
                           fg_color=BLUE).pack(anchor="w")

        # ── Rendimiento ──
        self._section(frame, "Rendimiento")
        ctk.CTkLabel(frame, text="Tamaño máximo de archivo a escanear (MB):",
                     font=ctk.CTkFont(size=10), text_color=T_MUT, anchor="w").pack(padx=16, anchor="w")
        self.size_entry = ctk.CTkEntry(frame, width=80, fg_color=BG_CARD,
                                        border_color=BORDER, text_color=T_PRI)
        self.size_entry.pack(padx=16, anchor="w", pady=(0, 8))
        self.size_entry.insert(0, str(self.config.get("max_file_size_mb", 50)))

        max_cpu = multiprocessing.cpu_count()
        ctk.CTkLabel(frame, text=f"Workers de escaneo (CPUs disponibles: {max_cpu}):",
                     font=ctk.CTkFont(size=10), text_color=T_MUT, anchor="w").pack(padx=16, anchor="w")
        self.workers_slider = ctk.CTkSlider(frame, from_=1, to=max_cpu,
                                             number_of_steps=max(1, max_cpu - 1), width=320,
                                             fg_color=BG_CARD, progress_color=BLUE,
                                             button_color=BLUE, button_hover_color=CYAN)
        self.workers_slider.pack(padx=16, anchor="w", pady=(0, 2))
        self.workers_slider.set(self.config.get("scan_workers", max(1, max_cpu - 1)))
        self.workers_lbl = ctk.CTkLabel(frame, text=f"{int(self.workers_slider.get())} workers",
                                         font=ctk.CTkFont(size=10), text_color=T_MUT)
        self.workers_lbl.pack(padx=16, anchor="w", pady=(0, 10))
        self.workers_slider.configure(command=lambda v: self.workers_lbl.configure(text=f"{int(v)} workers"))

        # ── Scoring ──
        self._section(frame, "Scoring")
        ctk.CTkLabel(frame, text="Threshold de confirmación (score ≥ threshold = malware confirmado):",
                     font=ctk.CTkFont(size=10), text_color=T_MUT).pack(padx=16, anchor="w")
        self.threshold_slider = ctk.CTkSlider(frame, from_=20, to=95,
                                               number_of_steps=15, width=320,
                                               fg_color=BG_CARD, progress_color=BLUE,
                                               button_color=BLUE, button_hover_color=CYAN)
        self.threshold_slider.pack(padx=16, anchor="w", pady=(0, 2))
        self.threshold_slider.set(self.config.get("confidence_threshold", 70))
        self.threshold_lbl = ctk.CTkLabel(
            frame, text=f"Threshold: {int(self.threshold_slider.get())}  (≥70 estricto, ≥50 permisivo)",
            font=ctk.CTkFont(size=10), text_color=T_MUT)
        self.threshold_lbl.pack(padx=16, anchor="w", pady=(0, 10))
        self.threshold_slider.configure(
            command=lambda v: self.threshold_lbl.configure(
                text=f"Threshold: {int(v)}  (≥70 estricto, ≥50 permisivo)"))

        # ── Filtrado ──
        self._section(frame, "Filtrado")
        ctk.CTkLabel(frame, text="Directorios excluidos del escaneo (separados por coma):",
                     font=ctk.CTkFont(size=10), text_color=T_MUT, anchor="w").pack(padx=16, anchor="w")
        self.excluded_entry = ctk.CTkEntry(frame, width=480,
                                            placeholder_text="vendor, node_modules, .git, tests, phpunit",
                                            fg_color=BG_CARD, border_color=BORDER, text_color=T_PRI)
        self.excluded_entry.pack(padx=16, anchor="w", pady=(0, 10))
        current = ", ".join(self.config.get("excluded_dirs", []))
        if current:
            self.excluded_entry.insert(0, current)

        # ── Cache ──
        self._section(frame, "Cache de escaneo")
        cache_row = ctk.CTkFrame(frame, fg_color="transparent")
        cache_row.pack(padx=16, anchor="w", pady=(0, 10))
        self.cache_lbl = ctk.CTkLabel(cache_row, text="Cargando...",
                                       font=ctk.CTkFont(size=10), text_color=T_MUT)
        self.cache_lbl.pack(side="left", padx=(0, 12))
        ctk.CTkButton(cache_row, text="Limpiar cache", width=110, height=28,
                      command=self._clear_cache, fg_color=BG_CARD, hover_color=RED,
                      text_color=RED, border_color=RED, border_width=1,
                      font=ctk.CTkFont(size=10)).pack(side="left")
        self._refresh_cache()

        # ── CMS ──
        self._section(frame, "CMS")
        self.restore_var = ctk.BooleanVar(value=self.config.get("restore_cms_core", True))
        ctk.CTkCheckBox(frame, text="Restaurar core/plugins/temas desde repositorios oficiales",
                        variable=self.restore_var, font=ctk.CTkFont(size=10), text_color=T_PRI,
                        fg_color=BLUE, hover_color=CYAN).pack(padx=16, anchor="w", pady=(0, 14))

        # ── Botones ──
        bf = ctk.CTkFrame(frame, fg_color="transparent")
        bf.pack(pady=8)
        ctk.CTkButton(bf, text="Guardar", width=120, height=34, command=self._save,
                      fg_color=GREEN, hover_color="#2ea043", text_color="#0d1117",
                      font=ctk.CTkFont(size=12, weight="bold")).pack(side="left", padx=8)
        ctk.CTkButton(bf, text="Cancelar", width=100, height=34, command=self.destroy,
                      fg_color=BG_CARD, hover_color=BORDER, text_color=T_MUT,
                      border_color=BORDER, border_width=1).pack(side="left", padx=8)

    def _section(self, parent, title):
        ctk.CTkLabel(parent, text=title, font=ctk.CTkFont(size=12, weight="bold"),
                     text_color=CYAN, anchor="w").pack(padx=16, anchor="w", pady=(8, 4))
        ctk.CTkFrame(parent, height=1, fg_color=BORDER).pack(fill="x", padx=16, pady=(0, 6))

    def _toggle_vt(self):
        self.vt_entry.configure(show="" if self.vt_entry.cget("show") == "*" else "*")

    def _validate_vt(self):
        import threading as _t
        key = self.vt_entry.get().strip()
        if not key:
            self.vt_status.configure(text="Ingresa una key primero", text_color=YELLOW)
            return
        self.vt_status.configure(text="Validando...", text_color=T_MUT)
        self.update()

        def do_check():
            try:
                import requests as _req
                resp = _req.get(
                    "https://www.virustotal.com/api/v3/files/"
                    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                    headers={"x-apikey": key}, timeout=12)
                if resp.status_code == 200:
                    msg, color = "✓ Key válida", GREEN
                elif resp.status_code == 401:
                    msg, color = "✗ Key inválida (401)", RED
                elif resp.status_code == 429:
                    msg, color = "✓ Válida (límite/min)", YELLOW
                else:
                    msg, color = f"⚠ HTTP {resp.status_code}", YELLOW
            except Exception as e:
                msg, color = f"✗ {str(e)[:32]}", RED
            self.after(0, lambda: self.vt_status.configure(text=msg, text_color=color))

        _t.Thread(target=do_check, daemon=True).start()

    def _save(self):
        self.config["virustotal_api_key"] = self.vt_entry.get().strip()
        self.config["vt_mode"] = self.vt_mode_var.get()
        try:
            self.config["max_file_size_mb"] = int(self.size_entry.get())
        except ValueError:
            pass
        self.config["scan_workers"] = int(self.workers_slider.get())
        self.config["confidence_threshold"] = int(self.threshold_slider.get())
        raw = self.excluded_entry.get().strip()
        self.config["excluded_dirs"] = [d.strip() for d in raw.split(",") if d.strip()] if raw else []
        self.config["restore_cms_core"] = self.restore_var.get()
        save_config(self.config)
        self.destroy()

    def _refresh_cache(self):
        try:
            from ..utils.hash_cache import HashCache
            stats = HashCache().stats()
            self.cache_lbl.configure(text=f"{stats['count']} archivos en caché — {stats['size_mb']} MB")
        except Exception:
            self.cache_lbl.configure(text="Caché no disponible")

    def _clear_cache(self):
        try:
            from ..utils.hash_cache import HashCache
            HashCache().clear()
            self._refresh_cache()
        except Exception:
            pass
