"""Generador de reportes HTML + PDF para cPacleanS — formato legible y robusto."""
import os
from datetime import datetime
from pathlib import Path
from jinja2 import Environment

from ..core.engine import ScanResult
from ..config.settings import APP_VERSION


def truncate_path(path, max_len=55):
    if len(path) <= max_len:
        return path
    parts = path.replace("\\", "/").split("/")
    if len(parts) <= 2:
        return path
    return parts[-1]


def short_name(path):
    return Path(path).name


def malware_ruta(path):
    """Ruta relativa desde el backup: homedir/.../archivo"""
    norm = path.replace("\\", "/")
    markers = ["homedir/", "public_html/", "backup-"]
    for m in markers:
        idx = norm.find(m)
        if idx >= 0:
            return norm[idx:]
    parts = norm.split("/")
    return "/".join(parts[-4:]) if len(parts) > 4 else norm


REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte cPacleanS</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #0f0f17; color: #ddd; padding: 24px; line-height: 1.5; }
        .container { max-width: 1100px; margin: 0 auto; }
        .header { background: linear-gradient(135deg, #1a1a2e, #16213e); border-radius: 12px; padding: 28px; margin-bottom: 18px; border: 1px solid #0f3460; }
        .header h1 { font-size: 26px; color: #00d4ff; }
        .header p { color: #8892b0; font-size: 13px; margin-top: 6px; }
        .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; margin-bottom: 18px; }
        .card { background: #1a1a2e; border-radius: 10px; padding: 16px; text-align: center; border: 1px solid #2a2a4a; }
        .card .num { font-size: 30px; font-weight: bold; }
        .card .lbl { color: #8892b0; font-size: 11px; margin-top: 4px; }
        .c-crit .num { color: #ff4444; }
        .c-high .num { color: #ff8800; }
        .c-med .num { color: #ffbb33; }
        .c-low .num { color: #00C851; }
        .c-conf .num { color: #ff4444; }
        .c-clean .num { color: #33b5e5; }
        .box { background: #1a1a2e; border-radius: 10px; padding: 18px; margin-bottom: 16px; border: 1px solid #2a2a4a; }
        .box h2 { color: #00d4ff; font-size: 16px; margin-bottom: 12px; padding-bottom: 8px; border-bottom: 1px solid #2a2a4a; }
        .tag { display: inline-block; background: #0f3460; color: #00d4ff; padding: 4px 10px; border-radius: 16px; font-size: 11px; margin: 2px; }
        table { width: 100%; border-collapse: collapse; }
        th { background: #16213e; color: #00d4ff; padding: 8px 10px; text-align: left; font-size: 12px; white-space: nowrap; }
        td { padding: 7px 10px; border-bottom: 1px solid #222; font-size: 12px; vertical-align: top; }
        td.fname { word-break: break-word; max-width: 180px; }
        td.desc { word-break: break-word; }
        td.ctx { font-family: Consolas, monospace; font-size: 11px; color: #aaa; word-break: break-all; max-width: 280px; }
        tr:hover { background: rgba(0,212,255,0.04); }
        .badge { padding: 2px 7px; border-radius: 10px; font-size: 10px; font-weight: 700; color: #fff; white-space: nowrap; }
        .b-critical { background: #ff4444; }
        .b-high { background: #ff8800; }
        .b-medium { background: #ffbb33; color: #333; }
        .b-low { background: #00C851; }
        .confirmed { color: #ff4444; font-weight: 700; font-size: 11px; }
        .suspect { color: #ffaa00; font-size: 11px; }
        .cleaned { background: #00C851; color: #fff; padding: 1px 6px; border-radius: 6px; font-size: 10px; }
        .bar-row { display: flex; align-items: center; margin: 2px 0; }
        .bar-label { width: 130px; font-size: 11px; color: #8892b0; overflow: hidden; text-overflow: ellipsis; }
        .bar-fill { height: 16px; border-radius: 3px; background: #0f3460; }
        .bar-count { margin-left: 6px; font-size: 11px; }
        .log-ok { color: #00C851; }
        .log-warn { color: #ffbb33; }
        .log-err { color: #ff4444; }
        .log-info { color: #33b5e5; }
        .db-row-deleted { color: #ff4444; font-size: 11px; }
        .db-suspicious { color: #ffbb33; font-size: 11px; }
        .db-protected { color: #33b5e5; font-size: 11px; }
        .reinstalled { color: #00C851; font-weight: 600; }
        .not-in-repo { color: #ffbb33; }
        .footer { text-align: center; color: #555; font-size: 11px; padding: 18px; }
        @media print { body { background: #fff; color: #222; } .box, .header, .card { background: #f8f8f8; border-color: #ddd; } }
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>cPacleanS - Reporte de Seguridad</h1>
        <p>{{ generated_at }} &bull; {{ result.total_files_scanned }} archivos &bull; {{ result.scan_duration_seconds }}s &bull; {{ result.workers_used }} workers
        {% if result.clean_mode_used %} &bull; Modo: <strong>{{ result.clean_mode_used|upper }}</strong>{% endif %}
        {% if result.critical_only_mode %} &bull; <span style="color:#33b5e5;">Solo contenido critico</span>{% endif %}</p>
        <p style="margin-top:4px;">Backup: {{ backup_path|short_name }}</p>
    </div>

    {% if result.critical_only_mode %}
    <div class="box" style="border-color:#0f3460; background:#12122a;">
        <h2 style="color:#33b5e5;">Modo Solo Contenido Critico</h2>
        <p style="color:#8892b0; font-size:12px; margin-top:4px;">
            Solo se escanearon rutas restaurables manualmente al hosting
            (<strong style="color:#c0c0c0;">public_html</strong>,
            <strong style="color:#c0c0c0;">mail</strong>,
            <strong style="color:#c0c0c0;">bases de datos SQL</strong>,
            <strong style="color:#c0c0c0;">moodledata</strong>).
            <strong style="color:#fff;">{{ result.omitted_paths_count }}</strong> archivos de sistema omitidos
            (ips, logs, ssl, bandwidth, etc. &mdash; cPanel los recrea automaticamente al restaurar la cuenta).
        </p>
    </div>
    {% endif %}

    <div class="cards">
        <div class="card c-crit"><div class="num">{{ result.summary_by_severity.get('critical', 0) }}</div><div class="lbl">Criticos</div></div>
        <div class="card c-high"><div class="num">{{ result.summary_by_severity.get('high', 0) }}</div><div class="lbl">Altos</div></div>
        <div class="card c-med"><div class="num">{{ result.summary_by_severity.get('medium', 0) }}</div><div class="lbl">Medios</div></div>
        <div class="card c-low"><div class="num">{{ result.summary_by_severity.get('low', 0) }}</div><div class="lbl">Bajos</div></div>
        <div class="card c-conf"><div class="num">{{ confirmed_count }}</div><div class="lbl">Confirmados</div></div>
        <div class="card c-clean"><div class="num">{{ result.total_cleaned }}</div><div class="lbl">Cuarentena</div></div>
    </div>

    {% if result.cms_detected %}
    <div class="box">
        <h2>CMS Detectados</h2>
        {% for cms in result.cms_detected %}<span class="tag">{{ cms|upper }}</span>{% endfor %}
        {% if result.db_prefixes %}
        <p style="color:#8892b0; font-size:11px; margin-top:8px;">
            Prefijos: {% for cms, prefix in result.db_prefixes.items() %}{{ cms|upper }}={{ prefix }} {% endfor %}
        </p>
        {% endif %}
    </div>
    {% endif %}

    {% if result.cms_restore_log %}
    <div class="box">
        <h2>Restauracion CMS</h2>
        {% for e in result.cms_restore_log %}
        <div class="log-{{ e.type }}">[{{ e.cms|upper }}] {{ e.message }}</div>
        {% endfor %}
    </div>
    {% endif %}

    {% if result.db_interventions_log %}
    <div class="box" style="border-color:#4a0f0f;">
        <h2 style="color:#ff6666;">Intervenciones en Base de Datos ({{ result.db_interventions_log|length }})</h2>
        <p style="color:#8892b0; font-size:11px; margin-bottom:10px;">
            Solo se eliminan filas con malware CRITICO CONFIRMADO en tablas protegidas.
            Las filas sospechosas se marcan para revision manual.
        </p>
        <table>
            <thead>
                <tr>
                    <th>Archivo</th><th>Tabla</th><th>CMS</th><th>Tipo</th><th>Detalle</th><th>Accion</th>
                </tr>
            </thead>
            <tbody>
            {% for e in result.db_interventions_log %}
            <tr>
                <td style="font-size:11px;">{{ e.file }}</td>
                <td style="font-weight:600;">{{ e.table }}</td>
                <td>{% if e.cms %}<span class="tag">{{ e.cms|upper }}</span>{% else %}-{% endif %}</td>
                <td>{% if e.type == 'row_deleted' %}<span class="db-row-deleted">FILA ELIMINADA</span>
                    {% elif e.type == 'removed_line' %}<span class="db-row-deleted">LINEA ELIMINADA</span>
                    {% elif e.type == 'suspicious' %}<span class="db-suspicious">SOSPECHOSO</span>
                    {% else %}<span style="color:#aaa;">{{ e.type }}</span>{% endif %}</td>
                <td class="ctx">{{ e.detail|e }}</td>
                <td style="font-size:11px;">{{ e.action }}</td>
            </tr>
            {% endfor %}
            </tbody>
        </table>
    </div>
    {% endif %}

    {% if result.plugins_temas_log %}
    <div class="box" style="border-color:#0f4a60;">
        <h2 style="color:#33b5e5;">Plugins y Temas Removidos ({{ result.plugins_temas_log|length }})</h2>
        <p style="color:#8892b0; font-size:11px; margin-bottom:10px;">
            Reinstalar SOLO desde repositorios oficiales del CMS — no reutilizar archivos originales.
        </p>
        <table>
            <thead>
                <tr>
                    <th>CMS</th><th>Tipo</th><th>Nombre</th><th>Version</th><th>Activo</th><th>Accion</th><th>Reinstalado</th>
                </tr>
            </thead>
            <tbody>
            {% for e in result.plugins_temas_log %}
            <tr>
                <td><span class="tag">{{ e.cms|upper }}</span></td>
                <td>{{ e.type }}</td>
                <td style="font-weight:600;">{{ e.name }}</td>
                <td style="color:#8892b0;">{{ e.version }}</td>
                <td>{% if e.is_active %}<span style="color:#00C851;">SI</span>{% else %}<span style="color:#666;">no</span>{% endif %}</td>
                <td>{% if e.action == 'cuarentena' %}<span style="color:#33b5e5;">cuarentena</span>
                    {% elif e.action == 'eliminado' %}<span style="color:#ff4444;">eliminado</span>
                    {% else %}<span style="color:#ffbb33;">{{ e.action[:40] }}</span>{% endif %}</td>
                <td>{% if e.reinstalled and e.reinstalled.status == 'reinstalled' %}<span class="reinstalled">v{{ e.reinstalled.version }}</span>
                    {% elif e.reinstalled and e.reinstalled.status == 'not_in_repo' %}<span class="not-in-repo">no en repo</span>
                    {% elif e.reinstalled and e.reinstalled.status == 'manual_required' %}<span class="not-in-repo">manual</span>
                    {% elif e.is_active %}<span style="color:#666;">pendiente</span>
                    {% else %}-{% endif %}</td>
            </tr>
            {% endfor %}
            </tbody>
        </table>
    </div>
    {% endif %}

    <div class="box">
        <h2>Por Categoria</h2>
        {% for cat, count in result.summary_by_category.items()|sort(attribute='1', reverse=True) %}
        <div class="bar-row">
            <span class="bar-label">{{ cat }}</span>
            <div class="bar-fill" style="width: {{ (count / max_cat * 250)|int }}px;"></div>
            <span class="bar-count">{{ count }}</span>
        </div>
        {% endfor %}
    </div>

    <div class="box">
        <h2>Hallazgos ({{ result.findings|length }})</h2>
        <table>
            <thead>
                <tr>
                    <th>Sev.</th>
                    <th>Tipo</th>
                    <th>Archivo</th>
                    <th>Ruta</th>
                    <th>Linea</th>
                    <th>Descripcion</th>
                    <th>Contexto</th>
                    <th>Estado</th>
                </tr>
            </thead>
            <tbody>
                {% for f in findings_sorted %}
                <tr>
                    <td><span class="badge b-{{ f.severity }}">{{ f.severity|upper }}</span></td>
                    <td>{% if f.confirmed_malware %}<span class="confirmed">CONFIRMADO</span>{% else %}<span class="suspect">Sospechoso</span>{% endif %}</td>
                    <td class="fname">{{ f.file_path|short_name }}</td>
                    <td class="fname" style="font-size:10px;color:#8892b0;">{{ f.file_path|malware_ruta }}</td>
                    <td>{{ f.line_number or '-' }}</td>
                    <td class="desc">{{ f.description }}</td>
                    <td class="ctx">{{ f.context|e }}</td>
                    <td>{% if f.cleaned %}<span class="cleaned">Limpiado</span>{% endif %}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>

    {% if result.virustotal_hits %}
    <div class="box">
        <h2>VirusTotal</h2>
        <table>
            <thead><tr><th>Archivo</th><th>Detecciones</th><th>Enlace</th></tr></thead>
            <tbody>
            {% for vt in result.virustotal_hits %}
            <tr>
                <td>{{ vt.file_path|short_name }}</td>
                <td>{{ vt.detection_count }}/{{ vt.total_engines }}</td>
                <td><a href="{{ vt.permalink }}" style="color:#00d4ff;">Ver</a></td>
            </tr>
            {% endfor %}
            </tbody>
        </table>
    </div>
    {% endif %}

    <div class="footer">cPacleanS v{{ app_version }} &bull; {{ generated_at }}</div>
</div>
</body>
</html>"""


class ReportGenerator:
    def __init__(self, output_dir: str = None):
        self.output_dir = Path(output_dir) if output_dir else Path.cwd()

    def generate(self, result: ScanResult, backup_path: str = "") -> str:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = self.output_dir / f"cpacleans_report_{timestamp}.html"

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings_sorted = sorted(result.findings, key=lambda f: severity_order.get(f.severity, 5))
        max_cat = max(result.summary_by_category.values(), default=1)
        confirmed_count = sum(1 for f in result.findings if f.confirmed_malware)

        env = Environment()
        env.filters["truncate_path"] = truncate_path
        env.filters["short_name"] = short_name
        env.filters["malware_ruta"] = malware_ruta
        template = env.from_string(REPORT_TEMPLATE)

        html = template.render(
            result=result, findings_sorted=findings_sorted, confirmed_count=confirmed_count,
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            backup_path=backup_path, max_cat=max_cat, app_version=APP_VERSION,
        )
        output_path.write_text(html, encoding="utf-8")
        return str(output_path)

    def generate_pdf(self, result: ScanResult, backup_path: str = "") -> str:
        """PDF resumen para clientes — robusto con backups grandes, maximo 50 hallazgos."""
        from fpdf import FPDF

        self.output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pdf_path = self.output_dir / f"cpacleans_report_{timestamp}.pdf"

        confirmed_count = sum(1 for f in result.findings if f.confirmed_malware)
        suspect_count = result.total_threats_found - confirmed_count

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=20)
        pdf.add_page()

        # -- Header --
        pdf.set_fill_color(26, 26, 46)
        pdf.rect(10, 10, 190, 30, "F")
        pdf.set_font("Helvetica", "B", 20)
        pdf.set_text_color(0, 212, 255)
        pdf.set_xy(15, 14)
        pdf.cell(0, 10, "cPacleanS - Reporte de Seguridad")
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(136, 146, 176)
        pdf.set_xy(15, 26)
        bname = Path(backup_path).name if backup_path else "N/A"
        pdf.cell(0, 6, self._safe_text(f"{datetime.now().strftime('%Y-%m-%d %H:%M')}  |  {bname}  |  {result.total_files_scanned} archivos  |  {result.scan_duration_seconds}s"))

        # -- Que encontramos --
        pdf.set_xy(10, 48)
        pdf.set_font("Helvetica", "B", 15)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 10, "Que encontramos")
        pdf.ln(14)

        pdf.set_font("Helvetica", "", 11)
        pdf.set_text_color(50, 50, 50)
        lines = [
            f"Se escanearon {result.total_files_scanned} archivos del backup.",
            f"Se encontraron {result.total_threats_found} posibles amenazas.",
            "",
            f"   {confirmed_count} son MALWARE CONFIRMADO (virus, shells, backdoors).",
            f"   {suspect_count} son sospechosos que requieren revision manual.",
            f"   {result.total_cleaned} archivos fueron puestos en cuarentena.",
        ]
        if result.cms_detected:
            lines.append("")
            lines.append(f"CMS detectados: {', '.join(c.upper() for c in result.cms_detected)}.")
            if getattr(result, "db_prefixes", None):
                prefixes_str = ", ".join(f"{c.upper()}={p}" for c, p in result.db_prefixes.items())
                lines.append(f"Prefijos BD: {prefixes_str}")
        if result.clean_mode_used:
            modes_es = {"normal": "Normal (solo confirmados)", "intermediate": "Intermedio", "strict": "Estricto (todo)"}
            lines.append(f"Modo de limpieza: {modes_es.get(result.clean_mode_used, result.clean_mode_used)}.")
        if getattr(result, "critical_only_mode", False) and getattr(result, "omitted_paths_count", 0) > 0:
            lines.append("")
            lines.append(f"Modo Solo Contenido Critico activo: {result.omitted_paths_count} archivos de")
            lines.append("sistema omitidos (logs, ssl, bandwidth — cPanel los recrea al restaurar).")

        for line in lines:
            pdf.cell(0, 6, self._safe_text(line))
            pdf.ln(6)

        # -- Severidad --
        pdf.ln(6)
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 10, "Nivel de riesgo")
        pdf.ln(12)

        colors = {"critical": (255, 68, 68), "high": (255, 136, 0), "medium": (255, 187, 51), "low": (0, 200, 81)}
        labels_es = {"critical": "CRITICO - Malware activo", "high": "ALTO - Codigo peligroso", "medium": "MEDIO - Sospechoso", "low": "BAJO - Informativo"}

        for sev in ["critical", "high", "medium", "low"]:
            count = result.summary_by_severity.get(sev, 0)
            if count > 0:
                r, g, b = colors[sev]
                pdf.set_font("Helvetica", "B", 11)
                pdf.set_text_color(r, g, b)
                pdf.cell(50, 7, f"  {labels_es[sev]}")
                pdf.set_text_color(50, 50, 50)
                pdf.set_font("Helvetica", "", 11)
                pdf.cell(0, 7, f"  {count} detecciones")
                pdf.ln(8)

        # -- CMS Restauracion --
        if result.cms_restore_log:
            pdf.ln(4)
            pdf.set_font("Helvetica", "B", 13)
            pdf.set_text_color(0, 0, 0)
            pdf.cell(0, 10, "Restauracion de CMS")
            pdf.ln(12)
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(50, 50, 50)
            shown_cms = 0
            for entry in result.cms_restore_log:
                if shown_cms >= 30:
                    pdf.cell(0, 5, self._safe_text(f"  ... y {len(result.cms_restore_log) - 30} entradas mas"))
                    break
                marker = {"success": "[OK]", "warning": "[!]", "error": "[X]", "info": "[i]"}.get(entry["type"], "[-]")
                pdf.cell(0, 5, self._safe_text(f"  {marker} [{entry['cms'].upper()}] {entry['message'][:100]}"))
                pdf.ln(5)
                shown_cms += 1

        # -- Intervenciones en BD --
        db_log = getattr(result, "db_interventions_log", None)
        if db_log:
            pdf.ln(4)
            pdf.set_font("Helvetica", "B", 13)
            pdf.set_text_color(0, 0, 0)
            pdf.cell(0, 10, f"Intervenciones en Base de Datos ({len(db_log)})")
            pdf.ln(12)
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(50, 50, 50)
            pdf.cell(0, 5, "Solo se eliminan filas con malware CRITICO CONFIRMADO.")
            pdf.ln(6)
            shown_db = 0
            for entry in db_log:
                if shown_db >= 30:
                    pdf.cell(0, 5, self._safe_text(f"  ... y {len(db_log) - 30} entradas mas"))
                    pdf.ln(5)
                    break
                e_type = entry.get("type", "")
                marker = "[X]" if "deleted" in e_type or "removed" in e_type else "[?]"
                table = entry.get("table", "?")
                action = entry.get("action", "")[:60]
                detail = entry.get("detail", "")[:80]
                pdf.cell(0, 5, self._safe_text(f"  {marker} {table} | {action} | {detail}"))
                pdf.ln(5)
                shown_db += 1

        # -- Plugins y Temas --
        if getattr(result, "plugins_temas_log", None):
            pdf.ln(4)
            pdf.set_font("Helvetica", "B", 13)
            pdf.set_text_color(0, 0, 0)
            pdf.cell(0, 10, f"Plugins y Temas Removidos ({len(result.plugins_temas_log)})")
            pdf.ln(12)
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(50, 50, 50)
            pdf.cell(0, 5, "Reinstalar SOLO desde repositorios oficiales del CMS.")
            pdf.ln(6)
            shown_pt = 0
            for entry in result.plugins_temas_log:
                if shown_pt >= 40:
                    remaining_pt = len(result.plugins_temas_log) - 40
                    pdf.cell(0, 5, self._safe_text(
                        f"  ... y {remaining_pt} mas. Ver reporte HTML o REINSTALAR_PLUGINS.txt"))
                    pdf.ln(5)
                    break
                ver = f" v{entry['version']}" if entry.get("version") != "desconocida" else ""
                action = entry.get("action", "")
                action_short = "cuarentena" if action == "cuarentena" else "eliminado" if action == "eliminado" else action[:20]
                active_mark = "[A]" if entry.get("is_active") else "[-]"
                ri = entry.get("reinstalled")
                ri_mark = ""
                if ri and isinstance(ri, dict):
                    if ri.get("status") == "reinstalled":
                        ri_mark = f" -> v{ri.get('version', '?')} (reinstalado)"
                    elif ri.get("status") == "not_in_repo":
                        ri_mark = " (no en repo)"
                    elif ri.get("status") == "manual_required":
                        ri_mark = " (manual)"
                pdf.cell(0, 5, self._safe_text(
                    f"  {active_mark} [{entry['cms'].upper()}] {entry['type']}: {entry['name']}{ver} -> {action_short}{ri_mark}"))
                pdf.ln(5)
                shown_pt += 1

        # -- Top hallazgos --
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 10, "Principales hallazgos")
        pdf.ln(12)

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_findings = sorted(result.findings, key=lambda f: severity_order.get(f.severity, 5))

        pdf.set_font("Helvetica", "B", 8)
        pdf.set_fill_color(230, 230, 230)
        pdf.cell(18, 6, "Riesgo", 1, fill=True)
        pdf.cell(15, 6, "Tipo", 1, fill=True)
        pdf.cell(45, 6, "Archivo", 1, fill=True)
        pdf.cell(0, 6, "Que se encontro", 1, fill=True)
        pdf.ln(6)

        MAX_PDF_ROWS = 50
        pdf.set_font("Helvetica", "", 7)
        shown = 0
        for f in sorted_findings:
            if shown >= MAX_PDF_ROWS:
                break
            fname = Path(f.file_path).name
            if len(fname) > 28:
                fname = fname[:25] + "..."
            tipo = "MALWARE" if f.confirmed_malware else "Sospec."
            desc = f.description
            if len(desc) > 65:
                desc = desc[:62] + "..."
            r, g, b = colors.get(f.severity, (100, 100, 100))
            pdf.set_text_color(r, g, b)
            pdf.cell(18, 5, f.severity.upper(), 1)
            pdf.set_text_color(50, 50, 50)
            pdf.cell(15, 5, tipo, 1)
            pdf.cell(45, 5, self._safe_text(fname), 1)
            pdf.cell(0, 5, self._safe_text(desc), 1)
            pdf.ln(5)
            shown += 1

        remaining = len(sorted_findings) - MAX_PDF_ROWS
        if remaining > 0:
            pdf.ln(3)
            pdf.set_font("Helvetica", "I", 8)
            pdf.set_text_color(120, 120, 120)
            pdf.cell(0, 6, f"  ... y {remaining} hallazgos mas. Ver reporte HTML completo para la lista detallada.")

        # -- Recomendaciones --
        pdf.ln(10)
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 10, "Que significa esto")
        pdf.ln(12)
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(50, 50, 50)
        recs = [
            "CONFIRMADO = Archivos que contienen virus, shells o codigo malicioso comprobado.",
            "Sospechoso = Patrones inusuales que pueden ser legitimos o maliciosos.",
            "",
            "Los archivos confirmados fueron puestos en cuarentena (copia de seguridad guardada).",
            "Los archivos sospechosos NO fueron modificados, solo se reportan.",
            "",
            "RECOMENDACIONES:",
            "  1. Revisar los archivos sospechosos con un desarrollador.",
            "  2. Cambiar todas las contrasenas (cPanel, FTP, DB, email).",
            "  3. Actualizar WordPress, plugins y temas a la ultima version.",
            "  4. Instalar un firewall (Wordfence, Sucuri) en el nuevo sitio.",
        ]
        for r in recs:
            pdf.cell(0, 6, self._safe_text(r))
            pdf.ln(6)

        # -- Footer --
        pdf.set_y(-20)
        pdf.set_font("Helvetica", "I", 7)
        pdf.set_text_color(150, 150, 150)
        pdf.cell(0, 8, f"cPacleanS v{APP_VERSION} | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", align="C")

        pdf.output(str(pdf_path))
        return str(pdf_path)

    @staticmethod
    def _safe_text(text: str) -> str:
        """Reemplaza caracteres que fpdf2 no puede codificar en latin-1."""
        return text.encode("latin-1", errors="replace").decode("latin-1")
