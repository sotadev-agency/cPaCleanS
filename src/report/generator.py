"""Generador de reportes HTML + PDF para cPacleanS — formato legible y robusto.

v2.6.7: el PDF se rediseña siguiendo la estructura del "Informe de limpieza":
  1. Malware encontrado (con ruta original)
  2. Plugins con malware / no instalados (dominio, nombre, autor, razon)
  3. Entradas y comentarios extraños por dominio
  4. Usuarios extraños por dominio
  5. Contrasenas generadas (cPanel, WordPress, BD, correos) con nota de cambio
  6. Observaciones adicionales (0KB, .htaccess, plugins de seguridad)
  7. Recomendaciones segun hallazgos
  8. Garantia de 30 dias post-limpieza
"""
import re
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
        .score { display: inline-block; min-width: 28px; text-align: center; padding: 2px 6px; border-radius: 8px; font-size: 10px; font-weight: 700; color: #fff; }
        .sc-high { background: #ff4444; }
        .sc-med { background: #ffbb33; color: #333; }
        .sc-low { background: #00C851; }
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
        {% if result.main_domain %}
        <p style="margin-top:4px;">Dominio principal: <strong style="color:#00d4ff;">{{ result.main_domain }}</strong>
        {% if result.all_domains and result.all_domains|length > 1 %}
            <span style="color:#8892b0; font-size:11px;">(+{{ result.all_domains|length - 1 }} dominios adicionales)</span>
        {% endif %}</p>
        {% endif %}
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

    {% if result.generated_passwords %}
    <div class="box" style="border-color:#0f4a2a;">
        <h2 style="color:#33ff99;">Contrasenas Generadas</h2>
        <p style="color:#8892b0; font-size:11px; margin-bottom:10px;">
            Nota: <strong style="color:#ffbb33;">cambiar por otra propia cuando pueda ingresar</strong>.
        </p>
        {% for cat, items in result.generated_passwords.items() %}
        {% if items %}
        <p style="color:#00d4ff; font-size:12px; margin-top:8px; text-transform:uppercase;">{{ cat }}</p>
        <table>
            <tbody>
            {% for it in items %}
            <tr>
                <td style="font-size:11px;">{{ it.get('domain') or it.get('db') or it.get('email') or '-' }}</td>
                <td style="font-size:11px;">{{ it.get('user') or '' }}</td>
                <td style="font-family:Consolas,monospace; color:#33ff99;">{{ it.get('pass') }}</td>
            </tr>
            {% endfor %}
            </tbody>
        </table>
        {% endif %}
        {% endfor %}
    </div>
    {% endif %}

    {% if result.db_cron_log %}
    <div class="box" style="border-color:#4a3a0f;">
        <h2 style="color:#ffbb33;">Eventos Cron Inseguros Neutralizados ({{ result.db_cron_log|length }})</h2>
        <table>
            <thead><tr><th>Dominio</th><th>Hook</th><th>Razon</th><th>Accion</th></tr></thead>
            <tbody>
            {% for c in result.db_cron_log %}
            <tr><td>{{ c.domain }}</td><td>{{ c.hook }}</td><td>{{ c.reason }}</td><td>{{ c.action }}</td></tr>
            {% endfor %}
            </tbody>
        </table>
    </div>
    {% endif %}

    {% if result.db_users_log %}
    <div class="box" style="border-color:#4a0f2a;">
        <h2 style="color:#ff6699;">Usuarios de Base de Datos ({{ result.db_users_log|length }})</h2>
        <table>
            <thead><tr><th>Dominio</th><th>Usuario</th><th>Accion</th><th>Razon</th></tr></thead>
            <tbody>
            {% for u in result.db_users_log %}
            <tr><td>{{ u.domain }}</td><td>{{ u.user }}</td><td>{{ u.action }}</td><td>{{ u.reason }}</td></tr>
            {% endfor %}
            </tbody>
        </table>
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

    {% if manual_plugins %}
    <div class="box" style="border-color:#4a2a0f;">
        <h2 style="color:#ff8833;">Plugins sin restaurar — instalacion manual requerida ({{ manual_plugins|length }})</h2>
        <p style="color:#8892b0; font-size:11px; margin-bottom:10px;">
            Estos plugins no estan disponibles en <strong style="color:#c0c0c0;">wordpress.org</strong>
            (probablemente premium o con licencia privada).
            Deben instalarse manualmente desde el sitio oficial del desarrollador.
            <strong style="color:#ff8833;">No reinstalar desde el backup original — puede contener malware.</strong>
        </p>
        <table>
            <thead>
                <tr><th>Plugin (slug)</th><th>Version instalada</th><th>Motivo</th></tr>
            </thead>
            <tbody>
            {% for p in manual_plugins %}
            <tr>
                <td style="font-weight:600; white-space:nowrap;">{{ p.name }}</td>
                <td style="color:#8892b0;">{{ p.version or 'desconocida' }}</td>
                <td style="font-size:11px; color:#ffaa66;">{{ p.reason }}</td>
            </tr>
            {% endfor %}
            </tbody>
        </table>
    </div>
    {% endif %}

    {% if db_interventions_filtered %}
    <div class="box" style="border-color:#4a0f0f;">
        <h2 style="color:#ff6666;">Intervenciones en Base de Datos ({{ db_interventions_filtered|length }}{% if db_interventions_omitted %} de {{ db_interventions_total }}{% endif %})</h2>
        <p style="color:#8892b0; font-size:11px; margin-bottom:10px;">
            Solo se eliminan filas con malware CRITICO CONFIRMADO en tablas protegidas.
            Las filas sospechosas se marcan para revision manual.
            {% if db_interventions_omitted %}<br>{{ db_interventions_omitted }} registros omitidos por datos insuficientes (menos de 4/5 campos confirmados).{% endif %}
        </p>
        <table>
            <thead>
                <tr>
                    <th>Archivo</th><th>Tabla</th><th>CMS</th><th>Tipo</th><th>Detalle</th><th>Accion</th>
                </tr>
            </thead>
            <tbody>
            {% for e in db_interventions_filtered %}
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
                    <th>Score</th>
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
                    <td><span class="score {% if f.confidence_score >= 70 %}sc-high{% elif f.confidence_score >= 30 %}sc-med{% else %}sc-low{% endif %}">{{ f.confidence_score }}</span></td>
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

    {% if result.junk_files_log %}
    <div class="box" style="border-color:#4a3a0f;">
        <h2 style="color:#ffbb33;">Archivos Residuales ({{ result.junk_files_log|length }})</h2>
        <p style="color:#8892b0; font-size:11px; margin-bottom:10px;">
            Archivos no pertenecientes al CMS limpio eliminados o puestos en cuarentena.
        </p>
        <table>
            <thead>
                <tr><th>Ruta</th><th>CMS</th><th>Categoria</th><th>Accion</th></tr>
            </thead>
            <tbody>
            {% for j in result.junk_files_log %}
            <tr>
                <td style="font-size:11px; word-break:break-all;">{{ j.path|truncate_path }}</td>
                <td><span class="tag">{{ j.cms|upper }}</span></td>
                <td>{{ j.category }}</td>
                <td>{% if j.action == 'quarantined' %}<span style="color:#33b5e5;">cuarentena</span>
                    {% elif j.action == 'deleted' %}<span style="color:#ff4444;">eliminado</span>
                    {% else %}<span style="color:#8892b0;">solo reporte</span>{% endif %}</td>
            </tr>
            {% endfor %}
            </tbody>
        </table>
    </div>
    {% endif %}

    {% if result.spam_posts_log %}
    <div class="box" style="border-color:#4a0f2a;">
        <h2 style="color:#ff6699;">Posts SPAM Eliminados ({{ result.spam_posts_log|length }})</h2>
        <p style="color:#8892b0; font-size:11px; margin-bottom:10px;">
            Publicaciones con contenido SPAM inyectado detectadas por scoring automatico.
        </p>
        <table>
            <thead>
                <tr><th>ID</th><th>Titulo</th><th>Score</th><th>Razones</th><th>Accion</th></tr>
            </thead>
            <tbody>
            {% for s in result.spam_posts_log %}
            <tr>
                <td>{{ s.post_id }}</td>
                <td style="font-size:11px;">{{ s.title_preview|e }}</td>
                <td><span class="score {% if s.score >= 65 %}sc-high{% elif s.score >= 30 %}sc-med{% else %}sc-low{% endif %}">{{ s.score }}</span></td>
                <td style="font-size:10px; color:#8892b0;">{{ s.reasons|join(', ') if s.reasons else '-' }}</td>
                <td>{% if s.action == 'deleted' %}<span class="db-row-deleted">ELIMINADO</span>
                    {% elif s.action == 'suspect_not_deleted' %}<span class="db-suspicious">NO ELIMINADO</span>
                    {% else %}<span style="color:#8892b0;">solo reporte</span>{% endif %}</td>
            </tr>
            {% endfor %}
            </tbody>
        </table>
    </div>
    {% endif %}

    {% if result.backups_isolated_log %}
    <div class="box" style="border-color:#0f4a1a;">
        <h2 style="color:#33ff77;">Backups Aislados ({{ result.backups_isolated_log|length }})</h2>
        <p style="color:#8892b0; font-size:11px; margin-bottom:10px;">
            Archivos y carpetas de backup detectados y aislados en <code>quarantine/backups/</code> antes del escaneo.
            No se contabilizan como amenazas &mdash; son copias de seguridad del usuario.
        </p>
        <table>
            <thead>
                <tr><th>Nombre</th><th>Tipo</th><th>Ruta</th><th>Accion</th></tr>
            </thead>
            <tbody>
            {% for b in result.backups_isolated_log %}
            <tr>
                <td style="font-weight:600; white-space:nowrap;">{{ b.name }}</td>
                <td><span class="tag">{{ b.type }}</span></td>
                <td style="font-size:11px; word-break:break-all; color:#8892b0;">{{ b.path }}</td>
                <td><span style="color:#33ff77; font-weight:600;">aislado</span></td>
            </tr>
            {% endfor %}
            </tbody>
        </table>
    </div>
    {% endif %}

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


# URLs de la base de conocimiento (cambio de contrasenas)
_KB_CPANEL = "https://hosting-ssd.com/hosting/index.php?rp=/knowledgebase/94/"
_KB_WORDPRESS = "https://hosting-ssd.com/hosting/index.php?rp=/knowledgebase/18/"
_KB_EMAIL = "https://hosting-ssd.com/hosting/index.php?rp=/knowledgebase/55/"
_KB_SECURITY = "https://hosting-ssd.com/hosting/index.php?rp=/knowledgebase/90/"


class ReportGenerator:
    def __init__(self, output_dir: str = None):
        self.output_dir = Path(output_dir) if output_dir else Path.cwd()

    @staticmethod
    def _filter_db_interventions(entries: list) -> tuple:
        """Filtra intervenciones de BD: solo mostrar registros con al menos
        3 de 4 campos confirmados (archivo, tabla, detalle, accion).
        Retorna (filtered_list, omitted_count, total_count).
        """
        if not entries:
            return [], 0, 0

        filtered = []
        for e in entries:
            fields_ok = 0
            if e.get("file", "").strip():
                fields_ok += 1
            if e.get("table", "").strip():
                fields_ok += 1
            if e.get("detail", "").strip():
                fields_ok += 1
            fragment = e.get("action", "") or e.get("context", "")
            if (fragment or "").strip():
                fields_ok += 1

            if fields_ok >= 3:
                filtered.append(e)

        omitted = len(entries) - len(filtered)
        return filtered, omitted, len(entries)

    def generate(self, result: ScanResult, backup_path: str = "") -> str:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = self.output_dir / f"cpacleans_report_{timestamp}.html"

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings_sorted = sorted(result.findings, key=lambda f: severity_order.get(f.severity, 5))
        max_cat = max(result.summary_by_category.values(), default=1)
        confirmed_count = sum(1 for f in result.findings if f.confirmed_malware)

        db_log = getattr(result, "db_interventions_log", None) or []
        db_log_no_spam = [e for e in db_log if e.get("type") != "spam_post"]
        db_filtered, db_omitted, db_total = self._filter_db_interventions(
            db_log_no_spam)

        env = Environment()
        env.filters["truncate_path"] = truncate_path
        env.filters["short_name"] = short_name
        env.filters["malware_ruta"] = malware_ruta
        template = env.from_string(REPORT_TEMPLATE)

        restore_log = getattr(result, "cms_restore_log", None) or []
        manual_plugins = [e for e in restore_log if e.get("type") == "manual_required"]

        html = template.render(
            result=result, findings_sorted=findings_sorted, confirmed_count=confirmed_count,
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            backup_path=backup_path, max_cat=max_cat, app_version=APP_VERSION,
            db_interventions_filtered=db_filtered,
            db_interventions_omitted=db_omitted,
            db_interventions_total=db_total,
            manual_plugins=manual_plugins,
        )
        output_path.write_text(html, encoding="utf-8")
        return str(output_path)

    # ───────────────────────── Helpers PDF (v2.6.7) ──────────────────────────

    # Regex de dominio real: etiqueta(s) + TLD alfabético de 2-24 chars.
    # Rechaza nombres de BD, "public_html", prefijos de tabla, rutas, etc.
    _DOMAIN_RE = re.compile(
        r'^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$',
        re.IGNORECASE,
    )
    # Etiquetas que NUNCA son dominios aunque tengan forma sospechosa
    _NON_DOMAIN_LABELS = frozenset({
        "public_html", "www", "htdocs", "principal", "sitio", "localhost",
        "wp-content", "homedir", "example.com", "localhost.localdomain",
    })

    @classmethod
    def _is_real_domain(cls, value: str) -> bool:
        """True solo si value es un nombre de dominio válido (no BD, no carpeta)."""
        d = (value or "").strip().strip("'\"").lower()
        d = d.split("://")[-1].split("/")[0].split(":")[0]
        if d.startswith("www."):
            d = d[4:]
        if not d or d in cls._NON_DOMAIN_LABELS:
            return False
        if d.replace(".", "").isdigit():   # IPs no son dominios aquí
            return False
        return bool(cls._DOMAIN_RE.match(d))

    @classmethod
    def _domains_from_result(cls, result: ScanResult) -> list:
        """Reune SOLO dominios reales desde varias fuentes del resultado.

        Issue v3.0.2 #2: campos `domain` de logs de BD/plugins pueden contener
        nombres de base de datos o etiquetas de carpeta ('public_html'). Se valida
        cada candidato contra un patrón de dominio real para no confundir al cliente.
        """
        domains = []
        seen = set()

        def _add(d):
            d = (d or "").strip()
            if not d or not cls._is_real_domain(d):
                return
            key = d.lower()
            if key not in seen:
                seen.add(key)
                domains.append(d)

        # Fuente autoritativa: dominio principal del hosting (de userdata/main).
        _add(getattr(result, "main_domain", "") or "")
        for d in getattr(result, "all_domains", None) or []:
            _add(d)

        # Fuentes secundarias: solo aportan si pasan la validación de dominio.
        gp = getattr(result, "generated_passwords", None) or {}
        for it in gp.get("wordpress", []) or []:
            _add(it.get("domain"))
        for u in getattr(result, "db_users_log", None) or []:
            _add(u.get("domain"))
        for c in getattr(result, "db_cron_log", None) or []:
            _add(c.get("domain"))
        for e in getattr(result, "plugins_temas_log", None) or []:
            _add(e.get("domain"))
        if not domains:
            _add("principal")  # no pasará la validación → lista queda vacía
        return domains or ["principal"]

    @staticmethod
    def _mc(pdf, h, text):
        """multi_cell robusto: deja el cursor en el margen izquierdo (evita el
        error 'Not enough horizontal space' por el new_x=RIGHT por defecto de fpdf2)."""
        from fpdf.enums import XPos, YPos
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, h, ReportGenerator._safe_text(text),
                       new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def _pdf_section(self, pdf, title):
        """Encabezado de seccion estandar."""
        if pdf.get_y() > 250:
            pdf.add_page()
        pdf.ln(3)
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_text_color(0, 51, 102)
        self._mc(pdf, 8, title)
        pdf.set_draw_color(0, 120, 200)
        pdf.set_line_width(0.4)
        y = pdf.get_y()
        pdf.line(10, y, 200, y)
        pdf.ln(3)
        pdf.set_text_color(50, 50, 50)

    def _pdf_paragraph(self, pdf, text, size=10):
        pdf.set_font("Helvetica", "", size)
        pdf.set_text_color(50, 50, 50)
        self._mc(pdf, 5, text)
        pdf.ln(1)

    def _pdf_subhead(self, pdf, text):
        """Subtitulo en negrita azul (7.1, categorias, Cobertura, etc.)."""
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(0, 51, 102)
        self._mc(pdf, 6, text)
        pdf.set_text_color(50, 50, 50)

    def generate_pdf(self, result: ScanResult, backup_path: str = "") -> str:
        """PDF tipo 'Informe de limpieza' — estructura orientada al cliente (v2.6.7)."""
        from fpdf import FPDF

        self.output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pdf_path = self.output_dir / f"cpacleans_informe_{timestamp}.pdf"

        # v2.6.8 Bug #3: consolidar rutas duplicadas — un registro representativo
        # por archivo (varios hallazgos del mismo archivo se muestran una vez).
        _sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        _by_path = {}
        for f in result.findings:
            if not f.confirmed_malware:
                continue
            key = f.file_path
            prev = _by_path.get(key)
            if prev is None or _sev_order.get(f.severity, 5) < _sev_order.get(prev.severity, 5):
                _by_path[key] = f
        confirmed = sorted(_by_path.values(),
                           key=lambda f: _sev_order.get(f.severity, 5))
        domains = self._domains_from_result(result)

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=18)
        pdf.add_page()

        # ── Portada ──
        pdf.set_fill_color(0, 51, 102)
        pdf.rect(10, 10, 190, 26, "F")
        pdf.set_font("Helvetica", "B", 19)
        pdf.set_text_color(255, 255, 255)
        pdf.set_xy(15, 16)
        pdf.cell(0, 10, "INFORME DE LIMPIEZA")
        pdf.set_font("Helvetica", "", 9)
        pdf.set_xy(15, 27)
        bname = Path(backup_path).name if backup_path else "N/A"
        pdf.cell(0, 6, self._safe_text(
            f"{datetime.now().strftime('%Y-%m-%d %H:%M')}  |  {bname}  |  "
            f"{result.total_files_scanned} archivos analizados"))
        pdf.ln(20)
        pdf.set_text_color(50, 50, 50)
        pdf.set_font("Helvetica", "", 10)
        cms_str = ", ".join(c.upper() for c in result.cms_detected) if result.cms_detected else "N/D"
        self._mc(pdf, 5,
            f"Se completó la limpieza de seguridad de la cuenta de hosting. "
            f"CMS detectados: {cms_str}. Dominios: {', '.join(domains)}.")
        pdf.ln(2)

        # ── 1. Malware encontrado + 2. Ruta de archivos infectados ──
        self._pdf_section(pdf, "1. Malware encontrado y rutas de archivos infectados")
        if confirmed:
            self._pdf_paragraph(pdf,
                f"Se detectaron {len(confirmed)} archivos con malware confirmado "
                "(rutas consolidadas, una por archivo). Se incluye la ruta original "
                "de cada archivo infectado:")
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_fill_color(230, 230, 230)
            pdf.cell(16, 6, "Riesgo", 1, fill=True)
            pdf.cell(45, 6, "Archivo", 1, fill=True)
            pdf.cell(0, 6, "Ruta original", 1, fill=True)
            pdf.ln(6)
            pdf.set_font("Helvetica", "", 7)
            for f in confirmed[:60]:
                fname = Path(f.file_path).name
                if len(fname) > 26:
                    fname = fname[:23] + "..."
                ruta = malware_ruta(f.file_path)
                if len(ruta) > 80:
                    ruta = "..." + ruta[-77:]
                pdf.cell(16, 5, self._safe_text(f.severity.upper()[:6]), 1)
                pdf.cell(45, 5, self._safe_text(fname), 1)
                pdf.cell(0, 5, self._safe_text(ruta), 1)
                pdf.ln(5)
            if len(confirmed) > 60:
                self._pdf_paragraph(pdf, f"... y {len(confirmed) - 60} archivos más (ver reporte HTML).", 8)
        else:
            self._pdf_paragraph(pdf, "No se encontraron archivos con malware confirmado.")

        # ── 2. Plugins con malware / no instalados ──
        self._pdf_section(pdf, "2. Plugins con malware / no instalados")
        restore_log = getattr(result, "cms_restore_log", None) or []
        manual_plugins = [e for e in restore_log if e.get("type") == "manual_required"]
        pt_log = getattr(result, "plugins_temas_log", None) or []
        plugin_rows = []
        for e in manual_plugins:
            plugin_rows.append({
                "domain": e.get("domain", "-"),
                "name": e.get("name", "-"),
                "author": e.get("author", "-"),
                "reason": e.get("reason", "no disponible en wordpress.org"),
            })
        for e in pt_log:
            if e.get("type") == "plugin" and e.get("reinstalled", {}) and \
                    e["reinstalled"].get("status") in ("not_in_repo", "manual_required"):
                plugin_rows.append({
                    "domain": e.get("domain", "-"),
                    "name": e.get("name", "-"),
                    "author": e.get("author", "-"),
                    "reason": "no disponible en repositorio oficial",
                })
        if plugin_rows:
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_fill_color(230, 230, 230)
            pdf.cell(38, 6, "Dominio", 1, fill=True)
            pdf.cell(50, 6, "Plugin", 1, fill=True)
            pdf.cell(42, 6, "Autor", 1, fill=True)
            pdf.cell(0, 6, "Razón", 1, fill=True)
            pdf.ln(6)
            pdf.set_font("Helvetica", "", 7)
            for r in plugin_rows[:50]:
                pdf.cell(38, 5, self._safe_text(str(r["domain"])[:22]), 1)
                pdf.cell(50, 5, self._safe_text(str(r["name"])[:30]), 1)
                pdf.cell(42, 5, self._safe_text(str(r["author"])[:24]), 1)
                pdf.cell(0, 5, self._safe_text(str(r["reason"])[:40]), 1)
                pdf.ln(5)
        else:
            self._pdf_paragraph(pdf, "No hay plugins con malware ni plugins pendientes de instalación manual.")

        # ── 3. Entradas y comentarios extraños por dominio ──
        self._pdf_section(pdf, "3. Entradas y comentarios extraños en WordPress")
        spam_log = getattr(result, "spam_posts_log", None) or []
        if spam_log:
            self._pdf_paragraph(pdf,
                f"Se detectaron {len(spam_log)} publicaciones/comentarios con contenido "
                "extraño (SPAM/malware inyectado):")
            pdf.set_font("Helvetica", "", 7)
            for s in spam_log[:30]:
                title = (s.get("title_preview", "") or "")[:60]
                kind = s.get("kind", "entrada")
                self._mc(pdf, 5,
                    f"  - {kind} ID {s.get('post_id', '?')} (score {s.get('score', 0)}): {title} -> {s.get('action', '')}")
            if len(spam_log) > 30:
                self._pdf_paragraph(pdf, f"... y {len(spam_log) - 30} más.", 8)
        else:
            self._pdf_paragraph(pdf, "No se encontraron entradas ni comentarios extraños.")
        for d in domains:
            self._pdf_paragraph(pdf,
                f"Dominio {d}: se desmarcó la opción de 'permitir avisos de enlaces de otros "
                "blogs (pingbacks y trackbacks) en las nuevas entradas'.", 9)

        # ── 4. Usuarios extraños por dominio ──
        self._pdf_section(pdf, "4. Usuarios extraños detectados")
        users_log = getattr(result, "db_users_log", None) or []
        dangerous_users = [u for u in users_log if "eliminado" in u.get("action", "") or "peligroso" in u.get("action", "")]
        if dangerous_users:
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_fill_color(230, 230, 230)
            pdf.cell(45, 6, "Dominio", 1, fill=True)
            pdf.cell(55, 6, "Usuario", 1, fill=True)
            pdf.cell(0, 6, "Acción", 1, fill=True)
            pdf.ln(6)
            pdf.set_font("Helvetica", "", 7)
            for u in dangerous_users[:40]:
                pdf.cell(45, 5, self._safe_text(str(u.get("domain", "-"))[:26]), 1)
                pdf.cell(55, 5, self._safe_text(str(u.get("user", "-"))[:32]), 1)
                pdf.cell(0, 5, self._safe_text(str(u.get("action", "-"))[:45]), 1)
                pdf.ln(5)
        else:
            for d in domains:
                self._pdf_paragraph(pdf, f"Dominio {d}: no se encontraron usuarios extraños.", 9)

        # ── 5. Contraseñas generadas ──
        self._pdf_section(pdf, "5. Contraseñas generadas (cPanel, WordPress, base de datos)")
        self._pdf_paragraph(pdf,
            "Nota: cambiar por otra propia cuando pueda ingresar. Se generaron como medida "
            "preventiva; permiten comprobar que se siguen las recomendaciones de seguridad.")
        gp = getattr(result, "generated_passwords", None) or {}
        cat_labels = {"cpanel": "cPanel", "wordpress": "WordPress",
                      "database": "Base de datos"}
        any_pwd = False
        for cat in ("cpanel", "wordpress", "database"):
            items = gp.get(cat, []) or []
            if not items:
                continue
            any_pwd = True
            self._pdf_subhead(pdf, cat_labels[cat] + ":")
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(50, 50, 50)
            for it in items:
                ident = it.get("domain") or it.get("db") or "-"
                user = it.get("user", "")
                pwd = it.get("pass", "")
                self._mc(pdf, 5,
                    f"   {ident}  |  usuario: {user}  |  contraseña: {pwd}")
            pdf.ln(1)
        if not any_pwd:
            self._pdf_paragraph(pdf, "No se generaron contraseñas en esta ejecución.")

        # ── 6b. Correos que requieren cambio manual (Mejora v2.6.8: NO se cambian
        #         automáticamente — solo se listan) ──
        emails = gp.get("emails", []) or []
        self._pdf_subhead(pdf, "Correos que requieren cambio manual de contraseña:")
        if emails:
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(50, 50, 50)
            for it in emails:
                addr = it.get("email") or "-"
                self._mc(pdf, 5, f"   {addr}  ->  cambiar contraseña manualmente desde cPanel")
        else:
            self._pdf_paragraph(pdf,
                "Cambiar manualmente la contraseña de todas las cuentas de correo corporativo "
                "desde cPanel. La herramienta no modifica contraseñas de correo automáticamente.", 9)

        # ── 6. Observaciones adicionales ──
        self._pdf_section(pdf, "6. Observaciones adicionales")
        obs = []
        obs.append("Se eliminaron archivos de tamaño 0 (0 KB).")
        obs.append("Se actualizó el archivo .htaccess para fortalecer la seguridad del servidor "
                   "y prevenir accesos no autorizados o ataques comunes.")
        obs.append("Se instalaron plugins de seguridad provenientes del repositorio oficial de WordPress.")
        if getattr(result, "db_cron_log", None):
            obs.append(f"Se comentaron/neutralizaron {len(result.db_cron_log)} eventos de cron maliciosos en la base de datos.")
        if getattr(result, "db_very_infected", False):
            obs.append("La base de datos presentaba un nivel alto de infección; se realizó limpieza profunda de filas maliciosas.")
        for o in obs:
            self._pdf_paragraph(pdf, f"- {o}", 10)

        # ── 7. Recomendaciones ──
        self._pdf_section(pdf, "7. Recomendaciones según lo encontrado")
        self._pdf_paragraph(pdf,
            "Desde ahora se desactiva la opción de 'permitir enlaces de notificaciones desde otros "
            "blogs (pingbacks y trackbacks)'. Asimismo, se desactiva el archivo xmlrpc.php de todas "
            "las páginas a nuestro cargo, debido a reportes internacionales de uso del servidor "
            "para atacar a terceros.")
        self._pdf_subhead(pdf, "7.1 Cambio de contraseñas")
        self._pdf_paragraph(pdf,
            "Se realizó el cambio de contraseñas como medida preventiva. Esta acción también "
            "permite comprobar si el cliente sigue las recomendaciones de seguridad indicadas.")
        self._pdf_subhead(pdf, "7.2 Plugins no instalados")
        self._pdf_paragraph(pdf,
            "Algunos plugins no se instalaron porque no son compatibles con la versión actual del "
            "sistema o no están actualizados, lo que podría representar un riesgo de seguridad o "
            "inestabilidad en el funcionamiento.")
        self._pdf_subhead(pdf, "7.3 Implementar CAPTCHA")
        self._pdf_paragraph(pdf,
            "Para fortalecer la seguridad de los formularios del sitio, se recomienda instalar un "
            "sistema CAPTCHA que previene el envío automatizado de spam y accesos maliciosos por bots.")

        # ── 8. Garantía ──
        self._pdf_section(pdf, "8. Garantía de 30 días post-limpieza")
        self._pdf_subhead(pdf, "Cobertura")
        self._pdf_paragraph(pdf,
            "Ofrecemos una garantía de 30 días posteriores a la limpieza. En el improbable caso de "
            "reinfección, realizaremos una nueva limpieza gratuita para asegurar el correcto "
            "funcionamiento de su sistema.")
        self._pdf_subhead(pdf, "Condiciones")
        self._pdf_paragraph(pdf,
            "La garantía aplica únicamente si: se siguen todas las recomendaciones de seguridad "
            "proporcionadas por nuestro equipo; y no se instalan plugins/themes/modificaciones no "
            "verificados durante este período.")
        self._pdf_subhead(pdf, "Excepciones")
        self._pdf_paragraph(pdf,
            "Reinfecciones causadas por acciones externas no vinculadas al servicio original "
            "(por ejemplo: contraseñas débiles, acceso de terceros no autorizados).")
        self._pdf_paragraph(pdf,
            "Por seguridad debe cambiar las contraseñas de cPanel, WordPress y correos corporativos:")
        self._pdf_paragraph(pdf, f"  - cPanel: {_KB_CPANEL}", 8)
        self._pdf_paragraph(pdf, f"  - WordPress: {_KB_WORDPRESS}", 8)
        self._pdf_paragraph(pdf, f"  - Correos corporativos: {_KB_EMAIL}", 8)
        self._pdf_paragraph(pdf, f"  - Recomendaciones de seguridad: {_KB_SECURITY}", 8)

        # ── Footer ──
        pdf.set_y(-15)
        pdf.set_font("Helvetica", "I", 7)
        pdf.set_text_color(150, 150, 150)
        pdf.cell(0, 8, f"cPacleanS v{APP_VERSION} | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", align="C")

        pdf.output(str(pdf_path))
        return str(pdf_path)

    # v2.6.8: mapa de caracteres Unicode comunes a equivalentes latin-1 imprimibles
    # (fpdf2 con fuentes core usa latin-1; las tildes y ñ SI estan en latin-1, pero
    #  guiones largos, comillas tipograficas, vinetas, flechas, etc. NO).
    _UNICODE_MAP = {
        "–": "-", "—": "-", "−": "-",      # – — −
        "‘": "'", "’": "'", "‚": "'",       # ‘ ’ ‚
        "“": '"', "”": '"', "„": '"',       # “ ” „
        "…": "...",                                    # …
        "•": "-", "●": "-", "·": "-",        # • ● ·
        "→": "->", "←": "<-", "⇒": "=>",     # → ← ⇒
        "✅": "[OK]", "✔": "[OK]", "❌": "[X]", # ✅ ✔ ❌
        " ": " ",  # nbsp (espacio duro)
    }

    @staticmethod
    def _safe_text(text: str) -> str:
        """Prepara texto para fpdf2 (latin-1): conserva tildes/ñ y traduce los
        caracteres Unicode no representables en latin-1 a equivalentes legibles."""
        if text is None:
            return ""
        for uni, repl in ReportGenerator._UNICODE_MAP.items():
            if uni in text:
                text = text.replace(uni, repl)
        return text.encode("latin-1", errors="replace").decode("latin-1")

    def generate_json(self, result: ScanResult, backup_path: str = "") -> str:
        """v3.1: Exporta resultados del escaneo a JSON estructurado.

        Útil para integraciones con sistemas de tickets (WHMCS, Jira, Slack),
        webhooks post-limpieza, o archivo de auditoría.
        """
        import json

        self.output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = self.output_dir / f"cpacleans_{timestamp}.json"

        confirmed_count = sum(1 for f in result.findings if f.confirmed_malware)

        data = {
            "meta": {
                "tool": "cPaCleanS",
                "version": APP_VERSION,
                "scan_date": datetime.now().isoformat(),
                "backup_file": Path(backup_path).name if backup_path else "",
                "clean_mode": result.clean_mode_used or "scan_only",
                "main_domain": getattr(result, "main_domain", ""),
                "domains": getattr(result, "all_domains", []),
            },
            "cms": {
                "detected": result.cms_detected,
                "prefixes": getattr(result, "db_prefixes", {}),
            },
            "summary": {
                "total_files_scanned": result.total_files_scanned,
                "total_threats": result.total_threats_found,
                "confirmed_malware": confirmed_count,
                "quarantined": result.total_cleaned,
                "scan_duration_seconds": result.scan_duration_seconds,
                "workers": result.workers_used,
                "by_severity": result.summary_by_severity,
                "by_category": result.summary_by_category,
            },
            "iocs": getattr(result, "iocs", {}),
            "findings": [
                {
                    "file": f.file_path,
                    "line": f.line_number,
                    "severity": f.severity,
                    "category": f.category,
                    "description": f.description,
                    "confidence": f.confidence_score,
                    "confirmed": f.confirmed_malware,
                    "cleaned": f.cleaned,
                    "sha256": f.sha256,
                    "context": f.context[:200] if f.context else "",
                }
                for f in result.findings
                if f.severity in ("critical", "high") or f.confirmed_malware
            ][:500],
            "database": {
                "interventions": len(getattr(result, "db_interventions_log", []) or []),
                "cron_neutralized": len(getattr(result, "db_cron_log", []) or []),
                "users_cleaned": len(getattr(result, "db_users_log", []) or []),
                "spam_posts": len(getattr(result, "spam_posts_log", []) or []),
                "very_infected": getattr(result, "db_very_infected", False),
            },
            "cms_restore": {
                "plugins_processed": len(getattr(result, "plugins_temas_log", []) or []),
                "log": [
                    {
                        "type": e.get("type"),
                        "message": e.get("message", "")[:120],
                    }
                    for e in (getattr(result, "cms_restore_log", []) or [])[:100]
                ],
            },
            "virustotal": [
                {
                    "file": Path(r.file_path).name,
                    "sha256": r.sha256,
                    "detections": r.detection_count,
                    "total_engines": r.total_engines,
                    "permalink": r.permalink,
                }
                for r in (getattr(result, "virustotal_hits", []) or [])
            ],
        }

        with open(str(json_path), "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)

        return str(json_path)
