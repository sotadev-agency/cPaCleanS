"""Escaner de dumps MySQL — detecta inyecciones SQL, backdoors en DB, codigo malicioso en campos."""
import re
from pathlib import Path
from ..core.engine import Finding
from ..utils.db_utils import iter_sql_lines

SQL_PATTERNS = [
    # Inyecciones y backdoors en datos
    ("critical", "db_backdoor", r'<\?php\s.{0,50}(eval|system|exec|passthru|shell_exec)', "Codigo PHP embebido en dump SQL"),
    ("critical", "db_backdoor", r"CONCAT\s*\(\s*(?:CHAR|0x)[^)]{20,}\)", "CONCAT con CHAR ofuscado (posible backdoor)"),
    ("critical", "db_injection", r"INTO\s+OUTFILE\s+['\"]", "SELECT INTO OUTFILE (escritura de archivo)"),
    ("critical", "db_injection", r"LOAD_FILE\s*\(\s*['\"]", "LOAD_FILE (lectura de archivo del servidor)"),

    # Usuarios maliciosos y privilegios
    ("high", "db_user", r"CREATE\s+USER\s+.*IDENTIFIED\s+BY", "Creacion de usuario MySQL en dump"),
    ("high", "db_user", r"GRANT\s+ALL\s+PRIVILEGES", "Otorgamiento de todos los privilegios"),
    ("high", "db_user", r"INSERT\s+INTO\s+.*(?:_users).*(?:admin|administrator)", "Insercion de usuario admin sospechoso"),

    # WordPress especifico
    ("high", "wp_malware", r"INSERT\s+INTO\s+.*_options.*(?:siteurl|home|blogname).*https?://(?!.*localhost)", "Modificacion de URL del sitio WordPress"),
    ("critical", "wp_malware", r"INSERT\s+INTO\s+.*_options.*(?:active_plugins|template|stylesheet).*(?:eval|base64|shell)", "Plugin/tema malicioso en options"),
    ("high", "wp_malware", r"INSERT\s+INTO\s+.*_posts.*<script[^>]*>", "Script inyectado en posts de WordPress"),
    ("high", "wp_malware", r"INSERT\s+INTO\s+.*_posts.*<iframe[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|width\s*=\s*[\"']?[01])", "iFrame oculto en posts de WordPress"),

    # Joomla especifico
    ("high", "joomla_malware", r"INSERT\s+INTO\s+.*_extensions.*(?:eval|base64|system)", "Extension maliciosa en tabla Joomla"),

    # Moodle especifico
    ("high", "moodle_malware", r"INSERT\s+INTO\s+.*_(?:config|config_plugins).*(?:eval|exec|system)", "Config maliciosa en tabla Moodle"),

    # Contenido inyectado generico
    ("high", "db_xss", r"<script[^>]*>(?:[^<]|<(?!/script))*(?:document\.cookie|window\.location|eval\()", "XSS almacenado con payload activo"),
    ("medium", "db_xss", r"<iframe[^>]*src\s*=\s*['\"]https?://", "iFrame externo en datos de la base"),
    ("medium", "db_spam", r"(?:viagra|cialis|casino|poker|pharm|pills|enlargement|lottery)\s", "Contenido spam en base de datos"),

    # Funciones MySQL peligrosas
    ("high", "db_dangerous", r"(?:BENCHMARK|SLEEP)\s*\(\s*\d{4,}", "Funcion de timing con valor alto (DoS)"),
    ("medium", "db_dangerous", r"(?:INFORMATION_SCHEMA|mysql\.user|performance_schema)", "Consulta a tablas de sistema"),
]


_WP_OPTIONS_RE = re.compile(
    r"INSERT\s+INTO\s+[`'\"]?\w*options[`'\"]?\s", re.IGNORECASE
)
_WP_SAFE_OPTION_RE = re.compile(
    r"""(?:'|")(widget_\w+|theme_mods_\w+|sidebars_widgets|"""
    r"""auto_load\w*|cron|_transient_\w+|_site_transient_\w+|"""
    r"""rewrite_rules|active_plugins|uninstall_plugins|"""
    r"""dismissed_wp_pointers|recently_activated|widget_block)(?:'|")""",
    re.IGNORECASE,
)


class DatabaseScanner:
    name = "Database Scanner"

    def __init__(self):
        self._compiled = [(re.compile(p, re.IGNORECASE | re.DOTALL), s, c, d) for s, c, p, d in SQL_PATTERNS]

    def scan(self, file_path: str) -> list:
        fp = Path(file_path)
        name = fp.name.lower()

        is_sql = (
            fp.suffix.lower() == ".sql"
            or name.endswith(".sql.gz")
            or name.endswith(".sql.bz2")
        )
        if not is_sql:
            return []

        findings = []
        max_findings = 500

        try:
            line_num = 0
            for line in iter_sql_lines(file_path):
                line_num += 1
                if len(findings) >= max_findings:
                    break
                if len(line) > 2_000_000:
                    continue
                is_wp_safe_opt = (
                    _WP_OPTIONS_RE.search(line) and _WP_SAFE_OPTION_RE.search(line)
                )
                for compiled, sev, cat, desc in self._compiled:
                    match = compiled.search(line)
                    if match:
                        actual_sev = sev
                        actual_desc = desc
                        if is_wp_safe_opt and sev in ("critical", "high", "medium"):
                            actual_sev = "low"
                            actual_desc = f"{desc} — Contenido serializado normal de WordPress"
                        ctx = match.group(0)[:200]
                        findings.append(Finding(
                            file_path=file_path,
                            line_number=line_num,
                            severity=actual_sev,
                            category=cat,
                            description=actual_desc,
                            matched_pattern=compiled.pattern[:80],
                            context=ctx,
                        ))
        except (OSError, PermissionError, UnicodeDecodeError):
            pass

        return findings

    def can_clean(self, finding: Finding) -> bool:
        return False

    def clean(self, finding: Finding) -> bool:
        return False
