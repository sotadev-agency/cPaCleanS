"""Escáner de dumps MySQL — detecta inyecciones SQL, backdoors en DB, código malicioso en campos."""
import re
import gzip
from pathlib import Path
from ..core.engine import Finding

SQL_PATTERNS = [
    # Inyecciones y backdoors en datos
    ("critical", "db_backdoor", r'<\?php\s.{0,50}(eval|system|exec|passthru|shell_exec)', "Código PHP embebido en dump SQL"),
    ("critical", "db_backdoor", r"CONCAT\s*\(\s*(?:CHAR|0x)[^)]{20,}\)", "CONCAT con CHAR ofuscado (posible backdoor)"),
    ("critical", "db_injection", r"INTO\s+OUTFILE\s+['\"]", "SELECT INTO OUTFILE (escritura de archivo)"),
    ("critical", "db_injection", r"LOAD_FILE\s*\(\s*['\"]", "LOAD_FILE (lectura de archivo del servidor)"),

    # Usuarios maliciosos y privilegios
    ("high", "db_user", r"CREATE\s+USER\s+.*IDENTIFIED\s+BY", "Creación de usuario MySQL en dump"),
    ("high", "db_user", r"GRANT\s+ALL\s+PRIVILEGES", "Otorgamiento de todos los privilegios"),
    ("high", "db_user", r"INSERT\s+INTO\s+.*(?:wp_users|jos_users|mdl_user).*(?:admin|administrator)", "Inserción de usuario admin sospechoso"),

    # WordPress específico
    ("high", "wp_malware", r"INSERT\s+INTO\s+.*wp_options.*(?:siteurl|home|blogname).*https?://(?!.*localhost)", "Modificación de URL del sitio WordPress"),
    ("critical", "wp_malware", r"INSERT\s+INTO\s+.*wp_options.*(?:active_plugins|template|stylesheet).*(?:eval|base64|shell)", "Plugin/tema malicioso en wp_options"),
    ("high", "wp_malware", r"INSERT\s+INTO\s+.*wp_posts.*<script[^>]*>", "Script inyectado en posts de WordPress"),
    ("high", "wp_malware", r"INSERT\s+INTO\s+.*wp_posts.*<iframe[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|width\s*=\s*[\"']?[01])", "iFrame oculto en posts de WordPress"),

    # Joomla específico
    ("high", "joomla_malware", r"INSERT\s+INTO\s+.*(?:jos|joomla)_extensions.*(?:eval|base64|system)", "Extensión maliciosa en tabla Joomla"),

    # Moodle específico
    ("high", "moodle_malware", r"INSERT\s+INTO\s+.*mdl_(?:config|config_plugins).*(?:eval|exec|system)", "Config maliciosa en tabla Moodle"),

    # Contenido inyectado genérico
    ("high", "db_xss", r"<script[^>]*>(?:[^<]|<(?!/script))*(?:document\.cookie|window\.location|eval\()", "XSS almacenado con payload activo"),
    ("medium", "db_xss", r"<iframe[^>]*src\s*=\s*['\"]https?://", "iFrame externo en datos de la base"),
    ("medium", "db_spam", r"(?:viagra|cialis|casino|poker|pharm|pills|enlargement|lottery)\s", "Contenido spam en base de datos"),

    # Funciones MySQL peligrosas
    ("high", "db_dangerous", r"(?:BENCHMARK|SLEEP)\s*\(\s*\d{4,}", "Función de timing con valor alto (DoS)"),
    ("medium", "db_dangerous", r"(?:INFORMATION_SCHEMA|mysql\.user|performance_schema)", "Consulta a tablas de sistema"),
]


class DatabaseScanner:
    name = "Database Scanner"

    def __init__(self):
        self._compiled = [(re.compile(p, re.IGNORECASE | re.DOTALL), s, c, d) for s, c, p, d in SQL_PATTERNS]

    def scan(self, file_path: str) -> list:
        fp = Path(file_path)
        ext = fp.suffix.lower()
        name = fp.name.lower()

        if ext not in (".sql",) and not name.endswith(".sql.gz"):
            return []

        findings = []
        max_findings = 500

        try:
            line_num = 0
            for line in self._iter_lines(file_path):
                line_num += 1
                if len(findings) >= max_findings:
                    break
                for compiled, sev, cat, desc in self._compiled:
                    match = compiled.search(line)
                    if match:
                        ctx = match.group(0)[:200]
                        findings.append(Finding(
                            file_path=file_path,
                            line_number=line_num,
                            severity=sev,
                            category=cat,
                            description=desc,
                            matched_pattern=compiled.pattern[:80],
                            context=ctx,
                        ))
        except (OSError, PermissionError, UnicodeDecodeError):
            pass

        return findings

    def _iter_lines(self, file_path: str):
        if file_path.endswith(".gz"):
            with gzip.open(file_path, "rt", encoding="utf-8", errors="replace") as f:
                for line in f:
                    yield line
        else:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    yield line

    def can_clean(self, finding: Finding) -> bool:
        return False

    def clean(self, finding: Finding) -> bool:
        return False
