"""Escáner especializado para CMS — WordPress, Joomla, Moodle, Laravel, Softaculous."""
import re
from pathlib import Path
from ..core.engine import Finding
from ..config.settings import CACHE_HTACCESS_SIGNATURES


CMS_CHECKS = {
    "wordpress": {
        "config_file": "wp-config.php",
        "core_dirs": ["wp-admin", "wp-includes"],
        "content_dir": "wp-content",
        "plugin_dir": "wp-content/plugins",
        "theme_dir": "wp-content/themes",
        "upload_dir": "wp-content/uploads",
        "suspicious_in_uploads": [".php", ".phtml", ".phar", ".php5"],
        "config_patterns": [
            ("high", "wp_debug_exposed", r"define\s*\(\s*['\"]WP_DEBUG['\"]\s*,\s*true\s*\)", "WP_DEBUG habilitado"),
            ("critical", "wp_config_backdoor", r"(eval|assert|system|exec)\s*\(", "Código malicioso en wp-config.php"),
            ("high", "wp_extra_user", r"define\s*\(\s*['\"](?:DB_USER|DB_PASSWORD)['\"]", None),
        ],
    },
    "joomla": {
        "config_file": "configuration.php",
        "core_dirs": ["administrator", "components", "modules", "plugins"],
        "content_dir": "media",
        "upload_dir": "images",
        "suspicious_in_uploads": [".php", ".phtml", ".phar", ".php5"],
        "config_patterns": [
            ("critical", "joomla_config_backdoor", r"(eval|assert|system|exec)\s*\(", "Código malicioso en configuration.php"),
            ("high", "joomla_debug", r"\$debug\s*=\s*['\"]?1['\"]?", "Debug habilitado en Joomla"),
        ],
    },
    "moodle": {
        "config_file": "config.php",
        "core_dirs": ["mod", "lib", "admin", "course"],
        "content_dir": "moodledata",
        "upload_dir": "moodledata/filedir",
        "suspicious_in_uploads": [".php", ".phtml", ".phar", ".php5"],
        "config_patterns": [
            ("critical", "moodle_config_backdoor", r"(eval|assert|system|exec)\s*\(", "Código malicioso en config.php de Moodle"),
            ("high", "moodle_debug", r"\$CFG->debug\s*=\s*\d{4,}", "Debug mode alto en Moodle"),
        ],
    },
    "laravel": {
        "config_file": ".env",
        "core_dirs": ["app", "routes", "config", "resources"],
        "content_dir": "storage",
        "upload_dir": "storage/app/public",
        "suspicious_in_uploads": [".php", ".phtml", ".phar", ".php5"],
        "config_patterns": [
            ("high", "laravel_debug", r"APP_DEBUG\s*=\s*true", "APP_DEBUG habilitado en producción"),
            ("critical", "laravel_key_exposed", r"APP_KEY\s*=\s*base64:", None),
            ("high", "laravel_env_exposed", r"(?:DB_PASSWORD|MAIL_PASSWORD|AWS_SECRET)\s*=\s*\S+", None),
        ],
    },
}

KNOWN_MALICIOUS_PLUGINS = [
    # ── WordPress: shells / backdoors disfrazados de plugins ──
    "wp-file-manager",             # CVE-2020-25213 — RCE sin autenticacion (explotado masivamente)
    "revslider",                   # Versiones nulled = backdoor; historico CVE-2014-9734
    "gravityforms-nulled",
    "developer-tools-hacked",
    "super-socializer-exploit",

    # ── WordPress: permiten ejecucion de PHP arbitrario ──
    "php-everywhere",              # CVE-2022-24663 — ejecuta PHP en cualquier widget/post
    "insert-php",                  # Permite PHP raw en posts
    "insert-php-code-snippet",
    "exec-php",
    "run-php",
    "allow-php-in-posts-and-pages",
    "wp-php-widget",

    # ── WordPress: file managers / acceso directo al sistema de archivos ──
    "wp-file-manager-pro",
    "file-manager-advanced",
    "file-manager-advanced-shortcode",
    "adminer",                     # phpMyAdmin alternativo — DB expuesto sin auth si mal configurado

    # ── WordPress: CVEs criticos explotados en campanas masivas ──
    "wp-automatic",                # SQLi + file upload RCE (explotado 2024)
    "yuzo-related-post",           # CVE-2019-6715 — PHP object injection
    "social-warfare",              # CVE-2019-9978 — RCE via stored XSS
    "yellow-pencil-visual-theme-customizer",  # CVE-2019-9943 — privilege escalation
    "wp-gdpr-compliance",          # CVE-2018-19207 — subscriber → admin
    "total-donations",             # Abandonado con file upload RCE
    "simple-file-list",            # CVE-2022-1119 — file upload sin autenticacion
    "instabuilder",                # Shell upload
    "coming-soon-page",
    "simple-social-buttons",

    # ── WordPress: plugins fake con nombres genericos sospechosos ──
    "wordpress-backup-free",
    "system-update-manager",
    "plugin-activator",
    "site-manager-pro",
    "admin-tools-manager",
    "wp-config-editor",
    "database-manager-pro",
    "wordpress-optimizer",
    "wp-performance-booster",

    # ── WordPress: versiones nulled de plugins premium conocidos ──
    "elementor-pro-nulled",
    "acf-pro-nulled",
    "wpbakery-nulled",
    "divi-theme-nulled",
    "avada-nulled",
    "the7-nulled",
    "bebuilder-nulled",
    "salient-nulled",

    # ── Joomla: extensiones con historial de RCE / SQLi ──
    "com_extplorer",               # File manager — RCE si accesible publicamente
    "com_jce",                     # JCE editor — versiones viejas con file upload
    "com_fabrik",                  # SQLi historico
    "mod_wrapper",                 # Puede inyectar iframes arbitrarios
    "com_media-fake",
]


class CMSScanner:
    name = "CMS Scanner"

    def __init__(self):
        self._detected_cms = {}

    def _path_contains_segment(self, fp_str: str, segment: str) -> bool:
        """Verifica que segment sea un componente de ruta real, no substring."""
        parts = fp_str.split("/")
        seg_parts = segment.split("/")
        seg_len = len(seg_parts)
        for i in range(len(parts) - seg_len + 1):
            if parts[i:i + seg_len] == seg_parts:
                return True
        return False

    def scan(self, file_path: str) -> list:
        fp = Path(file_path)
        findings = []
        fp_str = str(fp).replace("\\", "/")

        try:
            for cms_name, checks in CMS_CHECKS.items():
                if fp.name.lower() == checks["config_file"].lower():
                    findings.extend(self._scan_config(fp, cms_name, checks))

                upload_dir = checks.get("upload_dir", "")
                if upload_dir and self._path_contains_segment(fp_str, upload_dir):
                    in_core = any(core in fp_str for core in checks.get("core_dirs", []))
                    in_other_cms = False
                    for other_name, other_checks in CMS_CHECKS.items():
                        if other_name != cms_name:
                            if any(self._path_contains_segment(fp_str, d) for d in other_checks.get("core_dirs", [])):
                                in_other_cms = True
                                break
                    if not in_core and not in_other_cms:
                        findings.extend(self._check_uploads(fp, cms_name, checks))

                plugin_dir = checks.get("plugin_dir", "")
                if plugin_dir and self._path_contains_segment(fp_str, plugin_dir):
                    findings.extend(self._check_plugins(fp, cms_name))

            findings.extend(self._check_generic_cms(fp))
        except Exception:
            pass

        return findings

    def _scan_config(self, fp: Path, cms_name: str, checks: dict) -> list:
        findings = []
        try:
            content = fp.read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError):
            return findings

        for sev, cat, pattern, desc in checks.get("config_patterns", []):
            if desc is None:
                continue
            for i, line in enumerate(content.split("\n"), 1):
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        file_path=str(fp),
                        line_number=i,
                        severity=sev,
                        category=cat,
                        description=f"[{cms_name.upper()}] {desc}",
                        context=line.strip()[:200],
                    ))

        return findings

    SAFE_UPLOAD_PREFIXES = {
        "sucuri-", "wordfence", "ithemes-security", "wp-statistics",
        "woocommerce-", "wc-", "wp-mail-smtp",
    }

    def _check_uploads(self, fp: Path, cms_name: str, checks: dict) -> list:
        findings = []
        suspicious_exts = checks.get("suspicious_in_uploads", [".php", ".phtml", ".phar"])

        if fp.suffix.lower() in suspicious_exts:
            name_lower = fp.name.lower()
            is_known_safe = any(name_lower.startswith(p) for p in self.SAFE_UPLOAD_PREFIXES)
            if not is_known_safe:
                findings.append(Finding(
                    file_path=str(fp),
                    severity="critical",
                    category="cms_upload_php",
                    description=f"[{cms_name.upper()}] Archivo PHP en directorio de uploads: {fp.name}",
                ))

        if fp.suffix.lower() == ".htaccess":
            try:
                content = fp.read_text(encoding="utf-8", errors="replace")
                if re.search(r"AddHandler|SetHandler.*php|php_value", content, re.IGNORECASE):
                    content_lower = content.lower()
                    is_cache = any(sig.lower() in content_lower for sig in CACHE_HTACCESS_SIGNATURES)
                    findings.append(Finding(
                        file_path=str(fp),
                        severity="info" if is_cache else "critical",
                        category="cms_htaccess_override",
                        description=(f"[{cms_name.upper()}] Cache plugin htaccess - no malicioso"
                                     if is_cache else
                                     f"[{cms_name.upper()}] .htaccess malicioso en uploads habilitando PHP"),
                        context=content[:200],
                    ))
            except (OSError, PermissionError):
                pass

        return findings

    def _check_plugins(self, fp: Path, cms_name: str) -> list:
        findings = []
        path_str = str(fp).lower()

        for malicious in KNOWN_MALICIOUS_PLUGINS:
            if malicious in path_str:
                findings.append(Finding(
                    file_path=str(fp),
                    severity="high",
                    category="cms_malicious_plugin",
                    description=f"[{cms_name.upper()}] Plugin sospechoso/vulnerable: {malicious}",
                ))

        return findings

    def _check_generic_cms(self, fp: Path) -> list:
        findings = []
        name = fp.name.lower()

        if name == "index.php":
            try:
                content = fp.read_text(encoding="utf-8", errors="replace")
                if re.search(r'(eval|assert|base64_decode)\s*\(', content) and len(content) < 500:
                    findings.append(Finding(
                        file_path=str(fp),
                        severity="critical",
                        category="cms_index_hijack",
                        description="index.php posiblemente secuestrado (código ofuscado y corto)",
                        context=content[:200],
                    ))
            except (OSError, PermissionError):
                pass

        if name in (".user.ini", "php.ini"):
            try:
                content = fp.read_text(encoding="utf-8", errors="replace")
                if re.search(r"auto_(?:prepend|append)_file", content, re.IGNORECASE):
                    findings.append(Finding(
                        file_path=str(fp),
                        severity="critical",
                        category="cms_ini_injection",
                        description="PHP ini con auto_prepend/append_file — carga maliciosa automática",
                        context=content[:200],
                    ))
            except (OSError, PermissionError):
                pass

        return findings

    def can_clean(self, finding: Finding) -> bool:
        return finding.category in ("cms_upload_php", "cms_htaccess_override", "cms_index_hijack", "cms_ini_injection")

    def clean(self, finding: Finding) -> bool:
        fp = Path(finding.file_path)
        if not fp.exists():
            return False
        quarantine = fp.parent / ".quarantine"
        quarantine.mkdir(exist_ok=True)
        try:
            fp.rename(quarantine / f"{fp.name}.quarantined")
            return True
        except OSError:
            return False
