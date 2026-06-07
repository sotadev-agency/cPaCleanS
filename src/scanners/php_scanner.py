"""Escáner de archivos PHP, HTML, CSS, JS — detecta shells, backdoors, inyecciones."""
import re
import os
from pathlib import Path
from ..core.engine import Finding
from ..config.settings import (
    WP_TRUSTED_SLUGS, WP_WHITELIST_HASHES, CACHE_HTACCESS_SIGNATURES,
)

# Patrones PHP maliciosos (severidad, categoría, regex, descripción)
PHP_PATTERNS = [
    # Shells y backdoors
    ("critical", "webshell", r'\b(eval|assert|preg_replace)\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|gzdecode)\s*\(', "Ejecución con ofuscación (eval+decode)"),
    ("critical", "webshell", r'\b(eval|assert)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)', "Ejecución directa de input del usuario"),
    ("critical", "webshell", r'\b(FilesMan|c99shell|r57shell|b374k|p0wny)\b', "Shell web conocido detectado"),
    ("critical", "webshell", r'\b(WSO\s+\d|wso_version|alfa\s*shell)\b', "Shell web conocido detectado (WSO/Alfa)"),
    ("critical", "webshell", r'\$\w+\s*=\s*(?:chr\(\d+\)\s*\.?\s*){10,}', "Construcción de string por chr() encadenados"),
    ("critical", "backdoor", r'(system|exec|passthru|shell_exec|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)', "Ejecución de comandos desde input del usuario"),
    ("critical", "backdoor", r'<\?php\s+\$\w{1,3}\s*=\s*["\'][\w+/=]{50,}["\'];\s*(eval|assert)', "Backdoor ofuscado en base64"),

    # Inyecciones y código sospechoso
    ("high", "injection", r'\b(eval|assert)\s*\(\s*["\']', "Eval/assert con string literal"),
    ("high", "injection", r'preg_replace\s*\(\s*["\'][^"\']*\/e["\']', "preg_replace con modificador /e (ejecución)"),
    ("high", "injection", r'create_function\s*\(\s*["\'][^"\']*["\']', "create_function (ejecución dinámica)"),
    ("high", "injection", r'\bcall_user_func(_array)?\s*\(\s*\$', "call_user_func con variable (ejecución indirecta)"),
    ("high", "upload", r'move_uploaded_file\s*\(.*\$_(GET|POST|REQUEST)', "Upload con path controlado por usuario"),

    # Ofuscación
    ("high", "obfuscation", r'\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){10,}', "String con secuencias hex largas"),
    ("high", "obfuscation", r'base64_decode\s*\(\s*["\'][\w+/=]{100,}["\']', "Blob base64 largo decodificado"),
    ("medium", "obfuscation", r'\$\w+\s*=\s*str_replace\s*\([^)]+\)\s*;\s*\$\w+\s*\(', "Ejecución tras str_replace (evasión)"),
    ("medium", "obfuscation", r'(\$\w+\s*=\s*["\'][A-Za-z_]+["\'];\s*){3,}\$\w+\s*\(', "Variables intermedias para llamada ofuscada"),
    ("medium", "obfuscation", r'(?:gzinflate|gzdecode|gzuncompress)\s*\(\s*base64_decode', "Doble capa de ofuscación gz+base64"),

    # Funciones peligrosas sueltas
    ("medium", "suspicious", r'\b(dl|ini_set|ini_alter)\s*\(\s*["\']', "Carga dinámica de extensiones o config"),
    ("medium", "suspicious", r'file_(get|put)_contents\s*\(\s*\$_(GET|POST|REQUEST)', "Lectura/escritura de archivo con input del usuario"),
    ("medium", "suspicious", r'\bmail\s*\(\s*\$_(GET|POST|REQUEST)', "Envío de mail con input del usuario (spam relay)"),
    ("low", "suspicious", r'@(eval|assert|system|exec|passthru)', "Función peligrosa con supresión de errores"),
    ("low", "suspicious", r'(curl_exec|file_get_contents)\s*\(\s*["\']https?://', "Petición HTTP saliente hardcoded"),
]

JS_PATTERNS = [
    ("critical", "js_malware", r'document\.write\s*\(\s*unescape\s*\(', "document.write con unescape (inyección clásica)"),
    ("critical", "js_malware", r'eval\s*\(\s*(atob|unescape|decodeURIComponent)\s*\(', "Eval con decodificación (dropper JS)"),
    ("high", "js_malware", r'String\.fromCharCode\s*\(\s*(\d+\s*,\s*){20,}', "String.fromCharCode masivo (ofuscación)"),
    ("high", "js_injection", r'<script[^>]*src\s*=\s*["\']https?://(?!.*(?:googleapis|gstatic|cloudflare|jsdelivr|unpkg|cdnjs))', "Script externo de dominio no confiable"),
    ("medium", "js_suspicious", r'new\s+Function\s*\(\s*["\']', "new Function con string (eval implícito)"),
    ("medium", "js_crypto", r'(CoinHive|coinhive|cryptonight|minero?\b)', "Cripto-minero detectado"),
]

HTACCESS_PATTERNS = [
    ("critical", "htaccess_redirect", r'RewriteRule\s+.*https?://(?!.*(?:www\.)?(?:google|facebook|twitter))', "Redirección maliciosa en .htaccess"),
    ("high", "htaccess_handler", r'AddHandler\s+.*\.(?:jpg|gif|png|ico)', "Handler PHP en extensión de imagen"),
    ("high", "htaccess_php", r'php_value\s+auto_(?:prepend|append)_file', "Auto-inclusión de archivo PHP"),
    ("medium", "htaccess_suspicious", r'SetHandler\s+application/x-httpd-php', "SetHandler forzando PHP en directorio"),
]


FAST_KEYWORDS_PHP = {
    "eval", "assert", "preg_replace", "system", "exec", "passthru",
    "shell_exec", "popen", "proc_open", "base64_decode", "gzinflate",
    "gzuncompress", "str_rot13", "gzdecode", "create_function",
    "call_user_func", "move_uploaded_file", "chr(", "\\x",
    "FilesMan", "c99", "r57", "WSO", "b374k", "alfa",
    "file_get_contents", "file_put_contents", "mail(", "dl(",
    "ini_set", "curl_exec",
}

FAST_KEYWORDS_JS = {
    "document.write", "unescape", "eval", "atob", "decodeURIComponent",
    "String.fromCharCode", "<script", "new Function", "CoinHive",
    "coinhive", "cryptonight", "minero",
}

FAST_KEYWORDS_HTACCESS = {
    "RewriteRule", "AddHandler", "php_value", "SetHandler",
    "auto_prepend", "auto_append",
}


class PHPScanner:
    name = "PHP/Web Scanner"

    @staticmethod
    def _build_batch(patterns):
        """Agrupa patrones por categoria en un solo regex combinado con alternacion."""
        groups = {}
        for sev, cat, pattern, desc in patterns:
            groups.setdefault(cat, []).append((sev, pattern, desc))
        return [
            (cat, re.compile("|".join(f"(?:{p})" for _, p, _ in items), re.IGNORECASE), items)
            for cat, items in groups.items()
        ]

    def __init__(self):
        self._compiled = {}
        for sev, cat, pattern, desc in PHP_PATTERNS + JS_PATTERNS + HTACCESS_PATTERNS:
            self._compiled[pattern] = (re.compile(pattern, re.IGNORECASE), sev, cat, desc)

        self._batch_php = self._build_batch(PHP_PATTERNS)
        self._batch_js = self._build_batch(JS_PATTERNS)
        self._batch_htaccess = self._build_batch(HTACCESS_PATTERNS)
        self._batch_html = self._build_batch(PHP_PATTERNS + JS_PATTERNS)
        self._batch_css = self._batch_js

    def scan(self, file_path: str) -> list:
        fp = Path(file_path)
        ext = fp.suffix.lower()
        name = fp.name.lower()

        if ext in (".php", ".php5", ".php7", ".phtml", ".phar"):
            batch = self._batch_php
            fast_kw = FAST_KEYWORDS_PHP
        elif ext in (".js",):
            batch = self._batch_js
            fast_kw = FAST_KEYWORDS_JS
        elif ext in (".html", ".htm"):
            batch = self._batch_html
            fast_kw = FAST_KEYWORDS_PHP | FAST_KEYWORDS_JS
        elif name == ".htaccess":
            batch = self._batch_htaccess
            fast_kw = FAST_KEYWORDS_HTACCESS
        elif ext in (".css", ".svg"):
            batch = self._batch_css
            fast_kw = FAST_KEYWORDS_JS
        else:
            return []

        try:
            size = os.path.getsize(file_path)
            if size > 5 * 1024 * 1024 or size == 0:
                return []
            with open(file_path, "rb") as fb:
                raw = fb.read(8192)
                if b"\x00" in raw:
                    return []
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except (OSError, PermissionError, UnicodeDecodeError):
            return []

        content_lower = content.lower()
        if not any(kw.lower() in content_lower for kw in fast_kw):
            findings = []
            self._check_suspicious_filenames(file_path, findings)
            return findings

        findings = []
        lines = content.split("\n")

        for line_num, line in enumerate(lines, 1):
            for cat, batch_re, items in batch:
                if batch_re.search(line):
                    for sev, pattern, desc in items:
                        if self._compiled[pattern][0].search(line):
                            ctx = line.strip()[:200]
                            findings.append(Finding(
                                file_path=file_path,
                                line_number=line_num,
                                severity=sev,
                                category=cat,
                                description=desc,
                                matched_pattern=pattern[:80],
                                context=ctx,
                            ))

        self._check_suspicious_filenames(file_path, findings)
        if findings:
            findings = self._apply_whitelist(file_path, name, content_lower, findings)
        return findings

    CONFIRMED_MALWARE_CATS = {"webshell", "backdoor", "cryptominer", "dropper"}

    def _apply_whitelist(self, file_path, name, content_lower, findings):
        """Reduce falsos positivos via hash whitelist, slugs confiables y firmas de cache."""
        import hashlib as _hashlib

        if WP_WHITELIST_HASHES:
            try:
                sha = _hashlib.sha256()
                with open(file_path, "rb") as fh:
                    for chunk in iter(lambda: fh.read(65536), b""):
                        sha.update(chunk)
                if sha.hexdigest() in WP_WHITELIST_HASHES:
                    return []
            except (OSError, PermissionError):
                pass

        if name == ".htaccess":
            if any(sig.lower() in content_lower for sig in CACHE_HTACCESS_SIGNATURES):
                for f in findings:
                    f.severity = "info"
                    f.description = f"Cache plugin htaccess - {f.description}"
                return findings

        fp_norm = file_path.replace("\\", "/").lower()
        for segment in ("plugins", "themes"):
            marker = f"/wp-content/{segment}/"
            idx = fp_norm.find(marker)
            if idx >= 0:
                slug = fp_norm[idx + len(marker):].split("/")[0]
                if slug in WP_TRUSTED_SLUGS:
                    for f in findings:
                        if f.category not in self.CONFIRMED_MALWARE_CATS:
                            f.severity = "info"
                            f.description = f"[Plugin/tema confiable] {f.description}"
                    break

        return findings

    SAFE_DIRS = {
        "wp-admin", "wp-includes", "wp-content/plugins", "wp-content/themes",
        "administrator", "components", "modules", "plugins",
        "mod", "lib", "admin", "course",
        "app", "routes", "config", "vendor", "node_modules",
    }

    def _in_safe_dir(self, file_path: str) -> bool:
        fp_norm = file_path.replace("\\", "/").lower()
        return any(f"/{d}/" in fp_norm for d in self.SAFE_DIRS)

    def _check_suspicious_filenames(self, file_path: str, findings: list):
        name = Path(file_path).name.lower()

        always_suspicious = ["c99.php", "r57.php", "b374k.php", "wso.php", "alfa.php"]
        context_suspicious = [
            "shell.php", "cmd.php", "mini.php", "bypass.php",
            "uploader.php", "filemanager.php", "adminer.php",
        ]

        if name in always_suspicious:
            findings.append(Finding(
                file_path=file_path,
                severity="critical",
                category="suspicious_filename",
                description=f"Nombre de archivo sospechoso: {name}",
            ))
        elif name in context_suspicious and not self._in_safe_dir(file_path):
            findings.append(Finding(
                file_path=file_path,
                severity="critical",
                category="suspicious_filename",
                description=f"Nombre de archivo sospechoso: {name}",
            ))

        double_ext = re.search(r'\.(jpg|gif|png|ico|pdf)\.(php|phtml|phar)$', name)
        if double_ext:
            findings.append(Finding(
                file_path=file_path,
                severity="critical",
                category="double_extension",
                description="Doble extensión — posible archivo disfrazado",
            ))

    def can_clean(self, finding: Finding) -> bool:
        return finding.category in ("webshell", "backdoor", "suspicious_filename", "double_extension")

    def clean(self, finding: Finding) -> bool:
        fp = Path(finding.file_path)
        if not fp.exists():
            return False
        quarantine = fp.parent / ".quarantine"
        quarantine.mkdir(exist_ok=True)
        dest = quarantine / f"{fp.name}.quarantined"
        try:
            fp.rename(dest)
            return True
        except OSError:
            return False
