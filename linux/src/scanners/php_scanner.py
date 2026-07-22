"""Escáner de archivos PHP, HTML, CSS, JS — detecta shells, backdoors, inyecciones."""
import re
import os
import base64
import binascii
import zlib
import codecs
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
    ("critical", "backdoor", r'\b(?:eval|assert)\s*\(\s*\$\w+\s*\(', "eval/assert sobre funcion variable (backdoor por indireccion)"),
    ("high", "obfuscation", r'\$\w+\s*=\s*["\'](?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|create_function|assert|system|exec|shell_exec|passthru|popen|proc_open)["\']\s*;', "Nombre de funcion peligrosa asignado a variable (ofuscacion)"),

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

    # v2.6.5: Mailer backdoors — SPAM/phishing/mailing masivo
    ("critical", "mailer_backdoor", r'\$(?:mail|phpmailer|mailer)\s*->\s*(?:Password|Username)\s*=\s*["\'][^"\']{4,}["\']', "PHPMailer con credenciales SMTP hardcodeadas"),
    ("critical", "mailer_backdoor", r'\bmail\s*\([^)]*(?:Bcc|Cc)\s*:[^)]*@[^)]*\)', "Función mail() con header Bcc/Cc (mailing masivo)"),
    ("critical", "mailer_backdoor", r'(?:From|Reply-To|Bcc|X-Mailer)\s*:[^\r\n]*(?:[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})', "Header de email embebido en código PHP (spam relay)"),
    ("critical", "mailer_backdoor", r'foreach\s*\(\s*\$\w+\s+as\s+[^\)]+\)\s*\{[^}]*\bmail\s*\(', "Bucle de envío masivo: mail() dentro de foreach"),
    ("high", "mailer_backdoor", r'\$\w+\s*=\s*(?:array\s*\(|\[)\s*(?:["\'][a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}["\'][\s,]){2,}', "Lista de destinatarios de email embebida en código"),
    ("high", "mailer_backdoor", r'(?:SMTPAuth|SMTPSecure|Host)\s*=\s*(?:true|["\']).*(?:Password|Username)\s*=\s*["\'][^"\']{4,}["\']', "Configuración SMTP completa hardcodeada (phishing)"),
    ("high", "mailer_backdoor", r'(?:base64_decode|gzinflate|str_rot13)\s*\([^)]+\)[^;]*\bmail\s*\(', "Llamada a mail() precedida de ofuscación"),
    ("high", "mailer_backdoor", r'X-(?:Spam|Priority|Mailer)\s*:\s*\S+', "Headers anti-spam hardcodeados (evasión de filtros)"),
    ("medium", "mailer_backdoor", r'\bswiftmailer\b|\bSwift_Message\b', "SwiftMailer embebido (posible mailing masivo)"),
    ("medium", "mailer_backdoor", r'(?:smtp_host|smtp_pass|smtp_user)\s*=\s*["\'][^"\']{4,}["\']', "Configuración SMTP hardcodeada en variable"),

    # v3.0.0: Técnicas de ofuscación avanzada y evasión
    ("critical", "backdoor", r'\bhex2bin\s*\(\s*["\'][0-9a-fA-F]{40,}["\']', "hex2bin con blob hex largo (ofuscación moderna)"),
    ("critical", "backdoor", r'\binclude(?:_once)?\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)', "include() con path controlado por usuario (RFI/LFI)"),
    ("critical", "backdoor", r'\brequire(?:_once)?\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)', "require() con path controlado por usuario (LFI)"),
    ("critical", "webshell", r'\bfsockopen\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)', "fsockopen con host del usuario (C2 connection)"),
    ("critical", "backdoor", r'\bpcntl_exec\s*\(', "pcntl_exec detectado (ejecución de proceso nativo)"),
    ("high", "obfuscation", r'\barray_map\s*\(\s*["\'](?:assert|eval|system|exec|passthru|shell_exec)["\']', "array_map con función peligrosa como callback"),
    ("high", "obfuscation", r'\busort\s*\(\s*\$\w+\s*,\s*["\'](?:assert|system|exec)["\']', "usort con función peligrosa como comparador"),
    ("high", "injection", r'\bunserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)', "unserialize() con input de usuario (PHP Object Injection)"),
    ("high", "obfuscation", r'\bstr_split\s*\([^)]+\)\s*[;,\s]*\$\w+\s*=\s*implode\s*\(', "str_split+implode para construir string encadenado (evasión de regex)"),
    ("high", "obfuscation", r'\bob_start\s*\([^)]*\)\s*;[^;]*(?:eval|assert|system)\s*\(', "ob_start + eval/system (output buffer capture evasión)"),
    ("high", "backdoor", r'\bregister_shutdown_function\s*\(\s*["\'](?:system|exec|passthru|shell_exec)["\']', "register_shutdown_function con función peligrosa"),
    ("high", "obfuscation", r'\bReflectionFunction\s*\(\s*\$\w+\s*\)\s*->\s*invoke\s*\(', "ReflectionFunction->invoke() para ejecutar función ofuscada"),
    ("medium", "suspicious", r'\bfsockopen\s*\(\s*["\'](?:tcp|ssl)://', "fsockopen con protocolo explícito (conexión de red saliente)"),
    ("medium", "backdoor", r'\bset_error_handler\s*\(\s*(?:create_function|["\']eval)["\']', "set_error_handler con función peligrosa (evasión AV)"),
]

JS_PATTERNS = [
    ("critical", "js_malware", r'document\.write\s*\(\s*unescape\s*\(', "document.write con unescape (inyección clásica)"),
    ("critical", "js_malware", r'eval\s*\(\s*(atob|unescape|decodeURIComponent)\s*\(', "Eval con decodificación (dropper JS)"),
    ("high", "js_malware", r'String\.fromCharCode\s*\(\s*(\d+\s*,\s*){20,}', "String.fromCharCode masivo (ofuscación)"),
    ("high", "js_injection", r'<script[^>]*src\s*=\s*["\']https?://(?!.*(?:googleapis|gstatic|cloudflare|jsdelivr|unpkg|cdnjs|bootstrapcdn|jquery|fastly|akamai|stackpath|azureedge|cloudfront|amazonaws|fontawesome|shopify|wordpress\.com|wp\.com|gravatar))', "Script externo de dominio no confiable"),
    ("medium", "js_suspicious", r'new\s+Function\s*\(\s*["\']', "new Function con string (eval implícito)"),
    ("medium", "js_crypto", r'(CoinHive|coinhive|cryptonight|minero?\b)', "Cripto-minero detectado"),
]

HTACCESS_PATTERNS = [
    ("critical", "htaccess_redirect", r'RewriteRule\s+.*https?://(?!.*(?:www\.)?(?:google|facebook|twitter))', "Redirección maliciosa en .htaccess"),
    ("high", "htaccess_handler", r'AddHandler\s+.*\.(?:jpg|gif|png|ico)', "Handler PHP en extensión de imagen"),
    ("high", "htaccess_php", r'php_value\s+auto_(?:prepend|append)_file', "Auto-inclusión de archivo PHP"),
    ("medium", "htaccess_suspicious", r'SetHandler\s+application/x-httpd-php', "SetHandler forzando PHP en directorio"),
]

# v3.1: Archivos PHP codificados comercialmente — pueden ocultar malware
ENCODED_PHP_PATTERNS = [
    ("high", "encoded_php", r'ionCube|IonCube\s+PHP\s+Encoder|ioncube_read_file|the\s+ionCube\s+PHP\s+Loader', "Archivo PHP codificado con IonCube (revisar)"),
    ("high", "encoded_php", r'@Zend;|Zend\s+Guard|Zend\s+Optimizer|zend_loader', "Archivo PHP codificado con Zend Guard (revisar)"),
    ("high", "encoded_php", r'SourceGuardian|sg_load\s*\(|sg_validate', "Archivo PHP codificado con SourceGuardian (revisar)"),
    ("high", "encoded_php", r'Obfuscated\s+by\s+Obfuscator\.io|eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k', "PHP ofuscado con Obfuscator.io"),
]

# v3.1: .user.ini y php.ini — auto_prepend/append son inyección garantizada
USERINI_PATTERNS = [
    ("critical", "userini_php", r'auto_prepend_file\s*=\s*\S', "auto_prepend_file en archivo INI (ejecución automática)"),
    ("critical", "userini_php", r'auto_append_file\s*=\s*\S', "auto_append_file en archivo INI (ejecución automática)"),
    ("high", "userini_php", r'disable_functions\s*=\s*[\r\n]', "disable_functions vaciado en INI (habilita funciones peligrosas)"),
    ("high", "userini_php", r'open_basedir\s*=\s*[\r\n]', "open_basedir vaciado en INI (acceso irrestricto a filesystem)"),
    ("high", "userini_php", r'suhosin\.executor\.eval\.blacklist\s*=\s*[\r\n]', "Blacklist de suhosin vaciada en INI"),
]

FAST_KEYWORDS_PHP = {
    "eval", "assert", "preg_replace", "system", "exec", "passthru",
    "shell_exec", "popen", "proc_open", "base64_decode", "gzinflate",
    "gzuncompress", "str_rot13", "gzdecode", "create_function",
    "call_user_func", "move_uploaded_file", "chr(", "\\x",
    "FilesMan", "c99", "r57", "WSO", "b374k", "alfa",
    "file_get_contents", "file_put_contents", "mail(", "dl(",
    "ini_set", "curl_exec",
    # v2.6.5: mailer backdoor keywords
    "PHPMailer", "phpmailer", "SwiftMailer", "smtp_pass", "smtp_host",
    "SMTPAuth", "SMTPSecure", "X-Mailer", "X-Spam", "X-Priority",
    "Bcc:", "Reply-To:",
    # v3.0.0: técnicas avanzadas
    "hex2bin", "include(", "include_once", "require(", "require_once",
    "fsockopen", "pcntl_exec", "array_map", "usort", "unserialize",
    "str_split", "ob_start", "register_shutdown_function",
    "ReflectionFunction", "set_error_handler",
    # v3.1: codificadores comerciales
    "ionCube", "IonCube", "@Zend;", "SourceGuardian", "sg_load", "zend_loader",
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

FAST_KEYWORDS_USERINI = {
    "auto_prepend_file", "auto_append_file", "disable_functions",
    "open_basedir", "suhosin",
}

# ── v2.6.2: Detector de archivos PHP sin codigo ejecutable (Mejora #1) ──
_PHP_BLOCK_COMMENT_RE = re.compile(r'/\*.*?\*/', re.DOTALL)
# Tag solo: <?php o <? (sin nada mas)
_PHP_OPEN_TAG_ONLY_RE = re.compile(r'^\s*<\?(?:php)?\s*$', re.IGNORECASE)
# Tag solo: ?>
_PHP_CLOSE_TAG_RE = re.compile(r'^\s*\?>\s*$')
# Tag combinado vacio: <?php ?> o <? ?>
_PHP_EMPTY_TAGS_RE = re.compile(r'^\s*<\?(?:php)?\s*\?>\s*$', re.IGNORECASE)
_PHP_COMMENT_LINE_RE = re.compile(r'^\s*(?://|#)')


def is_php_functional(content: str) -> bool:
    """True si el archivo PHP tiene al menos 1 linea de codigo ejecutable real.

    Un archivo NO es funcional si todo su contenido son:
    - Lineas en blanco (whitespace)
    - Tags PHP solos: <?php, <?, ?>
    - Comentarios de linea: // ... o # ...
    - Bloques de comentario: /* ... */

    Ejemplos NO funcionales: 'silence is golden', index.php vacio, <?php ?>,
    archivos con solo comentarios de documentacion.

    Ejemplos SI funcionales: cualquier funcion, clase, asignacion, llamada,
    include, require, echo, eval, etc.
    """
    # Eliminar bloques de comentario /* ... */ antes de analizar lineas
    cleaned = _PHP_BLOCK_COMMENT_RE.sub('', content)
    for line in cleaned.split('\n'):
        stripped = line.strip()
        if not stripped:
            continue
        if _PHP_EMPTY_TAGS_RE.match(stripped):
            continue
        if _PHP_OPEN_TAG_ONLY_RE.match(stripped):
            continue
        if _PHP_CLOSE_TAG_RE.match(stripped):
            continue
        if _PHP_COMMENT_LINE_RE.match(stripped):
            continue
        # Esta linea no es ni whitespace, ni tag, ni comentario → es ejecutable
        return True
    return False


# ── v3.1.5: deteccion heuristica (multi-linea + desofuscacion) ──────────────
# Construcciones de ejecucion que pueden partirse en varias lineas (evasion del
# escaneo linea-a-linea): se buscan sobre TODO el contenido.
_MULTILINE_EXEC = [
    ("critical", "webshell",
     re.compile(r'\b(?:eval|assert|create_function)\s*\(\s*'
                r'(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|hex2bin|convert_uudecode)\s*\(',
                re.IGNORECASE),
     "Ejecucion con decodificacion (posible evasion multi-linea)"),
    ("critical", "backdoor",
     re.compile(r'\b(?:eval|assert)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b', re.IGNORECASE),
     "eval() de entrada del usuario (multi-linea)"),
    ("critical", "webshell",
     re.compile(r'\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]{0,40}\]\s*\(', re.IGNORECASE),
     "Funcion tomada de una superglobal (shell dinamico)"),
]

# Blobs codificados literales dentro del codigo. Umbral bajo (16) porque los payloads
# reales suelen ser cortos; la especificidad la aporta _DECODED_MALWARE, no la longitud.
_B64_LITERAL = re.compile(r"""['"]([A-Za-z0-9+/]{16,}={0,2})['"]""")
_HEX_LITERAL = re.compile(r"""['"]([0-9a-fA-F]{40,})['"]""")

# Indicadores de payload YA DECODIFICADO (alta especificidad, casi cero FP): solo se
# evaluan sobre el resultado de decodificar un blob, no sobre el fuente normal.
_DECODED_MALWARE = re.compile(
    r'(?:eval|assert|create_function)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)'
    r'|(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\('
    r'|\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]{0,40}\]\s*\('
    r'|preg_replace\s*\(\s*[\'"][^\'"]{0,120}/[a-z]*e[\'"]'
    r'|(?:eval|assert)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13|gzdecode)\s*\('
    r'|(?:FilesMan|c99shell|r57shell|b374k|IndoXploit|phpspy|WSOshell)',
    re.IGNORECASE,
)


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
        all_pats = PHP_PATTERNS + JS_PATTERNS + HTACCESS_PATTERNS + ENCODED_PHP_PATTERNS + USERINI_PATTERNS
        for sev, cat, pattern, desc in all_pats:
            self._compiled[pattern] = (re.compile(pattern, re.IGNORECASE), sev, cat, desc)

        self._batch_php = self._build_batch(PHP_PATTERNS + ENCODED_PHP_PATTERNS)
        self._batch_js = self._build_batch(JS_PATTERNS)
        self._batch_htaccess = self._build_batch(HTACCESS_PATTERNS)
        self._batch_html = self._build_batch(PHP_PATTERNS + JS_PATTERNS + ENCODED_PHP_PATTERNS)
        self._batch_css = self._batch_js
        self._batch_userini = self._build_batch(USERINI_PATTERNS)

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
        elif name in (".user.ini", "php.ini") or ext in (".ini",):
            batch = self._batch_userini
            fast_kw = FAST_KEYWORDS_USERINI
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

        # v2.6.2: Archivos PHP sin codigo ejecutable no generan findings del scanner.
        # Son stubs tipo "silence is golden" (creados por WP y plugins para bloquear
        # listado de directorios). No pueden contener codigo malicioso operativo.
        if ext in (".php", ".php5", ".php7", ".phtml", ".phar"):
            if not is_php_functional(content):
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

        if ext in (".php", ".php5", ".php7", ".phtml", ".phar", ".html", ".htm", ".js"):
            self._scan_multiline(content, file_path, findings)
            self._scan_deobfuscated(content, file_path, findings)

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

        always_suspicious = [
            "c99.php", "r57.php", "b374k.php", "wso.php", "alfa.php",
            "indoxploit.php", "priv8.php", "madshell.php", "cgitelnet.php",
            "wshell.php", "symlink.php", "cpanel.php", "cpanel_backup.php",
            "decode.php", "encoder.php", "locus7shell.php", "whmcs_exploit.php",
        ]
        context_suspicious = [
            "shell.php", "cmd.php", "mini.php", "bypass.php",
            "uploader.php", "filemanager.php", "adminer.php",
            "config.bak.php", "install.php", "setup.php",
            "test.php", "debug.php", "info.php", "phpinfo.php",
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

    def _scan_multiline(self, content, file_path, findings):
        """Ejecucion partida en varias lineas (el pase linea-a-linea no la ve)."""
        seen = {(f.category, f.line_number) for f in findings}
        for sev, cat, rx, desc in _MULTILINE_EXEC:
            m = rx.search(content)
            if not m:
                continue
            line_no = content.count("\n", 0, m.start()) + 1
            if (cat, line_no) in seen:
                continue
            seen.add((cat, line_no))
            findings.append(Finding(
                file_path=file_path, line_number=line_no, severity=sev,
                category=cat, description=desc,
                matched_pattern="multiline", context=m.group(0)[:160],
            ))

    def _scan_deobfuscated(self, content, file_path, findings):
        """Decodifica blobs base64/hex (con posible capa gz/rot13) y re-escanea el
        payload. Solo marca si el contenido DECODIFICADO contiene ejecucion real,
        por lo que blobs benignos (imagenes, JSON, tokens) no generan hallazgos."""
        blobs = []
        for m in _B64_LITERAL.finditer(content):
            blobs.append(("base64", m.group(1)))
            if len(blobs) >= 25:
                break
        for m in _HEX_LITERAL.finditer(content):
            blobs.append(("hex", m.group(1)))
            if len(blobs) >= 45:
                break
        hits = 0
        for kind, blob in blobs:
            if len(blob) > 300000:
                continue
            for decoded in self._decode_layers(kind, blob):
                if _DECODED_MALWARE.search(decoded):
                    findings.append(Finding(
                        file_path=file_path, line_number=0, severity="critical",
                        category="webshell",
                        description="Payload de ejecucion oculto tras desofuscar (base64/gz/hex/rot13)",
                        matched_pattern="deobfuscated",
                        context=decoded[:160].replace("\n", " "),
                    ))
                    hits += 1
                    break
            if hits >= 5:
                break

    @staticmethod
    def _decode_layers(kind, blob):
        """Textos decodificados (1-2 capas) a inspeccionar. Nunca lanza."""
        raws = []
        try:
            if kind == "base64":
                raws.append(base64.b64decode(blob, validate=True))
            else:
                raws.append(bytes.fromhex(blob))
        except (binascii.Error, ValueError):
            try:  # por si el base64 va rotado con rot13
                raws.append(base64.b64decode(codecs.decode(blob, "rot_13"), validate=True))
            except (binascii.Error, ValueError, UnicodeDecodeError):
                return []
        extra = []
        for r in raws:
            wbits = 47 if r[:2] == b"\x1f\x8b" else -15
            try:
                extra.append(zlib.decompress(r, wbits))
            except zlib.error:
                pass
        return [r.decode("utf-8", errors="replace") for r in raws + extra]

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
