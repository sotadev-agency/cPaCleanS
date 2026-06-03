"""Escaner de correos y codigo propio — detecta phishing, reinfeccion, adjuntos maliciosos."""
import re
import email
import email.policy
from pathlib import Path
from ..core.engine import Finding

EMAIL_PATTERNS = [
    # Phishing
    ("high", "phishing", r'(?:verify|confirm|update|suspend|restrict)\s+(?:your|account|identity|password)', "Lenguaje de phishing detectado"),
    ("high", "phishing", r'(?:click\s+here|act\s+now|immediate\s+action|urgent|expires?\s+(?:today|soon|in\s+\d+\s+hours?))', "Urgencia artificial (phishing)"),
    ("high", "phishing", r'(?:paypal|amazon|apple|microsoft|google|netflix|bank)\s*(?:\.com)?[^a-z].*(?:login|signin|verify|confirm)', "Suplantacion de marca conocida"),

    # Adjuntos peligrosos
    ("critical", "malicious_attachment", r'filename=["\']?[^"\']*\.(?:exe|scr|bat|cmd|com|pif|vbs|js|wsf|hta|cpl)["\']?', "Adjunto con extension ejecutable"),
    ("high", "malicious_attachment", r'filename=["\']?[^"\']*\.(?:php|phtml|php5|phar)["\']?', "Adjunto PHP (posible shell)"),
    ("medium", "suspicious_attachment", r'filename=["\']?[^"\']*\.(?:doc|xls|ppt)m["\']?', "Adjunto Office con macros"),
    ("high", "malicious_attachment", r'filename=["\']?[^"\']*\.[a-z]{3,4}\.[a-z]{2,4}["\']?', "Adjunto con doble extension"),

    # URLs maliciosas en correos
    ("high", "malicious_url", r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[/:]', "URL con IP directa en correo"),
    ("medium", "suspicious_url", r'https?://[^/]*(?:bit\.ly|tinyurl|t\.co|goo\.gl|is\.gd|buff\.ly)[/]', "URL acortada (puede ocultar destino)"),
    ("high", "malicious_url", r'(?:data:text/html|javascript:)', "Protocolo peligroso en enlace"),

    # Spam / scam
    ("low", "spam", r'(?:unsubscribe|opt.?out|remove\s+(?:me|from))', "Indicador de email masivo/spam"),
    ("medium", "spam", r'(?:congratulations|you\s+(?:have\s+)?won|claim\s+your\s+prize|lottery|million\s+dollars?)', "Contenido de estafa/scam"),

    # Headers sospechosos
    ("high", "spoofed", r'X-Mailer:\s*(?:PHPMailer|PHP/\d|swiftmailer)', "Enviado con PHPMailer (posible spam relay)"),
    ("medium", "spoofed", r'Received:.*(?:unknown|localhost|127\.0\.0\.1)', "Header Received sospechoso"),

    # === Patrones de reinfeccion en correos ===
    ("critical", "reinfection_risk", r'<script[^>]*src\s*=\s*["\']https?://', "Script externo en cuerpo del correo (vector de reinfeccion)"),
    ("critical", "reinfection_risk", r'<iframe[^>]*src\s*=\s*["\']https?://', "iFrame oculto en correo (vector de reinfeccion)"),
    ("high", "reinfection_risk", r'(?:eval|document\.write)\s*\(', "Codigo JS ejecutable en correo"),
    ("high", "reinfection_risk", r'<\?php', "Codigo PHP embebido en correo"),
    ("high", "reinfection_risk", r'(?:wget|curl|fetch)\s+https?://', "Comando de descarga en correo"),
    ("high", "reinfection_risk", r'(?:base64_decode|atob)\s*\(', "Decodificacion base64 en correo (posible payload)"),
    ("medium", "reinfection_risk", r'(?:cron|crontab|chmod|chown)\s+', "Comando de sistema en correo"),
]

# Patrones para codigo propio (PHP, HTML, JS sin CMS)
CODE_REINFECTION_PATTERNS = [
    ("critical", "reinfection_risk", r'file_get_contents\s*\(\s*["\']https?://[^"\']*(?:pastebin|paste\.ee|hastebin|ghostbin)', "Descarga de payload desde paste service"),
    ("critical", "reinfection_risk", r'(?:curl_exec|file_get_contents|fopen)\s*\(.*(?:eval|exec|system|passthru)\s*\(', "Descarga + ejecucion remota"),
    ("high", "reinfection_risk", r'(?:wp_remote_get|wp_remote_post)\s*\(\s*\$', "Peticion HTTP con variable (posible C&C)"),
    ("high", "reinfection_risk", r'(?:register_shutdown_function|set_error_handler)\s*\(\s*function.*(?:eval|base64)', "Handler de error con ejecucion oculta"),
    ("high", "reinfection_risk", r'@?(?:include|require)(?:_once)?\s*\(\s*(?:\$_(?:GET|POST|REQUEST|COOKIE)|(?:chr|base64_decode))', "Inclusion de archivo controlada por usuario"),
    ("medium", "reinfection_risk", r'(?:file_put_contents|fwrite)\s*\(.*(?:\$_(?:GET|POST|REQUEST)|base64_decode)', "Escritura de archivo con input externo"),
]


class EmailScanner:
    name = "Email Scanner"

    def __init__(self):
        self._email_compiled = [(re.compile(p, re.IGNORECASE), s, c, d) for s, c, p, d in EMAIL_PATTERNS]
        self._code_compiled = [(re.compile(p, re.IGNORECASE), s, c, d) for s, c, p, d in CODE_REINFECTION_PATTERNS]

    def scan(self, file_path: str) -> list:
        fp = Path(file_path)
        ext = fp.suffix.lower()
        fp_str = str(fp).replace("\\", "/").lower()

        # Escanear correos
        is_email = (
            ext in (".eml", ".mbox")
            or any(part in fp_str for part in ("/mail/", "/cur/", "/new/", "/tmp/", "/maildir/"))
        )

        # Escanear codigo propio (fuera de CMS core)
        is_custom_code = (
            ext in (".php", ".html", ".htm", ".js")
            and not any(d in fp_str for d in ("/wp-admin/", "/wp-includes/", "/vendor/", "/node_modules/",
                                               "/administrator/", "/moodle/lib/"))
        )

        if not is_email and not is_custom_code:
            return []

        try:
            size = fp.stat().st_size
            if size == 0 or size > 2_000_000:
                return []
            with open(file_path, "rb") as fb:
                raw = fb.read(4096)
                if b"\x00" in raw:
                    return []
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except (OSError, PermissionError):
            return []

        findings = []

        if is_email:
            self._scan_email_content(file_path, content, findings)
            self._scan_parsed_email(file_path, content, findings)

        if is_custom_code:
            self._scan_reinfection_code(file_path, content, findings)

        return findings

    def _scan_email_content(self, file_path, content, findings):
        lines = content.split("\n")
        for compiled, sev, cat, desc in self._email_compiled:
            for line_num, line in enumerate(lines, 1):
                if compiled.search(line):
                    findings.append(Finding(
                        file_path=file_path, line_number=line_num,
                        severity=sev, category=cat, description=desc,
                        context=line.strip()[:200],
                    ))

    def _scan_reinfection_code(self, file_path, content, findings):
        lines = content.split("\n")
        for compiled, sev, cat, desc in self._code_compiled:
            for line_num, line in enumerate(lines, 1):
                if compiled.search(line):
                    findings.append(Finding(
                        file_path=file_path, line_number=line_num,
                        severity=sev, category=cat, description=desc,
                        context=line.strip()[:200],
                    ))

    def _scan_parsed_email(self, file_path, content, findings):
        try:
            msg = email.message_from_string(content, policy=email.policy.default)
        except Exception:
            return

        from_header = str(msg.get("From", ""))
        reply_to = str(msg.get("Reply-To", ""))
        if from_header and reply_to:
            from_domain = self._extract_domain(from_header)
            reply_domain = self._extract_domain(reply_to)
            if from_domain and reply_domain and from_domain != reply_domain:
                findings.append(Finding(
                    file_path=file_path, severity="high", category="spoofed",
                    description=f"From ({from_domain}) difiere de Reply-To ({reply_domain})",
                    context=f"From: {from_header[:80]} | Reply-To: {reply_to[:80]}",
                ))

        for part in msg.walk():
            fn = part.get_filename()
            if fn:
                fn_lower = fn.lower()
                dangerous = (".exe", ".scr", ".bat", ".cmd", ".php", ".phar", ".vbs", ".js", ".hta", ".wsf", ".cpl")
                if any(fn_lower.endswith(e) for e in dangerous):
                    findings.append(Finding(
                        file_path=file_path, severity="critical",
                        category="malicious_attachment",
                        description=f"Adjunto peligroso: {fn}",
                        context=f"Content-Type: {part.get_content_type()}",
                    ))

    def _extract_domain(self, addr: str) -> str:
        match = re.search(r'@([\w.-]+)', addr)
        return match.group(1).lower() if match else ""

    def can_clean(self, finding: Finding) -> bool:
        return False

    def clean(self, finding: Finding) -> bool:
        return False
