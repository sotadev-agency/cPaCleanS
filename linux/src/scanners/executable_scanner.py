"""Escaner de ejecutables disfrazados, macros descargadoras y exploits Office/RTF/PDF/ZIP.

Cubre denominaciones de malware reportadas que el motor no reconocia por operar
solo sobre PHP/JS/HTML (php_scanner) y MIME de correo (email_scanner): binarios
Windows sueltos en contenido web, dobles extensiones, scripts AutoIt, macros de
Office con llamadas de descarga/ejecucion, exploits de Equation Editor en RTF,
acciones peligrosas en PDF y ejecutables embebidos en ZIP.
"""
import re
import zipfile
from pathlib import Path
from ..core.engine import Finding

_DOC_EXT = r'(?:pdf|docx?|docm|xlsx?|xlsm|pptx?|pptm|jpe?g|png|gif|bmp|zip|rar|7z|txt|csv|rtf)'
_EXEC_EXT = r'(?:exe|scr|com|pif|bat|cmd|cpl|msi|vbs?|vbe|jse?|wsf|wsh|hta|ps1|au3)'
_DOUBLE_EXT_RE = re.compile(r'\.' + _DOC_EXT + r'\.' + _EXEC_EXT + r'$', re.IGNORECASE)

_NATIVE_EXEC_EXTS = {".exe", ".dll", ".scr", ".com", ".cpl", ".ocx", ".sys", ".msi", ".pif"}
_HIGH_RISK_EXTS = {
    ".exe", ".scr", ".com", ".pif", ".cpl", ".msi",
    ".vbs", ".vbe", ".jse", ".wsf", ".wsh", ".hta", ".bat", ".cmd",
}

_AUTOIT_MARKERS = (b">>>AUTOIT NO CMDLINE<<<", b"AU3!EA06", b"AutoIt v3 Script")
_AU3_DOWNLOADER_KW = ("Run(", "ShellExecute(", "InetGet(", "FileInstall(", "DllCall(")

_OFFICE_DOWNLOADER_KW = (
    b"URLDownloadToFile", b"WinHttpOpen", b"WinHttpRequest", b"Msxml2.XMLHTTP",
    b"WScript.Shell", b"powershell", b"rundll32", b"cmd.exe /c", b"Shell(",
)
_OFFICE_AUTOEXEC_KW = (b"AutoOpen", b"Auto_Open", b"Document_Open", b"Workbook_Open", b"AutoExec")

_EQUATION_EXPLOIT_KW = (b"Equation.3", b"Equation Native")

_WEB_SCOPE_MARKERS = (
    "/uploads/", "/wp-content/", "/public_html/", "/htdocs/", "/www/",
    "/mail/", "/maildir/", "/media/", "/storage/app/public/", "/images/",
)
_EXCLUDED_SCOPE_MARKERS = ("/vendor/", "/node_modules/", "/.git/")

MAX_READ = 3_000_000
MAX_ZIP_ENTRIES = 60
MAX_ZIP_ENTRY_SIZE = 20_000_000


class ExecutableScanner:
    name = "Executable Scanner"

    def scan(self, file_path: str) -> list:
        fp = Path(file_path)
        ext = fp.suffix.lower()
        name = fp.name.lower()
        fp_str = str(fp).replace("\\", "/").lower()

        # Fuera del arbol web/correo no se analiza: evita ruido sobre partes
        # legitimas de un backup completo de cPanel (cron scripts, herramientas
        # de terceros, dependencias vendor/node_modules, etc.).
        if not any(m in fp_str for m in _WEB_SCOPE_MARKERS):
            return []
        if any(d in fp_str for d in _EXCLUDED_SCOPE_MARKERS):
            return []

        findings = []

        if _DOUBLE_EXT_RE.search(name):
            findings.append(Finding(
                file_path=file_path, severity="critical", category="double_extension",
                description=f"Doble extension — posible ejecutable disfrazado de documento: {fp.name}",
            ))

        if ext in _HIGH_RISK_EXTS:
            findings.append(Finding(
                file_path=file_path, severity="critical", category="malicious_attachment",
                description=f"Archivo ejecutable/script de alto riesgo en contenido web: {fp.name}",
                context=f"extension {ext}",
            ))

        try:
            size = fp.stat().st_size
        except OSError:
            return findings
        if size == 0 or size > 60_000_000:
            return findings

        try:
            with open(file_path, "rb") as f:
                header = f.read(8)
        except (OSError, PermissionError):
            return findings

        is_pe = header[:2] == b"MZ"
        is_ole = header[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
        is_zip_header = header[:2] == b"PK"
        is_rtf = header[:5] == b"{\\rtf"

        if is_pe and ext not in _NATIVE_EXEC_EXTS:
            findings.append(Finding(
                file_path=file_path, severity="critical", category="disguised_executable",
                description=f"Ejecutable (PE) con extension '{ext or 'sin extension'}' — disfrazado",
                context="cabecera MZ",
            ))

        if is_pe:
            findings.extend(self._check_autoit(file_path, size))

        if ext == ".au3":
            findings.extend(self._check_au3_source(file_path, size))

        if ext == ".xml":
            findings.extend(self._check_xml_script(file_path, size))

        if is_rtf or ext == ".rtf":
            findings.extend(self._check_rtf_exploit(file_path, size))

        if ext in (".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm"):
            if is_ole:
                findings.extend(self._check_ole_macro(file_path, size))
            elif is_zip_header:
                findings.extend(self._check_ooxml_macro(file_path))

        if ext == ".pdf":
            findings.extend(self._check_pdf(file_path, size))

        if ext == ".zip" and is_zip_header:
            findings.extend(self._check_zip_contents(file_path))

        return findings

    def _read(self, file_path, cap=MAX_READ):
        try:
            with open(file_path, "rb") as f:
                return f.read(cap)
        except (OSError, PermissionError):
            return b""

    def _check_autoit(self, file_path, size):
        data = self._read(file_path, min(size, MAX_READ))
        if any(m in data for m in _AUTOIT_MARKERS):
            return [Finding(
                file_path=file_path, severity="critical", category="malicious_attachment",
                description="Binario compilado con AutoIt (patron habitual de Formbook/Agensla/AutoIt-injectors)",
                context="firma AutoIt en binario",
            )]
        return []

    def _check_au3_source(self, file_path, size):
        data = self._read(file_path, min(size, MAX_READ))
        text = data.decode("utf-8", errors="replace")
        hits = [kw for kw in _AU3_DOWNLOADER_KW if kw in text]
        if hits:
            return [Finding(
                file_path=file_path, severity="high", category="suspicious_attachment",
                description="Script AutoIt (.au3) con llamadas de ejecucion/descarga — sin uso legitimo en sitio web",
                context=", ".join(hits[:4]),
            )]
        return [Finding(
            file_path=file_path, severity="medium", category="suspicious_attachment",
            description="Script AutoIt (.au3) presente — sin uso legitimo habitual en hosting web",
        )]

    def _check_xml_script(self, file_path, size):
        data = self._read(file_path, min(size, 500_000))
        if b"msxsl:script" in data or re.search(rb'language\s*=\s*["\'](?:JScript|VBScript)["\']', data, re.IGNORECASE):
            return [Finding(
                file_path=file_path, severity="critical", category="malicious_attachment",
                description="XML con script embebido (tecnica Squiblydoo / abuso de msxsl.exe)",
                context="namespace msxsl:script o language=JScript/VBScript",
            )]
        return []

    def _check_rtf_exploit(self, file_path, size):
        data = self._read(file_path, min(size, MAX_READ))
        if any(kw in data for kw in _EQUATION_EXPLOIT_KW):
            return [Finding(
                file_path=file_path, severity="high", category="malicious_attachment",
                description="RTF con objeto OLE Equation Editor embebido (patron de explotacion CVE-2017-11882 / CVE-2018-0802)",
                context="objeto Equation.3 / Equation Native",
            )]
        return []

    def _check_ole_macro(self, file_path, size):
        data = self._read(file_path, min(size, MAX_READ))
        return self._macro_findings(file_path, data, "Documento Office (OLE)")

    def _check_ooxml_macro(self, file_path):
        try:
            with zipfile.ZipFile(file_path) as z:
                vba_names = [n for n in z.namelist() if n.endswith("vbaProject.bin")]
                if not vba_names:
                    return []
                data = z.read(vba_names[0])[:MAX_READ]
        except (zipfile.BadZipFile, OSError, KeyError):
            return []
        return self._macro_findings(file_path, data, "Macro VBA (vbaProject.bin)")

    def _macro_findings(self, file_path, data, label):
        dl_hits = {kw for kw in _OFFICE_DOWNLOADER_KW if kw in data}
        auto_hits = {kw for kw in _OFFICE_AUTOEXEC_KW if kw in data}
        if not dl_hits:
            return []
        ctx = ", ".join(sorted(k.decode() for k in dl_hits)[:4])
        if auto_hits:
            return [Finding(
                file_path=file_path, severity="critical", category="malicious_attachment",
                description=f"{label} con autoejecucion + llamadas de descarga/ejecucion (downloader)",
                context=ctx,
            )]
        return [Finding(
            file_path=file_path, severity="medium", category="suspicious_attachment",
            description=f"{label} con cadenas de descarga/ejecucion embebidas",
            context=ctx,
        )]

    def _check_pdf(self, file_path, size):
        data = self._read(file_path, min(size, MAX_READ))
        findings = []
        if b"/Launch" in data:
            findings.append(Finding(
                file_path=file_path, severity="critical", category="malicious_attachment",
                description="PDF con accion /Launch (ejecuta programa externo al abrir)",
            ))
        m = re.search(rb'/EmbeddedFile.{0,400}?/F\s*\(([^)]*\.(?:exe|scr|bat|cmd|js|vbs|jar|ps1))\)',
                      data, re.IGNORECASE | re.DOTALL)
        if m:
            findings.append(Finding(
                file_path=file_path, severity="critical", category="malicious_attachment",
                description=f"PDF con archivo embebido ejecutable: {m.group(1).decode(errors='replace')}",
            ))
        if (b"/JavaScript" in data or b"/JS" in data) and (
            b"unescape" in data or re.search(rb'%(?:[0-9a-fA-F]{2}){40,}', data)
        ):
            findings.append(Finding(
                file_path=file_path, severity="high", category="malicious_attachment",
                description="PDF con JavaScript embebido y codificacion sospechosa (posible exploit/dropper)",
            ))
        return findings

    def _check_zip_contents(self, file_path):
        findings = []
        try:
            with zipfile.ZipFile(file_path) as z:
                for info in z.infolist()[:MAX_ZIP_ENTRIES]:
                    if info.is_dir() or info.file_size == 0 or info.file_size > MAX_ZIP_ENTRY_SIZE:
                        continue
                    try:
                        with z.open(info) as ef:
                            head = ef.read(2)
                    except (OSError, RuntimeError, zipfile.BadZipFile):
                        continue
                    if head == b"MZ":
                        findings.append(Finding(
                            file_path=file_path, severity="critical", category="malicious_attachment",
                            description=f"ZIP contiene ejecutable (PE): {info.filename}",
                        ))
        except (zipfile.BadZipFile, OSError):
            return []
        return findings

    def can_clean(self, finding: Finding) -> bool:
        return finding.category in ("double_extension", "disguised_executable", "malicious_attachment")

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
