"""Escáner YARA — usa reglas compiladas para detección avanzada."""
import os
from pathlib import Path
from ..core.engine import Finding

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


class YaraScanner:
    name = "YARA Scanner"

    def __init__(self, rules_dir: str = None):
        self._rules = None
        self._available = YARA_AVAILABLE

        if not self._available:
            return

        if rules_dir is None:
            rules_dir = str(Path(__file__).parent.parent / "signatures")

        rules_path = Path(rules_dir)
        rule_files = {}

        if rules_path.is_dir():
            for f in rules_path.glob("*.yar"):
                rule_files[f.stem] = str(f)
            for f in rules_path.glob("*.yara"):
                rule_files[f.stem] = str(f)

        if rule_files:
            try:
                self._rules = yara.compile(filepaths=rule_files)
            except yara.Error:
                self._available = False

    def scan(self, file_path: str) -> list:
        if not self._available or not self._rules:
            return []

        fp = Path(file_path)
        ext = fp.suffix.lower()

        scannable = {".php", ".php5", ".php7", ".phtml", ".phar",
                     ".html", ".htm", ".js", ".css", ".svg",
                     ".htaccess", ".sql", ".sh", ".cgi", ".pl"}

        if ext not in scannable and fp.name.lower() not in (".htaccess", ".user.ini"):
            return []

        try:
            if fp.stat().st_size > 10 * 1024 * 1024:
                return []
        except OSError:
            return []

        findings = []
        try:
            matches = self._rules.match(file_path, timeout=30)
            for match in matches:
                meta = match.meta
                severity = meta.get("severity", "medium")
                category = meta.get("category", "yara_match")
                description = meta.get("description", match.rule)

                strings_found = []
                for string_match in match.strings:
                    # yara-python >= 4.3: StringMatch objects; < 4.3: (offset, id, data) tuples
                    if hasattr(string_match, "instances"):
                        identifier = string_match.identifier
                        for inst in string_match.instances:
                            try:
                                decoded = inst.matched_data.decode("utf-8", errors="replace")[:100]
                            except (AttributeError, UnicodeDecodeError):
                                decoded = str(getattr(inst, "matched_data", ""))[:100]
                            strings_found.append(f"{identifier}: {decoded}")
                    else:
                        # backward compat: tuple (offset, identifier, data)
                        try:
                            _, identifier, data = string_match
                            decoded = data.decode("utf-8", errors="replace")[:100] if isinstance(data, bytes) else str(data)[:100]
                            strings_found.append(f"{identifier}: {decoded}")
                        except Exception:
                            pass

                findings.append(Finding(
                    file_path=file_path,
                    severity=severity,
                    category=category,
                    description=f"[YARA] {description} ({match.rule})",
                    matched_pattern=match.rule,
                    context="; ".join(strings_found[:3]),
                ))

        except yara.Error:
            pass
        except Exception:
            pass

        return findings

    def can_clean(self, finding: Finding) -> bool:
        return finding.severity == "critical" and finding.category in ("webshell", "backdoor", "cryptominer", "dropper")

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
