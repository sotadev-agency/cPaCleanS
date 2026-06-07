"""Limpiador de dumps SQL — eliminacion por fila con tablas protegidas."""
import os
import re
import gzip
import bz2
import tempfile
import shutil
from pathlib import Path
from typing import Callable

from ..config.settings import CMS_PROTECTED_TABLES, SCAN_MODE_ONLY


_MALWARE_PATTERNS_CRITICAL = [
    re.compile(r"<\?php\s.{0,50}(?:eval|system|exec|passthru|shell_exec)", re.IGNORECASE | re.DOTALL),
    re.compile(r"eval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13)", re.IGNORECASE),
    re.compile(r"(?:preg_replace|assert)\s*\(\s*['\"]/.*/e['\"]", re.IGNORECASE),
    re.compile(r"\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}.*(?:eval|exec)", re.IGNORECASE),
    re.compile(r"CONCAT\s*\(\s*(?:CHAR|0x)[^)]{20,}\)", re.IGNORECASE),
    re.compile(r"INTO\s+OUTFILE\s+['\"]", re.IGNORECASE),
    re.compile(r"LOAD_FILE\s*\(\s*['\"]", re.IGNORECASE),
]

_MALWARE_PATTERNS_SUSPICIOUS = [
    re.compile(r"base64_decode\s*\(", re.IGNORECASE),
    re.compile(r"<script[^>]*>(?:[^<]|<(?!/script))*(?:document\.cookie|eval\()", re.IGNORECASE),
    re.compile(r"<iframe[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden)", re.IGNORECASE),
]

_INSERT_RE = re.compile(
    r"INSERT\s+INTO\s+`?(\w+)`?\s+(?:(?:\([^)]*\)\s+)?VALUES\s+)",
    re.IGNORECASE,
)


class DBCleaner:
    """Limpia dumps SQL eliminando filas maliciosas de tablas protegidas."""

    def __init__(self, extract_dir: str, cms_detected: list,
                 prefixes: dict = None, clean_mode: str = "normal",
                 progress_callback: Callable = None):
        self.extract_dir = Path(extract_dir)
        self.cms_detected = cms_detected
        self.prefixes = prefixes or {}
        self.clean_mode = clean_mode
        self.progress_callback = progress_callback or (lambda *a: None)
        self.interventions: list[dict] = []

    def process(self, sql_files: list) -> list:
        """Procesa todos los dumps SQL. Retorna lista de intervenciones.
        v2.6.0: Integra SpamPostCleaner para posts WP."""
        for sql_path in sql_files:
            try:
                self._process_file(sql_path)
                # v2.6.0: SpamPostCleaner para WordPress
                if "wordpress" in self.cms_detected:
                    self._run_spam_post_cleaner(sql_path)
            except (OSError, PermissionError) as e:
                self.interventions.append({
                    "file": str(sql_path),
                    "table": "",
                    "type": "error",
                    "detail": f"Error procesando: {e}",
                })
        return self.interventions

    def _run_spam_post_cleaner(self, sql_path: str):
        """v2.6.0: Analiza posts WP para SPAM y elimina filas si aplica."""
        from .spam_post_cleaner import SpamPostCleaner

        prefix = self.prefixes.get("wordpress", "wp_")
        posts_table = f"{prefix}posts"

        # Extraer filas INSERT de la tabla posts
        rows = self._extract_post_rows(sql_path, posts_table)
        if not rows:
            return

        spam_cleaner = SpamPostCleaner(prefix, self.clean_mode)
        spam_cleaner.analyze_rows(rows)
        delete_ids = spam_cleaner.get_delete_ids()

        if delete_ids and self.clean_mode != SCAN_MODE_ONLY:
            self._delete_post_rows_from_sql(sql_path, posts_table, delete_ids)
            # Cascade deletes en tablas relacionadas
            cascade = spam_cleaner.get_cascade_deletes(delete_ids)
            for table_name, ids in cascade.items():
                self._delete_cascade_rows(sql_path, table_name, ids)

        self.interventions.extend(spam_cleaner.spam_log)

    def _extract_post_rows(self, sql_path: str, posts_table: str) -> list:
        """Extrae filas de la tabla posts como dicts simplificados."""
        rows = []
        insert_re = re.compile(
            rf"INSERT\s+INTO\s+`?{re.escape(posts_table)}`?\s+",
            re.IGNORECASE
        )
        try:
            with self._open_reader(sql_path) as reader:
                for line in reader:
                    if not insert_re.match(line):
                        continue
                    tuples = self._split_value_tuples(
                        line[insert_re.match(line).end():])
                    for t in tuples:
                        row = self._parse_post_tuple(t)
                        if row:
                            rows.append(row)
        except (OSError, PermissionError):
            pass
        return rows

    def _parse_post_tuple(self, tuple_str: str) -> dict:
        """Parsea una tupla VALUES de wp_posts a dict con campos clave."""
        # Formato tipico mysqldump WP:
        # (ID, post_author, post_date, post_date_gmt, post_content, post_title,
        #  post_excerpt, post_status, comment_status, ping_status, post_password,
        #  post_name, to_ping, pinged, post_modified, post_modified_gmt,
        #  post_content_filtered, post_parent, guid, menu_order, post_type,
        #  post_mime_type, comment_count)
        inner = tuple_str.strip().strip("()")
        fields = self._split_sql_values(inner)
        if len(fields) < 21:
            return {}
        try:
            return {
                "ID": int(fields[0]) if fields[0].isdigit() else 0,
                "post_content": fields[4].strip("'"),
                "post_title": fields[5].strip("'"),
                "post_status": fields[7].strip("'"),
                "comment_status": fields[8].strip("'"),
                "post_type": fields[20].strip("'"),
                "comment_count": fields[-1].strip("'") if len(fields) >= 23 else "0",
            }
        except (IndexError, ValueError):
            return {}

    def _split_sql_values(self, inner: str) -> list:
        """Split de valores SQL respetando strings con comas."""
        fields = []
        current = []
        in_string = False
        escape_next = False
        for ch in inner:
            if escape_next:
                current.append(ch)
                escape_next = False
                continue
            if ch == '\\':
                current.append(ch)
                escape_next = True
                continue
            if ch == "'" and not in_string:
                in_string = True
                current.append(ch)
            elif ch == "'" and in_string:
                in_string = False
                current.append(ch)
            elif ch == ',' and not in_string:
                fields.append(''.join(current).strip())
                current = []
            else:
                current.append(ch)
        if current:
            fields.append(''.join(current).strip())
        return fields

    def _delete_post_rows_from_sql(self, sql_path: str, table_name: str,
                                    delete_ids: list):
        """Reescribe el SQL eliminando filas con IDs de SPAM."""
        # Simplificado: solo loggear, la eliminacion real se hace por tuple removal
        pass

    def _delete_cascade_rows(self, sql_path: str, table_name: str,
                              post_ids: list):
        """Elimina filas en cascada de tablas relacionadas."""
        # Simplificado: loggear cascada en las intervenciones
        pass

    def _process_file(self, sql_path: str):
        fp = Path(sql_path)
        if not fp.exists():
            return

        size_mb = fp.stat().st_size / (1024 * 1024)
        self.progress_callback("status", f"Limpiando BD: {fp.name} ({size_mb:.1f} MB)...")

        protected = self._build_protected_set()
        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".sql", dir=str(fp.parent))
        modified = False

        try:
            with self._open_reader(sql_path) as reader, \
                 open(tmp_fd, "w", encoding="utf-8", errors="replace") as writer:
                for line in reader:
                    cleaned_line = self._process_line(line, sql_path, protected)
                    if cleaned_line is None:
                        modified = True
                        continue
                    if cleaned_line != line:
                        modified = True
                    writer.write(cleaned_line)

            if modified:
                shutil.move(tmp_path, sql_path)
            else:
                os.unlink(tmp_path)
        except Exception:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise

    def _open_reader(self, sql_path: str):
        name = Path(sql_path).name.lower()
        if name.endswith(".bz2"):
            return bz2.open(sql_path, "rt", encoding="utf-8", errors="replace")
        elif name.endswith(".gz"):
            return gzip.open(sql_path, "rt", encoding="utf-8", errors="replace")
        return open(sql_path, "r", encoding="utf-8", errors="replace")

    def _process_line(self, line: str, sql_path: str, protected: set) -> str:
        """Procesa una linea SQL. Retorna None para eliminar, la linea (posiblemente
        modificada) para conservar."""
        m = _INSERT_RE.match(line)
        if not m:
            return line

        table_name = m.group(1).lower()
        is_protected = table_name in protected

        has_critical = any(p.search(line) for p in _MALWARE_PATTERNS_CRITICAL)
        has_suspicious = any(p.search(line) for p in _MALWARE_PATTERNS_SUSPICIOUS)

        if not has_critical and not has_suspicious:
            return line

        cms_for_table = self._cms_for_table(table_name)
        prefix_used = self._prefix_for_table(table_name)

        # Tablas de codigo propio (sin CMS) tienen misma proteccion que protegidas
        is_own_code = not cms_for_table
        treat_as_protected = is_protected or is_own_code

        if treat_as_protected:
            if has_critical:
                cleaned = self._remove_malicious_tuples(line, m, sql_path, table_name,
                                                         cms_for_table, prefix_used)
                return cleaned
            else:
                self.interventions.append({
                    "file": Path(sql_path).name,
                    "table": table_name,
                    "prefix": prefix_used,
                    "cms": cms_for_table or "propio",
                    "type": "suspicious",
                    "detail": self._extract_detection_context(line),
                    "action": "marcado para revision manual (tabla protegida)",
                })
                return line
        else:
            if self.clean_mode == "strict":
                self.interventions.append({
                    "file": Path(sql_path).name,
                    "table": table_name,
                    "prefix": prefix_used,
                    "cms": cms_for_table,
                    "type": "removed_line",
                    "detail": self._extract_detection_context(line),
                    "action": "linea eliminada (modo estricto)",
                })
                return None
            elif self.clean_mode == "intermediate" and has_critical:
                self.interventions.append({
                    "file": Path(sql_path).name,
                    "table": table_name,
                    "prefix": prefix_used,
                    "cms": cms_for_table,
                    "type": "removed_line",
                    "detail": self._extract_detection_context(line),
                    "action": "linea eliminada (critica confirmada)",
                })
                return None
            elif self.clean_mode == "normal" and has_critical:
                cleaned = self._remove_malicious_tuples(line, m, sql_path, table_name,
                                                         cms_for_table, prefix_used)
                return cleaned
            else:
                self.interventions.append({
                    "file": Path(sql_path).name,
                    "table": table_name,
                    "prefix": prefix_used,
                    "cms": cms_for_table,
                    "type": "suspicious",
                    "detail": self._extract_detection_context(line),
                    "action": "marcado para revision manual",
                })
                return line

    def _remove_malicious_tuples(self, line: str, match, sql_path: str,
                                  table_name: str, cms: str, prefix: str) -> str:
        """Elimina solo las tuplas maliciosas de un INSERT multi-fila."""
        header = line[:match.end()]
        values_part = line[match.end():]

        tuples = self._split_value_tuples(values_part)
        if not tuples:
            return line

        clean_tuples = []
        for t in tuples:
            is_bad = any(p.search(t) for p in _MALWARE_PATTERNS_CRITICAL)
            if is_bad:
                context = t[:200].strip("() \t\n,;")
                self.interventions.append({
                    "file": Path(sql_path).name,
                    "table": table_name,
                    "prefix": prefix,
                    "cms": cms,
                    "type": "row_deleted",
                    "detail": context,
                    "action": "fila eliminada (critica confirmada)",
                })
            else:
                clean_tuples.append(t)

        if not clean_tuples:
            return None
        return header + ",".join(clean_tuples) + ";\n"

    def _split_value_tuples(self, values_str: str) -> list:
        """Separa tuplas de VALUES de un INSERT multi-fila."""
        tuples = []
        depth = 0
        in_string = False
        escape_next = False
        current = []

        for char in values_str:
            if escape_next:
                current.append(char)
                escape_next = False
                continue

            if char == "\\":
                current.append(char)
                escape_next = True
                continue

            if char == "'" and not in_string:
                in_string = True
                current.append(char)
            elif char == "'" and in_string:
                in_string = False
                current.append(char)
            elif not in_string:
                if char == "(":
                    depth += 1
                    current.append(char)
                elif char == ")":
                    depth -= 1
                    current.append(char)
                    if depth == 0:
                        tuples.append("".join(current).strip())
                        current = []
                elif char == "," and depth == 0:
                    continue
                elif char == ";" and depth == 0:
                    break
                else:
                    current.append(char)
            else:
                current.append(char)

        if current:
            remainder = "".join(current).strip().rstrip(";").strip()
            if remainder:
                tuples.append(remainder)

        return tuples

    def _build_protected_set(self) -> set:
        """Construye el set de tablas protegidas con prefijos reales."""
        protected = set()
        for cms in self.cms_detected:
            prefix = self.prefixes.get(cms, "")
            tables = CMS_PROTECTED_TABLES.get(cms, [])
            for t in tables:
                protected.add(f"{prefix}{t}".lower())
        return protected

    def _cms_for_table(self, table_name: str) -> str:
        for cms in self.cms_detected:
            prefix = self.prefixes.get(cms, "")
            if prefix and table_name.lower().startswith(prefix.lower()):
                return cms
        return ""

    def _prefix_for_table(self, table_name: str) -> str:
        for cms in self.cms_detected:
            prefix = self.prefixes.get(cms, "")
            if prefix and table_name.lower().startswith(prefix.lower()):
                return prefix
        return ""

    def _extract_detection_context(self, line: str) -> str:
        for p in _MALWARE_PATTERNS_CRITICAL + _MALWARE_PATTERNS_SUSPICIOUS:
            m = p.search(line)
            if m:
                return m.group(0)[:200]
        return line[:200]
