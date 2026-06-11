"""Limpiador de dumps SQL — eliminacion por fila con tablas protegidas.

v2.6.7: la BD ya NO se elimina/mueve salvo que este MUY infectada. En su lugar:
  - se comentan (neutralizan) los registros de cron inseguros y se reportan,
  - se eliminan/deshabilitan usuarios peligrosos dejando SIEMPRE el mas antiguo,
  - se regenera una contrasena segura para el usuario conservado (se reporta).
"""
import os
import re
import gzip
import bz2
import hashlib
import secrets
import string
import tempfile
import shutil
from pathlib import Path
from typing import Callable

from ..config.settings import CMS_PROTECTED_TABLES, SCAN_MODE_ONLY


# v2.6.7: umbral de "muy infectada" — sobre este nº de filas criticas confirmadas
# se permite la eliminacion agresiva de filas; por debajo se preserva la BD.
DB_VERY_INFECTED_THRESHOLD = 40

# Patrones de hooks/eventos de cron inseguros (WP almacena cron serializado en
# wp_options.option_name='cron').
_CRON_SUSPICIOUS = re.compile(
    r"(eval|base64_decode|gzinflate|gzuncompress|str_rot13|assert|"
    r"shell_exec|passthru|system|exec|popen|proc_open|file_get_contents|"
    r"curl_exec|wp_insert_user|wp_create_user|move_uploaded_file|"
    r"https?://[^\";']+\.(?:php|txt))",
    re.IGNORECASE,
)

# Logins de usuario WP claramente peligrosos / generados por malware.
_DANGEROUS_USER_PATTERNS = [
    re.compile(r"^(?:admin|administrator|wp[-_]?admin|user|test|root|support|"
               r"backup|demo|guest)\d+$", re.IGNORECASE),
    re.compile(r"^[a-f0-9]{10,}$", re.IGNORECASE),
    re.compile(r"(hack|shell|backdoor|spam|malware|inject|b374k|wso|"
               r"r57|c99|attacker)", re.IGNORECASE),
]


def generate_secure_password(length: int = 16) -> str:
    """Genera una contrasena segura sin caracteres ambiguos."""
    alphabet = (string.ascii_lowercase + string.ascii_uppercase +
                string.digits + "!@#$%*-_=+")
    # evitar ambiguos
    alphabet = alphabet.replace("l", "").replace("I", "").replace("O", "").replace("0", "")
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pwd) and any(c.isupper() for c in pwd)
                and any(c.isdigit() for c in pwd)
                and any(c in "!@#$%*-_=+" for c in pwd)):
            return pwd


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
        # v2.6.7: nuevos logs para el reporte
        self.cron_log: list[dict] = []        # registros cron inseguros neutralizados
        self.users_log: list[dict] = []       # usuarios eliminados/deshabilitados/conservados
        self.generated_passwords: dict = {    # contrasenas generadas/sugeridas
            "wordpress": [], "cpanel": [], "database": [], "emails": [],
        }
        self._critical_rows_count = 0
        self.db_very_infected = False

    def process(self, sql_files: list) -> list:
        """Procesa todos los dumps SQL. Retorna lista de intervenciones.
        v2.6.0: Integra SpamPostCleaner para posts WP."""
        for sql_path in sql_files:
            try:
                self._process_file(sql_path)
                # v2.6.0: SpamPostCleaner para WordPress
                if "wordpress" in self.cms_detected:
                    self._run_spam_post_cleaner(sql_path)
                    # v2.6.7: endurecimiento conservador (cron + usuarios + password)
                    self._harden_wp_db(sql_path)
            except (OSError, PermissionError) as e:
                self.interventions.append({
                    "file": str(sql_path),
                    "table": "",
                    "type": "error",
                    "detail": f"Error procesando: {e}",
                })

        # v2.6.7: contrasenas sugeridas para cPanel / BD (a aplicar manualmente)
        if "wordpress" in self.cms_detected or self.generated_passwords["wordpress"]:
            note = "cambiar por otra propia cuando pueda ingresar"
            if not self.generated_passwords["cpanel"]:
                self.generated_passwords["cpanel"].append(
                    {"domain": "principal", "user": "(usuario cPanel)",
                     "pass": generate_secure_password(), "note": note})
            if not self.generated_passwords["database"]:
                self.generated_passwords["database"].append(
                    {"db": "(base de datos)", "user": "(usuario BD)",
                     "pass": generate_secure_password(), "note": note})

        # v2.6.8 Mejora #1: NO cambiar contrasenas de correo automaticamente.
        # Solo LISTAR las cuentas de correo que requieren cambio manual.
        self.generated_passwords["emails"] = [
            {"email": acc, "action": "cambio manual requerido"}
            for acc in self._enumerate_email_accounts()
        ]
        return self.interventions

    def _enumerate_email_accounts(self) -> list:
        """v2.6.8: lista (best-effort) las cuentas de correo del backup cPanel para
        reportarlas como 'cambio manual requerido'. No modifica nada."""
        accounts = set()
        try:
            for root, dirs, files in os.walk(self.extract_dir):
                rp = Path(root)
                # cPanel guarda passwd de correo en homedir/etc/<dominio>/passwd
                if rp.name.lower() == "etc" and rp.parent.name.lower() == "homedir":
                    for dom_dir in rp.iterdir():
                        if dom_dir.is_dir():
                            passwd = dom_dir / "passwd"
                            if passwd.exists():
                                try:
                                    for line in passwd.read_text(
                                            encoding="utf-8", errors="replace").splitlines():
                                        user = line.split(":", 1)[0].strip()
                                        if user:
                                            accounts.add(f"{user}@{dom_dir.name}")
                                except OSError:
                                    pass
                    dirs[:] = []  # no descender mas en etc/
        except (OSError, PermissionError):
            pass
        return sorted(accounts)[:100]

    # ───────────────────────── v2.6.7: Endurecimiento WP ─────────────────────

    def _harden_wp_db(self, sql_path: str):
        """Neutraliza cron inseguro y limpia usuarios peligrosos, conservando el
        usuario mas antiguo y regenerando su contrasena. Preserva la BD."""
        prefix = self.prefixes.get("wordpress", "wp_")
        users_table = f"{prefix}users"
        options_table = f"{prefix}options"
        domain = Path(sql_path).stem

        # ── Pass 1: recolectar usuarios (ID, login) para decidir el mas antiguo ──
        # v2.6.8 Corrección #1: conservar UNICAMENTE el usuario mas antiguo; el resto
        # se elimina (los de login peligroso se marcan con razon especifica).
        users = self._collect_wp_users(sql_path, users_table)
        oldest_id = min((u["id"] for u in users), default=None)
        dangerous_ids = {u["id"] for u in users if u["id"] != oldest_id}

        new_pass = None
        new_hash = None
        kept_login = None
        if oldest_id is not None:
            kept = next((u for u in users if u["id"] == oldest_id), None)
            kept_login = kept["login"] if kept else "admin"
            new_pass = generate_secure_password()
            new_hash = hashlib.md5(new_pass.encode("utf-8")).hexdigest()

        if self.clean_mode == SCAN_MODE_ONLY:
            # Solo reporte: registrar hallazgos sin modificar
            for uid in dangerous_ids:
                u = next((x for x in users if x["id"] == uid), None)
                if u:
                    self.users_log.append({
                        "domain": domain, "user": u["login"], "action": "peligroso (no modificado)",
                        "reason": "login sospechoso"})
            return

        # ── Pass 2: reescribir el dump aplicando cambios ──
        fp = Path(sql_path)
        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".sql", dir=str(fp.parent))
        modified = False
        users_insert_re = re.compile(
            rf"INSERT\s+INTO\s+`?{re.escape(users_table)}`?\s+"
            rf"(?:\([^)]*\)\s*)?VALUES\s*", re.IGNORECASE)
        options_insert_re = re.compile(
            rf"INSERT\s+INTO\s+`?{re.escape(options_table)}`?\s+", re.IGNORECASE)
        try:
            # v3.0.0: cerrar el fd antes de abrirlo como writer para evitar leak en Windows
            os.close(tmp_fd)
            with self._open_reader(sql_path) as reader, \
                 open(tmp_path, "w", encoding="utf-8", errors="replace") as writer:
                for line in reader:
                    new_line = line
                    if users_insert_re.match(line):
                        rebuilt = self._rewrite_users_line(
                            line, users_insert_re, oldest_id, dangerous_ids, new_hash, domain)
                        if rebuilt is not None and rebuilt != line:
                            new_line = rebuilt
                            modified = True
                    elif options_insert_re.match(line) and "'cron'" in line.lower():
                        rebuilt = self._neutralize_cron_line(line, domain)
                        if rebuilt is not None and rebuilt != line:
                            new_line = rebuilt
                            modified = True
                    writer.write(new_line)
            if modified:
                shutil.move(tmp_path, sql_path)
            else:
                os.unlink(tmp_path)
        except Exception:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise

        # Registrar resultado de usuarios y contrasena generada
        if new_pass and kept_login:
            self.generated_passwords["wordpress"].append({
                "domain": domain, "user": kept_login, "pass": new_pass,
                "note": "cambiar por otra propia cuando pueda ingresar"})
            self.users_log.append({
                "domain": domain, "user": kept_login,
                "action": "conservado (mas antiguo) + contrasena regenerada",
                "reason": "usuario principal"})

    def _collect_wp_users(self, sql_path: str, users_table: str) -> list:
        """Extrae (id, login, registered) de las filas de wp_users."""
        users = []
        insert_re = re.compile(
            rf"INSERT\s+INTO\s+`?{re.escape(users_table)}`?\s+"
            rf"(?:\([^)]*\)\s*)?VALUES\s*", re.IGNORECASE)
        try:
            with self._open_reader(sql_path) as reader:
                for line in reader:
                    m = insert_re.match(line)
                    if not m:
                        continue
                    for t in self._split_value_tuples(line[m.end():]):
                        fields = self._split_sql_values(t.strip().strip("()"))
                        if len(fields) < 7:
                            continue
                        try:
                            uid = int(fields[0]) if fields[0].strip().isdigit() else None
                        except ValueError:
                            uid = None
                        if uid is None:
                            continue
                        users.append({
                            "id": uid,
                            "login": fields[1].strip().strip("'"),
                            "registered": fields[6].strip().strip("'"),
                        })
        except (OSError, PermissionError):
            pass
        return users

    @staticmethod
    def _is_dangerous_login(login: str) -> bool:
        if not login:
            return False
        return any(p.search(login) for p in _DANGEROUS_USER_PATTERNS)

    def _rewrite_users_line(self, line: str, insert_re, oldest_id, dangerous_ids,
                            new_hash: str, domain: str):
        """Reescribe una linea INSERT de wp_users: elimina usuarios peligrosos y
        regenera la contrasena (campo user_pass) del usuario mas antiguo."""
        m = insert_re.match(line)
        if not m:
            return None
        header = line[:m.end()]
        tuples = self._split_value_tuples(line[m.end():])
        if not tuples:
            return None
        kept_tuples = []
        for t in tuples:
            fields = self._split_sql_values(t.strip().strip("()"))
            if len(fields) < 7:
                kept_tuples.append(t)
                continue
            try:
                uid = int(fields[0]) if fields[0].strip().isdigit() else None
            except ValueError:
                uid = None
            login = fields[1].strip().strip("'")
            if uid is not None and uid in dangerous_ids:
                if self._is_dangerous_login(login):
                    reason = "login sospechoso generado por malware"
                else:
                    reason = "solo se conserva el usuario mas antiguo"
                self.users_log.append({
                    "domain": domain, "user": login,
                    "action": "eliminado (peligroso)" if self._is_dangerous_login(login)
                              else "eliminado (no es el mas antiguo)",
                    "reason": reason})
                continue  # no conservar
            if uid is not None and uid == oldest_id and new_hash:
                # Regenerar user_pass (campo indice 2). WP acepta MD5 y lo
                # re-cifra a phpass en el primer inicio de sesion.
                if len(fields) >= 3:
                    fields[2] = f"'{new_hash}'"
                kept_tuples.append("(" + ",".join(fields) + ")")
                continue
            kept_tuples.append(t)
        if not kept_tuples:
            return line  # no vaciar la tabla por seguridad
        return header + ",".join(kept_tuples) + ";\n"

    def _neutralize_cron_line(self, line: str, domain: str):
        """Si la opcion cron contiene eventos inseguros, la neutraliza dejando un
        cron vacio (WP reconstruye los eventos legitimos) y lo reporta."""
        if not _CRON_SUSPICIOUS.search(line):
            return None
        # Extraer hooks sospechosos para el reporte
        hooks = set(re.findall(r's:\d+:\\?"([a-zA-Z0-9_\-]{3,})\\?";', line))
        suspicious = [h for h in hooks if _CRON_SUSPICIOUS.search(h)] or ["(evento ofuscado)"]
        for h in suspicious[:20]:
            self.cron_log.append({
                "domain": domain, "hook": h,
                "action": "comentado/neutralizado",
                "reason": "evento de cron malware confirmado"})
        # v2.6.8 Corrección #1: COMENTAR (no eliminar) — se documenta el evento
        # malicioso en un comentario SQL y se neutraliza el valor a un cron vacio
        # (WP reconstruye los eventos legitimos). La fila NO se elimina.
        neutral = re.sub(
            r"('cron'\s*,\s*)'(?:[^'\\]|\\.)*'",
            r"\1'a:0:{}'",
            line, count=1, flags=re.IGNORECASE)
        comment = ("-- [cPacleanS] cron malicioso neutralizado (no eliminado): "
                   + ", ".join(suspicious[:10]) + "\n")
        return comment + neutral

    def _run_spam_post_cleaner(self, sql_path: str):
        """v2.6.0/2.6.8: Analiza posts y comentarios WP para SPAM/phishing y elimina
        las filas maliciosas (entradas de blog y comentarios) realmente del dump."""
        from .spam_post_cleaner import SpamPostCleaner

        prefix = self.prefixes.get("wordpress", "wp_")
        posts_table = f"{prefix}posts"
        comments_table = f"{prefix}comments"

        spam_cleaner = SpamPostCleaner(prefix, self.clean_mode)

        # Posts (entradas de blog maliciosas)
        post_rows = self._extract_post_rows(sql_path, posts_table)
        if post_rows:
            spam_cleaner.analyze_rows(post_rows)

        # v2.6.8: Comentarios spam/phishing
        comment_rows = self._extract_comment_rows(sql_path, comments_table)
        if comment_rows:
            spam_cleaner.analyze_comment_rows(comment_rows)

        if self.clean_mode != SCAN_MODE_ONLY:
            post_ids = spam_cleaner.get_delete_ids()
            if post_ids:
                self._delete_tuples_by_id(sql_path, posts_table, post_ids)
                cascade = spam_cleaner.get_cascade_deletes(post_ids)
                for table_name, ids in cascade.items():
                    if not table_name.endswith("comments"):
                        # postmeta/term_relationships referencian post_id (campo 1)
                        self._delete_tuples_by_id(sql_path, table_name, ids, id_index=1)
            comment_ids = spam_cleaner.get_comment_delete_ids()
            if comment_ids:
                self._delete_tuples_by_id(sql_path, comments_table, comment_ids)

        self.interventions.extend(spam_cleaner.spam_log)

    def _extract_comment_rows(self, sql_path: str, comments_table: str) -> list:
        """v2.6.8: extrae filas de wp_comments como dicts simplificados."""
        rows = []
        insert_re = re.compile(
            rf"INSERT\s+INTO\s+`?{re.escape(comments_table)}`?\s+"
            rf"(?:\([^)]*\)\s*)?VALUES\s*", re.IGNORECASE)
        try:
            with self._open_reader(sql_path) as reader:
                for line in reader:
                    m = insert_re.match(line)
                    if not m:
                        continue
                    for t in self._split_value_tuples(line[m.end():]):
                        fields = self._split_sql_values(t.strip().strip("()"))
                        # wp_comments: 0=comment_ID,1=comment_post_ID,4=comment_author_url,
                        # 8=comment_content,11=comment_approved (orden estandar)
                        if len(fields) < 12:
                            continue
                        try:
                            cid = int(fields[0]) if fields[0].strip().isdigit() else 0
                        except ValueError:
                            cid = 0
                        rows.append({
                            "comment_ID": cid,
                            "comment_author_url": fields[4].strip().strip("'"),
                            "comment_content": fields[8].strip().strip("'"),
                            "comment_approved": fields[11].strip().strip("'"),
                        })
        except (OSError, PermissionError):
            pass
        return rows

    def _delete_tuples_by_id(self, sql_path: str, table: str, ids: list,
                             id_index: int = 0):
        """v2.6.8: elimina del dump las tuplas de `table` cuyo campo `id_index`
        este en `ids`. Reescribe en sitio preservando el resto del archivo."""
        if not ids:
            return
        id_set = {str(i) for i in ids}
        fp = Path(sql_path)
        insert_re = re.compile(
            rf"INSERT\s+INTO\s+`?{re.escape(table)}`?\s+"
            rf"(?:\([^)]*\)\s*)?VALUES\s*", re.IGNORECASE)
        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".sql", dir=str(fp.parent))
        modified = False
        removed = 0
        try:
            os.close(tmp_fd)
            with self._open_reader(sql_path) as reader, \
                 open(tmp_path, "w", encoding="utf-8", errors="replace") as writer:
                for line in reader:
                    m = insert_re.match(line)
                    if not m:
                        writer.write(line)
                        continue
                    header = line[:m.end()]
                    kept = []
                    for t in self._split_value_tuples(line[m.end():]):
                        fields = self._split_sql_values(t.strip().strip("()"))
                        val = fields[id_index].strip().strip("'") if len(fields) > id_index else None
                        if val is not None and val in id_set:
                            removed += 1
                            continue
                        kept.append(t)
                    if removed and not kept:
                        modified = True
                        continue  # toda la linea eran filas spam
                    new_line = header + ",".join(kept) + ";\n" if kept else line
                    if new_line != line:
                        modified = True
                    writer.write(new_line)
            if modified:
                shutil.move(tmp_path, sql_path)
            else:
                os.unlink(tmp_path)
        except Exception:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            return
        if removed:
            self.interventions.append({
                "file": fp.name, "table": table, "cms": "wordpress",
                "type": "row_deleted", "detail": f"{removed} filas spam/phishing",
                "action": f"{removed} filas eliminadas de {table}",
            })

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
        """Split de valores SQL respetando strings con comas.
        v3.0.0: maneja comillas simples Y dobles (modo ANSI_QUOTES MySQL)."""
        fields = []
        current = []
        in_string = False
        string_char = ""
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
            if not in_string and ch in ("'", '"'):
                in_string = True
                string_char = ch
                current.append(ch)
            elif in_string and ch == string_char:
                in_string = False
                string_char = ""
                current.append(ch)
            elif ch == ',' and not in_string:
                fields.append(''.join(current).strip())
                current = []
            else:
                current.append(ch)
        if current:
            fields.append(''.join(current).strip())
        return fields

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
            os.close(tmp_fd)
            with self._open_reader(sql_path) as reader, \
                 open(tmp_path, "w", encoding="utf-8", errors="replace") as writer:
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
                self._critical_rows_count += 1
                if self._critical_rows_count >= DB_VERY_INFECTED_THRESHOLD:
                    self.db_very_infected = True
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
