"""Corpus de prueba versionado y determinista para cPacleanS.

No almacena malware vivo en el repositorio: los payloads viven codificados en
base64 y se ensamblan en tiempo de ejecucion dentro de un .tar.gz en un
directorio temporal. Esto evita disparar el antivirus del equipo y mantiene el
repo limpio, sin perder reproducibilidad (el builder es la fuente versionada).

API:
  build_clean_backup(dest_dir)    -> ruta .tar.gz (solo archivos legitimos)
  build_infected_backup(dest_dir) -> ruta .tar.gz (legitimos + muestras inertes)
  MANIFEST                        -> clasificacion esperada por arcname

CLI: python tests/fixtures/build_corpus.py <dir_salida>
"""
from __future__ import annotations
import base64
import io
import os
import tarfile

# Payloads codificados (inertes). Decodificados solo al construir el tar.
_B64 = {
    "webshell_eval": "PD9waHAgZXZhbChiYXNlNjRfZGVjb2RlKCRfUE9TVFsiY21kIl0pKTsgPz4K",
    "webshell_system": "PD9waHAgc3lzdGVtKCRfR0VUWyJjIl0pOyA/Pgo=",
    "backdoor_var": "PD9waHAgJHg9ImJhc2U2NF9kZWNvZGUiOyBldmFsKCR4KCJjM2x6ZEdWdEtDSnBaQ0lwT3c9PSIpKTsgPz4K",
    "htaccess_handler": "QWRkSGFuZGxlciBhcHBsaWNhdGlvbi94LWh0dHBkLXBocCAuanBnIC5naWYgLnBuZwo=",
    "htaccess_redirect": "UmV3cml0ZUVuZ2luZSBPbgpSZXdyaXRlUnVsZSBeKC4qKSQgaHR0cDovL2V2aWwuZXhhbXBsZS9yIFtSPTMwMSxMXQo=",
    "sql_inject": "LS0gTXlTUUwgZHVtcApDUkVBVEUgVEFCTEUgd3Bfb3B0aW9ucyAob3B0aW9uX2lkIGJpZ2ludCk7CklOU0VSVCBJTlRPIHdwX3Bvc3RzIFZBTFVFUyAoMSwieCIsIjxzY3JpcHQ+ZXZhbChhdG9iKHgpKTwvc2NyaXB0PiIpOwo=",
    "wpconfig": "PD9waHAKZGVmaW5lKCJEQl9OQU1FIiwidGVzdGRiIik7CmRlZmluZSgiREJfVVNFUiIsInUiKTsKJHRhYmxlX3ByZWZpeCA9ICJ3cF8iOwo=",
    "versionphp": "PD9waHAKJHdwX3ZlcnNpb24gPSAiNi40LjIiOwo=",
    "akismet": "PD9waHAKLyogUGx1Z2luIE5hbWU6IEFraXNtZXQgQW50aS1TcGFtICovCmZ1bmN0aW9uIGFraXNtZXRfY2hlY2soKSB7IHJldHVybiB0cnVlOyB9Cg==",
    "style": "LyogVGhlbWUgTmFtZTogVHdlbnR5IFR3ZW50eS1Gb3VyICovCmJvZHkgeyBtYXJnaW46IDA7IH0K",
    "index_stub": "PD9waHAKLy8gU2lsZW5jZSBpcyBnb2xkZW4K",
    "readme": "VHdlbnR5IFR3ZW50eS1Gb3VyIHRoZW1lLiBMaWNlbnNlIEdQTC4K",
    # Valor serializado de wp_options.cron con hook inseguro (URL .php + token
    # base64_decode SIN parentesis: dispara _CRON_SUSPICIOUS para el endurecimiento
    # pero NO el patron critico/sospechoso de _process_line). Inerte, no ejecutable.
    "cron_evil": ("YToxOntpOjE2OTk5OTk5OTk7YToxOntzOjEyOiJldmlsX2Nyb25qb2IiO2E6Mzp7"
                  "czo4OiJzY2hlZHVsZSI7czo2OiJob3VybHkiO3M6NDoiYXJncyI7YToxOntpOjA7"
                  "czozMDoiaHR0cDovL2V2aWwuZXhhbXBsZS94LnBocCBiYXNlNjRfZGVjb2RlIjt9"
                  "fX19"),
}
_EICAR_PARTS = ["WDVPIVAlQEFQWzRcUFpYNTQoUF4p", "N0NDKTd9JEVJQ0FSLVNUQU5EQVJE", "LUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo="]
# JPEG minimo valido (cabecera SOI/APP0 + EOI). Archivo legitimo, no debe marcarse.
_JPEG = bytes.fromhex("ffd8ffe000104a46494600010100000100010000ffd9")

_ROOT = "backup-test/homedir/public_html"

# Archivos legitimos comunes a ambos backups: deben quedar intactos (cero FP).
_LEGIT = {
    f"{_ROOT}/wp-config.php": ("wpconfig", "text"),
    f"{_ROOT}/wp-includes/version.php": ("versionphp", "text"),
    f"{_ROOT}/wp-content/plugins/akismet/akismet.php": ("akismet", "text"),
    f"{_ROOT}/wp-content/themes/twentytwentyfour/style.css": ("style", "text"),
    f"{_ROOT}/wp-content/themes/twentytwentyfour/readme.txt": ("readme", "text"),
    f"{_ROOT}/wp-content/index.php": ("index_stub", "text"),
    f"{_ROOT}/index.php": ("index_stub", "text"),
    f"{_ROOT}/wp-content/uploads/2024/01/photo.jpg": ("__jpeg__", "bin"),
}

# Muestras de malware inerte esperadas como CONFIRMADAS por cPacleanS.
_MALWARE = {
    f"{_ROOT}/shell.php": "webshell_eval",
    f"{_ROOT}/wp-config-backup.php": "backdoor_var",
    f"{_ROOT}/wp-content/uploads/2024/01/image.jpg.php": "webshell_system",
    f"{_ROOT}/wp-content/uploads/.htaccess": "htaccess_handler",
    f"{_ROOT}/.htaccess": "htaccess_redirect",
}
# EICAR: muestra para oraculo externo (AV). cPacleanS es anti-webshell, no AV
# binario; su deteccion de EICAR no es requisito.
_EICAR = f"{_ROOT}/wp-content/uploads/eicar.com.txt"
# Dump SQL con fila inyectada (lo procesa el DBCleaner, no clean_findings).
_SQL = "backup-test/mysql/testdb.sql"

MANIFEST = {
    "legit": sorted(_LEGIT.keys()),
    "malware_confirmed": sorted(_MALWARE.keys()),
    "eicar": _EICAR,
    "sql_dump": _SQL,
}


def _content(key: str) -> bytes:
    if key == "__jpeg__":
        return _JPEG
    return base64.b64decode(_B64[key])


def _eicar() -> bytes:
    return b"".join(base64.b64decode(p) for p in _EICAR_PARTS)


def _write_tar(path: str, files: dict):
    with tarfile.open(path, "w:gz") as tar:
        for arcname, data in files.items():
            ti = tarfile.TarInfo(name=arcname)
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))


def _legit_files() -> dict:
    out = {}
    for arc, (key, _kind) in _LEGIT.items():
        out[arc] = _content(key)
    return out


def build_clean_backup(dest_dir: str) -> str:
    os.makedirs(dest_dir, exist_ok=True)
    path = os.path.join(dest_dir, "control-limpio.tar.gz")
    _write_tar(path, _legit_files())
    return path


def build_infected_backup(dest_dir: str) -> str:
    os.makedirs(dest_dir, exist_ok=True)
    path = os.path.join(dest_dir, "control-infectado.tar.gz")
    files = _legit_files()
    for arc, key in _MALWARE.items():
        files[arc] = _content(key)
    files[_EICAR] = _eicar()
    files[_SQL] = _content("sql_inject")
    _write_tar(path, files)
    return path


# ─────────────── Dump SQL WordPress (cobertura DBCleaner) v3.1.3 ───────────────
# Filas legitimas + filas maliciosas inertes para ejercitar DBCleaner y
# SpamPostCleaner. El unico fragmento sensible (valor cron) viaja en base64
# (_B64['cron_evil']); el resto es SQL benigno (sin firmas crudas). Cada INSERT
# va en UNA sola linea (los cleaners procesan por linea). Prefijo wp_.

# Expectativas que el limpiador debe cumplir sobre el dump (para asserts).
SQL_DUMP_EXPECT = {
    "users_kept_login": "oldadmin",                        # id=1 mas antiguo: conservar
    "users_removed_logins": ["admin123", "deadbeefcafe"],  # peligrosos: eliminar
    "posts_kept_ids": [10, 11],                            # page protegida + post legitimo
    "posts_removed_id": 12,                                # spam casino/viagra
    "comments_kept_id": 1,
    "comments_removed_id": 2,                              # phishing
    "statistics_kept_id": 1,                               # fila legitima (tabla no protegida)
    "statistics_removed_id": 2,                            # fila critica (CONCAT 0x..)
    "cron_neutralized": "a:0:{}",
    "user_pass_literal": "5f4dcc3b5aa765d61d8327deb882cf99",  # debe desaparecer
}


def _post_tuple(pid, content, title, ptype, ccount):
    """23 campos estandar de wp_posts (orden mysqldump)."""
    f = [str(pid), "1", "'2024-01-01 00:00:00'", "'2024-01-01 00:00:00'",
         f"'{content}'", f"'{title}'", "''", "'publish'", "'closed'",
         "'closed'", "''", f"'slug-{pid}'", "''", "''",
         "'2024-01-01 00:00:00'", "'2024-01-01 00:00:00'", "''", "0",
         f"'http://example.com/?p={pid}'", "0", f"'{ptype}'", "''", str(ccount)]
    return "(" + ",".join(f) + ")"


def _user_tuple(uid, login, registered):
    """10 campos estandar de wp_users (pass = md5('password'))."""
    f = [str(uid), f"'{login}'", "'5f4dcc3b5aa765d61d8327deb882cf99'",
         f"'{login}'", f"'{login}@example.com'", "''", f"'{registered}'",
         "''", "0", f"'{login}'"]
    return "(" + ",".join(f) + ")"


def _comment_tuple(cid, post_id, url, content):
    """15 campos estandar de wp_comments."""
    f = [str(cid), str(post_id), "'visitor'", "'v@example.com'", f"'{url}'",
         "'127.0.0.1'", "'2024-01-01 00:00:00'", "'2024-01-01 00:00:00'",
         f"'{content}'", "0", "'1'", "''", "''", "0", "0"]
    return "(" + ",".join(f) + ")"


def wp_sql_dump_text() -> str:
    """Genera el texto del dump WP de prueba (determinista)."""
    cron_val = _content("cron_evil").decode("utf-8")
    # Fila critica de SQL injection: CONCAT(0x..) con >20 hex (inerte, sin webshell
    # literal). Tabla wp_statistics: prefijo wp_ pero NO protegida.
    concat = "CONCAT(0x3c3f7068702073797374656d28245f4745545b78 ,0x29)"
    lines = [
        "-- cPacleanS fixture dump (inerte)",
        ("INSERT INTO `wp_options` (option_id, option_name, option_value, autoload) "
         "VALUES (1,'siteurl','http://example.com','yes'),"
         f"(2,'cron','{cron_val}','yes');"),
        ("INSERT INTO `wp_users` VALUES "
         + _user_tuple(1, "oldadmin", "2019-01-01 00:00:00") + ","
         + _user_tuple(2, "admin123", "2023-05-05 00:00:00") + ","
         + _user_tuple(3, "deadbeefcafe", "2023-06-06 00:00:00") + ";"),
        # Spam en PRIMERA posicion: regresion del fix v3.1.3 (_extract_post_rows).
        ("INSERT INTO `wp_posts` VALUES "
         + _post_tuple(12, "Best online casino bonus and cheap viagra pills order now",
                       "Hot deals", "post", 0) + ","
         + _post_tuple(10, "About this site", "About", "page", 0) + ","
         + _post_tuple(11, "Welcome to my blog about gardening and cooking tips",
                       "My blog", "post", 0) + ";"),
        ("INSERT INTO `wp_comments` VALUES "
         + _comment_tuple(1, 11, "", "Great article thanks for sharing") + ","
         + _comment_tuple(2, 11, "http://spam.example",
                          "verify your account login to claim your prize") + ";"),
        ("INSERT INTO `wp_statistics` VALUES "
         "(1,'normal visit data'),"
         f"(2,'payload {concat} end');"),
    ]
    return "\n".join(lines) + "\n"


def build_wp_sql_dump(path: str) -> str:
    """Escribe el dump en `path` y retorna el texto generado."""
    text = wp_sql_dump_text()
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return text


if __name__ == "__main__":
    import sys
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    c = build_clean_backup(out)
    i = build_infected_backup(out)
    print("clean   :", c, os.path.getsize(c), "bytes")
    print("infected:", i, os.path.getsize(i), "bytes")
    print("legit   :", len(MANIFEST["legit"]), "archivos")
    print("malware :", len(MANIFEST["malware_confirmed"]), "muestras confirmadas esperadas")
