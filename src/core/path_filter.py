"""Filtro de rutas para modo 'Solo contenido critico'.

Omite directorios de servidor que cPanel recrea automaticamente y que nunca
se restauran manualmente al hosting (logs, ssl, ips, bandwidth, etc.).
Solo procesa rutas que el administrador sube de vuelta: public_html, mail, sql.
"""
from pathlib import Path

# Directorios que SE restauran manualmente al hosting
CRITICAL_WHITELIST = frozenset({
    "public_html",
    "moodledata",
    "sitejetbuilder",
    "mail",
    "www",
    "domains",          # addon domains en cPanel
    "home",             # algunas estructuras usan /home/user/
})

# Directorios de sistema — cPanel los recrea, no restaurar
CRITICAL_BLACKLIST = frozenset({
    "ips",
    "logs", "log",
    "cron",
    "meta",
    "mms",
    ".trash",
    "tmp", "temp",
    ".cpanel",
    ".cphorde",
    ".softaculous",
    "access-logs",
    "ssl",
    "bandwidth",
    "yarn",
    "perl5",
    "virtfs",
    "backups",
    ".npm",
    ".cache",
    ".local",
    ".config",
    "cpanelbackups",
    "softaculous_backups",
})

# Dotfiles de configuracion de entorno de shell — no restaurables
BLACKLISTED_FILENAMES = frozenset({
    ".bash_logout",
    ".bash_profile",
    ".bashrc",
    ".gemrc",
    ".lastlogin",
    ".htpasswds",
    ".my.cnf",
    ".cagefs",
    ".cl.selector",
    ".forward",
    ".procmailrc",
    ".bash_history",
})


def is_critical_path(file_path: str) -> bool:
    """
    Retorna True si el archivo debe escanearse en modo 'Solo contenido critico'.

    Logica (en orden de prioridad):
    1. Archivos .tar.gz / .zip / .gz anidados dentro del backup -> omitir
    2. Dotfiles de entorno de shell -> omitir
    3. Cualquier segmento de ruta en CRITICAL_BLACKLIST -> omitir
    4. Archivos .sql / .sql.gz -> SIEMPRE incluir (bases de datos)
    5. Cualquier segmento de ruta en CRITICAL_WHITELIST -> incluir
    6. Resto -> omitir
    """
    fp = Path(file_path)
    name_lower = fp.name.lower()
    suffix = fp.suffix.lower()

    # Archivos de backup anidados: siempre omitir
    if (name_lower.endswith(".tar.gz") or name_lower.endswith(".tgz")
            or suffix in (".zip", ".tar")):
        return False

    # Dotfiles de entorno de shell
    if name_lower in BLACKLISTED_FILENAMES:
        return False

    # Normalizar partes de la ruta (excluir la raiz de extraccion, usar solo segmentos relativos)
    parts_lower = {p.lower() for p in fp.parts}

    # Directorios de sistema -> omitir (prioridad sobre whitelist)
    if parts_lower & CRITICAL_BLACKLIST:
        return False

    # Dumps SQL -> siempre incluir
    if suffix == ".sql" or name_lower.endswith(".sql.gz"):
        return True

    # Directorios de contenido restaurable -> incluir
    if parts_lower & CRITICAL_WHITELIST:
        return True

    return False


def filter_files(file_paths: list, critical_only: bool = False) -> tuple:
    """
    Filtra la lista de archivos segun el modo critico.

    Args:
        file_paths: lista de rutas absolutas recopiladas por el engine
        critical_only: si True aplica el filtro whitelist/blacklist

    Returns:
        (files_to_scan, omitted_count)
    """
    if not critical_only:
        return file_paths, 0

    included = []
    omitted = 0
    for fp in file_paths:
        if is_critical_path(fp):
            included.append(fp)
        else:
            omitted += 1
    return included, omitted
