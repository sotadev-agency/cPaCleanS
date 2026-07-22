"""Filtro de rutas para modo 'Solo contenido critico'.

Omite directorios de servidor que cPanel recrea automaticamente y que nunca
se restauran manualmente al hosting (logs, ssl, ips, bandwidth, etc.).
Solo procesa rutas que el administrador sube de vuelta: public_html, mail, sql.

IMPORTANTE: siempre pasar base_dir (directorio de extraccion) para que el filtro
opere sobre la ruta RELATIVA, no la absoluta. Sin base_dir, segmentos del sistema
como 'Temp' (C:\\...\\AppData\\Local\\Temp\\...) pueden coincidir con el blacklist
y bloquear todos los archivos.
"""
from pathlib import Path

# Directorios que SE restauran manualmente al hosting
CRITICAL_WHITELIST = frozenset({
    "public_html",
    "moodledata",
    "sitejetbuilder",
    "mail",
    "www",
    "domains",          # addon domains en cPanel (subdirectorio de homedir)
    "home",             # algunas estructuras usan /home/user/
    "htdocs",           # alias de public_html en algunos paneles
    "httpdocs",         # alias en Plesk/DirectAdmin
})

# Directorios de sistema — cPanel los recrea, NO hay que restaurarlos
CRITICAL_BLACKLIST = frozenset({
    "ips",
    "logs", "log",
    "cron",
    "meta",
    "mms",
    ".trash",
    "tmp", "temp",      # ATENCION: se evalua sobre ruta RELATIVA al extract_dir
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


def is_critical_path(file_path: str, base_dir: str = None) -> bool:
    """
    Retorna True si el archivo debe escanearse en modo 'Solo contenido critico'.

    Args:
        file_path: ruta absoluta del archivo
        base_dir:  directorio raiz de extraccion del backup (SIEMPRE proporcionar).
                   Permite evaluar la ruta relativa en lugar de la absoluta,
                   evitando falsos positivos con directorios del sistema operativo
                   (ej: AppData/Local/Temp -> 'temp' estaria en el blacklist).

    Logica (en orden de prioridad):
    1. Archivos .tar.gz / .zip / .tar anidados -> omitir
    2. Dotfiles de entorno de shell -> omitir
    3. Cualquier segmento de directorio en CRITICAL_BLACKLIST -> omitir
    4. Archivos .sql / .sql.gz -> SIEMPRE incluir (bases de datos)
    5. Cualquier segmento de directorio en CRITICAL_WHITELIST -> incluir
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

    # Calcular los segmentos de DIRECTORIO sobre la ruta relativa.
    # Si base_dir no se proporciona usamos la ruta completa (menos segura).
    if base_dir:
        try:
            rel = fp.relative_to(base_dir)
            dir_parts = {p.lower() for p in rel.parts[:-1]}  # excluir nombre de archivo
        except ValueError:
            # Fallback: ruta no esta bajo base_dir
            dir_parts = {p.lower() for p in fp.parts[:-1]}
    else:
        dir_parts = {p.lower() for p in fp.parts[:-1]}

    # Directorios de sistema -> omitir (mayor prioridad)
    if dir_parts & CRITICAL_BLACKLIST:
        return False

    # Dumps SQL -> siempre incluir independientemente de la carpeta
    if suffix == ".sql" or name_lower.endswith(".sql.gz"):
        return True

    # Directorios de contenido restaurable -> incluir
    if dir_parts & CRITICAL_WHITELIST:
        return True

    return False


def filter_files(file_paths: list, critical_only: bool = False, base_dir: str = None) -> tuple:
    """
    Filtra la lista de archivos segun el modo critico.

    Args:
        file_paths:   lista de rutas absolutas recopiladas por el engine
        critical_only: si True aplica el filtro whitelist/blacklist
        base_dir:     directorio raiz de extraccion — pasar siempre para filtrado correcto

    Returns:
        (files_to_scan, omitted_count)
    """
    if not critical_only:
        return file_paths, 0

    included = []
    omitted = 0
    for fp in file_paths:
        if is_critical_path(fp, base_dir=base_dir):
            included.append(fp)
        else:
            omitted += 1
    return included, omitted
