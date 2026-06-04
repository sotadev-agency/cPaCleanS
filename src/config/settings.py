"""Configuracion global de cPacleanS."""
import os
import json
import multiprocessing
from pathlib import Path

APP_NAME = "cPacleanS"
APP_VERSION = "2.3.0"

# Directorios de cPanel que WHM necesita para restaurar dominios correctamente.
# Nunca deben ser cuarentenados aunque contengan patrones sospechosos.
CPANEL_PROTECTED_DIRS = frozenset({
    "etc",       # Configuracion de usuario: quota, subdominios, parked domains
    "userdata",  # Config virtual hosts de TODOS los dominios (critico para addon domains)
    "dns",       # Zonas DNS del usuario
    "cp",        # Datos del panel cPanel del usuario
})

# Archivos raiz de WordPress que son CORE (no archivos del usuario).
# Usados en el rebuild completo para saber que eliminar y reinstalar.
WP_CORE_ROOT_FILES = frozenset({
    "index.php", "wp-activate.php", "wp-blog-header.php",
    "wp-comments-post.php", "wp-cron.php", "wp-links-opml.php",
    "wp-load.php", "wp-login.php", "wp-mail.php", "wp-settings.php",
    "wp-signup.php", "wp-trackback.php", "xmlrpc.php",
})

# Tablas protegidas por CMS — NUNCA eliminar la tabla completa.
# Solo se eliminan FILAS especificas con severidad CRITICA CONFIRMADA.
CMS_PROTECTED_TABLES = {
    "wordpress": [
        "options", "users", "usermeta", "posts", "postmeta",
        "terms", "term_taxonomy", "term_relationships",
        "comments", "commentmeta", "links",
    ],
    "joomla": [
        "users", "session", "extensions", "menu", "modules",
        "content", "categories", "assets",
    ],
    "moodle": [
        "config", "config_plugins", "user", "course",
        "course_modules", "role", "role_assignments",
    ],
    "ojs": [
        "users", "journals", "publications", "submissions",
        "plugin_settings",
    ],
}

# Marcadores para validar deteccion de CMS (requiere AMBOS: archivo + directorio)
CMS_DETECTION_MARKERS = {
    "wordpress": {"file": "wp-config.php", "dir": "wp-includes"},
    "joomla":    {"file": "configuration.php", "dir": "administrator"},
    "moodle":    {"file": "config.php", "dir": "lib", "extra_file": "lib/moodlelib.php"},
    "ojs":       {"file": "config.inc.php", "dir": "lib", "extra_dir": "lib/pkp"},
}

SCAN_MODE_ONLY = "scan_only"
CLEAN_MODE_NORMAL = "normal"
CLEAN_MODE_INTERMEDIATE = "intermediate"
CLEAN_MODE_STRICT = "strict"

DEFAULT_CONFIG = {
    "virustotal_api_key": "",
    "max_file_size_mb": 50,
    "critical_only": False,
    "scan_workers": max(1, multiprocessing.cpu_count() - 1),
    "auto_clean": False,
    "quarantine_enabled": True,
    "restore_cms_core": True,
    "generate_targz": False,
    "output_dir": "",
    "clean_mode": CLEAN_MODE_NORMAL,
    "scan_extensions": {
        "php": [".php", ".php5", ".php7", ".phtml", ".phar"],
        "web": [".html", ".htm", ".js", ".css", ".svg"],
        "database": [".sql", ".sql.gz", ".sql.bz2"],
        "email": [".eml", ".mbox"],
        "config": [".htaccess", ".ini", ".conf", ".env", ".json", ".xml", ".yml", ".yaml"],
        "script": [".sh", ".bash", ".cgi", ".pl", ".py"],
    },
    "cms_patterns": {
        "wordpress": ["wp-config.php", "wp-content", "wp-includes"],
        "joomla": ["configuration.php", "components", "modules"],
        "moodle": ["config.php", "mod", "lib/moodlelib.php"],
        "laravel": ["artisan", "app/Http", ".env"],
        "softaculous": ["softaculous", "ACPLsoft"],
        "ojs": ["config.TEMPLATE.inc.php"],
    },
    "severity_levels": {
        "critical": {"color": "#FF0000", "label": "Critico"},
        "high": {"color": "#FF6600", "label": "Alto"},
        "medium": {"color": "#FFAA00", "label": "Medio"},
        "low": {"color": "#FFDD00", "label": "Bajo"},
        "info": {"color": "#0088FF", "label": "Info"},
    },
}

CONFIG_DIR = Path(os.environ.get("APPDATA", Path.home())) / "cPacleanS"
CONFIG_FILE = CONFIG_DIR / "config.json"


def load_config():
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                user_cfg = json.load(f)
            merged = {**DEFAULT_CONFIG, **user_cfg}
            return merged
        except (json.JSONDecodeError, OSError):
            pass
    return DEFAULT_CONFIG.copy()


def save_config(config):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
