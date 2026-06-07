"""Configuracion global de cPacleanS."""
import os
import json
import multiprocessing
from pathlib import Path

APP_NAME = "cPacleanS"
APP_VERSION = "2.6.1"

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

# Slugs de plugins/temas WP de confianza — findings dentro de estos directorios
# se reducen a severity "info" salvo categorias de malware confirmado.
WP_TRUSTED_SLUGS = frozenset({
    # Seguridad
    "wordfence", "sucuri-scanner", "ithemes-security-pro",
    "better-wp-security", "all-in-one-wp-security-and-firewall",
    "defender-security", "cerber-security", "security-ninja",
    "shield-security", "secupress",
    # Page builders
    "elementor", "elementor-pro", "js_composer", "wpbakery",
    "divi-builder", "beaver-builder-lite-version", "brizy",
    "fusion-builder", "tatsu",
    # SEO
    "wordpress-seo", "all-in-one-seo-pack", "rank-math-seo",
    "the-seo-framework",
    # E-commerce
    "woocommerce", "woocommerce-payments",
    "woocommerce-gateway-stripe",
    "woocommerce-gateway-paypal-express-checkout",
    "easy-digital-downloads",
    # Forms
    "contact-form-7", "wpforms-lite", "ninja-forms",
    "gravityforms", "formidable", "forminator",
    # Cache / Performance
    "wp-super-cache", "w3-total-cache", "litespeed-cache",
    "wp-fastest-cache", "autoptimize", "wp-rocket",
    "sg-cachepress", "breeze",
    # Backup / Migration
    "updraftplus", "duplicator", "all-in-one-wp-migration",
    "wp-migrate-db", "backwpup",
    # Analytics
    "google-analytics-for-wordpress", "google-site-kit",
    "monsterinsights",
    # Email
    "wp-mail-smtp", "mailchimp-for-wp", "newsletter",
    # Core utilities
    "jetpack", "akismet", "really-simple-ssl",
    "classic-editor", "gutenberg",
    "advanced-custom-fields", "duplicate-post",
    "regenerate-thumbnails", "tablepress",
    "tinymce-advanced", "redirection",
    # Media
    "wp-smushit", "imagify", "shortpixel-image-optimiser",
    "ewww-image-optimizer",
})

# Hashes SHA256 de archivos core de plugins/temas WP conocidos.
# Archivos con hash coincidente se omiten del reporte.
# Poblar con hashes de versiones estables via config externo.
WP_WHITELIST_HASHES = {}

# Firmas en .htaccess generadas por plugins de cache — no son maliciosas.
CACHE_HTACCESS_SIGNATURES = (
    "WP Super Cache", "W3 Total Cache", "LiteSpeed Cache",
    "WP Fastest Cache", "# BEGIN W3TC", "# BEGIN WPSuperCache",
    "# BEGIN LiteSpeedCache", "# BEGIN GzipWPFC",
)

# Dominios de email de confianza — se requieren 2+ indicadores
# de phishing para reportar cuando el remitente coincide.
TRUSTED_EMAIL_DOMAINS = frozenset({
    "paypal.com", "amazon.com", "github.com", "aws.amazon.com",
    "google.com", "microsoft.com", "apple.com", "netflix.com",
    "linkedin.com", "dropbox.com", "stripe.com", "cloudflare.com",
})

# ── v2.6.0: Spam post scoring ──
SPAM_SCORE_THRESHOLD = 65

SPAM_KEYWORDS = {
    "gambling": [
        "casino", "bet", "poker", "blackjack", "slot", "tragamoneda",
        "apuesta", "baccarat", "ruleta", "roulette", "sportsbook",
        "sports betting", "online gambling", "juegos de azar",
    ],
    "crypto_spam": [
        "bitcoin", "ethereum", "crypto", "forex", "trading signal",
        "investment opportunity", "get rich", "passive income",
        "señales de trading", "invertir en crypto",
    ],
    "pharma": [
        "viagra", "cialis", "levitra", "pharmacy", "farmacia online",
        "medicamento sin receta", "comprar online", "buy cheap",
        "generic pills",
    ],
    "piracy": [
        "crack", "keygen", "activator", "serial key", "license key free",
        "patch download", "software gratis", "nulled", "warez",
    ],
    "adult": [
        "xxx", "porn", "nude", "escort", "cam girl", "adult dating",
        "sexo", "videos adultos",
    ],
}

# ── v2.6.0: Junk categories (reglas para JunkCleaner) ──
JUNK_CATEGORIES = {
    "orphan_php_uploads": {"remove_policy": "always"},
    "injected_index_php": {"remove_policy": "always"},
    "log_file": {"remove_policy": "by_mode"},
    "orphan_txt": {"remove_policy": "by_mode"},
    "broken_image": {"remove_policy": "by_mode"},
}

# ── v2.6.0: Homedir exclude dirs for critical packaging ──
HOMEDIR_EXCLUDE_DIRS = frozenset({
    "backups", "tmp", ".trash", "perl5", "virtfs",
    ".cagefs", "cpanel3-skel",
})

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
    "confidence_threshold": 70,
    "excluded_dirs": ["vendor", "node_modules", ".git", "tests", "test", "phpunit"],
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
