"""Utilidades para lectura de dumps SQL y deteccion de prefijos de tablas."""
import re
import gzip
import bz2
from pathlib import Path
from typing import Iterator, Optional


def iter_sql_lines(file_path: str) -> Iterator[str]:
    """Iterador streaming de lineas SQL — soporta .sql, .sql.gz, .sql.bz2."""
    fp = Path(file_path)
    name = fp.name.lower()

    if name.endswith(".bz2"):
        with bz2.open(str(fp), "rt", encoding="utf-8", errors="replace") as f:
            yield from f
    elif name.endswith(".gz"):
        with gzip.open(str(fp), "rt", encoding="utf-8", errors="replace") as f:
            yield from f
    else:
        with open(str(fp), "r", encoding="utf-8", errors="replace") as f:
            yield from f


def detect_prefix_from_config(cms: str, cms_root: str) -> Optional[str]:
    """Detecta el prefijo de tablas leyendo el archivo de config del CMS."""
    root = Path(cms_root)

    if cms == "wordpress":
        config = root / "wp-config.php"
        if config.exists():
            try:
                content = config.read_text(encoding="utf-8", errors="replace")
                m = re.search(r"\$table_prefix\s*=\s*['\"]([^'\"]+)['\"]", content)
                if m:
                    return m.group(1)
            except OSError:
                pass
        return "wp_"

    elif cms == "joomla":
        config = root / "configuration.php"
        if config.exists():
            try:
                content = config.read_text(encoding="utf-8", errors="replace")
                m = re.search(r"\$dbprefix\s*=\s*['\"]([^'\"]+)['\"]", content)
                if m:
                    return m.group(1)
            except OSError:
                pass
        return "jos_"

    elif cms == "moodle":
        config = root / "config.php"
        if config.exists():
            try:
                content = config.read_text(encoding="utf-8", errors="replace")
                m = re.search(r"\$CFG->prefix\s*=\s*['\"]([^'\"]+)['\"]", content)
                if m:
                    return m.group(1)
            except OSError:
                pass
        return "mdl_"

    elif cms == "ojs":
        config = root / "config.inc.php"
        if config.exists():
            try:
                content = config.read_text(encoding="utf-8", errors="replace")
                m = re.search(r"table_name_prefix\s*=\s*(\S+)", content)
                if m and m.group(1):
                    return m.group(1)
            except OSError:
                pass
        return "ojs_"

    return None


def detect_prefix_from_dump(sql_path: str, cms: str) -> Optional[str]:
    """Fallback: escanea dump SQL para inferir prefijo por patron CREATE TABLE."""
    known_tables = {
        "wordpress": ["options", "posts", "users", "postmeta"],
        "joomla": ["extensions", "session", "users", "content"],
        "moodle": ["config", "user", "course"],
        "ojs": ["users", "journals", "submissions"],
    }

    targets = known_tables.get(cms, [])
    if not targets:
        return None

    alternatives = "|".join(re.escape(t) for t in targets)
    pattern = re.compile(
        rf"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?`?(\w*?)({alternatives})`?\s",
        re.IGNORECASE,
    )

    lines_checked = 0
    try:
        for line in iter_sql_lines(sql_path):
            lines_checked += 1
            if lines_checked > 50000:
                break
            m = pattern.search(line)
            if m:
                return m.group(1)
    except (OSError, PermissionError):
        pass

    return None


def read_active_from_dump(sql_path: str, cms: str, prefix: str) -> dict:
    """Lee plugins/temas activos desde un dump SQL segun el CMS.

    Retorna dict con keys: 'plugins' (set), 'theme' (str),
    'templates' (set), 'components' (set).
    """
    result = {
        "plugins": set(),
        "theme": "",
        "templates": set(),
        "components": set(),
    }

    try:
        for line in iter_sql_lines(sql_path):
            if len(line) > 2_000_000:
                continue
            if cms == "wordpress":
                _parse_wp_active(line, prefix, result)
            elif cms == "joomla":
                _parse_joomla_active(line, prefix, result)
            elif cms == "moodle":
                _parse_moodle_active(line, prefix, result)
            elif cms == "ojs":
                _parse_ojs_active(line, prefix, result)
    except (OSError, PermissionError):
        pass

    return result


def _parse_wp_active(line: str, prefix: str, result: dict):
    from .php_serializer import extract_active_plugins_wp

    table = f"{prefix}options"
    if table not in line:
        return

    if "active_plugins" in line:
        m = re.search(r"'active_plugins'\s*,\s*'(a:\d+:\{.*?\})'", line)
        if not m:
            m = re.search(r"active_plugins.*?(a:\d+:\{[^}]*(?:\{[^}]*\}[^}]*)*\})", line)
        if m:
            result["plugins"].update(extract_active_plugins_wp(m.group(1)))

    for key in ("stylesheet", "template"):
        if f"'{key}'" in line:
            m = re.search(rf"'{key}'\s*,\s*'([^']+)'", line)
            if m and not result["theme"]:
                result["theme"] = m.group(1)


def _parse_joomla_active(line: str, prefix: str, result: dict):
    table = f"{prefix}extensions"
    if table not in line:
        return

    for m in re.finditer(
        r"'(plugin|template|component|module)'\s*,\s*'([^']+)'", line
    ):
        ext_type = m.group(1)
        ext_name = m.group(2)
        if ext_type == "plugin":
            result["plugins"].add(ext_name)
        elif ext_type == "template":
            result["templates"].add(ext_name)
        elif ext_type == "component":
            result["components"].add(ext_name)


def _parse_moodle_active(line: str, prefix: str, result: dict):
    config_plugins_table = f"{prefix}config_plugins"
    config_table = f"{prefix}config"

    if config_plugins_table in line:
        for m in re.finditer(r"'(\w+)'\s*,\s*'version'\s*,\s*'(\d+)'", line):
            result["plugins"].add(m.group(1))
    elif config_table in line and "theme" in line:
        m = re.search(r"'theme'\s*,\s*'([^']+)'", line)
        if m:
            result["theme"] = m.group(1)


def _parse_ojs_active(line: str, prefix: str, result: dict):
    table = f"{prefix}plugin_settings"
    if table not in line:
        return

    if "enabled" in line:
        for m in re.finditer(
            r"'([^']+)'\s*,\s*'([^']+)'\s*,\s*'enabled'\s*,\s*'1'", line
        ):
            result["plugins"].add(f"{m.group(1)}/{m.group(2)}")
