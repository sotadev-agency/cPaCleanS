"""Parser de serializacion PHP para campos de BD (active_plugins, config)."""
import re


def unserialize_php(data: str) -> list:
    """Deserializa un string serializado PHP y extrae valores string.

    Soporta formato: a:N:{i:0;s:19:"plugin/plugin.php";...}
    Usa phpserialize (pip) si esta disponible, fallback a regex.
    """
    try:
        import phpserialize
        raw = phpserialize.loads(data.encode("utf-8"), decode_strings=True)
        if isinstance(raw, dict):
            return list(raw.values())
        if isinstance(raw, (list, tuple)):
            return list(raw)
        return [raw] if isinstance(raw, str) else []
    except Exception:
        pass
    return _regex_unserialize(data)


def _regex_unserialize(data: str) -> list:
    """Fallback regex para extraer strings de serializacion PHP."""
    results = []
    for m in re.finditer(r's:(\d+):"((?:[^"\\]|\\.)*)";', data):
        length = int(m.group(1))
        value = m.group(2)
        if abs(len(value) - length) <= 2:
            results.append(value)
    return results


def extract_active_plugins_wp(serialized: str) -> set:
    """Extrae slugs de plugins activos de WordPress desde campo serializado.

    WordPress almacena active_plugins como:
    a:3:{i:0;s:19:"akismet/akismet.php";i:1;s:33:"classic-editor/classic-editor.php";...}
    """
    values = unserialize_php(serialized)
    plugins = set()
    for v in values:
        if isinstance(v, str) and "/" in v:
            slug = v.split("/")[0]
            if slug:
                plugins.add(slug)
    return plugins
