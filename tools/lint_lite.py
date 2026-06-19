#!/usr/bin/env python3
"""lint_lite — linter offline basado en AST (sustituto sin red de ruff/pyflakes).

Detecta hallazgos de alta senal sin dependencias externas:
  F401 import sin usar        (omitido en __init__.py y si esta en __all__)
  F403 star import
  E722 except desnudo
  B006 default mutable en argumento
  E711 comparacion con None usando == / !=
  F601 clave duplicada en dict literal

Uso:
  python tools/lint_lite.py [ruta ...]      (por defecto: src)
Salida: una linea por hallazgo "archivo:linea: CODIGO mensaje". Exit 1 si hay
hallazgos de severidad ERROR (F601), 0 en caso contrario. Los WARNING no fallan
el exit por defecto; usar --strict para que cualquier hallazgo retorne 1.
"""
from __future__ import annotations
import ast
import sys
from pathlib import Path

BUILTINS = set(dir(__builtins__)) | {"__file__", "__name__", "__doc__"}
ERROR_CODES = {"F601"}


def _imported_names(tree: ast.AST):
    """Mapea nombre_local -> nodo import para detectar uso posterior."""
    names = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                local = (a.asname or a.name).split(".")[0]
                names[local] = node
        elif isinstance(node, ast.ImportFrom):
            if any(a.name == "*" for a in node.names):
                continue
            for a in node.names:
                names[a.asname or a.name] = node
    return names


def _used_names(tree: ast.AST):
    used = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            used.add(node.id)
        elif isinstance(node, ast.Attribute):
            base = node
            while isinstance(base, ast.Attribute):
                base = base.value
            if isinstance(base, ast.Name):
                used.add(base.id)
    return used


def _dunder_all(tree: ast.AST):
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == "__all__":
                    if isinstance(node.value, (ast.List, ast.Tuple)):
                        for e in node.value.elts:
                            if isinstance(e, ast.Constant) and isinstance(e.value, str):
                                out.add(e.value)
    return out


def check_file(path: Path):
    findings = []
    try:
        src = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        src = path.read_text(encoding="latin-1")
    try:
        tree = ast.parse(src, filename=str(path))
    except SyntaxError as e:
        return [(e.lineno or 0, "E999", f"syntax: {e.msg}")]

    is_init = path.name == "__init__.py"
    exported = _dunder_all(tree)

    # F401 / F403
    if not is_init:
        used = _used_names(tree)
        for local, node in _imported_names(tree).items():
            if local in used or local in exported:
                continue
            findings.append((node.lineno, "F401", f"import sin usar: '{local}'"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and any(a.name == "*" for a in node.names):
            findings.append((node.lineno, "F403", f"star import de '{node.module}'"))

    # E722 except desnudo
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            findings.append((node.lineno, "E722", "except desnudo (usar except Exception)"))

    # B006 defaults mutables
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for d in list(node.args.defaults) + list(node.args.kw_defaults):
                if isinstance(d, (ast.List, ast.Dict, ast.Set)):
                    findings.append((d.lineno, "B006", "default mutable en argumento"))
                elif isinstance(d, ast.Call) and isinstance(d.func, ast.Name) and d.func.id in {"list", "dict", "set"}:
                    findings.append((d.lineno, "B006", f"default mutable {d.func.id}()"))

    # E711 comparacion con None
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            for op, comp in zip(node.ops, node.comparators):
                if isinstance(op, (ast.Eq, ast.NotEq)) and isinstance(comp, ast.Constant) and comp.value is None:
                    findings.append((node.lineno, "E711", "comparacion con None: usar 'is'/'is not'"))

    # F601 claves duplicadas en dict
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            seen = set()
            for k in node.keys:
                if isinstance(k, ast.Constant):
                    if k.value in seen:
                        findings.append((k.lineno, "F601", f"clave duplicada en dict: {k.value!r}"))
                    seen.add(k.value)

    return findings


def main(argv):
    strict = "--strict" in argv
    args = [a for a in argv if not a.startswith("--")]
    roots = [Path(a) for a in args] or [Path("src")]
    files = []
    for r in roots:
        files.extend(sorted(r.rglob("*.py")) if r.is_dir() else [r])
    total = 0
    has_error = False
    for f in files:
        for line, code, msg in sorted(check_file(f)):
            print(f"{f}:{line}: {code} {msg}")
            total += 1
            if code in ERROR_CODES:
                has_error = True
    print(f"\nlint_lite: {total} hallazgo(s) en {len(files)} archivo(s)")
    return 1 if (has_error or (strict and total)) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
