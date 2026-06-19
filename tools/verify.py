#!/usr/bin/env python3
"""verify — verificacion local reproducible de cPacleanS (sin red).

Ejecuta en orden y resume PASS/FAIL:
  1. compileall src            (sintaxis)
  2. import de modulos no-GUI  (errores de import)
  3. tools/lint_lite.py src    (lint offline)
  4. unittest discover tests   (unit + integracion + integridad)

La suite es obligatoria: si tests/ no existe o se descubren 0 pruebas, FALLA
(evita el falso verde por suite ausente o corrupta).

Uso: python tools/verify.py
Exit 0 si todo pasa; 1 si algo falla. Portable Windows/Linux.
En Windows con red, complementar con: ruff check src && pytest -q
"""
from __future__ import annotations
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable


def run(label, args):
    print(f"\n=== {label} ===")
    r = subprocess.run([PY, *args], cwd=ROOT)
    ok = r.returncode == 0
    print(f"[{'PASS' if ok else 'FAIL'}] {label}")
    return ok


def import_check():
    print("\n=== import modulos no-GUI ===")
    code = (
        "import importlib,pkgutil,sys;sys.path.insert(0,'.');import src;"
        "f=0\n"
        "for m in pkgutil.walk_packages(src.__path__,'src.'):\n"
        " n=m.name\n"
        " if n.startswith('src.gui'):continue\n"
        " try:importlib.import_module(n)\n"
        " except Exception as e:\n"
        "  f+=1;print('FAIL',n,e)\n"
        "sys.exit(1 if f else 0)"
    )
    r = subprocess.run([PY, "-c", code], cwd=ROOT)
    ok = r.returncode == 0
    print(f"[{'PASS' if ok else 'FAIL'}] import modulos no-GUI")
    return ok


def unittest_check():
    print("\n=== unittest discover tests ===")
    tests_dir = ROOT / "tests"
    if not tests_dir.is_dir():
        print("[FAIL] tests/ no existe (suite obligatoria)")
        return False
    r = subprocess.run(
        [PY, "-m", "unittest", "discover", "-s", "tests", "-v"],
        cwd=ROOT, capture_output=True, text=True,
    )
    out = (r.stdout or "") + (r.stderr or "")
    print(out.rstrip())
    m = re.search(r"Ran (\d+) test", out)
    ran = int(m.group(1)) if m else 0
    ok = (r.returncode == 0) and (ran > 0)
    if ran == 0:
        print("[FAIL] unittest: 0 pruebas descubiertas (suite ausente o corrupta)")
    print(f"[{'PASS' if ok else 'FAIL'}] unittest discover tests ({ran} pruebas)")
    return ok


def main():
    results = []
    results.append(("compileall", run("compileall src", ["-m", "compileall", "-q", "src"])))
    results.append(("import", import_check()))
    results.append(("lint_lite", run("lint_lite src", ["tools/lint_lite.py", "src"])))
    results.append(("unittest", unittest_check()))
    print("\n================ RESUMEN ================")
    allok = True
    for name, ok in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
        allok = allok and ok
    print("========================================")
    return 0 if allok else 1


if __name__ == "__main__":
    sys.exit(main())
