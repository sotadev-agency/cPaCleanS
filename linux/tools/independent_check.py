#!/usr/bin/env python3
"""independent_check - oraculo de deteccion INDEPENDIENTE del motor de cPacleanS.

Sin red, sin ClamAV (no instalable offline). Usa heuristicas propias distintas a
las del scanner para cross-check de efectividad, detecta EICAR por firma y valida
estructuralmente reglas YARA (sin binario yara).

CLI: python tools/independent_check.py <dir> [<rules.yar> ...]
"""
from __future__ import annotations
import os
import re
import sys
from pathlib import Path

EICAR_SIG = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
_EXEC = re.compile(r'\b(eval|assert|system|exec|shell_exec|passthru|popen|proc_open)\s*\(', re.I)
_TAINT = re.compile(r'\$_(POST|GET|REQUEST|COOKIE)|base64_decode|gzinflate|str_rot13', re.I)
_KNOWN = re.compile(r'\b(c99|r57|b374k|wso|FilesMan|p0wny|alfashell)\b', re.I)
_TEXT_EXT = {".php", ".php5", ".phtml", ".js", ".htaccess", ".html", ".htm", ".txt", ".inc"}


def classify(content: str) -> str:
    if EICAR_SIG in content:
        return "eicar"
    if _KNOWN.search(content):
        return "known_shell"
    if _EXEC.search(content) and _TAINT.search(content):
        return "exec+taint"
    return ""


def scan_tree(root: str) -> dict:
    flagged = {}
    for d, _, files in os.walk(root):
        for fn in files:
            p = os.path.join(d, fn)
            ext = Path(fn).suffix.lower()
            if fn.lower() == ".htaccess":
                ext = ".htaccess"
            if ext not in _TEXT_EXT:
                continue
            try:
                with open(p, "r", encoding="utf-8", errors="replace") as f:
                    c = f.read(200000)
            except OSError:
                continue
            verdict = classify(c)
            if verdict:
                flagged[p.replace("\\", "/")] = verdict
    return flagged


def validate_yara(path: str) -> dict:
    try:
        txt = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return {"file": path, "ok": False, "error": str(e)}
    rules = len(re.findall(r'^\s*rule\s+\w+', txt, re.M))
    balanced = txt.count("{") == txt.count("}")
    has_cond = "condition:" in txt
    ok = rules > 0 and balanced and has_cond
    return {"file": path, "ok": ok, "rules": rules, "balanced": balanced, "has_condition": has_cond}


if __name__ == "__main__":
    args = sys.argv[1:]
    root = args[0] if args else "."
    if len(args) > 1:
        yars = args[1:]
    elif Path("src/signatures").is_dir():
        yars = [str(p) for p in Path("src/signatures").glob("*.yar")]
    else:
        yars = []
    fl = scan_tree(root)
    print(f"INDEPENDIENTE: {len(fl)} archivo(s) marcado(s)")
    for p, v in sorted(fl.items()):
        print(f"  [{v}] {p.split('public_html', 1)[-1] if 'public_html' in p else p}")
    for y in yars:
        print("YARA", validate_yara(y))
