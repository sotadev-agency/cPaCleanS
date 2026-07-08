"""Pruebas de deteccion heuristica (v3.1.5): desofuscacion (decode-and-rescan),
pase multilinea y decodificacion de partes de correo.

Sin firmas crudas en este archivo: los payloads se toman del corpus (que los
ensambla desde base64 en tiempo de ejecucion) o se re-codifican aqui, para no ser
cuarentenados por el antivirus del host. Incluye un caso benigno que prueba que
la desofuscacion NO genera falsos positivos.
"""
from __future__ import annotations
import base64
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.scanners.php_scanner import PHPScanner  # noqa: E402
from src.scanners.email_scanner import EmailScanner  # noqa: E402
from tests.fixtures import build_corpus  # noqa: E402


def _write(dirpath, name, data: bytes) -> str:
    p = Path(dirpath) / name
    p.write_bytes(data)
    return str(p)


class TestHeuristicDetection(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="deob_")

    def test_payload_anidado_base64_se_detecta(self):
        # backdoor_var del corpus lleva un ejecutor de comando en un base64 interno;
        # la desofuscacion debe revelarlo aunque el fuente solo muestre el blob.
        data = build_corpus._content("backdoor_var")
        fp = _write(self.tmp, "sample.php", data)
        findings = PHPScanner().scan(fp)
        self.assertTrue(
            any(getattr(f, "matched_pattern", "") == "deobfuscated" for f in findings),
            "El payload en base64 interno deberia detectarse tras desofuscar",
        )

    def test_ejecucion_partida_en_lineas_se_detecta(self):
        # El mismo webshell del corpus pero con saltos de linea insertados: evade el
        # pase linea-a-linea; el pase multilinea (sobre todo el contenido) lo captura.
        one_line = build_corpus._content("webshell_eval")
        split = one_line.replace(b"(", b"(\n")
        fp = _write(self.tmp, "split.php", split)
        findings = PHPScanner().scan(fp)
        self.assertTrue(
            any(getattr(f, "matched_pattern", "") == "multiline" for f in findings),
            "La ejecucion partida en varias lineas deberia detectarse",
        )

    def test_base64_benigno_no_genera_falso_positivo(self):
        # Un blob base64 benigno (texto normal) NO debe producir hallazgos de
        # ejecucion, aunque el archivo use el decodificador.
        benign_b64 = base64.b64encode(
            b"hello world, this is a perfectly fine and boring string"
        ).decode()
        php = ("<?php $x = base64_dec" + "ode(\"" + benign_b64 + "\"); echo $x; ?>").encode()
        fp = _write(self.tmp, "benign.php", php)
        findings = PHPScanner().scan(fp)
        bad = [
            f for f in findings
            if f.category in ("webshell", "backdoor")
            or getattr(f, "matched_pattern", "") in ("deobfuscated", "multiline")
        ]
        self.assertEqual(bad, [], f"Base64 benigno no debe marcarse: {[f.description for f in bad]}")

    def test_correo_con_parte_base64_php_se_detecta(self):
        # Parte MIME base64 que decodifica a un webshell PHP: debe marcarse aunque el
        # cuerpo del correo solo contenga base64 (el pase linea-a-linea no lo veria).
        php = build_corpus._content("webshell_system")
        b64 = base64.b64encode(php).decode()
        eml = (
            "From: a@evil.test\r\n"
            "Subject: nota\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Transfer-Encoding: base64\r\n\r\n"
            + b64 + "\r\n"
        ).encode()
        fp = _write(self.tmp, "mail.eml", eml)
        cats = [f.category for f in EmailScanner().scan(fp)]
        self.assertIn(
            "reinfection_risk", cats,
            "El PHP oculto en la parte base64 del correo deberia detectarse",
        )


if __name__ == "__main__":
    unittest.main()
