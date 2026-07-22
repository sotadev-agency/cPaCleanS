"""Pruebas del EmailScanner: gating is_email y deteccion de correo.

Regresion del falso positivo: una ruta con el substring '/tmp/' (raiz de
extraccion o carpeta tmp/ del propio sitio) hacia que TODO PHP se tratara como
correo y cada '<?php' se marcara reinfection_risk. Ahora solo se trata como
correo lo que esta bajo un arbol de correo real (mail/ o maildir/).
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.scanners.email_scanner import EmailScanner  # noqa: E402


class TestEmailScannerGating(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="emltest_"))

    def _write(self, relpath, content):
        p = self.tmp / relpath
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return str(p)

    def test_php_bajo_tmp_no_es_correo(self):
        # PHP benigno del sitio bajo una carpeta 'tmp' NO debe generar hallazgos
        # de correo (reinfection_risk "Codigo PHP embebido en correo").
        fp = self._write("wp-content/cache/tmp/tpl.php", "<?php _e('Hola mundo'); ?>")
        cats = [f.category for f in EmailScanner().scan(fp)]
        self.assertNotIn("reinfection_risk", cats)

    def test_eml_con_adjunto_peligroso_se_detecta(self):
        # El escaneo de correo real (.eml) debe seguir detectando adjuntos peligrosos.
        eml = (
            "From: a@evil.test\r\n"
            "Subject: factura\r\n"
            "Content-Type: multipart/mixed; boundary=b\r\n\r\n"
            "--b\r\n"
            "Content-Disposition: attachment; filename=\"invoice.exe\"\r\n\r\n"
            "MZ...\r\n"
            "--b--\r\n"
        )
        fp = self._write("mensaje.eml", eml)
        cats = [f.category for f in EmailScanner().scan(fp)]
        self.assertIn("malicious_attachment", cats)

    def test_php_embebido_en_correo_cpanel_si_es_sospechoso(self):
        # PHP dentro de un mensaje bajo homedir/mail/ (Maildir) SI debe marcarse.
        fp = self._write(
            "homedir/mail/example.com/user/cur/1700000000.msg",
            "From: x@y.test\r\nSubject: hi\r\n\r\n<?php echo 1; ?>\r\n",
        )
        cats = [f.category for f in EmailScanner().scan(fp)]
        self.assertIn("reinfection_risk", cats)


if __name__ == "__main__":
    unittest.main()
