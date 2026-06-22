"""Suite de pruebas cPacleanS — unittest, sin red, contra corpus determinista.

Reconstruida v3.1.2. La copia previa no quedaba persistida en disco: el archivo
contenia firmas crudas (codigo de webshell literal) que el antivirus del equipo
cuarentena al escribir. Por eso este archivo NO almacena firmas crudas; reutiliza
exclusivamente el corpus (tests/fixtures/build_corpus.py), que ensambla los
payloads inertes desde base64 en tiempo de ejecucion. Cobertura:
  - validez del corpus (control limpio / infectado),
  - deteccion de las muestras inertes (PHP y .htaccess) por el scanner,
  - is_php_functional (stub vs codigo ejecutable, ambos benignos),
  - cero falsos positivos a nivel scanner y motor,
  - integracion scan->clean con integridad por hash en NORMAL e INTERMEDIO,
  - eficacia: ESTRICTO elimina las 5 muestras inertes.

Los scanners de BD/CMS/Email/YARA quedan fuera (cobertura aparte). El motor se
ejercita con PHPScanner, que cubre las 5 muestras de forma determinista.
"""
from __future__ import annotations
import hashlib
import os
import shutil
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.core.engine import ScanEngine, CONFIRMED_MALWARE_CATEGORIES  # noqa: E402
from src.config.settings import (  # noqa: E402
    CLEAN_MODE_NORMAL, CLEAN_MODE_INTERMEDIATE, CLEAN_MODE_STRICT,
)
from src.scanners.php_scanner import PHPScanner, is_php_functional  # noqa: E402
from tests.fixtures import build_corpus  # noqa: E402

LEGIT = build_corpus.MANIFEST["legit"]
MALWARE = build_corpus.MANIFEST["malware_confirmed"]

# PHP benigno pero con codigo ejecutable real (sin firmas que dispare el AV).
_FUNCTIONAL_PHP = ('<?php $a = 1; echo $a;', '<?php function f() { return 1; }')
_STUB_PHP = ('<?php\n// silence is golden\n', '<?php ?>', '<?php /* solo doc */ ?>')


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _arc(extract_dir: str, arcname: str) -> str:
    return os.path.join(extract_dir, *arcname.split("/"))


def _pick(arcs, suffix: str) -> str:
    return next(a for a in arcs if a.endswith(suffix))


def _extract(tar_path: str, dest: str) -> None:
    with tarfile.open(tar_path, "r:gz") as t:
        try:
            t.extractall(dest, filter="data")
        except TypeError:
            t.extractall(dest)


def _build_extract(kind: str):
    """kind in {'clean','infected'} -> (extract_dir, tmp_root). tmp_root limpiable."""
    tmp = tempfile.mkdtemp(prefix=f"cps_{kind}_")
    corp = os.path.join(tmp, "corp")
    os.makedirs(corp, exist_ok=True)
    builder = (build_corpus.build_clean_backup if kind == "clean"
               else build_corpus.build_infected_backup)
    tar = builder(corp)
    ext = os.path.join(tmp, "extract")
    os.makedirs(ext, exist_ok=True)
    _extract(tar, ext)
    return ext, tmp


def _scan(extract_dir: str):
    eng = ScanEngine()
    eng.register_scanner_class(PHPScanner)
    res = eng.scan_directory(extract_dir)
    return eng, res


class CorpusTests(unittest.TestCase):
    def test_clean_corpus_has_8_legit_no_malware(self):
        ext, tmp = _build_extract("clean")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        self.assertEqual(len(LEGIT), 8)
        for arc in LEGIT:
            self.assertTrue(os.path.exists(_arc(ext, arc)), arc)
        for arc in MALWARE:
            self.assertFalse(os.path.exists(_arc(ext, arc)), arc)

    def test_infected_corpus_has_legit_and_5_malware(self):
        ext, tmp = _build_extract("infected")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        self.assertEqual(len(MALWARE), 5)
        for arc in LEGIT + MALWARE:
            self.assertTrue(os.path.exists(_arc(ext, arc)), arc)


class ScannerPatternTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ext, cls.tmp = _build_extract("infected")
        cls.scanner = PHPScanner()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _scan_one(self, suffix: str):
        return self.scanner.scan(_arc(self.ext, _pick(MALWARE, suffix)))

    def test_detect_root_php_sample(self):
        f = self._scan_one("/shell.php")
        self.assertTrue(f)
        self.assertTrue(any(x.category in CONFIRMED_MALWARE_CATEGORIES for x in f))

    def test_detect_indirection_php_sample(self):
        f = self._scan_one("/wp-config-backup.php")
        self.assertTrue(f)

    def test_detect_double_extension_sample(self):
        f = self._scan_one("/image.jpg.php")
        self.assertTrue(f)

    def test_detect_htaccess_sample(self):
        f = self._scan_one("uploads/.htaccess")
        self.assertTrue(f)

    def test_legit_files_no_findings(self):
        for arc in LEGIT:
            self.assertEqual(self.scanner.scan(_arc(self.ext, arc)), [], arc)


class PhpFunctionalTests(unittest.TestCase):
    def test_executable_is_functional(self):
        for snippet in _FUNCTIONAL_PHP:
            self.assertTrue(is_php_functional(snippet), snippet)

    def test_stub_is_not_functional(self):
        for snippet in _STUB_PHP:
            self.assertFalse(is_php_functional(snippet), snippet)


class EngineIntegrationTests(unittest.TestCase):
    def test_control_zero_findings_zero_confirmed(self):
        ext, tmp = _build_extract("clean")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        _eng, res = _scan(ext)
        self.assertEqual(res.total_threats_found, 0)
        self.assertEqual(sum(1 for f in res.findings if f.confirmed_malware), 0)

    def test_infected_five_detected_zero_legit_confirmed(self):
        ext, tmp = _build_extract("infected")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        _eng, res = _scan(ext)
        detected = {f.file_path for f in res.findings}
        for arc in MALWARE:
            self.assertIn(_arc(ext, arc), detected, arc)
        legit_paths = {_arc(ext, a) for a in LEGIT}
        confirmed_legit = [f.file_path for f in res.findings
                           if f.confirmed_malware and f.file_path in legit_paths]
        self.assertEqual(confirmed_legit, [])


class IntegrityTests(unittest.TestCase):
    def _setup_infected(self):
        ext, tmp = _build_extract("infected")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        qbase = os.path.join(tmp, "quarantine")
        os.makedirs(qbase, exist_ok=True)
        before = {a: _sha256(_arc(ext, a)) for a in LEGIT}
        eng, _res = _scan(ext)
        return ext, qbase, before, eng

    def _assert_legit_unchanged(self, ext, before):
        for arc, h in before.items():
            path = _arc(ext, arc)
            self.assertTrue(os.path.exists(path), arc)
            self.assertEqual(_sha256(path), h, arc)

    def test_integrity_normal(self):
        ext, qbase, before, eng = self._setup_infected()
        eng.clean_findings(qbase, mode=CLEAN_MODE_NORMAL)
        self._assert_legit_unchanged(ext, before)
        self.assertFalse(os.path.exists(_arc(ext, _pick(MALWARE, "/image.jpg.php"))))
        self.assertTrue(os.path.exists(_arc(ext, _pick(MALWARE, "/shell.php"))))

    def test_integrity_intermediate(self):
        ext, qbase, before, eng = self._setup_infected()
        eng.clean_findings(qbase, mode=CLEAN_MODE_INTERMEDIATE)
        self._assert_legit_unchanged(ext, before)
        self.assertFalse(os.path.exists(_arc(ext, _pick(MALWARE, "/shell.php"))))

    def test_strict_removes_all_malware_keeps_legit(self):
        ext, qbase, before, eng = self._setup_infected()
        eng.clean_findings(qbase, mode=CLEAN_MODE_STRICT)
        self._assert_legit_unchanged(ext, before)
        for arc in MALWARE:
            self.assertFalse(os.path.exists(_arc(ext, arc)), arc)


if __name__ == "__main__":
    unittest.main(verbosity=2)
