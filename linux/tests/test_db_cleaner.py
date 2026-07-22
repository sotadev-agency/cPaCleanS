"""Suite DBCleaner / SpamPostCleaner — v3.1.3, unittest, sin red.

Cobertura que faltaba (los cleaners de BD estaban fuera de test_suite.py):
  - parsing SQL: _split_sql_values / _split_value_tuples (comillas, comas,
    parentesis dentro de strings),
  - scoring SpamPostCleaner: post_types seguros, spam eliminado, scan_only sin
    borrar, post legitimo intacto, proteccion por comentarios, comentarios
    phishing,
  - integracion DBCleaner.process() sobre un dump WP (build_corpus.build_wp_sql_dump):
    spam/critico/usuarios/cron limpiados; filas legitimas intactas (integridad),
  - regresion del fix v3.1.3: la PRIMERA tupla de un INSERT de wp_posts ahora se
    extrae (antes "VALUES " la contaminaba y se descartaba).

Sin firmas crudas: el unico fragmento sensible (valor cron) viene en base64 desde
build_corpus; el resto es SQL/keywords benignos.
"""
from __future__ import annotations
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.cleaners.db_cleaner import DBCleaner  # noqa: E402
from src.cleaners.spam_post_cleaner import SpamPostCleaner  # noqa: E402
from src.config.settings import SCAN_MODE_ONLY, CLEAN_MODE_NORMAL  # noqa: E402
from tests.fixtures import build_corpus  # noqa: E402

EXPECT = build_corpus.SQL_DUMP_EXPECT


def _make_dump():
    tmp = tempfile.mkdtemp(prefix="cps_db_")
    p = os.path.join(tmp, "testdb.sql")
    build_corpus.build_wp_sql_dump(p)
    return tmp, p


def _cleaner(extract_dir, mode=CLEAN_MODE_NORMAL):
    return DBCleaner(extract_dir=extract_dir, cms_detected=["wordpress"],
                     prefixes={"wordpress": "wp_"}, clean_mode=mode)


class SqlParsingTests(unittest.TestCase):
    def setUp(self):
        self.d = DBCleaner.__new__(DBCleaner)

    def test_split_values_respects_quoted_commas(self):
        self.assertEqual(self.d._split_sql_values("1,'a,b','c'"),
                         ["1", "'a,b'", "'c'"])

    def test_split_values_double_quotes(self):
        self.assertEqual(self.d._split_sql_values('1,"x,y",3'),
                         ["1", '"x,y"', "3"])

    def test_split_tuples_multi_row(self):
        self.assertEqual(self.d._split_value_tuples("(1,'a'),(2,'b,c');"),
                         ["(1,'a')", "(2,'b,c')"])

    def test_split_tuples_ignores_parens_in_strings(self):
        self.assertEqual(self.d._split_value_tuples("(1,'f(x)'),(2,'y')"),
                         ["(1,'f(x)')", "(2,'y')"])


class SpamScoringTests(unittest.TestCase):
    def _post(self, **kw):
        base = dict(ID=1, post_title="t", post_content="", post_status="publish",
                    comment_status="closed", post_type="post", comment_count="0")
        base.update(kw)
        return base

    def test_safe_post_type_skipped(self):
        sc = SpamPostCleaner("wp_", CLEAN_MODE_NORMAL)
        sc.analyze_rows([self._post(ID=10, post_type="page",
                                    post_content="casino viagra pills")])
        self.assertEqual(sc.spam_log, [])

    def test_spam_post_deleted(self):
        sc = SpamPostCleaner("wp_", CLEAN_MODE_NORMAL)
        sc.analyze_rows([self._post(
            ID=12, post_content="Best online casino bonus and cheap viagra pills")])
        self.assertIn(12, sc.get_delete_ids())

    def test_scan_only_never_deletes(self):
        sc = SpamPostCleaner("wp_", SCAN_MODE_ONLY)
        sc.analyze_rows([self._post(
            ID=12, post_content="casino viagra bonus pills order now")])
        self.assertEqual(sc.get_delete_ids(), [])
        self.assertTrue(sc.spam_log)
        self.assertEqual(sc.spam_log[0]["action"], "logged_only")

    def test_legit_post_kept(self):
        sc = SpamPostCleaner("wp_", CLEAN_MODE_NORMAL)
        sc.analyze_rows([self._post(
            ID=11, post_content="Welcome to my blog about gardening and cooking")])
        self.assertEqual(sc.get_delete_ids(), [])

    def test_post_with_open_comments_not_deleted_when_moderate(self):
        # Score en [50,75) + comentarios abiertos => se preserva (no se borra).
        sc = SpamPostCleaner("wp_", CLEAN_MODE_NORMAL)
        sc.analyze_rows([self._post(
            ID=20, comment_count="3", comment_status="open",
            post_content="casino bitcoin ethereum crypto deals")])
        self.assertNotIn(20, sc.get_delete_ids())

    def test_comment_phishing_flagged(self):
        sc = SpamPostCleaner("wp_", CLEAN_MODE_NORMAL)
        sc.analyze_comment_rows([{
            "comment_ID": 2,
            "comment_author_url": "http://spam.example",
            "comment_content": "verify your account login to claim your prize",
            "comment_approved": "1"}])
        self.assertIn(2, sc.get_comment_delete_ids())


class PostExtractionRegressionTests(unittest.TestCase):
    """v3.1.3: la primera tupla de un INSERT de wp_posts debe extraerse."""

    def test_first_post_tuple_is_parsed(self):
        tmp, p = _make_dump()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        c = _cleaner(tmp)
        ids = {r["ID"] for r in c._extract_post_rows(p, "wp_posts")}
        self.assertIn(12, ids)   # spam va PRIMERO; antes del fix se perdia
        self.assertIn(11, ids)


class DbCleanerIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp, self.p = _make_dump()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.cleaner = _cleaner(self.tmp)
        self.interventions = self.cleaner.process([self.p])
        with open(self.p, encoding="utf-8") as fh:
            self.out = fh.read()

    def test_spam_post_first_tuple_removed(self):
        self.assertNotIn("casino", self.out)
        self.assertIn("gardening", self.out)   # post legitimo intacto
        self.assertIn("p=10", self.out)        # page protegida intacta

    def test_spam_comment_removed_legit_kept(self):
        self.assertNotIn("verify your account", self.out)
        self.assertIn("Great article", self.out)

    def test_dangerous_users_removed_oldest_kept(self):
        for login in EXPECT["users_removed_logins"]:
            self.assertNotIn(login, self.out)
        self.assertIn(EXPECT["users_kept_login"], self.out)
        # contrasena del usuario conservado regenerada (literal original ausente)
        self.assertNotIn(EXPECT["user_pass_literal"], self.out)
        self.assertTrue(self.cleaner.generated_passwords["wordpress"])

    def test_cron_neutralized(self):
        self.assertIn(EXPECT["cron_neutralized"], self.out)
        self.assertNotIn("evil.example", self.out)
        self.assertTrue(self.cleaner.cron_log)

    def test_critical_db_row_removed_legit_kept(self):
        self.assertNotIn("CONCAT", self.out)            # fila critica eliminada
        self.assertIn("normal visit data", self.out)    # fila legitima intacta

    def test_legit_option_preserved(self):
        self.assertIn("siteurl", self.out)
        self.assertTrue(self.interventions)


if __name__ == "__main__":
    unittest.main(verbosity=2)
