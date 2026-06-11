"""SpamPostCleaner v2.6.0 — detecta y elimina posts SPAM inyectados en BD WordPress.

Scoring por multiples indicadores: idioma no-latin, keywords de spam,
URLs externas masivas. Protege post_types seguros y posts con comentarios.
"""
import re
from typing import Optional

from ..config.settings import (
    SCAN_MODE_ONLY, SPAM_SCORE_THRESHOLD, SPAM_KEYWORDS,
)


class SpamPostCleaner:
    """Analiza y marca posts SPAM para eliminacion en dumps WP."""

    # Tipos de post que NUNCA se tocan — proteccion absoluta
    # v3.0.0: agregados tipos de WooCommerce, ACF, builders y membresías
    SAFE_POST_TYPES = frozenset([
        "page", "attachment", "nav_menu_item", "revision",
        "custom_css", "customize_changeset", "oembed_cache",
        "user_request", "wp_block", "wp_template", "wp_template_part",
        "wp_navigation", "wp_font_face", "wp_font_family",
        # WooCommerce
        "product", "product_variation", "shop_order", "shop_coupon",
        "shop_order_refund", "shop_webhook",
        # ACF (Advanced Custom Fields)
        "acf-field", "acf-field-group",
        # Page builders
        "elementor_library", "elementor_font", "elementor_icons",
        "fl-builder-template", "et_pb_layout",
        # Formularios
        "wpcf7_contact_form", "wpforms", "gf_form",
        # Membresías / LMS
        "pmpro_membership_level", "sfwd-courses", "sfwd-lessons",
        "llms_course", "llms_lesson",
        # Otros de confianza
        "acf-taxonomy", "tribe_events", "tribe_venue",
    ])

    # Tablas relacionadas a limpiar en cascada tras eliminar posts
    CASCADE_TABLES = ["postmeta", "term_relationships", "comments", "commentmeta"]

    # Regex para URLs externas en contenido
    _URL_RE = re.compile(r'href\s*=\s*["\']https?://[^"\']+["\']', re.IGNORECASE)

    # v2.6.8: indicadores de phishing en comentarios
    _PHISHING_HINTS = re.compile(
        r"(verify your account|confirm your password|login to claim|"
        r"bit\.ly|tinyurl|t\.me/|wa\.me/|telegram|whatsapp \+|"
        r"viagra|cialis|casino|porn|sex|loan|bitcoin|crypto wallet|seed phrase)",
        re.IGNORECASE,
    )

    def __init__(self, prefix: str, clean_mode: str):
        self.prefix = prefix
        self.clean_mode = clean_mode
        self.spam_log: list[dict] = []
        self._comment_delete_ids: list[int] = []  # v2.6.8

    def analyze_rows(self, rows: list[dict]) -> "SpamPostCleaner":
        """Analiza filas de {prefix}posts y popula spam_log.
        rows: dicts con campos ID, post_title, post_content, post_type,
              post_status, comment_count, comment_status."""
        for row in rows:
            post_type = row.get("post_type", "post")
            post_id = row.get("ID", 0)

            # Regla 1: Nunca tocar post_types seguros
            if post_type in self.SAFE_POST_TYPES:
                continue

            # Score
            score, reasons = self._score_post(row)
            if score <= 0:
                continue

            title_preview = (row.get("post_title", "") or "")[:60]
            entry = {
                "post_id": post_id,
                "title_preview": title_preview,
                "score": score,
                "reasons": reasons,
                "type": "spam_post",
                "action": "logged_only",
                "cascaded_tables": [],
            }

            # Regla 2: Nunca actuar en scan_only
            if self.clean_mode == SCAN_MODE_ONLY:
                self.spam_log.append(entry)
                continue

            # Regla 3: Nunca eliminar posts con comentarios aprobados
            comment_count = int(row.get("comment_count", 0) or 0)
            comment_status = row.get("comment_status", "")
            if comment_count > 0 and comment_status == "open":
                entry["action"] = "suspect_not_deleted"
                entry["reason"] = "has_comments"
                self.spam_log.append(entry)
                continue

            # Regla 5: Score minimo para eliminar
            if score < SPAM_SCORE_THRESHOLD:
                entry["action"] = "suspect_not_deleted"
                entry["reason"] = f"score_{score}"
                self.spam_log.append(entry)
                continue

            # Marcar para eliminacion
            entry["action"] = "deleted"
            entry["cascaded_tables"] = self.CASCADE_TABLES[:]
            self.spam_log.append(entry)

        return self

    def analyze_comment_rows(self, rows: list[dict]) -> "SpamPostCleaner":
        """v2.6.8: analiza filas de {prefix}comments y marca spam/phishing.
        rows: dicts con comment_ID, comment_content, comment_author_url,
              comment_approved."""
        for row in rows:
            cid = row.get("comment_ID", 0)
            content = row.get("comment_content", "") or ""
            author_url = row.get("comment_author_url", "") or ""
            approved = str(row.get("comment_approved", "")).strip().lower()

            score, reasons = self._score_comment(content, author_url)
            if approved == "spam":            # ya marcado spam por WP/Akismet
                score = max(score, 100)
                reasons.append("marked_spam")
            if score <= 0:
                continue

            entry = {
                "post_id": cid,
                "title_preview": content[:60],
                "score": score,
                "reasons": reasons,
                "type": "spam_post",
                "kind": "comentario",
                "action": "logged_only",
            }
            if self.clean_mode == SCAN_MODE_ONLY:
                self.spam_log.append(entry)
                continue
            if score < SPAM_SCORE_THRESHOLD:
                entry["action"] = "suspect_not_deleted"
                self.spam_log.append(entry)
                continue
            entry["action"] = "deleted"
            if cid:
                self._comment_delete_ids.append(cid)
            self.spam_log.append(entry)
        return self

    def _score_comment(self, content: str, author_url: str) -> tuple[int, list[str]]:
        score = 0
        reasons = []
        if self._detect_non_latin_script(content):
            score += 35
            reasons.append("non_latin_script")
        all_urls = re.findall(r'https?://[^\s<>"\']{5,}', content)
        if len(all_urls) >= 2:
            score += 25
            reasons.append(f"links_{len(all_urls)}")
        if author_url and len(author_url) > 5:
            score += 10
            reasons.append("author_url")
        if self._PHISHING_HINTS.search(content):
            score += 40
            reasons.append("phishing_keywords")
        text_lower = content.lower()
        for cat_name, keywords in SPAM_KEYWORDS.items():
            if sum(1 for kw in keywords if kw.lower() in text_lower) >= 2:
                score += 15
                reasons.append(f"{cat_name}")
        return min(score, 100), reasons

    def get_comment_delete_ids(self) -> list[int]:
        return list(self._comment_delete_ids)

    def get_delete_ids(self) -> list[int]:
        """IDs con accion 'deleted' que pasaron todas las reglas."""
        return [
            e["post_id"] for e in self.spam_log
            if e.get("action") == "deleted" and e.get("post_id")
            and e.get("kind") != "comentario"
        ]

    def get_cascade_deletes(self, deleted_ids: list[int]) -> dict[str, list]:
        """Retorna {table_name: [ids_to_delete]} para CASCADE_TABLES."""
        if not deleted_ids:
            return {}
        result = {}
        for table_base in self.CASCADE_TABLES:
            table_name = f"{self.prefix}{table_base}"
            result[table_name] = deleted_ids[:]
        return result

    def _score_post(self, row: dict) -> tuple[int, list[str]]:
        """Retorna (score 0-100, [razones_de_spam])."""
        title = row.get("post_title", "") or ""
        content = row.get("post_content", "") or ""
        text = f"{title} {content}"
        text_lower = text.lower()

        score = 0
        reasons = []

        # +35: Script no-latin (>30% chars en bloques no-latinos)
        if self._detect_non_latin_script(text):
            score += 35
            reasons.append("non_latin_script")

        # Keywords por categoria (tomar max de cada categoria, acumulable entre categorias)
        for cat_name, keywords in SPAM_KEYWORDS.items():
            hits = sum(1 for kw in keywords if kw.lower() in text_lower)
            if hits >= 2:
                points = {
                    "gambling": 20,
                    "adult": 20,
                    "pharma": 20,
                    "crypto_spam": 15,
                    "piracy": 15,
                }.get(cat_name, 10)
                score += points
                reasons.append(f"{cat_name}_{hits}hits")

        # +10: Titulo contiene keywords de gambling/pharma/adult
        title_lower = title.lower()
        title_cats = ("gambling", "pharma", "adult")
        for cat in title_cats:
            kws = SPAM_KEYWORDS.get(cat, [])
            if any(kw.lower() in title_lower for kw in kws):
                score += 10
                reasons.append(f"title_{cat}")
                break  # Solo +10 una vez por titulo

        # +10: Contenido con >4 URLs externas
        urls = self._URL_RE.findall(content)
        if len(urls) > 4:
            score += 10
            reasons.append(f"external_urls_{len(urls)}")

        return min(score, 100), reasons

    @staticmethod
    def _detect_non_latin_script(text: str) -> bool:
        """True si >30% de caracteres alfanumericos son de bloques no-latinos."""
        if not text:
            return False

        non_latin = 0
        total_alpha = 0

        for ch in text:
            if not ch.isalpha():
                continue
            total_alpha += 1
            cp = ord(ch)
            # Arabe
            if 0x0600 <= cp <= 0x06FF:
                non_latin += 1
            # Cirilico
            elif 0x0400 <= cp <= 0x04FF:
                non_latin += 1
            # CJK Unificado
            elif 0x4E00 <= cp <= 0x9FFF:
                non_latin += 1
            # Hiragana / Katakana
            elif 0x3040 <= cp <= 0x30FF:
                non_latin += 1
            # Hangul
            elif 0xAC00 <= cp <= 0xD7AF:
                non_latin += 1
            # Thai
            elif 0x0E00 <= cp <= 0x0E7F:
                non_latin += 1
            # Devanagari (Hindi, Marathi, etc.)
            elif 0x0900 <= cp <= 0x097F:
                non_latin += 1
            # Hebrew
            elif 0x0590 <= cp <= 0x05FF:
                non_latin += 1
            # Bengali
            elif 0x0980 <= cp <= 0x09FF:
                non_latin += 1

        if total_alpha < 10:
            return False
        return (non_latin / total_alpha) > 0.30
