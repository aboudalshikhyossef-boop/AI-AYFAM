"""
اختبارات شاملة للذكاء المحلي وأساليب الرد والمفاهيم الخاطئة والتعليم (brain/)
"""

import os
import tempfile
import unittest

from brain.conversation import ConversationEngine, Turn
from brain.knowledge_base import KnowledgeBase
from brain.language import analyze, find_misconceptions, correct_text
from brain.learning import PhraseMemory, parse_teaching
from brain.nlp import NLPEngine


class TestLocalIntelligence(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp_dir.name, "test_brain.db")
        self.kb = KnowledgeBase(db_path=self.db_path)
        self.nlp = NLPEngine(knowledge_base=self.kb)
        self.phrases = PhraseMemory(self.kb)
        self.engine = ConversationEngine(self.kb, self.nlp, self.phrases)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_multi_style_assignment(self):
        # 1) شرح مفهوم -> detailed_explanation
        turn_explain = self.engine.process("اشرح لي هجوم SQL Injection بالتفصيل")
        self.assertEqual(turn_explain.style, "detailed_explanation")

        # 2) أمر فحص -> brief_action
        turn_scan = self.engine.process("افحص الشبكة الان")
        self.assertEqual(turn_scan.style, "brief_action")

        # 3) مفهوم خاطئ -> misconception_correction
        turn_misc = self.engine.process("الـ VPN يجعلني مجهول الهوية 100%")
        self.assertEqual(turn_misc.style, "misconception_correction")

    def test_teaching_and_aliases(self):
        # تعليم قاعدة رد
        res = parse_teaching("عندما اقول تمام رد بكلمة ممتااز")
        self.assertIsNotNone(res)
        self.assertEqual(res.kind, "reply")

        self.phrases.learn(res.pairs[0][0], res.pairs[0][1], res.kind)
        matched = self.phrases.match("تمام")
        self.assertIsNotNone(matched)
        self.assertEqual(matched["reply"], "ممتااز")

    def test_expanded_misconceptions(self):
        # اختبار المفاهيم الخاطئة المضافة حديثاً
        found_mac = find_misconceptions("تغيير عنوان MAC يمنحني امان كامل ويعيد حمايتي")
        self.assertTrue(len(found_mac) > 0)
        self.assertEqual(found_mac[0].key, "mac_spoof_safe")

    def test_vocabulary_fuzzy_correction(self):
        fixed, corrections = correct_text("افحصص الشبكه")
        self.assertIn("افحص", fixed)


if __name__ == "__main__":
    unittest.main()
