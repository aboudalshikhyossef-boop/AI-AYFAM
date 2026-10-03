"""
AI AYFAM v3 — Smart Agent Brain
وكيل أمني ذكي حقيقي — يفهم لغتك، يعرف بيئته، يتطور
"""

from core.agent_v5 import AgentV5Mixin

import os
import socket
import time
import traceback
from datetime import datetime
from pathlib import Path

from config.settings import Settings
from ui.terminal import TerminalUI
from core.intelligence import SecurityIntelligence
from brain.knowledge_base import KnowledgeBase
from brain.nlp import NLPEngine
from brain.context_engine import ContextEngine
from brain.self_heal import SelfHealEngine
from tools import network, system
from tools.usb import list_usb_devices, scan_mounted_drives, get_connected_phones
from tools.usb_control import (
    authorize_device, deauthorize_device, eject_storage_device,
    deep_scan_flash, fix_flash_issues, diagnose_android_phone, adb_fix_action,
    get_wifi_adapters, wifi_adapter_control, get_bluetooth_adapters, bluetooth_control,
    detect_device_type, get_device_controls, DEVICE_TYPE_DESCRIPTIONS,
)
from tools.fix import apply_fix, list_available_fixes
from tools.github_tool import GitHubTool
from tools import web
from reports.generator import generate_markdown_report, save_report
from brain import library
from brain import relevance_engine
from engine.correlation import CorrelationEngine, SmartRemediationAdvisor
from utils import safe_exec
from engine.gemini_cti import GeminiCTIError, GeminiThreatClient, LocalThreatMatcher, ThreatHistory, markdown_report


def _run(cmd, timeout=30, sudo=False):
    """⚠️ لأوامر shell ثابتة فقط (بدون أي جزء متغيّر) — راجع utils/safe_exec.py
    لأي حالة تحتاج إدراج متغيّر (target, path, ip...)."""
    if sudo and os.geteuid() != 0:
        cmd = f"sudo {cmd}"
    res = safe_exec.run_trusted_shell(cmd, timeout=timeout)
    return res.ok, res.stdout, res.stderr


def _risk_border_style(level: str) -> str:
    return {"critical": "red", "high": "dark_orange", "medium": "yellow",
            "low": "cyan", "safe": "green"}.get((level or "").lower(), "grey35")


class AYFAMAgent(AgentV5Mixin):
    def __init__(self, settings: Settings, ui: TerminalUI, verbose: bool = False):
        self.settings   = settings
        self.ui         = ui
        self.verbose    = verbose
        self.lang       = settings.get("language", "ar")
        self.intel      = SecurityIntelligence(language=self.lang)
        self.github     = GitHubTool(token=settings.get("github_token", ""))
        self._hostname  = socket.gethostname()
        self._last_findings = []

        # ── Brain ──
        self.kb         = KnowledgeBase()
        self.nlp        = NLPEngine(knowledge_base=self.kb)
        self.ctx        = ContextEngine()
        self.healer     = SelfHealEngine(knowledge_base=self.kb, ui=ui)

        # ── Conversation state ──
        self._chat_history = []   # [(role, msg)]
        self._last_intent  = None
        self._last_entities = {}

        # ── Attack Chain Correlation Engine ──
        self.correlation = CorrelationEngine()

    def _t(self, ar: str, en: str) -> str:
        return ar if self.lang == "ar" else en

    def _ask_save_report(self, content: str):
        if self.ui.confirm(self._t("حفظ التقرير؟","Save report?"), default=False):
            report_dir = self.settings.get("report_dir", os.path.expanduser("~/ayfam-reports"))
            fpath = save_report(content, report_dir)
            self.ui.success(self._t(f"محفوظ: {fpath}", f"Saved: {fpath}"))
            if self.settings.get("github_token"):
                if self.ui.confirm(self._t("رفع على GitHub؟","Push to GitHub?"), False):
                    self._push_to_github(content)

    # ─────────────────────────────────────────────────────────────────────────
    # GEMINI CTI — public threat research, private local matching
    # ─────────────────────────────────────────────────────────────────────────
    def gemini_model_status(self):
        """Discover models for the configured key without sending host data."""
        key = self.settings.get("gemini_api_key", "") or os.environ.get("GEMINI_API_KEY", "")
        if not key:
            self.ui.warning(self._t("لم يتم إعداد مفتاح Gemini.", "Gemini API key is not configured."))
            return []
        client = None
        try:
            client = GeminiThreatClient(key)
            models = client.discover_models()
            names = ", ".join(model.short_name for model in models[:8])
            self.ui.success(self._t(
                f"المرشح التلقائي (بعد اكتشاف النماذج): {models[0].short_name}\nالنماذج القابلة للتوليد: {names}\nملاحظة: الحصة تُعرف فقط عند تنفيذ الطلب.",
                f"Automatic candidate: {models[0].short_name}\nGenerate-capable models: {names}\nNote: quota is verified only when a request is executed.",
            ))
            return models
        except GeminiCTIError as exc:
            self.ui.error(self._t(f"فشل اتصال Gemini: {exc}", f"Gemini connection failed: {exc}"))
            return []
        finally:
            if client:
                client.close()

    def run_gemini_threat_scan(self, window_hours: int = 48):
        """Fetch general CTI, then perform all host matching strictly offline."""
        key = self.settings.get("gemini_api_key", "") or os.environ.get("GEMINI_API_KEY", "")
        if not key:
            self.ui.error(self._t("أضف مفتاح Gemini أولاً عبر --configure-gemini أو GEMINI_API_KEY.", "Configure Gemini first with --configure-gemini or GEMINI_API_KEY."))
            return None
        client = None
        try:
            self.ui.info(self._t("جلب معلومات تهديدات عامة من المصادر الموثوقة...", "Fetching public threat intelligence from authoritative sources..."))
            client = GeminiThreatClient(key)
            feed = client.fetch_threats(window_hours=window_hours)
            model = client.selected_model.short_name
            self.ui.info(self._t("مطابقة النتائج مع الجهاز محلياً فقط...", "Matching results against this host locally only..."))
            matched = LocalThreatMatcher().match(feed)
            history = ThreatHistory()
            history.save(feed, matched, model)
            report = markdown_report(feed, matched, model)
            report_dir = Path(self.settings.get("report_dir", os.path.expanduser("~/ayfam-reports")))
            report_dir.mkdir(parents=True, exist_ok=True)
            path = report_dir / f"gemini_cti_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            path.write_text(report, encoding="utf-8")
            self.ui.success(self._t(f"اكتمل الفحص: {len(feed['threats'])} تهديد، {len(matched)} مطابق محلياً. التقرير: {path}", f"Scan complete: {len(feed['threats'])} threats, {len(matched)} local matches. Report: {path}"))
            return {"feed": feed, "matched": matched, "report_path": str(path), "model": model}
        except GeminiCTIError as exc:
            self.ui.error(self._t(f"فشل فحص Gemini: {exc}", f"Gemini scan failed: {exc}"))
            return None
        finally:
            if client:
                client.close()

    # ─────────────────────────────────────────────────────────────────────────
    #  TREND TRACKING — يقارن كل فحص بآخر فحص من نفس النوع، ثم يحفظه
    # ─────────────────────────────────────────────────────────────────────────

    def _save_and_show_trend(self, scan_type: str, risk: dict, findings: list, target: str = None):
        """يقارن هذا الفحص بآخر فحص محفوظ من نفس النوع (إن وُجد)، يعرض فرقاً
        مختصراً (تحسّن/تدهور/مستقر)، ثم يحفظ الفحص الحالي. استبدال لتكرار
        self.kb.save_scan(...) في كل معالج فحص على حدة."""
        previous = self.kb.get_last_scan(scan_type)
        comparison = self.intel.compare_scans(previous, {"risk": risk, "findings": findings})
        if comparison:
            self.ui.raw(self.intel.generate_trend_narrative(comparison, self.lang), style="dim cyan")
        self.kb.save_scan(scan_type, {"risk": risk, "findings": findings}, target=target)
        return comparison

    # ─────────────────────────────────────────────────────────────────────────
    #  CVE ENRICHMENT — يربط حزم النظام القابلة للترقية بقاعدة CVE/CISA KEV
    # ─────────────────────────────────────────────────────────────────────────

    def _enrich_packages_with_cve(self, packages: list) -> list:
        """يأخذ حزماً حسّاسة أمنياً قابلة للترقية (من system.list_upgradable_security_packages)
        ويطابقها مع CISA KEV (سريع، طلب واحد فقط) ثم NVD (مُقيَّد لأول عدة
        حزم فقط لتفادي بطء ملحوظ أو تجاوز حد الطلبات). كل نتيجة هنا موسومة
        بوضوح بمصدرها حتى يُفرَّق بينها وبين نتائج الفحص المحلي الخام."""
        findings = []
        if not packages:
            return findings

        kev = web.get_cisa_known_exploited(max_results=100)
        kev_products = {(v.get("product") or "").lower() for v in kev if "error" not in v and v.get("product")}

        nvd_key = self.settings.get("nvd_api_key", "")
        checked_via_nvd = 0
        for pkg in packages[:8]:
            name = pkg["package"]
            if any(name in p or p in name for p in kev_products if len(p) > 2):
                findings.append({
                    "severity": "critical",
                    "title": self._t(
                        f"حزمة {name} قابلة للترقية وقد تطابق ثغرة في قائمة CISA KEV المُستغَلة فعلياً",
                        f"Package {name} is upgradable and may match a CISA KEV actively-exploited vulnerability"),
                    "detail": self._t("تحقّق يدوياً من قائمة CISA KEV — راجع (7) مركز GitHub → CISA.",
                                       "Verify manually against the CISA KEV list — see (7) GitHub Center → CISA."),
                    "fix": f"sudo apt-get install --only-upgrade {name}",
                    "cve_enriched": True,
                })
                continue
            if checked_via_nvd >= 5:  # لا نُرسل أكثر من 5 طلبات NVD لكل فحص نظام
                continue
            checked_via_nvd += 1
            cves = web.search_cve(name, days_back=180, max_results=3, api_key=nvd_key)
            valid = [c for c in cves if "error" not in c and (c.get("severity") or "").upper() in ("HIGH", "CRITICAL")]
            if valid:
                top = valid[0]
                findings.append({
                    "severity": "high" if (top.get("severity") or "").upper() == "HIGH" else "critical",
                    "title": self._t(f"حزمة {name} قابلة للترقية — ثغرة محتملة الصلة: {top['id']}",
                                       f"Package {name} is upgradable — potentially related CVE: {top['id']}"),
                    "detail": f"{(top.get('description') or '')[:150]} (CVSS: {top.get('cvss_score','?')})",
                    "fix": f"sudo apt-get install --only-upgrade {name}\n{top.get('url','')}",
                    "cve_enriched": True,
                })
        return findings

    # ─────────────────────────────────────────────────────────────────────────
    #  MAIN INTERACTIVE MODE — Chat-first, NLP-powered
    # ─────────────────────────────────────────────────────────────────────────

    def interactive_mode(self):
        self.ui.matrix_splash(1.5)
        self.ui.banner(context=self.ctx)
        self.ui.dashboard(context=self.ctx, kb_stats=self.kb.get_stats())

        # Greet
        greeting = self._t(
            f"مرحباً {self.ctx.user.get('username','')}! "
            f"أنا AI AYFAM — وكيلك الأمني الذكي. "
            f"اكتب أي شيء بالعربي أو الإنجليزي وسأفهمك.\n"
            f"  مثال: 'افحص الشبكة'  |  'ما هو CVE-2024-1234'  |  'تحليل USB'  |  'اشرح Brute Force'",
            f"Hello {self.ctx.user.get('username','')}! I'm AI AYFAM. Type anything in Arabic or English.\n"
            f"  e.g.: 'scan network' | 'what is CVE-2024-1234' | 'analyze USB' | 'explain brute force'"
        )
        self.ui.chat_agent(greeting, intent="READY")

        while True:
            try:
                raw_input = self.ui.chat_input().strip()
                if not raw_input:
                    continue

                # Save to history + KB
                self.ui.chat_you(raw_input)
                self.kb.save_message("user", raw_input)
                self._chat_history.append(("user", raw_input))

                # Parse with NLP — augment with recent context for follow-up understanding
                self.ui.chat_thinking(self._t("أحلل طلبك...", "Analyzing..."))
                cmd = self.nlp.parse(raw_input)
                # Carry forward entities from previous turn when current input lacks them
                # (lets "now scan it" after an IP mention reuse the IP)
                if self._last_entities:
                    for k, v in self._last_entities.items():
                        if k not in cmd.entities and v:
                            cmd.entities.setdefault(k, v)
                self._last_intent  = cmd.intent
                self._last_entities = cmd.entities

                # Route
                self._route_nlp(cmd, raw_input)

            except KeyboardInterrupt:
                self.ui.warning(self._t("Ctrl+C — اضغط مرة أخرى للخروج","Ctrl+C — press again to exit"))
                try:
                    time.sleep(1.5)
                except KeyboardInterrupt:
                    break
            except EOFError:
                break
            except Exception as e:
                err_info = self.healer._analyze_error(e)
                self.healer.display_error(err_info)
                if err_info.get("can_auto_fix"):
                    self.healer.try_fix(err_info)

    # ─────────────────────────────────────────────────────────────────────────
    #  NLP Router
    # ─────────────────────────────────────────────────────────────────────────

    def _route_nlp(self, cmd, raw_input: str):
        intent  = cmd.intent
        score   = cmd.score
        entities = cmd.entities

        # Debug (verbose)
        if self.verbose:
            self.ui.info(f"[NLP] intent={intent} score={score:.2f} entities={entities}")

        # Low confidence — ask for clarification
        if not intent or score < 0.2:
            response = self._t(
                f"لم أفهم تماماً ما تقصده. هل تريد:\n"
                f"  • فحص الشبكة؟  • فحص USB؟  • البحث عن ثغرة؟  • مساعدة؟\n"
                f"يمكنك أيضاً كتابة رقم من القائمة (1-8)",
                f"I'm not quite sure what you mean. Do you want to:\n"
                f"  • Scan network? • Check USB? • Search CVE? • Help?\n"
                f"You can also type a number from the menu (1-8)"
            )
            self.ui.chat_agent(response, intent="CLARIFY")
            self.kb.save_message("agent", response, intent="clarify")
            return

        # Map to handler
        handlers = {
            "scan_network":  self._scan_network,
            "scan_ports":    lambda: self._scan_ports(entities.get("ip","127.0.0.1")),
            "check_firewall":self._check_firewall,
            "check_ip":      lambda: self._check_ip(entities.get("ip","") or self.ui.ask("IP")),
            "wifi":          self._wifi_status,
            "usb_control":   self._usb_control_center,
            "scan_system":   self._scan_system,
            "scan_logs":     self._scan_logs,
            "scan_website":  lambda: self._test_website(entities.get("url","")),
            "cve_search":    lambda: self._cve_search(entities.get("cve") or entities.get("keyword","") or entities.get("domain","")),
            "pkg_vuln_search": lambda: self._pkg_vuln_search(entities.get("package","")),
            "scan_trend":    self._show_trend,
            "rebuild_index": self._rebuild_index,
            "concept_explore": lambda: self._concept_explore(entities.get("concept","")),
            "concept_link":  lambda: self._concept_link(entities.get("concept_a",""), entities.get("concept_b","")),
            "summarize_doc": lambda: self._summarize_doc(entities.get("book_title","")),
            "github":        self._github_center,
            "web_search":    lambda: self._web_search(entities.get("keyword","") or raw_input),
            "autofix":       self._autofix_menu,
            "full_scan":     self._full_scan,
            "update_intel":  self._update_intel,
            "agent_status":  self._agent_status,
            "agent_update":  self._agent_self_update,
            "explain":       lambda: self._explain(cmd.explain_target or entities.get("keyword","") or raw_input),
            "help":          self._show_help,
            "config":        self._config_menu,
            "learn_file":    lambda: self._learn_from_file(entities.get("filepath","")),
            "teach":         lambda: self._teach(entities.get("fact","")),
            "show_learned":  self._show_learned,
            "ping_host":     lambda: self._ping_host(entities.get("ip","")),
            "exit":          None,
        }

        # Announce what we're doing
        desc = self.nlp.describe_intent(intent, self.lang)
        self.ui.info(self._t(f"🧠 فهمت طلبك: {desc} — سأبدأ الآن.", f"🧠 Understood: {desc} — starting now."))
        self.kb.save_message("agent", f"[{intent}] {desc}", intent=intent, entities=entities)

        if intent == "exit":
            self.ui.chat_agent(self._t("مع السلامة! 🛡️", "Goodbye! 🛡️"), intent="EXIT")
            raise EOFError()

        handler = handlers.get(intent)
        if handler:
            result, err = self.healer.intercept(handler)
            if err:
                self.healer.display_error(err)
                if err.get("can_auto_fix") and self.ui.confirm(
                    self._t("تطبيق الإصلاح التلقائي؟","Apply auto-fix?"), False
                ):
                    self.healer.try_fix(err, auto_approve=True)
        else:
            # Number shortcuts
            mapping = {"1":"scan_network","2":"scan_system","3":"usb_control",
                       "4":"full_scan","5":"scan_logs","6":"cve_search","7":"github","8":"agent_status"}
            if raw_input.strip() in mapping:
                self._route_nlp(type('C', (), {
                    'intent': mapping[raw_input.strip()], 'score': 1.0,
                    'entities': {}, 'explain_target': None
                })(), raw_input)
            else:
                self.ui.warning(self._t(f"لا أعرف كيف أعالج: '{raw_input}'","Don't know how to handle: '{raw_input}'"))

    # ─────────────────────────────────────────────────────────────────────────
    #  EXPLAIN — Knowledge base driven
    # ─────────────────────────────────────────────────────────────────────────

    def _explain(self, target: str):
        self.ui.section(self._t(f"📖 شرح: {target}", f"📖 Explain: {target}"))
        explanation = self.nlp.explain(target)
        self.ui.chat_agent(explanation, intent="EXPLAIN")

        # Offer web search if not enough info
        if "لم أجد" in explanation or "not found" in explanation.lower():
            if self.ui.confirm(self._t("البحث عن هذا في الإنترنت؟","Search the web for this?"), True):
                self._web_search(target)

    # ─────────────────────────────────────────────────────────────────────────
    #  LEARNING — مكتبة شخصية (كتب/ملفات) + تعليم مباشر + شفافية كاملة
    # ─────────────────────────────────────────────────────────────────────────

    def _learn_from_file(self, filepath: str):
        self.ui.section(self._t("📚 تعلّم من ملف", "📚 Learn from file"))
        if not filepath:
            filepath = self.ui.ask(self._t("مسار الملف (PDF/TXT/MD)", "File path (PDF/TXT/MD)"))
        if not filepath:
            self.ui.warning(self._t("لم يُحدَّد مسار.", "No path given."))
            return

        self.ui.info(self._t(
            f"سأقرأ الملف: {filepath}\nثم أستخرج نصه، أقسّمه لمقاطع، وأفهرسه بحثاً كاملاً محلياً — بدون أي اتصال خارجي.",
            f"I'll read: {filepath}\nThen extract its text, split it into chunks, and index it for local full-text search — no external calls."
        ))
        with self.ui.spinner(self._t("أستوعب الملف...", "Ingesting file...")) as prog:
            task = prog.add_task("ingest", total=None)
            try:
                result = library.ingest_file(filepath, self.kb)
            except library.IngestError as e:
                self.ui.error(str(e))
                return
            except Exception as e:
                self.ui.error(self._t(f"خطأ غير متوقع أثناء الاستيعاب: {e}", f"Unexpected error ingesting file: {e}"))
                return

        pages_line = f"{result['pages']} صفحة، " if result.get("pages") else ""
        tools_line = ""
        if result.get("tools_detected"):
            top_tools = ", ".join(
                f"{t['tool_name']} ({t['commands']} أمر)" if t["commands"] else t["tool_name"]
                for t in result["tools_detected"][:8]
            )
            tools_line = self._t(
                f"\n🔧 أدوات اكتشفتها في الكتاب: {top_tools}\n"
                f"   استخرجت {result['commands_extracted']} أمراً فعلياً قابلاً للاسترجاع الدقيق لاحقاً.\n",
                f"\n🔧 Tools detected in the book: {top_tools}\n"
                f"   Extracted {result['commands_extracted']} real command(s) for precise later retrieval.\n"
            )
        diag_line = ""
        if result.get("diagnostics"):
            diag_line = "\n" + "\n".join(result["diagnostics"]) + "\n"

        summary = self._t(
            f"✅ انتهيت من استيعاب «{result['title']}».\n\n"
            f"ماذا فعلت بالضبط:\n"
            f"  • قرأت {pages_line}{result['total_chars']:,} حرفاً من الملف\n"
            f"  • قسّمتها إلى {result['chunks']} مقطعاً قابلاً للبحث\n"
            f"  • فهرستها في مكتبتي الشخصية (بحث نصي كامل محلي، بدون أي اتصال خارجي)\n"
            f"{tools_line}{diag_line}\n"
            f"مثال على أول مقطع:\n  \"{result['preview']}\"\n\n"
            f"الآن يمكنك سؤالي عن أي أداة ذُكرت فيه (مثال: 'اشرح nmap') وسأعطيك "
            f"الأوامر الفعلية من الكتاب تحديداً، لا فقرة عامة. سأستخدمه أيضاً "
            f"كمرجع إن واجهت خطأً لا أعرف حله في الطرفية.\n\n"
            f"💡 بعد إضافة كل كتبك، شغّل 'إعادة بناء فهرس الذكاء' مرة واحدة "
            f"لتفعيل البحث المُرتَّب بالصلة عبر كل المكتبة، وربط المفاهيم بين "
            f"كتبك، والملخصات الاستخلاصية — لا داعي لتشغيلها بعد كل كتاب فردي.",
            f"✅ Finished ingesting «{result['title']}».\n\n"
            f"What I did exactly:\n"
            f"  • Read {pages_line}{result['total_chars']:,} characters\n"
            f"  • Split it into {result['chunks']} searchable chunks\n"
            f"  • Indexed it in my personal library (local full-text search only)\n"
            f"{tools_line}{diag_line}\n"
            f"First chunk preview:\n  \"{result['preview']}\"\n\n"
            f"Ask me about any tool it mentions (e.g. 'explain nmap') and I'll give "
            f"you the actual commands from the book, not a generic paragraph.\n\n"
            f"💡 After adding all your books, run 'rebuild intelligence index' once "
            f"to enable relevance-ranked search across the whole library, concept "
            f"linking between books, and extractive summaries — no need to run it "
            f"after every single book."
        )
        self.ui.chat_agent(summary, intent="LEARN")
        self.kb.log_update("library", 1, f"ingested {result['title']}")

    def _teach(self, fact: str):
        if not fact:
            fact = self.ui.ask(self._t("ماذا تريد أن تعلّمني؟", "What should I learn?"))
        if not fact:
            return
        key = self.kb.teach_fact(fact)
        response = self._t(
            f"✅ تم! سأتذكر هذا:\n  \"{fact}\"\n\n"
            f"سأستخدمه في أي شرح أو تشخيص لاحق ذي صلة، ويمكنك رؤية كل ما "
            f"علّمتني إياه عبر قول 'ماذا تعلمت'.",
            f"✅ Got it! I'll remember:\n  \"{fact}\"\n\n"
            f"I'll use it in future relevant explanations, and you can see "
            f"everything you've taught me by asking 'what have you learned'."
        )
        self.ui.chat_agent(response, intent="TEACH")
        self.kb.save_message("agent", f"[teach] {fact}", intent="teach")

    def _show_learned(self):
        self.ui.section(self._t("🧠 ماذا تعلمت حتى الآن", "🧠 What I've learned so far"))
        summary = self.kb.get_learning_summary()
        self.ui.print_table(
            [self._t("المصدر","Source"), self._t("العدد","Count")],
            [
                [self._t("حقائق علّمتني إياها مباشرة","Facts you taught me directly"), summary["facts_taught_by_user"]],
                [self._t("معرفة تعلّمتها ذاتياً من تكرار الأخطاء","Self-learned from repeated errors"), summary["self_learned_knowledge"]],
                [self._t("إصلاحات أخطاء متعلَّمة","Learned error fixes"), summary["learned_error_fixes"]],
                [self._t("تحسينات ذاتية طُبِّقت","Applied self-improvements"), summary["applied_self_improvements"]],
                [self._t("كتب/ملفات في مكتبتي","Documents in my library"), summary["library_documents"]],
                [self._t("مقاطع مفهرسة من المكتبة","Indexed library chunks"), summary["library_chunks"]],
            ]
        )

        taught = self.kb.get_taught_facts(limit=10)
        if taught:
            self.ui.subsection(self._t("آخر ما علّمتني إياه:", "Latest things you taught me:"))
            for f in taught:
                self.ui.info(f"• {f['content'][:150]}")

        docs = self.kb.list_library_documents()
        if docs:
            self.ui.subsection(self._t("مكتبتي الشخصية:", "My personal library:"))
            self.ui.print_table(
                [self._t("العنوان","Title"), self._t("النوع","Type"), self._t("مقاطع","Chunks"), self._t("أُضيف","Added")],
                [[d["title"], d["file_type"], d["chunk_count"], d["added_at"]] for d in docs]
            )
            if relevance_engine.is_index_built():
                meta = relevance_engine.get_index_meta()
                self.ui.info(self._t(
                    f"🧠 فهرس الذكاء مبني: {meta.get('chunks_indexed','?')} مقطع، {meta.get('vocabulary_size','?')} مصطلح فريد.",
                    f"🧠 Intelligence index built: {meta.get('chunks_indexed','?')} chunks, {meta.get('vocabulary_size','?')} unique terms."))
            else:
                self.ui.warning(self._t(
                    "🧠 فهرس الذكاء غير مبني بعد — البحث والربط بين الكتب لن يعملا حتى تشغّل 'إعادة بناء فهرس الذكاء'.",
                    "🧠 Intelligence index not built yet — cross-book search/linking won't work until you run 'rebuild intelligence index'."))
        else:
            self.ui.info(self._t(
                "لا توجد كتب/ملفات في مكتبتي بعد. علّمني واحداً بقول: 'تعلم من ملف <المسار>'",
                "No documents in my library yet. Teach me one: 'learn from file <path>'"
            ))

    def _rebuild_index(self):
        """يبني (أو يعيد بناء) فهرس الذكاء المحلي بالكامل: TF-IDF عبر كل
        مقاطع المكتبة، خريطة المفاهيم، وملخص استخلاصي حقيقي لكل كتاب.
        عملية صريحة ومنفصلة عن الاستيعاب نفسه — قد تستغرق وقتاً محسوساً
        على مكتبة كبيرة (مئات الكتب)."""
        self.ui.section(self._t("🧠 بناء فهرس الذكاء المحلي", "🧠 Building local intelligence index"))
        docs = self.kb.list_library_documents()
        if not docs:
            self.ui.warning(self._t("لا كتب في المكتبة بعد.", "No books in the library yet."))
            return

        self.ui.info(self._t(
            f"سأبني فهرس TF-IDF عبر {len(docs)} كتاب، ثم خريطة مفاهيم، ثم ملخصاً استخلاصياً لكل كتاب. "
            f"هذا حساب رياضي محلي بحت (بدون إنترنت، بدون نموذج مُحمَّل) — قد يستغرق وقتاً على مكتبة كبيرة.",
            f"I'll build a TF-IDF index across {len(docs)} books, then a concept graph, then an extractive "
            f"summary per book. Pure local math (no internet, no downloaded model) — may take a while on a large library."
        ))

        with self.ui.spinner(self._t("بناء فهرس TF-IDF...","Building TF-IDF index...")):
            pass
        idx_res = relevance_engine.build_index(self.kb)
        if not idx_res.get("success"):
            self.ui.error(idx_res.get("error", "?"))
            return
        self.ui.success(self._t(
            f"✅ فُهرس {idx_res['chunks_indexed']} مقطع، {idx_res['vocabulary_size']} مصطلح فريد.",
            f"✅ Indexed {idx_res['chunks_indexed']} chunks, {idx_res['vocabulary_size']} unique terms."))

        with self.ui.spinner(self._t("بناء خريطة المفاهيم...","Building concept graph...")):
            pass
        graph_res = relevance_engine.build_concept_graph(self.kb)
        if graph_res.get("success"):
            self.ui.success(self._t(
                f"✅ خريطة مفاهيم: {graph_res['terms_indexed']} مصطلحاً، {graph_res['edges_created']} رابطاً عبر {graph_res['documents']} كتاب.",
                f"✅ Concept graph: {graph_res['terms_indexed']} terms, {graph_res['edges_created']} links across {graph_res['documents']} books."))
        else:
            self.ui.warning(graph_res.get("error", "?"))

        with self.ui.spinner(self._t("توليد ملخص استخلاصي لكل كتاب...","Generating extractive summary per book...")):
            pass
        summarized = 0
        for doc in docs:
            full_text = self.kb.get_doc_full_text(doc["id"])
            sentences = relevance_engine.extractive_summary(full_text, n_sentences=6)
            if sentences:
                self.kb.save_document_summary(doc["id"], " ".join(sentences))
                summarized += 1
        self.kb.commit()
        self.ui.success(self._t(f"✅ ملخص استخلاصي جاهز لـ {summarized} كتاب.",
                                  f"✅ Extractive summary ready for {summarized} book(s)."))

        self.ui.raw(self._t(
            "الآن يمكنك: 'اشرح مفهوم <شيء>'، 'اربط بين <X> و <Y>'، 'لخص كتاب <اسم>'، "
            "وأي سؤال عام سيُبحث فيه بترتيب حسب الصلة الفعلية عبر كل كتبك دفعة واحدة.",
            "Now you can: 'explain concept <X>', 'link <X> and <Y>', 'summarize book <name>', "
            "and any general question will be searched with real relevance ranking across all your books at once."
        ))

    def _concept_explore(self, concept: str):
        """يستكشف مفهوماً واحداً عبر كل المكتبة: أي الكتب تناقشه، أفضل
        المقاطع صلةً به (مُرتَّبة إحصائياً لا مجرد تطابق حرفي)، مفاهيم
        مرتبطة به عبر خريطة المفاهيم، وملخص استخلاصي مبني من تلك المقاطع
        تحديداً (لا توليد حر)."""
        if not concept:
            concept = self.ui.ask(self._t("ما المفهوم الذي تريد استكشافه؟","Which concept do you want to explore?"))
        if not concept:
            return
        self.ui.section(self._t(f"🧭 استكشاف مفهوم: {concept}", f"🧭 Exploring concept: {concept}"))

        if not relevance_engine.is_index_current(self.kb):
            self.ui.warning(self._t(
            "فهرس الذكاء غير موجود أو لا يطابق الكتب الحالية — شغّل 'إعادة بناء فهرس الذكاء' أولاً.",
            "The intelligence index is missing or out of date — rebuild it first."))
            return

        matches = self.kb.get_concept_matches(concept, limit=8)
        if matches:
            self.ui.subsection(self._t("📚 الكتب التي تناقش هذا المفهوم","📚 Books discussing this concept"))
            self.ui.print_table(
                [self._t("الكتاب","Book"), self._t("وزن الصلة","Relevance weight")],
                [[m["title"], f"{m['weight']:.2f}"] for m in matches]
            )

        passages = relevance_engine.search(concept, self.kb, top_k=5)
        passages = [p for p in passages if "error" not in p]
        if passages:
            self.ui.subsection(self._t("📖 أفضل المقاطع صلةً (من كل المكتبة دفعة واحدة)",
                                          "📖 Most relevant passages (across the whole library at once)"))
            for p in passages[:5]:
                loc = f" ({p['page_hint']})" if p.get("page_hint") else ""
                self.ui.info(f"  📄 «{p['title']}»{loc} — {self._t('صلة','relevance')}: {p['relevance']}")
                self.ui.raw(f"     {p['content'][:220].strip()}…")

            combined = " ".join(p["content"] for p in passages)
            summary_sentences = relevance_engine.extractive_summary(combined, n_sentences=4)
            if summary_sentences:
                self.ui.subsection(self._t(
                    "🧩 خلاصة مبنية من هذه المقاطع تحديداً (جمل حقيقية مُستخلَصة، لا توليد حر)",
                    "🧩 Summary built from these passages specifically (extracted real sentences, not generated)"))
                for s in summary_sentences:
                    self.ui.raw(f"  • {s}")
        else:
            self.ui.warning(self._t(
                f"لم أجد مقاطع ذات صلة إحصائية كافية بـ '{concept}' في مكتبتك.",
                f"No statistically relevant passages found for '{concept}' in your library."))

        neighbors = self.kb.get_concept_neighbors(concept, limit=6)
        if neighbors:
            self.ui.subsection(self._t("🔗 مفاهيم مرتبطة (تتكرر معه في نفس الكتب)",
                                          "🔗 Related concepts (co-occur in the same books)"))
            self.ui.raw("  " + "  |  ".join(f"{n['neighbor']} ({n['weight']:.0f})" for n in neighbors))

    def _concept_link(self, concept_a: str, concept_b: str):
        """يفحص إن كان مفهومان مرتبطين فعلياً عبر مكتبتك: هل يتكرران معاً
        كأهم مصطلحات لنفس الكتب (خريطة المفاهيم)؟ وما المقاطع المحددة
        (إن وُجدت) التي تذكرهما معاً؟"""
        if not concept_a:
            concept_a = self.ui.ask(self._t("المفهوم الأول","First concept"))
        if not concept_b:
            concept_b = self.ui.ask(self._t("المفهوم الثاني","Second concept"))
        if not concept_a or not concept_b:
            return
        self.ui.section(self._t(f"🔗 الرابط بين: {concept_a} ↔ {concept_b}", f"🔗 Link between: {concept_a} ↔ {concept_b}"))

        if not relevance_engine.is_index_current(self.kb):
            self.ui.warning(self._t(
            "فهرس الذكاء غير موجود أو لا يطابق الكتب الحالية — شغّل 'إعادة بناء فهرس الذكاء' أولاً.",
            "The intelligence index is missing or out of date — rebuild it first."))
            return

        link = self.kb.get_direct_concept_link(concept_a, concept_b)
        if link["linked"]:
            self.ui.success(self._t(
                f"✅ مرتبطان مباشرة في خريطة المفاهيم (وزن: {link['weight']:.0f}) — "
                f"يتكرران معاً كأهم مصطلحات في نفس الكتب.",
                f"✅ Directly linked in the concept graph (weight: {link['weight']:.0f}) — "
                f"they co-occur as top terms in the same books."))
        else:
            self.ui.info(self._t(
                "ℹ️ غير مرتبطين مباشرة في خريطة المفاهيم (لا يظهران معاً كأهم مصطلحات لنفس كتاب) — "
                "قد يظهران معاً في فقرات محددة رغم ذلك، أبحث الآن...",
                "ℹ️ Not directly linked in the concept graph — checking for passages mentioning both anyway..."))

        passages = relevance_engine.search(f"{concept_a} {concept_b}", self.kb, top_k=5)
        passages = [p for p in passages if "error" not in p]
        if passages:
            self.ui.subsection(self._t("📖 مقاطع تذكر الاثنين معاً (أو قريباً منهما)",
                                          "📖 Passages mentioning both (or closely related)"))
            for p in passages[:4]:
                loc = f" ({p['page_hint']})" if p.get("page_hint") else ""
                self.ui.info(f"  📄 «{p['title']}»{loc} — {self._t('صلة','relevance')}: {p['relevance']}")
                self.ui.raw(f"     {p['content'][:220].strip()}…")
        else:
            self.ui.warning(self._t("لم أجد أي مقطع يربط بينهما مباشرة في مكتبتك.",
                                      "Found no passage directly linking them in your library."))

    def _summarize_doc(self, book_title: str):
        """ملخص استخلاصي حقيقي (جمل موجودة فعلاً في الكتاب، عبر TextRank)
        لكتاب مُستوعَب مسبقاً — يعمل حتى بدون تشغيل 'إعادة بناء فهرس
        الذكاء' أولاً، لأنه يُحسَب من نص الكتاب نفسه مباشرة عند الطلب."""
        if not book_title:
            book_title = self.ui.ask(self._t("اسم الكتاب (أو جزء منه)","Book name (or part of it)"))
        if not book_title:
            return
        doc = self.kb.find_document_by_title(book_title)
        if not doc:
            self.ui.warning(self._t(f"لم أجد كتاباً بعنوان يشبه '{book_title}' في مكتبتك.",
                                      f"No book matching '{book_title}' found in your library."))
            return

        self.ui.section(self._t(f"📋 ملخص: {doc['title']}", f"📋 Summary: {doc['title']}"))
        cached = self.kb.get_document_summary(doc["id"])
        if cached:
            sentences = cached.split(". ")
            self.ui.raw(cached)
        else:
            with self.ui.spinner(self._t("استخلاص أهم الجمل من الكتاب...","Extracting key sentences from the book...")):
                pass
            full_text = self.kb.get_doc_full_text(doc["id"])
            sentences = relevance_engine.extractive_summary(full_text, n_sentences=8)
            if sentences:
                summary = " ".join(sentences)
                self.kb.save_document_summary(doc["id"], summary)
                self.kb.commit()
                self.ui.raw(summary)
            else:
                self.ui.warning(self._t("الكتاب قصير جداً أو فارغ لاستخلاص ملخص منه.",
                                          "Book is too short or empty to extract a summary from."))
                return

        self.ui.info(self._t(
            "ℹ️ هذه جمل حقيقية مُستخلَصة من نص الكتاب مباشرة (TextRank) — وليست ملخصاً مُعاد صياغته.",
            "ℹ️ These are real sentences extracted directly from the book (TextRank) — not a rewritten summary."))

        tools = self.kb.list_known_tools_in_library()
        if tools:
            self.ui.subsection(self._t("🔧 أدوات اكتشفتها في كتبك:", "🔧 Tools discovered in your books:"))
            self.ui.print_table(
                [self._t("الأداة","Tool"), self._t("الفئة","Category"), self._t("مرات الذكر","Mentions"), self._t("أوامر مستخرجة","Commands")],
                [[t["tool_name"], t["category"], t["mentions"], t["commands"]] for t in tools[:15]]
            )

    def _ping_host(self, target: str):
        self.ui.section(self._t("📡 اختبار اتصال (ping)", "📡 Ping test"))
        if not target:
            target = self.ui.ask(self._t("الهدف (IP أو نطاق)", "Target (IP or domain)"))
        if not target:
            return
        with self.ui.spinner(self._t(f"أختبر الاتصال بـ {target}...", f"Pinging {target}...")):
            result = network.ping_host(target)
        if result.get("error"):
            self.ui.error(result["error"])
            return
        if result["reachable"]:
            self.ui.success(self._t(f"✅ {target} يستجيب.", f"✅ {target} is reachable."))
        else:
            self.ui.warning(self._t(
                f"⚠️ {target} لا يستجيب (أو يحظر ICMP، وهذا شائع ومقصود أحياناً كإجراء أمني).",
                f"⚠️ {target} did not respond (or blocks ICMP — sometimes an intentional security measure)."
            ))
        if result.get("output"):
            self.ui.raw(result["output"], style="green" if result["reachable"] else "yellow")

    # ─────────────────────────────────────────────────────────────────────────
    #  AGENT STATUS — يعرّف بنفسه
    # ─────────────────────────────────────────────────────────────────────────

    def _agent_status(self):
        self.ui.section(self._t("🤖 حالة الوكيل", "🤖 Agent Status"))
        self.ui.banner(context=self.ctx)
        self.ui.dashboard(context=self.ctx, kb_stats=self.kb.get_stats())
        self.ui.show_event_stream(n=10)

        # Who am I
        self.ui.chat_agent(self.ctx.who_am_i(), intent="STATUS")

        # KB stats
        stats = self.kb.get_stats()
        self.ui.print_tree({
            "قاعدة المعرفة": f"{stats['knowledge_entries']} سجل",
            "محادثات محفوظة": str(stats['conversations']),
            "فحوصات مخزّنة": str(stats['scans_cached']),
            "أنماط أخطاء": str(stats['error_patterns']),
            "تحسينات منتظرة": str(stats['pending_improvements']),
            "حجم قاعدة البيانات": f"{stats['db_size_mb']} MB / 1024 MB",
        }, "📊 إحصائيات الوكيل")

        # Diagnostics
        diag = self.healer.full_diagnostics()
        rows = []
        for k, v in diag.items():
            status = v.get("status","?")
            value  = v.get("value","")
            icon   = "✅" if status == "ok" else "⚠️ " if status == "warning" else "❌"
            rows.append([icon, k, value])
        self.ui.print_table(["", "Component", "Status"], rows, title="🔬 تشخيص الوكيل")

    # ─────────────────────────────────────────────────────────────────────────
    #  AGENT SELF-UPDATE — يقترح ما يحتاجه ليتطور
    # ─────────────────────────────────────────────────────────────────────────

    def _agent_self_update(self):
        self.ui.section(self._t("🔄 تحديث ذاتي لقاعدة المعرفة", "🔄 Agent Self-Update"))
        self.ui.info(self._t(
            "الوكيل يحلل ما يحتاجه للتطور...",
            "Agent is analyzing what it needs to improve..."
        ))

        # Check pending improvements
        pending = self.kb.get_pending_improvements()
        if pending:
            self.ui.info(self._t(
                f"وُجد {len(pending)} اقتراح تحسين منتظر:",
                f"Found {len(pending)} pending improvements:"
            ))
            for imp in pending:
                self.ui.show_improvement(imp)
                if self.ui.confirm(self._t(f"الموافقة على: {imp['description'][:60]}?",
                                           f"Approve: {imp['description'][:60]}?"), False):
                    self.kb.approve_improvement(imp["id"])
                    self.kb.apply_improvement(imp["id"])
                    self.ui.success(self._t("✅ تم تطبيق التحسين وإضافته لقاعدة المعرفة",
                                            "✅ Improvement applied to knowledge base"))
        else:
            self.ui.info(self._t("لا توجد تحسينات معلّقة حالياً.", "No pending improvements."))

        # Propose new knowledge from internet if connected
        conn = web.check_connectivity()
        if conn["connected"]:
            self.ui.info(self._t("الوكيل يفحص أحدث CVEs ليتعلمها...", "Agent fetching latest CVEs to learn..."))
            kev = web.get_cisa_known_exploited(max_results=5)
            added = 0
            for v in kev:
                if "error" not in v:
                    cve_id = v.get("cve_id","")
                    product = v.get("product","")
                    vendor  = v.get("vendor","")
                    desc = f"{vendor} {product} — أضيفت لقائمة CISA: {v.get('date_added','')}"
                    self.kb.add_knowledge("cve_live", cve_id, desc, source="cisa_kev")
                    added += 1

            if added:
                self.kb.log_update("CISA_KEV", added, f"أضاف {added} CVE حديث من CISA")
                self.ui.success(self._t(
                    f"✅ تعلّم الوكيل {added} ثغرة جديدة من CISA",
                    f"✅ Agent learned {added} new CVEs from CISA"
                ))

            # Propose learning from GitHub trending tools
            if self.settings.get("github_token"):
                tools = self.github.get_trending_security_tools(days_back=7, max_results=3)
                for t in tools:
                    self.kb.propose_improvement(
                        category="knowledge",
                        description=f"أداة أمنية جديدة: {t['name']}",
                        data={
                            "category": "tool",
                            "key": t["name"].split("/")[-1],
                            "content": t.get("description","") or f"أداة أمنية GitHub: {t['name']}"
                        }
                    )
                if tools:
                    self.ui.info(self._t(
                        f"اقترح الوكيل {len(tools)} أداة جديدة — راجعها في المرة القادمة",
                        f"Proposed {len(tools)} new tools for review"
                    ))
        else:
            self.ui.warning(self._t("لا اتصال بالإنترنت — التحديث المحلي فقط", "No internet — local update only"))

        self.ui.success(self._t("✅ اكتمل التحديث الذاتي", "✅ Self-update complete"))

    # ─────────────────────────────────────────────────────────────────────────
    #  HELP
    # ─────────────────────────────────────────────────────────────────────────

    def _show_help(self):
        self.ui.section(self._t("📋 دليل الأوامر", "📋 Command Guide"))
        help_text = self._t("""
يمكنك كتابة أي من هذه الأوامر أو ما يشبهها بكلماتك:

  🌐 NETWORK:
     افحص الشبكة  |  scan network  |  شبكة  |  اتصالات
     افحص المنافذ  |  scan ports 192.168.1.1
     فحص ip 8.8.8.8  |  check ip 1.2.3.4
     جدار الحماية  |  firewall

  🔌 USB & DEVICES:
     USB  |  يو اس بي  |  فلاشة  |  هاتف  |  أجهزة

  🖥️ SYSTEM:
     فحص النظام  |  scan system  |  نظام
     سجلات  |  logs  |  تحليل سجلات

  🌍 WEB & CVE:
     افحص موقع https://example.com
     CVE-2024-1234  |  ثغرات linux  |  cve search
     ثغرات حزمة requests  |  package vulnerabilities django  (بحث OSV.dev)

  📈 تطوّر الوضع (جديد):
     تطور الوضع الأمني  |  قارن بالفحص السابق  |  scan trend

  🐙 GITHUB:
     github  |  أدوات  |  تقرير

  📖 EXPLAIN:
     اشرح brute force  |  ما هو nmap  |  explain SQL injection
     ما هو منفذ 22  |  what is port 443

  🤖 AGENT:
     حالة الوكيل  |  agent status  |  كيف حالك
     تحديث قاعدة البيانات  |  update knowledge

  🔍 SEARCH:
     ابحث عن تقنية X  |  search for Y

  🧠 LEARNING (v4 — محرك ذكاء محلي حقيقي):
     تعلم من ملف /path/to/book.pdf  |  تعلم من كتاب ~/book.txt
     تعلم أن <حقيقة تريد أن أتذكرها>
     ماذا تعلمت؟  |  مكتبتك
     إعادة بناء فهرس الذكاء   (بعد إضافة كل كتبك — مرة واحدة)
     اشرح مفهوم <شيء>   (بحث مُرتَّب بالصلة عبر كل الكتب، لا حرفياً فقط)
     اربط بين <X> و <Y>   (هل يظهران معاً في نفس الكتب؟)
     لخص كتاب <اسم>   (ملخص استخلاصي حقيقي — جمل من الكتاب نفسه)

  ⚙️  CONFIG:
     إعدادات  |  settings  |  config
""", """
You can type any of these or anything similar in plain language:

  🌐 NETWORK:    scan network | ports | firewall | check ip 1.2.3.4
  🔌 USB:        usb | flash drive | android phone | devices
  🖥️ SYSTEM:     scan system | logs | analyze logs
  🌍 WEB/CVE:    scan website https://... | CVE-2024-1234 | cve search | package vulnerabilities django
  📈 TREND:      security trend | compare last scan
  🐙 GITHUB:     github | tools | push report
  📖 EXPLAIN:    explain brute force | what is nmap | what is port 22
  🤖 AGENT:      agent status | update knowledge | how are you
  🔍 SEARCH:     search for X | find info about Y
  🧠 LEARNING:   learn from file /path/book.pdf | remember that <fact> | what have you learned?
  🧠 INTELLIGENCE (v4): rebuild intelligence index | explain concept X | link X and Y | summarize book <name>
  ⚙️ CONFIG:     settings | config
  🚪 EXIT:       exit | quit | خروج
""")
        self.ui.chat_agent(help_text, intent="HELP")

    # ─────────────────────────────────────────────────────────────────────────
    #  NETWORK SCAN
    # ─────────────────────────────────────────────────────────────────────────

    def _scan_network(self):
        self.ui.section(self._t("🌐 فحص الشبكة الذكي", "🌐 Smart Network Scan"))
        with self.ui.spinner(self._t("تحليل الشبكة...", "Analyzing network...")):
            pass

        ifaces = network.get_network_interfaces()
        rows = [[i.get("name",""), i.get("state",""), ", ".join(i.get("addresses",[])[:2])] for i in ifaces]
        self.ui.print_table(["Interface", "State", "Addresses"], rows)

        connections = network.get_active_connections()
        trusted    = [c for c in connections if c["trust"] == "trusted"]
        suspicious = [c for c in connections if c["trust"] == "suspicious"]
        unknown    = [c for c in connections if c["trust"] == "unknown"]

        self.ui.info(self._t(
            f"موثوق: {len(trusted)} | مشبوه: {len(suspicious)} | يحتاج مراجعة: {len(unknown)}",
            f"Trusted: {len(trusted)} | Suspicious: {len(suspicious)} | Review: {len(unknown)}"
        ))
        review_conns = suspicious + unknown
        if review_conns:
            rows = [[c["proto"], c["local"], c["remote"], c["process"], c["risk"], c["reason"][:35]] for c in review_conns]
            self.ui.print_table(["Proto","Local","Remote","Process","Risk","Reason"], rows,
                                title=self._t("اتصالات تحتاج مراجعة","Connections to Review"))
        else:
            self.ui.success(self._t("✅ جميع الاتصالات موثوقة","✅ All connections trusted"))

        leak = network.check_data_leaks()
        fw   = network.check_firewall()
        self.ui.info(self._t(
            f"UFW: {'🟢 مُفعَّل' if fw['enabled'] else '🔴 معطَّل'}",
            f"UFW: {'🟢 Active' if fw['enabled'] else '🔴 Disabled'}"
        ))

        wifi = network.get_wifi_networks()
        if wifi:
            rows = [[w.get("ssid","?"), w.get("security","?"), "✓" if w.get("in_use") else " ", w.get("risk","low")] for w in wifi]
            self.ui.print_table(["SSID","Security","Connected","Risk"], rows)

        all_findings = self.intel.aggregate_findings(leak, fw)
        all_findings = self.intel.correlate_findings(all_findings)
        all_findings += self.intel.detect_compound_risks(all_findings)
        # ── Attack Chain Analysis: cross-domain correlation ──
        attack_chains = self.correlation.analyze(all_findings)
        all_findings.extend(attack_chains)
        self.ui.section(self._t("النتائج","Findings"))
        for f in all_findings:
            self.ui.print_finding(f["severity"], f["title"], f.get("detail",""), f.get("fix",""))
        if not all_findings:
            self.ui.success(self._t("🟢 الشبكة نظيفة","🟢 Network looks clean"))

        risk = self.intel.compute_risk_score(all_findings)
        self.ui.raw(self.intel.generate_summary(risk, all_findings, self._t("فحص الشبكة","Network Scan")), style=_risk_border_style(risk["level"]))
        self._last_findings = all_findings
        self._save_and_show_trend("network", risk, all_findings)

        if all_findings:
            report = generate_markdown_report({"risk": risk, "findings": all_findings, "sections": {}}, self._hostname, self.lang)
            self._ask_save_report(report)
        return all_findings

    def _check_firewall(self):
        self.ui.section(self._t("🔥 جدار الحماية","🔥 Firewall"))
        fw = network.check_firewall()
        self.ui.info(self._t(
            f"UFW: {'🟢 مُفعَّل' if fw['enabled'] else '🔴 معطَّل'} | الإصدار: {fw.get('version','')}",
            f"UFW: {'🟢 Active' if fw['enabled'] else '🔴 Disabled'} | Version: {fw.get('version','')}"
        ))
        for rule in fw.get("rules", [])[:10]:
            self.ui.info(f"  {rule}")
        for f in fw.get("findings", []):
            self.ui.print_finding(f["severity"], f["title"], f.get("detail",""), f.get("fix",""))

    def _wifi_status(self):
        self.ui.section(self._t("📶 WiFi","📶 WiFi"))
        wifi = network.get_wifi_networks()
        if wifi:
            rows = [[w.get("ssid","?"), w.get("security","?"), "✓" if w.get("in_use") else "", w.get("risk","low")] for w in wifi]
            self.ui.print_table(["SSID","Security","Active","Risk"], rows)
        else:
            self.ui.warning(self._t("لا شبكات WiFi مكتشفة","No WiFi networks found"))

    # ─────────────────────────────────────────────────────────────────────────
    #  PORT SCAN
    # ─────────────────────────────────────────────────────────────────────────

    def _scan_ports(self, target: str, port_range: str = None):
        if not target or target == "127.0.0.1":
            target = self.ui.ask(self._t("IP أو hostname","IP or hostname"), default="127.0.0.1")
        self.ui.section(self._t(f"🔍 فحص المنافذ: {target}", f"🔍 Port Scan: {target}"))
        if port_range is None:
            port_range = self.ui.ask(self._t("نطاق المنافذ","Port range"), default="1-1024")
        with self.ui.spinner(self._t(f"فحص {port_range}...", f"Scanning {port_range}...")):
            pass
        result = network.scan_ports(target, port_range)
        open_ports = result.get("open_ports",[])
        self.ui.info(self._t(f"الأداة: {result['tool_used']} | مفتوح: {len(open_ports)}",
                             f"Tool: {result['tool_used']} | Open: {len(open_ports)}"))
        if open_ports:
            rows = [[p["port"], p["state"], p["service"], p["risk"]] for p in open_ports]
            self.ui.print_table(["Port","State","Service","Risk"], rows,
                                title=self._t("المنافذ المفتوحة","Open Ports"))

            # Explain any suspicious ports from KB
            for p in open_ports:
                if p.get("risk") in ("high","critical"):
                    kb_info = self.kb.lookup("port", str(p["port"]))
                    if kb_info:
                        self.ui.info(f"  📖 منفذ {p['port']}: {kb_info}")
        findings = result.get("findings", [])
        self._last_findings = findings
        for f in findings:
            self.ui.print_finding(f["severity"], f["title"], f.get("detail",""), f.get("fix",""))

        from brain.narrator import narrate_findings
        narration = narrate_findings(findings,
                                      self._t(f"فحص المنافذ لـ {target}", f"port scan of {target}"), self.lang)
        self.ui.info(f"💬 {narration}")
        return findings

    # ─────────────────────────────────────────────────────────────────────────
    #  USB CONTROL CENTER
    # ─────────────────────────────────────────────────────────────────────────

    def _usb_control_center(self):
        self.ui.section(self._t("🔌 مركز تحكم USB","🔌 USB Control Center"))
        while True:
            devices = list_usb_devices()
            if not devices:
                self.ui.warning(self._t("لا توجد أجهزة USB","No USB devices found"))
                return
            enhanced = []
            for dev in devices:
                dev_type = detect_device_type(dev)
                dev["type"] = dev_type
                dev["type_ar"] = DEVICE_TYPE_DESCRIPTIONS.get(dev_type, {}).get("desc_ar", dev_type)
                enhanced.append(dev)
            rows = [[str(i+1), f"{d.get('bus','')}/{d.get('device','')}",
                     d.get("vendor_id",""), d.get("product","") or d.get("description",""),
                     d["type_ar"], d.get("risk","low")] for i, d in enumerate(enhanced)]
            self.ui.print_table(["#","Bus/Dev","VID","Product","النوع","Risk"], rows,
                                title=self._t("الأجهزة المتصلة","Connected Devices"))
            choice = self.ui.ask(self._t("اختر جهاز (#) أو [0] رجوع","Choose device (#) or [0] back"), default="0")
            if choice in ("0",""):
                break
            if choice.lower() == "r":
                continue
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(enhanced):
                    self._device_control_menu(enhanced[idx])
            except ValueError:
                self.ui.warning(self._t("أدخل رقماً","Enter a number"))

    def _device_control_menu(self, device: dict):
        dev_type = device.get("type","Unknown")
        name = device.get("product") or device.get("description") or "Unknown"
        self.ui.section(self._t(f"🎮 تحكم: {name}",f"🎮 Control: {name}"))
        self.ui.print_tree({
            "Product": name, "Type": device.get("type_ar", dev_type),
            "Vendor ID": device.get("vendor_id",""), "Risk": device.get("risk","low"),
            "Flags": " | ".join(device.get("flags",[])) or "None",
        }, self._t("معلومات الجهاز","Device Info"))

        options = [
            ("1","allow",   self._t("تفعيل","Allow")),
            ("2","block",   self._t("حجب","Block")),
            ("3","info",    self._t("معلومات","Info")),
        ]
        type_opts = {
            "Storage": [("4","deep_scan",self._t("فحص عميق","Deep scan")),
                        ("5","fix_flash",self._t("إصلاح الفلاشة","Fix flash")),
                        ("6","eject",    self._t("إخراج آمن","Safe eject"))],
            "Phone":   [("4","diagnose",self._t("تشخيص","Diagnose")),
                        ("5","files",   self._t("ملفات","Files")),
                        ("6","apps",    self._t("تطبيقات","Apps"))],
            "WiFi":    [("4","wifi_control",self._t("تحكم WiFi","WiFi control"))],
            "Bluetooth":[("4","bt_scan",self._t("فحص BT","BT scan"))],
        }
        all_opts = options + type_opts.get(dev_type,[]) + [("0","back",self._t("رجوع","Back"))]
        self.ui.print_table(["#","Action","Description"], all_opts)
        action = self.ui.ask(self._t("اختر","Choose"), default="0")
        for num, key, _ in all_opts:
            if action == num or action.lower() == key:
                action = key
                break

        if action == "allow":
            res = authorize_device(device.get("bus",""), device.get("device",""))
            self.ui.success(self._t("تم تفعيل الجهاز","Device authorized")) if res.get("success") else self.ui.error(res.get("error",""))
        elif action == "block":
            res = deauthorize_device(device.get("bus",""), device.get("device",""))
            self.ui.success(self._t("تم حجب الجهاز","Device blocked")) if res.get("success") else self.ui.error(res.get("error",""))
        elif action == "deep_scan":
            self._deep_scan_storage(device)
        elif action == "fix_flash":
            self._fix_flash_drive(device)
        elif action == "eject":
            ok, dev_path, _ = _run("lsblk -o NAME,TRAN | awk '/usb/{print \"/dev/\"$1}' | head -1")
            if dev_path:
                result = eject_storage_device(dev_path)
                self.ui.success(self._t("تم الإخراج الآمن","Safe ejected")) if result["success"] else self.ui.error("")
        elif action == "diagnose":
            self._diagnose_phone(device)
        elif action == "wifi_control":
            self._wifi_control_menu()

    def _deep_scan_storage(self, device: dict):
        self.ui.section(self._t("🔍 فحص عميق للتخزين","🔍 Deep Storage Scan"))
        drives = scan_mounted_drives()
        for d in drives:
            if d.get("is_usb"):
                for p in d.get("partitions",[]):
                    mp = p.get("mountpoint","")
                    if mp:
                        analysis = p.get("analysis", {})
                        self.ui.info(self._t(
                            f"مجلد: {mp} | ملفات: {analysis.get('total_files_checked',0)} | مشبوه: {len(analysis.get('suspicious_files',[]))}",
                            f"Mount: {mp} | Files: {analysis.get('total_files_checked',0)} | Suspicious: {len(analysis.get('suspicious_files',[]))}"
                        ))
                        for f in analysis.get("findings",[]):
                            self.ui.print_finding(f["severity"], f["title"], f.get("detail",""), f.get("fix",""))

    def _fix_flash_drive(self, device: dict):
        self.ui.section(self._t("🔧 إصلاح الفلاشة","🔧 Fix Flash Drive"))
        ok, path, _ = _run("lsblk -o NAME,TRAN | awk '/usb/{print \"/dev/\"$1}' | head -1")
        path = (path or "").strip().split("\n")[0]
        if not path:
            self.ui.warning(self._t("لم يتم العثور على مسار الجهاز","Device path not found"))
            return
        # Gather findings from a deep scan before attempting repairs
        findings = []
        try:
            scan_result = deep_scan_flash(path)
            findings = scan_result.get("findings", []) if isinstance(scan_result, dict) else []
        except Exception:
            findings = []
        result = fix_flash_issues(path, findings)
        if result.get("success"):
            self.ui.success(self._t("تم الإصلاح","Fixed"))
        for step in result.get("steps",[]):
            self.ui.info(f"  {'✅' if step.get('ok') else '❌'} {step.get('cmd','')}")

    def _diagnose_phone(self, device: dict):
        self.ui.section(self._t("📱 تشخيص الهاتف","📱 Phone Diagnosis"))
        ok, out, _ = _run("adb devices 2>/dev/null")
        if "device" not in out:
            self.ui.warning(self._t("لا هاتف مُتصل عبر ADB","No phone connected via ADB"))
            return
        serial = None
        for line in out.split("\n")[1:]:
            if "\t" in line and "device" in line:
                serial = line.split("\t")[0].strip()
                break
        if not serial:
            return
        result = diagnose_android_phone(serial)
        self.ui.print_tree(result.get("info",{}), self._t("تفاصيل الهاتف","Phone Details"))
        for f in result.get("findings",[]):
            self.ui.print_finding(f["severity"], f["title"], f.get("detail",""), f.get("fix",""))

    def _get_phone_serial(self, device: dict) -> str:
        ok, out, _ = _run("adb devices 2>/dev/null")
        for line in out.split("\n")[1:]:
            if "\t" in line and "device" in line:
                return line.split("\t")[0].strip()
        return ""

    def _wifi_control_menu(self):
        adapters = get_wifi_adapters()
        if not adapters:
            self.ui.warning(self._t("لا محوّلات WiFi","No WiFi adapters"))
            return
        iface = adapters[0]["interface"]
        actions = [("1","enable","تشغيل"),("2","disable","إيقاف"),
                   ("3","scan","فحص"),("0","back","رجوع")]
        self.ui.print_table(["#","Action","Description"], actions)
        choice = self.ui.ask(self._t("اختر","Choose"), default="0")
        mapping = {"1":"enable","2":"disable","3":"scan"}
        action = mapping.get(choice, choice)
        if action not in ("back","0"):
            res = wifi_adapter_control(iface, action)
            if res.get("success"):
                self.ui.success(f"✅ {action} on {iface}")
            elif res.get("out"):
                self.ui.raw(res["out"][:300])

    # ─────────────────────────────────────────────────────────────────────────
    #  SYSTEM SCAN
    # ─────────────────────────────────────────────────────────────────────────

    def _scan_system(self):
        self.ui.section(self._t("🖥️ فحص النظام الذكي","🖥️ Smart System Scan"))
        sysinfo = system.get_system_info()
        self.ui.print_tree({
            "Hostname": sysinfo.get("hostname",""), "OS": sysinfo.get("os",""),
            "Kernel": sysinfo.get("kernel",""), "Uptime": sysinfo.get("uptime",""),
            "CPU": sysinfo.get("cpu",""), "RAM": sysinfo.get("ram",""),
        }, self._t("معلومات النظام","System Info"))

        checks = [
            (self._t("SUID","SUID files"),        system.check_suid_files),
            (self._t("Cron","Cron jobs"),          system.check_crontabs),
            (self._t("عمليات","Processes"),        system.check_running_processes),
            (self._t("مستخدمون","Users"),          system.check_users_and_groups),
            (self._t("SSH","SSH config"),           system.check_ssh_config),
            (self._t("تحديثات","Updates"),         system.get_installed_packages_vulnerabilities),
            (self._t("ملفات","World-writable"),    system.check_world_writable),
        ]
        all_findings = []
        for label, fn in checks:
            self.ui.info(f"  🔍 {label}...")
            try:
                r = fn()
                all_findings.extend(r.get("findings",[]))
            except Exception as e:
                self.ui.warning(f"  {label}: {e}")

        # ربط تلقائي بين حزم النظام القابلة للترقية وقاعدة CVE/CISA KEV
        try:
            self.ui.info(f"  🔍 {self._t('مطابقة الحزم مع قاعدة CVE','Cross-checking packages against CVE database')}...")
            pkg_check = system.list_upgradable_security_packages()
            cve_findings = self._enrich_packages_with_cve(pkg_check.get("packages", []))
            all_findings.extend(cve_findings)
        except Exception as e:
            self.ui.warning(f"  CVE cross-check: {e}")

        all_findings = self.intel.correlate_findings(all_findings)
        all_findings += self.intel.detect_compound_risks(all_findings)
        # ── Attack Chain Analysis: cross-domain correlation ──
        attack_chains = self.correlation.analyze(all_findings)
        all_findings.extend(attack_chains)
        risk = self.intel.compute_risk_score(all_findings)
        self.ui.section(self._t("النتائج","Findings"))
        for f in all_findings:
            self.ui.print_finding(f["severity"], f["title"], f.get("detail",""), f.get("fix",""))
        if not all_findings:
            self.ui.success(self._t("🟢 النظام يبدو آمناً","🟢 System looks secure"))

        self.ui.raw(self.intel.get_remediation_plan(all_findings))
        # ── Smart Remediation Prioritization ──
        self.ui.raw(SmartRemediationAdvisor.format_recommendations(all_findings, top_n=5))
        self.ui.raw(self.intel.generate_summary(risk, all_findings, self._t("فحص النظام","System Scan")), style=_risk_border_style(risk["level"]))
        self._last_findings = all_findings
        self._save_and_show_trend("system", risk, all_findings)

        if all_findings:
            report = generate_markdown_report({"risk": risk, "findings": all_findings, "sections":{"sysinfo":sysinfo}}, self._hostname, self.lang)
            self._ask_save_report(report)
        return all_findings

    # ─────────────────────────────────────────────────────────────────────────
    #  LOG ANALYSIS
    # ─────────────────────────────────────────────────────────────────────────

    def _scan_logs(self):
        self.ui.section(self._t("📋 تحليل السجلات","📋 Log Analysis"))
        with self.ui.spinner(self._t("تحليل السجلات...","Analyzing logs...")):
            pass
        logs = system.analyze_logs()
        all_findings = self.intel.aggregate_findings(logs)
        all_findings = self.intel.correlate_findings(all_findings)
        all_findings += self.intel.detect_compound_risks(all_findings)

        if logs.get("brute_force_ips"):
            rows = [[ip, str(c)] for ip, c in sorted(logs["brute_force_ips"].items(), key=lambda x:-x[1])[:10]]
            self.ui.print_table(["IP Address","Attempts"], rows)
            for ip, count in logs["brute_force_ips"].items():
                if count >= 10 and self.ui.confirm(self._t(f"حجب {ip} ({count} محاولة)?",f"Ban {ip} ({count} attempts)?"), False):
                    res = apply_fix("ban_ip", ip=ip)
                    self.ui.success(self._t(f"تم حجب {ip}",f"Banned {ip}")) if res["success"] else self.ui.error(res.get("error",""))

        for f in all_findings:
            self.ui.print_finding(f["severity"], f["title"], f.get("detail",""), f.get("fix",""))
        if not all_findings:
            self.ui.success(self._t("🟢 السجلات نظيفة","🟢 Logs are clean"))

        risk = self.intel.compute_risk_score(all_findings)
        self.ui.raw(self.intel.generate_summary(risk, all_findings, self._t("تحليل السجلات","Log Analysis")), style=_risk_border_style(risk["level"]))
        self._last_findings = all_findings
        self._save_and_show_trend("logs", risk, all_findings)
        return all_findings

    # ─────────────────────────────────────────────────────────────────────────
    #  WEBSITE SECURITY TEST
    # ─────────────────────────────────────────────────────────────────────────

    def _test_website(self, url: str):
        if not url:
            url = self.ui.ask(self._t("رابط الموقع","Website URL"))
        if not url.startswith("http"):
            url = "https://" + url
        self.ui.section(self._t(f"🌐 فحص الموقع: {url}",f"🌐 Website Scan: {url}"))
        with self.ui.spinner(self._t("فحص...","Scanning...")):
            pass
        result = web.test_website_security(url)
        if not result.get("reachable"):
            self.ui.error(self._t("الموقع غير متاح","Website not reachable"))
            self._last_findings = []
            return []
        self.ui.print_tree({
            "URL": result.get("final_url",url), "Status": result.get("status_code",""),
            "Server": result.get("server","?"), "Response": f"{result.get('response_time_ms','?')}ms",
            "Grade": result.get("grade","?"), "Score": f"{result.get('score','?')}/100",
        }, self._t("نتيجة الفحص","Scan Result"))
        ssl_info = result.get("ssl",{})
        if ssl_info and not ssl_info.get("error"):
            self.ui.info(self._t(
                f"🔒 SSL: صالح {ssl_info.get('days_left','?')} يوم",
                f"🔒 SSL: Valid {ssl_info.get('days_left','?')} days"
            ))
        if result.get("missing_headers"):
            self.ui.info(self._t(
                f"⚠️  رؤوس مفقودة: {', '.join(result['missing_headers'])}",
                f"⚠️  Missing headers: {', '.join(result['missing_headers'])}"
            ))
        findings = result.get("findings", [])
        self._last_findings = findings
        for f in findings:
            self.ui.print_finding(f["severity"], f["title"], f.get("detail",""), f.get("fix",""))
        if self.ui.confirm(self._t("فتح في المتصفح؟","Open in browser?"), False):
            web.open_browser(url)
        return findings

    # ─────────────────────────────────────────────────────────────────────────
    #  CVE SEARCH
    # ─────────────────────────────────────────────────────────────────────────

    def _cve_search(self, keyword: str):
        if not keyword:
            keyword = self.ui.ask(self._t("كلمة البحث CVE","CVE keyword"))
        self.ui.section(self._t(f"🔍 بحث CVE: {keyword}",f"🔍 CVE Search: {keyword}"))
        nvd_key = self.settings.get("nvd_api_key", "")

        # Check local KB first
        local = self.kb.search_knowledge(keyword, limit=3)
        if local:
            self.ui.subsection(self._t("من قاعدة المعرفة المحلية","From local knowledge base"))
            for r in local:
                self.ui.info(f"  [{r['category']}|{r['key']}] {r['content'][:120]}")

        # Then NVD
        days = 365
        with self.ui.spinner(self._t("البحث في NVD...","Searching NVD...")):
            pass
        cves = web.search_cve(keyword, days_back=days, api_key=nvd_key)
        valid = [c for c in cves if "error" not in c]

        if not valid:
            self.ui.warning(self._t("لا نتائج من NVD","No CVE results from NVD"))
        else:
            rows = [[c["id"], c.get("severity","?"), str(c.get("cvss_score","?")),
                     c.get("published","?")[:10], c.get("description","")[:65]] for c in valid]
            self.ui.print_table(["CVE ID","Severity","CVSS","Date","Description"], rows, title=f"CVE — {keyword}")

            # Learn from results
            for c in valid[:5]:
                self.kb.add_knowledge("cve_search", c["id"],
                                      f"CVSS:{c.get('cvss_score','?')} | {c.get('description','')[:100]}",
                                      source="nvd")

        # مصدر إضافي: استغلالات معروفة محلياً (Exploit-DB) — يعمل حتى لو NVD لم يُرجع شيئاً
        exploits = web.search_exploitdb(keyword, max_results=5)
        valid_exploits = [e for e in exploits if "error" not in e]
        if valid_exploits:
            self.ui.subsection(self._t("🧨 استغلالات معروفة (Exploit-DB محلي)","🧨 Known exploits (local Exploit-DB)"))
            erows = [[e["edb_id"], e.get("type",""), e.get("platform",""), e.get("description","")[:60]] for e in valid_exploits]
            self.ui.print_table(["EDB-ID","Type","Platform","Description"], erows)
        elif exploits and "error" in exploits[0] and "غير موجود" in exploits[0]["error"]:
            self.ui.info(f"  ℹ️  {self._t('لتفعيل بحث Exploit-DB المحلي شغّل تحديث المعلومات الاستخباراتية أولاً (8)','To enable local Exploit-DB search, run Update Intelligence first (8)')}")

        if not valid and not valid_exploits:
            return

        cve_id = self.ui.ask(self._t("CVE ID للتفاصيل (أو Enter)","CVE ID for details (Enter skip)"), default="")
        if cve_id and cve_id.upper().startswith("CVE"):
            detail = web.get_cve_detail(cve_id.upper(), api_key=nvd_key)
            if "error" not in detail:
                self.ui.print_tree(detail, cve_id.upper())
                # Look up KB explanation
                kb_sev = self.kb.lookup("cve_severity", detail.get("severity","").lower())
                if kb_sev:
                    self.ui.info(f"  📖 {kb_sev}")
            if self.ui.confirm(self._t("فتح في المتصفح؟","Open in browser?"), False):
                web.open_browser(f"https://nvd.nist.gov/vuln/detail/{cve_id.upper()}")

    # ─────────────────────────────────────────────────────────────────────────
    #  GITHUB CENTER
    # ─────────────────────────────────────────────────────────────────────────

    def _github_center(self):
        self.ui.section(self._t("🐙 مركز GitHub","🐙 GitHub Center"))
        token = self.settings.get("github_token","")
        if not token:
            self.ui.warning(self._t("رمز GitHub غير مُعيَّن","GitHub token not set"))
            new_token = self.ui.ask(self._t("أدخل رمزك هنا","Enter token here"), default="")
            if new_token and len(new_token) > 10:
                self.settings.set("github_token", new_token)
                self.github = GitHubTool(token=new_token)
                token = new_token
                self.ui.success(self._t("تم الحفظ!","Saved!"))
            else:
                return

        conn = self.github.test_connection()
        if not conn["success"]:
            self.ui.error(self._t(f"فشل: {conn.get('error','')}",f"Failed: {conn.get('error','')}"))
            return
        self.ui.success(self._t(f"✅ @{conn['username']} | Repos: {conn['public_repos']}",
                                f"✅ @{conn['username']} | Repos: {conn['public_repos']}"))

        options = [
            ("1","trending",   self._t("أدوات أمن رائجة","Trending security tools")),
            ("2","advisories", self._t("تنبيهات الأمن","Security advisories")),
            ("3","cisa_kev",   self._t("CISA الثغرات المستغَلة","CISA Exploited CVEs")),
            ("4","my_repos",   self._t("مستودعاتي","My repos")),
            ("5","push_report",self._t("رفع تقرير","Push report")),
            ("0","back",       self._t("رجوع","Back")),
        ]
        self.ui.print_table(["#","Action","Description"], options)
        choice = self.ui.ask(self._t("اختر","Choose"), default="0")

        if choice in ("1","trending"):
            tools = self.github.get_trending_security_tools(days_back=7)
            if tools:
                rows = [[t["name"], str(t["stars"]), t["language"], t.get("description","")[:55]] for t in tools]
                self.ui.print_table(["Repository","⭐","Language","Description"], rows)
                idx = self.ui.ask(self._t("رقم الأداة لتحليلها","Tool # to analyze"), default="")
                if idx.isdigit() and 0 <= int(idx)-1 < len(tools):
                    info = self.github.analyze_tool(tools[int(idx)-1]["name"])
                    self.ui.print_tree(info, info.get("name",""))
                    self.ui.info(self._t(f"التثبيت: {self.github.suggest_install(info)}",
                                         f"Install: {self.github.suggest_install(info)}"))
        elif choice in ("2","advisories"):
            adv = self.github.get_security_advisories(max_results=10)
            if adv and "error" not in adv[0]:
                rows = [[a.get("id",""), a.get("severity",""), a.get("published","")[:10], a.get("summary","")[:60]] for a in adv]
                self.ui.print_table(["GHSA ID","Severity","Published","Summary"], rows)
        elif choice in ("3","cisa_kev"):
            kev = web.get_cisa_known_exploited(max_results=15)
            if kev and "error" not in kev[0]:
                rows = [[v.get("cve_id",""), v.get("vendor",""), v.get("product",""), v.get("date_added","")[:10]] for v in kev]
                self.ui.print_table(["CVE ID","Vendor","Product","Date Added"], rows)
        elif choice in ("4","my_repos"):
            repos = self.github.get_user_repos()
            rows = [[r["name"], "🔒" if r["private"] else "🌐", r["language"], str(r["stars"]), r["updated"]] for r in repos[:20]]
            self.ui.print_table(["Name","Type","Lang","⭐","Updated"], rows)
        elif choice in ("5","push_report"):
            if self._last_findings:
                risk = self.intel.compute_risk_score(self._last_findings)
                report = generate_markdown_report({"risk": risk, "findings": self._last_findings, "sections":{}}, self._hostname, self.lang)
                self._push_to_github(report)
            else:
                self.ui.warning(self._t("شغّل فحصاً أولاً","Run a scan first"))

    def _push_to_github(self, content: str):
        repos = self.github.get_user_repos()
        ayfam = [r for r in repos if "ayfam" in r["name"].lower() or "security" in r["name"].lower()]
        if ayfam:
            repo_name = ayfam[0]["full_name"]
        else:
            if self.ui.confirm(self._t("إنشاء مستودع AI-AYFAM-Reports?","Create AI-AYFAM-Reports?"), True):
                res = self.github.create_repo("AI-AYFAM-Reports", "Security reports", private=True)
                if res["success"]:
                    repo_name = res["full_name"]
                else:
                    self.ui.error(res.get("error","")); return
            else:
                repo_name = self.ui.ask(self._t("اسم المستودع","Repo name"))
        if repo_name:
            res = self.github.push_report(repo_name, content)
            if res.get("success"):
                self.ui.success(self._t(f"✅ تم الرفع: {res.get('url','')}",f"✅ Pushed: {res.get('url','')}"))
            else:
                self.ui.error(res.get("error",""))

    # ─────────────────────────────────────────────────────────────────────────
    #  WEB SEARCH
    # ─────────────────────────────────────────────────────────────────────────

    def _web_search(self, query: str):
        if not query:
            query = self.ui.ask(self._t("ماذا تريد البحث عنه؟","What to search for?"))
        self.ui.section(self._t(f"🔍 بحث: {query}",f"🔍 Search: {query}"))
        with self.ui.spinner(self._t("البحث في عدة مصادر (DuckDuckGo + Wikipedia)...","Searching multiple sources (DuckDuckGo + Wikipedia)...")):
            pass
        results = web.web_search(query)
        if not results or "error" in results[0]:
            msg = results[0]["error"] if results else self._t("لا نتائج","No results")
            self.ui.warning(msg)
            return
        for i, r in enumerate(results,1):
            self.ui.info(f"\n  [{i}] {r.get('title','')}  [dim]({r.get('source','')})[/dim]")
            if r.get("snippet"):
                self.ui.raw(f"      {r['snippet'][:100]}")
            if r.get("url"):
                self.ui.raw(f"      🔗 {r['url']}")
        choice = self.ui.ask(self._t("فتح رابط؟ (رقم أو Enter)","Open URL? (# or Enter)"), default="")
        if choice.isdigit() and 0 <= int(choice)-1 < len(results) and results[int(choice)-1].get("url"):
            web.open_browser(results[int(choice)-1]["url"])

    # ─────────────────────────────────────────────────────────────────────────
    #  IP REPUTATION
    # ─────────────────────────────────────────────────────────────────────────

    def _check_ip(self, ip: str):
        if not ip:
            ip = self.ui.ask("IP")
        self.ui.section(self._t(f"🌐 سمعة IP: {ip}",f"🌐 IP Rep: {ip}"))
        with self.ui.spinner("Checking..."):
            pass
        result = web.check_ip_reputation(ip, abuseipdb_key=self.settings.get("abuseipdb_key",""))
        self.ui.print_tree(result.get("info",{}), ip)
        sources = result.get("sources_checked", [])
        if sources:
            self.ui.info(f"  {self._t('المصادر المفحوصة','Sources checked')}: {', '.join(sources)}")
        findings = result.get("findings", [])
        self._last_findings = findings
        for f in findings:
            self.ui.print_finding(f["severity"], f["title"], f.get("detail",""), f.get("fix",""))
        return findings

    # ─────────────────────────────────────────────────────────────────────────
    #  PACKAGE VULNERABILITY SEARCH (OSV.dev)
    # ─────────────────────────────────────────────────────────────────────────

    def _pkg_vuln_search(self, package: str):
        if not package:
            package = self.ui.ask(self._t("اسم الحزمة (مثال: requests)","Package name (e.g. requests)"))
        eco = self.ui.ask(
            self._t("النظام: PyPI/npm/Go/crates.io/Packagist/RubyGems/Maven/NuGet",
                     "Ecosystem: PyPI/npm/Go/crates.io/Packagist/RubyGems/Maven/NuGet"),
            default="PyPI")
        self.ui.section(self._t(f"📦 ثغرات الحزمة: {package} ({eco})", f"📦 Package vulnerabilities: {package} ({eco})"))
        with self.ui.spinner(self._t("البحث في OSV.dev...","Searching OSV.dev...")):
            pass
        vulns = web.search_osv(package, ecosystem=eco)
        valid = [v for v in vulns if "error" not in v]

        if not valid:
            self.ui.success(self._t(f"🟢 لا ثغرات معروفة لـ {package} على OSV.dev",
                                      f"🟢 No known vulnerabilities for {package} on OSV.dev"))
        else:
            rows = [[v["id"], ", ".join(v.get("cve_ids", [])) or "—", v.get("published","?")[:10],
                     v.get("summary","")[:60]] for v in valid]
            self.ui.print_table(["OSV ID","CVE","Published","Summary"], rows, title=f"OSV.dev — {package}")
            for v in valid[:5]:
                self.kb.add_knowledge("cve_search", v["id"], v.get("summary","")[:150], source="osv.dev")

        # تكميلي: هل توجد استغلالات معروفة محلياً بهذا الاسم أيضاً؟
        exploits = [e for e in web.search_exploitdb(package, max_results=3) if "error" not in e]
        if exploits:
            self.ui.subsection(self._t("🧨 استغلالات محتملة الصلة (Exploit-DB محلي)","🧨 Possibly related exploits (local Exploit-DB)"))
            for e in exploits:
                self.ui.info(f"  EDB-{e['edb_id']}: {e.get('description','')[:70]}")

    # ─────────────────────────────────────────────────────────────────────────
    #  SECURITY TREND (تطوّر الوضع عبر الفحوصات السابقة)
    # ─────────────────────────────────────────────────────────────────────────

    def _show_trend(self):
        self.ui.section(self._t("📈 تطوّر الوضع الأمني","📈 Security Trend"))
        any_history = False
        labels = {
            "network": self._t("🌐 الشبكة","🌐 Network"), "system": self._t("🖥️ النظام","🖥️ System"),
            "logs": self._t("📋 السجلات","📋 Logs"), "full": self._t("🔒 شامل","🔒 Full"),
        }
        for scan_type, label in labels.items():
            history = self.kb.get_scan_history(scan_type, limit=8)
            if not history:
                continue
            any_history = True
            rows = [[h["scanned_at"][:16], h["risk_level"], str(h["findings_count"])] for h in reversed(history)]
            self.ui.print_table(
                [self._t("التاريخ","Date"), self._t("المستوى","Level"), self._t("عدد النتائج","Findings")],
                rows, title=label)

        if not any_history:
            self.ui.warning(self._t("لا يوجد سجل فحوصات سابقة بعد — شغّل أي فحص أولاً.",
                                      "No scan history yet — run a scan first."))
            return

        for scan_type in labels:
            history = self.kb.get_scan_history(scan_type, limit=2)
            if len(history) >= 2:
                older_row = history[1]
                self.ui.info(
                    f"  {labels[scan_type]}: {older_row['risk_level']} → {history[0]['risk_level']} "
                    f"({older_row['scanned_at'][:16]} → {history[0]['scanned_at'][:16]})")

    # ─────────────────────────────────────────────────────────────────────────
    #  AUTO-FIX MENU
    # ─────────────────────────────────────────────────────────────────────────

    def _autofix_menu(self):
        self.ui.section(self._t("🔧 الإصلاح التلقائي","🔧 Auto-Fix"))
        self.ui.warning(self._t("⚠️  بعض الإصلاحات تُعدّل إعدادات النظام!","⚠️  Some fixes modify system settings!"))
        available = list_available_fixes()
        rows = [[str(i+1), fix_id] for i, fix_id in enumerate(available)]
        self.ui.print_table(["#","Fix ID"], rows)
        choice = self.ui.ask(self._t("رقم الإصلاح","Fix number"), default="0")
        if choice == "0": return
        try:
            fix_id = available[int(choice)-1]
        except (ValueError, IndexError):
            fix_id = choice
        if not self.ui.confirm(self._t(f"تطبيق '{fix_id}'?",f"Apply '{fix_id}'?"), False):
            return
        kwargs = {}
        if fix_id == "ban_ip":
            kwargs["ip"] = self.ui.ask("IP")
        elif fix_id == "kill_process":
            kwargs["pid"] = self.ui.ask("PID")
        elif fix_id in ("remove_suid","restrict_world_writable","remove_autorun"):
            kwargs["filepath"] = self.ui.ask(self._t("مسار الملف","File path"))
        result = apply_fix(fix_id, **kwargs)
        if result.get("success"):
            self.ui.success(self._t(f"✅ تم '{fix_id}'!",f"✅ '{fix_id}' applied!"))
        else:
            self.ui.error(result.get("error",""))
        for step in result.get("steps",[]):
            self.ui.info(f"  {'✅' if step.get('ok') else '❌'} {step.get('cmd','')}")

    # ─────────────────────────────────────────────────────────────────────────
    #  FULL SCAN
    # ─────────────────────────────────────────────────────────────────────────

    def _full_scan(self):
        self.ui.section(self._t("🔒 الفحص الشامل الكامل","🔒 Full Comprehensive Scan"))
        self.ui.warning(self._t("قد يستغرق عدة دقائق...","May take several minutes..."))
        all_findings = []
        steps = [
            (self._t("🌐 الشبكة","Network"),   lambda: network.check_data_leaks()),
            (self._t("🔥 Firewall","FW"),       lambda: network.check_firewall()),
            (self._t("📋 سجلات","Logs"),        lambda: system.analyze_logs()),
            (self._t("🗂️ SUID","SUID"),         lambda: system.check_suid_files()),
            (self._t("⏱️ Cron","Cron"),         lambda: system.check_crontabs()),
            (self._t("🔐 SSH","SSH"),            lambda: system.check_ssh_config()),
            (self._t("👤 مستخدمون","Users"),    lambda: system.check_users_and_groups()),
            (self._t("📦 تحديثات","Updates"),   lambda: system.get_installed_packages_vulnerabilities()),
        ]
        for label, fn in steps:
            self.ui.info(f"  ⏳ {label}...")
            try:
                r = fn()
                all_findings.extend(r.get("findings",[]) if isinstance(r, dict) else [])
            except Exception as e:
                self.ui.warning(f"  {label}: {e}")

        try:
            self.ui.info(f"  ⏳ {self._t('مطابقة الحزم مع قاعدة CVE','Cross-checking packages against CVE')}...")
            pkg_check = system.list_upgradable_security_packages()
            all_findings.extend(self._enrich_packages_with_cve(pkg_check.get("packages", [])))
        except Exception as e:
            self.ui.warning(f"  CVE cross-check: {e}")

        all_findings = self.intel.correlate_findings(all_findings)
        all_findings += self.intel.detect_compound_risks(all_findings)
        # ── Attack Chain Analysis: cross-domain correlation ──
        attack_chains = self.correlation.analyze(all_findings)
        all_findings.extend(attack_chains)
        risk = self.intel.compute_risk_score(all_findings)
        self._last_findings = all_findings
        self._save_and_show_trend("full", risk, all_findings)

        self.ui.section(self._t("🚨 جميع النتائج","🚨 All Findings"))
        for f in all_findings:
            self.ui.print_finding(f["severity"], f["title"], f.get("detail",""), f.get("fix",""))
        self.ui.raw(self.intel.get_remediation_plan(all_findings))
        # ── Smart Remediation Prioritization ──
        self.ui.raw(SmartRemediationAdvisor.format_recommendations(all_findings, top_n=5))
        self.ui.raw(self.intel.generate_summary(risk, all_findings, self._t("الفحص الشامل","Full Scan")), style=_risk_border_style(risk["level"]))

        report = generate_markdown_report({"risk": risk, "findings": all_findings, "sections":{}}, self._hostname, self.lang)
        self._ask_save_report(report)
        return all_findings

    # ─────────────────────────────────────────────────────────────────────────
    #  UPDATE INTEL
    # ─────────────────────────────────────────────────────────────────────────

    def _update_intel(self):
        self.ui.section(self._t("🔄 تحديث معلومات التهديدات","🔄 Threat Intelligence Update"))
        conn = web.check_connectivity()
        if not conn["connected"]:
            self.ui.error(self._t("لا اتصال بالإنترنت","No internet")); return
        self.ui.info(self._t(f"IP العام: {conn['public_ip']}",f"Public IP: {conn['public_ip']}"))
        kev = web.get_cisa_known_exploited(max_results=10)
        if kev and "error" not in kev[0]:
            rows = [[v.get("cve_id",""), v.get("vendor",""), v.get("product",""), v.get("date_added","")[:10]] for v in kev]
            self.ui.print_table(["CVE ID","Vendor","Product","Date Added"], rows)
            for v in kev:
                self.kb.add_knowledge("cve_live", v.get("cve_id",""),
                                      f"{v.get('vendor','')} {v.get('product','')} — CISA: {v.get('date_added','')}", source="cisa")
            self.kb.log_update("CISA", len(kev), "CISA KEV update")
        news = web.fetch_security_news(max_items=5)
        self.ui.subsection(self._t("أخبار الأمن","Security News"))
        for item in news:
            self.ui.info(f"  📰 {item.get('title','')} [{item.get('source','')}]")

        self.ui.subsection(self._t("فهرس Exploit-DB المحلي","Local Exploit-DB index"))
        with self.ui.spinner(self._t("تحميل الفهرس (قد يستغرق دقيقة)...","Downloading index (may take a minute)...")):
            pass
        edb = web.update_exploitdb_index()
        if edb.get("success"):
            self.ui.success(self._t(f"✅ تم تحديث الفهرس: {edb['count']} إدخال — بحث محلي فوري بلا إنترنت لاحقاً",
                                      f"✅ Index updated: {edb['count']} entries — instant offline search afterwards"))
            self.kb.log_update("ExploitDB", edb["count"], "Exploit-DB local index refresh")
        else:
            self.ui.warning(self._t(f"تعذّر تحديث فهرس Exploit-DB: {edb.get('error','?')}",
                                      f"Could not update Exploit-DB index: {edb.get('error','?')}"))

    # ─────────────────────────────────────────────────────────────────────────
    #  CONFIG
    # ─────────────────────────────────────────────────────────────────────────

    def _config_menu(self):
        self.ui.section(self._t("⚙️ الإعدادات","⚙️ Settings"))
        rows = [[k, str(v)] for k, v in self.settings.all().items()]
        self.ui.print_table(["Setting","Value"], rows)
        options = [
            ("1","language","تغيير اللغة"),
            ("2","github_token","تعيين رمز GitHub"),
            ("3","report_dir","مجلد التقارير"),
            ("4","clear_history","مسح تاريخ المحادثات"),
            ("5","abuseipdb_key","تعيين مفتاح AbuseIPDB (اختياري — لفحص سمعة IP)"),
            ("6","nvd_api_key","تعيين مفتاح NVD (اختياري — يرفع حد بحث CVE)"),
            ("0","back","رجوع"),
        ]
        self.ui.print_table(["#","Setting","Description"], options)
        choice = self.ui.ask(self._t("اختر","Choose"), default="0")
        if choice == "1":
            lang = self.ui.ask(self._t("اللغة (ar/en)","Language (ar/en)"), default=self.lang)
            if lang in ("ar","en"):
                self.settings.set("language", lang); self.lang = lang; self.intel.language = lang
                self.ui.success(self._t("تم تغيير اللغة","Language changed"))
        elif choice == "2":
            token = self.ui.ask(self._t("رمز GitHub","GitHub token"))
            if token:
                self.settings.set("github_token", token)
                self.github = GitHubTool(token=token)
                self.ui.success(self._t("تم الحفظ!","Saved!"))
        elif choice == "3":
            d = self.ui.ask(self._t("مجلد التقارير","Reports dir"), default=self.settings.get("report_dir",""))
            if d: self.settings.set("report_dir", d); self.ui.success(self._t("تم","Done"))
        elif choice == "4":
            if self.ui.confirm(self._t("مسح تاريخ المحادثات؟","Clear conversation history?"), False):
                self.kb.clear_history()
                self.ui.success(self._t("تم مسح التاريخ","History cleared"))
        elif choice == "5":
            self.ui.info(self._t("مفتاح مجاني من: https://www.abuseipdb.com/account/api",
                                   "Free key from: https://www.abuseipdb.com/account/api"))
            key = self.ui.ask(self._t("مفتاح AbuseIPDB (Enter لإلغاء)","AbuseIPDB key (Enter to cancel)"), default="")
            if key:
                self.settings.set("abuseipdb_key", key)
                self.ui.success(self._t("تم الحفظ! سيُستخدَم تلقائياً في فحص سمعة IP القادم","Saved! Will be used automatically in the next IP reputation check"))
        elif choice == "6":
            self.ui.info(self._t("مفتاح مجاني من: https://nvd.nist.gov/developers/request-an-api-key",
                                   "Free key from: https://nvd.nist.gov/developers/request-an-api-key"))
            key = self.ui.ask(self._t("مفتاح NVD (Enter لإلغاء)","NVD key (Enter to cancel)"), default="")
            if key:
                self.settings.set("nvd_api_key", key)
                self.ui.success(self._t("تم الحفظ!","Saved!"))

    # ─────────────────────────────────────────────────────────────────────────
    #  PUBLIC API (for non-interactive use)
    # ─────────────────────────────────────────────────────────────────────────

    def run_scan(self, target, value=None, output_file=None):
        if target == "network": self._scan_network()
        elif target == "ports": self._scan_ports(value or "127.0.0.1")
        elif target == "usb":   self._usb_control_center()
        elif target == "system":self._scan_system()
        elif target == "logs":  self._scan_logs()
        elif target == "full":  self._full_scan()
        else: self.ui.warning(f"Unknown: {target}")

    def generate_full_report(self, output_file=None):
        self._full_scan()

    def update_intelligence(self):
        self._update_intel()

    def run_autofix(self, target=None):
        self._autofix_menu()

    def show_config(self):
        self._config_menu()
