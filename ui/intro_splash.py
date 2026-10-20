"""شاشة مقدمة وترحيب احترافية لمنظومة AI AYFAM (إصدار العمليات 2026)."""
from __future__ import annotations

import os
from pathlib import Path

from PyQt6.QtCore import QPoint, QRectF, QSize, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import (
    QColor,
    QCursor,
    QFont,
    QIcon,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
)
from PyQt6.QtSvg import QSvgRenderer
from PyQt6.QtWidgets import (
    QApplication,
    QDialog,
    QFrame,
    QGraphicsDropShadowEffect,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ui.theme import (
    ACCENT,
    ACCENT_HOVER,
    ACCENT_SECONDARY,
    BG_BASE,
    BG_ELEVATED,
    BG_SURFACE,
    BORDER,
    FONT_FAMILY,
    SEV_SAFE,
    TEXT_MUTED,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
    alpha,
)

ROOT_DIR = Path(__file__).resolve().parents[1]


class AyfamIntroSplash(QWidget):
    """شاشة مقدمة ودخول فائقة الأناقة والعصرية مع تسلسل تشخيص ذاتي تمهيدي."""

    ready_to_launch = pyqtSignal()

    BOOT_STEPS = [
        ("فحص سلامة النواة والبيئة المحلية", "Local Kernel & Sandbox Integrity Check", 18),
        ("تهيئة مستشعرات المراقبة والاتصالات الحية", "Initializing Telemetry & Network Radar", 42),
        ("تفعيل درع حماية الأجهزة والوسائط USB Sentry", "Activating USB Sentry & Isolation Guard", 68),
        ("تحميل حزم التحليل الأمني ومحرك الذكاء الاصطناعي", "Loading Threat Intel & Local AI Copilot", 88),
        ("اكتملت الجاهزية — كابينة العمليات جاهزة للدخول", "SOC Cockpit Ready — Access Granted", 100),
    ]

    TECH_LOGS = [
        "[OK] Integrity check passed: SHA256 verified",
        "[OK] Network socket listener initialized (lo, eth0)",
        "[OK] USB bus rule monitor active (/sys/bus/usb)",
        "[OK] Local intelligence engine linked",
        "[OK] Security Operations Center online",
    ]

    def __init__(self, parent=None, auto_close: bool = True) -> None:
        super().__init__(parent)
        self.auto_close = auto_close
        self._step_idx = 0
        self._drag_pos = QPoint()

        # ضبط خصائص النافذة الحديثة بدون إطار مع خلفية شفافة
        self.setWindowFlags(
            Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint
            | Qt.WindowType.SubWindow
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.setFixedSize(680, 440)

        self._setup_ui()
        self._center_on_screen()

        # مؤقت محاكاة تسلسل الإقلاع السلس والسريع
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._advance_boot)
        self.timer.start(450)

    def _setup_ui(self) -> None:
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(14, 14, 14, 14)

        # الحاوية الزجاجية الرئيسية
        self.card = QFrame()
        self.card.setObjectName("splashCard")
        self.card.setStyleSheet(f"""
            QFrame#splashCard {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #0d1726, stop:0.45 #08101a, stop:1 #050a12);
                border: 1px solid {alpha(ACCENT, 90)};
                border-radius: 20px;
            }}
        """)

        # تأثير الظل العصري المتوهج
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(28)
        shadow.setColor(QColor(0, 0, 0, 180))
        shadow.setOffset(0, 8)
        self.card.setGraphicsEffect(shadow)

        card_layout = QVBoxLayout(self.card)
        card_layout.setContentsMargins(28, 24, 28, 24)
        card_layout.setSpacing(14)

        # ── 1. الشريط العلوي: شارة النظام + زر الإغلاق/التخطي ──
        top_bar = QHBoxLayout()
        top_bar.setSpacing(10)

        sys_badge = QLabel("منظومة العمليات والأمان السيبراني  |  SOC 2026")
        sys_badge.setStyleSheet(f"""
            color: {ACCENT};
            font-size: 11px;
            font-weight: 700;
            background: {alpha(ACCENT, 25)};
            border: 1px solid {alpha(ACCENT, 65)};
            border-radius: 10px;
            padding: 4px 12px;
        """)
        top_bar.addWidget(sys_badge)
        top_bar.addStretch()

        skip_btn = QPushButton("دخول فوري  →")
        skip_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        skip_btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                color: {TEXT_MUTED};
                font-size: 11px;
                font-weight: 600;
                border: 1px solid {alpha(BORDER, 80)};
                border-radius: 8px;
                padding: 4px 10px;
            }}
            QPushButton:hover {{
                color: {TEXT_PRIMARY};
                background: {alpha(ACCENT, 30)};
                border-color: {ACCENT};
            }}
        """)
        skip_btn.clicked.connect(self._launch_now)
        top_bar.addWidget(skip_btn)
        card_layout.addLayout(top_bar)

        # ── 2. قسم الهوية والشعار ──
        brand_row = QHBoxLayout()
        brand_row.setSpacing(20)

        # أيقونة الشعار مع إطار متوهج
        icon_frame = QFrame()
        icon_frame.setFixedSize(76, 76)
        icon_frame.setStyleSheet(f"""
            QFrame {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 {alpha(ACCENT, 45)}, stop:1 {alpha(ACCENT_SECONDARY, 30)});
                border: 1.5px solid {alpha(ACCENT, 160)};
                border-radius: 18px;
            }}
        """)
        icon_layout = QVBoxLayout(icon_frame)
        icon_layout.setContentsMargins(6, 6, 6, 6)

        icon_label = QLabel()
        icon_path = ROOT_DIR / "resources" / "icon.svg"
        if icon_path.exists():
            pix = QIcon(str(icon_path)).pixmap(56, 56)
            icon_label.setPixmap(pix)
        else:
            icon_label.setText("AYFAM")
            icon_label.setStyleSheet(f"font-size: 18px; font-weight: 900; color: {ACCENT};")
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_layout.addWidget(icon_label)
        brand_row.addWidget(icon_frame)

        # عناوين الهوية
        brand_titles = QVBoxLayout()
        brand_titles.setSpacing(3)

        title_lbl = QLabel("AI AYFAM")
        title_lbl.setStyleSheet(f"""
            font-size: 26px;
            font-weight: 900;
            color: {TEXT_PRIMARY};
            letter-spacing: 1.5px;
        """)
        brand_titles.addWidget(title_lbl)

        sub_lbl = QLabel("كابينة القيادة التكتيكية والتحليل الجنائي المتقدم")
        sub_lbl.setStyleSheet(f"""
            color: {TEXT_SECONDARY};
            font-size: 13px;
            font-weight: 600;
        """)
        brand_titles.addWidget(sub_lbl)

        tagline = QLabel("تحكم كامل • حماية فورية للأجهزة • مساعدة ذكية محلية 100%")
        tagline.setStyleSheet(f"""
            color: {TEXT_MUTED};
            font-size: 11px;
        """)
        brand_titles.addWidget(tagline)

        brand_row.addLayout(brand_titles, 1)
        card_layout.addLayout(brand_row)

        # ── 3. مسار التقدم التشخيصي ──
        status_box = QVBoxLayout()
        status_box.setSpacing(8)

        status_header = QHBoxLayout()
        self.step_label = QLabel("جاري تهيئة كابينة العمليات الأمنية...")
        self.step_label.setStyleSheet(f"""
            color: {TEXT_PRIMARY};
            font-size: 13px;
            font-weight: 700;
        """)
        status_header.addWidget(self.step_label)
        status_header.addStretch()

        self.percent_label = QLabel("0%")
        self.percent_label.setStyleSheet(f"""
            color: {ACCENT};
            font-size: 13px;
            font-weight: 800;
            font-family: monospace;
        """)
        status_header.addWidget(self.percent_label)
        status_box.addLayout(status_header)

        # شريط التقدم الفخم
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(5)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(8)
        self.progress_bar.setStyleSheet(f"""
            QProgressBar {{
                background: #0d1b2a;
                border: 1px solid {alpha(BORDER, 100)};
                border-radius: 4px;
            }}
            QProgressBar::chunk {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 {ACCENT}, stop:0.6 {ACCENT_HOVER}, stop:1 {ACCENT_SECONDARY});
                border-radius: 3px;
            }}
        """)
        status_box.addWidget(self.progress_bar)

        # سجل تقني مصغر (Tech ticker)
        self.log_ticker = QLabel(self.TECH_LOGS[0])
        self.log_ticker.setStyleSheet(f"""
            color: {TEXT_MUTED};
            font-size: 10px;
            font-family: 'DejaVu Sans Mono', monospace;
            padding-top: 2px;
        """)
        status_box.addWidget(self.log_ticker)

        card_layout.addLayout(status_box)

        # ── 4. الشريط السفلي: معلومات المشغل وزر الدخول ──
        bottom_bar = QHBoxLayout()
        bottom_bar.setSpacing(12)

        op_badge = QFrame()
        op_badge.setStyleSheet(f"""
            QFrame {{
                background: {alpha(BG_SURFACE, 140)};
                border: 1px solid {alpha(BORDER, 90)};
                border-radius: 10px;
                padding: 4px 10px;
            }}
        """)
        op_layout = QHBoxLayout(op_badge)
        op_layout.setContentsMargins(8, 4, 8, 4)
        op_layout.setSpacing(6)

        dot = QLabel("●")
        dot.setStyleSheet(f"color: {SEV_SAFE}; font-size: 10px;")
        op_layout.addWidget(dot)

        uname = os.uname().nodename if hasattr(os, "uname") else "linux-node"
        op_text = QLabel(f"المشغل: Root / {uname}")
        op_text.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 11px; font-weight: 600;")
        op_layout.addWidget(op_text)
        bottom_bar.addWidget(op_badge)

        bottom_bar.addStretch()

        self.enter_btn = QPushButton("تشغيل كابينة العمليات")
        self.enter_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.enter_btn.setStyleSheet(f"""
            QPushButton {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #14b8a6, stop:1 #0f766e);
                color: #ffffff;
                font-size: 12px;
                font-weight: 700;
                border: 1px solid {alpha('#ffffff', 60)};
                border-radius: 10px;
                padding: 8px 18px;
            }}
            QPushButton:hover {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #5eead4, stop:1 #14b8a6);
                border-color: #ffffff;
            }}
        """)
        self.enter_btn.clicked.connect(self._launch_now)
        bottom_bar.addWidget(self.enter_btn)

        card_layout.addLayout(bottom_bar)
        root_layout.addWidget(self.card)

    def _center_on_screen(self) -> None:
        screen = QApplication.primaryScreen()
        if screen:
            geo = screen.availableGeometry()
            x = (geo.width() - self.width()) // 2
            y = (geo.height() - self.height()) // 2
            self.move(x, y)

    def _advance_boot(self) -> None:
        if self._step_idx < len(self.BOOT_STEPS):
            step_ar, step_en, target_pct = self.BOOT_STEPS[self._step_idx]
            self.step_label.setText(f"{step_ar}")
            self.progress_bar.setValue(target_pct)
            self.percent_label.setText(f"{target_pct}%")
            if self._step_idx < len(self.TECH_LOGS):
                self.log_ticker.setText(self.TECH_LOGS[self._step_idx])
            self._step_idx += 1
        else:
            self.timer.stop()
            self.step_label.setText("جاهز للانطلاق — تم تفعيل كافة المستشعرات بنجاح ✓")
            self.progress_bar.setValue(100)
            self.percent_label.setText("100%")
            if self.auto_close:
                # انتقال سلس وتلقائي خلال 350 ميلي ثانية
                QTimer.singleShot(350, self._launch_now)

    def _launch_now(self) -> None:
        if self.timer.isActive():
            self.timer.stop()
        self.ready_to_launch.emit()
        self.close()

    # دعم سحب النافذة بالماوس رغم كونها بدون إطار
    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_pos = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
            event.accept()

    def mouseMoveEvent(self, event) -> None:
        if event.buttons() == Qt.MouseButton.LeftButton and not self._drag_pos.isNull():
            self.move(event.globalPosition().toPoint() - self._drag_pos)
            event.accept()


class SystemOverviewDialog(QDialog):
    """نافذة أنيقة تعرض تفاصيل المنظومة ومخطط الدفاع التكتيكي للمشغل."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("دليل منظومة AI AYFAM — نظرة شاملة")
        self.resize(760, 520)
        self.setStyleSheet(f"""
            QDialog {{
                background: {BG_BASE};
                color: {TEXT_PRIMARY};
                font-family: {FONT_FAMILY};
            }}
        """)
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # Header
        header = QHBoxLayout()
        header.setSpacing(12)

        icon_path = ROOT_DIR / "resources" / "icon.svg"
        if icon_path.exists():
            icon_lbl = QLabel()
            icon_lbl.setPixmap(QIcon(str(icon_path)).pixmap(42, 42))
            header.addWidget(icon_lbl)

        title_box = QVBoxLayout()
        title = QLabel("AI AYFAM — منصة العمليات والأمن السيبراني")
        title.setStyleSheet(f"font-size: 20px; font-weight: 800; color: {TEXT_PRIMARY};")
        title_box.addWidget(title)
        sub = QLabel("الإصدار 8.0 • كابينة مركز العمليات الأمنية (SOC Cockpit) لبيئة Linux Mint")
        sub.setStyleSheet(f"color: {ACCENT}; font-size: 12px; font-weight: 600;")
        title_box.addWidget(sub)
        header.addLayout(title_box)
        header.addStretch()

        layout.addLayout(header)

        # Pillars Grid
        pillars = [
            ("رادار الشبكة والاتصالات", "مراقبة مباشرة للمقابس المفتوحة، العمليات المتصلة، وتحليل الاتصالات غير المعتادة لحظياً."),
            ("درع الأجهزة الذكي USB Sentry", "كشف دقيق للأجهزة التخزينية والواجهات الهجينة مع دعم الإخراج الآمن والتوصيل للقراءة فقط."),
            ("المساعد والمحلل الأمني الذكي", "محرك ذكاء اصطناعي محلي 100% لتحليل السجلات، صياغة تقارير الحوادث، وتقديم التوصيات."),
            ("ترسانة الأدوات وفحص الثغرات", "تكامل مرن مع أدوات الفحص المتقدمة (فحص المنافذ، الثغرات، أذونات النظام، وملفات التكوين)."),
        ]

        for p_title, p_desc in pillars:
            card = QFrame()
            card.setStyleSheet(f"""
                QFrame {{
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                        stop:0 #0f1c2d, stop:1 #09131e);
                    border: 1px solid {alpha(ACCENT, 70)};
                    border-radius: 12px;
                    padding: 8px;
                }}
            """)
            c_layout = QVBoxLayout(card)
            c_layout.setContentsMargins(14, 10, 14, 10)
            c_layout.setSpacing(4)

            t = QLabel(p_title)
            t.setStyleSheet(f"color: {TEXT_PRIMARY}; font-size: 14px; font-weight: 700;")
            c_layout.addWidget(t)

            d = QLabel(p_desc)
            d.setWordWrap(True)
            d.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px;")
            c_layout.addWidget(d)

            layout.addWidget(card)

        layout.addStretch()

        # Close button
        btn_box = QHBoxLayout()
        btn_box.addStretch()
        close_btn = QPushButton("إغلاق والعودة للكابينة")
        close_btn.setStyleSheet(f"""
            QPushButton {{
                background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #14b8a6, stop:1 #0f766e);
                color: #ffffff;
                font-weight: 700;
                padding: 8px 24px;
                border-radius: 10px;
                border: 1px solid {ACCENT};
            }}
            QPushButton:hover {{
                background: #0f766e;
            }}
        """)
        close_btn.clicked.connect(self.accept)
        btn_box.addWidget(close_btn)
        layout.addLayout(btn_box)
