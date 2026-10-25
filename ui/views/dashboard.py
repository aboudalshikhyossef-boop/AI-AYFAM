"""
AI AYFAM View — Dashboard View (Real Glass Glassmorphism)
شاشة غرفة العمليات الفاخرة — KPI cards, Glass Curves, Ring Gauge, Live Radar
"""

from PyQt6.QtCore import Qt, QRectF
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (
    QFrame, QGridLayout, QGroupBox, QHBoxLayout, QHeaderView,
    QLabel, QSplitter, QTableWidget, QVBoxLayout, QWidget
)

from ui.theme import (
    ACCENT, ACCENT_SECONDARY, CARD_ACCENTS, SEV_HIGH, SEV_LOW, SEV_MEDIUM, SEV_SAFE,
    TEXT_MUTED, TEXT_PRIMARY, TEXT_SECONDARY, alpha
)
from ui.tokens import Tokens
from ui.widgets import Curve, Dot, Glass, Ring, SecurityGauge, TelemetryChart, chip, draw_icon


def kpi_card(title: str, value_label_out: list[QLabel], tag_label_out: list[QLabel],
             color: QColor, default_val: str, default_tag: str, note: str) -> Glass:
    """بطاقة KPI زجاجية فاخرة بتأثير التمويه الخلفي والمنحنى المدمج."""
    g = Glass(24, tint=0.08)
    g.setMinimumHeight(132)
    v = QVBoxLayout(g)
    v.setContentsMargins(22, 16, 22, 12)
    v.setSpacing(0)

    top_row = QHBoxLayout()
    lbl = QLabel(title)
    lbl.setFont(QFont("Tajawal", 11, QFont.Weight.Medium))
    lbl.setStyleSheet(f"color: {Tokens.TEXT_SECONDARY}; background: transparent;")
    top_row.addWidget(lbl)
    top_row.addStretch()

    tag = chip(default_tag, color)
    tag_label_out.append(tag)
    top_row.addWidget(tag)
    v.addLayout(top_row)

    mid_row = QHBoxLayout()
    sample_curve = Curve([10, 15, 12, 22, 18, 25, 30], color)
    mid_row.addWidget(sample_curve, 1)

    val = QLabel(default_val)
    val.setFont(QFont("Tajawal", 28, QFont.Weight.Bold))
    val.setStyleSheet(f"color: {color.name()}; background: transparent;")
    val.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
    value_label_out.append(val)
    mid_row.addWidget(val)
    v.addLayout(mid_row, 1)

    sub_note = QLabel(note)
    sub_note.setFont(QFont("Tajawal", 10))
    sub_note.setStyleSheet(f"color: {Tokens.TEXT_MUTED}; background: transparent;")
    v.addWidget(sub_note)
    return g


class DashboardView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.metric_labels = {}
        self.metric_tags = {}
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(20)

        # Mission Banner Glass
        mission = Glass(28, tint=0.09)
        mission_layout = QHBoxLayout(mission)
        mission_layout.setContentsMargins(24, 16, 24, 16)
        mission_layout.setSpacing(20)

        mission_copy = QVBoxLayout()
        mission_copy.setSpacing(4)
        self.mission_kicker = QLabel("حالة الدفاع التكتيكية  •  مراقبة لحظية جارية")
        self.mission_kicker.setFont(QFont("Tajawal", 10, QFont.Weight.Bold))
        self.mission_kicker.setStyleSheet(f"color: {Tokens.TEAL_HEX}; background: transparent;")
        mission_copy.addWidget(self.mission_kicker)

        mission_title = QLabel("مركز المراقبة والتحكم الأمني المتقدم")
        mission_title.setFont(QFont("Tajawal", 20, QFont.Weight.Bold))
        mission_title.setStyleSheet(f"color: {Tokens.TEXT_PRIMARY}; background: transparent;")
        mission_copy.addWidget(mission_title)

        mission_sub = QLabel("رصد مباشر للشبكة والعمليات • حماية الوسائط المتصلة USB Sentry • استجابة ذكية للتهديدات")
        mission_sub.setFont(QFont("Tajawal", 12))
        mission_sub.setStyleSheet(f"color: {Tokens.TEXT_SECONDARY}; background: transparent;")
        mission_copy.addWidget(mission_sub)
        mission_layout.addLayout(mission_copy, 1)

        layout.addWidget(mission)

        # KPI Row
        metrics_grid = QGridLayout()
        metrics_grid.setHorizontalSpacing(18)
        metrics_grid.setVerticalSpacing(18)

        metric_configs = [
            ("connections", "اتصالات الشبكة", "نشط", Tokens.BLUE, "0", "مقابس الشبكة النشطة والمراقبة"),
            ("processes", "العمليات الحية", "نشط", Tokens.VIOLET, "0", "أعلى العمليات استهلاكاً للموارد"),
            ("findings", "الثغرات المكتشفة", "لم يُفحص", Tokens.AMBER, "0", "في آخر فحص مكتمل للمنظومة"),
            ("score", "الجاهزية الأمنية", "سليم", Tokens.GREEN, "100/100", "مؤشر تقييم خطوط الدفاع العام"),
        ]

        for col, (key, title, tag_str, col_obj, val_str, note) in enumerate(metric_configs):
            val_list, tag_list = [], []
            card_widget = kpi_card(title, val_list, tag_list, col_obj, val_str, tag_str, note)
            if val_list:
                self.metric_labels[key] = val_list[0]
            if tag_list:
                self.metric_tags[key] = tag_list[0]
            metrics_grid.addWidget(card_widget, 0, col)
            metrics_grid.setColumnStretch(col, 1)

        layout.addLayout(metrics_grid)

        # Analytics Row: Interactive Glass Curve Chart + Rating Ring
        analytics_row = QHBoxLayout()
        analytics_row.setSpacing(18)

        self.telemetry_chart = TelemetryChart("نشاط الشبكة والجاهزية الأمنية خلال 24 ساعة")
        self.security_gauge = SecurityGauge()
        self.security_gauge.set_pending()

        analytics_row.addWidget(self.telemetry_chart, 3)
        analytics_row.addWidget(self.security_gauge, 1)
        layout.addLayout(analytics_row)
