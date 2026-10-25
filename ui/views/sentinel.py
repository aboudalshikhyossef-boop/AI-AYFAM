"""واجهة سجل الحارس الأمني مع توضيح صادق لحالة المراقبة."""

from __future__ import annotations

from datetime import datetime

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QFrame,
    QHeaderView,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ui.theme import PAGE_ACCENTS, SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_SAFE

SEVERITY_COLORS = {
    "critical": SEV_CRITICAL,
    "high": SEV_HIGH,
    "medium": SEV_MEDIUM,
    "low": "#60a5fa",
    "info": "#38bdf8",
    "safe": SEV_SAFE,
}
SEVERITY_LABELS = {
    "critical": "حرجة / Critical",
    "high": "عالية / High",
    "medium": "متوسطة / Medium",
    "low": "منخفضة / Low",
    "info": "معلومة / Info",
    "safe": "آمنة / Safe",
}


class SentinelView(QWidget):
    refresh_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
        self._init_ui()

    def _init_ui(self) -> None:
        accent = PAGE_ACCENTS["sentinel"]
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(14)

        hero = QFrame(objectName="pageHero")
        hero_layout = QVBoxLayout(hero)
        hero_layout.setContentsMargins(18, 14, 18, 14)
        hero_layout.setSpacing(4)
        eyebrow = QLabel("المراقبة والاستجابة  /  MONITORING & RESPONSE")
        eyebrow.setObjectName("pageEyebrow")
        eyebrow.setStyleSheet(f"color: {accent};")
        hero_layout.addWidget(eyebrow)
        title = QLabel("الحارس اللحظي  /  Live Sentinel")
        title.setObjectName("pageHeading")
        hero_layout.addWidget(title)
        subtitle = QLabel("يعرض هذا التبويب الأحداث المحفوظة؛ لا يبدأ مراقبة النظام أو يغيّر إعداداته تلقائيًا.  /  Shows saved events only; opening this view does not start monitoring or change system settings.")
        subtitle.setObjectName("secondaryText")
        subtitle.setWordWrap(True)
        hero_layout.addWidget(subtitle)
        layout.addWidget(hero)

        status_row = QHBoxLayout()
        self.monitor_status = QLabel("عرض السجل المحفوظ / Saved history")
        self.monitor_status.setObjectName("glassBadge")
        self.monitor_status.setTextFormat(Qt.TextFormat.PlainText)
        status_row.addWidget(self.monitor_status)
        status_row.addStretch()
        self.event_count = QLabel("0 أحداث / events")
        self.event_count.setObjectName("glassBadge")
        status_row.addWidget(self.event_count)
        self.refresh_button = QPushButton("تحديث السجل / Refresh history")
        self.refresh_button.clicked.connect(self.refresh_requested.emit)
        status_row.addWidget(self.refresh_button)
        layout.addLayout(status_row)

        self.empty_state = QLabel("لا توجد أحداث مسجلة حتى الآن.  /  No events have been recorded yet.")
        self.empty_state.setObjectName("emptyState")
        self.empty_state.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_state.setMinimumHeight(150)
        layout.addWidget(self.empty_state)

        self.table = QTableWidget(0, 4)
        self.table.setObjectName("glassTable")
        self.table.setHorizontalHeaderLabels(["الوقت / Time", "الخطورة / Severity", "المصدر / Source", "الموضوع / Subject"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.table, 1)

    def set_events(self, events: list[dict], monitoring: bool = False) -> None:
        self.table.setRowCount(len(events))
        for row, event in enumerate(events):
            try:
                timestamp = datetime.fromtimestamp(float(event.get("wall_time", 0))).strftime("%Y-%m-%d  %H:%M:%S")
            except (TypeError, ValueError, OSError, OverflowError):
                timestamp = str(event.get("wall_time", "—"))
            severity = str(event.get("severity", "info")).lower()
            values = (
                timestamp,
                SEVERITY_LABELS.get(severity, SEVERITY_LABELS["info"]),
                str(event.get("source", "—")),
                str(event.get("subject", "—")),
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.ItemDataRole.UserRole, event)
                if column == 1:
                    item.setForeground(QColor(SEVERITY_COLORS.get(severity, SEVERITY_COLORS["info"])))
                    item.setToolTip(f"الخطورة / Severity: {SEVERITY_LABELS.get(severity, SEVERITY_LABELS['info'])}")
                self.table.setItem(row, column, item)
            self.table.setRowHeight(row, 44)
        self.event_count.setText(f"{len(events)} أحداث / events")
        self.monitor_status.setText("المراقبة نشطة / Monitoring active" if monitoring else "سجل محفوظ — المراقبة غير مفعلة / Saved history — monitoring off")
        self.empty_state.setVisible(not events)
        self.table.setVisible(bool(events))
