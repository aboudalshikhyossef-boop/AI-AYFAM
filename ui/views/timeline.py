"""صفحة الخط الزمني الموحد للأحداث والنتائج الأمنية."""

from __future__ import annotations

from datetime import datetime

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QFrame,
    QHeaderView,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ui.theme import PAGE_ACCENTS


class TimelineView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
        self._events: list[dict] = []
        self._init_ui()

    def _init_ui(self) -> None:
        accent = PAGE_ACCENTS["timeline"]
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(14)

        hero = QFrame(objectName="pageHero")
        hero_layout = QVBoxLayout(hero)
        hero_layout.setContentsMargins(18, 14, 18, 14)
        hero_layout.setSpacing(4)
        eyebrow = QLabel("التسلسل الأمني  /  TIMELINE")
        eyebrow.setObjectName("pageEyebrow")
        eyebrow.setStyleSheet(f"color: {accent};")
        hero_layout.addWidget(eyebrow)
        title = QLabel("الخط الزمني للحوادث  /  Incident Timeline")
        title.setObjectName("pageHeading")
        hero_layout.addWidget(title)
        subtitle = QLabel("أحدث الأحداث المسجلة والنتائج المكتشفة، مرتبة من الأحدث إلى الأقدم.  /  Recorded events and findings, newest first.")
        subtitle.setObjectName("secondaryText")
        hero_layout.addWidget(subtitle)
        layout.addWidget(hero)

        self.status = QLabel("جارٍ تجهيز سجل الأحداث… / Loading event history…")
        self.status.setObjectName("glassBadge")
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.status, 0, Qt.AlignmentFlag.AlignRight)

        self.empty_state = QLabel("لا توجد أحداث مسجلة أو نتائج فحص بعد.  /  No events or scan findings recorded yet.")
        self.empty_state.setObjectName("emptyState")
        self.empty_state.setTextFormat(Qt.TextFormat.PlainText)
        self.empty_state.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_state.setMinimumHeight(140)
        layout.addWidget(self.empty_state)

        self.table = QTableWidget(0, 4)
        self.table.setObjectName("glassTable")
        self.table.setHorizontalHeaderLabels(["الوقت / Time", "النوع / Type", "المصدر / Source", "الحدث / Event"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.cellClicked.connect(self._show_detail)

        self.detail = QPlainTextEdit()
        self.detail.setObjectName("findingDetail")
        self.detail.setReadOnly(True)
        self.detail.setPlaceholderText("حدد حدثًا لعرض التفاصيل.")
        self.splitter = QSplitter(Qt.Orientation.Vertical)
        self.splitter.addWidget(self.table)
        self.splitter.addWidget(self.detail)
        self.splitter.setStretchFactor(0, 3)
        self.splitter.setStretchFactor(1, 1)
        layout.addWidget(self.splitter, 1)
        self.table.hide()
        self.splitter.hide()

    def set_events(self, events: list[dict]) -> None:
        self._events = [dict(event) for event in events if isinstance(event, dict)]
        self.table.setRowCount(len(self._events))
        for row, event in enumerate(self._events):
            timestamp = event.get("timestamp", event.get("wall_time", ""))
            try:
                timestamp_text = datetime.fromtimestamp(float(timestamp)).strftime("%Y-%m-%d  %H:%M:%S")
            except (TypeError, ValueError, OSError, OverflowError):
                timestamp_text = str(timestamp or "—")
            item_type = str(event.get("item_type", event.get("event_type", "event")))
            label = "نتيجة فحص / Finding" if item_type == "finding" else "حدث / Event"
            values = (
                timestamp_text,
                label,
                str(event.get("source", event.get("category", "—"))),
                str(event.get("title", "حدث أمني / Security event")),
            )
            for column, value in enumerate(values):
                cell = QTableWidgetItem(value)
                cell.setData(Qt.ItemDataRole.UserRole, event)
                self.table.setItem(row, column, cell)
            self.table.setRowHeight(row, 38)
        count = len(self._events)
        self.status.setText(f"{count} عنصرًا في التسلسل / {count} timeline items")
        self.empty_state.setVisible(not count)
        self.table.setVisible(bool(count))
        self.splitter.setVisible(bool(count))
        if count:
            self.table.selectRow(0)
            self._show_detail(0, 0)

    def set_error(self, message: str) -> None:
        self._events = []
        self.table.setRowCount(0)
        self.status.setText("تعذر تحميل سجل الأحداث / Could not load event history")
        self.empty_state.setText(f"تعذر قراءة السجل المحلي.\n{message}\n\nCould not read the local event history.")
        self.empty_state.show()
        self.table.hide()
        self.splitter.hide()

    def _show_detail(self, row: int, _column: int = 0) -> None:
        if 0 <= row < len(self._events):
            event = self._events[row]
            self.detail.setPlainText(
                f"{event.get('title', 'حدث أمني / Security event')}\n\n"
                f"المصدر / Source: {event.get('source', event.get('category', '—'))}\n"
                f"النوع / Type: {event.get('item_type', event.get('event_type', 'event'))}\n"
                f"الخطورة / Severity: {event.get('severity', 'info')}\n\n"
                f"{event.get('detail', event.get('details', 'لا توجد تفاصيل إضافية / No additional details.'))}"
            )
