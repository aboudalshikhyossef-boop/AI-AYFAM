"""
واجهة النتائج الأمنية الفاخرة مع محرك الزجاج الحقيقي والبحث والتصفية.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (
    QComboBox, QHeaderView, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QSplitter, QTableWidget, QTableWidgetItem,
    QPlainTextEdit, QVBoxLayout, QWidget
)

from ui.theme import PAGE_ACCENTS, SEV_CRITICAL, SEV_HIGH, SEV_INFO, SEV_LOW, SEV_MEDIUM, SEV_SAFE
from ui.tokens import Tokens
from ui.widgets import Glass, chip

SEVERITY_LABELS = {
    "critical": "حرجة / Critical",
    "high": "عالية / High",
    "medium": "متوسطة / Medium",
    "low": "منخفضة / Low",
    "info": "معلومة / Info",
    "safe": "آمنة / Safe",
}
SEVERITY_COLORS = {
    "critical": SEV_CRITICAL,
    "high": SEV_HIGH,
    "medium": SEV_MEDIUM,
    "low": SEV_LOW,
    "info": SEV_INFO,
    "safe": SEV_SAFE,
}


class FindingsView(QWidget):
    """عرض وتصفية النتائج الأمنية داخل ألواح زجاجية حقيقية."""

    go_to_scans = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
        self._findings: list[dict] = []
        self._visible_findings: list[dict] = []
        self._init_ui()

    def _init_ui(self) -> None:
        accent = PAGE_ACCENTS["findings"]
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)

        # Hero Banner Glass
        heading = Glass(28, tint=0.09)
        heading_layout = QVBoxLayout(heading)
        heading_layout.setContentsMargins(24, 18, 24, 18)
        heading_layout.setSpacing(6)

        eyebrow = QLabel("مركز المراجع والتصفية  /  REVIEW & FILTER CENTER")
        eyebrow.setFont(QFont("Tajawal", 10, QFont.Weight.Bold))
        eyebrow.setStyleSheet(f"color: {accent}; background: transparent;")
        heading_layout.addWidget(eyebrow)

        title = QLabel("النتائج الأمنية الموحدة  /  Unified Security Findings")
        title.setFont(QFont("Tajawal", 20, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {Tokens.TEXT_PRIMARY}; background: transparent;")
        heading_layout.addWidget(title)

        subtitle = QLabel("رتّب النتائج حسب الخطورة، وابحث عنها، ثم راجع الدليل قبل اختيار أي إجراء.")
        subtitle.setFont(QFont("Tajawal", 12))
        subtitle.setStyleSheet(f"color: {Tokens.TEXT_SECONDARY}; background: transparent;")
        heading_layout.addWidget(subtitle)
        layout.addWidget(heading)

        # Toolbar
        toolbar = QHBoxLayout()
        toolbar.setSpacing(12)
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("ابحث في العنوان أو التفاصيل أو الفئة…")
        self.search_input.textChanged.connect(self._apply_filter)
        toolbar.addWidget(self.search_input, 1)

        self.severity_filter = QComboBox()
        self.severity_filter.addItem("كل الدرجات / All severities", "all")
        for key, label in SEVERITY_LABELS.items():
            self.severity_filter.addItem(label, key)
        self.severity_filter.currentIndexChanged.connect(self._apply_filter)
        toolbar.addWidget(self.severity_filter)

        self.count_badge = QLabel("لم يُجرَ فحص بعد / No scan yet")
        self.count_badge.setObjectName("glassBadge")
        toolbar.addWidget(self.count_badge)
        layout.addLayout(toolbar)

        # Empty State
        self.empty_box = Glass(24, tint=0.06)
        empty_layout = QVBoxLayout(self.empty_box)
        empty_layout.setContentsMargins(24, 24, 24, 24)
        self.empty_state = QLabel("لا توجد نتائج بعد\nابدأ فحصًا أمنيًا لتظهر النتائج هنا.")
        self.empty_state.setFont(QFont("Tajawal", 13))
        self.empty_state.setStyleSheet(f"color: {Tokens.TEXT_SECONDARY}; background: transparent;")
        self.empty_state.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.scan_button = QPushButton("الانتقال إلى الفحوصات / Go to scans")
        self.scan_button.setObjectName("primary")
        self.scan_button.clicked.connect(self.go_to_scans.emit)
        empty_layout.addWidget(self.empty_state)
        empty_layout.addWidget(self.scan_button, 0, Qt.AlignmentFlag.AlignHCenter)
        layout.addWidget(self.empty_box)

        # Table & Detail Splitter Glass Panel
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["الخطورة", "النتيجة", "الفئة", "الثقة"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setMinimumHeight(200)
        self.table.currentCellChanged.connect(self._show_detail)

        self.detail_text = QPlainTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setPlaceholderText("اختر نتيجة لعرض الوصف والأدلة والتوصية.")
        self.detail_text.setMinimumHeight(140)

        self.splitter = QSplitter(Qt.Orientation.Vertical)
        self.splitter.setChildrenCollapsible(False)
        self.splitter.addWidget(self.table)
        self.splitter.addWidget(self.detail_text)
        self.splitter.setStretchFactor(0, 3)
        self.splitter.setStretchFactor(1, 2)
        layout.addWidget(self.splitter, 1)
        self._sync_empty_state()

    def set_findings(self, findings: list[dict]) -> None:
        self._findings = [dict(item) for item in findings if isinstance(item, dict)]
        self._apply_filter()

    def _apply_filter(self, *_args) -> None:
        query = self.search_input.text().strip().casefold()
        severity = self.severity_filter.currentData()
        self._visible_findings = [
            finding for finding in self._findings
            if (severity in (None, "all") or str(finding.get("severity", "info")).lower() == severity)
            and (not query or query in " ".join(
                str(finding.get(field, "")) for field in ("title", "detail", "category")
            ).casefold())
        ]
        self.table.setUpdatesEnabled(False)
        try:
            self.table.setRowCount(len(self._visible_findings))
            for row, finding in enumerate(self._visible_findings):
                severity_key = str(finding.get("severity", "info")).lower()
                severity_label = SEVERITY_LABELS.get(severity_key, SEVERITY_LABELS["info"])
                severity_item = QTableWidgetItem(severity_label)
                severity_item.setForeground(QColor(SEVERITY_COLORS.get(severity_key, SEVERITY_COLORS["info"])))
                severity_item.setToolTip(f"درجة الخطورة: {severity_label}")
                severity_item.setData(Qt.ItemDataRole.UserRole, severity_key)
                self.table.setItem(row, 0, severity_item)
                self.table.setItem(row, 1, QTableWidgetItem(str(finding.get("title", "—"))))
                self.table.setItem(row, 2, QTableWidgetItem(str(finding.get("category", "—"))))
                confidence = finding.get("confidence")
                confidence_text = f"{float(confidence):.0%}" if isinstance(confidence, (int, float)) else "—"
                self.table.setItem(row, 3, QTableWidgetItem(confidence_text))
                self.table.setRowHeight(row, 40)
        finally:
            self.table.setUpdatesEnabled(True)

        visible = len(self._visible_findings)
        total = len(self._findings)
        self.count_badge.setText(f"{visible} من {total} نتيجة")
        self._sync_empty_state()
        if visible:
            self.table.selectRow(0)
            self._show_detail(0, 0, -1, -1)
        else:
            self.detail_text.clear()

    def _sync_empty_state(self) -> None:
        has_items = bool(self._visible_findings)
        no_scan = not self._findings
        self.empty_state.setText(
            "لا توجد نتائج بعد\nابدأ فحصًا أمنيًا لتظهر النتائج هنا."
            if no_scan else
            "لا توجد نتائج تطابق هذا البحث أو عامل التصفية."
        )
        self.empty_box.setVisible(not has_items)
        self.scan_button.setVisible(no_scan)
        self.table.setVisible(has_items)
        self.detail_text.setVisible(has_items)
        self.splitter.setVisible(has_items)

    def _show_detail(self, row: int, _column: int, _previous_row: int = -1, _previous_column: int = -1) -> None:
        if row < 0 or row >= len(self._visible_findings):
            return
        finding = self._visible_findings[row]
        evidence = finding.get("evidence")
        details = [
            str(finding.get("title", "نتيجة أمنية / Security finding")),
            f"الخطورة: {SEVERITY_LABELS.get(str(finding.get('severity', 'info')).lower(), SEVERITY_LABELS['info'])}",
            f"الفئة: {finding.get('category', '—')}",
            "",
            str(finding.get("detail") or "لا يوجد شرح إضافي مسجل."),
        ]
        if evidence:
            details.extend(["", "الدليل المسجل / Evidence:", str(evidence)])
        if finding.get("fix"):
            details.extend(["", "التوصية والإصلاح:", str(finding["fix"])])
        self.detail_text.setPlainText("\n".join(details))
