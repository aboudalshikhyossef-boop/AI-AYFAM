"""واجهة النتائج الأمنية مع البحث والتصفية والتفاصيل الآمنة."""

from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QComboBox,
    QFrame,
    QHeaderView,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QPlainTextEdit,
    QVBoxLayout,
    QWidget,
)

from ui.theme import PAGE_ACCENTS, SEV_CRITICAL, SEV_HIGH, SEV_INFO, SEV_LOW, SEV_MEDIUM


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
    "safe": "#34d399",
}


class FindingsView(QWidget):
    """Browse findings without duplicating scan execution or remediation logic."""

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
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(14)

        heading = QFrame(objectName="pageHero")
        heading.setProperty("accentColor", accent)
        heading_layout = QVBoxLayout(heading)
        heading_layout.setContentsMargins(18, 14, 18, 14)
        heading_layout.setSpacing(4)
        eyebrow = QLabel("مركز المراجعة  /  REVIEW CENTER")
        eyebrow.setObjectName("pageEyebrow")
        eyebrow.setStyleSheet(f"color: {accent};")
        heading_layout.addWidget(eyebrow)
        title = QLabel("النتائج الأمنية الموحدة  /  Unified Security Findings")
        title.setObjectName("pageHeading")
        heading_layout.addWidget(title)
        subtitle = QLabel("رتّب النتائج حسب الخطورة، وابحث عنها، ثم راجع الدليل قبل اختيار أي إجراء.  /  Filter, search, and review evidence before taking action.")
        subtitle.setObjectName("secondaryText")
        subtitle.setWordWrap(True)
        heading_layout.addWidget(subtitle)
        layout.addWidget(heading)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(10)
        self.search_input = QLineEdit()
        self.search_input.setAccessibleName("البحث في النتائج الأمنية / Search security findings")
        self.search_input.setPlaceholderText("ابحث في العنوان أو التفاصيل أو الفئة…  /  Search title, details, or category")
        self.search_input.textChanged.connect(self._apply_filter)
        toolbar.addWidget(self.search_input, 1)

        self.severity_filter = QComboBox()
        self.severity_filter.setAccessibleName("تصفية النتائج حسب الخطورة / Filter by severity")
        self.severity_filter.addItem("كل الدرجات / All severities", "all")
        for key, label in SEVERITY_LABELS.items():
            self.severity_filter.addItem(label, key)
        self.severity_filter.currentIndexChanged.connect(self._apply_filter)
        toolbar.addWidget(self.severity_filter)

        self.count_badge = QLabel("لم يُجرَ فحص بعد / No scan yet")
        self.count_badge.setObjectName("glassBadge")
        toolbar.addWidget(self.count_badge)
        layout.addLayout(toolbar)

        self.empty_state = QLabel("لا توجد نتائج بعد\nابدأ فحصًا أمنيًا لتظهر النتائج هنا.\n\nNo findings yet\nRun a security scan to see results here.")
        self.empty_state.setObjectName("emptyState")
        self.empty_state.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_state.setWordWrap(True)
        self.empty_state.setMinimumHeight(160)
        self.scan_button = QPushButton("الانتقال إلى الفحوصات / Go to scans")
        self.scan_button.setObjectName("primary")
        self.scan_button.clicked.connect(self.go_to_scans.emit)
        empty_box = QFrame(objectName="emptyGlassCard")
        empty_layout = QVBoxLayout(empty_box)
        empty_layout.setContentsMargins(20, 18, 20, 18)
        empty_layout.addWidget(self.empty_state)
        empty_layout.addWidget(self.scan_button, 0, Qt.AlignmentFlag.AlignHCenter)
        layout.addWidget(empty_box)

        self.table = QTableWidget(0, 4)
        self.table.setObjectName("glassTable")
        self.table.setHorizontalHeaderLabels(["الخطورة / Severity", "النتيجة / Finding", "الفئة / Category", "الثقة / Confidence"])
        self.table.horizontalHeader().setStretchLastSection(False)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setMinimumHeight(190)
        self.table.currentCellChanged.connect(self._show_detail)

        self.detail_text = QPlainTextEdit()
        self.detail_text.setObjectName("findingDetail")
        self.detail_text.setReadOnly(True)
        self.detail_text.setPlaceholderText("اختر نتيجة لعرض الوصف والأدلة والتوصية.  /  Select a finding to review its description, evidence, and recommendation.")
        self.detail_text.setMinimumHeight(120)

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
                severity_item.setToolTip(f"درجة الخطورة / Severity: {severity_label}")
                severity_item.setData(Qt.ItemDataRole.UserRole, severity_key)
                self.table.setItem(row, 0, severity_item)
                self.table.setItem(row, 1, QTableWidgetItem(str(finding.get("title", "—"))))
                self.table.setItem(row, 2, QTableWidgetItem(str(finding.get("category", "—"))))
                confidence = finding.get("confidence")
                confidence_text = f"{float(confidence):.0%}" if isinstance(confidence, (int, float)) else "—"
                self.table.setItem(row, 3, QTableWidgetItem(confidence_text))
                self.table.setRowHeight(row, 38)
        finally:
            self.table.setUpdatesEnabled(True)

        visible = len(self._visible_findings)
        total = len(self._findings)
        self.count_badge.setText(f"{visible} من {total} نتيجة / {visible} of {total} findings")
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
            "لا توجد نتائج بعد\nابدأ فحصًا أمنيًا لتظهر النتائج هنا.\n\nNo findings yet\nRun a security scan to see results here."
            if no_scan else
            "لا توجد نتائج تطابق هذا البحث أو عامل التصفية.\nغيّر كلمات البحث أو اختر درجة خطورة أخرى.\n\nNo findings match these filters.\nChange the search or choose another severity."
        )
        self.empty_state.parentWidget().setVisible(not has_items)
        self.scan_button.setVisible(no_scan)
        self.table.setVisible(has_items)
        self.detail_text.setVisible(has_items)
        self.splitter.setVisible(has_items)

    def _show_detail(self, row: int, _column: int, _previous_row: int, _previous_column: int) -> None:
        if row < 0 or row >= len(self._visible_findings):
            return
        finding = self._visible_findings[row]
        evidence = finding.get("evidence")
        details = [
            str(finding.get("title", "نتيجة أمنية / Security finding")),
            f"الخطورة / Severity: {SEVERITY_LABELS.get(str(finding.get('severity', 'info')).lower(), SEVERITY_LABELS['info'])}",
            f"الفئة / Category: {finding.get('category', '—')}",
            "",
            str(finding.get("detail") or "لا يوجد شرح إضافي مسجل / No additional details recorded."),
        ]
        if evidence:
            details.extend(["", "الدليل / Evidence:", str(evidence)])
        if finding.get("fix"):
            details.extend(["", "التوصية / Recommendation:", str(finding["fix"])])
        self.detail_text.setPlainText("\n".join(details))
