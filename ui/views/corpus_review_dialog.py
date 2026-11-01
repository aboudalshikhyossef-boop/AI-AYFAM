"""Review dialog for locally imported books and text chunks."""

from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QCheckBox, QDialog, QDialogButtonBox, QFormLayout, QGroupBox,
    QHBoxLayout, QLabel, QLineEdit, QPlainTextEdit, QSpinBox,
    QTableWidget, QTableWidgetItem, QVBoxLayout,
)

from model_factory.corpus_review import get_document_chunk

_REJECTED_LICENSES = {"", "unknown", "unspecified", "none", "n/a", "na", "no-license"}


class CorpusReviewDialog(QDialog):
    """Allow document-level metadata editing and chunk/document exclusions."""

    def __init__(self, raw_path: str | Path, report: dict[str, object], parent=None):
        super().__init__(parent)
        self.raw_path = Path(raw_path)
        raw_documents = report.get("documents", [])
        if not isinstance(raw_documents, list) or not raw_documents:
            raise ValueError("the imported corpus contains no reviewable documents")
        self.documents = raw_documents
        self.by_id = {str(row["document_id"]): row for row in self.documents}
        self.excluded_documents: set[str] = set()
        self.excluded_chunks: set[tuple[str, str]] = set()
        self.metadata_overrides: dict[str, dict[str, str]] = {}
        self.current_document_id: str | None = None
        self.current_chunk_id: str | None = None
        self._loading = False
        self._loading_chunk = False
        self._selection: dict[str, object] = {}

        self.setWindowTitle("مراجعة البيانات قبل تدريب AYFAM")
        self.resize(1080, 780)
        self._build_ui(report)
        self._populate_documents()

    def _build_ui(self, report: dict[str, object]) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(18, 16, 18, 16)
        root.setSpacing(9)

        intro = QLabel(
            "راجع الكتب والمقاطع قبل اعتمادها. يمكن تعديل العنوان والمصدر والترخيص لكل كتاب، "
            "أو استبعاد كتاب/مقطع. لن يبدأ التدريب من هذه النافذة."
        )
        intro.setWordWrap(True)
        root.addWidget(intro)

        self.summary = QLabel(
            f"المستندات: {len(self.documents)} | المقاطع: {int(report.get('chunks', 0)):,} | "
            f"الأحرف: {int(report.get('characters', 0)):,}\n"
            f"تكرارات: {int(report.get('duplicate_chunks', 0)):,} | "
            f"مقاطع قصيرة: {int(report.get('tiny_chunks', 0)):,} | "
            f"ترميز مشبوه: {int(report.get('malformed_chunks', 0)):,} | "
            f"تحتاج تطبيعًا: {int(report.get('unnormalized_chunks', 0)):,}"
        )
        self.summary.setWordWrap(True)
        self.summary.setObjectName("secondaryText")
        root.addWidget(self.summary)

        docs_group = QGroupBox("1. المستندات المستوردة")
        docs_layout = QVBoxLayout(docs_group)
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            ["الكتاب", "النوع", "صفحات نصية", "المقاطع", "الأحرف", "اللغة", "ملاحظات الجودة"]
        )
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setMinimumHeight(175)
        self.table.cellClicked.connect(self._select_row)
        docs_layout.addWidget(self.table)
        root.addWidget(docs_group)

        metadata_group = QGroupBox("2. بيانات الكتاب المحدد")
        metadata = QFormLayout(metadata_group)
        self.include_document = QCheckBox("إدراج الكتاب في corpus")
        self.include_document.toggled.connect(self._toggle_document)
        self.title_input = QLineEdit()
        self.source_input = QLineEdit()
        self.license_input = QLineEdit()
        self.title_input.setMaxLength(500)
        self.source_input.setMaxLength(500)
        self.license_input.setMaxLength(200)
        metadata.addRow(self.include_document)
        metadata.addRow("عنوان الكتاب:", self.title_input)
        metadata.addRow("المصدر:", self.source_input)
        metadata.addRow("الترخيص أو إذن المالك:", self.license_input)
        self.document_details = QLabel("اختر كتابًا من الجدول.")
        self.document_details.setWordWrap(True)
        self.document_details.setObjectName("secondaryText")
        metadata.addRow(self.document_details)
        root.addWidget(metadata_group)

        chunks_group = QGroupBox("3. معاينة المقاطع واستبعاد غير المناسب")
        chunks_layout = QVBoxLayout(chunks_group)
        controls = QHBoxLayout()
        controls.addWidget(QLabel("رقم المقطع:"))
        self.chunk_number = QSpinBox()
        self.chunk_number.setRange(1, 1)
        self.chunk_number.valueChanged.connect(self._load_chunk)
        controls.addWidget(self.chunk_number)
        self.include_chunk = QCheckBox("إدراج المقطع")
        self.include_chunk.toggled.connect(self._toggle_chunk)
        controls.addWidget(self.include_chunk)
        controls.addStretch(1)
        chunks_layout.addLayout(controls)
        self.chunk_details = QLabel("ستظهر بيانات المقطع هنا.")
        self.chunk_details.setWordWrap(True)
        chunks_layout.addWidget(self.chunk_details)
        self.preview = QPlainTextEdit()
        self.preview.setReadOnly(True)
        self.preview.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        self.preview.setMinimumHeight(170)
        chunks_layout.addWidget(self.preview)
        root.addWidget(chunks_group, 1)

        split_group = QGroupBox("4. توزيع الكتب على مجموعات البيانات")
        split = QFormLayout(split_group)
        self.train_ratio = QSpinBox()
        self.validation_ratio = QSpinBox()
        self.test_ratio = QSpinBox()
        for control in (self.train_ratio, self.validation_ratio, self.test_ratio):
            control.setRange(1, 98)
            control.setSuffix("%")
        self.train_ratio.setValue(90)
        self.validation_ratio.setValue(5)
        self.test_ratio.setValue(5)
        split.addRow("Train:", self.train_ratio)
        split.addRow("Validation:", self.validation_ratio)
        split.addRow("Test:", self.test_ratio)
        root.addWidget(split_group)

        self.error_label = QLabel("")
        self.error_label.setWordWrap(True)
        self.error_label.setObjectName("secondaryText")
        root.addWidget(self.error_label)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("اعتماد المراجعة وتجهيز Corpus")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("إلغاء")
        buttons.accepted.connect(self._accept_review)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

    def _populate_documents(self) -> None:
        self._loading = True
        try:
            self.table.setRowCount(len(self.documents))
            for row, document in enumerate(self.documents):
                document_id = str(document["document_id"])
                issues = []
                for field, label in (
                    ("duplicate_chunks", "مكرر"),
                    ("tiny_chunks", "قصير"),
                    ("malformed_chunks", "ترميز مشبوه"),
                    ("unnormalized_chunks", "تطبيع"),
                    ("metadata_conflicts", "تعارض بيانات"),
                ):
                    count = int(document.get(field, 0))
                    if count:
                        issues.append(f"{label}: {count}")
                languages = document.get("languages") or {}
                language_text = ", ".join(
                    f"{name}:{count}" for name, count in sorted(languages.items())
                )
                values = [
                    str(document.get("title") or document.get("filename") or document_id),
                    str(document.get("file_type") or "—"),
                    str(document.get("pages_with_text", 0)),
                    str(document.get("chunks", 0)),
                    f"{int(document.get('characters', 0)):,}",
                    language_text or "—",
                    "، ".join(issues) or "لا توجد ملاحظات آلية",
                ]
                for column, value in enumerate(values):
                    item = QTableWidgetItem(value)
                    item.setData(Qt.ItemDataRole.UserRole, document_id)
                    self.table.setItem(row, column, item)
            self.table.resizeColumnsToContents()
            self.table.selectRow(0)
        finally:
            self._loading = False
        self._select_row(0, 0)

    def _save_current(self) -> None:
        document_id = self.current_document_id
        if document_id is None:
            return
        document = self.by_id[document_id]
        edited = {
            "title": self.title_input.text().strip(),
            "source": self.source_input.text().strip(),
            "license": self.license_input.text().strip(),
        }
        original = {
            field: str(document.get(field, ""))
            for field in edited
        }
        # A document whose records disagree on provenance must be explicitly unified.
        if edited != original or int(document.get("metadata_conflicts", 0)):
            self.metadata_overrides[document_id] = edited
        else:
            self.metadata_overrides.pop(document_id, None)

    def _select_row(self, row: int, _column: int) -> None:
        item = self.table.item(row, 0)
        if item is None:
            return
        document_id = str(item.data(Qt.ItemDataRole.UserRole))
        if document_id == self.current_document_id:
            return
        self._save_current()
        self.current_document_id = document_id
        document = self.by_id[document_id]
        self._loading = True
        try:
            self.title_input.setText(str(document.get("title", "")))
            self.source_input.setText(str(document.get("source", "")))
            self.license_input.setText(str(document.get("license", "")))
            self.include_document.setChecked(document_id not in self.excluded_documents)
            chunk_count = max(1, int(document.get("chunks", 0)))
            self.chunk_number.setRange(1, chunk_count)
            self.chunk_number.setValue(1)
            enabled = document_id not in self.excluded_documents and int(document.get("chunks", 0)) > 0
            self.chunk_number.setEnabled(enabled)
            self.include_chunk.setEnabled(enabled)
            self.document_details.setText(
                f"الملف: {document.get('filename', '—')} | "
                f"صفحات ظهر فيها نص: {document.get('pages_with_text', 0)} | "
                f"المقاطع: {document.get('chunks', 0)} | "
                f"تعارض metadata بين المقاطع: {document.get('metadata_conflicts', 0)}\n"
                "قد يكون ترقيم صفحات DOCX تقريبياً وفق علامات فواصل الصفحات المتاحة في الملف."
            )
        finally:
            self._loading = False
        self._load_chunk(self.chunk_number.value())

    def _toggle_document(self, included: bool) -> None:
        if self._loading or self.current_document_id is None:
            return
        if included:
            self.excluded_documents.discard(self.current_document_id)
        else:
            self.excluded_documents.add(self.current_document_id)
        enabled = included and int(self.by_id[self.current_document_id].get("chunks", 0)) > 0
        self.chunk_number.setEnabled(enabled)
        self.include_chunk.setEnabled(enabled)

    def _load_chunk(self, one_based_index: int) -> None:
        document_id = self.current_document_id
        if document_id is None:
            return
        document = self.by_id[document_id]
        count = int(document.get("chunks", 0))
        if count < 1:
            self.preview.clear()
            self.chunk_details.setText("لا توجد مقاطع قابلة للمعاينة.")
            return
        try:
            chunk = get_document_chunk(self.raw_path, document_id, one_based_index - 1)
        except (OSError, ValueError, IndexError) as exc:
            self.preview.clear()
            self.chunk_details.setText(f"تعذرت معاينة المقطع: {exc}")
            return
        self.current_chunk_id = str(chunk["id"])
        key = (document_id, self.current_chunk_id)
        self._loading_chunk = True
        self.include_chunk.setChecked(key not in self.excluded_chunks)
        self._loading_chunk = False
        notes = []
        if chunk.get("tiny"):
            notes.append("مقطع قصير")
        if chunk.get("malformed"):
            notes.append("رموز قد تشير إلى ترميز تالف")
        if chunk.get("unnormalized"):
            notes.append("يحتاج تطبيع النص")
        self.chunk_details.setText(
            f"المقطع {one_based_index}/{count} | ID: {chunk['id']} | "
            f"الأحرف: {chunk['characters']} | اللغة: {chunk.get('language', '—')} | "
            f"الصفحة: {chunk.get('page') or '—'} | الفصل: {chunk.get('chapter') or '—'} | "
            f"الملاحظات: {'، '.join(notes) if notes else 'لا توجد'}"
        )
        self.preview.setPlainText(str(chunk["text"]))

    def _toggle_chunk(self, included: bool) -> None:
        if self._loading_chunk or self.current_document_id is None or not self.current_chunk_id:
            return
        key = (self.current_document_id, self.current_chunk_id)
        if included:
            self.excluded_chunks.discard(key)
        else:
            self.excluded_chunks.add(key)

    def _accept_review(self) -> None:
        self._save_current()
        if self.train_ratio.value() + self.validation_ratio.value() + self.test_ratio.value() != 100:
            self.error_label.setText("يجب أن يكون مجموع نسب Train وValidation وTest مساوياً 100%.")
            return

        active_documents = 0
        for document_id, document in self.by_id.items():
            if document_id in self.excluded_documents:
                continue
            count = int(document.get("chunks", 0))
            excluded = sum(1 for doc_id, _record_id in self.excluded_chunks if doc_id == document_id)
            if excluded >= count:
                continue
            fields = self.metadata_overrides.get(document_id, {
                "title": str(document.get("title", "")),
                "source": str(document.get("source", "")),
                "license": str(document.get("license", "")),
            })
            if not fields.get("source", "").strip():
                self.error_label.setText(f"أدخل مصدر الكتاب: {fields.get('title', document_id)}")
                return
            if fields.get("license", "").strip().casefold() in _REJECTED_LICENSES:
                self.error_label.setText(
                    f"أدخل ترخيصًا أو إذنًا واضحًا لتدريب النموذج للكتاب: {fields.get('title', document_id)}"
                )
                return
            if int(document.get("metadata_conflicts", 0)) and document_id not in self.metadata_overrides:
                self.error_label.setText(f"وحّد بيانات المصدر والترخيص للمقاطع التابعة للكتاب: {document_id}")
                return
            active_documents += 1
        if active_documents < 3:
            self.error_label.setText(
                "يجب الإبقاء على ثلاثة كتب/مجموعات مستقلة على الأقل لإنشاء Train وValidation وTest."
            )
            return

        self._selection = {
            "excluded_documents": set(self.excluded_documents),
            "excluded_chunks": set(self.excluded_chunks),
            "metadata_overrides": {key: dict(value) for key, value in self.metadata_overrides.items()},
            "train_ratio": self.train_ratio.value() / 100.0,
            "validation_ratio": self.validation_ratio.value() / 100.0,
            "test_ratio": self.test_ratio.value() / 100.0,
        }
        self.accept()

    def selection(self) -> dict[str, object]:
        """Return a defensive copy of the approved review choices."""
        return {
            **self._selection,
            "excluded_documents": set(self._selection.get("excluded_documents", set())),
            "excluded_chunks": set(self._selection.get("excluded_chunks", set())),
            "metadata_overrides": {
                key: dict(value)
                for key, value in dict(self._selection.get("metadata_overrides", {})).items()
            },
        }
