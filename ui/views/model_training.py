"""Desktop workspace for importing, preparing, and training AI AYFAM locally."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
import threading

from PyQt6.QtCore import QThread, QTimer, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QFileDialog,
    QCheckBox,
    QFormLayout,
    QGroupBox,
    QScrollArea,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from model_factory.active_model import ACTIVE_MODEL_MANIFEST, read_active_model_manifest
from model_factory.corpus_review import inspect_raw_corpus, prepare_reviewed_corpus
from model_factory.data import fingerprint_file
from model_factory.corpus_workspace import default_corpus_root, import_raw_corpus
from model_factory.document_ingestion import DocumentInput, ingest_documents
from ui.views.corpus_review_dialog import CorpusReviewDialog
from model_factory.hardware import HardwareProfile, build_training_plan
from model_factory.runner import TrainingRunConfig, run_training


_PHASE_LABELS = {
    "importing": "نسخ ملف JSONL الخام إلى مساحة AYFAM المحلية",
    "extracting_documents": "استخراج النصوص من المستندات وحفظ بيانات المصدر",
    "reviewing": "مراجعة الكتب والمقاطع وجودة النص قبل الاعتماد",
    "preparing": "تطبيق اختيارات المراجعة وتجهيز تقسيمات corpus",
    "validating_corpus": "التحقق من corpus ومصدر البيانات والتقسيمات",
    "preparing_tokenizer": "تجهيز tokenizer من بيانات التدريب فقط",
    "resuming_checkpoint": "تحميل checkpoint السابق",
    "evaluating_before": "قياس خط الأساس قبل تحديث الأوزان",
    "training": "تدريب Transformer محليًا على كامل مجموعة Train",
    "evaluating_after": "قياس التحسن بعد التدريب على Validation وTest",
    "exporting_model": "حفظ نسخة المحادثة وتفعيل النموذج المحلي",
    "completed": "اكتملت العملية وأصبح النموذج متاحًا في المحادثة",
}


class CorpusPreparationWorker(QThread):
    """Import/extract documents and inspect them before any preparation or training."""

    phase_changed = pyqtSignal(str)
    completed = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(
        self,
        source_paths: list[Path],
        license_name: str = "",
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        self.source_paths = [Path(path) for path in source_paths]
        self.license_name = license_name

    def run(self) -> None:
        try:
            if len(self.source_paths) == 1 and self.source_paths[0].suffix.casefold() == ".jsonl":
                self.phase_changed.emit("importing")
                imported_path = import_raw_corpus(self.source_paths[0])
                ingestion_report = None
            else:
                if any(path.suffix.casefold() == ".jsonl" for path in self.source_paths):
                    raise ValueError("Select one JSONL file by itself, or select document files only.")
                self.phase_changed.emit("extracting_documents")
                raw_dir = default_corpus_root() / "raw"
                raw_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
                run_id = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
                raw_path = raw_dir / f"documents-{run_id}.jsonl"
                documents = [
                    DocumentInput(
                        path=path,
                        source=path.name,
                        license=self.license_name,
                        title=path.stem,
                    )
                    for path in self.source_paths
                ]
                ingestion = ingest_documents(
                    documents,
                    raw_path,
                    require_held_out=False,
                )
                imported_path = Path(ingestion.output_path)
                ingestion_report = ingestion.to_dict()

            self.phase_changed.emit("reviewing")
            review_report = inspect_raw_corpus(imported_path)
        except Exception as exc:
            self.failed.emit(str(exc))
        else:
            self.completed.emit({
                "imported_path": str(imported_path),
                "ingestion_report": ingestion_report,
                "review_report": review_report,
            })


class CorpusReviewPreparationWorker(QThread):
    """Apply explicit review choices and create a validated training corpus."""

    phase_changed = pyqtSignal(str)
    completed = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(
        self,
        raw_path: Path,
        prepared_path: Path,
        selection: dict[str, object],
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        self.raw_path = Path(raw_path)
        self.prepared_path = Path(prepared_path)
        self.selection = selection

    def run(self) -> None:
        try:
            self.phase_changed.emit("preparing")
            report = prepare_reviewed_corpus(
                self.raw_path,
                self.prepared_path,
                excluded_documents=self.selection["excluded_documents"],
                excluded_chunks=self.selection["excluded_chunks"],
                metadata_overrides=self.selection["metadata_overrides"],
                train_ratio=float(self.selection["train_ratio"]),
                validation_ratio=float(self.selection["validation_ratio"]),
                test_ratio=float(self.selection["test_ratio"]),
                full_corpus_training=bool(self.selection.get("full_corpus_training", False)),
            )
        except Exception as exc:
            self.failed.emit(str(exc))
        else:
            self.completed.emit({
                "prepared_path": str(self.prepared_path),
                "report": report,
            })


class ModelTrainingWorker(QThread):
    """Run model training away from the GUI thread and expose safe progress signals."""

    phase_changed = pyqtSignal(str)
    plan_ready = pyqtSignal(object)
    progress_changed = pyqtSignal(object)
    completed = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, config: TrainingRunConfig, parent: QWidget | None = None):
        super().__init__(parent)
        self.config = config
        self._stop_event = threading.Event()
        self._plan: dict[str, object] = {}

    def request_stop(self) -> None:
        self._stop_event.set()

    def _report_plan(self, payload: dict[str, object]) -> None:
        self._plan = dict(payload)
        self.plan_ready.emit(self._plan)

    def run(self) -> None:
        try:
            result = run_training(
                self.config,
                on_phase=self.phase_changed.emit,
                on_plan=self._report_plan,
                on_step=self._report_step,
                should_stop=self._stop_event.is_set,
            )
        except Exception as exc:
            self.failed.emit(str(exc))
        else:
            self.completed.emit(result.to_dict())

    def _report_step(self, step_result) -> None:
        starting_step = int(self._plan.get("starting_step", 0))
        run_step = max(0, step_result.step - starting_step)
        steps_per_epoch = max(1, int(self._plan.get("optimizer_steps_per_epoch", 1)))
        batches_per_epoch = max(1, int(self._plan.get("batches_per_epoch", 1)))
        gradient_accumulation = max(1, int(self._plan.get("gradient_accumulation_steps", 1)))
        micro_batch = max(1, int(self._plan.get("micro_batch_size", 1)))
        blocks_per_epoch = max(1, int(self._plan.get("train_blocks_per_epoch", 1)))
        total_tokens = max(0, int(self._plan.get("train_tokens", 0)))
        block_size = max(1, int(self._plan.get("block_size", 1)))
        epoch = min(
            max(1, int(self._plan.get("epochs", 1))),
            max(1, (run_step + steps_per_epoch - 1) // steps_per_epoch),
        )
        steps_in_epoch = ((run_step - 1) % steps_per_epoch) + 1 if run_step else 0
        batches_seen = min(batches_per_epoch, steps_in_epoch * gradient_accumulation)
        blocks_seen = min(blocks_per_epoch, batches_seen * micro_batch)
        tokens_seen = min(
            total_tokens,
            int(round(total_tokens * blocks_seen / blocks_per_epoch)),
        )
        self.progress_changed.emit({
            "step": run_step,
            "global_step": step_result.step,
            "epoch": epoch,
            "epochs": int(self._plan.get("epochs", 1)),
            "steps_in_epoch": steps_in_epoch,
            "steps_per_epoch": steps_per_epoch,
            "blocks_seen": blocks_seen,
            "blocks_total": blocks_per_epoch,
            "tokens_seen": tokens_seen,
            "tokens_total": total_tokens,
            "loss": step_result.loss,
            "learning_rate": step_result.learning_rate,
        })


class ModelTrainingView(QWidget):
    """A user-controlled data and training panel; opening it starts no work."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.worker: ModelTrainingWorker | None = None
        self.prepare_worker: CorpusPreparationWorker | None = None
        self.review_worker: CorpusReviewPreparationWorker | None = None
        self.pending_review_path: Path | None = None
        self.pending_review_report: dict[str, object] | None = None
        self.raw_document_paths: list[Path] = []
        self.profile = HardwareProfile.detect()
        self.plan = build_training_plan(self.profile)
        self._build_ui()
        self.memory_timer = QTimer(self)
        self.memory_timer.setInterval(1_000)
        self.memory_timer.timeout.connect(self._refresh_memory)
        self.memory_timer.start()
        self._refresh_memory()

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        self.scroll_area = QScrollArea(self)
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        content = QWidget()
        root = QVBoxLayout(content)
        root.setContentsMargins(22, 20, 22, 22)
        root.setSpacing(14)

        title = QLabel("تدريب نموذج AYFAM المحلي")
        title.setObjectName("sectionTitle")
        root.addWidget(title)

        intro = QLabel(
            "اختر كتب PDF أو TXT أو DOCX أو Markdown، أو ملف JSONL جاهزًا. يستخرج AYFAM النصوص "
            "ويحفظ المصدر ثم يجهز البيانات للتدريب. لا يبدأ التدريب تلقائيًا. "
            "Select PDF, TXT, DOCX, Markdown, or an existing JSONL corpus. Training never starts automatically."
        )
        intro.setWordWrap(True)
        intro.setObjectName("secondaryText")
        root.addWidget(intro)

        hardware_group = QGroupBox("ملف الجهاز وخطة التدريب")
        hardware_layout = QVBoxLayout(hardware_group)
        self.hardware_label = QLabel()
        self.hardware_label.setWordWrap(True)
        hardware_layout.addWidget(self.hardware_label)
        self.plan_label = QLabel()
        self.plan_label.setWordWrap(True)
        hardware_layout.addWidget(self.plan_label)
        root.addWidget(hardware_group)
        self._refresh_hardware_summary()

        active_group = QGroupBox("حالة النموذج المحلي المستخدم في المحادثة")
        active_layout = QVBoxLayout(active_group)
        self.active_model_label = QLabel()
        self.active_model_label.setWordWrap(True)
        self.active_model_label.setObjectName("secondaryText")
        active_layout.addWidget(self.active_model_label)
        root.addWidget(active_group)
        self._refresh_active_model_status()

        raw_group = QGroupBox("1. استيراد ملف البيانات الخام")
        raw_layout = QVBoxLayout(raw_group)
        raw_row = QHBoxLayout()
        self.raw_corpus_input = QLineEdit()
        self.raw_corpus_input.setReadOnly(True)
        self.raw_corpus_input.setPlaceholderText("اختر ملف JSONL خامًا يحتوي على النص والمصدر والترخيص")
        self.raw_corpus_input.setMinimumHeight(36)
        self.raw_browse_button = QPushButton("اختيار كتب / ملفات")
        self.raw_browse_button.clicked.connect(self._browse_raw_corpus)
        raw_row.addWidget(self.raw_corpus_input, 1)
        raw_row.addWidget(self.raw_browse_button)
        raw_layout.addLayout(raw_row)

        license_help = QLabel(
            "تُستخرج النصوص أولاً. لا يمكن للبرنامج استنتاج حقوق النشر من الملف؛ "
            "أدخل مصدر كل كتاب وترخيصه أو إذن التدريب في شاشة المراجعة التالية."
        )
        license_help.setWordWrap(True)
        license_help.setObjectName("secondaryText")
        raw_layout.addWidget(license_help)

        self.prepare_button = QPushButton("استخراج ومعاينة البيانات / Extract and review")
        self.prepare_button.clicked.connect(self.prepare_corpus)
        raw_layout.addWidget(self.prepare_button)
        seed_path = Path(__file__).resolve().parents[2] / "data" / "seed_corpus" / "v0.1" / "ayfam-seed-v0.1.jsonl"
        if seed_path.is_file():
            self.raw_corpus_input.setText(str(seed_path))
        root.addWidget(raw_group)

        prepared_group = QGroupBox("2. مجموعة البيانات الجاهزة للتدريب")
        prepared_layout = QVBoxLayout(prepared_group)
        prepared_row = QHBoxLayout()
        self.corpus_input = QLineEdit()
        self.corpus_input.setPlaceholderText("سيظهر هنا ملف JSONL بعد نجاح التجهيز والتدقيق")
        self.corpus_input.setClearButtonEnabled(True)
        self.corpus_input.setMinimumHeight(36)
        self.corpus_input.textChanged.connect(self._refresh_start_button)
        self.browse_button = QPushButton("اختيار ملف جاهز")
        self.browse_button.clicked.connect(self._browse_corpus)
        prepared_row.addWidget(self.corpus_input, 1)
        prepared_row.addWidget(self.browse_button)
        prepared_layout.addLayout(prepared_row)

        options = QFormLayout()
        self.epochs_input = QSpinBox()
        self.epochs_input.setRange(1, 100)
        self.epochs_input.setValue(3)
        self.epochs_input.setToolTip(
            "عدد مرات المرور الكاملة على كل مقاطع Train. تُحسب خطوات optimizer تلقائيًا من حجم البيانات."
        )
        self.vocab_auto_label = QLabel(
            "تلقائي — يختار AYFAM حجم BPE بعد قياس UTF-8 bytes والذاكرة المتاحة. "
            "512 ليس عدد كلمات؛ إنه هدف لحجم قاموس الرموز."
        )
        self.vocab_auto_label.setWordWrap(True)
        self.vocab_auto_label.setObjectName("secondaryText")
        self.resume_checkbox = QCheckBox("استكمال آخر checkpoint إذا كان من مجموعة البيانات نفسها")
        self.resume_checkbox.setChecked(True)
        self.resume_checkbox.setToolTip(
            "يُستكمل النموذج السابق فقط عند تطابق بصمة corpus وملف tokenizer؛ وإلا يبدأ نموذج جديد."
        )
        options.addRow("مرات المرور الكاملة (Epochs):", self.epochs_input)
        options.addRow("حجم قاموس الرموز:", self.vocab_auto_label)
        options.addRow(self.resume_checkbox)
        prepared_layout.addLayout(options)
        self.workload_label = QLabel(
            "بعد اختيار Corpus سيحسب AYFAM عدد السجلات والـTokens والكتل وخطوات كل Epoch تلقائيًا."
        )
        self.workload_label.setWordWrap(True)
        self.workload_label.setObjectName("secondaryText")
        prepared_layout.addWidget(self.workload_label)
        root.addWidget(prepared_group)

        actions = QHBoxLayout()
        self.start_button = QPushButton("بدء التدريب المحلي")
        self.start_button.setObjectName("primaryButton")
        self.start_button.setEnabled(False)
        self.start_button.clicked.connect(self.start_training)
        self.stop_button = QPushButton("إيقاف آمن وحفظ checkpoint")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.request_stop)
        actions.addWidget(self.start_button)
        actions.addWidget(self.stop_button)
        actions.addStretch(1)
        root.addLayout(actions)

        progress_group = QGroupBox("مراقبة الاستيراد والتدريب")
        progress_layout = QVBoxLayout(progress_group)
        self.status_label = QLabel("جاهز — لم يبدأ استيراد أو تدريب")
        self.status_label.setWordWrap(True)
        progress_layout.addWidget(self.status_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(0)
        progress_layout.addWidget(self.progress_bar)

        metrics = QHBoxLayout()
        self.step_label = QLabel("الخطوة: لم يبدأ الحساب بعد")
        self.loss_label = QLabel("Loss: —")
        self.learning_rate_label = QLabel("Learning rate: —")
        self.memory_label = QLabel("ذاكرة العملية: —")
        for label in (self.step_label, self.loss_label, self.learning_rate_label, self.memory_label):
            label.setWordWrap(True)
            metrics.addWidget(label)
        progress_layout.addLayout(metrics)

        self.output_label = QLabel("مكان الحفظ: checkpoint + inference artifact محليان")
        self.output_label.setWordWrap(True)
        progress_layout.addWidget(self.output_label)
        root.addWidget(progress_group)

        self.log_output = QPlainTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setMaximumBlockCount(250)
        self.log_output.setPlaceholderText("تظهر مراحل استيراد البيانات وتجهيزها والتدريب هنا.")
        self.log_output.setMinimumHeight(150)
        root.addWidget(self.log_output, 1)

        disclaimer = QLabel(
            "يتضمن المستودع Corpus تجريبيًا صغيرًا لاختبار مسار العمل، وليس مجموعة تدريب كافية لجودة نموذج نهائي. "
            "استخدم فقط بيانات تملك حق تدريب نموذج عليها، وراجع المصادر والمحتوى قبل التدريب."
        )
        disclaimer.setWordWrap(True)
        disclaimer.setObjectName("secondaryText")
        root.addWidget(disclaimer)

        self.scroll_area.setWidget(content)
        outer.addWidget(self.scroll_area, 1)

    def _refresh_active_model_status(self) -> None:
        manifest = read_active_model_manifest()
        if manifest is None:
            self.active_model_label.setText(
                "لا يوجد نموذج عصبي مدرّب ومفعّل للمحادثة بعد. "
                "بعد أول تدريب ناجح سيظهر هنا checkpoint الفعّال."
            )
            return
        self.active_model_label.setText(
            f"النموذج فعّال في المحادثة المحلية | "
            f"Global step: {int(manifest.get('global_step', 0)):,} | "
            f"Epochs تراكمية: {int(manifest.get('epochs_completed', 0))} | "
            f"Parameters: {int(manifest.get('model_parameters', 0)):,} | "
            f"Corpus: {manifest.get('data_fingerprint', '')[:16]}…"
        )

    def _refresh_hardware_summary(self) -> None:
        self.hardware_label.setText(
            f"RAM الكلية: {self.profile.total_ram_mb:,} MB | "
            f"المتاحة لحظة الفحص: {self.profile.available_ram_mb:,} MB | "
            f"أنوية CPU المنطقية: {self.profile.logical_cores} | "
            f"CUDA: {'مكتشف' if self.profile.cuda_device_detected else 'غير مكتشف'}"
        )
        self.plan_label.setText(
            f"خطة الذاكرة: micro-batch={self.plan.micro_batch_size}، "
            f"تجميع التدرج={self.plan.gradient_accumulation_steps}، "
            f"CPU threads={self.plan.num_threads}، "
            f"حفظ checkpoint كل {self.plan.checkpoint_interval_steps} خطوة. "
            "كل كتل Train تمر كاملة في كل Epoch. وضع تدريب كامل الكتاب يستخدم 100% من المقاطع؛ "
            "وضع التقييم المستقل يحجز Validation وTest ولا يدرّب عليهما."
        )

    def _browse_raw_corpus(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(
            self,
            "اختيار كتب أو ملف بيانات خام / Select books or a raw corpus",
            str(Path.home()),
            "AYFAM documents (*.pdf *.txt *.docx *.md *.markdown *.jsonl);;"
            "PDF (*.pdf);;Text (*.txt);;Word (*.docx);;Markdown (*.md *.markdown);;JSON Lines (*.jsonl)",
        )
        if paths:
            self.pending_review_path = None
            self.pending_review_report = None
            self.prepare_button.setText("استخراج ومعاينة البيانات / Extract and review")
            self.raw_document_paths = [Path(path) for path in paths]
            names = ", ".join(path.name for path in self.raw_document_paths[:3])
            if len(self.raw_document_paths) > 3:
                names += f", +{len(self.raw_document_paths) - 3}"
            self.raw_corpus_input.setText(
                f"{len(self.raw_document_paths)} file(s): {names}"
            )

    def _browse_corpus(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "اختيار corpus مُجهّز",
            str(default_corpus_root() / "prepared"),
            "JSON Lines (*.jsonl);;All files (*)",
        )
        if path:
            self.corpus_input.setText(path)

    def _refresh_start_button(self) -> None:
        """Enable training only when an existing prepared corpus is selected and workers are idle."""
        corpus_text = self.corpus_input.text().strip()
        prepared_ready = bool(corpus_text and Path(corpus_text).expanduser().is_file())
        workers_idle = all(
            worker is None or not worker.isRunning()
            for worker in (self.worker, self.prepare_worker, self.review_worker)
        )
        self.start_button.setEnabled(prepared_ready and workers_idle)

    def prepare_corpus(self) -> None:
        if (self.prepare_worker is not None and self.prepare_worker.isRunning()) or (
            self.worker is not None and self.worker.isRunning()
        ) or (self.review_worker is not None and self.review_worker.isRunning()):
            return

        if self.pending_review_path is not None and self.pending_review_report is not None:
            self._show_corpus_review()
            return

        source_paths = list(self.raw_document_paths)
        if not source_paths:
            raw_text = self.raw_corpus_input.text().strip()
            if raw_text:
                source_paths = [Path(raw_text).expanduser()]
        if not source_paths or any(not path.is_file() for path in source_paths):
            self.status_label.setText("اختر ملفات موجودة أولًا / Select existing files first.")
            return

        jsonl_paths = [path for path in source_paths if path.suffix.casefold() == ".jsonl"]
        if jsonl_paths and (len(source_paths) != 1 or len(jsonl_paths) != 1):
            self.status_label.setText(
                "اختر ملف JSONL واحدًا وحده، أو اختر الكتب والمستندات فقط. / "
                "Select one JSONL file alone, or select document files only."
            )
            return
        self.prepare_button.setEnabled(False)
        self.raw_browse_button.setEnabled(False)
        self.browse_button.setEnabled(False)
        self.start_button.setEnabled(False)
        self.status_label.setText("بدء استخراج المستندات وفحص جودة النصوص…")
        self._append_log("الملفات المحددة: " + ", ".join(path.name for path in source_paths))
        self.prepare_worker = CorpusPreparationWorker(
            source_paths,
            "",
            self,
        )
        self.prepare_worker.phase_changed.connect(self._on_prepare_phase_changed)
        self.prepare_worker.completed.connect(self._on_corpus_prepared)
        self.prepare_worker.failed.connect(self._on_prepare_failed)
        self.prepare_worker.finished.connect(self._on_prepare_finished)
        self.prepare_worker.start()

    def _show_corpus_review(self) -> None:
        if self.pending_review_path is None or self.pending_review_report is None:
            return
        dialog = CorpusReviewDialog(
            self.pending_review_path,
            self.pending_review_report,
            self,
        )
        if not dialog.exec():
            self.status_label.setText(
                "تم الاحتفاظ بالبيانات الخام محليًا. لم يتم اعتمادها أو تجهيزها للتدريب."
            )
            self.prepare_button.setText("إعادة فتح مراجعة البيانات")
            return

        selection = dialog.selection()
        prepared_dir = default_corpus_root() / "prepared"
        prepared_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        run_id = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        label = self.pending_review_path.stem[:48]
        prepared_path = prepared_dir / f"{label}-{run_id}-prepared.jsonl"

        self.prepare_button.setEnabled(False)
        self.raw_browse_button.setEnabled(False)
        self.browse_button.setEnabled(False)
        self.start_button.setEnabled(False)
        self.status_label.setText("تطبيق قرارات المراجعة وتجهيز corpus المعتمد…")
        self._append_log(
            "المراجعة: "
            f"استبعاد {len(selection['excluded_documents'])} كتاب و"
            f"{len(selection['excluded_chunks'])} مقطع."
        )
        self.review_worker = CorpusReviewPreparationWorker(
            self.pending_review_path,
            prepared_path,
            selection,
            self,
        )
        self.review_worker.phase_changed.connect(self._on_prepare_phase_changed)
        self.review_worker.completed.connect(self._on_review_prepared)
        self.review_worker.failed.connect(self._on_review_failed)
        self.review_worker.finished.connect(self._on_review_finished)
        self.review_worker.start()

    def _on_prepare_phase_changed(self, phase: str) -> None:
        label = _PHASE_LABELS.get(phase, phase)
        self.status_label.setText(label)
        self._append_log(label)

    def _on_corpus_prepared(self, payload: dict) -> None:
        self.pending_review_path = Path(str(payload.get("imported_path", "")))
        self.pending_review_report = payload.get("review_report") or {}
        self.status_label.setText("اكتمل الاستخراج. راجع الكتب والمقاطع قبل اعتمادها.")
        self.raw_document_paths = []
        self.raw_corpus_input.setText(str(self.pending_review_path))
        self.prepare_button.setText("مراجعة البيانات وتجهيز Corpus")
        self._append_log(f"النسخة الخام المحلية: {self.pending_review_path}")

        ingestion = payload.get("ingestion_report") or {}
        if ingestion:
            self._append_log(
                "الاستخراج: "
                f"مستندات={ingestion.get('documents', 0)}, "
                f"صفحات={ingestion.get('pages', 0)}, "
                f"صفحات فارغة={ingestion.get('empty_pages', 0)}, "
                f"مقاطع={ingestion.get('chunks', 0)}, "
                f"أحرف={ingestion.get('characters', 0):,}"
            )
            self._append_log(f"لغات المستندات: {ingestion.get('languages', {})}")
        review = self.pending_review_report
        self._append_log(
            "فحص الجودة: "
            f"مكررات={review.get('duplicate_chunks', 0)}, "
            f"قصيرة={review.get('tiny_chunks', 0)}, "
            f"ترميز مشبوه={review.get('malformed_chunks', 0)}, "
            f"تحتاج تطبيعًا={review.get('unnormalized_chunks', 0)}"
        )
        self._show_corpus_review()

    def _on_prepare_failed(self, message: str) -> None:
        self.status_label.setText("تعذر استيراد أو تجهيز مجموعة البيانات.")
        self._append_log(f"خطأ تجهيز البيانات: {message}")

    def _on_prepare_finished(self) -> None:
        worker = self.prepare_worker
        self.prepare_worker = None
        if worker is not None:
            worker.deleteLater()
        training_running = self.worker is not None and self.worker.isRunning()
        review_running = self.review_worker is not None and self.review_worker.isRunning()
        enabled = not training_running and not review_running
        self.prepare_button.setEnabled(enabled)
        self.raw_browse_button.setEnabled(enabled)
        self.browse_button.setEnabled(enabled)
        prepared_text = self.corpus_input.text().strip()
        prepared_ready = bool(prepared_text and Path(prepared_text).expanduser().is_file())
        self.start_button.setEnabled(enabled and prepared_ready)
        if self.pending_review_path is not None:
            self.prepare_button.setText("إعادة فتح مراجعة البيانات")

    def _on_review_prepared(self, payload: dict) -> None:
        report = payload.get("report") or {}
        splits = report.get("records_by_split") or {}
        self.corpus_input.setText(str(payload.get("prepared_path", "")))
        self.pending_review_path = None
        self.pending_review_report = None
        self.prepare_button.setText("استخراج ومعاينة البيانات / Extract and review")
        self.status_label.setText("اعتمدت المراجعة وتم تجهيز corpus واجتاز التدقيق.")
        self._append_log(f"ملف التدريب المعتمد: {payload.get('prepared_path')}")
        self._append_log(
            "السجلات النهائية: "
            f"train={splits.get('train', 0)}, "
            f"validation={splits.get('validation', 0)}, "
            f"test={splits.get('test', 0)}"
        )
        self._append_log(
            "قرارات المراجعة: "
            f"سجلات={report.get('reviewed_records', 0)}, "
            f"كتب مستبعدة={report.get('excluded_documents', 0)}, "
            f"مقاطع مستبعدة={report.get('excluded_chunks', 0)}"
        )
        self._append_log(
            "التقسيمات: "
            f"Train={report.get('train_ratio', 0):.0%}, "
            f"Validation={report.get('validation_ratio', 0):.0%}, "
            f"Test={report.get('test_ratio', 0):.0%}"
        )
        self._append_log(f"SHA-256: {report.get('fingerprint', '')}")
        self._append_log(f"Manifest: {report.get('manifest_path', '')}")

    def _on_review_failed(self, message: str) -> None:
        self.status_label.setText("لم يتم تجهيز corpus بعد المراجعة.")
        self._append_log(f"خطأ اعتماد corpus: {message}")

    def _on_review_finished(self) -> None:
        worker = self.review_worker
        self.review_worker = None
        if worker is not None:
            worker.deleteLater()
        training_running = self.worker is not None and self.worker.isRunning()
        importing_running = self.prepare_worker is not None and self.prepare_worker.isRunning()
        enabled = not training_running and not importing_running
        self.prepare_button.setEnabled(enabled)
        self.raw_browse_button.setEnabled(enabled)
        self.browse_button.setEnabled(enabled)
        prepared_text = self.corpus_input.text().strip()
        prepared_ready = bool(prepared_text and Path(prepared_text).expanduser().is_file())
        self.start_button.setEnabled(enabled and prepared_ready)
        if self.pending_review_path is not None:
            self.prepare_button.setText("إعادة فتح مراجعة البيانات")

    def _refresh_memory(self) -> None:
        try:
            for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
                if line.startswith("VmRSS:"):
                    value_kb = int(line.split()[1])
                    self.memory_label.setText(f"ذاكرة العملية: {value_kb / 1024:.0f} MB")
                    return
        except (OSError, ValueError, IndexError):
            pass
        self.memory_label.setText("ذاكرة العملية: غير متاحة")

    def _append_log(self, message: str) -> None:
        self.log_output.appendPlainText(message)

    def start_training(self) -> None:
        if self.prepare_worker is not None and self.prepare_worker.isRunning():
            return
        if self.worker is not None and self.worker.isRunning():
            return
        if self.review_worker is not None and self.review_worker.isRunning():
            return
        corpus_path = Path(self.corpus_input.text().strip()).expanduser()
        if not corpus_path.is_file():
            self.status_label.setText("اختر ملف corpus مُجهّزًا موجودًا أولًا.")
            return

        run_id = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        output_dir = (
            Path.home() / ".local" / "share" / "ayfam" / "training" / "runs" / f"run-{run_id}"
        )
        try:
            current_fingerprint = fingerprint_file(corpus_path)
        except OSError as exc:
            self.status_label.setText(f"تعذّر قراءة بصمة Corpus: {exc}")
            return

        resume_checkpoint = None
        tokenizer_config_path = None
        previous_epochs_completed = 0
        previous = read_active_model_manifest() if self.resume_checkbox.isChecked() else None
        if previous and previous.get("data_fingerprint") == current_fingerprint:
            previous_checkpoint = Path(previous["checkpoint_path"]).expanduser()
            previous_tokenizer = Path(str(previous.get("tokenizer_path") or "")).expanduser()
            if previous_checkpoint.is_file() and previous_tokenizer.is_file():
                resume_checkpoint = previous_checkpoint
                tokenizer_config_path = previous_tokenizer
                previous_epochs_completed = int(previous.get("epochs_completed", 0))

        config = TrainingRunConfig(
            corpus_path=corpus_path,
            checkpoint_path=output_dir / "latest.pt",
            max_steps=None,
            epochs=self.epochs_input.value(),
            device="cpu",
            tokenizer_mode="bpe",
            tokenizer_vocab_size=None,
            tokenizer_config_path=tokenizer_config_path,
            tokenizer_output_path=output_dir / "tokenizer.json",
            resume_checkpoint=resume_checkpoint,
            previous_epochs_completed=previous_epochs_completed,
            inference_artifact_path=output_dir / "inference.pt",
            active_model_manifest_path=ACTIVE_MODEL_MANIFEST,
        )

        self.log_output.clear()
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(0)
        self.step_label.setText("حساب حجم مجموعة Train والـTokens...")
        self.loss_label.setText("Loss: —")
        self.learning_rate_label.setText("Learning rate: —")
        self.output_label.setText(f"حفظ الجلسة: {output_dir}")
        self.workload_label.setText("يجري قياس النص الفعلي لاختيار قاموس الرموز وعدد الخطوات...")
        self.status_label.setText(
            "سيُستخدم النموذج السابق بعد التحقق من تطابق corpus."
            if resume_checkpoint else "يتم تجهيز خطة تدريب كاملة من أوزان جديدة..."
        )
        if resume_checkpoint is not None:
            self._append_log(f"استكمال checkpoint: {resume_checkpoint}")
        self.start_button.setEnabled(False)
        self.browse_button.setEnabled(False)
        self.prepare_button.setEnabled(False)
        self.raw_browse_button.setEnabled(False)
        self.epochs_input.setEnabled(False)
        self.resume_checkbox.setEnabled(False)
        self.stop_button.setEnabled(True)

        self.worker = ModelTrainingWorker(config, self)
        self.worker.phase_changed.connect(self._on_phase_changed)
        self.worker.plan_ready.connect(self._on_training_plan)
        self.worker.progress_changed.connect(self._on_progress)
        self.worker.completed.connect(self._on_completed)
        self.worker.failed.connect(self._on_failed)
        self.worker.finished.connect(self._on_worker_finished)
        self.worker.start()

    def request_stop(self) -> None:
        if self.worker is None or not self.worker.isRunning():
            return
        self.worker.request_stop()
        self.stop_button.setEnabled(False)
        self.status_label.setText(
            "وصل طلب الإيقاف. سيتوقف التدريب عند أقرب خطوة optimizer ويحفظ آخر checkpoint."
        )
        self._append_log("تم طلب إيقاف آمن؛ لن تُنهى العملية قسرًا.")

    def _on_phase_changed(self, phase: str) -> None:
        label = _PHASE_LABELS.get(phase, phase)
        self.status_label.setText(label)
        self._append_log(label)

    def _on_training_plan(self, payload: dict) -> None:
        total_steps = int(payload.get("additional_steps", 1))
        self.progress_bar.setRange(0, max(1, total_steps))
        self.progress_bar.setValue(0)
        self._training_plan = payload
        train_records = int(payload.get("train_records", 0))
        train_tokens = int(payload.get("train_tokens", 0))
        blocks = int(payload.get("train_blocks_per_epoch", 0))
        steps_per_epoch = int(payload.get("optimizer_steps_per_epoch", 0))
        epochs = int(payload.get("epochs", 0))
        vocab_target = int(payload.get("tokenizer_vocab_target", 0))
        vocab_actual = int(payload.get("tokenizer_vocab_actual", 0))
        summary = (
            f"Train: {train_records:,} مقطع | {train_tokens:,} Token هدف لكل Epoch | "
            f"{blocks:,} كتلة بطول {payload.get('block_size')} Token. "
            f"كل Epoch = {steps_per_epoch:,} خطوة Optimizer؛ "
            f"{epochs} Epoch = {total_steps:,} خطوة إضافية. "
            f"BPE تلقائي: الهدف {vocab_target}، الفعلي {vocab_actual}."
        )
        if payload.get("starting_step"):
            summary += f" استكمال من global step {payload['starting_step']}."
        self.workload_label.setText(summary)
        self._append_log(summary)
        evaluation_split = str(payload.get("evaluation_split", "validation/test (held-out)"))
        if evaluation_split == "train (in-sample)":
            self._append_log(
                "وضع كامل الكتاب: 100% من المقاطع المقبولة تدخل في Train في كل Epoch. "
                "المقارنة التالية على Train نفسه وليست اختبارًا مستقلاً للتعميم."
            )
        else:
            self._append_log(
                "وضع التقييم المستقل: جميع كتل Train تدخل في كل Epoch؛ "
                "Validation وTest للقياس فقط ولا تدخلان في تحديث الأوزان."
            )
        self._append_log(
            f"خطة الذاكرة: micro-batch={payload.get('micro_batch_size')}, "
            f"gradient accumulation={payload.get('gradient_accumulation_steps')}, "
            f"block size={payload.get('block_size')}."
        )

    def _on_progress(self, payload: dict) -> None:
        step = int(payload.get("step", 0))
        loss = float(payload.get("loss", 0.0))
        learning_rate = float(payload.get("learning_rate", 0.0))
        epoch = int(payload.get("epoch", 1))
        epochs = int(payload.get("epochs", 1))
        self.progress_bar.setValue(step)
        self.step_label.setText(
            f"الخطوة الإضافية: {step:,} / {self.progress_bar.maximum():,} | "
            f"Epoch: {epoch}/{epochs} | "
            f"كتل: {int(payload.get('blocks_seen', 0)):,}/{int(payload.get('blocks_total', 0)):,}"
        )
        self.loss_label.setText(f"Training loss: {loss:.4f}")
        self.learning_rate_label.setText(f"Learning rate: {learning_rate:.3g}")
        self._append_log(
            f"epoch={epoch}/{epochs} | step={step} | "
            f"train blocks={payload.get('blocks_seen')}/{payload.get('blocks_total')} | "
            f"tokens≈{int(payload.get('tokens_seen', 0)):,}/{int(payload.get('tokens_total', 0)):,} | "
            f"loss={loss:.4f} | lr={learning_rate:.3g}"
        )

    @staticmethod
    def _log_evaluation_change(label: str, before: dict | None, after: dict | None) -> str:
        if not before or not after:
            return f"{label}: لا تتوفر مقارنة كافية."
        before_loss = float(before.get("loss", 0.0))
        after_loss = float(after.get("loss", 0.0))
        change = before_loss - after_loss
        loss_state = "تحسن" if change > 0 else "تراجع" if change < 0 else "لم يتغير"
        return (
            f"{label}: Loss {before_loss:.4f} → {after_loss:.4f} "
            f"({loss_state} بمقدار {change:+.4f}) | "
            f"Next-token accuracy {float(before.get('next_token_accuracy', 0.0)):.1%} → "
            f"{float(after.get('next_token_accuracy', 0.0)):.1%}."
        )

    def _on_completed(self, payload: dict) -> None:
        stopped = bool(payload.get("stopped_early"))
        state = "توقف التدريب بأمان بعد حفظ الأوزان" if stopped else "اكتمل التدريب وحُفظ النموذج"
        self.status_label.setText(state + " — أصبح متاحًا للمحادثة المحلية")
        self._append_log(state)
        self._append_log(
            f"الخطوات المنفذة: {payload.get('completed_steps')} / "
            f"{payload.get('requested_steps')} | Epochs مكتملة: "
            f"{payload.get('epochs_completed')}/{payload.get('epochs_requested')} "
            f"في هذه الجلسة | الإجمالي التراكمي: {payload.get('epochs_completed_total')}"
        )
        self._append_log(
            f"البيانات في كل Epoch: {int(payload.get('train_records', 0)):,} مقطع | "
            f"{int(payload.get('train_tokens_per_epoch', 0)):,} Token | "
            f"{int(payload.get('train_blocks_per_epoch', 0)):,} كتلة"
        )
        self._append_log(
            f"BPE vocabulary: {payload.get('tokenizer_vocab_size')} "
            f"(target {payload.get('tokenizer_vocab_target')}) | "
            f"Model parameters: {int(payload.get('model_parameters', 0)):,}"
        )
        if payload.get("evaluation_split") == "train (in-sample)":
            self._append_log(
                self._log_evaluation_change(
                    "Train in-sample قبل/بعد",
                    payload.get("evaluation_before"),
                    payload.get("evaluation_after"),
                )
            )
            self._append_log(
                "تنبيه: انخفاض Train Loss يثبت أن النموذج تحسّن على نصوص التدريب، "
                "ولا يثبت وحده قدرته على التعميم أو الاستدلال."
            )
        else:
            self._append_log(
                self._log_evaluation_change(
                    "Validation قبل/بعد", payload.get("validation_before"), payload.get("validation")
                )
            )
            self._append_log(
                self._log_evaluation_change(
                    "Test قبل/بعد", payload.get("test_before"), payload.get("test")
                )
            )
        self._append_log(f"Checkpoint: {payload.get('checkpoint_path')}")
        self._append_log(f"Tokenizer: {payload.get('tokenizer_path')}")
        self._append_log(f"Inference artifact: {payload.get('inference_artifact_path')}")
        self._append_log(f"النموذج الفعال للمحادثة: {payload.get('active_model_manifest_path')}")
        self._refresh_active_model_status()
        self.stop_button.setEnabled(False)

    def _on_failed(self, message: str) -> None:
        self.status_label.setText("تعذر إكمال التدريب")
        self._append_log(f"خطأ: {message}")
        self.stop_button.setEnabled(False)

    def _on_worker_finished(self) -> None:
        worker = self.worker
        self.worker = None
        if worker is not None:
            worker.deleteLater()
        self._refresh_start_button()
        self.browse_button.setEnabled(True)
        self.prepare_button.setEnabled(True)
        self.raw_browse_button.setEnabled(True)
        self.epochs_input.setEnabled(True)
        self.resume_checkbox.setEnabled(True)
        self.stop_button.setEnabled(False)
