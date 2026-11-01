"""Desktop workspace for importing, preparing, and training AI AYFAM locally."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
import threading

from PyQt6.QtCore import QThread, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QFileDialog,
    QFormLayout,
    QGroupBox,
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

from model_factory.corpus_tools import prepare_corpus
from model_factory.corpus_workspace import default_corpus_root, import_raw_corpus
from model_factory.document_ingestion import DocumentInput, ingest_documents
from model_factory.hardware import HardwareProfile, build_training_plan
from model_factory.runner import TrainingRunConfig, run_training


_PHASE_LABELS = {
    "importing": "نسخ ملف JSONL الخام إلى مساحة AYFAM المحلية",
    "extracting_documents": "استخراج النصوص من المستندات وحفظ بيانات المصدر",
    "preparing": "تنظيف البيانات وإزالة التكرارات وتجهيز التقسيمات",
    "validating_corpus": "التحقق من corpus ومصدر البيانات والتقسيمات",
    "preparing_tokenizer": "تجهيز tokenizer من بيانات التدريب فقط",
    "resuming_checkpoint": "تحميل checkpoint السابق",
    "training": "تدريب Transformer محليًا على المعالج",
    "evaluating": "تقييم النموذج على مجموعة validation",
    "completed": "اكتملت العملية",
}


class CorpusPreparationWorker(QThread):
    """Extract selected documents or import JSONL, then prepare a training corpus."""

    phase_changed = pyqtSignal(str)
    completed = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(
        self,
        source_paths: list[Path],
        prepared_path: Path,
        license_name: str = "",
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        self.source_paths = [Path(path) for path in source_paths]
        self.prepared_path = prepared_path
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
                    require_held_out=True,
                )
                imported_path = Path(ingestion.output_path)
                ingestion_report = ingestion.to_dict()

            self.phase_changed.emit("preparing")
            report = prepare_corpus(
                imported_path,
                self.prepared_path,
                require_held_out=True,
            )
        except Exception as exc:
            self.failed.emit(str(exc))
        else:
            self.completed.emit({
                "imported_path": str(imported_path),
                "prepared_path": str(self.prepared_path),
                "report": report.to_dict(),
                "ingestion_report": ingestion_report,
            })


class ModelTrainingWorker(QThread):
    """Run model training away from the GUI thread and expose safe progress signals."""

    phase_changed = pyqtSignal(str)
    progress_changed = pyqtSignal(object)
    completed = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, config: TrainingRunConfig, parent: QWidget | None = None):
        super().__init__(parent)
        self.config = config
        self._stop_event = threading.Event()

    def request_stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        try:
            result = run_training(
                self.config,
                on_phase=self.phase_changed.emit,
                on_step=self._report_step,
                should_stop=self._stop_event.is_set,
            )
        except Exception as exc:
            self.failed.emit(str(exc))
        else:
            self.completed.emit(result.to_dict())

    def _report_step(self, step_result) -> None:
        self.progress_changed.emit({
            "step": step_result.step,
            "loss": step_result.loss,
            "learning_rate": step_result.learning_rate,
        })


class ModelTrainingView(QWidget):
    """A user-controlled data and training panel; opening it starts no work."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.worker: ModelTrainingWorker | None = None
        self.prepare_worker: CorpusPreparationWorker | None = None
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
        root = QVBoxLayout(self)
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

        self.license_input = QLineEdit()
        self.license_input.setPlaceholderText(
            "الترخيص أو إذن المالك، مثل CC-BY-4.0 / License or owner's permission"
        )
        self.license_input.setToolTip(
            "يُطبّق هذا الترخيص على جميع المستندات المحددة. تحقق من حقك في استخدامها لتدريب النموذج."
        )
        raw_layout.addWidget(QLabel(
            "ترخيص المستندات المحددة (مطلوب للكتب والملفات، وليس لملف JSONL موثق) / "
            "Selected documents license (required for books/files)"
        ))
        raw_layout.addWidget(self.license_input)

        self.prepare_button = QPushButton("استخراج وتجهيز البيانات / Extract and prepare")
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
        self.browse_button = QPushButton("اختيار ملف جاهز")
        self.browse_button.clicked.connect(self._browse_corpus)
        prepared_row.addWidget(self.corpus_input, 1)
        prepared_row.addWidget(self.browse_button)
        prepared_layout.addLayout(prepared_row)

        options = QFormLayout()
        self.steps_input = QSpinBox()
        self.steps_input.setRange(1, 100_000)
        self.steps_input.setValue(20)
        self.steps_input.setToolTip("عدد خطوات optimizer الإجمالي المستهدف. ابدأ بتجربة قصيرة.")
        self.vocab_input = QSpinBox()
        self.vocab_input.setRange(260, 2_048)
        self.vocab_input.setSingleStep(64)
        self.vocab_input.setValue(512)
        self.vocab_input.setToolTip("حجم مفردات Byte BPE. يتم تعلمها من split=train فقط.")
        options.addRow("خطوات التدريب الأولية:", self.steps_input)
        options.addRow("حجم مفردات BPE:", self.vocab_input)
        prepared_layout.addLayout(options)
        root.addWidget(prepared_group)

        actions = QHBoxLayout()
        self.start_button = QPushButton("بدء التدريب المحلي")
        self.start_button.setObjectName("primaryButton")
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
        self.progress_bar.setRange(0, 20)
        self.progress_bar.setValue(0)
        progress_layout.addWidget(self.progress_bar)

        metrics = QHBoxLayout()
        self.step_label = QLabel("الخطوة: 0 / 20")
        self.loss_label = QLabel("Loss: —")
        self.learning_rate_label = QLabel("Learning rate: —")
        self.memory_label = QLabel("ذاكرة العملية: —")
        for label in (self.step_label, self.loss_label, self.learning_rate_label, self.memory_label):
            label.setWordWrap(True)
            metrics.addWidget(label)
        progress_layout.addLayout(metrics)

        self.output_label = QLabel("مكان الحفظ: سيُنشأ محليًا عند بدء التدريب")
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

    def _refresh_hardware_summary(self) -> None:
        self.hardware_label.setText(
            f"RAM الكلية: {self.profile.total_ram_mb:,} MB | "
            f"المتاحة لحظة الفحص: {self.profile.available_ram_mb:,} MB | "
            f"أنوية CPU المنطقية: {self.profile.logical_cores} | "
            f"CUDA: {'مكتشف' if self.profile.cuda_device_detected else 'غير مكتشف'}"
        )
        self.plan_label.setText(
            f"الخطة المحافظة: micro-batch={self.plan.micro_batch_size}، "
            f"gradient accumulation={self.plan.gradient_accumulation_steps}، "
            f"CPU threads={self.plan.num_threads}، "
            f"checkpoint كل {self.plan.checkpoint_interval_steps} خطوة. "
            "أبعاد النموذج لا تتغير تلقائيًا."
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

    def prepare_corpus(self) -> None:
        if (self.prepare_worker is not None and self.prepare_worker.isRunning()) or (
            self.worker is not None and self.worker.isRunning()
        ):
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
        if not jsonl_paths and not self.license_input.text().strip():
            self.status_label.setText(
                "أدخل الترخيص أو إذن المالك قبل استيراد الكتب. / "
                "Enter the license or owner's permission before importing documents."
            )
            return

        prepared_dir = default_corpus_root() / "prepared"
        prepared_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        run_id = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        label = source_paths[0].stem[:48] if len(source_paths) == 1 else "document-batch"
        prepared_path = prepared_dir / f"{label}-{run_id}-prepared.jsonl"

        self.prepare_button.setEnabled(False)
        self.raw_browse_button.setEnabled(False)
        self.browse_button.setEnabled(False)
        self.license_input.setEnabled(False)
        self.start_button.setEnabled(False)
        self.status_label.setText("بدء استخراج المستندات وتجهيز البيانات…")
        self._append_log("الملفات المحددة: " + ", ".join(path.name for path in source_paths))
        self.prepare_worker = CorpusPreparationWorker(
            source_paths,
            prepared_path,
            self.license_input.text().strip(),
            self,
        )
        self.prepare_worker.phase_changed.connect(self._on_prepare_phase_changed)
        self.prepare_worker.completed.connect(self._on_corpus_prepared)
        self.prepare_worker.failed.connect(self._on_prepare_failed)
        self.prepare_worker.finished.connect(self._on_prepare_finished)
        self.prepare_worker.start()

    def _on_prepare_phase_changed(self, phase: str) -> None:
        label = _PHASE_LABELS.get(phase, phase)
        self.status_label.setText(label)
        self._append_log(label)

    def _on_corpus_prepared(self, payload: dict) -> None:
        report = payload.get("report") or {}
        splits = report.get("records_by_split") or {}
        languages = report.get("languages") or {}
        self.corpus_input.setText(str(payload.get("prepared_path", "")))
        self.status_label.setText("تم استيراد البيانات وتجهيزها واجتازت التدقيق.")
        self._append_log(f"النسخة المحلية الخام: {payload.get('imported_path')}")
        self._append_log(f"ملف التدريب الجاهز: {payload.get('prepared_path')}")
        self._append_log(
            "السجلات: "
            f"train={splits.get('train', 0)}, "
            f"validation={splits.get('validation', 0)}, "
            f"test={splits.get('test', 0)}"
        )
        self._append_log(f"ملخص اللغة: {languages}")
        self._append_log(f"المكررات المحذوفة: {report.get('duplicates_removed', 0)}")
        self._append_log(f"SHA-256: {report.get('fingerprint', '')}")
        ingestion = payload.get("ingestion_report") or {}
        if ingestion:
            self._append_log(
                "المستندات: "
                f"{ingestion.get('documents', 0)} | "
                f"الصفحات: {ingestion.get('pages', 0)} | "
                f"المقاطع المستخرجة: {ingestion.get('chunks', 0)} | "
                f"الأحرف: {ingestion.get('characters', 0):,}"
            )
            self._append_log(f"لغات المستندات: {ingestion.get('languages', {})}")
            self._append_log(f"بصمة الاستيراد: {ingestion.get('fingerprint', '')}")
        self.raw_document_paths = []
        imported_path = payload.get("imported_path")
        if imported_path:
            self.raw_corpus_input.setText(str(imported_path))
        self.start_button.setEnabled(True)

    def _on_prepare_failed(self, message: str) -> None:
        self.status_label.setText("تعذر استيراد أو تجهيز مجموعة البيانات.")
        self._append_log(f"خطأ تجهيز البيانات: {message}")

    def _on_prepare_finished(self) -> None:
        worker = self.prepare_worker
        self.prepare_worker = None
        if worker is not None:
            worker.deleteLater()
        training_running = self.worker is not None and self.worker.isRunning()
        self.prepare_button.setEnabled(not training_running)
        self.raw_browse_button.setEnabled(not training_running)
        self.browse_button.setEnabled(True)
        self.license_input.setEnabled(not training_running)
        self.start_button.setEnabled(not training_running)

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
        corpus_path = Path(self.corpus_input.text().strip()).expanduser()
        if not corpus_path.is_file():
            self.status_label.setText("اختر ملف corpus مُجهّزًا موجودًا أولًا.")
            return

        run_id = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        output_dir = (
            Path.home() / ".local" / "share" / "ayfam" / "training" / "runs" / f"run-{run_id}"
        )
        config = TrainingRunConfig(
            corpus_path=corpus_path,
            checkpoint_path=output_dir / "latest.pt",
            max_steps=self.steps_input.value(),
            device="cpu",
            tokenizer_mode="bpe",
            tokenizer_vocab_size=self.vocab_input.value(),
            tokenizer_output_path=output_dir / "tokenizer.json",
        )

        self.log_output.clear()
        self.progress_bar.setRange(0, config.max_steps)
        self.progress_bar.setValue(0)
        self.step_label.setText(f"الخطوة: 0 / {config.max_steps}")
        self.loss_label.setText("Loss: —")
        self.learning_rate_label.setText("Learning rate: —")
        self.output_label.setText(f"مكان الحفظ: {output_dir}")
        self.status_label.setText("يتم تجهيز جلسة التدريب والتحقق من البيانات…")
        self.start_button.setEnabled(False)
        self.browse_button.setEnabled(False)
        self.prepare_button.setEnabled(False)
        self.raw_browse_button.setEnabled(False)
        self.license_input.setEnabled(False)
        self.steps_input.setEnabled(False)
        self.vocab_input.setEnabled(False)
        self.stop_button.setEnabled(True)

        self.worker = ModelTrainingWorker(config, self)
        self.worker.phase_changed.connect(self._on_phase_changed)
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

    def _on_progress(self, payload: dict) -> None:
        step = int(payload.get("step", 0))
        loss = float(payload.get("loss", 0.0))
        learning_rate = float(payload.get("learning_rate", 0.0))
        self.progress_bar.setValue(step)
        self.step_label.setText(f"الخطوة: {step} / {self.progress_bar.maximum()}")
        self.loss_label.setText(f"Loss: {loss:.4f}")
        self.learning_rate_label.setText(f"Learning rate: {learning_rate:.3g}")
        self._append_log(f"step={step} | loss={loss:.4f} | lr={learning_rate:.3g}")

    def _on_completed(self, payload: dict) -> None:
        stopped = bool(payload.get("stopped_early"))
        state = "توقف التدريب بأمان" if stopped else "اكتمل التدريب"
        validation = payload.get("validation") or {}
        self.status_label.setText(state)
        self._append_log(f"{state}: {payload.get('completed_steps')} خطوة")
        if validation:
            self._append_log(
                f"Validation loss={validation.get('loss', float('nan')):.4f} | "
                f"perplexity={validation.get('perplexity', float('nan')):.3f}"
            )
        self._append_log(f"Checkpoint: {payload.get('checkpoint_path')}")
        self._append_log(f"Model parameters: {payload.get('model_parameters'):,}")
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
        self.start_button.setEnabled(True)
        self.browse_button.setEnabled(True)
        self.prepare_button.setEnabled(True)
        self.raw_browse_button.setEnabled(True)
        self.license_input.setEnabled(True)
        self.steps_input.setEnabled(True)
        self.vocab_input.setEnabled(True)
        self.stop_button.setEnabled(False)
