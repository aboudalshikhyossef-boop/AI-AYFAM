"""Desktop workspace for explicit, local AI AYFAM model training."""

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

from model_factory.hardware import HardwareProfile, build_training_plan
from model_factory.runner import TrainingRunConfig, run_training


_PHASE_LABELS = {
    "validating_corpus": "التحقق من corpus ومصدر البيانات والتقسيمات",
    "preparing_tokenizer": "تجهيز tokenizer من بيانات التدريب فقط",
    "resuming_checkpoint": "تحميل checkpoint السابق",
    "training": "تدريب Transformer محليًا على المعالج",
    "evaluating": "تقييم النموذج على مجموعة validation",
    "completed": "اكتملت العملية",
}


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
    """A user-controlled training panel; opening the page never starts training."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.worker: ModelTrainingWorker | None = None
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
            "هذه مساحة تدريب مستقلة عن المحادثة الأمنية. لا يبدأ التدريب عند فتح التطبيق؛ "
            "لن يعمل إلا بعد اختيار ملف corpus مُجهّز والضغط على زر البدء. "
            "التدريب هنا محلي على CPU ولا يحمّل أوزان نماذج خارجية."
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

        corpus_group = QGroupBox("بيانات التدريب")
        corpus_layout = QVBoxLayout(corpus_group)
        corpus_row = QHBoxLayout()
        self.corpus_input = QLineEdit()
        self.corpus_input.setPlaceholderText("اختر ملف JSONL الناتج عن prepare-corpus")
        self.corpus_input.setClearButtonEnabled(True)
        self.corpus_input.setMinimumHeight(36)
        self.browse_button = QPushButton("اختيار corpus")
        self.browse_button.clicked.connect(self._browse_corpus)
        corpus_row.addWidget(self.corpus_input, 1)
        corpus_row.addWidget(self.browse_button)
        corpus_layout.addLayout(corpus_row)

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
        corpus_layout.addLayout(options)
        root.addWidget(corpus_group)

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

        progress_group = QGroupBox("مراقبة التدريب")
        progress_layout = QVBoxLayout(progress_group)
        self.status_label = QLabel("جاهز — لم يبدأ أي تدريب")
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

        self.output_label = QLabel("مكان الحفظ: سيُنشأ محليًا عند بدء التشغيل")
        self.output_label.setWordWrap(True)
        progress_layout.addWidget(self.output_label)
        root.addWidget(progress_group)

        self.log_output = QPlainTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setMaximumBlockCount(250)
        self.log_output.setPlaceholderText("تظهر مراحل التحقق والتدريب والنتائج هنا.")
        self.log_output.setMinimumHeight(150)
        root.addWidget(self.log_output, 1)

        disclaimer = QLabel(
            "مهم: لا يحتوي المستودع على corpus جاهز. يجب أن تكون البيانات مُجهّزة، "
            "ومصادرها وتراخيصها معروفة، وأن تحتوي على train وvalidation وtest. "
            "النموذج الناتج في هذه المرحلة نموذج لغوي أولي، وليس مساعدًا جاهزًا لاتخاذ قرارات أمنية."
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

    def _browse_corpus(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "اختيار corpus مُجهّز",
            str(Path.home()),
            "JSON Lines (*.jsonl);;All files (*)",
        )
        if path:
            self.corpus_input.setText(path)

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
        if self.worker is not None and self.worker.isRunning():
            return
        corpus_path = Path(self.corpus_input.text().strip()).expanduser()
        if not corpus_path.is_file():
            self.status_label.setText("اختر ملف corpus موجودًا بصيغة JSONL أولًا.")
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
        self.steps_input.setEnabled(True)
        self.vocab_input.setEnabled(True)
        self.stop_button.setEnabled(False)

