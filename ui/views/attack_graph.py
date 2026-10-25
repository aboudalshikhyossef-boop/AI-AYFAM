"""رسم تفاعلي لسلاسل الهجوم مع إظهار أدلتها المرتبطة."""

from __future__ import annotations

import html

from PyQt6.QtCore import QPointF, Qt
from PyQt6.QtGui import QBrush, QColor, QFont, QPainter, QPainterPath, QPen, QPolygonF
from PyQt6.QtWidgets import (
    QFrame,
    QGraphicsScene,
    QGraphicsView,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from ui.theme import PAGE_ACCENTS, SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, TEXT_PRIMARY, TEXT_SECONDARY


class AttackChainGraphView(QWidget):
    NODE_WIDTH = 280
    NODE_HEIGHT = 84
    ROW_GAP = 220

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
        self._init_ui()

    def _init_ui(self) -> None:
        accent = PAGE_ACCENTS["attack_graph"]
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(14)

        hero = QFrame(objectName="pageHero")
        hero_layout = QVBoxLayout(hero)
        hero_layout.setContentsMargins(18, 14, 18, 14)
        hero_layout.setSpacing(4)
        eyebrow = QLabel("الربط والتحليل  /  CORRELATION")
        eyebrow.setObjectName("pageEyebrow")
        eyebrow.setStyleSheet(f"color: {accent};")
        hero_layout.addWidget(eyebrow)
        title = QLabel("سلاسل الهجوم المرتبطة  /  Correlated Attack Chains")
        title.setObjectName("pageHeading")
        hero_layout.addWidget(title)
        subtitle = QLabel("تظهر هنا العلاقات التي استنتجها محرك الارتباط من نتائج الفحص، مع الأدلة التي دعمت كل مسار.  /  Correlations inferred from scan findings, with the evidence behind each chain.")
        subtitle.setObjectName("secondaryText")
        subtitle.setWordWrap(True)
        hero_layout.addWidget(subtitle)
        layout.addWidget(hero)

        self.summary = QLabel("بانتظار نتائج الفحص / Waiting for scan results")
        self.summary.setObjectName("glassBadge")
        layout.addWidget(self.summary, 0, Qt.AlignmentFlag.AlignRight)

        self.empty_state = QLabel("لا توجد سلسلة مرتبطة لعرضها.\nشغّل فحصًا شاملًا لتجميع الأدلة عبر المجالات.\n\nNo correlated chains to display.\nRun a full scan to correlate evidence across domains.")
        self.empty_state.setObjectName("emptyState")
        self.empty_state.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_state.setMinimumHeight(180)
        layout.addWidget(self.empty_state)

        self.scene = QGraphicsScene(self)
        self.view = QGraphicsView(self.scene)
        self.view.setObjectName("attackGraphCanvas")
        self.view.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.view.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.view.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.view.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.view.setMinimumHeight(380)
        self.view.setToolTip("اسحب لتحريك الرسم واستخدم عجلة الفأرة للتنقل.  /  Drag to pan; use the mouse wheel to navigate.")
        layout.addWidget(self.view, 1)
        self.view.hide()

    def render_chain(self, attack_chain_findings: list, source_findings: list | None = None) -> None:
        self.scene.clear()
        sources = {
            str(finding.get("id")): str(finding.get("title", "دليل أمني"))
            for finding in (source_findings or [])
            if isinstance(finding, dict) and finding.get("id") is not None
        }
        chains = [item for item in attack_chain_findings if isinstance(item, dict)]
        if not chains:
            self.summary.setText("لا توجد سلاسل مرتبطة / No correlated chains")
            self.empty_state.show()
            self.view.hide()
            return

        for chain_index, chain in enumerate(chains):
            y = chain_index * self.ROW_GAP
            severity = str(chain.get("severity", "high")).lower()
            accent = SEV_CRITICAL if severity == "critical" else SEV_HIGH if severity == "high" else SEV_MEDIUM
            evidence = self._evidence_titles(chain.get("evidence"), sources)
            root_x = 680
            self._add_node(root_x, y, str(chain.get("title", "سلسلة هجوم / Attack chain")), str(chain.get("detail", "")), accent, True)

            if not evidence:
                evidence = ["لا تتوفر تفاصيل أدلة منفصلة لهذه السلسلة / No separate evidence details are available."]
            for evidence_index, title in enumerate(evidence[:4]):
                node_x = 40 + (evidence_index % 2) * 310
                node_y = y + (evidence_index // 2) * 98
                self._add_edge(QPointF(node_x + self.NODE_WIDTH, node_y + self.NODE_HEIGHT / 2),
                               QPointF(root_x, y + self.NODE_HEIGHT / 2), accent)
                self._add_node(node_x, node_y, f"الدليل {evidence_index + 1} / Evidence {evidence_index + 1}", title, accent, False)

        scene_rect = self.scene.itemsBoundingRect().adjusted(-24, -24, 24, 24)
        self.scene.setSceneRect(scene_rect)
        total_evidence = sum(len(self._evidence_titles(c.get("evidence"), sources)) for c in chains)
        self.summary.setText(f"{len(chains)} سلسلة / chains  •  {total_evidence} دليل / evidence")
        self.empty_state.hide()
        self.view.show()
        self.view.fitInView(scene_rect, Qt.AspectRatioMode.KeepAspectRatio)

    @staticmethod
    def _evidence_titles(evidence, sources: dict[str, str]) -> list[str]:
        if not isinstance(evidence, dict):
            return []
        titles: list[str] = []
        for key, value in evidence.items():
            if key == "indicators" and isinstance(value, list):
                titles.extend(str(item.get("title") or item.get("type") or "مؤشر أمني / Security indicator")
                              for item in value if isinstance(item, dict))
            elif key.endswith("_title") and value:
                titles.append(str(value))
            elif key.endswith("_finding_id") and value is not None:
                title = sources.get(str(value))
                if title:
                    titles.append(title)
        return list(dict.fromkeys(titles))

    def _add_node(self, x: float, y: float, title: str, detail: str, color: str, prominent: bool) -> None:
        accent = QColor(color)
        fill = QColor(18, 29, 49, 235 if prominent else 205)
        pen = QPen(accent, 2.0 if prominent else 1.2)
        shape = QPainterPath()
        shape.addRoundedRect(x, y, self.NODE_WIDTH, self.NODE_HEIGHT, 14, 14)
        rect = self.scene.addPath(shape, pen, QBrush(fill))
        rect.setZValue(1)
        rect.setToolTip(html.escape((detail or title)[:1000]))
        title_item = self.scene.addText("")
        title_item.setPlainText(title[:70])
        title_item.setDefaultTextColor(QColor(TEXT_PRIMARY))
        title_item.setFont(QFont("Tajawal", 10, QFont.Weight.Bold if prominent else QFont.Weight.DemiBold))
        title_item.setTextWidth(self.NODE_WIDTH - 24)
        title_item.setPos(x + 12, y + 8)
        title_item.setZValue(2)
        detail_item = self.scene.addText("")
        detail_item.setPlainText(detail[:90] if detail else "")
        detail_item.setDefaultTextColor(QColor(TEXT_SECONDARY))
        detail_item.setFont(QFont("Tajawal", 8))
        detail_item.setTextWidth(self.NODE_WIDTH - 24)
        detail_item.setPos(x + 12, y + 42)
        detail_item.setZValue(2)

    def _add_edge(self, start: QPointF, end: QPointF, color: str) -> None:
        edge_color = QColor(color)
        edge_color.setAlpha(145)
        pen = QPen(edge_color, 1.7, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)
        line = self.scene.addLine(start.x(), start.y(), end.x(), end.y(), pen)
        line.setZValue(0)
        arrow = QPolygonF([
            QPointF(end.x(), end.y()),
            QPointF(end.x() - 10, end.y() - 5),
            QPointF(end.x() - 10, end.y() + 5),
        ])
        self.scene.addPolygon(arrow, QPen(edge_color, 0.5), QBrush(edge_color)).setZValue(0)
