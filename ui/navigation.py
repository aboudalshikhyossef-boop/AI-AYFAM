"""Seven-workspace navigation and grouping for the AI AYFAM desktop UI.

The top-level navigation stays deliberately small. Related screens remain
available through a workspace selector, while internal page keys keep working
for existing actions, shortcuts, and tests.
"""

from __future__ import annotations

from PyQt6.QtWidgets import QComboBox, QHBoxLayout, QLabel, QStackedWidget, QVBoxLayout, QWidget


NAV_ITEMS = [
    ("dashboard", "غرفة العمليات"),
    ("scans", "الفحوصات الأمنية"),
    ("findings", "النتائج والتحليل"),
    ("sentinel", "المراقبة والحماية"),
    ("chat", "المساعد والمعرفة"),
    ("model_training", "تدريب نموذج AYFAM"),
    ("settings", "الإعدادات"),
]

# (Arabic selector label, [(legacy page key, visible selector label), ...])
NAV_GROUPS = {
    "dashboard": ("نظرة عامة", (("dashboard", "لوحة المؤشرات"),)),
    "scans": (
        "الفحوصات والأدوات",
        (("scans", "الفحوصات الأمنية"), ("tools", "الأدوات والتحصين")),
    ),
    "findings": (
        "النتائج والتحليل",
        (
            ("findings", "النتائج الأمنية"),
            ("timeline", "الخط الزمني"),
            ("attack_graph", "سلاسل الهجوم"),
            ("reports", "التقارير"),
        ),
    ),
    "sentinel": (
        "المراقبة والحماية",
        (("sentinel", "الحارس اللحظي"), ("usb", "الأجهزة المتصلة")),
    ),
    "chat": (
        "المساعد والمعرفة",
        (
            ("chat", "المحادثة الذكية"),
            ("library", "مكتبة المعرفة"),
            ("playbooks", "خطط العمل"),
        ),
    ),
    "model_training": ("تدريب AYFAM", (("model_training", "مساحة تدريب النموذج"),)),
    "settings": ("إعدادات النظام", (("settings", "إعدادات النظام"),)),
}

PAGE_TO_SECTION = {
    page_key: section_key
    for section_key, (_section_label, pages) in NAV_GROUPS.items()
    for page_key, _page_label in pages
}

NAV_ICON_KEYS = {
    "dashboard": "dashboard",
    "scans": "scans",
    "findings": "findings",
    "sentinel": "sentinel",
    "chat": "chat",
    "model_training": "model_training",
    "settings": "settings",
}


def build_navigation_sections(page_widgets: dict[str, QWidget], parent=None) -> dict[str, dict]:
    """Build seven top-level widgets and selectors for their related legacy pages."""
    sections: dict[str, QWidget] = {}
    selectors: dict[str, QComboBox | None] = {}
    stacks: dict[str, QStackedWidget | None] = {}

    missing_pages = set(PAGE_TO_SECTION) - set(page_widgets)
    if missing_pages:
        raise ValueError(f"Missing navigation page widgets: {sorted(missing_pages)}")

    for section_key, (section_label, pages) in NAV_GROUPS.items():
        if len(pages) == 1:
            page_key, _page_label = pages[0]
            sections[section_key] = page_widgets[page_key]
            selectors[section_key] = None
            stacks[section_key] = None
            continue

        section = QWidget(parent)
        section.setObjectName(f"workspace_{section_key}")
        layout = QVBoxLayout(section)
        layout.setContentsMargins(20, 16, 20, 18)
        layout.setSpacing(12)

        selector_row = QHBoxLayout()
        selector_label = QLabel(f"{section_label}:")
        selector_label.setObjectName("secondaryText")
        selector = QComboBox(section)
        selector.setObjectName(f"workspaceSelector_{section_key}")
        selector.setAccessibleName(f"اختيار مساحة العمل: {section_label}")
        selector.setMinimumHeight(36)
        selector.setMinimumWidth(220)

        stack = QStackedWidget(section)
        stack.setObjectName(f"workspaceStack_{section_key}")
        for page_key, page_label in pages:
            selector.addItem(page_label, page_key)
            stack.addWidget(page_widgets[page_key])

        selector.currentIndexChanged.connect(stack.setCurrentIndex)
        selector_row.addWidget(selector_label)
        selector_row.addWidget(selector, 1)
        selector_row.addStretch(1)
        layout.addLayout(selector_row)
        layout.addWidget(stack, 1)

        sections[section_key] = section
        selectors[section_key] = selector
        stacks[section_key] = stack

    return {"sections": sections, "selectors": selectors, "stacks": stacks}
