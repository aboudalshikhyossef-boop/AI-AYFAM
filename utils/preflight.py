"""فحوصات ما قبل التشغيل لـ AI AYFAM.

تتحقق من صلاحيات root، مكتبات Python، وأدوات النظام اللازمة للوظيفة المطلوبة.
لا تقوم هذه الوحدة بتثبيت أي شيء تلقائيًا؛ بل تعرض أمر التثبيت الآمن بوضوح.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class Requirement:
    name: str
    kind: str
    install_hint: str
    feature: str = "core"


PYTHON_REQUIREMENTS = (
    Requirement("rich", "Python", "python3 -m pip install rich"),
    Requirement("requests", "Python", "python3 -m pip install requests"),
    Requirement("pypdf", "Python", "python3 -m pip install pypdf"),
    Requirement("sklearn", "Python", "python3 -m pip install scikit-learn"),
    Requirement("numpy", "Python", "python3 -m pip install numpy"),
    Requirement("scipy", "Python", "python3 -m pip install scipy"),
)

FEATURE_REQUIREMENTS = {
    "gui": (Requirement("PyQt6", "Python", "python3 -m pip install PyQt6", "gui"),),
    "network": (Requirement("ss", "system", "sudo apt install iproute2", "network"),),
    "ports": (Requirement("nmap", "system", "sudo apt install nmap", "ports"),),
    "usb": (Requirement("lsusb", "system", "sudo apt install usbutils", "usb"),),
    "lynis": (Requirement("lynis", "system", "sudo apt install lynis", "lynis"),),
    "rootkits": (Requirement("chkrootkit", "system", "sudo apt install chkrootkit", "rootkits"),),
}

# Qt can import PyQt6 successfully while still aborting at QApplication startup
# if these X11 runtime libraries are absent.
FEATURE_REQUIREMENTS["gui"] += (
    Requirement("libgl1", "package", "sudo apt install libgl1", "gui"),
    Requirement("libxcb-cursor0", "package", "sudo apt install libxcb-cursor0", "gui"),
    Requirement("libxkbcommon-x11-0", "package", "sudo apt install libxkbcommon-x11-0", "gui"),
    Requirement("libxcb-xinerama0", "package", "sudo apt install libxcb-xinerama0", "gui"),
    Requirement("libxcb-icccm4", "package", "sudo apt install libxcb-icccm4", "gui"),
    Requirement("libxcb-image0", "package", "sudo apt install libxcb-image0", "gui"),
    Requirement("libxcb-keysyms1", "package", "sudo apt install libxcb-keysyms1", "gui"),
    Requirement("libxcb-render-util0", "package", "sudo apt install libxcb-render-util0", "gui"),
    Requirement("libxcb-xkb1", "package", "sudo apt install libxcb-xkb1", "gui"),
    Requirement("libxcb-randr0", "package", "sudo apt install libxcb-randr0", "gui"),
    Requirement("libxcb-shape0", "package", "sudo apt install libxcb-shape0", "gui"),
    Requirement("libxcb-xfixes0", "package", "sudo apt install libxcb-xfixes0", "gui"),
    Requirement("libxcb-sync1", "package", "sudo apt install libxcb-sync1", "gui"),
    Requirement("libxcb-shm0", "package", "sudo apt install libxcb-shm0", "gui"),
    Requirement("libxcb-util1", "package", "sudo apt install libxcb-util1", "gui"),
    Requirement("libx11-xcb1", "package", "sudo apt install libx11-xcb1", "gui"),
)


@dataclass
class PreflightReport:
    missing_required: list[Requirement]
    missing_optional: list[Requirement]

    @property
    def ok(self) -> bool:
        return not self.missing_required

    def text(self) -> str:
        lines = [f"Python: {sys.version.split()[0]}", f"Root: {'yes' if is_root() else 'no'}"]
        if self.missing_required:
            lines.append("Missing required requirements:")
            lines.extend(f"  - {r.name} ({r.kind}): {r.install_hint}" for r in self.missing_required)
        if self.missing_optional:
            lines.append("Missing optional requirements (some features will be limited):")
            lines.extend(f"  - {r.name} ({r.feature}): {r.install_hint}" for r in self.missing_optional)
        if self.ok and not self.missing_optional:
            lines.append("All checked requirements are available.")
        return "\n".join(lines)


def is_root() -> bool:
    """Return whether the current process has effective UID 0."""
    return hasattr(os, "geteuid") and os.geteuid() == 0


def root_error() -> str:
    return "AI AYFAM requires root privileges. Run it with: sudo -E ayfam [options]"


def _available(requirement: Requirement) -> bool:
    if requirement.kind == "Python":
        return importlib.util.find_spec(requirement.name) is not None
    if requirement.kind == "package":
        try:
            result = subprocess.run(
                ["dpkg-query", "-W", "-f=${Status}", requirement.name],
                capture_output=True, text=True, timeout=3,
            )
            return result.returncode == 0 and "install ok installed" in result.stdout
        except (OSError, subprocess.SubprocessError):
            return False
    return shutil.which(requirement.name) is not None


def check_requirements(features: Iterable[str] = ()) -> PreflightReport:
    """Check core requirements plus feature-specific requirements.

    Feature-specific requirements are required only when that feature is explicitly
    selected. Other missing system tools are reported as optional so the agent can
    still run independent local checks.
    """
    requested = set(features)
    required: list[Requirement] = []
    optional: list[Requirement] = []
    for requirement in PYTHON_REQUIREMENTS:
        if not _available(requirement):
            required.append(requirement)
    for feature in requested:
        for requirement in FEATURE_REQUIREMENTS.get(feature, ()):
            if not _available(requirement):
                required.append(requirement)
    for feature, requirements in FEATURE_REQUIREMENTS.items():
        if feature in requested:
            continue
        for requirement in requirements:
            if not _available(requirement):
                optional.append(requirement)
    # A missing core package is never optional; remove accidental duplicates.
    unique_required = {r.name: r for r in required}
    unique_optional = {r.name: r for r in optional if r.name not in unique_required}
    return PreflightReport(list(unique_required.values()), list(unique_optional.values()))


def feature_flags(args) -> set[str]:
    """Translate parsed CLI arguments to the requirements they actually need."""
    features: set[str] = set()
    if getattr(args, "gui", False):
        features.add("gui")
    scan = getattr(args, "scan", None)
    if scan:
        features.add(scan)
    if getattr(args, "lynis", False):
        features.add("lynis")
    if getattr(args, "rootkits", False):
        features.add("rootkits")
    return features
