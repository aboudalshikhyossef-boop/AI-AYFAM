"""
AI AYFAM Data Models
نماذج البيانات الموحدة
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any
from enum import Enum
from datetime import datetime


class SeverityLevel(Enum):
    """مستويات الخطورة"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    SAFE = "safe"


class RiskLevel(Enum):
    """مستويات المخاطر"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class ScanType(Enum):
    """أنواع الفحوصات"""
    NETWORK = "network"
    PORTS = "ports"
    SYSTEM = "system"
    LOGS = "logs"
    USB = "usb"
    CVE = "cve"
    FULL = "full"


@dataclass
class Finding:
    """نتيجة واحدة من نتائج الفحص"""
    severity: str
    title: str
    detail: str = ""
    fix: str = ""
    references: List[str] = field(default_factory=list)
    compound: bool = False
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        """تحويل إلى قاموس"""
        return asdict(self)
    
    def __repr__(self) -> str:
        return f"Finding({self.severity}: {self.title})"


@dataclass
class ScanResult:
    """نتيجة الفحص الكاملة"""
    scan_type: str
    timestamp: datetime
    target: Optional[str] = None
    findings: List[Finding] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "safe"
    metadata: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    
    def to_dict(self) -> Dict:
        """تحويل إلى قاموس"""
        return {
            "scan_type": self.scan_type,
            "timestamp": self.timestamp.isoformat(),
            "target": self.target,
            "findings": [f.to_dict() for f in self.findings],
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "metadata": self.metadata,
            "error": self.error,
        }
    
    def get_critical_count(self) -> int:
        """عدد النتائج الحرجة"""
        return len([f for f in self.findings if f.severity == "critical"])
    
    def get_high_count(self) -> int:
        """عدد النتائج العالية"""
        return len([f for f in self.findings if f.severity == "high"])
    
    def get_total_count(self) -> int:
        """إجمالي النتائج"""
        return len(self.findings)
    
    def __repr__(self) -> str:
        return f"ScanResult({self.scan_type}: {self.get_total_count()} findings)"


@dataclass
class SystemInfo:
    """معلومات النظام"""
    hostname: str
    os: str
    kernel: str
    uptime: str
    cpu: str
    ram: str
    disk: str
    python_version: str
    
    def to_dict(self) -> Dict:
        """تحويل إلى قاموس"""
        return asdict(self)


@dataclass
class NetworkInterface:
    """واجهة شبكة"""
    name: str
    state: str
    addresses: List[str] = field(default_factory=list)
    mac_address: Optional[str] = None
    
    def to_dict(self) -> Dict:
        """تحويل إلى قاموس"""
        return asdict(self)


@dataclass
class Connection:
    """اتصال نشط"""
    protocol: str
    local_address: str
    remote_address: str
    state: str
    process: str
    trust_level: str
    risk_level: str
    reason: str
    
    def to_dict(self) -> Dict:
        """تحويل إلى قاموس"""
        return asdict(self)


@dataclass
class Port:
    """منفذ مفتوح"""
    port_number: int
    protocol: str
    service: str
    state: str
    risk_level: str
    
    def to_dict(self) -> Dict:
        """تحويل إلى قاموس"""
        return asdict(self)


@dataclass
class CVEInfo:
    """معلومات CVE"""
    cve_id: str
    severity: str
    cvss_score: float
    description: str
    published_date: str
    affected_packages: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        """تحويل إلى قاموس"""
        return asdict(self)


@dataclass
class USBDevice:
    """جهاز USB"""
    vendor_id: str
    product_id: str
    product: str
    bus: str
    device: str
    device_type: str
    risk_level: str
    flags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        """تحويل إلى قاموس"""
        return asdict(self)


@dataclass
class Report:
    """تقرير الفحص"""
    title: str
    timestamp: datetime
    scans: List[ScanResult] = field(default_factory=list)
    system_info: Optional[SystemInfo] = None
    summary: str = ""
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        """تحويل إلى قاموس"""
        return {
            "title": self.title,
            "timestamp": self.timestamp.isoformat(),
            "scans": [s.to_dict() for s in self.scans],
            "system_info": self.system_info.to_dict() if self.system_info else None,
            "summary": self.summary,
            "recommendations": self.recommendations,
        }
    
    def get_total_findings(self) -> int:
        """إجمالي النتائج في كل الفحوصات"""
        return sum(s.get_total_count() for s in self.scans)
    
    def get_critical_findings(self) -> int:
        """إجمالي النتائج الحرجة"""
        return sum(s.get_critical_count() for s in self.scans)
