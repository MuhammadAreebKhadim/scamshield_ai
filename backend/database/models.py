from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any
from datetime import datetime

@dataclass
class Indicator:
    name: str
    evidence: str
    severity: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL
    category: Optional[str] = None
    description: Optional[str] = None

    def to_dict(self):
        return asdict(self)

@dataclass
class ThreatIntelligenceResult:
    urlhaus: Dict[str, Any] = field(default_factory=dict)
    virustotal: Dict[str, Any] = field(default_factory=dict)
    google_safe_browsing: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)

@dataclass
class AIAnalysisResult:
    risk_level: str = "LOW"
    risk_score: int = 0
    category: str = "General"
    summary: str = ""
    indicators: List[Dict[str, Any]] = field(default_factory=list)
    highlighted_sentences: List[Dict[str, str]] = field(default_factory=list)
    recommendation: str = ""

    def to_dict(self):
        return asdict(self)

@dataclass
class ScanRecord:
    scan_id: str
    user_id: Optional[str] = None
    user_email: Optional[str] = None
    input_type: str = "url"
    input_summary: str = ""
    input_data: Dict[str, Any] = field(default_factory=dict)
    risk_score: int = 0
    risk_level: str = "LOW"
    is_threat_confirmed: bool = False
    indicators: List[Dict[str, Any]] = field(default_factory=list)
    threat_intelligence: Dict[str, Any] = field(default_factory=dict)
    ai_analysis: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    score_breakdown: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self):
        return asdict(self)

@dataclass
class UserProfile:
    user_id: str
    email: str
    name: str
    picture: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self):
        return asdict(self)

@dataclass
class DashboardStats:
    total_scans: int = 0
    high_risk_detections: int = 0
    suspicious_detections: int = 0
    caution_detections: int = 0
    safe_detections: int = 0
    recent_scans: List[Dict[str, Any]] = field(default_factory=list)
    threat_categories: Dict[str, int] = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)
