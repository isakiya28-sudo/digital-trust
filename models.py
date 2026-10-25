from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class Indicator(BaseModel):
    id: str
    label: str
    severity: str  # "high", "medium", "low", "info"
    description: str
    matched_phrases: List[str] = Field(default_factory=list)

class ScanResult(BaseModel):
    scan_id: str
    scan_type: str  # "message", "url", "content_text", "content_image"
    target_summary: str
    risk_score: int  # 0 to 100
    risk_category: str  # "Low Risk", "Medium Risk", "High Risk"
    indicators: List[Indicator] = Field(default_factory=list)
    highlighted_phrases: List[str] = Field(default_factory=list)
    explanation: str
    recommendations: List[str] = Field(default_factory=list)
    is_ai_fallback: bool = True
    scoring_method: str
    timestamp: str
    details: Dict[str, Any] = Field(default_factory=dict)

class MessageScanRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=15000, description="The message or email body to analyze")

class UrlScanRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048, description="The URL to inspect")

class TextContentScanRequest(BaseModel):
    text: str = Field(..., min_length=5, max_length=25000, description="News headline, article snippet, or social post")

class ScanHistoryItem(BaseModel):
    id: str
    scan_type: str
    target_summary: str
    risk_score: int
    risk_category: str
    timestamp: str
    indicator_count: int
    explanation: Optional[str] = None

class DashboardStats(BaseModel):
    total_scans: int
    low_risk_count: int
    medium_risk_count: int
    high_risk_count: int
    scan_types: Dict[str, int]
    recent_scans: List[ScanHistoryItem]
    is_demo_data: bool = False
