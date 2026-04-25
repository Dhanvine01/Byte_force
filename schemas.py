"""
Team 1 — Step 4a: JSON Contract / Data Schemas
Defines the exact structure of the Privacy Map that Team 2 consumes.
Uses Pydantic v2 for validation and automatic OpenAPI docs generation.
"""

from __future__ import annotations
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------

class BoundingBox(BaseModel):
    """Pixel-space bounding box on the document page."""
    x: int = Field(..., description="Left edge in pixels")
    y: int = Field(..., description="Top edge in pixels")
    w: int = Field(..., description="Width in pixels")
    h: int = Field(..., description="Height in pixels")


class Detection(BaseModel):
    """A single PII or signature detection with its location and risk metadata."""
    type: str = Field(..., description="PII type key, e.g. 'aadhaar', 'pan', 'signature'")
    label: str = Field(..., description="Human-readable label, e.g. 'Aadhaar Number'")
    text: str = Field(..., description="Detected text (will be '[Redacted]' in safe output)")
    page: int = Field(1, description="1-indexed page number where detection was found")
    coordinates: Optional[BoundingBox] = Field(
        None,
        description="Bounding box on the page. None if coordinate mapping failed."
    )
    confidence: float = Field(..., ge=0.0, le=1.0, description="Detection confidence 0–1")
    risk_level: str = Field(..., description="low / medium / high / critical")
    suggested_mask: bool = Field(
        True,
        description="Whether this field should be masked by default (based on doc type + privacy level)"
    )
    warning_message: Optional[str] = Field(
        None,
        description="Human-friendly warning for this specific detection"
    )


class MaskingPreset(BaseModel):
    """Context-smart masking preset for the detected document type."""
    auto_mask: List[str] = Field(..., description="PII types masked by default")
    optional: List[str] = Field(..., description="PII types the user can choose to mask")
    description: str = Field(..., description="Human-readable explanation of the preset")


class RiskBreakdown(BaseModel):
    """Detailed risk score breakdown."""
    total_score: int = Field(..., description="Raw numeric risk score")
    overall_risk: str = Field(..., description="low / medium / high / critical")
    type_breakdown: Dict[str, int] = Field(
        ...,
        description="Per-PII-type score contribution"
    )


class PrivacyMap(BaseModel):
    """
    The core JSON Contract between Team 1 (Intelligence Engine)
    and Team 2 (Security Gatekeeper).

    Team 2 should consume this object to:
      - Render highlight overlays using `detections[].coordinates`
      - Set default toggle states using `detections[].suggested_mask`
      - Show risk banners using `risk.overall_risk`
      - Display warnings using `warnings[]`
      - Apply privacy presets using `masking_preset`
    """
    # Document identity
    document_type: str = Field(
        ...,
        description="Classified document type: aadhaar_card, pan_card, bank_statement, resume, invoice, medical_record, unknown"
    )
    classification_confidence: float = Field(
        ..., ge=0.0, le=1.0,
        description="Confidence score of the document classification"
    )

    # Page metadata (Team 2 needs this to scale overlays correctly)
    pages: List[PageMeta] = Field(..., description="Per-page size metadata")

    # Core detections
    detections: List[Detection] = Field(
        default_factory=list,
        description="All detected PII and signatures across all pages"
    )

    # Risk analysis
    risk: RiskBreakdown = Field(..., description="Overall document risk analysis")

    # UX helpers for Team 2
    warnings: List[str] = Field(
        default_factory=list,
        description="Deduplicated human-friendly warning messages"
    )
    masking_preset: MaskingPreset = Field(
        ...,
        description="Default masking rules for this document type"
    )

    # Summary counts (for Team 2 dashboard/header)
    total_detections: int = Field(0, description="Total number of PII detections")
    critical_count: int = Field(0, description="Number of critical-risk detections")
    high_count: int = Field(0, description="Number of high-risk detections")


class PageMeta(BaseModel):
    """Pixel dimensions of each page (needed by Team 2 to scale overlay boxes)."""
    page: int
    width: int
    height: int


# Resolve forward reference
PrivacyMap.model_rebuild()


# ---------------------------------------------------------------------------
# Request / Response models for the API
# ---------------------------------------------------------------------------

class AnalyzeResponse(BaseModel):
    """Top-level API response envelope."""
    success: bool = True
    privacy_map: PrivacyMap
    processing_time_ms: int = Field(..., description="Server-side processing time")


class ErrorResponse(BaseModel):
    success: bool = False
    error: str
    detail: Optional[str] = None
