"""
Team 1 — Step 4b: Master Pipeline
Wires OCR → Classifier → PII Detector → Signature Detector → Risk Engine
into a single function that returns a validated PrivacyMap.

Usage:
    from pipeline import run_pipeline
    privacy_map = run_pipeline("path/to/document.pdf", privacy_level="medium")
"""

from __future__ import annotations

import time
import logging
from pathlib import Path
from typing import Optional

from PIL import Image

# Team 1 modules
from ocr_engine import ingest_file, ingest_bytes
from classifier import classify_document, get_masking_preset
from pii_detector import detect_pii_all_pages
from signature_detector import detect_signatures
from risk_engine import (
    compute_risk_score,
    build_warning_messages,
    decide_suggested_mask,
    FRIENDLY_WARNINGS,
)
from schemas import (
    PrivacyMap,
    Detection,
    BoundingBox,
    PageMeta,
    RiskBreakdown,
    MaskingPreset,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

def run_pipeline(
    file_path: Optional[str] = None,
    privacy_level: str = "medium",
    *,
    file_bytes: Optional[bytes] = None,
    filename: Optional[str] = None,
    pages: Optional[list] = None,
) -> PrivacyMap:
    """
    Full Team 1 pipeline. Accepts either a file path OR raw bytes + filename.
    If 'pages' is provided, skips OCR and uses the pre-computed pages directly.
    """
    t0 = time.time()

    if pages is not None:
        logger.info(f"[Pipeline] Using pre-computed OCR pages ({len(pages)} page(s)) | level={privacy_level}")
        return _build_privacy_map(pages, privacy_level, t0)

    if file_bytes is not None:
        logger.info(f"[Pipeline] Starting analysis (bytes): {filename} | level={privacy_level}")
        pages = ingest_bytes(file_bytes, filename or "upload")
        logger.info(f"[Pipeline] OCR complete: {len(pages)} page(s)")
        return _build_privacy_map(pages, privacy_level, t0)

    if file_path is None:
        raise ValueError("Either file_path or file_bytes must be provided.")

    logger.info(f"[Pipeline] Starting analysis: {file_path} | level={privacy_level}")

    pages = ingest_file(file_path)
    logger.info(f"[Pipeline] OCR complete: {len(pages)} page(s)")

    return _build_privacy_map(pages, privacy_level, t0)


def run_pipeline_bytes(
    data: bytes,
    filename: str,
    privacy_level: str = "medium",
) -> PrivacyMap:
    """
    Same as run_pipeline but accepts raw file bytes (for API upload handlers).
    """
    t0 = time.time()
    logger.info(f"[Pipeline] Starting analysis (bytes): {filename} | level={privacy_level}")

    pages = ingest_bytes(data, filename)
    logger.info(f"[Pipeline] OCR complete: {len(pages)} page(s)")

    return _build_privacy_map(pages, privacy_level, t0)


# ---------------------------------------------------------------------------
# Internal orchestration
# ---------------------------------------------------------------------------

def _build_privacy_map(
    pages: list,
    privacy_level: str,
    t0: float,
) -> PrivacyMap:
    """
    Core orchestration: takes OCR page list, runs all analysis steps,
    returns a PrivacyMap.
    """

    # ── Step 2a: Classify document ───────────────────────────────────────
    full_text = "\n".join(p["full_text"] for p in pages)
    classification = classify_document(full_text)
    doc_type   = classification["document_type"]
    doc_conf   = classification["confidence"]
    logger.info(f"[Pipeline] Classified as '{doc_type}' (conf={doc_conf})")

    # ── Step 2b: PII detection ────────────────────────────────────────────
    pii_matches = detect_pii_all_pages(pages)
    logger.info(f"[Pipeline] PII detections: {len(pii_matches)}")

    # ── Step 2c: Signature detection ─────────────────────────────────────
    sig_detections = []
    for page_data in pages:
        # Reconstruct PIL image from OCR data for signature detection
        # If the OCR engine stored a PIL image, use it; otherwise skip
        pil_img = page_data.get("pil_image")
        if pil_img is not None:
            sigs = detect_signatures(pil_img, page_num=page_data["page"])
            sig_detections.extend(sigs)
    logger.info(f"[Pipeline] Signature detections: {len(sig_detections)}")

    # ── Step 3: Risk scoring ──────────────────────────────────────────────
    masking_preset_raw = get_masking_preset(doc_type)
    all_detections_raw = list(pii_matches) + sig_detections

    risk_result  = compute_risk_score(all_detections_raw)
    warnings     = build_warning_messages(all_detections_raw)

    # ── Step 4: Build Detection objects ──────────────────────────────────
    detections = []

    # PII matches
    for m in pii_matches:
        suggested = decide_suggested_mask(
            pii_type       = m.pii_type,
            document_type  = doc_type,
            masking_preset = masking_preset_raw,
            privacy_level  = privacy_level,
        )
        bbox = None
        if m.coordinates:
            bbox = BoundingBox(**m.coordinates)

        detections.append(Detection(
            type            = m.pii_type,
            label           = m.label,
            text            = m.text,
            page            = m.page,
            coordinates     = bbox,
            confidence      = m.confidence,
            risk_level      = m.risk_level,
            suggested_mask  = suggested,
            warning_message = FRIENDLY_WARNINGS.get(m.pii_type),
        ))

    # Signature detections
    for sig in sig_detections:
        suggested = decide_suggested_mask(
            pii_type       = "signature",
            document_type  = doc_type,
            masking_preset = masking_preset_raw,
            privacy_level  = privacy_level,
        )
        coords = sig.get("coordinates")
        bbox = BoundingBox(**coords) if coords else None

        detections.append(Detection(
            type            = "signature",
            label           = "Handwritten Signature",
            text            = "[Signature]",
            page            = sig.get("page", 1),
            coordinates     = bbox,
            confidence      = sig.get("confidence", 0.8),
            risk_level      = "critical",
            suggested_mask  = suggested,
            warning_message = FRIENDLY_WARNINGS.get("signature"),
        ))

    # ── Step 4: Assemble PrivacyMap ───────────────────────────────────────
    page_metas = [
        PageMeta(page=p["page"], width=p["width"], height=p["height"])
        for p in pages
    ]

    critical_count = sum(1 for d in detections if d.risk_level == "critical")
    high_count     = sum(1 for d in detections if d.risk_level == "high")

    privacy_map = PrivacyMap(
        document_type             = doc_type,
        classification_confidence = doc_conf,
        pages                     = page_metas,
        detections                = detections,
        risk                      = RiskBreakdown(**risk_result),
        warnings                  = warnings,
        masking_preset            = MaskingPreset(**masking_preset_raw),
        total_detections          = len(detections),
        critical_count            = critical_count,
        high_count                = high_count,
    )

    elapsed_ms = int((time.time() - t0) * 1000)
    logger.info(f"[Pipeline] Done in {elapsed_ms}ms | risk={risk_result['overall_risk']} | detections={len(detections)}")

    return privacy_map
