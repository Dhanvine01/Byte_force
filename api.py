"""
Team 1 — Step 4c: FastAPI Server
Exposes the Privacy Decision Assistant pipeline as an HTTP API.
Team 2 calls POST /analyze with a file upload and gets a PrivacyMap JSON back.

Run with:
    pip install fastapi uvicorn python-multipart
    uvicorn api:app --reload --port 8000

Swagger docs auto-generated at: http://localhost:8000/docs
"""

from __future__ import annotations

import time
import logging
import traceback
from typing import Optional

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from pipeline import run_pipeline_bytes
from schemas import AnalyzeResponse, ErrorResponse, PrivacyMap

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Privacy Decision Assistant — Team 1 API",
    description=(
        "Analyzes uploaded documents for PII, signatures, and privacy risk. "
        "Returns a structured Privacy Map for Team 2's frontend to consume."
    ),
    version="1.0.0",
)

# Allow Team 2's frontend to call this API (adjust origins in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # Restrict to Team 2's domain in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SUPPORTED_MIME_TYPES = {
    "application/pdf",
    "image/jpeg",
    "image/png",
    "image/bmp",
    "image/tiff",
    "image/webp",
}

SUPPORTED_EXTENSIONS = {".pdf", ".jpg", ".jpeg", ".png", ".bmp", ".tiff", ".webp"}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", summary="Health check")
def root():
    return {"status": "ok", "service": "Privacy Decision Assistant — Team 1 API"}


@app.get("/health", summary="Health check")
def health():
    return {"status": "ok"}


@app.post(
    "/analyze",
    response_model=AnalyzeResponse,
    summary="Analyze a document for PII and privacy risk",
    responses={
        200: {"description": "Analysis complete — PrivacyMap returned"},
        400: {"model": ErrorResponse, "description": "Unsupported file type or bad request"},
        422: {"model": ErrorResponse, "description": "Processing error"},
        500: {"model": ErrorResponse, "description": "Internal server error"},
    }
)
async def analyze_document(
    file: UploadFile = File(..., description="PDF or image file to analyze"),
    privacy_level: str = Form(
        "medium",
        description="Privacy level: 'basic' | 'medium' | 'strict'"
    ),
):
    """
    **Main endpoint for Team 2.**

    Upload a PDF or image. Receive a full Privacy Map containing:
    - `document_type` — classified document category
    - `detections[]` — each detected PII/signature with coordinates,
      risk level, and suggested_mask flag
    - `risk` — overall risk score and grade
    - `warnings[]` — human-friendly warning messages
    - `masking_preset` — default masking rules for this doc type
    - `pages[]` — page dimensions for overlay scaling

    ### Privacy Levels
    | Level   | Behavior |
    |---------|----------|
    | basic   | Only masks critical PII (Aadhaar, PAN, credit cards) |
    | medium  | Masks based on document type context (recommended) |
    | strict  | Masks all detected personal information |
    """
    t0 = time.time()

    # ── Validate file type ────────────────────────────────────────────────
    filename = file.filename or "upload"
    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    if ext not in SUPPORTED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{ext}'. Supported: {', '.join(SUPPORTED_EXTENSIONS)}"
        )

    if privacy_level not in ("basic", "medium", "strict"):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid privacy_level '{privacy_level}'. Must be: basic, medium, or strict."
        )

    # ── Read file bytes ───────────────────────────────────────────────────
    try:
        file_bytes = await file.read()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not read uploaded file: {e}")

    if len(file_bytes) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    if len(file_bytes) > 50 * 1024 * 1024:   # 50 MB limit
        raise HTTPException(status_code=400, detail="File too large. Maximum size is 50 MB.")

    # ── Run pipeline ──────────────────────────────────────────────────────
    try:
        privacy_map: PrivacyMap = run_pipeline_bytes(
            data          = file_bytes,
            filename      = filename,
            privacy_level = privacy_level,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Pipeline error: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

    elapsed_ms = int((time.time() - t0) * 1000)

    return AnalyzeResponse(
        success          = True,
        privacy_map      = privacy_map,
        processing_time_ms = elapsed_ms,
    )


@app.post(
    "/analyze/risk-preview",
    summary="Get a quick risk summary without full coordinate mapping",
    response_model=dict,
)
async def risk_preview(
    file: UploadFile = File(...),
    privacy_level: str = Form("medium"),
):
    """
    Lightweight version of /analyze — returns only the risk grade and
    warning count. Useful for Team 2's upload screen pre-check.
    """
    filename  = file.filename or "upload"
    file_bytes = await file.read()

    try:
        privacy_map = run_pipeline_bytes(file_bytes, filename, privacy_level)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return {
        "document_type":    privacy_map.document_type,
        "overall_risk":     privacy_map.risk.overall_risk,
        "total_detections": privacy_map.total_detections,
        "critical_count":   privacy_map.critical_count,
        "high_count":       privacy_map.high_count,
        "warnings":         privacy_map.warnings,
    }


# ---------------------------------------------------------------------------
# Run directly for development
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
