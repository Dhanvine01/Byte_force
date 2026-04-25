# 🛡️ Privacy Gatekeeper — Personal Data Privacy Analyzer

> **Hackathon Problem Statement #3 — Personal Data Privacy Analyzer**
> *Help users safeguard personal data and promote responsible data sharing practices.*

---

## Problem Statement

Users often unknowingly share sensitive personal information in documents — scanned IDs, bank statements, resumes, medical records — without realizing the privacy exposure they create. Once a document containing an Aadhaar number, PAN, or bank account is shared via email, WhatsApp, or uploaded to a portal, that data can be misused for identity theft, financial fraud, or unauthorized access.

**The challenge:** Build a tool that scans uploaded files (PDFs, images, documents), identifies sensitive data such as Aadhaar, PAN, phone numbers, and emails, and highlights or masks the sensitive information — all before the document leaves the user's hands.

---

## What Privacy Gatekeeper Does

Privacy Gatekeeper is a standalone Windows desktop application that gives users full visibility and control over the personal data inside their documents. Before sharing any file, users can:

1. **Drag & drop or browse** for a PDF or image document
2. **Automatically scan** for Aadhaar, PAN, bank details, phone numbers, emails, signatures, and more
3. **See colored bounding boxes** overlaid on every detected sensitive field
4. **Toggle individual fields** to choose exactly what to redact
5. **Export a permanently redacted file** (true black-box redaction, not blur) — PDF or image
6. **Optionally password-protect** the exported file

No cloud uploads. No server. Everything runs locally on the user's machine.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    Privacy Gatekeeper (app.py)                   │
│                     PyQt6 Desktop Interface                      │
│  ┌─────────────┐  ┌─────────────┐  ┌──────────────────────────┐ │
│  │  Document   │  │  Detection  │  │     Export & Redaction   │ │
│  │   Viewer    │  │   Panel     │  │   (Pillow / PyMuPDF)     │ │
│  │(GraphicsView│  │ (Checkboxes │  │                          │ │
│  │  + Overlays)│  │  + Risk UI) │  │                          │ │
│  └──────┬──────┘  └──────┬──────┘  └──────────────────────────┘ │
└─────────┼────────────────┼───────────────────────────────────────┘
          │                │
          ▼                ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Intelligence Pipeline (pipeline.py)             │
│                                                                  │
│  Step 1          Step 2a          Step 2b         Step 2c        │
│  ┌──────────┐   ┌────────────┐   ┌───────────┐  ┌───────────┐  │
│  │  OCR &   │──▶│ Document   │──▶│    PII    │  │ Signature │  │
│  │ Ingestion│   │ Classifier │   │ Detector  │  │ Detector  │  │
│  │(ocr_engine│  │(classifier │   │(pii_detect│  │(signature_│  │
│  │   .py)   │   │   .py)     │   │  or.py)   │  │detector.py│  │
│  └──────────┘   └────────────┘   └───────────┘  └───────────┘  │
│       │                │               │               │         │
│       ▼                ▼               ▼               ▼         │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │              Step 3: Risk Engine (risk_engine.py)        │    │
│  │         Risk Score → Grade → Warnings → Masking Preset  │    │
│  └─────────────────────────────────────────────────────────┘    │
│       │                                                          │
│       ▼                                                          │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │         Step 4: PrivacyMap (schemas.py — Pydantic)       │    │
│  │   document_type · detections[] · risk · warnings[]       │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

The app also ships with `api.py` — a FastAPI server that exposes the same pipeline as a REST endpoint (`POST /analyze`), enabling integration with web frontends or other services.

---

## Project Structure

```
privacy_gatekeeper/
├── app.py                    ← PyQt6 desktop UI (main entry point)
├── pipeline.py               ← Master orchestrator: wires all steps together
├── schemas.py                ← Pydantic data contracts (PrivacyMap, Detection, etc.)
├── ocr_engine.py             ← Step 1: Ingestion, OCR, bounding-box extraction
├── classifier.py             ← Step 2a: Document type classifier
├── pii_detector.py           ← Step 2b: PII detection with regex + position mapping
├── signature_detector.py     ← Step 2c: Handwritten signature detection (CV)
├── signature_detector_backup.py ← Backup with relaxed thresholds
├── risk_engine.py            ← Step 3: Risk scoring, warning messages, masking logic
├── api.py                    ← FastAPI REST server (for web integration)
├── requirements_desktop.txt  ← Python dependencies
├── launch_app.bat            ← Windows launcher (double-click to run)
├── create_shortcut.py        ← Creates a Desktop shortcut
├── icon.png / icon.ico       ← App icon
├── SETUP_INSTRUCTIONS.md     ← Complete step-by-step setup guide
└── README.md                 ← This file
```

---

## Technical Implementation

### Step 1 — OCR & Ingestion (`ocr_engine.py`)

Handles multi-format document ingestion and text extraction with bounding box coordinates.

**Supported formats:** PDF, JPG, PNG, BMP, TIFF, WebP

**OCR Pipeline:**
- **Primary:** EasyOCR (deep learning, GPU-optional) — superior for Indian scripts (Kannada, Hindi)
- **Fallback:** Tesseract OCR (`eng+hin+kan`) for environments without EasyOCR
- **PDFs:** Native text extraction via `pdfplumber` (no OCR needed for digital PDFs); falls back to image rendering + OCR for scanned PDFs

**Preprocessing steps:**
1. Upscale images narrower than 2400px (higher resolution → better OCR accuracy)
2. Grayscale conversion
3. Fast non-local means denoising (preserves text detail)
4. CLAHE contrast enhancement (handles multi-script documents better than binary thresholding)

**Output:** Per-page list with `full_text`, `words[]` (each with pixel bounding box), and page dimensions.

---

### Step 2a — Document Classifier (`classifier.py`)

Identifies the document type from extracted text using weighted keyword heuristics.

**Supported document types:**

| Type | Key Signals |
|------|-------------|
| `aadhaar_card` | "aadhaar", "UIDAI", 12-digit pattern |
| `pan_card` | "permanent account number", PAN format `[A-Z]{5}[0-9]{4}[A-Z]` |
| `id_card` | "voter", "driving licence", "passport", "date of birth" |
| `bank_statement` | "IFSC", "opening balance", "debit", "credit", "transaction" |
| `resume` | "curriculum vitae", "work experience", "skills", "LinkedIn" |
| `invoice` | "GSTIN", "HSN", "tax invoice", "bill to", "quantity" |
| `medical_record` | "prescription", "diagnosis", "patient", "dosage", "hospital" |
| `unknown` | Fallback when no type scores above zero |

Each document type maps to a **masking preset** — a context-aware default that auto-masks relevant PII while leaving optional fields for user decision.

---

### Step 2b — PII Detector (`pii_detector.py`)

Detects 20+ categories of personally identifiable information using compiled regular expressions, mapped back to pixel bounding boxes on the original document.

**Detected PII types:**

| Category | PII Types | Risk Level |
|----------|-----------|------------|
| **Government IDs** | Aadhaar (12-digit), Aadhaar VID (16-digit), PAN, Passport, Voter ID, Driving License | Critical / High |
| **Financial** | Bank Account Number, IFSC Code, GSTIN, Credit/Debit Card, Partial Card, UPI ID | Critical / High |
| **Contact** | Phone Number (+91 / 10-digit), Email Address, IP Address | High / Medium |
| **Personal** | Full Name, Gender, Date of Birth, Vehicle Registration, PIN Code | Medium / Low |
| **Location** | Address blocks (detected via word-position analysis, not just regex) | Medium |
| **Custom** | User-defined keywords via the desktop UI | Configurable |

**Coordinate mapping:** Each detection is mapped back to pixel coordinates on the OCR image so the UI can draw precise bounding boxes over the exact text location.

---

### Step 2c — Signature Detector (`signature_detector.py`)

Detects handwritten signature regions using computer vision — no ML model required.

**Algorithm:**
1. Binarize the image (Otsu threshold after Gaussian blur)
2. Horizontally dilate (kernel `20×3`) to connect cursive strokes
3. Extract contours and filter by area (`3500–80,000 px²`)
4. Skip detections in the top 15% of the image (headers/logos)
5. Score each candidate on four heuristics:
   - **Aspect ratio** (ideal: wide, ~5:1 width:height)
   - **Fill ratio / ink density** (ideal: 5–35% of bounding box filled)
   - **Connected component count** (cursive writing = many loops; minimum 6)
   - **Width heuristic** (signatures span significant horizontal space)
6. Accept candidates scoring ≥ 0.80 confidence
7. Merge overlapping boxes (IoU > 0.3) to handle multi-stroke signatures

---

### Step 3 — Risk Engine (`risk_engine.py`)

Computes a risk score for the document based on what was detected.

**Risk weights (sample):**

| PII Type | Weight |
|----------|--------|
| Aadhaar, Credit Card | 100 |
| Passport | 95 |
| PAN | 90 |
| Account Number | 85 |
| Signature | 80 |
| Voter ID | 75 |
| Phone | 50 |
| Email | 40 |
| PIN Code | 10 |

**Risk grades:**
- `low` — score 0–30
- `medium` — score 31–70
- `high` — score 71–150
- `critical` — score > 150

**Masking decision logic** (`decide_suggested_mask`):

| Privacy Level | Behavior |
|---------------|----------|
| `basic` | Only masks critical types: Aadhaar, PAN, Passport, Credit Card, Account Number, Signature |
| `medium` | Masks based on document type context (recommended default) |
| `strict` | Masks all detected personal information |

---

### Step 4 — PrivacyMap Schema (`schemas.py`)

The structured output contract — a validated Pydantic v2 model returned by the pipeline and consumed by the UI.

```json
{
  "document_type": "aadhaar_card",
  "classification_confidence": 0.94,
  "pages": [{ "page": 1, "width": 2400, "height": 1600 }],
  "detections": [
    {
      "type": "aadhaar",
      "label": "Aadhaar Number",
      "text": "1234 5678 9012",
      "page": 1,
      "coordinates": { "x": 320, "y": 480, "w": 210, "h": 28 },
      "confidence": 0.97,
      "risk_level": "critical",
      "suggested_mask": true,
      "warning_message": "⚠️ This document contains your Aadhaar number..."
    }
  ],
  "risk": {
    "total_score": 215,
    "overall_risk": "critical",
    "type_breakdown": { "aadhaar": 100, "phone": 50, "email": 40, "dob": 35 }
  },
  "warnings": ["⚠️ Aadhaar number detected...", "📞 Phone number detected..."],
  "masking_preset": {
    "auto_mask": ["aadhaar", "dob", "address", "phone"],
    "optional": ["name", "gender"],
    "description": "Aadhaar card: mask UID, DOB, address, and contact details by default."
  },
  "total_detections": 4,
  "critical_count": 1,
  "high_count": 1
}
```

---

### Desktop UI (`app.py`)

Built with PyQt6. Key components:

- **AnalysisWorker** — runs the pipeline on a background `QThread` so the UI stays responsive during analysis
- **DocumentViewer** — `QGraphicsView`-based viewer that renders the document and overlays colored bounding boxes. Click any box to toggle its mask state
- **DetectionPanel** — scrollable list of all detections with checkboxes, risk badges, and confidence scores
- **Risk Dashboard** — shows overall risk grade, detection counts, and human-readable warnings
- **Privacy Level Selector** — Basic / Medium / Strict presets with one-click apply
- **Export** — Permanent redaction via Pillow (images) or PyMuPDF (PDFs), with optional password protection

**Overlay color coding:**

| Color | Risk Level | Examples |
|-------|-----------|---------|
| 🟣 Purple | Critical | Aadhaar, Passport, Credit Card |
| 🔴 Red | High | PAN, Phone, Bank Account |
| 🟡 Amber | Medium | DOB, Vehicle Registration |
| 🟢 Green | Low | PIN Code, IP Address |

---

### REST API (`api.py`)

FastAPI server for web frontend integration.

**Endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Health check |
| `GET` | `/health` | Health check |
| `POST` | `/analyze` | Full analysis — returns complete PrivacyMap |
| `POST` | `/analyze/risk-preview` | Lightweight risk summary (grade + counts only) |

**Usage:**
```bash
uvicorn api:app --reload --port 8000
# Swagger UI: http://localhost:8000/docs
```

**Request (multipart/form-data):**
- `file` — PDF or image (max 50 MB)
- `privacy_level` — `basic` | `medium` | `strict` (default: `medium`)

---

## Setup & Installation

### Prerequisites

- **Python 3.11** — https://www.python.org/downloads/
- **Tesseract OCR 5.x** — https://github.com/UB-Mannheim/tesseract/wiki
  - During install, select **Hindi** and **Kannada** language packs
  - Add `C:\Program Files\Tesseract-OCR` to your system PATH

### Install Dependencies

```bash
pip install PyQt6 Pillow opencv-python-headless pytesseract pdfplumber numpy pydantic PyMuPDF easyocr
```

Or using the requirements file:
```bash
pip install -r requirements_desktop.txt
pip install easyocr  # deep learning OCR (optional but recommended)
```

### Run the App

```bash
python app.py
```

### Create a Desktop Shortcut (Windows)

```bash
python create_shortcut.py
```

### Build a Standalone .EXE (Optional)

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name "PrivacyGatekeeper" app.py
# Output: dist/PrivacyGatekeeper.exe
```

> Note: Tesseract must still be installed separately on the target machine. The .exe bundles Python and all Python libraries (~200–400 MB).

---

## Supported File Types

| Format | Support |
|--------|---------|
| PDF (digital/text) | ✅ Native text extraction (fast, accurate) |
| PDF (scanned/image) | ✅ OCR fallback |
| JPG / JPEG | ✅ |
| PNG | ✅ |
| BMP | ✅ |
| TIFF | ✅ |
| WebP | ✅ |

**Maximum file size:** 50 MB (API) / unlimited (desktop app)

---

## Languages Supported

| Language | OCR Engine |
|----------|-----------|
| English | EasyOCR + Tesseract |
| Hindi (Devanagari) | EasyOCR + Tesseract |
| Kannada | EasyOCR + Tesseract |

---

## Privacy & Security

- **100% local processing** — no document data is sent to any external server
- **No internet required** — the desktop app works completely offline
- **True redaction** — exported files use opaque black boxes drawn directly onto the image/PDF layer, not CSS overlays or metadata. The original text cannot be recovered from the exported file
- **No logs retained** — the app does not write document content to disk

---

## Troubleshooting

**"tesseract is not installed or it's not in your PATH"**
→ Re-run Step 2 of SETUP_INSTRUCTIONS.md. Restart Command Prompt after adding Tesseract to PATH.

**"No module named 'PyQt6'"**
→ Run: `pip install PyQt6`

**"No module named 'pipeline'"**
→ Ensure `app.py` and all `.py` files are in the same folder.

**App opens but shows "Demo Mode"**
→ Pipeline modules not found. Check that all Team 1 files are in the same directory as `app.py`.

**PDF export not working**
→ Run: `pip install PyMuPDF`

**Analysis is slow on first run**
→ Normal — EasyOCR downloads its model weights on first use (~100 MB). Subsequent runs are faster. Tesseract also loads slowly on first invocation.

**False positive detections (e.g., PIN codes in phone numbers)**
→ Use the detection panel to uncheck individual detections before exporting. Adjust the Privacy Level to `basic` to reduce low-confidence matches.

---

## Team

Built at the hackathon as a combined Team 1 + Team 2 solution:

- **Team 1 — Intelligence Engine:** OCR pipeline, document classification, PII detection, signature detection, risk scoring, REST API
- **Team 2 — Security Interface:** Bounding box overlay UI, detection toggle controls, risk dashboard, redaction export — reimplemented as a native PyQt6 desktop app in `app.py`

---

## Dependencies

| Library | Purpose |
|---------|---------|
| `PyQt6` | Desktop GUI framework |
| `pdfplumber` | Native PDF text extraction |
| `pytesseract` | Tesseract OCR wrapper |
| `easyocr` | Deep learning OCR (primary, handles Indian scripts) |
| `Pillow` | Image processing, image redaction export |
| `opencv-python-headless` | Signature detection (computer vision) |
| `numpy` | Array operations for CV pipeline |
| `pydantic` | Data validation and schema enforcement |
| `PyMuPDF` | PDF redaction export |
| `fastapi` + `uvicorn` | REST API server (optional web integration) |

---

## License

Built for educational and hackathon purposes. All document analysis is performed locally. No user data is collected or transmitted.
