# Privacy Gatekeeper — Desktop App
## Complete Step-by-Step Setup Guide

---

## WHAT YOU ARE BUILDING

A Windows desktop application that:
1. You open like any normal program (.exe or python script)
2. Drag & drop or browse for a PDF or image
3. It automatically scans for Aadhaar, PAN, bank details, phone, email, signatures, etc.
4. Highlights each detection with a colored box on the document
5. You toggle which fields to mask
6. Click Export → get a permanently redacted file (black boxes, not blur)
7. Optionally password-protect the export

---

## FOLDER STRUCTURE

After setup, your project folder should look like this:

```
privacy_gatekeeper/
├── app.py                    ← Desktop app (new file — provided below)
├── pipeline.py               ← From Team 1
├── schemas.py                ← From Team 1
├── ocr_engine.py             ← From Team 1
├── classifier.py             ← From Team 1
├── pii_detector.py           ← From Team 1
├── signature_detector.py     ← From Team 1
├── risk_engine.py            ← From Team 1
├── requirements_desktop.txt  ← Provided below
└── (no Team 2 files needed — all replaced by app.py)
```

---

## STEP 1 — Install Python

1. Go to https://www.python.org/downloads/
2. Download Python **3.11** (recommended — most stable with all libraries)
3. During install, CHECK ✅ "Add Python to PATH"
4. Click Install Now

Verify in Command Prompt:
```
python --version
```
Should show: `Python 3.11.x`

---

## STEP 2 — Install Tesseract OCR (Required for text extraction)

1. Go to: https://github.com/UB-Mannheim/tesseract/wiki
2. Download the installer: **tesseract-ocr-w64-setup-5.x.x.exe**
3. Install it — default path is `C:\Program Files\Tesseract-OCR\`
4. During install, select additional languages:
   - ✅ Hindi
   - ✅ Kannada
5. After install, add to PATH:
   - Search "Environment Variables" in Windows search
   - Click "Environment Variables"
   - Under System Variables, find "Path" → Edit
   - Click New → paste: `C:\Program Files\Tesseract-OCR`
   - Click OK on all dialogs

Verify in Command Prompt:
```
tesseract --version
```
Should show version info.

---

## STEP 3 — Create Your Project Folder

1. Create a folder anywhere, e.g.: `C:\privacy_gatekeeper\`
2. Copy ALL Team 1 files into it:
   - `pipeline.py`
   - `schemas.py`
   - `ocr_engine.py`
   - `classifier.py`
   - `pii_detector.py`
   - `signature_detector.py`
   - `risk_engine.py`
3. Copy `app.py` into the same folder (the new desktop app file)
4. Copy `requirements_desktop.txt` into the same folder

---

## STEP 4 — Install Python Dependencies

Open Command Prompt in your project folder:
- Hold Shift + Right-click in the folder → "Open PowerShell window here"
- OR open Command Prompt and type: `cd C:\privacy_gatekeeper`

Then run:
```
pip install PyQt6 Pillow opencv-python-headless pytesseract pdfplumber numpy pydantic PyMuPDF
```

This installs everything needed. It may take 3-5 minutes.

---

## STEP 5 — Run the App

In Command Prompt inside your project folder:
```
python app.py
```

The Privacy Gatekeeper window should open.

---

## STEP 6 — Test It

1. Open the app
2. Select **Privacy Level**: Medium (default)
3. Click **Browse File** or drag a document onto the window
4. Wait for analysis (progress bar shows at top)
5. Colored boxes appear over detected sensitive fields:
   - 🟣 Purple = Critical (Aadhaar, Passport, Credit Card)
   - 🔴 Red = High (PAN, Phone, Email, Bank Account)
   - 🟡 Amber = Medium (DOB, Vehicle Reg)
   - 🟢 Green = Low (PIN Code, IP)
6. Toggle checkboxes on the right panel to choose what to mask
7. Click any box on the document to toggle it
8. Use **Mask All / Unmask All** or **Strict / Medium / Basic** presets
9. Click **Export Redacted File** → choose save location → done

---

## STEP 7 — Build a Windows .EXE (Optional)

To make a double-clickable .exe that works on any Windows PC without Python:

Install PyInstaller:
```
pip install pyinstaller
```

Build the exe:
```
pyinstaller --onefile --windowed --name "PrivacyGatekeeper" app.py
```

Find your exe at: `dist\PrivacyGatekeeper.exe`

**Note:** The .exe will be large (~200-400 MB) because it bundles Python and all libraries.
**Note:** Tesseract must still be installed separately on the target PC.

---

## TROUBLESHOOTING

### "tesseract is not installed or it's not in your PATH"
→ Re-do Step 2. Make sure you added Tesseract to PATH and restarted Command Prompt.

### "No module named 'PyQt6'"
→ Run: `pip install PyQt6`

### "No module named 'pipeline'"
→ Make sure app.py and all Team 1 .py files are in the SAME folder.

### App opens but shows "Demo Mode"
→ This is expected if Team 1 modules aren't found. Check Step 3.

### PDF export not working
→ Run: `pip install PyMuPDF`

### Analysis takes very long
→ Normal for first run (Tesseract loads slowly). Subsequent runs are faster.

---

## HOW THE DESKTOP APP DIFFERS FROM THE WEB VERSION

| Web Version | Desktop Version |
|---|---|
| Next.js frontend (Team 2) | PyQt6 desktop window (app.py) |
| FastAPI server (api.py) | Direct function call to pipeline.py |
| Browser renders document | Qt GraphicsView renders document |
| Canvas API for redaction | Pillow/PyMuPDF for redaction |
| Runs in browser | Runs as native Windows app |
| Requires Node.js + Python | Requires Python only |
| Two separate processes | Single process |

Team 2's logic (bounding box overlays, toggle controls, risk dashboard, export) is fully reimplemented in app.py using PyQt6. Team 1's code (pipeline.py and all modules) is used unchanged.

---

## CONTEXT FOR AI ASSISTANTS

If you want to continue developing this with an AI, use this prompt:

> I am building a PyQt6 desktop application called "Privacy Gatekeeper" that scans documents for PII (Aadhaar, PAN, bank details, phone, email, signatures) and allows permanent redaction before sharing.
> 
> Architecture:
> - `pipeline.py` — Team 1 orchestrator: takes file bytes → returns PrivacyMap (JSON with document_type, overall_risk, detections with coordinates)
> - `app.py` — PyQt6 desktop UI: uploads file, calls pipeline.py directly, overlays bounding boxes on document, allows toggle-based masking, exports redacted file using Pillow (images) or PyMuPDF (PDFs)
> 
> The PrivacyMap JSON contract:
> ```json
> {
>   "document_type": "aadhaar_card",
>   "overall_risk": "critical",
>   "risk_score": 210,
>   "warnings": ["..."],
>   "detections": [
>     {"id": "uuid", "type": "aadhaar", "label": "Aadhaar Number",
>      "text": "1234 5678 9012", "page": 1,
>      "coordinates": {"x": 80, "y": 120, "w": 180, "h": 24},
>      "confidence": 0.95, "risk_level": "critical", "suggested_mask": true}
>   ]
> }
> ```
> 
> Please help me with: [your task here]
