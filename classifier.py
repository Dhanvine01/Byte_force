"""
Team 1 — Step 2a: Document Classifier
Identifies the document type from extracted text using keyword heuristics.
Supported types: id_card, aadhaar_card, pan_card, bank_statement,
                 resume, invoice, medical_record, unknown
"""

import re
from typing import Dict, List, Tuple

# ---------------------------------------------------------------------------
# Keyword signatures per document type
# Each entry: (document_type, weight, [keyword_patterns])
# Higher total score → chosen type
# ---------------------------------------------------------------------------
CLASSIFIER_RULES: List[Tuple[str, float, List[str]]] = [
    (
        "aadhaar_card", 10.0,
        [
            r"\baadhaar\b", r"\buidai\b", r"\bunique identification\b",
            r"\bvid\b.*\d{16}", r"\d{4}\s\d{4}\s\d{4}",   # 12-digit Aadhaar pattern
        ]
    ),
    (
        "pan_card", 10.0,
        [
            r"\bpermanent account number\b", r"\bincome.tax\b",
            r"\bpan\b", r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",     # PAN format
        ]
    ),
    (
        "id_card", 8.0,
        [
            r"\bvoting\b", r"\bvoter\b", r"\bdriving licen[cs]e\b",
            r"\bpassport\b", r"\bgovernment of india\b", r"\bidentity\b",
            r"\bdate of birth\b", r"\bdob\b", r"\bnationality\b",
        ]
    ),
    (
        "bank_statement", 9.0,
        [
            r"\bbank statement\b", r"\baccount (number|no\.?)\b",
            r"\bifsc\b", r"\bmicr\b", r"\bopening balance\b",
            r"\bclosing balance\b", r"\bdebit\b", r"\bcredit\b",
            r"\btransaction\b", r"\biban\b", r"\bswift\b",
        ]
    ),
    (
        "resume", 8.0,
        [
            r"\bcurriculum vitae\b", r"\bresume\b",
            r"\bwork experience\b", r"\bemployment history\b",
            r"\bskills\b", r"\beducation\b", r"\bobjective\b",
            r"\breferences\b", r"\blinkedin\b", r"\bgithub\b",
            r"\bprojects\b", r"\bacheivements\b",
        ]
    ),
    (
        "invoice", 8.0,
        [
            r"\binvoice\b", r"\bbill to\b", r"\bship to\b",
            r"\bgstin\b", r"\bgst\b", r"\bhsn\b", r"\bsac\b",
            r"\btaxable amount\b", r"\btax invoice\b",
            r"\bdue date\b", r"\bpayment terms\b",
            r"\btotal amount\b", r"\bquantity\b",
        ]
    ),
    (
        "medical_record", 7.0,
        [
            r"\bprescription\b", r"\bdiagnosis\b", r"\bpatient\b",
            r"\bdr\.?\s", r"\bdoctor\b", r"\bhospital\b",
            r"\bmg\b", r"\bdosage\b", r"\brx\b", r"\bblood\b",
            r"\bbmi\b", r"\bweight\b.*\bkg\b",
        ]
    ),
]


def classify_document(text: str) -> Dict:
    """
    Classify a document based on its full OCR text.

    Args:
        text: Full extracted text from all pages.

    Returns:
        {
          "document_type": str,
          "confidence":    float,   # 0.0 – 1.0
          "scores":        dict     # per-type raw scores (debug)
        }
    """
    lower_text = text.lower()
    scores: Dict[str, float] = {}

    for doc_type, weight, patterns in CLASSIFIER_RULES:
        score = 0.0
        for pattern in patterns:
            matches = re.findall(pattern, lower_text)
            score  += weight * len(matches)
        scores[doc_type] = score

    if not scores:
        return {"document_type": "unknown", "confidence": 0.0, "scores": {}}

    best_type = max(scores, key=lambda k: scores[k])
    best_score = scores[best_type]

    # Normalise to a rough 0-1 confidence
    total = sum(scores.values()) or 1
    confidence = round(min(best_score / total, 1.0), 3) if best_score > 0 else 0.0

    if best_score == 0:
        best_type = "unknown"
        confidence = 0.0

    return {
        "document_type": best_type,
        "confidence":    confidence,
        "scores":        {k: round(v, 2) for k, v in scores.items()},
    }


def get_masking_preset(document_type: str) -> Dict:
    """
    Returns the context-smart masking preset for a given document type.
    Team 2 uses this to know which PII classes should be masked by default.

    Returns:
        {
          "auto_mask":   [pii_type, ...],   # masked by default
          "optional":    [pii_type, ...],   # user decides
          "description": str
        }
    """
    PRESETS = {
        "aadhaar_card": {
            "auto_mask":   ["aadhaar", "dob", "address", "phone"],
            "optional":    ["name", "gender"],
            "description": "Aadhaar card: mask UID, DOB, address, and contact details by default."
        },
        "pan_card": {
            "auto_mask":   ["pan", "dob"],
            "optional":    ["name", "father_name"],
            "description": "PAN card: mask PAN number and DOB by default."
        },
        "id_card": {
            "auto_mask":   ["id_number", "dob", "address"],
            "optional":    ["name", "phone"],
            "description": "Government ID: mask ID number, DOB, and address by default."
        },
        "bank_statement": {
            "auto_mask":   ["account_number", "ifsc", "balance", "transaction_id"],
            "optional":    ["name", "address", "phone"],
            "description": "Bank statement: mask account details and transactions by default."
        },
        "resume": {
            "auto_mask":   ["phone", "email", "address"],
            "optional":    ["name", "linkedin", "github", "dob"],
            "description": "Resume: mask contact details by default; name is optional."
        },
        "invoice": {
            "auto_mask":   ["gstin", "account_number", "pan"],
            "optional":    ["phone", "email", "address"],
            "description": "Invoice: mask GSTIN, PAN, and bank details by default."
        },
        "medical_record": {
            "auto_mask":   ["name", "dob", "phone", "address", "diagnosis"],
            "optional":    ["email"],
            "description": "Medical record: mask all patient-identifying data by default."
        },
        "unknown": {
            "auto_mask":   ["aadhaar", "pan", "phone", "email", "account_number"],
            "optional":    ["name", "address", "dob"],
            "description": "Unknown document type: mask common PII by default."
        },
    }
    return PRESETS.get(document_type, PRESETS["unknown"])
