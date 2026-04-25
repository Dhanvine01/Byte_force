"""
Team 1 — Step 3: Risk Analysis & Smart Masking Engine
Computes overall document risk grade and decides suggested_mask per detection.
"""

from typing import List, Dict, Any
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Risk weight per PII type
# ---------------------------------------------------------------------------
RISK_WEIGHTS: Dict[str, int] = {
    "aadhaar":          100,
    "pan":               90,
    "passport":          95,
    "credit_card":      100,
    "account_number":    85,
    "ifsc":              60,
    "gstin":             55,
    "voter_id":          75,
    "driving_license":   70,
    "phone":             50,
    "email":             40,
    "upi_id":            45,
    "dob":               35,
    "vehicle_reg":       30,
    "pincode":           10,
    "ipv4":              15,
    "signature":         80,
    "credit_card_masked": 50,
    "address":           65,
    "address_vtc":       60,
    "address_district":  60,
    "address_state":     50,
    "address_po":        60,
    "address_locality":  55,
    "custom":            70,
}

RISK_THRESHOLDS = {
    "low":    (0,   30),
    "medium": (31,  70),
    "high":   (71, 150),
    # "critical" if score > 150
}


# ---------------------------------------------------------------------------
# Human-friendly warning messages
# ---------------------------------------------------------------------------
FRIENDLY_WARNINGS: Dict[str, str] = {
    "aadhaar":
        "⚠️ This document contains your Aadhaar number. "
        "Sharing it could allow identity theft or fraud.",
    "pan":
        "⚠️ This document contains your PAN number. "
        "Misuse could lead to tax fraud in your name.",
    "passport":
        "🔴 Passport numbers are sensitive travel documents. "
        "Exposure could enable identity fraud.",
    "credit_card":
        "🔴 Credit/Debit card numbers are present. "
        "Sharing this could lead to financial fraud immediately.",
    "account_number":
        "🔴 Bank account details found. "
        "This information could be misused for unauthorized transactions.",
    "ifsc":
        "⚠️ Bank IFSC code found. Combined with account number, "
        "this enables bank transfers.",
    "gstin":
        "⚠️ GSTIN found. This identifies your business tax registration.",
    "phone":
        "📞 Phone number detected. Could be used for spam or social engineering.",
    "email":
        "📧 Email address found. Exposure may lead to phishing attempts.",
    "signature":
        "✍️ A handwritten signature was detected. "
        "This could be misused to forge documents.",
    "dob":
        "📅 Date of birth detected. Often used as a security verification answer.",
    "upi_id":
        "💸 UPI ID found. Could enable unsolicited payment requests.",
    "voter_id":
        "🪪 Voter ID found. A sensitive government identity document.",
    "driving_license":
        "🪪 Driving License number found. Could be used for identity fraud.",
    "pincode":
        "📍 PIN code found (low risk on its own, but reveals location).",
    "vehicle_reg":
        "🚗 Vehicle registration number found.",
    "ipv4":
        "🌐 IP address found (usually low risk).",
    "credit_card_masked":
        "💳 Partial card number found.",
}


# ---------------------------------------------------------------------------
# Data Contract builder
# ---------------------------------------------------------------------------

def compute_risk_score(pii_matches: List[Any]) -> Dict[str, Any]:
    """
    Given a list of PIIMatch / signature dicts, compute:
      - total risk score
      - overall_risk label (low / medium / high / critical)
      - per-type contribution
    """
    type_scores: Dict[str, int] = {}
    for m in pii_matches:
        pii_type = getattr(m, "pii_type", None) or m.get("type", "unknown")
        weight   = RISK_WEIGHTS.get(pii_type, 20)
        type_scores[pii_type] = type_scores.get(pii_type, 0) + weight

    total = sum(type_scores.values())

    if total == 0:
        grade = "low"
    elif total <= RISK_THRESHOLDS["low"][1]:
        grade = "low"
    elif total <= RISK_THRESHOLDS["medium"][1]:
        grade = "medium"
    elif total <= RISK_THRESHOLDS["high"][1]:
        grade = "high"
    else:
        grade = "critical"

    return {
        "total_score":   total,
        "overall_risk":  grade,
        "type_breakdown": type_scores,
    }


def build_warning_messages(pii_matches: List[Any]) -> List[str]:
    """Return deduplicated human-friendly warning strings."""
    seen = set()
    warnings = []
    for m in pii_matches:
        pii_type = getattr(m, "pii_type", None) or m.get("type", "unknown")
        if pii_type not in seen and pii_type in FRIENDLY_WARNINGS:
            warnings.append(FRIENDLY_WARNINGS[pii_type])
            seen.add(pii_type)
    return warnings


def decide_suggested_mask(
    pii_type: str,
    document_type: str,
    masking_preset: Dict[str, Any],
    privacy_level: str = "medium"
) -> bool:
    """
    Decide whether a given PII field should be masked by default.

    Args:
        pii_type:        detected PII type string
        document_type:   classified document type
        masking_preset:  output of classifier.get_masking_preset()
        privacy_level:   "basic" | "medium" | "strict"

    Returns:
        True if the field should be masked by default.
    """
    auto_mask = masking_preset.get("auto_mask", [])
    optional  = masking_preset.get("optional", [])

    if privacy_level == "strict":
        # Mask everything
        return True

    if privacy_level == "basic":
        # Only mask critical types
        critical_types = {"aadhaar", "pan", "passport", "credit_card",
                          "account_number", "signature"}
        return pii_type in critical_types

    # Default: medium
    # Treat address subtypes (address_vtc, address_district, etc.) as "address"
    check_type = pii_type
    if pii_type.startswith("address_"):
        check_type = "address"
    return check_type in auto_mask


# ---------------------------------------------------------------------------
# Privacy Level Presets (for Team 2's UI toggles)
# ---------------------------------------------------------------------------
PRIVACY_LEVEL_DESCRIPTIONS = {
    "basic": {
        "label":       "Basic",
        "description": "Masks the most critical information only: "
                       "Aadhaar, PAN, bank account numbers, and signatures.",
        "color":       "#F59E0B",   # amber
    },
    "medium": {
        "label":       "Medium",
        "description": "Masks financial and identity information based on "
                       "the detected document type.",
        "color":       "#EF4444",   # red
    },
    "strict": {
        "label":       "Strict",
        "description": "Masks all detected personal information. "
                       "Maximum privacy — recommended before public sharing.",
        "color":       "#7C3AED",   # violet
    },
}
