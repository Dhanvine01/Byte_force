from __future__ import annotations
import re, logging
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Set
logger = logging.getLogger(__name__)

@dataclass
class PIIMatch:
    pii_type: str; label: str; text: str; page: int
    confidence: float; risk_level: str
    coordinates: Optional[Dict[str, int]] = None

def _r(p): return re.compile(p, re.IGNORECASE | re.MULTILINE)

PII_PATTERNS = [
    ("name","Full Name","high",0.85,[
        # Label-based: "Name:", "Name -", "Name /", or just "Name " followed by caps
        _r(r"(?:name|full\s*name)\s*[:\-/]?\s*([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+){1,4})"),
        # Father/Mother/Husband name
        _r(r"(?:father'?s?\s*name|mother'?s?\s*name|husband'?s?\s*name)\s*[:\-/]?\s*([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+){0,3})"),
        _r(r"\b(?:s/o|d/o|w/o|c/o)\s+([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+){0,3})"),
        # Standalone ALL-CAPS names (2-4 words, common on Indian ID cards)
        _r(r"(?:^|\n)\s*([A-Z][A-Z]+(?:\s+[A-Z][A-Z]+){1,3})\s*(?:$|\n)"),
    ]),
    ("gender","Gender","medium",0.90,[
        _r(r"(?:gender|sex)\s*[:/]?\s*(male|female|transgender|other)\b"),
        _r(r"\b(male|female)\s*/\s*(male|female)\b"),
    ]),
    ("aadhaar","Aadhaar Number","critical",0.97,[
        _r(r"(?<!\d)([2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4})(?![\s\-]?\d)"),
    ]),
    ("aadhaar_vid","Aadhaar Virtual ID (VID)","critical",0.97,[
        _r(r"\bVID\s*[:\-]?\s*(\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4})\b"),
        _r(r"\b\d{4}\s\d{4}\s\d{4}\s\d{4}\b"),
    ]),
    ("pan","PAN Number","critical",0.98,[
        _r(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
        # Handle OCR reading PAN with spaces
        _r(r"\b([A-Z]{5}\s?[0-9]{4}\s?[A-Z])\b"),
    ]),
    ("passport","Passport Number","critical",0.95,[
        _r(r"\b[A-PR-WY][1-9]\d\s?\d{4}[1-9]\b"),
        _r(r"\bpassport\s*(?:no|number|#)[\s:\-]*([A-Z]\d{7})\b"),
    ]),
    ("voter_id","Voter ID","high",0.93,[
        _r(r"\b[A-Z]{3}[0-9]{7}\b"),
        _r(r"\bepic\s*(?:no|number|#)[\s:\-]*([A-Z]{3}[0-9]{7})\b"),
    ]),
    ("driving_license","Driving License Number","high",0.90,[
        _r(r"\b[A-Z]{2}[\-\s]?\d{2}[\-\s]?\d{4}[\-\s]?\d{7}\b"),
        _r(r"\bDL\s*(?:no|number|#)[\s:\-]*([A-Z0-9\-]+)\b"),
    ]),
    ("vehicle_reg","Vehicle Registration Number","medium",0.88,[
        _r(r"\b[A-Z]{2}[\s\-]?\d{2}[\s\-]?[A-Z]{1,3}[\s\-]?\d{4}\b"),
    ]),
    ("gstin","GSTIN","high",0.96,[_r(r"\b\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b")]),
    ("ifsc","IFSC Code","high",0.97,[_r(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")]),
    ("account_number","Bank Account Number","critical",0.88,[
        _r(r"(?:account\s*(?:no|number|#|num)[\s:\-]*)([\d\s]{9,18})"),
        _r(r"(?:a/c\s*(?:no|number|#)?[\s:\-]*)([\d\s]{9,18})"),
    ]),
    ("credit_card","Credit/Debit Card Number","critical",0.97,[
        _r(r"\b(?:4\d{3}|5[1-5]\d{2}|6011|3[47]\d{2})[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}\b"),
    ]),
    ("credit_card_masked","Partial Card Number","high",0.85,[
        _r(r"\b[X\*]{4}[\s\-]?[X\*]{4}[\s\-]?[X\*]{4}[\s\-]?\d{4}\b"),
    ]),
    ("upi_id","UPI ID","medium",0.95,[
        _r(r"\b[\w.\-]+@(?:okaxis|okhdfcbank|okicici|oksbi|ybl|upi|paytm|ibl|axl|pingpay|apl|waicici|jupiteraxis|fbl|rbl|kotak|indus|aubank|airtel|jio|gpay|phonepe|bhim)\b"),
    ]),
    ("phone","Phone Number","high",0.90,[
        _r(r"(?<!\d)\+91[\s\-]?([6-9]\d{9})(?!\d)"),
        _r(r"(?<!\d)([6-9]\d{9})(?!\d)"),
    ]),
    ("email","Email Address","medium",0.97,[
        _r(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    ]),
    ("dob","Date of Birth","medium",0.90,[
        _r(r"(?:date\s*of\s*birth[^:]{0,10}:|dob\s*[:\-]|d\.o\.b\s*[:\-]|birth\s*date\s*[:\-])\s*(\d{1,2}[\s/\-\.]\d{1,2}[\s/\-\.]\d{2,4})"),
        _r(r"\b(\d{2}[/\-\.]\d{2}[/\-\.]\d{4})\b"),
    ]),
    ("pincode","PIN Code","low",0.80,[
        _r(r"(?:pin\s*(?:code)?|pincode|zip)[\s:\-]*(\d{6})\b"),
        _r(r"\b[1-9][0-9]{5}\b"),
    ]),
    # Address is detected by detect_address_blocks() using word positions
    # for tighter bounding boxes — no regex patterns needed here.

    ("ipv4","IP Address","low",0.95,[_r(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")]),
]

# Address marker words used by detect_address_blocks()
# These are ANCHOR labels that MUST appear to start an address block
# 'address' is safe here because we validate that collected words contain
# at least 1 real address content word (compound, nagar, district, etc.)
_ADDR_START = re.compile(
    r"^(c/o|s/o|d/o|w/o|address|addr|residence|to|house|flat|door|plot)$",
    re.IGNORECASE
)
# These are SPECIFIC content words that confirm we're inside an address block.
# Keep this list tight — generic words cause false positives on info text.
_ADDR_CONTENT = re.compile(
    r"(nagar|colony|road|street|lane|layout|compound|extension|enclave|vihar|"
    r"puram|bagh|chowk|marg|gali|wadi|sector|phase|dist|district|"
    r"taluk|mandal|tehsil|vtc|village|town|po|post|state|"
    r"karnataka|maharashtra|tamilnadu|kerala|andhra|telangana|rajasthan|"
    r"gujarat|bengaluru|bangalore|mumbai|chennai|hyderabad|mangalore|"
    r"pradesh|madhya|uttar|delhi|pune|jaipur|lucknow|kolkata|"
    r"hoshangabad|dewas|ashoka|school)",
    re.IGNORECASE
)
_ADDR_END = re.compile(
    r"^(mobile|phone|aadhaar|vid|enrollment|enrolment|email|"
    r"signature|document|download|information|note|your|"
    r"assembly|constituency|poll|serial|epic|kindly|"
    r"\d{4}\s?\d{4}\s?\d{4})$",
    re.IGNORECASE
)

def _clean_text(text):
    """Light cleanup — preserve character positions as much as possible."""
    return text.strip()

def _find_bbox_by_offset(words, match_start, match_end):
    """
    Find bounding box for a regex match at [match_start, match_end) in full_text.
    Uses char_start/char_end offsets stored in each word by the OCR engine.
    """
    matching_words = [
        w for w in words
        if w.get("char_end", 0) > match_start and w.get("char_start", 0) < match_end
    ]
    if not matching_words:
        return None
    return {
        "x": min(w["x"] for w in matching_words),
        "y": min(w["y"] for w in matching_words),
        "w": max(w["x"] + w["w"] for w in matching_words) - min(w["x"] for w in matching_words),
        "h": max(w["y"] + w["h"] for w in matching_words) - min(w["y"] for w in matching_words),
    }

def _deduplicate(matches):
    """Keep same text at different locations as separate detections."""
    seen = {}
    for m in matches:
        coord_key = ""
        if m.coordinates:
            coord_key = f"{m.coordinates.get('x',0)},{m.coordinates.get('y',0)}"
        key = f"{m.pii_type}::{re.sub(r'[ \\-]','',m.text.lower())}::{coord_key}"
        if key not in seen or m.confidence > seen[key].confidence:
            seen[key] = m
    return list(seen.values())

def detect_pii_in_page(page):
    page_num = page.get("page", 1)
    text     = _clean_text(page.get("full_text", ""))
    words    = page.get("words", [])
    matches  = []

    for (pii_type, label, risk_level, base_conf, patterns) in PII_PATTERNS:
        for pattern in patterns:
            for m in pattern.finditer(text):
                try:
                    detected = m.group(1).strip()
                    # Use the capture group's position
                    match_start = m.start(1)
                    match_end = m.end(1)
                except IndexError:
                    detected = m.group(0).strip()
                    match_start = m.start(0)
                    match_end = m.end(0)
                if not detected or len(detected) < 3:
                    continue
                # Use character offsets to find the exact words
                bbox = _find_bbox_by_offset(words, match_start, match_end)
                conf = base_conf if bbox else max(base_conf - 0.1, 0.5)
                matches.append(PIIMatch(
                    pii_type=pii_type, label=label, text=detected,
                    page=page_num, confidence=conf, risk_level=risk_level,
                    coordinates=bbox
                ))
    return _deduplicate(matches)

def detect_pii_all_pages(pages):
    all_matches = []
    for page in pages:
        pm = detect_pii_in_page(page)
        # Also detect address blocks from word positions
        pm.extend(detect_address_blocks(page))
        all_matches.extend(pm)
        logger.info(f"[PII] Page {page.get('page','?')}: {len(pm)} detections")
    logger.info(f"[PII] Total: {len(all_matches)}")
    return all_matches


def detect_address_blocks(page):
    """
    Detect address regions by scanning OCR words for an explicit address label
    anchor (Address:, C/O, S/O, To, etc.) and then collecting the VALUE words
    that follow it.  Only the value portion is masked — the label itself is
    excluded from the bounding box.  Returns ONE detection per address anchor
    with a tight bbox covering all value words.

    Fallback: if no anchor is found, cluster nearby address content words.
    """
    words = page.get("words", [])
    page_num = page.get("page", 1)
    if not words:
        return []

    results = []
    used_anchors: set = set()  # avoid duplicate detections from nearby anchors
    anchor_found = False

    # ── Scan for anchor labels ─────────────────────────────────────────
    for i, w in enumerate(words):
        txt = w["text"].strip().rstrip(":.,;")
        if not _ADDR_START.match(txt):
            continue

        # "To" anchor: only use if the NEXT word looks like a name or address
        # (avoid matching "to" in normal sentences)
        if txt.lower() == "to" and i + 1 < len(words):
            next_txt = words[i + 1]["text"].strip().rstrip(":.,;")
            # Skip if next word is a common non-address word
            if re.match(r"^(the|a|an|be|is|verify|use|download|this|that|your|know|help)$", next_txt, re.IGNORECASE):
                continue

        # Skip if this anchor overlaps with a previous detection range
        if i in used_anchors:
            continue

        anchor_found = True

        # Found an anchor — collect VALUE words that follow it
        # Skip the anchor label itself (start from i+1)
        value_words = []
        for j in range(i + 1, min(i + 30, len(words))):
            wt = words[j]["text"].strip().rstrip(":.,;")

            # Stop at end markers
            if _ADDR_END.match(wt):
                break

            # Stop if we hit another PII label (Name:, DOB:, Gender:, etc.)
            if re.match(r"^(name|dob|gender|sex|father|mother|husband|date|birth|pin\s*code|mobile|phone)$", wt, re.IGNORECASE):
                break

            # Skip if this word is itself an address anchor (avoid nesting)
            if _ADDR_START.match(wt):
                used_anchors.add(j)
                continue

            value_words.append(words[j])

            # Stop after a pincode (6-digit number)
            if re.match(r"^\d{6}$", wt):
                break

        if len(value_words) < 2:
            continue

        # Validation: the collected words must contain at least 1 address
        # content word (district, nagar, VTC, state name, etc.)
        # This prevents false positives like "address should be updated"
        content_count = sum(
            1 for vw in value_words
            if _ADDR_CONTENT.search(vw["text"].strip().rstrip(":.,;"))
        )
        if content_count < 1:
            continue

        bbox = _build_address_bbox(value_words)
        if not bbox:
            continue

        # Build text summary
        addr_text = " ".join(vw["text"] for vw in value_words)
        if len(addr_text) > 80:
            addr_text = addr_text[:77] + "..."

        results.append(PIIMatch(
            pii_type="address",
            label="Address",
            text=addr_text,
            page=page_num,
            confidence=0.82,
            risk_level="high",
            coordinates=bbox,
        ))

    # ── Also run content-word clustering to catch addresses without anchors ──
    # This runs even if anchor-based detections were found, to catch
    # additional address blocks (e.g. multiple cards in one image).
    # Skip clusters that overlap with already-detected address boxes.
    fallback = _detect_address_by_content(words, page_num)
    for fb in fallback:
        if not _overlaps_existing(fb, results):
            results.append(fb)

    return results

def _overlaps_existing(new_match, existing_matches):
    """Check if new_match's bbox overlaps significantly with any existing match."""
    nc = new_match.coordinates
    if not nc:
        return False
    for em in existing_matches:
        ec = em.coordinates
        if not ec:
            continue
        # Check Y overlap (same vertical region)
        ny1, ny2 = nc["y"], nc["y"] + nc["h"]
        ey1, ey2 = ec["y"], ec["y"] + ec["h"]
        overlap_y = max(0, min(ny2, ey2) - max(ny1, ey1))
        min_h = min(nc["h"], ec["h"]) or 1
        if overlap_y / min_h > 0.3:
            return True
    return False


def _build_address_bbox(value_words):
    """Build ONE tight bounding box for a list of address value words."""
    if not value_words:
        return None

    # Group value words by Y position (lines) to compute per-line widths
    lines: Dict[int, list] = {}
    for vw in value_words:
        y_key = vw["y"]
        placed = False
        for lk in lines:
            if abs(lk - y_key) < 8:
                lines[lk].append(vw)
                placed = True
                break
        if not placed:
            lines[y_key] = [vw]

    # Compute per-line x-ranges
    line_ranges = []
    for line_words in lines.values():
        if not line_words:
            continue
        lx = min(lw["x"] for lw in line_words)
        lx_end = max(lw["x"] + lw["w"] for lw in line_words)
        ly = min(lw["y"] for lw in line_words)
        ly_end = max(lw["y"] + lw["h"] for lw in line_words)
        line_ranges.append((lx, ly, lx_end, ly_end))

    if not line_ranges:
        return None

    first_x = line_ranges[0][0]
    max_line_w = max(r[2] - r[0] for r in line_ranges)
    top_y = min(r[1] for r in line_ranges)
    bot_y = max(r[3] for r in line_ranges)

    return {
        "x": first_x,
        "y": top_y,
        "w": max_line_w,
        "h": bot_y - top_y,
    }


def _detect_address_by_content(words, page_num):
    """
    Fallback: find clusters of address content words (nagar, road, district,
    state names, etc.) even when no explicit anchor is present.
    """
    results = []
    content_indices = []

    for i, w in enumerate(words):
        txt = w["text"].strip().rstrip(":.,;")
        if _ADDR_CONTENT.search(txt):
            content_indices.append(i)

    if len(content_indices) < 3:
        return results

    # Cluster nearby content words (within 8 word positions of each other)
    clusters = []
    current_cluster = [content_indices[0]]
    for k in range(1, len(content_indices)):
        if content_indices[k] - content_indices[k - 1] <= 8:
            current_cluster.append(content_indices[k])
        else:
            if len(current_cluster) >= 3:
                clusters.append(current_cluster)
            current_cluster = [content_indices[k]]
    if len(current_cluster) >= 3:
        clusters.append(current_cluster)

    for cluster in clusters:
        # Expand cluster to include words between content words
        start_idx = max(0, cluster[0] - 1)
        end_idx = min(len(words), cluster[-1] + 2)
        value_words = words[start_idx:end_idx]

        if len(value_words) < 3:
            continue

        bbox = _build_address_bbox(value_words)
        if not bbox:
            continue

        addr_text = " ".join(vw["text"] for vw in value_words)
        if len(addr_text) > 80:
            addr_text = addr_text[:77] + "..."

        results.append(PIIMatch(
            pii_type="address",
            label="Address",
            text=addr_text,
            page=page_num,
            confidence=0.72,
            risk_level="high",
            coordinates=bbox,
        ))

    return results

def detect_custom_keywords(pages, keywords):
    """
    Search for user-specified keywords/phrases in OCR output.
    Exact match only (case-insensitive).
    """
    if not keywords:
        return []

    all_matches = []
    for page in pages:
        page_num = page.get("page", 1)
        text = _clean_text(page.get("full_text", ""))
        words = page.get("words", [])

        for keyword in keywords:
            keyword = keyword.strip()
            if len(keyword) < 2:
                continue

            kw_lower = keyword.lower()
            search_text = text.lower()
            start = 0
            while True:
                idx = search_text.find(kw_lower, start)
                if idx == -1:
                    break
                start = idx + len(kw_lower)
                bbox = _find_bbox_by_offset(words, idx, idx + len(keyword))
                all_matches.append(PIIMatch(
                    pii_type="custom",
                    label=f"Custom: {keyword}",
                    text=keyword,
                    page=page_num,
                    confidence=1.0,
                    risk_level="high",
                    coordinates=bbox,
                ))

    return all_matches


if __name__ == "__main__":
    aadhaar_test = {
        "page": 1,
        "full_text": """
        Government of India
        Sutapa Pal Datta
        Date of Birth/DOB: 26/01/1979
        Female/ FEMALE
        6641 2804 9316
        VID : 9179 3343 7087 9130
        """,
        "words": []
    }
    results = detect_pii_in_page(aadhaar_test)
    print(f"\n{'='*65}")
    print(f"  Aadhaar Card — {len(results)} detections")
    print(f"{'='*65}")
    for r in results:
        print(f"  [{r.risk_level.upper():8}] {r.label:35} -> {r.text}")

