"""
Team 1 — Step 2c: Signature Protection (Computer Vision)
Detects handwritten signature regions using contour analysis and
heuristics (aspect ratio, ink density, connected-component count).
"""

import cv2
import numpy as np
from typing import List, Dict, Any, Optional
from PIL import Image


# ---------------------------------------------------------------------------
# Tunable thresholds
# ---------------------------------------------------------------------------
MIN_CONTOUR_AREA   = 2000          # Minimum pixel area to consider
MAX_CONTOUR_AREA   = 80_000      # Too large = printed text block, not sig
MIN_ASPECT_RATIO   = 2.5          # Width / Height – sigs are wide
MAX_ASPECT_RATIO   = 12.0
MIN_FILL_RATIO     = 0.03         # % of bbox filled with dark pixels
MAX_FILL_RATIO     = 0.40         # High fill → printed text block
MIN_CC_COUNT       = 4            # Connected components in ROI (cursive loops)
SIG_CONFIDENCE_THRESHOLD = 0.72   # Minimum score to label as signature


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect_signatures(
    pil_img: Image.Image,
    page_num: int = 1,
    dpi: int = 150
) -> List[Dict[str, Any]]:
    """
    Detect probable handwritten signature regions in a PIL image.

    Returns:
        [
          {
            "type":        "signature",
            "label":       "Handwritten Signature",
            "coordinates": { "x": int, "y": int, "w": int, "h": int },
            "confidence":  float,
            "risk_level":  "critical",
            "page":        int
          },
          ...
        ]
    """
    cv_img = _pil_to_cv2(pil_img)
    gray   = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY)
    binary = _binarize(gray)

    candidates = _extract_candidates(binary)
    detections = []

    for (x, y, w, h, contour) in candidates:
        roi_binary = binary[y:y+h, x:x+w]
        score = _score_candidate(roi_binary, w, h)

        if score >= SIG_CONFIDENCE_THRESHOLD:
            detections.append({
                "type":        "signature",
                "label":       "Handwritten Signature",
                "coordinates": {"x": int(x), "y": int(y), "w": int(w), "h": int(h)},
                "confidence":  round(score, 3),
                "risk_level":  "critical",
                "page":        page_num,
            })

    # Merge overlapping boxes (handles cursive loops split across contours)
    detections = _merge_overlapping(detections)
    return detections


def detect_signatures_all_pages(pages_pil: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Run signature detection across all rasterised pages.

    Args:
        pages_pil: list of { "page": int, "pil_image": PIL.Image }
    """
    results = []
    for entry in pages_pil:
        sigs = detect_signatures(entry["pil_image"], page_num=entry["page"])
        results.extend(sigs)
    return results


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _pil_to_cv2(pil_img: Image.Image) -> np.ndarray:
    return cv2.cvtColor(np.array(pil_img.convert("RGB")), cv2.COLOR_RGB2BGR)


def _binarize(gray: np.ndarray) -> np.ndarray:
    """Otsu threshold after Gaussian blur to reduce noise."""
    blurred = cv2.GaussianBlur(gray, (5, 5), 0)
    _, binary = cv2.threshold(blurred, 0, 255,
                               cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU)
    return binary


def _extract_candidates(binary: np.ndarray):
    """
    Find contours, dilate horizontally (to join cursive strokes),
    and return bounding boxes for candidate regions.
    """
    # Dilate to connect nearby strokes
    kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (20, 3))
    dilated = cv2.dilate(binary, kernel, iterations=2)

    contours, _ = cv2.findContours(
        dilated, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE
    )
    candidates = []
    for c in contours:
        x, y, w, h = cv2.boundingRect(c)
        area = w * h
        if MIN_CONTOUR_AREA <= area <= MAX_CONTOUR_AREA:
            candidates.append((x, y, w, h, c))
    return candidates


def _score_candidate(roi_binary: np.ndarray, w: int, h: int) -> float:
    """
    Compute a 0-1 score reflecting likelihood of being a signature.
    Combines aspect ratio, ink density, and connected-component count.
    """
    scores = []

    # 1. Aspect ratio score
    ar = w / h if h > 0 else 0
    if MIN_ASPECT_RATIO <= ar <= MAX_ASPECT_RATIO:
        ar_score = 1.0 - abs(ar - 5.0) / 10.0   # Peak score around AR=5
        scores.append(max(0.0, ar_score))
    else:
        scores.append(0.0)

    # 2. Fill ratio score (ink density)
    fill = np.count_nonzero(roi_binary) / (roi_binary.size or 1)
    if MIN_FILL_RATIO <= fill <= MAX_FILL_RATIO:
        # Ideal signatures have ~5-20% fill
        fill_score = 1.0 - abs(fill - 0.12) / 0.12
        scores.append(max(0.0, min(1.0, fill_score)))
    else:
        scores.append(0.0)

    # 3. Connected-component count (cursive = many loops)
    try:
        num_labels, _ = cv2.connectedComponents(roi_binary)
        cc_count = num_labels - 1   # subtract background
        cc_score = min(cc_count / 15.0, 1.0) if cc_count >= MIN_CC_COUNT else 0.0
        scores.append(cc_score)
    except Exception:
        scores.append(0.3)          # Neutral fallback

    # 4. Width heuristic: signatures span at least ~15% of page width
    # (relative scoring – treat roi width as fraction of total)
    width_score = min(w / 300, 1.0)   # 300 px baseline
    scores.append(width_score * 0.5)  # lower weight

    return sum(scores) / len(scores) if scores else 0.0


def _merge_overlapping(detections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Merge bounding boxes that overlap significantly (IoU > 0.3)."""
    if len(detections) <= 1:
        return detections

    boxes = [d["coordinates"] for d in detections]
    merged_flags = [False] * len(boxes)
    result = []

    for i in range(len(boxes)):
        if merged_flags[i]:
            continue
        bx = boxes[i].copy()
        best_conf = detections[i]["confidence"]

        for j in range(i + 1, len(boxes)):
            if merged_flags[j]:
                continue
            if _iou(bx, boxes[j]) > 0.3:
                # Merge j into i
                x1 = min(bx["x"], boxes[j]["x"])
                y1 = min(bx["y"], boxes[j]["y"])
                x2 = max(bx["x"] + bx["w"], boxes[j]["x"] + boxes[j]["w"])
                y2 = max(bx["y"] + bx["h"], boxes[j]["y"] + boxes[j]["h"])
                bx = {"x": x1, "y": y1, "w": x2 - x1, "h": y2 - y1}
                best_conf = max(best_conf, detections[j]["confidence"])
                merged_flags[j] = True

        result.append({
            **detections[i],
            "coordinates": bx,
            "confidence":  round(best_conf, 3),
        })

    return result


def _iou(a: Dict, b: Dict) -> float:
    """Intersection over Union for two bbox dicts."""
    ax1, ay1 = a["x"], a["y"]
    ax2, ay2 = a["x"] + a["w"], a["y"] + a["h"]
    bx1, by1 = b["x"], b["y"]
    bx2, by2 = b["x"] + b["w"], b["y"] + b["h"]

    inter_w = max(0, min(ax2, bx2) - max(ax1, bx1))
    inter_h = max(0, min(ay2, by2) - max(ay1, by1))
    inter   = inter_w * inter_h
    union   = (ax2-ax1)*(ay2-ay1) + (bx2-bx1)*(by2-by1) - inter
    return inter / union if union else 0.0

