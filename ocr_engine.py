"""
Team 1 — Step 1: Ingestion & OCR Layer
Handles PDF / Image ingestion, multi-language OCR, and bounding-box extraction.
Supports: English, Hindi, Kannada (tesseract lang codes: eng, hin, kan)
"""

import io
import os
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from PIL import Image
import pytesseract
import pdfplumber
import cv2
import numpy as np

logger = logging.getLogger(__name__)

SUPPORTED_IMAGE_TYPES = {".jpg", ".jpeg", ".png", ".bmp", ".tiff", ".webp"}
SUPPORTED_DOC_TYPES   = {".pdf"} | SUPPORTED_IMAGE_TYPES
OCR_LANGUAGES = "eng+hin+kan"


def _pil_to_cv2(pil_img: Image.Image) -> np.ndarray:
    return cv2.cvtColor(np.array(pil_img.convert("RGB")), cv2.COLOR_RGB2BGR)


def _preprocess_for_ocr(pil_img: Image.Image) -> Image.Image:
    img_cv = _pil_to_cv2(pil_img)
    h, w = img_cv.shape[:2]

    # Upscale small images — higher resolution = better OCR
    if w < 2400:
        scale = 2400 / w
        img_cv = cv2.resize(img_cv, None, fx=scale, fy=scale,
                             interpolation=cv2.INTER_CUBIC)

    gray = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY)

    # Light denoising (preserve text detail)
    gray = cv2.fastNlMeansDenoising(gray, h=5)

    # Note: deskew removed — it rotates the image, causing OCR bounding
    # boxes to be offset from the original image when mapping back.
    # EasyOCR handles slight skew internally.

    # CLAHE contrast enhancement — works much better than binary thresholding
    # for multi-script documents (Kannada, Hindi, Tamil, Telugu)
    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
    gray = clahe.apply(gray)

    return Image.fromarray(gray)


def _deskew(gray: np.ndarray) -> np.ndarray:
    try:
        coords = np.column_stack(np.where(gray < 128))
        if len(coords) < 100:
            return gray
        angle = cv2.minAreaRect(coords)[-1]
        if angle < -45:
            angle = 90 + angle
        if abs(angle) < 0.5:
            return gray
        h, w = gray.shape
        M = cv2.getRotationMatrix2D((w // 2, h // 2), angle, 1.0)
        return cv2.warpAffine(gray, M, (w, h),
                              flags=cv2.INTER_CUBIC,
                              borderMode=cv2.BORDER_REPLICATE)
    except Exception:
        return gray


# ── EasyOCR setup (lazy-loaded) ──────────────────────────────────────────────
_easyocr_reader = None

def _get_easyocr_reader():
    global _easyocr_reader
    if _easyocr_reader is None:
        try:
            import sys, io
            # Fix Windows console encoding for EasyOCR's progress bars
            if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
                try:
                    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
                    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
                except Exception:
                    pass

            import easyocr
            _easyocr_reader = easyocr.Reader(
                ['en', 'kn'],  # English + Kannada
                gpu=False,
                verbose=False,
            )
            logger.info("[OCR] EasyOCR reader initialized (en+hi+kn)")
        except Exception as e:
            logger.warning(f"[OCR] EasyOCR init failed: {e}")
            _easyocr_reader = False  # Mark as unavailable
    return _easyocr_reader if _easyocr_reader is not False else None


def _ocr_image(pil_img: Image.Image, lang: str = OCR_LANGUAGES,
               preprocess: bool = True) -> Dict[str, Any]:
    if preprocess:
        proc_img = _preprocess_for_ocr(pil_img)
    else:
        proc_img = pil_img

    proc_w, proc_h = proc_img.size

    # Try EasyOCR first (much better for Indian languages)
    reader = _get_easyocr_reader()
    if reader is not None:
        return _ocr_with_easyocr(reader, proc_img, proc_w, proc_h)

    # Fallback to Tesseract
    return _ocr_with_tesseract(proc_img, lang, proc_w, proc_h)


def _ocr_with_easyocr(reader, proc_img, proc_w, proc_h):
    """OCR using EasyOCR — deep learning based, much more accurate."""
    import numpy as np
    img_array = np.array(proc_img)

    results = reader.readtext(img_array, detail=1, paragraph=False)

    # Build word list with char offsets (same format as Tesseract path)
    words = []
    text_parts = []
    char_offset = 0

    for (bbox_pts, text, conf) in results:
        text = text.strip()
        if not text or conf < 0.15:
            continue

        # EasyOCR bbox is [[x1,y1],[x2,y2],[x3,y3],[x4,y4]]
        xs = [int(p[0]) for p in bbox_pts]
        ys = [int(p[1]) for p in bbox_pts]
        x = min(xs)
        y = min(ys)
        w = max(xs) - x
        h = max(ys) - y

        # Split multi-word results into individual words
        split_words = [sw for sw in text.split() if sw.strip()]
        total_chars = sum(len(sw) for sw in split_words)

        for word_idx, word in enumerate(split_words):
            word = word.strip()
            if not word:
                continue

            if char_offset > 0:
                text_parts.append(" ")
                char_offset += 1

            word_start = char_offset
            text_parts.append(word)
            char_offset += len(word)

            # Proportionally split the phrase bbox for each word
            if total_chars > 0 and len(split_words) > 1:
                chars_before = sum(len(split_words[k]) for k in range(word_idx))
                word_x = x + int(w * chars_before / total_chars)
                word_w = max(1, int(w * len(word) / total_chars))
            else:
                word_x = x
                word_w = w

            words.append({
                "text": word,
                "conf": round(float(conf) * 100, 2),
                "x": word_x,
                "y": y,
                "w": word_w,
                "h": h,
                "char_start": word_start,
                "char_end": char_offset,
            })

    full_text = "".join(text_parts)
    logger.info(f"[OCR] EasyOCR: {len(words)} words, {len(full_text)} chars")

    return {
        "full_text": full_text,
        "words": words,
        "proc_width": proc_w,
        "proc_height": proc_h,
    }


def _ocr_with_tesseract(proc_img, lang, proc_w, proc_h):
    """Fallback OCR using Tesseract."""
    custom_config = r"--oem 3 --psm 3"

    try:
        data = pytesseract.image_to_data(
            proc_img, lang=lang, config=custom_config,
            output_type=pytesseract.Output.DICT
        )
    except pytesseract.TesseractError:
        data = pytesseract.image_to_data(
            proc_img, lang="eng", config=custom_config,
            output_type=pytesseract.Output.DICT
        )

    words = []
    text_parts = []
    char_offset = 0
    prev_block = -1
    prev_line = -1
    n = len(data["text"])

    for i in range(n):
        word = data["text"][i].strip()
        if not word:
            continue
        conf = float(data["conf"][i])
        if conf < 20:
            continue

        block = int(data["block_num"][i])
        line = int(data["line_num"][i])

        if prev_block >= 0:
            if block != prev_block or line != prev_line:
                text_parts.append(" ")
                char_offset += 1
            else:
                text_parts.append(" ")
                char_offset += 1

        word_start = char_offset
        text_parts.append(word)
        char_offset += len(word)

        words.append({
            "text": word,
            "conf": round(conf, 2),
            "x":    int(data["left"][i]),
            "y":    int(data["top"][i]),
            "w":    int(data["width"][i]),
            "h":    int(data["height"][i]),
            "char_start": word_start,
            "char_end":   char_offset,
        })

        prev_block = block
        prev_line = line

    full_text = "".join(text_parts)

    return {
        "full_text": full_text,
        "words": words,
        "proc_width": proc_w,
        "proc_height": proc_h,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def ingest_file(file_path: str) -> List[Dict[str, Any]]:
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    ext = path.suffix.lower()
    if ext not in SUPPORTED_DOC_TYPES:
        raise ValueError(f"Unsupported file type: {ext}")
    if ext == ".pdf":
        return _ingest_pdf(str(path))
    else:
        return _ingest_image(str(path))


def ingest_bytes(data: bytes, filename: str) -> List[Dict[str, Any]]:
    ext = Path(filename).suffix.lower()
    if ext not in SUPPORTED_DOC_TYPES:
        raise ValueError(f"Unsupported file type: {ext}")
    if ext == ".pdf":
        return _ingest_pdf_bytes(data)
    else:
        img = Image.open(io.BytesIO(data))
        return [_page_result(img, page_num=1)]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _page_result(pil_img: Image.Image, page_num: int) -> Dict[str, Any]:
    ocr = _ocr_image(pil_img)
    # Report preprocessed dimensions — bounding boxes from Tesseract
    # are in this coordinate space, so the viewer can scale correctly.
    return {
        "page":      page_num,
        "width":     ocr["proc_width"],
        "height":    ocr["proc_height"],
        "full_text": ocr["full_text"],
        "words":     ocr["words"],
        "pil_image": pil_img,
    }


def _ingest_image(file_path: str) -> List[Dict[str, Any]]:
    img = Image.open(file_path)
    return [_page_result(img, page_num=1)]


def _ingest_pdf(file_path: str) -> List[Dict[str, Any]]:
    results = []
    with pdfplumber.open(file_path) as pdf:
        for page_num, page in enumerate(pdf.pages, start=1):
            text = page.extract_text() or ""
            words_native = _pdfplumber_words(page)
            if words_native:
                results.append({
                    "page":      page_num,
                    "width":     int(page.width),
                    "height":    int(page.height),
                    "full_text": text.strip(),
                    "words":     words_native,
                })
            else:
                logger.info(f"Page {page_num}: no native text, using OCR")
                pil_img = _pdf_page_to_image(page)
                results.append(_page_result(pil_img, page_num))
    return results


def _ingest_pdf_bytes(data: bytes) -> List[Dict[str, Any]]:
    results = []
    with pdfplumber.open(io.BytesIO(data)) as pdf:
        for page_num, page in enumerate(pdf.pages, start=1):
            words_native = _pdfplumber_words(page)
            text = page.extract_text() or ""
            if words_native:
                results.append({
                    "page":      page_num,
                    "width":     int(page.width),
                    "height":    int(page.height),
                    "full_text": text.strip(),
                    "words":     words_native,
                })
            else:
                pil_img = _pdf_page_to_image(page)
                results.append(_page_result(pil_img, page_num))
    return results


def _pdfplumber_words(page) -> List[Dict[str, Any]]:
    raw = page.extract_words(
        x_tolerance=3, y_tolerance=3,
        keep_blank_chars=False, use_text_flow=True
    ) or []
    words = []
    for w in raw:
        words.append({
            "text": w["text"],
            "conf": 99.0,
            "x":    int(w["x0"]),
            "y":    int(w["top"]),
            "w":    int(w["x1"] - w["x0"]),
            "h":    int(w["bottom"] - w["top"]),
        })
    return words


def _pdf_page_to_image(page, dpi: int = 200) -> Image.Image:
    page_image = page.to_image(resolution=dpi)
    return page_image.original
