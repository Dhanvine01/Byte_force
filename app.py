"""
Privacy Gatekeeper — Desktop Application
Combines Team 1 (Intelligence Engine) + Team 2 (Security Interface)
into a single standalone PyQt6 desktop app.

Run: python app.py
"""

import sys
import os
import uuid
import json
import threading
from pathlib import Path
from typing import Optional, List, Dict, Any

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QFileDialog, QScrollArea, QFrame,
    QCheckBox, QProgressBar, QMessageBox, QLineEdit, QDialog,
    QDialogButtonBox, QComboBox, QSplitter, QSizePolicy, QGraphicsScene,
    QGraphicsView, QGraphicsRectItem, QGraphicsPixmapItem, QGraphicsTextItem
)
from PyQt6.QtGui import (
    QPixmap, QPainter, QColor, QPen, QBrush, QFont, QFontMetrics,
    QDragEnterEvent, QDropEvent, QPalette, QLinearGradient
)
from PyQt6.QtCore import (
    Qt, QThread, QObject, pyqtSignal, QRectF, QTimer, QSize, QPoint
)

# ── Import Team 1 pipeline ───────────────────────────────────────────────────
try:
    from pipeline import run_pipeline
    from schemas import PrivacyMap, Detection
    PIPELINE_AVAILABLE = True
except ImportError:
    PIPELINE_AVAILABLE = False
    print("WARNING: Team 1 pipeline not found. Running in demo mode.")

try:
    from pii_detector import detect_custom_keywords
    CUSTOM_KEYWORDS_AVAILABLE = True
except ImportError:
    CUSTOM_KEYWORDS_AVAILABLE = False


# ════════════════════════════════════════════════════════════════════════════
# THEME
# ════════════════════════════════════════════════════════════════════════════
COLORS = {
    "bg":           "#09090e",
    "surface":      "#0f0f14",
    "border":       "rgba(255,255,255,0.07)",
    "text":         "#f1f5f9",
    "text_dim":     "#64748b",
    "accent":       "#818cf8",
    "accent_bg":    "rgba(99,102,241,0.12)",
    "red":          "#ef4444",
    "amber":        "#f59e0b",
    "green":        "#22c55e",
    "purple":       "#7c3aed",
}

RISK_COLORS = {
    "low":      ("#22c55e", "#052e16"),
    "medium":   ("#f59e0b", "#1c1400"),
    "high":     ("#ef4444", "#1f0707"),
    "critical": ("#7c3aed", "#1a0a2e"),
}

STYLESHEET = """
QMainWindow, QWidget {
    background-color: #09090e;
    color: #f1f5f9;
    font-family: 'Segoe UI', 'SF Pro Display', sans-serif;
    font-size: 13px;
}
QScrollArea { border: none; background: transparent; }
QScrollBar:vertical {
    background: #0f0f14; width: 6px; border-radius: 3px;
}
QScrollBar::handle:vertical {
    background: rgba(255,255,255,0.15); border-radius: 3px;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QPushButton {
    background: rgba(255,255,255,0.05);
    border: 1px solid rgba(255,255,255,0.12);
    color: rgba(255,255,255,0.7);
    border-radius: 6px;
    padding: 7px 16px;
    font-size: 12px;
    font-weight: 600;
}
QPushButton:hover { background: rgba(255,255,255,0.1); color: #fff; }
QPushButton:disabled { opacity: 0.35; }
QLabel { color: #f1f5f9; }
QLineEdit {
    background: rgba(255,255,255,0.05);
    border: 1px solid rgba(255,255,255,0.12);
    border-radius: 6px;
    padding: 8px 12px;
    color: #f1f5f9;
    font-size: 13px;
}
QComboBox {
    background: rgba(255,255,255,0.05);
    border: 1px solid rgba(255,255,255,0.12);
    border-radius: 6px;
    padding: 6px 12px;
    color: #f1f5f9;
}
QComboBox::drop-down { border: none; }
QProgressBar {
    background: rgba(255,255,255,0.08);
    border: none;
    border-radius: 3px;
    height: 4px;
}
QProgressBar::chunk {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #818cf8,stop:1 #7c3aed);
    border-radius: 3px;
}
QSplitter::handle { background: rgba(255,255,255,0.05); width: 1px; }
QCheckBox { color: rgba(255,255,255,0.7); font-size: 12px; }
QCheckBox::indicator {
    width: 16px; height: 16px;
    border: 1px solid rgba(255,255,255,0.2);
    border-radius: 4px;
    background: rgba(255,255,255,0.04);
}
QCheckBox::indicator:checked {
    background: #818cf8;
    border-color: #818cf8;
}
"""


# ════════════════════════════════════════════════════════════════════════════
# WORKER THREAD — runs pipeline without freezing the UI
# ════════════════════════════════════════════════════════════════════════════
class AnalysisWorker(QObject):
    finished  = pyqtSignal(object)   # PrivacyMap or dict (demo)
    error     = pyqtSignal(str)
    progress  = pyqtSignal(str)

    def __init__(self, file_path: str, privacy_level: str, custom_keywords: list = None):
        super().__init__()
        self.file_path       = file_path
        self.privacy_level   = privacy_level
        self.custom_keywords = custom_keywords or []

    def run(self):
        try:
            self.progress.emit("Running OCR...")

            if PIPELINE_AVAILABLE:
                # Run OCR once, reuse pages for both pipeline and custom keywords
                from ocr_engine import ingest_file
                ocr_pages = ingest_file(self.file_path)

                self.progress.emit("Detecting PII...")
                self.progress.emit("Scoring risk...")
                result = run_pipeline(
                    privacy_level = self.privacy_level,
                    pages         = ocr_pages,
                )
                normalized = self._normalize(result)

                # Custom keyword detection using same OCR pages
                if self.custom_keywords and CUSTOM_KEYWORDS_AVAILABLE:
                    self.progress.emit("Searching custom keywords...")
                    pages_no_img = [
                        {k: v for k, v in p.items() if k != "pil_image"}
                        for p in ocr_pages
                    ]
                    custom_matches = detect_custom_keywords(pages_no_img, self.custom_keywords)
                    normalized["_custom_matches"] = [
                        {
                            "pii_type": cm.pii_type,
                            "label": cm.label,
                            "text": cm.text,
                            "page": cm.page,
                            "confidence": cm.confidence,
                            "risk_level": cm.risk_level,
                            "coordinates": cm.coordinates or {},
                        }
                        for cm in custom_matches
                    ]

                self.finished.emit(normalized)
            else:
                self.finished.emit(self._demo_result())

        except Exception as e:
            self.error.emit(str(e))

    def _normalize(self, result) -> dict:
        """
        Convert PrivacyMap Pydantic model (Team 1's schema) into a flat dict
        that app.py's UI layer understands uniformly.
        """
        if isinstance(result, dict):
            raw = result
        elif hasattr(result, "model_dump"):
            raw = result.model_dump()
        else:
            raw = result.__dict__

        # ── Detections ──────────────────────────────────────────────────
        detections = []
        for i, d in enumerate(raw.get("detections", [])):
            # d may be a dict or Pydantic model
            if hasattr(d, "model_dump"):
                d = d.model_dump()

            # Coordinates: may be nested dict or BoundingBox model
            coords = d.get("coordinates") or d.get("bbox") or {}
            if hasattr(coords, "model_dump"):
                coords = coords.model_dump()

            detections.append({
                "id":            d.get("id") or str(uuid.uuid4()),
                "type":          d.get("type", "unknown"),
                "label":         d.get("label", d.get("type", "Unknown")),
                "text":          d.get("text", ""),
                "page":          d.get("page", 1),
                "coordinates":   coords,
                "confidence":    float(d.get("confidence", 0.8)),
                "risk_level":    d.get("risk_level", "low"),
                "suggested_mask":bool(d.get("suggested_mask", False)),
            })

        # ── Risk: handle both flat and nested structures ─────────────────
        risk = raw.get("risk") or {}
        if hasattr(risk, "model_dump"):
            risk = risk.model_dump()
        overall_risk = (
            risk.get("overall_risk")
            or raw.get("overall_risk")
            or "low"
        )
        risk_score = (
            risk.get("total_score")
            or raw.get("risk_score")
            or 0
        )

        # ── Page info: handle PageMeta objects ───────────────────────────
        page_info = []
        for p in raw.get("pages", []):
            if hasattr(p, "model_dump"):
                p = p.model_dump()
            page_info.append(p)

        return {
            "document_type": raw.get("document_type", "unknown"),
            "overall_risk":  overall_risk,
            "risk_score":    risk_score,
            "warnings":      raw.get("warnings", []),
            "page_info":     page_info,
            "detections":    detections,
            "_ocr_pages":    raw.get("_ocr_pages", []),
        }

    def _demo_result(self) -> dict:
        return {
            "document_type":  "aadhaar_card",
            "doc_confidence": 0.92,
            "overall_risk":   "critical",
            "risk_score":     210,
            "risk_breakdown": {"aadhaar": 100, "phone": 50, "dob": 35, "email": 40},
            "warnings": [
                "⚠️ Aadhaar number found. Sharing this could enable identity theft.",
                "📞 Phone number detected. Could be used for spam or social engineering.",
            ],
            "masking_preset": {
                "auto_mask":   ["aadhaar", "dob", "address", "phone"],
                "optional":    ["name", "gender"],
                "description": "Demo: Aadhaar card masking preset active.",
            },
            "privacy_level": self.privacy_level,
            "pages": 1,
            "page_info": [{"page": 1, "width": 800, "height": 600}],
            "detections": [
                {"id": str(uuid.uuid4()), "type": "aadhaar",  "label": "Aadhaar Number",
                 "text": "1234 5678 9012", "page": 1, "coordinates": {"x": 80,  "y": 120, "w": 180, "h": 24},
                 "confidence": 0.95, "risk_level": "critical", "suggested_mask": True},
                {"id": str(uuid.uuid4()), "type": "phone",    "label": "Phone Number",
                 "text": "+91 9876543210", "page": 1, "coordinates": {"x": 80,  "y": 200, "w": 140, "h": 22},
                 "confidence": 0.85, "risk_level": "high",     "suggested_mask": True},
                {"id": str(uuid.uuid4()), "type": "dob",      "label": "Date of Birth",
                 "text": "15/08/1990",    "page": 1, "coordinates": {"x": 80,  "y": 280, "w": 100, "h": 22},
                 "confidence": 0.70, "risk_level": "medium",   "suggested_mask": True},
                {"id": str(uuid.uuid4()), "type": "email",    "label": "Email Address",
                 "text": "user@email.com","page": 1, "coordinates": {"x": 80,  "y": 360, "w": 160, "h": 22},
                 "confidence": 0.95, "risk_level": "high",     "suggested_mask": False},
            ],
        }


# ════════════════════════════════════════════════════════════════════════════
# DETECTION ROW WIDGET
# ════════════════════════════════════════════════════════════════════════════
class DetectionRow(QFrame):
    toggled = pyqtSignal(str, bool)

    LEVEL_COLORS = {
        "critical": "#7c3aed",
        "high":     "#ef4444",
        "medium":   "#f59e0b",
        "low":      "#22c55e",
    }

    def __init__(self, detection: dict, masked: bool = False, parent=None):
        super().__init__(parent)
        self.det_id  = detection["id"]
        self.masked  = masked
        self.det     = detection
        self._build(detection)
        self._refresh_style()

    def _build(self, det: dict):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(10)

        self.checkbox = QCheckBox()
        self.checkbox.setChecked(self.masked)
        self.checkbox.stateChanged.connect(self._on_toggle)
        layout.addWidget(self.checkbox)

        info = QVBoxLayout()
        info.setSpacing(2)

        name_row = QHBoxLayout()
        name_row.setSpacing(8)
        lbl_type = QLabel(det["label"])
        lbl_type.setStyleSheet("font-weight: 700; font-size: 12px; color: #f1f5f9;")
        name_row.addWidget(lbl_type)

        color = self.LEVEL_COLORS.get(det["risk_level"], "#64748b")
        lbl_level = QLabel(det["risk_level"].upper())
        lbl_level.setStyleSheet(
            f"font-size: 9px; font-weight: 700; letter-spacing: 1px; color: {color};"
            f"background: {color}22; border: 1px solid {color}44;"
            f"border-radius: 3px; padding: 1px 5px;"
        )
        name_row.addWidget(lbl_level)
        name_row.addStretch()
        info.addLayout(name_row)

        lbl_text = QLabel(det.get("text", ""))
        lbl_text.setStyleSheet("font-size: 11px; color: #64748b; font-family: 'Courier New', monospace;")
        info.addWidget(lbl_text)
        layout.addLayout(info, 1)

        conf = int(det.get("confidence", 0) * 100)
        lbl_conf = QLabel(f"{conf}%")
        conf_color = "#ef4444" if conf >= 90 else "#f59e0b" if conf >= 70 else "#22c55e"
        lbl_conf.setStyleSheet(f"font-size: 11px; font-weight: 700; color: {conf_color}; font-family: 'Courier New', monospace;")
        layout.addWidget(lbl_conf)

        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def _refresh_style(self):
        if self.masked:
            self.setStyleSheet(
                "DetectionRow { background: rgba(239,68,68,0.06); border: 1px solid rgba(239,68,68,0.2);"
                "border-radius: 8px; } DetectionRow:hover { background: rgba(239,68,68,0.1); }"
            )
        else:
            self.setStyleSheet(
                "DetectionRow { background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.06);"
                "border-radius: 8px; } DetectionRow:hover { background: rgba(255,255,255,0.05); }"
            )

    def _on_toggle(self, state):
        self.masked = bool(state)
        self._refresh_style()
        self.toggled.emit(self.det_id, self.masked)

    def set_masked(self, masked: bool):
        self.masked = masked
        self.checkbox.blockSignals(True)
        self.checkbox.setChecked(masked)
        self.checkbox.blockSignals(False)
        self._refresh_style()

    def mousePressEvent(self, event):
        self.checkbox.setChecked(not self.checkbox.isChecked())


# ════════════════════════════════════════════════════════════════════════════
# DOCUMENT VIEWER — shows image with overlay boxes
# ════════════════════════════════════════════════════════════════════════════
class DocumentViewer(QGraphicsView):
    detection_toggled = pyqtSignal(str)

    RISK_BOX_COLORS = {
        "critical": (QColor(124, 58, 237, 180),  QColor(124, 58, 237, 40)),
        "high":     (QColor(239, 68, 68, 200),   QColor(239, 68, 68, 40)),
        "medium":   (QColor(245, 158, 11, 180),  QColor(245, 158, 11, 30)),
        "low":      (QColor(34, 197, 94, 160),   QColor(34, 197, 94, 25)),
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self.scene = QGraphicsScene(self)
        self.setScene(self.scene)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setBackgroundBrush(QBrush(QColor("#0d0d0f")))
        self.setStyleSheet("border: none;")
        self._detection_items: Dict[str, QGraphicsRectItem] = {}
        self._detection_data: Dict[str, dict] = {}
        self._masked_ids: set = set()
        self._natural_w = 1
        self._natural_h = 1
        self._pixmap_item: Optional[QGraphicsPixmapItem] = None

    def load_image(self, path: str):
        self.scene.clear()
        self._detection_items.clear()
        self._detection_data.clear()
        pixmap = QPixmap(path)
        if pixmap.isNull():
            return
        self._natural_w = pixmap.width()
        self._natural_h = pixmap.height()
        self._pixmap_item = self.scene.addPixmap(pixmap)
        self.scene.setSceneRect(self._pixmap_item.boundingRect())
        self.fitInView(self._pixmap_item, Qt.AspectRatioMode.KeepAspectRatio)

    def load_placeholder(self, width: int = 800, height: int = 600):
        """Show placeholder when file is PDF (rendered separately)."""
        self.scene.clear()
        self._detection_items.clear()
        self._natural_w = width
        self._natural_h = height
        rect = self.scene.addRect(
            0, 0, width, height,
            QPen(QColor("#1e1e2e")),
            QBrush(QColor("#0d0d0f"))
        )
        txt = self.scene.addText("PDF — detections overlaid below", QFont("Courier New", 14))
        txt.setDefaultTextColor(QColor("#334155"))
        txt.setPos(width//2 - 180, height//2 - 20)
        self.scene.setSceneRect(0, 0, width, height)
        self.fitInView(self.scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)

    def set_detections(self, detections: List[dict], masked_ids: set,
                       ocr_width: int = 0, ocr_height: int = 0):
        """
        Place detection boxes on the scene.

        ocr_width / ocr_height: the page dimensions as seen by OCR (from page_info).
        If the scene (original image) is a different size, coordinates are scaled.
        """
        # Remove old boxes
        for item in self._detection_items.values():
            self.scene.removeItem(item)
        self._detection_items.clear()
        self._detection_data.clear()
        self._masked_ids = set(masked_ids)

        # ── SCALE FIX: map OCR coords → scene (original image) coords ────
        # Tesseract preprocesses images to ~1800px wide. OCR coords are in
        # that preprocessed space. We need to scale back to original image space.
        scene_w = self._natural_w  # original image pixel width
        scene_h = self._natural_h
        sx = (scene_w / ocr_width)  if ocr_width  > 0 and scene_w > 0 else 1.0
        sy = (scene_h / ocr_height) if ocr_height > 0 and scene_h > 0 else 1.0

        for det in detections:
            coords = det.get("coordinates") or {}
            x = coords.get("x", 0)
            y = coords.get("y", 0)
            w = coords.get("w", 0)
            h = coords.get("h", 0)
            if w <= 0 or h <= 0:
                continue
            # Apply coordinate scaling
            self._add_box(det, int(x * sx), int(y * sy),
                          max(1, int(w * sx)), max(1, int(h * sy)))

    def _add_box(self, det: dict, x, y, w, h):
        det_id     = det["id"]
        risk       = det.get("risk_level", "low")
        pen_color, fill_color = self.RISK_BOX_COLORS.get(risk, self.RISK_BOX_COLORS["low"])

        masked = det_id in self._masked_ids
        if masked:
            rect_item = self.scene.addRect(
                x, y, w, h,
                QPen(QColor("#000000"), 0),
                QBrush(QColor("#000000"))
            )
        else:
            rect_item = self.scene.addRect(
                x, y, w, h,
                QPen(pen_color, 2),
                QBrush(fill_color)
            )

        rect_item.setData(0, det_id)
        rect_item.setCursor(Qt.CursorShape.PointingHandCursor)
        rect_item.setToolTip(f"{det['label']} — click to toggle mask")
        self._detection_items[det_id] = rect_item
        self._detection_data[det_id]  = det

    def update_mask(self, det_id: str, masked: bool):
        item = self._detection_items.get(det_id)
        if not item:
            return
        det = self._detection_data[det_id]
        if masked:
            self._masked_ids.add(det_id)
            item.setBrush(QBrush(QColor("#000000")))
            item.setPen(QPen(QColor("#000000"), 0))
        else:
            self._masked_ids.discard(det_id)
            risk = det.get("risk_level", "low")
            pen_color, fill_color = self.RISK_BOX_COLORS.get(risk, self.RISK_BOX_COLORS["low"])
            item.setBrush(QBrush(fill_color))
            item.setPen(QPen(pen_color, 2))

    def mousePressEvent(self, event):
        item = self.itemAt(event.pos())
        if item and isinstance(item, QGraphicsRectItem):
            det_id = item.data(0)
            if det_id:
                self.detection_toggled.emit(det_id)
        super().mousePressEvent(event)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self.scene.sceneRect().isValid():
            self.fitInView(self.scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)


# ════════════════════════════════════════════════════════════════════════════
# UPLOAD ZONE
# ════════════════════════════════════════════════════════════════════════════
class UploadZone(QFrame):
    file_selected = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setMinimumHeight(200)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setStyleSheet("""
            UploadZone {
                border: 2px dashed rgba(129,140,248,0.3);
                border-radius: 16px;
                background: rgba(99,102,241,0.04);
            }
            UploadZone:hover {
                border-color: rgba(129,140,248,0.6);
                background: rgba(99,102,241,0.08);
            }
        """)
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(12)

        icon = QLabel("🛡️")
        icon.setStyleSheet("font-size: 48px;")
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(icon)

        title = QLabel("Drop your document here")
        title.setStyleSheet("font-size: 18px; font-weight: 800; color: #f8fafc;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        sub = QLabel("PDF or Image (JPG, PNG, BMP, TIFF) — max 20 MB")
        sub.setStyleSheet("font-size: 13px; color: #64748b;")
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(sub)

        btn = QPushButton("Browse File")
        btn.setFixedWidth(140)
        btn.setStyleSheet("""
            QPushButton {
                background: rgba(99,102,241,0.2);
                border: 1px solid rgba(99,102,241,0.4);
                color: #818cf8;
                border-radius: 8px;
                padding: 10px 24px;
                font-weight: 700;
            }
            QPushButton:hover {
                background: rgba(99,102,241,0.35);
            }
        """)
        btn.clicked.connect(self._browse)
        layout.addWidget(btn, alignment=Qt.AlignmentFlag.AlignCenter)

    def _browse(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Document", "",
            "Documents (*.pdf *.jpg *.jpeg *.png *.bmp *.tiff *.webp)"
        )
        if path:
            self.file_selected.emit(path)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        urls = event.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            if Path(path).suffix.lower() in {".pdf", ".jpg", ".jpeg", ".png", ".bmp", ".tiff", ".webp"}:
                self.file_selected.emit(path)

    def mousePressEvent(self, event):
        self._browse()


# ════════════════════════════════════════════════════════════════════════════
# PASSWORD DIALOG
# ════════════════════════════════════════════════════════════════════════════
class ExportDialog(QDialog):
    def __init__(self, masked_count: int, total_count: int, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Export Redacted Document")
        self.setFixedWidth(420)
        self.setStyleSheet(STYLESHEET + """
            QDialog { background: #0f0f14; border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; }
        """)
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(24, 24, 24, 24)

        layout.addWidget(QLabel(f"<b>{masked_count}/{total_count}</b> detections will be redacted."))

        self.use_password = QCheckBox("Password-protect the exported file")
        layout.addWidget(self.use_password)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter password...")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setEnabled(False)
        layout.addWidget(self.password_input)

        self.use_password.stateChanged.connect(
            lambda s: self.password_input.setEnabled(bool(s))
        )

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def get_password(self) -> Optional[str]:
        if self.use_password.isChecked():
            return self.password_input.text().strip() or None
        return None


# ════════════════════════════════════════════════════════════════════════════
# MAIN WINDOW
# ════════════════════════════════════════════════════════════════════════════
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Privacy Gatekeeper")
        self.setMinimumSize(1100, 700)
        self.resize(1280, 800)
        self.setStyleSheet(STYLESHEET)

        # State — multi-file support
        self._file_paths: List[str] = []
        self._privacy_maps: List[Optional[dict]] = []
        self._detection_states_list: List[Dict[str, bool]] = []
        self._current_idx: int = 0
        # Current file working variables (swapped on navigation)
        self._file_path: Optional[str]      = None
        self._privacy_map: Optional[dict]   = None
        self._detection_states: Dict[str, bool] = {}
        self._worker_thread: Optional[QThread] = None
        self._analysis_queue: List[int] = []

        self._build_ui()
        self._show_upload_screen()

    # ── UI Construction ──────────────────────────────────────────────────

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Header
        root.addWidget(self._build_header())

        # Content stack
        self._upload_screen = self._build_upload_screen()
        self._workspace     = self._build_workspace()
        self._workspace.hide()

        root.addWidget(self._upload_screen)
        root.addWidget(self._workspace)

    def _build_header(self) -> QWidget:
        header = QFrame()
        header.setFixedHeight(56)
        header.setStyleSheet("""
            QFrame {
                background: rgba(255,255,255,0.02);
                border-bottom: 1px solid rgba(255,255,255,0.07);
            }
        """)
        layout = QHBoxLayout(header)
        layout.setContentsMargins(24, 0, 24, 0)

        shield = QLabel("🛡️")
        shield.setStyleSheet("font-size: 20px;")
        layout.addWidget(shield)

        brand = QLabel("Privacy Gatekeeper")
        brand.setStyleSheet("font-size: 15px; font-weight: 800; color: #f1f5f9; letter-spacing: -0.3px;")
        layout.addWidget(brand)

        tag = QLabel("INTELLIGENCE ENGINE + SECURITY INTERFACE")
        tag.setStyleSheet("""
            font-size: 9px; font-weight: 700; letter-spacing: 1.5px;
            color: rgba(129,140,248,0.6);
            border: 1px solid rgba(99,102,241,0.2);
            padding: 2px 8px; border-radius: 4px;
            background: rgba(99,102,241,0.06);
            font-family: 'Courier New', monospace;
        """)
        layout.addWidget(tag)
        layout.addStretch()

        self._reset_btn = QPushButton("↺  Reset")
        self._reset_btn.clicked.connect(self._reset)
        self._reset_btn.hide()
        layout.addWidget(self._reset_btn)
        return header

    def _build_upload_screen(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(32)
        layout.setContentsMargins(40, 40, 40, 40)

        hero_title = QLabel("Redact Before You Share")
        hero_title.setStyleSheet("""
            font-size: 36px; font-weight: 900; color: #f8fafc;
            letter-spacing: -1px;
        """)
        hero_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(hero_title)

        hero_sub = QLabel(
            "Upload a document → detect PII → review & mask → export a permanently redacted file."
        )
        hero_sub.setStyleSheet("font-size: 14px; color: #64748b;")
        hero_sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(hero_sub)

        self._upload_zone = UploadZone()
        self._upload_zone.setMaximumWidth(600)
        self._upload_zone.file_selected.connect(self._on_file_added)
        layout.addWidget(self._upload_zone, alignment=Qt.AlignmentFlag.AlignCenter)

        # ── File list ──
        file_list_container = QWidget()
        file_list_container.setMaximumWidth(600)
        fl_layout = QVBoxLayout(file_list_container)
        fl_layout.setContentsMargins(0, 0, 0, 0)
        fl_layout.setSpacing(6)

        self._file_list_widget = QWidget()
        self._file_list_layout = QVBoxLayout(self._file_list_widget)
        self._file_list_layout.setContentsMargins(0, 0, 0, 0)
        self._file_list_layout.setSpacing(4)
        fl_layout.addWidget(self._file_list_widget)

        add_btn = QPushButton("+  Add More Files")
        add_btn.setStyleSheet("""
            QPushButton {
                background: rgba(34,197,94,0.12); border: 1px solid rgba(34,197,94,0.3);
                color: #22c55e; border-radius: 8px; padding: 8px 16px;
                font-weight: 700; font-size: 12px;
            }
            QPushButton:hover { background: rgba(34,197,94,0.25); }
        """)
        add_btn.clicked.connect(self._browse_more_files)
        fl_layout.addWidget(add_btn)
        layout.addWidget(file_list_container, alignment=Qt.AlignmentFlag.AlignCenter)

        # Privacy level selector
        level_row = QHBoxLayout()
        level_row.setAlignment(Qt.AlignmentFlag.AlignCenter)
        level_row.setSpacing(12)
        level_row.addWidget(QLabel("Privacy Level:"))
        self._level_combo = QComboBox()
        self._level_combo.addItems(["Basic", "Medium", "Strict"])
        self._level_combo.setCurrentIndex(1)
        self._level_combo.setFixedWidth(120)
        level_row.addWidget(self._level_combo)
        layout.addLayout(level_row)

        # ── Custom keywords input ──
        kw_container = QWidget()
        kw_container.setMaximumWidth(600)
        kw_layout = QVBoxLayout(kw_container)
        kw_layout.setContentsMargins(0, 0, 0, 0)
        kw_layout.setSpacing(6)

        kw_label = QLabel("🔍  Custom Text to Mask (optional)")
        kw_label.setStyleSheet("font-size: 13px; font-weight: 700; color: #818cf8;")
        kw_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        kw_layout.addWidget(kw_label)

        kw_sub = QLabel("Enter any text to find and mask — comma-separated for multiple")
        kw_sub.setStyleSheet("font-size: 11px; color: #64748b;")
        kw_sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        kw_layout.addWidget(kw_sub)

        self._custom_keywords_input = QLineEdit()
        self._custom_keywords_input.setPlaceholderText('e.g.  "123", "Main Road", "John Doe"')
        self._custom_keywords_input.setStyleSheet("""
            QLineEdit {
                background: rgba(99,102,241,0.08);
                border: 1px solid rgba(99,102,241,0.3);
                border-radius: 8px;
                padding: 10px 16px;
                color: #f1f5f9;
                font-size: 13px;
            }
            QLineEdit:focus {
                border-color: rgba(99,102,241,0.6);
                background: rgba(99,102,241,0.12);
            }
        """)
        kw_layout.addWidget(self._custom_keywords_input)
        layout.addWidget(kw_container, alignment=Qt.AlignmentFlag.AlignCenter)

        # ── Analyze button ──
        self._analyze_btn = QPushButton("🔍  Analyze All Files")
        self._analyze_btn.setFixedWidth(300)
        self._analyze_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 rgba(99,102,241,0.8),stop:1 rgba(124,58,237,0.8));
                border: 1px solid rgba(139,92,246,0.5); color: #fff; border-radius: 10px;
                padding: 14px; font-size: 14px; font-weight: 700;
            }
            QPushButton:hover { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 rgba(99,102,241,1),stop:1 rgba(124,58,237,1)); }
            QPushButton:disabled { opacity: 0.4; }
        """)
        self._analyze_btn.clicked.connect(self._start_all_analysis)
        self._analyze_btn.setEnabled(False)
        layout.addWidget(self._analyze_btn, alignment=Qt.AlignmentFlag.AlignCenter)

        return w

    def _build_workspace(self) -> QWidget:
        w = QWidget()
        layout = QHBoxLayout(w)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        # ── Left: Document Viewer ──
        viewer_container = QWidget()
        vl = QVBoxLayout(viewer_container)
        vl.setContentsMargins(0, 0, 0, 0)
        vl.setSpacing(0)

        self._progress_label = QLabel("Analyzing document...")
        self._progress_label.setStyleSheet("padding: 10px 16px; color: #818cf8; font-size: 12px; background: rgba(99,102,241,0.08);")
        self._progress_label.hide()
        vl.addWidget(self._progress_label)

        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 0)  # Indeterminate
        self._progress_bar.hide()
        vl.addWidget(self._progress_bar)

        # ── Navigation bar ──
        nav_bar = QFrame()
        nav_bar.setStyleSheet("background: rgba(255,255,255,0.03); border-bottom: 1px solid rgba(255,255,255,0.07);")
        nav_layout = QHBoxLayout(nav_bar)
        nav_layout.setContentsMargins(12, 6, 12, 6)
        nav_layout.setSpacing(10)

        self._prev_btn = QPushButton("◀  Prev")
        self._prev_btn.setFixedWidth(80)
        self._prev_btn.setStyleSheet("QPushButton { font-size: 11px; padding: 5px; } QPushButton:disabled { color: #333; }")
        self._prev_btn.clicked.connect(self._prev_file)
        nav_layout.addWidget(self._prev_btn)

        self._nav_label = QLabel("File 1 of 1")
        self._nav_label.setStyleSheet("font-size: 12px; font-weight: 700; color: #818cf8; font-family: 'Courier New', monospace;")
        self._nav_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        nav_layout.addWidget(self._nav_label, 1)

        self._next_btn = QPushButton("Next  ▶")
        self._next_btn.setFixedWidth(80)
        self._next_btn.setStyleSheet("QPushButton { font-size: 11px; padding: 5px; } QPushButton:disabled { color: #333; }")
        self._next_btn.clicked.connect(self._next_file)
        nav_layout.addWidget(self._next_btn)

        vl.addWidget(nav_bar)

        self._viewer = DocumentViewer()
        self._viewer.detection_toggled.connect(self._toggle_from_viewer)
        vl.addWidget(self._viewer)

        splitter.addWidget(viewer_container)

        # ── Right: Dashboard Panel ──
        self._dashboard = self._build_dashboard()
        splitter.addWidget(self._dashboard)
        splitter.setSizes([780, 320])
        splitter.setChildrenCollapsible(False)

        layout.addWidget(splitter)
        return w

    def _build_dashboard(self) -> QWidget:
        outer = QFrame()
        outer.setFixedWidth(320)
        outer.setStyleSheet("background: #0f0f14; border-left: 1px solid rgba(255,255,255,0.07);")
        ol = QVBoxLayout(outer)
        ol.setContentsMargins(0, 0, 0, 0)
        ol.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet("border: none; background: #0f0f14;")

        self._dash_inner = QWidget()
        self._dash_inner.setStyleSheet("background: transparent;")
        self._dash_layout = QVBoxLayout(self._dash_inner)
        self._dash_layout.setContentsMargins(0, 0, 0, 0)
        self._dash_layout.setSpacing(0)
        self._dash_layout.addStretch()

        scroll.setWidget(self._dash_inner)
        ol.addWidget(scroll)
        return outer

    # ── UI State ─────────────────────────────────────────────────────────

    def _show_upload_screen(self):
        self._upload_screen.show()
        self._workspace.hide()
        self._reset_btn.hide()

    def _show_workspace(self):
        self._upload_screen.hide()
        self._workspace.show()
        self._reset_btn.show()

    def _reset(self):
        self._file_paths.clear()
        self._privacy_maps.clear()
        self._detection_states_list.clear()
        self._current_idx = 0
        self._analysis_queue.clear()
        self._file_path   = None
        self._privacy_map = None
        self._detection_states.clear()
        self._viewer.scene.clear()
        self._clear_dashboard()
        while self._file_list_layout.count():
            item = self._file_list_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._analyze_btn.setEnabled(False)
        self._show_upload_screen()

    # ── File Handling (multi-file) ─────────────────────────────────────────

    def _on_file_added(self, path: str):
        if path in self._file_paths:
            return
        self._file_paths.append(path)
        self._privacy_maps.append(None)
        self._detection_states_list.append({})
        self._refresh_file_list_ui()
        self._analyze_btn.setEnabled(True)

    def _browse_more_files(self):
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Select Documents", "",
            "Documents (*.pdf *.jpg *.jpeg *.png *.bmp *.tiff *.webp)"
        )
        for p in paths:
            self._on_file_added(p)

    def _refresh_file_list_ui(self):
        while self._file_list_layout.count():
            item = self._file_list_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        for idx, fp in enumerate(self._file_paths):
            row = QFrame()
            row.setStyleSheet("background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.08); border-radius: 6px;")
            rl = QHBoxLayout(row)
            rl.setContentsMargins(10, 6, 10, 6)
            lbl = QLabel(f"\U0001f4c4  {Path(fp).name}")
            lbl.setStyleSheet("font-size: 12px; color: #94a3b8;")
            rl.addWidget(lbl, 1)
            rm_btn = QPushButton("\u2715")
            rm_btn.setFixedSize(24, 24)
            rm_btn.setStyleSheet("QPushButton { background: transparent; color: #ef4444; border: none; font-size: 14px; font-weight: 700; } QPushButton:hover { color: #fff; }")
            rm_btn.clicked.connect(lambda _, i=idx: self._remove_file(i))
            rl.addWidget(rm_btn)
            self._file_list_layout.addWidget(row)
        self._analyze_btn.setEnabled(len(self._file_paths) > 0)

    def _remove_file(self, idx: int):
        if 0 <= idx < len(self._file_paths):
            self._file_paths.pop(idx)
            self._privacy_maps.pop(idx)
            self._detection_states_list.pop(idx)
            self._refresh_file_list_ui()

    def _start_all_analysis(self):
        if not self._file_paths:
            return
        self._current_idx = 0
        self._analysis_queue = list(range(len(self._file_paths)))
        self._show_workspace()
        self._load_file_into_viewer(0)
        self._analyze_next_in_queue()

    def _analyze_next_in_queue(self):
        if not self._analysis_queue:
            self._progress_label.hide()
            self._progress_bar.hide()
            return
        idx = self._analysis_queue.pop(0)
        self._current_idx = idx
        self._file_path = self._file_paths[idx]
        self._load_file_into_viewer(idx)
        self._start_analysis(self._file_path)

    def _load_file_into_viewer(self, idx: int):
        path = self._file_paths[idx]
        ext = Path(path).suffix.lower()
        if ext in {".jpg", ".jpeg", ".png", ".bmp", ".tiff", ".webp"}:
            self._viewer.load_image(path)
        else:
            self._viewer.load_placeholder(794, 1123)
        self._update_nav_ui()

    def _update_nav_ui(self):
        total = len(self._file_paths)
        idx = self._current_idx
        name = Path(self._file_paths[idx]).name if idx < total else ""
        self._nav_label.setText(f"File {idx + 1} of {total}:  {name}")
        self._prev_btn.setEnabled(idx > 0)
        self._next_btn.setEnabled(idx < total - 1)

    def _save_current_state(self):
        idx = self._current_idx
        if 0 <= idx < len(self._privacy_maps):
            self._privacy_maps[idx] = self._privacy_map
            self._detection_states_list[idx] = dict(self._detection_states)

    def _next_file(self):
        if self._current_idx < len(self._file_paths) - 1:
            self._save_current_state()
            self._current_idx += 1
            self._switch_to_file(self._current_idx)

    def _prev_file(self):
        if self._current_idx > 0:
            self._save_current_state()
            self._current_idx -= 1
            self._switch_to_file(self._current_idx)

    def _switch_to_file(self, idx: int):
        self._file_path = self._file_paths[idx]
        self._privacy_map = self._privacy_maps[idx]
        self._detection_states = self._detection_states_list[idx] if idx < len(self._detection_states_list) else {}
        self._load_file_into_viewer(idx)
        if self._privacy_map:
            ext = Path(self._file_path).suffix.lower()
            if ext == ".pdf":
                page_info = self._privacy_map.get("page_info", [])
                if page_info:
                    pi = page_info[0]
                    self._viewer.load_placeholder(pi.get("width", 794), pi.get("height", 1123))
            page_info = self._privacy_map.get("page_info", [])
            ocr_w = page_info[0].get("width", 0) if page_info else 0
            ocr_h = page_info[0].get("height", 0) if page_info else 0
            self._viewer.set_detections(
                self._privacy_map.get("detections", []),
                {did for did, m in self._detection_states.items() if m},
                ocr_width=ocr_w, ocr_height=ocr_h,
            )
            self._build_dashboard_content()
        else:
            self._clear_dashboard()

    def _start_analysis(self, path: str):
        self._progress_label.setText(f"\U0001f50d  Analyzing file {self._current_idx + 1}/{len(self._file_paths)}...")
        self._progress_label.show()
        self._progress_bar.show()

        level = self._level_combo.currentText().lower()
        kw_text = self._custom_keywords_input.text().strip()
        custom_kws = [k.strip().strip('"').strip("'") for k in kw_text.split(",")] if kw_text else []
        custom_kws = [k for k in custom_kws if len(k) >= 2]

        self._worker_thread = QThread()
        self._worker = AnalysisWorker(path, level, custom_kws)
        self._worker.moveToThread(self._worker_thread)
        self._worker_thread.started.connect(self._worker.run)
        self._worker.finished.connect(self._on_analysis_done)
        self._worker.error.connect(self._on_analysis_error)
        self._worker.progress.connect(lambda msg: self._progress_label.setText(f"\U0001f50d  [{self._current_idx+1}/{len(self._file_paths)}] {msg}"))
        self._worker.finished.connect(self._worker_thread.quit)
        self._worker.error.connect(self._worker_thread.quit)
        self._worker_thread.start()

    def _on_analysis_done(self, result):
        self._privacy_map = result

        for cm in result.get("_custom_matches", []):
            det = {
                "id":             str(uuid.uuid4()),
                "type":           "custom",
                "label":          cm["label"],
                "text":           cm["text"],
                "page":           cm["page"],
                "coordinates":    cm.get("coordinates", {}),
                "confidence":     cm["confidence"],
                "risk_level":     cm["risk_level"],
                "suggested_mask": True,
            }
            self._privacy_map["detections"].append(det)

        ext = Path(self._file_path).suffix.lower() if self._file_path else ""
        if ext == ".pdf":
            page_info = result.get("page_info", [])
            if page_info:
                pi = page_info[0]
                self._viewer.load_placeholder(pi.get("width", 794), pi.get("height", 1123))

        self._detection_states = {
            d["id"]: d.get("suggested_mask", False)
            for d in self._privacy_map.get("detections", [])
        }

        self._save_current_state()

        page_info = self._privacy_map.get("page_info", [])
        ocr_w = page_info[0].get("width",  0) if page_info else 0
        ocr_h = page_info[0].get("height", 0) if page_info else 0

        self._viewer.set_detections(
            self._privacy_map.get("detections", []),
            {did for did, m in self._detection_states.items() if m},
            ocr_width=ocr_w, ocr_height=ocr_h,
        )
        self._build_dashboard_content()

        if self._analysis_queue:
            QTimer.singleShot(200, self._analyze_next_in_queue)
        else:
            self._progress_label.hide()
            self._progress_bar.hide()
            if self._current_idx != 0:
                self._current_idx = 0
                self._switch_to_file(0)

    def _on_analysis_error(self, msg: str):
        self._progress_label.hide()
        self._progress_bar.hide()
        QMessageBox.critical(self, "Analysis Failed", f"Error analyzing file {self._current_idx + 1}: {msg}")
        if self._analysis_queue:
            QTimer.singleShot(200, self._analyze_next_in_queue)

    # ── Dashboard ─────────────────────────────────────────────────────────

    def _clear_dashboard(self):
        layout = self._dash_layout
        while layout.count():
            item = layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
            elif item.layout():
                # clear nested layouts
                sub = item.layout()
                while sub.count():
                    sub_item = sub.takeAt(0)
                    if sub_item.widget():
                        sub_item.widget().deleteLater()

    def _section_label(self, text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet(
            "font-size: 9px; font-weight: 700; letter-spacing: 2px; color: rgba(255,255,255,0.25);"
            "font-family: 'Courier New', monospace; padding: 16px 20px 6px 20px;"
        )
        return lbl

    def _divider(self) -> QFrame:
        d = QFrame()
        d.setFixedHeight(1)
        d.setStyleSheet("background: rgba(255,255,255,0.05); margin: 0 20px;")
        return d

    def _build_dashboard_content(self):
        self._clear_dashboard()
        pm   = self._privacy_map
        dl   = self._dash_layout
        dets = pm.get("detections", [])

        # ── Risk ──
        dl.addWidget(self._section_label("RISK ASSESSMENT"))
        risk       = pm.get("overall_risk", "low")
        score      = pm.get("risk_score", 0)
        pen, bg    = RISK_COLORS.get(risk, ("#22c55e", "#052e16"))
        risk_card  = QFrame()
        risk_card.setStyleSheet(f"background: {bg}; border: 1px solid {pen}44; border-radius: 8px; margin: 0 16px 8px 16px;")
        rl = QHBoxLayout(risk_card)
        rl.setContentsMargins(12, 10, 12, 10)
        lbl_risk = QLabel(risk.upper())
        lbl_risk.setStyleSheet(f"font-size: 20px; font-weight: 900; color: {pen}; font-family: 'Courier New', monospace;")
        rl.addWidget(lbl_risk)
        rl.addStretch()
        lbl_score = QLabel(f"Score: {score}")
        lbl_score.setStyleSheet(f"font-size: 11px; color: {pen}88;")
        rl.addWidget(lbl_score)
        dl.addWidget(risk_card)

        doc_type = QLabel(pm.get("document_type", "unknown").replace("_", " ").title())
        doc_type.setStyleSheet("""
            font-size: 11px; font-weight: 700; color: #818cf8;
            background: rgba(99,102,241,0.12); border: 1px solid rgba(99,102,241,0.25);
            border-radius: 20px; padding: 3px 12px; margin: 0 20px 8px 20px;
        """)
        doc_type.setAlignment(Qt.AlignmentFlag.AlignCenter)
        dl.addWidget(doc_type)
        dl.addWidget(self._divider())

        # ── Warnings ──
        warnings = pm.get("warnings", [])
        if warnings:
            dl.addWidget(self._section_label("WARNINGS"))
            for w in warnings:
                warn_frame = QFrame()
                warn_frame.setStyleSheet("background: rgba(239,68,68,0.07); border: 1px solid rgba(239,68,68,0.2); border-radius: 6px; margin: 2px 16px;")
                wl = QVBoxLayout(warn_frame)
                wl.setContentsMargins(10, 8, 10, 8)
                lbl_w = QLabel(w)
                lbl_w.setStyleSheet("font-size: 11px; color: rgba(239,68,68,0.85); line-height: 1.5;")
                lbl_w.setWordWrap(True)
                wl.addWidget(lbl_w)
                dl.addWidget(warn_frame)
            dl.addWidget(self._divider())

        # ── Privacy preset buttons ──
        dl.addWidget(self._section_label("PRIVACY PRESETS"))
        preset_row = QHBoxLayout()
        preset_row.setContentsMargins(16, 0, 16, 8)
        preset_row.setSpacing(6)
        for preset, color in [("Basic", "#22c55e"), ("Medium", "#f59e0b"), ("Strict", "#ef4444")]:
            btn = QPushButton(preset)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background: {color}18; border: 1px solid {color}44;
                    color: {color}; border-radius: 5px; padding: 6px 4px;
                    font-size: 10px; font-weight: 700; font-family: 'Courier New', monospace;
                }}
                QPushButton:hover {{ background: {color}30; }}
            """)
            btn.clicked.connect(lambda _, p=preset: self._apply_preset(p))
            preset_row.addWidget(btn)
        dl.addLayout(preset_row)

        bulk_row = QHBoxLayout()
        bulk_row.setContentsMargins(16, 0, 16, 8)
        bulk_row.setSpacing(6)
        mask_all_btn = QPushButton("Mask All")
        mask_all_btn.clicked.connect(self._mask_all)
        unmask_btn = QPushButton("Unmask All")
        unmask_btn.setStyleSheet("QPushButton { color: rgba(239,68,68,0.6); border-color: rgba(239,68,68,0.3); } QPushButton:hover { background: rgba(239,68,68,0.08); color: #ef4444; }")
        unmask_btn.clicked.connect(self._unmask_all)
        bulk_row.addWidget(mask_all_btn)
        bulk_row.addWidget(unmask_btn)
        dl.addLayout(bulk_row)
        dl.addWidget(self._divider())

        # ── Detection list ──
        masked   = sum(1 for m in self._detection_states.values() if m)
        total    = len(dets)
        dl.addWidget(self._section_label(f"DETECTIONS — {masked}/{total} MASKED"))

        self._det_rows: Dict[str, DetectionRow] = {}
        det_list = QWidget()
        det_layout = QVBoxLayout(det_list)
        det_layout.setContentsMargins(12, 0, 12, 8)
        det_layout.setSpacing(5)

        for det in dets:
            row = DetectionRow(det, masked=self._detection_states.get(det["id"], False))
            row.toggled.connect(self._toggle_from_dashboard)
            det_layout.addWidget(row)
            self._det_rows[det["id"]] = row

        dl.addWidget(det_list)
        dl.addWidget(self._divider())

        # ── Export ──
        dl.addWidget(self._section_label("EXPORT"))
        export_section = QWidget()
        el = QVBoxLayout(export_section)
        el.setContentsMargins(16, 4, 16, 16)
        el.setSpacing(8)

        self._export_btn = QPushButton("Export Redacted File")
        self._export_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 rgba(99,102,241,0.8),stop:1 rgba(124,58,237,0.8));
                border: 1px solid rgba(139,92,246,0.5); color: #fff; border-radius: 8px;
                padding: 12px; font-size: 11px; font-weight: 700; letter-spacing: 1px;
                font-family: 'Courier New', monospace;
            }
            QPushButton:hover { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 rgba(99,102,241,1),stop:1 rgba(124,58,237,1)); }
        """)
        self._export_btn.clicked.connect(self._export)
        el.addWidget(self._export_btn)
        dl.addWidget(export_section)
        dl.addStretch()

    def _update_masked_count_label(self):
        """Refresh the detection section label with current count."""
        # Rebuild is cheapest given Qt layout
        pass

    # ── Toggle Logic ──────────────────────────────────────────────────────

    def _toggle_detection(self, det_id: str):
        if det_id not in self._detection_states:
            return
        new_masked = not self._detection_states[det_id]
        self._detection_states[det_id] = new_masked
        self._viewer.update_mask(det_id, new_masked)
        if det_id in getattr(self, "_det_rows", {}):
            self._det_rows[det_id].set_masked(new_masked)

    def _toggle_from_viewer(self, det_id: str):
        self._toggle_detection(det_id)

    def _toggle_from_dashboard(self, det_id: str, masked: bool):
        self._detection_states[det_id] = masked
        self._viewer.update_mask(det_id, masked)

    def _mask_all(self):
        for det_id in self._detection_states:
            self._detection_states[det_id] = True
            self._viewer.update_mask(det_id, True)
            if det_id in getattr(self, "_det_rows", {}):
                self._det_rows[det_id].set_masked(True)

    def _unmask_all(self):
        for det_id in self._detection_states:
            self._detection_states[det_id] = False
            self._viewer.update_mask(det_id, False)
            if det_id in getattr(self, "_det_rows", {}):
                self._det_rows[det_id].set_masked(False)

    def _apply_preset(self, preset: str):
        dets = self._privacy_map.get("detections", []) if self._privacy_map else []
        for det in dets:
            risk = det.get("risk_level", "low")
            if preset == "Strict":
                masked = True
            elif preset == "Medium":
                masked = risk in {"critical", "high", "medium"}
            else:  # Basic
                masked = risk in {"critical"}
            self._detection_states[det["id"]] = masked
            self._viewer.update_mask(det["id"], masked)
            if det["id"] in getattr(self, "_det_rows", {}):
                self._det_rows[det["id"]].set_masked(masked)

    # ── Export ────────────────────────────────────────────────────────────

    def _export(self):
        if not self._file_path or not self._privacy_map:
            return

        masked_count = sum(1 for m in self._detection_states.values() if m)
        total_count  = len(self._detection_states)

        dlg = ExportDialog(masked_count, total_count, self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return

        password = dlg.get_password()
        ext      = Path(self._file_path).suffix.lower()

        if ext in {".jpg", ".jpeg", ".png", ".bmp", ".tiff", ".webp"}:
            self._export_image(password)
        elif ext == ".pdf":
            self._export_pdf(password)

    def _export_image(self, password: Optional[str]):
        """Export image file as a redacted PDF (always .pdf — no more .pgk)."""
        save_path, _ = QFileDialog.getSaveFileName(
            self, "Save Redacted Document", "redacted_document.pdf", "PDF (*.pdf)"
        )
        if not save_path:
            return
        if not save_path.lower().endswith(".pdf"):
            save_path += ".pdf"

        try:
            from PIL import Image, ImageDraw
            import io as _io

            # Open original image and draw permanent black boxes
            img  = Image.open(self._file_path).convert("RGB")
            draw = ImageDraw.Draw(img)
            orig_w, orig_h = img.size

            # OCR coordinates are in preprocessed (upscaled) space.
            # Scale them back to original image space for correct redaction.
            page_info = self._privacy_map.get("page_info", [])
            ocr_w = page_info[0].get("width",  orig_w) if page_info else orig_w
            ocr_h = page_info[0].get("height", orig_h) if page_info else orig_h
            sx = orig_w / ocr_w if ocr_w > 0 else 1.0
            sy = orig_h / ocr_h if ocr_h > 0 else 1.0

            dets = self._privacy_map.get("detections", [])
            for det in dets:
                if not self._detection_states.get(det["id"], False):
                    continue
                coords = det.get("coordinates") or {}
                x = coords.get("x", 0); y = coords.get("y", 0)
                w = coords.get("w", 0); h = coords.get("h", 0)
                if w > 0 and h > 0:
                    rx = int(x * sx); ry = int(y * sy)
                    rw = max(1, int(w * sx)); rh = max(1, int(h * sy))
                    draw.rectangle([rx, ry, rx + rw, ry + rh], fill=(0, 0, 0))

            # Save as proper PDF
            try:
                import fitz
                buf = _io.BytesIO()
                img.save(buf, "PNG")
                buf.seek(0)
                img_doc   = fitz.open(stream=buf.read(), filetype="png")
                pdf_bytes = img_doc.convert_to_pdf()
                img_doc.close()
                doc = fitz.open("pdf", pdf_bytes)
                if password:
                    doc.save(save_path, encryption=fitz.PDF_ENCRYPT_AES_256,
                             owner_pw=password, user_pw=password)
                else:
                    doc.save(save_path)
                doc.close()
            except ImportError:
                # Fallback: Pillow built-in PDF (no password support)
                img.save(save_path, "PDF", resolution=150)
                if password:
                    QMessageBox.warning(self, "Password Not Applied",
                        "Install PyMuPDF for password protection:\n  pip install PyMuPDF\n\nSaved as unprotected PDF.")

            QMessageBox.information(self, "Export Complete", f"Redacted PDF saved to:\n{save_path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", str(e))

    def _export_pdf(self, password: Optional[str]):
        """Export redacted PDF with permanent black fill over masked detections."""
        try:
            import fitz
        except ImportError:
            QMessageBox.warning(self, "Missing Dependency",
                "PDF export requires PyMuPDF.\nInstall with: pip install PyMuPDF\n\nFalling back to image export.")
            self._export_image(password)
            return

        save_path, _ = QFileDialog.getSaveFileName(
            self, "Save Redacted PDF", "redacted_document.pdf", "PDF (*.pdf)"
        )
        if not save_path:
            return
        if not save_path.lower().endswith(".pdf"):
            save_path += ".pdf"

        try:
            doc  = fitz.open(self._file_path)
            dets = self._privacy_map.get("detections", [])
            page_info = self._privacy_map.get("page_info", [])

            for det in dets:
                if not self._detection_states.get(det["id"], False):
                    continue
                coords   = det.get("coordinates") or {}
                x = coords.get("x", 0); y = coords.get("y", 0)
                w = coords.get("w", 0); h = coords.get("h", 0)
                page_num = det.get("page", 1) - 1
                if w > 0 and h > 0 and 0 <= page_num < len(doc):
                    page = doc[page_num]
                    # Scale OCR coordinates (pixel space) to PDF coordinates (point space)
                    pdf_w = page.rect.width
                    pdf_h = page.rect.height
                    pi = page_info[page_num] if page_num < len(page_info) else {}
                    ocr_w = pi.get("width", pdf_w)
                    ocr_h = pi.get("height", pdf_h)
                    sx = pdf_w / ocr_w if ocr_w > 0 else 1.0
                    sy = pdf_h / ocr_h if ocr_h > 0 else 1.0
                    rx = x * sx; ry = y * sy
                    rw = w * sx; rh = h * sy
                    rect = fitz.Rect(rx, ry, rx + rw, ry + rh)
                    page.draw_rect(rect, color=(0, 0, 0), fill=(0, 0, 0), overlay=True)

            if password:
                doc.save(save_path, encryption=fitz.PDF_ENCRYPT_AES_256,
                         owner_pw=password, user_pw=password)
            else:
                doc.save(save_path)
            doc.close()
            QMessageBox.information(self, "Export Complete", f"Redacted PDF saved to:\n{save_path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", str(e))


# ════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ════════════════════════════════════════════════════════════════════════════
def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Privacy Gatekeeper")
    app.setOrganizationName("PrivacyGatekeeper")

    # Dark palette
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window,          QColor("#09090e"))
    palette.setColor(QPalette.ColorRole.WindowText,      QColor("#f1f5f9"))
    palette.setColor(QPalette.ColorRole.Base,            QColor("#0f0f14"))
    palette.setColor(QPalette.ColorRole.AlternateBase,   QColor("#09090e"))
    palette.setColor(QPalette.ColorRole.Text,            QColor("#f1f5f9"))
    palette.setColor(QPalette.ColorRole.Button,          QColor("#0f0f14"))
    palette.setColor(QPalette.ColorRole.ButtonText,      QColor("#f1f5f9"))
    palette.setColor(QPalette.ColorRole.Highlight,       QColor("#818cf8"))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
    app.setPalette(palette)

    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()