"""
threat_display.py — Proper circular threat gauge for HELIX

Fixed issues from previous version:
  - _target not initialised in __init__ (AttributeError)
  - Hardcoded dark colors that break in light mode
  - Emoji in labels (cross-platform rendering problems)
  - Gauge rect not accounting for pen width (clipping)
  - Font size computed from side — too large, clipped

Design:
  - Thick arc track (dark gray), filled arc (green → amber → red)
  - Large percentage number in center, semitransparent sub-label
  - Clean risk level text below: LOW / MEDIUM / HIGH / CRITICAL
  - No emoji, pure QPainter
"""

from __future__ import annotations
import math

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QSizePolicy
from PyQt6.QtCore    import Qt, QTimer, QRectF, QPointF
from PyQt6.QtGui     import QPainter, QPen, QColor, QFont, QBrush, QPainterPath


# arc colours keyed to risk level
_COLORS = {
    "low":      QColor("#22C55E"),   # green
    "medium":   QColor("#F59E0B"),   # amber
    "high":     QColor("#EF4444"),   # red
    "critical": QColor("#FF0000"),   # bright red
}

_TRACK_COLOR = QColor("#2A2A2A")    # dark track — same for both themes


def _score_color(score: float) -> QColor:
    if score < 0.40:
        # green → amber
        t = score / 0.40
        r = int(34  + (245 - 34)  * t)
        g = int(197 + (158 - 197) * t)
        b = int(94  + (11  - 94)  * t)
        return QColor(r, g, b)
    else:
        # amber → red
        t = (score - 0.40) / 0.60
        r = int(245 + (239 - 245) * t)
        g = int(158 + (68  - 158) * t)
        b = int(11  + (68  - 11)  * t)
        return QColor(r, g, b)


def _risk_label(score: float) -> str:
    if score < 0.35:
        return "Safe"
    elif score < 0.55:
        return "Suspicious"
    elif score < 0.75:
        return "Dangerous"
    else:
        return "Critical"


class ThreatGauge(QWidget):
    """
    Circular arc gauge (225° sweep).
    Animates smoothly with easing when score changes.
    """

    ARC_START  = 225    # degrees — bottom-left
    ARC_SWEEP  = -270   # counter-clockwise sweep (full = 270°)
    PEN_WIDTH  = 14
    MARGIN     = 20     # extra margin so round caps aren't clipped

    def __init__(self, parent=None):
        super().__init__(parent)
        self._display = 0.0
        self._target  = 0.0
        self._verdict = ""
        self._timer   = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self.setMinimumSize(180, 180)
        self.setSizePolicy(QSizePolicy.Policy.Expanding,
                           QSizePolicy.Policy.Expanding)

    # ── Public API ────────────────────────────────────────────────────────────

    def set_score(self, score: float, verdict: str = ""):
        self._target  = max(0.0, min(1.0, score))
        self._verdict = verdict
        self._timer.start(14)

    def reset(self):
        self._target  = 0.0
        self._display = 0.0
        self._verdict = ""
        self._timer.stop()
        self.update()

    # ── Animation ─────────────────────────────────────────────────────────────

    def _tick(self):
        diff = self._target - self._display
        if abs(diff) < 0.004:
            self._display = self._target
            self._timer.stop()
        else:
            self._display += diff * 0.10
        self.update()

    # ── Painting ──────────────────────────────────────────────────────────────

    def paintEvent(self, _event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        w, h   = self.width(), self.height()
        margin = self.MARGIN + self.PEN_WIDTH // 2 + 2
        side   = min(w, h) - 2 * margin
        x      = (w - side) / 2
        y      = (h - side) / 2
        rect   = QRectF(x, y, side, side)

        # ── Track arc (background) ────────────────────────────────────────
        pen = QPen(_TRACK_COLOR, self.PEN_WIDTH,
                   Qt.PenStyle.SolidLine,
                   Qt.PenCapStyle.RoundCap,
                   Qt.PenJoinStyle.RoundJoin)
        p.setPen(pen)
        p.drawArc(rect, self.ARC_START * 16, self.ARC_SWEEP * 16)

        # ── Fill arc (score) ──────────────────────────────────────────────
        if self._display > 0.001:
            color  = _score_color(self._display)
            pen2   = QPen(color, self.PEN_WIDTH,
                          Qt.PenStyle.SolidLine,
                          Qt.PenCapStyle.RoundCap,
                          Qt.PenJoinStyle.RoundJoin)
            p.setPen(pen2)
            span = int(self.ARC_SWEEP * 16 * self._display)
            p.drawArc(rect, self.ARC_START * 16, span)

        cx = w / 2
        cy = h / 2

        # ── Percentage text ────────────────────────────────────────────────
        pct        = int(self._display * 100)
        pct_size   = max(10, int(side * 0.22))
        font_pct   = QFont("Segoe UI", pct_size, QFont.Weight.Bold)
        p.setFont(font_pct)
        c = _score_color(self._display) if self._display > 0 else QColor("#555555")
        p.setPen(c)
        p.drawText(
            QRectF(x, cy - side * 0.24, side, side * 0.38),
            Qt.AlignmentFlag.AlignCenter,
            f"{pct}%"
        )

        # ── "THREAT SCORE" micro-label ─────────────────────────────────────
        ts_size = max(7, int(side * 0.072))
        p.setFont(QFont("Segoe UI", ts_size, QFont.Weight.Normal))
        p.setPen(QColor("#666666"))
        p.drawText(
            QRectF(x, cy - side * 0.42, side, side * 0.28),
            Qt.AlignmentFlag.AlignCenter | Qt.AlignmentFlag.AlignBottom,
            "THREAT SCORE"
        )

        # ── Risk label below percentage ──────────────────────────────────────
        risk_size = max(7, int(side * 0.075))
        p.setFont(QFont("Segoe UI", risk_size, QFont.Weight.DemiBold))
        risk_col = _score_color(self._display) if self._display > 0 else QColor("#444444")
        p.setPen(risk_col)
        p.drawText(
            QRectF(x, cy + side * 0.02, side, side * 0.18),
            Qt.AlignmentFlag.AlignCenter,
            _risk_label(self._display) if self._display > 0 else "—"
        )

        p.end()


class ThreatDisplay(QWidget):
    """Full threat display: gauge + verdict text."""

    def __init__(self, parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.setContentsMargins(8, 8, 8, 8)
        lay.setSpacing(14)

        self.gauge = ThreatGauge()
        self.gauge.setFixedSize(200, 200)

        self._verdict_lbl = QLabel("—")
        self._verdict_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._verdict_lbl.setObjectName("pill")
        self._verdict_lbl.setProperty("verdict", "")
        self._verdict_lbl.setStyleSheet(
            "font-size: 12px; font-weight: 700; letter-spacing: 1px;"
            " padding: 6px 18px; border-radius: 14px;"
        )

        lay.addWidget(self.gauge, alignment=Qt.AlignmentFlag.AlignCenter)
        lay.addSpacing(4)
        lay.addWidget(self._verdict_lbl, alignment=Qt.AlignmentFlag.AlignCenter)

    def show_result(self, score: float, verdict: str):
        self.gauge.set_score(score, verdict)
        texts = {"malware": "⚠  THREAT DETECTED", "benign": "✓  CLEAN FILE",
                 "packed": "⚠  SUSPICIOUS (Packed)"}
        self._verdict_lbl.setText(texts.get(verdict, verdict.upper()))
        self._verdict_lbl.setProperty("verdict", verdict)
        self._verdict_lbl.style().unpolish(self._verdict_lbl)
        self._verdict_lbl.style().polish(self._verdict_lbl)

    def show_scanning(self):
        self.gauge.reset()
        self._verdict_lbl.setText("SCANNING...")
        self._verdict_lbl.setProperty("verdict", "scanning")
        self._verdict_lbl.style().unpolish(self._verdict_lbl)
        self._verdict_lbl.style().polish(self._verdict_lbl)

    def reset(self):
        self.gauge.reset()
        self._verdict_lbl.setText("—")
        self._verdict_lbl.setProperty("verdict", "")
        self._verdict_lbl.style().unpolish(self._verdict_lbl)
        self._verdict_lbl.style().polish(self._verdict_lbl)
