"""
alert_dialog.py — Malware Detection Alert Dialog

Shown when the background file-watcher detects a new EXE that scores
above the threat threshold. Non-modal, always-on-top, urgent design.

User choices:
  [Block & Quarantine]  → moves file to quarantine folder, prevents execution
  [Delete File]         → permanently deletes the file
  [Run Anyway]          → user accepts risk and runs the file
  [Dismiss]             → closes dialog, takes no action
"""

from __future__ import annotations
import os
import shutil
import subprocess
from datetime import datetime

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QFrame, QWidget
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui  import QFont, QColor, QPalette


QUARANTINE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "quarantine"
)


class MalwareAlertDialog(QDialog):
    """
    Urgent blocking alert shown when a malware EXE is detected.
    Always on top, non-resizable, high-contrast danger styling.
    """

    action_taken = pyqtSignal(str, str)   # (action, filepath)

    def __init__(self, filepath: str, score: float, verdict: str,
                 top_features: dict | None = None, parent=None):
        super().__init__(parent)
        self.filepath      = filepath
        self.score         = score
        self.verdict       = verdict
        self.top_features  = top_features or {}

        self.setWindowTitle("⚠  Threat Detected — HELIX")
        self.setWindowFlags(
            Qt.WindowType.Dialog |
            Qt.WindowType.WindowStaysOnTopHint |
            Qt.WindowType.FramelessWindowHint
        )
        self.setModal(True)
        self.setFixedWidth(480)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self._build_ui()

    def _build_ui(self):
        # Outer container with border
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)

        card = QFrame()
        card.setStyleSheet("""
            QFrame {
                background-color: #13111A;
                border: 2px solid #EF4444;
                border-radius: 16px;
            }
        """)
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(28, 24, 28, 24)
        card_layout.setSpacing(16)

        # ── Header strip ─────────────────────────────────────────────
        header = QFrame()
        header.setStyleSheet(
            "background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            "stop:0 rgba(239,68,68,0.25), stop:1 transparent);"
            "border-radius: 8px; border: none;"
        )
        hh = QHBoxLayout(header)
        hh.setContentsMargins(12, 8, 12, 8)

        icon_lbl = QLabel("🛑")
        icon_lbl.setStyleSheet("font-size: 32px; background: transparent;")

        title_col = QVBoxLayout()
        t1 = QLabel("THREAT DETECTED")
        t1.setStyleSheet("font-size: 18px; font-weight: 700; color: #EF4444;"
                         " background: transparent; letter-spacing: 2px;")
        t2 = QLabel("HELIX — Real-time Protection")
        t2.setStyleSheet("font-size: 11px; color: #94A3B8; background: transparent;")
        title_col.addWidget(t1)
        title_col.addWidget(t2)

        hh.addWidget(icon_lbl)
        hh.addSpacing(8)
        hh.addLayout(title_col)
        hh.addStretch()
        card_layout.addWidget(header)

        # ── File info ─────────────────────────────────────────────────
        fname = os.path.basename(self.filepath)
        fsize = os.path.getsize(self.filepath) // 1024 if os.path.exists(self.filepath) else 0

        file_frame = QFrame()
        file_frame.setStyleSheet(
            "background: #1E1B2E; border-radius: 8px; border: 1px solid #2D2B40;"
        )
        ff = QVBoxLayout(file_frame)
        ff.setContentsMargins(14, 10, 14, 10)
        ff.setSpacing(4)

        fn_lbl = QLabel(f"📄  {fname}")
        fn_lbl.setStyleSheet("font-size: 14px; font-weight: 600; color: #F1F5F9;"
                              " background: transparent;")
        fn_lbl.setWordWrap(True)

        fp_lbl = QLabel(self.filepath)
        fp_lbl.setStyleSheet("font-size: 10px; color: #64748B; background: transparent;")
        fp_lbl.setWordWrap(True)

        meta = QLabel(f"Size: {fsize} KB   |   Threat Score: {self.score*100:.1f}%")
        meta.setStyleSheet("font-size: 11px; color: #94A3B8; background: transparent;")

        ff.addWidget(fn_lbl)
        ff.addWidget(fp_lbl)
        ff.addWidget(meta)
        card_layout.addWidget(file_frame)

        # ── Score bar ─────────────────────────────────────────────────
        score_row = QHBoxLayout()
        score_lbl = QLabel("Threat Level")
        score_lbl.setStyleSheet("color: #94A3B8; font-size: 11px; background: transparent;")
        pct_lbl = QLabel(f"{self.score*100:.0f}%")
        pct_lbl.setStyleSheet("color: #EF4444; font-size: 13px; font-weight: 700;"
                               " background: transparent;")
        score_row.addWidget(score_lbl)
        score_row.addStretch()
        score_row.addWidget(pct_lbl)
        card_layout.addLayout(score_row)

        bar_bg = QFrame()
        bar_bg.setFixedHeight(8)
        bar_bg.setStyleSheet("background: #2D2B40; border-radius: 4px; border: none;")
        bar_fg = QFrame(bar_bg)
        bar_fg.setFixedHeight(8)
        bar_fg.setFixedWidth(int((self.width() - 56) * self.score))
        bar_fg.setStyleSheet("background: #EF4444; border-radius: 4px; border: none;")
        card_layout.addWidget(bar_bg)

        # ── Warning message ───────────────────────────────────────────
        warn = QLabel(
            "⚠  This file looks dangerous and may harm your computer.\n"
            "We recommend deleting or quarantining it. Choose an action below."
        )
        warn.setStyleSheet(
            "color: #FCD34D; font-size: 12px; background: transparent; "
            "padding: 8px; border-radius: 6px;"
            "background-color: rgba(252, 211, 77, 0.08);"
            "border: 1px solid rgba(252, 211, 77, 0.2);"
        )
        warn.setWordWrap(True)
        card_layout.addWidget(warn)

        # ── Action buttons ────────────────────────────────────────────
        btn_row = QVBoxLayout()
        btn_row.setSpacing(8)

        self.quarantine_btn = self._make_btn(
            "🔒  Block & Quarantine",
            "#7C3AED", "#6D28D9",
            "Move to quarantine folder — file cannot run"
        )
        self.delete_btn = self._make_btn(
            "🗑  Delete File",
            "#EF4444", "#DC2626",
            "Permanently delete this file from disk"
        )

        row2 = QHBoxLayout()
        self.run_btn = self._make_btn(
            "⚠  Run Anyway",
            "#374151", "#4B5563",
            "I understand the risk — run this file"
        )
        self.run_btn.setStyleSheet(self.run_btn.styleSheet() +
                                    " color: #F59E0B;")
        self.dismiss_btn = self._make_btn(
            "✕  Dismiss",
            "#1E293B", "#334155",
            "Close without action"
        )

        row2.addWidget(self.run_btn)
        row2.addWidget(self.dismiss_btn)

        btn_row.addWidget(self.quarantine_btn)
        btn_row.addWidget(self.delete_btn)
        btn_row.addLayout(row2)
        card_layout.addLayout(btn_row)

        self.quarantine_btn.clicked.connect(self._quarantine)
        self.delete_btn.clicked.connect(self._delete)
        self.run_btn.clicked.connect(self._run_anyway)
        self.dismiss_btn.clicked.connect(self.reject)

        root.addWidget(card)

    def _make_btn(self, text: str, bg: str, hover: str, tip: str) -> QPushButton:
        btn = QPushButton(text)
        btn.setToolTip(tip)
        btn.setFixedHeight(42)
        btn.setStyleSheet(f"""
            QPushButton {{
                background: {bg}; color: #F1F5F9;
                border: none; border-radius: 8px;
                font-size: 13px; font-weight: 600;
                padding: 0 16px;
            }}
            QPushButton:hover {{ background: {hover}; }}
            QPushButton:pressed {{ background: #111; }}
        """)
        return btn

    def _quarantine(self):
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        name = os.path.basename(self.filepath)
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        dst  = os.path.join(QUARANTINE_DIR, f"{ts}_{name}")
        try:
            shutil.move(self.filepath, dst)
            self.action_taken.emit("quarantine", dst)
        except Exception as e:
            self.action_taken.emit("quarantine_error", str(e))
        self.accept()

    def _delete(self):
        try:
            os.remove(self.filepath)
            self.action_taken.emit("delete", self.filepath)
        except Exception as e:
            self.action_taken.emit("delete_error", str(e))
        self.accept()

    def _run_anyway(self):
        self.action_taken.emit("run", self.filepath)
        try:
            subprocess.Popen([self.filepath], shell=False)
        except Exception:
            pass
        self.accept()
