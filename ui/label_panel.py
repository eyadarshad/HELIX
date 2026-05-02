"""
label_panel.py — User feedback / labeling panel

Allows the user to confirm or correct the model's verdict:
  [✔ Correct]        → feeds the correct label to online_learner
  [✘ False Positive] → feeds the opposite label to online_learner
  [🔍 Scan Another]  → resets the UI for the next file

Connects directly to OnlineLearner.update_from_dict()
"""

from __future__ import annotations

from PyQt6.QtWidgets import (QWidget, QHBoxLayout, QPushButton,
                              QLabel, QVBoxLayout)
from PyQt6.QtCore    import Qt, pyqtSignal


class LabelPanel(QWidget):
    """Feedback panel shown after a scan result."""

    label_submitted = pyqtSignal(str)   # emits "malware" or "benign"
    scan_another    = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._features     = None
        self._verdict      = None
        self._learner      = None
        self._setup_ui()
        self.setVisible(False)

    def _setup_ui(self):
        vbox = QVBoxLayout(self)
        vbox.setSpacing(8)
        vbox.setContentsMargins(0, 8, 0, 0)

        # Header
        header = QLabel("Was this verdict correct?")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet("color: #8B949E; font-size: 12px;")
        vbox.addWidget(header)

        # Buttons row
        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)

        self.correct_btn = QPushButton("✔  Correct")
        self.correct_btn.setObjectName("correctBtn")
        self.correct_btn.setToolTip("Confirm — this prediction was correct")
        self.correct_btn.clicked.connect(self._on_correct)

        self.fp_btn = QPushButton("✘  Wrong")
        self.fp_btn.setObjectName("fpBtn")
        self.fp_btn.setToolTip("The verdict was wrong — provide the real label")
        self.fp_btn.clicked.connect(self._on_false_positive)

        self.next_btn = QPushButton("🔍  Scan Another")
        self.next_btn.clicked.connect(self.scan_another.emit)

        btn_row.addWidget(self.correct_btn)
        btn_row.addWidget(self.fp_btn)
        btn_row.addStretch()
        btn_row.addWidget(self.next_btn)

        vbox.addLayout(btn_row)

        # Feedback confirmation
        self.feedback_label = QLabel("")
        self.feedback_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.feedback_label.setStyleSheet("color: #3FB950; font-size: 11px;")
        vbox.addWidget(self.feedback_label)

    def setup(self, features: dict, verdict: str, learner=None):
        """
        Activate the panel for a new result.

        Args:
            features: 14-feature dict from extract_features()
            verdict:  "malware" or "benign"
            learner:  OnlineLearner instance (or None to skip model update)
        """
        self._features = features
        self._verdict  = verdict
        self._learner  = learner
        self.feedback_label.setText("")
        self.correct_btn.setEnabled(True)
        self.fp_btn.setEnabled(True)
        self.setVisible(True)

    def _on_correct(self):
        """User confirms the verdict is correct."""
        self._submit_label(self._verdict)

    def _on_false_positive(self):
        """User says the verdict was wrong — flip the label."""
        corrected = "benign" if self._verdict == "malware" else "malware"
        self._submit_label(corrected)

    def _submit_label(self, label: str):
        """Shared logic: update local learner + push correction to server."""
        if not self._learner or not self._features:
            self.correct_btn.setEnabled(False)
            self.fp_btn.setEnabled(False)
            return

        try:
            from features.extractor import FEATURE_NAMES
            status   = self._learner.update_from_dict(self._features, label)
            buffered = self._learner.buffered_count
            applied  = self._learner.applied_count
            needed   = max(0, 10 - buffered)

            # ── Push to central server (non-blocking background thread) ─────────
            vec    = [self._features.get(f, 0.0) for f in FEATURE_NAMES]
            sha256 = self._features.get("_sha256", "")
            pushed = self._learner.push_correction_to_server(
                sha256=sha256,
                feature_vector=vec,
                label=1 if label == "malware" else 0,
            )
            server_note = "  [synced to server ↗]" if pushed else ""

            if status == "updated":
                self.feedback_label.setText(
                    f"✔ Batch applied! Model updated with {applied} labels.{server_note}"
                )
            else:
                self.feedback_label.setText(
                    f"✔ Buffered ({buffered}/10). "
                    f"{needed} more needed to update model.{server_note}"
                )
        except Exception as e:
            self.feedback_label.setText(f"Update failed: {e}")

        self.correct_btn.setEnabled(False)
        self.fp_btn.setEnabled(False)
        self.label_submitted.emit(label)

    def hide_panel(self):
        self.setVisible(False)
        self.feedback_label.setText("")
