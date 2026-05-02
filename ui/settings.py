"""
settings.py — Settings dialog for the malware sandbox UI

Configures:
  - FastAPI server URL (for Phase 6 global learning sync)
  - Max instructions per scan (speed vs depth trade-off)
  - Model auto-sync on startup toggle
"""

from __future__ import annotations
import json, os

from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel,
                              QLineEdit, QSpinBox, QCheckBox,
                              QDialogButtonBox, QGroupBox, QFormLayout)
from PyQt6.QtCore    import Qt

# Default settings
SETTINGS_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "ui", ".settings.json"
)
DEFAULTS = {
    "server_url":        "https://goldie-gripiest-guillermo.ngrok-free.dev",
    "max_instructions":  50000,
    "auto_sync":         False,
}


def load_settings() -> dict:
    try:
        with open(SETTINGS_PATH, "r") as f:
            data = json.load(f)
            return {**DEFAULTS, **data}
    except Exception:
        return DEFAULTS.copy()


def save_settings(settings: dict):
    with open(SETTINGS_PATH, "w") as f:
        json.dump(settings, f, indent=2)


class SettingsDialog(QDialog):

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setMinimumWidth(400)
        self.setModal(True)
        self._settings = load_settings()
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(14)

        # ── Server settings ────────────────────────────────────────────
        server_group = QGroupBox("Global Learning Server (Phase 6)")
        server_form  = QFormLayout(server_group)

        self.url_edit = QLineEdit(self._settings["server_url"])
        self.url_edit.setPlaceholderText("http://localhost:8000")
        server_form.addRow("Server URL:", self.url_edit)

        self.sync_cb = QCheckBox("Auto-sync model on startup")
        self.sync_cb.setChecked(self._settings["auto_sync"])
        server_form.addRow("", self.sync_cb)
        layout.addWidget(server_group)

        # ── Sandbox settings ───────────────────────────────────────────
        scan_group = QGroupBox("Sandbox")
        scan_form  = QFormLayout(scan_group)

        self.instr_spin = QSpinBox()
        self.instr_spin.setRange(500, 20000)
        self.instr_spin.setSingleStep(500)
        self.instr_spin.setValue(self._settings["max_instructions"])
        self.instr_spin.setSuffix(" instructions")
        scan_form.addRow("Max instructions:", self.instr_spin)

        note = QLabel("Higher = deeper analysis, slower scan")
        note.setStyleSheet("color: #8B949E; font-size: 11px;")
        scan_form.addRow("", note)
        layout.addWidget(scan_group)

        # ── Buttons ────────────────────────────────────────────────────
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok |
            QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._on_ok)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _on_ok(self):
        self._settings["server_url"]       = self.url_edit.text().strip()
        self._settings["max_instructions"] = self.instr_spin.value()
        self._settings["auto_sync"]        = self.sync_cb.isChecked()
        save_settings(self._settings)
        self.accept()

    def get_settings(self) -> dict:
        return self._settings
