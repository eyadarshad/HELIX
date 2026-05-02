"""
tray_app.py — Background System Tray Guard Service

Runs in the background on Windows startup and watches the user's common
download / execution paths for new EXE and DLL files.

When a new file appears:
  1. Scans it through the sandbox pipeline in a background thread
  2. If threat score < threshold → shows brief "Clean" tray notification
  3. If threat score >= threshold → shows MalwareAlertDialog

Watched folders (configurable):
  - Downloads, Desktop, Temp, AppData/Local/Temp

Usage:
    python main.py --tray         ← headless tray mode (on startup)
    python main.py                ← full UI mode
"""

from __future__ import annotations
import os
import sys
import time
import threading
from pathlib import Path

from PyQt6.QtWidgets import (
    QApplication, QSystemTrayIcon, QMenu, QWidget
)
from PyQt6.QtGui    import QIcon, QPixmap, QPainter, QColor, QBrush
from PyQt6.QtCore   import Qt, QThread, pyqtSignal, QObject, QTimer

# Watched file extensions
# Watched file extensions — only PE formats the model is trained on
# MSI/BAT/PS1/CMD removed: scanner rejects them with "unsupported format"
WATCH_EXTENSIONS = {".exe", ".dll", ".com"}

# Threat threshold above which the alert dialog is shown
THREAT_THRESHOLD = 0.52   # matches MALWARE_THRESHOLD in online_learner.py

# Default watched directories
DEFAULT_WATCH_DIRS = [
    Path.home() / "Downloads",
    Path.home() / "Desktop",
    Path.home() / "AppData" / "Local" / "Temp",
    Path("C:/Temp"),
]


_WORKSPACE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ICON_PATH = os.path.join(_WORKSPACE, "ICONS", "favicon", "icon (2).png")


def _make_tray_icon() -> QIcon:
    """Load the custom HX icon for the tray, or paint a fallback."""
    if os.path.exists(_ICON_PATH):
        return QIcon(_ICON_PATH)

    # Fallback: painted violet square with 'H'
    from PyQt6.QtCore import QRectF
    from PyQt6.QtGui  import QFont, QPen

    size = 64
    px = QPixmap(size, size)
    px.fill(Qt.GlobalColor.transparent)
    p = QPainter(px)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setBrush(QBrush(QColor("#7C3AED")))
    p.setPen(Qt.PenStyle.NoPen)
    p.drawRoundedRect(QRectF(0, 0, size, size), size * 0.22, size * 0.22)
    font = QFont("Segoe UI", int(size * 0.48))
    font.setWeight(QFont.Weight.Bold)
    p.setFont(font)
    p.setPen(QPen(QColor("#FFFFFF")))
    p.drawText(QRectF(0, 0, size, size), Qt.AlignmentFlag.AlignCenter, "H")
    p.end()
    return QIcon(px)


class ScanSignals(QObject):
    scan_result = pyqtSignal(str, float, str, dict)  # filepath, score, verdict, features


class FileScanWorker(threading.Thread):
    """Scans a single file in a daemon thread — production pipeline."""

    _model_checked = False   # class-level flag: only check for updates once per session

    def __init__(self, filepath: str, signals: ScanSignals):
        super().__init__(daemon=True)
        self.filepath = filepath
        self.signals  = signals

    def run(self):
        try:
            WORKSPACE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            if WORKSPACE not in sys.path:
                sys.path.insert(0, WORKSPACE)

            from features.extractor import extract_features, FEATURE_NAMES
            from ml.online_learner  import OnlineLearner

            learner = OnlineLearner()

            # Check for model updates from server (once per session)
            if not FileScanWorker._model_checked:
                FileScanWorker._model_checked = True
                learner.check_model_update()   # non-blocking if server not configured

            # ── VT hash check first ────────────────────────────────────────────
            file_sha256 = ""
            vt_score    = None
            try:
                from bridge.vt_check import check_hash, vt_verdict_to_score, sha256_of_file
                file_sha256 = sha256_of_file(self.filepath)
                vt_result   = check_hash(self.filepath)
                vt_score    = vt_verdict_to_score(vt_result)
            except Exception:
                vt_result = None

            if vt_score is not None and vt_score > 0.80:
                features = {"_vt_bypass": True, "_vt_score": vt_score,
                            "_sha256": file_sha256}
                self.signals.scan_result.emit(
                    self.filepath, vt_score, "malware", features
                )
                return

            # ── PE-only feature extraction (matches training distribution) ─────
            features = extract_features({}, filepath=self.filepath)
            features["_sha256"] = file_sha256
            vec = [features.get(f, 0.0) for f in FEATURE_NAMES]

            score   = learner.predict_proba(vec)
            verdict = learner.predict(vec)

            self.signals.scan_result.emit(
                self.filepath, score, verdict, features
            )
        except Exception as e:
            print(f"[Guard] Scan failed for {self.filepath}: {e}")


class FileWatcher(QThread):
    """
    Watches specified directories for new EXE/DLL files using polling.
    Uses watchdog library if available, falls back to polling.
    """
    new_file = pyqtSignal(str)

    def __init__(self, watch_dirs: list[Path] | None = None):
        super().__init__()
        self.watch_dirs = [str(d) for d in (watch_dirs or DEFAULT_WATCH_DIRS)]
        self._running   = True
        self._seen      = set()

    def stop(self):
        self._running = False

    def run(self):
        # Initial snapshot — don't alert on files that already existed
        for d in self.watch_dirs:
            if os.path.isdir(d):
                for f in os.listdir(d):
                    self._seen.add(os.path.join(d, f).lower())

        try:
            self._run_watchdog()
        except ImportError:
            self._run_polling()

    def _run_watchdog(self):
        """Use watchdog for efficient file system event monitoring."""
        from watchdog.observers import Observer
        from watchdog.events    import FileSystemEventHandler

        watcher = self

        class Handler(FileSystemEventHandler):
            def on_created(self, event):
                if not event.is_directory:
                    ext = os.path.splitext(event.src_path)[1].lower()
                    if ext in WATCH_EXTENSIONS:
                        # Small delay: wait for file to finish writing
                        time.sleep(1.5)
                        if os.path.exists(event.src_path):
                            watcher.new_file.emit(event.src_path)

        observer = Observer()
        for d in self.watch_dirs:
            if os.path.isdir(d):
                observer.schedule(Handler(), d, recursive=False)

        observer.start()
        while self._running:
            time.sleep(1)
        observer.stop()
        observer.join()

    def _run_polling(self):
        """Fallback: poll every 3 seconds."""
        while self._running:
            for d in self.watch_dirs:
                if not os.path.isdir(d):
                    continue
                for fname in os.listdir(d):
                    full = os.path.join(d, fname)
                    key  = full.lower()
                    ext  = os.path.splitext(fname)[1].lower()
                    if ext in WATCH_EXTENSIONS and key not in self._seen:
                        self._seen.add(key)
                        time.sleep(1.0)   # wait for write to finish
                        if os.path.exists(full):
                            self.new_file.emit(full)
            time.sleep(3)


class TrayApp:
    """
    The main background guard process.
    Manages the system tray icon, file watcher, and scan results.
    """

    def __init__(self, app: QApplication):
        self.app      = app
        self._signals = ScanSignals()
        self._signals.scan_result.connect(self._on_scan_result)

        # System tray
        self.tray = QSystemTrayIcon(_make_tray_icon())
        self.tray.setToolTip("HELIX — Real-time Guard Active")

        menu = QMenu()
        menu.setStyleSheet("""
            QMenu { background: #1A1A2E; color: #F1F5F9; border: 1px solid #2D2B3E; }
            QMenu::item:selected { background: #7C3AED; }
        """)
        open_act    = menu.addAction("🛡  Open Scanner")
        menu.addSeparator()
        startup_act = menu.addAction("⚡  Startup: ON")
        menu.addSeparator()
        exit_act    = menu.addAction("✕  Exit Guard")

        open_act.triggered.connect(self._open_main_window)
        exit_act.triggered.connect(self.app.quit)
        startup_act.triggered.connect(self._toggle_startup)

        self.tray.setContextMenu(menu)
        self.tray.activated.connect(self._on_tray_activated)
        self.tray.show()

        # File watcher
        self._watcher = FileWatcher()
        self._watcher.new_file.connect(self._on_new_file)
        self._watcher.start()

        self.tray.showMessage(
            "HELIX Guard",
            "Background protection active — watching Downloads, Desktop & Temp",
            QSystemTrayIcon.MessageIcon.Information,
            3000
        )

    def _on_new_file(self, filepath: str):
        name = os.path.basename(filepath)
        self.tray.showMessage(
            "HELIX — Scanning...",
            f"Checking: {name}",
            QSystemTrayIcon.MessageIcon.NoIcon,
            2000
        )
        worker = FileScanWorker(filepath, self._signals)
        worker.start()

    def _on_scan_result(self, filepath: str, score: float,
                         verdict: str, features: dict):
        name = os.path.basename(filepath)
        if score < THREAT_THRESHOLD:
            self.tray.showMessage(
                "✅  File is Safe",
                f"{name} — threat score {score*100:.0f}%",
                QSystemTrayIcon.MessageIcon.Information,
                4000
            )
            return

        # Show the malware alert dialog
        from ui.alert_dialog import MalwareAlertDialog
        dlg = MalwareAlertDialog(filepath, score, verdict, features)
        dlg.action_taken.connect(
            lambda action, fp: self._on_action(action, fp)
        )
        dlg.exec()

    def _on_action(self, action: str, fp: str):
        messages = {
            "quarantine":       "🔒  File quarantined — moved to safe folder",
            "delete":           "🗑  File deleted permanently",
            "run":              "⚠  File allowed — we'll remember your choice",
            "quarantine_error": "❌  Quarantine failed — check file permissions",
            "delete_error":     "❌  Delete failed — file may be in use",
        }
        self.tray.showMessage(
            "HELIX Guard",
            messages.get(action, action),
            QSystemTrayIcon.MessageIcon.Information,
            3000
        )

        # If user chose "Run Anyway", send a correction to the server
        # (user says this file is actually safe → improves the model for everyone)
        if action == "run":
            try:
                from ml.online_learner import OnlineLearner
                learner = OnlineLearner()
                learner.push_correction_to_server(fp, "benign")
            except Exception:
                pass  # server may be offline

    def _on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            self._open_main_window()

    def _open_main_window(self):
        from ui.main_window import MainWindow
        if not hasattr(self, "_main_window") or not self._main_window.isVisible():
            self._main_window = MainWindow()
            self._main_window.show()
        else:
            self._main_window.raise_()
            self._main_window.activateWindow()

    def _toggle_startup(self):
        from ui.startup import register_startup, unregister_startup, is_registered
        if is_registered():
            unregister_startup()
        else:
            register_startup()
