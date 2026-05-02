"""
main.py — Application entry point for MalwareSandbox AI

Modes:
  python main.py          → Launch full UI (main window)
  python main.py --tray   → Launch headless background guard (tray only)
                            Used for Windows startup auto-launch

The tray mode watches Downloads, Desktop & Temp for new EXE/DLL files,
scans them automatically, and shows a MalwareAlertDialog when threats
are detected.
"""

import sys
import os
import warnings

# Silence harmless urllib3/requests version mismatch warning
warnings.filterwarnings("ignore", message="urllib3.*doesn't match a supported version")

# Workspace root on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore    import Qt
from PyQt6.QtGui     import QFont


def main():
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )
    app = QApplication(sys.argv)
    app.setApplicationName("HELIX")
    app.setOrganizationName("HELIX Project")
    app.setFont(QFont("Segoe UI", 10))

    # Tray-only mode (startup / background guard)
    if "--tray" in sys.argv:
        app.setQuitOnLastWindowClosed(False)   # keep alive even with no window
        from ui.tray_app import TrayApp
        tray = TrayApp(app)                    # noqa: F841 — kept alive by app loop
        sys.exit(app.exec())

    # Full UI mode
    from ui.main_window import MainWindow
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
