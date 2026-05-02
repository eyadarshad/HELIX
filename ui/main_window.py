"""
main_window.py — Premium redesigned UI matching the provided template

Structure (mirrors template):
  ┌─ Header bar ────────────────────────────────────────────────┐
  │  [Logo] MalwareSandbox AI    [search]    [☀/◐ theme]      │
  ├─ Sidebar ─┬─ Content (stacked pages) ──────────────────────┤
  │  [DB]     │  Dashboard / Scanner / History / Settings       │
  │  [SC]     │                                                  │
  │  [LG]     │                                                  │
  │           │                                                  │
  │  [CF]     │                                                  │
  └───────────┴──────────────────────────────────────────────────┘

Design matches template:
  - #1A1A1A bg, #111111 sidebar, #202020 cards
  - Outlined pill buttons (border-only, rounded)
  - 56px narrow icon sidebar, active = white rounded btn
  - Clean section headers + sub-labels
  - Stat row at top, list rows below (like "Best New App" rows)
  - Light mode via reactive toggle in header
"""

from __future__ import annotations
import os, json, datetime

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QFrame,
    QLabel, QPushButton, QProgressBar, QStackedWidget,
    QFileDialog, QTableWidget, QTableWidgetItem, QHeaderView,
    QScrollArea, QSizePolicy, QApplication, QMessageBox,
    QGroupBox, QFormLayout, QLineEdit, QSpinBox, QCheckBox,
    QSpacerItem
)
from PyQt6.QtCore  import Qt, QTimer, QPropertyAnimation, QEasingCurve, pyqtSlot
from PyQt6.QtGui   import QFont, QDragEnterEvent, QDropEvent, QColor, QPixmap, QIcon, QPainter, QPainterPath, QBrush, QPen

from ui.styles          import DARK_STYLESHEET, LIGHT_STYLESHEET, DARK, LIGHT
from ui.threat_display  import ThreatDisplay
from ui.label_panel     import LabelPanel
from ui.scanner_thread  import ScannerThread
from ui.settings        import load_settings, save_settings
from features.extractor import FEATURE_NAMES

HISTORY_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "ui", ".scan_history.json"
)

MALWARE_FEATURES = {
    "int_frequency", "nop_sled_ratio", "stack_anomaly_score",
    "memory_write_density", "loop_density", "call_ret_imbalance",
    "cpuid_frequency", "rdtsc_check",
}

MAX_VALS = {
    "int_frequency": 20, "nop_sled_ratio": 1, "stack_anomaly_score": 1,
    "memory_write_density": 1, "loop_density": 1, "unique_opcodes": 50,
    "call_ret_imbalance": 20, "avg_flag_change_rate": 1,
    "register_volatility": 1, "max_stack_depth": 20,
    "control_flow_entropy": 5, "self_modify_detected": 1,
    "cpuid_frequency": 5, "rdtsc_check": 1,
}


def _load_history() -> list[dict]:
    try:
        with open(HISTORY_PATH) as f:
            return json.load(f)
    except Exception:
        return []


def _save_history(records: list[dict]):
    try:
        with open(HISTORY_PATH, "w") as f:
            json.dump(records[-500:], f, indent=2)
    except Exception:
        pass


# ── Drop zone ──────────────────────────────────────────────────────────────────

class DropZone(QFrame):
    def __init__(self, on_file, parent=None):
        super().__init__(parent)
        self.setObjectName("dropZone")
        self.setAcceptDrops(True)
        self._cb = on_file

        lay = QVBoxLayout(self)
        lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.setSpacing(8)

        arrow = QLabel("↓")
        arrow.setAlignment(Qt.AlignmentFlag.AlignCenter)
        arrow.setStyleSheet(
            "font-size: 24px; font-weight: 200; color: #7C3AED;"
            " background: transparent;"
        )

        t = QLabel("Drop an EXE or DLL here to scan")
        t.setAlignment(Qt.AlignmentFlag.AlignCenter)
        t.setStyleSheet(
            "font-size: 14px; font-weight: 600; background: transparent;"
        )

        sub = QLabel(".exe · .dll   |   supported formats · click anywhere to browse")
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub.setStyleSheet(
            "font-size: 11px; background: transparent;"
        )
        sub.setObjectName("sectionSub")

        hint = QLabel("HELIX uses static PE analysis + ML to detect threats in seconds")
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hint.setStyleSheet(
            "font-size: 10px; font-style: italic; background: transparent;"
            " color: #666666; margin-top: 2px;"
        )

        lay.addWidget(arrow)
        lay.addWidget(t)
        lay.addWidget(sub)
        lay.addWidget(hint)

    def mousePressEvent(self, e):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select File to Scan", "",
            "PE Executables (*.exe *.dll);;All Files (*)"
        )
        if path:
            self._cb(path)

    def dragEnterEvent(self, e: QDragEnterEvent):
        if e.mimeData().hasUrls():
            exts = {".exe", ".dll"}
            if any(os.path.splitext(u.toLocalFile())[1].lower() in exts
                   for u in e.mimeData().urls()):
                e.acceptProposedAction()
                self.setProperty("dragover", "true")
                self.style().unpolish(self); self.style().polish(self)

    def dragLeaveEvent(self, e):
        self.setProperty("dragover", "false")
        self.style().unpolish(self); self.style().polish(self)

    def dropEvent(self, e: QDropEvent):
        self.setProperty("dragover", "false")
        self.style().unpolish(self); self.style().polish(self)
        for url in e.mimeData().urls():
            p = url.toLocalFile()
            if os.path.splitext(p)[1].lower() in {".exe", ".dll"}:
                self._cb(p); break


# ── Feature bar ────────────────────────────────────────────────────────────────

class FeatureBar(QWidget):
    def __init__(self, name: str, t: dict, parent=None):
        super().__init__(parent)
        self._name     = name
        self._is_bad   = name in MALWARE_FEATURES
        self._theme    = t
        self._build(t)

    def _build(self, t: dict):
        while self.layout() and self.layout().count():
            item = self.layout().takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        if self.layout():
            QWidget().setLayout(self.layout())

        row = QHBoxLayout(self)
        row.setContentsMargins(0, 1, 0, 1)
        row.setSpacing(8)

        lbl = QLabel(self._name.replace("_", " ").title())
        lbl.setFixedWidth(188)
        lbl.setStyleSheet(f"color: {t['text2']}; font-size: 11px; background: transparent;")

        self._bg = QFrame()
        self._bg.setFixedHeight(5)
        self._bg.setStyleSheet(
            f"background: {t['border2']}; border-radius: 3px; border: none;"
        )
        self._bg.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._fill = QFrame(self._bg)
        self._fill.setFixedHeight(5)
        self._fill.setFixedWidth(0)

        self._val = QLabel("—")
        self._val.setFixedWidth(52)
        self._val.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self._val.setStyleSheet(
            f"color: {t['text3']}; font-size: 11px;"
            " font-family: 'Consolas', monospace; background: transparent;"
        )

        row.addWidget(lbl)
        row.addWidget(self._bg, stretch=1)
        row.addWidget(self._val)

    def set_value(self, raw: float, max_v: float, t: dict):
        norm  = min(raw / max_v, 1.0) if max_v > 0 else 0.0
        color = t['danger']  if (self._is_bad and norm > 0.3) else \
                t['warning'] if (self._is_bad and norm > 0.08) else t['success']
        QTimer.singleShot(30, lambda: self._apply(norm, raw, color))

    def _apply(self, norm, raw, color):
        w = int(self._bg.width() * norm)
        self._fill.setFixedWidth(max(w, 0))
        self._fill.setStyleSheet(
            f"background: {color}; border-radius: 3px;"
            " border: none; min-height:5px; max-height:5px;"
        )
        self._val.setText(f"{raw:.3f}" if raw < 10 else f"{int(raw)}")
        self._val.setStyleSheet(
            f"color: {color}; font-size: 11px;"
            " font-family: 'Consolas', monospace; background: transparent;"
        )

    def reset(self):
        self._fill.setFixedWidth(0)
        self._val.setText("—")


# ── Logo helper ───────────────────────────────────────────────────────────────────────

_ICON_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "ICONS", "favicon", "icon (2).png"
)


def _make_rounded_logo(path: str, size: int, radius: int = 6) -> QPixmap:
    """Load a PNG, scale with 2× oversampling for sharp edges, round corners."""
    from PyQt6.QtCore import QRectF

    # 2× oversample then scale down = much sharper at small sizes
    hi = size * 2
    src = QPixmap(path).scaled(
        hi, hi,
        Qt.AspectRatioMode.KeepAspectRatio,
        Qt.TransformationMode.SmoothTransformation,
    ).scaled(
        size, size,
        Qt.AspectRatioMode.KeepAspectRatio,
        Qt.TransformationMode.SmoothTransformation,
    )
    out = QPixmap(size, size)
    out.fill(Qt.GlobalColor.transparent)
    p = QPainter(out)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
    clip = QPainterPath()
    clip.addRoundedRect(QRectF(0, 0, size, size), radius, radius)
    p.setClipPath(clip)
    x_off = (size - src.width()) // 2
    y_off = (size - src.height()) // 2
    p.drawPixmap(x_off, y_off, src)
    p.end()
    return out


def _make_logo_pixmap(size: int = 32) -> QPixmap:
    """Load the custom HX icon, or fall back to a painted 'H' mark."""
    if os.path.exists(_ICON_PATH):
        return _make_rounded_logo(_ICON_PATH, size, radius=int(size * 0.15))

    # Fallback: painted violet square with 'H'
    from PyQt6.QtCore import QRectF
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
    return px


# ── Main Window ────────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self._dark      = True
        self._theme     = DARK
        self._settings  = load_settings()
        self._learner   = self._load_learner()
        self._scanner   = None
        self._features  = None
        self._verdict   = None
        self._filepath  = None
        self._history   = _load_history()

        self.setWindowTitle("HELIX — Malware Intelligence")
        self.setMinimumSize(980, 640)
        self.resize(1120, 720)

        # Window / taskbar icon — painted, no external file needed
        self.setWindowIcon(QIcon(_make_logo_pixmap(64)))

        self._apply_theme()
        self._build_ui()
        self._set_status("Ready — drop or browse a PE file to begin analysis")

    def _load_learner(self):
        try:
            from ml.online_learner import OnlineLearner
            return OnlineLearner()
        except Exception as e:
            print(f"[WARN] {e}")
            return None

    def _apply_theme(self):
        t = DARK if self._dark else LIGHT
        self._theme = t
        QApplication.instance().setStyleSheet(
            DARK_STYLESHEET if self._dark else LIGHT_STYLESHEET
        )

    # ── Build ──────────────────────────────────────────────────────────────────

    def _build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        vbox = QVBoxLayout(root)
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.setSpacing(0)

        vbox.addWidget(self._build_header())

        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)
        body.addWidget(self._build_sidebar())

        self._pages = QStackedWidget()
        self._pages.addWidget(self._build_dashboard())   # 0
        self._pages.addWidget(self._build_scanner())     # 1
        self._pages.addWidget(self._build_history())     # 2
        self._pages.addWidget(self._build_settings())    # 3
        body.addWidget(self._pages, stretch=1)

        vbox.addLayout(body, stretch=1)
        self._nav_to(1)

    # ── Header ─────────────────────────────────────────────────────────────────

    def _build_header(self) -> QFrame:
        bar = QFrame()
        bar.setObjectName("headerBar")
        row = QHBoxLayout(bar)
        row.setContentsMargins(12, 0, 20, 0)   # tighter left = logo closer to edge
        row.setSpacing(10)

        # Logo — painted violet rounded square with 'H'
        logo = QLabel()
        logo.setFixedSize(34, 34)
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo.setStyleSheet("background: transparent;")
        logo.setPixmap(_make_logo_pixmap(34))

        # App name + tagline column
        title_col = QVBoxLayout()
        title_col.setSpacing(1)
        t1 = QLabel("HELIX")
        t1.setObjectName("appTitle")
        t1.setStyleSheet(
            "font-size: 17px; font-weight: 800; letter-spacing: 3px;"
            " font-family: 'Segoe UI', Arial, sans-serif;"
        )
        t2 = QLabel("Heuristic Emulation Level Intelligence eXaminer")
        t2.setObjectName("appSubtitle")
        title_col.addWidget(t1)
        title_col.addWidget(t2)

        row.addWidget(logo)
        row.addSpacing(6)
        row.addLayout(title_col)
        row.addStretch()

        # Status pill
        self._status_pill = QLabel("Idle")
        self._status_pill.setObjectName("pill")
        self._status_pill.setProperty("verdict", "")
        row.addWidget(self._status_pill)

        # Theme toggle
        self._theme_btn = QPushButton("◐")
        self._theme_btn.setObjectName("themeBtn")
        self._theme_btn.setToolTip("Toggle light / dark mode")
        self._theme_btn.clicked.connect(self._toggle_theme)
        row.addWidget(self._theme_btn)

        return bar

    # ── Sidebar ────────────────────────────────────────────────────────────────

    def _build_sidebar(self) -> QFrame:
        sb = QFrame()
        sb.setObjectName("sidebar")
        lay = QVBoxLayout(sb)
        lay.setContentsMargins(8, 16, 8, 16)
        lay.setSpacing(4)
        lay.setAlignment(Qt.AlignmentFlag.AlignTop)

        self._nav_btns: list[QPushButton] = []
        nav = [("⊞", "Dashboard", 0),
               ("◆",  "Scanner",   1),
               ("≡",  "History",   2)]

        for lbl, tip, idx in nav:
            btn = self._nav_btn(lbl, tip, idx)
            self._nav_btns.append(btn)
            lay.addWidget(btn, alignment=Qt.AlignmentFlag.AlignHCenter)

        lay.addStretch()

        cfg = self._nav_btn("⊙", "Settings", 3)
        self._nav_btns.append(cfg)
        lay.addWidget(cfg, alignment=Qt.AlignmentFlag.AlignHCenter)

        return sb

    def _nav_btn(self, label: str, tip: str, idx: int) -> QPushButton:
        btn = QPushButton(label)
        btn.setObjectName("navBtn")
        btn.setToolTip(tip)
        btn.setProperty("active", "false")
        btn.clicked.connect(lambda _, i=idx: self._nav_to(i))
        return btn

    def _nav_to(self, idx: int):
        self._pages.setCurrentIndex(idx)
        for i, btn in enumerate(self._nav_btns):
            act = "true" if i == idx else "false"
            btn.setProperty("active", act)
            btn.style().unpolish(btn)
            btn.style().polish(btn)

    # ── Dashboard ──────────────────────────────────────────────────────────────

    def _build_dashboard(self) -> QWidget:
        page = QWidget()
        lay  = QVBoxLayout(page)
        lay.setContentsMargins(20, 20, 20, 16)
        lay.setSpacing(16)

        # Section title row
        hdr = self._section_header("Dashboard", "Scan statistics & recent activity", "See all",
                                    lambda: self._nav_to(2))
        lay.addLayout(hdr)

        # Stats row (like top-free row in template)
        stats = QHBoxLayout()
        stats.setSpacing(10)
        self._stat_total   = self._stat_card("Total Scans",   "0", "#7C3AED")
        self._stat_malware = self._stat_card("Threats",       "0", self._theme['danger'])
        self._stat_clean   = self._stat_card("Clean",         "0", self._theme['success'])
        self._stat_pct     = self._stat_card("Detection rate","—",  self._theme['warning'])
        for c in [self._stat_total, self._stat_malware,
                  self._stat_clean, self._stat_pct]:
            stats.addWidget(c, stretch=1)
        lay.addLayout(stats)

        # Recent scans panel (like "Best New Apps" list rows)
        recent_lbl, _ = self._section_header_pair(
            "Recent Scans", "Last 6 analyzed files"
        )
        lay.addLayout(recent_lbl)

        self._dash_panel = QFrame()
        self._dash_panel.setObjectName("panel")
        self._dash_items  = QVBoxLayout(self._dash_panel)
        self._dash_items.setContentsMargins(0, 0, 0, 0)
        self._dash_items.setSpacing(0)
        lay.addWidget(self._dash_panel)
        lay.addStretch()

        self._refresh_dashboard()
        return page

    def _section_header(self, title: str, sub: str,
                         link_text: str = "", link_cb=None) -> QHBoxLayout:
        row = QHBoxLayout()
        col = QVBoxLayout()
        col.setSpacing(2)
        t = QLabel(title); t.setObjectName("sectionHeader")
        s = QLabel(sub);   s.setObjectName("sectionSub")
        col.addWidget(t); col.addWidget(s)
        row.addLayout(col)
        row.addStretch()
        if link_text and link_cb:
            lnk = QPushButton(link_text)
            lnk.clicked.connect(link_cb)
            row.addWidget(lnk)
        return row

    def _section_header_pair(self, title: str, sub: str):
        row = QHBoxLayout()
        col = QVBoxLayout(); col.setSpacing(2)
        t = QLabel(title); t.setObjectName("sectionHeader")
        s = QLabel(sub);   s.setObjectName("sectionSub")
        col.addWidget(t); col.addWidget(s)
        row.addLayout(col); row.addStretch()
        return row, None

    def _stat_card(self, label: str, value: str, color: str) -> QFrame:
        card = QFrame(); card.setObjectName("panel")
        lay  = QVBoxLayout(card)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(3)

        v = QLabel(value); v.setObjectName("statNum")
        v.setStyleSheet(f"font-size: 28px; font-weight: 700; color: {color};"
                        " background: transparent; font-family: 'Consolas', monospace;")
        l = QLabel(label); l.setObjectName("statLbl")

        accent = QFrame()
        accent.setFixedHeight(2)
        accent.setStyleSheet(f"background: {color}; border-radius: 1px; border: none;")

        lay.addWidget(v); lay.addWidget(l); lay.addWidget(accent)
        card._val = v
        return card

    def _refresh_dashboard(self):
        total   = len(self._history)
        malware = sum(1 for r in self._history if r.get("verdict") == "malware")
        clean   = total - malware
        pct     = f"{malware/total*100:.0f}%" if total else "—"

        if hasattr(self, "_stat_total"):
            self._stat_total._val.setText(str(total))
            self._stat_malware._val.setText(str(malware))
            self._stat_clean._val.setText(str(clean))
            self._stat_pct._val.setText(pct)

        if not hasattr(self, "_dash_items"):
            return

        # Clear existing rows
        while self._dash_items.count():
            item = self._dash_items.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        recent = self._history[-6:][::-1]
        for i, rec in enumerate(recent):
            self._dash_items.addWidget(self._make_scan_row(rec))
            if i < len(recent) - 1:
                div = QFrame(); div.setObjectName("divider")
                self._dash_items.addWidget(div)

    def _make_scan_row(self, rec: dict) -> QFrame:
        row = QFrame()
        row.setObjectName("subPanel")
        row.setFixedHeight(52)
        rlay = QHBoxLayout(row)
        rlay.setContentsMargins(14, 0, 14, 0)
        rlay.setSpacing(10)

        # Colour dot
        verdict = rec.get("verdict", "?")
        dot_color = self._theme['danger']  if verdict == "malware" else \
                    self._theme['warning'] if verdict == "packed"  else \
                    self._theme['success']
        dot = QFrame()
        dot.setFixedSize(8, 8)
        dot.setStyleSheet(
            f"background: {dot_color}; border-radius: 4px; border: none;"
        )

        # Texts
        txt = QVBoxLayout(); txt.setSpacing(1)
        name = os.path.basename(rec.get("file", "?"))
        t1 = QLabel(name); t1.setObjectName("rowTitle")
        ts = rec.get("timestamp", "")[:16].replace("T", "  ")
        t2 = QLabel(ts);   t2.setObjectName("rowSub")
        txt.addWidget(t1); txt.addWidget(t2)

        # Score pill
        score   = rec.get("score", 0.0)
        pill    = QLabel(f"{score*100:.0f}%")
        pill.setObjectName("pill")
        pill.setProperty("verdict", verdict)
        pill.style().unpolish(pill); pill.style().polish(pill)

        rlay.addWidget(dot)
        rlay.addLayout(txt, stretch=1)
        rlay.addWidget(pill)
        return row

    # ── Scanner ────────────────────────────────────────────────────────────────

    def _build_scanner(self) -> QWidget:
        page = QWidget()
        lay  = QVBoxLayout(page)
        lay.setContentsMargins(20, 20, 20, 16)
        lay.setSpacing(14)

        # Header row — title + verdict pill
        hdr_row = QHBoxLayout()
        title_col = QVBoxLayout(); title_col.setSpacing(2)
        t1 = QLabel("File Scanner"); t1.setObjectName("sectionHeader")
        t2 = QLabel("Static PE analysis + ML classification + VirusTotal lookup");  t2.setObjectName("sectionSub")
        title_col.addWidget(t1); title_col.addWidget(t2)
        self._verdict_pill = QLabel("—")
        self._verdict_pill.setObjectName("pill")
        self._verdict_pill.setProperty("verdict", "")
        self._verdict_pill.setVisible(False)
        hdr_row.addLayout(title_col)
        hdr_row.addStretch()
        hdr_row.addWidget(self._verdict_pill)
        lay.addLayout(hdr_row)

        # Drop zone
        self.drop_zone = DropZone(self._on_file_selected)
        self.drop_zone.setFixedHeight(120)
        lay.addWidget(self.drop_zone)

        # File + scan row
        file_row = QHBoxLayout(); file_row.setSpacing(10)
        self._file_lbl = QLabel("")
        self._file_lbl.setObjectName("sectionSub")
        self._file_lbl.setStyleSheet("font-family: 'Consolas', monospace;")
        self.scan_btn = QPushButton("Scan")
        self.scan_btn.setObjectName("primaryBtn")
        self.scan_btn.setVisible(False)
        self.scan_btn.clicked.connect(self._start_scan)
        file_row.addWidget(self._file_lbl, stretch=1)
        file_row.addWidget(self.scan_btn)
        lay.addLayout(file_row)

        # Progress
        self._progress = QProgressBar()
        self._progress.setVisible(False)
        lay.addWidget(self._progress)

        # Results: gauge card + feature bars side by side
        results = QHBoxLayout(); results.setSpacing(14)

        gauge_panel = QFrame(); gauge_panel.setObjectName("panel")
        gauge_lay   = QVBoxLayout(gauge_panel)
        gauge_lay.setContentsMargins(16, 16, 16, 16)
        self.threat_display = ThreatDisplay()
        gauge_lay.addWidget(self.threat_display)
        gauge_panel.setFixedWidth(240)
        results.addWidget(gauge_panel)

        bars_panel = QFrame(); bars_panel.setObjectName("panel")
        bars_lay   = QVBoxLayout(bars_panel)
        bars_lay.setContentsMargins(14, 14, 14, 14)
        bars_lay.setSpacing(6)

        bl = QLabel("BEHAVIORAL FEATURES")
        bl.setObjectName("sectionSub")
        bl.setStyleSheet(f"font-size: 10px; font-weight: 700; letter-spacing: 1.5px;"
                         f" color: {self._theme['text2']}; background: transparent;")
        bars_lay.addWidget(bl)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        bars_w = QWidget(); bars_w.setStyleSheet("background: transparent;")
        self._bars_layout = QVBoxLayout(bars_w)
        self._bars_layout.setSpacing(4)
        self._bars_layout.setContentsMargins(0, 0, 4, 0)

        self._feature_bars: dict[str, FeatureBar] = {}
        for feat in FEATURE_NAMES:
            bar = FeatureBar(feat, self._theme)
            self._feature_bars[feat] = bar
            self._bars_layout.addWidget(bar)
        self._bars_layout.addStretch()

        scroll.setWidget(bars_w)
        bars_lay.addWidget(scroll)
        results.addWidget(bars_panel, stretch=1)
        lay.addLayout(results, stretch=1)

        # Label panel
        self.label_panel = LabelPanel()
        self.label_panel.scan_another.connect(self._reset_scanner)
        lay.addWidget(self.label_panel)

        return page

    # ── History ────────────────────────────────────────────────────────────────

    def _build_history(self) -> QWidget:
        page = QWidget()
        lay  = QVBoxLayout(page)
        lay.setContentsMargins(20, 20, 20, 16)
        lay.setSpacing(14)

        hdr_row = QHBoxLayout()
        col = QVBoxLayout(); col.setSpacing(2)
        t1 = QLabel("Scan History"); t1.setObjectName("sectionHeader")
        t2 = QLabel("All analyzed files — sorted by most recent")
        t2.setObjectName("sectionSub")
        col.addWidget(t1); col.addWidget(t2)
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self._clear_history)
        hdr_row.addLayout(col)
        hdr_row.addStretch()
        hdr_row.addWidget(clear_btn)
        lay.addLayout(hdr_row)

        # Empty state placeholder
        self._hist_empty = QLabel(
            "ℹ  No scans yet\n\n"
            "Go to the Scanner tab, drop a file, and hit Scan.\n"
            "Your scan results will appear here automatically."
        )
        self._hist_empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._hist_empty.setObjectName("sectionSub")
        self._hist_empty.setStyleSheet(
            "font-size: 13px; padding: 40px; color: #888;"
        )
        lay.addWidget(self._hist_empty)

        self._hist_table = QTableWidget(0, 5)
        self._hist_table.setHorizontalHeaderLabels(
            ["File", "Path", "Verdict", "Score", "Time"]
        )
        self._hist_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents)
        self._hist_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch)
        self._hist_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.Fixed)
        self._hist_table.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeMode.Fixed)
        self._hist_table.horizontalHeader().setSectionResizeMode(
            4, QHeaderView.ResizeMode.ResizeToContents)
        self._hist_table.setColumnWidth(2, 80)
        self._hist_table.setColumnWidth(3, 66)
        self._hist_table.verticalHeader().setVisible(False)
        self._hist_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._hist_table.setAlternatingRowColors(True)
        self._hist_table.setSortingEnabled(True)
        lay.addWidget(self._hist_table)

        self._rebuild_hist_table()
        return page

    # ── Settings ───────────────────────────────────────────────────────────────

    def _build_settings(self) -> QWidget:
        page = QWidget()
        lay  = QVBoxLayout(page)
        lay.setContentsMargins(20, 20, 340, 20)
        lay.setSpacing(14)

        t1 = QLabel("Settings"); t1.setObjectName("sectionHeader")
        t2 = QLabel("Customize how HELIX scans and protects your computer")
        t2.setObjectName("sectionSub")
        lay.addWidget(t1); lay.addWidget(t2)

        # ── Scan Settings ──────────────────────────────────────────────
        scan = QGroupBox("Scan Settings")
        sf  = QFormLayout(scan)

        self._instr_spin = QSpinBox()
        self._instr_spin.setRange(1000, 100000)
        self._instr_spin.setSingleStep(5000)
        self._instr_spin.setValue(self._settings.get("max_instructions", 50000))
        self._instr_spin.setSuffix(" steps")
        sf.addRow("Scan depth:", self._instr_spin)

        depth_note = QLabel("How deep HELIX looks into the file. Higher = more thorough but slower.")
        depth_note.setObjectName("sectionSub")
        depth_note.setWordWrap(True)
        sf.addRow("", depth_note)
        lay.addWidget(scan)

        # ── Cloud Sync ─────────────────────────────────────────────────
        cloud = QGroupBox("Cloud Sync")
        cf = QFormLayout(cloud)

        self._url_edit = QLineEdit(self._settings.get("server_url",
            "https://goldie-gripiest-guillermo.ngrok-free.dev"))
        self._url_edit.setPlaceholderText("Clear this field to use HELIX offline")
        cf.addRow("Server address:", self._url_edit)

        cloud_note = QLabel(
            "HELIX is connected to a shared server by default. "
            "Your corrections help improve detection for all users. "
            "Clear the address above to run in offline mode."
        )
        cloud_note.setObjectName("sectionSub")
        cloud_note.setWordWrap(True)
        cf.addRow("", cloud_note)
        lay.addWidget(cloud)

        # ── Background Protection ──────────────────────────────────────
        guard = QGroupBox("Background Protection")
        gl = QVBoxLayout(guard)
        self._startup_cb = QCheckBox("Start HELIX when Windows starts")
        try:
            from ui.startup import is_registered
            self._startup_cb.setChecked(is_registered())
        except Exception:
            pass
        self._startup_cb.stateChanged.connect(self._toggle_startup)
        guard_note = QLabel(
            "When enabled, HELIX runs in your system tray and automatically scans "
            "any new files that appear in your Downloads, Desktop, or Temp folders."
        )
        guard_note.setObjectName("sectionSub")
        guard_note.setWordWrap(True)
        gl.addWidget(self._startup_cb)
        gl.addWidget(guard_note)
        lay.addWidget(guard)

        # ── Save button ────────────────────────────────────────────────
        save = QPushButton("Save Settings")
        save.setObjectName("primaryBtn")
        save.clicked.connect(self._save_settings_page)
        lay.addWidget(save, alignment=Qt.AlignmentFlag.AlignLeft)
        lay.addStretch()
        return page

    # ── Theme toggle ───────────────────────────────────────────────────────────

    def _toggle_theme(self):
        self._dark = not self._dark
        self._theme_btn.setText("◐" if self._dark else "☀")
        self._apply_theme()
        # Refresh feature bars with new theme colours
        for bar in self._feature_bars.values():
            bar._theme = self._theme

    # ── Scanner logic ──────────────────────────────────────────────────────────

    def _on_file_selected(self, path: str):
        self._filepath = path
        name = os.path.basename(path)
        sz   = os.path.getsize(path) // 1024
        self._file_lbl.setText(f"{name}  ·  {sz} KB")
        self.scan_btn.setVisible(True)
        self.label_panel.hide_panel()
        self.threat_display.reset()
        self._reset_feature_bars()
        self._verdict_pill.setVisible(False)
        self._status_pill.setText("Ready")
        self._nav_to(1)
        self._set_status(f"Selected: {name}")

    def _start_scan(self):
        if not self._filepath:
            return
        self.scan_btn.setEnabled(False)
        self._progress.setVisible(True)
        self._progress.setRange(0, 0)
        self.label_panel.hide_panel()
        self.threat_display.show_scanning()
        self._reset_feature_bars()
        self._verdict_pill.setVisible(False)
        self._status_pill.setText("Scanning…")

        self._scanner = ScannerThread(
            self._filepath,
            self._settings.get("max_instructions", 3000)
        )
        self._scanner.progress.connect(self._on_progress)
        self._scanner.status.connect(self._set_status)
        self._scanner.result.connect(self._on_scan_result)
        self._scanner.error.connect(self._on_scan_error)
        self._scanner.start()

    @pyqtSlot(int)
    def _on_progress(self, v: int):
        if v == 0:
            self._progress.setRange(0, 0)
        else:
            self._progress.setRange(0, 100)
            self._progress.setValue(v)

    @pyqtSlot(dict, list)
    def _on_scan_result(self, features: dict, opcodes: list):
        self._features = features
        self._progress.setVisible(False)
        self.scan_btn.setEnabled(True)

        score, verdict = self._classify(features)
        self._verdict  = verdict

        self.threat_display.show_result(score, verdict)

        labels = {"malware": "THREAT", "benign": "CLEAN", "packed": "PACKED"}
        self._verdict_pill.setText(labels.get(verdict, verdict.upper()))
        self._verdict_pill.setProperty("verdict", verdict)
        self._verdict_pill.style().unpolish(self._verdict_pill)
        self._verdict_pill.style().polish(self._verdict_pill)
        self._verdict_pill.setVisible(True)
        self._status_pill.setText(verdict.upper())
        self._status_pill.setProperty("verdict", verdict)
        self._status_pill.style().unpolish(self._status_pill)
        self._status_pill.style().polish(self._status_pill)

        # Feature bars
        for feat, bar in self._feature_bars.items():
            val  = features.get(feat, 0.0)
            maxv = MAX_VALS.get(feat, 1.0)
            bar.set_value(float(val), float(maxv), self._theme)

        self.label_panel.setup(features, verdict, self._learner)

        rec = {
            "file": self._filepath, "verdict": verdict,
            "score": score, "timestamp": datetime.datetime.now().isoformat(),
            "opcodes": len(opcodes),
        }
        self._history.append(rec)
        _save_history(self._history)
        self._refresh_dashboard()
        self._rebuild_hist_table()

        name = os.path.basename(self._filepath)
        self._set_status(
            f"{name}  →  {verdict.upper()}  ({score*100:.1f}%)  "
            f"·  {len(opcodes)} instructions"
        )

    @pyqtSlot(str)
    def _on_scan_error(self, msg: str):
        self._progress.setVisible(False)
        self.scan_btn.setEnabled(True)
        self.threat_display.reset()
        self._status_pill.setText("Error")

        if "packed" in msg.lower() or "encrypt" in msg.lower():
            self._verdict_pill.setText("PACKED")
            self._verdict_pill.setProperty("verdict", "packed")
            self._verdict_pill.style().unpolish(self._verdict_pill)
            self._verdict_pill.style().polish(self._verdict_pill)
            self._verdict_pill.setVisible(True)
            self.threat_display.show_result(0.70, "malware")
            self._set_status("Packed/encrypted binary — scored 70% (suspicious)")
            packed_feats = {f: 0.0 for f in FEATURE_NAMES}
            packed_feats["nop_sled_ratio"] = 0.7
            self.label_panel.setup(packed_feats, "malware", self._learner)
        else:
            self._set_status(f"Error: {msg.split(chr(10))[0]}")
            QMessageBox.critical(self, "Scan Error", msg)

    def _classify(self, features: dict) -> tuple[float, str]:
        if self._learner:
            try:
                vec   = [features.get(f, 0.0) for f in FEATURE_NAMES]
                score = float(self._learner.predict_proba(vec))
                label = self._learner.predict(vec)
                return score, label
            except Exception:
                pass
        bad = (features.get("int_frequency", 0) > 2.0 or
               features.get("nop_sled_ratio", 0) > 0.3 or
               features.get("stack_anomaly_score", 0) > 0.7)
        return (0.8, "malware") if bad else (0.15, "benign")

    def _reset_scanner(self):
        self.threat_display.reset()
        self._reset_feature_bars()
        self.label_panel.hide_panel()
        self._file_lbl.setText("")
        self._verdict_pill.setVisible(False)
        self.scan_btn.setVisible(False)
        self._progress.setVisible(False)
        self._filepath = None
        self._status_pill.setText("Idle")
        self._set_status("Ready — drop or browse a file to scan")

    def _reset_feature_bars(self):
        for bar in self._feature_bars.values():
            bar.reset()

    # ── History table ──────────────────────────────────────────────────────────

    def _rebuild_hist_table(self):
        if not hasattr(self, "_hist_table"):
            return
        records = self._history[::-1]

        # Toggle empty state vs table
        if hasattr(self, "_hist_empty"):
            self._hist_empty.setVisible(len(records) == 0)
            self._hist_table.setVisible(len(records) > 0)

        self._hist_table.setRowCount(len(records))
        for row, rec in enumerate(records):
            name    = os.path.basename(rec.get("file", "?"))
            path    = rec.get("file", "")
            verdict = rec.get("verdict", "?")
            score   = rec.get("score", 0.0)
            ts      = rec.get("timestamp", "")[:16].replace("T", " ")

            self._hist_table.setItem(row, 0, QTableWidgetItem(name))
            self._hist_table.setItem(row, 1, QTableWidgetItem(path))
            v_item = QTableWidgetItem(verdict.upper())
            col = (self._theme['danger']  if verdict == "malware" else
                   self._theme['warning'] if verdict == "packed"  else
                   self._theme['success'])
            v_item.setForeground(QColor(col))
            self._hist_table.setItem(row, 2, v_item)
            self._hist_table.setItem(row, 3, QTableWidgetItem(f"{score*100:.0f}%"))
            self._hist_table.setItem(row, 4, QTableWidgetItem(ts))

    def _clear_history(self):
        self._history = []
        _save_history([])
        self._refresh_dashboard()
        self._rebuild_hist_table()

    # ── Settings helpers ───────────────────────────────────────────────────────

    def _save_settings_page(self):
        self._settings["server_url"]       = self._url_edit.text().strip()
        self._settings["max_instructions"] = self._instr_spin.value()
        save_settings(self._settings)
        self._set_status("Settings saved.")

    def _toggle_startup(self, state: int):
        try:
            from ui.startup import register_startup, unregister_startup
            if state == Qt.CheckState.Checked.value:
                register_startup()
            else:
                unregister_startup()
        except Exception:
            pass

    # ── Status ─────────────────────────────────────────────────────────────────

    def _set_status(self, msg: str):
        self.statusBar().showMessage(f"  {msg}")
