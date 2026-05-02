"""
styles.py — Dark/Light theme system matching the uploaded template

Template reference:
  - Dark bg:    #1A1A1A (main), #111111 (sidebar), #202020 (cards)
  - Light bg:   #F2F2F2 (main), #E5E5E5 (sidebar), #FFFFFF (cards)
  - Borders:    #2A2A2A dark / #D8D8D8 light
  - Text:       #FFFFFF / #111111  secondary: #888888 / #666666
  - Accent:     #7C3AED (violet — brand colour)
  - Pill btns:  outlined, no fill, 20px radius
  - Sidebar:    48px wide icon strip with active indicator
"""

# ── colour tokens ──────────────────────────────────────────────────────────────

DARK = {
    "bg":          "#1A1A1A",
    "sidebar":     "#111111",
    "card":        "#202020",
    "card2":       "#282828",
    "border":      "#2A2A2A",
    "border2":     "#333333",
    "text":        "#FFFFFF",
    "text2":       "#888888",
    "text3":       "#555555",
    "accent":      "#7C3AED",
    "accent_dim":  "#3D1F7A",
    "danger":      "#EF4444",
    "success":     "#22C55E",
    "warning":     "#F59E0B",
    "hover":       "#2A2A2A",
    "active_nav":  "#FFFFFF",
    "active_text": "#111111",
    "pill_border": "#444444",
}

LIGHT = {
    "bg":          "#F2F2F2",
    "sidebar":     "#E5E5E5",
    "card":        "#FFFFFF",
    "card2":       "#F8F8F8",
    "border":      "#D8D8D8",
    "border2":     "#E0E0E0",
    "text":        "#111111",
    "text2":       "#666666",
    "text3":       "#999999",
    "accent":      "#7C3AED",
    "accent_dim":  "#EEE5FF",
    "danger":      "#DC2626",
    "success":     "#16A34A",
    "warning":     "#D97706",
    "hover":       "#EBEBEB",
    "active_nav":  "#111111",
    "active_text": "#FFFFFF",
    "pill_border": "#BBBBBB",
}


def make_stylesheet(t: dict) -> str:
    return f"""
/* ── Global ──────────────────────────────────────────────────────── */
* {{
    font-family: -apple-system, 'Segoe UI', 'Inter', Arial, sans-serif;
    font-size: 13px;
    outline: none;
}}
QWidget {{
    background: {t['bg']};
    color: {t['text']};
    border: none;
}}
QMainWindow, QDialog {{
    background: {t['bg']};
}}

/* ── Header bar ─────────────────────────────────────────────────── */
QFrame#headerBar {{
    background: {t['card']};
    border-bottom: 1px solid {t['border']};
    min-height: 56px;
    max-height: 56px;
}}
QLabel#appTitle {{
    font-size: 17px;
    font-weight: 700;
    color: {t['text']};
    letter-spacing: -0.3px;
}}
QLabel#appSubtitle {{
    font-size: 11px;
    color: {t['text2']};
}}

/* ── Sidebar ─────────────────────────────────────────────────────── */
QFrame#sidebar {{
    background: {t['sidebar']};
    border-right: 1px solid {t['border']};
    min-width: 56px;
    max-width: 56px;
}}
QPushButton#navBtn {{
    background: transparent;
    border: none;
    border-radius: 12px;
    color: {t['text2']};
    font-size: 15px;
    font-weight: 600;
    font-family: 'Segoe UI', 'SF Symbols', sans-serif;
    min-width: 44px;
    max-width: 44px;
    min-height: 44px;
    max-height: 44px;
    padding: 0;
}}
QPushButton#navBtn:hover {{
    background: {t['hover']};
    color: {t['text']};
}}
QPushButton#navBtn[active="true"] {{
    background: {t['active_nav']};
    color: {t['active_text']};
}}

/* ── Content panels ─────────────────────────────────────────────── */
QFrame#panel {{
    background: {t['card']};
    border: 1px solid {t['border']};
    border-radius: 14px;
}}
QFrame#panelFlat {{
    background: {t['card']};
    border-radius: 14px;
}}
QFrame#subPanel {{
    background: {t['card2']};
    border: 1px solid {t['border2']};
    border-radius: 10px;
}}
QFrame#divider {{
    background: {t['border']};
    min-height: 1px;
    max-height: 1px;
}}

/* ── Labels ──────────────────────────────────────────────────────── */
QLabel {{ background: transparent; color: {t['text']}; }}
QLabel#sectionHeader {{
    font-size: 16px;
    font-weight: 700;
    color: {t['text']};
}}
QLabel#sectionSub {{
    font-size: 11px;
    color: {t['text2']};
}}
QLabel#statNum {{
    font-size: 28px;
    font-weight: 700;
    color: {t['text']};
    font-family: 'Consolas', monospace;
}}
QLabel#statLbl {{
    font-size: 11px;
    color: {t['text2']};
    letter-spacing: 0.3px;
}}
QLabel#rowTitle {{
    font-size: 13px;
    font-weight: 600;
    color: {t['text']};
}}
QLabel#rowSub {{
    font-size: 11px;
    color: {t['text2']};
}}
QLabel#pill {{
    font-size: 11px;
    font-weight: 600;
    padding: 5px 14px;
    border-radius: 12px;
    border: 1px solid {t['pill_border']};
    color: {t['text']};
    min-height: 16px;
    max-height: 22px;
}}
QLabel#pill[verdict="malware"] {{
    color: {t['danger']};
    border-color: {t['danger']};
}}
QLabel#pill[verdict="benign"] {{
    color: {t['success']};
    border-color: {t['success']};
}}
QLabel#pill[verdict="packed"] {{
    color: {t['warning']};
    border-color: {t['warning']};
}}
QLabel#accentLabel {{
    font-size: 11px;
    color: {t['accent']};
    font-weight: 600;
}}

/* ── Buttons ─────────────────────────────────────────────────────── */
QPushButton {{
    background: transparent;
    color: {t['text']};
    border: 1px solid {t['pill_border']};
    border-radius: 18px;
    padding: 6px 16px;
    font-size: 12px;
    font-weight: 600;
    min-height: 30px;
}}
QPushButton:hover {{
    border-color: {t['text2']};
    color: {t['text']};
}}
QPushButton:pressed {{
    background: {t['hover']};
}}
QPushButton#primaryBtn {{
    background: {t['accent']};
    color: #FFFFFF;
    border: none;
    border-radius: 18px;
    font-size: 13px;
    font-weight: 700;
    padding: 9px 28px;
    min-height: 38px;
    letter-spacing: 0.3px;
}}
QPushButton#primaryBtn:hover {{
    background: #6D28D9;
}}
QPushButton#primaryBtn:disabled {{
    background: {t['border']};
    color: {t['text3']};
}}
QPushButton#iconBtn {{
    background: transparent;
    border: 1px solid {t['border2']};
    border-radius: 10px;
    padding: 6px;
    color: {t['text2']};
    font-size: 15px;
    min-width: 34px;
    max-width: 34px;
    min-height: 34px;
    max-height: 34px;
}}
QPushButton#iconBtn:hover {{
    background: {t['hover']};
    color: {t['text']};
    border-color: {t['text2']};
}}
QPushButton#correctBtn {{
    border-color: {t['success']};
    color: {t['success']};
}}
QPushButton#correctBtn:hover {{
    background: rgba(34, 197, 94, 0.08);
}}
QPushButton#fpBtn {{
    border-color: {t['danger']};
    color: {t['danger']};
}}
QPushButton#fpBtn:hover {{
    background: rgba(239, 68, 68, 0.08);
}}

/* ── Theme toggle ────────────────────────────────────────────────── */
QPushButton#themeBtn {{
    background: {t['card2']};
    border: 1px solid {t['border']};
    border-radius: 16px;
    min-width: 52px;
    max-width: 52px;
    min-height: 28px;
    max-height: 28px;
    font-size: 14px;
    padding: 0;
}}
QPushButton#themeBtn:hover {{
    border-color: {t['accent']};
}}

/* ── Drop zone ───────────────────────────────────────────────────── */
QFrame#dropZone {{
    background: {t['card2']};
    border: 1.5px dashed {t['border2']};
    border-radius: 14px;
    min-height: 130px;
}}
QFrame#dropZone:hover {{
    border-color: {t['accent']};
    background: rgba(124,58,237,0.04);
}}
QFrame#dropZone[dragover="true"] {{
    border-color: {t['accent']};
    background: rgba(124,58,237,0.08);
}}

/* ── Progress bar ────────────────────────────────────────────────── */
QProgressBar {{
    background: {t['border']};
    border: none;
    border-radius: 2px;
    min-height: 3px;
    max-height: 3px;
    text-align: center;
    color: transparent;
}}
QProgressBar::chunk {{
    background: {t['accent']};
    border-radius: 2px;
}}

/* ── Table ───────────────────────────────────────────────────────── */
QTableWidget {{
    background: transparent;
    alternate-background-color: {t['card2']};
    gridline-color: {t['border']};
    border: none;
    selection-background-color: {t['hover']};
    outline: none;
}}
QTableWidget::item {{
    padding: 8px 12px;
    color: {t['text']};
}}
QTableWidget::item:selected {{
    background: {t['hover']};
}}
QHeaderView::section {{
    background: {t['card']};
    color: {t['text2']};
    padding: 7px 12px;
    border: none;
    border-bottom: 1px solid {t['border']};
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 1.5px;
    text-transform: uppercase;
}}

/* ── Scrollbar ───────────────────────────────────────────────────── */
QScrollBar:vertical {{
    background: transparent;
    width: 5px;
    border: none;
}}
QScrollBar::handle:vertical {{
    background: {t['border2']};
    border-radius: 3px;
    min-height: 20px;
}}
QScrollBar::handle:vertical:hover {{ background: {t['text2']}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal {{ height: 5px; background: transparent; border: none; }}
QScrollBar::handle:horizontal {{
    background: {t['border2']};
    border-radius: 3px;
    min-width: 20px;
}}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}

/* ── Input fields ────────────────────────────────────────────────── */
QLineEdit, QSpinBox {{
    background: {t['card2']};
    border: 1px solid {t['border']};
    border-radius: 8px;
    padding: 7px 12px;
    color: {t['text']};
    selection-background-color: {t['accent']};
}}
QLineEdit:focus, QSpinBox:focus {{ border-color: {t['accent']}; }}
QSpinBox::up-button, QSpinBox::down-button {{
    background: {t['hover']};
    border: none;
    width: 18px;
    border-radius: 4px;
}}
QCheckBox {{
    color: {t['text2']};
    spacing: 8px;
}}
QCheckBox::indicator {{
    width: 17px;
    height: 17px;
    border: 1px solid {t['border2']};
    border-radius: 5px;
    background: {t['card2']};
}}
QCheckBox::indicator:checked {{
    background: {t['accent']};
    border-color: {t['accent']};
}}
QGroupBox {{
    border: 1px solid {t['border']};
    border-radius: 10px;
    margin-top: 14px;
    padding: 12px;
    color: {t['text2']};
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 1.5px;
    text-transform: uppercase;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 6px;
}}

/* ── Status bar ──────────────────────────────────────────────────── */
QStatusBar {{
    background: {t['card']};
    color: {t['text2']};
    border-top: 1px solid {t['border']};
    font-size: 11px;
    padding: 0 12px;
    min-height: 26px;
}}

/* ── Tooltip ─────────────────────────────────────────────────────── */
QToolTip {{
    background: {t['card']};
    color: {t['text']};
    border: 1px solid {t['border2']};
    padding: 5px 9px;
    border-radius: 6px;
    font-size: 12px;
}}
"""


DARK_STYLESHEET  = make_stylesheet(DARK)
LIGHT_STYLESHEET = make_stylesheet(LIGHT)

# Legacy compat
DARK_THEME = DARK_STYLESHEET
