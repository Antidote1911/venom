#pragma once
#include <QString>

namespace VenomStyle {

inline QString darkStyleSheet() {
    return R"(
QWidget {
    background-color: #12121a;
    color: #dcdce6;
    font-family: "Segoe UI", "SF Pro Text", "Noto Sans", sans-serif;
    font-size: 13px;
}
QMainWindow, QDialog {
    background-color: #12121a;
}
/* ── Buttons ── */
QPushButton {
    background-color: #1e1e2c;
    color: #dcdce6;
    border: 1px solid #373746;
    border-radius: 6px;
    padding: 6px 14px;
    min-height: 28px;
}
QPushButton:hover  { background-color: #2a2a3c; border-color: #5ab0ff; }
QPushButton:pressed{ background-color: #373752; }
QPushButton[primary="true"] {
    background-color: #3778d2;
    border-color: #4a90e2;
    color: #ffffff;
    font-weight: bold;
}
QPushButton[primary="true"]:hover { background-color: #4a90e2; }
QPushButton[danger="true"] {
    background-color: #8b3232;
    border-color: #b05050;
    color: #ffffff;
}
QPushButton[danger="true"]:hover { background-color: #aa4040; }
QPushButton:disabled { background-color: #1a1a24; color: #55556a; border-color: #252535; }
/* ── Inputs ── */
QLineEdit, QComboBox, QSpinBox {
    background-color: #1a1a28;
    border: 1px solid #373746;
    border-radius: 5px;
    padding: 5px 8px;
    color: #dcdce6;
    selection-background-color: #3778d2;
}
QLineEdit:focus, QComboBox:focus {
    border-color: #5ab0ff;
}
QComboBox::drop-down { border: none; width: 22px; }
QComboBox::down-arrow { image: none; border-left: 4px solid transparent;
    border-right: 4px solid transparent; border-top: 5px solid #9090a0; margin-right: 6px; }
QComboBox QAbstractItemView {
    background-color: #1e1e2e;
    border: 1px solid #444;
    selection-background-color: #3778d2;
}
/* ── Labels ── */
QLabel { background: transparent; }
QLabel[section="true"] { color: #8080a0; font-size: 11px; font-weight: bold; }
QLabel[accent="true"]  { color: #5ab0ff; }
QLabel[success="true"] { color: #50c878; }
QLabel[warn="true"]    { color: #f0be3c; }
QLabel[error="true"]   { color: #dc5050; }
/* ── Frames / cards ── */
QFrame[card="true"] {
    background-color: #1e1e2c;
    border: 1px solid #373746;
    border-radius: 8px;
}
QFrame[card_selected="true"] {
    background-color: #192840;
    border: 1.5px solid #5ab0ff;
    border-radius: 8px;
}
/* ── Checkboxes ── */
QCheckBox::indicator {
    width: 16px; height: 16px;
    border: 1px solid #555566;
    border-radius: 4px;
    background: #1a1a28;
}
QCheckBox::indicator:checked {
    background-color: #3778d2;
    border-color: #5ab0ff;
    image: none;
}
/* ── Radio buttons ── */
QRadioButton::indicator {
    width: 14px; height: 14px;
    border: 1px solid #555566;
    border-radius: 7px;
    background: #1a1a28;
}
QRadioButton::indicator:checked {
    background-color: #3778d2;
    border-color: #5ab0ff;
}
/* ── Scroll bars ── */
QScrollBar:vertical { background: #12121a; width: 8px; margin: 0; }
QScrollBar::handle:vertical { background: #373746; border-radius: 4px; min-height: 20px; }
QScrollBar::handle:vertical:hover { background: #5a5a70; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal { background: #12121a; height: 8px; }
QScrollBar::handle:horizontal { background: #373746; border-radius: 4px; min-width: 20px; }
/* ── Separator ── */
QFrame[frameShape="4"], QFrame[frameShape="5"] { color: #2e2e40; }
/* ── Tab bar (for dialogs with tabs) ── */
QTabBar::tab {
    background: #1a1a28; color: #8080a0;
    padding: 7px 18px; border-bottom: 2px solid transparent;
}
QTabBar::tab:selected { color: #5ab0ff; border-bottom-color: #5ab0ff; background: #12121a; }
QTabWidget::pane { border: 1px solid #2e2e40; }
/* ── Status bar ── */
QStatusBar { background: #0e0e18; color: #6060a0; border-top: 1px solid #2e2e40; }
/* ── Tool tips ── */
QToolTip { background: #2a2a3c; color: #dcdce6; border: 1px solid #5ab0ff; padding: 4px; }
)";
}

// Accent colours for programmatic use
namespace Color {
    constexpr auto BG       = "#12121a";
    constexpr auto PANEL    = "#1e1e2c";
    constexpr auto BORDER   = "#373746";
    constexpr auto ACCENT   = "#5ab0ff";
    constexpr auto SUCCESS  = "#50c878";
    constexpr auto WARN     = "#f0be3c";
    constexpr auto ERROR_C  = "#dc5050";
    constexpr auto TEXT     = "#dcdce6";
    constexpr auto MUTED    = "#8080a0";
    constexpr auto PURPLE   = "#b478f0";
}

} // namespace VenomStyle
