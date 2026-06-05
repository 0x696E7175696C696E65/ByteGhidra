"""
Destiny 2 Private Server — Control Panel
==========================================
PyQt6 GUI for managing all server components.

Features:
  - Start/stop each server component independently
  - Real-time log viewer with color coding
  - Live connection monitor (API requests + relay sessions)
  - Player list with session info
  - Database browser (accounts, characters, items)
  - Memory patch launcher
  - Config editor

Requirements:
    pip install PyQt6 psutil requests

Usage:
    python gui.py
"""

import sys
import os
import time
import json
import logging
import threading
import subprocess
import sqlite3
import queue

import psutil
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTextEdit, QTableWidget, QTableWidgetItem,
    QTabWidget, QGroupBox, QStatusBar, QHeaderView, QSplitter,
    QLineEdit, QComboBox, QCheckBox, QSpinBox, QFormLayout,
    QMessageBox, QFileDialog, QProgressBar, QFrame, QScrollArea,
    QAbstractItemView, QTreeWidget, QTreeWidgetItem,
)
from PyQt6.QtCore import (
    Qt, QTimer, QThread, pyqtSignal, pyqtSlot, QSettings
)
from PyQt6.QtGui import (
    QColor, QFont, QTextCursor, QPalette, QIcon, QPixmap,
    QSyntaxHighlighter, QTextCharFormat, QBrush
)

# ── Constants ─────────────────────────────────────────────────────────────────

APP_NAME    = "D2 Private Server"
APP_VERSION = "1.0.0"
DB_PATH     = os.path.join(os.path.dirname(__file__), "d2_private.db")
SETTINGS    = QSettings("D2RE", "PrivateServer")

DARK_BG     = "#101114"
DARK_PANEL  = "#171a1f"
DARK_CARD   = "#232832"
ACCENT      = "#7aa2f7"
ACCENT2     = "#2d3642"
TEXT_MAIN   = "#e5e7eb"
TEXT_DIM    = "#8b949e"
GREEN       = "#7ee787"
YELLOW      = "#d29922"
RED         = "#ff7b72"
BLUE        = "#79c0ff"
ORANGE      = "#d18616"
LED_OFF     = "#3a3f47"

STYLE = """
QMainWindow, QWidget {{
    background-color: {bg};
    color: {text};
    font-family: 'Segoe UI', sans-serif;
    font-size: 12px;
}}
QTabWidget::pane {{
    border: 1px solid {accent2};
    background-color: {panel};
    border-radius: 6px;
}}
QTabBar::tab {{
    background-color: transparent;
    color: {dim};
    padding: 8px 18px;
    border: none;
    border-bottom: 2px solid transparent;
    min-width: 100px;
}}
QTabBar::tab:selected {{
    color: {text};
    background-color: {card};
    border-bottom: 2px solid {accent};
}}
QTabBar::tab:hover {{
    color: {text};
    background-color: {accent2};
}}
QGroupBox {{
    border: 1px solid {accent2};
    border-radius: 6px;
    margin-top: 14px;
    padding: 10px;
    color: {dim};
    font-size: 11px;
    font-weight: bold;
    letter-spacing: 1px;
    text-transform: uppercase;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 6px;
    background-color: {bg};
}}
QPushButton {{
    background-color: {card};
    color: {text};
    border: 1px solid {accent2};
    border-radius: 4px;
    padding: 6px 16px;
    font-size: 12px;
}}
QPushButton:hover {{
    background-color: {accent2};
    border-color: {accent};
}}
QPushButton:pressed {{
    background-color: #334b6d;
    border-color: {accent};
}}
QPushButton:disabled {{
    color: {dim};
    background-color: {panel};
}}
QPushButton#start {{
    background-color: #14251b;
    border-color: {green};
    color: {green};
    font-weight: bold;
}}
QPushButton#start:hover {{
    background-color: #183321;
}}
QPushButton#stop {{
    background-color: #2a1718;
    border-color: {red};
    color: {red};
    font-weight: bold;
}}
QPushButton#stop:hover {{
    background-color: #3a1e20;
}}
QPushButton#patch {{
    background-color: #182433;
    border-color: {blue};
    color: {blue};
    font-weight: bold;
}}
QPushButton#patch:hover {{
    background-color: #20344a;
}}
QTextEdit, QLineEdit {{
    background-color: {panel};
    color: {text};
    border: 1px solid {accent2};
    border-radius: 4px;
    padding: 4px 8px;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 11px;
}}
QTableWidget {{
    background-color: {panel};
    color: {text};
    border: 1px solid {accent2};
    gridline-color: {accent2};
    selection-background-color: #29313d;
    selection-color: {text};
}}
QTableWidget::item {{
    padding: 4px 8px;
    border: none;
}}
QHeaderView::section {{
    background-color: {bg};
    color: {dim};
    padding: 6px 8px;
    border: none;
    border-bottom: 1px solid {accent2};
    font-size: 11px;
    font-weight: bold;
    letter-spacing: 1px;
    text-transform: uppercase;
}}
QScrollBar:vertical {{
    background: {panel};
    width: 8px;
    border: none;
}}
QScrollBar::handle:vertical {{
    background: {accent2};
    border-radius: 4px;
    min-height: 20px;
}}
QScrollBar::handle:vertical:hover {{
    background: {accent};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
}}
QStatusBar {{
    background-color: {bg};
    color: {dim};
    border-top: 1px solid {accent2};
}}
QSpinBox, QComboBox {{
    background-color: {panel};
    color: {text};
    border: 1px solid {accent2};
    border-radius: 4px;
    padding: 4px 8px;
}}
QCheckBox {{
    color: {text};
    spacing: 6px;
}}
QCheckBox::indicator {{
    width: 14px;
    height: 14px;
    border: 1px solid {accent2};
    border-radius: 3px;
    background: {panel};
}}
QCheckBox::indicator:checked {{
    background: {accent};
    border-color: {accent};
}}
QTreeWidget {{
    background-color: {panel};
    color: {text};
    border: 1px solid {accent2};
}}
QSplitter::handle {{
    background: {accent2};
    width: 2px;
    height: 2px;
}}
""".format(bg=DARK_BG, panel=DARK_PANEL, card=DARK_CARD,
           accent=ACCENT, accent2=ACCENT2, text=TEXT_MAIN,
           dim=TEXT_DIM, green=GREEN, red=RED, blue=BLUE)

# ── Log Handler ───────────────────────────────────────────────────────────────

class QueueHandler(logging.Handler):
    def __init__(self, log_queue):
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record):
        self.log_queue.put(self.format(record))

# ── Server Thread ─────────────────────────────────────────────────────────────

class ServerThread(QThread):
    log_signal     = pyqtSignal(str, str)   # (message, level)
    status_signal  = pyqtSignal(str, bool)  # (component, running)
    api_request_signal = pyqtSignal(str, str, int, int)  # method, path, status, duration_ms

    def __init__(self, component, config):
        super().__init__()
        self.component = component
        self.config    = config
        self._stop     = threading.Event()
        self._server   = None

    def run(self):
        self.status_signal.emit(self.component, True)
        self.log_signal.emit(
            "[{}] Starting...".format(self.component), "INFO")
        try:
            if self.component == "api":
                self._run_api()
            elif self.component == "relay":
                self._run_relay()
            elif self.component == "proxy":
                self._run_proxy()
        except Exception as e:
            self.log_signal.emit(
                "[{}] Error: {}".format(self.component, e), "ERROR")
        finally:
            self.status_signal.emit(self.component, False)
            self.log_signal.emit(
                "[{}] Stopped.".format(self.component), "WARN")

    def _run_api(self):
        sys.path.insert(0, os.path.dirname(__file__))
        from flask import g, request
        from api.bungie_api import create_api_app
        app = create_api_app(db_path=self.config.get("db_path", DB_PATH))
        host = self.config.get("host", "0.0.0.0")
        port = self.config.get("api_port", 8443)
        cert_path = os.path.join(os.path.dirname(__file__), "certs", "server.crt")
        key_path  = os.path.join(os.path.dirname(__file__), "certs", "server.key")

        @app.before_request
        def _track_request_start():
            g.gui_request_started_at = time.time()

        @app.after_request
        def _track_request_done(response):
            started_at = getattr(g, "gui_request_started_at", time.time())
            duration_ms = int((time.time() - started_at) * 1000)
            self.api_request_signal.emit(
                request.method, request.full_path.rstrip("?"),
                response.status_code, duration_ms)
            return response

        self.log_signal.emit(
            "[API] Listening on {}:{}".format(host, port), "INFO")
        if os.path.exists(cert_path) and os.path.exists(key_path):
            import ssl
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert_path, key_path)
            self.log_signal.emit("[API] TLS enabled", "INFO")
            app.run(host=host, port=port, ssl_context=ctx, threaded=True,
                    use_reloader=False, debug=False)
        else:
            self.log_signal.emit(
                "[API] TLS certs missing; run GEN CERTS before starting the game",
                "WARN")
            app.run(host=host, port=port, threaded=True, use_reloader=False,
                    debug=False)

    def _run_relay(self):
        sys.path.insert(0, os.path.dirname(__file__))
        from relay.udp_relay import RelayServer
        host  = self.config.get("host", "0.0.0.0")
        port  = self.config.get("relay_port", 7777)
        self._server = RelayServer(host, port)
        self.log_signal.emit(
            "[RELAY] UDP listening on {}:{}".format(host, port), "INFO")
        self._server.run()

    def _run_proxy(self):
        sys.path.insert(0, os.path.dirname(__file__))
        from proxy.winhttp_proxy import start_proxy
        host      = self.config.get("host", "0.0.0.0")
        port      = self.config.get("proxy_port", 8080)
        api_port  = self.config.get("api_port", 8443)
        self.log_signal.emit(
            "[PROXY] Installing redirects. Proxy on {}:{}".format(host, port), "INFO")
        start_proxy(host, port, api_port)

    def stop(self):
        self._stop.set()
        if self._server:
            try: self._server.stop()
            except Exception: pass
        self.terminate()

# ── Status LED ────────────────────────────────────────────────────────────────

class StatusLED(QLabel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(12, 12)
        self.set_state(False)

    def set_state(self, running):
        color = GREEN if running else LED_OFF
        border = "#2f5137" if running else ACCENT2
        self.setStyleSheet("""
            background-color: {};
            border-radius: 6px;
            border: 1px solid {};
        """.format(color, border))

# ── Server Card ───────────────────────────────────────────────────────────────

class ServerCard(QGroupBox):
    start_clicked = pyqtSignal(str)
    stop_clicked  = pyqtSignal(str)

    def __init__(self, name, key, description, port_label="", parent=None):
        super().__init__(name, parent)
        self.key = key
        self._running = False

        layout = QHBoxLayout(self)
        layout.setSpacing(10)

        # LED + status
        left = QVBoxLayout()
        left.setSpacing(2)
        self.led = StatusLED()
        self.status_label = QLabel("STOPPED")
        self.status_label.setStyleSheet("color: {}; font-size: 10px; font-weight: bold;".format(RED))
        left.addWidget(self.led)
        left.addWidget(self.status_label)
        left.addStretch()

        # Description
        mid = QVBoxLayout()
        mid.setSpacing(2)
        desc_label = QLabel(description)
        desc_label.setStyleSheet("color: {}; font-size: 11px;".format(TEXT_DIM))
        desc_label.setWordWrap(True)
        self.port_label = QLabel(port_label)
        self.port_label.setStyleSheet("color: {}; font-size: 10px; font-family: monospace;".format(BLUE))
        self.stats_label = QLabel("")
        self.stats_label.setStyleSheet("color: {}; font-size: 10px;".format(TEXT_DIM))
        mid.addWidget(desc_label)
        mid.addWidget(self.port_label)
        mid.addWidget(self.stats_label)

        # Buttons
        right = QVBoxLayout()
        right.setSpacing(4)
        self.btn_start = QPushButton("▶  START")
        self.btn_start.setObjectName("start")
        self.btn_start.setFixedWidth(110)
        self.btn_stop = QPushButton("■  STOP")
        self.btn_stop.setObjectName("stop")
        self.btn_stop.setFixedWidth(110)
        self.btn_stop.setEnabled(False)
        right.addWidget(self.btn_start)
        right.addWidget(self.btn_stop)
        right.addStretch()

        self.btn_start.clicked.connect(lambda: self.start_clicked.emit(self.key))
        self.btn_stop.clicked.connect(lambda: self.stop_clicked.emit(self.key))

        layout.addLayout(left)
        layout.addLayout(mid, 1)
        layout.addLayout(right)

    def set_running(self, running):
        self._running = running
        self.led.set_state(running)
        if running:
            self.status_label.setText("RUNNING")
            self.status_label.setStyleSheet(
                "color: {}; font-size: 10px; font-weight: bold;".format(GREEN))
        else:
            self.status_label.setText("STOPPED")
            self.status_label.setStyleSheet(
                "color: {}; font-size: 10px; font-weight: bold;".format(RED))
        self.btn_start.setEnabled(not running)
        self.btn_stop.setEnabled(running)

    def update_stats(self, text):
        self.stats_label.setText(text)

    def update_port(self, text):
        self.port_label.setText(text)

# ── Log Widget ────────────────────────────────────────────────────────────────

class LogWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0,0,0,0)
        layout.setSpacing(4)

        # Toolbar
        toolbar = QHBoxLayout()
        toolbar.setSpacing(6)
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Filter logs...")
        self.filter_edit.setFixedHeight(28)
        self.filter_edit.textChanged.connect(self._apply_filter)

        self.level_combo = QComboBox()
        self.level_combo.addItems(["ALL", "INFO", "WARN", "ERROR"])
        self.level_combo.setFixedWidth(80)
        self.level_combo.setFixedHeight(28)
        self.level_combo.currentTextChanged.connect(self._apply_filter)

        btn_clear = QPushButton("Clear")
        btn_clear.setFixedWidth(60)
        btn_clear.setFixedHeight(28)
        btn_clear.clicked.connect(self._clear)

        btn_save = QPushButton("Save")
        btn_save.setFixedWidth(60)
        btn_save.setFixedHeight(28)
        btn_save.clicked.connect(self._save)

        self.auto_scroll = QCheckBox("Auto-scroll")
        self.auto_scroll.setChecked(True)

        toolbar.addWidget(QLabel("Filter:"))
        toolbar.addWidget(self.filter_edit, 1)
        toolbar.addWidget(self.level_combo)
        toolbar.addWidget(self.auto_scroll)
        toolbar.addWidget(btn_clear)
        toolbar.addWidget(btn_save)

        self.text_edit = QTextEdit()
        self.text_edit.setReadOnly(True)
        self.text_edit.setFont(QFont("Consolas", 10))
        self.text_edit.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)

        layout.addLayout(toolbar)
        layout.addWidget(self.text_edit)

        self._all_lines = []
        self._colors = {
            "INFO":  TEXT_MAIN,
            "WARN":  YELLOW,
            "ERROR": RED,
            "DEBUG": TEXT_DIM,
            "API":   BLUE,
            "RELAY": GREEN,
            "PROXY": ORANGE,
            "PATCH": ACCENT,
        }

    def append(self, message, level="INFO"):
        ts = time.strftime("%H:%M:%S")
        line = "[{}] {}".format(ts, message)
        self._all_lines.append((line, level))
        self._render_line(line, level)

    def _render_line(self, line, level):
        filter_text = self.filter_edit.text().lower()
        min_level   = self.level_combo.currentText()
        if filter_text and filter_text not in line.lower():
            return
        levels = ["DEBUG", "INFO", "WARN", "ERROR"]
        if min_level != "ALL":
            if levels.index(level) < levels.index(min_level):
                return

        color = self._colors.get(level, TEXT_MAIN)
        # Check component prefix
        for (comp, comp_color) in self._colors.items():
            if "[{}]".format(comp) in line:
                color = comp_color
                break

        cursor = self.text_edit.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        fmt = QTextCharFormat()
        fmt.setForeground(QColor(color))
        cursor.insertText(line + "\n", fmt)

        if self.auto_scroll.isChecked():
            self.text_edit.setTextCursor(cursor)
            self.text_edit.ensureCursorVisible()

    def _apply_filter(self):
        self.text_edit.clear()
        for (line, level) in self._all_lines[-2000:]:
            self._render_line(line, level)

    def _clear(self):
        self._all_lines.clear()
        self.text_edit.clear()

    def _save(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Log", "d2_server.log", "Log Files (*.log *.txt)")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                for (line, _) in self._all_lines:
                    f.write(line + "\n")

# ── Connections Tab ───────────────────────────────────────────────────────────

class ConnectionsWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        splitter = QSplitter(Qt.Orientation.Vertical)

        # API requests table
        api_group = QGroupBox("Recent API Requests")
        api_layout = QVBoxLayout(api_group)
        self.api_table = QTableWidget(0, 5)
        self.api_table.setHorizontalHeaderLabels(
            ["Time", "Method", "Path", "Status", "Duration"])
        self.api_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.Stretch)
        self.api_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)
        self.api_table.verticalHeader().setVisible(False)
        self.api_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers)
        api_layout.addWidget(self.api_table)

        # Relay sessions table
        relay_group = QGroupBox("Relay Sessions")
        relay_layout = QVBoxLayout(relay_group)
        self.relay_table = QTableWidget(0, 4)
        self.relay_table.setHorizontalHeaderLabels(
            ["Session ID", "Players", "Packets", "Age"])
        self.relay_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch)
        self.relay_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)
        self.relay_table.verticalHeader().setVisible(False)
        self.relay_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers)
        relay_layout.addWidget(self.relay_table)

        splitter.addWidget(api_group)
        splitter.addWidget(relay_group)
        splitter.setSizes([300, 200])

        layout.addWidget(splitter)

        # Stats bar
        stats_layout = QHBoxLayout()
        self.lbl_api_count    = QLabel("API requests: 0")
        self.lbl_relay_count  = QLabel("Relay sessions: 0")
        self.lbl_total_players= QLabel("Connected players: 0")
        for lbl in [self.lbl_api_count, self.lbl_relay_count, self.lbl_total_players]:
            lbl.setStyleSheet("color: {}; font-size: 11px;".format(TEXT_DIM))
            stats_layout.addWidget(lbl)
        stats_layout.addStretch()
        layout.addLayout(stats_layout)

        self._api_requests = []
        self._relay_sessions = {}

    def add_api_request(self, method, path, status, duration_ms):
        ts = time.strftime("%H:%M:%S")
        self._api_requests.append((ts, method, path, status, duration_ms))
        row = self.api_table.rowCount()
        self.api_table.insertRow(row)
        items = [ts, method, path, str(status), "{}ms".format(duration_ms)]
        for (col, val) in enumerate(items):
            item = QTableWidgetItem(val)
            if status >= 400:
                item.setForeground(QColor(RED))
            elif status == 200:
                item.setForeground(QColor(GREEN))
            self.api_table.setItem(row, col, item)
        if row > 200:
            self.api_table.removeRow(0)
        self.api_table.scrollToBottom()
        self.lbl_api_count.setText("API requests: {}".format(len(self._api_requests)))

    def update_relay_sessions(self, sessions):
        self._relay_sessions = sessions
        self.relay_table.setRowCount(0)
        total_players = 0
        for (sid, data) in sessions.items():
            row = self.relay_table.rowCount()
            self.relay_table.insertRow(row)
            player_count = data.get("players", 0)
            total_players += player_count
            items = [
                "0x{:08x}".format(sid),
                str(player_count),
                str(data.get("packets", 0)),
                "{}s".format(int(data.get("age", 0))),
            ]
            for (col, val) in enumerate(items):
                self.relay_table.setItem(row, col, QTableWidgetItem(val))
        self.lbl_relay_count.setText("Relay sessions: {}".format(len(sessions)))
        self.lbl_total_players.setText("Connected players: {}".format(total_players))

# ── Database Tab ──────────────────────────────────────────────────────────────

class DatabaseWidget(QWidget):
    def __init__(self, db_path, parent=None):
        super().__init__(parent)
        self.db_path = db_path
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        # Toolbar
        toolbar = QHBoxLayout()
        self.table_combo = QComboBox()
        self.table_combo.addItems(
            ["accounts", "characters", "items", "loadouts", "records"])
        self.table_combo.currentTextChanged.connect(self.load_table)
        btn_refresh = QPushButton("⟳ Refresh")
        btn_refresh.setFixedWidth(90)
        btn_refresh.clicked.connect(self.load_table)
        btn_add_item = QPushButton("+ Add Item")
        btn_add_item.setFixedWidth(100)
        btn_add_item.clicked.connect(self._add_item_dialog)
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Search...")
        self.search_edit.setFixedHeight(28)
        self.search_edit.textChanged.connect(self._filter_table)
        self.row_count_label = QLabel("0 rows")
        self.row_count_label.setStyleSheet("color: {};".format(TEXT_DIM))
        toolbar.addWidget(QLabel("Table:"))
        toolbar.addWidget(self.table_combo)
        toolbar.addWidget(btn_refresh)
        toolbar.addWidget(btn_add_item)
        toolbar.addWidget(self.search_edit, 1)
        toolbar.addWidget(self.row_count_label)

        self.table_widget = QTableWidget()
        self.table_widget.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents)
        self.table_widget.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)
        self.table_widget.verticalHeader().setVisible(False)

        layout.addLayout(toolbar)
        layout.addWidget(self.table_widget)
        self.load_table()

    def load_table(self):
        table = self.table_combo.currentText()
        if not os.path.exists(self.db_path):
            return
        try:
            db   = sqlite3.connect(self.db_path)
            db.row_factory = sqlite3.Row
            rows = db.execute("SELECT * FROM {} LIMIT 500".format(table)).fetchall()
            db.close()
        except Exception as e:
            self.row_count_label.setText("Error: {}".format(e))
            return

        if not rows:
            self.table_widget.setRowCount(0)
            self.row_count_label.setText("0 rows")
            return

        cols = rows[0].keys()
        self.table_widget.setColumnCount(len(cols))
        self.table_widget.setHorizontalHeaderLabels(list(cols))
        self.table_widget.setRowCount(len(rows))

        for (r, row) in enumerate(rows):
            for (c, col) in enumerate(cols):
                val = row[col]
                item = QTableWidgetItem(str(val) if val is not None else "NULL")
                if val is None:
                    item.setForeground(QColor(TEXT_DIM))
                self.table_widget.setItem(r, c, item)

        self.row_count_label.setText("{} rows".format(len(rows)))
        self._all_rows = rows
        self._cols     = list(cols)

    def _filter_table(self):
        text = self.search_edit.text().lower()
        for row in range(self.table_widget.rowCount()):
            match = False
            for col in range(self.table_widget.columnCount()):
                item = self.table_widget.item(row, col)
                if item and text in item.text().lower():
                    match = True
                    break
            self.table_widget.setRowHidden(row, not match and bool(text))

    def _add_item_dialog(self):
        QMessageBox.information(
            self, "Add Item",
            "Use the SQLite database directly to add items:\n\n"
            "Database: {}\n\n"
            "Or implement item import from the D2 manifest.".format(self.db_path))

# ── Config Tab ────────────────────────────────────────────────────────────────

class ManifestWidget(QWidget):
    """Manifest download, status and query tab."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._thread = None
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        # Status group
        status_group = QGroupBox("Manifest Status")
        status_layout = QVBoxLayout(status_group)

        self.status_label = QLabel("Checking...")
        self.status_label.setStyleSheet("font-family: monospace; font-size: 11px; color: {};".format(TEXT_DIM))
        self.status_label.setWordWrap(True)
        status_layout.addWidget(self.status_label)

        # Download group
        dl_group = QGroupBox("Download from Bungie CDN")
        dl_layout = QFormLayout(dl_group)

        self.api_key_edit = QLineEdit()
        self.api_key_edit.setPlaceholderText("Optional — get free key at bungie.net/en/Application")
        self.api_key_edit.setEchoMode(QLineEdit.EchoMode.Password)

        self.lang_edit = QLineEdit("en")
        self.lang_edit.setFixedWidth(120)

        self.force_check = QCheckBox("Force re-download even if cached")

        btn_row = QHBoxLayout()
        self.btn_download = QPushButton("⬇  Download Manifest")
        self.btn_download.setObjectName("start")
        self.btn_download.setFixedHeight(32)
        self.btn_download.clicked.connect(self._download)

        self.btn_refresh = QPushButton("⟳ Refresh Status")
        self.btn_refresh.setFixedHeight(32)
        self.btn_refresh.setFixedWidth(130)
        self.btn_refresh.clicked.connect(self._refresh_status)

        btn_row.addWidget(self.btn_download)
        btn_row.addWidget(self.btn_refresh)
        btn_row.addStretch()

        dl_layout.addRow("API Key:", self.api_key_edit)
        dl_layout.addRow("Languages:", self.lang_edit)
        dl_layout.addRow("", self.force_check)
        dl_layout.addRow("", btn_row)

        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setStyleSheet(
            "QProgressBar {{ background: {}; border: 1px solid {}; border-radius: 3px; }}"
            "QProgressBar::chunk {{ background: {}; border-radius: 3px; }}".format(
                DARK_PANEL, DARK_CARD, GREEN))

        # Query group
        query_group = QGroupBox("Query Manifest Database")
        query_layout = QHBoxLayout(query_group)

        self.query_table = QLineEdit("DestinyInventoryItemDefinition")
        self.query_table.setPlaceholderText("Table name")

        self.query_hash = QLineEdit()
        self.query_hash.setPlaceholderText("Hash (optional, hex or dec)")
        self.query_hash.setFixedWidth(200)

        btn_query = QPushButton("Query")
        btn_query.setFixedWidth(80)
        btn_query.clicked.connect(self._query)

        self.query_results = QTextEdit()
        self.query_results.setReadOnly(True)
        self.query_results.setFont(QFont("Consolas", 10))
        self.query_results.setMaximumHeight(150)

        query_layout.addWidget(QLabel("Table:"))
        query_layout.addWidget(self.query_table, 1)
        query_layout.addWidget(QLabel("Hash:"))
        query_layout.addWidget(self.query_hash)
        query_layout.addWidget(btn_query)

        layout.addWidget(status_group)
        layout.addWidget(dl_group)
        layout.addWidget(self.progress_bar)
        layout.addWidget(query_group)
        layout.addWidget(self.query_results)
        layout.addStretch()

        self._refresh_status()

    def _refresh_status(self):
        try:
            import sys, os
            db_dir = os.path.join(os.path.dirname(__file__), 'db')
            sys.path.insert(0, db_dir)
            from manifest_manager import MANIFEST_JSON, CONTENT_DIR, ASSETS_DIR
            lines = []
            if MANIFEST_JSON.exists():
                import json
                with open(MANIFEST_JSON) as f:
                    m = json.load(f)
                lines.append("✅ Manifest index:  v{}".format(m.get("version","?")))
            else:
                lines.append("❌ Manifest index:  not downloaded")
            if CONTENT_DIR.exists():
                files = list(CONTENT_DIR.iterdir())
                total_mb = sum(f.stat().st_size for f in files) / 1024 / 1024
                lines.append("✅ Content files:   {} files  ({:.0f}MB)".format(
                    len(files), total_mb))
            else:
                lines.append("❌ Content files:   not downloaded")
            if ASSETS_DIR.exists() and any(ASSETS_DIR.iterdir()):
                lines.append("✅ Asset files:     downloaded")
            else:
                lines.append("⚠️  Asset files:    not downloaded (optional)")
            self.status_label.setText("\n".join(lines))
            all_ok = "❌" not in "\n".join(lines[:2])
            self.status_label.setStyleSheet(
                "font-family: monospace; font-size: 11px; color: {};".format(
                    GREEN if all_ok else YELLOW))
        except Exception as e:
            self.status_label.setText("Status check failed: {}".format(e))

    def _download(self):
        if self._thread and self._thread.isRunning():
            return
        self.btn_download.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # indeterminate

        api_key = self.api_key_edit.text().strip()
        langs   = [l.strip() for l in self.lang_edit.text().split(",")]
        force   = self.force_check.isChecked()

        class DownloadThread(QThread):
            done = pyqtSignal(bool, str)
            def __init__(self, api_key, langs, force):
                super().__init__()
                self.api_key = api_key
                self.langs   = langs
                self.force   = force
            def run(self):
                try:
                    import sys, os
                    sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'db'))
                    from manifest_manager import download_manifest
                    ok = download_manifest(self.api_key, self.langs, self.force)
                    self.done.emit(ok, "Download complete" if ok else "Download failed")
                except Exception as e:
                    self.done.emit(False, str(e))

        self._thread = DownloadThread(api_key, langs, force)
        self._thread.done.connect(self._on_download_done)
        self._thread.start()

    def _on_download_done(self, ok, msg):
        self.progress_bar.setVisible(False)
        self.progress_bar.setRange(0, 100)
        self.btn_download.setEnabled(True)
        self._refresh_status()

    def _query(self):
        try:
            import sys, os, json
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'db'))
            from manifest_manager import (MANIFEST_JSON, CONTENT_DIR,
                                          query_manifest_db, get_manifest_tables)
            if not MANIFEST_JSON.exists():
                self.query_results.setPlainText("No manifest — download first")
                return
            with open(MANIFEST_JSON) as f:
                manifest = json.load(f)
            world_path = manifest.get("mobileWorldContentPaths", {}).get("en", "")
            if not world_path:
                self.query_results.setPlainText("No world content path in manifest")
                return
            from pathlib import Path
            db_path = CONTENT_DIR / Path(world_path).name
            if not db_path.exists():
                self.query_results.setPlainText("Content file missing — download first")
                return
            table = self.query_table.text().strip()
            hash_str = self.query_hash.text().strip()
            item_hash = None
            if hash_str:
                item_hash = int(hash_str, 16) if hash_str.startswith("0x") else int(hash_str)
            results = query_manifest_db(db_path, table, item_hash, limit=20)
            if not results:
                tables = get_manifest_tables(db_path)
                matches = [t for t in tables if table.lower() in t.lower()]
                self.query_results.setPlainText(
                    "No results.\nSimilar tables:\n" + "\n".join(matches[:10]))
            else:
                lines = []
                for r in results:
                    d = r["data"]
                    name = d.get("displayProperties", {}).get("name", "")
                    desc = d.get("displayProperties", {}).get("description", "")[:80]
                    lines.append("id={:<12}  {:40}  {}".format(r["id"], name[:40], desc))
                self.query_results.setPlainText("\n".join(lines))
        except Exception as e:
            self.query_results.setPlainText("Error: {}".format(e))


class ConfigWidget(QWidget):
    config_changed = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        # Server config
        server_group = QGroupBox("Server Configuration")
        server_form  = QFormLayout(server_group)
        self.host_edit     = QLineEdit(SETTINGS.value("host", "0.0.0.0"))
        self.api_port      = QSpinBox()
        self.api_port.setRange(1, 65535)
        self.api_port.setValue(int(SETTINGS.value("api_port", 8443)))
        self.relay_port    = QSpinBox()
        self.relay_port.setRange(1, 65535)
        self.relay_port.setValue(int(SETTINGS.value("relay_port", 7777)))
        self.proxy_port    = QSpinBox()
        self.proxy_port.setRange(1, 65535)
        self.proxy_port.setValue(int(SETTINGS.value("proxy_port", 8080)))
        self.db_path_edit  = QLineEdit(SETTINGS.value("db_path", DB_PATH))
        btn_browse_db = QPushButton("Browse")
        btn_browse_db.setFixedWidth(70)
        btn_browse_db.clicked.connect(self._browse_db)
        db_row = QHBoxLayout()
        db_row.addWidget(self.db_path_edit)
        db_row.addWidget(btn_browse_db)
        server_form.addRow("Bind Host:", self.host_edit)
        server_form.addRow("API Port (HTTPS):", self.api_port)
        server_form.addRow("Relay Port (UDP):", self.relay_port)
        server_form.addRow("Proxy Port (HTTP):", self.proxy_port)
        server_form.addRow("Database:", db_row)

        # Patch config
        patch_group = QGroupBox("Memory Patch Configuration")
        patch_form  = QFormLayout(patch_group)
        self.auto_patch  = QCheckBox("Auto-patch when game process detected")
        self.auto_patch.setChecked(SETTINGS.value("auto_patch", False, type=bool))
        self.patch_delay = QSpinBox()
        self.patch_delay.setRange(0, 60)
        self.patch_delay.setValue(int(SETTINGS.value("patch_delay", 10)))
        self.patch_delay.setSuffix("s")
        patch_form.addRow("", self.auto_patch)
        patch_form.addRow("Patch delay after launch:", self.patch_delay)

        # Tier select
        tier_group = QGroupBox("Server Tier")
        tier_layout = QHBoxLayout(tier_group)
        self.tier1_check = QCheckBox("Tier 1 — API + Proxy (Solo/Offline)")
        self.tier2_check = QCheckBox("Tier 2 — + UDP Relay (Multiplayer)")
        self.tier1_check.setChecked(True)
        tier_layout.addWidget(self.tier1_check)
        tier_layout.addWidget(self.tier2_check)
        tier_layout.addStretch()

        # Save button
        btn_save = QPushButton("Save Configuration")
        btn_save.clicked.connect(self._save)

        layout.addWidget(server_group)
        layout.addWidget(patch_group)
        layout.addWidget(tier_group)
        layout.addStretch()
        layout.addWidget(btn_save)

    def _browse_db(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Database Location", self.db_path_edit.text(),
            "SQLite (*.db)")
        if path:
            self.db_path_edit.setText(path)

    def _save(self):
        config = self.get_config()
        for (k, v) in config.items():
            SETTINGS.setValue(k, v)
        self.config_changed.emit(config)

    def get_config(self):
        return {
            "host":        self.host_edit.text(),
            "api_port":    self.api_port.value(),
            "relay_port":  self.relay_port.value(),
            "proxy_port":  self.proxy_port.value(),
            "db_path":     self.db_path_edit.text(),
            "auto_patch":  self.auto_patch.isChecked(),
            "patch_delay": self.patch_delay.value(),
            "tier1":       self.tier1_check.isChecked(),
            "tier2":       self.tier2_check.isChecked(),
        }

# ── Main Window ───────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("{} v{}".format(APP_NAME, APP_VERSION))
        self.resize(1100, 750)
        self.setMinimumSize(900, 600)

        self._threads  = {}
        self._config   = {}
        self._log_queue= queue.Queue()
        self._api_count= 0

        self._setup_ui()
        self._setup_logging()
        self._setup_timers()
        self._load_config()

    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(10, 8, 10, 8)
        root.setSpacing(8)

        # Header
        header = QHBoxLayout()
        title = QLabel("⚡ DESTINY 2 PRIVATE SERVER")
        title.setStyleSheet(
            "color: {}; font-size: 16px; font-weight: bold; "
            "letter-spacing: 2px;".format(ACCENT))
        self._overall_led = StatusLED()
        self._overall_led.setFixedSize(16, 16)
        self._overall_label = QLabel("ALL STOPPED")
        self._overall_label.setStyleSheet(
            "color: {}; font-size: 11px; font-weight: bold;".format(RED))
        header.addWidget(title)
        header.addStretch()
        header.addWidget(self._overall_led)
        header.addWidget(self._overall_label)
        root.addLayout(header)

        # Divider
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setStyleSheet("color: {};".format(DARK_CARD))
        root.addWidget(line)

        # Server cards
        cards_row = QHBoxLayout()
        cards_row.setSpacing(8)
        self.card_api = ServerCard(
            "API SERVER", "api",
            "Bungie.net REST API emulator\nOAuth, profiles, inventory, loadouts",
            "HTTPS  :8443")
        self.card_relay = ServerCard(
            "UDP RELAY", "relay",
            "Multiplayer packet relay\nSession-based player grouping",
            "UDP  :7777")
        self.card_proxy = ServerCard(
            "HTTP PROXY", "proxy",
            "WinHTTP redirect via hosts file\nRoutes game traffic to local API",
            "HTTP  :8080")
        for card in [self.card_api, self.card_relay, self.card_proxy]:
            card.start_clicked.connect(self._start_server)
            card.stop_clicked.connect(self._stop_server)
            cards_row.addWidget(card)

        # Patch button
        patch_col = QVBoxLayout()
        patch_col.setSpacing(6)
        self.btn_patch = QPushButton("🔧  PATCH GAME")
        self.btn_patch.setObjectName("patch")
        self.btn_patch.setFixedWidth(130)
        self.btn_patch.setFixedHeight(36)
        self.btn_patch.clicked.connect(self._run_patch)
        self.btn_certs = QPushButton("🔑  GEN CERTS")
        self.btn_certs.setFixedWidth(130)
        self.btn_certs.setFixedHeight(36)
        self.btn_certs.clicked.connect(self._gen_certs)
        self.btn_start_all = QPushButton("▶▶  START ALL")
        self.btn_start_all.setObjectName("start")
        self.btn_start_all.setFixedWidth(130)
        self.btn_start_all.setFixedHeight(36)
        self.btn_start_all.clicked.connect(self._start_all)
        self.btn_stop_all = QPushButton("■■  STOP ALL")
        self.btn_stop_all.setObjectName("stop")
        self.btn_stop_all.setFixedWidth(130)
        self.btn_stop_all.setFixedHeight(36)
        self.btn_stop_all.clicked.connect(self._stop_all)
        patch_col.addWidget(self.btn_start_all)
        patch_col.addWidget(self.btn_stop_all)
        patch_col.addWidget(self.btn_patch)
        patch_col.addWidget(self.btn_certs)
        patch_col.addStretch()
        cards_row.addLayout(patch_col)

        root.addLayout(cards_row)

        # Tabs
        self.tabs = QTabWidget()
        self.log_widget      = LogWidget()
        self.conn_widget     = ConnectionsWidget()
        self.db_widget       = DatabaseWidget(DB_PATH)
        self.manifest_widget = ManifestWidget()
        self.cfg_widget      = ConfigWidget()

        self.tabs.addTab(self.log_widget,      "📋  Logs")
        self.tabs.addTab(self.conn_widget,     "🌐  Connections")
        self.tabs.addTab(self.db_widget,       "🗄️  Database")
        self.tabs.addTab(self.manifest_widget, "📦  Manifest")
        self.tabs.addTab(self.cfg_widget,      "⚙️  Config")
        self.cfg_widget.config_changed.connect(self._load_config)

        root.addWidget(self.tabs, 1)

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self._status_api_label   = QLabel("API: stopped")
        self._status_relay_label = QLabel("Relay: stopped")
        self._status_proxy_label = QLabel("Proxy: stopped")
        self._status_game_label  = QLabel("Game: not running")
        for lbl in [self._status_api_label, self._status_relay_label,
                    self._status_proxy_label, self._status_game_label]:
            lbl.setStyleSheet("color: {}; padding: 0 8px;".format(TEXT_DIM))
            self.status_bar.addWidget(lbl)

    def _setup_logging(self):
        handler = QueueHandler(self._log_queue)
        handler.setFormatter(logging.Formatter("%(name)s: %(message)s"))
        root_logger = logging.getLogger()
        root_logger.addHandler(handler)
        root_logger.setLevel(logging.DEBUG)

    def _setup_timers(self):
        # Log drain timer
        self._log_timer = QTimer()
        self._log_timer.timeout.connect(self._drain_logs)
        self._log_timer.start(100)

        # Stats refresh timer
        self._stats_timer = QTimer()
        self._stats_timer.timeout.connect(self._update_stats)
        self._stats_timer.start(2000)

    def _load_config(self, config=None):
        if config:
            self._config = config
        else:
            self._config = self.cfg_widget.get_config()
        # Update port labels
        self.card_api.update_port(
            "HTTPS  :{}".format(self._config.get("api_port", 8443)))
        self.card_relay.update_port(
            "UDP  :{}".format(self._config.get("relay_port", 7777)))
        self.card_proxy.update_port(
            "HTTP  :{}".format(self._config.get("proxy_port", 8080)))

    def _start_server(self, key):
        if key in self._threads and self._threads[key].isRunning():
            return
        thread = ServerThread(key, self._config)
        thread.log_signal.connect(self._on_log)
        thread.status_signal.connect(self._on_status)
        if key == "api":
            thread.api_request_signal.connect(self.conn_widget.add_api_request)
        self._threads[key] = thread
        thread.start()
        self._on_log("[{}] Starting component...".format(key.upper()), "INFO")

    def _stop_server(self, key):
        if key in self._threads:
            self._threads[key].stop()

    def _start_all(self):
        self._start_server("api")
        self._start_server("proxy")
        if self._config.get("tier2", False):
            self._start_server("relay")

    def _stop_all(self):
        for key in list(self._threads.keys()):
            self._stop_server(key)

    def _run_patch(self):
        patch_root = os.path.join(os.path.dirname(__file__), "patch")
        exe_path = os.path.join(
            patch_root, "driver_patcher", "bin", "x64", "Release", "d2_driver_patcher.exe")
        legacy_exe_path = os.path.join(
            patch_root, "driver_patcher", "bin", "x64", "Release", "d2_driver_patcher_logged.exe")
        if not os.path.exists(exe_path):
            exe_path = legacy_exe_path
        patch_path = exe_path if os.path.exists(exe_path) else os.path.join(
            patch_root, "patch_memory.py")
        if not os.path.exists(patch_path):
            QMessageBox.warning(self, "Not Found",
                                "Memory patcher not found at:\n{}".format(patch_path))
            return
        self._on_log(
            "[PATCH] Launching driver-backed memory patcher (no DNS/hosts changes)...",
            "PATCH")
        try:
            subprocess.Popen(
                [patch_path, "--pause"] if patch_path == exe_path else [sys.executable, patch_path],
                creationflags=subprocess.CREATE_NEW_CONSOLE
                if sys.platform == "win32" else 0)
        except Exception as e:
            self._on_log("[PATCH] Failed: {}".format(e), "ERROR")

    def _gen_certs(self):
        cert_path = os.path.join(
            os.path.dirname(__file__), "patch", "gen_certs.py")
        self._on_log("[CERTS] Generating TLS certificates...", "INFO")
        try:
            subprocess.Popen(
                [sys.executable, cert_path],
                creationflags=subprocess.CREATE_NEW_CONSOLE
                if sys.platform == "win32" else 0)
        except Exception as e:
            self._on_log("[CERTS] Failed: {}".format(e), "ERROR")

    @pyqtSlot(str, str)
    def _on_log(self, message, level):
        self.log_widget.append(message, level)

    @pyqtSlot(str, bool)
    def _on_status(self, component, running):
        card_map = {"api": self.card_api, "relay": self.card_relay, "proxy": self.card_proxy}
        status_map = {
            "api":   self._status_api_label,
            "relay": self._status_relay_label,
            "proxy": self._status_proxy_label,
        }
        if component in card_map:
            card_map[component].set_running(running)
        if component in status_map:
            label = status_map[component]
            color = GREEN if running else TEXT_DIM
            label.setStyleSheet("color: {}; padding: 0 8px;".format(color))
            label.setText("{}: {}".format(
                component.upper(), "running" if running else "stopped"))
        self._update_overall_status()

    def _update_overall_status(self):
        any_running = any(
            t.isRunning() for t in self._threads.values())
        all_running = (
            self._threads.get("api",   ServerThread("","{}")).isRunning() and
            self._threads.get("proxy", ServerThread("","{}")).isRunning())
        if all_running:
            self._overall_led.set_state(True)
            self._overall_label.setText("RUNNING")
            self._overall_label.setStyleSheet(
                "color: {}; font-size: 11px; font-weight: bold;".format(GREEN))
        elif any_running:
            self._overall_led.setStyleSheet(
                "background-color: {}; border-radius: 8px; border: 1px solid {};".format(
                    YELLOW, "#5c471d"))
            self._overall_label.setText("PARTIAL")
            self._overall_label.setStyleSheet(
                "color: {}; font-size: 11px; font-weight: bold;".format(YELLOW))
        else:
            self._overall_led.set_state(False)
            self._overall_label.setText("ALL STOPPED")
            self._overall_label.setStyleSheet(
                "color: {}; font-size: 11px; font-weight: bold;".format(RED))

    def _drain_logs(self):
        try:
            while True:
                msg = self._log_queue.get_nowait()
                level = "INFO"
                if "ERROR" in msg or "error" in msg:   level = "ERROR"
                elif "WARN"  in msg or "warning" in msg: level = "WARN"
                elif "DEBUG" in msg:                    level = "DEBUG"
                self.log_widget.append(msg, level)
        except queue.Empty:
            pass

    def _update_stats(self):
        # Check if game is running
        game_running = any(
            "destiny2" in p.info["name"].lower()
            for p in psutil.process_iter(["name"])
            if p.info.get("name"))
        color = GREEN if game_running else TEXT_DIM
        self._status_game_label.setStyleSheet(
            "color: {}; padding: 0 8px;".format(color))
        self._status_game_label.setText(
            "Game: {}".format("running" if game_running else "not running"))

        # Update card stats
        for (key, card) in [("api", self.card_api),
                              ("relay", self.card_relay),
                              ("proxy", self.card_proxy)]:
            if key in self._threads and self._threads[key].isRunning():
                card.update_stats("⬤ Active")
            else:
                card.update_stats("")

        relay_thread = self._threads.get("relay")
        relay_server = getattr(relay_thread, "_server", None) if relay_thread else None
        if relay_thread and relay_thread.isRunning() and relay_server:
            self.conn_widget.update_relay_sessions(relay_server.get_session_stats())
        else:
            self.conn_widget.update_relay_sessions({})

    def closeEvent(self, event):
        reply = QMessageBox.question(
            self, "Exit",
            "Stop all servers and exit?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self._stop_all()
            # Clean up hosts file
            try:
                from proxy.winhttp_proxy import remove_hosts
                remove_hosts()
            except Exception:
                pass
            event.accept()
        else:
            event.ignore()

# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    app.setStyleSheet(STYLE)

    # Set dark palette
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window,          QColor(DARK_BG))
    palette.setColor(QPalette.ColorRole.WindowText,      QColor(TEXT_MAIN))
    palette.setColor(QPalette.ColorRole.Base,            QColor(DARK_PANEL))
    palette.setColor(QPalette.ColorRole.AlternateBase,   QColor(DARK_CARD))
    palette.setColor(QPalette.ColorRole.Text,            QColor(TEXT_MAIN))
    palette.setColor(QPalette.ColorRole.ButtonText,      QColor(TEXT_MAIN))
    palette.setColor(QPalette.ColorRole.Highlight,       QColor(ACCENT2))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor(TEXT_MAIN))
    app.setPalette(palette)

    window = MainWindow()
    window.show()
    window.log_widget.append(
        "[SERVER] D2 Private Server Control Panel started", "INFO")
    window.log_widget.append(
        "[SERVER] Configure in the Config tab, then click START ALL", "INFO")
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
