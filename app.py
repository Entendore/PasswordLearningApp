#!/usr/bin/env python3
"""
Password Security Learning App v2
Enhanced with Game Indicator, Challenge Mode, Passphrase Generator, and Phishing Quiz.
"""

import sys
import hashlib
import secrets
import string
import math
import re
import time

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QLabel, QLineEdit, QPushButton, QTextEdit, QCheckBox,
    QSlider, QGroupBox, QProgressBar, QComboBox, QGridLayout,
    QFrame, QScrollArea, QSizePolicy, QStackedWidget
)
from PySide6.QtCore import Qt, QTimer, QRectF, QPointF
from PySide6.QtGui import QFont, QPainter, QConicalGradient, QColor, QPen, QRadialGradient

# ---------------------------------------------------------------------------
# Wordlist for Passphrase Generator (EFF-style subset)
# ---------------------------------------------------------------------------
WORDLIST = [
    "apple", "brave", "cloud", "dance", "eagle", "flame", "grape", "heart",
    "ivory", "jewel", "kneel", "lemon", "maple", "noble", "ocean", "pearl",
    "quest", "river", "storm", "tiger", "unity", "vivid", "water", "xenon",
    "yacht", "zealot", "alpha", "bravo", "delta", "gamma", "orbit", "pulse",
    "solar", "lunar", "pixel", "cyber", "crypto", "matrix", "logic", "sonic",
    "swift", "force", "blade", "ghost", "raven", "hawk", "wolf", "bear",
    "lion", "cobra", "viper", "panther", "phoenix", "dragon", "titan", "atlas",
    "nova", "apex", "summit", "peak", "base", "camp", "trail", "path",
    "forest", "grove", "field", "stone", "rock", "sand", "surf", "reef",
]

# Common passwords list
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "guest", "qwerty",
    "12345678", "111111", "12345", "col123456", "123123",
    "abc123", "password1", "1234567", "sunshine", "princess",
    "admin", "welcome", "login", "football", "master",
    "hello", "freedom", "whatever", "qazwsx", "trustno1",
    "dragon", "baseball", "shadow", "monkey", "superman",
    "letmein", "696969", "mustang", "michael", "batman",
    "access", "yankees", "1q2w3e4r", "987654321", "iloveyou",
    "starwars", "1234", "1234567890", "password123", "changeme",
    "secret", "qwerty123", "1q2w3e", "admin123", "passw0rd",
    "654321", "supersecret", "p@ssw0rd", "pass123", "test",
    "root", "default", "1qaz2wsx", "qweasdzxc", "azerty",
}

# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------
def calculate_entropy(password: str) -> float:
    if not password: return 0.0
    charset_size = 0
    if re.search(r"[a-z]", password): charset_size += 26
    if re.search(r"[A-Z]", password): charset_size += 26
    if re.search(r"[0-9]", password): charset_size += 10
    if re.search(r"[^a-zA-Z0-9]", password): charset_size += 33
    return len(password) * math.log2(charset_size) if charset_size else 0.0

def estimate_crack_time(entropy: float, guesses_per_second: float) -> str:
    total = 2 ** entropy
    seconds = total / guesses_per_second
    if seconds < 0.001: return "Instantly"
    if seconds < 1: return f"{seconds*1000:.0f} ms"
    if seconds < 60: return f"{seconds:.0f} seconds"
    if seconds < 3600: return f"{seconds/60:.1f} minutes"
    if seconds < 86400: return f"{seconds/3600:.1f} hours"
    if seconds < 86400 * 365: return f"{seconds/86400:.1f} days"
    years = seconds / (86400 * 365)
    if years < 1_000: return f"{years:.1f} years"
    if years < 1_000_000: return f"{years/1_000:.1f} thousand years"
    if years < 1_000_000_000: return f"{years/1_000_000:.1f} million years"
    return f"{years/1_000_000_000:.1f} billion+ years"

def get_strength_level(entropy: float):
    if entropy < 28: return 0, "Very Weak", "#ff0000"
    if entropy < 36: return 1, "Weak", "#ff6600"
    if entropy < 60: return 2, "Fair", "#ffcc00"
    if entropy < 80: return 3, "Strong", "#66cc00"
    return 4, "Very Strong", "#00cc00"

# ---------------------------------------------------------------------------
# Shared stylesheets
# ---------------------------------------------------------------------------
GROUP_STYLE = """
    QGroupBox { font-size: 14px; font-weight: bold; color: #00d4ff;
        border: 2px solid #333; border-radius: 8px;
        margin-top: 12px; padding-top: 20px; }
    QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; }
"""
INPUT_STYLE = """
    QLineEdit { padding: 12px; font-size: 16px;
        border: 2px solid #333; border-radius: 8px;
        background: #1a1a2e; color: white; }
    QLineEdit:focus { border-color: #00d4ff; }
"""
PRIMARY_BTN = """
    QPushButton { background: #00d4ff; color: #000; border: none;
        border-radius: 8px; padding: 12px 24px;
        font-size: 14px; font-weight: bold; }
    QPushButton:hover { background: #33ddff; }
    QPushButton:pressed { background: #0099cc; }
    QPushButton:disabled { background: #333; color: #666; }
"""
SECONDARY_BTN = """
    QPushButton { background: #2a2a3e; color: #00d4ff;
        border: 2px solid #00d4ff; border-radius: 8px;
        padding: 10px 20px; font-size: 13px; font-weight: bold; }
    QPushButton:hover { background: #3a3a4e; }
    QPushButton:disabled { border-color: #333; color: #555; }
"""
CHECKBOX_STYLE = """
    QCheckBox { color: #cccccc; font-size: 13px; spacing: 8px; }
    QCheckBox::indicator { width: 18px; height: 18px; border-radius: 4px;
        border: 2px solid #555; background: #1a1a2e; }
    QCheckBox::indicator:checked { background: #00d4ff; border-color: #00d4ff; }
"""
COMBO_STYLE = """
    QComboBox { padding: 8px; border: 2px solid #333; border-radius: 6px;
        background: #1a1a2e; color: white; font-size: 13px; }
    QComboBox::drop-down { border: none; }
    QComboBox QAbstractItemView { background: #1a1a2e; color: white;
        selection-background-color: #00d4ff; }
"""

# ═══════════════════════════════════════════════════════════════════════════
#  CUSTOM WIDGET: Shield Game Indicator
# ═══════════════════════════════════════════════════════════════════════════
class ShieldGameIndicator(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(220, 220)
        self.value = 0.0  # 0.0 to 100.0
        self.color = "#ff0000"
        self.label = "Empty"

    def set_strength(self, percent, color, label):
        self.value = percent
        self.color = color
        self.label = label
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        side = min(self.width(), self.height())
        center = QPointF(self.width() / 2, self.height() / 2)
        radius = (side - 30) / 2

        # Background Circle
        painter.setPen(Qt.NoPen)
        grad = QRadialGradient(center, radius)
        grad.setColorAt(0, QColor("#1a1a2e"))
        grad.setColorAt(1, QColor("#0f0f23"))
        painter.setBrush(grad)
        painter.drawEllipse(center, radius, radius)

        # Draw Hackers/Threats (Red dots approaching)
        if self.value < 80:
            threat_dist = radius - (radius * (self.value / 100))
            for i in range(8):
                angle = math.radians(i * 45 + time.time() * 20)
                tx = center.x() + (radius + 10 - threat_dist) * math.cos(angle)
                ty = center.y() + (radius + 10 - threat_dist) * math.sin(angle)
                painter.setBrush(QColor("#ff3333"))
                painter.drawEllipse(QPointF(tx, ty), 5, 5)

        # Shield Arc (Circular Progress)
        pen = QPen()
        pen.setWidth(10)
        pen.setCapStyle(Qt.RoundCap)
        
        # Background track
        pen.setColor(QColor("#333333"))
        painter.setPen(pen)
        rect = QRectF(center.x() - radius + 10, center.y() - radius + 10, 
                      2*radius - 20, 2*radius - 20)
        painter.drawArc(rect, 0, 360 * 16)

        # Active track
        pen.setColor(QColor(self.color))
        painter.setPen(pen)
        span_angle = (self.value / 100.0) * 360 * 16
        painter.drawArc(rect, 90 * 16, -span_angle)

        # Inner Shield Icon Representation
        shield_path = QPainterPath()
        sx, sy = center.x(), center.y()
        w, h = 30, 40
        shield_path.moveTo(sx, sy - h)
        shield_path.cubicTo(sx + w, sy - h, sx + w, sy - h/2, sx + w, sy)
        shield_path.cubicTo(sx + w, sy + h/2, sx, sy + h, sx, sy + h)
        shield_path.cubicTo(sx, sy + h, sx - w, sy + h/2, sx - w, sy)
        shield_path.cubicTo(sx - w, sy - h/2, sx - w, sy - h, sx, sy - h)
        
        shield_grad = QRadialGradient(center, 40)
        c = QColor(self.color)
        c.setAlpha(80)
        shield_grad.setColorAt(0, c)
        shield_grad.setColorAt(1, QColor("#0f0f23"))
        painter.setPen(Qt.NoPen)
        painter.setBrush(shield_grad)
        painter.drawPath(shield_path)

        # Text
        painter.setPen(QColor("white"))
        font = QFont("Segoe UI", 16, QFont.Bold)
        painter.setFont(font)
        painter.drawText(rect, Qt.AlignCenter, f"{self.value:.0f}%")

        # Label underneath
        painter.setPen(QColor(self.color))
        font = QFont("Segoe UI", 9, QFont.Bold)
        painter.setFont(font)
        label_rect = QRectF(0, self.height() - 25, self.width(), 20)
        painter.drawText(label_rect, Qt.AlignCenter, self.label)


# ═══════════════════════════════════════════════════════════════════════════
#  TAB 1 — Password Analyzer + Challenge Mode
# ═══════════════════════════════════════════════════════════════════════════
class PasswordAnalyzerTab(QWidget):
    def __init__(self):
        super().__init__()
        self._challenge_active = False
        self._challenge_start = 0
        self._challenge_target = 60.0  # bits of entropy
        self._challenge_timer = QTimer()
        self._challenge_timer.timeout.connect(self._update_challenge_timer)
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setSpacing(14)

        title = QLabel("🔐 Password Analyzer & Game")
        title.setFont(QFont("Segoe UI", 20, QFont.Bold))
        title.setStyleSheet("color:#00d4ff; margin-bottom:4px;")
        root.addWidget(title)

        # --- Challenge Mode Bar ---
        g_chall = QGroupBox("🎮 Strength Challenge")
        g_chall.setStyleSheet(GROUP_STYLE)
        cl = QVBoxLayout(g_chall)
        
        challenge_desc = QLabel(f"Try to create a password with over {self._challenge_target:.0f} bits of entropy as fast as you can!")
        challenge_desc.setStyleSheet("color:#ccc; font-size:12px;")
        cl.addWidget(challenge_desc)
        
        ch_row = QHBoxLayout()
        self.btn_start_challenge = QPushButton("Start Challenge ⏱️")
        self.btn_start_challenge.setStyleSheet(PRIMARY_BTN)
        self.btn_start_challenge.clicked.connect(self._start_challenge)
        ch_row.addWidget(self.btn_start_challenge)
        
        self.lbl_challenge_timer = QLabel("Time: 0.0s")
        self.lbl_challenge_timer.setFont(QFont("Segoe UI", 16, QFont.Bold))
        self.lbl_challenge_timer.setStyleSheet("color:#ff9900;")
        ch_row.addWidget(self.lbl_challenge_timer)
        cl.addLayout(ch_row)
        root.addWidget(g_chall)

        # --- Visual Game & Input ---
        g_game = QGroupBox("Visual Strength Shield")
        g_game.setStyleSheet(GROUP_STYLE)
        gl = QHBoxLayout(g_game)

        self.shield_indicator = ShieldGameIndicator()
        gl.addWidget(self.shield_indicator, alignment=Qt.AlignCenter)

        gl_right = QVBoxLayout(g_game)
        self.pwd_input = QLineEdit()
        self.pwd_input.setPlaceholderText("Type a password to analyse…")
        self.pwd_input.setEchoMode(QLineEdit.Password)
        self.pwd_input.setStyleSheet(INPUT_STYLE)
        self.pwd_input.textChanged.connect(self._analyse)
        gl_right.addWidget(self.pwd_input)

        self.toggle_btn = QPushButton("👁")
        self.toggle_btn.setFixedSize(44, 44)
        self.toggle_btn.setStyleSheet(
            "QPushButton{background:#2a2a3e;border:2px solid #333;border-radius:8px;"
            "font-size:18px;color:white} QPushButton:hover{border-color:#00d4ff;}"
        )
        self.toggle_btn.clicked.connect(self._toggle_vis)
        gl_right.addWidget(self.toggle_btn, alignment=Qt.AlignRight)
        gl.addLayout(gl_right)
        root.addWidget(g_game)

        # --- Detailed checks ---
        g_checks = QGroupBox("Detailed Analysis")
        g_checks.setStyleSheet(GROUP_STYLE)
        cl2 = QGridLayout(g_checks)
        cl2.setSpacing(6)

        self._chk = {}
        checks = [
            ("length", "📏 Length ≥ 8 characters"), ("upper", "🔤 Uppercase (A-Z)"),
            ("lower", "🔡 Lowercase (a-z)"), ("digits", "🔢 Digits (0-9)"),
            ("special", "✨ Special characters"), ("common", "🚫 Not common"),
            ("sequential", "🔄 No sequential"), ("repeated", "🔁 No repeated"),
        ]
        for i, (key, text) in enumerate(checks):
            lbl = QLabel(text); lbl.setStyleSheet("color:#bbb;font-size:13px;padding:3px;")
            status = QLabel("—"); status.setFixedWidth(28); status.setAlignment(Qt.AlignCenter)
            status.setFont(QFont("Segoe UI", 13)); status.setStyleSheet("color:#666;")
            cl2.addWidget(lbl, i, 0); cl2.addWidget(status, i, 1)
            self._chk[key] = status
        root.addWidget(g_checks)

        # --- Crack time ---
        g_crack = QGroupBox("Estimated Crack Time")
        g_crack.setStyleSheet(GROUP_STYLE)
        crl = QGridLayout(g_crack)
        self.lbl_entropy = QLabel("Entropy: — bits")
        self.lbl_entropy.setStyleSheet("color:#00d4ff;font-size:14px;font-weight:bold;")
        crl.addWidget(self.lbl_entropy, 0, 0, 1, 2)
        
        self._crack = {}
        attack_types = [("🌐 Online (100/s)", "online"), ("💻 Offline (10M/s)", "offline"), ("🖥️ GPU (100B/s)", "gpu")]
        for i, (txt, key) in enumerate(attack_types):
            l = QLabel(txt); l.setStyleSheet("color:#ccc;font-size:13px;")
            v = QLabel("—"); v.setStyleSheet("color:#ff6600;font-size:13px;font-weight:bold;")
            crl.addWidget(l, i+1, 0); crl.addWidget(v, i+1, 1)
            self._crack[key] = v
        root.addWidget(g_crack)

        # --- Suggestions ---
        g_sugg = QGroupBox("Improvement Suggestions")
        g_sugg.setStyleSheet(GROUP_STYLE)
        sl = QVBoxLayout(g_sugg)
        self.txt_sugg = QTextEdit(); self.txt_sugg.setReadOnly(True); self.txt_sugg.setMaximumHeight(100)
        self.txt_sugg.setStyleSheet("QTextEdit{background:#1a1a2e;border:none;color:#ccc;font-size:13px;padding:8px;}")
        sl.addWidget(self.txt_sugg)
        root.addWidget(g_sugg)
        root.addStretch()

    def _toggle_vis(self):
        self.pwd_input.setEchoMode(QLineEdit.Normal if self.pwd_input.echoMode() == QLineEdit.Password else QLineEdit.Password)

    def _start_challenge(self):
        self._challenge_active = True
        self._challenge_start = time.time()
        self.pwd_input.clear()
        self.pwd_input.setFocus()
        self.btn_start_challenge.setEnabled(False)
        self.lbl_challenge_timer.setStyleSheet("color:#ff3333;")
        self._challenge_timer.start(50)

    def _update_challenge_timer(self):
        if not self._challenge_active: return
        elapsed = time.time() - self._challenge_start
        self.lbl_challenge_timer.setText(f"Time: {elapsed:.1f}s")

    def _stop_challenge(self, won):
        self._challenge_active = False
        self._challenge_timer.stop()
        self.btn_start_challenge.setEnabled(True)
        elapsed = time.time() - self._challenge_start
        if won:
            self.lbl_challenge_timer.setText(f"🏆 Cleared in {elapsed:.2f}s!")
            self.lbl_challenge_timer.setStyleSheet("color:#00ff88;")
        else:
            self.lbl_challenge_timer.setText(f"❌ Failed at {elapsed:.2f}s")
            self.lbl_challenge_timer.setStyleSheet("color:#ff3333;")

    @staticmethod
    def _has_sequential(pw):
        low = pw.lower()
        seqs = ["abcdefghijklmnopqrstuvwxyz", "qwertyuiop", "0123456789"]
        for s in seqs:
            for i in range(len(s)-2):
                chunk = s[i:i+3]
                if chunk in low or chunk[::-1] in low: return True
        return False

    @staticmethod
    def _has_repeated(pw):
        for i in range(len(pw)-2):
            if pw[i]==pw[i+1]==pw[i+2]: return True
        return False

    def _analyse(self, pw):
        if not pw:
            self.shield_indicator.set_strength(0, "#ff0000", "Empty")
            self.lbl_entropy.setText("Entropy: — bits")
            for v in self._chk.values(): v.setText("—"); v.setStyleSheet("color:#666;font-size:13px;")
            for v in self._crack.values(): v.setText("—")
            self.txt_sugg.clear()
            return

        # Checks
        has_up = bool(re.search(r"[A-Z]", pw)); has_lo = bool(re.search(r"[a-z]", pw))
        has_di = bool(re.search(r"[0-9]", pw)); has_sp = bool(re.search(r"[^a-zA-Z0-9]", pw))
        is_long = len(pw) >= 8; is_common = pw.lower() in COMMON_PASSWORDS
        has_seq = self._has_sequential(pw); has_rep = self._has_repeated(pw)

        results = {"length": is_long, "upper": has_up, "lower": has_lo, "digits": has_di,
                   "special": has_sp, "common": not is_common, "sequential": not has_seq, "repeated": not has_rep}
        
        for key, ok in results.items():
            self._chk[key].setText("✅" if ok else "❌")
            self._chk[key].setStyleSheet(f"color:{'#00cc00' if ok else '#ff3333'};font-size:14px;")

        tips = []
        if is_common: tips.append("⚠️  Common password! Choose something unique!")
        if not is_long: tips.append("📏  Use at least 8 characters. Aim for 12+.")
        if not has_up: tips.append("🔤  Add uppercase letters.")
        if not has_lo: tips.append("🔡  Add lowercase letters.")
        if not has_di: tips.append("🔢  Include numbers.")
        if not has_sp: tips.append("✨  Special characters (!@#$) dramatically increase strength.")
        if has_seq: tips.append("🔄  Avoid sequential patterns like 'abc', '123'.")
        if has_rep: tips.append("🔁  Avoid repeated characters like 'aaa'.")
        if not tips: tips.append("✅  Great password! Use a password manager to store it safely.")
        self.txt_sugg.setPlainText("\n".join(tips))

        entropy = calculate_entropy(pw)
        _, label, colour = get_strength_level(entropy)
        self.lbl_entropy.setText(f"Entropy: {entropy:.1f} bits")
        
        # Update Shield Game
        bar_v = min(100, max(0, int((entropy / 128) * 100)))
        self.shield_indicator.set_strength(bar_v, colour, label)

        # Crack times
        speeds = {"online": 100, "offline": 10_000_000, "gpu": 100_000_000_000}
        for key, speed in speeds.items():
            t = estimate_crack_time(entropy if not is_common else 0, speed)
            self._crack[key].setText("Instantly (common!)" if is_common else t)
            c = "#ff3333" if any(w in t for w in ("Instantly", "ms", "seconds", "minutes")) else "#ff6600" if any(w in t for w in ("hours", "days")) else "#00cc00"
            self._crack[key].setStyleSheet(f"color:{c};font-size:12px;font-weight:bold;")

        # Challenge Logic
        if self._challenge_active:
            if entropy >= self._challenge_target:
                self._stop_challenge(True)


# ═══════════════════════════════════════════════════════════════════════════
#  TAB 2 — Password Generator (With Passphrase)
# ═══════════════════════════════════════════════════════════════════════════
class PasswordGeneratorTab(QWidget):
    def __init__(self):
        super().__init__()
        self._mode = "password"
        self._build_ui()
        self._generate()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setSpacing(14)

        title = QLabel("🎲 Generator & Passphrases")
        title.setFont(QFont("Segoe UI", 20, QFont.Bold))
        title.setStyleSheet("color:#00d4ff;margin-bottom:4px;")
        root.addWidget(title)

        # Mode Toggle
        mode_row = QHBoxLayout()
        self.btn_mode_pw = QPushButton("Standard Password")
        self.btn_mode_pw.setStyleSheet(PRIMARY_BTN)
        self.btn_mode_pw.clicked.connect(lambda: self._set_mode("password"))
        mode_row.addWidget(self.btn_mode_pw)

        self.btn_mode_pp = QPushButton("Passphrase (Words)")
        self.btn_mode_pp.setStyleSheet(SECONDARY_BTN)
        self.btn_mode_pp.clicked.connect(lambda: self._set_mode("passphrase"))
        mode_row.addWidget(self.btn_mode_pp)
        root.addLayout(mode_row)

        # Display
        g_disp = QGroupBox("Generated")
        g_disp.setStyleSheet(GROUP_STYLE)
        dl = QVBoxLayout(g_disp)
        self.display = QLineEdit()
        self.display.setReadOnly(True); self.display.setAlignment(Qt.AlignCenter)
        self.display.setStyleSheet(
            "QLineEdit{padding:16px;font-size:20px;font-family:'Consolas','Courier New',monospace;"
            "border:2px solid #333;border-radius:8px;background:#1a1a2e;color:#00ff88;letter-spacing:2px;}"
        )
        dl.addWidget(self.display)

        row = QHBoxLayout()
        btn_gen = QPushButton("🔄 Generate New"); btn_gen.setStyleSheet(PRIMARY_BTN)
        btn_gen.clicked.connect(self._generate); row.addWidget(btn_gen)
        self.btn_copy = QPushButton("📋 Copy"); self.btn_copy.setStyleSheet(SECONDARY_BTN)
        self.btn_copy.clicked.connect(self._copy); row.addWidget(self.btn_copy)
        dl.addLayout(row)
        root.addWidget(g_disp)

        # Options Stack
        self.stack = QStackedWidget()
        
        # -- Standard PW Options
        pw_opt = QWidget(); ol = QGridLayout(pw_opt); ol.setSpacing(10)
        lbl_len = QLabel("Length:"); lbl_len.setStyleSheet("color:#ccc;"); ol.addWidget(lbl_len, 0, 0)
        self.slider = QSlider(Qt.Horizontal); self.slider.setRange(4, 64); self.slider.setValue(16)
        self.slider.setStyleSheet("QSlider::groove:horizontal{border:2px solid #333;height:8px;background:#1a1a2e;border-radius:4px;} QSlider::handle:horizontal{background:#00d4ff;width:20px;margin:-6px 0;border-radius:10px;} QSlider::sub-page:horizontal{background:#00d4ff;border-radius:4px;}")
        ol.addWidget(self.slider, 0, 1)
        self.lbl_len_val = QLabel("16"); self.lbl_len_val.setFont(QFont("Segoe UI", 14, QFont.Bold)); self.lbl_len_val.setStyleSheet("color:#00d4ff;"); ol.addWidget(self.lbl_len_val, 0, 2)
        self.slider.valueChanged.connect(lambda v: self.lbl_len_val.setText(str(v)))

        self.chk_up = QCheckBox("Uppercase (A-Z)"); self.chk_up.setChecked(True); self.chk_up.setStyleSheet(CHECKBOX_STYLE); ol.addWidget(self.chk_up, 1, 0, 1, 3)
        self.chk_lo = QCheckBox("Lowercase (a-z)"); self.chk_lo.setChecked(True); self.chk_lo.setStyleSheet(CHECKBOX_STYLE); ol.addWidget(self.chk_lo, 2, 0, 1, 3)
        self.chk_di = QCheckBox("Digits (0-9)"); self.chk_di.setChecked(True); self.chk_di.setStyleSheet(CHECKBOX_STYLE); ol.addWidget(self.chk_di, 3, 0, 1, 3)
        self.chk_sp = QCheckBox("Special (!@#$)"); self.chk_sp.setChecked(True); self.chk_sp.setStyleSheet(CHECKBOX_STYLE); ol.addWidget(self.chk_sp, 4, 0, 1, 3)
        self.stack.addWidget(pw_opt)

        # -- Passphrase Options
        pp_opt = QWidget(); pl = QVBoxLayout(pp_opt)
        lbl_words = QLabel("Number of Words:"); lbl_words.setStyleSheet("color:#ccc;"); pl.addWidget(lbl_words)
        self.slider_words = QSlider(Qt.Horizontal); self.slider_words.setRange(3, 8); self.slider_words.setValue(4)
        self.slider_words.setStyleSheet(self.slider.styleSheet())
        pl.addWidget(self.slider_words)
        
        self.chk_sep = QCheckBox("Hyphen Separator (word-word)"); self.chk_sep.setChecked(True); self.chk_sep.setStyleSheet(CHECKBOX_STYLE); pl.addWidget(self.chk_sep)
        self.chk_cap = QCheckBox("Capitalize Words (Word)"); self.chk_cap.setStyleSheet(CHECKBOX_STYLE); pl.addWidget(self.chk_cap)
        self.stack.addWidget(pp_opt)
        
        root.addWidget(self.stack)

        # Strength
        g_str = QGroupBox("Strength")
        g_str.setStyleSheet(GROUP_STYLE)
        sl = QVBoxLayout(g_str)
        self.gen_bar = QProgressBar(); self.gen_bar.setRange(0, 100); self.gen_bar.setValue(0); self.gen_bar.setTextVisible(False); self.gen_bar.setFixedHeight(20)
        self.gen_bar.setStyleSheet("QProgressBar{border:2px solid #333;border-radius:10px;background:#1a1a2e;} QProgressBar::chunk{border-radius:8px;background:#ff0000;}")
        sl.addWidget(self.gen_bar)
        self.gen_lbl = QLabel(""); self.gen_lbl.setAlignment(Qt.AlignCenter); self.gen_lbl.setStyleSheet("color:#666;font-size:13px;"); sl.addWidget(self.gen_lbl)
        self.gen_ent = QLabel(""); self.gen_ent.setAlignment(Qt.AlignCenter); self.gen_ent.setStyleSheet("color:#00d4ff;font-size:12px;"); sl.addWidget(self.gen_ent)
        root.addWidget(g_str)

        root.addStretch()

    def _set_mode(self, mode):
        self._mode = mode
        if mode == "password":
            self.btn_mode_pw.setStyleSheet(PRIMARY_BTN)
            self.btn_mode_pp.setStyleSheet(SECONDARY_BTN)
            self.stack.setCurrentIndex(0)
        else:
            self.btn_mode_pp.setStyleSheet(PRIMARY_BTN)
            self.btn_mode_pw.setStyleSheet(SECONDARY_BTN)
            self.stack.setCurrentIndex(1)
        self._generate()

    def _generate(self):
        if self._mode == "password":
            chars = ""
            if self.chk_lo.isChecked(): chars += string.ascii_lowercase
            if self.chk_up.isChecked(): chars += string.ascii_uppercase
            if self.chk_di.isChecked(): chars += string.digits
            if self.chk_sp.isChecked(): chars += "!@#$%^&*()_+-="
            if not chars: chars = string.ascii_letters + string.digits
            pw = "".join(secrets.choice(chars) for _ in range(self.slider.value()))
        else:
            num_words = self.slider_words.value()
            words = [secrets.choice(WORDLIST) for _ in range(num_words)]
            if self.chk_cap.isChecked(): words = [w.capitalize() for w in words]
            sep = "-" if self.chk_sep.isChecked() else ""
            pw = sep.join(words)
            
        self.display.setText(pw)
        entropy = calculate_entropy(pw)
        _, label, colour = get_strength_level(entropy)
        bv = min(100, max(0, int((entropy / 128) * 100)))
        self.gen_bar.setValue(bv)
        self.gen_bar.setStyleSheet(f"QProgressBar{{border:2px solid #333;border-radius:10px;background:#1a1a2e;}} QProgressBar::chunk{{border-radius:8px;background:{colour};}}")
        self.gen_lbl.setText(label); self.gen_lbl.setStyleSheet(f"color:{colour};font-size:13px;font-weight:bold;")
        self.gen_ent.setText(f"Entropy: {entropy:.1f} bits")

    def _copy(self):
        QApplication.clipboard().setText(self.display.text())
        self.btn_copy.setText("✅ Copied!")
        QTimer.singleShot(2000, lambda: self.btn_copy.setText("📋 Copy"))


# ═══════════════════════════════════════════════════════════════════════════
#  TAB 3 — Crack Simulator (Same as before, kept for completeness)
# ═══════════════════════════════════════════════════════════════════════════
class CrackSimulatorTab(QWidget):
    def __init__(self):
        super().__init__()
        self._cracking = False; self._attempts = 0
        self._timer = QTimer(); self._timer.timeout.connect(self._step)
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self); root.setSpacing(14)
        title = QLabel("⏱️ Crack Simulator"); title.setFont(QFont("Segoe UI", 20, QFont.Bold)); title.setStyleSheet("color:#00d4ff;"); root.addWidget(title)
        desc = QLabel("See how quickly different passwords can be cracked using brute force."); desc.setWordWrap(True); desc.setStyleSheet("color:#aaa;"); root.addWidget(desc)
        # Setup
        g_setup = QGroupBox("Setup"); g_setup.setStyleSheet(GROUP_STYLE); sl = QVBoxLayout(g_setup)
        row1 = QHBoxLayout(); row1.addWidget(QLabel("Password:")); self.sim_pwd = QLineEdit(); self.sim_pwd.setStyleSheet(INPUT_STYLE); row1.addWidget(self.sim_pwd); sl.addLayout(row1)
        row2 = QHBoxLayout(); row2.addWidget(QLabel("Speed:")); self.speed_combo = QComboBox(); self.speed_combo.addItems(["Online (100/s)", "Offline (10K/s)", "GPU (10M/s)", "Cluster (100B/s)"]); self.speed_combo.setStyleSheet(COMBO_STYLE); row2.addWidget(self.speed_combo); sl.addLayout(row2)
        root.addWidget(g_setup)
        # Controls
        crow = QHBoxLayout()
        self.btn_start = QPushButton("▶ Start"); self.btn_start.setStyleSheet(PRIMARY_BTN); self.btn_start.clicked.connect(self._start); crow.addWidget(self.btn_start)
        self.btn_stop = QPushButton("⏹ Stop"); self.btn_stop.setStyleSheet(SECONDARY_BTN); self.btn_stop.setEnabled(False); self.btn_stop.clicked.connect(self._stop); crow.addWidget(self.btn_stop)
        root.addLayout(crow)
        # Results
        g_res = QGroupBox("Results"); g_res.setStyleSheet(GROUP_STYLE); rl = QGridLayout(g_res)
        self._res = {}
        for i, (txt, key) in enumerate([("Target:", "target"), ("Space:", "charset"), ("Combinations:", "combos"), ("Attempts:", "attempts"), ("Time:", "elapsed"), ("Progress:", "progress"), ("Status:", "status")]):
            l = QLabel(txt); l.setStyleSheet("color:#ccc;"); rl.addWidget(l, i, 0)
            v = QLabel("—"); v.setStyleSheet("color:#00d4ff;font-weight:bold;"); rl.addWidget(v, i, 1); self._res[key] = v
        self.sim_bar = QProgressBar(); self.sim_bar.setRange(0, 10000); self.sim_bar.setValue(0); self.sim_bar.setFixedHeight(20)
        self.sim_bar.setStyleSheet("QProgressBar{border:2px solid #333;border-radius:10px;background:#1a1a2e;} QProgressBar::chunk{border-radius:8px;background:#ff6600;}")
        rl.addWidget(self.sim_bar, len(self._res), 0, 1, 2)
        root.addWidget(g_res); root.addStretch()

    def _start(self):
        pw = self.sim_pwd.text()
        if not pw: return
        self._cracking = True; self._attempts = 0; self._t0 = time.time()
        cs = sum([26 if re.search(r"[a-z]", pw) else 0, 26 if re.search(r"[A-Z]", pw) else 0, 10 if re.search(r"[0-9]", pw) else 0, 33 if re.search(r"[^a-zA-Z0-9]", pw) else 0])
        self._cs = cs or 26; self._total = self._cs ** len(pw)
        self._gps = [100, 10000, 10000000, 100000000000][self.speed_combo.currentIndex()]
        self._res["target"].setText("••••••"); self._res["charset"].setText(f"{self._cs} chars"); self._res["combos"].setText(f"{self._total:,}")
        self._res["status"].setText("🔄 Cracking…"); self._res["status"].setStyleSheet("color:#ff6600;font-weight:bold;")
        self._timer.start(50); self.btn_start.setEnabled(False); self.btn_stop.setEnabled(True)

    def _step(self):
        if not self._cracking: return
        elapsed = time.time() - self._t0; self._attempts = int(elapsed * self._gps)
        effort = 2 ** calculate_entropy(self.sim_pwd.text())
        if self._attempts >= effort or elapsed > 300:
            self._cracking = False; self._timer.stop()
            self._res["status"].setText("🔓 CRACKED!"); self._res["status"].setStyleSheet("color:#ff3333;font-weight:bold;")
            self._res["target"].setText(self.sim_pwd.text()); self.sim_bar.setValue(10000)
            self.btn_start.setEnabled(True); self.btn_stop.setEnabled(False); return
        self._res["attempts"].setText(f"{self._attempts:.2e}")
        self._res["elapsed"].setText(f"{elapsed:.1f}s")
        prog = min(10000, int((math.log(self._attempts+1)/math.log(effort+1))*10000))
        self.sim_bar.setValue(prog); self._res["progress"].setText(f"{prog/100:.4f}%")

    def _stop(self):
        self._cracking = False; self._timer.stop(); self._res["status"].setText("⏹ Stopped"); self._res["status"].setStyleSheet("color:#ffcc00;font-weight:bold;")
        self.btn_start.setEnabled(True); self.btn_stop.setEnabled(False)


# ═══════════════════════════════════════════════════════════════════════════
#  TAB 4 — Hash Explorer (Same as before, kept for completeness)
# ═══════════════════════════════════════════════════════════════════════════
class HashExplorerTab(QWidget):
    def __init__(self): super().__init__(); self._build_ui()
    def _build_ui(self):
        root = QVBoxLayout(self); root.setSpacing(14)
        title = QLabel("🔍 Hash Explorer"); title.setFont(QFont("Segoe UI", 20, QFont.Bold)); title.setStyleSheet("color:#00d4ff;"); root.addWidget(title)
        g_in = QGroupBox("Input"); g_in.setStyleSheet(GROUP_STYLE); il = QVBoxLayout(g_in)
        self.hash_input = QLineEdit(); self.hash_input.setPlaceholderText("Enter text…"); self.hash_input.setStyleSheet(INPUT_STYLE); self.hash_input.textChanged.connect(self._update); il.addWidget(self.hash_input); root.addWidget(g_in)
        g_out = QGroupBox("Hashes"); g_out.setStyleSheet(GROUP_STYLE); ol = QVBoxLayout(g_out)
        self._hashes = {}
        for name, key, note in [("MD5", "md5", "⚠️ Broken"), ("SHA-256", "sha256", "✅ Secure"), ("SHA-512", "sha512", "✅ Secure")]:
            nl = QLabel(f"{name}:"); nl.setStyleSheet("color:#00d4ff;font-weight:bold;"); ol.addWidget(nl)
            vl = QLabel("—"); vl.setWordWrap(True); vl.setStyleSheet("color:#00ff88;font-family:monospace;font-size:12px;padding:4px;background:#1a1a2e;border-radius:3px;"); ol.addWidget(vl)
            ntl = QLabel(note); ntl.setStyleSheet("color:#888;font-size:11px;"); ol.addWidget(ntl); self._hashes[key] = vl
        root.addWidget(g_out)
        g_salt = QGroupBox("🧂 Salting Demo"); g_salt.setStyleSheet(GROUP_STYLE); sal = QVBoxLayout(g_salt)
        info = QLabel("Salting adds random data before hashing, preventing Rainbow Table attacks."); info.setWordWrap(True); info.setStyleSheet("color:#ccc;"); sal.addWidget(info)
        self._salted = []
        for _ in range(3):
            lbl = QLabel("—"); lbl.setWordWrap(True); lbl.setStyleSheet("color:#ff9900;font-family:monospace;font-size:11px;padding:4px;background:#1a1a2e;border-radius:3px;"); sal.addWidget(lbl); self._salted.append(lbl)
        root.addWidget(g_salt); root.addStretch()

    def _update(self, text):
        if not text:
            for v in self._hashes.values(): v.setText("—")
            for lbl in self._salted: lbl.setText("—"); return
        enc = text.encode("utf-8")
        self._hashes["md5"].setText(hashlib.md5(enc).hexdigest())
        self._hashes["sha256"].setText(hashlib.sha256(enc).hexdigest())
        self._hashes["sha512"].setText(hashlib.sha512(enc).hexdigest())
        for lbl in self._salted:
            salt = secrets.token_hex(4)
            lbl.setText(f"Salt: {salt} → {hashlib.sha256((salt+text).encode()).hexdigest()}")


# ═══════════════════════════════════════════════════════════════════════════
#  TAB 5 — Learn (Enhanced with Phishing Game)
# ═══════════════════════════════════════════════════════════════════════════
class LearnTab(QWidget):
    def __init__(self): super().__init__(); self._build_ui()
    def _build_ui(self):
        root = QVBoxLayout(self)
        title = QLabel("📚 Learn & Games"); title.setFont(QFont("Segoe UI", 20, QFont.Bold)); title.setStyleSheet("color:#00d4ff;"); root.addWidget(title)
        scroll = QScrollArea(); scroll.setWidgetResizable(True); scroll.setStyleSheet("QScrollArea{border:none;background:transparent;}")
        content = QWidget(); cl = QVBoxLayout(content); cl.setSpacing(16)

        # Password Quiz
        g_quiz = QGroupBox("🧪 Password Knowledge Quiz"); g_quiz.setStyleSheet(GROUP_STYLE); ql = QVBoxLayout(g_quiz)
        self._quiz_fb = []
        quizzes = [
            {"q": "1. What's the best way to manage 50+ unique passwords?", "opts": ["A) Reuse one", "B) Notebook", "C) Password Manager", "D) Birthday+Site"], "ans": 2},
            {"q": "2. Which is strongest against brute force?", "opts": ["A) P@ssw0rd!", "B) correct-horse-battery-staple", "C) MyDog2023", "D) qwerty123"], "ans": 1},
        ]
        for qd in quizzes:
            ql.addWidget(self._make_label(qd["q"], "#ccc", 13, True))
            for idx, opt in enumerate(qd["opts"]):
                btn = QPushButton(opt); btn.setStyleSheet("QPushButton{background:#2a2a3e;color:#ccc;border:1px solid #444;border-radius:4px;padding:7px;text-align:left;} QPushButton:hover{background:#3a3a4e;border-color:#00d4ff;}")
                fb_ref = len(self._quiz_fb)
                btn.clicked.connect(lambda _, d=qd, i=idx, ref=fb_ref: self._answer(d, i, ref))
                ql.addWidget(btn)
            fb = QLabel(""); fb.setWordWrap(True); ql.addWidget(fb); self._quiz_fb.append(fb)
        cl.addWidget(g_quiz)

        # Phishing Game
        g_phish = QGroupBox("🎣 Spot the Phishing URL Game"); g_phish.setStyleSheet(GROUP_STYLE); pl = QVBoxLayout(g_phish)
        pl.addWidget(self._make_label("Hackers trick you into clicking fake links. Can you spot the fake URL?", "#ccc", 12, False))
        self._phish_fb = []
        phishes = [
            {"url": "https://www.google.com/search", "safe": True},
            {"url": "https://g00gle-search.com/login", "safe": False},
            {"url": "https://www.paypal.com/pay", "safe": True},
            {"url": "https://www.paypa1.com/secure", "safe": False},  # paypa1 with a one
            {"url": "https://amazon.com/gp/cart", "safe": True},
            {"url": "https://amazon-deals.shop/item", "safe": False},
        ]
        for p in phishes:
            btn = QPushButton(p["url"]); btn.setStyleSheet("QPushButton{background:#1a1a2e;color:#00d4ff;border:1px solid #555;border-radius:4px;padding:8px;font-family:monospace;font-size:12px;} QPushButton:hover{background:#2a2a3e;border-color:white;}")
            fb_ref = len(self._phish_fb)
            btn.clicked.connect(lambda _, d=p, ref=fb_ref: self._phish_check(d, ref))
            pl.addWidget(btn)
            fb = QLabel(""); fb.setWordWrap(True); pl.addWidget(fb); self._phish_fb.append(fb)
        cl.addWidget(g_phish)
        cl.addStretch()
        scroll.setWidget(content); root.addWidget(scroll)

    def _make_label(self, text, color, size, bold):
        l = QLabel(text); l.setWordWrap(True)
        l.setStyleSheet(f"color:{color};font-size:{size}px;font-weight:{'bold' if bold else 'normal'};margin-top:8px;")
        return l

    def _answer(self, qdata, idx, fb_idx):
        fb = self._quiz_fb[fb_idx]
        if idx == qdata["ans"]:
            fb.setText("✅ Correct!"); fb.setStyleSheet("color:#00cc00;font-size:12px;")
        else:
            fb.setText(f"❌ Wrong. It was: {qdata['opts'][qdata['ans']]}"); fb.setStyleSheet("color:#ff3333;font-size:12px;")

    def _phish_check(self, data, fb_idx):
        fb = self._phish_fb[fb_idx]
        if data["safe"]:
            fb.setText("✅ Safe! This is the legitimate domain."); fb.setStyleSheet("color:#00cc00;font-size:12px;")
        else:
            fb.setText("🚨 PHISHING! Look closely at the domain name. Hackers use misspellings (paypa1) or wrong extensions (.shop)."); fb.setStyleSheet("color:#ff3333;font-size:12px;")


# ═══════════════════════════════════════════════════════════════════════════
#  Main Window
# ═══════════════════════════════════════════════════════════════════════════
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔐 Password Security Learning App")
        self.setMinimumSize(780, 870)
        self.resize(820, 900)
        self._build()

    def _build(self):
        self.setStyleSheet("""
            QMainWindow { background: #0f0f23; }
            QWidget     { background: #0f0f23; }
            QTabWidget::pane { border: 2px solid #333; border-radius: 8px; background: #0f0f23; }
            QTabBar::tab { background: #1a1a2e; color: #888;
                padding: 12px 22px; margin-right: 4px;
                border-top-left-radius: 8px; border-top-right-radius: 8px;
                font-size: 13px; font-weight: bold; min-width: 110px; }
            QTabBar::tab:selected { background: #2a2a4e; color: #00d4ff; }
            QTabBar::tab:hover    { background: #2a2a3e; color: #ccc; }
        """)
        central = QWidget(); self.setCentralWidget(central)
        vbox = QVBoxLayout(central); vbox.setContentsMargins(16, 16, 16, 16); vbox.setSpacing(8)
        hdr = QLabel("🔐 Password Security Learning App"); hdr.setFont(QFont("Segoe UI", 24, QFont.Bold)); hdr.setAlignment(Qt.AlignCenter); hdr.setStyleSheet("color:#00d4ff;margin-bottom:2px;"); vbox.addWidget(hdr)
        sub = QLabel("Learn how to create, evaluate, and protect your passwords"); sub.setAlignment(Qt.AlignCenter); sub.setStyleSheet("color:#888;font-size:14px;margin-bottom:10px;"); vbox.addWidget(sub)
        tabs = QTabWidget()
        tabs.addTab(PasswordAnalyzerTab(),  "🔐 Analyser")
        tabs.addTab(PasswordGeneratorTab(),  "🎲 Generator")
        tabs.addTab(CrackSimulatorTab(),     "⏱️ Crack Sim")
        tabs.addTab(HashExplorerTab(),       "🔍 Hashes")
        tabs.addTab(LearnTab(),              "📚 Learn")
        vbox.addWidget(tabs)


def main():
    app = QApplication(sys.argv)
    app.setFont(QFont("Segoe UI", 11))
    win = MainWindow()
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()