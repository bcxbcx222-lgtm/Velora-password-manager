import sys
import os
import traceback
from pathlib import Path

# --- ФИКС ДЛЯ СБОРКИ В EXE / PYW ---
LOG_FILE = Path(__file__).parent / "crash_log.txt"

def log_uncaught_exceptions(exctype, value, tb):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write("=== ОШИБКА ===\n")
        traceback.print_exception(exctype, value, tb, file=f)
    from PyQt6.QtWidgets import QApplication, QMessageBox
    app = QApplication.instance() or QApplication(sys.argv)
    QMessageBox.critical(None, "Ошибка", f"Произошла ошибка:\n{value}\n\nПодробности в crash_log.txt")
    sys.exit(1)

sys.excepthook = log_uncaught_exceptions

class NullWriter:
    def write(self, text): pass
    def flush(self): pass

if sys.stdout is None: sys.stdout = NullWriter()
if sys.stderr is None: sys.stderr = NullWriter()
# ------------------------------------

import json
import base64
import hashlib
import sqlite3
import secrets
import string

from cryptography.fernet import Fernet, InvalidToken
from PyQt6.QtCore import Qt, QPropertyAnimation, QEasingCurve, QRect, pyqtSignal, QTimer, QSize
from PyQt6.QtGui import QFont, QGuiApplication
from PyQt6.QtWidgets import (
    QApplication, QWidget, QMainWindow, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QLineEdit, QPushButton, QFrame, QStackedWidget, QMessageBox,
    QListWidget, QListWidgetItem, QDialog, QDialogButtonBox, QCheckBox
)

APP_DIR = Path.home() / ".velora_password_manager"
DB_PATH = APP_DIR / "vault_v2.db"
APP_DIR.mkdir(parents=True, exist_ok=True)


def derive_key(master_password: str, salt: bytes) -> bytes:
    key = hashlib.pbkdf2_hmac(
        "sha256",
        master_password.encode("utf-8"),
        salt,
        390_000,
        dklen=32
    )
    return base64.urlsafe_b64encode(key)


def mask_email(email: str) -> str:
    """Маскирует часть email адреса (например: us***@gmail.com)."""
    if not email or "@" not in email:
        return "***"
    parts = email.split("@")
    name, domain = parts[0], parts[1]
    if len(name) <= 2:
        masked_name = name[0] + "***"
    else:
        masked_name = name[:2] + "***"
    return f"{masked_name}@{domain}"


class Vault:
    def __init__(self, master_password: str):
        self.master_password = master_password
        self.conn = sqlite3.connect(DB_PATH)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS metadata (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                salt BLOB NOT NULL,
                verifier BLOB NOT NULL
            )
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service BLOB NOT NULL,
                username BLOB NOT NULL,
                email BLOB,
                password BLOB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        self.conn.commit()

        # Проверка и добавление колонки email для старых баз
        cursor = self.conn.execute("PRAGMA table_info(entries)")
        columns = [column[1] for column in cursor.fetchall()]
        if "email" not in columns:
            self.conn.execute("ALTER TABLE entries ADD COLUMN email BLOB")
            self.conn.commit()

        row = self.conn.execute(
            "SELECT salt, verifier FROM metadata WHERE id = 1"
        ).fetchone()

        if row is None:
            self.salt = secrets.token_bytes(16)
            self.key = derive_key(master_password, self.salt)
            self.fernet = Fernet(self.key)
            verifier = self.fernet.encrypt(b"VELORA_VAULT_OK")
            self.conn.execute(
                "INSERT INTO metadata (id, salt, verifier) VALUES (1, ?, ?)",
                (self.salt, verifier)
            )
            self.conn.commit()
        else:
            self.salt = row[0]
            self.key = derive_key(master_password, self.salt)
            self.fernet = Fernet(self.key)
            try:
                self.fernet.decrypt(row[1])
            except InvalidToken:
                self.conn.close()
                raise ValueError("Неверный мастер-пароль.")

    def _enc(self, value: str) -> bytes:
        if value is None:
            return b""
        return self.fernet.encrypt(value.encode("utf-8"))

    def _dec(self, value: bytes) -> str:
        if not value:
            return ""
        return self.fernet.decrypt(value).decode("utf-8")

    def add(self, service: str, username: str, email: str, password: str):
        self.conn.execute(
            "INSERT INTO entries (service, username, email, password) VALUES (?, ?, ?, ?)",
            (self._enc(service), self._enc(username), self._enc(email), self._enc(password))
        )
        self.conn.commit()

    def get_all(self):
        rows = self.conn.execute(
            "SELECT id, service, username, email, password FROM entries ORDER BY id DESC"
        ).fetchall()
        result = []
        for row in rows:
            result.append({
                "id": row[0],
                "service": self._dec(row[1]),
                "username": self._dec(row[2]),
                "email": self._dec(row[3]) if row[3] else "",
                "password": self._dec(row[4])
            })
        return result

    def delete(self, entry_id: int):
        self.conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
        self.conn.commit()

    def close(self):
        self.conn.close()


class HoverButton(QPushButton):
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self._animation = None
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def enterEvent(self, event):
        self._animate_scale(True)
        super().enterEvent(event)

    def leaveEvent(self, event):
        self._animate_scale(False)
        super().leaveEvent(event)

    def _animate_scale(self, enlarged):
        if not self.isVisible():
            return
        g = self.geometry()
        amount = 3 if enlarged else 0
        target = QRect(
            g.x() - amount,
            g.y() - amount,
            g.width() + amount * 2,
            g.height() + amount * 2
        )

        if self._animation and self._animation.state() == QPropertyAnimation.State.Running:
            self._animation.stop()

        self._animation = QPropertyAnimation(self, b"geometry")
        self._animation.setDuration(100)
        self._animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._animation.setStartValue(g)
        self._animation.setEndValue(target)
        self._animation.start()


class Toast(QFrame):
    def __init__(self, parent, text):
        super().__init__(parent)
        self.setObjectName("toast")
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.ToolTip)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(18, 10, 18, 10)
        label = QLabel(text)
        label.setObjectName("toastLabel")
        layout.addWidget(label)
        self.adjustSize()

        if parent:
            parent_pos = parent.mapToGlobal(parent.rect().center())
            self.move(
                parent_pos.x() - self.width() // 2,
                parent_pos.y() + parent.height() // 2 - 80
            )
        self.show()
        self.raise_()
        QTimer.singleShot(1700, self.close)


class ConfirmMasterDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Подтверждение")
        self.setFixedSize(360, 200)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)

        lbl = QLabel("Введите мастер-пароль\nдля просмотра:")
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(lbl)

        self.input = QLineEdit()
        self.input.setEchoMode(QLineEdit.EchoMode.Password)
        self.input.setPlaceholderText("Мастер-пароль")
        self.input.returnPressed.connect(self.accept)
        layout.addWidget(self.input)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | 
            QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def get_password(self):
        return self.input.text()


class PasswordCard(QFrame):
    deleted = pyqtSignal(int)

    def __init__(self, vault, entry, parent=None):
        super().__init__(parent)
        self.vault = vault
        self.entry = entry
        self.email_unlocked = False
        self.setObjectName("passwordCard")
        self.setMinimumHeight(190)

        main = QVBoxLayout(self)
        main.setContentsMargins(20, 16, 20, 16)
        main.setSpacing(10)

        top = QHBoxLayout()
        service = QLabel(entry["service"])
        service.setObjectName("serviceTitle")
        top.addWidget(service)
        top.addStretch()

        delete_btn = QPushButton("Удалить")
        delete_btn.setObjectName("dangerButton")
        delete_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        delete_btn.clicked.connect(self.remove)
        top.addWidget(delete_btn)
        main.addLayout(top)

        info = QGridLayout()
        info.setHorizontalSpacing(10)
        info.setVerticalSpacing(7)

        self.username = QLineEdit(entry["username"])
        self.username.setReadOnly(True)

        # Поле почты
        self.email = QLineEdit(mask_email(entry["email"]) if entry["email"] else "Не указана")
        self.email.setReadOnly(True)

        # Поле пароля
        self.password = QLineEdit(entry["password"])
        self.password.setReadOnly(True)
        self.password.setEchoMode(QLineEdit.EchoMode.Password)

        # Глаз для Почты
        self.email_eye_btn = QPushButton("👁")
        self.email_eye_btn.setObjectName("smallButton")
        self.email_eye_btn.setFixedWidth(38)
        self.email_eye_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.email_eye_btn.clicked.connect(self.toggle_email_visibility)

        # Глаз для Пароля
        self.pass_eye_btn = QPushButton("👁")
        self.pass_eye_btn.setObjectName("smallButton")
        self.pass_eye_btn.setFixedWidth(38)
        self.pass_eye_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.pass_eye_btn.clicked.connect(self.toggle_password_visibility)

        copy_user = QPushButton("Копировать")
        copy_email = QPushButton("Копировать")
        copy_pass = QPushButton("Копировать")
        for btn in (copy_user, copy_email, copy_pass):
            btn.setObjectName("smallButton")

        copy_user.clicked.connect(lambda: self.copy_text(entry["username"], "Логин скопирован"))
        copy_email.clicked.connect(lambda: self.copy_text(entry["email"], "Почта скопирована"))
        copy_pass.clicked.connect(lambda: self.copy_text(entry["password"], "Пароль скопирован"))

        # Размещение в сетке
        # Ссылка/Логин
        info.addWidget(QLabel("Логин"), 0, 0)
        info.addWidget(self.username, 0, 1, 1, 2)
        info.addWidget(copy_user, 0, 3)

        # Почта
        info.addWidget(QLabel("Почта"), 1, 0)
        info.addWidget(self.email, 1, 1)
        info.addWidget(self.email_eye_btn, 1, 2)
        info.addWidget(copy_email, 1, 3)

        # Пароль
        info.addWidget(QLabel("Пароль"), 2, 0)
        info.addWidget(self.password, 2, 1)
        info.addWidget(self.pass_eye_btn, 2, 2)
        info.addWidget(copy_pass, 2, 3)

        main.addLayout(info)

    def toggle_email_visibility(self):
        if not self.entry["email"]:
            return
        if not self.email_unlocked:
            dialog = ConfirmMasterDialog(self)
            if dialog.exec() == QDialog.DialogCode.Accepted:
                if dialog.get_password() == self.vault.master_password:
                    self.email.setText(self.entry["email"])
                    self.email_unlocked = True
                else:
                    QMessageBox.critical(self, "Ошибка", "Неверный мастер-пароль!")
        else:
            self.email.setText(mask_email(self.entry["email"]))
            self.email_unlocked = False

    def toggle_password_visibility(self):
        if self.password.echoMode() == QLineEdit.EchoMode.Password:
            dialog = ConfirmMasterDialog(self)
            if dialog.exec() == QDialog.DialogCode.Accepted:
                if dialog.get_password() == self.vault.master_password:
                    self.password.setEchoMode(QLineEdit.EchoMode.Normal)
                else:
                    QMessageBox.critical(self, "Ошибка", "Неверный мастер-пароль!")
        else:
            self.password.setEchoMode(QLineEdit.EchoMode.Password)

    def copy_text(self, text, message):
        if not text:
            Toast(self.window(), "Пусто для копирования")
            return
        QGuiApplication.clipboard().setText(text)
        Toast(self.window(), message)

    def remove(self):
        answer = QMessageBox.question(
            self,
            "Удалить запись",
            f"Удалить «{self.entry['service']}»?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if answer == QMessageBox.StandardButton.Yes:
            self.vault.delete(self.entry["id"])
            self.deleted.emit(self.entry["id"])


class MasterPasswordDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Velora — Защищённое хранилище")
        self.setFixedSize(430, 310)
        self.password = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(36, 32, 36, 30)
        layout.setSpacing(16)

        title = QLabel("VELORA")
        title.setObjectName("brand")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        subtitle = QLabel("Введите мастер-пароль\nдля открытия защищённого хранилища")
        subtitle.setObjectName("dialogSubtitle")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(subtitle)

        self.input = QLineEdit()
        self.input.setPlaceholderText("Мастер-пароль")
        self.input.setEchoMode(QLineEdit.EchoMode.Password)
        self.input.returnPressed.connect(self.accept)
        layout.addWidget(self.input)

        self.show_pass = QCheckBox("Показать пароль")
        self.show_pass.toggled.connect(
            lambda checked: self.input.setEchoMode(
                QLineEdit.EchoMode.Normal if checked
                else QLineEdit.EchoMode.Password
            )
        )
        layout.addWidget(self.show_pass)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok |
            QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def accept(self):
        if not self.input.text():
            QMessageBox.warning(self, "Ошибка", "Введите мастер-пароль.")
            return
        self.password = self.input.text()
        super().accept()


class AddPage(QWidget):
    saved = pyqtSignal()

    def __init__(self, vault):
        super().__init__()
        self.vault = vault

        layout = QVBoxLayout(self)
        layout.setContentsMargins(80, 50, 80, 50)

        header = QLabel("Добавить пароль")
        header.setObjectName("pageTitle")
        layout.addWidget(header)

        subtitle = QLabel("Сохраните данные аккаунта в зашифрованном хранилище.")
        subtitle.setObjectName("muted")
        layout.addWidget(subtitle)

        layout.addSpacing(28)

        form = QFrame()
        form.setObjectName("formCard")
        form_layout = QVBoxLayout(form)
        form_layout.setContentsMargins(30, 30, 30, 30)
        form_layout.setSpacing(14)

        self.service = QLineEdit()
        self.service.setPlaceholderText("Название сервиса / приложения  ·  Steam, Google...")
        self.username = QLineEdit()
        self.username.setPlaceholderText("Логин / Username")
        self.email = QLineEdit()
        self.email.setPlaceholderText("Электронная почта (Email)")
        self.password = QLineEdit()
        self.password.setPlaceholderText("Пароль")
        self.password.setEchoMode(QLineEdit.EchoMode.Password)

        for field in (self.service, self.username, self.email, self.password):
            form_layout.addWidget(field)

        row = QHBoxLayout()
        row.addStretch()

        generate = HoverButton("Сгенерировать пароль")
        generate.setObjectName("secondaryButton")
        generate.clicked.connect(self.generate_password)

        save = HoverButton("Сохранить пароль")
        save.setObjectName("primaryButton")
        save.clicked.connect(self.save)

        row.addWidget(generate)
        row.addWidget(save)
        form_layout.addLayout(row)

        layout.addWidget(form)
        layout.addStretch()

    def generate_password(self):
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
        password = "".join(secrets.choice(alphabet) for _ in range(20))
        self.password.setText(password)
        self.password.setEchoMode(QLineEdit.EchoMode.Normal)

    def save(self):
        service = self.service.text().strip()
        username = self.username.text().strip()
        email = self.email.text().strip()
        password = self.password.text()

        if not service or not username or not password:
            QMessageBox.warning(
                self,
                "Не хватает данных",
                "Заполните сервис, логин и пароль."
            )
            return

        self.vault.add(service, username, email, password)
        self.service.clear()
        self.username.clear()
        self.email.clear()
        self.password.clear()
        Toast(self.window(), "Успешно сохранено")
        self.saved.emit()


class PasswordsPage(QWidget):
    def __init__(self, vault):
        super().__init__()
        self.vault = vault

        layout = QVBoxLayout(self)
        layout.setContentsMargins(80, 42, 80, 42)

        header_row = QHBoxLayout()
        title = QLabel("Ваши пароли")
        title.setObjectName("pageTitle")
        header_row.addWidget(title)
        header_row.addStretch()

        self.count = QLabel()
        self.count.setObjectName("countBadge")
        header_row.addWidget(self.count)
        layout.addLayout(header_row)

        subtitle = QLabel("Все записи хранятся локально и шифруются мастер-паролем.")
        subtitle.setObjectName("muted")
        layout.addWidget(subtitle)
        layout.addSpacing(22)

        self.list = QListWidget()
        self.list.setObjectName("passwordList")
        self.list.setFrameShape(QFrame.Shape.NoFrame)
        self.list.setSpacing(12)
        self.list.setVerticalScrollMode(QListWidget.ScrollMode.ScrollPerPixel)
        layout.addWidget(self.list)

        self.refresh()

    def refresh(self):
        self.list.clear()
        entries = self.vault.get_all()
        self.count.setText(f"{len(entries)} записей")

        if not entries:
            empty = QListWidgetItem()
            empty.setSizeHint(self._empty_size())
            self.list.addItem(empty)
            widget = QFrame()
            widget.setObjectName("emptyCard")
            box = QVBoxLayout(widget)
            box.setAlignment(Qt.AlignmentFlag.AlignCenter)
            label = QLabel("Пока нет сохранённых паролей")
            label.setObjectName("emptyTitle")
            hint = QLabel("Откройте «Добавить», чтобы создать первую запись.")
            hint.setObjectName("muted")
            box.addWidget(label, alignment=Qt.AlignmentFlag.AlignCenter)
            box.addWidget(hint, alignment=Qt.AlignmentFlag.AlignCenter)
            self.list.setItemWidget(empty, widget)
            return

        for entry in entries:
            item = QListWidgetItem()
            item.setSizeHint(self._card_size())
            self.list.addItem(item)
            card = PasswordCard(self.vault, entry)
            card.deleted.connect(self.refresh)
            self.list.setItemWidget(item, card)

    def _card_size(self):
        return QSize(100, 210)

    def _empty_size(self):
        return QSize(100, 180)


class MainWindow(QMainWindow):
    def __init__(self, vault):
        super().__init__()
        self.vault = vault
        self.setWindowTitle("Velora Password Manager")
        self.resize(1120, 760)
        self.setMinimumSize(900, 650)

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        nav = QFrame()
        nav.setObjectName("nav")
        nav.setFixedHeight(86)
        nav_layout = QHBoxLayout(nav)
        nav_layout.setContentsMargins(34, 18, 34, 18)
        nav_layout.setSpacing(10)

        brand = QLabel("VELORA")
        brand.setObjectName("brandNav")
        nav_layout.addWidget(brand)
        nav_layout.addSpacing(25)

        self.passwords_btn = HoverButton("Пароли")
        self.add_btn = HoverButton("Добавить")
        self.passwords_btn.setObjectName("navButton")
        self.add_btn.setObjectName("navButton")

        self.passwords_btn.clicked.connect(lambda: self.switch_page(0))
        self.add_btn.clicked.connect(lambda: self.switch_page(1))

        nav_layout.addWidget(self.passwords_btn)
        nav_layout.addWidget(self.add_btn)
        nav_layout.addStretch()

        secure = QLabel("●  LOCAL VAULT")
        secure.setObjectName("secure")
        nav_layout.addWidget(secure)

        root.addWidget(nav)

        self.stack = QStackedWidget()
        self.passwords_page = PasswordsPage(vault)
        self.add_page = AddPage(vault)
        self.add_page.saved.connect(self.passwords_page.refresh)

        self.stack.addWidget(self.passwords_page)
        self.stack.addWidget(self.add_page)
        root.addWidget(self.stack)

        self.switch_page(0)

    def switch_page(self, index):
        self.stack.setCurrentIndex(index)
        self.passwords_btn.setProperty("active", index == 0)
        self.add_btn.setProperty("active", index == 1)
        self.passwords_btn.style().unpolish(self.passwords_btn)
        self.passwords_btn.style().polish(self.passwords_btn)
        self.add_btn.style().unpolish(self.add_btn)
        self.add_btn.style().polish(self.add_btn)

    def closeEvent(self, event):
        self.vault.close()
        event.accept()


STYLESHEET = """
* {
    font-family: "Segoe UI", Arial, sans-serif;
    color: #eeeeef;
}

QMainWindow, QWidget {
    background: #0b0b0d;
}

QFrame#nav {
    background: #101012;
    border-bottom: 1px solid #252529;
}

QLabel#brandNav, QLabel#brand {
    font-size: 22px;
    font-weight: 800;
    letter-spacing: 3px;
    color: #ffffff;
}

QLabel#pageTitle {
    font-size: 32px;
    font-weight: 750;
    color: #ffffff;
}

QLabel#muted, QLabel#dialogSubtitle {
    color: #85858d;
    font-size: 14px;
}

QLabel#secure {
    color: #77777f;
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 1px;
}

QLabel#countBadge {
    background: #18181c;
    border: 1px solid #29292e;
    border-radius: 12px;
    padding: 7px 12px;
    color: #a6a6ae;
}

QPushButton#navButton {
    background: transparent;
    border: 1px solid #29292e;
    border-radius: 13px;
    padding: 12px 22px;
    font-size: 14px;
    font-weight: 650;
    color: #9d9da5;
}

QPushButton#navButton:hover {
    background: #1c1c20;
    color: #ffffff;
    border-color: #45454d;
}

QPushButton#navButton[active="true"] {
    background: #f0f0f2;
    color: #0b0b0d;
    border-color: #000000;
}

QPushButton#primaryButton {
    background: #eeeeef;
    color: #0a0a0b;
    border: 2px solid #000000;
    border-radius: 13px;
    padding: 13px 22px;
    font-weight: 750;
}

QPushButton#primaryButton:hover {
    background: #ffffff;
}

QPushButton#secondaryButton {
    background: #17171a;
    color: #dddddf;
    border: 1px solid #34343a;
    border-radius: 13px;
    padding: 13px 18px;
    font-weight: 650;
}

QPushButton#secondaryButton:hover {
    background: #222226;
    border-color: #55555e;
}

QFrame#formCard {
    background: #111113;
    border: 1px solid #29292e;
    border-radius: 22px;
}

QLineEdit {
    background: #17171a;
    border: 1px solid #2e2e34;
    border-radius: 12px;
    padding: 8px 14px;
    min-height: 24px;
    color: #f4f4f5;
    selection-background-color: #4a4a50;
    font-size: 14px;
}

QLineEdit:focus {
    border: 1px solid #77777f;
    background: #1a1a1e;
}

QListWidget#passwordList {
    background: transparent;
    outline: none;
}

QFrame#passwordCard, QFrame#emptyCard {
    background: #111113;
    border: 1px solid #29292e;
    border-radius: 18px;
}

QFrame#passwordCard:hover {
    border-color: #414149;
}

QLabel#serviceTitle {
    font-size: 18px;
    font-weight: 720;
    color: #ffffff;
}

QPushButton#smallButton {
    background: #1a1a1e;
    border: 1px solid #303037;
    border-radius: 9px;
    padding: 8px 13px;
    color: #c8c8ce;
}

QPushButton#smallButton:hover {
    background: #25252a;
    color: #ffffff;
}

QPushButton#dangerButton {
    background: transparent;
    border: 1px solid #30292b;
    border-radius: 9px;
    padding: 7px 12px;
    color: #a9878b;
}

QPushButton#dangerButton:hover {
    background: #24191b;
    color: #e5b9bd;
}

QLabel#emptyTitle {
    font-size: 18px;
    font-weight: 700;
    color: #d8d8dc;
}

QFrame#toast {
    background: #eeeeef;
    border: 2px solid #000000;
    border-radius: 12px;
}

QLabel#toastLabel {
    color: #0a0a0b;
    font-weight: 700;
}

QDialog {
    background: #111113;
}

QDialog QLineEdit {
    min-height: 20px;
}

QDialogButtonBox QPushButton {
    background: #eeeeef;
    color: #0a0a0b;
    border: 2px solid #000000;
    border-radius: 10px;
    padding: 9px 22px;
    font-weight: 700;
}

QCheckBox {
    color: #9d9da5;
}

QScrollBar:vertical {
    background: transparent;
    width: 10px;
    margin: 3px;
}

QScrollBar::handle:vertical {
    background: #303037;
    border-radius: 5px;
    min-height: 35px;
}

QScrollBar::handle:vertical:hover {
    background: #494950;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}
"""


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(STYLESHEET)

    dialog = MasterPasswordDialog()
    if dialog.exec() != QDialog.DialogCode.Accepted:
        return 0

    try:
        vault = Vault(dialog.password)
    except ValueError:
        QMessageBox.critical(
            None,
            "Доступ запрещён",
            "Неверный мастер-пароль."
        )
        return 1

    window = MainWindow(vault)
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())