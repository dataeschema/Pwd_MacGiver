import sys

from PySide6 import QtWidgets

from app.database import Database
from app.dialogs import LoginDialog
from app.main_window import MainWindow
from app.utils import get_db_path


def main():
    """Main entry point for the application."""
    app = QtWidgets.QApplication(sys.argv)

    db_path = get_db_path()
    db = Database(db_path)

    crypto = LoginDialog.get_crypto(db)
    if crypto is None:
        sys.exit(0)  # User cancelled login

    win = MainWindow(db, crypto)
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
