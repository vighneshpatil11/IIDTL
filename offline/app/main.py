"""Offline standalone application launcher."""

import sys
from PySide6.QtWidgets import QApplication
from offline.app.ui.main_window import MainWindow


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
