from PyQt5.QtWidgets import QApplication
from gui import SecureFileManager
import sys

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = SecureFileManager()
    window.show()
    sys.exit(app.exec_())
