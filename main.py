import sys
import os

# Menambahkan directory saat ini ke sys.path supaya package razorscan bisa di-import
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from razorscan.cli import app

if __name__ == "__main__":
    app()
