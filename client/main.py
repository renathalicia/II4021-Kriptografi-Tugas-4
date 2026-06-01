import sys
import os

# Tambahin root project ke sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from client.cli.menu import tampilkan_menu_utama

if __name__ == "__main__":
    tampilkan_menu_utama()