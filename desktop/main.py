"""
SecureVault Desktop Application Entry Point
"""

import sys
import os

# Add parent directory to sys.path so desktop module can be imported cleanly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from desktop.gui import run_desktop_gui

if __name__ == "__main__":
    run_desktop_gui()
