#!/usr/bin/env python3
"""
PyForensic Desk - Main Application Launcher
Runs the PyQt6 desktop interface and forensic engine.
"""
import sys
import os

# Ensure current directory is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ui_assistant import main

if __name__ == "__main__":
    main()
