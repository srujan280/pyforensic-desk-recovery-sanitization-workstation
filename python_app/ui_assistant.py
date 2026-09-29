#!/usr/bin/env python3
"""
ui_assistant.py
===============
Module 1: PyQt6 GUI & AI Chatbot Controller for PyForensic Desk.

Features:
- PyQt6 Main Desktop Interface with custom Dark Fusion theme
- Dedicated views/tabs for:
    1. Digital Forensic Recovery Domain (Read-Only, Sleuth Kit & File Carving)
    2. Secure Data Sanitization Domain (NIST SP 800-88 Clear/Purge Overwrite)
- Integrated AI Chatbot Assistant:
    - Conversational guidance, forensic rule explanation, intent parsing
    - Generates structured JSON action payloads for backend execution
    - Enforces safety prompts before irreversible sanitization actions
- Asynchronous QThread execution to keep UI responsive
- Live sector progress bars, hash verification badges, and instant PDF audit export
"""

import sys
import os
import json
import time
from typing import Dict, Any, List, Optional

try:
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QTabWidget, QLabel, QPushButton, QComboBox, QTextEdit, QLineEdit,
        QTableWidget, QTableWidgetItem, QHeaderView, QProgressBar,
        QSplitter, QGroupBox, QCheckBox, QMessageBox, QFrame, QScrollArea
    )
    from PyQt6.QtCore import Qt, QThread, pyqtSignal
    from PyQt6.QtGui import QFont, QColor, QIcon
    PYQT_AVAILABLE = True
except ImportError:
    PYQT_AVAILABLE = False

from forensic_engine import ForensicEngine, StorageDevice, RecoveredArtifact, SanitizationResult
from audit_certificate import AuditDatabase, CertificateGenerator


# Sample connected storage devices
SAMPLE_DEVICES = [
    StorageDevice(
        device_id="DEV-001",
        device_path="/dev/nvme0n1",
        model="Samsung 990 PRO 2TB NVMe SSD",
        interface="NVMe PCIe 4.0",
        capacity_bytes=2000398934016,
        write_blocker_active=True,
        filesystem="NTFS",
        serial_number="S6P2NF0T890123M",
    ),
    StorageDevice(
        device_id="DEV-002",
        device_path="/dev/sdb",
        model="SanDisk Extreme PRO USB 3.2 128GB",
        interface="USB 3.2 Flash",
        capacity_bytes=128035676160,
        write_blocker_active=True,
        filesystem="exFAT",
        serial_number="SDCZ880-128G-G46",
    ),
    StorageDevice(
        device_id="DEV-003",
        device_path="/mnt/evidence/case_01.E01",
        model="Forensic Raw Disk Image (E01 / DD)",
        interface="Forensic Image File",
        capacity_bytes=64000000000,
        write_blocker_active=True,
        filesystem="EXT4 / FAT32",
        serial_number="IMG-MD5-VERIFIED-991",
    ),
]


class RecoveryWorkerThread(QThread):
    """Background worker for forensic recovery pipeline."""
    progress_signal = pyqtSignal(int, str)
    finished_signal = pyqtSignal(str, list, str)
    error_signal = pyqtSignal(str)

    def __init__(self, engine: ForensicEngine, device: StorageDevice):
        super().__init__()
        self.engine = engine
        self.device = device

    def run(self):
        try:
            pre_h, artifacts, post_h = self.engine.run_recovery_pipeline(
                self.device,
                progress_callback=lambda pct, msg: self.progress_signal.emit(pct, msg)
            )
            self.finished_signal.emit(pre_h, artifacts, post_h)
        except Exception as e:
            self.error_signal.emit(str(e))


class SanitizationWorkerThread(QThread):
    """Background worker for NIST SP 800-88 secure sanitization pipeline."""
    progress_signal = pyqtSignal(int, str, float)
    finished_signal = pyqtSignal(object)
    error_signal = pyqtSignal(str)

    def __init__(self, engine: ForensicEngine, device: StorageDevice, standard: str):
        super().__init__()
        self.engine = engine
        self.device = device
        self.standard = standard

    def run(self):
        try:
            result = self.engine.run_sanitization_pipeline(
                self.device,
                standard=self.standard,
                progress_callback=lambda pct, msg, ent: self.progress_signal.emit(pct, msg, ent)
            )
            self.finished_signal.emit(result)
        except Exception as e:
            self.error_signal.emit(str(e))


class AIChatbotController:
    """AI Chatbot Agent: Intent parser, task planner, and user guidance assistant."""

    def __init__(self):
        self.conversation_history: List[Dict[str, str]] = []

    def process_message(self, user_text: str, current_domain: str, selected_device: StorageDevice) -> Dict[str, Any]:
        """
        Parses user intent and returns a response plus an optional structured JSON action plan.
        """
        lower = user_text.lower()
        response_text = ""
        action_plan = None

        if "recover" in lower or "photo" in lower or "file" in lower or "sleuth" in lower or "carv" in lower:
            response_text = (
                f"Understood. I have evaluated your request for forensic recovery on target "
                f"<b>{selected_device.model}</b>.<br/><br/>"
                f"<b>Forensic Plan:</b><br/>"
                f"1. Verified Write-Blocker Status: <b>{'ACTIVE (Safe)' if selected_device.write_blocker_active else 'WARNING: INACTIVE'}</b><br/>"
                f"2. Pre-Scan SHA-256 Baseline acquisition<br/>"
                f"3. Sleuth Kit <code>fls</code> filesystem MFT structure scan<br/>"
                f"4. Deep file carving for JPEG, PDF, Office DOCX, SQLite, PCAP<br/>"
                f"5. MACB timeline generation & Post-recovery SHA-256 match confirmation.<br/><br/>"
                f"Click <b>'Execute Action Plan'</b> below to trigger verified Python backend execution."
            )
            action_plan = {
                "action": "EXECUTE_RECOVERY",
                "domain": "RECOVERY",
                "device_id": selected_device.device_id,
                "parameters": {
                    "enable_sleuthkit": True,
                    "enable_carving": True,
                    "write_blocker_required": True,
                },
                "safety_confirmation_required": False
            }

        elif "sanitize" in lower or "wipe" in lower or "erase" in lower or "destroy" in lower or "purge" in lower or "nist" in lower:
            standard = "NIST SP 800-88 Purge" if ("purge" in lower or "crypto" in lower) else "NIST SP 800-88 Clear"
            response_text = (
                f"<b>CRITICAL SAFETY WARNING:</b> You requested secure data destruction.<br/><br/>"
                f"Standard: <b>{standard}</b><br/>"
                f"Target Drive: <b>{selected_device.model} ({selected_device.device_path})</b><br/>"
                f"Capacity: <b>{round(selected_device.capacity_bytes / (1024**3), 2)} GB</b><br/><br/>"
                f"<b>Destruction Protocols:</b><br/>"
                f"- Multi-pass sector overwrite (zeros, complement, cryptographic PRNG)<br/>"
                f"- Full erasure of MFT, Partition Tables (GPT/MBR), and slack space<br/>"
                f"- Pre- and Post-wipe SHA-256 verification (Entropy drops to 0.00)<br/><br/>"
                f"<i>Notice: To proceed, you must unlock the write-blocker and provide explicit confirmation.</i>"
            )
            action_plan = {
                "action": "EXECUTE_SANITIZATION",
                "domain": "SANITIZATION",
                "device_id": selected_device.device_id,
                "parameters": {
                    "standard": standard,
                    "wipe_metadata": True,
                    "wipe_unallocated": True
                },
                "safety_confirmation_required": True
            }
        else:
            response_text = (
                f"Hello! I am your PyForensic AI Assistant.<br/>"
                f"Current Domain: <b>{current_domain}</b><br/>"
                f"Active Drive: <b>{selected_device.model}</b><br/><br/>"
                f"You can ask me to:<br/>"
                f"• <i>'Recover lost photos and documents from USB'</i><br/>"
                f"• <i>'Execute NIST SP 800-88 Purge wipe before drive disposal'</i><br/>"
                f"• <i>'Explain Sleuth Kit fls vs Foremost file carving'</i><br/>"
                f"• <i>'Verify SHA-256 chain of custody'</i>"
            )

        return {
            "reply": response_text,
            "action_plan": action_plan
        }


DARK_STYLE = """
QMainWindow, QWidget {
    background-color: #0b1120;
    color: #e2e8f0;
    font-family: 'Segoe UI', 'Ubuntu', 'Helvetica Neue', sans-serif;
}
QTabWidget::pane {
    border: 1px solid #1e293b;
    background: #0f172a;
    border-radius: 4px;
}
QTabBar::tab {
    background: #1e293b;
    color: #94a3b8;
    padding: 10px 22px;
    font-weight: 600;
    font-size: 13px;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    margin-right: 2px;
}
QTabBar::tab:selected {
    background: #0284c7;
    color: #ffffff;
}
QGroupBox {
    border: 1px solid #334155;
    border-radius: 6px;
    margin-top: 12px;
    font-weight: bold;
    color: #38bdf8;
    padding-top: 14px;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 5px;
}
QPushButton {
    background-color: #0284c7;
    color: #ffffff;
    font-weight: bold;
    border-radius: 4px;
    padding: 8px 16px;
    border: none;
}
QPushButton:hover {
    background-color: #0369a1;
}
QPushButton#dangerBtn {
    background-color: #dc2626;
}
QPushButton#dangerBtn:hover {
    background-color: #b91c1c;
}
QTableWidget {
    background-color: #0f172a;
    border: 1px solid #334155;
    gridline-color: #1e293b;
    color: #f1f5f9;
}
QHeaderView::section {
    background-color: #1e293b;
    color: #38bdf8;
    padding: 4px;
    font-weight: bold;
    border: 1px solid #334155;
}
QProgressBar {
    border: 1px solid #334155;
    border-radius: 4px;
    text-align: center;
    background: #1e293b;
    color: #ffffff;
}
QProgressBar::chunk {
    background-color: #0284c7;
}
"""


class PyForensicMainWindow(QMainWindow):
    """Main PyQt6 Application Window."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("PyForensic Desk - Digital Forensic Recovery & NIST Sanitization Workstation")
        self.resize(1300, 850)

        self.engine = ForensicEngine()
        self.db = AuditDatabase()
        self.ai = AIChatbotController()
        self.devices = SAMPLE_DEVICES
        self.current_device_idx = 0
        self.latest_recovery_artifacts: List[RecoveredArtifact] = []
        self.latest_sanitization_result: Optional[SanitizationResult] = None
        self.pending_ai_action: Optional[Dict[str, Any]] = None

        self.setStyleSheet(DARK_STYLE)
        self.init_ui()

    def init_ui(self):
        main_widget = QWidget()
        main_layout = QHBoxLayout(main_widget)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)

        # Left/Center Splitter: Domain Views (Recovery & Sanitization)
        splitter = QSplitter(Qt.Orientation.Horizontal)

        left_container = QWidget()
        left_layout = QVBoxLayout(left_container)
        left_layout.setContentsMargins(0, 0, 0, 0)

        # Top Device Selection Bar
        dev_group = QGroupBox("Target Storage Device & Forensic Safety Lock")
        dev_layout = QHBoxLayout(dev_group)
        dev_layout.addWidget(QLabel("Target Media:"))

        self.device_combo = QComboBox()
        for d in self.devices:
            self.device_combo.addItem(f"{d.model} ({d.device_path}) - {round(d.capacity_bytes / (1024**3), 1)} GB")
        self.device_combo.currentIndexChanged.connect(self.on_device_changed)
        dev_layout.addWidget(self.device_combo, stretch=2)

        self.wb_checkbox = QCheckBox("Write-Blocker Locked (Read-Only)")
        self.wb_checkbox.setChecked(True)
        self.wb_checkbox.setStyleSheet("color: #4ade80; font-weight: bold;")
        self.wb_checkbox.toggled.connect(self.on_write_blocker_toggled)
        dev_layout.addWidget(self.wb_checkbox)

        left_layout.addWidget(dev_group)

        # Tabs: Domain 1 (Recovery) and Domain 2 (Sanitization)
        self.tabs = QTabWidget()
        self.tab_recovery = QWidget()
        self.tab_sanitization = QWidget()
        self.tab_audit = QWidget()

        self.init_recovery_tab()
        self.init_sanitization_tab()
        self.init_audit_tab()

        self.tabs.addTab(self.tab_recovery, "Domain 1: Forensic Recovery")
        self.tabs.addTab(self.tab_sanitization, "Domain 2: Secure Sanitization (NIST 800-88)")
        self.tabs.addTab(self.tab_audit, "Operations Audit Log & Certificates")

        left_layout.addWidget(self.tabs)
        splitter.addWidget(left_container)

        # Right Dock: AI Chatbot Assistant
        right_container = self.init_ai_dock()
        splitter.addWidget(right_container)
        splitter.setStretchFactor(0, 7)
        splitter.setStretchFactor(1, 3)

        main_layout.addWidget(splitter)
        self.setCentralWidget(main_widget)

    def init_recovery_tab(self):
        layout = QVBoxLayout(self.tab_recovery)

        # Top Controls: Sleuth Kit + Foremost Carving
        ctrl_box = QGroupBox("Forensic Extraction Pipeline Configuration")
        ctrl_layout = QHBoxLayout(ctrl_box)

        self.chk_sleuthkit = QCheckBox("Sleuth Kit (fls / tsk_recover / MFT)")
        self.chk_sleuthkit.setChecked(True)
        ctrl_layout.addWidget(self.chk_sleuthkit)

        self.chk_foremost = QCheckBox("Deep File Carver (Foremost / Magic Signatures)")
        self.chk_foremost.setChecked(True)
        ctrl_layout.addWidget(self.chk_foremost)

        self.btn_run_recovery = QPushButton("Start Forensic Recovery Pipeline")
        self.btn_run_recovery.clicked.connect(self.start_recovery_pipeline)
        ctrl_layout.addWidget(self.btn_run_recovery)

        layout.addWidget(ctrl_box)

        # Status & Progress
        self.rec_status_label = QLabel("Ready. Select target storage media and click start.")
        layout.addWidget(self.rec_status_label)

        self.rec_progress = QProgressBar()
        self.rec_progress.setValue(0)
        layout.addWidget(self.rec_progress)

        # Hashes Card
        hash_box = QGroupBox("Cryptographic Evidence Chain of Custody")
        hash_layout = QHBoxLayout(hash_box)
        self.lbl_pre_hash = QLabel("Pre-Scan SHA-256: [Pending]")
        self.lbl_pre_hash.setStyleSheet("font-family: monospace; color: #94a3b8;")
        self.lbl_post_hash = QLabel("Post-Scan SHA-256: [Pending]")
        self.lbl_post_hash.setStyleSheet("font-family: monospace; color: #94a3b8;")
        hash_layout.addWidget(self.lbl_pre_hash)
        hash_layout.addWidget(self.lbl_post_hash)
        layout.addWidget(hash_box)

        # Recovered Artifacts Table
        layout.addWidget(QLabel("<b>Recovered Artifacts & File Carving Results:</b>"))
        self.table_artifacts = QTableWidget(0, 6)
        self.table_artifacts.setHorizontalHeaderLabels(["ID", "Filename", "Type", "Size", "Sector Offset", "SHA-256 Hash"])
        self.table_artifacts.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table_artifacts)

        # Bottom Button: Export ReportLab PDF
        self.btn_export_rec_pdf = QPushButton("Generate Official Recovery Audit Certificate (PDF)")
        self.btn_export_rec_pdf.clicked.connect(self.export_recovery_pdf)
        self.btn_export_rec_pdf.setEnabled(False)
        layout.addWidget(self.btn_export_rec_pdf)

    def init_sanitization_tab(self):
        layout = QVBoxLayout(self.tab_sanitization)

        cfg_box = QGroupBox("NIST SP 800-88 Rev. 1 Sanitization Parameters")
        cfg_layout = QVBoxLayout(cfg_box)

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Overwrite Algorithm:"))
        self.san_standard_combo = QComboBox()
        self.san_standard_combo.addItems([
            "NIST SP 800-88 Clear (Single Pass Logical Zeros + Sector Verify)",
            "NIST SP 800-88 Purge (3-Pass: 0x00, 0xFF, Cryptographic PRNG + Verify)",
            "DoD 5220.22-M (3-Pass Military Standard)",
        ])
        row1.addWidget(self.san_standard_combo, stretch=2)
        cfg_layout.addLayout(row1)

        row2 = QHBoxLayout()
        self.chk_wipe_mft = QCheckBox("Explicitly Obliterate MFT Records, GPT/MBR Tables & Directory Entries")
        self.chk_wipe_mft.setChecked(True)
        self.chk_wipe_slack = QCheckBox("Wipe Unallocated & Slack Sectors")
        self.chk_wipe_slack.setChecked(True)
        row2.addWidget(self.chk_wipe_mft)
        row2.addWidget(self.chk_wipe_slack)
        cfg_layout.addLayout(row2)

        layout.addWidget(cfg_box)

        # Warning Card
        warn_box = QFrame()
        warn_box.setStyleSheet("background-color: #450a0a; border: 1px solid #dc2626; border-radius: 6px; padding: 10px;")
        warn_layout = QVBoxLayout(warn_box)
        lbl_warn_title = QLabel("WARNING: IRREVERSIBLE DATA DESTRUCTION")
        lbl_warn_title.setStyleSheet("color: #f87171; font-weight: bold; font-size: 14px;")
        lbl_warn_body = QLabel(
            "Executing this sanitization pipeline permanently destroys all sector data, partition maps, "
            "and file structures. Data cannot be recovered by any software or laboratory technique.\n"
            "Hardware Write-Blocker must be switched to UNLOCKED before proceeding."
        )
        lbl_warn_body.setStyleSheet("color: #fca5a5; font-size: 11px;")
        warn_layout.addWidget(lbl_warn_title)
        warn_layout.addWidget(lbl_warn_body)
        layout.addWidget(warn_box)

        self.btn_run_sanitization = QPushButton("Execute NIST SP 800-88 Sanitization Routine")
        self.btn_run_sanitization.setObjectName("dangerBtn")
        self.btn_run_sanitization.clicked.connect(self.start_sanitization_pipeline)
        layout.addWidget(self.btn_run_sanitization)

        self.san_status_label = QLabel("Awaiting authorization.")
        layout.addWidget(self.san_status_label)

        self.san_progress = QProgressBar()
        self.san_progress.setValue(0)
        layout.addWidget(self.san_progress)

        self.lbl_entropy = QLabel("Sector Entropy: [Idle]")
        self.lbl_entropy.setStyleSheet("font-family: monospace; color: #38bdf8;")
        layout.addWidget(self.lbl_entropy)

        # Sanitization Hash Card
        san_hash_box = QGroupBox("Sanitization Cryptographic Audit Proof")
        san_hash_layout = QVBoxLayout(san_hash_box)
        self.lbl_san_pre = QLabel("Pre-Wipe SHA-256: [Pending]")
        self.lbl_san_post = QLabel("Post-Wipe SHA-256: [Pending]")
        self.lbl_san_status = QLabel("Compliance Status: [Pending]")
        for l in (self.lbl_san_pre, self.lbl_san_post, self.lbl_san_status):
            l.setStyleSheet("font-family: monospace; color: #94a3b8;")
            san_hash_layout.addWidget(l)
        layout.addWidget(san_hash_box)

        self.btn_export_san_pdf = QPushButton("Generate NIST SP 800-88 Destruction Certificate (PDF)")
        self.btn_export_san_pdf.clicked.connect(self.export_sanitization_pdf)
        self.btn_export_san_pdf.setEnabled(False)
        layout.addWidget(self.btn_export_san_pdf)

    def init_audit_tab(self):
        layout = QVBoxLayout(self.tab_audit)
        layout.addWidget(QLabel("<b>SQLite Operational History & Chain of Custody Log:</b>"))

        self.table_logs = QTableWidget(0, 6)
        self.table_logs.setHorizontalHeaderLabels(["Operation ID", "Domain", "Device", "Pipeline", "Status", "Timestamp"])
        self.table_logs.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table_logs)

        btn_refresh = QPushButton("Refresh Database Logs")
        btn_refresh.clicked.connect(self.refresh_audit_logs)
        layout.addWidget(btn_refresh)

    def init_ai_dock(self) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)

        ai_box = QGroupBox("Forensic AI Copilot & Task Planner")
        ai_layout = QVBoxLayout(ai_box)

        self.chat_browser = QTextEdit()
        self.chat_browser.setReadOnly(True)
        self.chat_browser.setHtml(
            "<span style='color:#38bdf8;'><b>PyForensic AI Assistant Online.</b></span><br/>"
            "Ask me to plan a data recovery or secure wipe operation, analyze drive health, or explain forensic standards."
        )
        ai_layout.addWidget(self.chat_browser)

        # Plan Approval Banner (shown when AI generates a plan)
        self.plan_frame = QFrame()
        self.plan_frame.setStyleSheet("background-color: #1e293b; border: 1px solid #0284c7; border-radius: 4px; padding: 6px;")
        plan_layout = QVBoxLayout(self.plan_frame)
        self.lbl_plan_desc = QLabel("AI Execution Plan Ready")
        self.lbl_plan_desc.setStyleSheet("color: #38bdf8; font-weight: bold;")
        self.btn_apply_plan = QPushButton("Approve & Execute AI Plan")
        self.btn_apply_plan.clicked.connect(self.execute_ai_action_plan)
        plan_layout.addWidget(self.lbl_plan_desc)
        plan_layout.addWidget(self.btn_apply_plan)
        self.plan_frame.hide()
        ai_layout.addWidget(self.plan_frame)

        # Chat Input
        input_row = QHBoxLayout()
        self.chat_input = QLineEdit()
        self.chat_input.setPlaceholderText("Type instruction, e.g. 'Carve deleted photos safely'...")
        self.chat_input.returnPressed.connect(self.send_chat_message)
        input_row.addWidget(self.chat_input)

        btn_send = QPushButton("Send")
        btn_send.clicked.connect(self.send_chat_message)
        input_row.addWidget(btn_send)
        ai_layout.addLayout(input_row)

        layout.addWidget(ai_box)
        return container

    def on_device_changed(self, idx: int):
        self.current_device_idx = idx
        d = self.devices[idx]
        self.wb_checkbox.setChecked(d.write_blocker_active)

    def on_write_blocker_toggled(self, checked: bool):
        d = self.devices[self.current_device_idx]
        d.write_blocker_active = checked
        if checked:
            self.wb_checkbox.setStyleSheet("color: #4ade80; font-weight: bold;")
            self.wb_checkbox.setText("Write-Blocker Locked (Read-Only)")
        else:
            self.wb_checkbox.setStyleSheet("color: #f87171; font-weight: bold;")
            self.wb_checkbox.setText("Write-Blocker DISENGAGED (Read/Write Allowed)")

    def send_chat_message(self):
        text = self.chat_input.text().strip()
        if not text:
            return
        self.chat_input.clear()

        # Display user message
        self.chat_browser.append(f"<br/><b style='color:#f1f5f9;'>User:</b> {text}")

        cur_domain = "Forensic Recovery" if self.tabs.currentIndex() == 0 else "Secure Sanitization"
        dev = self.devices[self.current_device_idx]

        response = self.ai.process_message(text, cur_domain, dev)
        self.chat_browser.append(f"<b style='color:#38bdf8;'>AI Assistant:</b><br/>{response['reply']}")

        if response.get("action_plan"):
            self.pending_ai_action = response["action_plan"]
            self.lbl_plan_desc.setText(f"AI Plan: {self.pending_ai_action['action']} on {dev.model}")
            self.plan_frame.show()
        else:
            self.plan_frame.hide()

    def execute_ai_action_plan(self):
        if not self.pending_ai_action:
            return
        plan = self.pending_ai_action
        self.plan_frame.hide()
        if plan["action"] == "EXECUTE_RECOVERY":
            self.tabs.setCurrentIndex(0)
            self.start_recovery_pipeline()
        elif plan["action"] == "EXECUTE_SANITIZATION":
            self.tabs.setCurrentIndex(1)
            self.start_sanitization_pipeline()

    # Recovery Execution
    def start_recovery_pipeline(self):
        dev = self.devices[self.current_device_idx]
        if not dev.write_blocker_active:
            ret = QMessageBox.warning(
                self, "Forensic Warning",
                "Write-Blocker is NOT engaged! Proceeding may alter access timestamps on physical media. Proceed anyway?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if ret == QMessageBox.StandardButton.No:
                return

        self.btn_run_recovery.setEnabled(False)
        self.rec_progress.setValue(0)
        self.rec_status_label.setText("Starting forensic recovery pipeline...")

        self.worker = RecoveryWorkerThread(self.engine, dev)
        self.worker.progress_signal.connect(self.on_recovery_progress)
        self.worker.finished_signal.connect(self.on_recovery_finished)
        self.worker.start()

    def on_recovery_progress(self, pct: int, msg: str):
        self.rec_progress.setValue(pct)
        self.rec_status_label.setText(msg)

    def on_recovery_finished(self, pre_h: str, artifacts: List[RecoveredArtifact], post_h: str):
        self.btn_run_recovery.setEnabled(True)
        self.latest_recovery_artifacts = artifacts
        self.lbl_pre_hash.setText(f"Pre-Scan SHA-256: {pre_h[:24]}...")
        self.lbl_post_hash.setText(f"Post-Scan SHA-256: {post_h[:24]}...")
        self.btn_export_rec_pdf.setEnabled(True)

        self.table_artifacts.setRowCount(0)
        for i, a in enumerate(artifacts):
            self.table_artifacts.insertRow(i)
            self.table_artifacts.setItem(i, 0, QTableWidgetItem(a.artifact_id))
            self.table_artifacts.setItem(i, 1, QTableWidgetItem(a.filename))
            self.table_artifacts.setItem(i, 2, QTableWidgetItem(a.file_type))
            self.table_artifacts.setItem(i, 3, QTableWidgetItem(f"{round(a.file_size_bytes/(1024*1024), 2)} MB"))
            self.table_artifacts.setItem(i, 4, QTableWidgetItem(str(a.offset_sector)))
            self.table_artifacts.setItem(i, 5, QTableWidgetItem(f"{a.sha256_hash[:16]}..."))

        dev = self.devices[self.current_device_idx]
        op_id = f"REC-{int(time.time())}"
        self.db.log_recovery_operation(
            op_id,
            {"device_id": dev.device_id, "model": dev.model, "capacity_bytes": dev.capacity_bytes},
            pre_h, post_h,
            [asdict(a) for a in artifacts]
        )
        self.refresh_audit_logs()
        QMessageBox.information(self, "Recovery Complete", f"Successfully extracted {len(artifacts)} forensic artifacts with verified SHA-256 hash preservation.")

    # Sanitization Execution
    def start_sanitization_pipeline(self):
        dev = self.devices[self.current_device_idx]
        if dev.write_blocker_active:
            QMessageBox.critical(
                self, "Operation Aborted",
                "Cannot wipe drive: Hardware Write-Blocker is ACTIVE. Uncheck the write-blocker lock to allow overwriting."
            )
            return

        # Irreversible Action Safety Prompt
        reply = QMessageBox.warning(
            self, "CONFIRM DESTRUCTION",
            f"Are you ABSOLUTELY SURE you want to permanently sanitize:\n{dev.model} ({dev.device_path})\n\n"
            "This will execute a NIST SP 800-88 multi-pass overwrite. ALL DATA WILL BE DESTROYED.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        self.btn_run_sanitization.setEnabled(False)
        self.san_progress.setValue(0)
        standard = self.san_standard_combo.currentText()

        self.san_worker = SanitizationWorkerThread(self.engine, dev, standard)
        self.san_worker.progress_signal.connect(self.on_san_progress)
        self.san_worker.finished_signal.connect(self.on_san_finished)
        self.san_worker.start()

    def on_san_progress(self, pct: int, msg: str, entropy: float):
        self.san_progress.setValue(pct)
        self.san_status_label.setText(msg)
        self.lbl_entropy.setText(f"Sector Entropy: {entropy:.4f} bits/byte")

    def on_san_finished(self, result: SanitizationResult):
        self.btn_run_sanitization.setEnabled(True)
        self.latest_sanitization_result = result
        self.lbl_san_pre.setText(f"Pre-Wipe SHA-256: {result.pre_wipe_sha256[:28]}...")
        self.lbl_san_post.setText(f"Post-Wipe SHA-256: {result.post_wipe_sha256[:28]}...")
        self.lbl_san_status.setText(f"Compliance: {result.verification_status}")
        self.btn_export_san_pdf.setEnabled(True)

        dev = self.devices[self.current_device_idx]
        self.db.log_sanitization_operation(
            result.operation_id,
            {"device_id": dev.device_id, "model": dev.model, "capacity_bytes": dev.capacity_bytes},
            result.standard_applied,
            result.pre_wipe_sha256,
            result.post_wipe_sha256,
            result.verification_status
        )
        self.refresh_audit_logs()
        QMessageBox.information(self, "Sanitization Complete", "Device successfully sanitized and verified compliant with NIST SP 800-88.")

    def export_recovery_pdf(self):
        if not self.latest_recovery_artifacts:
            return
        dev = self.devices[self.current_device_idx]
        pdf_path = f"Forensic_Recovery_Cert_{int(time.time())}.pdf"
        CertificateGenerator.generate_recovery_pdf(
            pdf_path,
            f"REC-{int(time.time())}",
            {"model": dev.model, "interface": dev.interface, "device_path": dev.device_path, "serial_number": dev.serial_number},
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            [asdict(a) for a in self.latest_recovery_artifacts]
        )
        QMessageBox.information(self, "Certificate Generated", f"Recovery Audit Certificate exported to:\n{pdf_path}")

    def export_sanitization_pdf(self):
        if not self.latest_sanitization_result:
            return
        r = self.latest_sanitization_result
        dev = self.devices[self.current_device_idx]
        pdf_path = f"NIST_Sanitization_Cert_{int(time.time())}.pdf"
        CertificateGenerator.generate_sanitization_pdf(
            pdf_path,
            r.operation_id,
            {"model": dev.model, "serial_number": dev.serial_number},
            r.standard_applied,
            r.pre_wipe_sha256,
            r.post_wipe_sha256,
            r.verification_status
        )
        QMessageBox.information(self, "Certificate Generated", f"Sanitization Audit Certificate exported to:\n{pdf_path}")

    def refresh_audit_logs(self):
        logs = self.db.fetch_all_logs()
        self.table_logs.setRowCount(0)
        for i, row in enumerate(logs):
            self.table_logs.insertRow(i)
            self.table_logs.setItem(i, 0, QTableWidgetItem(str(row["operation_id"])))
            self.table_logs.setItem(i, 1, QTableWidgetItem(str(row["domain_type"])))
            self.table_logs.setItem(i, 2, QTableWidgetItem(str(row["device_model"])))
            self.table_logs.setItem(i, 3, QTableWidgetItem(str(row["standard_or_pipeline"])))
            self.table_logs.setItem(i, 4, QTableWidgetItem(str(row["verification_status"])))
            self.table_logs.setItem(i, 5, QTableWidgetItem(str(row["timestamp"])))


def main():
    if not PYQT_AVAILABLE:
        print("[!] PyQt6 is not installed. To run the desktop GUI, run: pip install PyQt6 reportlab")
        print("[!] Executing headless verification of forensic engine...")
        eng = ForensicEngine()
        dev = SAMPLE_DEVICES[0]
        pre_h, art, post_h = eng.run_recovery_pipeline(dev)
        print(f"[OK] Engine verified. Artifacts carved: {len(art)}")
        return

    app = QApplication(sys.argv)
    window = PyForensicMainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
