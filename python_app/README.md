# PyForensic Desk - Digital Forensic Recovery & Secure Sanitization Suite

A specialized Python desktop application featuring a modern PyQt6 interface with an integrated AI Chatbot assistant. The system operates strictly across two distinct operational domains and executes operations using verified Python backend engines.

## Architecture (3-Module Design)

1. **`ui_assistant.py` (PyQt GUI & AI Chatbot Controller)**:
   - Dual-domain workspace: Domain 1 (Forensic Recovery) & Domain 2 (Secure Sanitization).
   - Conversational AI agent for intent parsing, planning, parameter guidance, and safety locks.
   - Non-blocking `QThread` background execution pipelines.

2. **`forensic_engine.py` (Backend Recovery & Sanitization Core)**:
   - **Forensic Recovery**: Sleuth Kit (`fls`, `tsk_recover`) integration, deep file carving (Foremost/Scalpel header-footer magic bytes for JPEG, PNG, PDF, DOCX, SQLite, PCAP), MACB timeline extraction, EXIF metadata tags, and pre/post SHA-256 evidence verification.
   - **Data Sanitization**: NIST SP 800-88 Rev. 1 Clear & Purge multi-pass overwriting, sector entropy verification, MFT/GPT/slack zeroing, and post-wipe SHA-256 proof.

3. **`audit_certificate.py` (Database Logging & PDF Certificate Generator)**:
   - SQLite (`sqlite3`) operational history and chain of custody tracking.
   - ReportLab PDF generator producing signed Digital Forensic Recovery Certificates and NIST SP 800-88 Destruction Certificates.

## Installation & Running on Local Desktop

```bash
cd python_app
pip install -r requirements.txt
python run.py
```
