# 🛡️ AegisForensics

## Integrated Secure Data Erasure and Advanced File Recovery Tool for Digital Forensics and Data Sanitization

### SIH26149 – NTRO

**Codename:** AegisForensics
**Category:** Digital Forensics & Cybersecurity
**Architecture:** Dual-State Forensic Recovery + Secure Data Sanitization
**Status:** Prototype / Demonstration System

---

# 📌 Overview

**AegisForensics** is an integrated digital forensics and data sanitization platform designed to demonstrate two critical and opposite cybersecurity operations within a unified system:

1. 🔍 **Advanced Forensic File Recovery**
2. 🛡️ **Secure Data Sanitization and Validation**

The system follows a **Dual-State Architecture**, allowing forensic investigators to analyze and recover files from raw storage images while maintaining strict read-only operations, followed by controlled data sanitization workflows for authorized demonstration media.

The platform is designed around the concept of the **Zero-Retention Validation Loop**, where a secondary forensic scan is performed after sanitization to verify that recoverable residual data is no longer detected.

> ⚠️ **Safety Notice:**
> This prototype is intended for controlled forensic laboratories, mock disk images, test files, and authorized demonstration environments. It must not be used against storage media or systems without explicit authorization.

---

# 🎯 Problem Statement

Modern digital storage devices often contain sensitive information even after files are deleted or storage media is formatted.

Traditional file recovery tools usually depend on filesystem metadata such as:

* Master File Table (MFT)
* FAT
* Inode structures
* Directory entries
* File allocation metadata

When these structures are corrupted, deleted, formatted, or unavailable, conventional recovery methods may fail.

At the same time, organizations require reliable methods for securely sanitizing sensitive data before storage devices are reused, transferred, or retired.

The challenge is therefore two-sided:

### Recovery Challenge

How can investigators recover potential evidence when filesystem metadata is missing or corrupted?

### Sanitization Challenge

How can authorized users validate that data remaining after a controlled sanitization process is no longer recoverable?

**AegisForensics combines both capabilities into one controlled forensic workflow.**

---

# 🚀 Proposed Solution

AegisForensics provides a unified platform consisting of:

```text
                ┌──────────────────────────┐
                │     AegisForensics       │
                │  Integrated Platform     │
                └────────────┬─────────────┘
                             │
             ┌───────────────┴───────────────┐
             │                               │
             ▼                               ▼
 ┌─────────────────────────┐      ┌─────────────────────────┐
 │ MODE 1                  │      │ MODE 2                  │
 │ FORENSIC RECOVERY       │      │ DATA SANITIZATION       │
 │                         │      │                         │
 │ • Raw Image Analysis    │      │ • Controlled Overwrite  │
 │ • Magic Byte Detection  │      │ • SHA-256 Verification  │
 │ • File Carving          │      │ • Residual Validation   │
 │ • Integrity Checks      │      │ • Audit Certificate     │
 └────────────┬────────────┘      └────────────┬────────────┘
              │                                │
              └───────────────┬────────────────┘
                              ▼
                  ┌────────────────────────┐
                  │ ZERO-RETENTION LOOP   │
                  │ Post-Operation Scan   │
                  │ Residual Verification │
                  └────────────────────────┘
```

---

# ⚡ Key Features

## 🔍 Mode 1: Advanced Forensic File Carving

The forensic recovery engine operates in **strict read-only mode**.

### Features

* Direct raw binary stream traversal
* Does not depend on filesystem metadata
* Magic-byte signature detection
* Header and footer matching
* JPEG carving
* PNG carving
* PDF carving
* ZIP carving
* DOCX detection
* Structural integrity validation
* File confidence scoring
* SHA-256 evidence hashing
* Recovery from formatted or corrupted mock disk images

---

# 🧬 Supported File Signatures

| File Type | Header Signature | Footer Signature          |
| --------- | ---------------- | ------------------------- |
| JPEG      | `FF D8 FF`       | `FF D9`                   |
| PNG       | `89 50 4E 47`    | `49 45 4E 44 AE 42 60 82` |
| PDF       | `%PDF-`          | `%%EOF`                   |
| ZIP       | `PK 03 04`       | ZIP structure             |
| DOCX      | `PK 03 04`       | ZIP-based structure       |

---

# 📊 File Confidence Scoring

Recovered files are analyzed and assigned a dynamic confidence score.

The confidence score considers factors such as:

* Header signature validity
* Footer availability
* File stream continuity
* Structural integrity
* Parser validation
* Entropy consistency
* File extraction success

Example:

```text
JPEG Evidence
────────────────────────────
Header Detected       ✓
Footer Detected       ✓
Pillow Validation     ✓
Entropy Continuity    ✓

Confidence Score: 96%
```

---

# 🖼️ Structural Integrity Validation

AegisForensics uses file-aware validation mechanisms.

### Image Validation

Recovered image files can be checked using:

```text
Pillow
```

Validation includes:

* Image opening
* Header validation
* Image structure verification
* Corruption detection

### PDF Validation

Recovered PDF files can be analyzed using:

```text
pypdf
```

Validation includes:

* PDF parsing
* Basic structural validation
* Reader compatibility

---

# 🛡️ Mode 2: Secure Data Sanitization

The sanitization module is designed for controlled demonstration environments.

It performs authorized overwrite operations on:

* Mock `.raw` disk images
* Test files
* Controlled laboratory media

The demonstration implementation intentionally avoids unrestricted destructive access to physical operating-system disks.

---

# 🔐 Supported Sanitization Concepts

The system demonstrates multi-pass overwrite strategies inspired by recognized data sanitization approaches.

Example workflow:

```text
PASS 1
Write Pattern: 0x00

        ↓

PASS 2
Write Pattern: 0xFF

        ↓

PASS 3
Write Pattern: Pseudo-Random Data

        ↓

Verification Scan
```

The sanitization process includes:

* Controlled overwrite workflow
* Block-by-block processing
* Real-time progress telemetry
* SHA-256 baseline generation
* Post-operation hashing
* Residual verification
* Audit logging

---

# 🔄 Zero-Retention Validation Loop

The primary innovation of AegisForensics is the:

## Zero-Retention Validation Loop

Instead of assuming that sanitization was successful, the platform performs a secondary verification process.

```text
┌──────────────────────┐
│ Original Raw Image   │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ SHA-256 Baseline     │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Sanitization Process │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Secondary Deep Scan  │
│ File Signature Scan  │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Residual Validation  │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Audit Certificate    │
└──────────────────────┘
```

The system checks for:

* Remaining file signatures
* Detectable evidence structures
* Recoverable payload indicators
* Post-operation hash values

The result is displayed as a demonstration-oriented residual data validation metric.

---

# 🔑 Authentication and Access Control

AegisForensics includes an examiner authentication gateway.

### Features

* Examiner login
* Credential validation
* Session management
* Role-based access control
* Admin-only operational access
* Examiner identity logging

Example role:

```text
ROLE: ADMIN
CLEARANCE: FORENSIC_EXAMINER
```

---

# 🖥️ User Interface

The frontend follows a **Cyberpunk Military Terminal aesthetic**.

### Design Features

* CRT scanline overlay
* Neon green telemetry
* Cyan operational highlights
* Red security alerts
* Terminal-inspired panels
* Monospace typography
* Interactive system logs
* Animated telemetry
* Web Audio API cyber sound effects
* Single-page workflow

### Primary Colors

```text
Neon Green: #00ff66
Cyber Cyan: #00f0ff
Alert Red:  #ff003c
```

### Recommended Fonts

```text
JetBrains Mono
Orbitron
```

---

# 🏗️ System Architecture

```text
                        ┌─────────────────────┐
                        │     Web Browser     │
                        │ Cyberpunk Interface │
                        └──────────┬──────────┘
                                   │
                                   │ HTTP / JSON
                                   ▼
                        ┌─────────────────────┐
                        │    Flask Server     │
                        │     server.py       │
                        └──────────┬──────────┘
                                   │
             ┌─────────────────────┼─────────────────────┐
             │                     │                     │
             ▼                     ▼                     ▼
    ┌────────────────┐   ┌────────────────┐   ┌────────────────┐
    │ Authentication │   │ Forensic Engine│   │ Sanitization   │
    │    auth.py     │   │   carver.py    │   │  sanitizer.py  │
    └────────────────┘   └────────────────┘   └────────────────┘
             │                     │                     │
             └─────────────────────┼─────────────────────┘
                                   │
                                   ▼
                        ┌─────────────────────┐
                        │ Reporting Engine    │
                        │    reporter.py      │
                        └──────────┬──────────┘
                                   │
                                   ▼
                        ┌─────────────────────┐
                        │ PDF Audit Report    │
                        │ Chain of Custody    │
                        └─────────────────────┘
```

---

# 📂 Project Structure

```text
AegisForensics/
│
├── server.py
├── requirements.txt
├── README.md
│
├── core/
│   ├── __init__.py
│   ├── auth.py
│   ├── carver.py
│   ├── sanitizer.py
│   └── reporter.py
│
├── templates/
│   └── index.html
│
├── evidence/
│   └── mock_disk.raw
│
├── recovered/
│
├── reports/
│
└── tests/
    └── make_mock_disk.py
```

---

# 🧩 Core Modules

## 1. `core/auth.py`

Responsible for:

* Examiner authentication
* Credential validation
* Session authorization
* Role-based access control

---

## 2. `core/carver.py`

Responsible for:

* Raw binary stream traversal
* Magic byte detection
* Header/footer matching
* File extraction
* Integrity checks
* Confidence scoring
* Evidence hashing

---

## 3. `core/sanitizer.py`

Responsible for:

* Controlled overwrite demonstrations
* Block processing
* SHA-256 hashing
* Multi-pass workflows
* Post-operation verification
* Residual signature checking

---

## 4. `core/reporter.py`

Responsible for generating:

* PDF forensic reports
* Examiner information
* Evidence information
* Hash values
* Operation logs
* Verification results
* Chain-of-custody details

The PDF certificate is generated using:

```text
ReportLab
```

---

## 5. `templates/index.html`

Contains the complete frontend.

Technologies:

* HTML5
* Tailwind CSS CDN
* Vanilla JavaScript
* Lucide Icons
* Web Audio API

---

## 6. `server.py`

The Flask backend connects:

```text
Frontend
   ↓
Flask REST API
   ↓
Authentication
   ↓
Carving Engine
   ↓
Sanitization Engine
   ↓
Verification
   ↓
PDF Reporting
```

---

# ⚙️ Installation

## Step 1: Clone the Repository

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
```

Move into the project directory:

```bash
cd AegisForensics
```

---

## Step 2: Create a Virtual Environment

### Windows

```bash
python -m venv venv
```

Activate:

```bash
venv\Scripts\activate
```

### Linux / macOS

```bash
python3 -m venv venv
```

Activate:

```bash
source venv/bin/activate
```

---

## Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

---

# 🧪 Generate Mock Disk Image

Run:

```bash
python tests/make_mock_disk.py
```

This creates a demonstration raw disk image containing embedded sample evidence payloads.

Example:

```text
evidence/mock_disk.raw
```

The generated image can be used for demonstrating:

* File carving
* Signature detection
* Evidence extraction
* Integrity validation
* Controlled sanitization workflows

---

# ▶️ Running AegisForensics

Start the Flask server:

```bash
python server.py
```

The terminal should display a local server address.

Open the application in your browser using the address displayed by Flask.

---

# 🔐 Demo Authentication

The default demonstration credentials are configured through environment variables.

Example configuration:

```text
Examiner ID:
NTRO-EXAMINER-01

Password:
Aegis@2026
```

For improved security, change these values using:

```text
AEGIS_EXAMINER_ID
AEGIS_PASSWORD
```

Example:

### Windows PowerShell

```powershell
$env:AEGIS_EXAMINER_ID="YOUR_EXAMINER_ID"
$env:AEGIS_PASSWORD="YOUR_SECURE_PASSWORD"
python server.py
```

### Linux / macOS

```bash
export AEGIS_EXAMINER_ID="YOUR_EXAMINER_ID"
export AEGIS_PASSWORD="YOUR_SECURE_PASSWORD"

python server.py
```

---

# 🔍 Forensic Demonstration Workflow

## Step 1

Generate the mock disk:

```bash
python tests/make_mock_disk.py
```

---

## Step 2

Launch AegisForensics:

```bash
python server.py
```

---

## Step 3

Authenticate as an authorized examiner.

---

## Step 4

Select the forensic recovery module.

---

## Step 5

Load the mock raw disk image.

Example:

```text
mock_disk.raw
```

---

## Step 6

Start the forensic scan.

The system performs:

```text
Raw Binary Traversal
        ↓
Magic Byte Detection
        ↓
Header/Footer Matching
        ↓
File Extraction
        ↓
Integrity Validation
        ↓
Confidence Scoring
```

---

## Step 7

Review recovered evidence.

Example:

```text
Evidence ID: EV-001
File Type: JPEG
Offset: 0x0001A400
Integrity: VALID
Confidence: 96%
```

---

# 🛡️ Sanitization Demonstration Workflow

The demonstration sanitization workflow should only be performed on:

* Mock raw images
* Test files
* Authorized laboratory data

Workflow:

```text
Select Authorized Test Media
        ↓
Generate SHA-256 Baseline
        ↓
Start Controlled Sanitization
        ↓
Multi-Pass Processing
        ↓
Generate Post-Operation Hash
        ↓
Secondary Forensic Scan
        ↓
Residual Verification
        ↓
Generate PDF Audit Certificate
```

---

# 📜 Audit Certificate

AegisForensics generates a tamper-evident style forensic audit record containing information such as:

```text
Certificate ID
Date and Time
Examiner ID
Role
Evidence Identifier
Target File
Pre-Operation SHA-256
Post-Operation SHA-256
Sanitization Method
Verification Result
Residual Scan Summary
Chain of Custody Log
```

Generated reports are stored in:

```text
reports/
```

---

# 🧠 Technology Stack

## Backend

```text
Python
Flask
```

## Forensic Processing

```text
Raw Binary Processing
Magic Byte Signatures
SHA-256
Entropy Analysis
Pillow
pypdf
```

## Reporting

```text
ReportLab
```

## Frontend

```text
HTML5
Tailwind CSS
Vanilla JavaScript
Lucide Icons
Web Audio API
```

---

# 🔐 Security Principles

AegisForensics follows these design principles:

### Read-Only Forensic Analysis

The recovery module should not modify evidence during analysis.

### Evidence Integrity

SHA-256 hashes are generated to help establish evidence consistency.

### Access Control

Only authenticated and authorized examiner sessions can access operational modules.

### Controlled Sanitization

Destructive demonstration functionality is limited to authorized test targets.

### Post-Operation Validation

Operations are followed by verification rather than relying solely on process completion.

---

# ⭐ Unique Selling Point

## Zero-Retention Validation Loop

Most tools focus on only one side of the problem:

```text
Recovery Tool
OR
Data Erasure Tool
```

AegisForensics integrates both.

```text
        FORENSIC RECOVERY
               ↓
        EVIDENCE ANALYSIS
               ↓
       CONTROLLED SANITIZATION
               ↓
      SECONDARY DEEP SCAN
               ↓
       RESIDUAL VALIDATION
               ↓
        AUDIT CERTIFICATE
```

This creates a closed-loop workflow for demonstrating the relationship between:

* Data recovery
* Data destruction
* Evidence validation
* Post-operation verification

---

# 🎓 SIH Demonstration Value

AegisForensics demonstrates multiple Smart India Hackathon-relevant concepts:

* Cybersecurity
* Digital Forensics
* Secure Data Management
* Binary Analysis
* File System Independent Recovery
* Evidence Integrity
* Access Control
* Data Sanitization Concepts
* Auditability
* Automated Reporting

---

# 🔮 Future Enhancements

Potential future versions may include:

* AI-based fragmented file reconstruction
* Advanced entropy visualization
* More file signature support
* Video and audio carving
* Timeline analysis
* Forensic case management
* Secure examiner multi-user authentication
* Hardware-backed evidence signing
* Immutable audit logging
* Distributed chain-of-custody records
* Advanced filesystem parsers
* Isolated forensic virtual machine integration
* Hardware write-blocker support

---

# ⚠️ Ethical and Legal Disclaimer

AegisForensics is intended for:

* Academic research
* Smart India Hackathon demonstrations
* Digital forensic laboratories
* Authorized security testing
* Controlled mock environments

Users must ensure that they have explicit authorization before analyzing or modifying any storage media or data.

The project should not be used for unauthorized access, destruction of data, interference with systems, or any activity that violates applicable laws or organizational policies.

---

# 👨‍💻 Project Codename

```text
 █████╗ ███████╗ ██████╗ ██╗███████╗
██╔══██╗██╔════╝██╔════╝ ██║██╔════╝
███████║█████╗  ██║  ███╗██║███████╗
██╔══██║██╔══╝  ██║   ██║██║╚════██║
██║  ██║███████╗╚██████╔╝██║███████║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝

        AEGISFORENSICS
  DEFEND • RECOVER • VERIFY
```

---

# 🏁 Conclusion

**AegisForensics** is a unified cybersecurity and digital forensics platform that demonstrates the complete lifecycle of digital evidence handling:

> **Detect → Recover → Validate → Sanitize → Verify → Certify**

By combining forensic file carving with controlled sanitization validation, AegisForensics presents a unique **Dual-State Architecture** for demonstrating both offensive evidence reconstruction and defensive data protection within a single integrated system.

---

## 🛡️ AegisForensics

**Integrated Secure Data Erasure and Advanced File Recovery Tool for Digital Forensics and Data Sanitization**

### SIH26149 – NTRO

**Recover the evidence. Validate the integrity. Verify the sanitization.**
