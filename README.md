# Secure Document Distribution Platform

> **Cryptographic Access Control, Invisible Forensic Watermarking, and Access Traceability**  
> Developed as a production-grade monorepo containing two operational implementations: **Online (Web/Cloud)** and **Offline (Air-Gapped Desktop)**.

---

## 1. System Overview

Modern organizations frequently share confidential documents with multiple recipients. While standard encryption protects data in transit and at rest, it fails to solve two critical operational challenges:
1. **The Traitor-Tracing Problem:** Once authorized recipients decrypt a document, an untrusted party may redistribute a plaintext copy. Standard encryption cannot prove which recipient's copy was exfiltrated.
2. **Air-Gapped Local Distribution:** In zero-connectivity environments, document owners must be able to enforce device-specific cryptographic authorization and maintain tamper-evident audit logs without remote servers.

This project delivers two distinct but complementary systems sharing a tested cryptographic and document-processing foundation:

* **Online System:** Multi-recipient distribution with dynamic recipient key wrapping (X25519 + HKDF-SHA256 + AES-256-GCM), multi-layer invisible forensic watermarking in PDFs, encrypted forensic vault mapping, and leak attribution investigation.
* **Offline System:** Standalone air-gapped desktop system with cryptographic device identities (Ed25519 + X25519), owner-signed registration certificates, multi-device `.secure` container packaging, and a blockchain-like hash-linked tamper-evident local audit log.

---

## 2. Monorepo Architecture

```
d:\IIDTL\
├── shared/                         # Shared Cryptographic & Document Core
│   ├── crypto/                     # AES-256-GCM, X25519, Ed25519, HKDF-SHA256
│   ├── documents/                  # Document handlers, integrity verification, SHA-256
│   ├── models/                     # Package serialization (.enc and .secure formats)
│   ├── utils/                      # Canonical JSON, base64, cryptographic ID generators
│   └── watermark/                  # Multi-layer invisible forensic watermarking & extraction
├── online/
│   ├── backend/                    # FastAPI application
│   │   ├── app/                    # Auth, Documents, Recipients, Distributions, Investigation, Audit
│   │   └── tests/                  # End-to-end online workflow test suite
│   └── frontend/
│       └── public/index.html       # Modern responsive Web Application UI
├── offline/
│   ├── app/
│   │   ├── database/               # Local SQLite models and schema
│   │   ├── security/               # Device identities, certificates, keystore encryption
│   │   ├── services/               # Hash-linked audit service & offline multi-device packager
│   │   └── ui/                     # PySide6 desktop GUI
├── scripts/
│   ├── demo_crypto_cli.py          # Phase 1 CLI demonstration
│   ├── run_online_demo.py          # Scenarios A & B demonstration (Distribution & Leak Investigation)
│   └── run_offline_demo.py         # Scenarios C, D & E demonstration (Registration, Packaging, Audit)
├── tests/
│   ├── shared/                     # Crypto and watermarking test suites
│   ├── offline/                    # Offline registration, packaging, and audit tests
│   └── integration/                # Large-file, tamper-resistance, and edge-case tests
└── README.md
```

---

## 3. Cryptographic Foundation & Key Separation

No custom cryptography is invented; the implementation adheres strictly to NIST SP 800-38D, RFC 7748, RFC 8032, and RFC 5869:

| Key Role | Primitive | Purpose | Protection / Storage |
|---|---|---|---|
| **Document Encryption Key (DEK)** | AES-256-GCM (256-bit) | Symmetric encryption of individual document copies | Ephemeral; generated fresh via CSPRNG per recipient/package. Never stored in plaintext. |
| **Recipient Key Pairs** | Curve25519 (X25519) | ECIES-style key agreement and DEK wrapping | Private keys held exclusively by recipients; public keys registered with owner. |
| **Device Signatures** | Ed25519 (64-byte sigs) | Device registration requests, owner certificates, audit block signatures | Private keys protected by AES-256-GCM passphrase keystore. |
| **Owner Forensic Key (OFK)** | AES-256-GCM (256-bit) | Encrypts `(DocID, WatermarkID) -> RecipientID` in the forensic mapping vault | Stored in protected backend vault environment; never shared with recipients. |
| **Tamper-Evident Audit Log** | Hash-Linked SHA-256 Chain | Guarantees audit integrity: $H_i = \text{SHA-256}(H_{i-1} \parallel \dots)$ | Signed by device Ed25519 key; tampering or truncation breaks chain. |

---

## 4. Invisible Forensic Watermarking Engine

To resist standard PDF document sanitizers (which easily strip `/Info` and XMP metadata), the platform implements a **multi-layer steganographic pipeline**:
1. **Syntactic Zero-Width Steganography:** Injects framed, CRC16-protected zero-width Unicode markers (`\u200B`, `\u200C`, `\u200D`, `\uFEFF`) into text content streams (survives plain-text extraction and copy-paste).
2. **Invisible Rendering Operators:** Appends PDF content streams with rendering mode 3 (`3 Tr (payload) Tj`), invisible to visual rendering but parsable by PDF structure extractors.
3. **Structural Catalog Piece Info:** Attaches a private `/ForensicPieceInfo` dictionary to the PDF root catalog.
4. **Confidence Scoring:** Extraction cross-checks all layers and returns an objective confidence score ($0.0 - 1.0$) alongside explicit attribution limitation statements.

---

## 5. Running the Automated Test Suite

All 31 tests across shared cryptography, forensic watermarking, online backend, unified multi-recipient packages, offline system, and full integration can be run via:

```powershell
python -m pytest tests/ online/backend/tests/ -v
```

### Test Coverage Highlights
* `tests/shared/test_crypto_core.py`: AES-256-GCM authenticated encryption, tag verification failure, tampered AAD rejection, fresh nonce verification, X25519 key agreement, Ed25519 digital signatures.
* `tests/shared/test_unified_package.py`: Single-file distribution container (`UnifiedMultiRecipientPackage`), multi-recipient slot unwrapping, unauthorized access rejection, owner Ed25519 tamper detection, and end-to-end API workflow.
* `tests/shared/test_watermark.py`: Zero-width roundtrip, text watermarking, multi-layer PDF watermarking and extraction, unwatermarked PDF rejection, corrupted payload CRC rejection.
* `online/backend/tests/test_online_workflow.py`: Owner registration, login, document upload, recipient key management, multi-recipient distribution, recipient `.enc` download, client-side decryption, unauthorized access rejection, leak investigation attribution, recipient revocation, audit trail.
* `tests/offline/test_offline_system.py`: Device identity generation, registration request signing, owner certificate verification, multi-device `.secure` packaging, authorized decryption, unauthorized rejection, tamper-evident audit verification, data tampering detection, keystore encryption.
* `tests/integration/test_full_system.py`: 5 MB large-file memory safety, false-positive watermark resistance, audit record deletion/truncation detection.

---

## 6. Running Interactive Demonstrations

### Scenario A, B & C: Online Distribution, Leak Investigation & Single-File Container
Demonstrates uploading a confidential PDF, distributing individually or as **ONE single `.secure` file for all recipients**, proving unauthorized parties cannot open it, and investigating simulated leaks to trace attribution:

```powershell
python scripts/run_online_demo.py
```

### Scenario C, D & E: Offline Standalone Application
Demonstrates registering two air-gapped devices, issuing signed certificates, packaging a `.secure` container authorizing only Device 1, proving Device 2 is rejected, and cryptographically verifying the hash-linked audit chain before and after tampering:

```powershell
python scripts/run_offline_demo.py
```

---

## 7. Launching User Interfaces

### A. Online Web Application
Start the FastAPI server:
```powershell
python -m uvicorn online.backend.app.main:app --port 8000 --reload
```
Open your browser at: **`http://localhost:8000`** to access the complete responsive web application (Owner Dashboard, Upload, Recipients, Distribute, Recipient Portal, Leak Investigation, Audit Trail).

### B. Offline PySide6 Desktop Application
Run the standalone desktop GUI:
```powershell
python offline/app/main.py
```
Provides the full graphical workflow: Device Registry & Approvals, Document Packaging, Secure Document Decryption, and the Tamper-Evident Audit Explorer.

---

## 8. Technical Security Limitations

1. **Attribution Boundaries:** Watermarking cryptographically proves which distributed recipient copy an exfiltrated file originated from. It does not independently identify the physical human who extracted or leaked the file.
2. **Post-Decryption Plaintext:** Once a recipient decrypts a document into memory or plaintext, the application cannot prevent operating system-level screenshots or physical photography ("analog hole").
3. **Air-Gapped Revocation:** In an offline environment, revocation takes effect when updated signed authorization registries are imported into devices or embedded into new distribution packages.
4. **Local Audit Logs:** Hash-linked audit logs are **tamper-evident**, not tamper-proof against full local root/administrator compromise (an attacker with OS root could wipe the disk or delete the database file).
