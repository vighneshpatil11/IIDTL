"""PySide6 Desktop Application UI for Offline Prototype."""

import os
import json
from pathlib import Path
from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QTabWidget,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QFileDialog,
    QMessageBox,
    QTextEdit,
    QLineEdit,
    QCheckBox,
    QGroupBox,
    QScrollArea,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

from offline.app.database.connection import init_offline_db, get_offline_db
from offline.app.database.models import OfflineDevice, OfflineAuditLog, OfflineDocument
from offline.app.security.device_keys import (
    DeviceKeyManager,
    DeviceRegistrationRequest,
    DeviceCertificate,
)
from offline.app.services.offline_packager import OfflinePackagingService
from offline.app.services.audit_service import HashLinkedAuditService
from shared.crypto.signatures import (
    generate_ed25519_keypair,
    ed25519_public_to_bytes,
    ed25519_private_to_bytes,
)
from shared.crypto.key_exchange import x25519_public_to_bytes, x25519_private_to_bytes
from shared.utils.serialization import b64encode_str, b64decode_str


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DocFortress - Air-Gapped Document Security (Offline)")
        self.resize(1050, 720)

        # Initialize local database
        init_offline_db()
        self.db = get_offline_db()

        # Temporary in-memory owner keys for session (can be persisted)
        self.owner_sign_priv, self.owner_sign_pub = generate_ed25519_keypair()
        self.owner_id = "OWNER-ADMIN-01"

        # Active device keys for testing decryption
        self.active_dev_id, self.active_dev_sign_priv, self.active_dev_enc_priv = (
            DeviceKeyManager.create_device_identity("Local-Field-Laptop")
        )

        self._setup_ui()
        self.refresh_all_views()

    def _setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Header Banner
        header = QWidget()
        header.setStyleSheet("background-color: #0f172a; color: white; border-radius: 8px; padding: 10px;")
        h_layout = QHBoxLayout(header)
        title_label = QLabel("🛡️ DocFortress Offline - Standalone Cryptographic Access Control")
        title_label.setFont(QFont("Segoe UI", 12, QFont.Bold))
        h_layout.addWidget(title_label)
        status_label = QLabel(f"Owner ID: {self.owner_id} | Air-Gapped Mode")
        status_label.setStyleSheet("color: #94a3b8; font-size: 11px;")
        h_layout.addStretch()
        h_layout.addWidget(status_label)
        main_layout.addWidget(header)

        # Tabs
        self.tabs = QTabWidget()
        self.tabs.setFont(QFont("Segoe UI", 9))

        self.tab_devices = QWidget()
        self.tab_packaging = QWidget()
        self.tab_decryption = QWidget()
        self.tab_audit = QWidget()

        self.tabs.addTab(self.tab_devices, "1. Device Registry & Approvals")
        self.tabs.addTab(self.tab_packaging, "2. Package & Encrypt Document")
        self.tabs.addTab(self.tab_decryption, "3. Secure Document Decryption")
        self.tabs.addTab(self.tab_audit, "4. Tamper-Evident Audit Trail")

        main_layout.addWidget(self.tabs)

        self._build_device_tab()
        self._build_packaging_tab()
        self._build_decryption_tab()
        self._build_audit_tab()

    def _build_device_tab(self):
        layout = QVBoxLayout(self.tab_devices)

        # Actions
        actions_box = QGroupBox("Device Registration Actions")
        act_layout = QHBoxLayout(actions_box)

        btn_new_device = QPushButton("➕ Register New Simulated Device")
        btn_new_device.clicked.connect(self._create_simulated_device)
        act_layout.addWidget(btn_new_device)

        btn_import_req = QPushButton("📂 Import Registration Request (.json)")
        btn_import_req.clicked.connect(self._import_registration_request)
        act_layout.addWidget(btn_import_req)

        layout.addWidget(actions_box)

        # Device Table
        self.dev_table = QTableWidget()
        self.dev_table.setColumnCount(5)
        self.dev_table.setHorizontalHeaderLabels(["Device ID", "Device Name", "Status", "Public Sign Key", "Actions"])
        self.dev_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.dev_table)

    def _build_packaging_tab(self):
        layout = QVBoxLayout(self.tab_packaging)

        # File selection
        file_box = QGroupBox("Select Confidential Document")
        fb_layout = QHBoxLayout(file_box)
        self.txt_pkg_file = QLineEdit()
        self.txt_pkg_file.setPlaceholderText("Select file to encrypt (.pdf, .txt, .docx)...")
        btn_browse = QPushButton("Browse...")
        btn_browse.clicked.connect(self._browse_document_to_package)
        fb_layout.addWidget(self.txt_pkg_file)
        fb_layout.addWidget(btn_browse)
        layout.addWidget(file_box)

        # Authorized devices selection
        dev_sel_box = QGroupBox("Authorize Approved Devices for this Document")
        self.dev_checkbox_layout = QVBoxLayout(dev_sel_box)
        self.dev_checkboxes = {}
        layout.addWidget(dev_sel_box)

        btn_create_pkg = QPushButton("🔒 Encrypt Document & Export .secure Package")
        btn_create_pkg.setStyleSheet("background-color: #059669; color: white; font-weight: bold; padding: 10px;")
        btn_create_pkg.clicked.connect(self._create_package_action)
        layout.addWidget(btn_create_pkg)

        self.txt_pkg_log = QTextEdit()
        self.txt_pkg_log.setReadOnly(True)
        self.txt_pkg_log.setMaximumHeight(160)
        self.txt_pkg_log.setPlaceholderText("Packaging telemetry and status...")
        layout.addWidget(self.txt_pkg_log)

    def _build_decryption_tab(self):
        layout = QVBoxLayout(self.tab_decryption)

        input_box = QGroupBox("Target Package (.secure)")
        in_layout = QHBoxLayout(input_box)
        self.txt_dec_file = QLineEdit()
        self.txt_dec_file.setPlaceholderText("Select encrypted .secure container...")
        btn_browse_pkg = QPushButton("Browse...")
        btn_browse_pkg.clicked.connect(self._browse_package_to_decrypt)
        in_layout.addWidget(self.txt_dec_file)
        in_layout.addWidget(btn_browse_pkg)
        layout.addWidget(input_box)

        dev_info_box = QGroupBox("Active Device Decryption Credentials")
        di_layout = QHBoxLayout(dev_info_box)
        self.lbl_active_dev = QLabel(f"Active Device: {self.active_dev_id}")
        self.lbl_active_dev.setFont(QFont("Segoe UI", 9, QFont.Bold))
        btn_switch_dev = QPushButton("Switch Target Device...")
        btn_switch_dev.clicked.connect(self._switch_active_device)
        di_layout.addWidget(self.lbl_active_dev)
        di_layout.addStretch()
        di_layout.addWidget(btn_switch_dev)
        layout.addWidget(dev_info_box)

        btn_decrypt = QPushButton("🔓 Verify Owner Signature & Decrypt Package")
        btn_decrypt.setStyleSheet("background-color: #2563eb; color: white; font-weight: bold; padding: 10px;")
        btn_decrypt.clicked.connect(self._decrypt_package_action)
        layout.addWidget(btn_decrypt)

        # Viewer output
        viewer_box = QGroupBox("Decrypted Document Buffer")
        v_layout = QVBoxLayout(viewer_box)
        self.txt_decrypted_view = QTextEdit()
        self.txt_decrypted_view.setReadOnly(True)
        self.txt_decrypted_view.setFont(QFont("Consolas", 9))
        v_layout.addWidget(self.txt_decrypted_view)
        layout.addWidget(viewer_box)

    def _build_audit_tab(self):
        layout = QVBoxLayout(self.tab_audit)

        # Audit toolbar
        tb = QHBoxLayout()
        btn_verify = QPushButton("🔍 Verify Cryptographic Chain Integrity")
        btn_verify.setStyleSheet("background-color: #4f46e5; color: white; font-weight: bold; padding: 6px 12px;")
        btn_verify.clicked.connect(self._verify_audit_action)
        tb.addWidget(btn_verify)

        self.lbl_audit_status = QLabel("Chain Status: Unverified")
        self.lbl_audit_status.setStyleSheet("font-weight: bold; padding-left: 10px;")
        tb.addWidget(self.lbl_audit_status)
        tb.addStretch()

        btn_refresh = QPushButton("Refresh Table")
        btn_refresh.clicked.connect(self.refresh_audit_table)
        tb.addWidget(btn_refresh)
        layout.addLayout(tb)

        # Table
        self.audit_table = QTableWidget()
        self.audit_table.setColumnCount(7)
        self.audit_table.setHorizontalHeaderLabels([
            "Seq", "Event ID", "Device ID", "Event Type", "Result", "Previous Hash", "Event Hash"
        ])
        self.audit_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        layout.addWidget(self.audit_table)

    def _create_simulated_device(self):
        import secrets
        name = f"Terminal-{secrets.token_hex(2).upper()}"
        dev_id, sign_priv, enc_priv = DeviceKeyManager.create_device_identity(name)

        req = DeviceKeyManager.export_registration_request(dev_id, name, sign_priv, enc_priv.public_key())
        cert = DeviceKeyManager.approve_device_registration(req, self.owner_id, self.owner_sign_priv)

        device = OfflineDevice(
            device_id=dev_id,
            device_name=name,
            public_sign_key=req.public_sign_key,
            public_enc_key=req.public_enc_key,
            registration_status="APPROVED",
            owner_certificate_signature=cert.owner_signature,
        )
        self.db.add(device)
        self.db.commit()

        # Log audit
        HashLinkedAuditService.record_event(
            self.db,
            device_id=self.owner_id,
            event_type="DEVICE_REGISTERED",
            result="APPROVED",
            document_id=dev_id,
        )

        QMessageBox.information(self, "Device Registered", f"Device {dev_id} ({name}) registered and approved!")
        self.refresh_all_views()

    def _import_registration_request(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open Registration Request", "", "JSON Files (*.json)")
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            req = DeviceRegistrationRequest(**data)
            cert = DeviceKeyManager.approve_device_registration(req, self.owner_id, self.owner_sign_priv)

            device = OfflineDevice(
                device_id=req.device_id,
                device_name=req.device_name,
                public_sign_key=req.public_sign_key,
                public_enc_key=req.public_enc_key,
                registration_status="APPROVED",
                owner_certificate_signature=cert.owner_signature,
            )
            self.db.add(device)
            self.db.commit()

            HashLinkedAuditService.record_event(
                self.db,
                device_id=self.owner_id,
                event_type="DEVICE_IMPORTED",
                result="APPROVED",
                document_id=req.device_id,
            )
            QMessageBox.information(self, "Success", f"Approved and registered {req.device_id}!")
            self.refresh_all_views()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to import request: {str(e)}")

    def _browse_document_to_package(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Document", "", "All Files (*.*)")
        if path:
            self.txt_pkg_file.setText(path)

    def _browse_package_to_decrypt(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Package",
            "",
            "All Protected Packages (*.secure *.enc);;Offline Packages (*.secure);;Online Packages (*.enc);;All Files (*)",
        )
        if path:
            self.txt_dec_file.setText(path)

    def _create_package_action(self):
        doc_path = self.txt_pkg_file.text().strip()
        if not doc_path or not Path(doc_path).is_file():
            QMessageBox.warning(self, "Warning", "Please select a valid document file.")
            return

        selected_devs = [dev_id for dev_id, cb in self.dev_checkboxes.items() if cb.isChecked()]
        if not selected_devs:
            QMessageBox.warning(self, "Warning", "Please select at least one approved device.")
            return

        save_dir = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if not save_dir:
            return

        try:
            with open(doc_path, "rb") as f:
                doc_bytes = f.read()

            pkg, out_path = OfflinePackagingService.create_package(
                db=self.db,
                document_bytes=doc_bytes,
                filename=Path(doc_path).name,
                owner_id=self.owner_id,
                owner_sign_priv=self.owner_sign_priv,
                authorized_device_ids=selected_devs,
                output_dir=save_dir,
            )

            msg = (
                f"[+] Successfully encrypted document!\n"
                f"    - Package ID: {pkg.package_id}\n"
                f"    - Document ID: {pkg.document_id}\n"
                f"    - SHA-256: {pkg.original_sha256}\n"
                f"    - Authorized Devices ({len(selected_devs)}): {', '.join(selected_devs)}\n"
                f"    - Saved to: {out_path}\n"
            )
            self.txt_pkg_log.setText(msg)
            QMessageBox.information(self, "Success", f"Package saved to:\n{out_path}")
            self.refresh_audit_table()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Packaging failed: {str(e)}")

    def _decrypt_package_action(self):
        pkg_path = self.txt_dec_file.text().strip()
        if not pkg_path or not Path(pkg_path).is_file():
            QMessageBox.warning(self, "Warning", "Please select a valid .secure package file.")
            return

        try:
            with open(pkg_path, "rb") as f:
                pkg_bytes = f.read()

            plaintext = OfflinePackagingService.decrypt_package_on_device(
                db=self.db,
                package_bytes=pkg_bytes,
                device_id=self.active_dev_id,
                device_enc_priv=self.active_dev_enc_priv,
                device_sign_priv=self.active_dev_sign_priv,
            )

            # Display preview
            try:
                preview = plaintext.decode("utf-8")
            except Exception:
                preview = f"[Binary Document Stream - {len(plaintext)} bytes]\n(PDF Magic: {plaintext[:5].decode('latin1', 'ignore')})"

            self.txt_decrypted_view.setText(f"=== DECRYPTED CONTENT ({len(plaintext)} bytes) ===\n\n{preview}")
            QMessageBox.information(self, "Decryption Succeeded", f"Document integrity verified.\nDecrypted for {self.active_dev_id}")
            self.refresh_audit_table()
        except Exception as e:
            self.txt_decrypted_view.setText(f"[ACCESS DENIED]\nReason: {str(e)}")
            QMessageBox.critical(self, "Access Denied", f"Decryption rejected:\n{str(e)}")
            self.refresh_audit_table()

    def _verify_audit_action(self):
        is_valid, msg, telemetry = HashLinkedAuditService.verify_audit_chain(self.db)
        if is_valid:
            self.lbl_audit_status.setText(f"✅ {msg}")
            self.lbl_audit_status.setStyleSheet("color: #16a34a; font-weight: bold; padding-left: 10px;")
            QMessageBox.information(self, "Audit Verified", f"Cryptographic audit chain intact.\n{msg}")
        else:
            self.lbl_audit_status.setText(f"❌ {msg}")
            self.lbl_audit_status.setStyleSheet("color: #dc2626; font-weight: bold; padding-left: 10px;")
            QMessageBox.critical(self, "Tampering Detected!", f"Integrity check failed!\n{msg}")

    def _switch_active_device(self):
        devices = self.db.query(OfflineDevice).all()
        if not devices:
            QMessageBox.warning(self, "No Devices", "No registered devices exist.")
            return
        dev_names = [f"{d.device_id} ({d.device_name}) [{d.registration_status}]" for d in devices]
        from PySide6.QtWidgets import QInputDialog
        choice, ok = QInputDialog.getItem(self, "Switch Device", "Select active device:", dev_names, 0, False)
        if ok and choice:
            selected_id = choice.split(" ")[0]
            self.active_dev_id = selected_id
            self.lbl_active_dev.setText(f"Active Device: {self.active_dev_id}")

    def refresh_all_views(self):
        self.refresh_device_table()
        self.refresh_device_checkboxes()
        self.refresh_audit_table()

    def refresh_device_table(self):
        devices = self.db.query(OfflineDevice).all()
        self.dev_table.setRowCount(len(devices))
        for row, d in enumerate(devices):
            self.dev_table.setItem(row, 0, QTableWidgetItem(d.device_id))
            self.dev_table.setItem(row, 1, QTableWidgetItem(d.device_name))
            self.dev_table.setItem(row, 2, QTableWidgetItem(d.registration_status))
            self.dev_table.setItem(row, 3, QTableWidgetItem(f"{d.public_sign_key[:16]}..."))

            btn_revoke = QPushButton("Revoke" if d.registration_status == "APPROVED" else "Re-Approve")
            btn_revoke.clicked.connect(lambda _, dev=d: self._toggle_device_status(dev))
            self.dev_table.setCellWidget(row, 4, btn_revoke)

    def _toggle_device_status(self, device):
        device.registration_status = "REVOKED" if device.registration_status == "APPROVED" else "APPROVED"
        self.db.commit()
        HashLinkedAuditService.record_event(
            self.db,
            device_id=self.owner_id,
            event_type="DEVICE_STATUS_CHANGED",
            result=device.registration_status,
            document_id=device.device_id,
        )
        self.refresh_all_views()

    def refresh_device_checkboxes(self):
        # Clear existing
        while self.dev_checkbox_layout.count():
            item = self.dev_checkbox_layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()
        self.dev_checkboxes.clear()

        devices = self.db.query(OfflineDevice).filter(OfflineDevice.registration_status == "APPROVED").all()
        if not devices:
            self.dev_checkbox_layout.addWidget(QLabel("No approved devices available."))
            return

        for d in devices:
            cb = QCheckBox(f"{d.device_name} ({d.device_id})")
            cb.setChecked(True)
            self.dev_checkboxes[d.device_id] = cb
            self.dev_checkbox_layout.addWidget(cb)

    def refresh_audit_table(self):
        logs = self.db.query(OfflineAuditLog).order_by(OfflineAuditLog.sequence_id.desc()).all()
        self.audit_table.setRowCount(len(logs))
        for row, l in enumerate(logs):
            self.audit_table.setItem(row, 0, QTableWidgetItem(str(l.sequence_id)))
            self.audit_table.setItem(row, 1, QTableWidgetItem(l.event_id))
            self.audit_table.setItem(row, 2, QTableWidgetItem(l.device_id))
            self.audit_table.setItem(row, 3, QTableWidgetItem(l.event_type))
            self.audit_table.setItem(row, 4, QTableWidgetItem(l.result))
            self.audit_table.setItem(row, 5, QTableWidgetItem(f"{l.previous_hash[:12]}..."))
            self.audit_table.setItem(row, 6, QTableWidgetItem(f"{l.event_hash[:12]}..."))
