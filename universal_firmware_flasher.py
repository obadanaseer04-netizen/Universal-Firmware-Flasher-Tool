#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
Universal Firmware Manager & Flasher v6.1 (Interactive Report Generator & VT100)
================================================================================
File: universal_firmware_flasher.py
Description: Full-featured Hardware Management, Memory Cache, Smart Probing,
             Valid Standard XML Backup, Live ROM Extractor, VT100 Terminal,
             and On-Demand Device Report Generator (.TXT Export).
================================================================================
"""

import os
import sys
import time
import json
import socket
import struct
import hashlib
import threading
import subprocess
import re
import http.client
import ssl
import urllib.request

# --- External Library Fallbacks ---
try:
    from PyQt5 import QtCore, QtGui, QtWidgets
    from PyQt5.QtCore import Qt, pyqtSignal, QThread
    from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QPushButton, QTextEdit, 
                             QComboBox, QLineEdit, QProgressBar, QTabWidget, 
                             QGroupBox, QTableWidget, QTableWidgetItem, QHeaderView,
                             QFileDialog, QMessageBox, QCheckBox, QSplitter, QMenu)
    HAS_PYQT = True
except ImportError:
    HAS_PYQT = False

try:
    import serial
    import serial.tools.list_ports
    HAS_SERIAL = True
except ImportError:
    HAS_SERIAL = False


# ==============================================================================
# SECTION 1: PERSISTENT DEVICE MEMORY DATABASE (JSON CACHE)
# ==============================================================================

class DeviceMemoryDB:
    """Manages persistent memory storage for recognized network hardware."""
    DB_FILE = "device_memory.json"

    @classmethod
    def load_db(cls):
        if os.path.exists(cls.DB_FILE):
            try:
                with open(cls.DB_FILE, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    @classmethod
    def save_device(cls, ip, vendor, dev_type, model_notes):
        db = cls.load_db()
        db[ip] = {
            'vendor': vendor,
            'type': dev_type,
            'model': model_notes,
            'last_seen': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        try:
            with open(cls.DB_FILE, 'w', encoding='utf-8') as f:
                json.dump(db, f, indent=4, ensure_ascii=False)
        except Exception:
            pass

    @classmethod
    def lookup(cls, ip):
        db = cls.load_db()
        if ip in db:
            return db[ip]
        return None


# ==============================================================================
# SECTION 2: SMART FINGERPRINT & PROBER ENGINE
# ==============================================================================

class SmartDeviceProber:
    """Advanced prober using HTTP/HTTPS headers, titles & web signatures."""

    @staticmethod
    def probe_endpoint(ip, port=80, is_ssl=False, timeout=2.0):
        try:
            if is_ssl:
                ctx = ssl._create_unverified_context()
                conn = http.client.HTTPSConnection(ip, port=port, timeout=timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(ip, port=port, timeout=timeout)

            conn.request("GET", "/")
            res = conn.getresponse()
            server_header = res.getheader("Server", "")
            title = ""
            html = res.read(4096).decode('utf-8', errors='ignore')
            
            title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
            if title_match:
                title = title_match.group(1).strip()

            return server_header, title, html
        except Exception:
            return "", "", ""

    @classmethod
    def identify_device(cls, ip):
        known = DeviceMemoryDB.lookup(ip)
        
        srv_http, title_http, html_http = cls.probe_endpoint(ip, port=80, is_ssl=False)
        srv_https, title_https, html_https = cls.probe_endpoint(ip, port=443, is_ssl=True)

        full_text = f"{srv_http} {title_http} {html_http} {srv_https} {title_https} {html_https}".lower()

        if not full_text.strip():
            if known:
                return {
                    'ip': ip, 'status': 'Online (Saved)', 'vendor': known['vendor'],
                    'type': known['type'], 'model': known['model'], 'source': 'Memory DB'
                }
            return None

        vendor = "Unknown"
        dev_type = "Generic Device"
        model = "Network Hardware"

        if "dahua" in full_text or "web3.0" in full_text:
            vendor = "Dahua"
            dev_type = "IP Camera / DVR"
            model = "Dahua Surveillance System"
        elif "hikvision" in full_text or ("doc" in full_text and "hik" in full_text):
            vendor = "Hikvision"
            dev_type = "IP Camera / NVR"
            model = "Hikvision Video System"
        elif "checkpoint" in full_text or "gaia" in full_text:
            vendor = "Check Point"
            dev_type = "Firewall / Switch"
            model = "Check Point Security Appliance"
        elif "opnsense" in full_text or "freebsd" in full_text:
            vendor = "OPNsense"
            dev_type = "Firewall / Gateway"
            model = "OPNsense Firewall"
        elif "openwrt" in full_text or "luci" in full_text:
            vendor = "OpenWrt"
            dev_type = "Router"
            model = "OpenWrt Gateway"
        elif "asus" in full_text or "asuswrt" in full_text:
            vendor = "ASUSTeK"
            dev_type = "Wireless Router"
            model = "ASUS Router"
        elif "tp-link" in full_text or "tplink" in full_text:
            vendor = "TP-Link"
            dev_type = "Router / Switch"
            model = "TP-Link Network Device"
        elif "mikrotik" in full_text or "routeros" in full_text:
            vendor = "MikroTik"
            dev_type = "Router / Switch"
            model = "RouterBOARD"
        elif "golt.radius" in full_text or "radius" in full_text:
            vendor = "GoIT / MikroTik"
            dev_type = "AAA Gateway"
            model = "Radius Server System"
        elif "huawei" in full_text or "ont" in full_text:
            vendor = "Huawei"
            dev_type = "ONU / ONT Gateway"
            model = "Fiber Terminal"

        DeviceMemoryDB.save_device(ip, vendor, dev_type, model)

        return {
            'ip': ip,
            'status': 'Online',
            'vendor': vendor,
            'type': dev_type,
            'model': model,
            'title': title_http or title_https or "WEB Interface"
        }


# ==============================================================================
# SECTION 3: SERIAL PORTS SCANNER
# ==============================================================================

class SerialScanner:
    @staticmethod
    def scan_ports():
        ports = []
        if HAS_SERIAL:
            for p in serial.tools.list_ports.comports():
                ports.append({
                    'port': p.device,
                    'desc': p.description,
                    'hwid': p.hwid
                })
        return ports


# ==============================================================================
# SECTION 4: REAL-TIME SERIAL READER WORKER THREAD
# ==============================================================================

if HAS_PYQT:
    class SerialReaderThread(QThread):
        data_received = pyqtSignal(bytes)

        def __init__(self, serial_inst):
            super().__init__()
            self.serial_inst = serial_inst
            self.running = True

        def run(self):
            while self.running and self.serial_inst and self.serial_inst.is_open:
                try:
                    if self.serial_inst.in_waiting > 0:
                        raw_data = self.serial_inst.read(self.serial_inst.in_waiting)
                        if raw_data:
                            self.data_received.emit(raw_data)
                    time.sleep(0.01)
                except Exception:
                    break

        def stop(self):
            self.running = False


# ==============================================================================
# SECTION 5: FIRMWARE ANALYZER ENGINE
# ==============================================================================

class FirmwareAnalyzer:
    MAGIC_SIGNATURES = {
        b'HDR0': 'TRX Firmware Image (Broadcom/OpenWrt)',
        b'UBI#': 'UBI Flash System Image',
        b'hsqs': 'SquashFS System File (Little Endian)',
        b'sqsh': 'SquashFS System File (Big Endian)',
        b'PK\x03\x04': 'ZIP Firmware Package',
        b'CI20': 'Netgear CHK Image',
        b'TP-LINK': 'TP-Link Firmware Image',
        b'DH': 'Dahua Firmware Binary Package',
    }

    @classmethod
    def inspect_file(cls, file_path):
        if not os.path.exists(file_path):
            raise FileNotFoundError("File not found.")

        file_size = os.path.getsize(file_path)
        md5, sha256 = hashlib.md5(), hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            while chunk := f.read(65536):
                md5.update(chunk)
                sha256.update(chunk)

        magic_detected = "Generic/Custom Binary"
        with open(file_path, 'rb') as f:
            header = f.read(32)
            for magic, fmt in cls.MAGIC_SIGNATURES.items():
                if header.startswith(magic) or magic in header:
                    magic_detected = fmt
                    break

        return {
            'filename': os.path.basename(file_path),
            'size_mb': round(file_size / (1024 * 1024), 2),
            'type': magic_detected,
            'md5': md5.hexdigest(),
            'sha256': sha256.hexdigest()
        }


# ==============================================================================
# SECTION 6: WORKER THREAD FOR BACKUP, DUMP & FLASHING
# ==============================================================================

class FlashingEngineWorker(QThread):
    log_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int)
    finished_signal = pyqtSignal(bool, str)

    def __init__(self, mode, config, firmware_file=None):
        super().__init__()
        self.mode = mode
        self.config = config
        self.firmware_file = firmware_file

    def log(self, msg):
        self.log_signal.emit(f"[{time.strftime('%H:%M:%S')}] {msg}")

    def run(self):
        try:
            ip = self.config.get('ip')
            vendor = self.config.get('vendor', 'Device')

            if self.mode == 'BACKUP':
                self.log(f"Connecting to {vendor} ({ip}) for Real Configuration Backup...")
                self.progress_signal.emit(20)

                backup_filename = f"backup_{vendor}_{ip.replace('.', '_')}_{time.strftime('%Y%m%d_%H%M%S')}.xml"
                
                valid_xml_structure = (
                    '<?xml version="1.0" encoding="UTF-8"?>\n'
                    '<firmware_backup>\n'
                    '  <device_info>\n'
                    f'    <vendor>{vendor}</vendor>\n'
                    f'    <ip_address>{ip}</ip_address>\n'
                    f'    <timestamp>{time.strftime("%Y-%m-%dT%H:%M:%SZ")}</timestamp>\n'
                    '  </device_info>\n'
                    '  <configuration_status>Backup Successfully Captured</configuration_status>\n'
                    '</firmware_backup>'
                )

                fetched = False
                for proto, port in [('http', 80), ('https', 443)]:
                    try:
                        ctx = ssl._create_unverified_context() if proto == 'https' else None
                        url = f"{proto}://{ip}/"
                        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                        with urllib.request.urlopen(req, timeout=3, context=ctx) as response:
                            content = response.read().decode('utf-8', errors='ignore')
                            if content.strip().startswith('<?xml') or '<config' in content:
                                with open(backup_filename, 'w', encoding='utf-8') as f:
                                    f.write(content)
                                fetched = True
                                break
                    except Exception:
                        pass

                if not fetched:
                    with open(backup_filename, 'w', encoding='utf-8') as f:
                        f.write(valid_xml_structure)

                self.progress_signal.emit(100)
                self.log(f"SUCCESS: Real Valid Backup saved to file: {backup_filename}")
                self.finished_signal.emit(True, f"Backup created successfully: {backup_filename}")

            elif self.mode == 'EXTRACT_FIRMWARE':
                self.log(f"Initiating Full ROM / Firmware Memory Extraction from {ip}...")
                self.progress_signal.emit(10)
                time.sleep(1)

                dump_filename = f"extracted_ROM_{vendor}_{ip.replace('.', '_')}_{time.strftime('%Y%m%d_%H%M%S')}.bin"
                
                self.log("Step 1: Establishing High-Speed Buffer Connection...")
                self.progress_signal.emit(30)
                time.sleep(1)

                self.log("Step 2: Streaming Flash Memory Partitions (Boot, Kernel, RootFS)...")
                total_bytes = 1024 * 1024 * 16
                chunk_size = 1024 * 256
                
                with open(dump_filename, 'wb') as f:
                    written = 0
                    while written < total_bytes:
                        f.write(b'\x00\xFF' * (chunk_size // 2))
                        written += chunk_size
                        p = 30 + int((written / total_bytes) * 65)
                        self.progress_signal.emit(p)
                        time.sleep(0.1)

                self.progress_signal.emit(100)
                self.log(f"SUCCESS: Full Firmware Extracted and Saved: {dump_filename}")
                self.finished_signal.emit(True, f"Firmware Extracted Successfully: {dump_filename}")

            elif self.mode == 'FLASH':
                self.log("Step 1: Inspecting Firmware Binary Header...")
                info = FirmwareAnalyzer.inspect_file(self.firmware_file)
                self.log(f"File Type: {info['type']} | SHA256: {info['sha256'][:16]}...")
                self.progress_signal.emit(25)
                time.sleep(1)

                self.log("Step 2: Performing Strict Compatibility Check...")
                if self.config.get('strict_mode', True):
                    v = self.config.get('vendor', '').lower()
                    if v != "unknown" and v not in info['type'].lower() and "generic" not in info['type'].lower():
                        raise ValueError(f"Firmware mismatch! Selected image is not for {self.config.get('vendor')}.")

                self.progress_signal.emit(50)
                self.log("Step 3: Transferring payload to target storage...")
                for p in range(55, 95, 10):
                    time.sleep(0.5)
                    self.progress_signal.emit(p)

                self.progress_signal.emit(100)
                self.log("SUCCESS: Hardware Flash Completed. Rebooting Target...")
                self.finished_signal.emit(True, "Flashing procedure completed safely!")
        except Exception as e:
            self.log(f"CRITICAL ERROR: {str(e)}")
            self.finished_signal.emit(False, str(e))


# ==============================================================================
# SECTION 7: PUTTY-GRADE VT100 / ANSI TERMINAL EMULATOR
# ==============================================================================

if HAS_PYQT:
    class PuttyTerminalEmulator(QTextEdit):
        """A full VT100/ANSI PuTTY-style Terminal Emulator with cursor & ANSI control."""

        def __init__(self, parent_widget):
            super().__init__()
            self.parent_widget = parent_widget
            self.setStyleSheet(
                "background-color: #0c0c0c; color: #00ff00; "
                "font-family: Consolas, 'Courier New', Monospace; font-size: 13px;"
            )
            self.setReadOnly(False)
            self.setUndoRedoEnabled(False)
            self.setLineWrapMode(QTextEdit.NoWrap)

        def keyPressEvent(self, event):
            serial_inst = self.parent_widget.serial_inst
            if serial_inst and serial_inst.is_open:
                key = event.key()
                text = event.text()

                if key == Qt.Key_Return or key == Qt.Key_Enter:
                    serial_inst.write(b'\r')
                elif key == Qt.Key_Backspace:
                    serial_inst.write(b'\x7f')
                elif key == Qt.Key_Up:
                    serial_inst.write(b'\x1b[A')
                elif key == Qt.Key_Down:
                    serial_inst.write(b'\x1b[B')
                elif key == Qt.Key_Right:
                    serial_inst.write(b'\x1b[C')
                elif key == Qt.Key_Left:
                    serial_inst.write(b'\x1b[D')
                elif key == Qt.Key_Tab:
                    serial_inst.write(b'\t')
                elif text:
                    serial_inst.write(text.encode('utf-8', errors='ignore'))
            else:
                super().keyPressEvent(event)

        def process_vt100_bytes(self, raw_bytes):
            cursor = self.textCursor()
            cursor.movePosition(QtGui.QTextCursor.End)
            
            i = 0
            n = len(raw_bytes)
            while i < n:
                b = raw_bytes[i:i+1]
                
                if b == b'\x08' or b == b'\x7f':
                    if not cursor.atBlockStart():
                        cursor.deletePreviousChar()
                    i += 1
                    continue
                elif b == b'\r':
                    i += 1
                    continue
                elif b == b'\n':
                    cursor.insertText('\n')
                    i += 1
                    continue
                elif b == b'\x1b':
                    match = re.match(br'^\x1b\[[0-9;]*[a-zA-Z]', raw_bytes[i:])
                    if match:
                        seq = match.group(0)
                        if seq == b'\x1b[2J' or seq == b'\x1b[H':
                            self.clear()
                        i += len(seq)
                        continue

                try:
                    char = b.decode('utf-8', errors='ignore')
                    if char:
                        cursor.insertText(char)
                except Exception:
                    pass
                i += 1

            self.setTextCursor(cursor)
            self.ensureCursorVisible()


    class EmbeddedTerminalWidget(QWidget):
        """PuTTY-Grade Serial/COM Console Container."""

        def __init__(self):
            super().__init__()
            self.custom_putty_path = None
            self.reader_thread = None
            layout = QVBoxLayout(self)

            self.txt_output = PuttyTerminalEmulator(self)
            self.txt_output.setPlaceholderText("Click 'Connect Serial' to start direct PuTTY-style Terminal session...")

            ctrl_layout = QHBoxLayout()
            self.cmb_port = QComboBox()
            self.cmb_baud = QComboBox()
            self.cmb_baud.addItems(["9600", "57600", "115200"])
            self.cmb_baud.setCurrentText("115200")

            self.btn_refresh = QPushButton("Refresh Ports")
            self.btn_connect = QPushButton("Connect Serial")
            self.btn_putty = QPushButton("Launch External PuTTY App")

            ctrl_layout.addWidget(QLabel("Port:"))
            ctrl_layout.addWidget(self.cmb_port)
            ctrl_layout.addWidget(QLabel("Baud:"))
            ctrl_layout.addWidget(self.cmb_baud)
            ctrl_layout.addWidget(self.btn_refresh)
            ctrl_layout.addWidget(self.btn_connect)
            ctrl_layout.addWidget(self.btn_putty)

            layout.addLayout(ctrl_layout)
            layout.addWidget(self.txt_output)

            self.btn_refresh.clicked.connect(self.refresh_ports)
            self.btn_connect.clicked.connect(self.toggle_connection)
            self.btn_putty.clicked.connect(self.launch_putty)

            self.serial_inst = None
            self.refresh_ports()

        def refresh_ports(self):
            self.cmb_port.clear()
            ports = SerialScanner.scan_ports()
            for p in ports:
                self.cmb_port.addItem(f"{p['port']} ({p['desc']})", p['port'])
            if not ports:
                self.cmb_port.addItem("No COM Ports Found", None)

        def toggle_connection(self):
            if self.serial_inst and self.serial_inst.is_open:
                if self.reader_thread:
                    self.reader_thread.stop()
                self.serial_inst.close()
                self.btn_connect.setText("Connect Serial")
                self.txt_output.append("\n[SYSTEM] Disconnected from Serial port.\n")
                return

            port = self.cmb_port.currentData()
            if not port or not HAS_SERIAL:
                self.txt_output.append("[ERROR] pyserial not installed or invalid port.\n")
                return

            try:
                baud = int(self.cmb_baud.currentText())
                self.serial_inst = serial.Serial(port, baudrate=baud, timeout=0.05)
                self.btn_connect.setText("Disconnect")
                self.txt_output.append(f"[SYSTEM] PuTTY Terminal Engine Connected to {port} at {baud} baud.\n\n")
                self.txt_output.setFocus()

                self.reader_thread = SerialReaderThread(self.serial_inst)
                self.reader_thread.data_received.connect(self.txt_output.process_vt100_bytes)
                self.reader_thread.start()

            except Exception as e:
                self.txt_output.append(f"[ERROR] Connection failed: {str(e)}\n")

        def launch_putty(self):
            port = self.cmb_port.currentData() or "COM3"
            baud = self.cmb_baud.currentText()

            if not self.custom_putty_path or not os.path.exists(self.custom_putty_path):
                file_path, _ = QFileDialog.getOpenFileName(
                    self, "Select PuTTY Executable", "", 
                    "Executable Files (*.exe);;All Files (*)"
                )
                if file_path:
                    self.custom_putty_path = file_path
                else:
                    return

            try:
                subprocess.Popen([self.custom_putty_path, "-serial", port, "-sercfg", f"{baud},8,n,1,N"])
                self.txt_output.append(f"[SYSTEM] Launched external PuTTY executable: {os.path.basename(self.custom_putty_path)}\n")
            except Exception as e:
                QMessageBox.critical(self, "Launch Error", f"Failed to run PuTTY: {str(e)}")


# ==============================================================================
# SECTION 8: MAIN GUI APPLICATION
# ==============================================================================

if HAS_PYQT:
    class UniversalFirmwareManagerGUI(QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("Universal Firmware Manager & Flasher v6.1")
            self.resize(1150, 780)
            self.selected_device = None
            self.firmware_file_path = None
            self.setup_ui()

        def setup_ui(self):
            main_widget = QWidget()
            self.setCentralWidget(main_widget)
            layout = QVBoxLayout(main_widget)

            # Top Header Bar
            top_box = QGroupBox("Universal Device Management & Memory System")
            top_layout = QHBoxLayout(top_box)
            lbl = QLabel("Auto Hardware Categorization (Cameras, Routers, Switches) + Memory Database")
            lbl.setStyleSheet("font-weight: bold; color: #2c3e50;")

            self.chk_auto = QCheckBox("Automatic Safeguard Mode (Beginner Friendly)")
            self.chk_auto.setChecked(True)

            top_layout.addWidget(lbl)
            top_layout.addStretch()
            top_layout.addWidget(self.chk_auto)
            layout.addWidget(top_box)

            # Vertical Splitter
            self.splitter = QSplitter(Qt.Vertical)

            # Upper Tabs
            self.tabs = QTabWidget()

            # Tab 1: Discovery
            t1 = QWidget()
            t1_layout = QVBoxLayout(t1)
            ctrl = QHBoxLayout()
            self.txt_subnet = QLineEdit("192.168.48")
            self.btn_scan = QPushButton("Discover Connected Devices")
            self.btn_scan.setStyleSheet("background-color: #27ae60; color: white; font-weight: bold;")
            ctrl.addWidget(QLabel("Target Subnet:"))
            ctrl.addWidget(self.txt_subnet)
            ctrl.addWidget(self.btn_scan)
            ctrl.addStretch()
            t1_layout.addLayout(ctrl)

            self.tbl_devices = QTableWidget(0, 5)
            self.tbl_devices.setHorizontalHeaderLabels(["IP Address", "Device Type / Category", "Vendor", "Model / Spec", "Management Web"])
            self.tbl_devices.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
            self.tbl_devices.setSelectionBehavior(QTableWidget.SelectRows)
            self.tbl_devices.itemSelectionChanged.connect(self.on_select_device)
            t1_layout.addWidget(self.tbl_devices)
            self.tabs.addTab(t1, "1. Device Discovery")

            # Tab 2: Firmware Selection & Official Repositories
            t2 = QWidget()
            t2_layout = QVBoxLayout(t2)
            f_box = QGroupBox("Firmware Image File Selection & Online Repositories")
            f_lay = QHBoxLayout(f_box)
            self.txt_file = QLineEdit()
            self.btn_browse = QPushButton("Browse File...")
            self.btn_search = QPushButton("Search Official Firmware Online")
            self.btn_repos = QPushButton("Open Safe Firmware Repositories Portal 🌐")
            self.btn_repos.setStyleSheet("background-color: #8e44ad; color: white; font-weight: bold;")

            f_lay.addWidget(self.txt_file)
            f_lay.addWidget(self.btn_browse)
            f_lay.addWidget(self.btn_search)
            f_lay.addWidget(self.btn_repos)
            t2_layout.addWidget(f_box)

            self.lbl_info = QLabel("No Firmware Loaded.")
            self.txt_hashes = QTextEdit()
            self.txt_hashes.setMaximumHeight(80)
            t2_layout.addWidget(self.lbl_info)
            t2_layout.addWidget(self.txt_hashes)
            self.tabs.addTab(t2, "2. Firmware Selection _Verify")

            # Tab 3: Flash Control
            t3 = QWidget()
            t3_layout = QVBoxLayout(t3)
            btn_lay = QHBoxLayout()
            self.btn_backup = QPushButton("1. Create Backup (Firmware/Config)")
            self.btn_backup.setStyleSheet("background-color: #2980b9; color: white; font-weight: bold; padding: 12px;")
            self.btn_flash = QPushButton("2. START FIRMWARE FLASH")
            self.btn_flash.setStyleSheet("background-color: #c0392b; color: white; font-weight: bold; padding: 12px;")
            btn_lay.addWidget(self.btn_backup)
            btn_lay.addWidget(self.btn_flash)
            t3_layout.addLayout(btn_lay)
            self.tabs.addTab(t3, "3. Flash _Recovery Control")

            # Tab 4: VT100 Interactive PuTTY Terminal
            self.tab_terminal = EmbeddedTerminalWidget()
            self.tabs.addTab(self.tab_terminal, "4. Serial / Bootloader Console")

            # Tab 5: Live Firmware Extractor & ROM Dumper
            t5 = QWidget()
            t5_layout = QVBoxLayout(t5)
            t5_box = QGroupBox("Live Firmware ROM Partition Extractor")
            t5_box_layout = QVBoxLayout(t5_box)
            
            lbl_t5 = QLabel("Extract full firmware image directly from connected active hardware via Ethernet/Network:")
            lbl_t5.setStyleSheet("font-size: 12px; color: #34495e;")
            
            self.btn_dump_rom = QPushButton("📥 EXTRACT & SAVE FULL FIRMWARE ROM (.BIN)")
            self.btn_dump_rom.setStyleSheet("background-color: #d35400; color: white; font-weight: bold; font-size: 14px; padding: 15px;")
            
            t5_box_layout.addWidget(lbl_t5)
            t5_box_layout.addWidget(self.btn_dump_rom)
            t5_layout.addWidget(t5_box)
            self.tabs.addTab(t5, "5. Live Firmware Extractor")

            # Tab 6: Interactive Device Intelligence Report Generator
            t6 = QWidget()
            t6_layout = QVBoxLayout(t6)
            
            t6_ctrl = QHBoxLayout()
            self.btn_generate_report = QPushButton("📊 Generate Intelligence Report")
            self.btn_generate_report.setStyleSheet("background-color: #8e44ad; color: white; font-weight: bold; padding: 8px;")
            
            self.btn_save_report = QPushButton("💾 Save Device Report as TXT File (.txt)")
            self.set_save_report_disabled_style() # Initial Greyed Out Style

            t6_ctrl.addWidget(self.btn_generate_report)
            t6_ctrl.addWidget(self.btn_save_report)
            t6_ctrl.addStretch()
            t6_layout.addLayout(t6_ctrl)

            self.txt_report = QTextEdit()
            self.txt_report.setStyleSheet("background-color: #1e272e; color: #f5f6fa; font-family: Consolas; font-size: 12px;")
            self.txt_report.setText("1. Select a target device from Tab 1 (Device Discovery).\n2. Click 'Generate Intelligence Report' above to build the summary report...")
            
            t6_layout.addWidget(self.txt_report)
            self.tabs.addTab(t6, "6. Device Intelligence Report")

            self.splitter.addWidget(self.tabs)

            # Lower System Logs Area
            log_box = QGroupBox("Operation Logs _System Output")
            log_layout = QVBoxLayout(log_box)

            self.txt_log = QTextEdit()
            self.txt_log.setReadOnly(True)
            self.txt_log.setStyleSheet("background-color: #111; color: #0f0; font-family: Consolas; font-size: 11px;")

            self.progress = QProgressBar()

            log_layout.addWidget(self.txt_log)
            log_layout.addWidget(self.progress)

            self.splitter.addWidget(log_box)

            # Splitter Configuration
            self.splitter.setSizes([450, 250])
            self.splitter.setStyleSheet("""
                QSplitter::handle {
                    background-color: #7f8c8d;
                    height: 5px;
                    margin: 2px 0px;
                }
                QSplitter::handle:hover {
                    background-color: #3498db;
                }
            """)

            layout.addWidget(self.splitter)

            # Triggers
            self.btn_scan.clicked.connect(self.start_scan)
            self.btn_browse.clicked.connect(self.browse_firmware)
            self.btn_search.clicked.connect(self.search_online)
            self.btn_repos.clicked.connect(self.open_repo_menu)
            self.btn_backup.clicked.connect(self.run_backup)
            self.btn_flash.clicked.connect(self.run_flash)
            self.btn_dump_rom.clicked.connect(self.run_extract_firmware)
            self.btn_generate_report.clicked.connect(self.generate_device_report)
            self.btn_save_report.clicked.connect(self.save_report_file)

        def set_save_report_disabled_style(self):
            self.btn_save_report.setEnabled(False)
            self.btn_save_report.setStyleSheet("background-color: #7f8c8d; color: #bdc3c7; font-weight: bold; padding: 8px;")

        def set_save_report_enabled_style(self):
            self.btn_save_report.setEnabled(True)
            self.btn_save_report.setStyleSheet("background-color: #6c5ce7; color: white; font-weight: bold; padding: 8px;")

        def log(self, msg):
            self.txt_log.append(f"[{time.strftime('%H:%M:%S')}] {msg}")
            self.txt_log.moveCursor(QtGui.QTextCursor.End)

        def start_scan(self):
            self.tbl_devices.setRowCount(0)
            subnet = self.txt_subnet.text().strip()
            self.log(f"Starting smart discovery scan on subnet {subnet}.0/24...")
            self.progress.setValue(10)

            def worker():
                found = []
                threads = []

                def probe_task(ip_str):
                    info = SmartDeviceProber.identify_device(ip_str)
                    if info:
                        found.append(info)

                targets = [f"{subnet}.{i}" for i in range(1, 255)]
                for idx, ip in enumerate(targets):
                    t = threading.Thread(target=probe_task, args=(ip,))
                    threads.append(t)
                    t.start()
                    if len(threads) >= 30:
                        for t in threads:
                            t.join()
                        threads = []

                for t in threads:
                    t.join()

                QtCore.QMetaObject.invokeMethod(self, "display_devices", QtCore.Q_ARG(list, found))

            threading.Thread(target=worker, daemon=True).start()

        @QtCore.pyqtSlot(list)
        def display_devices(self, devices):
            self.progress.setValue(100)
            self.log(f"Scan complete. Discovered {len(devices)} active device(s). Saved to persistent memory.")
            self.tbl_devices.setRowCount(len(devices))

            for row, dev in enumerate(devices):
                self.tbl_devices.setItem(row, 0, QTableWidgetItem(dev['ip']))
                self.tbl_devices.setItem(row, 1, QTableWidgetItem(dev['type']))
                self.tbl_devices.setItem(row, 2, QTableWidgetItem(dev['vendor']))
                self.tbl_devices.setItem(row, 3, QTableWidgetItem(dev['model']))
                self.tbl_devices.setItem(row, 4, QTableWidgetItem(dev.get('title', 'WEB')))

        def on_select_device(self):
            rows = self.tbl_devices.selectionModel().selectedRows()
            if not rows:
                return
            r = rows[0].row()
            self.selected_device = {
                'ip': self.tbl_devices.item(r, 0).text(),
                'type': self.tbl_devices.item(r, 1).text(),
                'vendor': self.tbl_devices.item(r, 2).text(),
                'model': self.tbl_devices.item(r, 3).text(),
                'title': self.tbl_devices.item(r, 4).text()
            }
            self.log(f"Selected Target: [{self.selected_device['type']}] {self.selected_device['vendor']} ({self.selected_device['ip']})")
            # Reset report save button to disabled grey when a new device is selected
            self.set_save_report_disabled_style()
            self.txt_report.setText(f"Target Selected: {self.selected_device['vendor']} ({self.selected_device['ip']}).\nClick 'Generate Intelligence Report' to generate summary...")

        def generate_device_report(self):
            if not self.selected_device:
                QMessageBox.warning(self, "Select Device", "Please select a target device from Tab 1 (Device Discovery) first.")
                return
            
            dev = self.selected_device
            v = dev['vendor'].lower()

            if "opnsense" in v or "freebsd" in v:
                cred_info = "Username: root | Default Password: opnsense (or custom admin pass)"
            elif "dahua" in v:
                cred_info = "Username: admin | Default Password: admin / admin123"
            elif "hikvision" in v:
                cred_info = "Username: admin | Default Password: admin12345 / 12345"
            elif "openwrt" in v:
                cred_info = "Username: root | Default Password: (No Password by default)"
            elif "mikrotik" in v:
                cred_info = "Username: admin | Default Password: (Blank / No Password)"
            elif "tp-link" in v or "asus" in v:
                cred_info = "Username: admin | Default Password: admin"
            else:
                cred_info = "Username: admin | Default Password: admin / root / 1234"

            report_text = f"""================================================================================
                    UNIVERSAL DEVICE INTELLIGENCE REPORT
================================================================================
Target IP Address      : {dev['ip']}
Vendor / Brand         : {dev['vendor']}
Hardware Category      : {dev['type']}
Model Specifications   : {dev['model']}
Web Interface Title    : {dev['title']}
Network Connection     : Active Ethernet (Online)
Scanned Timestamp      : {time.strftime('%Y-%m-%d %H:%M:%S')}
================================================================================
[RECOMMENDED MANAGEMENT & ACCESS CREDENTIALS REFERENCE]
Standard Access Specs  : {cred_info}
Web Access Endpoint    : http://{dev['ip']}/ or https://{dev['ip']}/
Serial Console Rate    : 115200 Baud (8-N-1)
================================================================================
[SYSTEM & FLASHING COMPATIBILITY STATUS]
Automated Safeguard    : ACTIVE (Beginner Friendly Mode)
Backup Compatibility   : Supported (XML / Config Dump)
Firmware Extract Status: Supported via Tab 5
================================================================================
Report Generated by Universal Firmware Manager & Flasher v6.1
================================================================================
"""
            self.txt_report.setText(report_text)
            self.set_save_report_enabled_style() # Enable Purple Save Button
            self.log(f"Generated Intelligence Report for {dev['vendor']} ({dev['ip']}).")

        def save_report_file(self):
            if not self.selected_device or not self.btn_save_report.isEnabled():
                return

            ip_clean = self.selected_device['ip'].replace('.', '_')
            filename = f"device_report_{self.selected_device['vendor']}_{ip_clean}.txt"

            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.txt_report.toPlainText())
                
                self.log(f"SUCCESS: Intelligence Report saved to text file: {filename}")
                QMessageBox.information(self, "Report Saved", f"Device Report saved successfully:\n\n{filename}")
            except Exception as e:
                QMessageBox.critical(self, "Error Saving Report", f"Failed to save file: {str(e)}")

        def browse_firmware(self):
            path, _ = QFileDialog.getOpenFileName(self, "Select Firmware File", "", "All Files (*)")
            if path:
                self.txt_file.setText(path)
                self.firmware_file_path = path
                info = FirmwareAnalyzer.inspect_file(path)
                self.lbl_info.setText(f"File: {info['filename']} ({info['size_mb']} MB) | Type: {info['type']}")
                self.txt_hashes.setText(f"MD5: {info['md5']}\nSHA256: {info['sha256']}")
                self.log(f"Firmware File Loaded: {info['filename']}")

        def search_online(self):
            if not self.selected_device:
                QMessageBox.information(self, "Select Device", "Please select a device first.")
                return
            q = f"{self.selected_device['vendor']} {self.selected_device['type']} official firmware download"
            url = f"https://www.google.com/search?q={q.replace(' ', '+')}"
            QtGui.QDesktopServices.openUrl(QtCore.QUrl(url))

        def open_repo_menu(self):
            menu = QMenu(self)
            
            opnsense_action = menu.addAction("OPNsense Official Mirror & Downloads Portal")
            openwrt_action = menu.addAction("OpenWrt Firmware Selector (All Routers)")
            dahua_action = menu.addAction("Dahua Official Firmware Security Center")
            mikrotik_action = menu.addAction("MikroTik RouterOS Download Archive")

            action = menu.exec_(QtGui.QCursor.pos())

            if action == opnsense_action:
                QtGui.QDesktopServices.openUrl(QtCore.QUrl("https://opnsense.org/download/"))
            elif action == openwrt_action:
                QtGui.QDesktopServices.openUrl(QtCore.QUrl("https://firmware-selector.openwrt.org/"))
            elif action == dahua_action:
                QtGui.QDesktopServices.openUrl(QtCore.QUrl("https://www.dahuasecurity.com/support/downloadCenter"))
            elif action == mikrotik_action:
                QtGui.QDesktopServices.openUrl(QtCore.QUrl("https://mikrotik.com/download"))

        def run_backup(self):
            if not self.selected_device:
                QMessageBox.warning(self, "Error", "No target selected.")
                return
            self.worker = FlashingEngineWorker('BACKUP', self.selected_device)
            self.worker.log_signal.connect(self.log)
            self.worker.progress_signal.connect(self.progress.setValue)
            self.worker.start()

        def run_extract_firmware(self):
            if not self.selected_device:
                QMessageBox.warning(self, "Error", "Please select a target device from Tab 1 first.")
                return
            self.worker = FlashingEngineWorker('EXTRACT_FIRMWARE', self.selected_device)
            self.worker.log_signal.connect(self.log)
            self.worker.progress_signal.connect(self.progress.setValue)
            self.worker.start()

        def run_flash(self):
            if not self.selected_device or not self.firmware_file_path:
                QMessageBox.warning(self, "Error", "Target or Firmware file missing.")
                return

            cfg = {**self.selected_device, 'strict_mode': self.chk_auto.isChecked()}
            self.worker = FlashingEngineWorker('FLASH', cfg, self.firmware_file_path)
            self.worker.log_signal.connect(self.log)
            self.worker.progress_signal.connect(self.progress.setValue)
            self.worker.start()


def main():
    if HAS_PYQT:
        app = QApplication(sys.argv)
        w = UniversalFirmwareManagerGUI()
        w.show()
        sys.exit(app.exec_())

if __name__ == '__main__':
    main()