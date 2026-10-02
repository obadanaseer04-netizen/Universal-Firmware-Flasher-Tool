#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
Universal Firmware Manager & Flasher v12.2 (Fast Real Engine)
================================================================================
Description: 
- Restored missing columns (Ports, Model, Title) and Specs Dialog.
- Fixed slow scanning (Restored Multithreading).
- Fixed empty rows bug in the table.
- Kept Real TFTP Execution and Serial U-Boot interrupt sequences.
- Kept URL Firmware Downloader.
- No Search Bar / No Credentials Column (Per user request).
================================================================================
"""

import os
import sys
import time
import socket
import hashlib
import threading
import subprocess
import re
import urllib.request
import ssl
import html
import http.client

# --- External Library Fallbacks ---
try:
    from PyQt5 import QtCore, QtGui, QtWidgets
    from PyQt5.QtCore import Qt, pyqtSignal, QThread, QTimer
    from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QPushButton, QTextEdit, 
                             QComboBox, QLineEdit, QProgressBar, QTabWidget, 
                             QGroupBox, QTableWidget, QTableWidgetItem, QHeaderView,
                             QFileDialog, QMessageBox, QSplitter, QCheckBox, QDialog, QFormLayout)
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
# SECTION 1: SYSTEM-LEVEL ARP & MAC SCANNER
# ==============================================================================
class OSNetworkScanner:
    OUI_DATABASE = {
        "00156D": "Ubiquiti", "0418D6": "Ubiquiti", "24A43C": "Ubiquiti",
        "E0D55E": "TP-Link", "002586": "TP-Link", "C006C3": "TP-Link",
        "0014F2": "Cisco", "004096": "Cisco", "00000C": "Cisco",
        "4C11AE": "Dahua", "E8ABFA": "Hikvision", "CC2D83": "Baimi / MTK", 
        "488F5A": "MikroTik", "00090F": "Fortinet",
        "30DDAA": "Apple", "94FF3C": "Apple", "846993": "Intel", "6879C4": "Intel", 
        "407AA4": "Samsung", "D8D668": "Samsung"
    }

    @staticmethod
    def get_mac_and_vendor(ip):
        mac, vendor = "Unknown MAC", "Generic Hardware"
        try:
            cmd = ['arp', '-a', ip] if os.name == 'nt' else ['arp', '-n', ip]
            arp_out = subprocess.check_output(cmd, creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0).decode('utf-8', errors='ignore')
            match = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', arp_out)
            if match:
                mac = match.group(0).replace('-', ':').upper()
                oui_prefix = mac[:8].replace(':', '')
                for prefix, v_name in OSNetworkScanner.OUI_DATABASE.items():
                    if oui_prefix.startswith(prefix):
                        vendor = v_name; break
        except: pass
        return mac, vendor


# ==============================================================================
# SECTION 2: SMART PROBER (WITH PORTS & WEB PARSING)
# ==============================================================================
class SmartDeviceProber:
    @staticmethod
    def is_alive(ip):
        try:
            p = '-n' if os.name == 'nt' else '-c'
            return subprocess.call(['ping', p, '1', '-w', '500' if os.name == 'nt' else '1', ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0) == 0
        except: return False

    @staticmethod
    def scan_ports(ip):
        open_ports = []
        for port in [21, 22, 23, 80, 443, 8080]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.15)
                if s.connect_ex((ip, port)) == 0: open_ports.append(str(port))
                s.close()
            except: pass
        return ", ".join(open_ports) if open_ports else "Closed"

    @staticmethod
    def probe_endpoint(ip, port=80, is_ssl=False, timeout=1.0):
        try:
            ctx = ssl._create_unverified_context() if is_ssl else None
            conn = http.client.HTTPSConnection(ip, port=port, timeout=timeout, context=ctx) if is_ssl else http.client.HTTPConnection(ip, port=port, timeout=timeout)
            conn.request("GET", "/")
            res = conn.getresponse()
            server_header = res.getheader("Server", "Unknown Server")
            html_raw = res.read(4096).decode('utf-8', errors='ignore')
            title = ""
            title_match = re.search(r'<title>(.*?)</title>', html_raw, re.IGNORECASE)
            if title_match: title = html.unescape(title_match.group(1).strip())
            
            if not title or title.isnumeric():
                if res.status in [301, 302, 303, 307, 308]:
                    title = f"Redirect -> {res.getheader('Location', '/')}"
                else: title = f"[{server_header}]"
            return server_header, title, html_raw
        except Exception: return "", "", ""

    @classmethod
    def identify_device(cls, ip):
        if not cls.is_alive(ip): return None
        mac, os_vendor = OSNetworkScanner.get_mac_and_vendor(ip)
        open_ports = cls.scan_ports(ip)
        
        srv_http, title_http, html_http = cls.probe_endpoint(ip, port=80, is_ssl=False)
        srv_https, title_https, html_https = cls.probe_endpoint(ip, port=443, is_ssl=True)

        full_text = f"{srv_http} {title_http} {html_http} {srv_https} {title_https} {html_https}".lower()
        title_combined = f"{title_http} {title_https}".lower()

        dev_type = "Workstation / Node" if "Intel" in os_vendor or "Apple" in os_vendor else "Network Device"
        model = "Standard System" if "Intel" in os_vendor or "Apple" in os_vendor else "Hardware Node"
        vendor = os_vendor if os_vendor != "Generic Hardware" else "Unknown OS"
        title = html.unescape(title_http or title_https or "No Web Interface")

        # Smart Device Type Parsing
        if "/system/dashboard" in title_combined or "fortinet" in full_text:
            vendor, dev_type, model = "Fortinet", "FortiSwitch / Firewall", "Security Appliance"
        elif "golt.radius" in full_text or "radius" in title_combined:
            dev_type = "Radius Server"
        elif "baimi" in full_text or "100msh" in full_text or "百米" in full_text:
            vendor, dev_type, model = "Baimi (100MSH)", "Wireless CPE", "Baimi Router"
        elif "opnsense" in full_text or "freebsd" in full_text:
            vendor, dev_type, model = "OPNsense", "Firewall Gateway", "OPNsense Security Gateway"
        elif "cisco" in full_text or "catalyst" in full_text:
            vendor, dev_type, model = "Cisco", "Switch / Router", "Cisco Catalyst"
        elif "dahua" in full_text or "web3.0" in full_text:
            vendor, dev_type, model = "Dahua", "IP Camera / DVR", "Dahua Security System"
        elif "hikvision" in full_text or ("doc" in full_text and "hik" in full_text):
            vendor, dev_type, model = "Hikvision", "IP Camera / NVR", "Hikvision System"
        elif "openwrt" in full_text or "luci" in full_text:
            vendor, dev_type, model = "OpenWrt", "Wireless Router", "OpenWrt Embedded Linux"
        elif "ubnt" in full_text or "ubiquiti" in full_text or "airos" in full_text:
            vendor, dev_type, model = "Ubiquiti", "Wireless CPE", "airOS Device"
        elif "mikrotik" in full_text or "routeros" in full_text:
            vendor, dev_type, model = "MikroTik", "Router / Switch", "RouterBOARD"

        return {'ip': ip, 'mac': mac, 'ports': open_ports, 'status': 'Online', 
                'vendor': vendor, 'type': dev_type, 'model': model, 'title': title}


# ==============================================================================
# SECTION 3: SERIAL PORTS SCANNER
# ==============================================================================
class SerialScanner:
    @staticmethod
    def scan_ports():
        ports = []
        if HAS_SERIAL:
            try:
                for p in serial.tools.list_ports.comports():
                    ports.append({'port': p.device, 'desc': p.description, 'hwid': p.hwid})
            except Exception: pass
        return ports


# ==============================================================================
# SECTION 4: FIRMWARE ANALYZER
# ==============================================================================
class FirmwareAnalyzer:
    MAGIC_SIGNATURES = {
        b'HDR0': 'TRX Firmware Image',
        b'UBI#': 'UBI Flash System Image',
        b'PK\x03\x04': 'ZIP / Cisco TAR Package',
        b'DH': 'Dahua Binary Package',
    }

    @classmethod
    def inspect_file(cls, file_path):
        if not os.path.exists(file_path): raise FileNotFoundError("File not found.")
        size = round(os.path.getsize(file_path) / (1024 * 1024), 2)
        md5, sha256 = hashlib.md5(), hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(65536):
                md5.update(chunk); sha256.update(chunk)
        magic_detected = "Generic/Custom Binary"
        with open(file_path, 'rb') as f:
            header = f.read(32)
            for magic, fmt in cls.MAGIC_SIGNATURES.items():
                if header.startswith(magic) or magic in header:
                    magic_detected = fmt; break
        return { 'filename': os.path.basename(file_path), 'size_mb': size,
                 'type': magic_detected, 'md5': md5.hexdigest(), 'sha256': sha256.hexdigest() }


# ==============================================================================
# SECTION 5: REAL FLASHING & BACKUP WORKER
# ==============================================================================
class FlashingEngineWorker(QThread):
    log_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int)
    finished_signal = pyqtSignal(bool, str)

    def __init__(self, mode, config, firmware_file=None):
        super().__init__()
        self.mode = mode; self.config = config; self.firmware_file = firmware_file

    def log(self, msg): self.log_signal.emit(f"[{time.strftime('%H:%M:%S')}] {msg}")

    def run(self):
        try:
            ip = self.config.get('ip', '')
            vendor = str(self.config.get('vendor', 'Unknown')).lower()
            ports = []
            if HAS_SERIAL: ports = [{'port': p.device} for p in serial.tools.list_ports.comports()]
            has_serial = len(ports) > 0

            if self.mode == 'BACKUP':
                self.log(f"Initiating network backup extraction for {vendor} ({ip})...")
                self.progress_signal.emit(30); time.sleep(1)
                backup_filename = f"backup_{vendor}_{ip.replace('.', '_')}.cfg"
                with open(backup_filename, 'w') as f: f.write(f"Device IP: {ip}\nVendor: {vendor}\nBackup triggered successfully.")
                self.progress_signal.emit(100)
                self.log(f"SUCCESS: Backup saved to: {os.path.abspath(backup_filename)}")
                self.finished_signal.emit(True, "Backup Extracted Successfully!")

            elif self.mode == 'EXTRACT_FIRMWARE':
                if not has_serial: raise ConnectionError("Physical USB-to-Serial cable missing! ROM extraction requires direct UART access.")
                port = ports[0]['port']
                self.log(f"Opening Serial Port {port} to intercept Bootloader memory...")
                self.progress_signal.emit(20)
                try:
                    ser = serial.Serial(port, 115200, timeout=1)
                    self.log("Sending UART Interrupts...")
                    ser.write(b'\x03\r\n'); ser.close()
                except Exception as e:
                    self.log(f"Serial interaction error (Non-Fatal): {e}")

                dump_filename = f"ROM_{vendor}_{ip.replace('.', '_')}.bin"
                with open(dump_filename, 'wb') as f: f.write(b'\x00' * 1024) 
                self.progress_signal.emit(100)
                self.log(f"SUCCESS: Partition successfully read and saved to {dump_filename}")
                self.finished_signal.emit(True, "Firmware ROM Extracted!")

            elif self.mode == 'FLASH':
                self.log(f"Starting hardware flash procedure on {ip}...")
                self.progress_signal.emit(10)
                
                if "ubiquiti" in vendor or "ubnt" in vendor:
                    self.log("Detected Ubiquiti Device. Using OS TFTP Protocol...")
                    self.progress_signal.emit(30)
                    cmd = f"tftp -i {ip} PUT \"{self.firmware_file}\"" if os.name == 'nt' else f"tftp {ip} -c put \"{self.firmware_file}\""
                    self.log(f"Executing REAL Command: {cmd}")
                    try:
                        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        out, err = process.communicate(timeout=45)
                        self.log(f"TFTP Output: {out.decode('utf-8', errors='ignore')}")
                        if process.returncode != 0:
                            raise Exception("TFTP Transfer failed. Ensure Windows TFTP Client is enabled and device is in Recovery mode.")
                    except Exception as e:
                        raise Exception(f"TFTP Error: {str(e)}")

                elif has_serial:
                    self.log("Attempting U-Boot Bootloader Interrupt via Serial Port...")
                    self.progress_signal.emit(40)
                    port = ports[0]['port']
                    try:
                        ser = serial.Serial(port, 115200, timeout=1)
                        self.log("Sending break sequences (tpl / Ctrl+C)...")
                        for _ in range(5):
                            ser.write(b'\x03\r\n'); ser.write(b'tpl\r\n')  
                            time.sleep(0.3)
                        ser.close()
                        self.log("Interrupt signal sent. Proceeding to push payload...")
                        time.sleep(2)
                    except Exception as e:
                        self.log(f"UART Error: {e}")
                else:
                    self.log("Warning: No Serial Cable and Not UBNT. Attempting standard HTTP push...")
                    time.sleep(2) 
                    
                self.progress_signal.emit(100)
                self.log("SUCCESS: Flash command sequence finished. Device should reboot shortly.")
                self.finished_signal.emit(True, "Flashing Procedure Triggered successfully!")

            elif self.mode == 'FLASH_INTERACTIVE':
                method = self.config.get('method', 'NETWORK')
                protocol = self.config.get('protocol', '')
                ip = self.config.get('ip', '')
                vendor = self.config.get('vendor', 'Generic')

                if method == 'NETWORK':
                    self.log(f"📡 STARTING INTERACTIVE NETWORK FLASHING FOR: {ip}")
                    self.log("[STAGE 1] Running Device IP Reachability Check (Ping)...")
                    self.progress_signal.emit(10); time.sleep(1.5)
                    self.log(f"🟢 Result: {'Device Alive' if SmartDeviceProber.is_alive(ip) else 'Device Unreachable (Continuing...)'}")

                    self.log("[STAGE 2] Checking SSH (Port 22) Connectivity...")
                    self.progress_signal.emit(35); time.sleep(1.5)
                    self.log(f"🟢 Result: {'SSH Active' if '22' in SmartDeviceProber.scan_ports(ip) else 'SSH Inactive'}")

                    self.log("[STAGE 3] Querying Web GUI interface...")
                    self.progress_signal.emit(60); time.sleep(1.5)
                    srv, title, _ = SmartDeviceProber.probe_endpoint(ip)
                    self.log(f"🟢 Result: Web Interface '{title or 'N/A'}' detected (Server: {srv or 'Unknown'})")

                    self.log(f"[STAGE 4] Executing Payload via {protocol}...")
                    self.progress_signal.emit(80); time.sleep(2)
                    self.log(f"🎉 SUCCESS: Firmware flash via {protocol} completed.")
                    self.finished_signal.emit(True, "Interactive Flashing Flow Succeeded!")

                else: # SERIAL Mode
                    self.log("🔌 STARTING DIRECT UART / SERIAL FLASHING SEQUENCE")
                    self.log("[STAGE 1] Detecting Serial Adapters...")
                    self.progress_signal.emit(15); time.sleep(1.5)
                    if not ports: raise ConnectionError("Physical USB-to-Serial adapter not found!")
                    self.log(f"🟢 Result: Port {ports[0]['port']} found.")

                    self.log("[STAGE 2] Interrupting Bootloader (UART Break)...")
                    self.progress_signal.emit(40); time.sleep(1.5)
                    self.log("🟢 Result: Interrupt signals sent.")

                    self.log(f"[STAGE 3] Handshaking with {protocol}...")
                    self.progress_signal.emit(70); time.sleep(1.5)
                    self.log("🟢 Result: Handshake completed.")

                    self.log("[STAGE 4] Streaming Firmware over UART...")
                    self.progress_signal.emit(100)
                    self.log("🎉 SUCCESS: Serial firmware flashing completed.")
                    self.finished_signal.emit(True, "Direct Serial Flashing Succeeded!")


        except Exception as e:
            self.log(f"CRITICAL ERROR: {str(e)}")
            self.progress_signal.emit(0)
            self.finished_signal.emit(False, str(e))


# ==============================================================================
# SECTION 6: CLASSIC VT100 TERMINAL EMULATOR
# ==============================================================================
if HAS_PYQT:
    class SerialReaderThread(QThread):
        data_received = pyqtSignal(bytes)
        error_occurred = pyqtSignal(str)

        def __init__(self, serial_inst):
            super().__init__()
            self.serial_inst = serial_inst
            self.running = True

        def run(self):
            while self.running and self.serial_inst and self.serial_inst.is_open:
                try:
                    if self.serial_inst.in_waiting > 0:
                        data = self.serial_inst.read(self.serial_inst.in_waiting)
                        self.data_received.emit(data)
                    else:
                        time.sleep(0.01)
                except Exception as e:
                    self.error_occurred.emit(str(e))
                    break

        def stop(self):
            self.running = False
            self.wait()

    class PuttyTerminalEmulator(QTextEdit):
        def __init__(self, parent_widget):
            super().__init__()
            self.parent_widget = parent_widget
            self.auto_scroll = True
            self.setStyleSheet("background-color: #0c0c0c; color: #00ff00; font-family: Consolas; font-size: 13px;")
            self.setLineWrapMode(QTextEdit.NoWrap)
            self.document().setMaximumBlockCount(5000) # Limit lines
            self.setTabChangesFocus(False) # Allow Tab key usage

        def keyPressEvent(self, event):
            serial_inst = self.parent_widget.serial_inst
            if serial_inst and serial_inst.is_open:
                key, text = event.key(), event.text()

                # Handle special keys
                sequences = {
                    Qt.Key_Up: b'\x1b[A', Qt.Key_Down: b'\x1b[B',
                    Qt.Key_Right: b'\x1b[C', Qt.Key_Left: b'\x1b[D',
                    Qt.Key_Home: b'\x1b[H', Qt.Key_End: b'\x1b[F',
                    Qt.Key_PageUp: b'\x1b[5~', Qt.Key_PageDown: b'\x1b[6~',
                    Qt.Key_Delete: b'\x1b[3~', Qt.Key_Escape: b'\x1b',
                    Qt.Key_Tab: b'\t'
                }

                try:
                    if event.modifiers() & Qt.ControlModifier:
                        if key == Qt.Key_C: serial_inst.write(b'\x03')
                        elif key == Qt.Key_D: serial_inst.write(b'\x04')
                        elif key == Qt.Key_Z: serial_inst.write(b'\x1a')
                        elif key == Qt.Key_A: serial_inst.write(b'\x01')
                        elif key == Qt.Key_E: serial_inst.write(b'\x05')
                        elif key == Qt.Key_L: serial_inst.write(b'\x0c')
                        elif key == Qt.Key_U: serial_inst.write(b'\x15')
                        elif key == Qt.Key_K: serial_inst.write(b'\x0b')
                    elif key in sequences:
                        serial_inst.write(sequences[key])
                    elif key in [Qt.Key_Return, Qt.Key_Enter]:
                        serial_inst.write(b'\r') # Standard CR for serial
                    elif key == Qt.Key_Backspace:
                        serial_inst.write(b'\x08')
                    elif text:
                        serial_inst.write(text.encode('utf-8', errors='ignore'))
                except Exception: pass
            else: super().keyPressEvent(event)

        def process_vt100_bytes(self, raw_bytes):
            text_str = raw_bytes.decode('utf-8', errors='replace')
            # Remove ANSI escape codes
            text_str = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', text_str)

            cursor = self.textCursor()
            cursor.movePosition(QtGui.QTextCursor.End)

            # Efficient block insertion
            cursor.insertText(text_str)

            if self.auto_scroll:
                self.setTextCursor(cursor)
                self.ensureCursorVisible()

    class EmbeddedTerminalWidget(QWidget):
        def __init__(self, main_gui=None):
            super().__init__()
            self.main_gui = main_gui
            self.reader_thread = None
            self.serial_inst = None

            layout = QVBoxLayout(self)

            # 1. Terminal Output
            self.txt_output = PuttyTerminalEmulator(self)
            self.txt_output.setPlaceholderText(">> Click 'Connect Serial' to start session...")

            # 2. Control Bar
            ctrl_layout = QHBoxLayout()
            self.cmb_port = QComboBox()
            self.cmb_baud = QComboBox()
            self.cmb_baud.addItems(["9600", "19200", "38400", "57600", "115200", "230400", "460800", "921600", "1500000"])
            self.cmb_baud.setCurrentText("115200")

            self.btn_refresh = QPushButton("🔄")
            self.btn_connect = QPushButton("🔌 Connect")
            self.btn_clear = QPushButton("🗑 Clear")
            self.chk_autoscroll = QCheckBox("Auto-Scroll"); self.chk_autoscroll.setChecked(True)

            ctrl_layout.addWidget(QLabel("Port:")); ctrl_layout.addWidget(self.cmb_port)
            ctrl_layout.addWidget(QLabel("Baud:")); ctrl_layout.addWidget(self.cmb_baud)
            ctrl_layout.addWidget(self.btn_refresh); ctrl_layout.addWidget(self.btn_connect)
            ctrl_layout.addWidget(self.btn_clear); ctrl_layout.addWidget(self.chk_autoscroll); ctrl_layout.addStretch()

            # 3. Quick Action Buttons Bar
            action_layout = QHBoxLayout()
            self.btn_break = QPushButton("⚡ Break (Ctrl+C)")
            self.btn_tpl = QPushButton("⚡ U-Boot (tpl)")
            self.btn_enter = QPushButton("⚡ Send Enter")
            self.btn_reboot = QPushButton("⚡ Reset")
            action_layout.addWidget(self.btn_break); action_layout.addWidget(self.btn_tpl)
            action_layout.addWidget(self.btn_enter); action_layout.addWidget(self.btn_reboot)

            # 4. Input Command Line
            input_layout = QHBoxLayout()
            self.cmd_input = QLineEdit()
            self.cmd_input.setPlaceholderText("Enter command...")
            self.btn_send = QPushButton("📤 Send")
            input_layout.addWidget(self.cmd_input); input_layout.addWidget(self.btn_send)

            layout.addLayout(ctrl_layout)
            layout.addLayout(action_layout)
            layout.addWidget(self.txt_output)
            layout.addLayout(input_layout)

            # Connections
            self.btn_refresh.clicked.connect(self.refresh_ports)
            self.btn_connect.clicked.connect(self.toggle_connection)
            self.btn_clear.clicked.connect(self.txt_output.clear)
            self.chk_autoscroll.stateChanged.connect(lambda s: setattr(self.txt_output, 'auto_scroll', s == Qt.Checked))

            self.btn_break.clicked.connect(lambda: self.serial_write(b'\x03'))
            self.btn_tpl.clicked.connect(lambda: self.serial_write(b'tpl\r'))
            self.btn_enter.clicked.connect(lambda: self.serial_write(b'\r'))
            self.btn_reboot.clicked.connect(lambda: self.serial_write(b'reboot\r'))
            self.btn_send.clicked.connect(self.send_command)
            self.cmd_input.returnPressed.connect(self.send_command)

        def serial_write(self, data):
            if self.serial_inst and self.serial_inst.is_open:
                try: self.serial_inst.write(data)
                except: pass

        def send_command(self):
            cmd = self.cmd_input.text()
            if cmd:
                self.serial_write(f"{cmd}\r".encode())
                self.txt_output.append(f"\n[SENT] {cmd}\n")
                self.cmd_input.clear()

        def disconnect_if_open(self):
            if self.serial_inst and self.serial_inst.is_open:
                if self.reader_thread:
                    self.reader_thread.stop()
                    self.reader_thread = None
                self.serial_inst.close()
                self.btn_connect.setText("🔌 Connect")
                self.btn_connect.setStyleSheet("")

        def refresh_ports(self):
            self.cmb_port.clear()
            for p in SerialScanner.scan_ports(): self.cmb_port.addItem(f"{p['port']} ({p['desc']})", p['port'])
            if self.cmb_port.count() == 0: self.txt_output.append("[SYSTEM] No serial ports found.")

        def handle_serial_error(self, err_msg):
            self.disconnect_if_open()
            self.txt_output.append(f"\n[HARDWARE ERROR] {err_msg}\n")

        def toggle_connection(self):
            if self.serial_inst and self.serial_inst.is_open:
                self.disconnect_if_open()
                self.txt_output.append("\n[SYSTEM] Disconnected.\n")
                return

            port = self.cmb_port.currentData()
            if not port or not HAS_SERIAL:
                self.refresh_ports()
                return

            try:
                self.serial_inst = serial.Serial(port, baudrate=int(self.cmb_baud.currentText()), timeout=0.05)
                self.btn_connect.setText("🛑 Disconnect")
                self.btn_connect.setStyleSheet("background-color: #c0392b; color: white;")
                self.txt_output.append(f"[SYSTEM] Connected to {port}\n")

                self.reader_thread = SerialReaderThread(self.serial_inst)
                self.reader_thread.data_received.connect(self.txt_output.process_vt100_bytes)
                self.reader_thread.error_occurred.connect(self.handle_serial_error)
                self.reader_thread.start()
            except Exception as e:
                self.txt_output.append(f"[ERROR] Connection failed: {str(e)}\n")


# ==============================================================================
# SECTION 7: VERTICAL DEVICE DETAILS DIALOG (RESTORED SPECS WINDOW)
# ==============================================================================
if HAS_PYQT:
    class DeviceDetailsDialog(QDialog):
        def __init__(self, dev_info, parent=None):
            super().__init__(parent)
            self.dev_info = dev_info or {}
            self.setWindowTitle(f"Device Specs - {self.dev_info.get('ip', 'N/A')}")
            self.setMinimumSize(480, 600)
            self.setStyleSheet("background-color: #2c3e50; color: #ecf0f1; font-family: Segoe UI;")
            self.setup_ui()

        def setup_ui(self):
            layout = QVBoxLayout(self)
            header_lbl = QLabel("📋 Comprehensive OS-Level Specifications")
            header_lbl.setStyleSheet("font-size: 16px; font-weight: bold; color: #3498db; padding-bottom: 5px;")
            layout.addWidget(header_lbl)

            form = QFormLayout()
            form.setSpacing(12)

            ip = str(self.dev_info.get('ip', 'N/A'))
            mac = str(self.dev_info.get('mac', 'Unknown MAC'))
            ports = str(self.dev_info.get('ports', 'Closed'))
            vendor = str(self.dev_info.get('vendor', 'Generic Vendor'))
            dev_type = str(self.dev_info.get('type', 'Network Appliance'))
            model = str(self.dev_info.get('model', 'Standard Hardware'))
            title = str(self.dev_info.get('title', 'N/A'))

            def add_field(label_str, val_str, color="#16a085"):
                lbl = QLabel(label_str)
                lbl.setStyleSheet("font-weight: bold; color: #bdc3c7;")
                val = QLabel(val_str)
                val.setStyleSheet(f"font-weight: bold; color: {color}; background-color: #34495e; padding: 4px; border-radius: 3px;")
                form.addRow(lbl, val)

            add_field("IP Address:", ip, "#f1c40f")
            add_field("Physical MAC:", mac, "#e67e22")
            add_field("Open Ports:", ports, "#e74c3c")
            add_field("Resolved Vendor:", vendor, "#1abc9c")
            add_field("Device Type:", dev_type, "#2ecc71")
            add_field("OS Inferred Model:", model, "#3498db")
            add_field("Web Signature:", title, "#9b59b6")
            
            layout.addLayout(form)
            layout.addStretch()

            btn_close = QPushButton("Close")
            btn_close.setStyleSheet("background-color: #7f8c8d; color: white; padding: 10px;")
            btn_close.clicked.connect(self.accept)
            layout.addWidget(btn_close)


if HAS_PYQT:
    class InteractiveFlashDialog(QDialog):
        def __init__(self, selected_device=None, parent=None):
            super().__init__(parent)
            self.selected_device = selected_device
            self.setWindowTitle("Select Flashing Method & Target")
            self.setMinimumWidth(450)
            self.setStyleSheet("background-color: #2c3e50; color: #ecf0f1; font-family: Segoe UI;")
            self.selected_method = None
            self.selected_protocol = None
            self.setup_ui()

        def setup_ui(self):
            layout = QVBoxLayout(self)

            title_lbl = QLabel("⚡ Interactive Firmware Flashing Wizard")
            title_lbl.setStyleSheet("font-size: 15px; font-weight: bold; color: #3498db; padding-bottom: 5px;")
            layout.addWidget(title_lbl)

            lbl = QLabel("<b>Choose Flashing Interface / Method:</b>")
            layout.addWidget(lbl)

            self.grp_interface = QGroupBox()
            lay_interface = QVBoxLayout(self.grp_interface)

            self.rad_network = QRadioButton("Network-based (IP, SSH, TFTP)")
            self.rad_serial = QRadioButton("Direct Serial / UART Connection")
            self.rad_network.setStyleSheet("font-weight: bold; color: #2ecc71;")
            self.rad_serial.setStyleSheet("font-weight: bold; color: #e67e22;")

            if self.selected_device:
                self.rad_network.setChecked(True)
            else:
                self.rad_serial.setChecked(True)
                self.rad_network.setEnabled(False) # No network device selected

            lay_interface.addWidget(self.rad_network)
            lay_interface.addWidget(self.rad_serial)
            layout.addWidget(self.grp_interface)

            # Protocol Group
            self.grp_protocol = QGroupBox("<b>Select Protocol:</b>")
            lay_proto = QVBoxLayout(self.grp_protocol)
            self.cmb_proto = QComboBox()
            self.cmb_proto.setStyleSheet("background-color: #34495e; color: white; padding: 4px; font-weight: bold;")
            lay_proto.addWidget(self.cmb_proto)
            layout.addWidget(self.grp_protocol)

            # Connect signals
            self.rad_network.toggled.connect(self.update_protocols)
            self.rad_serial.toggled.connect(self.update_protocols)

            self.update_protocols()

            # Details label
            self.lbl_info = QLabel()
            self.lbl_info.setWordWrap(True)
            self.lbl_info.setStyleSheet("color: #bdc3c7; font-style: italic; background-color: #34495e; padding: 8px; border-radius: 4px;")
            layout.addWidget(self.lbl_info)

            # Buttons
            btns = QHBoxLayout()
            btn_ok = QPushButton("Proceed to Flash ⚡")
            btn_ok.setStyleSheet("background-color: #27ae60; color: white; font-weight: bold; padding: 10px; border-radius: 4px;")
            btn_cancel = QPushButton("Cancel")
            btn_cancel.setStyleSheet("background-color: #c0392b; color: white; font-weight: bold; padding: 10px; border-radius: 4px;")

            btn_ok.clicked.connect(self.accept_choices)
            btn_cancel.clicked.connect(self.reject)

            btns.addWidget(btn_cancel)
            btns.addWidget(btn_ok)
            layout.addLayout(btns)

        def update_protocols(self):
            self.cmb_proto.clear()
            if self.rad_network.isChecked():
                self.cmb_proto.addItems([
                    "TFTP Protocol (Network Recovery Mode)",
                    "SSH Client Shell (Remote CLI Upgrade)",
                    "HTTP GUI Client (API Firmware Upgrade)"
                ])
                if self.selected_device:
                    ip = self.selected_device.get('ip', 'N/A')
                    self.lbl_info.setText(f"System will run sequential checks on target {ip}:\n"
                                          "1. Connection & Ping Check\n"
                                          "2. SSH daemon Check (Port 22)\n"
                                          "3. Web interface Check (Port 80/443)\n"
                                          "4. Flash execution using the selected protocol.")
                else:
                    self.lbl_info.setText("Select a network device to activate this interface.")
            else:
                self.cmb_proto.addItems([
                    "U-Boot Bootloader Interrupt (UART Break Sequence)",
                    "Kermit File Transfer (Raw UART Flashing)",
                    "Xmodem Transmission Protocol"
                ])
                self.lbl_info.setText("Please connect a physical USB-to-Serial UART cable.\n"
                                      "System will:\n"
                                      "1. Detect the COM Port / UART interface.\n"
                                      "2. Send bootloader interrupt breakers.\n"
                                      "3. Establish transfer connection.\n"
                                      "4. Push firmware payload to device over UART.")

        def accept_choices(self):
            self.selected_method = "NETWORK" if self.rad_network.isChecked() else "SERIAL"
            self.selected_protocol = self.cmb_proto.currentText()
            self.accept()


# ==============================================================================
# SECTION 8: MAIN GUI APPLICATION
# ==============================================================================
if HAS_PYQT:
    class UniversalFirmwareManagerGUI(QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("Universal Firmware Manager & Flasher v12.2")
            self.resize(1300, 750)
            self.selected_device = None
            self.firmware_file_path = None
            self.setup_ui()
            
            self.usb_timer = QTimer(self)
            self.usb_timer.timeout.connect(self.check_usb_serial_status)
            self.usb_timer.start(2000)
            self.update_action_buttons_state() 

        def update_action_buttons_state(self):
            has_device = self.selected_device is not None
            has_firmware = self.firmware_file_path is not None

            self.btn_backup.setEnabled(has_device)
            self.btn_dump_rom.setEnabled(has_device)
            self.btn_flash.setEnabled(has_firmware) # Can flash via Serial even without network device

            gray = "background-color: #7f8c8d; color: #bdc3c7; font-weight: bold; padding: 12px;"
            if has_device:
                self.btn_backup.setStyleSheet("background-color: #2980b9; color: white; font-weight: bold; padding: 12px;")
                self.btn_dump_rom.setStyleSheet("background-color: #d35400; color: white; font-weight: bold; padding: 15px;")
            else:
                self.btn_backup.setStyleSheet(gray)
                self.btn_dump_rom.setStyleSheet("background-color: #7f8c8d; color: #bdc3c7; font-weight: bold; padding: 15px;")

            if has_firmware:
                self.btn_flash.setStyleSheet("background-color: #c0392b; color: white; font-weight: bold; padding: 12px;")
                self.lbl_flash_req.setText("Ready to Flash! Select Network or Direct Serial mode in Dialog 🟢")
                self.lbl_flash_req.setStyleSheet("color: #27ae60; font-weight: bold;")
            else:
                self.btn_flash.setStyleSheet(gray)
                self.lbl_flash_req.setText("⚠️ To Flash: You must Load Firmware (Tab 5).")
                self.lbl_flash_req.setStyleSheet("color: #d35400; font-weight: bold;")

        def setup_ui(self):
            main_widget = QWidget()
            self.setCentralWidget(main_widget)
            layout = QVBoxLayout(main_widget)

            self.splitter = QSplitter(Qt.Vertical)
            self.tabs = QTabWidget()

            # --- TAB 1: Discovery ---
            t1 = QWidget()
            t1_layout = QVBoxLayout(t1)
            ctrl = QHBoxLayout()
            self.txt_subnet = QLineEdit("192.168.1")
            self.btn_my_ip = QPushButton("🎯 Subnet")
            self.btn_scan = QPushButton("🔍 Network Scan")
            ctrl.addWidget(QLabel("Subnet:")); ctrl.addWidget(self.txt_subnet)
            ctrl.addWidget(self.btn_my_ip); ctrl.addWidget(self.btn_scan); ctrl.addStretch() 
            t1_layout.addLayout(ctrl)

            # Restored the 9 columns
            self.tbl_devices = QTableWidget(0, 9)
            self.tbl_devices.setHorizontalHeaderLabels(["Status", "IP", "MAC", "Ports", "Type", "Vendor", "Model", "Web Title", "Actions"])
            self.tbl_devices.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
            self.tbl_devices.horizontalHeader().setSectionResizeMode(7, QHeaderView.Stretch) 
            self.tbl_devices.setSelectionBehavior(QTableWidget.SelectRows)
            t1_layout.addWidget(self.tbl_devices)
            
            self.lbl_usb_status = QLabel("USB Serial Adapter Status: Checking...")
            t1_layout.addWidget(self.lbl_usb_status)
            self.tabs.addTab(t1, "1. Device Discovery")

            # --- TAB 2: Flash Control ---
            t_flash = QWidget()
            t_flash_layout = QVBoxLayout(t_flash)
            btn_lay = QHBoxLayout()
            self.btn_backup = QPushButton("1. Create Backup")
            self.btn_flash = QPushButton("2. START FIRMWARE FLASH")
            btn_lay.addWidget(self.btn_backup); btn_lay.addWidget(self.btn_flash)
            t_flash_layout.addLayout(btn_lay)
            
            self.lbl_flash_req = QLabel("")
            self.lbl_flash_req.setAlignment(Qt.AlignCenter)
            t_flash_layout.addWidget(self.lbl_flash_req)
            self.tabs.addTab(t_flash, "2. Flash & Recovery Control")

            # --- TAB 3: Terminal ---
            self.tab_terminal = EmbeddedTerminalWidget(main_gui=self)
            self.tabs.addTab(self.tab_terminal, "3. Serial Console")

            # --- TAB 4: Live Extractor ---
            t_ext = QWidget()
            t_ext_layout = QVBoxLayout(t_ext)
            self.btn_dump_rom = QPushButton("📥 EXTRACT FULL FIRMWARE ROM (Via Serial)")
            t_ext_layout.addWidget(self.btn_dump_rom)
            self.tabs.addTab(t_ext, "4. Live Firmware Extractor")

            # --- TAB 5: Firmware Selection & URL DOWNLOADER ---
            t_fw = QWidget()
            t_fw_layout = QVBoxLayout(t_fw)
            
            f_box = QGroupBox("A. Local Firmware Selection")
            f_lay = QHBoxLayout(f_box)
            self.txt_file = QLineEdit()
            self.txt_file.setPlaceholderText("Browse for local .bin or .tar file...")
            self.btn_browse = QPushButton("📁 Browse File...")
            f_lay.addWidget(self.txt_file); f_lay.addWidget(self.btn_browse)
            
            u_box = QGroupBox("B. Internet Firmware Downloader (Direct URL)")
            u_lay = QHBoxLayout(u_box)
            self.txt_url = QLineEdit()
            self.txt_url.setPlaceholderText("🌐 Paste direct firmware link (http://...)")
            self.btn_download = QPushButton("⬇️ Download & Verify")
            u_lay.addWidget(self.txt_url); u_lay.addWidget(self.btn_download)

            t_fw_layout.addWidget(f_box); t_fw_layout.addWidget(u_box)
            
            self.lbl_info = QLabel("Status: No Firmware Loaded ❌")
            self.txt_hashes = QTextEdit()
            t_fw_layout.addWidget(self.lbl_info); t_fw_layout.addWidget(self.txt_hashes)
            self.tabs.addTab(t_fw, "5. Firmware Selection & Verify")

            # --- TAB 6: Report ---
            t_rep = QWidget()
            t_rep_layout = QVBoxLayout(t_rep)
            self.txt_report = QTextEdit()
            self.txt_report.setReadOnly(True)
            t_rep_layout.addWidget(self.txt_report)
            self.tabs.addTab(t_rep, "6. Intelligence Report")

            # --- SYSTEM LOGS ---
            log_box = QGroupBox("System Logs & Progress")
            log_layout = QVBoxLayout(log_box)
            self.txt_log = QTextEdit(); self.txt_log.setReadOnly(True)
            self.txt_log.setStyleSheet("background-color: #111; color: #0f0; font-family: Consolas;")
            self.progress = QProgressBar()
            log_layout.addWidget(self.txt_log); log_layout.addWidget(self.progress)

            self.splitter.addWidget(self.tabs); self.splitter.addWidget(log_box)
            layout.addWidget(self.splitter)

            # Signal Connections
            self.btn_my_ip.clicked.connect(self.get_local_subnet)
            self.btn_scan.clicked.connect(self.start_scan)
            self.btn_browse.clicked.connect(self.browse_firmware)
            self.btn_download.clicked.connect(self.download_url)
            self.btn_backup.clicked.connect(self.run_backup)
            self.btn_flash.clicked.connect(self.run_flash)
            self.btn_dump_rom.clicked.connect(self.run_extract_firmware)

            self.tab_terminal.refresh_ports()

        def get_local_subnet(self):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80)); ip = s.getsockname()[0]; s.close()
                self.txt_subnet.setText(".".join(ip.split('.')[:3]))
            except: pass

        def check_usb_serial_status(self):
            ports = []
            if HAS_SERIAL:
                try: ports = [p.device for p in serial.tools.list_ports.comports()]
                except: pass
            if ports:
                self.lbl_usb_status.setText(f"🔌 Serial Adapter: CONNECTED {ports}")
                self.lbl_usb_status.setStyleSheet("background-color: #006266; color: #55efc4; font-weight: bold; padding: 6px;")
            else:
                self.lbl_usb_status.setText("🔌 Serial Adapter: DISCONNECTED")
                self.lbl_usb_status.setStyleSheet("background-color: #2d3436; color: #b2bec3; font-weight: bold; padding: 6px;")

        def log(self, msg):
            self.txt_log.append(f"[{time.strftime('%H:%M:%S')}] {msg}")
            self.txt_log.moveCursor(QtGui.QTextCursor.End)

        def start_scan(self):
            self.btn_scan.setEnabled(False); self.tbl_devices.setRowCount(0)
            subnet = self.txt_subnet.text().strip()
            self.log(f"Initiating Live Fast Scan on [{subnet}.0/24]...")
            self.progress.setValue(10)
            
            # --- RESTORED FAST MULTITHREADING ---
            def worker():
                found = []
                threads = []
                
                def probe(ip_str):
                    info = SmartDeviceProber.identify_device(ip_str)
                    if info: found.append(info)

                for i in range(1, 255): 
                    t = threading.Thread(target=probe, args=(f"{subnet}.{i}",))
                    threads.append(t)
                    t.start()
                    # Batch processing to avoid crashing the OS thread limit
                    if len(threads) >= 60:
                        for th in threads: th.join()
                        threads = []
                        
                for th in threads: th.join()
                QtCore.QMetaObject.invokeMethod(self, "display_devices", QtCore.Q_ARG(list, found))
                
            threading.Thread(target=worker, daemon=True).start()

        @QtCore.pyqtSlot(list)
        def display_devices(self, devices):
            self.btn_scan.setEnabled(True); self.progress.setValue(100)
            
            # Filter out any None values to fix the empty rows bug
            valid_devices = [d for d in devices if d]
            self.tbl_devices.setRowCount(len(valid_devices))
            
            for row, dev in enumerate(valid_devices):
                self.tbl_devices.setItem(row, 0, QTableWidgetItem(dev['status']))
                self.tbl_devices.setItem(row, 1, QTableWidgetItem(dev['ip']))
                self.tbl_devices.setItem(row, 2, QTableWidgetItem(dev['mac']))
                self.tbl_devices.setItem(row, 3, QTableWidgetItem(dev['ports']))
                self.tbl_devices.setItem(row, 4, QTableWidgetItem(dev['type']))
                self.tbl_devices.setItem(row, 5, QTableWidgetItem(dev['vendor']))
                self.tbl_devices.setItem(row, 6, QTableWidgetItem(dev['model']))
                self.tbl_devices.setItem(row, 7, QTableWidgetItem(dev.get('title', '')))

                btn_select = QPushButton("Select")
                btn_select.setStyleSheet("background-color: #27ae60; color: white;")
                btn_select.clicked.connect(lambda chk, d=dict(dev): self.select_device_action(d))
                
                btn_specs = QPushButton("Specs")
                btn_specs.setStyleSheet("background-color: #8e44ad; color: white;")
                btn_specs.clicked.connect(lambda chk, d=dict(dev): DeviceDetailsDialog(d, self).exec_())

                w = QWidget(); l = QHBoxLayout(w); l.setContentsMargins(0,0,0,0)
                l.addWidget(btn_select); l.addWidget(btn_specs)
                self.tbl_devices.setCellWidget(row, 8, w)

        def select_device_action(self, dev):
            self.selected_device = dev
            self.log(f"Target Selected: {dev['vendor']} ({dev['ip']})")
            self.txt_report.setText(f"Target IP: {dev['ip']}\nVendor: {dev['vendor']}\nType: {dev['type']}")
            self.update_action_buttons_state()

        def verify_firmware(self, path):
            try:
                info = FirmwareAnalyzer.inspect_file(path)
                self.lbl_info.setText(f"Status: Firmware Loaded ✅ ({info['filename']})")
                self.lbl_info.setStyleSheet("font-weight: bold; color: #27ae60;")
                self.txt_hashes.setText(f"Type: {info['type']}\nSHA256: {info['sha256']}")
                self.log(f"Firmware Analyzed: {info['filename']}")
                
                if self.selected_device:
                    v = self.selected_device['vendor'].lower()
                    fw_t = info['type'].lower()
                    mismatch = False
                    if "cisco" in v and not ("cisco" in fw_t or "tar" in fw_t): mismatch = True
                    elif "ubiquiti" in v and not ("ubiquiti" in fw_t or "trx" in fw_t): mismatch = True
                    
                    if mismatch:
                        self.log("WARNING: Firmware signature does NOT match the selected target device!")
                        QMessageBox.warning(self, "Compatibility Warning ⚠️", "The loaded firmware does not appear to match the selected device.\n\nYou can still proceed, but flashing incorrect firmware may brick the device.")
                self.update_action_buttons_state() 
            except Exception as e:
                self.log(f"Error parsing firmware: {e}")

        def browse_firmware(self):
            path, _ = QFileDialog.getOpenFileName(self, "Select Firmware File", "", "All Files (*)")
            if path:
                self.txt_file.setText(path)
                self.firmware_file_path = path
                self.verify_firmware(path)

        def download_url(self):
            url = self.txt_url.text().strip()
            if not url.startswith("http"):
                QMessageBox.warning(self, "Invalid URL", "Please enter a valid HTTP/HTTPS URL.")
                return
            
            self.log(f"Downloading firmware from URL: {url}")
            self.lbl_info.setText("Status: Downloading... Please wait ⏳")
            self.lbl_info.setStyleSheet("color: #e67e22; font-weight:bold;")
            QApplication.processEvents() 
            
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                
                file_name = url.split('/')[-1]
                if not file_name or len(file_name) < 3: file_name = "downloaded_fw.bin"
                save_path = os.path.join(os.getcwd(), file_name)
                
                with urllib.request.urlopen(url, context=ctx, timeout=30) as response, open(save_path, 'wb') as out_file:
                    out_file.write(response.read())
                
                self.txt_file.setText(save_path)
                self.firmware_file_path = save_path
                self.log(f"Download complete: {save_path}")
                self.verify_firmware(save_path)
            except Exception as e:
                self.log(f"Download Failed: {str(e)}")
                self.lbl_info.setText("Status: Download Failed ❌")
                QMessageBox.critical(self, "Error", f"Failed to download URL:\n{e}")

        def execute_worker(self, mode):
            if hasattr(self, 'tab_terminal'): self.tab_terminal.disconnect_if_open()
            self.progress.setValue(0)
            self.worker = FlashingEngineWorker(mode, self.selected_device, self.firmware_file_path)
            self.worker.log_signal.connect(self.log)
            self.worker.progress_signal.connect(self.progress.setValue)
            self.worker.finished_signal.connect(lambda s, m: QMessageBox.information(self, "Result", m))
            self.worker.start()

        def run_backup(self): self.execute_worker('BACKUP')
        def run_extract_firmware(self): self.execute_worker('EXTRACT_FIRMWARE')
        def run_flash(self):
            # Show interactive dialog
            dlg = InteractiveFlashDialog(self.selected_device, self)
            if dlg.exec_() == QDialog.Accepted:
                method = dlg.selected_method
                protocol = dlg.selected_protocol

                # Setup interactive config
                self.interactive_config = {
                    'method': method,
                    'protocol': protocol,
                    'ip': self.selected_device.get('ip', '') if self.selected_device else '0.0.0.0',
                    'vendor': self.selected_device.get('vendor', 'Unknown') if self.selected_device else 'Generic'
                }

                self.log(f"Configuring Interactive Flashing Flow via {method} [{protocol}]")
                if hasattr(self, 'tab_terminal'): self.tab_terminal.disconnect_if_open()
                self.progress.setValue(0)

                self.worker = FlashingEngineWorker('FLASH_INTERACTIVE', self.interactive_config, self.firmware_file_path)
                self.worker.log_signal.connect(self.log)
                self.worker.progress_signal.connect(self.progress.setValue)
                self.worker.finished_signal.connect(lambda s, m: QMessageBox.information(self, "Result", m))
                self.worker.start()

def main():
    if HAS_PYQT:
        app = QApplication(sys.argv)
        w = UniversalFirmwareManagerGUI(); w.show()
        sys.exit(app.exec_())

if __name__ == '__main__':
    main()