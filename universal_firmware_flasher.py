#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
Universal Firmware Manager & Flasher v14.0 (Safety + Testing Improvements)
================================================================================
Description: 
- Restored missing columns (Ports, Model, Title) and Specs Dialog.
- Fixed slow scanning (Restored Multithreading & Parallel Port Scanning).
- Fixed empty rows bug in the table.
- Thread-Safe GUI Updates using PyQt Signal/Slot for scan results.
- Added explicit Upgrade / Downgrade / Restore / Backup / Delete operations.
- Blocks unsupported generic writes instead of reporting fake success.
- Secure streamed downloads, compatibility gating, validation states, and safer operation workflow.
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
import json
import logging
import glob
import ipaddress
import zipfile
import tarfile
import tempfile
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, unquote
from datetime import datetime

# --- External Library Fallbacks ---
try:
    from PyQt5 import QtCore, QtGui, QtWidgets
    from PyQt5.QtCore import Qt, pyqtSignal, QThread, QTimer
    from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                                 QHBoxLayout, QLabel, QPushButton, QTextEdit, 
                                 QComboBox, QLineEdit, QProgressBar, QTabWidget, 
                                 QGroupBox, QTableWidget, QTableWidgetItem, QHeaderView,
                                 QFileDialog, QMessageBox, QSplitter, QCheckBox, QDialog, 
                                 QFormLayout, QRadioButton)
    HAS_PYQT = True
except ImportError:
    HAS_PYQT = False

try:
    import serial
    import serial.tools.list_ports
    HAS_SERIAL = True
except ImportError:
    HAS_SERIAL = False

try:
    import pyte
    HAS_PYTE = True
except ImportError:
    HAS_PYTE = False

try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False


# ==============================================================================
# SECTION 0: PURE HELPERS (unit-testable, no GUI / no hardware)
# ==============================================================================
def sanitize_filename(name, fallback="file.bin"):
    """Strip anything but safe filename characters."""
    name = os.path.basename(name or "")
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", name).strip("._") or fallback
    return cleaned


def validate_subnet_prefix(text):
    """True when text is a valid first-three-octets IPv4 prefix like '192.168.1'."""
    if not text or not re.fullmatch(r"(?:\d{1,3}\.){2}\d{1,3}", text.strip()):
        return False
    try:
        ipaddress.ip_address(text.strip() + ".1")
        return True
    except ValueError:
        return False


def build_extract_config(fields, out_dir, stamp):
    """Validate SSH-extract form fields and build a worker config.

    Pure: does not touch the filesystem. Returns (config, error_message);
    exactly one of the two is None.
    """
    host = (fields.get('host') or '').strip()
    user = (fields.get('user') or '').strip()
    password = fields.get('password') or ''
    key_file = (fields.get('key_file') or '').strip()
    method = fields.get('method')

    if not host or not user:
        return None, "Host/IP and Username are required."
    if not password and not key_file:
        return None, "Provide a password or a private key file."

    cfg = {
        'host': host,
        'port': (fields.get('port') or '').strip() or "22",
        'user': user,
        'password': password,
        'key_file': key_file or None,
    }

    try:
        int(cfg['port'])
    except ValueError:
        return None, "Port must be a number."

    if method == 'list':
        cfg['method'] = 'list'
        return cfg, None

    safe_host = sanitize_filename(host, "host")
    if method == 'exec':
        cmd = (fields.get('command') or '').strip()
        if not cmd:
            return None, "Enter the command to run."
        cfg['method'] = 'exec'
        cfg['command'] = cmd
        cfg['out_path'] = os.path.join(out_dir, f"fw_{safe_host}_{stamp}.bin")
        return cfg, None
    if method == 'sftp':
        remote = (fields.get('remote') or '').strip()
        if not remote:
            return None, "Enter the remote file path."
        base = sanitize_filename(os.path.basename(remote), "download.bin")
        cfg['method'] = 'sftp'
        cfg['source'] = remote
        cfg['out_path'] = os.path.join(out_dir, f"{safe_host}_{stamp}_{base}")
        return cfg, None
    return None, "Unknown extraction method."


# Open ports that are worth flagging on a management network, with a severity.
RISKY_PORT_NOTES = {
    23: ("HIGH", "Telnet is open", "Telnet sends credentials in clear text. Disable it and use SSH."),
    21: ("MEDIUM", "FTP is open", "Plain FTP is unencrypted. Prefer SFTP/SCP or disable it."),
    2323: ("HIGH", "Alternate Telnet (2323) is open", "Often used by IoT/botnets. Disable if not required."),
    1900: ("MEDIUM", "UPnP/SSDP (1900) is open", "UPnP is a common attack surface. Disable if unused."),
    7547: ("MEDIUM", "TR-069 (7547) is open", "Remote-management port; restrict to the ISP or disable."),
    445: ("MEDIUM", "SMB (445) is open", "File-sharing port; keep off untrusted networks."),
}


def audit_device_security(device):
    """Local, read-only heuristic security review of an already-scanned device.

    Returns a list of findings: {'severity', 'title', 'detail'}. No packets are
    sent; this only reasons about data already collected during the scan.
    Informational only, for devices the operator owns/administers.
    """
    findings = []
    ports_raw = str((device or {}).get('ports', '') or '')
    open_ports = set()
    for tok in re.findall(r"\d+", ports_raw):
        try:
            open_ports.add(int(tok))
        except ValueError:
            pass

    for port, (sev, title, detail) in RISKY_PORT_NOTES.items():
        if port in open_ports:
            findings.append({'severity': sev, 'title': title, 'detail': detail})

    if 80 in open_ports and 443 not in open_ports:
        findings.append({'severity': "MEDIUM", 'title': "Web UI without HTTPS",
                         'detail': "Port 80 is open but 443 is not. The management UI may be unencrypted."})
    if 22 in open_ports:
        findings.append({'severity': "INFO", 'title': "SSH is reachable",
                         'detail': "SSH is open. Use a strong password or key and restrict access."})

    vendor = str((device or {}).get('vendor', '')).lower()
    title = str((device or {}).get('title', '')).lower()
    if any(k in vendor or k in title for k in ("dahua", "hikvision")):
        findings.append({'severity': "HIGH", 'title': "IP camera / NVR exposed",
                         'detail': "Cameras/NVRs have a long history of default-credential and firmware CVEs. "
                                   "Change defaults, update firmware, and never expose them to the internet."})
    if "default" in title or "admin" in title:
        findings.append({'severity': "MEDIUM", 'title': "Possible default landing page",
                         'detail': "The web title hints at a default/setup page. Confirm default credentials were changed."})

    if not findings:
        findings.append({'severity': "INFO", 'title': "No obvious issues from passive data",
                         'detail': "Nothing flagged from the scan data alone. This is not a full vulnerability assessment."})
    # Sort HIGH > MEDIUM > LOW > INFO
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    findings.sort(key=lambda f: order.get(f['severity'], 9))
    return findings


def nmap_available():
    """True if an 'nmap' binary is on PATH."""
    return shutil.which("nmap") is not None


def build_nmap_command(ip, service=True, os_detect=False, vuln=False):
    """Build an nmap argument list for an authorized scan of a single host."""
    cmd = ["nmap", "-Pn", "-T4"]
    if service:
        cmd.append("-sV")
    if os_detect:
        cmd.append("-O")
    if vuln:
        cmd += ["--script", "vuln"]
    cmd.append(str(ip))
    return cmd


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
                        vendor = v_name
                        break
        except Exception:
            pass
        return mac, vendor


# ==============================================================================
# SECTION 2: SMART PROBER (WITH PARALLEL PORTS & WEB PARSING)
# ==============================================================================
class SmartDeviceProber:
    @staticmethod
    def is_alive(ip):
        try:
            p = '-n' if os.name == 'nt' else '-c'
            return subprocess.call(['ping', p, '1', '-w', '500' if os.name == 'nt' else '1', ip], 
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, 
                                   creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0) == 0
        except Exception:
            return False

    @staticmethod
    def scan_ports(ip):
        """Probe only the small set of common management ports, in parallel."""
        target_ports = [21, 22, 23, 80, 443, 8080]

        def check_port(port):
            try:
                with socket.create_connection((ip, port), timeout=0.35):
                    return port
            except (OSError, socket.timeout):
                return None

        with ThreadPoolExecutor(max_workers=len(target_ports)) as executor:
            results = [future.result() for future in
                       (executor.submit(check_port, port) for port in target_ports)]
        open_ports = sorted(port for port in results if port is not None)
        return ", ".join(map(str, open_ports)) if open_ports else "Closed"

    @staticmethod
    def probe_endpoint(ip, port=80, is_ssl=False, timeout=1.0):
        try:
            # Device-local HTTPS interfaces frequently use self-signed certificates.
            # This probe is identification-only; firmware downloads use normal TLS verification.
            ctx = ssl._create_unverified_context() if is_ssl else None
            conn = (http.client.HTTPSConnection(ip, port=port, timeout=timeout, context=ctx)
                    if is_ssl else http.client.HTTPConnection(ip, port=port, timeout=timeout))
            conn.request("GET", "/", headers={"User-Agent": "Universal-Firmware-Manager/14.1"})
            res = conn.getresponse()
            server_header = res.getheader("Server", "Unknown Server")
            html_raw = res.read(8192).decode('utf-8', errors='ignore')
            conn.close()
            title = ""
            title_match = re.search(r'<title[^>]*>(.*?)</title>', html_raw, re.IGNORECASE | re.DOTALL)
            if title_match:
                title = html.unescape(re.sub(r'\s+', ' ', title_match.group(1)).strip())
            if not title:
                title = f"[{server_header}]" if server_header else "Web Interface"
            return server_header, title[:160], html_raw
        except Exception:
            return "", "", ""

    @classmethod
    def identify_device(cls, ip):
        """Identify a reachable host without requiring ICMP ping to be enabled."""
        open_ports = cls.scan_ports(ip)
        alive = cls.is_alive(ip)
        if open_ports == "Closed" and not alive:
            return None

        mac, os_vendor = OSNetworkScanner.get_mac_and_vendor(ip)
        srv_http = title_http = html_http = ""
        srv_https = title_https = html_https = ""
        if open_ports != "Closed":
            ports_set = {int(x) for x in open_ports.split(', ')}
            if 80 in ports_set or 8080 in ports_set:
                srv_http, title_http, html_http = cls.probe_endpoint(ip, 80 if 80 in ports_set else 8080, False)
            if 443 in ports_set:
                srv_https, title_https, html_https = cls.probe_endpoint(ip, 443, True)

        full_text = f"{srv_http} {title_http} {html_http} {srv_https} {title_https} {html_https}".lower()
        title_combined = f"{title_http} {title_https}".lower()

        dev_type = "Workstation / Node" if "Intel" in os_vendor or "Apple" in os_vendor else "Network Device"
        model = "Standard System" if "Intel" in os_vendor or "Apple" in os_vendor else "Hardware Node"
        vendor = os_vendor if os_vendor != "Generic Hardware" else "Unknown OS"
        title = html.unescape(title_http or title_https or "No Web Interface")

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
            except Exception:
                pass
        return ports


# ==============================================================================
# SECTION 4: FIRMWARE ANALYZER
# ==============================================================================
class FirmwareAnalyzer:
    MAGIC_SIGNATURES = {
        b'HDR0': 'TRX Firmware Image',
        b'UBI#': 'UBI Flash System Image',
    }

    @classmethod
    def inspect_file(cls, file_path):
        if not file_path or not os.path.isfile(file_path):
            raise FileNotFoundError("Firmware file not found.")
        size_bytes = os.path.getsize(file_path)
        if size_bytes == 0:
            raise ValueError("Firmware file is empty.")

        md5, sha256 = hashlib.md5(), hashlib.sha256()
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                md5.update(chunk)
                sha256.update(chunk)

        with open(file_path, 'rb') as f:
            header = f.read(512)

        extension = os.path.splitext(file_path)[1].lower() or '(no extension)'
        magic_detected = cls._detect_type(file_path, header, extension)
        return {
            'filename': os.path.basename(file_path),
            'size_bytes': size_bytes,
            'size_mb': round(size_bytes / (1024 * 1024), 2),
            'extension': extension,
            'type': magic_detected,
            'md5': md5.hexdigest(),
            'sha256': sha256.hexdigest(),
        }

    @classmethod
    def _detect_type(cls, file_path, header, extension):
        for magic, fmt in cls.MAGIC_SIGNATURES.items():
            if header.startswith(magic):
                return fmt
        if header.startswith(b'PK\x03\x04'):
            return 'ZIP Archive / Package'
        if header.startswith(b'\x1f\x8b'):
            return 'GZIP Compressed Image'
        try:
            if tarfile.is_tarfile(file_path):
                return 'TAR Archive / Package'
        except (OSError, tarfile.TarError):
            pass
        if extension in {'.bin', '.img', '.trx', '.chk', '.fw', '.rom', '.image'}:
            return f'Firmware Binary ({extension})'
        if extension in {'.zip', '.tar', '.tgz', '.gz'}:
            return f'Archive ({extension})'
        return 'Generic / Custom Binary'


# ==============================================================================
# SECTION 5: REAL FLASHING & NETWORK SCAN WORKERS
# ==============================================================================
if HAS_PYQT:
    class NetworkScannerWorker(QThread):
        devices_found_signal = pyqtSignal(list)
        progress_signal = pyqtSignal(int)

        def __init__(self, subnet):
            super().__init__()
            self.subnet = subnet

        def run(self):
            found = []
            threads = []
            lock = threading.Lock()
            
            def probe(ip_str):
                info = SmartDeviceProber.identify_device(ip_str)
                if info:
                    with lock:
                        found.append(info)

            for i in range(1, 255): 
                t = threading.Thread(target=probe, args=(f"{self.subnet}.{i}",))
                threads.append(t)
                t.start()
                if len(threads) >= 60:
                    for th in threads:
                        th.join()
                    threads = []
                    self.progress_signal.emit(int((i / 255) * 100))
                    
            for th in threads:
                th.join()
            self.progress_signal.emit(100)
            self.devices_found_signal.emit(found)


    class FirmwareDownloadWorker(QThread):
        progress_signal = pyqtSignal(int)
        log_signal = pyqtSignal(str)
        finished_signal = pyqtSignal(bool, str, str)

        def __init__(self, url, save_path):
            super().__init__()
            self.url = url
            self.save_path = save_path

        def run(self):
            try:
                request = urllib.request.Request(
                    self.url,
                    headers={"User-Agent": "Universal-Firmware-Manager/1.0"},
                    method="GET"
                )
                with urllib.request.urlopen(request, timeout=30) as response:
                    final_url = response.geturl()
                    if urlparse(final_url).scheme.lower() != "https":
                        raise RuntimeError("The download was redirected to a non-HTTPS URL; download blocked for safety.")
                    total = int(response.headers.get("Content-Length", "0") or 0)
                    if total > 2 * 1024 * 1024 * 1024:
                        raise RuntimeError("The firmware file is larger than the 2 GB safety limit.")
                    received = 0
                    with open(self.save_path, "wb") as out_file:
                        while True:
                            chunk = response.read(1024 * 1024)
                            if not chunk:
                                break
                            out_file.write(chunk)
                            received += len(chunk)
                            if received > 2 * 1024 * 1024 * 1024:
                                raise RuntimeError("The firmware download exceeded the 2 GB safety limit.")
                            if total:
                                self.progress_signal.emit(min(99, int(received * 100 / total)))
                if os.path.getsize(self.save_path) == 0:
                    raise RuntimeError("The server returned an empty firmware file.")
                self.progress_signal.emit(100)
                self.finished_signal.emit(True, self.save_path, "Download completed.")
            except Exception as e:
                try:
                    if os.path.exists(self.save_path):
                        os.remove(self.save_path)
                except OSError:
                    pass
                self.log_signal.emit(f"Download failed: {e}")
                self.finished_signal.emit(False, "", str(e))

    class FlashingEngineWorker(QThread):
        log_signal = pyqtSignal(str)
        progress_signal = pyqtSignal(int)
        finished_signal = pyqtSignal(bool, str)

        def __init__(self, operation, config, firmware_file=None):
            super().__init__()
            self.operation = operation
            self.config = config or {}
            self.firmware_file = firmware_file

        def log(self, msg):
            self.log_signal.emit(f"[{time.strftime('%H:%M:%S')}] {msg}")

        def require_firmware(self):
            if not self.firmware_file or not os.path.isfile(self.firmware_file):
                raise RuntimeError("Firmware file is required for this operation.")
            info = FirmwareAnalyzer.inspect_file(self.firmware_file)
            self.log(f"Firmware: {info['filename']} | {info['size_mb']} MB | {info['type']}")
            self.log(f"SHA256: {info['sha256']}")
            return info

        def real_tftp_put(self):
            ip = self.config.get('ip', '').strip()
            if not ip:
                raise RuntimeError("Target IP address is missing.")
            if os.name == 'nt':
                cmd = ["tftp", "-i", ip, "PUT", self.firmware_file]
            else:
                cmd = ["tftp", ip, "-m", "binary", "-c", "put", self.firmware_file]
            self.log("REAL TFTP transfer started.")
            self.log("Command: " + subprocess.list2cmdline(cmd))
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=120,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
                )
            except FileNotFoundError:
                raise RuntimeError("TFTP client not found. Enable Windows TFTP Client or install a TFTP client.")
            except subprocess.TimeoutExpired:
                raise RuntimeError("TFTP transfer timed out.")
            if result.stdout.strip():
                self.log("TFTP: " + result.stdout.strip())
            if result.stderr.strip():
                self.log("TFTP ERR: " + result.stderr.strip())
            if result.returncode != 0:
                raise RuntimeError(
                    "TFTP transfer failed. Check that the router is in its TFTP/recovery mode "
                    "and that it expects this transfer."
                )
            self.progress_signal.emit(100)

        def real_uart_interrupt(self):
            if not HAS_SERIAL:
                raise RuntimeError("pyserial is not installed.")
            ports = list(serial.tools.list_ports.comports())
            port = self.config.get('serial_port') or (ports[0].device if ports else None)
            if not port:
                raise RuntimeError("No USB-to-Serial/UART port was detected.")
            baud = int(self.config.get('baud', 115200))
            self.log(f"Opening REAL UART {port} at {baud} baud.")
            try:
                with serial.Serial(port, baudrate=baud, timeout=1) as ser:
                    for _ in range(5):
                        ser.write(b'\x03')
                        time.sleep(0.25)
                    ser.write(b'\r\n')
                    time.sleep(1)
                    data = ser.read(4096)
            except Exception as e:
                raise RuntimeError(f"UART operation failed: {e}")
            if data:
                self.log("Bootloader response:\n" + data.decode('utf-8', errors='replace')[-2000:])
            else:
                self.log("No bootloader response received.")
            raise RuntimeError(
                "Bootloader interrupt was sent, but no model-specific firmware write command is configured. "
                "No firmware was written."
            )

        def run(self):
            try:
                op = self.operation
                ip = self.config.get('ip', '').strip()
                vendor = self.config.get('vendor', 'Unknown')
                protocol = str(self.config.get('protocol', '')).lower()
                self.log(f"Operation: {op}")
                self.log(f"Target: {ip or 'Serial device'} | Vendor: {vendor}")

                if op in ("UPGRADE", "DOWNGRADE", "RESTORE"):
                    self.require_firmware()
                    self.progress_signal.emit(15)

                    if "tftp" in protocol:
                        self.log(f"{op}: executing REAL TFTP file transfer.")
                        self.real_tftp_put()
                        self.finished_signal.emit(
                            True,
                            f"{op.title()} firmware transfer completed.\n"
                            "Transfer succeeded; the device must install the image according to its bootloader/recovery procedure."
                        )
                        return

                    if "uart" in protocol or "serial" in protocol:
                        self.real_uart_interrupt()
                        return

                    raise RuntimeError(
                        f"{op.title()} cannot be performed generically over {protocol or 'unknown'}.\n"
                        "SSH/HTTP firmware installation is model-specific, so the tool will not pretend it flashed the router."
                    )

                if op == "BACKUP":
                    if not ip:
                        raise RuntimeError("Target IP address is missing.")
                    if not SmartDeviceProber.is_alive(ip):
                        raise RuntimeError("Device is not reachable by ping. No backup was created.")
                    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    folder = os.path.join(os.getcwd(), "backups")
                    os.makedirs(folder, exist_ok=True)
                    path = os.path.join(folder, f"device_info_{ip.replace('.', '_')}_{stamp}.txt")
                    mac, vendor_name = OSNetworkScanner.get_mac_and_vendor(ip)
                    ports = SmartDeviceProber.scan_ports(ip)
                    with open(path, "w", encoding="utf-8") as f:
                        f.write("DEVICE INFORMATION REPORT\n")
                        f.write(f"Timestamp: {datetime.now().isoformat()}\n")
                        f.write(f"IP: {ip}\nMAC: {mac}\nVendor: {vendor_name}\nOpen ports: {ports}\n")
                        f.write("\nIMPORTANT: This is NOT a configuration/firmware backup.\n")
                        f.write("A real backup requires the exact device model and its supported backup mechanism.\n")
                    self.progress_signal.emit(100)
                    self.log(f"Device information report saved: {path}")
                    self.finished_signal.emit(True, f"Device information report saved:\n{path}")
                    return

                if op == "DELETE":
                    raise RuntimeError(
                        "Delete is blocked because flash-file/partition syntax is device-specific. "
                        "The exact model and bootloader command are required to safely delete a firmware image."
                    )

                if op == "EXTRACT_FIRMWARE":
                    if not HAS_SERIAL:
                        raise RuntimeError("pyserial is not installed.")
                    ports = list(serial.tools.list_ports.comports())
                    if not ports:
                        raise RuntimeError("No USB-to-Serial/UART adapter was found.")
                    port = self.config.get('serial_port') or ports[0].device
                    self.log(f"Opening UART {port} for bootloader inspection.")
                    try:
                        with serial.Serial(port, baudrate=115200, timeout=1) as ser:
                            for _ in range(5):
                                ser.write(b'\x03')
                                time.sleep(0.25)
                            ser.write(b'\r\n')
                            time.sleep(1)
                            data = ser.read(8192)
                    except Exception as e:
                        raise RuntimeError(f"UART inspection failed: {e}")
                    if data:
                        self.log(data.decode('utf-8', errors='replace')[-4000:])
                    raise RuntimeError(
                        "Bootloader access was attempted, but a full ROM dump requires the exact flash chip, "
                        "memory map and bootloader commands. No fake ROM file was created."
                    )

                raise RuntimeError(f"Unknown operation: {op}")

            except Exception as e:
                self.log(f"CRITICAL ERROR: {e}")
                self.progress_signal.emit(0)
                self.finished_signal.emit(False, str(e))

    class SSHExtractWorker(QThread):
        """Authenticated, no-hardware firmware/config extraction over SSH/SFTP.

        Intended for devices the operator owns or administers. The user supplies
        valid credentials; this worker does NOT bypass authentication, brute-force,
        or exploit any device. It simply runs the requested command (e.g. dumping a
        flash/MTD device the logged-in account can already read) or downloads an
        existing file over SFTP, streaming the result to a local file.
        """
        log_signal = pyqtSignal(str)
        progress_signal = pyqtSignal(int)
        finished_signal = pyqtSignal(bool, str)

        def __init__(self, config):
            super().__init__()
            self.config = config or {}

        def log(self, msg):
            self.log_signal.emit(f"[{time.strftime('%H:%M:%S')}] {msg}")

        def run(self):
            if not HAS_PARAMIKO:
                self.finished_signal.emit(False, "paramiko is not installed. Run: python -m pip install paramiko")
                return
            # Keep paramiko's own transport thread from dumping tracebacks to stderr.
            logging.getLogger("paramiko").setLevel(logging.CRITICAL)
            logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)

            c = self.config
            host = c['host']
            port = int(c['port'])

            # Pre-flight: is the SSH port actually open? Fail fast with a clear message
            # instead of waiting for a cryptic "banner" timeout.
            self.log(f"Checking TCP {host}:{port} ...")
            try:
                with socket.create_connection((host, port), timeout=6):
                    pass
            except OSError as e:
                self.progress_signal.emit(0)
                self.finished_signal.emit(
                    False,
                    f"Cannot reach {host}:{port}.\n\n"
                    f"The SSH port looks closed, filtered, or wrong ({e}).\n"
                    "• Make sure SSH (or Dropbear) is enabled on the device.\n"
                    "• Check the port number — many routers use 22, some use a different one.\n"
                    "• Confirm the device is on and reachable from this PC."
                )
                return

            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                self.log(f"Connecting to {host}:{port} as '{c['user']}' ...")
                kwargs = dict(hostname=host, port=port, username=c['user'],
                              timeout=20, banner_timeout=30, auth_timeout=20,
                              allow_agent=False, look_for_keys=False)
                if c.get('key_file'):
                    kwargs['key_filename'] = c['key_file']
                if c.get('password'):
                    kwargs['password'] = c['password']
                client.connect(**kwargs)
                self.log("Authentication succeeded.")

                method = c.get('method')
                if method == 'list':
                    self._run_simple(client,
                                     "cat /proc/mtd 2>/dev/null; echo '----- /dev/mtd* -----'; "
                                     "ls -l /dev/mtd* 2>/dev/null; echo '----- block devices -----'; "
                                     "cat /proc/partitions 2>/dev/null")
                    client.close()
                    self.finished_signal.emit(True, "Flash partition listing complete. See the log, then choose a partition to dump.")
                    return

                if method == 'sftp':
                    self._sftp_download(client, c['source'], c['out_path'])
                else:
                    self._exec_to_file(client, c['command'], c['out_path'])

                client.close()
                self.progress_signal.emit(100)
                self.finished_signal.emit(True, f"Firmware image saved:\n{c['out_path']}")
            except paramiko.AuthenticationException:
                self._fail(client, "Authentication failed.\n\nThe username, password, or key was not accepted by the device.")
            except paramiko.SSHException as e:
                if "banner" in str(e).lower():
                    self._fail(client,
                               "Connected to the port, but no SSH banner was received.\n\n"
                               "The service on this port is probably not SSH (it might be Telnet or a web "
                               "interface), or SSH is very slow/blocked. Check the port and that SSH/Dropbear "
                               "is enabled on the device.")
                else:
                    self._fail(client, f"SSH protocol error: {e}")
            except (socket.timeout, TimeoutError):
                self._fail(client, "The connection timed out. The host is unreachable or the SSH port is closed.")
            except Exception as e:
                self._fail(client, f"SSH extraction failed: {e}")

        def _fail(self, client, message):
            try:
                client.close()
            except Exception:
                pass
            self.progress_signal.emit(0)
            self.finished_signal.emit(False, message)

        def _run_simple(self, client, cmd):
            self.log(f"Running: {cmd}")
            _in, out, err = client.exec_command(cmd, timeout=25)
            out_text = out.read().decode('utf-8', errors='ignore').strip()
            err_text = err.read().decode('utf-8', errors='ignore').strip()
            if out_text:
                self.log("Output:\n" + out_text)
            if err_text:
                self.log("stderr:\n" + err_text)
            if not out_text and not err_text:
                self.log("No output returned.")

        def _exec_to_file(self, client, cmd, out_path):
            self.log(f"Running: {cmd}")
            self.log(f"Streaming output to: {out_path}")
            _in, out, err = client.exec_command(cmd, timeout=None)
            chan = out.channel
            received = 0
            last_logged = 0
            with open(out_path, 'wb') as f:
                while True:
                    data = chan.recv(65536)
                    if not data:
                        break
                    f.write(data)
                    received += len(data)
                    if received - last_logged >= 512 * 1024:
                        last_logged = received
                        self.log(f"Received {received // 1024} KB ...")
                        # Total size is unknown for a stream; show activity without a false 100%.
                        self.progress_signal.emit(min(95, 10 + (received // (256 * 1024)) % 85))
            exit_status = chan.recv_exit_status()
            err_text = err.read().decode('utf-8', errors='ignore').strip()
            if err_text:
                self.log("stderr:\n" + err_text)
            if received == 0:
                raise RuntimeError(
                    "The command produced no data. Check the device/partition path and that the "
                    "account is allowed to read it (root is usually required for /dev/mtd*)."
                )
            if exit_status != 0:
                self.log(f"WARNING: remote command exit status {exit_status}; the image may be incomplete.")
            self.log(f"Done. {received} bytes written.")

        def _sftp_download(self, client, remote, out_path):
            sftp = client.open_sftp()
            try:
                total = sftp.stat(remote).st_size
                self.log(f"Downloading '{remote}' ({total} bytes) via SFTP ...")

                def cb(done, tot):
                    if tot:
                        self.progress_signal.emit(min(99, int(done * 100 / tot)))
                sftp.get(remote, out_path, callback=cb)
            finally:
                sftp.close()
            if os.path.getsize(out_path) == 0:
                raise RuntimeError("Downloaded file is empty.")
            self.log(f"Done. Saved {os.path.getsize(out_path)} bytes.")

    class NmapWorker(QThread):
        """Runs an external, authorized nmap scan against a single host and streams output."""
        log_signal = pyqtSignal(str)
        finished_signal = pyqtSignal(bool, str)

        def __init__(self, ip, vuln=False):
            super().__init__()
            self.ip = ip
            self.vuln = vuln

        def run(self):
            if not nmap_available():
                self.finished_signal.emit(False, "nmap is not installed or not on PATH. Install it from https://nmap.org.")
                return
            cmd = build_nmap_command(self.ip, service=True, vuln=self.vuln)
            self.log_signal.emit("Running: " + subprocess.list2cmdline(cmd))
            try:
                proc = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=600,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
                )
            except FileNotFoundError:
                self.finished_signal.emit(False, "nmap binary not found.")
                return
            except subprocess.TimeoutExpired:
                self.finished_signal.emit(False, "nmap scan timed out (10 min).")
                return
            out = (proc.stdout or "").strip()
            err = (proc.stderr or "").strip()
            if out:
                self.log_signal.emit(out)
            if err:
                self.log_signal.emit("nmap stderr: " + err)
            ok = proc.returncode == 0
            self.finished_signal.emit(ok, out or err or "nmap finished with no output.")

# ==============================================================================
# SECTION 6: REAL VT100 SERIAL TERMINAL (PuTTY / Termius style, pyte-backed)
# ==============================================================================
if HAS_PYQT:
    # --- VT100 color palette (PuTTY/Termius-like) ---
    TERM_DEFAULT_FG = "#e6e6e6"
    TERM_DEFAULT_BG = "#0c0c0c"
    TERM_CURSOR_BG = "#00ff9c"
    TERM_ANSI_COLORS = {
        "black": "#3b3b3b", "red": "#ff5f56", "green": "#5af78e",
        "brown": "#f3f99d", "yellow": "#f3f99d", "blue": "#57c7ff",
        "magenta": "#ff6ac1", "cyan": "#9aedfe", "white": "#eff0eb",
    }

    def _term_color(token, default):
        if not token or token == "default":
            return default
        if token in TERM_ANSI_COLORS:
            return TERM_ANSI_COLORS[token]
        if isinstance(token, str) and len(token) == 6:
            try:
                int(token, 16)
                return "#" + token
            except ValueError:
                return default
        return default

    class SerialReaderThread(QThread):
        """Reads raw bytes from the serial port on a background thread."""
        data_received = pyqtSignal(bytes)
        error_occurred = pyqtSignal(str)

        def __init__(self, serial_inst):
            super().__init__()
            self.serial_inst = serial_inst
            self.running = True

        def run(self):
            while self.running and self.serial_inst and self.serial_inst.is_open:
                try:
                    waiting = self.serial_inst.in_waiting
                    if waiting:
                        data = self.serial_inst.read(waiting)
                        if data:
                            self.data_received.emit(data)
                    else:
                        time.sleep(0.01)
                except Exception as e:
                    if self.running:
                        self.error_occurred.emit(str(e))
                    break

        def stop(self):
            self.running = False
            self.wait(2000)

    class TerminalView(QTextEdit):
        """Read-only display surface. Forwards keystrokes to the owning widget."""
        def __init__(self, owner):
            super().__init__()
            self.owner = owner
            self.setReadOnly(True)
            self.setLineWrapMode(QTextEdit.NoWrap)
            self.setCursorWidth(0)
            self.setContextMenuPolicy(Qt.DefaultContextMenu)
            self.setStyleSheet(
                f"background-color: {TERM_DEFAULT_BG}; color: {TERM_DEFAULT_FG};"
                " border: 1px solid #3d5366;"
            )
            font = QtGui.QFont("Consolas", 11)
            font.setStyleHint(QtGui.QFont.Monospace)
            self.setFont(font)
            self.verticalScrollBar().setStyleSheet("")

        def keyPressEvent(self, event):
            if self.owner.is_connected():
                if event.matches(QtGui.QKeySequence.Copy):
                    super().keyPressEvent(event)
                    return
                if self.owner.handle_key(event):
                    return
                event.accept()
                return
            if event.matches(QtGui.QKeySequence.Copy):
                super().keyPressEvent(event)
            else:
                event.ignore()

        def resizeEvent(self, event):
            super().resizeEvent(event)
            self.owner.resize_grid()

    class EmbeddedTerminalWidget(QWidget):
        """Real serial terminal (PuTTY / Termius style) backed by a pyte VT100 screen."""
        ARROW_SEQUENCES = {
            Qt.Key_Up: b"\x1b[A", Qt.Key_Down: b"\x1b[B",
            Qt.Key_Right: b"\x1b[C", Qt.Key_Left: b"\x1b[D",
            Qt.Key_Home: b"\x1b[H", Qt.Key_End: b"\x1b[F",
            Qt.Key_PageUp: b"\x1b[5~", Qt.Key_PageDown: b"\x1b[6~",
            Qt.Key_Delete: b"\x1b[3~", Qt.Key_Insert: b"\x1b[2~",
            Qt.Key_F1: b"\x1bOP", Qt.Key_F2: b"\x1bOQ",
            Qt.Key_F3: b"\x1bOR", Qt.Key_F4: b"\x1bOS",
        }

        def __init__(self, main_gui=None):
            super().__init__()
            self.main_gui = main_gui
            self.reader_thread = None
            self.serial_inst = None
            self.log_file = None
            self._dirty = False

            self.screen = None
            self.stream = None
            if HAS_PYTE:
                self.screen = pyte.Screen(100, 30)
                self.stream = pyte.ByteStream(self.screen)

            self._build_ui()

            # Render loop: repaint the screen only when new data arrived.
            self.render_timer = QTimer(self)
            self.render_timer.timeout.connect(self._render_if_dirty)
            self.render_timer.start(40)

            self.refresh_ports()

        # ---------- UI ----------
        def _build_ui(self):
            layout = QVBoxLayout(self)
            layout.setSpacing(6)

            # Row 1: port / baud / connect
            conn_row = QHBoxLayout()
            self.cmb_port = QComboBox()
            self.cmb_port.setMinimumWidth(220)
            self.cmb_baud = QComboBox()
            self.cmb_baud.addItems(["9600", "19200", "38400", "57600", "115200",
                                    "230400", "460800", "921600", "1500000"])
            self.cmb_baud.setCurrentText("115200")
            self.cmb_baud.setEditable(True)
            self.btn_refresh = QPushButton("🔄")
            self.btn_refresh.setToolTip("Refresh serial ports")
            self.btn_refresh.setMaximumWidth(40)
            self.btn_connect = QPushButton("🔌 Connect")

            conn_row.addWidget(QLabel("Port:"))
            conn_row.addWidget(self.cmb_port)
            conn_row.addWidget(QLabel("Baud:"))
            conn_row.addWidget(self.cmb_baud)
            conn_row.addWidget(self.btn_refresh)
            conn_row.addWidget(self.btn_connect)
            conn_row.addStretch()
            layout.addLayout(conn_row)

            # Row 2: serial framing (PuTTY-style)
            cfg_row = QHBoxLayout()
            self.cmb_databits = QComboBox()
            self.cmb_databits.addItems(["5", "6", "7", "8"])
            self.cmb_databits.setCurrentText("8")
            self.cmb_parity = QComboBox()
            self.cmb_parity.addItems(["None", "Even", "Odd", "Mark", "Space"])
            self.cmb_stopbits = QComboBox()
            self.cmb_stopbits.addItems(["1", "1.5", "2"])
            self.cmb_flow = QComboBox()
            self.cmb_flow.addItems(["None", "XON/XOFF", "RTS/CTS"])
            self.cmb_newline = QComboBox()
            self.cmb_newline.addItems(["CR", "LF", "CRLF"])
            self.cmb_newline.setToolTip("Bytes sent when you press Enter")
            self.chk_echo = QCheckBox("Local echo")

            for lbl, w in (("Data:", self.cmb_databits), ("Parity:", self.cmb_parity),
                           ("Stop:", self.cmb_stopbits), ("Flow:", self.cmb_flow),
                           ("Enter:", self.cmb_newline)):
                cfg_row.addWidget(QLabel(lbl))
                cfg_row.addWidget(w)
            cfg_row.addWidget(self.chk_echo)
            cfg_row.addStretch()
            layout.addLayout(cfg_row)

            # Row 3: quick actions
            act_row = QHBoxLayout()
            self.btn_break = QPushButton("⚡ Break (Ctrl+C)")
            self.btn_tpl = QPushButton("⚡ U-Boot (tpl)")
            self.btn_enter = QPushButton("⚡ Enter")
            self.btn_reboot = QPushButton("⚡ reboot")
            self.btn_clear = QPushButton("🗑 Clear")
            self.btn_log = QPushButton("📝 Log: Off")
            self.btn_log.setCheckable(True)
            for b in (self.btn_break, self.btn_tpl, self.btn_enter,
                      self.btn_reboot, self.btn_clear, self.btn_log):
                act_row.addWidget(b)
            act_row.addStretch()
            layout.addLayout(act_row)

            # Display
            self.view = TerminalView(self)
            self.view.setPlaceholderText(">> Choose a port and click Connect to start a serial session.")
            layout.addWidget(self.view, 1)

            # Input line
            in_row = QHBoxLayout()
            self.cmd_input = QLineEdit()
            self.cmd_input.setPlaceholderText("Type a command and press Enter (history: ↑ / ↓)...")
            self.btn_send = QPushButton("📤 Send")
            in_row.addWidget(self.cmd_input)
            in_row.addWidget(self.btn_send)
            layout.addLayout(in_row)

            if not HAS_PYTE:
                warn = QLabel("⚠️ pyte not installed — using a basic renderer. Install it with: python -m pip install pyte")
                warn.setStyleSheet("color: #e67e22;")
                layout.addWidget(warn)

            # History for the input line
            self._history = []
            self._history_idx = 0

            # Wiring
            self.btn_refresh.clicked.connect(self.refresh_ports)
            self.btn_connect.clicked.connect(self.toggle_connection)
            self.btn_clear.clicked.connect(self.clear_screen)
            self.btn_log.clicked.connect(self.toggle_log)
            self.btn_break.clicked.connect(lambda: self.write_bytes(b"\x03"))
            self.btn_tpl.clicked.connect(lambda: self.write_bytes(b"tpl\r"))
            self.btn_enter.clicked.connect(lambda: self.write_bytes(self._newline_bytes()))
            self.btn_reboot.clicked.connect(lambda: self.write_bytes(b"reboot" + self._newline_bytes()))
            self.btn_send.clicked.connect(self.send_command)
            self.cmd_input.returnPressed.connect(self.send_command)
            self.cmd_input.installEventFilter(self)

        # ---------- state helpers ----------
        def is_connected(self):
            return bool(self.serial_inst and self.serial_inst.is_open)

        def _newline_bytes(self):
            return {"CR": b"\r", "LF": b"\n", "CRLF": b"\r\n"}[self.cmb_newline.currentText()]

        # ---------- ports ----------
        def refresh_ports(self):
            current = self.cmb_port.currentData()
            self.cmb_port.clear()
            for p in SerialScanner.scan_ports():
                self.cmb_port.addItem(f"{p['port']} — {p['desc']}", p['port'])
            if self.cmb_port.count() == 0:
                self.cmb_port.addItem("No serial ports found", None)
            else:
                idx = self.cmb_port.findData(current)
                if idx >= 0:
                    self.cmb_port.setCurrentIndex(idx)

        # ---------- connection ----------
        def _serial_kwargs(self):
            bytesize = {"5": serial.FIVEBITS, "6": serial.SIXBITS,
                        "7": serial.SEVENBITS, "8": serial.EIGHTBITS}[self.cmb_databits.currentText()]
            parity = {"None": serial.PARITY_NONE, "Even": serial.PARITY_EVEN,
                      "Odd": serial.PARITY_ODD, "Mark": serial.PARITY_MARK,
                      "Space": serial.PARITY_SPACE}[self.cmb_parity.currentText()]
            stopbits = {"1": serial.STOPBITS_ONE, "1.5": serial.STOPBITS_ONE_POINT_FIVE,
                        "2": serial.STOPBITS_TWO}[self.cmb_stopbits.currentText()]
            flow = self.cmb_flow.currentText()
            return dict(bytesize=bytesize, parity=parity, stopbits=stopbits,
                        xonxoff=(flow == "XON/XOFF"), rtscts=(flow == "RTS/CTS"),
                        timeout=0.05)

        def toggle_connection(self):
            if self.is_connected():
                self.disconnect_if_open()
                self._append_system("Disconnected.")
                return
            if not HAS_SERIAL:
                self._append_system("pyserial is not installed.")
                return
            port = self.cmb_port.currentData()
            if not port:
                self.refresh_ports()
                self._append_system("No serial port selected.")
                return
            try:
                baud = int(self.cmb_baud.currentText())
            except ValueError:
                self._append_system("Invalid baud rate.")
                return
            try:
                self.serial_inst = serial.Serial(port, baudrate=baud, **self._serial_kwargs())
            except Exception as e:
                self._append_system(f"Connection failed: {e}")
                self.serial_inst = None
                return

            self._reset_screen()
            self.resize_grid()
            self.btn_connect.setText("🛑 Disconnect")
            self.btn_connect.setStyleSheet("background-color: #c0392b; color: white; font-weight: bold;")
            self._append_system(
                f"Connected to {port} @ {baud} "
                f"{self.cmb_databits.currentText()}{self.cmb_parity.currentText()[0]}{self.cmb_stopbits.currentText()}"
            )
            self.reader_thread = SerialReaderThread(self.serial_inst)
            self.reader_thread.data_received.connect(self.feed_data)
            self.reader_thread.error_occurred.connect(self.handle_serial_error)
            self.reader_thread.start()
            self.view.setFocus()

        def disconnect_if_open(self):
            if self.reader_thread:
                self.reader_thread.stop()
                self.reader_thread = None
            if self.serial_inst:
                try:
                    if self.serial_inst.is_open:
                        self.serial_inst.close()
                except Exception:
                    pass
                self.serial_inst = None
            self.btn_connect.setText("🔌 Connect")
            self.btn_connect.setStyleSheet("")
            self._close_log()

        def handle_serial_error(self, err_msg):
            self.disconnect_if_open()
            self._append_system(f"[HARDWARE ERROR] {err_msg}")

        # ---------- data in / out ----------
        def feed_data(self, data):
            if self.log_file:
                try:
                    self.log_file.write(data)
                    self.log_file.flush()
                except Exception:
                    pass
            if self.stream is not None:
                try:
                    self.stream.feed(data)
                except Exception:
                    pass
            else:
                self._fallback_append(data)
            self._dirty = True

        def write_bytes(self, data):
            if not self.is_connected():
                return
            try:
                self.serial_inst.write(data)
            except Exception as e:
                self.handle_serial_error(str(e))
                return
            if self.chk_echo.isChecked() and data:
                self.feed_data(data)

        def handle_key(self, event):
            if not self.is_connected():
                return False
            key, text, mods = event.key(), event.text(), event.modifiers()
            data = None
            if mods & Qt.ControlModifier and Qt.Key_A <= key <= Qt.Key_Z:
                data = bytes([key - Qt.Key_A + 1])
            elif key in EmbeddedTerminalWidget.ARROW_SEQUENCES:
                data = EmbeddedTerminalWidget.ARROW_SEQUENCES[key]
            elif key in (Qt.Key_Return, Qt.Key_Enter):
                data = self._newline_bytes()
            elif key == Qt.Key_Backspace:
                data = b"\x08"
            elif key == Qt.Key_Tab:
                data = b"\t"
            elif key == Qt.Key_Escape:
                data = b"\x1b"
            elif text:
                data = text.encode("utf-8", errors="ignore")
            if data is None:
                return False
            self.write_bytes(data)
            return True

        def send_command(self):
            cmd = self.cmd_input.text()
            if not self.is_connected():
                self._append_system("Not connected.")
                return
            self.write_bytes(cmd.encode("utf-8", errors="ignore") + self._newline_bytes())
            if cmd:
                self._history.append(cmd)
                self._history_idx = len(self._history)
            self.cmd_input.clear()

        def eventFilter(self, obj, event):
            if obj is self.cmd_input and event.type() == QtCore.QEvent.KeyPress:
                if event.key() == Qt.Key_Up and self._history:
                    self._history_idx = max(0, self._history_idx - 1)
                    self.cmd_input.setText(self._history[self._history_idx])
                    return True
                if event.key() == Qt.Key_Down and self._history:
                    self._history_idx = min(len(self._history), self._history_idx + 1)
                    self.cmd_input.setText(self._history[self._history_idx] if self._history_idx < len(self._history) else "")
                    return True
            return super().eventFilter(obj, event)

        # ---------- logging ----------
        def toggle_log(self):
            if self.btn_log.isChecked():
                path, _ = QFileDialog.getSaveFileName(self, "Save session log", "serial_session.log",
                                                      "Log files (*.log *.txt);;All Files (*)")
                if not path:
                    self.btn_log.setChecked(False)
                    return
                try:
                    self.log_file = open(path, "ab")
                    self.btn_log.setText("📝 Log: On")
                    self._append_system(f"Logging raw session to: {path}")
                except Exception as e:
                    self.btn_log.setChecked(False)
                    self._append_system(f"Could not open log file: {e}")
            else:
                self._close_log()

        def _close_log(self):
            if self.log_file:
                try:
                    self.log_file.close()
                except Exception:
                    pass
                self.log_file = None
            self.btn_log.setChecked(False)
            self.btn_log.setText("📝 Log: Off")

        # ---------- screen / rendering ----------
        def _reset_screen(self):
            if self.screen is not None:
                self.screen.reset()
            else:
                self.view.clear()

        def clear_screen(self):
            if self.screen is not None:
                self.screen.reset()
                self._dirty = True
            self.view.clear()

        def resize_grid(self):
            if self.screen is None:
                return
            fm = QtGui.QFontMetricsF(self.view.font())
            cw = fm.horizontalAdvance("M") or 8.0
            ch = fm.lineSpacing() or 14.0
            vp = self.view.viewport().size()
            cols = max(20, int(vp.width() / cw) - 1)
            rows = max(10, int(vp.height() / ch))
            if cols != self.screen.columns or rows != self.screen.lines:
                try:
                    self.screen.resize(rows, cols)
                    self._dirty = True
                except Exception:
                    pass

        def _render_if_dirty(self):
            if self._dirty and self.screen is not None:
                self._dirty = False
                try:
                    self._render_screen()
                except Exception:
                    pass

        def _render_screen(self):
            screen = self.screen
            cursor = screen.cursor
            rows_html = []
            for y in range(screen.lines):
                buffer_row = screen.buffer[y]
                parts = []
                run_chars = []
                run_style = None
                for x in range(screen.columns):
                    cell = buffer_row[x]
                    ch = cell.data or " "
                    fg = _term_color(cell.fg, TERM_DEFAULT_FG)
                    bg = _term_color(cell.bg, TERM_DEFAULT_BG)
                    if cell.reverse:
                        fg, bg = bg, fg
                    if not cursor.hidden and y == cursor.y and x == cursor.x:
                        fg, bg = TERM_DEFAULT_BG, TERM_CURSOR_BG
                    style = (fg, bg, bool(cell.bold), bool(cell.underscore))
                    if style != run_style and run_chars:
                        parts.append(self._span(run_style, "".join(run_chars)))
                        run_chars = []
                    run_style = style
                    run_chars.append(html.escape(ch))
                if run_chars:
                    parts.append(self._span(run_style, "".join(run_chars)))
                rows_html.append("".join(parts))
            doc = (
                '<pre style="margin:0;font-family:Consolas,\'Courier New\',monospace;'
                f'font-size:11pt;line-height:1.05;color:{TERM_DEFAULT_FG};'
                f'background:{TERM_DEFAULT_BG};">' + "\n".join(rows_html) + "</pre>"
            )
            self.view.setHtml(doc)

        @staticmethod
        def _span(style, text):
            fg, bg, bold, underscore = style
            css = f"color:{fg};background-color:{bg};"
            if bold:
                css += "font-weight:bold;"
            if underscore:
                css += "text-decoration:underline;"
            return f'<span style="{css}">{text}</span>'

        def _fallback_append(self, data):
            text = data.decode("utf-8", errors="replace")
            text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text)
            text = text.replace("\r", "")
            cursor = self.view.textCursor()
            cursor.movePosition(QtGui.QTextCursor.End)
            cursor.insertText(text)
            self.view.setTextCursor(cursor)
            self.view.ensureCursorVisible()

        def _append_system(self, msg):
            if self.screen is not None:
                self.feed_data(f"\r\n[SYSTEM] {msg}\r\n".encode())
            else:
                self.view.append(f"[SYSTEM] {msg}")



# ==============================================================================
# SECTION 7: VERTICAL DEVICE DETAILS & FLASH WIZARD DIALOGS
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

    class InteractiveFlashDialog(QDialog):
        def __init__(self, selected_device=None, parent=None, operation="UPGRADE"):
            super().__init__(parent)
            self.selected_device = selected_device or {}
            self.operation = operation
            self.selected_method = None
            self.selected_protocol = None
            self.setWindowTitle(f"Firmware Operation - {operation.title()}")
            self.setMinimumWidth(540)
            self.setStyleSheet("background-color: #2c3e50; color: #ecf0f1; font-family: Segoe UI;")
            self.setup_ui()

        def setup_ui(self):
            layout = QVBoxLayout(self)
            title = QLabel(f"⚙️ {self.operation.title()} Firmware")
            title.setStyleSheet("font-size: 17px; font-weight: bold; color: #3498db;")
            layout.addWidget(title)

            target = QLabel(
                f"Target IP: <b>{self.selected_device.get('ip', 'N/A')}</b><br>"
                f"Vendor: <b>{self.selected_device.get('vendor', 'Unknown')}</b><br>"
                f"Model: <b>{self.selected_device.get('model', 'Unknown')}</b>"
            )
            target.setWordWrap(True)
            layout.addWidget(target)

            group = QGroupBox("Connection / Transfer Method")
            gl = QVBoxLayout(group)
            self.rad_tftp = QRadioButton("TFTP — REAL file transfer / recovery")
            self.rad_serial = QRadioButton("UART / Serial — REAL bootloader interrupt")
            self.rad_ssh = QRadioButton("SSH — model-specific install command required")
            self.rad_http = QRadioButton("HTTP — model-specific firmware API required")
            self.rad_tftp.setChecked(True)
            for r in (self.rad_tftp, self.rad_serial, self.rad_ssh, self.rad_http):
                gl.addWidget(r)
            layout.addWidget(group)

            self.info = QLabel()
            self.info.setWordWrap(True)
            self.info.setStyleSheet("background-color: #34495e; padding: 8px;")
            layout.addWidget(self.info)
            for r in (self.rad_tftp, self.rad_serial, self.rad_ssh, self.rad_http):
                r.toggled.connect(self.update_info)
            self.update_info()

            row = QHBoxLayout()
            cancel = QPushButton("Cancel")
            proceed = QPushButton("Proceed")
            proceed.setStyleSheet("background-color: #c0392b; color: white; font-weight: bold; padding: 10px;")
            cancel.clicked.connect(self.reject)
            proceed.clicked.connect(self.accept_choices)
            row.addWidget(cancel)
            row.addWidget(proceed)
            layout.addLayout(row)

        def update_info(self):
            if self.rad_tftp.isChecked():
                self.info.setText(
                    "REAL ACTION: transfer the selected firmware file with TFTP. "
                    "The router must already be in the correct TFTP/recovery mode and may require a specific filename."
                )
            elif self.rad_serial.isChecked():
                self.info.setText(
                    "REAL ACTION: open UART and send Ctrl+C to the bootloader. "
                    "The generic program will stop before writing firmware because the write command is model-specific."
                )
            elif self.rad_ssh.isChecked():
                self.info.setText(
                    "SSH is only a transport. Firmware installation commands differ by vendor/model, so generic flashing is blocked."
                )
            else:
                self.info.setText(
                    "HTTP firmware update APIs differ by vendor/model. Generic flashing is blocked to prevent corruption."
                )

        def accept_choices(self):
            if self.rad_tftp.isChecked():
                self.selected_method, self.selected_protocol = "NETWORK", "TFTP"
            elif self.rad_serial.isChecked():
                self.selected_method, self.selected_protocol = "SERIAL", "UART"
            elif self.rad_ssh.isChecked():
                self.selected_method, self.selected_protocol = "NETWORK", "SSH"
            else:
                self.selected_method, self.selected_protocol = "NETWORK", "HTTP"

            if self.operation == "DELETE":
                answer = QMessageBox.warning(
                    self, "Dangerous Operation",
                    "DELETE is potentially destructive. This generic version will validate the operation "
                    "but will not execute a device-specific delete command without an exact model profile.\n\nContinue?",
                    QMessageBox.Yes | QMessageBox.No
                )
                if answer != QMessageBox.Yes:
                    return
            self.accept()

    class AuthExtractDialog(QDialog):
        """Collects credentials for an authenticated, no-hardware SSH/SFTP extraction."""
        def __init__(self, device=None, parent=None):
            super().__init__(parent)
            self.device = device or {}
            self.result_config = None
            self.setWindowTitle("Extract Firmware over SSH (no hardware, authenticated)")
            self.setMinimumWidth(560)
            self.setup_ui()

        def setup_ui(self):
            layout = QVBoxLayout(self)

            title = QLabel("🔐 Authenticated Firmware Extraction (SSH / SFTP)")
            title.setStyleSheet("font-size: 16px; font-weight: bold; color: #3498db;")
            layout.addWidget(title)

            notice = QLabel(
                "For devices you own or administer only. You must provide valid credentials. "
                "This does <b>not</b> bypass authentication, brute-force, or exploit the device — "
                "it logs in normally and reads what your account is already allowed to read "
                "(dumping a flash/MTD partition usually needs the <b>root</b> account)."
            )
            notice.setWordWrap(True)
            notice.setStyleSheet("background-color: #34495e; color: #ecf0f1; padding: 8px; border-radius: 4px;")
            layout.addWidget(notice)

            form = QFormLayout()
            self.in_host = QLineEdit(str(self.device.get('ip', '')))
            self.in_port = QLineEdit("22")
            self.in_user = QLineEdit("root")
            self.in_pass = QLineEdit()
            self.in_pass.setEchoMode(QLineEdit.Password)
            key_row = QHBoxLayout()
            self.in_key = QLineEdit()
            self.in_key.setPlaceholderText("Optional private key file (leave empty to use password)")
            btn_key = QPushButton("📁")
            btn_key.setMaximumWidth(40)
            btn_key.clicked.connect(self._browse_key)
            key_row.addWidget(self.in_key)
            key_row.addWidget(btn_key)
            key_wrap = QWidget()
            key_wrap.setLayout(key_row)
            key_row.setContentsMargins(0, 0, 0, 0)

            form.addRow("Host / IP:", self.in_host)
            form.addRow("Port:", self.in_port)
            form.addRow("Username:", self.in_user)
            form.addRow("Password:", self.in_pass)
            form.addRow("Private key:", key_wrap)
            layout.addLayout(form)

            method_box = QGroupBox("What to do")
            ml = QVBoxLayout(method_box)
            self.rad_list = QRadioButton("1) List flash partitions (safe, read-only — run this first)")
            self.rad_dump = QRadioButton("2) Dump a partition / run a command and save the output")
            self.rad_sftp = QRadioButton("3) Download an existing file via SFTP")
            self.rad_list.setChecked(True)
            for r in (self.rad_list, self.rad_dump, self.rad_sftp):
                ml.addWidget(r)

            self.in_command = QLineEdit("cat /dev/mtd0")
            self.in_command.setToolTip("Example: cat /dev/mtd0  |  dd if=/dev/mtdblock0 bs=65536  |  sysupgrade -b -")
            self.in_remote = QLineEdit("/tmp/backup.tar.gz")
            ml.addWidget(QLabel("Command (for option 2):"))
            ml.addWidget(self.in_command)
            ml.addWidget(QLabel("Remote file path (for option 3):"))
            ml.addWidget(self.in_remote)
            layout.addWidget(method_box)

            row = QHBoxLayout()
            cancel = QPushButton("Cancel")
            run = QPushButton("Connect & Extract")
            run.setStyleSheet("background-color: #c0392b; color: white; font-weight: bold; padding: 10px;")
            cancel.clicked.connect(self.reject)
            run.clicked.connect(self._accept)
            row.addWidget(cancel)
            row.addWidget(run)
            layout.addLayout(row)

        def _browse_key(self):
            path, _ = QFileDialog.getOpenFileName(self, "Select private key file", "", "All Files (*)")
            if path:
                self.in_key.setText(path)

        def _collect_fields(self):
            if self.rad_list.isChecked():
                method = 'list'
            elif self.rad_dump.isChecked():
                method = 'exec'
            else:
                method = 'sftp'
            return {
                'host': self.in_host.text(),
                'port': self.in_port.text(),
                'user': self.in_user.text(),
                'password': self.in_pass.text(),
                'key_file': self.in_key.text(),
                'method': method,
                'command': self.in_command.text(),
                'remote': self.in_remote.text(),
            }

        def _accept(self):
            fields = self._collect_fields()
            out_dir = os.path.join(os.getcwd(), "extracted_firmware")
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            cfg, error = build_extract_config(fields, out_dir, stamp)
            if error:
                QMessageBox.warning(self, "Cannot continue", error)
                return
            if cfg.get('out_path'):
                os.makedirs(out_dir, exist_ok=True)
            self.result_config = cfg
            self.accept()

# ==============================================================================
# SECTION 8: MAIN GUI APPLICATION
# ==============================================================================
if HAS_PYQT:
    class UniversalFirmwareManagerGUI(QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("Universal Firmware Manager & Flasher v15.0")
            self.resize(1300, 750)
            self.selected_device = None
            self.firmware_file_path = None
            self.firmware_compatibility = "none"
            self.download_worker = None
            self.scan_worker = None
            self.worker = None
            self.ssh_worker = None
            self.nmap_worker = None
            self.setup_ui()
            
            self.usb_timer = QTimer(self)
            self.usb_timer.timeout.connect(self.check_usb_serial_status)
            self.usb_timer.start(2000)
            self.update_action_buttons_state() 

        def update_action_buttons_state(self):
            has_device = self.selected_device is not None
            has_firmware = self.firmware_file_path is not None and self.firmware_compatibility != "incompatible"

            self.btn_backup.setEnabled(has_device)
            self.btn_backup.setToolTip(
                "Save a device information report."
                if has_device else "Select a device in Tab 1 first.")
            self.btn_delete.setEnabled(False)
            self.btn_delete.setToolTip("Disabled in the universal build: deletion is device/bootloader specific and potentially destructive.")

            if not has_device:
                fw_tip = "Select a device in Tab 1 first."
            elif self.firmware_file_path is None:
                fw_tip = "Load a firmware file in Tab 5 (Browse or Download) to enable this."
            elif self.firmware_compatibility == "incompatible":
                fw_tip = "The loaded firmware looks incompatible with the selected device."
            else:
                fw_tip = "Ready: opens the transfer-method dialog (TFTP / UART / SSH / HTTP)."
            for btn in (self.btn_upgrade, self.btn_downgrade, self.btn_restore):
                btn.setEnabled(has_device and has_firmware)
                btn.setToolTip(fw_tip)

            self.btn_dump_rom.setEnabled(has_device)
            self.btn_dump_rom.setToolTip(
                "Extract firmware over serial/UART from the selected device."
                if has_device else "Select a device in Tab 1 first.")

            ssh_ok = has_device and HAS_PARAMIKO
            self.btn_ssh_extract.setEnabled(ssh_ok)
            if not has_device:
                self.btn_ssh_extract.setToolTip("Select a device in Tab 1 first.")
            elif not HAS_PARAMIKO:
                self.btn_ssh_extract.setToolTip("Install 'paramiko' to enable SSH extraction: python -m pip install paramiko")
            else:
                self.btn_ssh_extract.setToolTip("Log in with your credentials and dump firmware — no hardware needed.")

            self.btn_audit.setEnabled(has_device)
            self.btn_nmap.setEnabled(has_device and nmap_available())
            if not nmap_available():
                self.btn_nmap.setToolTip("Install nmap (https://nmap.org) to enable active scanning.")
            elif not has_device:
                self.btn_nmap.setToolTip("Select a device in Tab 1 first.")
            else:
                self.btn_nmap.setToolTip("Active nmap scan of the selected device. Authorized use only.")

            gray = "background-color: #7f8c8d; color: #bdc3c7; font-weight: bold; padding: 12px;"
            if has_device:
                self.btn_backup.setStyleSheet("background-color: #2980b9; color: white; font-weight: bold; padding: 12px;")
                self.btn_dump_rom.setStyleSheet("background-color: #d35400; color: white; font-weight: bold; padding: 15px;")
            else:
                self.btn_backup.setStyleSheet(gray)
                self.btn_dump_rom.setStyleSheet("background-color: #7f8c8d; color: #bdc3c7; font-weight: bold; padding: 15px;")

            if has_firmware:
                for btn in (self.btn_upgrade, self.btn_downgrade, self.btn_restore):
                    btn.setStyleSheet("background-color: #c0392b; color: white; font-weight: bold; padding: 10px;")
                self.lbl_flash_req.setText("Firmware loaded. Upgrade / Downgrade / Restore are available.")
                self.lbl_flash_req.setStyleSheet("color: #27ae60; font-weight: bold;")
            else:
                for btn in (self.btn_upgrade, self.btn_downgrade, self.btn_restore):
                    btn.setStyleSheet(gray)
                self.lbl_flash_req.setText("⚠️ Load firmware from Tab 5 before Upgrade / Downgrade / Restore.")
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
            self.txt_subnet.setToolTip("Enter the first three octets, e.g. 192.168.1")
            self.btn_my_ip = QPushButton("🎯 Subnet")
            self.btn_scan = QPushButton("🔍 Network Scan")
            ctrl.addWidget(QLabel("Subnet:"))
            ctrl.addWidget(self.txt_subnet)
            ctrl.addWidget(self.btn_my_ip)
            ctrl.addWidget(self.btn_scan)
            ctrl.addStretch() 
            t1_layout.addLayout(ctrl)

            self.tbl_devices = QTableWidget(0, 9)
            self.tbl_devices.setHorizontalHeaderLabels(["Status", "IP", "MAC", "Ports", "Type", "Vendor", "Model", "Web Title", "Actions"])
            
            header = self.tbl_devices.horizontalHeader()
            # Make every column the same width and fill the entire table/form.
            # No column is wider or narrower than another.
            header.setSectionResizeMode(QHeaderView.Stretch)
            

            self.tbl_devices.setSelectionBehavior(QTableWidget.SelectRows)
            t1_layout.addWidget(self.tbl_devices)
            
            self.lbl_usb_status = QLabel("USB Serial Adapter Status: Checking...")
            t1_layout.addWidget(self.lbl_usb_status)
            self.tabs.addTab(t1, "1. Device Discovery")

            # --- TAB 2: Firmware Management
            t_flash = QWidget()
            t_flash_layout = QVBoxLayout(t_flash)

            intro = QLabel(
                "<b>Firmware Management</b><br>"
                "Select the operation you want to perform. The tool will only report success when a real supported action completed."
            )
            intro.setWordWrap(True)
            t_flash_layout.addWidget(intro)

            btn_lay = QHBoxLayout()
            self.btn_upgrade = QPushButton("⬆ Upgrade")
            self.btn_downgrade = QPushButton("⬇ Downgrade")
            self.btn_restore = QPushButton("♻ Restore")
            self.btn_backup = QPushButton("📋 Device Report")
            self.btn_delete = QPushButton("🗑 Delete (Model-Specific)")
            for b in (self.btn_upgrade, self.btn_downgrade, self.btn_restore, self.btn_backup, self.btn_delete):
                btn_lay.addWidget(b)
            t_flash_layout.addLayout(btn_lay)

            self.lbl_flash_req = QLabel("")
            self.lbl_flash_req.setAlignment(Qt.AlignCenter)
            self.lbl_flash_req.setWordWrap(True)
            t_flash_layout.addWidget(self.lbl_flash_req)
            self.tabs.addTab(t_flash, "2. Firmware Management")

            # --- TAB 3: Terminal ---
            self.tab_terminal = EmbeddedTerminalWidget(main_gui=self)
            self.tabs.addTab(self.tab_terminal, "3. Serial Console")

            # --- TAB 4: Live Extractor ---
            t_ext = QWidget()
            t_ext_layout = QVBoxLayout(t_ext)

            ext_intro = QLabel(
                "<b>Firmware Extraction</b><br>"
                "Choose a method. Extraction only works on a device you own or administer, "
                "with either physical access (serial) or valid login credentials (SSH)."
            )
            ext_intro.setWordWrap(True)
            t_ext_layout.addWidget(ext_intro)

            ssh_box = QGroupBox("A. No-hardware extraction over SSH / SFTP (authenticated)")
            ssh_l = QVBoxLayout(ssh_box)
            ssh_desc = QLabel(
                "Log in to the selected device with your own credentials and dump a flash/MTD "
                "partition (e.g. <code>cat /dev/mtd0</code>) or download a backup — no cable or "
                "adapter needed. Requires valid credentials; it does not bypass device security."
            )
            ssh_desc.setWordWrap(True)
            self.btn_ssh_extract = QPushButton("🔐 EXTRACT FIRMWARE VIA SSH (No Hardware)")
            self.btn_ssh_extract.setStyleSheet("background-color: #16a085; color: white; font-weight: bold; padding: 14px;")
            ssh_l.addWidget(ssh_desc)
            ssh_l.addWidget(self.btn_ssh_extract)
            t_ext_layout.addWidget(ssh_box)

            serial_box = QGroupBox("B. Physical extraction over Serial / UART")
            serial_l = QVBoxLayout(serial_box)
            serial_desc = QLabel(
                "Uses a USB-to-UART adapter wired to the board. Opens the bootloader for inspection; "
                "a full ROM dump still needs the exact flash/memory map for the model."
            )
            serial_desc.setWordWrap(True)
            self.btn_dump_rom = QPushButton("📥 EXTRACT FULL FIRMWARE ROM (Via Serial)")
            serial_l.addWidget(serial_desc)
            serial_l.addWidget(self.btn_dump_rom)
            t_ext_layout.addWidget(serial_box)
            t_ext_layout.addStretch()
            self.tabs.addTab(t_ext, "4. Live Firmware Extractor")

            # --- TAB 5: Firmware Selection & URL DOWNLOADER ---
            t_fw = QWidget()
            t_fw_layout = QVBoxLayout(t_fw)
            
            f_box = QGroupBox("A. Local Firmware Selection")
            f_lay = QHBoxLayout(f_box)
            self.txt_file = QLineEdit()
            self.txt_file.setPlaceholderText("Browse for local .bin or .tar file...")
            self.btn_browse = QPushButton("📁 Browse File...")
            f_lay.addWidget(self.txt_file)
            f_lay.addWidget(self.btn_browse)
            
            u_box = QGroupBox("B. Internet Firmware Downloader (Direct URL)")
            u_lay = QHBoxLayout(u_box)
            self.txt_url = QLineEdit()
            self.txt_url.setPlaceholderText("🌐 Paste a direct HTTPS firmware link...")
            self.btn_download = QPushButton("⬇️ Download & Verify")
            u_lay.addWidget(self.txt_url)
            u_lay.addWidget(self.btn_download)

            t_fw_layout.addWidget(f_box)
            t_fw_layout.addWidget(u_box)
            
            self.lbl_info = QLabel("Status: No Firmware Loaded ❌")
            self.txt_hashes = QTextEdit()
            t_fw_layout.addWidget(self.lbl_info)
            t_fw_layout.addWidget(self.txt_hashes)
            self.tabs.addTab(t_fw, "5. Firmware Selection & Verify")

            # --- TAB 6: Report + Security Audit ---
            t_rep = QWidget()
            t_rep_layout = QVBoxLayout(t_rep)

            audit_row = QHBoxLayout()
            self.btn_audit = QPushButton("🛡 Security Audit (passive, local)")
            self.btn_audit.setToolTip("Review the selected device's scan data for risky exposed services. No packets are sent.")
            self.btn_nmap = QPushButton("🔎 nmap Service/Vuln Scan (authorized)")
            self.btn_nmap.setToolTip("Active scan of the selected device using nmap. Only for devices you are authorized to test.")
            self.chk_nmap_vuln = QCheckBox("include vuln scripts")
            audit_row.addWidget(self.btn_audit)
            audit_row.addWidget(self.btn_nmap)
            audit_row.addWidget(self.chk_nmap_vuln)
            audit_row.addStretch()
            t_rep_layout.addLayout(audit_row)

            self.txt_report = QTextEdit()
            self.txt_report.setReadOnly(True)
            t_rep_layout.addWidget(self.txt_report)
            self.tabs.addTab(t_rep, "6. Intelligence & Security")

            # --- SYSTEM LOGS ---
            log_box = QGroupBox("System Logs & Progress")
            log_layout = QVBoxLayout(log_box)
            self.txt_log = QTextEdit()
            self.txt_log.setReadOnly(True)
            self.txt_log.setStyleSheet("background-color: #111; color: #0f0; font-family: Consolas;")
            self.progress = QProgressBar()
            log_layout.addWidget(self.txt_log)
            log_layout.addWidget(self.progress)

            self.splitter.addWidget(self.tabs)
            self.splitter.addWidget(log_box)
            layout.addWidget(self.splitter)

            # Signal Connections
            self.btn_my_ip.clicked.connect(self.get_local_subnet)
            self.btn_scan.clicked.connect(self.start_scan)
            self.btn_browse.clicked.connect(self.browse_firmware)
            self.btn_download.clicked.connect(self.download_url)
            self.txt_url.returnPressed.connect(self.download_url)
            self.btn_upgrade.clicked.connect(lambda: self.run_firmware_operation("UPGRADE"))
            self.btn_downgrade.clicked.connect(lambda: self.run_firmware_operation("DOWNGRADE"))
            self.btn_restore.clicked.connect(lambda: self.run_firmware_operation("RESTORE"))
            self.btn_backup.clicked.connect(self.run_backup)
            self.btn_delete.clicked.connect(lambda: self.run_firmware_operation("DELETE"))
            self.btn_dump_rom.clicked.connect(self.run_extract_firmware)
            self.btn_ssh_extract.clicked.connect(self.run_ssh_extract)
            self.btn_audit.clicked.connect(self.run_security_audit)
            self.btn_nmap.clicked.connect(self.run_nmap_scan)

            self.tab_terminal.refresh_ports()

        def get_local_subnet(self):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
                s.close()
                self.txt_subnet.setText(".".join(ip.split('.')[:3]))
            except Exception:
                pass

        def check_usb_serial_status(self):
            ports = []
            if HAS_SERIAL:
                try:
                    ports = [p.device for p in serial.tools.list_ports.comports()]
                except Exception:
                    pass
            if ports:
                self.lbl_usb_status.setText(f"🔌 Serial Adapter: CONNECTED — {', '.join(ports)}")
                self.lbl_usb_status.setStyleSheet("background-color: #006266; color: #55efc4; font-weight: bold; padding: 6px;")
            else:
                self.lbl_usb_status.setText("🔌 Serial Adapter: DISCONNECTED")
                self.lbl_usb_status.setStyleSheet("background-color: #2d3436; color: #b2bec3; font-weight: bold; padding: 6px;")

        def log(self, msg):
            self.txt_log.append(f"[{time.strftime('%H:%M:%S')}] {msg}")
            self.txt_log.moveCursor(QtGui.QTextCursor.End)

        def start_scan(self):
            self.btn_scan.setEnabled(False)
            self.tbl_devices.setRowCount(0)
            subnet = self.txt_subnet.text().strip()
            if not validate_subnet_prefix(subnet):
                QMessageBox.warning(self, "Invalid Subnet", "Enter a valid subnet prefix such as 192.168.1")
                self.btn_scan.setEnabled(True)
                return
            self.log(f"Initiating Fast Parallel Scan on [{subnet}.0/24]...")
            self.progress.setValue(0)
            
            self.scan_worker = NetworkScannerWorker(subnet)
            self.scan_worker.devices_found_signal.connect(self.display_devices)
            self.scan_worker.progress_signal.connect(self.progress.setValue)
            self.scan_worker.start()

        @QtCore.pyqtSlot(list)
        def display_devices(self, devices):
            self.btn_scan.setEnabled(True)
            self.progress.setValue(100)
            
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

                w = QWidget()
                l = QHBoxLayout(w)
                l.setContentsMargins(0, 0, 0, 0)
                l.addWidget(btn_select)
                l.addWidget(btn_specs)
                self.tbl_devices.setCellWidget(row, 8, w)

        def select_device_action(self, dev):
            self.selected_device = dev
            self.firmware_compatibility = "unknown" if self.firmware_file_path else "none"
            self.log(f"Target Selected: {dev['vendor']} ({dev['ip']})")
            self.txt_report.setText(
                f"Target IP: {dev.get('ip', 'N/A')}\n"
                f"MAC: {dev.get('mac', 'N/A')}\n"
                f"Vendor: {dev.get('vendor', 'Unknown')}\n"
                f"Type: {dev.get('type', 'Unknown')}\n"
                f"Model: {dev.get('model', 'Unknown')}\n"
                f"Ports: {dev.get('ports', 'Unknown')}\n"
                f"Web Title: {dev.get('title', 'N/A')}"
            )
            if self.firmware_file_path:
                self.verify_firmware(self.firmware_file_path)
            self.update_action_buttons_state()

        def verify_firmware(self, path):
            try:
                info = FirmwareAnalyzer.inspect_file(path)
                self.firmware_compatibility = "unknown"
                self.lbl_info.setText(f"Status: Firmware Loaded ✅ ({info['filename']})")
                self.lbl_info.setStyleSheet("font-weight: bold; color: #27ae60;")
                self.txt_hashes.setText(
                    f"Type: {info['type']}\nSize: {info['size_mb']} MB\n"
                    f"MD5: {info['md5']}\nSHA256: {info['sha256']}"
                )
                self.log(f"Firmware Analyzed: {info['filename']} | {info['type']} | SHA256 {info['sha256']}")

                if self.selected_device:
                    vendor = self.selected_device.get('vendor', '').lower()
                    model = self.selected_device.get('model', '').lower()
                    filename = info['filename'].lower()
                    combined = f"{vendor} {model} {filename}"
                    known_vendor_tokens = ["cisco", "ubiquiti", "mikrotik", "tplink", "tp-link", "fortinet", "openwrt", "dahua", "hikvision"]
                    selected_known = next((x for x in known_vendor_tokens if x in vendor or x in model), None)
                    # A filename match is not enough to prove exact model/hardware revision.
                    # The universal build therefore never upgrades an image to "compatible" from
                    # a filename alone. It only blocks an obvious vendor contradiction.
                    other_known = [x for x in known_vendor_tokens if x in filename and x != selected_known]
                    if selected_known and other_known and selected_known not in filename:
                        self.firmware_compatibility = "incompatible"

                if self.firmware_compatibility == "incompatible":
                    self.log("BLOCKED: Firmware filename does not match the detected vendor/model.")
                    self.lbl_info.setText("Status: Firmware appears INCOMPATIBLE ❌")
                    self.lbl_info.setStyleSheet("font-weight: bold; color: #e74c3c;")
                elif self.firmware_compatibility == "unknown":
                    self.log("Compatibility: UNKNOWN — exact device/firmware match could not be proven automatically.")
                    self.lbl_info.setText(f"Status: Firmware verified, compatibility UNKNOWN ⚠️ ({info['filename']})")
                    self.lbl_info.setStyleSheet("font-weight: bold; color: #e67e22;")
                else:
                    self.log("Compatibility: no trusted exact model/hardware profile is available; status remains UNKNOWN.")
                self.update_action_buttons_state()
            except Exception as e:
                self.firmware_compatibility = "none"
                self.log(f"Error parsing firmware: {e}")
                QMessageBox.critical(self, "Firmware Validation Error", str(e))

        def browse_firmware(self):
            path, _ = QFileDialog.getOpenFileName(self, "Select Firmware File", "", "All Files (*)")
            if path:
                self.txt_file.setText(path)
                self.firmware_file_path = path
                self.verify_firmware(path)

        def download_url(self):
            url = self.txt_url.text().strip()
            parsed = urlparse(url)
            if parsed.scheme.lower() != "https" or not parsed.netloc:
                QMessageBox.warning(self, "Secure URL Required", "For firmware downloads, use a valid HTTPS direct-download URL.")
                return

            filename = sanitize_filename(os.path.basename(unquote(parsed.path)), "downloaded_firmware.bin")
            download_dir = os.path.join(os.getcwd(), "firmware_downloads")
            os.makedirs(download_dir, exist_ok=True)
            save_path = os.path.join(download_dir, filename)
            self.log(f"Starting secure firmware download: {url}")
            self.lbl_info.setText("Status: Downloading... ⏳")
            self.lbl_info.setStyleSheet("color: #e67e22; font-weight: bold;")
            self.btn_download.setEnabled(False)
            self.progress.setValue(0)

            self.download_worker = FirmwareDownloadWorker(url, save_path)
            self.download_worker.progress_signal.connect(self.progress.setValue)
            self.download_worker.log_signal.connect(self.log)
            self.download_worker.finished_signal.connect(self.on_download_finished)
            self.download_worker.start()

        def on_download_finished(self, success, path, message):
            self.btn_download.setEnabled(True)
            if success:
                self.txt_file.setText(path)
                self.firmware_file_path = path
                self.log(f"Download complete: {path}")
                self.verify_firmware(path)
            else:
                self.lbl_info.setText("Status: Download Failed ❌")
                self.lbl_info.setStyleSheet("color: #e74c3c; font-weight: bold;")
                QMessageBox.critical(self, "Download Failed", message)

        def execute_worker(self, operation, config=None):
            if hasattr(self, 'tab_terminal'):
                self.tab_terminal.disconnect_if_open()
            self.progress.setValue(0)

            cfg = dict(config or {})
            if self.selected_device:
                cfg.setdefault('ip', self.selected_device.get('ip', ''))
                cfg.setdefault('vendor', self.selected_device.get('vendor', 'Unknown'))
                cfg.setdefault('model', self.selected_device.get('model', 'Unknown'))

            self.worker = FlashingEngineWorker(operation, cfg, self.firmware_file_path)
            self.worker.log_signal.connect(self.log)
            self.worker.progress_signal.connect(self.progress.setValue)
            self.worker.finished_signal.connect(self.on_operation_finished)
            self.worker.start()

        def on_operation_finished(self, success, message):
            if success:
                QMessageBox.information(self, "Operation Result", message)
            else:
                QMessageBox.critical(self, "Operation Failed", message)
            self.update_action_buttons_state()

        def run_firmware_operation(self, operation):
            if not self.selected_device:
                QMessageBox.warning(self, "No Device", "Select a target device first.")
                return
            if operation in ("UPGRADE", "DOWNGRADE", "RESTORE") and not self.firmware_file_path:
                QMessageBox.warning(self, "No Firmware", "Load the firmware file first from Tab 5.")
                return
            if operation in ("UPGRADE", "DOWNGRADE", "RESTORE") and self.firmware_compatibility == "incompatible":
                QMessageBox.critical(self, "Firmware Blocked", "The selected firmware appears incompatible with the detected device. Choose a verified image before continuing.")
                return
            if operation in ("UPGRADE", "DOWNGRADE", "RESTORE") and self.firmware_compatibility != "compatible":
                answer = QMessageBox.warning(
                    self, "Compatibility Not Proven",
                    "The tool cannot automatically prove that this firmware is correct for this exact device.\n\n"
                    "Only continue if you have independently verified the exact model, hardware revision, and firmware source.",
                    QMessageBox.Yes | QMessageBox.No
                )
                if answer != QMessageBox.Yes:
                    return

            dlg = InteractiveFlashDialog(self.selected_device, self, operation)
            if dlg.exec_() != QDialog.Accepted:
                return

            config = {
                'method': dlg.selected_method,
                'protocol': dlg.selected_protocol,
                'ip': self.selected_device.get('ip', ''),
                'vendor': self.selected_device.get('vendor', 'Unknown'),
                'model': self.selected_device.get('model', 'Unknown')
            }
            if dlg.selected_protocol == "UART":
                ports = SerialScanner.scan_ports()
                if ports:
                    config['serial_port'] = ports[0]['port']

            self.log(f"Preparing REAL {operation} operation via {dlg.selected_protocol}...")
            self.execute_worker(operation, config)

        def run_backup(self):
            if not self.selected_device:
                QMessageBox.warning(self, "No Device", "Select a target device first.")
                return
            self.log("Creating a device information report (not a firmware/config backup).")
            self.execute_worker("BACKUP", {'ip': self.selected_device.get('ip', '')})

        def run_extract_firmware(self):
            self.execute_worker('EXTRACT_FIRMWARE')

        def run_ssh_extract(self):
            if not HAS_PARAMIKO:
                QMessageBox.critical(
                    self, "Missing dependency",
                    "SSH extraction needs the 'paramiko' library.\n\nInstall it with:\npython -m pip install paramiko")
                return
            if self.ssh_worker is not None and self.ssh_worker.isRunning():
                QMessageBox.information(self, "Busy", "An SSH extraction is already running.")
                return

            dlg = AuthExtractDialog(self.selected_device or {}, self)
            if dlg.exec_() != QDialog.Accepted or not dlg.result_config:
                return
            cfg = dlg.result_config

            if hasattr(self, 'tab_terminal'):
                self.tab_terminal.disconnect_if_open()
            self.progress.setValue(0)
            self.btn_ssh_extract.setEnabled(False)
            self.log(f"SSH extraction ({cfg['method']}) → {cfg['host']} as '{cfg['user']}'")

            self.ssh_worker = SSHExtractWorker(cfg)
            self.ssh_worker.log_signal.connect(self.log)
            self.ssh_worker.progress_signal.connect(self.progress.setValue)
            self.ssh_worker.finished_signal.connect(self.on_ssh_extract_finished)
            self.ssh_worker.start()

        def on_ssh_extract_finished(self, success, message):
            self.btn_ssh_extract.setEnabled(self.selected_device is not None)
            if not success:
                QMessageBox.critical(self, "SSH Extraction Failed", message)
                return
            QMessageBox.information(self, "SSH Extraction", message)
            # If an image file was produced, auto-load and verify it in Tab 5.
            path = (self.ssh_worker.config or {}).get('out_path') if self.ssh_worker else None
            if path and os.path.isfile(path) and os.path.getsize(path) > 0:
                self.txt_file.setText(path)
                self.firmware_file_path = path
                self.verify_firmware(path)
                self.tabs.setCurrentIndex(4)

        def run_security_audit(self):
            if not self.selected_device:
                QMessageBox.warning(self, "No Device", "Select a target device first.")
                return
            dev = self.selected_device
            findings = audit_device_security(dev)
            colors = {"HIGH": "#e74c3c", "MEDIUM": "#e67e22", "LOW": "#f1c40f", "INFO": "#3498db"}
            lines = [
                "<h3>🛡 Security Audit (passive)</h3>",
                f"<b>Target:</b> {dev.get('ip', 'N/A')} — {dev.get('vendor', 'Unknown')} "
                f"({dev.get('model', 'Unknown')})<br>",
                f"<b>Open ports:</b> {dev.get('ports', 'Unknown')}<br><br>",
            ]
            for f in findings:
                c = colors.get(f['severity'], "#ecf0f1")
                lines.append(
                    f"<p style='margin:4px 0;'><b style='color:{c};'>[{f['severity']}] {f['title']}</b><br>"
                    f"{f['detail']}</p>")
            lines.append(
                "<br><i>Passive review of scan data only — not a full vulnerability assessment. "
                "For an active scan, use the nmap button (authorized devices only).</i>")
            self.txt_report.setHtml("".join(lines))
            self.tabs.setCurrentIndex(5)
            self.log(f"Security audit complete for {dev.get('ip', 'N/A')} — {len(findings)} finding(s).")

        def run_nmap_scan(self):
            if not self.selected_device:
                QMessageBox.warning(self, "No Device", "Select a target device first.")
                return
            if not nmap_available():
                QMessageBox.critical(self, "nmap not found",
                                     "nmap is not installed or not on PATH.\nInstall it from https://nmap.org.")
                return
            if self.nmap_worker is not None and self.nmap_worker.isRunning():
                QMessageBox.information(self, "Busy", "An nmap scan is already running.")
                return
            ip = self.selected_device.get('ip', '')
            vuln = self.chk_nmap_vuln.isChecked()
            warn = (
                f"You are about to run an ACTIVE nmap scan against {ip}"
                + (" with vulnerability scripts" if vuln else "") + ".\n\n"
                "Only scan devices you own or are explicitly authorized to test. "
                "Unauthorized scanning may be illegal.\n\nProceed?"
            )
            if QMessageBox.question(self, "Authorized scan only", warn,
                                    QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
                return
            self.log(f"Starting nmap scan on {ip} (vuln={vuln}) ...")
            self.btn_nmap.setEnabled(False)
            self.nmap_worker = NmapWorker(ip, vuln=vuln)
            self.nmap_worker.log_signal.connect(self.log)
            self.nmap_worker.finished_signal.connect(self.on_nmap_finished)
            self.nmap_worker.start()

        def on_nmap_finished(self, success, output):
            self.btn_nmap.setEnabled(self.selected_device is not None and nmap_available())
            header = "🔎 nmap scan result\n\n" if success else "⚠️ nmap scan problem\n\n"
            self.txt_report.setPlainText(header + output)
            self.tabs.setCurrentIndex(5)
            if not success:
                QMessageBox.warning(self, "nmap", output[:500])

        def closeEvent(self, event):
            """Cleanly stop timers and background threads so the app exits without crashing."""
            try:
                self.usb_timer.stop()
            except Exception:
                pass
            if hasattr(self, 'tab_terminal'):
                try:
                    self.tab_terminal.disconnect_if_open()
                except Exception:
                    pass
            for attr in ('scan_worker', 'download_worker', 'worker', 'ssh_worker', 'nmap_worker'):
                w = getattr(self, attr, None)
                if w is not None and w.isRunning():
                    w.quit()
                    w.wait(2000)
            event.accept()


def run_self_test():
    """Run deterministic, non-destructive checks without opening the GUI or touching hardware."""
    import ast
    import tempfile

    source = os.path.abspath(__file__)
    with open(source, 'r', encoding='utf-8') as f:
        tree = ast.parse(f.read(), filename=source)
    assert isinstance(tree, ast.Module)

    with tempfile.TemporaryDirectory(prefix='ufm_selftest_') as tmp:
        sample = os.path.join(tmp, 'sample.bin')
        payload = b'HDR0' + bytes(range(256)) * 4
        with open(sample, 'wb') as f:
            f.write(payload)
        info = FirmwareAnalyzer.inspect_file(sample)
        assert info['type'] == 'TRX Firmware Image'
        assert info['size_bytes'] == len(payload)
        assert len(info['sha256']) == 64

        empty = os.path.join(tmp, 'empty.bin')
        open(empty, 'wb').close()
        try:
            FirmwareAnalyzer.inspect_file(empty)
        except ValueError:
            pass
        else:
            raise AssertionError('Empty firmware was not rejected')

        archive = os.path.join(tmp, 'sample.zip')
        with zipfile.ZipFile(archive, 'w') as zf:
            zf.writestr('manifest.txt', 'test')
        archive_info = FirmwareAnalyzer.inspect_file(archive)
        assert archive_info['type'] == 'ZIP Archive / Package'

    print('SELF-TEST PASSED')
    print('- Python AST parse: PASS')
    print('- Firmware hashing/type detection: PASS')
    print('- Empty firmware rejection: PASS')
    print('- ZIP detection: PASS')
    print('- No hardware/network write operation was performed.')


def apply_dark_theme(app):
    """Consistent Fusion-based dark theme across the whole application."""
    app.setStyle("Fusion")
    palette = QtGui.QPalette()
    palette.setColor(QtGui.QPalette.Window, QtGui.QColor("#1e2a36"))
    palette.setColor(QtGui.QPalette.WindowText, QtGui.QColor("#ecf0f1"))
    palette.setColor(QtGui.QPalette.Base, QtGui.QColor("#263544"))
    palette.setColor(QtGui.QPalette.AlternateBase, QtGui.QColor("#2c3e50"))
    palette.setColor(QtGui.QPalette.Text, QtGui.QColor("#ecf0f1"))
    palette.setColor(QtGui.QPalette.Button, QtGui.QColor("#34495e"))
    palette.setColor(QtGui.QPalette.ButtonText, QtGui.QColor("#ecf0f1"))
    palette.setColor(QtGui.QPalette.Highlight, QtGui.QColor("#2980b9"))
    palette.setColor(QtGui.QPalette.HighlightedText, QtGui.QColor("#ffffff"))
    palette.setColor(QtGui.QPalette.ToolTipBase, QtGui.QColor("#ecf0f1"))
    palette.setColor(QtGui.QPalette.ToolTipText, QtGui.QColor("#1e2a36"))
    palette.setColor(QtGui.QPalette.Disabled, QtGui.QPalette.ButtonText, QtGui.QColor("#7f8c8d"))
    palette.setColor(QtGui.QPalette.Disabled, QtGui.QPalette.Text, QtGui.QColor("#7f8c8d"))
    app.setPalette(palette)
    app.setStyleSheet("""
        QWidget { font-family: 'Segoe UI'; font-size: 13px; }
        QGroupBox {
            border: 1px solid #3d5366; border-radius: 6px;
            margin-top: 10px; padding-top: 8px; font-weight: bold;
        }
        QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 4px; color: #3498db; }
        QTabWidget::pane { border: 1px solid #3d5366; border-radius: 4px; }
        QTabBar::tab {
            background: #2c3e50; color: #bdc3c7; padding: 8px 16px;
            border-top-left-radius: 4px; border-top-right-radius: 4px; margin-right: 2px;
        }
        QTabBar::tab:selected { background: #2980b9; color: white; }
        QTabBar::tab:hover:!selected { background: #34495e; }
        QPushButton {
            background-color: #34495e; color: #ecf0f1; border: none;
            border-radius: 4px; padding: 7px 12px;
        }
        QPushButton:hover { background-color: #3d5366; }
        QPushButton:pressed { background-color: #2980b9; }
        QPushButton:disabled { background-color: #2c3e50; color: #7f8c8d; }
        QLineEdit, QComboBox {
            background-color: #263544; border: 1px solid #3d5366;
            border-radius: 4px; padding: 5px; color: #ecf0f1;
        }
        QLineEdit:focus, QComboBox:focus { border: 1px solid #2980b9; }
        QProgressBar {
            border: 1px solid #3d5366; border-radius: 4px; text-align: center;
            background-color: #263544; color: #ecf0f1;
        }
        QProgressBar::chunk { background-color: #27ae60; border-radius: 3px; }
        QTableWidget { gridline-color: #3d5366; background-color: #263544; }
        QHeaderView::section {
            background-color: #2c3e50; color: #ecf0f1; padding: 6px; border: none;
            border-right: 1px solid #3d5366;
        }
    """)


def main():
    if '--self-test' in sys.argv:
        run_self_test()
        return
    if not HAS_PYQT:
        print("PyQt5 is not installed. Install it with: python -m pip install PyQt5")
        return
    if HAS_PYQT:
        app = QApplication(sys.argv)
        apply_dark_theme(app)
        w = UniversalFirmwareManagerGUI()
        w.show()
        sys.exit(app.exec_())

if __name__ == '__main__':
    main()