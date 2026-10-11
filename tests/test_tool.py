#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test suite for Universal Firmware Flasher Tool.

Covers the pure helpers, firmware analysis, device fingerprinting, the SSH/nmap
workers' guard paths, and offscreen GUI construction. No real network device or
serial hardware is required; external effects are stubbed.

Run:  python -m unittest discover -s tests -v
"""
import os
import sys
import gzip
import tarfile
import zipfile
import hashlib
import tempfile
import importlib.util
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

# --- Load the single-file application as a module -----------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_SRC = os.path.join(_ROOT, "universal_firmware_flasher.py")
_spec = importlib.util.spec_from_file_location("ufm", _SRC)
ufm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ufm)


# ==============================================================================
# Pure helpers
# ==============================================================================
class TestSanitizeFilename(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(ufm.sanitize_filename("firmware.bin"), "firmware.bin")

    def test_strips_bad_chars(self):
        out = ufm.sanitize_filename("fw v2:final?.bin")
        self.assertNotIn(" ", out)
        self.assertTrue(out.endswith(".bin"))
        self.assertTrue(all(c.isalnum() or c in "._-" for c in out))

    def test_path_is_reduced_to_basename(self):
        self.assertEqual(ufm.sanitize_filename("/etc/passwd"), "passwd")

    def test_empty_uses_fallback(self):
        self.assertEqual(ufm.sanitize_filename("", "fb.bin"), "fb.bin")
        self.assertEqual(ufm.sanitize_filename(None, "fb.bin"), "fb.bin")

    def test_only_bad_chars_uses_fallback(self):
        self.assertEqual(ufm.sanitize_filename("///", "fb.bin"), "fb.bin")


class TestValidateSubnet(unittest.TestCase):
    def test_valid(self):
        for s in ("192.168.1", "10.0.0", "172.16.5", "8.8.8"):
            self.assertTrue(ufm.validate_subnet_prefix(s), s)

    def test_invalid(self):
        for s in ("192.168", "192.168.1.1", "999.1.1", "abc", "", "1.2.3.", "256.0.0"):
            self.assertFalse(ufm.validate_subnet_prefix(s), s)

    def test_whitespace_trimmed(self):
        self.assertTrue(ufm.validate_subnet_prefix("  192.168.1  "))


class TestBuildExtractConfig(unittest.TestCase):
    def _fields(self, **kw):
        base = {'host': '10.0.0.1', 'port': '22', 'user': 'root',
                'password': 'pw', 'key_file': '', 'method': 'list',
                'command': '', 'remote': ''}
        base.update(kw)
        return base

    def test_list_ok(self):
        cfg, err = ufm.build_extract_config(self._fields(method='list'), "/out", "20260101_000000")
        self.assertIsNone(err)
        self.assertEqual(cfg['method'], 'list')
        self.assertNotIn('out_path', cfg)

    def test_exec_ok(self):
        cfg, err = ufm.build_extract_config(
            self._fields(method='exec', command='cat /dev/mtd0'), "/out", "S")
        self.assertIsNone(err)
        self.assertEqual(cfg['command'], 'cat /dev/mtd0')
        self.assertTrue(cfg['out_path'].endswith("fw_10.0.0.1_S.bin"))

    def test_sftp_ok(self):
        cfg, err = ufm.build_extract_config(
            self._fields(method='sftp', remote='/tmp/backup.tar.gz'), "/out", "S")
        self.assertIsNone(err)
        self.assertEqual(cfg['source'], '/tmp/backup.tar.gz')
        self.assertTrue(cfg['out_path'].endswith("backup.tar.gz"))

    def test_missing_host(self):
        cfg, err = ufm.build_extract_config(self._fields(host=''), "/out", "S")
        self.assertIsNone(cfg)
        self.assertIn("Host", err)

    def test_missing_credentials(self):
        cfg, err = ufm.build_extract_config(self._fields(password='', key_file=''), "/out", "S")
        self.assertIsNone(cfg)
        self.assertIn("password", err.lower())

    def test_key_file_counts_as_credential(self):
        cfg, err = ufm.build_extract_config(
            self._fields(password='', key_file='/home/u/id_rsa'), "/out", "S")
        self.assertIsNone(err)
        self.assertEqual(cfg['key_file'], '/home/u/id_rsa')

    def test_missing_command(self):
        cfg, err = ufm.build_extract_config(self._fields(method='exec', command=''), "/out", "S")
        self.assertIsNone(cfg)
        self.assertIn("command", err.lower())

    def test_missing_remote(self):
        cfg, err = ufm.build_extract_config(self._fields(method='sftp', remote=''), "/out", "S")
        self.assertIsNone(cfg)

    def test_bad_port(self):
        cfg, err = ufm.build_extract_config(self._fields(port='abc'), "/out", "S")
        self.assertIsNone(cfg)
        self.assertIn("Port", err)

    def test_default_port(self):
        cfg, err = ufm.build_extract_config(self._fields(port=''), "/out", "S")
        self.assertEqual(cfg['port'], "22")


class TestSecurityAudit(unittest.TestCase):
    def test_telnet_high(self):
        f = ufm.audit_device_security({'ports': '23, 80'})
        self.assertTrue(any(x['severity'] == "HIGH" and "Telnet" in x['title'] for x in f))

    def test_ftp_medium(self):
        f = ufm.audit_device_security({'ports': '21'})
        self.assertTrue(any("FTP" in x['title'] for x in f))

    def test_http_without_https(self):
        f = ufm.audit_device_security({'ports': '80'})
        self.assertTrue(any("HTTPS" in x['title'] for x in f))

    def test_https_present_no_http_flag(self):
        f = ufm.audit_device_security({'ports': '80, 443'})
        self.assertFalse(any("without HTTPS" in x['title'] for x in f))

    def test_ssh_info(self):
        f = ufm.audit_device_security({'ports': '22'})
        self.assertTrue(any("SSH" in x['title'] for x in f))

    def test_camera_high(self):
        f = ufm.audit_device_security({'ports': '80', 'vendor': 'Hikvision', 'title': 'web'})
        self.assertTrue(any(x['severity'] == "HIGH" for x in f))

    def test_empty_returns_info(self):
        f = ufm.audit_device_security({'ports': 'Closed'})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]['severity'], "INFO")

    def test_sorted_high_first(self):
        f = ufm.audit_device_security({'ports': '22, 23'})
        order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
        sev = [order[x['severity']] for x in f]
        self.assertEqual(sev, sorted(sev))


class TestNmapHelpers(unittest.TestCase):
    def test_command_service(self):
        cmd = ufm.build_nmap_command("1.2.3.4")
        self.assertEqual(cmd[0], "nmap")
        self.assertIn("-sV", cmd)
        self.assertEqual(cmd[-1], "1.2.3.4")
        self.assertNotIn("--script", cmd)

    def test_command_vuln(self):
        cmd = ufm.build_nmap_command("1.2.3.4", vuln=True)
        self.assertIn("--script", cmd)
        self.assertIn("vuln", cmd)

    def test_available_is_bool(self):
        self.assertIn(ufm.nmap_available(), (True, False))


# ==============================================================================
# FirmwareAnalyzer
# ==============================================================================
class TestFirmwareAnalyzer(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ufm_test_")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, name, data):
        p = os.path.join(self.tmp, name)
        with open(p, "wb") as f:
            f.write(data)
        return p

    def test_trx(self):
        p = self._write("fw.bin", b"HDR0" + b"\x00" * 600)
        info = ufm.FirmwareAnalyzer.inspect_file(p)
        self.assertEqual(info['type'], 'TRX Firmware Image')

    def test_ubi(self):
        p = self._write("fw.img", b"UBI#" + b"\x00" * 600)
        self.assertEqual(ufm.FirmwareAnalyzer.inspect_file(p)['type'], 'UBI Flash System Image')

    def test_zip(self):
        p = os.path.join(self.tmp, "a.zip")
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("x.txt", "hi")
        self.assertEqual(ufm.FirmwareAnalyzer.inspect_file(p)['type'], 'ZIP Archive / Package')

    def test_gzip(self):
        p = os.path.join(self.tmp, "a.gz")
        with gzip.open(p, "wb") as g:
            g.write(b"hello" * 100)
        self.assertEqual(ufm.FirmwareAnalyzer.inspect_file(p)['type'], 'GZIP Compressed Image')

    def test_tar(self):
        inner = self._write("inner.txt", b"data")
        p = os.path.join(self.tmp, "a.tar")
        with tarfile.open(p, "w") as t:
            t.add(inner, arcname="inner.txt")
        self.assertEqual(ufm.FirmwareAnalyzer.inspect_file(p)['type'], 'TAR Archive / Package')

    def test_bin_extension_generic(self):
        p = self._write("x.bin", b"\x12\x34" * 300)
        self.assertIn("Firmware Binary", ufm.FirmwareAnalyzer.inspect_file(p)['type'])

    def test_no_extension_generic(self):
        p = self._write("noext", b"\x99" * 600)
        self.assertEqual(ufm.FirmwareAnalyzer.inspect_file(p)['type'], 'Generic / Custom Binary')

    def test_hashes_match(self):
        payload = b"ABC" * 1000
        p = self._write("h.bin", payload)
        info = ufm.FirmwareAnalyzer.inspect_file(p)
        self.assertEqual(info['md5'], hashlib.md5(payload).hexdigest())
        self.assertEqual(info['sha256'], hashlib.sha256(payload).hexdigest())
        self.assertEqual(info['size_bytes'], len(payload))

    def test_empty_rejected(self):
        p = self._write("empty.bin", b"")
        with self.assertRaises(ValueError):
            ufm.FirmwareAnalyzer.inspect_file(p)

    def test_missing_rejected(self):
        with self.assertRaises(FileNotFoundError):
            ufm.FirmwareAnalyzer.inspect_file(os.path.join(self.tmp, "nope.bin"))


# ==============================================================================
# Device fingerprinting (network effects stubbed)
# ==============================================================================
class TestIdentifyDevice(unittest.TestCase):
    def setUp(self):
        self._orig = {
            'scan_ports': ufm.SmartDeviceProber.scan_ports,
            'is_alive': ufm.SmartDeviceProber.is_alive,
            'probe_endpoint': ufm.SmartDeviceProber.probe_endpoint,
            'mac': ufm.OSNetworkScanner.get_mac_and_vendor,
        }

    def tearDown(self):
        ufm.SmartDeviceProber.scan_ports = self._orig['scan_ports']
        ufm.SmartDeviceProber.is_alive = self._orig['is_alive']
        ufm.SmartDeviceProber.probe_endpoint = self._orig['probe_endpoint']
        ufm.OSNetworkScanner.get_mac_and_vendor = self._orig['mac']

    def _stub(self, ports="80, 443", alive=True, html="", server="", title=""):
        ufm.SmartDeviceProber.scan_ports = staticmethod(lambda ip: ports)
        ufm.SmartDeviceProber.is_alive = staticmethod(lambda ip: alive)
        ufm.SmartDeviceProber.probe_endpoint = staticmethod(
            lambda ip, port=80, is_ssl=False, timeout=1.0: (server, title, html))
        ufm.OSNetworkScanner.get_mac_and_vendor = staticmethod(
            lambda ip: ("AA:BB:CC:DD:EE:FF", "Generic Hardware"))

    def test_none_when_closed_and_dead(self):
        self._stub(ports="Closed", alive=False)
        self.assertIsNone(ufm.SmartDeviceProber.identify_device("10.0.0.9"))

    def test_mikrotik(self):
        self._stub(html="<html>RouterOS by MikroTik</html>")
        info = ufm.SmartDeviceProber.identify_device("10.0.0.2")
        self.assertEqual(info['vendor'], "MikroTik")

    def test_openwrt(self):
        self._stub(html="Powered by LuCI OpenWrt")
        self.assertEqual(ufm.SmartDeviceProber.identify_device("10.0.0.3")['vendor'], "OpenWrt")

    def test_fortinet(self):
        self._stub(title="FortiSwitch", html="fortinet appliance")
        self.assertEqual(ufm.SmartDeviceProber.identify_device("10.0.0.4")['vendor'], "Fortinet")

    def test_generic(self):
        self._stub(html="<html><title>Login</title></html>")
        info = ufm.SmartDeviceProber.identify_device("10.0.0.5")
        self.assertEqual(info['ip'], "10.0.0.5")
        self.assertEqual(info['status'], "Online")


class TestMacVendor(unittest.TestCase):
    def setUp(self):
        import subprocess
        self._orig = subprocess.check_output

    def tearDown(self):
        import subprocess
        subprocess.check_output = self._orig

    def _patch(self, text):
        import subprocess
        subprocess.check_output = lambda *a, **k: text.encode()

    def test_known_oui(self):
        # 48:8F:5A -> MikroTik in the OUI table
        self._patch("? (10.0.0.1) at 48:8f:5a:11:22:33 [ether] on eth0")
        mac, vendor = ufm.OSNetworkScanner.get_mac_and_vendor("10.0.0.1")
        self.assertEqual(mac, "48:8F:5A:11:22:33")
        self.assertEqual(vendor, "MikroTik")

    def test_unknown_oui(self):
        self._patch("? (10.0.0.1) at 12:34:56:78:9a:bc [ether] on eth0")
        _, vendor = ufm.OSNetworkScanner.get_mac_and_vendor("10.0.0.1")
        self.assertEqual(vendor, "Generic Hardware")


# ==============================================================================
# Worker guard paths
# ==============================================================================
class TestWorkerGuards(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from PyQt5.QtWidgets import QApplication
        cls.app = QApplication.instance() or QApplication(sys.argv)

    def test_ssh_preflight_closed_port(self):
        got = []
        w = ufm.SSHExtractWorker({'host': '127.0.0.1', 'port': 1, 'user': 'root',
                                  'password': 'x', 'method': 'list'})
        w.finished_signal.connect(lambda ok, msg: got.append((ok, msg)))
        w.run()  # synchronous for the test
        self.assertTrue(got)
        self.assertFalse(got[0][0])
        self.assertIn("Cannot reach", got[0][1])

    def test_nmap_worker_when_unavailable(self):
        orig = ufm.nmap_available
        ufm.nmap_available = lambda: False
        try:
            got = []
            w = ufm.NmapWorker("127.0.0.1")
            w.finished_signal.connect(lambda ok, msg: got.append((ok, msg)))
            w.run()
            self.assertTrue(got)
            self.assertFalse(got[0][0])
            self.assertIn("nmap", got[0][1].lower())
        finally:
            ufm.nmap_available = orig


# ==============================================================================
# Offscreen GUI construction
# ==============================================================================
class TestGui(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from PyQt5.QtWidgets import QApplication
        cls.app = QApplication.instance() or QApplication(sys.argv)
        ufm.apply_dark_theme(cls.app)

    def setUp(self):
        self.w = ufm.UniversalFirmwareManagerGUI()

    def tearDown(self):
        self.w.close()

    def test_tabs(self):
        self.assertEqual(self.w.tabs.count(), 6)

    def test_buttons_disabled_without_device(self):
        self.w.selected_device = None
        self.w.update_action_buttons_state()
        self.assertFalse(self.w.btn_upgrade.isEnabled())
        self.assertFalse(self.w.btn_backup.isEnabled())
        self.assertFalse(self.w.btn_audit.isEnabled())
        self.assertFalse(self.w.btn_ssh_extract.isEnabled() and not ufm.HAS_PARAMIKO)

    def test_select_device_enables(self):
        dev = {'ip': '192.168.1.1', 'vendor': 'OpenWrt', 'model': 't', 'mac': 'AA',
               'ports': '22, 80', 'type': 'Router', 'title': 'x', 'status': 'Online'}
        self.w.select_device_action(dev)
        self.assertTrue(self.w.btn_backup.isEnabled())
        self.assertTrue(self.w.btn_dump_rom.isEnabled())
        self.assertTrue(self.w.btn_audit.isEnabled())
        if ufm.HAS_PARAMIKO:
            self.assertTrue(self.w.btn_ssh_extract.isEnabled())

    def test_security_audit_populates_report(self):
        dev = {'ip': '192.168.1.1', 'vendor': 'Generic', 'model': 't',
               'ports': '23, 80', 'title': '', 'status': 'Online'}
        self.w.select_device_action(dev)
        self.w.run_security_audit()
        self.assertIn("Security Audit", self.w.txt_report.toPlainText())
        self.assertIn("Telnet", self.w.txt_report.toPlainText())

    def test_terminal_tab_present(self):
        self.assertTrue(hasattr(self.w, 'tab_terminal'))
        self.assertEqual(ufm.HAS_PYTE, self.w.tab_terminal.screen is not None)


class TestAuthDialog(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from PyQt5.QtWidgets import QApplication
        cls.app = QApplication.instance() or QApplication(sys.argv)

    def test_collect_and_build(self):
        d = ufm.AuthExtractDialog({'ip': '10.0.0.9'})
        d.in_user.setText("root")
        d.in_pass.setText("secret")
        d.rad_dump.setChecked(True)
        d.in_command.setText("cat /dev/mtd0")
        fields = d._collect_fields()
        self.assertEqual(fields['method'], 'exec')
        cfg, err = ufm.build_extract_config(fields, tempfile.gettempdir(), "S")
        self.assertIsNone(err)
        self.assertEqual(cfg['command'], "cat /dev/mtd0")
        d.deleteLater()


if __name__ == "__main__":
    unittest.main(verbosity=2)
