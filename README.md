# Universal Firmware Flasher Tool

A PyQt5 desktop tool for discovering network/serial devices, inspecting and
transferring firmware, driving a real serial console, and reviewing a device's
security posture — built to be honest (it never fakes a flash) and to only act
on devices you own or are authorized to test.

## Features

1. **Device Discovery** — fast parallel subnet scan with MAC/OUI vendor
   resolution, open-port detection, and web-interface fingerprinting.
2. **Firmware Management** — Upgrade / Downgrade / Restore over real TFTP or a
   real UART bootloader interrupt; a device information report. Generic
   SSH/HTTP flashing is intentionally blocked (model-specific).
3. **Serial Console** — a real VT100 terminal (PuTTY/Termius-style) backed by
   `pyte`: ANSI colors, cursor addressing, full serial framing, line endings,
   local echo, and session logging.
4. **Firmware Extraction**
   - **SSH / SFTP (no hardware)** — log in with your own credentials and dump a
     flash/MTD partition or download a backup. Requires valid credentials; it
     does **not** bypass device security.
   - **Serial / UART** — physical bootloader access.
5. **Firmware Selection & Verify** — local file or HTTPS download, with
   MD5/SHA-256 hashing and type detection.
6. **Intelligence & Security** — a passive security audit of the scan data, plus
   an optional authorized **nmap** service/vulnerability scan.

## Install

```bash
python -m pip install -r requirements.txt
```

Optional: install [nmap](https://nmap.org) and put it on PATH to enable the
active scan button.

## Run

```bash
python universal_firmware_flasher.py
```

## Test

```bash
python -m unittest discover -s tests -v
# quick built-in check:
python universal_firmware_flasher.py --self-test
```

## Responsible use

Firmware extraction, nmap scanning, and flashing must only target devices you
own or are explicitly authorized to test. The tool requires valid credentials
and physical/authorized access; it does not exploit or bypass security.
