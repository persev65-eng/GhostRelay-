#!/usr/bin/env python3
"""
GhostRelay - LoRa mesh relay with ECDSA signatures, ECIES encryption, and credit system.

TRANSPORT MODES (config.json → "connection_type"):
  "tcp"       — TCP socket to an ESP32 Bluetooth-TCP bridge app (original mode)
  "usb"       — Direct USB serial via pyserial (/dev/ttyUSB0, /dev/ttyACM0, COM3…)
  "bluetooth" — Direct Bluetooth serial via pyserial (/dev/rfcomm0 on Linux/Android-root)
  "wifi_ap"   — Direct TCP connection to ESP32 in Access-Point mode (no bridge app needed)
                Uses wifi_ap_ip (default 192.168.4.1) and wifi_ap_port (default 8080).
                Connect your computer/phone to the ESP32's WiFi network first.

FALLBACK:
  Set "fallback_order": ["wifi_ap", "usb", "bluetooth", "tcp"] in config to try
  alternatives automatically if the primary connection fails.

PROTOCOL:
  - Node A creates: payload = text + 16hex_timestamp
                    signs with private key → tx <payload><sigA>
  - Node B receives: verifies sigA against trusted_keys.json.
      Unknown key → silently discard.
      Known key   → strip sigA, sign same payload with sigB → retransmit.
      Queue priority = per-message value starting at sender's credit, decayed
      as floor(base/(n_tx+1)) after each relay; message expires after 60 s.
  - When msg[sigB] returns to A: A recognises payload (original_cache),
      credits B with total_pts // place (1st=100%, 2nd=50%, 3rd=33%, N=100/N%).
  - Credit window: only 60 seconds from first return. After that, no more credit.
  - When msg[sigB] arrives at D: D treats it as a new message from B,
      re-signs with sigD. When sigD returns to B: B recognises payload
      (relayed_cache) and credits D — same logic at every hop.
  - Time window: timestamp older than 20 min or more than 10 min in future → discard.
  - Duplicate: same (payload, signer_fp) → ignore.
  - Max buffer: 10 MB.

CONTACTS AND ENCRYPTION:
  - Contacts stored in contacts.json: name → public key PEM.
  - Encrypted send:  "message:contact_name"
  - Plaintext send:  "message"  (asks confirmation)
  - All received messages are silently attempted for decryption.

PACKET FORMAT ON THE NETWORK:
  tx <payload><sig88chars>\n
  payload = <content_utf8><16hex_timestamp>
  content = plaintext OR base64(ECIES blob) — no prefix, no marker
  sig     = base64 of 64-byte ECDSA NIST-P256 → always 88 chars

ECIES BLOB LAYOUT (bytes before base64):
  [0 :33] ephemeral compressed public key (SECP256R1)
  [33:45] AES-GCM nonce (12 bytes)
  [45:  ] ciphertext + GCM tag (16 bytes)

CREDITS:
  Persisted atomically to credits.json and credited_order.json every 10 s.
  Nodes with more credit have their messages prioritised in the relay queue.
"""

import base64
import hashlib
import heapq
import json
import logging
import os
import queue
import select
import socket
import sys
import tempfile
import threading
import time
from abc import ABC, abstractmethod
from pathlib import Path

# ECDSA signing / verification
from ecdsa import NIST256p, SigningKey, VerifyingKey
from ecdsa.util import sigdecode_string, sigencode_string

# ECIES encryption (ECDH + HKDF + AES-256-GCM)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec as _ec
from cryptography.hazmat.primitives.asymmetric.ec import ECDH, SECP256R1, generate_private_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

# pyserial — optional; only required for USB / Bluetooth modes
try:
    import serial
    import serial.serialutil
    _SERIAL_AVAILABLE = True
    _SerialException  = serial.serialutil.SerialException
except ImportError:
    _SERIAL_AVAILABLE = False
    _SerialException  = Exception   # fallback so the name always exists

# ------------------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------------------

PROJECT_NAME   = "GhostRelay"
MONERO_ADDRESS = "49YdksRCWR3TY2A3WopX9322EGzzxBrFv4NbTho4DCNhSzUGfnAivcJNuAqEYCFjw8EYwbk4x745XjTt1Kh5n9KbNorXSD6"

APP_DIR             = Path.home() / "lora_relay"
CONFIG_PATH         = APP_DIR / "config.json"
KEY_PATH            = APP_DIR / "private_key.pem"
TRUSTED_KEYS_PATH   = APP_DIR / "trusted_keys.json"
CONTACTS_PATH       = APP_DIR / "contacts.json"
CREDITS_PATH        = APP_DIR / "credits.json"
CREDITED_ORDER_PATH = APP_DIR / "credited_order.json"

MAX_BUFFER_BYTES      = 10 * 1024 * 1024
MAX_MSG_LEN           = 200
MAX_ENC_LEN           = 400
MAX_RECV_BUF          = 64 * 1024
CACHE_EXPIRE_SEC      = 20 * 60
MAX_RELAY_AGE_SEC     = 20 * 60
MAX_FUTURE_SEC        = 10 * 60
SIG_CHARS             = 88
TIMESTAMP_CHARS       = 16
CREDITS_SAVE_INTERVAL = 10
CACHE_CLEAN_INTERVAL  = 60
MAX_PRIO_REORDERS     = 5
RELAY_TTL_SEC         = 60      # max lifetime of a message in the relay queue
CONNECT_TIMEOUT_SEC   = 10
SERIAL_READ_TIMEOUT   = 0.5     # aumentado para respostas mais lentas (antes 0.1)
HKDF_INFO             = b"ghostrelay-ecies-v1"

ESP_CMDS = {"status", "help", "reset", "diag", "debug3", "sf", "bw", "freq", "cr", "pwr"}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("ghostrelay")

# ------------------------------------------------------------------------------
# Platform / environment detection
# ------------------------------------------------------------------------------

def _is_termux() -> bool:
    return "com.termux" in os.environ.get("PREFIX", "") or \
           Path("/data/data/com.termux").exists()

def _is_android() -> bool:
    return _is_termux() or Path("/system/build.prop").exists()

# ------------------------------------------------------------------------------
# Atomic persistence  (defined early — used by config writer too)
# ------------------------------------------------------------------------------

def _save_atomic(path: Path, data):
    """Write JSON atomically: write to temp file then os.replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", dir=path.parent, delete=False, suffix=".tmp"
        ) as tf:
            json.dump(data, tf, indent=2, ensure_ascii=False)
            tmp = tf.name
        os.replace(tmp, path)
    except Exception:
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        raise

# ------------------------------------------------------------------------------
# Config
# ------------------------------------------------------------------------------

_DEFAULT_CONFIG = {
    "connection_type": "wifi_ap",
    "fallback_order":  ["wifi_ap","tcp", "usb", "bluetooth"],
    "tcp_host":        "127.0.0.1",
    "tcp_port":        8080,
    "usb_device":      "/dev/ttyUSB0",
    "baudrate":        115200,
    "bt_device":       "/dev/rfcomm0",
    "bt_baudrate":     115200,
    # WiFi Access-Point mode: ESP32 acts as AP; connect this device to its network first.
    "wifi_ap_ssid":    "",              # informational only (not used for connecting)
    "wifi_ap_ip":      "192.168.4.1",  # ESP32 AP gateway IP (fixed by the firmware)
    "wifi_ap_port":    8080,           # TCP port the ESP32 listens on
}

def load_config() -> dict:
    if not CONFIG_PATH.exists():
        _save_atomic(CONFIG_PATH, _DEFAULT_CONFIG)
        print(f"[CONFIG] Created default config at {CONFIG_PATH} — please edit it.")
        sys.exit(1)
    with open(CONFIG_PATH) as f:
        return json.load(f)

CFG = load_config()

# ------------------------------------------------------------------------------
# Private key / node identity
# ------------------------------------------------------------------------------

def load_or_create_key() -> SigningKey:
    APP_DIR.mkdir(exist_ok=True)
    if KEY_PATH.exists():
        key = SigningKey.from_pem(KEY_PATH.read_bytes())
        log.info("[KEY] Loaded private key from %s", KEY_PATH)
        return key
    key = SigningKey.generate(curve=NIST256p)
    KEY_PATH.write_bytes(key.to_pem())
    try:
        os.chmod(KEY_PATH, 0o600)
    except Exception as e:
        log.warning("[KEY] Could not set key file permissions: %s", e)
    log.info("[KEY] Generated new private key at %s", KEY_PATH)
    return key

sk         = load_or_create_key()
MY_VK      = sk.get_verifying_key()
MY_VK_PEM  = MY_VK.to_pem().decode()
_crypto_sk = load_pem_private_key(sk.to_pem(), password=None)

def _fp(vk: VerifyingKey) -> str:
    """8-hex-char fingerprint — cryptographic identity of a node."""
    return hashlib.sha256(vk.to_string()).hexdigest()[:8]

MY_NODE_ID = _fp(MY_VK)

# ==============================================================================
# TRANSPORT LAYER
# ==============================================================================

class Transport(ABC):
    """Abstract base for all transport modes."""
    @abstractmethod
    def connect(self): pass
    @abstractmethod
    def send(self, data: bytes): pass
    @abstractmethod
    def close(self): pass
    @abstractmethod
    def label(self) -> str: pass
    @abstractmethod
    def start_reader(self, line_queue: queue.Queue, stop_event: threading.Event): pass


# ── TCP Transport ──────────────────────────────────────────────────────────────
class TcpTransport(Transport):
    def __init__(self, host: str, port: int):
        self._host = host
        self._port = port
        self._sock = None
        self._lock = threading.Lock()

    def label(self) -> str:
        return f"TCP {self._host}:{self._port}"

    def connect(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(CONNECT_TIMEOUT_SEC)
            sock.connect((self._host, self._port))
            sock.setblocking(True)
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
            raise
        with self._lock:
            self._sock = sock

    def _get_sock(self):
        with self._lock:
            return self._sock

    def send(self, data: bytes):
        sock = self._get_sock()
        if sock is None:
            raise OSError("Not connected")
        sock.sendall(data)

    def close(self):
        with self._lock:
            s, self._sock = self._sock, None
        if s:
            try:
                s.close()
            except Exception:
                pass

    def start_reader(self, line_queue: queue.Queue, stop_event: threading.Event):
        def _run():
            buf = ""
            while not stop_event.is_set():
                try:
                    sock = self._get_sock()
                    if sock is None:
                        break
                    ready, _, _ = select.select([sock], [], [], 0.2)
                    if not ready:
                        continue
                    chunk = sock.recv(4096)
                    if not chunk:
                        log.warning("[TCP] Connection closed by server")
                        break
                    buf += chunk.decode("utf-8", errors="replace")
                    buf, lines = _split_lines(buf)
                    for line in lines:
                        line_queue.put(line)
                except (BlockingIOError, UnicodeDecodeError):
                    continue
                except Exception as e:
                    if not stop_event.is_set():
                        log.error("[TCP] Read error: %s", e)
                    break
            line_queue.put(None)
        threading.Thread(target=_run, daemon=True, name="tcp-reader").start()


# ── WiFi AP Transport ─────────────────────────────────────────────────────────
class WifiApTransport(TcpTransport):
    def __init__(self, ip: str, port: int, ssid: str = ''):
        super().__init__(host=ip, port=port)
        self._ssid = ssid

    def label(self) -> str:
        ssid_hint = f' ({self._ssid})' if self._ssid else ''
        return f'WIFI_AP {self._host}:{self._port}{ssid_hint}'

    def connect(self):
        try:
            super().connect()
        except OSError as e:
            raise OSError(
                f'Cannot reach ESP32 at {self._host}:{self._port}.\n'
                '  Make sure this device is connected to the ESP32 WiFi network.\n'
                f'  Expected AP SSID : {self._ssid or "(see ESP32 serial console)"}\n'
                '  Verify the ESP32 firmware has the TCP server enabled.\n'
                f'  Original error   : {e}'
            ) from e


# ── Serial Transport (USB and Bluetooth) com suporte a \r e \n ────────────────
class SerialTransport(Transport):
    def __init__(self, device: str, baudrate: int, kind: str = "usb"):
        self._device = device
        self._baudrate = baudrate
        self._kind = kind
        self._ser = None
        self._lock = threading.Lock()

    def label(self) -> str:
        return f"{self._kind.upper()} {self._device}@{self._baudrate}"

    def connect(self):
        if not _SERIAL_AVAILABLE:
            raise ImportError("pyserial is not installed. Run: pip install pyserial")
        self._check_permissions()
        ser = serial.Serial(
            port=self._device,
            baudrate=self._baudrate,
            timeout=SERIAL_READ_TIMEOUT,
        )
        with self._lock:
            self._ser = ser
        log.info("[SERIAL] Opened %s", self.label())

    def _check_permissions(self):
        dev = Path(self._device)
        if not dev.exists():
            if self._kind == "bluetooth":
                if _is_android():
                    raise PermissionError(
                        f"Bluetooth device {self._device} not found.\n"
                        "  On Android/Termux you need root and an rfcomm binding:\n"
                        "    rfcomm bind 0 <MAC_ADDRESS>\n"
                        "  Without root, use TCP mode with a Bluetooth-bridge app instead."
                    )
                raise PermissionError(
                    f"Bluetooth device {self._device} not found.\n"
                    "  On Linux, pair and bind first:\n"
                    "    bluetoothctl pair <MAC>\n"
                    "    rfcomm bind 0 <MAC>\n"
                    "  Then retry."
                )
            raise FileNotFoundError(
                f"USB device {self._device} not found.\n"
                "  On Termux (no root), use:\n"
                "    termux-usb -l              (list devices)\n"
                "    termux-usb -r -e ghostrelay.py /dev/bus/usb/...\n"
                "  Or switch to TCP mode."
            )
        if not os.access(self._device, os.R_OK | os.W_OK):
            if _is_termux():
                if self._kind == "usb":
                    raise PermissionError(
                        f"No permission to access {self._device}.\n"
                        "  In Termux, launch with termux-usb:\n"
                        "    termux-usb -r -e ghostrelay.py <device_path>\n"
                        "  Or add your user to the 'dialout' group (requires root):\n"
                        "    usermod -aG dialout $USER"
                    )
                raise PermissionError(
                    f"No permission to access {self._device}.\n"
                    "  Bluetooth serial in Termux requires root.\n"
                    "  Alternatively, use TCP mode with a BT-bridge app."
                )
            raise PermissionError(
                f"No permission to access {self._device}.\n"
                "  Add your user to the dialout group and re-login:\n"
                "    sudo usermod -aG dialout $USER"
            )

    def _get_ser(self):
        with self._lock:
            return self._ser

    def send(self, data: bytes):
        ser = self._get_ser()
        if ser is None or not ser.is_open:
            raise OSError("Serial port not open")
        ser.write(data)
        ser.flush()

    def close(self):
        with self._lock:
            ser, self._ser = self._ser, None
        if ser and ser.is_open:
            try:
                ser.close()
            except Exception:
                pass

    def start_reader(self, line_queue: queue.Queue, stop_event: threading.Event):
        def _run():
            buf = ""
            while not stop_event.is_set():
                try:
                    ser = self._get_ser()
                    if ser is None or not ser.is_open:
                        break
                    # Lê até encontrar \n ou \r (qualquer um dos dois)
                    raw = ser.read_until(b'\n')
                    if not raw:
                        # Se timeout e não leu nada, tenta ler \r (caso a linha termine só com \r)
                        raw = ser.read_until(b'\r')
                        if not raw:
                            continue
                    # Se a linha terminou com \r, adicionamos um \n artificial para o split
                    decoded = raw.decode("utf-8", errors="replace")
                    if raw.endswith(b'\r') and not raw.endswith(b'\n'):
                        decoded += '\n'
                    buf += decoded
                    buf, lines = _split_lines(buf)
                    for line in lines:
                        line_queue.put(line)
                except _SerialException as e:
                    if not stop_event.is_set():
                        log.error("[SERIAL] Read error: %s", e)
                    break
                except Exception as e:
                    if not stop_event.is_set():
                        log.error("[SERIAL] Unexpected error: %s", e)
                    break
            line_queue.put(None)

        threading.Thread(target=_run, daemon=True, name=f"{self._kind}-reader").start()


# ── Line buffer helper (agora também divide por \r) ───────────────────────────
def _split_lines(buf: str) -> tuple:
    """Extrai linhas terminadas por \n ou \r (ou \r\n). Retorna (resto, [linhas])."""
    lines = []
    # Primeiro normaliza \r\n para \n
    buf = buf.replace('\r\n', '\n')
    # Depois quebra por \n
    while '\n' in buf:
        line, buf = buf.split('\n', 1)
        line = line.strip()
        if line:
            lines.append(line)
    # Se ainda houver \r solto (sem \n), trata como linha também
    while '\r' in buf:
        line, buf = buf.split('\r', 1)
        line = line.strip()
        if line:
            lines.append(line)
    if len(buf.encode("utf-8")) > MAX_RECV_BUF:
        log.warning("[TRANSPORT] Newline-free fragment exceeds %d KB — discarded", MAX_RECV_BUF // 1024)
        buf = ""
    return buf, lines


# ── WiFi scan helper (opcional) ──────────────────────────────────────────────
def cmd_wifi_scan():
    import shutil
    import subprocess
    print('\n=== WIFI SCAN ===')
    def _run(cmd):
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=10)
            return out.decode('utf-8', errors='replace').strip()
        except Exception:
            return None
    result = None
    if shutil.which('nmcli'):
        result = _run(['nmcli', '-f', 'SSID,SIGNAL,SECURITY', 'dev', 'wifi', 'list'])
    elif shutil.which('iwlist'):
        raw = _run(['iwlist', 'wlan0', 'scan'])
        if raw:
            result = '\n'.join(l.strip() for l in raw.splitlines() if 'ESSID' in l)
    elif shutil.which('netsh'):
        result = _run(['netsh', 'wlan', 'show', 'networks'])
    elif _is_termux():
        result = _run(['termux-wifi-scaninfo'])
    if result:
        print(result)
    else:
        print('  No supported WiFi scan tool found on this platform.')
        print('  Use your system WiFi manager to find the ESP32 AP network.')
    ap_ip = CFG.get('wifi_ap_ip', '192.168.4.1')
    ssid  = CFG.get('wifi_ap_ssid', '')
    print(f'\n  Configured ESP32 AP  : {ssid or "(wifi_ap_ssid not set in config.json)"}')
    print(f'  Configured ESP32 IP  : {ap_ip}')
    print('=================\n')


# ── Transport Manager (atualizado para incluir wifi_ap) ──────────────────────
class TransportManager:
    def __init__(self, cfg: dict):
        self._cfg = cfg
        self._chain = self._build_chain()
        self._index = 0

    def _build_chain(self) -> list:
        cfg = self._cfg
        primary = cfg.get("connection_type", "tcp").lower()
        order = cfg.get("fallback_order", [primary])
        seen = set()
        ordered = []
        for m in ([primary] + [x for x in order if x != primary]):
            if m not in seen:
                seen.add(m)
                ordered.append(m)
        chain = []
        for mode in ordered:
            t = self._make_transport(mode)
            if t:
                chain.append(t)
        return chain

    def _make_transport(self, mode: str):
        cfg = self._cfg
        if mode == "tcp":
            return TcpTransport(host=cfg.get("tcp_host", "127.0.0.1"), port=int(cfg.get("tcp_port", 8080)))
        if mode == "usb":
            return SerialTransport(device=cfg.get("usb_device", "/dev/ttyUSB0"), baudrate=int(cfg.get("baudrate", 115200)), kind="usb")
        if mode in ("bluetooth", "bt"):
            return SerialTransport(device=cfg.get("bt_device", "/dev/rfcomm0"), baudrate=int(cfg.get("bt_baudrate", cfg.get("baudrate", 115200))), kind="bluetooth")
        if mode in ("wifi_ap", "wifi"):
            return WifiApTransport(ip=cfg.get("wifi_ap_ip", "192.168.4.1"), port=int(cfg.get("wifi_ap_port", 8080)), ssid=cfg.get("wifi_ap_ssid", ""))
        log.warning("[CONFIG] Unknown connection_type '%s' — skipped", mode)
        return None

    def connect_next(self) -> Transport:
        if not self._chain:
            raise RuntimeError("No transports configured.")
        n = len(self._chain)
        start = self._index
        for i in range(n):
            idx = (start + i) % n
            t = self._chain[idx]
            log.info("[TRANSPORT] Trying %s …", t.label())
            try:
                t.connect()
                log.info("[TRANSPORT] Connected via %s", t.label())
                self._index = idx
                return t
            except (PermissionError, ImportError) as e:
                print(f"\n{type(e).__name__}: {e}\n")
            except Exception as e:
                log.warning("[TRANSPORT] %s failed: %s", t.label(), e)
        self._index = (start + 1) % n
        raise RuntimeError("All configured transports failed. Check config.json and device availability.")


# ------------------------------------------------------------------------------
# Trusted relay nodes
# ------------------------------------------------------------------------------
trusted_lock = threading.Lock()
_trusted = {}

def load_trusted_keys() -> dict:
    if not TRUSTED_KEYS_PATH.exists():
        return {}
    with open(TRUSTED_KEYS_PATH) as f:
        data = json.load(f)
    result = {}
    for name, pem in data.items():
        try:
            vk = VerifyingKey.from_pem(pem)
            result[_fp(vk)] = vk
        except Exception as e:
            log.warning("[TRUSTED] Invalid key for '%s': %s", name, e)
    return result

def get_trusted() -> dict:
    with trusted_lock:
        return dict(_trusted)

def reload_trusted():
    global _trusted
    loaded = load_trusted_keys()
    with trusted_lock:
        _trusted = loaded

def add_trusted_node(name: str, pem_or_b64: str) -> bool:
    raw = pem_or_b64.strip()
    if not raw.startswith("-----"):
        raw = f"-----BEGIN PUBLIC KEY-----\n{raw}\n-----END PUBLIC KEY-----\n"
    try:
        vk = VerifyingKey.from_pem(raw)
    except Exception as e:
        print(f"[ERROR] Invalid key: {e}")
        return False
    node_fp = _fp(vk)
    existing = {}
    if TRUSTED_KEYS_PATH.exists():
        try:
            with open(TRUSTED_KEYS_PATH) as f:
                existing = json.load(f)
        except Exception:
            pass
    existing[name] = vk.to_pem().decode()
    _save_atomic(TRUSTED_KEYS_PATH, existing)
    with trusted_lock:
        _trusted[node_fp] = vk
    log.info("[ADDNODE] Node '%s' added (fp=%s)", name, node_fp)
    return True

def show_my_pubkey():
    b64 = base64.b64encode(MY_VK.to_der()).decode()
    print("\n=== MY PUBLIC KEY (share with other nodes) ===")
    print(f"  Fingerprint : {MY_NODE_ID}")
    print(f"  Base64 DER  : {b64}")
    print(f"  PEM:\n{MY_VK_PEM}")
    print("================================================\n")


# ------------------------------------------------------------------------------
# Contacts
# ------------------------------------------------------------------------------
contacts_lock = threading.Lock()
_contacts = {}

def _parse_contact_key(pem_or_b64: str):
    raw = pem_or_b64.strip()
    if not raw.startswith("-----"):
        raw = f"-----BEGIN PUBLIC KEY-----\n{raw}\n-----END PUBLIC KEY-----\n"
    vk_ecdsa = VerifyingKey.from_pem(raw)
    vk_crypto = load_pem_public_key(vk_ecdsa.to_pem())
    return vk_ecdsa, vk_crypto

def load_contacts():
    global _contacts
    if not CONTACTS_PATH.exists():
        return
    try:
        with open(CONTACTS_PATH) as f:
            data = json.load(f)
        loaded = {}
        for name, pem in data.items():
            try:
                vk_ecdsa, vk_crypto = _parse_contact_key(pem)
                loaded[name.lower()] = {"name": name, "vk": vk_ecdsa, "vk_crypto": vk_crypto}
            except Exception as e:
                log.warning("[CONTACTS] Invalid key for '%s': %s", name, e)
        with contacts_lock:
            _contacts = loaded
        log.info("[CONTACTS] Loaded %d contact(s)", len(loaded))
    except Exception as e:
        log.warning("[CONTACTS] Failed to load contacts.json: %s", e)

def _save_contacts():
    with contacts_lock:
        snap = {v["name"]: v["vk"].to_pem().decode() for v in _contacts.values()}
    _save_atomic(CONTACTS_PATH, snap)

def add_contact(name: str, pem_or_b64: str) -> bool:
    try:
        vk_ecdsa, vk_crypto = _parse_contact_key(pem_or_b64)
    except Exception as e:
        print(f"[ERROR] Invalid key: {e}")
        return False
    with contacts_lock:
        _contacts[name.lower()] = {"name": name, "vk": vk_ecdsa, "vk_crypto": vk_crypto}
    _save_contacts()
    print(f"✓ Contact '{name}' saved (fp={_fp(vk_ecdsa)})")
    return True

def get_contact(name: str):
    with contacts_lock:
        entry = _contacts.get(name.lower())
        return dict(entry) if entry else None

def cmd_contacts():
    with contacts_lock:
        snap = list(_contacts.values())
    print("\n=== CONTACTS ===")
    if snap:
        for c in sorted(snap, key=lambda x: x["name"].lower()):
            print(f"  {c['name']:<24} fp={_fp(c['vk'])}")
    else:
        print("  (no contacts saved)")
    print("  Hint: addcontact <name> <base64_key>")
    print("================\n")


# ------------------------------------------------------------------------------
# ECIES encryption/decryption
# ------------------------------------------------------------------------------
def _derive_aes_key(shared_secret: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=HKDF_INFO).derive(shared_secret)

def encrypt_for_contact(plaintext: str, vk_crypto) -> str:
    eph_sk = generate_private_key(SECP256R1())
    shared = eph_sk.exchange(ECDH(), vk_crypto)
    aes_key = _derive_aes_key(shared)
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext.encode("utf-8"), None)
    eph_pub_bytes = eph_sk.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
    return base64.b64encode(eph_pub_bytes + nonce + ciphertext).decode("ascii")

def decrypt_message(content: str):
    try:
        raw = base64.b64decode(content, validate=True)
        if len(raw) < 33 + 12 + 16:
            return None
        eph_key = _ec.EllipticCurvePublicKey.from_encoded_point(SECP256R1(), raw[:33])
        shared = _crypto_sk.exchange(ECDH(), eph_key)
        aes_key = _derive_aes_key(shared)
        plain = AESGCM(aes_key).decrypt(raw[33:45], raw[45:], None)
        return plain.decode("utf-8")
    except Exception:
        return None


# ------------------------------------------------------------------------------
# Credits
# ------------------------------------------------------------------------------
credits_lock = threading.Lock()
credits = {}
credited_order_lock = threading.Lock()
credited_order = {}
_credit_expiry = {}

def load_credits():
    global credits, credited_order
    if CREDITS_PATH.exists():
        try:
            with open(CREDITS_PATH) as f:
                data = json.load(f)
            with credits_lock:
                credits = data
        except Exception as e:
            log.warning("[LOAD] credits.json: %s", e)
    if CREDITED_ORDER_PATH.exists():
        try:
            with open(CREDITED_ORDER_PATH) as f:
                data = json.load(f)
            with credited_order_lock:
                credited_order = data
        except Exception as e:
            log.warning("[LOAD] credited_order.json: %s", e)

def save_credits():
    with credits_lock:
        snap_c = dict(credits)
    with credited_order_lock:
        snap_o = {k: list(v) for k, v in credited_order.items()}
    _save_atomic(CREDITS_PATH, snap_c)
    _save_atomic(CREDITED_ORDER_PATH, snap_o)

def credits_saver_thread():
    while True:
        time.sleep(CREDITS_SAVE_INTERVAL)
        try:
            save_credits()
        except Exception as e:
            log.warning("[SAVE] %s", e)

def get_credit(fp: str) -> int:
    with credits_lock:
        return credits.get(fp, 0)

def add_credit(fp: str, points: int):
    with credits_lock:
        credits[fp] = credits.get(fp, 0) + points
        total = credits[fp]
    log.info("[CREDIT] +%d to %s (total: %d)", points, fp, total)


# ------------------------------------------------------------------------------
# Caches
# ------------------------------------------------------------------------------
cache_lock = threading.Lock()
original_cache = {}
relayed_cache = {}
seen_packets = {}

def mark_original(payload: str):
    with cache_lock:
        original_cache[payload] = time.monotonic()

def mark_relayed(payload: str, node_id: str = None):
    if node_id is None:
        node_id = MY_NODE_ID
    with cache_lock:
        relayed_cache[(payload, node_id)] = time.monotonic()

def has_relayed(payload: str, node_id: str = None) -> bool:
    if node_id is None:
        node_id = MY_NODE_ID
    with cache_lock:
        return (payload, node_id) in relayed_cache

def i_know_payload(payload: str) -> bool:
    with cache_lock:
        return payload in original_cache

def mark_seen(payload: str, signer_fp: str):
    with cache_lock:
        seen_packets[(payload, signer_fp)] = time.monotonic()

def already_seen(payload: str, signer_fp: str) -> bool:
    with cache_lock:
        return (payload, signer_fp) in seen_packets

def clean_caches_once():
    now = time.monotonic()
    cutoff = now - CACHE_EXPIRE_SEC
    with cache_lock:
        for k in list(original_cache.keys()):
            if original_cache[k] < cutoff:
                original_cache.pop(k, None)
        for k in list(relayed_cache.keys()):
            if relayed_cache[k] < cutoff:
                relayed_cache.pop(k, None)
        for k in list(seen_packets.keys()):
            if seen_packets[k] < cutoff:
                seen_packets.pop(k, None)
    credit_cutoff = now - RELAY_TTL_SEC
    with credited_order_lock:
        for p in list(credited_order.keys()):
            expiry = _credit_expiry.get(p)
            if expiry is None or expiry < credit_cutoff:
                del credited_order[p]
                _credit_expiry.pop(p, None)
    relay_ttl_cutoff = now - RELAY_TTL_SEC
    with queue_lock:
        for p in list(_relay_state.keys()):
            if _relay_state[p]["born"] < relay_ttl_cutoff:
                _relay_state.pop(p, None)

def cache_cleaner_thread():
    while True:
        time.sleep(CACHE_CLEAN_INTERVAL)
        try:
            clean_caches_once()
        except Exception as e:
            log.warning("[CACHE] Cleanup error: %s", e)


# ------------------------------------------------------------------------------
# Signing / verification
# ------------------------------------------------------------------------------
def sign_payload(payload: str) -> str:
    digest = hashlib.sha256(payload.encode("utf-8")).digest()
    sig_bytes = sk.sign_digest(digest, sigencode=sigencode_string)
    return base64.b64encode(sig_bytes).decode("ascii")

def verify_payload(payload: str, sig_b64: str, vk: VerifyingKey) -> bool:
    try:
        sig = base64.b64decode(sig_b64, validate=True)
        digest = hashlib.sha256(payload.encode("utf-8")).digest()
        vk.verify_digest(sig, digest, sigdecode=sigdecode_string)
        return True
    except Exception:
        return False

def identify_signer(payload: str, sig_b64: str):
    if verify_payload(payload, sig_b64, MY_VK):
        return (MY_NODE_ID, MY_VK)
    for fp, vk in get_trusted().items():
        if verify_payload(payload, sig_b64, vk):
            return (fp, vk)
    return None


# ------------------------------------------------------------------------------
# Timestamp
# ------------------------------------------------------------------------------
def make_timestamp() -> str:
    return f"{time.time_ns():016x}"

def is_timestamp_valid(ts_hex: str) -> bool:
    try:
        diff = (time.time_ns() - int(ts_hex, 16)) / 1_000_000_000.0
        return -MAX_FUTURE_SEC <= diff <= MAX_RELAY_AGE_SEC
    except Exception:
        return False


# ------------------------------------------------------------------------------
# Priority queue and retransmission worker
# ------------------------------------------------------------------------------
queue_lock = threading.Lock()
priority_queue = []
current_buffer_bytes = 0
_relay_state = {}

def enqueue(payload: str, origin_fp: str):
    global current_buffer_bytes
    size = len(payload.encode("utf-8"))
    with queue_lock:
        if current_buffer_bytes + size > MAX_BUFFER_BYTES:
            log.warning("[BUFFER] Full — message from %s dropped", origin_fp)
            return
        if payload not in _relay_state:
            raw_credit = get_credit(origin_fp)
            base = raw_credit if raw_credit >= 1 else 10
            _relay_state[payload] = {"base": base, "n_tx": 0, "born": time.monotonic()}
        state = _relay_state[payload]
        value = max(1, state["base"] // (state["n_tx"] + 1))
        heapq.heappush(priority_queue, (-value, time.monotonic(), payload, origin_fp, size))
        current_buffer_bytes += size

send_lock = threading.Lock()

def safe_send(transport: Transport, data: bytes):
    with send_lock:
        transport.send(data)

def retransmit_worker(transport: Transport, stop_event: threading.Event):
    global current_buffer_bytes
    MIN_RETX_INTERVAL = 0.5
    last_sent = {}

    while not stop_event.is_set():
        item = None
        with queue_lock:
            if priority_queue:
                item = heapq.heappop(priority_queue)
        if item is None:
            time.sleep(0.05)
            continue

        neg_value, _enqueue_time, payload, origin_fp, size = item

        now = time.monotonic()
        if now - last_sent.get(payload, 0.0) < MIN_RETX_INTERVAL:
            with queue_lock:
                heapq.heappush(priority_queue, item)
            time.sleep(0.05)
            continue

        with queue_lock:
            state = _relay_state.get(payload)

        if state is None or (now - state["born"]) > RELAY_TTL_SEC:
            log.info("[TX] TTL expired — dropped | origin=%s", origin_fp)
            with queue_lock:
                current_buffer_bytes = max(0, current_buffer_bytes - size)
                _relay_state.pop(payload, None)
            last_sent.pop(payload, None)
            continue

        if not is_timestamp_valid(payload[-TIMESTAMP_CHARS:]):
            log.info("[TX] Timestamp expired in queue — dropped")
            with queue_lock:
                current_buffer_bytes = max(0, current_buffer_bytes - size)
            last_sent.pop(payload, None)
            continue

        new_sig = sign_payload(payload)
        packet = f"tx {payload}{new_sig}\n".encode("utf-8")

        try:
            safe_send(transport, packet)
            mark_relayed(payload, MY_NODE_ID)
            last_sent[payload] = time.monotonic()
        except Exception as e:
            log.warning("[TX] Send failed, re-queuing: %s", e)
            with queue_lock:
                heapq.heappush(priority_queue, item)
            time.sleep(0.5)
            continue

        with queue_lock:
            state = _relay_state.get(payload)
            if state is not None:
                n_tx_before = state["n_tx"]
                new_value = state["base"] // (n_tx_before + 1)
                state["n_tx"] += 1
            else:
                n_tx_before = 0
                new_value = 0

            current_buffer_bytes = max(0, current_buffer_bytes - size)
            age = now - (state["born"] if state else 0)
            if state is not None and new_value >= 1 and age <= RELAY_TTL_SEC:
                if current_buffer_bytes + size <= MAX_BUFFER_BYTES:
                    heapq.heappush(priority_queue, (-new_value, time.monotonic(), payload, origin_fp, size))
                    current_buffer_bytes += size
                    log.info("[TX] Relayed+requeued | origin=%s n_tx=%d→%d value=%d→%d ttl_left=%.0fs",
                             origin_fp, n_tx_before, state["n_tx"], -neg_value, new_value, RELAY_TTL_SEC - age)
                else:
                    log.warning("[TX] Buffer full — not requeuing after relay")
                    _relay_state.pop(payload, None)
                    last_sent.pop(payload, None)
            else:
                _relay_state.pop(payload, None)
                last_sent.pop(payload, None)
                log.info("[TX] Relayed (final) | origin=%s n_tx=%d value_was=%d reason=%s",
                         origin_fp, state["n_tx"] if state else "?", -neg_value,
                         "value=0" if new_value < 1 else "TTL")

        time.sleep(0.05)


# ------------------------------------------------------------------------------
# Incoming packet processing (handle_lora_packet) - sem alterações
# ------------------------------------------------------------------------------
def handle_lora_packet(content: str):
    if len(content) < TIMESTAMP_CHARS + SIG_CHARS + 1:
        return
    sig_b64 = content[-SIG_CHARS:]
    payload = content[:-SIG_CHARS]
    if not is_timestamp_valid(payload[-TIMESTAMP_CHARS:]):
        log.debug("[RX] Timestamp out of window")
        return
    result = identify_signer(payload, sig_b64)
    if result is None:
        log.debug("[RX] Unknown signer or bad signature")
        return
    signer_fp, _ = result
    if signer_fp == MY_NODE_ID:
        return
    if payload in original_cache:
        with credited_order_lock:
            if payload not in _credit_expiry:
                _credit_expiry[payload] = time.monotonic()
            else:
                if time.monotonic() - _credit_expiry[payload] > RELAY_TTL_SEC:
                    return
            order = credited_order.setdefault(payload, [])
            place = len(order) + 1
            text_len = len(payload[:-TIMESTAMP_CHARS].encode("utf-8"))
            total_pts = text_len + TIMESTAMP_CHARS + SIG_CHARS
            reward = max(1, total_pts // place)
            order.append(signer_fp)
        add_credit(signer_fp, reward)
        log.info("[CREDIT] %s | place %d | +%d pts", signer_fp, place, reward)
        return
    if already_seen(payload, signer_fp):
        return
    mark_seen(payload, signer_fp)
    if has_relayed(payload, signer_fp):
        log.debug("[RX] Already relayed by %s — skipping", signer_fp)
        return
    content_part = payload[:-TIMESTAMP_CHARS]
    decrypted = decrypt_message(content_part)
    if decrypted is not None:
        print(f"\n🔒 [PRIVATE] from {signer_fp}: {decrypted}\n> ", end="", flush=True)
    else:
        print(f"\n📢 [OPEN]    from {signer_fp}: {content_part}\n> ", end="", flush=True)
    enqueue(payload, signer_fp)

def dispatch_line(line: str):
    if line.startswith("[LoRa] "):
        content = line[7:].strip()
        if content.startswith("tx "):
            content = content[3:]
        handle_lora_packet(content)
    else:
        print(f"[ESP32] {line}")


# ------------------------------------------------------------------------------
# Console commands
# ------------------------------------------------------------------------------
def is_esp_cmd(cmd: str) -> bool:
    parts = cmd.strip().split()
    return bool(parts) and parts[0].lower() in ESP_CMDS

def cmd_credits():
    with credits_lock:
        snap = sorted(credits.items(), key=lambda x: x[1], reverse=True)
    print("\n=== CREDITS (nodes that relayed my messages) ===")
    for fp, pts in snap:
        print(f"  {fp} : {pts} pts")
    if not snap:
        print("  (no credits yet)")
    print("=================================================\n")

def cmd_queue():
    now = time.monotonic()
    with queue_lock:
        if not priority_queue:
            print("\n=== QUEUE empty ===\n")
            return
        snap = sorted(priority_queue)
        total_bytes = current_buffer_bytes
        state_snap = {p: dict(s) for p, s in _relay_state.items()}
    print(f"\n=== QUEUE ({len(snap)} msgs · {total_bytes} bytes) ===")
    for i, (neg_val, _, payload, origin_fp, size) in enumerate(snap[:20]):
        value = -neg_val
        st = state_snap.get(payload, {})
        base = st.get("base", "?")
        n_tx = st.get("n_tx", "?")
        age = now - st.get("born", now)
        ttl = max(0.0, RELAY_TTL_SEC - age)
        print(f"  {i+1:2d}. value={value:6d}  base={base}  tx={n_tx}  ttl={ttl:4.0f}s  origin={origin_fp}  size={size}b  payload={payload[:20]}...")
    print("============================================\n")

def cmd_trusted():
    t = get_trusted()
    print("\n=== TRUSTED RELAY NODES ===")
    for fp in t:
        print(f"  {fp}")
    if not t:
        print("  (none)")
    print(f"  MY ID : {MY_NODE_ID}")
    print("===========================\n")

def stdin_reader_thread(stdin_queue: queue.Queue):
    try:
        while True:
            try:
                line = sys.stdin.readline()
            except EOFError:
                break
            if line == "":
                break
            line = line.strip()
            if line:
                stdin_queue.put(line)
    finally:
        stdin_queue.put(None)


# ------------------------------------------------------------------------------
# Main loop
# ------------------------------------------------------------------------------
def main():
    reload_trusted()
    load_credits()
    load_contacts()

    print(f"""
╔══════════════════════════════════════════════════════════════════╗
║                   WELCOME TO {PROJECT_NAME}!                      ║
║                                                                  ║
║  Decentralised LoRa mesh · ECDSA NIST-P256 · ECIES AES-256-GCM  ║
║                                                                  ║
║  Time window : 20 min past  ·  10 min future                    ║
║  Credit      : 1st=100% · 2nd=50% · 3rd=33% · Nth=100/N% bytes  ║
║  Credit window: 60 seconds from first return.                   ║
║  Queue       : higher-credit nodes are relayed first             ║
║                                                                  ║
║  {MONERO_ADDRESS}                                                ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
""")
    print(f"[START] My fingerprint  : {MY_NODE_ID}")
    t = get_trusted()
    print(f"[START] Trusted peers   : {list(t.keys()) or '(none)'}")
    with contacts_lock:
        nc = len(_contacts)
    print(f"[START] Contacts        : {nc} saved")
    print(f"[START] Max buffer      : {MAX_BUFFER_BYTES // 1024 // 1024} MB")
    print(f"[START] pyserial        : {'available' if _SERIAL_AVAILABLE else 'NOT installed — USB/BT modes disabled'}")
    primary = CFG.get("connection_type", "tcp").lower()
    print(f"[START] Primary mode    : {primary.upper()}")
    if primary in ("wifi_ap", "wifi"):
        ssid = CFG.get("wifi_ap_ssid", "")
        print(f"[START] ESP32 AP IP     : {CFG.get('wifi_ap_ip', '192.168.4.1')}:{CFG.get('wifi_ap_port', 8080)}" + (f"  (SSID: {ssid})" if ssid else "  (wifi_ap_ssid not set)"))
    fallback = CFG.get("fallback_order", [])
    if len(fallback) > 1:
        print(f"[START] Fallback order  : {' → '.join(fallback)}")
    print()

    print("Commands:")
    print("  <message>:<contact>      — send ENCRYPTED message to a contact")
    print("  <message>                — send PLAINTEXT message (asks confirmation)")
    print("  contacts                 — list saved contacts")
    print("  addcontact <name> <key>  — add a contact")
    print("  credits                  — view accumulated credits")
    print("  queue                    — view retransmission queue")
    print("  trusted                  — view trusted relay nodes")
    print("  addnode <name> <key>     — add a trusted relay node")
    print("  mykey                    — show your public key")
    print("  wifiscan                 — list nearby WiFi networks (debug)")
    print("  clear                    — clear screen")
    print("  <ESP32 command>          — status sf bw freq cr pwr diag reset...\n")

    threading.Thread(target=credits_saver_thread, daemon=True, name="credits-saver").start()
    threading.Thread(target=cache_cleaner_thread, daemon=True, name="cache-cleaner").start()

    stdin_queue = queue.Queue()
    threading.Thread(target=stdin_reader_thread, args=(stdin_queue,), daemon=True, name="stdin-reader").start()

    manager = TransportManager(CFG)
    pending_confirm = None
    RETRY_DELAY = 5

    while True:
        transport = None
        stop_event = None
        worker = None
        line_queue = queue.Queue()

        try:
            transport = manager.connect_next()
        except RuntimeError as e:
            log.error("[MAIN] %s — retrying in %ds…", e, RETRY_DELAY)
            time.sleep(RETRY_DELAY)
            continue

        try:
            stop_event = threading.Event()
            transport.start_reader(line_queue, stop_event)

            worker = threading.Thread(target=retransmit_worker, args=(transport, stop_event), daemon=True, name="tx-worker")
            worker.start()

            connection_lost = False
            while not connection_lost:
                drained = False
                while not drained:
                    try:
                        line = line_queue.get_nowait()
                        if line is None:
                            log.warning("[MAIN] Transport disconnected")
                            connection_lost = True
                            break
                        dispatch_line(line)
                    except queue.Empty:
                        drained = True
                if connection_lost:
                    break

                try:
                    cmd = stdin_queue.get_nowait()
                except queue.Empty:
                    time.sleep(0.05)
                    continue
                if cmd is None:
                    break

                cmd = cmd.strip()
                if not cmd:
                    continue
                low = cmd.lower()

                if pending_confirm is not None:
                    if low == "yes":
                        packet, payload = pending_confirm
                        if not is_timestamp_valid(payload[-TIMESTAMP_CHARS:]):
                            print("✗ Message expired while waiting — not sent.")
                        else:
                            try:
                                safe_send(transport, packet)
                                mark_original(payload)
                                log.info("[SENT PLAINTEXT] ts=%s", payload[-TIMESTAMP_CHARS:])
                            except Exception as e:
                                log.error("[SEND] Failed: %s", e)
                    else:
                        print("✗ Send cancelled.")
                    pending_confirm = None
                    continue

                if low == "credits":
                    cmd_credits()
                elif low == "queue":
                    cmd_queue()
                elif low == "trusted":
                    cmd_trusted()
                elif low == "contacts":
                    cmd_contacts()
                elif low == "mykey":
                    show_my_pubkey()
                elif low == "clear":
                    print("\033[2J\033[H", end="")
                elif low == "wifiscan":
                    cmd_wifi_scan()
                elif low.startswith("addnode "):
                    parts = cmd.split(maxsplit=2)
                    if len(parts) == 3:
                        add_trusted_node(parts[1], parts[2])
                    else:
                        print("Usage: addnode <name> <base64_key_or_PEM>")
                elif low.startswith("addcontact "):
                    parts = cmd.split(maxsplit=2)
                    if len(parts) == 3:
                        add_contact(parts[1], parts[2])
                    else:
                        print("Usage: addcontact <name> <base64_key_or_PEM>")
                elif is_esp_cmd(cmd):
                    # CORREÇÃO: envia com \r\n para compatibilidade com ESP32
                    try:
                        safe_send(transport, f"{cmd}\r\n".encode("utf-8"))
                        print(f"[CMD] {cmd}")
                    except Exception as e:
                        log.error("[CMD] Send failed: %s", e)
                else:
                    # Envio de mensagem (plaintext ou criptografada)
                    contact_name = None
                    text = cmd
                    if ":" in cmd:
                        left, right = cmd.rsplit(":", 1)
                        candidate = right.strip()
                        if candidate and get_contact(candidate) is not None:
                            text = left
                            contact_name = candidate
                    if not text.strip():
                        print("[ERROR] Empty message.")
                        continue
                    if contact_name:
                        c = get_contact(contact_name)
                        try:
                            enc_blob = encrypt_for_contact(text, c["vk_crypto"])
                        except Exception as e:
                            print(f"[ERROR] Encryption failed: {e}")
                            continue
                        if len(enc_blob.encode("utf-8")) > MAX_ENC_LEN:
                            print(f"[ERROR] Encrypted message too long (max ~{MAX_ENC_LEN} bytes)")
                            continue
                        ts_hex = make_timestamp()
                        payload = f"{enc_blob}{ts_hex}"
                        sig = sign_payload(payload)
                        packet = f"tx {payload}{sig}\n".encode("utf-8")
                        try:
                            safe_send(transport, packet)
                            mark_original(payload)
                            print(f"🔒 [SENT ENCRYPTED] to '{c['name']}'")
                        except Exception as e:
                            log.error("[SEND] Failed: %s", e)
                    else:
                        if len(text.encode("utf-8")) > MAX_MSG_LEN:
                            print(f"[ERROR] Message too long (max {MAX_MSG_LEN} UTF-8 bytes)")
                            continue
                        ts_hex = make_timestamp()
                        payload = f"{text}{ts_hex}"
                        sig = sign_payload(payload)
                        packet = f"tx {payload}{sig}\n".encode("utf-8")
                        print("\n⚠️  This message is NOT encrypted.")
                        print("    Any node on the network will be able to read it.")
                        print("    Are you sure you want to send it? (yes / no)\n> ", end="", flush=True)
                        pending_confirm = (packet, payload)

        except Exception as e:
            log.error("[MAIN] Unexpected error: %s", e)
        finally:
            if stop_event:
                stop_event.set()
            if worker and worker.is_alive():
                worker.join(timeout=1.0)
            if transport:
                transport.close()
            pending_confirm = None

        log.info("[MAIN] Reconnecting in %ds…", RETRY_DELAY)
        time.sleep(RETRY_DELAY)


if __name__ == "__main__":
    main()
