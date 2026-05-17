#!/usr/bin/env python3
"""
GhostRelay - Interface Gráfica Tkinter com abas:
- Aba Mensagens: log, entrada de comandos/mensagens, botões de atalho
- Aba Lista de Nós: lista de nós confiáveis ordenada por créditos
Barra lateral mantém apenas a lista de contatos (com pseudo-contato para comandos públicos)
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
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

# Dependências
from ecdsa import NIST256p, SigningKey, VerifyingKey
from ecdsa.util import sigdecode_string, sigencode_string
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec as _ec
from cryptography.hazmat.primitives.asymmetric.ec import ECDH, SECP256R1, generate_private_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

try:
    import serial
    import serial.serialutil
    _SERIAL_AVAILABLE = True
    _SerialException = serial.serialutil.SerialException
except ImportError:
    _SERIAL_AVAILABLE = False
    _SerialException = Exception

# ------------------------------------------------------------------------------
# Constantes
# ------------------------------------------------------------------------------
PROJECT_NAME = "GhostRelay"
MONERO_ADDRESS = "49YdksRCWR3TY2A3WopX9322EGzzxBrFv4NbTho4DCNhSzUGfnAivcJNuAqEYCFjw8EYwbk4x745XjTt1Kh5n9KbNorXSD6"

APP_DIR = Path.home() / "lora_relay"
CONFIG_PATH = APP_DIR / "config.json"
KEY_PATH = APP_DIR / "private_key.pem"
TRUSTED_KEYS_PATH = APP_DIR / "trusted_keys.json"
CONTACTS_PATH = APP_DIR / "contacts.json"
CREDITS_PATH = APP_DIR / "credits.json"
CREDITED_ORDER_PATH = APP_DIR / "credited_order.json"

MAX_BUFFER_BYTES = 10 * 1024 * 1024
MAX_MSG_LEN = 200
MAX_ENC_LEN = 400
MAX_RECV_BUF = 64 * 1024
CACHE_EXPIRE_SEC = 20 * 60
MAX_RELAY_AGE_SEC = 20 * 60
MAX_FUTURE_SEC = 10 * 60
SIG_CHARS = 88
TIMESTAMP_CHARS = 16
CREDITS_SAVE_INTERVAL = 10
CACHE_CLEAN_INTERVAL = 60
MAX_PRIO_REORDERS = 5
RELAY_TTL_SEC = 60
CONNECT_TIMEOUT_SEC = 10
SERIAL_READ_TIMEOUT = 2
HKDF_INFO = b"ghostrelay-ecies-v1"

ESP_CMDS = {"status", "help", "reset", "diag", "debug3", "sf", "bw", "freq", "cr", "pwr"}

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("ghostrelay")

# ------------------------------------------------------------------------------
# Funções auxiliares
# ------------------------------------------------------------------------------
def _is_termux(): return "com.termux" in os.environ.get("PREFIX", "") or Path("/data/data/com.termux").exists()
def _is_android(): return _is_termux() or Path("/system/build.prop").exists()

def _save_atomic(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False, suffix=".tmp") as tf:
            json.dump(data, tf, indent=2, ensure_ascii=False)
            tmp = tf.name
        os.replace(tmp, path)
    except Exception:
        if tmp is not None:
            try: os.unlink(tmp)
            except OSError: pass
        raise

_DEFAULT_CONFIG = {
    "connection_type": "wifi_ap",
    "fallback_order": ["wifi_ap", "tcp", "usb", "bluetooth"],
    "tcp_host": "127.0.0.1",
    "tcp_port": 8080,
    "usb_device": "/dev/ttyUSB0",
    "baudrate": 115200,
    "bt_device": "/dev/rfcomm0",
    "bt_baudrate": 115200,
    "wifi_ap_ssid": "",
    "wifi_ap_ip": "192.168.4.1",
    "wifi_ap_port": 8080,
}

def load_config():
    if not CONFIG_PATH.exists():
        _save_atomic(CONFIG_PATH, _DEFAULT_CONFIG)
        print(f"[CONFIG] Created default config at {CONFIG_PATH} — please edit it.")
        sys.exit(1)
    with open(CONFIG_PATH) as f:
        return json.load(f)

CFG = load_config()

def load_or_create_key():
    APP_DIR.mkdir(exist_ok=True)
    if KEY_PATH.exists():
        key = SigningKey.from_pem(KEY_PATH.read_bytes())
        return key
    key = SigningKey.generate(curve=NIST256p)
    KEY_PATH.write_bytes(key.to_pem())
    try: os.chmod(KEY_PATH, 0o600)
    except: pass
    return key

sk = load_or_create_key()
MY_VK = sk.get_verifying_key()
MY_VK_PEM = MY_VK.to_pem().decode()
_crypto_sk = load_pem_private_key(sk.to_pem(), password=None)

def _fp(vk): return hashlib.sha256(vk.to_string()).hexdigest()[:8]
MY_NODE_ID = _fp(MY_VK)

# ------------------------------------------------------------------------------
# Transportes
# ------------------------------------------------------------------------------
class Transport(ABC):
    @abstractmethod
    def connect(self): pass
    @abstractmethod
    def send(self, data: bytes): pass
    @abstractmethod
    def close(self): pass
    @abstractmethod
    def label(self) -> str: pass
    @abstractmethod
    def start_reader(self, line_queue, stop_event): pass

class TcpTransport(Transport):
    def __init__(self, host, port):
        self._host = host
        self._port = port
        self._sock = None
        self._lock = threading.Lock()
    def label(self): return f"TCP {self._host}:{self._port}"
    def connect(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(CONNECT_TIMEOUT_SEC)
            sock.connect((self._host, self._port))
            sock.setblocking(True)
        except Exception:
            try: sock.close()
            except: pass
            raise
        with self._lock: self._sock = sock
    def _get_sock(self):
        with self._lock: return self._sock
    def send(self, data):
        sock = self._get_sock()
        if sock is None: raise OSError("Not connected")
        sock.sendall(data)
    def close(self):
        with self._lock:
            s, self._sock = self._sock, None
        if s: s.close()
    def start_reader(self, line_queue, stop_event):
        def _run():
            buf = ""
            while not stop_event.is_set():
                try:
                    sock = self._get_sock()
                    if sock is None: break
                    ready, _, _ = select.select([sock], [], [], 0.2)
                    if not ready: continue
                    chunk = sock.recv(4096)
                    if not chunk: break
                    buf += chunk.decode("utf-8", errors="replace")
                    buf, lines = _split_lines(buf)
                    for line in lines: line_queue.put(line)
                except: pass
            line_queue.put(None)
        threading.Thread(target=_run, daemon=True).start()

class WifiApTransport(TcpTransport):
    def __init__(self, ip, port, ssid=''):
        super().__init__(ip, port)
        self._ssid = ssid
    def label(self): return f"WIFI_AP {self._host}:{self._port}"
    def connect(self):
        try:
            super().connect()
        except OSError as e:
            raise OSError(f"Cannot reach ESP32 at {self._host}:{self._port}.\nMake sure you are connected to the ESP32 WiFi network.") from e

class SerialTransport(Transport):
    def __init__(self, device, baudrate, kind="usb"):
        self._device = device
        self._baudrate = baudrate
        self._kind = kind
        self._ser = None
        self._lock = threading.Lock()
    def label(self): return f"{self._kind.upper()} {self._device}@{self._baudrate}"
    def connect(self):
        if not _SERIAL_AVAILABLE:
            raise ImportError("pyserial not installed")
        ser = serial.Serial(port=self._device, baudrate=self._baudrate, timeout=SERIAL_READ_TIMEOUT)
        with self._lock: self._ser = ser
    def _get_ser(self):
        with self._lock: return self._ser
    def send(self, data):
        ser = self._get_ser()
        if ser is None or not ser.is_open: raise OSError("Serial port not open")
        ser.write(data)
        ser.flush()
    def close(self):
        with self._lock:
            ser, self._ser = self._ser, None
        if ser and ser.is_open: ser.close()
    def start_reader(self, line_queue, stop_event):
        def _run():
            buf = ""
            while not stop_event.is_set():
                try:
                    ser = self._get_ser()
                    if ser is None or not ser.is_open: break
                    raw = ser.read_until(b'\n')
                    if not raw:
                        raw = ser.read_until(b'\r')
                        if not raw: continue
                    decoded = raw.decode("utf-8", errors="replace")
                    if raw.endswith(b'\r') and not raw.endswith(b'\n'): decoded += '\n'
                    buf += decoded
                    buf, lines = _split_lines(buf)
                    for line in lines: line_queue.put(line)
                except: break
            line_queue.put(None)
        threading.Thread(target=_run, daemon=True).start()

def _split_lines(buf):
    lines = []
    buf = buf.replace('\r\n', '\n')
    while '\n' in buf:
        line, buf = buf.split('\n', 1)
        line = line.strip()
        if line: lines.append(line)
    while '\r' in buf:
        line, buf = buf.split('\r', 1)
        line = line.strip()
        if line: lines.append(line)
    if len(buf.encode()) > MAX_RECV_BUF: buf = ""
    return buf, lines

class TransportManager:
    def __init__(self, cfg):
        self._cfg = cfg
        self._chain = self._build_chain()
        self._index = 0
    def _build_chain(self):
        primary = self._cfg.get("connection_type", "tcp").lower()
        order = self._cfg.get("fallback_order", [primary])
        seen = set()
        ordered = []
        for m in ([primary] + [x for x in order if x != primary]):
            if m not in seen:
                seen.add(m)
                ordered.append(m)
        chain = []
        for mode in ordered:
            t = self._make_transport(mode)
            if t: chain.append(t)
        return chain
    def _make_transport(self, mode):
        cfg = self._cfg
        if mode == "tcp":
            return TcpTransport(cfg.get("tcp_host", "127.0.0.1"), int(cfg.get("tcp_port", 8080)))
        if mode == "usb":
            return SerialTransport(cfg.get("usb_device", "/dev/ttyUSB0"), int(cfg.get("baudrate", 115200)), "usb")
        if mode in ("bluetooth", "bt"):
            return SerialTransport(cfg.get("bt_device", "/dev/rfcomm0"), int(cfg.get("bt_baudrate", cfg.get("baudrate", 115200))), "bluetooth")
        if mode in ("wifi_ap", "wifi"):
            return WifiApTransport(cfg.get("wifi_ap_ip", "192.168.4.1"), int(cfg.get("wifi_ap_port", 8080)), cfg.get("wifi_ap_ssid", ""))
        return None
    def connect_next(self):
        if not self._chain: raise RuntimeError("No transports")
        n = len(self._chain)
        start = self._index
        for i in range(n):
            idx = (start + i) % n
            t = self._chain[idx]
            log.info(f"[TRANSPORT] Trying {t.label()}…")
            try:
                t.connect()
                log.info(f"[TRANSPORT] Connected via {t.label()}")
                self._index = idx
                return t
            except Exception as e:
                log.warning(f"{t.label()} failed: {e}")
        self._index = (start + 1) % n
        raise RuntimeError("All transports failed")

# ------------------------------------------------------------------------------
# Trusted nodes, contacts, ECIES, credits, caches, assinaturas
# ------------------------------------------------------------------------------
trusted_lock = threading.Lock()
_trusted = {}

def load_trusted_keys():
    if not TRUSTED_KEYS_PATH.exists(): return {}
    with open(TRUSTED_KEYS_PATH) as f:
        data = json.load(f)
    result = {}
    for name, pem in data.items():
        try:
            vk = VerifyingKey.from_pem(pem)
            result[_fp(vk)] = vk
        except: pass
    return result

def get_trusted():
    with trusted_lock: return dict(_trusted)

def reload_trusted():
    global _trusted
    loaded = load_trusted_keys()
    with trusted_lock: _trusted = loaded

def add_trusted_node(name, pem_or_b64):
    raw = pem_or_b64.strip()
    if not raw.startswith("-----"):
        raw = f"-----BEGIN PUBLIC KEY-----\n{raw}\n-----END PUBLIC KEY-----\n"
    try:
        vk = VerifyingKey.from_pem(raw)
    except Exception as e:
        return False
    node_fp = _fp(vk)
    existing = {}
    if TRUSTED_KEYS_PATH.exists():
        try:
            with open(TRUSTED_KEYS_PATH) as f: existing = json.load(f)
        except: pass
    existing[name] = vk.to_pem().decode()
    _save_atomic(TRUSTED_KEYS_PATH, existing)
    with trusted_lock: _trusted[node_fp] = vk
    return True

def show_my_pubkey(log_func=None):
    b64 = base64.b64encode(MY_VK.to_der()).decode()
    msg = (f"\n=== MY PUBLIC KEY ===\n"
           f"Fingerprint: {MY_NODE_ID}\n"
           f"Base64 DER: {b64}\n"
           f"PEM:\n{MY_VK_PEM}\n"
           f"=====================\n")
    if log_func: log_func(msg)
    else: print(msg)

# Contacts
contacts_lock = threading.Lock()
_contacts = {}

def _parse_contact_key(pem_or_b64):
    raw = pem_or_b64.strip()
    if not raw.startswith("-----"):
        raw = f"-----BEGIN PUBLIC KEY-----\n{raw}\n-----END PUBLIC KEY-----\n"
    vk_ecdsa = VerifyingKey.from_pem(raw)
    vk_crypto = load_pem_public_key(vk_ecdsa.to_pem())
    return vk_ecdsa, vk_crypto

def load_contacts():
    global _contacts
    if not CONTACTS_PATH.exists(): return
    with open(CONTACTS_PATH) as f:
        data = json.load(f)
    loaded = {}
    for name, pem in data.items():
        try:
            vk_ecdsa, vk_crypto = _parse_contact_key(pem)
            loaded[name.lower()] = {"name": name, "vk": vk_ecdsa, "vk_crypto": vk_crypto}
        except: pass
    with contacts_lock: _contacts = loaded

def _save_contacts():
    with contacts_lock: snap = {v["name"]: v["vk"].to_pem().decode() for v in _contacts.values()}
    _save_atomic(CONTACTS_PATH, snap)

def add_contact(name, pem_or_b64):
    try:
        vk_ecdsa, vk_crypto = _parse_contact_key(pem_or_b64)
    except Exception as e:
        return False
    with contacts_lock:
        _contacts[name.lower()] = {"name": name, "vk": vk_ecdsa, "vk_crypto": vk_crypto}
    _save_contacts()
    return True

def get_contact(name):
    with contacts_lock: entry = _contacts.get(name.lower())
    return dict(entry) if entry else None

def cmd_contacts(log_func=None):
    with contacts_lock: snap = list(_contacts.values())
    if not snap:
        msg = "No contacts saved."
    else:
        msg = "\n=== CONTACTS ===\n"
        for c in sorted(snap, key=lambda x: x["name"].lower()):
            msg += f"  {c['name']:<24} fp={_fp(c['vk'])}\n"
    if log_func: log_func(msg)
    else: print(msg)

# ECIES
def _derive_aes_key(shared): return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=HKDF_INFO).derive(shared)
def encrypt_for_contact(plaintext, vk_crypto):
    eph_sk = generate_private_key(SECP256R1())
    shared = eph_sk.exchange(ECDH(), vk_crypto)
    aes_key = _derive_aes_key(shared)
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext.encode("utf-8"), None)
    eph_pub_bytes = eph_sk.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
    return base64.b64encode(eph_pub_bytes + nonce + ciphertext).decode("ascii")
def decrypt_message(content):
    try:
        raw = base64.b64decode(content, validate=True)
        if len(raw) < 33+12+16: return None
        eph_key = _ec.EllipticCurvePublicKey.from_encoded_point(SECP256R1(), raw[:33])
        shared = _crypto_sk.exchange(ECDH(), eph_key)
        aes_key = _derive_aes_key(shared)
        plain = AESGCM(aes_key).decrypt(raw[33:45], raw[45:], None)
        return plain.decode("utf-8")
    except: return None

# Credits
credits_lock = threading.Lock()
credits = {}
credited_order_lock = threading.Lock()
credited_order = {}
_credit_expiry = {}

def load_credits():
    global credits, credited_order
    if CREDITS_PATH.exists():
        try:
            with open(CREDITS_PATH) as f: credits = json.load(f)
        except: pass
    if CREDITED_ORDER_PATH.exists():
        try:
            with open(CREDITED_ORDER_PATH) as f: credited_order = json.load(f)
        except: pass

def save_credits():
    with credits_lock: snap_c = dict(credits)
    with credited_order_lock: snap_o = {k: list(v) for k, v in credited_order.items()}
    _save_atomic(CREDITS_PATH, snap_c)
    _save_atomic(CREDITED_ORDER_PATH, snap_o)

def credits_saver_thread():
    while True:
        time.sleep(CREDITS_SAVE_INTERVAL)
        try: save_credits()
        except: pass

def get_credit(fp):
    with credits_lock: return credits.get(fp, 0)

def add_credit(fp, points):
    with credits_lock:
        credits[fp] = credits.get(fp, 0) + points
        total = credits[fp]
    log.info(f"[CREDIT] +{points} to {fp} (total: {total})")

# Caches
cache_lock = threading.Lock()
original_cache = {}
relayed_cache = {}
seen_packets = {}

def mark_original(payload):
    with cache_lock: original_cache[payload] = time.monotonic()
def mark_relayed(payload, node_id=None):
    if node_id is None: node_id = MY_NODE_ID
    with cache_lock: relayed_cache[(payload, node_id)] = time.monotonic()
def has_relayed(payload, node_id=None):
    if node_id is None: node_id = MY_NODE_ID
    with cache_lock: return (payload, node_id) in relayed_cache
def i_know_payload(payload):
    with cache_lock: return payload in original_cache
def mark_seen(payload, signer_fp):
    with cache_lock: seen_packets[(payload, signer_fp)] = time.monotonic()
def already_seen(payload, signer_fp):
    with cache_lock: return (payload, signer_fp) in seen_packets

def clean_caches_once():
    now = time.monotonic()
    cutoff = now - CACHE_EXPIRE_SEC
    with cache_lock:
        for k in list(original_cache.keys()):
            if original_cache[k] < cutoff: original_cache.pop(k, None)
        for k in list(relayed_cache.keys()):
            if relayed_cache[k] < cutoff: relayed_cache.pop(k, None)
        for k in list(seen_packets.keys()):
            if seen_packets[k] < cutoff: seen_packets.pop(k, None)
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
            if _relay_state[p]["born"] < relay_ttl_cutoff: _relay_state.pop(p, None)

def cache_cleaner_thread():
    while True:
        time.sleep(CACHE_CLEAN_INTERVAL)
        try: clean_caches_once()
        except: pass

# Signing/verification
def sign_payload(payload):
    digest = hashlib.sha256(payload.encode()).digest()
    sig_bytes = sk.sign_digest(digest, sigencode=sigencode_string)
    return base64.b64encode(sig_bytes).decode("ascii")
def verify_payload(payload, sig_b64, vk):
    try:
        sig = base64.b64decode(sig_b64, validate=True)
        digest = hashlib.sha256(payload.encode()).digest()
        vk.verify_digest(sig, digest, sigdecode=sigdecode_string)
        return True
    except: return False
def identify_signer(payload, sig_b64):
    if verify_payload(payload, sig_b64, MY_VK): return (MY_NODE_ID, MY_VK)
    for fp, vk in get_trusted().items():
        if verify_payload(payload, sig_b64, vk): return (fp, vk)
    return None

# Timestamp
def make_timestamp(): return f"{time.time_ns():016x}"
def is_timestamp_valid(ts_hex):
    try:
        diff = (time.time_ns() - int(ts_hex, 16)) / 1_000_000_000.0
        return -MAX_FUTURE_SEC <= diff <= MAX_RELAY_AGE_SEC
    except: return False

# Priority queue
queue_lock = threading.Lock()
priority_queue = []
current_buffer_bytes = 0
_relay_state = {}

def enqueue(payload, origin_fp):
    global current_buffer_bytes
    size = len(payload.encode())
    with queue_lock:
        if current_buffer_bytes + size > MAX_BUFFER_BYTES:
            log.warning(f"[BUFFER] Full - message from {origin_fp} dropped")
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
def safe_send(transport, data):
    with send_lock: transport.send(data)

def retransmit_worker(transport, stop_event):
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
        neg_value, _enq_time, payload, origin_fp, size = item
        now = time.monotonic()
        if now - last_sent.get(payload, 0.0) < MIN_RETX_INTERVAL:
            with queue_lock: heapq.heappush(priority_queue, item)
            time.sleep(0.05)
            continue
        with queue_lock: state = _relay_state.get(payload)
        if state is None or (now - state["born"]) > RELAY_TTL_SEC:
            log.info(f"[TX] TTL expired - dropped | origin={origin_fp}")
            with queue_lock:
                current_buffer_bytes = max(0, current_buffer_bytes - size)
                _relay_state.pop(payload, None)
            last_sent.pop(payload, None)
            continue
        if not is_timestamp_valid(payload[-TIMESTAMP_CHARS:]):
            log.info("[TX] Timestamp expired in queue - dropped")
            with queue_lock: current_buffer_bytes = max(0, current_buffer_bytes - size)
            last_sent.pop(payload, None)
            continue
        new_sig = sign_payload(payload)
        packet = f"tx {payload}{new_sig}\n".encode()
        try:
            safe_send(transport, packet)
            mark_relayed(payload, MY_NODE_ID)
            last_sent[payload] = now
        except Exception as e:
            log.warning(f"[TX] Send failed, re-queuing: {e}")
            with queue_lock: heapq.heappush(priority_queue, item)
            time.sleep(0.5)
            continue
        with queue_lock:
            state = _relay_state.get(payload)
            if state is not None:
                n_tx_before = state["n_tx"]
                new_value = state["base"] // (n_tx_before + 1)
                state["n_tx"] += 1
            else:
                n_tx_before = 0; new_value = 0
            current_buffer_bytes = max(0, current_buffer_bytes - size)
            age = now - (state["born"] if state else 0)
            if state and new_value >= 1 and age <= RELAY_TTL_SEC:
                if current_buffer_bytes + size <= MAX_BUFFER_BYTES:
                    heapq.heappush(priority_queue, (-new_value, time.monotonic(), payload, origin_fp, size))
                    current_buffer_bytes += size
                    log.info(f"[TX] Relayed+requeued | origin={origin_fp} n_tx={n_tx_before}->{state['n_tx']} value={-neg_value}->{new_value} ttl_left={RELAY_TTL_SEC-age:.0f}s")
                else:
                    log.warning("[TX] Buffer full - not requeuing")
                    _relay_state.pop(payload, None)
                    last_sent.pop(payload, None)
            else:
                _relay_state.pop(payload, None)
                last_sent.pop(payload, None)
                log.info(f"[TX] Relayed (final) | origin={origin_fp} n_tx={state['n_tx'] if state else '?'} value_was={-neg_value}")
        time.sleep(0.05)

# ------------------------------------------------------------------------------
# Incoming packet processing
# ------------------------------------------------------------------------------
def handle_lora_packet(content, log_func):
    if len(content) < TIMESTAMP_CHARS + SIG_CHARS + 1: return
    sig_b64 = content[-SIG_CHARS:]
    payload = content[:-SIG_CHARS]
    if not is_timestamp_valid(payload[-TIMESTAMP_CHARS:]): return
    result = identify_signer(payload, sig_b64)
    if result is None: return
    signer_fp, _ = result
    if signer_fp == MY_NODE_ID: return
    if i_know_payload(payload):
        with credited_order_lock:
            if payload not in _credit_expiry:
                _credit_expiry[payload] = time.monotonic()
            else:
                if time.monotonic() - _credit_expiry[payload] > RELAY_TTL_SEC: return
            order = credited_order.setdefault(payload, [])
            place = len(order) + 1
            text_len = len(payload[:-TIMESTAMP_CHARS].encode())
            total_pts = text_len + TIMESTAMP_CHARS + SIG_CHARS
            reward = max(1, total_pts // place)
            order.append(signer_fp)
        add_credit(signer_fp, reward)
        log.info(f"[CREDIT] {signer_fp} | place {place} | +{reward} pts")
        return
    if already_seen(payload, signer_fp): return
    mark_seen(payload, signer_fp)
    if has_relayed(payload, signer_fp): return
    content_part = payload[:-TIMESTAMP_CHARS]
    decrypted = decrypt_message(content_part)
    msg = f"\n🔒 [PRIVATE] from {signer_fp}: {decrypted}" if decrypted else f"\n📢 [OPEN] from {signer_fp}: {content_part}"
    log_func(msg)
    enqueue(payload, signer_fp)

def dispatch_line(line, log_func):
    if line.startswith("[LoRa] "):
        content = line[7:].strip()
        if content.startswith("tx "): content = content[3:]
        handle_lora_packet(content, log_func)
    else:
        log_func(f"[ESP32] {line}")

# ------------------------------------------------------------------------------
# Classe GhostRelayNode (integração com GUI)
# ------------------------------------------------------------------------------
class GhostRelayNode:
    def __init__(self, log_callback=None):
        self.log_callback = log_callback or print
        self.command_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.running = False
        self.thread = None

    def log(self, msg):
        self.log_callback(msg)

    def start(self):
        if self.running:
            return
        self.running = True
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._main_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=2)

    def send_command(self, cmd):
        self.command_queue.put(cmd)

    def _main_loop(self):
        reload_trusted()
        load_credits()
        load_contacts()

        self.log(f"[START] My fingerprint: {MY_NODE_ID}")
        trusted_list = list(get_trusted().keys())
        self.log(f"[START] Trusted peers: {trusted_list or '(none)'}")
        with contacts_lock:
            nc = len(_contacts)
        self.log(f"[START] Contacts: {nc} saved")
        self.log(f"[START] Primary mode: {CFG.get('connection_type', 'tcp').upper()}")
        fallback = CFG.get("fallback_order", [])
        if len(fallback) > 1:
            self.log(f"[START] Fallback order: {' → '.join(fallback)}")
        self.log(f"[START] Max buffer: {MAX_BUFFER_BYTES // 1024 // 1024} MB")
        self.log(f"[START] pyserial: {'available' if _SERIAL_AVAILABLE else 'NOT installed'}")

        threading.Thread(target=credits_saver_thread, daemon=True).start()
        threading.Thread(target=cache_cleaner_thread, daemon=True).start()

        manager = TransportManager(CFG)
        RETRY_DELAY = 5
        pending_confirm = None

        while self.running:
            transport = None
            stop_event = None
            worker = None
            line_queue = queue.Queue()

            try:
                transport = manager.connect_next()
            except RuntimeError as e:
                self.log(f"[MAIN] {e} — retrying in {RETRY_DELAY}s…")
                time.sleep(RETRY_DELAY)
                continue

            try:
                stop_event = threading.Event()
                transport.start_reader(line_queue, stop_event)
                worker = threading.Thread(target=retransmit_worker, args=(transport, stop_event), daemon=True)
                worker.start()

                connection_lost = False
                while not connection_lost and self.running:
                    # Processar linhas da serial/TCP
                    try:
                        line = line_queue.get_nowait()
                        if line is None:
                            self.log("[MAIN] Transport disconnected")
                            connection_lost = True
                            break
                        dispatch_line(line, self.log)
                    except queue.Empty:
                        pass

                    # Processar comandos da GUI
                    try:
                        cmd = self.command_queue.get_nowait()
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
                                self.log("✗ Message expired while waiting — not sent.")
                            else:
                                try:
                                    safe_send(transport, packet)
                                    mark_original(payload)
                                    self.log(f"[SENT PLAINTEXT] ts={payload[-TIMESTAMP_CHARS:]}")
                                except Exception as e:
                                    self.log(f"[SEND] Failed: {e}")
                        else:
                            self.log("✗ Send cancelled.")
                        pending_confirm = None
                        continue

                    # Comandos internos
                    if low == "credits":
                        self._cmd_credits()
                    elif low == "queue":
                        self._cmd_queue()
                    elif low == "trusted":
                        self._cmd_trusted()
                    elif low == "contacts":
                        cmd_contacts(log_func=self.log)
                    elif low == "mykey":
                        show_my_pubkey(log_func=self.log)
                    elif low == "clear":
                        self.log("\033[2J\033[H")
                    elif low == "wifiscan":
                        self._cmd_wifiscan()
                    elif low.startswith("addnode "):
                        parts = cmd.split(maxsplit=2)
                        if len(parts) == 3:
                            if add_trusted_node(parts[1], parts[2]):
                                self.log(f"✓ Node '{parts[1]}' added")
                            else:
                                self.log("✗ Invalid key")
                        else:
                            self.log("Usage: addnode <name> <base64_key_or_PEM>")
                    elif low.startswith("addcontact "):
                        parts = cmd.split(maxsplit=2)
                        if len(parts) == 3:
                            if add_contact(parts[1], parts[2]):
                                self.log(f"✓ Contact '{parts[1]}' added")
                            else:
                                self.log("✗ Invalid key")
                        else:
                            self.log("Usage: addcontact <name> <base64_key_or_PEM>")
                    elif self._is_esp_cmd(cmd):
                        try:
                            safe_send(transport, f"{cmd}\r\n".encode())
                            self.log(f"[CMD] {cmd}")
                        except Exception as e:
                            self.log(f"[CMD] Send failed: {e}")
                    else:
                        # Enviar mensagem (plaintext ou criptografada)
                        contact_name = None
                        text = cmd
                        if ":" in cmd:
                            left, right = cmd.rsplit(":", 1)
                            candidate = right.strip()
                            if candidate and get_contact(candidate):
                                text = left
                                contact_name = candidate
                        if not text.strip():
                            self.log("[ERROR] Empty message.")
                            continue
                        if contact_name:
                            c = get_contact(contact_name)
                            try:
                                enc_blob = encrypt_for_contact(text, c["vk_crypto"])
                            except Exception as e:
                                self.log(f"[ERROR] Encryption failed: {e}")
                                continue
                            if len(enc_blob.encode()) > MAX_ENC_LEN:
                                self.log(f"[ERROR] Encrypted message too long (max {MAX_ENC_LEN} bytes)")
                                continue
                            ts_hex = make_timestamp()
                            payload = f"{enc_blob}{ts_hex}"
                            sig = sign_payload(payload)
                            packet = f"tx {payload}{sig}\n".encode()
                            try:
                                safe_send(transport, packet)
                                mark_original(payload)
                                self.log(f"🔒 [SENT ENCRYPTED] to '{c['name']}'")
                            except Exception as e:
                                self.log(f"[SEND] Failed: {e}")
                        else:
                            if len(text.encode()) > MAX_MSG_LEN:
                                self.log(f"[ERROR] Message too long (max {MAX_MSG_LEN} UTF-8 bytes)")
                                continue
                            ts_hex = make_timestamp()
                            payload = f"{text}{ts_hex}"
                            sig = sign_payload(payload)
                            packet = f"tx {payload}{sig}\n".encode()
                            self.log("\n⚠️  This message is NOT encrypted.")
                            self.log("    Any node on the network will be able to read it.")
                            self.log("    Are you sure you want to send it? (yes / no)")
                            pending_confirm = (packet, payload)

            except Exception as e:
                self.log(f"[MAIN] Unexpected error: {e}")
            finally:
                if stop_event:
                    stop_event.set()
                if worker and worker.is_alive():
                    worker.join(timeout=1.0)
                if transport:
                    transport.close()
                pending_confirm = None

            if self.running:
                self.log(f"[MAIN] Reconnecting in {RETRY_DELAY}s…")
                time.sleep(RETRY_DELAY)

    def _cmd_credits(self):
        with credits_lock:
            snap = sorted(credits.items(), key=lambda x: x[1], reverse=True)
        if not snap:
            self.log("No credits yet.")
            return
        out = "\n=== CREDITS (nodes that relayed my messages) ===\n"
        for fp, pts in snap:
            out += f"  {fp} : {pts} pts\n"
        self.log(out)

    def _cmd_queue(self):
        now = time.monotonic()
        with queue_lock:
            if not priority_queue:
                self.log("Queue empty.")
                return
            snap = sorted(priority_queue)
            total_bytes = current_buffer_bytes
            state_snap = {p: dict(s) for p, s in _relay_state.items()}
        out = f"\n=== QUEUE ({len(snap)} msgs · {total_bytes} bytes) ===\n"
        for i, (neg_val, _, payload, origin_fp, size) in enumerate(snap[:20]):
            value = -neg_val
            st = state_snap.get(payload, {})
            base = st.get("base", "?")
            n_tx = st.get("n_tx", "?")
            age = now - st.get("born", now)
            ttl = max(0.0, RELAY_TTL_SEC - age)
            out += f"  {i+1:2d}. value={value:6d}  base={base}  tx={n_tx}  ttl={ttl:4.0f}s  origin={origin_fp}  size={size}b  payload={payload[:20]}...\n"
        self.log(out)

    def _cmd_trusted(self):
        t = get_trusted()
        out = "\n=== TRUSTED RELAY NODES ===\n"
        for fp in t:
            out += f"  {fp}\n"
        if not t:
            out += "  (none)\n"
        out += f"  MY ID : {MY_NODE_ID}\n"
        self.log(out)

    def _cmd_wifiscan(self):
        import shutil, subprocess
        self.log('\n=== WIFI SCAN ===')
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
            self.log(result)
        else:
            self.log('  No supported WiFi scan tool found on this platform.')
            self.log('  Use your system WiFi manager to find the ESP32 AP network.')
        ap_ip = CFG.get('wifi_ap_ip', '192.168.4.1')
        ssid = CFG.get('wifi_ap_ssid', '')
        self.log(f'\n  Configured ESP32 AP  : {ssid or "(wifi_ap_ssid not set in config.json)"}')
        self.log(f'  Configured ESP32 IP  : {ap_ip}')
        self.log('=================\n')

    def _is_esp_cmd(self, cmd):
        parts = cmd.strip().split()
        return bool(parts) and parts[0].lower() in ESP_CMDS

# ------------------------------------------------------------------------------
# Interface Gráfica Tkinter com abas (Mensagens | Lista de Nós)
# Barra lateral mantém apenas os contatos
# ------------------------------------------------------------------------------
class GhostRelayGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("GhostRelay - Rede Mesh LoRa")
        self.root.geometry("1200x700")
        self.selected_contact = None
        self.node = GhostRelayNode(log_callback=self.log)
        self.setup_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.start_node()
        self.refresh_contacts()
        self.refresh_node_list()
        self.schedule_node_refresh()
        self.root.mainloop()

    def setup_ui(self):
        # Frame principal
        main_pane = tk.Frame(self.root)
        main_pane.pack(fill=tk.BOTH, expand=True)

        # Barra lateral (apenas contatos)
        sidebar = tk.Frame(main_pane, width=200, bg='#f0f0f0')
        sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
        sidebar.pack_propagate(False)

        tk.Label(sidebar, text="Contatos", bg='#f0f0f0',
                 font=('Arial', 12, 'bold')).pack(pady=5)

        self.contact_listbox = tk.Listbox(sidebar, bg='white', selectmode=tk.SINGLE)
        self.contact_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.contact_listbox.bind('<<ListboxSelect>>', self.on_contact_select)

        refresh_contacts_btn = tk.Button(sidebar, text="Atualizar contatos",
                                         command=self.refresh_contacts)
        refresh_contacts_btn.pack(pady=5)

        # Área principal com abas
        self.notebook = ttk.Notebook(main_pane)
        self.notebook.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # --- Aba 1: Mensagens ---
        self.messages_tab = tk.Frame(self.notebook)
        self.notebook.add(self.messages_tab, text="Mensagens")
        self.setup_messages_tab()

        # --- Aba 2: Lista de Nós ---
        self.nodes_tab = tk.Frame(self.notebook)
        self.notebook.add(self.nodes_tab, text="Lista de Nós")
        self.setup_nodes_tab()

        # Indicador de contato selecionado (colocar na aba de mensagens)
        self.selected_label = tk.Label(self.messages_tab, text="Nenhum contato selecionado", fg="blue")
        self.selected_label.pack(pady=2)

    def setup_messages_tab(self):
        # Área de log
        self.log_area = scrolledtext.ScrolledText(self.messages_tab, wrap=tk.WORD,
                                                  font=("Consolas", 10))
        self.log_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Frame de entrada
        frame = tk.Frame(self.messages_tab)
        frame.pack(fill=tk.X, padx=5, pady=5)

        self.entry = tk.Entry(frame)
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0,5))
        self.entry.bind("<Return>", self.send_command)

        self.send_btn = tk.Button(frame, text="Enviar", command=self.send_command)
        self.send_btn.pack(side=tk.RIGHT)

        # Botões de atalho
        btn_frame = tk.Frame(self.messages_tab)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)
        buttons = [
            ("Credits", "credits"), ("Queue", "queue"), ("Trusted", "trusted"),
            ("My Key", "mykey"), ("Contacts", "contacts"), ("WiFi Scan", "wifiscan")
        ]
        for text, cmd in buttons:
            btn = tk.Button(btn_frame, text=text, command=lambda c=cmd: self.send_cmd(c))
            btn.pack(side=tk.LEFT, padx=2)

    def setup_nodes_tab(self):
        # Lista de nós (ordenada por pontos)
        self.node_listbox = tk.Listbox(self.nodes_tab, bg='white', font=("Consolas", 10))
        self.node_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Botão de atualização manual
        refresh_btn = tk.Button(self.nodes_tab, text="Atualizar agora", command=self.refresh_node_list)
        refresh_btn.pack(pady=5)

        # Status label (opcional)
        self.node_status = tk.Label(self.nodes_tab, text="Atualizando a cada 10 segundos...", fg="gray")
        self.node_status.pack(pady=2)

    # ---------- Lista de nós (ordenada por créditos) ----------
    def refresh_node_list(self):
        """Atualiza a lista de nós confiáveis com seus créditos (ordenados decrescente)."""
        self.node_listbox.delete(0, tk.END)
        with credits_lock:
            cred_snapshot = dict(credits)
        trusted_fps = list(get_trusted().keys())
        nodes = []
        for fp in trusted_fps:
            points = cred_snapshot.get(fp, 0)
            nodes.append((fp, points))
        nodes.sort(key=lambda x: x[1], reverse=True)
        for fp, pts in nodes:
            self.node_listbox.insert(tk.END, f"{fp}  ({pts} pts)")

    def schedule_node_refresh(self):
        """Atualiza a lista de nós a cada 10 segundos."""
        self.refresh_node_list()
        self.root.after(10000, self.schedule_node_refresh)

    # ---------- Contatos (barra lateral) ----------
    def refresh_contacts(self):
        self.contact_listbox.delete(0, tk.END)
        self.contact_listbox.insert(tk.END, "🔓 Público / Comandos")
        with contacts_lock:
            names = sorted(_contacts.keys())
        for name in names:
            self.contact_listbox.insert(tk.END, name)

    def on_contact_select(self, event):
        selection = self.contact_listbox.curselection()
        if selection:
            selected = self.contact_listbox.get(selection[0])
            if selected == "🔓 Público / Comandos":
                self.selected_contact = None
                self.selected_label.config(text="Modo: Comandos / Mensagens públicas")
            else:
                self.selected_contact = selected
                self.selected_label.config(text=f"Enviando para: {selected} (criptografado)")
        else:
            self.selected_contact = None
            self.selected_label.config(text="Nenhum contato selecionado")

    # ---------- Envio de comandos / mensagens ----------
    def send_command(self, event=None):
        cmd = self.entry.get().strip()
        if not cmd:
            return
        self.entry.delete(0, tk.END)

        if self.selected_contact is None:
            self.node.send_command(cmd)
            self.log(f"[GUI] Enviando comando/mensagem pública: {cmd}")
        else:
            c = get_contact(self.selected_contact)
            if c is None:
                self.log(f"ERRO: Contato '{self.selected_contact}' não existe mais.")
                self.selected_contact = None
                self.selected_label.config(text="Nenhum contato selecionado")
                self.refresh_contacts()
                return
            full_cmd = f"{cmd}:{self.selected_contact}"
            self.node.send_command(full_cmd)
            self.log(f"[GUI] Enviando criptografado para {self.selected_contact}: {cmd}")

    def send_cmd(self, cmd):
        self.node.send_command(cmd)

    def log(self, msg):
        self.log_area.insert(tk.END, f"{msg}\n")
        self.log_area.see(tk.END)

    def start_node(self):
        self.node.start()

    def on_close(self):
        if messagebox.askokcancel("Sair", "Deseja encerrar o GhostRelay?"):
            self.node.stop()
            self.root.destroy()

# ------------------------------------------------------------------------------
if __name__ == "__main__":
    app = GhostRelayGUI()
