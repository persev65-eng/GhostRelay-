#!/usr/bin/env python3
"""
GhostRelay - LoRa mesh relay with ECDSA signatures, ECIES encryption, credits,
invite/candidates, race ranking, and independent expunge windows.
...
"""

from __future__ import annotations

import base64
import hashlib
import heapq
import json
import logging
import os
import queue
import select
import secrets
import socket
import sys
import tempfile
import threading
import time
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ecdsa import NIST256p, SigningKey, VerifyingKey
from ecdsa.util import sigdecode_string, sigencode_string
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec as _ec
from cryptography.hazmat.primitives.asymmetric.ec import ECDH, SECP256R1, generate_private_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

try:
    import serial  # type: ignore
    _SERIAL_AVAILABLE = True
except Exception:
    serial = None
    _SERIAL_AVAILABLE = False

# ----------------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------------
PROJECT_NAME = "GhostRelay"
MONERO_ADDRESS = "49YdksRCWR3TY2A3WopX9322EGzzxBrFv4NbTho4DCNhSzUGfnAivcJNuAqEYCFjw8EYwbk4x745XjTt1Kh5n9KbNorXSD6"

APP_DIR = Path.home() / "lora_relay"
CONFIG_PATH = APP_DIR / "config.json"
KEY_PATH = APP_DIR / "private_key.pem"
TRUSTED_KEYS_PATH = APP_DIR / "trusted_keys.json"
CREDITS_PATH = APP_DIR / "credits.json"
CONTACTS_PATH = APP_DIR / "contacts.json"
CANDIDATES_PATH = APP_DIR / "candidates.json"
HASH_CACHE_PATH = APP_DIR / "processed_hash_cache.txt"

MAX_BUFFER_BYTES = 10 * 1024 * 1024
MAX_MSG_LEN = 200
MAX_ENC_LEN = 400
MAX_RECV_BUF = 64 * 1024
CACHE_MAX = 10_000
RACE_WINDOW_SEC = 60.0
WINDOW_SEC = 60.0
QUEUE_TTL_SEC = 60.0
CACHE_EXPIRE_SEC = 20 * 60
MAX_RELAY_AGE_SEC = 20 * 60
MAX_FUTURE_SEC = 10 * 60
SIG_CHARS = 88
TIMESTAMP_CHARS = 16
CREDITS_SAVE_INTERVAL = 10
CACHE_CLEAN_INTERVAL = 60
CONNECT_TIMEOUT_SEC = 10
SERIAL_READ_TIMEOUT = 2
HKDF_INFO = b"ghostrelay-ecies-v1"
MIN_PRIORITY = 10
TX_CONFIRM_TIMEOUT = 5.0

ESP_CMDS = {"status", "help", "reset", "diag", "debug3", "sf", "bw", "freq", "cr", "pwr"}

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("ghostrelay")

# ----------------------------------------------------------------------------
# General helpers
# ----------------------------------------------------------------------------

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
            try:
                os.unlink(tmp)
            except OSError:
                pass
        raise


def _fp(vk: VerifyingKey) -> str:
    return hashlib.sha256(vk.to_string()).hexdigest()[:8]


def _normalize_pem_or_b64(pem_or_b64: str) -> str:
    raw = pem_or_b64.strip()
    if not raw.startswith("-----"):
        raw = f"-----BEGIN PUBLIC KEY-----\n{raw}\n-----END PUBLIC KEY-----\n"
    return raw


def _split_lines(buf: str):
    lines = []
    buf = buf.replace("\r\n", "\n")
    while "\n" in buf:
        line, buf = buf.split("\n", 1)
        line = line.strip()
        if line:
            lines.append(line)
    while "\r" in buf:
        line, buf = buf.split("\r", 1)
        line = line.strip()
        if line:
            lines.append(line)
    if len(buf.encode("utf-8", errors="ignore")) > MAX_RECV_BUF:
        buf = ""
    return buf, lines


def _to_bool_env(path: str) -> bool:
    return "com.termux" in os.environ.get("PREFIX", "") or Path(path).exists()

# ----------------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------------

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
        print(f"[CONFIG] Created default config at {CONFIG_PATH}. Edit it and run again.")
        sys.exit(1)
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


CFG = load_config()

# ----------------------------------------------------------------------------
# Identity / keys
# ----------------------------------------------------------------------------

def load_or_create_key() -> SigningKey:
    APP_DIR.mkdir(exist_ok=True)
    if KEY_PATH.exists():
        key = SigningKey.from_pem(KEY_PATH.read_bytes())
        try:
            os.chmod(KEY_PATH, 0o600)
        except Exception:
            pass
        return key
    key = SigningKey.generate(curve=NIST256p)
    KEY_PATH.write_bytes(key.to_pem())
    try:
        os.chmod(KEY_PATH, 0o600)
    except Exception:
        pass
    return key


sk = load_or_create_key()
MY_VK: VerifyingKey = sk.get_verifying_key()
MY_VK_PEM: str = MY_VK.to_pem().decode()
MY_NODE_ID = _fp(MY_VK)
_crypto_sk = load_pem_private_key(sk.to_pem(), password=None)

# ----------------------------------------------------------------------------
# Data classes
# ----------------------------------------------------------------------------

@dataclass
class TrustedEntry:
    pubkey_pem: str
    vk: VerifyingKey
    points: int = 0


@dataclass
class CandidateEntry:
    pubkey_pem: str
    vk: VerifyingKey


@dataclass
class ContactEntry:
    name: str
    vk: VerifyingKey
    crypto_key: object


@dataclass
class RaceState:
    end: float
    ranking: list[str] = field(default_factory=list)
    total_bytes: int = 0


@dataclass
class WindowState:
    end: float
    snapshot: set[str] = field(default_factory=set)
    payload_hash: str = ""


@dataclass
class RelayState:
    base: int
    n_tx: int = 0
    born: float = field(default_factory=time.monotonic)


@dataclass
class QueueItem:
    priority: int
    enqueued_at: float
    payload_hash: str
    content: str
    msg_id: str
    origin_fp: str
    size: int
    base: int
    n_tx: int
    born: float

    def as_heap_tuple(self):
        return (-self.priority, self.enqueued_at, self.payload_hash, self.content, self.msg_id, self.origin_fp, self.size, self.base, self.n_tx, self.born)

    @staticmethod
    def from_heap_tuple(t):
        neg_priority, enqueued_at, payload_hash, content, msg_id, origin_fp, size, base, n_tx, born = t
        return QueueItem(-neg_priority, enqueued_at, payload_hash, content, msg_id, origin_fp, size, base, n_tx, born)

# ----------------------------------------------------------------------------
# Storage / state locks
# ----------------------------------------------------------------------------

trusted_lock = threading.Lock()
_trusted: dict[str, TrustedEntry] = {}

candidates_lock = threading.Lock()
_candidates: dict[str, CandidateEntry] = {}

contacts_lock = threading.Lock()
_contacts: dict[str, ContactEntry] = {}

races_lock = threading.Lock()
active_races: dict[str, RaceState] = {}

windows_lock = threading.Lock()
active_windows: dict[str, WindowState] = {}

credits_lock = threading.Lock()


cache_lock = threading.Lock()
processed_hash_cache = deque()
processed_hash_set: set[str] = set()

def load_processed_hash_cache() -> None:
    global processed_hash_cache, processed_hash_set
    with cache_lock:
        processed_hash_cache.clear()
        processed_hash_set.clear()
    if not HASH_CACHE_PATH.exists():
        return
    try:
        with open(HASH_CACHE_PATH, "r", encoding="utf-8") as f:
            for line in f:
                h = line.strip()
                if not h:
                    continue
                if h in processed_hash_set:
                    continue
                processed_hash_cache.append(h)
                processed_hash_set.add(h)
                if len(processed_hash_cache) > CACHE_MAX:
                    old = processed_hash_cache.popleft()
                    processed_hash_set.discard(old)
        save_processed_hash_cache()
    except Exception as e:
        log.warning("[CACHE] failed to load hash cache: %s", e)

def save_processed_hash_cache() -> None:
    with cache_lock:
        snap = list(processed_hash_cache)
    HASH_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=HASH_CACHE_PATH.parent, delete=False, suffix=".tmp", encoding="utf-8") as tf:
            tf.write("\n".join(snap))
            tf.write("\n" if snap else "")
            tmp = tf.name
        os.replace(tmp, HASH_CACHE_PATH)
    except Exception:
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        raise


queue_lock = threading.Lock()
priority_queue: list = []
current_buffer_bytes = 0
relay_state: dict[str, RelayState] = {}

confirm_event = threading.Event()

# ----------------------------------------------------------------------------
# Trusted persistence
# ----------------------------------------------------------------------------

def _trusted_to_json() -> dict:
    with trusted_lock:
        return {fp: {"pubkey": entry.pubkey_pem, "points": entry.points} for fp, entry in _trusted.items()}


def load_trusted_keys() -> dict[str, TrustedEntry]:
    if not TRUSTED_KEYS_PATH.exists() and not CREDITS_PATH.exists():
        return {}
    path = TRUSTED_KEYS_PATH if TRUSTED_KEYS_PATH.exists() else CREDITS_PATH
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    result: dict[str, TrustedEntry] = {}
    for key, value in data.items():
        try:
            if isinstance(value, str):
                pem = value
                pts = 0
            else:
                pem = value.get("pubkey") or value.get("pem") or value.get("key")
                pts = int(value.get("points", 0))
            vk = VerifyingKey.from_pem(pem)
            fp = _fp(vk)
            result[fp] = TrustedEntry(pubkey_pem=pem, vk=vk, points=pts)
        except Exception as e:
            log.warning("[TRUSTED] Invalid entry for %s: %s", key, e)
    return result


def reload_trusted():
    global _trusted
    loaded = load_trusted_keys()
    with trusted_lock:
        _trusted = loaded


def save_trusted():
    snap = _trusted_to_json()
    _save_atomic(TRUSTED_KEYS_PATH, snap)
    _save_atomic(CREDITS_PATH, snap)


def get_trusted() -> dict[str, TrustedEntry]:
    with trusted_lock:
        return dict(_trusted)


def is_trusted(fp: str) -> bool:
    with trusted_lock:
        return fp in _trusted


def get_trusted_points(fp: str) -> int:
    with trusted_lock:
        entry = _trusted.get(fp)
        return entry.points if entry else 0


def add_or_update_trusted(fp: str, vk: VerifyingKey, points: int):
    with trusted_lock:
        if fp in _trusted:
            _trusted[fp].points += points
        else:
            _trusted[fp] = TrustedEntry(pubkey_pem=vk.to_pem().decode(), vk=vk, points=points)
        total = _trusted[fp].points
    save_trusted()
    log.info("[TRUSTED] %s +%d (total=%d)", fp, points, total)


def add_trusted_node(name: str, pem_or_b64: str) -> bool:
    raw = _normalize_pem_or_b64(pem_or_b64)
    try:
        vk = VerifyingKey.from_pem(raw)
    except Exception as e:
        log.error("[ADDNODE] Invalid key: %s", e)
        return False
    fp = _fp(vk)
    add_or_update_trusted(fp, vk, 0)
    remove_candidate(fp)
    log.info("[ADDNODE] Node '%s' added as trusted (%s)", name, fp)
    return True


def show_my_pubkey():
    b64 = base64.b64encode(MY_VK.to_der()).decode()
    print("\n=== MY PUBLIC KEY (share with other nodes) ===")
    print(f"  Fingerprint : {MY_NODE_ID}")
    print(f"  Base64 DER  : {b64}")
    print(f"  PEM:\n{MY_VK_PEM}")
    print("================================================\n")

# ----------------------------------------------------------------------------
# Candidates persistence
# ----------------------------------------------------------------------------

def load_candidates() -> dict[str, CandidateEntry]:
    if not CANDIDATES_PATH.exists():
        return {}
    with open(CANDIDATES_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    result: dict[str, CandidateEntry] = {}
    for key, value in data.items():
        try:
            if isinstance(value, str):
                pem = value
            else:
                pem = value.get("pubkey") or value.get("pem") or value.get("key")
            vk = VerifyingKey.from_pem(pem)
            result[_fp(vk)] = CandidateEntry(pubkey_pem=pem, vk=vk)
        except Exception as e:
            log.warning("[CANDIDATES] Invalid entry for %s: %s", key, e)
    return result


def reload_candidates():
    global _candidates
    loaded = load_candidates()
    with candidates_lock:
        _candidates = loaded
    log.info("[CANDIDATES] Loaded %d candidate(s)", len(loaded))


def save_candidates():
    with candidates_lock:
        snap = {fp: {"pubkey": entry.pubkey_pem} for fp, entry in _candidates.items()}
    _save_atomic(CANDIDATES_PATH, snap)


def get_candidates_list() -> list[str]:
    with candidates_lock:
        return list(_candidates.keys())


def get_candidate_vk(fp: str) -> Optional[VerifyingKey]:
    with candidates_lock:
        entry = _candidates.get(fp)
        return entry.vk if entry else None


def is_candidate(fp: str) -> bool:
    with candidates_lock:
        return fp in _candidates


def add_candidate(vk: VerifyingKey) -> bool:
    fp = _fp(vk)
    with candidates_lock:
        if fp in _candidates or is_trusted(fp):
            return False
        _candidates[fp] = CandidateEntry(pubkey_pem=vk.to_pem().decode(), vk=vk)
    save_candidates()
    log.info("[CANDIDATES] Added %s", fp)
    return True


def remove_candidate(fp: str) -> bool:
    with candidates_lock:
        if fp not in _candidates:
            return False
        del _candidates[fp]
    save_candidates()
    log.info("[CANDIDATES] Removed %s", fp)
    return True


def clear_candidates():
    with candidates_lock:
        _candidates.clear()
    save_candidates()
    print("[CANDIDATES] All candidates cleared.\n")


def remove_candidate_from_all_window_snapshots(fp: str):
    with windows_lock:
        for window in active_windows.values():
            window.snapshot.discard(fp)


def promote_candidate_to_trusted(fp: str, points: int) -> bool:
    with candidates_lock:
        cand = _candidates.get(fp)
        if cand is None:
            return False
    add_or_update_trusted(fp, cand.vk, points)
    remove_candidate(fp)
    remove_candidate_from_all_window_snapshots(fp)
    return True


def cmd_candidates():
    fps = get_candidates_list()
    print("\n=== CANDIDATES ===")
    if fps:
        for fp in fps:
            print(f"  {fp}")
    else:
        print("  (none)")
    print("=================\n")

# ----------------------------------------------------------------------------
# Contacts / ECIES
# ----------------------------------------------------------------------------

def _parse_contact_key(pem_or_b64: str):
    raw = _normalize_pem_or_b64(pem_or_b64)
    vk_ecdsa = VerifyingKey.from_pem(raw)
    vk_crypto = load_pem_public_key(vk_ecdsa.to_pem())
    return vk_ecdsa, vk_crypto


def load_contacts() -> dict[str, ContactEntry]:
    if not CONTACTS_PATH.exists():
        return {}
    with open(CONTACTS_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    result: dict[str, ContactEntry] = {}
    for name, value in data.items():
        try:
            if isinstance(value, str):
                pem = value
            else:
                pem = value.get("pubkey") or value.get("pem") or value.get("key")
            vk_ecdsa, vk_crypto = _parse_contact_key(pem)
            result[name.lower()] = ContactEntry(name=name, vk=vk_ecdsa, crypto_key=vk_crypto)
        except Exception as e:
            log.warning("[CONTACTS] Invalid entry for %s: %s", name, e)
    return result


def reload_contacts():
    global _contacts
    loaded = load_contacts()
    with contacts_lock:
        _contacts = loaded
    log.info("[CONTACTS] Loaded %d contact(s)", len(loaded))


def save_contacts():
    with contacts_lock:
        snap = {entry.name: {"pubkey": entry.vk.to_pem().decode()} for entry in _contacts.values()}
    _save_atomic(CONTACTS_PATH, snap)


def add_contact(name: str, pem_or_b64: str) -> bool:
    try:
        vk_ecdsa, vk_crypto = _parse_contact_key(pem_or_b64)
    except Exception as e:
        print(f"[ERROR] Invalid contact key: {e}")
        return False
    with contacts_lock:
        _contacts[name.lower()] = ContactEntry(name=name, vk=vk_ecdsa, crypto_key=vk_crypto)
    save_contacts()
    print(f"✓ Contact '{name}' saved (fp={_fp(vk_ecdsa)})")
    return True


def get_contact(name: str) -> Optional[ContactEntry]:
    with contacts_lock:
        entry = _contacts.get(name.lower())
        return entry


def cmd_contacts():
    with contacts_lock:
        snap = list(_contacts.values())
    print("\n=== CONTACTS ===")
    if snap:
        for c in sorted(snap, key=lambda x: x.name.lower()):
            print(f"  {c.name:<24} fp={_fp(c.vk)}")
    else:
        print("  (no contacts saved)")
    print("================\n")


def _derive_aes_key(shared: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=HKDF_INFO).derive(shared)


def encrypt_for_contact(plaintext: str, crypto_key) -> str:
    eph_sk = generate_private_key(SECP256R1())
    shared = eph_sk.exchange(ECDH(), crypto_key)
    aes_key = _derive_aes_key(shared)
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext.encode("utf-8"), None)
    eph_pub = eph_sk.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
    return base64.b64encode(eph_pub + nonce + ciphertext).decode("ascii")


def decrypt_message(content: str) -> Optional[str]:
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

# ----------------------------------------------------------------------------
# FIFO hash cache
# ----------------------------------------------------------------------------

def cache_contains(h: str) -> bool:
    with cache_lock:
        return h in processed_hash_set


def cache_add(h: str):
    with cache_lock:
        if h in processed_hash_set:
            return
        processed_hash_cache.append(h)
        processed_hash_set.add(h)
        if len(processed_hash_cache) > CACHE_MAX:
            old = processed_hash_cache.popleft()
            processed_hash_set.discard(old)
    save_processed_hash_cache()

# ----------------------------------------------------------------------------
# Races
# ----------------------------------------------------------------------------

def start_race(h: str, total_bytes: int):
    with races_lock:
        active_races[h] = RaceState(end=time.monotonic() + RACE_WINDOW_SEC, total_bytes=total_bytes)
    log.info("[RACE] Started hash=%s total_bytes=%d", h[:8], total_bytes)


def handle_return(h: str, signer_fp: str, signer_vk: VerifyingKey) -> bool:
    now = time.monotonic()
    with races_lock:
        race = active_races.get(h)
        if race is None:
            return False
        if now > race.end:
            active_races.pop(h, None)
            return False
        place = len(race.ranking) + 1
        race.ranking.append(signer_fp)
        total = race.total_bytes
        points = max(1, total // place)
    if is_candidate(signer_fp):
        promote_candidate_to_trusted(signer_fp, points)
    else:
        add_or_update_trusted(signer_fp, signer_vk, points)
    log.info("[CREDIT] return from %s place=%d +%d pts", signer_fp, place, points)
    return True


def race_watcher_thread():
    while True:
        time.sleep(0.5)
        now = time.monotonic()
        with races_lock:
            expired = [h for h, r in active_races.items() if now > r.end]
            for h in expired:
                del active_races[h]

# ----------------------------------------------------------------------------
# Expunge windows
# ----------------------------------------------------------------------------

def start_new_window(payload_hash: str):
    with candidates_lock:
        snapshot = set(_candidates.keys())
    with windows_lock:
        active_windows[payload_hash] = WindowState(end=time.monotonic() + WINDOW_SEC, snapshot=snapshot, payload_hash=payload_hash)
    log.info("[WINDOW] Started for %s with %d candidates", payload_hash[:8], len(snapshot))


def expunge_watcher_thread():
    while True:
        time.sleep(0.5)
        now = time.monotonic()
        expired: list[tuple[str, WindowState]] = []
        with windows_lock:
            for h, w in list(active_windows.items()):
                if now >= w.end:
                    expired.append((h, w))
                    del active_windows[h]
        for _, w in expired:
            for fp in list(w.snapshot):
                if is_candidate(fp):
                    remove_candidate(fp)
            log.info("[WINDOW] Expired payload=%s", w.payload_hash[:8])

# ----------------------------------------------------------------------------
# Signing / verification
# ----------------------------------------------------------------------------

def make_timestamp() -> str:
    return f"{time.time_ns():016x}"


def is_timestamp_valid(ts_hex: str) -> bool:
    try:
        diff = (time.time_ns() - int(ts_hex, 16)) / 1e9
        return -MAX_FUTURE_SEC <= diff <= MAX_RELAY_AGE_SEC
    except Exception:
        return False


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
    with trusted_lock:
        for fp, entry in _trusted.items():
            if verify_payload(payload, sig_b64, entry.vk):
                return (fp, entry.vk)
    with candidates_lock:
        for fp, entry in _candidates.items():
            if verify_payload(payload, sig_b64, entry.vk):
                return (fp, entry.vk)
    return None


def verify_invite(pubkey_der: bytes, sig_b64: str) -> bool:
    try:
        vk = VerifyingKey.from_der(pubkey_der)
        sig = base64.b64decode(sig_b64, validate=True)
        digest = hashlib.sha256(pubkey_der).digest()
        vk.verify_digest(sig, digest, sigdecode=sigdecode_string)
        return True
    except Exception:
        return False

# ----------------------------------------------------------------------------
# Relay queue
# ----------------------------------------------------------------------------

send_lock = threading.Lock()


def safe_send(transport, data: bytes):
    with send_lock:
        transport.send(data)


def enqueue_message(payload_hash: str, content: str, msg_id: str, origin_fp: str, base_priority: int):
    global current_buffer_bytes
    size = len((content + msg_id).encode("utf-8")) + SIG_CHARS
    if size <= 0:
        return
    with queue_lock:
        if current_buffer_bytes + size > MAX_BUFFER_BYTES:
            log.warning("[BUFFER] Full - dropping message from %s", origin_fp)
            return
        state = relay_state.get(payload_hash)
        if state is None:
            state = RelayState(base=max(1, base_priority))
            relay_state[payload_hash] = state
        current_buffer_bytes += size
        item = QueueItem(
            priority=max(1, state.base // (state.n_tx + 1)),
            enqueued_at=time.monotonic(),
            payload_hash=payload_hash,
            content=content,
            msg_id=msg_id,
            origin_fp=origin_fp,
            size=size,
            base=state.base,
            n_tx=state.n_tx,
            born=state.born,
        )
        heapq.heappush(priority_queue, item.as_heap_tuple())


def retransmit_worker(transport, stop_event: threading.Event):
    global current_buffer_bytes
    min_retx_interval = 0.5
    last_sent: dict[str, float] = {}
    while not stop_event.is_set():
        item = None
        with queue_lock:
            if priority_queue:
                item = QueueItem.from_heap_tuple(heapq.heappop(priority_queue))
        if item is None:
            time.sleep(0.05)
            continue

        now = time.monotonic()
        if now - last_sent.get(item.payload_hash, 0.0) < min_retx_interval:
            with queue_lock:
                heapq.heappush(priority_queue, item.as_heap_tuple())
            time.sleep(0.05)
            continue

        with queue_lock:
            state = relay_state.get(item.payload_hash)
        if state is None or (now - state.born) > QUEUE_TTL_SEC:
            log.info("[TX] Queue TTL expired - dropped | hash=%s", item.payload_hash[:8])
            with queue_lock:
                current_buffer_bytes = max(0, current_buffer_bytes - item.size)
                relay_state.pop(item.payload_hash, None)
            continue

        sig = sign_payload(item.content + item.msg_id)
        packet = f"tx {item.content} {item.msg_id} {sig}\n".encode("utf-8")

        try:
            confirm_event.clear()
            safe_send(transport, packet)
        except Exception as e:
            log.warning("[TX] Send failed, re-queuing: %s", e)
            with queue_lock:
                heapq.heappush(priority_queue, item.as_heap_tuple())
            time.sleep(0.5)
            continue

        try:
            confirm_event.wait(timeout=TX_CONFIRM_TIMEOUT)
        except Exception:
            pass

        if not confirm_event.is_set():
            log.warning("[TX] Timeout waiting for ESP32 confirmation")
            with queue_lock:
                heapq.heappush(priority_queue, item.as_heap_tuple())
            time.sleep(1.0)
            continue

        # confirmed
        new_n_tx = item.n_tx + 1
        new_priority = max(1, item.base // (new_n_tx + 1))
        last_sent[item.payload_hash] = now

        with queue_lock:
            state = relay_state.get(item.payload_hash)
            if state is not None:
                state.n_tx = new_n_tx

        if new_priority >= 1 and (now - item.born) <= QUEUE_TTL_SEC:
            with queue_lock:
                new_item = QueueItem(
                    priority=new_priority,
                    enqueued_at=time.monotonic(),
                    payload_hash=item.payload_hash,
                    content=item.content,
                    msg_id=item.msg_id,
                    origin_fp=item.origin_fp,
                    size=item.size,
                    base=item.base,
                    n_tx=new_n_tx,
                    born=item.born,
                )
                heapq.heappush(priority_queue, new_item.as_heap_tuple())
            log.info("[TX] Relayed+requeued | hash=%s priority=%d n_tx=%d", item.payload_hash[:8], new_priority, new_n_tx)
        else:
            with queue_lock:
                current_buffer_bytes = max(0, current_buffer_bytes - item.size)
                relay_state.pop(item.payload_hash, None)
            log.info("[TX] Final relay | hash=%s n_tx=%d", item.payload_hash[:8], new_n_tx)

        time.sleep(0.05)

# ----------------------------------------------------------------------------
# Invite handling
# ----------------------------------------------------------------------------

def send_invite(transport):
    pubkey_der = MY_VK.to_der()
    pubkey_b64 = base64.b64encode(pubkey_der).decode("ascii")
    digest = hashlib.sha256(pubkey_der).digest()
    sig_b64 = base64.b64encode(sk.sign_digest(digest, sigencode=sigencode_string)).decode("ascii")
    line = f"{pubkey_b64} {sig_b64}\r\n"
    safe_send(transport, line.encode("utf-8"))
    log.info("[INVITE] sent")


def process_invite(line: str) -> bool:
    parts = line.strip().split()
    if len(parts) != 2:
        return False
    pubkey_b64, sig_b64 = parts
    try:
        pubkey_der = base64.b64decode(pubkey_b64, validate=True)
        vk = VerifyingKey.from_der(pubkey_der)
        if not verify_invite(pubkey_der, sig_b64):
            return False
    except Exception:
        return False

    fp = _fp(vk)
    if fp == MY_NODE_ID:
        return True
    if is_trusted(fp):
        return True
    add_candidate(vk)
    log.info("[INVITE] Received candidate %s", fp)
    return True

# ----------------------------------------------------------------------------
# Incoming packet processing
# ----------------------------------------------------------------------------

def handle_lora_packet(content: str) -> bool:
    parts = content.strip().split()
    if parts and parts[0].lower() == "tx":
        parts = parts[1:]
    if len(parts) < 3:
        return False

    sig_b64 = parts[-1]
    msg_id = parts[-2]
    msg_content = " ".join(parts[:-2])

    payload_for_sig = msg_content + msg_id
    payload_hash = hashlib.sha256(payload_for_sig.encode("utf-8")).hexdigest()

    result = identify_signer(payload_for_sig, sig_b64)
    if result is None:
        return False

    signer_fp, signer_vk = result
    if signer_fp == MY_NODE_ID:
        return False

    if cache_contains(payload_hash):
        if handle_return(payload_hash, signer_fp, signer_vk):
            return True
        return False

    cache_add(payload_hash)

    decrypted = decrypt_message(msg_content)
    if decrypted is not None:
        print(f"\n🔒 [PRIVATE] de {signer_fp}: {decrypted}\n> ", end="", flush=True)
    else:
        print(f"\n📢 [OPEN]    de {signer_fp}: {msg_content}\n> ", end="", flush=True)

    if handle_return(payload_hash, signer_fp, signer_vk):
        return True

    if is_trusted(signer_fp):
        base_priority = max(1, get_trusted_points(signer_fp))
    elif is_candidate(signer_fp):
        base_priority = MIN_PRIORITY
    else:
        return False

    enqueue_message(payload_hash, msg_content, msg_id, signer_fp, base_priority)
    return True


def dispatch_line(line: str):
    raw = line.strip()

    if raw.startswith("[ESP32] "):
        raw = raw[len("[ESP32] "):].strip()

    if "[LoRa] OK" in raw:
        confirm_event.set()
        print(f"[ESP32] {line.strip()}")
        return

    if raw.startswith("[LoRa] "):
        content = raw[len("[LoRa] "):].strip()
        if content.startswith("tx "):
            if handle_lora_packet(content[3:].strip()):
                return
        else:
            if handle_lora_packet(content):
                return
            print(f"[ESP32] {content}")
        return

    if process_invite(raw):
        return
    if handle_lora_packet(raw):
        return

    print(f"[ESP32] {raw}")

# ----------------------------------------------------------------------------
# Commands
# ----------------------------------------------------------------------------

def is_esp_cmd(cmd: str) -> bool:
    parts = cmd.strip().split()
    return bool(parts) and parts[0].lower() in ESP_CMDS


def cmd_credits():
    with trusted_lock:
        snap = sorted(_trusted.items(), key=lambda x: x[1].points, reverse=True)
    print("\n=== TRUSTED (points) ===")
    if snap:
        for fp, entry in snap:
            print(f"  {fp} : {entry.points} pts")
    else:
        print("  (no trusted nodes yet)")
    print("========================\n")


def cmd_trusted():
    with trusted_lock:
        snap = sorted(_trusted.items(), key=lambda x: x[1].points, reverse=True)
    print("\n=== TRUSTED NODES (points) ===")
    if snap:
        for fp, entry in snap:
            print(f"  {fp} : {entry.points} pts")
    else:
        print("  (none)")
    print(f"  MY ID : {MY_NODE_ID}")
    print("=============================\n")


def _queue_snapshot():
    with queue_lock:
        snap = [QueueItem.from_heap_tuple(t) for t in sorted(priority_queue)]
        total = current_buffer_bytes
    return snap, total


def cmd_queue():
    now = time.monotonic()
    snap, total = _queue_snapshot()
    if not snap:
        print("\n=== QUEUE empty ===\n")
        return
    print(f"\n=== QUEUE ({len(snap)} msgs · {total} bytes) ===")
    for i, item in enumerate(snap[:20]):
        ttl = max(0.0, QUEUE_TTL_SEC - (now - item.born))
        print(
            f"  {i+1:2d}. prio={item.priority:4d} base={item.base:4d} tx={item.n_tx} ttl={ttl:4.0f}s "
            f"origin={item.origin_fp} size={item.size}b hash={item.payload_hash[:8]}..."
        )
    print("============================================\n")


def cmd_wifi_scan():
    import shutil
    import subprocess

    print("\n=== WIFI SCAN ===")

    def _run(cmd):
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=10)
            return out.decode("utf-8", errors="replace").strip()
        except Exception:
            return None

    result = None
    if shutil.which("nmcli"):
        result = _run(["nmcli", "-f", "SSID,SIGNAL,SECURITY", "dev", "wifi", "list"])
    elif shutil.which("iwlist"):
        raw = _run(["iwlist", "wlan0", "scan"])
        if raw:
            result = "\n".join(l.strip() for l in raw.splitlines() if "ESSID" in l)
    elif shutil.which("netsh"):
        result = _run(["netsh", "wlan", "show", "networks"])
    elif _to_bool_env("/data/data/com.termux"):
        result = _run(["termux-wifi-scaninfo"])

    if result:
        print(result)
    else:
        print("  No supported WiFi scan tool found.")

    ap_ip = CFG.get("wifi_ap_ip", "192.168.4.1")
    ssid = CFG.get("wifi_ap_ssid", "")
    print(f"\n  Configured ESP32 AP  : {ssid or '(wifi_ap_ssid not set in config.json)'}")
    print(f"  Configured ESP32 IP  : {ap_ip}")
    print("=================\n")

# ----------------------------------------------------------------------------
# Transport abstraction
# ----------------------------------------------------------------------------

class Transport(ABC):
    @abstractmethod
    def connect(self): ...

    @abstractmethod
    def send(self, data: bytes): ...

    @abstractmethod
    def close(self): ...

    @abstractmethod
    def label(self) -> str: ...

    @abstractmethod
    def start_reader(self, line_queue, stop_event): ...


class TcpTransport(Transport):
    def __init__(self, host, port):
        self._host = host
        self._port = port
        self._sock = None
        self._lock = threading.Lock()

    def label(self):
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

    def send(self, data):
        sock = self._get_sock()
        if sock is None:
            raise OSError("TCP socket not connected")
        sock.sendall(data)

    def close(self):
        with self._lock:
            s, self._sock = self._sock, None
        if s:
            try:
                s.close()
            except Exception:
                pass

    def start_reader(self, line_queue, stop_event):
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
                        log.warning("[TCP] peer closed connection")
                        break
                    buf += chunk.decode("utf-8", errors="replace")
                    buf, lines = _split_lines(buf)
                    for line in lines:
                        line_queue.put(line)
                except (OSError, ValueError) as e:
                    log.warning("[TCP] reader error: %s", e)
                    break
                except Exception as e:
                    log.warning("[TCP] unexpected reader error: %s", e)
                    break
            line_queue.put(None)

        threading.Thread(target=_run, daemon=True, name="tcp-reader").start()


class WifiApTransport(TcpTransport):
    def label(self):
        return f"WIFI_AP {self._host}:{self._port}"

    def connect(self):
        try:
            super().connect()
        except Exception as e:
            raise OSError(f"Cannot reach ESP32 at {self._host}:{self._port}. Check WiFi AP, IP, and port.") from e


class SerialTransport(Transport):
    def __init__(self, device, baudrate, kind="usb"):
        self._device = device
        self._baudrate = baudrate
        self._kind = kind
        self._ser = None
        self._lock = threading.Lock()

    def label(self):
        return f"{self._kind.upper()} {self._device}@{self._baudrate}"

    def connect(self):
        if not _SERIAL_AVAILABLE:
            raise ImportError("pyserial is not installed")
        try:
            ser = serial.Serial(
                port=self._device,
                baudrate=self._baudrate,
                timeout=SERIAL_READ_TIMEOUT,
                exclusive=True,
            )
        except TypeError:
            ser = serial.Serial(port=self._device, baudrate=self._baudrate, timeout=SERIAL_READ_TIMEOUT)

        time.sleep(2.0)
        try:
            ser.reset_input_buffer()
            ser.reset_output_buffer()
        except Exception:
            pass

        with self._lock:
            self._ser = ser

    def _get_ser(self):
        with self._lock:
            return self._ser

    def send(self, data):
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

    def start_reader(self, line_queue, stop_event):
        def _run():
            buf = ""
            while not stop_event.is_set():
                try:
                    ser = self._get_ser()
                    if ser is None or not ser.is_open:
                        break
                    raw = ser.read_until(b"\n")
                    if not raw:
                        raw = ser.read_until(b"\r")
                        if not raw:
                            continue
                    decoded = raw.decode("utf-8", errors="replace")
                    if raw.endswith(b"\r") and not raw.endswith(b"\n"):
                        decoded += "\n"
                    buf += decoded
                    buf, lines = _split_lines(buf)
                    for line in lines:
                        line_queue.put(line)
                except Exception as e:
                    log.warning("[%s] reader error: %s", self._kind.upper(), e)
                    break
            line_queue.put(None)

        threading.Thread(target=_run, daemon=True, name=f"{self._kind}-reader").start()


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
        for mode in [primary] + [x for x in order if x != primary]:
            if mode not in seen:
                seen.add(mode)
                ordered.append(mode)
        chain = []
        for mode in ordered:
            t = self._make_transport(mode)
            if t:
                chain.append(t)
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
            return WifiApTransport(cfg.get("wifi_ap_ip", "192.168.4.1"), int(cfg.get("wifi_ap_port", 8080)))
        return None

    def connect_next(self):
        if not self._chain:
            raise RuntimeError("No transports configured")
        n = len(self._chain)
        start = self._index
        for i in range(n):
            idx = (start + i) % n
            t = self._chain[idx]
            log.info("[TRANSPORT] Trying %s", t.label())
            try:
                t.connect()
                log.info("[TRANSPORT] Connected via %s", t.label())
                self._index = idx
                return t
            except Exception as e:
                log.warning("[TRANSPORT] %s failed: %s", t.label(), e)
        self._index = (start + 1) % n
        raise RuntimeError("All transports failed")

# ----------------------------------------------------------------------------
# Input / stdin thread
# ----------------------------------------------------------------------------

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

# ----------------------------------------------------------------------------
# Message sending
# ----------------------------------------------------------------------------

def send_normal_message(transport, text: str, encrypt_to: Optional[str] = None) -> bool:
    if encrypt_to is not None:
        contact = get_contact(encrypt_to)
        if contact is None:
            print(f"[ERROR] Unknown contact '{encrypt_to}'")
            return False
        try:
            content = encrypt_for_contact(text, contact.crypto_key)
        except Exception as e:
            print(f"[ERROR] Encryption failed: {e}")
            return False
        if len(content.encode("utf-8")) > MAX_ENC_LEN:
            print(f"[ERROR] Encrypted message too long (max {MAX_ENC_LEN} bytes)")
            return False
    else:
        content = text
        if len(content.encode("utf-8")) > MAX_MSG_LEN:
            print(f"[ERROR] Message too long (max {MAX_MSG_LEN} UTF-8 bytes)")
            return False

    msg_id = secrets.token_hex(10)
    payload_for_sig = content + msg_id
    sig_b64 = sign_payload(payload_for_sig)
    packet = f"tx {content} {msg_id} {sig_b64}\n".encode("utf-8")
    payload_hash = hashlib.sha256(payload_for_sig.encode("utf-8")).hexdigest()
    total_bytes = len(content.encode("utf-8")) + len(msg_id.encode("utf-8")) + len(sig_b64.encode("utf-8"))

    try:
        safe_send(transport, packet)
    except Exception as e:
        print(f"[ERROR] Send failed: {e}")
        return False

    cache_add(payload_hash)
    start_race(payload_hash, total_bytes)
    start_new_window(payload_hash)
    return True

# ----------------------------------------------------------------------------
# Background cleanup
# ----------------------------------------------------------------------------

def cleanup_thread():
    while True:
        time.sleep(CACHE_CLEAN_INTERVAL)
        now = time.monotonic()
        with races_lock:
            for h in [h for h, r in active_races.items() if now > r.end]:
                del active_races[h]
        expired_windows = []
        with windows_lock:
            for h, w in list(active_windows.items()):
                if now >= w.end:
                    expired_windows.append(w)
                    del active_windows[h]
        for w in expired_windows:
            for fp in list(w.snapshot):
                if is_candidate(fp):
                    remove_candidate(fp)
        save_trusted()
        save_candidates()
        save_contacts()

# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------

def main():
    reload_trusted()
    reload_candidates()
    reload_contacts()
    load_processed_hash_cache()

    print(f"""
╔══════════════════════════════════════════════════════════════════╗
║                   WELCOME TO {PROJECT_NAME}!                      ║
║                                                                  ║
║  ID+hash FIFO · races · expunge windows · ECIES · invite         ║
║                                                                  ║
║  Time window : 20 min past · 10 min future                       ║
║  Cache FIFO  : {CACHE_MAX} hashes                                 ║
║  Queue TTL   : {QUEUE_TTL_SEC:.0f}s                              ║
║                                                                  ║
║  {MONERO_ADDRESS}                                                ║
╚══════════════════════════════════════════════════════════════════╝
""")
    print(f"[START] My fingerprint  : {MY_NODE_ID}")
    print(f"[START] Trusted peers   : {list(get_trusted().keys()) or '(none)'}")
    with contacts_lock:
        print(f"[START] Contacts        : {len(_contacts)} saved")
    print(f"[START] Candidates      : {len(get_candidates_list())} saved")
    print(f"[START] Max buffer      : {MAX_BUFFER_BYTES // 1024 // 1024} MB")
    print(f"[START] pyserial        : {'available' if _SERIAL_AVAILABLE else 'NOT installed'}")
    print(f"[START] Primary mode    : {CFG.get('connection_type', 'tcp').upper()}")
    print()

    print("Commands:")
    print("  <message>:<contact>      — send ENCRYPTED message to a contact")
    print("  <message>                — send PLAINTEXT message (asks confirmation)")
    print("  contacts                 — list saved contacts")
    print("  addcontact <name> <key>  — add a contact")
    print("  credits                  — view trusted nodes and points")
    print("  queue                    — view retransmission queue")
    print("  trusted                  — view trusted relay nodes")
    print("  addnode <name> <key>     — add a trusted relay node")
    print("  mykey                    — show your public key")
    print("  invite                   — send your public key as an invitation")
    print("  candidates               — list current candidates")
    print("  clear_candidates         — remove all candidates")
    print("  wifiscan                 — list nearby WiFi networks")
    print("  clear                    — clear screen")
    print("  <ESP32 command>          — status sf bw freq cr pwr diag reset...\n")

    threading.Thread(target=cleanup_thread, daemon=True, name="cleanup").start()

    stdin_queue = queue.Queue()
    threading.Thread(target=stdin_reader_thread, args=(stdin_queue,), daemon=True, name="stdin-reader").start()

    manager = TransportManager(CFG)
    pending_confirm: Optional[tuple[str, Optional[str]]] = None
    RETRY_DELAY = 5

    while True:
        transport = None
        stop_event = None
        worker = None
        line_queue = queue.Queue()

        try:
            transport = manager.connect_next()
        except RuntimeError as e:
            log.error("[MAIN] %s - retrying in %ds...", e, RETRY_DELAY)
            time.sleep(RETRY_DELAY)
            continue

        try:
            if isinstance(transport, SerialTransport):
                time.sleep(2.0)
                try:
                    transport.send(b"")
                except Exception:
                    pass

            stop_event = threading.Event()
            transport.start_reader(line_queue, stop_event)
            worker = threading.Thread(target=retransmit_worker, args=(transport, stop_event), daemon=True, name="tx-worker")
            worker.start()

            connection_lost = False
            while not connection_lost:
                while True:
                    try:
                        line = line_queue.get_nowait()
                    except queue.Empty:
                        break
                    if line is None:
                        log.warning("[MAIN] Transport disconnected")
                        connection_lost = True
                        break
                    dispatch_line(line)
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
                        text, contact_name = pending_confirm
                        if contact_name:
                            ok = send_normal_message(transport, text, encrypt_to=contact_name)
                            if ok:
                                print(f"🔒 [SENT ENCRYPTED] to '{contact_name}'")
                        else:
                            ok = send_normal_message(transport, text)
                            if ok:
                                log.info("[SENT PLAINTEXT] queued for race/window")
                        pending_confirm = None
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
                elif low == "invite":
                    try:
                        send_invite(transport)
                    except Exception as e:
                        log.error("[INVITE] failed: %s", e)
                elif low == "candidates":
                    cmd_candidates()
                elif low == "clear_candidates":
                    clear_candidates()
                elif low.startswith("addnode "):
                    parts = cmd.split(maxsplit=2)
                    if len(parts) == 3:
                        print("✓" if add_trusted_node(parts[1], parts[2]) else "✗ Invalid key")
                    else:
                        print("Usage: addnode <name> <base64_key_or_PEM>")
                elif low.startswith("addcontact "):
                    parts = cmd.split(maxsplit=2)
                    if len(parts) == 3:
                        print("✓" if add_contact(parts[1], parts[2]) else "✗ Invalid key")
                    else:
                        print("Usage: addcontact <name> <base64_key_or_PEM>")
                elif is_esp_cmd(cmd):
                    try:
                        safe_send(transport, f"{cmd}\r\n".encode("utf-8"))
                        print(f"[CMD] {cmd}")
                    except Exception as e:
                        log.error("[CMD] Send failed: %s", e)
                else:
                    contact_name = None
                    text = cmd
                    if ":" in cmd:
                        left, right = cmd.rsplit(":", 1)
                        candidate = right.strip()
                        if candidate and get_contact(candidate):
                            text = left.strip()
                            contact_name = candidate

                    if not text.strip():
                        print("[ERROR] Empty message.")
                        continue

                    if contact_name:
                        ok = send_normal_message(transport, text, encrypt_to=contact_name)
                        if ok:
                            print(f"🔒 [SENT ENCRYPTED] to '{contact_name}'")
                    else:
                        if len(text.encode("utf-8")) > MAX_MSG_LEN:
                            print(f"[ERROR] Message too long (max {MAX_MSG_LEN} UTF-8 bytes)")
                            continue
                        print("\n⚠️  This message is NOT encrypted.")
                        print("    Any node on the network will be able to read it.")
                        print("    Are you sure you want to send it? (yes / no)\n> ", end="", flush=True)
                        pending_confirm = (text, None)

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

        log.info("[MAIN] Reconnecting in %ds...", RETRY_DELAY)
        time.sleep(RETRY_DELAY)


if __name__ == "__main__":
    main()
