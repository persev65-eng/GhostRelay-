#!/usr/bin/env python3
"""
GhostRelay - LoRa mesh relay with ECDSA signatures, ECIES encryption, and credit system.

PROTOCOL:
  - Node A creates: payload = text + 16hex_timestamp
                    signs with private key → tx <payload><sigA>
  - Node B receives: verifies sigA against trusted_keys.json.
      Unknown key → silently discard.
      Known key   → strip sigA, sign same payload with sigB → retransmit.
      Queue priority = accumulated credit of the signer who delivered the message.
  - When msg[sigB] returns to A: A recognises payload (original_cache),
      credits B with total_pts // place (1st=100%, 2nd=50%, 3rd=33%, N=100/N%).
  - When msg[sigB] arrives at D: D treats it as a new message from B,
      re-signs with sigD. When sigD returns to B: B recognises payload
      (relayed_cache) and credits D — same logic at every hop.
  - Time window: timestamp older than 20 min or more than 10 min in future → discard.
  - Duplicate: same (payload, signer_fp) → ignore.
  - Max buffer: 10 MB.

CONTACTS AND ENCRYPTION:
  - Contacts stored in contacts.json: name → public key PEM.
  - Encrypted send: "message:contact_name"
      Message is encrypted with ECIES (ECDH ephemeral + HKDF + AES-256-GCM).
      Travels the network as opaque base64 — indistinguishable from random data.
      Only the holder of the matching private key can decrypt it.
  - Plaintext send: "message" (no :contact suffix)
      Displays a warning and asks for confirmation before sending.
  - Every received message is silently attempted for decryption.
      If it succeeds → shown as private. Otherwise shown as plaintext.
  - addcontact <name> <base64_or_PEM> — add a contact.

PACKET FORMAT ON THE NETWORK:
  tx <payload><sig88chars>\n
  payload = <content_utf8><16hex_timestamp>
  content = plaintext OR base64(ECIES blob) — no prefix, no marker
  sig     = base64 of 64-byte ECDSA NIST-P256 signature → always 88 chars

ECIES BLOB LAYOUT (bytes before base64 encoding):
  [0 :33] ephemeral compressed public key (SECP256R1)
  [33:45] AES-GCM nonce (12 bytes)
  [45:  ] ciphertext + GCM authentication tag (16 bytes at the end)

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
import select
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

# ECDSA signing / verification
from ecdsa import BadSignatureError, NIST256p, SigningKey, VerifyingKey
from ecdsa.util import sigdecode_string, sigencode_string

# ECIES encryption (ECDH + HKDF + AES-256-GCM)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec as _ec
from cryptography.hazmat.primitives.asymmetric.ec import ECDH, SECP256R1, generate_private_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

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

MAX_BUFFER_BYTES      = 10 * 1024 * 1024  # 10 MB
MAX_MSG_LEN           = 200               # max bytes of plaintext (excl. timestamp + sig)
MAX_ENC_LEN           = 400               # max bytes of encrypted blob (larger than plaintext)
MAX_RECV_BUF          = 64 * 1024         # 64 KB — max newline-free TCP fragment
CACHE_EXPIRE_SEC      = 20 * 60
MAX_RELAY_AGE_SEC     = 20 * 60           # reject timestamps older than 20 min
MAX_FUTURE_SEC        = 10 * 60           # reject timestamps more than 10 min ahead
SIG_CHARS             = 88                # base64(64 bytes) → 88 chars, always
TIMESTAMP_CHARS       = 16               # 16 hex chars = uint64 nanoseconds
CREDITS_SAVE_INTERVAL = 10               # seconds between credit saves
CACHE_CLEAN_INTERVAL  = 60               # seconds between cache cleanups
MAX_PRIO_REORDERS     = 5                # max consecutive priority re-evaluations before forcing send
CONNECT_TIMEOUT_SEC   = 10               # TCP connect timeout  [BUG-3 FIX]
HKDF_INFO             = b"ghostrelay-ecies-v1"

ESP_CMDS = {"status", "help", "reset", "diag", "debug3", "sf", "bw", "freq", "cr", "pwr"}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("ghostrelay")

# ------------------------------------------------------------------------------
# Config
# ------------------------------------------------------------------------------

def load_config():
    with open(CONFIG_PATH) as f:
        cfg = json.load(f)
    return cfg.get("tcp_host", "127.0.0.1"), int(cfg.get("tcp_port", 8080))

HOST, PORT = load_config()

# ------------------------------------------------------------------------------
# Private key / node identity
# ------------------------------------------------------------------------------

def load_or_create_key():
    APP_DIR.mkdir(exist_ok=True)
    if KEY_PATH.exists():
        key = SigningKey.from_pem(KEY_PATH.read_bytes())
        log.info("[KEY] Loaded private key from %s", KEY_PATH)
        return key
    key = SigningKey.generate(curve=NIST256p)
    KEY_PATH.write_bytes(key.to_pem())
    # BUG-6 FIX: restrict key file to owner-read-write only (600)
    try:
        os.chmod(KEY_PATH, 0o600)
    except Exception as e:
        log.warning("[KEY] Could not set key file permissions: %s", e)
    log.info("[KEY] Generated new private key at %s", KEY_PATH)
    return key

sk        = load_or_create_key()
MY_VK     = sk.get_verifying_key()
MY_VK_PEM = MY_VK.to_pem().decode()

# cryptography-library private key (used for ECDH decryption only)
_crypto_sk = load_pem_private_key(sk.to_pem(), password=None)

def _fp(vk):
    """8-hex-char fingerprint — cryptographic identity of a node."""
    return hashlib.sha256(vk.to_string()).hexdigest()[:8]

MY_NODE_ID = _fp(MY_VK)

# ------------------------------------------------------------------------------
# Atomic persistence
# BUG-1 FIX: clean up temp file if json.dump fails
# ------------------------------------------------------------------------------

def _save_atomic(path, data):
    """Write JSON atomically via a temp file + os.replace."""
    APP_DIR.mkdir(exist_ok=True)
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", dir=APP_DIR, delete=False, suffix=".tmp"
        ) as tf:
            json.dump(data, tf, indent=2, ensure_ascii=False)
            tmp = tf.name
        os.replace(tmp, path)
    except Exception:
        # Remove the orphaned temp file so it doesn't accumulate on disk
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        raise

# ------------------------------------------------------------------------------
# Trusted relay nodes  (trusted_keys.json)
# ------------------------------------------------------------------------------

trusted_lock = threading.Lock()
_trusted = {}   # fp → VerifyingKey

def load_trusted_keys():
    """Load trusted_keys.json from disk. No locks — caller decides."""
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

def get_trusted():
    with trusted_lock:
        return dict(_trusted)

def reload_trusted():
    """Reload from disk. I/O happens outside the lock to avoid blocking."""
    global _trusted
    loaded = load_trusted_keys()   # file I/O — no lock held here
    with trusted_lock:
        _trusted = loaded

def add_trusted_node(name, pem_or_b64):
    """Add a trusted relay peer. Accepts full PEM or raw base64 DER."""
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
# Contacts  (contacts.json)
# ------------------------------------------------------------------------------

contacts_lock = threading.Lock()
# name_lower → {"name": str, "vk": VerifyingKey, "vk_crypto": EllipticCurvePublicKey}
_contacts = {}

def _parse_contact_key(pem_or_b64):
    """
    Parse a public key from PEM or raw base64 DER.
    Returns (VerifyingKey, EllipticCurvePublicKey).
    """
    raw = pem_or_b64.strip()
    if not raw.startswith("-----"):
        raw = f"-----BEGIN PUBLIC KEY-----\n{raw}\n-----END PUBLIC KEY-----\n"
    vk_ecdsa  = VerifyingKey.from_pem(raw)
    vk_crypto = load_pem_public_key(vk_ecdsa.to_pem())
    return vk_ecdsa, vk_crypto

def load_contacts():
    """Load contacts.json from disk. Called once at startup."""
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
                loaded[name.lower()] = {
                    "name": name,
                    "vk": vk_ecdsa,
                    "vk_crypto": vk_crypto,
                }
            except Exception as e:
                log.warning("[CONTACTS] Invalid key for '%s': %s", name, e)
        with contacts_lock:
            _contacts = loaded
        log.info("[CONTACTS] Loaded %d contact(s)", len(loaded))
    except Exception as e:
        log.warning("[CONTACTS] Failed to load contacts.json: %s", e)

def _save_contacts():
    """Persist contacts to disk (called after every mutation)."""
    with contacts_lock:
        snap = {v["name"]: v["vk"].to_pem().decode() for v in _contacts.values()}
    _save_atomic(CONTACTS_PATH, snap)

def add_contact(name, pem_or_b64):
    """Add or update a contact. Returns True on success."""
    try:
        vk_ecdsa, vk_crypto = _parse_contact_key(pem_or_b64)
    except Exception as e:
        print(f"[ERROR] Invalid key: {e}")
        return False
    entry = {"name": name, "vk": vk_ecdsa, "vk_crypto": vk_crypto}
    with contacts_lock:
        _contacts[name.lower()] = entry
    _save_contacts()
    print(f"✓ Contact '{name}' saved (fp={_fp(vk_ecdsa)})")
    return True

def get_contact(name):
    """
    Look up a contact by name (case-insensitive).
    Returns a *copy* of the entry dict, or None.
    """
    with contacts_lock:
        entry = _contacts.get(name.lower())
        return dict(entry) if entry is not None else None

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
# ECIES encryption / decryption
# ------------------------------------------------------------------------------

def _derive_aes_key(shared_secret: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=HKDF_INFO,
    ).derive(shared_secret)

def encrypt_for_contact(plaintext: str, vk_crypto) -> str:
    """
    Encrypt plaintext for a recipient using ECIES.
    Returns a base64 string (no prefix or marker).
    Indistinguishable from random data to any third party.

    Blob layout (before base64):
      [0 :33] ephemeral compressed public key
      [33:45] AES-GCM nonce (12 bytes, random)
      [45:  ] ciphertext + 16-byte GCM tag
    """
    eph_sk        = generate_private_key(SECP256R1())
    shared        = eph_sk.exchange(ECDH(), vk_crypto)
    aes_key       = _derive_aes_key(shared)
    nonce         = os.urandom(12)
    ciphertext    = AESGCM(aes_key).encrypt(nonce, plaintext.encode("utf-8"), None)
    eph_pub_bytes = eph_sk.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.CompressedPoint,
    )
    return base64.b64encode(eph_pub_bytes + nonce + ciphertext).decode("ascii")

def decrypt_message(content: str):
    """
    Silently attempt to decrypt content using our private key.
    Returns the plaintext string if decryption succeeds, else None.

    Failure is the normal case for messages addressed to other nodes —
    the AES-GCM authentication tag cleanly rejects wrong keys.
    """
    try:
        # validate=True rejects non-base64 characters immediately
        raw = base64.b64decode(content, validate=True)
        if len(raw) < 33 + 12 + 16:
            return None
        eph_key = _ec.EllipticCurvePublicKey.from_encoded_point(SECP256R1(), raw[:33])
        shared  = _crypto_sk.exchange(ECDH(), eph_key)
        aes_key = _derive_aes_key(shared)
        plain   = AESGCM(aes_key).decrypt(raw[33:45], raw[45:], None)
        return plain.decode("utf-8")
    except Exception:
        return None

# ------------------------------------------------------------------------------
# Credits
# ------------------------------------------------------------------------------

credits_lock = threading.Lock()
credits = {}              # fp → total points

credited_order_lock = threading.Lock()
credited_order = {}       # payload → [fp1, fp2, ...] in return order

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

def get_credit(fp):
    with credits_lock:
        return credits.get(fp, 0)

def add_credit(fp, points):
    with credits_lock:
        credits[fp] = credits.get(fp, 0) + points
        total = credits[fp]
    # Log outside the lock — avoids potential deadlock with logging handlers
    log.info("[CREDIT] +%d to %s (total: %d)", points, fp, total)

# ------------------------------------------------------------------------------
# Caches
# ------------------------------------------------------------------------------

cache_lock     = threading.Lock()
original_cache = {}   # payload → monotonic  (I created this)
relayed_cache  = {}   # payload → monotonic  (I already relayed this)
seen_packets   = {}   # (payload, signer_fp) → monotonic  (dedup per signer)

def mark_original(payload):
    with cache_lock:
        original_cache[payload] = time.monotonic()

def mark_relayed(payload):
    with cache_lock:
        relayed_cache[payload] = time.monotonic()

def i_know_payload(payload):
    """True if I created OR already relayed this payload."""
    with cache_lock:
        return payload in original_cache or payload in relayed_cache

def mark_seen(payload, signer_fp):
    with cache_lock:
        seen_packets[(payload, signer_fp)] = time.monotonic()

def already_seen(payload, signer_fp):
    with cache_lock:
        return (payload, signer_fp) in seen_packets

def clean_caches_once():
    now    = time.monotonic()
    cutoff = now - CACHE_EXPIRE_SEC
    with cache_lock:
        for d in (original_cache, relayed_cache):
            for k in [k for k, t in d.items() if t < cutoff]:
                d.pop(k, None)
        for k in [k for k, t in seen_packets.items() if t < cutoff]:
            seen_packets.pop(k, None)
        known = set(original_cache) | set(relayed_cache)
    # Remove credited_order entries for payloads no longer in any cache
    with credited_order_lock:
        for p in [p for p in credited_order if p not in known]:
            del credited_order[p]

def cache_cleaner_thread():
    while True:
        time.sleep(CACHE_CLEAN_INTERVAL)
        try:
            clean_caches_once()
        except Exception as e:
            log.warning("[CACHE] Cleanup error: %s", e)

# ------------------------------------------------------------------------------
# ECDSA signing / verification
# ------------------------------------------------------------------------------

def sign_payload(payload: str) -> str:
    """Sign payload with our private key. Returns always-88-char base64."""
    digest    = hashlib.sha256(payload.encode("utf-8")).digest()
    sig_bytes = sk.sign_digest(digest, sigencode=sigencode_string)
    return base64.b64encode(sig_bytes).decode("ascii")

def verify_payload(payload: str, sig_b64: str, vk) -> bool:
    try:
        # validate=True: reject malformed base64 before passing to crypto
        sig    = base64.b64decode(sig_b64, validate=True)
        digest = hashlib.sha256(payload.encode("utf-8")).digest()
        vk.verify_digest(sig, digest, sigdecode=sigdecode_string)
        return True
    except Exception:
        return False

def identify_signer(payload: str, sig_b64: str):
    """
    Try to match (payload, sig) against our own key, then all trusted nodes.
    Returns (fingerprint, VerifyingKey) or None.
    """
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
# Priority queue
# heap entries: (priority, enqueue_time, payload, origin_fp, size)
# priority = -credit(origin_fp): lower number = higher priority = more credit
# ------------------------------------------------------------------------------

queue_lock           = threading.Lock()
priority_queue       = []
current_buffer_bytes = 0

def enqueue(payload: str, origin_fp: str):
    global current_buffer_bytes
    size     = len(payload.encode("utf-8"))
    priority = -get_credit(origin_fp)
    with queue_lock:
        if current_buffer_bytes + size > MAX_BUFFER_BYTES:
            log.warning("[BUFFER] Full — message from %s dropped", origin_fp)
            return
        heapq.heappush(priority_queue, (priority, time.monotonic(), payload, origin_fp, size))
        current_buffer_bytes += size

# ------------------------------------------------------------------------------
# Retransmission worker thread
# ------------------------------------------------------------------------------

send_lock = threading.Lock()

def safe_send(sock, data: bytes):
    """
    Thread-safe send. Sets socket to blocking for the duration of the send.
    BUG-2 FIX: setblocking(False) in finally is wrapped so that if the
    socket is already closed/invalid, the original exception is not masked.
    """
    with send_lock:
        try:
            sock.setblocking(True)
            sock.sendall(data)
        finally:
            try:
                sock.setblocking(False)
            except Exception:
                pass   # socket may already be closed; ignore

def retransmit_worker(sock, stop_event):
    global current_buffer_bytes
    reorder_count = 0

    while not stop_event.is_set():
        item = None
        with queue_lock:
            if priority_queue:
                item = heapq.heappop(priority_queue)

        if item is None:
            reorder_count = 0
            time.sleep(0.05)
            continue

        stored_prio, enqueue_time, payload, origin_fp, size = item

        # Re-evaluate priority (credit may have changed since enqueue).
        # Bounded by MAX_PRIO_REORDERS to prevent infinite re-queueing
        # when the entire queue has stale priorities simultaneously.
        current_prio = -get_credit(origin_fp)
        if current_prio != stored_prio and reorder_count < MAX_PRIO_REORDERS:
            with queue_lock:
                heapq.heappush(
                    priority_queue,
                    (current_prio, enqueue_time, payload, origin_fp, size),
                )
            reorder_count += 1
            time.sleep(0.01)
            continue

        reorder_count = 0

        # Discard if we have already relayed or created this payload
        if i_know_payload(payload):
            with queue_lock:
                current_buffer_bytes = max(0, current_buffer_bytes - size)
            continue

        # BUG-4 FIX: removed dead-code length check (guaranteed by enqueue minimum)

        # Timestamp may have expired while the message waited in the queue
        if not is_timestamp_valid(payload[-TIMESTAMP_CHARS:]):
            log.info("[TX] Timestamp expired in queue — dropped")
            with queue_lock:
                current_buffer_bytes = max(0, current_buffer_bytes - size)
            continue

        new_sig = sign_payload(payload)
        packet  = f"tx {payload}{new_sig}\n".encode("utf-8")

        try:
            safe_send(sock, packet)
            mark_relayed(payload)
            with queue_lock:
                current_buffer_bytes = max(0, current_buffer_bytes - size)
            log.info(
                "[TX] Relayed | origin=%s credit=%d size=%db",
                origin_fp, get_credit(origin_fp), len(payload),
            )
        except Exception as e:
            log.warning("[TX] Send failed, re-queuing: %s", e)
            with queue_lock:
                heapq.heappush(priority_queue, item)
            time.sleep(0.5)
            continue

        time.sleep(0.05)

# ------------------------------------------------------------------------------
# Incoming packet processing
# ------------------------------------------------------------------------------

def handle_lora_packet(content: str):
    """
    Process one packet received from the ESP32.
    content = everything after "[LoRa] ", with any leading "tx " already stripped.
    Expected structure: <payload><sig88chars>
    """
    if len(content) < TIMESTAMP_CHARS + SIG_CHARS + 1:
        return

    sig_b64 = content[-SIG_CHARS:]
    payload  = content[:-SIG_CHARS]

    # 1. Identify and verify signer
    result = identify_signer(payload, sig_b64)
    if result is None:
        log.debug("[RX] Unknown signer or bad signature")
        return

    signer_fp, _ = result

    # 2. Ignore echo of our own transmissions
    if signer_fp == MY_NODE_ID:
        return

    # 3. Validate timestamp
    # NOTE: len(payload) >= TIMESTAMP_CHARS is guaranteed by the length check above
    if not is_timestamp_valid(payload[-TIMESTAMP_CHARS:]):
        log.debug("[RX] Timestamp out of window")
        return

    # 4. Deduplication: same payload + same signer → ignore
    if already_seen(payload, signer_fp):
        return
    mark_seen(payload, signer_fp)

    # 5. Known payload → it's a return of something we sent or relayed → credit
    #    BUG-8 FIX: compute reward inside the lock but call add_credit OUTSIDE it.
    #    This avoids holding credited_order_lock while acquiring credits_lock,
    #    eliminating the unnecessary nested lock pattern.
    if i_know_payload(payload):
        reward = None
        place  = None
        with credited_order_lock:
            order = credited_order.setdefault(payload, [])
            if signer_fp not in order:
                place     = len(order) + 1   # 1-based position
                text_len  = len(payload[:-TIMESTAMP_CHARS].encode("utf-8"))
                total_pts = text_len + TIMESTAMP_CHARS + SIG_CHARS
                # 1st=100%, 2nd=50%, 3rd=33%, Nth=100/N% of total bytes
                reward = max(1, total_pts // place)
                # Append BEFORE releasing lock to prevent a race where another
                # thread credits the same signer for the same payload
                order.append(signer_fp)
        # Credit and log happen outside the credited_order_lock
        if reward is not None:
            add_credit(signer_fp, reward)
            log.info("[CREDIT] %s | place %d | +%d pts", signer_fp, place, reward)
        return

    # 6. New message → try silent decryption, display, then queue for relay
    content_part = payload[:-TIMESTAMP_CHARS]
    decrypted    = decrypt_message(content_part)
    if decrypted is not None:
        print(f"\n🔒 [PRIVATE] from {signer_fp}: {decrypted}\n> ", end="", flush=True)
    else:
        print(f"\n📢 [OPEN]    from {signer_fp}: {content_part}\n> ", end="", flush=True)

    enqueue(payload, signer_fp)

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
    with queue_lock:
        if not priority_queue:
            print("\n=== QUEUE empty ===\n")
            return
        snap  = sorted(priority_queue)
        total = current_buffer_bytes
    print(f"\n=== QUEUE ({len(snap)} msgs · {total} bytes) ===")
    for i, (prio, _, payload, origin_fp, size) in enumerate(snap[:20]):
        print(
            f"  {i+1:2d}. prio={prio:4d} (credit={-prio})"
            f"  origin={origin_fp}  size={size}b"
            f"  payload={payload[:20]}..."
        )
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
    print(f"[START] Max buffer      : {MAX_BUFFER_BYTES // 1024 // 1024} MB\n")

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
    print("  clear                    — clear screen")
    print("  <ESP32 command>          — status sf bw freq cr pwr diag reset...\n")

    threading.Thread(target=credits_saver_thread, daemon=True, name="credits-saver").start()
    threading.Thread(target=cache_cleaner_thread,  daemon=True, name="cache-cleaner").start()

    # Pending plaintext confirmation: (packet_bytes, payload_str) or None
    pending_confirm = None

    while True:
        sock       = None
        stop_event = None
        worker     = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # BUG-3 FIX: set connect timeout so a silent drop doesn't block forever
            sock.settimeout(CONNECT_TIMEOUT_SEC)
            sock.connect((HOST, PORT))
            # Switch to non-blocking AFTER the connect succeeds
            sock.setblocking(False)
            log.info("[NET] Connected to %s:%d", HOST, PORT)

            stop_event = threading.Event()
            worker = threading.Thread(
                target=retransmit_worker,
                args=(sock, stop_event),
                daemon=True,
                name="tx-worker",
            )
            worker.start()

            recv_buf = ""

            while True:
                r, _, _ = select.select([sock, sys.stdin], [], [], 0.2)

                # ── Data from ESP32 ──
                if sock in r:
                    try:
                        chunk = sock.recv(4096).decode("utf-8", errors="replace")
                        if not chunk:
                            log.warning("[NET] Connection closed by server")
                            break

                        recv_buf += chunk

                        # Process all complete lines first
                        while "\n" in recv_buf:
                            line, recv_buf = recv_buf.split("\n", 1)
                            line = line.strip()
                            if not line:
                                continue
                            if line.startswith("[LoRa] "):
                                content = line[7:].strip()
                                if content.startswith("tx "):
                                    content = content[3:]
                                handle_lora_packet(content)
                            else:
                                print(f"[ESP32] {line}")

                        # Then guard against an unbounded newline-free fragment
                        if len(recv_buf) > MAX_RECV_BUF:
                            log.warning(
                                "[NET] Fragment without newline exceeds %d KB — discarded",
                                MAX_RECV_BUF // 1024,
                            )
                            recv_buf = ""

                    except BlockingIOError:
                        pass
                    except UnicodeDecodeError:
                        pass
                    except Exception as e:
                        log.error("[NET] Read error: %s", e)
                        break

                # ── User input ──
                if sys.stdin in r:
                    try:
                        cmd = sys.stdin.readline()
                    except EOFError:
                        break
                    cmd = cmd.strip()
                    if not cmd:
                        continue

                    low = cmd.lower()

                    # ── Pending plaintext confirmation ──
                    if pending_confirm is not None:
                        if low == "yes":
                            packet, payload = pending_confirm
                            # BUG-7 FIX: re-check timestamp before sending —
                            # the user may have taken too long to answer
                            if not is_timestamp_valid(payload[-TIMESTAMP_CHARS:]):
                                print("✗ Message expired while waiting for confirmation — not sent.")
                            else:
                                safe_send(sock, packet)
                                mark_original(payload)
                                log.info("[SENT PLAINTEXT] ts=%s", payload[-TIMESTAMP_CHARS:])
                        else:
                            print("✗ Send cancelled.")
                        pending_confirm = None
                        continue

                    # ── Internal commands (all case-insensitive) ──
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

                    # BUG-5 FIX: match command name case-insensitively,
                    # but preserve the key/name argument as typed
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
                        safe_send(sock, f"{cmd}\n".encode("utf-8"))
                        print(f"[CMD] {cmd}")

                    else:
                        # ── Send a message ──
                        # Syntax: "text:contact" for encrypted, "text" for plaintext.
                        # Split on the LAST ":" so colons inside the text are allowed.
                        contact_name = None
                        text         = cmd

                        if ":" in cmd:
                            left, right = cmd.rsplit(":", 1)
                            candidate   = right.strip()
                            if candidate and get_contact(candidate) is not None:
                                text         = left
                                contact_name = candidate

                        if not text.strip():
                            print("[ERROR] Empty message.")
                            continue

                        if contact_name:
                            # ── Encrypted send ──
                            c = get_contact(contact_name)
                            try:
                                enc_blob = encrypt_for_contact(text, c["vk_crypto"])
                            except Exception as e:
                                print(f"[ERROR] Encryption failed: {e}")
                                continue

                            if len(enc_blob.encode("utf-8")) > MAX_ENC_LEN:
                                print(f"[ERROR] Encrypted message too long (max ~{MAX_ENC_LEN} bytes)")
                                continue

                            ts_hex  = make_timestamp()
                            payload = f"{enc_blob}{ts_hex}"
                            sig     = sign_payload(payload)
                            packet  = f"tx {payload}{sig}\n".encode("utf-8")
                            safe_send(sock, packet)
                            mark_original(payload)
                            print(f"🔒 [SENT ENCRYPTED] to '{c['name']}'")

                        else:
                            # ── Plaintext send — ask for confirmation ──
                            if len(text.encode("utf-8")) > MAX_MSG_LEN:
                                print(f"[ERROR] Message too long (max {MAX_MSG_LEN} UTF-8 bytes)")
                                continue

                            ts_hex  = make_timestamp()
                            payload = f"{text}{ts_hex}"
                            sig     = sign_payload(payload)
                            packet  = f"tx {payload}{sig}\n".encode("utf-8")

                            print("\n⚠️  This message is NOT encrypted.")
                            print("    Any node on the network will be able to read it.")
                            print("    Are you sure you want to send it? (yes / no)\n> ", end="", flush=True)
                            pending_confirm = (packet, payload)

        except ConnectionRefusedError:
            log.warning("[NET] Connection refused — retrying in 5s...")
            pending_confirm = None
            time.sleep(5)
        except socket.timeout:
            log.warning("[NET] Connect timed out after %ds — retrying in 5s...", CONNECT_TIMEOUT_SEC)
            pending_confirm = None
            time.sleep(5)
        except Exception as e:
            log.error("[ERROR] %s — reconnecting in 5s...", e)
            pending_confirm = None
            time.sleep(5)
        finally:
            if stop_event:
                stop_event.set()
            if worker and worker.is_alive():
                worker.join(timeout=1.0)
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

if __name__ == "__main__":
    main()
