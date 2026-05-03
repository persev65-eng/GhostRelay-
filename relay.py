#!/usr/bin/env python3
"""
GhostRelay - LoRa retransmission with ECDSA signature and credit by return order.

PROTOCOL:
  - Node A creates: payload = text + 16hex timestamp
                 signs with private key → tx <payload><sigA>
  - Node B receives: checks sigA against trusted_keys.json.
      Unknown key   → silently discard.
      Known key     → remove sigA, sign same payload with sigB → retransmit.
      Queue priority = accumulated credit of the signer who delivered the message.
  - When msg[sigB] returns to A: A recognizes payload (original_cache),
      credits B with total_pts // position (1st=100%, 2nd=50%, 3rd=33%, N=100/N%).
  - When msg[sigB] arrives at D: D treats it as a new message from B,
      re‑signs with sigD. When sigD returns to B: B recognizes payload
      (relayed_cache), credits D — same logic.
  - Time window: timestamp > 20 min in past or > 10 min in future → discard.
  - Duplicate: same (payload, signer_fp) → ignore.
  - Max buffer: 10 MB.

PACKET FORMAT ON THE NETWORK:
  tx <payload><sig88chars>\n
  payload = <utf8_text><16hex_timestamp>
  sig     = base64 of 64 bytes ECDSA NIST-P256 → always 88 chars

CREDITS:
  Persisted atomically in credits.json and credited_order.json every 10s.
  Nodes with higher credit have their messages prioritized in the output queue.
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

from ecdsa import BadSignatureError, NIST256p, SigningKey, VerifyingKey
from ecdsa.util import sigdecode_string, sigencode_string

# ------------------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------------------

PROJECT_NAME = "GhostRelay"
MONERO_ADDRESS = "49YdksRCWR3TY2A3WopX9322EGzzxBrFv4NbTho4DCNhSzUGfnAivcJNuAqEYCFjw8EYwbk4x745XjTt1Kh5n9KbNorXSD6"

APP_DIR = Path.home() / "lora_relay"
CONFIG_PATH = APP_DIR / "config.json"
KEY_PATH = APP_DIR / "private_key.pem"
TRUSTED_KEYS_PATH = APP_DIR / "trusted_keys.json"
CREDITS_PATH = APP_DIR / "credits.json"
CREDITED_ORDER_PATH = APP_DIR / "credited_order.json"

MAX_BUFFER_BYTES = 10 * 1024 * 1024          # 10 MB
MAX_MSG_LEN = 200                            # bytes of text (without timestamp and sig)
MAX_RECV_BUF = 64 * 1024                     # 64 KB — max fragment without newline
CACHE_EXPIRE_SEC = 20 * 60                   # 20 min
MAX_RELAY_AGE_SEC = 20 * 60                  # discard timestamps older than 20 min
MAX_FUTURE_SEC = 10 * 60                     # discard timestamps more than 10 min in future
SIG_CHARS = 88                               # base64 of 64 bytes → 88 chars
TIMESTAMP_CHARS = 16                         # 16 hex chars = uint64 nanoseconds
CREDITS_SAVE_INTERVAL = 10                   # seconds between saves
CACHE_CLEAN_INTERVAL = 60                    # seconds between cache cleanups
MAX_PRIO_REORDERS = 5                        # max consecutive reorders before forcing send

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
# Private key / identity
# ------------------------------------------------------------------------------

def load_or_create_key():
    APP_DIR.mkdir(exist_ok=True)
    if KEY_PATH.exists():
        sk = SigningKey.from_pem(KEY_PATH.read_bytes())
        log.info("[KEY] Loaded key from %s", KEY_PATH)
        return sk
    sk = SigningKey.generate(curve=NIST256p)
    KEY_PATH.write_bytes(sk.to_pem())
    log.info("[KEY] Generated new key at %s", KEY_PATH)
    return sk

sk = load_or_create_key()
MY_VK = sk.get_verifying_key()
MY_VK_PEM = MY_VK.to_pem().decode()

def _fp(vk):
    """8‑hex fingerprint — cryptographic identity of the node."""
    return hashlib.sha256(vk.to_string()).hexdigest()[:8]

MY_NODE_ID = _fp(MY_VK)

# ------------------------------------------------------------------------------
# Atomic persistence (used for credits and trusted_keys)
# ------------------------------------------------------------------------------

def _save_atomic(path, data):
    APP_DIR.mkdir(exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", dir=APP_DIR, delete=False, suffix=".tmp"
    ) as tf:
        json.dump(data, tf, indent=2)
        tmp = tf.name
    os.replace(tmp, path)

# ------------------------------------------------------------------------------
# Trusted nodes
# ------------------------------------------------------------------------------

trusted_lock = threading.Lock()
_trusted = {}   # fp → VerifyingKey

def load_trusted_keys():
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
    global _trusted
    loaded = load_trusted_keys()
    with trusted_lock:
        _trusted = loaded

def add_trusted_node(name, pem_or_b64):
    """Accepts full PEM or raw base64 DER of the public key."""
    raw = pem_or_b64.strip()
    if not raw.startswith("-----"):
        raw = f"-----BEGIN PUBLIC KEY-----\n{raw}\n-----END PUBLIC KEY-----\n"
    try:
        vk = VerifyingKey.from_pem(raw)
    except Exception as e:
        log.error("[ADDNODE] Invalid key: %s", e)
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
    _save_atomic(TRUSTED_KEYS_PATH, existing)   # atomic write
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
    print("=================================================\n")

# ------------------------------------------------------------------------------
# Credits
# ------------------------------------------------------------------------------

credits_lock = threading.Lock()
credits = {}              # fp → total points

credited_order_lock = threading.Lock()
credited_order = {}       # payload → [fp1, fp2, ...] in order of return

def load_credits():
    global credits, credited_order
    if CREDITS_PATH.exists():
        try:
            with open(CREDITS_PATH) as f:
                data = json.load(f)
            with credits_lock:
                credits = data
        except Exception as e:
            log.warning("[LOAD] Error loading credits.json: %s", e)
    if CREDITED_ORDER_PATH.exists():
        try:
            with open(CREDITED_ORDER_PATH) as f:
                data = json.load(f)
            with credited_order_lock:
                credited_order = data
        except Exception as e:
            log.warning("[LOAD] Error loading credited_order.json: %s", e)

def save_credits():
    with credits_lock:
        snap_credits = dict(credits)
    with credited_order_lock:
        snap_order = {k: list(v) for k, v in credited_order.items()}
    _save_atomic(CREDITS_PATH, snap_credits)
    _save_atomic(CREDITED_ORDER_PATH, snap_order)

def credits_saver_thread():
    while True:
        time.sleep(CREDITS_SAVE_INTERVAL)
        try:
            save_credits()
        except Exception as e:
            log.warning("[SAVE] Error saving credits: %s", e)

def get_credit(fp):
    with credits_lock:
        return credits.get(fp, 0)

def add_credit(fp, points):
    with credits_lock:
        credits[fp] = credits.get(fp, 0) + points
        total = credits[fp]
    # Log outside lock — avoids deadlock with logging handler
    log.info("[CREDIT] +%d to %s (total: %d)", points, fp, total)

# ------------------------------------------------------------------------------
# Caches
# ------------------------------------------------------------------------------

cache_lock = threading.Lock()
original_cache = {}   # payload → monotonic (I created it)
relayed_cache = {}    # payload → monotonic (I retransmitted it)
seen_packets = {}     # (payload, fp) → monotonic (dedup by signer)

def mark_original(payload):
    with cache_lock:
        original_cache[payload] = time.monotonic()

def mark_relayed(payload):
    with cache_lock:
        relayed_cache[payload] = time.monotonic()

def i_know_payload(payload):
    """True if I created OR already retransmitted this payload."""
    with cache_lock:
        return payload in original_cache or payload in relayed_cache

def mark_seen(payload, signer_fp):
    with cache_lock:
        seen_packets[(payload, signer_fp)] = time.monotonic()

def already_seen(payload, signer_fp):
    with cache_lock:
        return (payload, signer_fp) in seen_packets

def clean_caches_once():
    now = time.monotonic()
    cutoff = now - CACHE_EXPIRE_SEC
    with cache_lock:
        for d in (original_cache, relayed_cache):
            for k in [k for k, t in d.items() if t < cutoff]:
                d.pop(k, None)
        for k in [k for k, t in seen_packets.items() if t < cutoff]:
            seen_packets.pop(k, None)
        known = set(original_cache) | set(relayed_cache)
    # Remove credited_order entries for payloads that are no longer in any cache
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
# Cryptography
# ------------------------------------------------------------------------------

def sign_payload(payload):
    digest = hashlib.sha256(payload.encode("utf-8")).digest()
    sig_bytes = sk.sign_digest(digest, sigencode=sigencode_string)
    return base64.b64encode(sig_bytes).decode("ascii")

def verify_payload(payload, sig_b64, vk):
    try:
        sig = base64.b64decode(sig_b64)
        digest = hashlib.sha256(payload.encode("utf-8")).digest()
        vk.verify_digest(sig, digest, sigdecode=sigdecode_string)
        return True
    except Exception:
        return False

def identify_signer(payload, sig_b64):
    """
    Checks against my own key and all trusted nodes.
    Returns (fingerprint, vk) or None.
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

def make_timestamp():
    return f"{time.time_ns():016x}"

def is_timestamp_valid(ts_hex):
    try:
        diff = (time.time_ns() - int(ts_hex, 16)) / 1_000_000_000.0
        return -MAX_FUTURE_SEC <= diff <= MAX_RELAY_AGE_SEC
    except Exception:
        return False

# ------------------------------------------------------------------------------
# Priority queue
# ------------------------------------------------------------------------------

queue_lock = threading.Lock()
priority_queue = []
current_buffer_bytes = 0

def enqueue(payload, origin_fp):
    global current_buffer_bytes
    size = len(payload.encode("utf-8"))
    priority = -get_credit(origin_fp)
    with queue_lock:
        if current_buffer_bytes + size > MAX_BUFFER_BYTES:
            log.warning("[BUFFER] Full — msg from %s dropped", origin_fp)
            return
        heapq.heappush(
            priority_queue,
            (priority, time.monotonic(), payload, origin_fp, size)
        )
        current_buffer_bytes += size

# ------------------------------------------------------------------------------
# Retransmission thread
# ------------------------------------------------------------------------------

send_lock = threading.Lock()

def safe_send(sock, data):
    with send_lock:
        sock.setblocking(True)
        try:
            sock.sendall(data)
        finally:
            sock.setblocking(False)

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

        # Re‑evaluate priority with a limit on reorder attempts
        current_prio = -get_credit(origin_fp)
        if current_prio != stored_prio and reorder_count < MAX_PRIO_REORDERS:
            with queue_lock:
                heapq.heappush(
                    priority_queue,
                    (current_prio, enqueue_time, payload, origin_fp, size)
                )
            reorder_count += 1
            time.sleep(0.01)
            continue

        reorder_count = 0

        # Discard if we already know this payload
        if i_know_payload(payload):
            with queue_lock:
                current_buffer_bytes = max(0, current_buffer_bytes - size)
            continue

        # Minimum length check
        if len(payload) < TIMESTAMP_CHARS:
            log.warning("[TX] Short payload dropped: %s", payload[:40])
            with queue_lock:
                current_buffer_bytes = max(0, current_buffer_bytes - size)
            continue

        # Timestamp may have expired while waiting in queue
        if not is_timestamp_valid(payload[-TIMESTAMP_CHARS:]):
            log.info("[TX] Expired timestamp in queue — dropped")
            with queue_lock:
                current_buffer_bytes = max(0, current_buffer_bytes - size)
            continue

        # Sign and transmit
        new_sig = sign_payload(payload)
        packet = f"tx {payload}{new_sig}\n".encode("utf-8")

        try:
            safe_send(sock, packet)
            mark_relayed(payload)
            with queue_lock:
                current_buffer_bytes = max(0, current_buffer_bytes - size)
            log.info(
                "[TX] Retransmitted | origin=%s credit=%d size=%db",
                origin_fp, get_credit(origin_fp), len(payload),
            )
        except Exception as e:
            log.warning("[TX] Send failed, re‑queueing: %s", e)
            with queue_lock:
                heapq.heappush(priority_queue, item)
            time.sleep(0.5)
            continue

        time.sleep(0.05)

# ------------------------------------------------------------------------------
# Incoming packet processing
# ------------------------------------------------------------------------------

def handle_lora_packet(content):
    """
    Processes a packet received from the ESP32.
    content = string after "[LoRa] " without the "tx " prefix.
    Structure: <payload><sig88chars>
    """
    if len(content) < TIMESTAMP_CHARS + SIG_CHARS + 1:
        return

    sig_b64 = content[-SIG_CHARS:]
    payload = content[:-SIG_CHARS]

    # 1. Identify signer
    result = identify_signer(payload, sig_b64)
    if result is None:
        log.debug("[RX] Invalid signature or unknown node: %s...", payload[:20])
        return

    signer_fp, _ = result

    # 2. Ignore echo of our own transmissions
    if signer_fp == MY_NODE_ID:
        return

    # 3. Validate timestamp
    if len(payload) < TIMESTAMP_CHARS:
        return
    if not is_timestamp_valid(payload[-TIMESTAMP_CHARS:]):
        log.debug("[RX] Timestamp out of window: %s", payload[-TIMESTAMP_CHARS:])
        return

    # 4. Deduplication: same payload + same signer → ignore
    if already_seen(payload, signer_fp):
        return
    mark_seen(payload, signer_fp)

    # 5. Payload already known → it's a return → credit the signer
    if i_know_payload(payload):
        with credited_order_lock:
            order = credited_order.setdefault(payload, [])
            if signer_fp not in order:
                place = len(order) + 1          # 1‑based
                text_len = len(payload[:-TIMESTAMP_CHARS].encode("utf-8"))
                total_pts = text_len + TIMESTAMP_CHARS + SIG_CHARS
                # 1st=100%, 2nd=50%, 3rd=33%, 4th=25%, N=100/N%
                reward = max(1, total_pts // place)
                add_credit(signer_fp, reward)
                order.append(signer_fp)
                log.info("[CREDIT] %s | %dº place | +%d pts", signer_fp, place, reward)
        return

    # 6. New message → queue for retransmission
    enqueue(payload, signer_fp)

# ------------------------------------------------------------------------------
# Console commands
# ------------------------------------------------------------------------------

def is_esp_cmd(cmd):
    parts = cmd.strip().split()
    return bool(parts) and parts[0].lower() in ESP_CMDS

def cmd_credits():
    with credits_lock:
        snap = sorted(credits.items(), key=lambda x: x[1], reverse=True)
    print("\n=== CREDITS (nodes that retransmitted my messages) ===")
    for fp, pts in snap:
        print(f"  {fp} : {pts} pts")
    if not snap:
        print("  (no credits yet)")
    print("======================================================\n")

def cmd_queue():
    with queue_lock:
        if not priority_queue:
            print("\n=== QUEUE empty ===\n")
            return
        snap = sorted(priority_queue)
        total = current_buffer_bytes
    print(f"\n=== QUEUE ({len(snap)} msgs · {total} bytes) ===")
    for i, (prio, _, payload, origin_fp, size) in enumerate(snap[:20]):
        print(
            f"  {i+1:2d}. prio={prio:4d} (credit {-prio}) "
            f"origin={origin_fp} size={size}b "
            f"payload={payload[:25]}..."
        )
    print("==========================================\n")

def cmd_trusted():
    t = get_trusted()
    print("\n=== TRUSTED NODES ===")
    for fp in t:
        print(f"  {fp}")
    if not t:
        print("  (none)")
    print(f"  MY ID : {MY_NODE_ID}")
    print("====================\n")

# ------------------------------------------------------------------------------
# Main loop
# ------------------------------------------------------------------------------

def main():
    reload_trusted()
    load_credits()

    print(f"""
╔══════════════════════════════════════════════════════════════════╗
║                    WELCOME TO {PROJECT_NAME}!                     ║
║                                                                  ║
║  Decentralized LoRa network with ECDSA NIST-P256 signatures.     ║
║                                                                  ║
║  Time window : 20 min past · 10 min future                      ║
║  Credit      : 1st=100% · 2nd=50% · 