# GhostRelay

Hello everyone from the Mesh networking community,

I have been working for a few months on a project aiming to create a decentralized means of communication. The proposal is to develop a system where the network nodes themselves collaborate in message retransmission, using cryptographic signatures and an incentive mechanism based on message return.

Below is the detailed explanation of the system logic. The complete script and installation instructions are available in this repository – clone or download it to join the network.

---

## 📡 Overview

GhostRelay is a **reputation‑based mesh relay protocol** for low‑bandwidth LoRa networks (ESP32). Every node maintains:

- A **FIFO cache** (default 10 000 entries) to avoid processing the same message more than once.
- A **trusted_keys list** of nodes that have already proven useful, along with their accumulated points.
- A **candidates list** of nodes that sent an `invite` but have not yet returned any message.
- A **priority queue** for retransmission – messages from high‑reputation nodes go out first, and the priority decays with each hop.
- A **race window** (60 s) during which the original author awards points to anyone who returns the message.

The goal is to make collaboration self‑sustaining: nodes that actively relay messages earn points and get their own messages relayed faster, while passive or unknown nodes are gradually removed.

---

## 🧠 Detailed Description of the Operation

### 1. Creation and sending of a message (by the author)

When node A creates a message, it performs the following steps:

1. Generate a unique random `ID` (e.g., 10 digits).
2. Calculate `hash = SHA‑256( content + ID )`.
3. Store this hash in its **FIFO cache** (so it never processes its own message as a relay).
4. Sign the string `content + ID` with its private key.
5. Transmit via LoRa:  
   `<content> <ID> <signature>`
6. Add the hash to its **race list** (`active_races`), along with:
   - `expire_time = now + 60 s`
   - `ranking = []` (empty list of returner fingerprints)
   - `total_bytes = len(content + ID + signature)`

---

### 2. Reception by another node (e.g., B)

When node B receives a message, it runs the following pipeline:

1. Extract `content`, `ID`, `signature`.
2. Compute `hash = SHA‑256(content + ID)`.
3. **Cache check** – if the hash is already in the local FIFO cache → discard (duplicate).
4. **Signature verification** – try to verify the signature using the public keys B knows:
   - Its own key (could be a return of its own message).
   - The `trusted_keys` list.
   - The `candidates` list.  
   If no key matches → discard (unknown sender).
5. **Add hash to cache** (prevents future duplicates).
6. **Attempt decryption** (ECIES) if the content looks like an encrypted blob.
   - If decryption succeeds → display as `🔒 [PRIVATE] from <fingerprint>: <plaintext>`
   - Otherwise → display as `📢 [OPEN] from <fingerprint>: <content>`
7. **Decision**:
   - If B is the **original author** of this hash (hash is in its `active_races`) → handle as **return** (go to Section 3).
   - Else if the sender is in `trusted_keys` → enqueue with **priority = sender’s points** (Section 4).
   - Else if the sender is in `candidates` → enqueue with **fixed priority = 10** (Section 5).

---

### 3. Message return and reward (only the original author)

When the original author A receives a message whose hash is in its `active_races` **and** the 60 s window has not expired:

1. Determine the return position:  
   `place = len(ranking) + 1`  
   (the same node can appear multiple times if it returns again later).
2. Append the fingerprint of the signer to `ranking`.
3. Calculate points:  
   `points = total_bytes // place` (integer division, minimum 1).  
   Examples for a 106‑byte message:  
   - 1st return → 106 pts  
   - 2nd return → 53 pts  
   - 3rd return → 35 pts  
   - 4th return → 26 pts, etc.
4. Update `trusted_keys`: add the points to the signer’s record.
5. If the signer was in `candidates`, **promote** it to `trusted_keys` and remove from `candidates`.
6. The return message itself is **not retransmitted**.

After 60 s, the hash is removed from `active_races` and no further returns are credited.

---

### 4. Messages from trusted nodes

If the sender is in `trusted_keys`:

- The message enters the **priority queue** with:
  - `priority = current points of the sender` (from `trusted_keys`)
  - `base = priority`
  - `tx_count = 0`
  - `born = monotonic timestamp`

A separate thread (`retransmit_worker`) constantly processes the queue, always picking the item with the **highest priority**.

For each item:
1. Sign `content + ID` with the node’s **own** private key (the original signature is replaced).
2. Transmit `<content> <ID> <new_signature>` via ESP32.
3. Wait for the ESP32 confirmation (`OK`).  
   - **Failure**: the item is re‑enqueued with the same priority.  
   - **Success**:  
     - `tx_count += 1`  
     - `new_priority = base // (tx_count + 1)`  
     - If `new_priority >= 1` **and** `now - born < 60 s`, re‑enqueue with `new_priority`.  
     - Otherwise, discard the item.

Thus, high‑reputation messages are relayed more often and survive longer in the queue, but every message decays and eventually expires.

---

### 5. Messages from candidates

Candidates (nodes that sent an `invite` but never returned a message) receive a **fixed initial priority of 10**. The same decay and TTL rules apply. This gives them a small chance to prove themselves – if they return a message during its race window, they are promoted to `trusted_keys` and start accumulating real points.

---

### 6. Invitations and the `candidates` list

- Any node can broadcast an invitation with the `invite` command.  
  The invitation contains: `<public_key_base64> <signature_of_public_key>`.
- Receiving nodes verify the self‑signature; if valid and the key is **not** in `trusted_keys`, they add the key to `candidates` (persisted in `candidates.json`).

**Candidate expiry (purge):**

- Every time the node sends a **normal message** (not an invite), it takes a snapshot of its current `candidates`.
- After **60 seconds**, all candidates that are still in the list and were not promoted are **removed**.
- Candidates added *after* the snapshot are safe – they will face expiry only when the next message is sent.

This mechanism ensures that passive nodes that never relay anything are eventually forgotten, freeing resources.

---

### 7. Priority queue and decay summary

| Origin | Initial priority | Decay formula | Max lifetime in queue |
|--------|------------------|---------------|----------------------|
| Trusted node | Points in `trusted_keys` | `base // (tx_count+1)` | 60 s |
| Candidate | 10 | `10 // (tx_count+1)` | 60 s |

The queue is capped at 10 MB; if it becomes full, the lowest‑priority messages are dropped.

---

### 🕵️ Anonymity of the original author

Because each relaying node **replaces the signature** with its own, no intermediate node can trace the message back to the original creator. They only see the immediate predecessor. Only the original author (and the intended recipient, if encryption is used) know the true origin – hence the name **Ghost**Relay.

---

## 📥 Installation & Usage

### Prerequisites

- **Python 3.8+** (3.10+ recommended)
- **pyserial**, **ecdsa**, **cryptography** – installed via `pip`
- USB‑to‑TTL adapter / direct USB cable (or Bluetooth / WiFi as described below)
- ESP32 with LoRa module running a compatible AT‑firmware

### Get the code

```bash
git clone https://github.com/persev65-eng/GhostRelay-.git
cd GhostRelay-
```

Install dependencies

```bash
pip install pyserial ecdsa cryptography
```

On Termux (Android) you may need:

```bash
pkg install python-cryptography
pip install ecdsa pyserial
```

Configure the connection (config.json)

A default config.json is created on first run. Edit it to match your setup:

```json
{
    "connection_type": "tcp",
    "fallback_order": ["tcp", "usb", "bluetooth", "wifi_ap"],
    "tcp_host": "127.0.0.1",
    "tcp_port": 8080,
    "usb_device": "/dev/ttyUSB0",
    "baudrate": 115200,
    "bt_device": "/dev/rfcomm0",
    "wifi_ap_ssid": "",
    "wifi_ap_ip": "192.168.4.1",
    "wifi_ap_port": 8080
}
```

Mode connection_type Required fields Notes
TCP bridge "tcp" tcp_host, tcp_port Works everywhere without special permissions.
USB serial "usb" usb_device, baudrate Direct cable. On Android use OTG + termux-usb.
Bluetooth direct "bluetooth" bt_device (e.g., /dev/rfcomm0) Needs root on Android; on Linux pair and bind with rfcomm.
WiFi AP "wifi_ap" wifi_ap_ip, wifi_ap_port Connect your PC/phone to the ESP32 hotspot first.

The script tries the modes in fallback_order if the primary fails.

Run the node

```bash
python3 relay.py
```

On first launch it generates your keys and shows your public key.

---

📋 Commands (while the node is running)

Command Description
mykey Show your public key (share with others).
addnode <name> <base64_key> Add a trusted relay node manually.
addcontact <name> <base64_key> Add a contact for encrypted messaging.
contacts List all contacts.
credits View your own points earned from retransmissions.
queue Show the retransmission queue (priorities, decay, TTL).
trusted List trusted nodes and their points.
candidates Show current candidate nodes.
clear_candidates Remove all candidates manually.
invite Broadcast your invitation (public key + signature).
<message>:<contact> Send an encrypted message to that contact.
<message> Send a plaintext message (asks confirmation).
status, bw, sf, freq, … Direct ESP32 commands (if supported).
clear Clear screen.
Ctrl+C Stop the node.

---

🧪 Quick test (two nodes)

1. Node A – run relay.py, type mykey, copy the Base64 DER line.
2. Node B – run relay.py, type addnode NodeA <that_key>.
3. Node A – type addnode NodeB <NodeB's_key> (optionally also addcontact Bob <key> for encryption).
4. Node B – send Hello Alice:Alice (if Alice is a contact) → encrypted message.
5. Node A receives and decrypts it automatically.

Both nodes will now relay each other’s messages and accumulate points.

---

💰 Support the project

I truly believe this project can change the world.
If you find this work useful and would like to support its development with a donation, I would be very grateful.

Monero address:
49YdksRCWR3TY2A3WopX9322EGzzxBrFv4NbTho4DCNhSzUGfnAivcJNuAqEYCFjw8EYwbk4x745XjTt1Kh5n9KbNorXSD6

---

📝 License / Contributing

Feel free to open issues, fork the repository, and submit pull requests. Let’s build a truly decentralized mesh together!
