# GhostRelay

Hello everyone from the Mesh networking community,

I have been working for a few months on a project aiming to create a decentralized means of communication. The proposal is to develop a system where the network nodes themselves collaborate in message retransmission, using cryptographic signatures and an incentive mechanism based on message return.

Below is the detailed explanation of the system logic. The complete script and installation instructions are available in this repository – clone or download it to join the network.

---

## 📡 Detailed Description of the Operation

When a node A creates a message, it performs the following steps:

1. It builds the message containing:  
   - the payload (content)  
   - a timestamp (16 hex characters from `time.time_ns()`)

2. Then it signs the message with its private key  

3. After that, it transmits the message to the network  

---

### 🔁 Reception by another node (e.g., B)

When node B receives this message, it performs the following sequence:

**1. Signature verification**  
- B extracts the signature from the message  
- It checks its “notebook” (local list `trusted_keys.json`) to see if there is a corresponding public key  
- If not found → the message is discarded and not retransmitted  
- If found → the message is considered valid  

**2. Signature replacement**  
- B removes the original signature (from A)  
- B signs the same payload again using its own private key  

**3. Duplicate and relay prevention**  
- B checks if it has already **relayed this exact payload** (stored in `relayed_cache` with key `(payload, B_fingerprint)`).  
- If yes → the message is ignored (prevents infinite loops).  

**4. Priority definition**  
- Each **new** message (never seen before by B) is assigned an **initial priority** equal to the current credit of the **original sender** (the one who created the message).  
- If the sender has no credits, a minimum base of 10 is used.  
- B maintains a retransmission queue (max 10 MB) where messages are ordered by priority (higher priority = earlier transmission).  

**5. Retransmission**  
- B retransmits the message with its own signature  

**6. Priority decay and requeue**  
- After each successful retransmission, the message’s priority is recalculated:  
  `new_value = base // (number_of_retransmissions_done + 1)`  
- If the new value is still ≥ 1 and the message’s TTL (60 seconds) has not expired, the message is re‑enqueued with the lower priority.  
- Otherwise, it is removed from the queue.

---

### 🔄 Message return and reward (only the original author rewards)

After retransmission, the message may eventually return to the original node A.

When A receives the message back, it verifies:  
- The payload is the same (A stores it in `original_cache`)  
- The timestamp is the same  
- The signature now belongs to another node (e.g., B)  

If these conditions are met:  
1. A understands that B retransmitted its message  
2. A checks the **credit window**: only **60 seconds after the first return** of this message are credits granted. After that, further returns are ignored.  
3. A rewards B with points  

**💰 Scoring rule**  
The number of points is based on the message size (payload + timestamp + signature).  
`Points = total_bytes // position`  
where `position = 1` for the first return, `2` for the second, etc.  

👉 **A node can earn points multiple times for the same message, but only within the 60‑second window.**  
If the same node B returns the same payload again later (because it retransmitted it again), it will occupy the next free position in the return order and receive fewer points.  

Example:  
- Message size = 100 bytes.  
- B returns first → position 1 → reward = 100 // 1 = 100 points.  
- C returns second → position 2 → reward = 100 // 2 = 50 points.  
- B returns third (again) → position 3 → reward = 100 // 3 = 33 points.  

Thus, the earlier a node returns a message, the more points it gets, and the same node can collect multiple decreasing rewards over time (but only within 60 seconds).

---

### 🏁 Multiple nodes retransmitting (e.g., B, C, D)

All nodes that ever retransmit the same message are eligible for rewards **when the message returns to the original creator**.  
The **order of return** determines the reward: the first returner gets the highest reward, the second gets half, the third gets one third, etc.

> **Important:** Only the original author gives credits. Intermediate nodes (like B) do **not** credit other nodes (e.g., D) when the message returns to B. This prevents self‑feeding loops and keeps the incentive clean.

---

### 🔁 Chain propagation

The message continues to propagate across the network:  

Example:  
1. A sends → B receives  
2. B signs and retransmits → D receives  

At this point:  
- D sees the message signed by B, therefore D considers the message as coming from B (not A)  
- D then repeats the same process:  
  1. Verifies B’s public key  
  2. Removes B’s signature  
  3. Signs with its own key  
  4. Retransmits  

---

### 🕵️ Anonymity of the original author

Because each node **removes the previous signature** before adding its own, no intermediate node can trace the message back to the original creator.  
- Everyone sees only the **last transmitter** (the node that signed the message they received).  
- Only the original author and the intended recipient (if encryption is used) know who originated the message.  

To the network, the author is a **ghost**.

---

### ⏱️ Time rules

To control propagation:  
1. **Old messages** – If the timestamp is more than 20 minutes in the past → the message is **not** retransmitted  
2. **Future messages** – If the timestamp is more than 10 minutes ahead of the node’s clock → the message is **not** retransmitted  

Additionally, each message in the retransmission queue has a **maximum lifetime of 60 seconds** (TTL); after that, it is automatically discarded (even if its timestamp is still valid).

---

### 🔐 End‑to‑end encryption (ECIES)

GhostRelay now supports **private messages** using ECIES (Elliptic Curve Integrated Encryption Scheme).  

- Contacts are stored in `contacts.json` with a name and the recipient’s public key (PEM or base64 DER).  
- To send an encrypted message, use the syntax:  

```

<message>:<contact_name>

```

  Example: `Hello Alice:Alice`

- The script automatically encrypts the message using ephemeral ECDH key + HKDF + AES‑256‑GCM.  
- Every received message is silently attempted for decryption using our private key.  
  - If decryption succeeds → displayed as `🔒 [PRIVATE] from <fingerprint>: <plaintext>`  
  - Otherwise → displayed as `📢 [OPEN] from <fingerprint>: <content>`  

Plaintext messages (without `:contact`) still work, but they ask for confirmation because they are visible to all nodes.

---

## 📥 Installation & Usage

### Prerequisites

- **Python 3.8+** (recommended: 3.10 or higher)  
- **pyserial**, **ecdsa**, **cryptography** – will be installed via `pip`  
- For **USB** mode: a USB‑to‑TTL adapter or direct USB cable to your ESP32 (OTG cable for Android)  
- For **Bluetooth** direct mode (optional): a paired Bluetooth serial adapter and proper permissions (root on Android, `rfcomm` on Linux)  
- For **WiFi AP** mode: the ESP32 must be configured as an Access Point with a TCP server (firmware dependent).

### Get the code

Clone the repository and enter the directory:

```bash
git clone https://github.com/persev65-eng/GhostRelay-.git
cd GhostRelay-
```

Install dependencies

```bash
pip install pyserial ecdsa cryptography
```

On Termux (Android) you may need to install the pre‑compiled cryptography package:

```bash
pkg install python-cryptography
pip install ecdsa pyserial
```

Configure the connection (config.json)

The file config.json defines how the script talks to your ESP32 (or any serial‑based radio).
A default one is created automatically at first run. You can edit it manually.

Basic options:

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
TCP (original) "tcp" tcp_host, tcp_port Uses a Bluetooth‑to‑TCP bridge app. Works everywhere without special permissions.
USB serial "usb" usb_device, baudrate Direct cable connection. On Android you need OTG and termux-usb. On Linux add your user to dialout group.
Bluetooth direct "bluetooth" bt_device (usually /dev/rfcomm0) Requires root on Android. On Linux: pair device, then rfcomm bind 0 <MAC>.
WiFi AP "wifi_ap" wifi_ap_ip, wifi_ap_port, wifi_ap_ssid (info) Connect your computer/phone to the ESP32’s WiFi hotspot first. Then the script opens a TCP connection to the ESP32.

Fallback – the script will try the modes in the order listed in fallback_order. If the primary mode fails, it moves to the next one automatically.

Run the node

```bash
python3 relay.py
```

The first execution will create all necessary files (private_key.pem, contacts.json, trusted_keys.json, etc.) and show you your public key.

---

Commands (once the node is running)

Command Description
mykey Show your public key (share with others)
addnode <name> <base64_key> Add a trusted relay node (its public key)
addcontact <name> <base64_key> Add a contact for encrypted messaging
contacts List all contacts
credits View points earned from retransmissions
queue See the retransmission queue (ordered by current priority)
trusted List trusted relay nodes
wifiscan List nearby WiFi networks (debug, helps find the ESP32 AP)
<message>:<contact> Send an encrypted message to that contact
<message> Send a plaintext message (asks confirmation)
status, sf 9, freq 915, … Direct ESP32 commands (if supported by firmware)
clear Clear screen
Ctrl+C Stop the node

---

Quick test (two nodes)

1. Node A: run relay.py, type mykey, copy the Base64 DER line.
2. Node B: run relay.py, type addnode NodeA <that_key>.
3. Node A: type addnode NodeB <NodeB's_base64_key> (you can also add as contact for encryption: addcontact Bob <key>).
4. Node B: send Hello Alice:Alice (if Alice is the contact name in B’s contacts.json) – it will be encrypted.
5. Node A will receive and decrypt it automatically.

---

💰 Support the project

I truly believe this project can change the world.
If you find this work useful and would like to support its development with a donation, I would be very grateful.

Monero address:
49YdksRCWR3TY2A3WopX9322EGzzxBrFv4NbTho4DCNhSzUGfnAivcJNuAqEYCFjw8EYwbk4x745XjTt1Kh5n9KbNorXSD6

---

📝 License / Contributing

Feel free to open issues, fork the repository, and submit pull requests. Let’s build a truly decentralized mesh together!
