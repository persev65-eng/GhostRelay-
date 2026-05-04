```markdown
# GhostRelay

Hello everyone from the Mesh networking community,

I have been working for a few months on a project aiming to create a decentralized means of communication. The proposal is to develop a system where the network nodes themselves collaborate in message retransmission, using cryptographic signatures and an incentive mechanism based on message return.

Below is the detailed explanation of the system logic. The complete script and installation instructions are available in this repository – clone or download it to join the network.

---

## 📡 Detailed Description of the Operation

When a node A creates a message, it performs the following steps:

1. It builds the message containing:  
   - the payload (content)  
   - a timestamp  

2. Then it signs the message with its private key  

3. After that, it transmits the message to the network  

---

### 🔁 Reception by another node (e.g., B)

When node B receives this message, it performs the following sequence:

**1. Signature verification**  
- B extracts the signature from the message  
- It checks its “notebook” (local list) to see if there is a corresponding public key  
- If not found → the message is discarded and not retransmitted  
- If found → the message is considered valid  

**2. Signature replacement**  
- B removes the original signature (from A)  
- B signs the message again using its own private key  

**3. Priority definition**  
- B checks the priority associated with its wallet (public key)  
- Based on that, it organizes a retransmission queue  
- Queue rules: Messages with higher priority are placed closer to the top; messages at the top are retransmitted first  

**4. Retransmission**  
- B retransmits the message with its own signature  

---

### 🔄 Message return and reward

After retransmission, the message may eventually return to the original node A.

When A receives the message back, it verifies:  
- The payload is the same  
- The timestamp is the same  
- The signature now belongs to another node (e.g., B)  

If these conditions are met:  
1. A understands that B retransmitted its message  
2. A rewards B with points  

**💰 Scoring rule**  
The number of points is based on the message size:  
`points = number of bytes in the message`

---

### 🏁 Multiple nodes retransmitting (e.g., B, C, D)

If multiple nodes retransmit the same message:  
- The node whose retransmission returns first receives more points  
- The others receive progressively fewer points  

Example:  
1. B retransmits and the message returns first → receives 100% of the points  
2. C retransmits later → receives 50%  
3. D retransmits later → receives 33%  

In other words, the reward depends on the order in which the message returns.

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

### 🔄 Multi‑level rewards

When the message returns:  
- If it returns to B with D’s signature:  
  - B understands that D retransmitted its message  
  - B rewards D  
- At the same time: A has already rewarded B  

✔️ **General rule**  
👉 Each node rewards whoever retransmitted the version of the message that it signed.

---

### ⏱️ Time rules

To control propagation:  
1. **Old messages** – If the timestamp is more than 20 minutes in the past → the message is **not** retransmitted  
2. **Future messages** – If the timestamp is more than 10 minutes ahead of the node’s clock → the message is **not** retransmitted  

---

### 🔐 End‑to‑end encryption (ECIES)

GhostRelay now supports **private messages** using ECIES (Elliptic Curve Integrated Encryption Scheme).  

- Contacts are stored in `contacts.json` with a name and the recipient’s public key (PEM or base64 DER).  
- To send an encrypted message, use the syntax:  

```

<message>:<contact_name>

```

  Example: `Hello Alice:Alice`

- The script automatically encrypts the message using ECDH ephemeral key + HKDF + AES‑256‑GCM.  
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
    "fallback_order": ["tcp", "usb", "bluetooth"],
    "tcp_host": "127.0.0.1",
    "tcp_port": 8080,
    "usb_device": "/dev/ttyUSB0",
    "baudrate": 115200,
    "bt_device": "/dev/rfcomm0"
}
```

Mode connection_type Required fields Notes
TCP (original) "tcp" tcp_host, tcp_port Uses a Bluetooth‑to‑TCP bridge app (e.g. “Bluetooth TCP Bridge”). Works everywhere without special permissions.
USB serial "usb" usb_device, baudrate Direct cable connection. On Android you need OTG and termux-usb. On Linux add your user to dialout group.
Bluetooth direct "bluetooth" bt_device (usually /dev/rfcomm0) Requires root on Android. On Linux: pair device, then rfcomm bind 0 <MAC>.

Fallback – the script will try the modes in the order listed in fallback_order. If the primary mode fails, it moves to the next one automatically.

Run the node

```bash
python3 relay.py
```

The first execution will create all necessary files (private_key.pem, contacts.json, etc.) and show you your public key.

Commands (once the node is running)

Command Description
mykey Show your public key (share with others)
addnode <name> <base64_key> Add a trusted relay node (its public key)
addcontact <name> <base64_key> Add a contact for encrypted messaging
contacts List all contacts
credits View points earned from retransmissions
queue See the retransmission queue (ordered by credit)
trusted List trusted relay nodes
<message>:<contact> Send an encrypted message to that contact
<message> Send a plaintext message (asks confirmation)
status, sf 9, freq 915, … Direct ESP32 commands
clear Clear screen
Ctrl+C Stop the node

Quick test (two nodes)

1. Node A: run relay.py, type mykey, copy the Base64 DER line.
2. Node B: also run relay.py, type addnode NodeA <that_key>.
3. Node A: type addnode NodeB <NodeB's_base64_key> (you can also add as contact for encryption: addcontact Bob <key>).
4. Node B: send Hello Alice:Alice (if Alice is the contact name) – it will be encrypted.
5. Node A will receive and decrypt it automatically.

---

💰 Support the project

I truly believe this project can change the world.
If you find this work useful and would like to support its development with a donation, I would be very grateful.

Monero address:
49YdksRCWR3TY2A3WopX9322EGzzxBrFv4NbTho4DCNhSzUGfnAivcJNuAqEYCFjw8EYwbk4x745XjTt1Kh5n9KbNorXSD6
