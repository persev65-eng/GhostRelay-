> ⚠️ **WARNING: PROJECT UNDER CONSTRUCTION** ⚠️
>
> This project is still under development and **has not been fully tested**.
>
> It is very likely to contain **bugs**, **incomplete parts**, and **missing scripts**.
>
> **It is not ready for production use.** Use at your own risk.
>
> Contributions, corrections, and suggestions are very welcome!


# GhostRelay — Message Protocol, Phantom Retransmission, and Economic Incentive

GhostRelay is a decentralized LoRa mesh network in which every node helps carry messages it cannot read, for senders it cannot identify, and is rewarded for it.

Messages are **end-to-end encrypted** from author to recipient. Relays see only an opaque block, re-sign it with their own wallet at every hop, and pass it on. The network runs on a **reputation economy**: the author of a message pays the nodes that helped carry it — but **only after the recipient confirms delivery**. No central server, no global ledger, no tokens: every node keeps its own accounts of the nodes around it.

> **Section numbers are stable.** The source code refers to them in comments (for example, "section 21"). New material was added as sections 24 and up, so existing references keep working.

---

## Table of Contents

- [Hardware](#hardware)

**Part I — The Protocol**

- [1. General Concept](#1-general-concept)
- [2. Node Identity and Wallets](#2-node-identity-and-wallets)
- [3. Medium Access Rules (MAC)](#3-medium-access-rules-mac)
- [4. Message Structure](#4-message-structure)
- [5. Creating Your Own Message](#5-creating-your-own-message)
- [6. Memory Cache and Loop Prevention](#6-memory-cache-and-loop-prevention)
- [7. Race List](#7-race-list)
- [8. Economic Value of a Message](#8-economic-value-of-a-message)
- [9. Initial Priority of Your Own Message](#9-initial-priority-of-your-own-message)
- [10. Rewards, Positions and the Two Races](#10-rewards-positions-and-the-two-races)
- [11. Retransmission Queue](#11-retransmission-queue)
- [12. Wallet Invite](#12-wallet-invite)
- [13. Receiving a Message](#13-receiving-a-message)
- [14. Cache Verification](#14-cache-verification)
- [15. Wallet Verification](#15-wallet-verification)
- [16. Signature Replacement During Retransmission](#16-signature-replacement-during-retransmission)
- [17. Priority of Messages from Known Neighbors](#17-priority-of-messages-from-known-neighbors)
- [18. Unknown Neighbors](#18-unknown-neighbors)
- [19. Promotion of an Unknown Neighbor](#19-promotion-of-an-unknown-neighbor)
- [20. Messages from Unknown Neighbors](#20-messages-from-unknown-neighbors)
- [21. Fidelity to Radio Parameters](#21-fidelity-to-radio-parameters)
- [22. Communication with External Programs](#22-communication-with-external-programs)
- [23. Final Remarks](#23-final-remarks)
- [24. Contacts](#24-contacts)
- [25. Delivery Confirmation](#25-delivery-confirmation)
- [26. Why Only the Author Pays](#26-why-only-the-author-pays)

**Part II — Implementation**

- [27. Architecture and Modules](#27-architecture-and-modules)
- [28. Serial Protocol Between PC and ESP32](#28-serial-protocol-between-pc-and-esp32)
- [29. Persistence](#29-persistence)
- [30. Limits](#30-limits)
- [31. Getting Started](#31-getting-started)
- [32. Diagnostics](#32-diagnostics)
- [33. Known Limitations and Roadmap](#33-known-limitations-and-roadmap)

---

## Hardware

### 📦 Modules Used

| Component | Model |
| :--- | :--- |
| **Microcontroller** | ESP32 DevKit V1 (DOIT) — ESP32-D0WD-V3 |
| **Radio Module** | Ebyte E80-900M2212S(LR2021) — Semtech LR2021 Chip |

### 📡 Pinout Used

| Pin on E80-900M2212S(LR2021) | ESP32 Pin | Actual GPIO | Function |
| :--- | :--- | :--- | :--- |
| **GND** | GND | — | Ground |
| **VCC** | 3.3V | — | Power |
| **MISO** | D19 | GPIO19 | SPI — Master In Slave Out |
| **MOSI** | D23 | GPIO23 | SPI — Master Out Slave In |
| **SCK** | D18 | GPIO18 | SPI — Clock |
| **NSS** | D5 | GPIO5 | SPI — Chip Select |
| **BUSY** | D4 | GPIO4 | Busy signal |
| **LR_NRESET** | D21 | GPIO21 | Module reset |
| **DIO5** | D33 | GPIO33 | TX/RX interrupt |
| **DIO6** | D32 | GPIO32 | CAD interrupt |
| **DIO7** | D26 | GPIO26 | Reserve |
| **DIO8** | D27 | GPIO27 | Reserve |
| **DIO9** | D13 | GPIO13 | Reserve |
| **DIO10** | D25 | GPIO25 | Reserve |
| **DIO11** | D22 | GPIO22 | Reserve |
| **ANT_SUBGHZ** | *(physical antenna)* | — | Sub-GHz antenna (868/915 MHz) |
| **ANT_2.4G** | *(physical antenna)* | — | 2.4 GHz antenna |

SPI runs on VSPI at 1 MHz. The ESP32 talks to the PC over USB serial at 115200 baud.

### Hardware Notes

**One interrupt line.** RadioLib uses a single interrupt pin — the one passed to the `Module()` constructor, here DIO5. The chip raises that same line for a received packet, a finished transmission **and** a finished CAD. The firmware clears its interrupt flag after every transmission and every CAD; otherwise it would try to read a packet that does not exist. DIO6 does not need to be connected for CAD to work.

**Power.** At 22 dBm the E80 draws current peaks of several hundred mA. Powering it from the DevKit's 3.3 V regulator commonly causes brownouts during transmission: the ESP32 resets on its own, or the radio stops answering SPI commands. Use a dedicated 3.3 V supply with a common ground and a 100 µF (or larger) capacitor close to the module.

**Antenna.** Never transmit without an antenna connected — the power amplifier can be damaged.

**Distance.** Two modules at 22 dBm less than a meter apart can saturate each other's receivers. For bench tests, keep them a few meters apart or lower the power (`CONFIG PWR=10`).

---

# Part I — The Protocol

## 1. General Concept

GhostRelay is a communication network based on **distributed retransmission**, where each node participates in transporting messages without knowing their real origin.

The concept of "ghost" comes from the idea of **anonymity** within the network:

- A message does not reveal who originally created it;
- Relays do not know who the author is, nor who the recipient is;
- Relays cannot read the content — it is encrypted for the recipient;
- Each node only knows who transmitted the message to it at that moment;
- The network operates through **economic cooperation** between nodes.

### 1.1 What sustains anonymity

Two mechanisms, working together:

- **The hop signature is replaced at every hop** (section 16). A packet carries only the signature of whoever just transmitted it. The chain of previous transmitters is discarded along the way.
- **The content is an encrypted block** (section 4). The author's identity travels *inside* it, readable only by the recipient.

### 1.2 What sustains the economy

Retransmitting costs airtime, the scarce resource of the network. The author pays for that airtime in points, and the payment halves with each position (section 10).

There is no central authority and no global balance: **each node keeps its own accounts of its neighbors**, and those accounts serve only to decide the order of that node's retransmission queue. Earning points with a neighbor means *that neighbor* will prioritize your messages. Nothing more — and that is enough. There is nothing to inflate.

### 1.3 Paid only for delivery

A node is paid by the author only when the recipient **confirms delivery** (section 25). A relay therefore has a direct interest not only in transmitting, but in the message actually reaching its destination.

---

## 2. Node Identity and Wallets

Each node has a **digital wallet** composed of:

- Private key;
- Public key.

The **private key** remains only on the device itself. It is used to:

- Sign each transmission (the hop signature);
- Encrypt and decrypt messages exchanged with contacts;
- Participate in the network economy.

The **public key** is shared with neighbors through the invite system (section 12) and with contacts by registration (section 24).

### 2.1 Algorithm and sizes

Ed25519 for signatures. Sizes are fixed, which is what allows the signature to be separated by counting backwards (section 13):

| Element | Raw bytes | Base64 (what goes on air) |
| :--- | ---: | ---: |
| Seed / private key | 32 | 44 characters |
| Public key | 32 | 44 characters |
| Signature | 64 | **88 characters** |

Base64 uses only `A-Z a-z 0-9 + / =`. It never produces `<`, `>` or line breaks, so the `<0>` marker stays recognizable and the serial line never breaks.

Ed25519 is **deterministic**: the same wallet signing the same content always produces the same signature. This is useful to verify a backup — a restored wallet signs exactly like the original.

### 2.2 One key for signing and encryption

For encryption, the same Ed25519 wallet is converted to X25519 (the standard conversion supported by libsodium/PyNaCl). There is no second key pair to generate, store, or exchange.

### 2.3 The wallet is the node

Losing the private key means ceasing to be who you were for every neighbor: the points they accumulated for you no longer count, and you become an unknown neighbor that must send an invite and be promoted again (sections 18 and 19). Your contacts will also no longer recognize your messages.

For this reason the implementation:

- stores the key with `0600` permissions, in a `0700` data folder;
- preserves an unreadable seed under a timestamped name instead of overwriting it;
- warns loudly before replacing the identity;
- offers `exportar_semente()` and `importar_semente()` for backup and restore.

The exported seed is 44 characters long and **is the whole node**. Whoever has it can sign in your place and receive the points your neighbors accumulated for you.

---

## 3. Medium Access Rules (MAC)

Before any transmission, the node follows a set of decentralized rules to avoid collisions and ensure fairness in channel usage.

### 3.1 Mandatory Listening (Listen Before Talk)

- The node **listens to the channel before transmitting**.

In practice this is the LR2021's **CAD** (Channel Activity Detection): the radio briefly leaves receive mode, sniffs the air for a few symbols, and answers free or busy.

- **A busy channel has no timeout.** The node waits as long as necessary. Talking over someone else helps no one — both packets are lost.
- **While waiting, the node does not poll.** It goes back to listening and waits for a reception to end (a decoded packet, a CRC error, or a discarded packet), then checks again. Each CAD takes the radio out of receive mode for tens of milliseconds, and an SF12 preamble lasts 131 ms: polling every few milliseconds would make the node deaf to the very transmission it is waiting for.
- **Without CAD support**, the node operates without listen-before-talk and warns once. Section 3.2 still protects it partially.

### 3.2 Random Wait Window

- When the channel becomes free, the node draws a random wait time between **0 and 50 ms**.
- If, during the wait, the node hears a valid transmission, it **stops counting** and waits for that transmission to end.
- When the channel becomes free again, the node **draws a new time** within a window reduced by half (0 to 25 ms in the example).
- If the wait time reaches zero, the node **transmits immediately** — but its random window **doubles** for the next round (0 to 100 ms in the example).

"Valid transmission" means a **decoded packet**. A packet with a CRC error does not count (section 3.3).

The countdown advances in 1 ms steps. Using the symbol time as the step (16.4 ms at SF12/BW250) would leave only two or three possible values inside a 50 ms window.

### 3.3 Tactical Rules

| Event | Effect on Wait Window |
| :--- | :--- |
| **Transmitted successfully** | Becomes **2 times more patient** (doubles the window) |
| **Lost to another node** | Becomes **2 times less patient** (halves the window) |
| **Collision** | Ignored — the node continues counting normally |

**Rationale:** whoever manages to transmit yields space and becomes more patient. Whoever fails becomes more impatient, increasing their chances in the next round. Collisions are ignored because the node only reacts to transmissions it **can decode** — if it does not understand the message, it keeps counting until its turn comes.

### 3.4 Complete MAC Cycle

1. The node listens to the channel.
2. If the channel is busy, it waits for the transmission to end.
3. When the channel becomes free, it draws a time within the current window.
4. If another node transmits first, it halves the window.
5. If it transmits itself, it doubles the window.
6. Repeats the cycle indefinitely.

### 3.5 Why the window has no ceiling

Doubling is the brake on a node that talks too much, and it only works if the window can grow:

| Consecutive transmissions | Window |
| :--- | :--- |
| 1 | 100 ms |
| 5 | 1.6 s |
| 10 | 51 s |
| 13 | 6.8 min |
| 15 | 27 min |
| 18 | 3.6 h |
| 20 | 14.6 h |

A node alone on the network, repeating the same message, **silences itself**. As soon as it hears a neighbor — it lost the contest — the window halves and it starts talking again. A ceiling would disable this brake.

The **floor** exists for a mathematical reason: with a zero window the draw always returns zero, the random wait of section 3.2 disappears, and two nodes in that state would always collide. The floor is 1 ms, the resolution of the countdown itself.

### 3.6 Symbol times, for reference

| Configuration | Symbol time |
| :--- | ---: |
| SF7 / BW250 | 0.51 ms |
| SF9 / BW250 | 2.05 ms |
| SF12 / BW250 | 16.38 ms |
| SF12 / BW125 | 32.77 ms |

The contention window is measured in tens of milliseconds, while an SF12 transmission occupies the channel for **seconds**. The MAC decides who talks; the cost is decided by section 8.

---

## 4. Message Structure

Every packet has the same outer structure:

```
[CONTENT][HOP SIGNATURE]<0>
```

- **CONTENT** is what the packet carries (see below);
- **HOP SIGNATURE** is the Ed25519 signature, in base64, of the node that transmitted this packet, over the content. It is replaced at every hop (section 16);
- **`<0>`** is the end-of-transmission marker.

The marker lets the receiver know exactly when it has received the complete packet.

### 4.1 The content of a message: an encrypted block

For messages and delivery confirmations, CONTENT is an **encrypted block in base64**:

```
[ENCRYPTED BLOCK (base64)][HOP SIGNATURE]<0>
                │
                └── authenticated box, author → recipient
                      24 bytes  nonce
                       n bytes  encrypted payload
                      16 bytes  authentication tag
```

The block is an **authenticated box** (`crypto_box` from NaCl: X25519 + XSalsa20-Poly1305) between the author's wallet and the recipient's wallet. It does two things at once:

- **only the recipient can open it**;
- **opening it proves who created it**, because the author's private key is part of the computation.

The author's signature is therefore *fused into* the encryption instead of taking 64 extra bytes inside the block. Inside the box, the first byte says what it is:

| Inside the box | Meaning |
| :--- | :--- |
| `"M"` + text | a message (up to 82 bytes of text) |
| `"C"` + 32-byte hash | a delivery confirmation (section 25) |

Relays cannot see this type byte. For them, messages and confirmations are indistinguishable blocks.

### 4.2 The invite: in clear

The invite (section 12) keeps its original format, unencrypted:

```
[PUBLIC KEY][SIGNATURE]<0>
```

### 4.3 What fits

```
      255 bytes   LoRa packet
    -  88 bytes   hop signature (base64)
    -   3 bytes   marker <0>
    -----------
      164 base64 characters for the block  =  123 bytes of block
    -  40 bytes   encryption (24 nonce + 16 authentication)
    -   1 byte    type (message or confirmation)
    -----------
       82 bytes   of text
```

**82 bytes, not 82 characters.** "ç" takes 2 bytes, an emoji takes 4. The radio transmits bytes, and the packet overflows by bytes.

Longer texts require the multi-packet reassembly described in section 13, which is not implemented yet (section 33).

Since the text is encrypted and then base64-encoded, it may contain anything — including `<0>` or line breaks. None of that can reach the air in clear.

---

## 5. Creating Your Own Message

Every message has a recipient, chosen among your contacts (section 24). The flow is:

```
Choose a recipient among the contacts
   ↓
Encrypt "M" + text for the recipient      (authenticated box)
   ↓
Base64 → sign with the hop signature → add marker <0>
   ↓
Calculate the block hash                  (same at every hop)
   ↓
Calculate the content hash                (known only to author and recipient)
   ↓
Store the block hash in the memory cache
   ↓
Add the message to the race list          (value = airtime, two races)
   ↓
Place the message in the retransmission queue
```

Storing your own hash in the cache at creation has a consequence: **your message coming back will hit the cache**. That is why the race list is checked *before* the cache on reception (section 13).

---

## 6. Memory Cache and Loop Prevention

Every packet has a **hash**, which works as the network's memory. This hash is stored in a FIFO memory called the **memory cache**, which prevents packets from circulating infinitely.

**Loop example:**

```
Node A → Node B → Node C → Node A (again)
```

When A receives the same packet back:

1. Calculates the hash;
2. Checks the cache;
3. If the hash already exists → **discards it**;
4. If it does not exist → registers it in the cache and continues processing.

### 6.1 What gets hashed

The hash is SHA-256 of the **content** — the encrypted block — without the hop signature and without the marker. The block does not change from hop to hop (only the hop signature does), so every node computes the same hash for the same message.

### 6.2 What the cache resolves besides loops

It makes repetition cheap. When a node transmits the same message several times, **whoever already heard it discards it at once**: no priority recalculation, no re-signing, no requeueing. The cost of a repetition, for those who already know it, is only its airtime.

### 6.3 Properties

- Size: 1000 entries, FIFO, no time-based expiration.
- Lookup and registration are atomic: two threads can never both consider the same packet "new".
- Delivery confirmations are cached like any other packet.
- **Invites are not cached** (section 12.3).

---

## 7. Race List

Besides the memory cache, **your own messages** enter a second structure, the **race list** (`lista corrida`). It has an economic function: it records the messages that can generate rewards for the nodes that help carry them.

> **Only your own messages enter the race list. Relayed messages never do.**
>
> Earlier versions of this document said, in section 20, that relayed messages should be inserted into the race list. That was an error: it allowed an author to earn infinite points (section 26). Relays never pay anyone.

### 7.1 What an entry holds

| Field | Purpose |
| :--- | :--- |
| block hash | recognizes the message coming back retransmitted |
| content hash | matches the delivery confirmation (section 25) |
| recipient | who must confirm, and who gets contact points |
| value | the message's airtime, decided once (section 8) |
| SF, BW, CR | section 21 compares them with every return |
| outbound race | positions of those who retransmitted the message |
| return race | positions of those who delivered the confirmation |
| confirmed | whether the first confirmation has arrived |
| confirmation hash | recognizes further copies of the confirmation |

### 7.2 One message, one entry

However many times the message is transmitted, it is registered **once**. Returns occupy positions *inside* that entry (section 10), not separate entries.

---

## 8. Economic Value of a Message

The value of a message does not depend on its size in bytes. What matters is the **time it occupies the radio**:

```
1 millisecond of transmission = 1 point
```

The whole packet counts: encrypted block, hop signature and marker.

### 8.1 Calculated once, not measured

Airtime in LoRa is an exact function of packet size, SF, BW and CR (Semtech formula, AN1200.13). The value is **calculated**, not timed with a clock, for three reasons:

1. **A PC stopwatch measures the wrong thing** — serial latency plus air, different on each side.
2. **Section 21 requires both sides to agree** on the number.
3. **A calculated value cannot be forged**: it comes from the bytes that actually went on air and the configuration used.

And it is calculated **once**, when the message enters the race list. After that the value is never recomputed: it only halves with each position (section 10). Relays compute airtime only when they need it for a priority (sections 17 and 20); nobody measures a transmission after the fact.

```
T_symbol   = 2^SF / BW
T_preamble = (n_preamble + 4.25) × T_symbol

n_payload  = 8 + max( ceil( (8·PL − 4·SF + 28 + 16·CRC − 20·IH)
                             / (4·(SF − 2·DE)) ) × (CR + 4), 0 )

T_packet   = T_preamble + n_payload × T_symbol
```

`DE` = 1 when the symbol time exceeds 16 ms (the case of SF12/BW250). `PL` is the entire packet.

### 8.2 Reference table

Airtime of the whole packet, BW250 / CR 4:7:

| Text | Packet | SF7 | SF9 | SF10 | SF12 |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 10 B | 159 B | 175 ms | 558 ms | 1,000 ms | 4,002 ms |
| 20 B | 175 B | 193 ms | 615 ms | 1,115 ms | 4,346 ms |
| 50 B | 215 B | 233 ms | 730 ms | 1,345 ms | 5,263 ms |
| 82 B | 255 B | 276 ms | 859 ms | 1,574 ms | 6,181 ms |
| confirmation | 191 B | 211 ms | 658 ms | 1,201 ms | 4,805 ms |
| invite | 135 B | 154 ms | 486 ms | 886 ms | 3,428 ms |

### 8.3 The price of anonymity and privacy

In a short message, most of the packet is overhead: the hop signature, the encryption and the base64 inflation. A 10-byte text becomes a 159-byte packet — roughly 90% overhead.

That is not waste: it is the cost of section 16, which hides the path, and of section 4, which hides the content and the author. But it explains why SF12 makes the network slow, and why SF9 is usually a better starting point for a messaging network.

---

## 9. Initial Priority of Your Own Message

Before entering the retransmission queue, the message receives a priority that depends on your neighbors' scores:

| Neighbor | Points |
| :--- | :--- |
| Neighbor A | 500 |
| Neighbor B | 200 |
| Neighbor C | 100 |

The highest value is **500**, so a newly created message receives:

```
Priority = highest neighbor score + 1 = 501
```

This message enters the queue with maximum priority.

**A node without neighbors** has a highest score of 0, so the priority is 1. The message is still its most urgent item, because relayed traffic enters with `points / time` or `10 / time` — typically well below 1 (section 17.1).

---

## 10. Rewards, Positions and the Two Races

### 10.1 Positions, halving

Each time you hear your message being retransmitted, the retransmitter occupies a **position**, and the value of each position is half the previous one — no matter who it is:

| Position | Reward |
| :--- | :--- |
| Message created | worth 100 points |
| 1st position | 100 points |
| 2nd position | 50 points |
| 3rd position | 25 points |
| 4th position | 12.5 points |
| ... | ... until the entry leaves the FIFO list |

*The same public key can occupy several positions.*

Repeating is part of the protocol: it increases the chance of the message reaching someone who missed it. **The balance is economic, not a rule**: repeating costs the same airtime and earns half. There is no penalty for repetition, no limit of positions, no list of who was already paid — any such rule would break the mechanism.

### 10.2 The two races

Each message opens **two races of the same value**, and both work exactly the same way:

| Race | Who occupies positions | When they are paid |
| :--- | :--- | :--- |
| **Outbound** (`ida`) | nodes the author hears retransmitting the message | **held** until the first confirmation |
| **Return** (`volta`) | nodes that deliver the confirmation to the author | immediately |

The outbound race is **held**: positions are occupied normally — each return consumes a position and halves the next one, even while held — but nobody is paid until the first confirmation arrives. If it never arrives, nobody is ever paid. Once it arrives, all held positions are paid, and later returns are paid immediately.

The positions keep halving while held because otherwise a return before the confirmation and another after it would be worth the same.

### 10.3 Worked example

Message from A to D, worth 100 points. B and C are A's radio neighbors:

```
Outbound race (held until the first confirmation)
  B retransmits          → position 1: 100   held
  C retransmits          → position 2:  50   held

  ── first confirmation arrives ──
     B receives 100, C receives 50
     D receives 100 contact points (once)

  B retransmits again    → position 3:  25   paid now

Return race (paid immediately)
  C delivers the confirmation     → position 1: 100
  B delivers another copy         → position 2:  50
```

### 10.4 Conditions for occupying a position

A return occupies a position only if:

1. the block hash is in the race list;
2. the hop signature belongs to a known wallet (trusted or candidate);
3. the hop signature is **not** your own (echo of your own transmission);
4. SF, BW and CR match the entry exactly (section 21).

If any condition fails, **the position is not consumed and the value does not drop**. This matters: if an invalid return consumed a position, transmitting in a cheap configuration would burn the expensive positions of those who transmitted correctly.

### 10.5 Until when

The entry keeps paying until it **leaves the race list**, and it only leaves by FIFO when the list is full. There is no minimum value and no maximum number of positions.

---

## 11. Retransmission Queue

All packets that need to be transmitted — own messages, relayed messages, confirmations, invites — enter a **priority queue**.

When a packet is transmitted, its priority **halves**:

| Transmission | Priority |
| :--- | :--- |
| In queue | 100 |
| 1st transmission | 50 |
| 2nd transmission | 25 |
| 3rd transmission | 12.5 |

When the queue reaches its maximum capacity, the **oldest item is removed** (FIFO policy).

### 11.1 An item does not leave for having been transmitted

It stays in the queue with its priority falling, and only leaves when the queue is full and it is the oldest. What makes an item stop being chosen is its priority falling below the others, not a transmission counter.

With B entering at 500 and A at 100:

```
transmits B → B drops to 250    (B is still the highest)
transmits B → B drops to 125    (B is still the highest)
transmits B → B drops to 62.5   (now A, at 100, goes first)
transmits A → A drops to 50
```

Higher priority means more consecutive chances, not exclusivity.

### 11.2 One packet, one position

Registering the same hash again updates the existing position instead of creating a second one. The higher priority is kept, and the packet and its SF/BW/CR are updated **together** — the packet was signed to go on air in that configuration.

### 11.3 Eviction is by age

When the queue is full, the oldest item **by arrival** leaves, not the lowest priority. With a small queue, an old high-priority item can be evicted while newer low-priority items remain.

### 11.4 The queue is not persisted

See section 29.

---

## 12. Wallet Invite

The **invite** shares a public wallet with the nodes within radio range:

```
[PUBLIC KEY][SIGNATURE]<0>
```

It is transmitted like any packet — it has a signature, an end marker, enters the queue and has a priority — but **it does not enter the race list** and generates no reward.

### 12.1 How an invite is recognized

The packet has no type field, and needs none. An invite identifies itself:

> the content is exactly the size of a public key (44 characters) **and** the signature verifies with that same content used as the key.

An encrypted block is at least 56 characters long, so it can never be mistaken for an invite.

### 12.2 An invite is one hop only

**A received invite is never retransmitted.** It announces direct neighborhood: "this is my wallet, I am within range of your radio". If it were passed on, every node would end up with every wallet among its candidates, and the list would stop meaning "who I can hear".

### 12.3 Invites are not cached

The cache exists to stop retransmission loops, and invites are not retransmitted. Repeated invites are handled by the neighbor list itself: a key already registered means nothing to do.

### 12.4 When to announce

Without invites, nobody becomes a candidate, nobody is promoted, and the network does not form. The node operator chooses:

| Mode | Behavior |
| :--- | :--- |
| `periodico` | announces at startup and every interval (default: 5 min) |
| `manual` | announces only when the application asks |

In both modes the application can trigger an invite at any time.

> **Neighbors are not contacts.** An invite makes you a *radio neighbor* (one hop, for relaying and reputation). To exchange encrypted messages, two nodes must be *contacts* (end to end, any distance). See section 24.

---

## 13. Receiving a Message

When a node receives a transmission, it keeps listening until it finds the marker:

```
<0>
```

Only then does it consider the packet complete:

1. Removes the `<0>`, leaving `[CONTENT][HOP SIGNATURE]`;
2. Separates the hop signature by counting backwards (fixed size: 88 characters);
3. Isolates the content.

### 13.1 The canonical order of reception

Sections 12 to 25 describe steps. The order between them is not arbitrary:

```
 1  separate <0> and the hop signature               section 13
 2  hash of the content (the block)                  section 14
 3  is it an invite?  → unknown neighbor, STOP        sections 12, 18
 4  is it MY message coming back?
        → outbound race (held until confirmed), STOP  section 10
 5  is it a copy of MY confirmation, already known?
        → return race, STOP                           section 25
 6  already in the cache?  → discard                  section 14
 7  does the hop signature belong to a neighbor?      section 15
        → if not, discard
 8  register in the cache
 9  try to open the block with each contact:
        a message for me      → deliver to the app,
                                queue the confirmation  section 25
        a confirmation for me → release the outbound race,
                                credit the recipient,
                                return race             section 25
        does not open         → I am a relay:
                                re-sign, prioritize,
                                queue with same SF/BW/CR  sections 16-21
```

**Why steps 4 and 5 come before the cache.** Section 5 puts your own message in your cache at creation, and section 14 says a cached packet is discarded. Applied in that order, your message coming back would be discarded *before* being counted, and section 10 would never happen. Checking the race list first resolves it: if the hash is in your race list, it is a **return**, not a duplicate.

**Why the invite comes first.** It goes through none of the later steps: no cache, no race list, no retransmission, no delivery to the application.

### 13.2 Multi-packet reassembly — NOT IMPLEMENTED

The separation above is implemented. **Reassembly across several LoRa packets is not.** Today each received packet is treated as a complete message; that works because nothing larger than one packet is ever generated, and it is why there is an 82-byte text limit (section 4.3). See section 33.

---

## 14. Cache Verification

The node calculates the hash **only of the content** — the encrypted block — without the hop signature and without the `<0>`:

```
HASH = hash(content)
```

- If the hash **already exists** → discards the packet;
- If it **does not exist** → registers it and continues.

Hashing only the content is what makes the hash **survive the signature replacement** of section 16: the same packet has the same hash in every node, even though each one signs it with its own wallet. If the signature were hashed, every hop would create a "new" packet and the cache would never cut any loop.

---

## 15. Wallet Verification

The node verifies the **hop signature** and looks for which public wallet it belongs to, among:

- Known neighbors (`trusted_keys`);
- Neighbors in the invite list (`candidates`).

If the signature **does not belong to any wallet** → discards the packet. If it **belongs** → continues.

There is no sender field in the packet: the signature is tested against each known wallet until one matches. The cost is one Ed25519 verification per wallet tested, negligible next to the seconds of airtime of each packet.

**What this rule protects:** it prevents a stranger from injecting traffic. To be heard you must have sent a valid invite and be among the candidates — that is, be physically within someone's range.

### 15.1 Two different checks

| Check | Who | Against | Question |
| :--- | :--- | :--- | :--- |
| hop signature | every node | neighbors | *did a neighbor transmit this?* |
| opening the block | recipient | contacts | *did a contact write this, for me?* |

A message addressed to you by someone who is **not** your contact does not open, and is therefore handled as traffic for someone else — it is relayed onward. The two cases are indistinguishable, which is good for anonymity.

---

## 16. Signature Replacement During Retransmission

GhostRelay **does not accumulate signatures**. The previous hop signature is removed and replaced:

```
received:     [BLOCK][HOP_SIGNATURE_A]<0>
retransmits:  [BLOCK][HOP_SIGNATURE_B]<0>
```

Each retransmission carries **only the current node's signature**. The block is untouched — its hash stays the same, so every cache recognizes it — and whoever receives it knows only who transmitted it that time.

The only exception is the invite (section 12.2), which is never retransmitted.

---

## 17. Priority of Messages from Known Neighbors

When a valid packet arrives from a **known neighbor** and is to be relayed:

```
Priority = accumulated points of the neighbor / packet airtime in ms
```

| Data | Value |
| :--- | :--- |
| Neighbor points | 1000 |
| Packet airtime | 10 ms |
| **Priority** | 1000 / 10 = **100** |

### 17.1 What the formula means

It is a cost-benefit ratio: **how much reputation I earn per millisecond of airtime I spend**. A short packet from a generous neighbor is the best deal and goes first; a long packet from a barely useful neighbor goes last.

Since real packets take hundreds or thousands of milliseconds, priorities of relayed traffic tend to be small numbers, while own messages enter with `highest + 1`. **Own messages going first is the expected behavior.**

---

## 18. Unknown Neighbors

There is an intermediate category: **unknown neighbors** (`candidates`).

When a valid invite arrives, the node checks:

1. Does the signature correspond to the public key?
2. Does this key already exist in any list?

If it **already exists** → discards the invite. If **not** → adds it to the candidates.

Since invites are one hop only (section 12.2), candidates are literally **who I can hear on my radio**. A candidate has no score yet. The list is FIFO (section 23): when full, the oldest leaves. That limit is defensive — without it, anyone generating wallets and sending invites could fill the node's memory.

---

## 19. Promotion of an Unknown Neighbor

An unknown neighbor **does not gain trust just by sending an invite**. It must demonstrate contribution.

When it earns a paid position in one of your races, it is promoted:

```
UNKNOWN NEIGHBOR → KNOWN NEIGHBOR
```

Then it receives the points of that position.

### 19.1 Promotion happens when payment happens

Promote **and then** credit, never promote without credit. A neighbor promoted with 0 points would get priority 0 under section 17 — behind any unknown neighbor, which at least has the fixed 10 of section 20. Being promoted would make things worse for it.

For this reason, a candidate holding a **held** position in an outbound race is promoted only when that position is released by the confirmation, together with its payment. A return with the wrong SF/BW/CR (section 21) promotes nobody.

---

## 20. Messages from Unknown Neighbors

When a packet arrives from an unknown neighbor and is to be relayed, the process is:

1. Calculate the hash;
2. Store it in the cache;
3. Verify the hop signature;
4. Remove the old hop signature;
5. Add your own hop signature;
6. Place it in the **retransmission queue**.

The **priority** is different:

```
Priority = 10 / packet airtime in ms
```

> **Correction:** earlier versions of this document said, in step 6, "insert into the race list". Relayed packets never enter the race list — see sections 7 and 26.

---

## 21. Fidelity to Radio Parameters

Every received packet that goes to the retransmission queue must, **before entering the queue**, have its radio parameters recorded:

- **SF** (Spreading Factor);
- **BW** (Bandwidth);
- **CR** (Coding Rate).

The LR2021 supports **multiple SFs**, so it is essential to correctly identify which configuration was used in the original transmission.

**When transmitting**, the node **must mandatorily** use the same SF, BW, and CR with which the packet was heard.

**The author only awards points** if the packet that returns has **exactly the same SF, BW, and CR** as the original transmission. Otherwise, the reward **is not granted** — and the position is not consumed.

**The confirmation travels with the same SF, BW and CR as the message it confirms**, so both races of a message are checked against the same parameters.

### 21.1 Why it exists

The value of a message is its airtime (section 8), and airtime depends on the configuration. The same 175-byte packet takes about 4,346 ms at SF12 and 193 ms at SF7 — over 20 times less. Without this rule the scheme is obvious: receive at SF12, retransmit at SF7, charge the SF12 price.

### 21.2 Mandatory means mandatory

If the radio cannot apply a packet's parameters, **the transmission does not happen**. That packet will never be transmittable by this node, so it is removed from the queue; otherwise, since a failure does not halve priority, it would stay at the top forever and the node would stop transmitting anything else.

### 21.3 Notations

Parameters circulate in more than one notation and are normalized before comparison:

| Parameter | Accepted forms | Canonical |
| :--- | :--- | :--- |
| SF | `12`, `"12"` | integer 5–12 |
| BW | `250`, `250.0`, `"250"`, `250000` (Hz) | float in kHz |
| CR | `7`, `"7"`, `"4/7"`, `47`, `3` (index) | denominator 5–8 |

### 21.4 Physical limitation

**The radio listens to one SF at a time.** A node has a *listening configuration* (default SF12 / BW250 / CR 4:7). To transmit a packet heard in another configuration it switches, transmits and **returns** to its listening configuration. While transmitting or reconfiguring, it is deaf.

---

## 22. Communication with External Programs

External applications (PC programs, apps, web services) use the GhostRelay network through a **WebSocket / HTTP interface**:

```
[External application]
        ↓
   WebSocket (port 8000) / HTTP (port 8080)
        ↓
   [PC: GhostRelay protocol, Python]
        ↓
   USB serial, 115200 baud
        ↓
   [ESP32 firmware]
        ↓
   [E80-900M2212S (LR2021)]
        ↓
    LoRa network
```

The protocol — wallets, encryption, economy, queue, MAC — runs on the PC. The ESP32 is a thin bridge to the radio: it does not know what a hash, a signature or a race list is (section 27).

Any program that can open a WebSocket can send and receive encrypted messages without knowing anything about LoRa.

### 22.1 Commands (application → node)

Plain JSON objects. Field names follow the source code:

| Command | Effect |
| :--- | :--- |
| `{"tipo": "tx", "dados": "text", "para": "<name or key>"}` | sends an encrypted message to a contact |
| `{"tipo": "contato", "chave": "<public key>", "nome": "...", "categoria": "pessoa"}` | registers a contact (`categoria`: `pessoa` or `site`) |
| `{"tipo": "remover_contato", "chave": "..."}` | removes a contact |
| `{"tipo": "contatos"}` | lists contacts |
| `{"tipo": "convite"}` | announces the wallet now |
| `{"tipo": "status"}` | node state |

`para` accepts the full public key, a prefix of 12 or more characters, or the contact name (ambiguous names are rejected rather than guessed).

### 22.2 Messages (node → application)

| Message | Meaning |
| :--- | :--- |
| `{"tipo": "rx", "dados": "...", "de": "<contact>", "chave": "...", "vizinho": "...", "rssi": -91.5, "snr": 8.2, "sf": 12, "bw": 250, "cr": 7}` | a message for you arrived and was opened |
| `{"tipo": "entregue", "dados": "...", "hash": "..."}` | your message was confirmed by its recipient |
| `{"tipo": "erro", "dados": "reason"}` | something was refused (too long, unknown recipient, invalid key, full queue...) |
| `{"tipo": "evento", "dados": "..."}` | informational |
| `{"tipo": "contatos", "dados": [...]}` | contact list |
| `{"tipo": "status", ...}` | node state, including `chave_publica` (your full key), `contatos`, `limite_texto`, `entregues`, `confirmacoes_recebidas` |

The error channel is not decoration: without it, a message that does not fit or a missing recipient would simply vanish.

### 22.3 HTTP routes

| Route | Returns |
| :--- | :--- |
| `/` | test page: choose a recipient, add contacts, see your public key |
| `/status` | node state as JSON |
| `/rx` | last 100 received items as JSON |

The test page counts **bytes**, not characters, and takes the limit from the node itself.

---

## 23. Final Remarks

- The system creates a **reputation economy**: nodes that retransmit correctly earn points and have their own messages propagated with higher priority.
- **Only the author pays**, and the outbound reward is **conditional on delivery**.
- Unknown nodes enter as **candidates** and prove their usefulness by earning paid positions.
- The **hash cache** prevents loops and repeated processing.
- The **race list**, **candidates** and **priority queue** are FIFO caches, without fixed expiration times.
- **Fidelity to radio parameters** (SF, BW, CR) is essential for the reward mechanism.
- The reward is proportional to the **airtime** of the message (1 ms = 1 point).
- **Anonymity** is preserved by the hop signature replacement; **privacy** by end-to-end encryption.

### 23.1 No artificial limits

Every time the protocol seems to need a limit, the brake already exists and is economic or physical:

| Temptation | The brake that already exists |
| :--- | :--- |
| limit how many times a message repeats | the reward halves (section 10) |
| limit nodes that talk too much | the window doubles at each TX (section 3.3) |
| punish repetition | repeating earns half for the same cost |
| remove old items from the queue | FIFO, when the queue is full (section 11) |
| stop paying small values | FIFO, when the race list is full (section 10.5) |
| pay for undelivered traffic | payment waits for the confirmation (section 25) |

The only legitimate limits are physical (255-byte packets, one SF at a time) and memory limits, which the protocol already defines as FIFO.

---

## 24. Contacts

**Neighbors and contacts are different things:**

| | Neighbor | Contact |
| :--- | :--- | :--- |
| Scope | one hop, radio range | end to end, any distance |
| How it enters | invite (section 12) | registration |
| Points | neighbor points (reputation for relaying) | contact points (reputation for confirming) |
| Used for | hop signatures, relay priority | encrypting, opening, confirmation priority |

A contact is a person or a site whose public key you keep, so you can encrypt messages for it and open the messages it sends you. Two nodes that want to talk must register each other.

### 24.1 Registration

A contact can be registered:

- **manually**, by pasting its 44-character public key (the test page shows your own key so you can pass it on);
- **by request of an application** — an HTML site or a program connected to the node's WebSocket sends `{"tipo": "contato", ...}`.

> **Currently, registration requests are accepted without asking the user.** A security layer that asks before accepting is planned (section 33).

The key is validated (it must decode to a valid Ed25519 public key). Registering an existing contact again updates its name and category without resetting its points.

### 24.2 Contact points

When the author receives the first confirmation of a message, it credits the recipient, **in its contact book**, with the value of the message — once per message, however many copies of the confirmation arrive.

The points *I* hold for a contact decide how quickly I confirm *its* messages (section 25.4). Whoever confirms my messages builds reputation with me, and I start confirming theirs first. Reciprocity, as in section 17 — but between the two ends of a conversation instead of between radio neighbors.

---

## 25. Delivery Confirmation

This is the mechanism that ties the economy to actual delivery.

### 25.1 The full cycle

```
A (author)          R (relay)            D (recipient)
    │                   │                     │
    │── message ───────►│                     │   R cannot read it
    │                   │── message ─────────►│   D opens it
    │◄── R's retransmission (outbound race: position HELD)
    │                   │                     │
    │                   │◄──── confirmation ──│   hash, encrypted for A
    │◄── confirmation ──│                     │
    │                                         │
    ├─ first confirmation: release the held outbound positions
    ├─ credit D with contact points (once)
    └─ pay R a position in the return race
```

### 25.2 What each node does

| Node | Does | Does not |
| :--- | :--- | :--- |
| **Author** | encrypts for the contact, opens two races, pays on confirmation | pay anything before the confirmation |
| **Relay** | re-signs and retransmits the block | read it, register it in a race list, pay anyone |
| **Recipient** | opens, delivers to the app, sends the confirmation | pay whoever carries the confirmation, register it in a race list |

### 25.3 The confirmation

```
[ENCRYPTED BLOCK: "C" + hash of the message in clear][HOP SIGNATURE]<0>
                   └── box from the recipient to the author
```

It is **the hash of the message in clear** (the `"M"` + text the recipient decrypted), encrypted for the author. Only the real recipient can build it: it had to open the message to know that hash, and the authenticated box proves it came from the recipient's wallet.

**Why the hash in clear and not the block hash.** The block hash is public — any node that heard the packet can compute it. A confirmation carrying it could be forged by anyone. The hash of the text in clear is known only to author and recipient.

The confirmation is transmitted like any packet: it goes to the queue, halves its priority at each transmission, is cached (so the recipient does not mistake it for a new packet when it comes back), and travels with the same SF/BW/CR as the message it confirms. It **does not enter the recipient's race list**.

### 25.4 Confirmation priority

At the recipient:

```
              max(1, contact points of the author) × message airtime
Priority  =  ─────────────────────────────────────────────────────────
                             confirmation airtime
```

**The numerator.** More contact points and a larger message mean more urgency: the confirmation always costs the same, but the credit it unlocks at the author is the value of the message. The **floor of 1** is what allows the very first confirmation between two nodes that never talked before — without it, `0 × airtime = 0` and nobody could ever start.

**The denominator** puts the confirmation on the same scale as the rest of the queue. Without it, at SF12 a confirmation would enter at about 24 million against about 15 thousand for an own message, and would be transmitted 11 times in a row — 54 seconds of airtime — before anything else got a turn. Dividing by its own cost is the logic of section 17 (benefit per millisecond spent) and does not change the order between confirmations, since they all cost the same.

With 4,919 contact points and equal airtimes, the priority is 4,919: on the scale of an own message.

### 25.5 The recipient does not retransmit the message

By default, the recipient does not retransmit a message addressed to it: it has arrived, and retransmitting would waste airtime. Retransmitting would hide the recipient better — it would behave like any relay. This is a configuration constant (`DESTINATARIO_RETRANSMITE`).

### 25.6 Three hashes per message

| Hash | Of what | Who knows it | Used for |
| :--- | :--- | :--- | :--- |
| block hash | the encrypted block | everyone | cache, recognizing returns |
| content hash | the text in clear | author and recipient | the confirmation |
| confirmation hash | the confirmation's block | everyone | recognizing further copies of the confirmation |

---

## 26. Why Only the Author Pays

### 26.1 The infinite-points exploit

If relays paid relays — registering relayed messages in their own race lists — this would happen:

```
A creates M and transmits
B retransmits M   →  and registers M in B's race list
A repeats M       →  B sees M in its own race list
                  →  B pays A
```

The author would get paid by the relay for transmitting its own message. With no ceiling: every new message A creates and B relays becomes a new payment source, which A milks by repeating — never carrying anything for anyone. This was observed in testing and is why only own messages enter the race list.

### 26.2 The out-of-band warning problem

The original incentive relied on uncertainty: since nobody can tell whether a transmitter is the author or a relay, it pays to carry everything, hoping the transmitter is an author who will pay.

But a node can break that uncertainty voluntarily — announcing "this one is not mine" by any channel, even another frequency or a simple beep. That cannot be prevented, and it would let nodes coordinate outside the protocol to carry only messages whose authors pay.

Conditioning payment on **delivery** changes the incentive: a relay adjacent to the author is paid only if the message actually reaches the recipient, so it has a direct interest in the next hop carrying it too. An announcement changes nothing — the payment never depended on who the author was.

### 26.3 The honest consequence: a neighborhood economy

The author can only credit the nodes it can hear: its radio neighbors, on the way out and on the way back. A relay two or more hops away receives nothing *for that specific message*, from anyone. It carries transit traffic because the neighbor handing it over has built up reputation with it over time, as an author.

In other words, GhostRelay's economy is a **neighborhood economy**, not a route economy: a node is paid for being a good neighbor, not per hop. This is coherent with the design, and it is a property contributors should keep in mind (section 33).

---

# Part II — Implementation

## 27. Architecture and Modules

Python modules on the PC, plus the firmware on the ESP32. Each module has a declared boundary.

| Module | Responsibility | Sections |
| :--- | :--- | :--- |
| `identity.py` | wallet, signing, end-to-end encryption, invites, backup | 2, 4, 12, 15, 16, 18 |
| `contacts.py` | contacts and contact points | 24, 25 |
| `cache.py` | seen hashes, FIFO | 6, 14 |
| `economy.py` | airtime, points, priorities, radio fidelity | 8, 9, 17, 20, 21, 25.4 |
| `neighbors.py` | trusted, candidates, promotion, neighbor points | 9, 15, 17, 18, 19 |
| `race.py` | own messages, the two races, held settlement | 7, 10, 25 |
| `relay_queue.py` | priority queue | 11, 21 |
| `message.py` | packet format, encrypt/open, confirmations, invites | 4, 5, 12, 13, 16, 25 |
| `mac.py` | medium access, serial bridge to the ESP32 | 3, 21 |
| `main.py` | the order in which modules are called | 5, 13, 25 |
| `server.py` | WebSocket, HTTP and test page | 22 |
| `storage.py` | persistence | 29 |
| `diag.py` | radio link test, without the protocol | 32 |
| `ghostrelay_esp32.ino` | firmware: the radio | 3, 21, 28 |

### 27.1 The most important boundaries

- **`main.py` computes nothing.** It decides the **order** in which modules are called — and that order *is* the protocol (section 13.1).
- **`message.py` does not decide discards.** It builds, separates, encrypts and opens packets.
- **`mac.py` does not know the protocol.** It listens, contends, transmits and reports.
- **The firmware knows nothing** — neither the protocol nor the economy.

---

## 28. Serial Protocol Between PC and ESP32

ASCII text lines terminated by `\n`, at 115200 baud.

### 28.1 PC → ESP32

| Command | Effect |
| :--- | :--- |
| `TX <packet>` | transmits (blocking until finished) |
| `RX_START` / `RX_STOP` | enters / leaves receive mode |
| `CAD` | probes the channel (section 3.1) |
| `CONFIG SF=12 BW=250 CR=7 [FREQ=915.0] [PWR=22]` | applies the parameters at once |
| `SET_SF` / `SET_BW` / `SET_CR` / `SET_FREQ <value>` | individual parameters |
| `STATUS` | current state |
| `PING` | liveness |
| `DIAG` | reinitializes the radio and reports |

### 28.2 ESP32 → PC

| Event | Meaning |
| :--- | :--- |
| `EVENT:BOOT` | the ESP32 (re)started |
| `EVENT:READY` | radio initialized |
| `EVENT:CAPS:CONFIG,CAD,SET_SF,SET_BW,SET_CR,SET_FREQ,PING` | what this firmware can do |
| `EVENT:RX_STARTED` | listening |
| `EVENT:RX` | **packet decoded** — section 3.2 |
| `MSG:<packet>\|SF=..\|BW=..\|CR=..\|RSSI=..\|SNR=..` | the packet and how it arrived |
| `EVENT:CRC_ERROR` | **collision** — section 3.3, ignored |
| `EVENT:RX_DISCARDED:CTRL` | packet with a control byte, discarded |
| `EVENT:TX_START` / `EVENT:TX_OK` / `EVENT:TX_ERROR:<n>` | transmission |
| `EVENT:CAD_FREE` / `EVENT:CAD_BUSY` | channel state |
| `EVENT:CAD_UNSUPPORTED:<n>` | CAD failed; continuing without listen-before-talk |
| `EVENT:CONFIG_OK` / `EVENT:CONFIG_ERROR:<field>` | configuration |
| `EVENT:RX_RETRY` | receive mode failed, retrying |
| `EVENT:RADIO_RESET:<n>` | the chip stopped answering SPI and is being reinitialized |
| `EVENT:CMD_RECEIVED:<cmd>` | echo — not an event, ignore |

### 28.3 Details that matter

- **`MSG:` comes on a single line, with its parameters.** Fields are parsed **from the end**, accepting only known keys, so a `|` inside the content cannot fool the parser.
- **`EVENT:RX` and `EVENT:CRC_ERROR` are different things**: the first makes the node lose the contest (3.2), the second is ignored (3.3).
- **Capabilities are announced at boot** (`EVENT:CAPS`), so the PC does not discover them by trial and error with timeouts.
- **A configuration has three possible outcomes:** applied (`CONFIG_OK`), refused (`CONFIG_ERROR` — the command exists, the value does not), or no answer (the command does not exist in that firmware).
- **CAD results are compared by name**, not by sign: RadioLib uses 0 for success and negative codes for everything else, including "channel busy". An unknown code is reported as unsupported, never as busy — a false "busy" would silence the node forever, since the channel wait has no timeout.
- **A wedged chip is recovered**: after 3 consecutive SPI errors (codes −705 to −707), the firmware reinitializes the radio (`EVENT:RADIO_RESET`) instead of retrying forever.
- **An oversized command line is discarded entirely** up to the next line break, never executed in pieces.

---

## 29. Persistence

Everything lives in the `ghostrelay_data/` folder (`0700`, files `0600`), next to the code, or wherever the `GHOST_DATA` environment variable points.

| What | Saved? | Why |
| :--- | :--- | :--- |
| Wallet | **yes** | it is the node's identity |
| Neighbors and points | **yes** | the economic memory; without it the economy restarts at each boot |
| Contacts and contact points | **yes** | without them, encrypted messages can no longer be opened |
| Race list | **yes** | messages still circulating must keep paying, and held positions must survive until the confirmation |
| Hash cache | **yes** | avoids reprocessing what returns during a restart |
| Retransmission queue | **no** | see below |

**The queue is deliberately not saved.** It is work in progress, not economic memory. A node that was off for an hour and came back retransmitting everything that was pending would put on air messages the network has already forgotten, spending everyone's airtime on stale echoes.

Writes are atomic (temporary file + `fsync` + `replace`), and an unreadable file is preserved under another name instead of crashing the node. Race list entries from the old unencrypted format are discarded at the first boot.

---

## 30. Limits

### 30.1 Physical — cannot be removed

| Limit | Value | Origin |
| :--- | :--- | :--- |
| LoRa packet | 255 bytes | radio |
| Text per message | 82 bytes | section 4.3 |
| Backoff window floor | 1 ms | below the resolution there is no draw |
| One SF at a time | — | the radio cannot listen to two |

### 30.2 Memory — FIFO, as the protocol requires

| Structure | Default |
| :--- | ---: |
| Hash cache | 1000 |
| Race list | 1000 |
| Retransmission queue | 1000 |
| Candidates | 256 |

### 30.3 Operational choices

| Parameter | Default | Where |
| :--- | :--- | :--- |
| Listening configuration | SF12 / BW250 / CR 4:7 | `LISTEN_CONFIG`, `mac.py` |
| Initial backoff window | 50 ms | `mac.py` |
| Invite mode | periodic | `CONVITE_MODO`, `main.py` |
| Invite interval | 5 min | `INTERVALO_CONVITE`, `main.py` |
| Recipient retransmits? | no | `DESTINATARIO_RETRANSMITE`, `main.py` |
| Data folder | `ghostrelay_data/` | `GHOST_DATA` environment variable |
| Serial port | auto-detected | `GHOST_PORTA` environment variable |

SF12 gives maximum range and maximum cost — over 4 seconds for a short message. SF9 delivers the same message in about 600 ms with still very good range. Measure before settling on one.

---

## 31. Getting Started

### 31.1 Requirements

- Two (or more) ESP32 + E80-900M2212S nodes, wired as in the pinout, **with antennas**.
- Arduino IDE with the ESP32 core and the **RadioLib** library.
- Python 3 on each PC, with:

```bash
pip install pynacl pyserial websockets
```

### 31.2 Flash the firmware

The Arduino IDE requires the sketch to be inside a folder **with the same name**:

```
ghostrelay_esp32/
└── ghostrelay_esp32.ino
```

Flash it to each ESP32. Do not paste the Python files into the IDE.

### 31.3 Test the radio link first

Close `main.py` and any serial monitor (two programs cannot open the same port), then:

```bash
# machine A
python3 diag.py --rx

# machine B
python3 diag.py --tx "hello"
```

`diag.py` talks directly to the firmware, with no protocol at all. If it works and `main.py` does not, the problem is in the protocol; if it does not work either, the problem is the radio, antenna, configuration or power — no point looking in the Python code. Options: `--sf`, `--bw`, `--cr`, `--freq`, `--intervalo`, `--quantidade`, `--porta`, `--ping`.

### 31.4 Run a node

```bash
python3 main.py
```

Then open **http://localhost:8080**.

1. Copy **your public key** from the page and give it to the other node's owner.
2. Paste **their key** in "add contact", with a name.
3. Wait for the invites to be exchanged (they make you radio neighbors).
4. Choose the recipient, type a message (up to 82 bytes) and send.
5. When the recipient confirms, the page shows **ENTREGUE** (delivered).

---

## 32. Diagnostics

| Message | What to investigate |
| :--- | :--- |
| `EVENT:INIT_ERROR:<n>` | the radio did not answer `begin()`. Check SPI, NSS/BUSY/RESET and the TCXO configuration |
| `[RADIO] o ESP32 reiniciou` | brownout — the module's power supply during TX |
| `EVENT:RADIO_RESET` repeatedly | the chip keeps wedging; suspect power first, then distance (saturation) |
| `[RADIO] sem CAD` | firmware without CAD, or an unrecognized CAD code; no listen-before-talk |
| `[RADIO] sem SET_CR` | old firmware: packets with another CR cannot go out (21.2) |
| `[MAC] canal ocupado` | someone is on air; if permanent, look for interference |
| `SEM RECOMPENSA: SF/BW/CR diferentes` | someone retransmitted in the wrong configuration (21) |
| `RETIDO: posicao N da ida` | normal: an outbound position waiting for the confirmation |
| `CONFIRMADA` / `CONTATO: +N` | a delivery was confirmed and settled |
| `destinatario nao e um contato` | register the recipient before sending |
| `[MESSAGE] mensagem recusada` | text over 82 bytes, or empty |
| `ATENCAO: A CARTEIRA VAI SER SUBSTITUIDA` | unreadable seed. **Stop the node** and restore the backup before continuing |
| `RSSI` around −20 dBm | modules too close — risk of saturation |

---

## 33. Known Limitations and Roadmap

**Multi-packet reassembly (section 13).** Not implemented, which keeps the 82-byte text limit. It needs changes in three places at once: splitting in `message.py`, transmitting all slices in a single channel access in `mac.py` (otherwise another node could transmit in between and mix two messages), and accumulating slices up to the `<0>` in `main.py`. Open design points: slices from different senders mixing, a lost slice invalidating the whole message, and each slice paying its own preamble.

**Binary on air.** Base64 inflates everything by one third. Having the firmware transmit raw bytes over the air — keeping base64 only on the serial line — would raise the text capacity per packet considerably.

**Contact registration security.** Registration requests from applications are accepted without asking the user. A confirmation step is planned.

**MAC duty cycle.** A node that always has something queued transmits back to back, and at SF12 it can spend only a few percent of its time listening. Two improvements are planned: probing the channel again immediately before transmitting (not only before the countdown), and yielding the air for at least one packet time after each transmission.

**Round-trip dependency.** Outbound rewards require both the message and the confirmation to arrive. On lossy links, many relays will do real work and never be paid, by design.

**Neighborhood economy.** Per-message payments reach only the author's direct neighbors (section 26.3). Deeper relays are motivated by accumulated neighbor reputation.

**Hardware checks pending.** TCXO configuration of the E80, CAD support for the LR2021 in the installed RadioLib version, and power supply stability at 22 dBm.

**Encryption on real hardware.** The end-to-end encryption path has been validated in simulation; its first validation between two physical nodes is pending.

---

## 💰 Support the project

I truly believe this project can change the world. If you find this work useful and would like to support its development with a donation, I would be very grateful.

Monero address: 49YdksRCWR3TY2A3WopX9322EGzzxBrFv4NbTho4DCNhSzUGfnAivcJNuAqEYCFjw8EYwbk4x745XjTt1Kh5n9KbNorXSD6

## 📝 License / Contributing

Feel free to open issues, fork the repository, and submit pull requests. Let's build a truly decentralized mesh together!
