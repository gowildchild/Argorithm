# 📑 Argorithm & TACO

# Polyamoric Context-Attestation Protocol

### Open-Source Reference Implementation (PoC v0.2.0)
**Author:** Gunther Voet  
**Reference Specification:** [IETF Draft: draft-voet-bgp-oob-validation]([https://ietf.org](https://datatracker.ietf.org/doc/draft-voet-bgp-oob-validation/))

---

## 1. Core Philosophy: The Invisible Honey-Snare (Based on Argorithm
Traditional Zero-Trust frameworks communicate failure loudly. When an endpoint or transit node fails a validation check, typical corporate platforms throw explicit "Access Denied" errors, instantly alerting a malicious actor or a thief that they have hit a security perimeter. 

The **Argorithm** protocol completely subverts this attacker visibility. It is an elegant, stateless, low-overhead context-attestation protocol that compresses dense multi-layered identity, physical hardware layer metrics, local network topology, and external wide-area BGP routing path signatures into a compact hexadecimal string.

Instead of locking up execution paths or announcing an enforcement drop, the engine shifts state **silently**. It engages a **"Poisoned/Demo instance"** that behaves normally to an intruder, generating randomized or dummy data output to corrupt their research, while using background licensing threads to stream real-time tracking telemetry and rogue wide-area public WAN IP metrics back to centralized security logs.

---

## 2. Cryptographic Architecture: Polyamoric Touch Handshakes
Unlike rigid authentication systems that rely on static database queries or fixed tokens (which are vulnerable to hard-disk thefts), the **TACO / SesamID** framework functions through **Polyamoric Touch Handshakes**. 

Tokens act as live, self-mutating carrier blocks. When an Outbound Token touches an Inbound Mirror Register, they execute an asymmetric, interactive cryptographic handshake natively in RAM. They read each other's parameters, verify sequence paths, and dynamically morph their underlying internal structures into a fresh alignment plane for the next clock cycle.

### The Three Defensive Pillars:
1. **The Complementary Mirror Constraint:** Counters are not stored as single fuzza-ble integers. The architecture enforces two simultaneous loop registers: an Incremental Up-Counter and a Decremental Down-Counter. They must evaluate perfectly to the structural ceiling:
   $$\text{COUNTER\_UP} + \text{COUNTER\_DOWN} = \text{CEILING} \pmod{\text{Width}}$$
   If even a single bit drifts, the mathematical bridge collapses.
2. **The 1-Minute Cryptographic Expiration Wall:** The polyamoric stream cipher binds its encryption XOR mask sequence directly to a rolling 1-minute time block window ($T = \lfloor\text{time} / 60\rfloor$). The exact same bit layout produces completely different scrambled ciphertext from one minute to the next, rendering wire interceptions and packet replay attacks useless.
3. **Self-Healing Convergence Ring:** Built strictly for highly volatile networking environments like the global BGP routing plane, the protocol tolerates minor clock lag. The receiver checks the $T$ window first, falling back to the previous minute $T-1$ to absorb natural network jitter. If an un-synchronized alteration breaks both gates, the token freezes its sequence registers permanently to zero, bricks the production channel, and activates its hidden alarm triplines.

---

## 3. Structural Field Packaging Matrices
The reference module features an **Adaptive Width Processor** that automatically adapts its parsing algorithms based on the incoming string character length:

### 128-Bit Core Frame Layout (32 Hex Characters)
For application layer gates, fast OAuth2 key salt provisioning, and automated local workflow tasks:
* `LID_BYTE` (8 bits): Operational instruction state flag.
* `COUNTER_UP` (8 bits) & `COUNTER_DOWN` (8 bits): Complementary mirror counter loop.
* `TOKEN_TIME` (8 bits): Rolling 1-minute clock epoch index.
* `DATA_FIELD_32` (32 bits): Universal multi-byte generic data payload slot.
* `PROVISION_SALT` (32 bits): Next generation dynamic crypto key salt factor.
* `UNIVERSAL_META_BITS` (24 bits): EXISTENZ active canary alarm triplines.
* `ECC_BYTE` (8 bits): Argorithm Tier B Modulo-256 Plaintext Sum Check.

### 256-Bit Expanded Layout (64 Hex Characters)
For out-of-band Inter-AS trajectory validation, route-leak tracing, and hardware farm perimeter enclosure:
* `LID_BYTE` (16 bits) | `COUNTER_UP` (16 bits) | `COUNTER_DOWN` (16 bits) | `TOKEN_TIME` (16 bits)
* `UPLINK_AS` (32 bits): Source/Uplink Autonomous System Number.
* `DOWNLINK_AS` (32 bits): Destination/Downlink Autonomous System Number.
* `PROVISION_SALT` (32 bits) | `UNIVERSAL_META_BITS` (56 bits) | `ECC_BYTE` (8 bits)

---

## 4. Operational Command Reference
The compiled reference module provides comprehensive testing vectors out of the box:

### Generate a Pristine Configuration State File
```bash
python3 poly_engine.py --create new --width 128 --encrypt SesamID2012 --out client_vault.json
```

### Programmatically Process an Encrypted Token String
```bash
python3 poly_engine.py --in-token OK:6A993B0B3F53D3F4A66EBC6E758CFF73 --encrypt SesamID2012
```

### Launch the Split-Screen Interactive Visual Laboratory Dashboard
Run the multi-pane terminal simulation dashboard to visually monitor handshakes, inject attacks, step counters, and trace real-time JSON emission streams:
```bash
python3 poly_engine.py --loopback --width 128 --encrypt SesamID2012
```

#### Dashboard Interface Keybinds:
* `[UP ARROW]`: Fires a successful forward handshake touch cycle across the top/bottom panes.
* `[DOWN ARROW]`: Injects a corrupted counter fuzzing vector to test your honeypot traps.
* `[R]`: Synchronizes local time parameters with the current upstream minute window.
* `[U]`: Executes your client's automated link reset command to purge locks and reset registers.
* `[Q]`: Safely exits the curses execution buffer back to standard terminal output.

---

## 5. Licensing and Open-Source Distribution
Copyright (C) 2026 Gunther Voet. All Rights Reserved.

Codenamed: **Argorithm & TACO (Context-Attestation Reference Framework)**

This architecture is distributed in the hope that it will be useful, but **WITHOUT ANY WARRANTY**; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 

This reference documentation and the underlying protocol implementation code are free software; you can redistribute them and/or modify them under the terms of the **GNU General Public License v3 (GPLv3)** as published by the Free Software Foundation. See the official GNU documentation for comprehensive licensing parameters.
