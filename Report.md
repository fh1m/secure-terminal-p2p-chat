# Encrypted Peer-to-Peer Chat System: Visual + First-Principles Report

## 1) What the system is trying to guarantee (from first principles)

A secure chat system is not just “encrypt text.” It must answer four practical questions:

1. **Who am I talking to?** (authentication / identity confidence)
2. **How do we agree on one secret key safely?** (key distribution)
3. **Can an attacker tamper with messages?** (integrity)
4. **Can old packets be replayed to confuse the session?** (freshness)

This project solves those with explicit protocol steps in `Code/main.py`, using:
- **RSA-2048 + OAEP** for key transport,
- **RSA-PSS** for signature-based key-authentication,
- **AES-256-GCM** for authenticated encryption,
- **nonce + timestamp + sequence checks** for replay resistance.

---

## 2) Layered architecture (what runs where)

```mermaid
flowchart TB
    subgraph UI["User Interface Layer"]
        U1["ui.py: Console formatting"]
        U2["ui.py: ChatInput prompt"]
    end

    subgraph APP["Application + State Layer"]
        A1["main.py: SecureChatClient"]
        A2["Command handlers: /sendpub /share /rekey"]
        A3["State: peer key, verified flag, pending initiator/responder, session key, seq counters"]
    end

    subgraph PROTO["Protocol Layer"]
        P1["protocol.py: encode_message/decode_message"]
        P2["Envelope: {v, type, payload} + freshness window"]
    end

    subgraph CRYPTO["Crypto Layer"]
        C1["crypto.py: RSA keygen + fingerprint"]
        C2["RSA-OAEP encrypt/decrypt + RSA-PSS sign/verify"]
        C3["AES-256-GCM encrypt/decrypt + AAD binding"]
    end

    NET["TCP socket: newline-delimited JSON"]

    U1 --> A1
    U2 --> A2
    A2 --> P1
    A1 --> C1
    A1 --> C2
    A1 --> C3
    P1 --> NET
```

**Runtime model:** one main thread handles input/sending, while a receiver thread
decodes incoming lines and dispatches handlers. Shared state is guarded by locks.

---

## 3) Full protocol sequence (public keys + shared key + secure chat)

```mermaid
sequenceDiagram
    participant A as Peer A (initiator)
    participant N as Untrusted network
    participant B as Peer B (responder)

    Note over A,B: Phase 0: connect + hello
    A->>N: HELLO{sender, ts, features}
    N->>B: HELLO
    B->>N: HELLO
    N->>A: HELLO

    Note over A,B: Phase 1: in-band public key exchange
    A->>N: PUBKEY{pem, fingerprint, reply_expected=true}
    N->>B: PUBKEY
    B->>B: Load PEM, compute fingerprint, store peer key
    B->>N: PUBKEY{pem, fingerprint, reply_expected=false}
    N->>A: PUBKEY
    A->>A: Load PEM, compute fingerprint, store peer key
    Note over A,B: Operator may run /verify out-of-band fingerprint check

    Note over A,B: Phase 2: shared session key establishment
    A->>N: KEY_REQ{sender, ts, nonce_a, rekey}
    N->>B: KEY_REQ
    B->>B: Check timestamp freshness (±180s)
    B->>B: Create nonce_b, store pending_responder
    B->>N: KEY_CHALLENGE{sender, ts, nonce_a, nonce_b, rekey}
    N->>A: KEY_CHALLENGE

    A->>A: Generate 32-byte session_key
    A->>A: key_id = SHA256(session_key)[:16]
    A->>A: ek = RSA-OAEP(peer_pub, session_key)
    A->>A: sig = RSA-PSS(sign canonical{sender,ts,nonce_a,nonce_b,key_id,ek})
    A->>N: KEY_SET{sender, ts, nonce_a, nonce_b, key_id, ek, sig}
    N->>B: KEY_SET

    B->>B: Verify nonce binding + freshness + signature
    B->>B: Decrypt ek with local private RSA key
    B->>B: Validate derived key_id
    B->>B: Activate secure session (seq reset)
    B->>N: KEY_ACK{sender, ts, key_id, blob}
    Note over B: blob = AES-GCM(session_key, {sender,ts,nonce_b,key_id}, AAD="P2P-CHAT-V2|KEY_ACK|key_id")
    N->>A: KEY_ACK

    A->>A: Decrypt blob with pending session_key + KEY_ACK AAD
    A->>A: Verify nonce_b, key_id, and decrypted timestamp freshness
    A->>A: Activate secure session (seq reset)

    Note over A,B: Phase 3: encrypted chat
    A->>N: SEC_CHAT{sender, ts, key_id, blob}
    Note over A: blob = AES-GCM(session_key, {sender,ts,seq,text}, AAD="P2P-CHAT-V2|SEC_CHAT|key_id")
    N->>B: SEC_CHAT
    B->>B: Check active key_id, decrypt, enforce seq == last+1
```

### Why this sequence works

- **Authentication of key material:** `KEY_SET` is signed by the initiator’s RSA private key, so the responder can verify who authorized the transported key.
- **Confidential key transport:** `ek` is encrypted with responder’s public key, so only responder can recover the session key.
- **Key confirmation:** `KEY_ACK` proves responder could decrypt and use the same key.
- **Context binding:** AAD includes message purpose (`KEY_ACK` vs `SEC_CHAT`) and `key_id`, preventing cross-use of ciphertext.

---

## 4) Trust and threat model visualization

```mermaid
flowchart LR
    A["Peer A process"]
    B["Peer B process"]
    NET["Untrusted network"]
    X["Active attacker"]

    A -->|"JSON envelopes"| NET
    NET -->|"JSON envelopes"| B

    X -. "eavesdrop" .-> NET
    X -. "inject/modify" .-> NET
    X -. "replay/delay/reorder" .-> NET

    A <-->|"out-of-band fingerprint check"| B

    V{"Fingerprint verified via /verify?"}
    V -->|Yes| T1["Higher confidence key belongs to peer"]
    V -->|No| T2["MITM/key-substitution risk remains"]
```

### Security objective mapping

- **Confidentiality:** AES-GCM protects `SEC_CHAT` payload text.
- **Integrity:** GCM tags + RSA signature checks reject modified payloads.
- **Authentication:** signature verification + fingerprint verification process.
- **Freshness:** timestamps for handshake and monotonic `seq` for secure chat.

---

## 5) Lifecycle and state machine

```mermaid
stateDiagram-v2
    [*] --> Connected
    Connected --> PublicKeyKnown: PUBKEY stored
    Connected --> Connected: HELLO / NICK_UPDATE / PLAIN_CHAT

    PublicKeyKnown --> PublicKeyVerified: /verify matches fingerprint
    PublicKeyKnown --> InitiatorPending: /share or /rekey sends KEY_REQ
    PublicKeyKnown --> ResponderPending: receive valid KEY_REQ

    InitiatorPending --> AwaitAck: receive valid KEY_CHALLENGE + send KEY_SET
    AwaitAck --> SecureSession: receive valid KEY_ACK

    ResponderPending --> SecureSession: receive valid KEY_SET + send KEY_ACK

    SecureSession --> SecureSession: accept in-order SEC_CHAT
    SecureSession --> InitiatorPending: /rekey
    PublicKeyKnown --> PublicKeyKnown: peer key change resets verified flag
```

Implementation-aligned details:
- `pending_initiator` and `pending_responder` hold nonce context.
- `_activate_session(...)` installs key, sets `session_established=True`, resets send/recv sequence counters, and clears pending handshake state.
- Secure receive path rejects stale key IDs, replayed sequences, and out-of-order sequences.

---

## 6) Packet evidence and validation workflow

```mermaid
flowchart TD
    P["Captured line/packet"] --> D["Decode envelope: decode_message()"]
    D --> E{"Valid {v,type,payload}?"}

    E -->|No| R1["Reject + warning (ProtocolError)"]
    E -->|Yes| T{"Message type"}

    T -->|PUBKEY| K1["Recompute fingerprint from PEM"]
    K1 --> K2["Store peer key; reset verified if key changed"]

    T -->|KEY_REQ/KEY_CHALLENGE/KEY_SET| H1["Check mandatory fields + timestamp freshness"]
    H1 --> H2["Check nonce binding across handshake"]
    H2 --> H3["Verify signature / decrypt RSA key / validate key_id"]
    H3 --> H4["Accept or reject handshake step"]

    T -->|KEY_ACK| A1["Decrypt blob with pending key and KEY_ACK AAD"]
    A1 --> A2["Validate nonce_b + key_id + decrypted ts"]
    A2 --> A3["Activate session if valid"]

    T -->|SEC_CHAT| S1["Check active key_id"]
    S1 --> S2["AES-GCM decrypt with SEC_CHAT AAD"]
    S2 --> S3["Validate seq == last+1"]
    S3 --> S4["Render message / reject replay or out-of-order"]

    T -->|PLAIN_CHAT| P1["Read visible sender/text/ts (pre-secure mode)"]
```

### What packet evidence should show

1. **Before `/share`:** `PLAIN_CHAT` text readable in capture.
2. **During handshake:** visible metadata for `PUBKEY`, `KEY_REQ`, `KEY_CHALLENGE`, `KEY_SET`, `KEY_ACK`.
3. **After session activation:** `SEC_CHAT.blob` visible as base64 ciphertext, not readable plaintext.
4. **Negative tests:** replayed `SEC_CHAT` or stale handshake timestamps are logged and ignored.

---

## 7) Principle-driven explanation of core controls

| Principle | How this implementation enforces it |
|---|---|
| Authentication | RSA-PSS signature on canonical `KEY_SET` payload; optional operator fingerprint verification via `/verify`. |
| Key distribution | Initiator generates random 32-byte key, wraps with responder public RSA key (`ek`) and signs the context. |
| Trust establishment | Fingerprints are computed from PEM locally and can be verified out-of-band; trust is explicit, not assumed. |
| Freshness | Handshake timestamps checked with bounded skew (`MAX_CLOCK_SKEW_SECONDS = 180`), plus nonces and strict secure-message sequence counters. |
| Integrity + context binding | AES-GCM tags and AAD domain separation (`P2P-CHAT-V2|PURPOSE|key_id`) prevent undetected tampering and cross-context replay. |

### Added commands (aligned with reference implementation)

| Command | Description |
|---|---|
| `/showkeys` (updated) | Displays full PEM of local and peer public keys, plus fingerprints. Previously showed fingerprints only. |
| `/showsession` | Shows detailed handshake state: session key presence, handshake role (A initiator / B responder), pending nonce state, and send/recv sequence counters. Parallel to the reference implementation's `/showsession`. |
| `/status` (updated) | Now includes `Messages sent: N \| received: N` counters tracked across the session. |

---

## 8) Operational walkthrough aligned with implemented commands

1. Start peers:
   - `python3 Code/main.py listen 5000 --nick Alice`
   - `python3 Code/main.py connect 127.0.0.1 5000 --nick Bob`
2. Optional plaintext test: send a normal message before key sharing (`PLAIN_CHAT`).
3. Generate keys if not yet done: `/genkeys`.
4. Exchange public keys: `/sendpub` (peer auto-replies once).
5. Inspect keys and fingerprints: `/showkeys` — shows full PEM of both local and peer keys, plus their fingerprints.
6. Optionally verify peer fingerprint out-of-band: `/verify <fingerprint>`.
7. Start secure setup: `/share` — triggers `KEY_REQ` → `KEY_CHALLENGE` → `KEY_SET` → `KEY_ACK`.
8. Send normal text again; it now goes as encrypted `SEC_CHAT` once session is active.
9. Inspect detailed session state: `/showsession` — shows key presence, handshake role (A/B), and sequence counters.
10. Check message counters and overall state: `/status` — shows `Sent: N | Received: N` along with session summary.
11. Rotate session key at any time: `/rekey`.
12. Use `/history` to review past messages; exit with `/quit`.

---

## 9) Current limits and realistic next steps

- Identity proof is still operator-dependent unless fingerprints are verified out-of-band.
- RSA key transport does not provide forward secrecy if long-term keys are later compromised.
- Freshness depends partly on endpoint clocks for handshake timestamp checks.

High-value improvements:
1. Move to authenticated ephemeral key agreement for forward secrecy.
2. Add persisted trust-on-first-use or certificate-backed identity.
3. Add structured audit logs for accepted/rejected security events.
