# libp2p Secure Gossip Lab

A learning experiment exploring the separation between **transport-layer security** and **application-layer security** in a peer-to-peer gossip network built with [libp2p](https://libp2p.io/).

## What This Experiment Is About

libp2p already secures the transport with **Noise protocol** (encrypts the wire, authenticates peers by their `PeerId`). But that only answers: *"is this the peer I connected to?"*

It does **not** answer: *"can I trust the content this peer is publishing?"*

This experiment adds a second, independent identity layer on top:
- Each node has an **Ed25519 signing key** (separate from the libp2p transport key)
- Outgoing messages are **signed** with this key
- Incoming messages are **verified** before being accepted
- Gossipsub is configured to **enforce** validation at the protocol level — rejected messages are not propagated to other peers

The key insight: **two separate identities, two separate trust levels**.

| Layer | Key | What it proves |
|---|---|---|
| Transport (Noise) | libp2p `Keypair` → `PeerId` | You're talking to a specific peer |
| Application | Ed25519 `SigningKey` → `node_id` | The message content was authored by a specific node |

## Architecture

```
src/
  main.rs       — CLI arg parsing, swarm setup, event loop, message signing
  lib.rs        — NetworkBehaviour, swarm builder, event handling, signature verification
  message.rs    — SignedChatMessage envelope (sender_id, payload, signature)
  identity.rs   — Key management: load/generate Ed25519 keypairs, trusted senders map
keys/
  demo_keys.json — Auto-generated keypairs for node1, node2, node3 (gitignored)
```

### Message Envelope

Every published message is a JSON envelope:

```json
{
  "sender_id": "node1",
  "payload": "hello world",
  "signature": "<base64-encoded Ed25519 signature>"
}
```

The signature covers `sender_id + "\n" + payload` — this prevents a peer from relaying a valid message while swapping the `sender_id`.

### Validation Flow (receive side)

```
message arrives
     │
     ├─ not valid JSON envelope → Ignore (drop silently, no penalty)
     │
     ├─ signature empty → Reject (unsigned messages not allowed)
     │
     └─ signature present
           │
           ├─ sender_id not in trusted_senders → Reject
           ├─ signature base64 decode fails   → Reject
           ├─ Ed25519 verify fails            → Reject
           └─ verify passes                  → Accept (verified ✓)

Reject = gossipsub treats the message as invalid and does not propagate it. Depending on peer scoring configuration, rejected messages may affect peer score.
```

## Running the Experiment

Keys are auto-generated on first run into `keys/demo_keys.json`.

**Two nodes with mDNS discovery (simplest):**
```bash
# Terminal 1
cargo run -- 5152 --node-id node1

# Terminal 2
cargo run -- 5153 --node-id node2
```

**Without mDNS (manual dial):**
```bash
# Terminal 1 — note the listening address it prints
cargo run -- 5152 --node-id node1 --no-mdns

# Terminal 2 — dial the address from terminal 1
cargo run -- 5153 --node-id node2 --no-mdns /ip4/127.0.0.1/tcp/5152
```

**Unsigned/untrusted node demo:**
```bash
cargo run -- 5154
```
Running without `--node-id` creates unsigned messages, which connected peers reject.

### Expected Output

```
From: node1 (verified ✓): [<id>] 'hello'
From: node2 (verified ✓): [<id>] 'world'
REJECTED message from '<peer-id>': unsigned messages not allowed
REJECTED message from 'unknown': unknown sender 'unknown'
```

## Dependencies

| Crate | Purpose |
|---|---|
| `libp2p 0.56` | TCP transport, Noise encryption, mDNS discovery, Gossipsub |
| `ed25519-dalek 2` | Application-level Ed25519 signing and verification |
| `serde` / `serde_json` | JSON message envelope serialization |
| `base64 0.22` | Encoding keys and signatures |
| `tokio 1` | Async runtime |

## Security Scope

This experiment demonstrates application-level message authenticity and static authorization.

It protects against:
- Payload tampering.
- Forged sender IDs.
- Messages signed by unknown application identities.
- Unsigned messages being propagated.

It does not provide:
- Message confidentiality.
- Replay protection.
- Key rotation.
- Dynamic trust management.
- Secure private-key storage.
- Protection from a compromised trusted sender.

Replay protection is intentionally left out. A production design would include a nonce, timestamp, or sequence number in the signed payload and track previously seen messages.

## What This Is NOT

- Not production-ready — key management is intentionally naive (keys stored in plaintext JSON)
- Not a complete trust model — `trusted_senders` is a static allowlist loaded at startup
- The mDNS dial tie-breaker (lexicographic `PeerId` comparison) is only for experiment convenience

## Series Context

This is **Experiment 6** in a series exploring libp2p security layers:

- Exp 5: Basic gossipsub + mDNS
- **Exp 6 (this)**: Application-level Ed25519 signing + gossipsub validation enforcement
- Exp 7 (planned): Symmetric encryption of message payloads
- Exp 8 (planned): MLS (Messaging Layer Security) for group key agreement
