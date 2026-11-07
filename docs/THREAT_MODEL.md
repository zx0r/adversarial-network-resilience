# Adversarial Threat Model & Traffic Analysis Surface

## 1. Overview
This threat model formalizes the capabilities of state-level and enterprise adversaries operating Deep Packet Inspection (DPI) infrastructure, against which modern resilient network protocols are designed to defend.

---

## 2. Adversary Classes & Capabilities

### Tier 1: Passive Network Observer (Path Eavesdropper)
- **Capabilities**: Captures raw packets at Internet Exchange Points (IXPs) or ISP boundaries.
- **Attack Vectors**:
  - **SNI Inspection**: Extracts unencrypted Server Name Indication fields in TLS handshakes.
  - **IP / Port Filtering**: Cross-references destination addresses against IP reputation blacklists.
  - **Statistical Analysis**: Measures packet length distributions, inter-arrival times, and traffic entropy.
- **Countermeasures**: Standard TLS 1.3 encryption, Encrypted Client Hello (ECH), packet padding.

### Tier 2: Stateful Active Probing Adversary (GFW Class)
- **Capabilities**: Deploys automated probing clusters that actively connect to suspicious IP:Port endpoints observed in passive traffic.
- **Attack Vectors**:
  - **Protocol Fingerprint Replay**: Replays intercepted handshakes or malformed payloads to elicit distinctive error codes (e.g. Shadowsocks probe resistance attacks).
  - **Certificate / SNI Verification**: Verifies whether an endpoint presenting a TLS certificate actually owns the matching domain.
- **Countermeasures**:
  - **VLESS-XTLS-Reality**: Bypasses certificate ownership by stealing/forwarding public handshakes of legitimate high-reputation servers (e.g., Apple, Microsoft, Yahoo), terminating connection on invalid short IDs without distinctive signatures.
  - **Salamander / Obfs4 XOR Steganography**: Masks protocol initiation headers behind shared-secret symmetric transforms.

### Tier 3: Quality-of-Service Throttling & UDP Blackholing
- **Capabilities**: Selectively throttles or drops UDP traffic, or degrades bandwidth upon detecting non-standard encrypted flows.
- **Attack Vectors**:
  - **QUIC / UDP Rate-Limiting**: Forcing connection fallback to TCP by dropping UDP datagrams.
  - **Bufferbloat / Random Drop**: Inducing TCP congestion window collapse.
- **Countermeasures**:
  - **Hysteria 2 (Brutal Congestion Control)**: Disables standard TCP/BBR loss-based backoff, transmitting at a fixed configured rate regardless of simulated packet loss.
  - **Multipath / Failover**: Automated transport switching from QUIC (TUIC/Hy2) to TCP/TLS (VLESS-Reality) upon UDP degradation.

---

## 3. Defense-in-Depth Architecture

```
User Client
  │
  ├── [Layer 1: DNS Privacy] ────── Encrypted DoH / DoT (Oblivious DNS)
  │
  ├── [Layer 2: Transport Obfs] ─── TLS 1.3 uTLS Fingerprint + Reality SNI Stealing
  │
  ├── [Layer 3: Tunnel Encapsulation] VLESS / Trojan / Shadowsocks-2022
  │
  └── [Layer 4: Inbound Routing] ── Xray / sing-box / Mihomo Router Engine
```
