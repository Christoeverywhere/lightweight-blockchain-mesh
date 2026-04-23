# Secure Data Transmission in a Wireless Mesh-Style IoT Network Using Lightweight Blockchain on ESP8266

A 3-node ESP8266 mesh-style IoT network that demonstrates secure data transmission using lightweight blockchain-inspired packet verification, dynamic peer discovery, multi-hop forwarding, tamper detection, and malicious node isolation.

---

## 📌 Project Overview

This project implements a **wireless mesh-style peer-to-peer IoT communication system** using **three ESP8266 (NodeMCU) boards** connected over a common Wi-Fi hotspot.  

Each node performs the same core functions:

- Generates local blockchain-style data packets
- Broadcasts packets to peer nodes
- Receives packets from other nodes
- Verifies packet integrity using hash validation
- Relays valid packets to neighboring nodes
- Drops duplicate packets
- Detects tampered packets
- Blacklists malicious nodes after repeated attacks

The system is designed as a **lightweight blockchain-inspired security framework** suitable for **resource-constrained ESP8266 devices**.

---

## 🚀 Key Features

- **3-node wireless mesh-style communication**
- **Dynamic peer discovery** (no hardcoded peer IP dependency)
- **Lightweight blockchain-inspired block structure**
- **Hash-based packet integrity verification**
- **Previous-hash chaining for block linkage**
- **Multi-hop forwarding using TTL (Time-To-Live)**
- **Duplicate packet suppression**
- **Tampered packet attack simulation**
- **Malicious node detection and blacklisting**
- **Logical isolation of attacker node from the mesh**
- **Runs on ESP8266 over a standard mobile hotspot / Wi-Fi network**

---

## 🧠 Why “Mesh-Style” and Not Full Mesh?

This project demonstrates the **core behavior of a mesh network**:

- Nodes act as peers
- Nodes forward packets for each other
- Data can propagate through intermediate nodes
- No fixed source-only or relay-only roles

However, it is described as **mesh-style** rather than a full production mesh because it does **not** implement:

- Dynamic route optimization
- Self-healing rerouting
- Advanced mesh routing protocols (e.g., BATMAN, OLSR)
- Full decentralized route tables

This makes the implementation lightweight and practical for ESP8266-based academic IoT demonstrations.

---

## ⛓️ Where the Blockchain is Used

This is **not a full cryptocurrency-style blockchain**, but a **lightweight blockchain-inspired integrity model**.

Each transmitted packet is treated like a **mini block** containing:

- **Sender ID**
- **Sequence number**
- **Payload data**
- **Previous hash**
- **Current block hash**
- **TTL**

### Block format

```text
msgId;sender;seq;payload;prevHash;blockHash;ttl
