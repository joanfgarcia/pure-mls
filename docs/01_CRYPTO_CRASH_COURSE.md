# CRYPTO 101: Understanding MLS (Without the Headache)

Welcome to the asynchronous cryptography rabbit hole!

Since we are building **pure-mls** (a strict implementation of [RFC 9420](https://datatracker.ietf.org/doc/rfc9420/)) from scratch, we first need to understand why the "linear ratchet" (hash chain) fails for large groups, and why MLS is the current gold standard (adopted by Cisco, WhatsApp, and the IETF).

---

## 1. The Problem: The Signal Bottleneck
Before MLS, the gold standard was the Signal protocol (Double Ratchet). 
It is perfect for 2 people. But what happens if we create a group chat with **50,000 agents**? 
With Signal, if you send a message, you have to encrypt it **49,999 individual times** (once with the public key of each member). This destroys battery life, bandwidth, and performance (computational complexity **O(N)**).

## 2. The Solution: TreeKEM (Tree Key Encapsulation Mechanism)
MLS solves this by using a mathematical **Binary Tree** (computational complexity **O(log N)**).

Imagine a classic tennis tournament bracket:
- At the base (the **Leaves** / *LeafNodes*), you have the agents. Each has their own key.
- Each upper level of the tree mathematically combines the keys of those below it.
- At the very top is the **Root** (*Root Key* or *Group Secret*).
- This root is the symmetric key (AES-GCM) that **everyone** uses to actually encrypt the real chat messages.

### What is the magic of the Tree?
If a new agent wants to join the group of 50,000, we do not have to send 50,000 messages. The new agent attaches to a branch of the tree, and their public key mathematically propagates UP altering only the nodes in *their specific branch* until reaching the root. 
The computational complexity drops from 50,000 calculations (O(N)) to barely **16 calculations** (O(log N)). It's mathematical black magic.

---

## 3. Key Concepts of the MLS Dictionary
To ensure we are on the same page when we dive into the Python code, here are the sacred terms of RFC 9420:

*   **KeyPackage**: The "Cryptographic ID card". Your public business card that says "Hello, my name is X and these are my pre-computed X25519 public keys".
*   **Proposal**: The intent to do something. Ex: "I propose adding Agent_X to the group" or "I propose changing my own key because it's compromised (Ratchet)".
*   **Commit**: The "Notary Seal". Once the community sees one or more Proposals, a designated operator packages them into a Commit. By accepting the Commit, the group mathematically advances to a new era.
*   **Epoch**: Every time a new Commit is ratified, the group enters a new Epoch with a completely new and unpredictable *Root Secret* (base key).
*   **Welcome**: The special encrypted message sent to newcomers to give them the current state of the Binary Tree so they can derive the base key.

## 4. PCS and PFS (True Invulnerability)
- **PFS (Perfect Forward Secrecy)**: "Protection towards the Past". If I break your private key today, I cannot decrypt the Epochs that occurred yesterday, because the hash destroys information in reverse.
- **PCS (Post-Compromise Security)**: "Healing towards the Future". If a thief steals your private key and sneaks into the group, as soon as you make a Commit to rotate your key (*Update Proposal*), you automatically kick the thief out of the tree without having to recreate the entire community. The system "heals" itself.

---

From here, in `pure-mls` we will code each of these blocks step by step. We will start from the base (`LeafNode` and the Ed25519 elliptic curve cryptography) and climb the branch until we conquer the `Root Key`.
