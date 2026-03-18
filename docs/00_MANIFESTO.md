# 00 - Declaration of Intent & Plausible Deniability

## The Threat Model
`pure-mls` is an uncompromisable mathematical implementation of the Messaging Layer Security protocol (RFC 9420). 

By design, this library operates on the principle of **Zero-Knowledge** and **Plausible Deniability** for the developers and the operators holding the infrastructure.

## Our Stance
If a government agency, intelligence service, or malicious actor demands access to the cryptographic keys, metadata, or the ability to decrypt the communications managed by this library, our definitive legal and technical answer is:
**We cannot.**

1. **No Master Keys**: The authors of this library hold zero asymmetric private keys. All cryptographic material is generated dynamically and stored exclusively on the local, sovereign hardware of the end-users.
2. **No Backdoors**: There are no administrative overrides, no 'god-mode', and no key escrow mechanisms intentionally built into this mathematical tree.
3. **Open Source Accountability**: The code is 100% open-source and released under the GPLv3 license. You do not have to trust our words; we encourage you to audit the cryptography yourself against the standard RFC test vectors.

`pure-mls` is neutral mathematics. What users choose to encrypt with it is their sovereign right, their privacy, and their sole responsibility.
