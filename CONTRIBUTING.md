# Contributing to pure-mls

Thank you for your interest in contributing to `pure-mls`! 

This project aims to provide the first strictly native, zero-dependency Python implementation of the Messaging Layer Security protocol ([RFC 9420](https://datatracker.ietf.org/doc/rfc9420/)). To keep the architecture pure and manageable, we follow a very specific set of collaborative rules.

## 1. The Language Policy
- **Code & Comments:** 100% English. All variables, classes, docstrings, and inline comments must be written in professional English to ensure international accessibility.
- **Pull Requests & Issues:** Please open issues and describe your Pull Requests entirely in English.

## 2. The "Protocol of Silence" (Style & Formatting)
We prioritize **Mathematical Purity and Logic** over rigid formatting tyranny. 
- You will not find aggressive linters failing your build because you used two spaces instead of four on a blank line. 
- We do not enforce strict PEP8 compliance regarding line lengths or arbitrary spacing if breaking it makes a matrix or cryptographic derivation easier to read.
- **ViveCoded Philosophy**: Code should be functional, self-evident, and silent. Avoid watermarks, excessive robotic disclaimers, or "over-engineering" the structure. If it mathematically works and is legible, it merges.

## 3. The "Absolute Purity" Rule (Zero Dependencies)
This is the hardest rule: **We do not accept third-party bindings, Rust extensions, or C++ foreign functions.**
- If you need a cryptographic primitive (like Ed25519 or AES-GCM), rely on the standard library or, at most, widely accepted universal Python libraries like `cryptography.io`.
- No `cargo`, no `cmake`, no compilation required to install the package. It must deploy seamlessly via `pip` or `uv` on edge arm64 devices just as easily as on an x86 cloud server.

## 4. Cryptographic Validation
- Any contribution modifying cryptographic logic (TreeKEM operations, HKDF paths, KeySchedules) MUST be accompanied by a test that passes against the **official RFC 9420 Test Vectors**.
- Do not invent assumptions. If the RFC states an operation is done in a specific byte order, it must physically match the test vector.

## Getting Started
1. Clone the repository.
2. Initialize the environment: `uv sync`
3. Study `docs/01_CRYPTO_CRASH_COURSE.md` and `docs/02_ARCHITECTURE.md` before attempting to modify existing layers.

Welcome to the architecture. Let's build something indestructible.
