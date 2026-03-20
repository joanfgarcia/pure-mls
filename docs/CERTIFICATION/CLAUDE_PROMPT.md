# Pure-MLS Comprehensive Audit Request

Act as an expert Cryptography Auditor and Senior Software Engineer. I am providing you with the complete source code of a new, pure-Python library called `pure-mls`.

This library implements a lightweight subset of the Messaging Layer Security (MLS) protocol (RFC 9420), including:
- **HPKE** (Hybrid Public Key Encryption) using X25519, SHA-256, and AES-GCM.
- **TreeKEM** group key agreement and epoch ratcheting.
- **End-to-End Tests** (WebSockets, MQTT, gRPC, WebRTC).
- **Sound of Silence** formatting and linting rules (Ruff).

Your tasks are:
1. **Cryptographic Review (P0)**: Analyze the `hkdf.py`, `hpke.py`, and `tree_math.py` implementations. Look for subtle mathematical vulnerabilities, non-constant-time comparisons (if applicable), improper initialization vectors (IVs) in AES-GCM, or bad HKDF extraction/expansion parameters.
2. **State Machine Integrity**: Review `group.py` and `epoch.py`. Are there potential race conditions, desynchronizations between group members, or edge cases during commit/welcome handling?
3. **E2E Transport Verification**: Review the tests in `tests/test_e2e_*.py`. Do they properly simulate realistic async behaviors without artificial blockings?
4. **Code Quality**: Ensure the code adheres perfectly to my "Sound of Silence" policy (no ornamental comments, tab-only indentation, strong Python typing).

If you find severe issues, provide the exact corrected code. 
If the architecture is flawlessly implemented and secure, please issue a formal **"Engineering Grade Certification"** summarizing the library's strengths.

Attached below is the output of the full repository digest.
