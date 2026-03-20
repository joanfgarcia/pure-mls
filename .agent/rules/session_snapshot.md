# Session Snapshot: pure-mls v0.1.0 Engineering Grade

## 1. Diccionario de Términos/Alias Técnico
- `group.py` -> MLS Group State Machine (`MLSGroup`, `EpochState`, `WelcomeInfo`, `GroupUpdate`).
- `hpke.py` -> RFC 9180 Base Mode encryptor (AES-GCM, HKDF-SHA256, X25519).
- `tree.py` -> LBBT Math & Data Structures (`RatchetTree`, `LeafNode`, `ParentNode`).
- `hkdf.py` -> RFC 5869 Extract & Expand primitives.
- E2E Transports -> `test_e2e_websockets.py`, `test_e2e_mqtt.py`, `test_e2e_webrtc.py`, `test_e2e_grpc.py`.

## 2. Mapa de Arquitectura TÉCNICA
- **pure-mls**: Implementación pura en Python del protocolo Messaging Layer Security (RFC 9420 / TreeKEM) agnóstica al transporte.
- Depende únicamente de `cryptography` para las primitivas abstractas (Ed25519, X25519, AES256-GCM, SHA256).
- Estado operando bajo inmutabilidad estricta (Dataclasses frozen y ruteo determinista LBBT).

## 3. Registro de Decisiones Técnicas (Log)
| Prioridad | Decisión Técnica | Razón (Why) | Estado |
| :--- | :--- | :--- | :--- |
| **P0** | **HPKE RFC-9180 Compliance** | Inyectados prefijos `HPKE-v1` y `SUITE_ID` en `extract/expand` para aislar el dominio de derivación según RFC. | Completado |
| **P0** | **WelcomeInfo State Sync** | Serializar `joiner_index` elimina la desincronización y los hardcodes espurios en inicializaciones multipartitas. | Completado |
| **P0** | **AES-GCM Nonce XOR Counter** | Aplicar XOR a `base_nonce` con un contador aleatorio salva fallas críticas de colisión de cifrado en llaves efímeras reutilizadas. | Completado |
| **P0** | **Commit Signature Coverage** | Incluir el `tree.to_bytes()` en el digest de la firma Ed25519 autentica la integridad estructural impidiendo bifurcaciones sibilinas. | Completado |
| **P0** | **WelcomeInfo HMAC Sealing** | Adoptar bytes prefijados, indexación explícita de `RatchetTree` y firmas MAC desbarata cualquier alteración a nivel byte (ej. Padding nulos). | Completado |

## 4. Última Frontera (Checkpoint)
- **Situación**: Batería de E2E Transports en verde absoluto (100% Coverage, 32 passed test). Linter enmudecido ("Sound of Silence").
- **Acciones Recientes**: Pusheados commits 5238c90 y aa9dfe6 al master remote origin, ostentando validación 'Engineering Grade'.
- **Blocker**: Ninguno. Listo para hibernación.
