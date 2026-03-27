# Session Snapshot — pure-mls B760 Audit
**Fecha:** 2026-03-26 · **Branch:** `feat/v3.0-phase6-interop` · **Último commit:** `88b2625`

---

## 1. Diccionario de Alias Técnico

| Alias | Real |
|---|---|
| `advance_epoch` | `EpochState.advance_epoch()` → `src/pure_mls/epoch.py:28` |
| `_psk_secret` | `keyschedule._psk_secret(psk_list)` → `src/pure_mls/keyschedule.py:36` |
| `application_key` | Propiedad deprecated en `MLSGroup` — usar `encrypt/decrypt_application_message()` |
| `gi_ctx` | `GroupContext` parseado en `MLSGroup.join()` → `group.py:~1268` |
| `_make_group_context` | Helper en `group.py` → construye `GroupContext` TLS bytes |
| `group_ctx_verify` | `GroupContext` con `transcript_hash` real (process_update) → `group.py:1343` |
| `varint_encode` | Canonical MLS VarInt → `hkdf.py` (3-tier, max 2^30-1) |
| `SecretTree` | API E2E: `encrypt/decrypt_application_message` → `src/pure_mls/secret_tree.py` |
| `B760` | Identificador de la auditoría criptográfica de este sprint |

---

## 2. Mapa de Arquitectura

```
src/pure_mls/
├── group.py         # MLSGroup: create, add_member, join, process_update, encrypt/decrypt_app_msg
├── epoch.py         # EpochState + advance_epoch(group_context=...) [P0-01 fix]
├── keyschedule.py   # KeySchedule.derive(psk_list) [PSK §8.4 implementado]
├── hkdf.py          # expand_with_label, varint_encode [encode_varint eliminado N-01]
├── hpke.py          # HPKE seal/open
├── keys.py          # SignatureKey, KemKey
├── tree.py          # RatchetTree, LeafNode.verify_signature(group_id, leaf_index) [P1-04]
├── secret_tree.py   # SecretTree ratchet per-leaf
└── tls.py           # Wire format helpers
# tree_math.py → ELIMINADO (P1-03)
```

---

## 3. Log de Decisiones Técnicas

| Prioridad | Decisión | Razón | Estado |
|---|---|---|---|
| P0 | `advance_epoch()` acepta `group_context: bytes` | RFC 9420 §8: epoch secrets deben estar bound al GroupContext (group_id, epoch, tree_hash, transcript_hash). `b""` = domain collapse | ✅ `88b2625` |
| P0 | `join()` usa `gi_ctx.to_bytes()` para `epoch_secret` | Mirror de P0-01; joiner debe derivar el mismo epoch secret que el creador | ✅ `88b2625` |
| P0 | `test_e2e_websockets.py` migrado a `encrypt/decrypt_application_message` | MQTT y WebRTC ya migrados; WebSocket quedó olvidado. Elimina raw AESGCM, nonce en claro, empty AAD | ✅ `88b2625` |
| P1 | `tree_math.py` eliminado | Dead code — implementación duplicada de RatchetTree. `RatchetTree` inline es canonical | ✅ `88b2625` |
| P1 | `LeafNode.verify_signature(group_id, leaf_index)` | TBS para `update`/`commit` source incluye group_id+leaf_index per RFC §7.2. Sin estos args → false positive silencioso | ✅ `88b2625` |
| N1 | `encode_varint()` eliminado de `hkdf.py` | Duplicado del QUIC tier (8-byte, no en RFC 9420). `varint_encode()` es canonical | ✅ `88b2625` |
| Minor | `import hmac` inline → module-level | Style fix audit B760 | ✅ `993f9a9` |
| Minor | `application_key` DeprecationWarnings eliminados en tests | Tests reescritos con roundtrip encrypt/decrypt | ✅ `993f9a9` |
| Minor | PSK injection RFC §8.4 implementado | `_psk_secret()` XOR chain multi-PSK; reemplaza `NotImplementedError` | ✅ `d57e08e` |

---

## 4. Última Frontera (Checkpoint)

### Últimas 3 acciones
1. **B760 re-audit: 6 findings resueltos** — commit `f67aacb` + changelog `88b2625` pusheados a `feat/v3.0-phase6-interop`
2. **B760 minor findings (4 items)** — commits `b91a2e3`→`6105a4c` (inline import, DeprecationWarnings, PSK §8.4, xfail docs)
3. **Reverse merge `main`→`feat/v3.0-phase6-interop`** — conflictos resueltos favoreciendo feature branch

### Estado actual
```
branch: feat/v3.0-phase6-interop
HEAD:   88b2625
tests:  145 passed · 0 failed · 50 xfailed · ruff clean
```

### Blocker / Próximos pasos
- **No hay P0 blockers** — todos los B760 findings resueltos
- **50 xfails** son backlog legítimo de fases 7+8:
  - 41 × `test_secret_tree_key_nonce` — SecretTree IETF wire format (Fase 7)
  - 8 × `test_passive_client_welcome` — Welcome HPKE wire format (Fase 8)
  - 1 × `test_key_schedule_epoch_0_suite_1` — IETF PSK vector sin descomponer
- **Próximo paso sugerido**: abrir PR `feat/v3.0-phase6-interop` → `main` (o continuar con Fase 7: SecretTree IETF vectors)
- **`main` protegida** — sólo vía PR
