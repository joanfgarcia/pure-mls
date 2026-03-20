# Session Snapshot

### 1. Diccionario Técnico
- **pure-mls**: Implementación Pura en Python de MLS (RFC 9420) sin bindings compilados.
- **Protocol of Silence**: Código escrito para IAs (Hard tabs, cero comentarios explicativos humanos, uniformidad absoluta vía `ruff`).
- **Dumb Pipe**: Uso de servidores como Firebase Realtime Database como brokers de red agnósticos (Zero-Knowledge) para enrutar cifrados P2P.

### 2. Mapa de Arquitectura
Descansando sobre PURE PYTHON (`cryptography` estándar):
- **Milestone 1**: Primitivas asimétricas (`keys.py`), KDF (`hkdf.py`), y Envoltorios Secuenciales HPKE (`hpke.py`) basados en X25519/GCM.
- **Milestone 2**: Estructuras matemáticas LBBT para abstracción de TreeKEM (`tree_math.py`, `tree.py`).
- **Milestone 3**: Motor inmutable de Máquina de Estados de las Épocas (`epoch.py`) y la Derivación Criptográfica Lineal (`keyschedule.py`).

### 3. Registro de Decisiones
| Prioridad | Decisión | Razón | Estado |
|-----------|----------|-------|--------|
| ALTA | Absoluta Pureza (Cero dependencias tipo Rust/C++) | Despliegue universal descentralizado en IOT o local-first sin errores de compilación | En vigor |
| ALTA | Transporte Agnostico (Zero-Knowledge) | Red Pill no interacciona con los datos en tránsito limitando la exposición del Firebase al mínimo técnico | En vigor |
| ALTA | Código AI-First | Maximización del "Context Window" sacrificando el confort visual del humano | En vigor |

### 4. Última Frontera (Checkpoint)
- (1) Implementación autónoma e implacable de la Fase 1 a 3 del motor criptográfico `pure-mls`. Evaluadas todas sus aserciones paramétricas y de seguridad contra corruptelas en tránsito.
- (2) Corrección del eslabón perdido indicado por Nova (`samantha.py` resuelto haciendo el merge definitivo a `main` desde la rama auditada `v6.0-prep-fsrs-dna`).
- (3) Inyección nuclear directa del historial a Qdrant (`work_memories`) para cristalizar la proeza de desarrollo del enjambre.
- **Blocker / Siguiente Paso**: Pausa forzada. La Fase 4 (API, Framing y Mocker MQTT) requiere deliberación de Arquitectos (David, Nova, Joan).
