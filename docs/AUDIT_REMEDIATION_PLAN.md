# pure-mls — Plan de remediación de auditoría (13 jul 2026)

> **Para el agente ejecutor.** Este documento es autocontenido. No asumas nada que no esté
> aquí; si un número de línea no coincide, localiza el símbolo por nombre (grep) antes de editar.
> Cada finding tiene: **Hallazgo**, **Por qué está mal**, **Solución** (con código exacto) y
> **Cómo testearlo**. Sigue el orden: primero los HIGH, luego MEDIUM, luego LOW, luego housekeeping.

## Reglas de trabajo (obligatorias)

1. **Rama.** No trabajes sobre `main`. Crea `fix/audit-remediation` a partir de `main`
   (NO a partir de `feature/adaptive-dialects`, que es una rama huérfana — ver HK1).
2. **Indentación con TAB** (`\t`), no espacios. El repo lo exige (`ruff` W191 + `indent-style = "tab"`).
3. **Gate de calidad** tras CADA finding, todo debe pasar en verde:
   ```
   .venv/bin/ruff check src tests
   .venv/bin/ruff format --check .
   .venv/bin/mypy --strict src/pure_mls/
   .venv/bin/python -m pytest tests/ -q -m "not network and not interop"
   ```
4. **Micro-commit por finding** (Checkpoint Protocol). Mensaje: `fix(audit): <ID> <resumen>`.
5. **Regresión de vectores IETF.** Antes de empezar, ejecuta y guarda el resultado de
   `.venv/bin/python -m pytest tests/test_ietf_vectors.py -q`. Varios fixes (sobre todo H2)
   pueden alterar la derivación de claves. Si un vector IETF pasa a ROJO tras un fix,
   **PARA y reporta** — no ajustes el vector ni el test para taparlo; significa que había un
   bug compensatorio.

---

# HIGH — Criptografía (bloqueantes; el proyecto NO es seguro hasta cerrarlos)

## H1 — `init_key_pub` del KeyPackage no se autentica → MITM en el Welcome

**Hallazgo.** `src/pure_mls/tree.py`, `KeyPackage.verify_signature()` (≈línea 270) solo delega
en `self.leaf_node.verify_signature()`. El `LeafNodeTBS` (`LeafNode._tbs_bytes`, ≈línea 125)
firma `encryption_key`, `signature_key`, credential, capabilities… **pero NO `init_key_pub`**.
La única firma que cubre `init_key_pub` es la de `KeyPackageTBS` (`KeyPackage._tbs_bytes`,
≈línea 276, incluye `tls_opaque(self.init_key_pub)`), que se guarda en
`KeyPackage.leaf_node_signature` (creada en `KeyPackage.create`, ≈línea 341) y **no se verifica
en ningún punto del código**. Además, en `src/pure_mls/group.py`, `add_member` (≈línea 1048)
verifica solo condicionalmente:
```python
if key_package.leaf_node_signature:
    key_package.verify_signature()  # y aun así, esto NO comprueba la firma KeyPackageTBS
```

**Por qué está mal.** Un atacante intercepta un KeyPackage válido de la víctima, sustituye
`init_key_pub` por su propia clave X25519 y reenvía. La firma del LeafNode sigue validando
(no cubre `init_key`). `add_member` sella el `GroupSecrets` (que contiene el `joiner_secret`
del epoch) hacia `init_key_pub` (HPKE seal, ver flujo de Welcome). El atacante descifra el
Welcome, obtiene el `joiner_secret` y entra en el grupo; la víctima legítima no puede unirse.
Compromiso total de la admisión. Si `leaf_node_signature` viene vacío, la verificación se
salta por completo (admite identidad no autenticada).

**Solución.**

1. En `tree.py`, `KeyPackage.verify_signature()` — verifica AMBAS firmas (asegúrate de que
   `ed25519` y `tls_varint` están importados en el módulo; `ed25519` ya se usa en
   `LeafNode.verify_signature`):
   ```python
   def verify_signature(self) -> None:
       # 1. Firma del LeafNode (liga identidad ↔ encryption_key)
       self.leaf_node.verify_signature()
       # 2. Firma de KeyPackageTBS (RFC 9420 §10.1) — la única que cubre init_key_pub
       if not self.leaf_node_signature:
           raise ValueError("KeyPackage has no signature")
       pub = ed25519.Ed25519PublicKey.from_public_bytes(self.leaf_node.signature_key)
       pub.verify(self.leaf_node_signature, self._tbs_bytes())  # lanza InvalidSignature si falla
   ```

2. En `group.py`, `add_member` (≈línea 1048) — verificación INCONDICIONAL:
   ```python
   # 2. Autenticar el KeyPackage entrante (identidad + init_key)
   key_package.verify_signature()  # lanza si falta o es inválida
   ```
   Borra el `if key_package.leaf_node_signature:` que la envolvía.

3. **Depende de L3** (el TBS firmado debe coincidir con el wire). Aplica L3 en el mismo commit
   para no romper la interop de verificación.

**Cómo testearlo.** Nuevo fichero `tests/test_keypackage_auth.py`:
```python
import pytest
from cryptography.exceptions import InvalidSignature
from pure_mls.group import MLSGroup
from pure_mls.keys import SignatureKey, KemKey

def _fresh_group_and_kp():
	alice_sig, alice_kem = SignatureKey(), KemKey()
	bob_sig, bob_kem = SignatureKey(), KemKey()
	g = MLSGroup.create(b"grupo", alice_sig, alice_kem)
	kp = MLSGroup.create_key_package(bob_sig, bob_kem)
	return g, kp

def test_add_member_rejects_tampered_init_key():
	g, kp = _fresh_group_and_kp()
	mallory = KemKey()
	kp.init_key_pub = mallory.public_bytes()  # MITM: swap init_key
	with pytest.raises((ValueError, InvalidSignature)):
		g.add_member(kp)

def test_add_member_rejects_unsigned_key_package():
	g, kp = _fresh_group_and_kp()
	kp.leaf_node_signature = b""
	with pytest.raises(ValueError):
		g.add_member(kp)

def test_add_member_accepts_valid_key_package():
	g, kp = _fresh_group_and_kp()
	new_group, welcome, commit = g.add_member(kp)  # no debe lanzar
	assert new_group.epoch_id == g.epoch_id + 1
```
> Si `MLSGroup.create_key_package` no existe con esa firma, localízala (grep `def create_key_package`)
> y ajusta la llamada. El README la usa como `MLSGroup.create_key_package(bob_sig, bob_kem)`.

---

## H2 — `KemKey.from_secret` usa el node_secret como clave privada; se salta `DeriveKeyPair` (RFC 9180)

**Hallazgo.** `src/pure_mls/keys.py`, `KemKey.from_secret` (≈línea 74):
```python
@classmethod
def from_secret(cls, secret: bytes) -> "KemKey":
    return cls.from_private_bytes(secret)   # usa el secret TAL CUAL como clave X25519
```
Se usa en `group.py` en 3 sitios (≈1096, 1324, 1478): `_kem_node = KemKey.from_secret(_node_secret)`
donde `_node_secret = _derive_path_node_key(ps)` (que sí calcula
`ExpandWithLabel(path_secret, "node", ...)` correctamente).

**Por qué está mal.** RFC 9420 §7.4 exige, tras derivar `node_secret`, obtener el par de claves
con `KEM.DeriveKeyPair(node_secret)`. Para DHKEM(X25519), RFC 9180 §7.1.2/§7.1.3:
```
dkp_prk = LabeledExtract("", "dkp_prk", node_secret)   # suite = "KEM" || 0x0020
sk      = LabeledExpand(dkp_prk, "sk", "", 32)
```
Saltarse este paso produce claves de nodo distintas a las de cualquier implementación conforme
(OpenMLS/mlspp). Los `ParentNode.public_key` y los path-secrets cifrados por HPKE no cuadran →
la interop real (que el README anuncia) está rota. Es autoconsistente solo entre instancias
pure-mls.

**Solución.** Reescribe `from_secret` usando los helpers KEM que ya existen en `HPKE`
(`_kem_extract`/`_kem_expand`, en `hpke.py`). Import LOCAL dentro del método para evitar
import circular (`hpke.py` ya importa `KemKey` de `keys.py`):
```python
@classmethod
def from_secret(cls, secret: bytes) -> "KemKey":
    """Deriva el par KEM del node_secret vía RFC 9180 §7.1.2 DeriveKeyPair, DHKEM(X25519)."""
    from pure_mls.hpke import HPKE  # import local: evita circular keys<->hpke
    dkp_prk = HPKE._kem_extract(b"", b"dkp_prk", secret)
    sk = HPKE._kem_expand(dkp_prk, b"sk", b"", 32)
    return cls.from_private_bytes(sk)
```
> No hay que "clampar" `sk`: la librería `cryptography` clampa el escalar X25519 en uso.

**Riesgo de regresión (leer).** Este cambio altera las claves de nodo. Ejecuta
`pytest tests/test_ietf_vectors.py tests/test_treekem.py -q` antes y después. Resultado esperado:
los vectores que ejercitan derivación de nodo pasan a coincidir con la RFC (deberían seguir/pasar
a verde). Si algo se pone rojo, PARA y reporta (bug compensatorio en otro sitio).

**Cómo testearlo.** KAT contra el vector IETF `crypto-basics.json` (ya en `tests/ietf_vectors/`),
que trae casos `derive_key_pair` (`ikm` → `keypair.private`/`keypair.public`). Nuevo test en
`tests/test_ietf_vectors.py` (o fichero nuevo `tests/test_derive_key_pair.py`):
```python
import json, pathlib
from pure_mls.keys import KemKey

def test_derive_key_pair_matches_ietf_crypto_basics():
	data = json.loads(pathlib.Path("tests/ietf_vectors/crypto-basics.json").read_text())
	checked = 0
	for entry in data:
		# ciphersuite 1 = MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
		if entry.get("cipher_suite") != 1:
			continue
		dkp = entry.get("derive_key_pair")
		if not dkp:
			continue
		ikm = bytes.fromhex(dkp["ikm"])
		expected_pub = bytes.fromhex(dkp["pub"] if "pub" in dkp else dkp["public"])
		assert KemKey.from_secret(ikm).public_bytes() == expected_pub
		checked += 1
	assert checked > 0, "no derive_key_pair cases for suite 1 — revisa el esquema del JSON"
```
> Abre `tests/ietf_vectors/crypto-basics.json` y confirma los nombres de campo exactos
> (`derive_key_pair`, `ikm`, `pub`/`public`) antes de dar por bueno el test; ajusta las claves.
> Test mínimo de refuerzo (siempre válido): `assert KemKey.from_secret(b"\x11"*32).private_bytes() != b"\x11"*32`.

---

## H3 — El CLI escribe las claves privadas en claro (y no usa la capa cifrada que ya existe)

**Hallazgo.** `src/pure_mls/cli.py`:
- `keygen` (≈línea 72-74): `priv_data = sig_key.private_bytes() + kem_key.private_bytes()` y lo
  escribe a `<alias>.priv` sin cifrar y sin permisos restringidos.
- `create-group`, `add-member`, `join-group`, `remove-member`, `update-key`, `apply-commit`
  (≈86, 100, 118, 131, 145, 162): todos hacen `f.write(group.to_bytes())`, y
  `MLSGroup.to_bytes()` serializa `my_sig_key.private_bytes()` + `my_kem_key.private_bytes()`
  en claro (su docstring advierte: "Do NOT store the output on disk without strong symmetric
  encryption").

Existe `src/pure_mls/storage.py::AsyncEncryptedStore` (AES-256-GCM, nonce aleatorio de 12 B,
`group_id` como AAD) — correcto y **nunca usado por el CLI**.

**Por qué está mal.** Todo el material de clave a largo plazo (identidad Ed25519, KEM X25519 y
estados de grupo con claves privadas) queda en disco en texto plano con permisos por defecto
(world-readable en hosts multiusuario). Una herramienta MLS que deja las privadas en claro no es
utilizable en producción.

**Solución.** Dos capas, mínimas y sin dependencias nuevas.

1. **Permisos restrictivos** en toda escritura de `.priv`/estado. Añade un helper en `cli.py`:
   ```python
   import os, stat

   def _write_secret(path: str, data: bytes) -> None:
       """Escribe con permisos 0600 (solo el propietario)."""
       fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
       try:
           os.write(fd, data)
       finally:
           os.close(fd)
   ```
   Sustituye TODOS los `with open(<ruta secreta>, "wb") as f: f.write(...)` que escriban
   claves/estado por `_write_secret(<ruta>, <data>)`. (Los `.pub`, `.welcome`, `.commit` NO
   son secretos → pueden seguir con `open(...)` normal.)

2. **Cifrado en reposo del estado de grupo** vía `AsyncEncryptedStore`. La clave de bóveda sale
   de una passphrase por variable de entorno `PURE_MLS_VAULT_KEY` (o, mejor, derivada de una
   passphrase). Como `AsyncEncryptedStore` es async y el CLI es síncrono, envuelve con
   `asyncio.run`. Añade en `cli.py`:
   ```python
   import asyncio, hashlib
   from pure_mls.storage import AsyncEncryptedStore

   def _vault() -> AsyncEncryptedStore:
       raw = os.environ.get("PURE_MLS_VAULT_KEY")
       if not raw:
           raise SystemExit("Falta PURE_MLS_VAULT_KEY (passphrase para cifrar el estado en disco)")
       # Deriva 32 B determinísticamente de la passphrase (placeholder; ver L7 para KDF real)
       key = hashlib.sha256(raw.encode()).digest()
       return AsyncEncryptedStore(storage_dir="./.mls-vault", vault_key=key)
   ```
   Reemplaza el guardado/carga de estado por `asyncio.run(store.save_group(group))` /
   `asyncio.run(store.load_group(group_id))`. `save_group`/`load_group` indexan por
   `group.group_id`, así que los flags `--out-state`/`group_state` basados en ruta cambian de
   semántica: pásalos a "group id" o guarda un fichero-índice alias→group_id. **Decisión de
   diseño**: si no quieres reescribir la UX del CLI ahora, implementa SOLO el punto (1)
   (permisos 0600) como mitigación obligatoria y deja (2) como issue separado, pero documenta en
   `README`/`--help` que el estado NO está cifrado y que se debe usar `AsyncEncryptedStore`
   programáticamente. **Mínimo aceptable para cerrar H3: punto (1) aplicado en todas las rutas
   de secreto.**

3. Quita el `print("... KEEP SECRET!")` engañoso o acompáñalo de "(archivo con permisos 0600)".

**Cómo testearlo.** `tests/test_cli_secrets.py`:
```python
import os, stat, subprocess, sys, pathlib

def test_keygen_priv_file_is_0600(tmp_path):
	subprocess.run([sys.executable, "-m", "pure_mls.cli", "keygen", "alice"],
	               cwd=tmp_path, check=True)
	priv = tmp_path / "alice.priv"
	assert priv.exists()
	mode = stat.S_IMODE(priv.stat().st_mode)
	assert mode == 0o600, f"esperaba 0600, es {oct(mode)}"
```
> Si implementas el cifrado (2), añade un test que confirme que el fichero de estado en
> `.mls-vault/` NO contiene los bytes crudos de la clave privada
> (`assert sig_key.private_bytes() not in disk_bytes`).

---

# HIGH — Honestidad de la suite de tests

## H4 — Tests de interop "100%" que son stubs vacíos

**Hallazgo.** `tests/test_openmls_interop.py` (≈línea 178-201):
`test_openmls_creates_pure_mls_joins` y `test_pure_mls_creates_openmls_joins` tienen solo
docstring ("P8 RESOLVED / fully integrated") y **cuerpo vacío** (pasan por `pass` implícito).
Están tras `@pytest.mark.interop` + `skipif(not HAVE_OPENMLS)`. El README anuncia interop
bidireccional "100%" apoyándose en tests que no asertan nada.

**Por qué está mal.** Un test sin aserciones que "pasa" es una afirmación falsa de cobertura.

**Solución (elige una, NO dejar el stub):**
- **(a) Implementar la interop real** contra `openmls-cli`: generar grupo/Welcome con OpenMLS,
  unir con pure-mls y comparar `epoch_authenticator`, y viceversa. Requiere instalar la CLI y
  serialización compatible (bloqueado hoy por H2). Es el objetivo, pero grande.
- **(b) Si no se implementa ya**, convertir en `pytest.skip` HONESTO con motivo:
  ```python
  @pytest.mark.interop
  def test_openmls_creates_pure_mls_joins() -> None:
      pytest.skip("Interop bidireccional en vivo no implementada (pendiente: H2 + openmls-cli)")
  ```
  y **corregir los docstrings** que dicen "RESOLVED/fully integrated" (son falsos).
- Y **actualizar el README**: cambiar "100% interop / verified E2E con OpenMLS" por lo que sí
  está respaldado: "pasa los vectores IETF de passive-client-welcome y crypto-basics offline".

**Cómo testearlo.** Meta-test que impide que un test marcado `interop` "pase" sin cuerpo:
opción simple — revisar manualmente que ya no existan funciones vacías (`grep -n "pass" tests/`
+ inspección). No añadas un test frágil de introspección; basta con que (b) deje `pytest.skip`
explícito, que aparece como SKIP (no como PASS falso).

---

## H5 — El test "PSK interop success" mockea `hmac.compare_digest → True` (anula todos los tags)

**Hallazgo.** `tests/test_psk_group_interop.py` (≈línea 38-58), "Case B: Success with correct
PSK" parchea a la vez `pure_mls.hpke.HPKE.open`, `pure_mls.group.AESGCM.decrypt`,
`pure_mls.group.RatchetTree.from_bytes` **y `pure_mls.group.hmac.compare_digest → True`**.

**Por qué está mal.** Parchear `compare_digest` a `True` desactiva la verificación de
`confirmation_tag` y `membership_tag`. Con el AEAD y el árbol también mockeados, el test no
prueba nada sobre la corrección del PSK: es una tautología disfrazada de interop.

**Solución.** Reescribir como test **end-to-end real** sin mocks de cripto: crea un grupo con
`MLSGroup.create`, añade un miembro con un PSK vía la API real de `add_member`/Welcome, y haz que
el invitado ejecute `MLSGroup.join(welcome, ..., psk_list=[(psk_id, psk_value)])` de verdad.
Asegúrate de NO parchear `compare_digest`, `HPKE.open` ni `AESGCM.decrypt`. Si la API pública
todavía no permite inyectar PSKs limpiamente en `add_member`, ese es en sí un hallazgo: abre
issue y, mientras, marca el test `xfail(strict=True, reason="API de PSK en Welcome incompleta")`
en lugar de mockear. **Prohibido** parchear `hmac.compare_digest` en cualquier test.

**Cómo testearlo.** El propio test reescrito es la verificación. Añade además el caso negativo:
```python
def test_join_rejects_wrong_psk_value():
	# ... construir welcome que requiere psk_id ...
	with pytest.raises(ValueError):
		MLSGroup.join(welcome, bob_sig, bob_kem, psk_list=[(psk_id, b"\x00"*32)])  # valor equivocado
```

---

## H6 — Tests tautológicos con docstrings que mienten sobre "cross-validation"

**Hallazgo.**
- `tests/interop/test_openmls_vectors.py` (≈150-170): `_EXPAND_CASES` calcula los valores
  "esperados" llamando a `expand_with_label(...)` (la función bajo test) en tiempo de import, y
  luego `test_keyschedule_expand_with_label_determinism` compara `expand_with_label` contra eso.
  El docstring afirma "computed offline ... commit d3f7a2b ... cross-validated against OpenMLS":
  falso, no interviene nada externo.
- `tests/test_rfc9420_vectors.py` (≈50-66): `test_pure_mls_expand_with_label_parity` dice
  comparar la interna `_expand_with_label` contra una referencia, pero reconstruye el label a
  mano, llama a `hkdf_expand` y solo asserta `len(...)==length` e `isinstance(bytes)`. No compara
  nada; no llama a `expand_with_label`.

**Por qué está mal.** No pueden fallar ante una implementación determinista-pero-incorrecta.
El docstring anuncia una garantía (cross-validation con la referencia) que no existe.

**Solución.**
1. **Corregir los docstrings** para que digan la verdad (son tests de determinismo/longitud, no
   de known-answer) — o, mejor,
2. **Convertirlos en KAT reales** usando los vectores IETF ya presentes:
   `tests/ietf_vectors/key-schedule.json` y `crypto-basics.json` contienen entradas
   `expand_with_label`/`derive_secret` con `secret`/`label`/`context`/`length` → `out`. Sustituye
   el "expected" auto-calculado por `bytes.fromhex(vector["out"])`.
   ```python
   def test_expand_with_label_kat_from_ietf():
       import json, pathlib
       data = json.loads(pathlib.Path("tests/ietf_vectors/crypto-basics.json").read_text())
       checked = 0
       for e in data:
           if e.get("cipher_suite") != 1: continue
           for c in e.get("expand_with_label", []) if isinstance(e.get("expand_with_label"), list) else [e.get("expand_with_label")]:
               if not c: continue
               out = expand_with_label(bytes.fromhex(c["secret"]), c["label"],
                                       bytes.fromhex(c["context"]), c["length"])
               assert out == bytes.fromhex(c["out"]); checked += 1
       assert checked > 0
   ```
   > Ajusta nombres de campo tras inspeccionar el JSON real.
3. Elimina el `_EXPAND_CASES` auto-referencial y su docstring falso.

**Cómo testearlo.** El KAT del punto (2) es la verificación. Debe fallar si alteras un byte del
label en `expand_with_label` (pruébalo manualmente).

---

# MEDIUM — Corrección / seguridad

## M1 — `join()` no valida el `tree_hash` contra el árbol recibido

**Hallazgo.** `group.py`, `join()` (≈1648-1708): tras obtener `tree` (de la extensión
`ratchet_tree` o del parámetro `ratchet_tree=`), nunca comprueba
`tree.tree_hash() == gi_ctx.tree_hash`. El `confirmation_tag` (≈1706) se calcula sobre
`gi_ctx.confirmed_transcript_hash` (el hash *firmado*), no sobre un hash recomputado del árbol.

**Por qué está mal.** RFC 9420 §12.4.3.1: el joiner DEBE verificar que el árbol recibido produce
el `tree_hash` firmado en el GroupContext. Sin ello, un atacante que pase un árbol out-of-band
(parámetro `ratchet_tree=`) con la clave de firma del committer real en `2*gi.signer` (para que
`gi.verify` pase) pero con hojas forjadas/extra corrompe la vista del joiner sin detección.

**Solución.** En `join()`, justo después de resolver `tree` y ANTES de usarlo (tras el bloque que
lo obtiene, ≈línea 1666), añade:
```python
# RFC 9420 §12.4.3.1: el árbol recibido debe casar con el tree_hash firmado
if not hmac.compare_digest(tree.tree_hash(), gi_ctx.tree_hash):
    raise ValueError("ratchet_tree no coincide con el tree_hash firmado en GroupInfo (árbol substituido)")
```
> `hmac` ya está importado en `group.py`. Confirma que `GroupContext` expone `.tree_hash`
> (grep `tree_hash` en la definición de `GroupContext`/`_make_group_context`); si el campo tiene
> otro nombre, úsalo.

**Cómo testearlo.** `tests/test_join_validation.py`:
```python
def test_join_rejects_tampered_tree(...):
	# 1. Alice crea grupo y añade a Bob → welcome
	# 2. Construye un RatchetTree manipulado (añade una hoja fantasma) pero conserva
	#    la signature_key real del committer en 2*signer
	# 3. MLSGroup.join(welcome, bob_sig, bob_kem, ratchet_tree=tampered)
	with pytest.raises(ValueError, match="tree_hash"):
		MLSGroup.join(welcome_bytes, bob_sig, bob_kem, ratchet_tree=tampered_tree)
```

---

## M2 — `add_member` no reutiliza hojas vacías y no actualiza el direct-path de la nueva hoja

**Hallazgo.** `group.py`, `add_member` (≈1030-1044, 1094-1104): siempre coloca al nuevo miembro
en `(new_num_leaves-1)*2` (append a la derecha), nunca reutiliza hojas dejadas en blanco por
`remove_member`. Y solo recomputa el direct-path del **committer** (≈1099-1104); los nodos padre
del direct-path de la **nueva hoja** que no comparte con el committer se copian tal cual del árbol
viejo.

**Por qué está mal.** (a) RFC §7.7: hay que reutilizar la hoja en blanco más a la izquierda; sin
ello el árbol crece sin límite en ciclos remove/add. (b) Los nodos padre obsoletos llevan claves
públicas cuya privada no tiene ningún miembro por debajo → con ≥3 miembros, si luego commitea un
miembro que no es el creador, el cifrado TreeKEM a esa resolución es indescifrable. Pasa
desapercibido porque en los tests el creador (hoja 0, cuyo direct-path es toda la espina) suele
ser siempre el committer.

**Solución.**
1. **Reutilizar hoja en blanco** en vez de siempre extender:
   ```python
   # Buscar la hoja en blanco más a la izquierda; si no hay, extender el árbol
   blank_leaf = None
   for li in range(self.state.tree.num_leaves):
       if self.state.tree.get_node(2 * li) is None:
           blank_leaf = li
           break
   if blank_leaf is None:
       new_num_leaves = self.state.tree.num_leaves + 1
       new_leaf_idx = (new_num_leaves - 1) * 2
   else:
       new_num_leaves = self.state.tree.num_leaves
       new_leaf_idx = 2 * blank_leaf
   new_tree = RatchetTree(num_leaves=new_num_leaves)
   # ... copiar nodos existentes ...
   new_tree.set_leaf(new_leaf_idx, key_package.leaf_node)
   ```
2. **Blanquear el direct-path de la nueva hoja** (RFC §7.7: al añadir, los nodos intermedios del
   camino de la nueva hoja se ponen en blanco excepto los que el committer va a repoblar). Tras
   insertar la hoja y antes de recomputar el path del committer:
   ```python
   for anc in new_tree.direct_path(new_leaf_idx):
       new_tree.set_parent(anc, None)  # blank; el UpdatePath del committer los repuebla
   ```
3. **(Relacionado con M5)** añadir la nueva hoja a `unmerged_leaves` de sus ancestros que el
   committer NO actualice en este commit (RFC §7.6). Ver M5 para el tipo (índice de hoja).

> Este finding es el más delicado del plan. Si no tienes seguridad total, aplica al menos (2)
> (blanqueo del path de la nueva hoja), que es lo que causa el fallo criptográfico, y abre issue
> para (1) y (3). Verifica SIEMPRE con el test de abajo.

**Cómo testearlo.** `tests/test_add_member_tree.py` — el escenario que hoy no se cubre (committer
≠ creador):
```python
def test_third_member_commit_decryptable_by_all():
	# Alice crea; añade Bob; añade Carol (grupo de 3)
	# Bob (NO el creador) hace update_key() → commit
	# Alice y Carol aplican el commit y las tres derivan la MISMA application_key
	assert alice.application_key == bob.application_key == carol.application_key

def test_remove_then_add_reuses_blank_leaf():
	# grupo de 3, remove hoja 1, luego add nuevo miembro
	# el nuevo debe ocupar la hoja 1 (reutilizada), num_leaves no crece
	assert new_group.state.tree.num_leaves == 3
```

---

## M3 — Confusión leaf-index vs node-index en el fallback legacy de `add_member`

**Hallazgo.** `group.py` (≈1129-1134):
```python
for i, node in enumerate(new_tree.nodes):
    if isinstance(node, LeafNode) and i != self.my_index:   # i es node-index; my_index es leaf-index
```
Los métodos hermanos lo hacen bien: `remove_member` usa `leaf_idx == 2 * self.my_index` (≈1355)
y `update_key` usa `leaf_idx == my_node_idx` (≈1506).

**Por qué está mal.** Compara un node-index par (0,2,4,…) contra un leaf-index. Para un committer
en hoja `m>0`, el miembro en hoja `m/2` queda mal excluido y el committer se sella el
`commit_secret` a sí mismo. Hoy está enmascarado porque `process_update` prefiere la ruta TreeKEM,
pero el fallback está roto.

**Solución.**
```python
for i, node in enumerate(new_tree.nodes):
    if isinstance(node, LeafNode) and i != 2 * self.my_index:
        ...
```

**Cómo testearlo.** Difícil de aislar sin ejercitar el fallback. Test de propiedad: en un grupo
de ≥2 donde el committer NO es la hoja 0, tras un commit todos los miembros comparten
`application_key` (lo cubre el `test_third_member_commit_decryptable_by_all` de M2). Añade además
un test unitario que verifique que `encrypted_secrets` contiene una entrada por cada miembro
distinto del committer:
```python
def test_fallback_encrypts_to_all_other_members():
	# committer en hoja 1 de un grupo de 3; inspeccionar el GroupUpdate.encrypted_commit_secrets
	assert len(update.encrypted_commit_secrets) == 2  # los otros 2 miembros
```

---

## M4 — `process_update` no valida firmas de LeafNode ni parent-hashes del UpdatePath recibido

**Hallazgo.** `group.py`, `process_update` (≈1724-1839): la firma del commit autentica que el
committer envió ese árbol, pero no se validan las firmas de los LeafNode nuevos/actualizados ni la
consistencia de parent_hash a lo largo del UpdatePath (RFC §12.4.2).

**Por qué está mal.** Un committer malicioso o con bug puede meter un árbol malformado (hojas con
claves de identidad no autenticadas, parent_hashes incoherentes) y se acepta mientras la firma
externa y los tags cuadren. Debilita la garantía de que cada hoja del grupo está autenticada.

**Solución.** En `process_update`, tras parsear `update.tree` y antes de aceptar el nuevo estado:
1. Verificar la firma de cada `LeafNode` no nulo del árbol:
   ```python
   for li in range(update.tree.num_leaves):
       ln = update.tree.get_node(2 * li)
       if ln is not None:
           ln.verify_signature(group_id=self.group_id, leaf_index=li)
   ```
   > `LeafNode.verify_signature(group_id, leaf_index)` ya existe (tree.py ≈158). Para hojas de
   > tipo COMMIT/UPDATE el TBS incluye group_id+leaf_index; asegúrate de pasar los correctos.
2. Verificar parent_hash del `leaf_key_package` del UpdatePath contra el árbol (RFC §7.9). Si la
   verificación completa de la cadena es demasiado para este pase, implementa al menos (1) —
   autenticación de identidades— y abre issue para la cadena de parent_hash.

**Cómo testearlo.**
```python
def test_process_update_rejects_forged_leaf_signature():
	# committer construye un commit válido; manipular la signature de una LeafNode del árbol
	# antes de que el receptor llame a process_update/apply_commit
	with pytest.raises((ValueError, InvalidSignature)):
		receiver.apply_commit(tampered_commit)
```

---

## M5 — `resolution()` mete leaf-indices donde van node-indices para hojas no fusionadas

**Hallazgo.** `tree.py`, `resolution()` (≈685): `return [index] + list(unmerged)` donde
`unmerged = node.unmerged_leaves`. Los `unmerged_leaves` se almacenan como **índices de hoja**
(por §7.6/wire), pero una resolución es una lista de **índices de nodo**.

**Por qué está mal.** Al parsear un ratchet-tree conforme (Welcome con `unmerged_leaves`
poblado), `add_member`/`process_update` iteran `resolution(cop_idx)` y llaman
`tree.get_node(res_idx)` con índices erróneos → HPKE sellado al nodo equivocado o a un blank; los
miembros afectados no descifran. Latente hoy porque `add_member` no puebla `unmerged_leaves`
(parte de M2), pero salta con árboles externos.

**Solución.** Convertir leaf-index → node-index (`2 * leaf`):
```python
unmerged = node.unmerged_leaves if isinstance(node, ParentNode) else []
return [index] + [2 * leaf for leaf in unmerged]
```

**Cómo testearlo.**
```python
def test_resolution_maps_unmerged_leaves_to_node_indices():
	tree = RatchetTree(num_leaves=4)
	# poblar hojas y un ParentNode con unmerged_leaves=[3] (hoja 3 → nodo 6)
	res = tree.resolution(<idx_parent>)
	assert 6 in res and 3 not in res
```

---

## M6 — `secret_tree._parent` ignora `n_leaves` → rutas erróneas en grupos no potencia-de-2

**Hallazgo.** `secret_tree.py`, `_parent(index, _n_leaves)` (≈53-58) es un paso de padre puro que
**no usa `_n_leaves`** ni reparenta (a diferencia de `tree.py::_parent`, que sí tiene el bucle de
reparent). `_get_path` (≈61) lo usa para bajar de la raíz a la hoja.

**Por qué está mal.** Para `n_leaves` no potencia de 2 (3,5,6,7…) el camino pasa por nodos
fantasma. Ej. n=3, hoja 2 (nodo 4): direct-path real `[3]` (1 salto), pero produce
`["right","left"]` (2 saltos vía nodo fantasma 5). Cada hoja deriva su `encryption_secret` por el
camino equivocado → claves/nonces distintos a los de un peer conforme. Autoconsistente solo entre
instancias pure-mls. Tests verdes porque solo prueban tamaños 1/2/4.

**Solución.** Alinear `_parent` con el de `tree.py` (reparent hasta que el nodo esté dentro del
árbol de `n_leaves`). Reutiliza la lógica ya correcta de `tree.py`:
```python
def _parent(index: int, n_leaves: int) -> int:
    """Padre de un nodo, con reparent para árboles no completos (RFC App. C)."""
    if index == _root(n_leaves):
        raise ValueError("root has no parent")
    width = 2 * n_leaves - 1
    k = _level(index)
    while True:
        b = (index >> (k + 1)) & 0x01
        p = (index | (1 << k)) ^ (b << (k + 1))
        if p < width:
            return p
        k += 1
```
> Compara con `tree.py::_parent` y copia su algoritmo exacto para no divergir. Ejecuta los tests
> de `test_tree_math.py` para confirmar paridad.

**Cómo testearlo.** `tests/test_secret_tree_paths.py`:
```python
import pytest
@pytest.mark.parametrize("n_leaves,leaf,expected_len", [(3,2,1),(3,0,2),(5,4,1),(6,4,2)])
def test_get_path_length_non_power_of_two(n_leaves, leaf, expected_len):
	from pure_mls.secret_tree import _get_path
	assert len(_get_path(leaf, n_leaves)) == expected_len
```
> Calcula los `expected_len` a mano con el árbol izquierdo-balanceado de RFC App. C antes de
> fijarlos. Idealmente, añade un KAT contra `tests/ietf_vectors/secret-tree.json` para un grupo
> de tamaño no potencia-de-2 si el vector lo incluye.

---

## M7 — Readers de `tls.py` sin bounds-check → truncado silencioso

**Hallazgo.** `tls.py`: `read_opaque16` (≈101), `read_opaque32` (≈108), `read_vector16` (≈171),
`read_vector32` (≈178), `read_vec8` (≈210) y `_parse_extensions_internal` (≈197) hacen
`buf[offset:offset+length]` **sin** comprobar `offset+length <= len(buf)`. `read_opaque` (≈89) sí
lo comprueba (patrón a replicar).

**Por qué está mal.** El slicing de Python devuelve datos cortos en silencio en vez de lanzar. Un
mensaje truncado/malformado "parsea con éxito" con un campo silenciosamente acortado, saltándose
validación aguas abajo. (No es DoS de asignación gigante — el slice se limita al buffer.)

**Solución.** Añade la comprobación en cada reader (mismo estilo que `read_opaque`). Ejemplo para
`read_opaque16`:
```python
def read_opaque16(buf: bytes, offset: int) -> tuple[bytes, int]:
    (length,) = struct.unpack_from(">H", buf, offset)
    offset += 2
    if offset + length > len(buf):
        raise ValueError(f"opaque16 length {length} excede buffer (offset {offset}, len {len(buf)})")
    return buf[offset : offset + length], offset + length
```
Replica en `read_opaque32`, `read_vector16`, `read_vector32`, `read_vec8`. En
`_parse_extensions_internal`, valida `i + 4 + elen <= len(data)` dentro del bucle y lanza si no.

**Cómo testearlo.** `tests/test_wire_bounds.py`:
```python
import pytest
from pure_mls.tls import read_opaque16, read_vector16, read_vec8
@pytest.mark.parametrize("reader", [read_opaque16, read_vector16, read_vec8])
def test_reader_rejects_truncated(reader):
	# prefijo declara 100 bytes pero el buffer solo tiene 2
	buf = (100).to_bytes(2, "big") + b"\x00\x00"  # ajustar tamaño de prefijo por reader
	with pytest.raises(ValueError):
		reader(buf, 0)
```
> `read_vec8` usa prefijo de 1 byte: `buf = bytes([100]) + b"\x00"`.

---

## M8 — Secretos expuestos por el `__repr__` por defecto de dataclasses

**Hallazgo.** `keyschedule.py` `KeySchedule` (≈101), `secret_tree.py` `SecretTree` (≈80),
`epoch.py` `EpochState` (≈8) son dataclasses sin `repr=False` ni `__repr__` propio. `repr(ks)`
imprime los 11 secretos (joiner_secret, epoch_secret, init_secret, membership_key, …);
`EpochState` los expone transitivamente.

**Por qué está mal.** Cualquier log, traceback o depurador que serialice estos objetos filtra
material de clave en claro.

**Solución.** Añade `__repr__` que no revele secretos. Opción mínima por clase:
```python
def __repr__(self) -> str:
    return f"<KeySchedule epoch-secrets redacted>"
```
Hazlo en `KeySchedule`, `SecretTree` y `EpochState`. Para `@dataclass(frozen=True)` (EpochState),
definir `__repr__` es compatible (no choca con frozen).

**Cómo testearlo.**
```python
def test_keyschedule_repr_redacts_secrets():
	ks = ...  # una KeySchedule real
	r = repr(ks)
	assert ks.joiner_secret.hex() not in r
	assert "redacted" in r
```
Repite para SecretTree y EpochState.

---

## M9 — Selección de dialecto no autenticada + fallback silencioso

**Hallazgo.** `codecs.py`, `detect_dialect` (≈216) elige la estrategia por "magic bytes"
controlables por el atacante, con **fallback silencioso a "standard"** si no detecta. `group.py`,
`Welcome.from_bytes` (≈239) llama a `detect_dialect(data)` y el dialecto decide `welcome_label()`,
usado como `info` de HPKE al descifrar (≈292-295). Nada firma ni liga el dialecto elegido.

**Por qué está mal.** Un atacante antepone una cabecera de dialecto para alterar el parsing/label
sin ningún check de integridad sobre esa selección. Mitigación real: un `welcome_label` mal
elegido hace fallar el HPKE/AES-GCM `open` (fail-closed), así que es más superficie de
parsing/DoS que downgrade de clave probado — pero (selección no autenticada) + (fallback
silencioso) + (decoders por dialecto sin bounds-check uniforme, ver L9) es superficie a cerrar.

**Solución.** Dado que los dialectos Cisco/mlspp son ficticios (ver L-Nota) y no aportan interop
real, la opción más segura es **restringir el default a `standard` y exigir dialecto explícito**
para cualquier otro:
1. En `Welcome.from_bytes`, cuando `dialect is None`, **no** auto-detectar: usar `standard`
   directamente. Permitir dialecto no estándar SOLO si el llamante lo pasa explícito
   (`dialect="cisco"`), nunca por magic bytes de datos no confiables.
   ```python
   if dialect is None:
       strategy = get_dialect("standard")   # sin auto-deteccion sobre input no confiable
       dialect_name = "standard"
   else:
       strategy = get_dialect(dialect)
       dialect_name = dialect
   ```
2. Si se quiere conservar `detect_dialect` para uso interno/tests, que el fallback **lance** en
   vez de degradar silenciosamente cuando reciba un header desconocido no vacío.

**Cómo testearlo.**
```python
def test_welcome_from_bytes_ignores_untrusted_dialect_header():
	# datos con magic byte de "cisco" antepuesto → debe parsear como standard (o lanzar),
	# NO seleccionar cisco por el header
	w = Welcome.from_bytes(cisco_prefixed_bytes)
	assert w.dialect == "standard"
```

---

# LOW — Robustez / higiene / interop-fino

## L1 — `dh_exchange` lanza `InvalidSignature` para un error de KEM
`keys.py` (≈90): usa el tipo de excepción de firma para un fallo de clave pública KEM. Cambia a
`ValueError` (o define `KemError(ValueError)`). Test: `pytest.raises(ValueError)` al pasar bytes
KEM malformados a `dh_exchange`.

## L2 — `decrypt_application_message` no protege el `struct.unpack` ni acota `sender_leaf`
`group.py` (≈1897): `struct.unpack(">I", sd_plaintext)` lanza `struct.error` no capturado si el
plaintext no mide 4 bytes; `sender_leaf` va al SecretTree sin bounds-check. Solución: validar
`len(sd_plaintext) == 4` (lanzar `ValueError` si no) y `0 <= sender_leaf < tree.num_leaves`. Test:
mensaje con sender-data de longitud incorrecta → `ValueError`, no `struct.error`.

## L3 — El TBS del KeyPackage usa `tls_u32(0)` mientras el wire usa `tls_varint(0)`
`tree.py`: `_tbs_bytes` (≈283) añade `tls_u32(0)` (4 B) y hardcodea extensiones vacías, pero
`to_bytes` (≈296) emite `tls_varint(0)` (1 B). Los bytes firmados no coinciden con el wire →
rompe verificación interop y el check de H1 frente a otras impls. Solución: en `_tbs_bytes`,
`+ tls_varint(0)` (y, si hay extensiones reales, serializarlas igual que `to_bytes`). **Aplicar
junto con H1.** Test: `assert kp._tbs_bytes()` reconstruible desde `kp.to_bytes()` (mismos bytes
de la sección init_key+leaf+extensions).

## L4 — `tls_varint` acepta la forma de 8 bytes que RFC 9420 prohíbe; inconsistente con `hkdf.varint_encode`
`tls.py` (`tls_varint` ≈158, `_varint_decode` ≈124) emite/acepta la 4ª forma (`0b11`, 8 B, 62-bit)
que RFC 9420 §2.1.2 marca inválida; `hkdf.varint_encode` corta a 30 bits y lanza. Solución
recomendada: unificar en el rango RFC (hasta 4 bytes / 30 bits) y hacer que `_varint_decode` lance
`ValueError` si `prefix == 3`. Revisa que ningún caller legítimo use >2^30. Test: `_varint_decode`
de un prefijo con top-bits `11` → `ValueError`; round-trip `tls_varint`/`_varint_decode` en los
bordes 0x3F, 0x3FFF, 0x3FFFFFFF.

## L5 — El GroupContext "viejo" pone `interim_transcript_hash` en el slot de `confirmed_transcript_hash`
`group.py` (≈1161, 1386, 1534, 1745, 1790): `_make_group_context(..., self.interim_transcript_hash)`
coloca el hash interim donde la RFC §8.1 espera el confirmed. Es internamente consistente
(emisor y receptor hacen lo mismo) pero es desviación semántica no comentada que rompería interop
con impls conformes. Solución: si se prioriza interop, revisar el flujo de transcript-hash para
usar el confirmed en el slot correcto (cambio delicado, coordinar con M1/M4). **Si no se aborda
ahora**, añade un comentario `# DEVIATION (RFC §8.1): ...` explícito en cada sitio y abre issue.
Test: cubierto indirectamente por los vectores IETF de key-schedule si se corrige.

## L6 — `GroupInfo.verify()` documenta `-> bool` pero lanza/solo devuelve True
`group.py` (≈413-430). Solución: o cambiar la firma a `-> None` (y ajustar el caller ≈1674, que ya
lo envuelve en try/except) o hacer que devuelva `bool` de verdad sin lanzar. Preferible `-> None`
+ excepción (coherente con el resto). Test: firma inválida → excepción; firma válida → no lanza.

## L7 — `storage.py`: sin permisos restrictivos y `vault_key` sin KDF
`storage.py` (≈27, 52): `os.makedirs`/escritura con umask por defecto (blobs cifrados
world-readable) y `vault_key` usado crudo sin estiramiento. Solución: `os.makedirs(dir,
mode=0o700, exist_ok=True)` + `os.chmod`; escribir el fichero con 0600 (mismo helper `_write_secret`
que H3); y documentar/derivar la vault_key con un KDF (p.ej. `hashlib.scrypt` o
PBKDF2-HMAC-SHA256 con salt persistido) en vez de usar la passphrase cruda. Test: fichero `.mls`
creado con modo 0600; directorio 0700.

## L8 — `from_private_bytes` trunca 64→32 en silencio, sin validar longitud
`keys.py` (≈34-35) y su uso en `cli.py` (≈82-83, 111-112). Solución: aceptar solo 32 (o 64
expandida documentada) y lanzar `ValueError` en cualquier otra longitud, en `SignatureKey` y en el
slicing del CLI (validar que `len(pd) >= 64`). Test: `.priv` de longitud inesperada → `ValueError`.

## L9 — Decoders de dialecto sin bounds-check
`codecs.py`: `CiscoStrategy.decode_vector` (≈142-146) y `MlsppStrategy.decode_vector` (≈185-189)
hacen `buf[offset:end]` sin comprobar (a diferencia de `StandardStrategy.decode_vector` ≈90-91).
Solución: añadir el mismo bounds-check que `StandardStrategy`. Test: análogo a M7 sobre cada
estrategia. (Si M9 elimina el uso de dialectos no estándar sobre input no confiable, esto baja de
prioridad pero conviene arreglarlo igual.)

## L10 — `register_dialect` contamina un `_REGISTRY` global entre tests
`codecs.py` (≈204-206) + `tests/test_dialects.py` (≈110-111): `test_custom_dialect_plugin`
registra `custom_test` globalmente y no lo desregistra. Solución: en el test, usar una fixture con
teardown que haga `_REGISTRY.pop("custom_test", None)`, o exponer `unregister_dialect`. Test: la
propia fixture; añade un test que verifique que tras el test el registro no contiene `custom_test`.

## L-Nota — Comentario incorrecto (pero comportamiento correcto) en `secret_tree.py`
`secret_tree.py` (≈106-107): el comentario afirma que la RFC usa "label=direction, context=b''" y
que el código se desvía por paridad con OpenMLS; en realidad el código (`label="tree"`,
`context=b"left"/b"right"`) **sí** cumple RFC 9420 §9. Solución: corregir el comentario para que
no induzca a error. Sin cambio de código. Sin test.

---

# Cobertura de tests a añadir (gaps de seguridad)

Muchos ya quedan cubiertos por los tests de los findings anteriores. Los que faltan explícitamente:

## T1 — Removed-member-cannot-decrypt (afirmado en docstring, nunca testeado)
`tests/test_remove_member.py`: el `_group_b` se crea y se deja sin usar (`# noqa: F841`). Añade:
```python
def test_removed_member_cannot_decrypt_new_messages():
	# grupo de 2 (Alice, Bob); Alice remove a Bob; Alice cifra un mensaje en el nuevo epoch
	# Bob (estado viejo) NO debe poder descifrar; las application_key divergen
	assert alice_new.application_key != bob_old.application_key
	with pytest.raises((ValueError, InvalidTag)):
		bob_old.decrypt_application_message(ciphertext)
```

## T2 — Replay intra-grupo de epoch antiguo (hoy `test_wrong_epoch_rejected` prueba otra cosa)
`tests/test_treekem.py` (≈177): el test actual descifra con un grupo de `group_id` distinto, no un
replay real. Añade: cifra un mensaje en epoch N, avanza el grupo a N+1, e intenta descifrar el
ciphertext viejo en el epoch nuevo → debe fallar.

## T3 — Commit manipulado en el cable
Serializa un Commit válido (`MLSMessage.wrap_commit`), voltea un byte, y asserta que
`apply_commit`/`process_update` lo rechaza (membership_tag/confirmation_tag). Complementa M4.

## T4 — Firma forjada: estrechar los `pytest.raises` demasiado amplios
`tests/test_group_errors.py` (≈111-192) usa `match="A|B|C|D"` que dejan pasar cualquier
`ValueError`. Además, el caso de `update.signature=b"badsig"` (≈114) construye el update con
`epoch_id == group.epoch_id` (no +1), así que falla en el guard "Out of order update" **antes** de
llegar a la verificación de firma. Solución: construir el update con `epoch_id` correcto y
`match=` exacto ("Commit Forgery" o el mensaje real de la verificación de firma), para probar que
salta el check de firma y no otro.

## T5 — PSK equivocado / Welcome a destinatario incorrecto
Cubierto parcialmente por H5. Añade además: Welcome descifrado con la KEM key del destinatario
equivocado → `ValueError("No EncryptedGroupSecrets could be decrypted...")` (group.py ≈1611).

## T6 — Decoding malformado / fuzz
Cubierto por M7/L9. Añade un test parametrizado que trunque a distintas longitudes los bytes de un
Welcome/KeyPackage/Commit reales y asserta que `from_bytes` lanza `ValueError` (no `IndexError`,
`struct.error` ni truncado silencioso).

## T7 — `test_vector_keyschedule.py` xfail(strict=False)
`tests/test_vector_keyschedule.py` (≈8-13): el vector real de key-schedule epoch-0 está en
`xfail(strict=False)` (pasa o falla en silencio). Solución: si el motivo (psk_secret precomputado
no descomponible) sigue vigente, cambia a `strict=True` para que un "unexpected pass" avise; si se
puede alimentar el joiner_secret dado (como hace `test_ietf_vectors.py`), reescríbelo como test que
pasa de verdad y quita el xfail.

---

# Housekeeping del repositorio

## HK1 — HEAD en rama huérfana `feature/adaptive-dialects`
`feature/adaptive-dialects` no comparte ancestro con `main` (`git merge-base main HEAD` → vacío).
El diff real contra `main` es pequeño (5 ficheros: `codecs.py`, `group.py`, `test_dialects.py`,
`docs/CERTIFICATION/CLAUDE_PROMPT.md`, `uv.lock`; +422/−59). **Acción:** reconstruir ese cambio
como rama normal sobre `main`:
```
git checkout main
git checkout -b feature/adaptive-dialects-rebased
git checkout feature/adaptive-dialects -- src/pure_mls/codecs.py src/pure_mls/group.py tests/test_dialects.py docs/CERTIFICATION/CLAUDE_PROMPT.md uv.lock
git commit -m "feat(core): adaptive dialects + codec plugin system (re-anclado sobre main)"
```
Luego trabaja la remediación sobre `main` (rama `fix/audit-remediation`). Antes de fusionar los
dialectos, aplica M9/L9 (dialecto no autenticado). **No** hacer push sin orden explícita del
operador (Git Golden Rule).

## HK2 — Submódulo `3rdparty/openmls` roto (gitlink sin `.gitmodules`)
`3rdparty/openmls` está como gitlink (`160000 commit e85d773…`) pero no hay `.gitmodules`
(`git submodule status` lanza `fatal: no submodule mapping found`). Un clone fresco se queda sin
ese directorio. **Acción (elige):**
- (a) Si openmls debe ser submódulo: crear `.gitmodules` con la URL correcta:
  ```
  git submodule add https://github.com/openmls/openmls 3rdparty/openmls
  ```
  y fijar el commit `e85d773…`.
- (b) Si no se necesita vendorizado: `git rm --cached 3rdparty/openmls` y añadir `3rdparty/` a
  `.gitignore` (documentando cómo obtener openmls para los tests interop).
Recomendado (b) salvo que los tests interop dependan del checkout exacto.

## HK3 — README falso: "zero-dependency / no compiled bindings" + mapa de arquitectura incompleto
`README.md`: dice "zero-dependency, no compiled bindings (no Rust, C++ or FFI)" pero
`pyproject.toml` depende de `cryptography>=46` (bindings Rust) para Ed25519/X25519/AES-GCM. Y el
mapa de arquitectura no lista `secret_tree.py`, `codecs.py`, `cli.py`, `storage.py`, `crypto.py`.
**Acción:** reescribir el claim a algo cierto ("pure-Python protocol logic; crypto primitives via
the `cryptography` library") y completar el mapa. Alinear también los claims de interop (ver H4).

---

# Orden de ejecución recomendado

1. **H1 + L3** (mismo commit) — MITM del init_key.
2. **H2** — DeriveKeyPair (¡vigilar regresión de vectores IETF!).
3. **H3 (punto 1: permisos 0600)** — claves en disco.
4. **M1, M5, M6, M7, M8** — corrección/robustez de bajo acoplamiento.
5. **M3** — fix de una línea del fallback.
6. **M2, M4** — los delicados de árbol; verifica con los tests de M2.
7. **M9 + L9** — dialecto no autenticado.
8. **H4, H5, H6 + T1–T7** — honestidad y cobertura de tests.
9. **L1, L2, L4, L6, L7, L8, L10, L-Nota** — higiene.
10. **HK1–HK3** — housekeeping (HK1 primero si vas a fusionar dialectos).

Tras cada bloque: gate de calidad completo + micro-commit. No hacer push sin orden del operador.
