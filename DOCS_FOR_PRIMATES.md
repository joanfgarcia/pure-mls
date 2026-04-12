# DOCS_FOR_PRIMATES.md  
**Guía del Mono Sobreviviendo a pure-mls**  
*(o cómo cifrar chats grupales como un señor sin vender tu alma al servidor)*

### Bienvenido, primate.

Has llegado aquí porque estás harto de que:
- Signal te limite los grupos a 1000 monos como mucho.
- WhatsApp/Telegram lean todo lo que escribes (aunque digan que no).
- Cualquier app “segura” dependa de un servidor que puede ser hackeado, obligado por ley o simplemente vendido mañana.

**pure-mls** es una librería escrita en Python puro que implementa **MLS** (Messaging Layer Security), el protocolo que usan los que van en serio con la encriptación de grupos grandes.

En cristiano:  
Es como Signal, pero pensado para **grupos grandes** (miles de monos) y para que **nadie** (ni el servidor, ni el dueño de la app, ni un gobierno) pueda leer tus mensajes aunque quiera.

### ¿Por qué cojones usar esto en vez de Signal o WhatsApp?

Imagina que sois 50 monos en un grupo de Telegram.  
Con Signal/WhatsApp clásico: cada vez que alguien escribe, tiene que cifrar el mensaje **49 veces** (una por cada mono).  
Eso es lento, gasta batería y cuando el grupo crece a 5000… se muere.

MLS usa un truco matemático llamado **TreeKEM** (un árbol binario de llaves).  
Resultado: cifrar un mensaje cuesta casi lo mismo con 10 monos que con 10.000.  
Además, si a un mono le roban el móvil (compromiso), el grupo se “cura” solo cuando alguien hace un commit. Magia negra criptográfica.

Y lo mejor: **el servidor es tonto**. Solo ve bytes cifrados. No sabe ni quién habla con quién de verdad. Zero knowledge total.

### ¿Qué pinta tiene usar pure-mls? (ejemplo para monos)

```python
from pure_mls.group import MLSGroup
from pure_mls.keys import SignatureKey, KemKey

# Cada mono genera sus llaves privadas (como DNI criptográfico)
alice_sig, alice_kem = SignatureKey(), KemKey()
bob_sig, bob_kem = SignatureKey(), KemKey()

# Alice crea el grupo soberano
grupo = MLSGroup.create(b"los-primates-rebeldes", alice_sig, alice_kem)

# Alice invita a Bob (manda un Welcome por donde sea: WebSocket, MQTT, carrier pigeon...)
bob_kp = MLSGroup.create_key_package(bob_sig, bob_kem)
grupo_nuevo, welcome, update = grupo.add_member(bob_kp)

# Bob se une
grupo_bob = MLSGroup.join(welcome, bob_sig, bob_kem)

# Ahora los dos tienen la misma llave mágica
mensaje = b"Hola primates, hoy robamos bananas"
cifrado = grupo_nuevo.encrypt_application_message(mensaje)
print(grupo_bob.decrypt_application_message(cifrado))   # → b"Hola primates..."
```

Funciona. De verdad. Y puedes tirarlo por WebSocket, MQTT, WebRTC o lo que te dé la gana. El servidor solo ve mierda cifrada.

### ¿Qué significa "soberano" aquí?

- No hay llaves maestras escondidas.
- No hay backdoors (que sepamos, y el código está abierto para que lo mires).
- Si un gobierno te pide las llaves → le enseñas el código y le dices “no las tengo, están en el móvil del usuario”.
- Plausible deniability máxima.

Es el equivalente criptográfico a “yo solo fabrico la caja fuerte, lo que guardes dentro es tu problema”.

### Advertencias de primate responsable

- Es más complicado que Signal. Porque hace cosas más potentes.
- Todavía está en modo “ingeniero cabrón” (la API es limpia pero no es un `pip install chat-seguro` de un clic).
- Si solo quieres chatear con tu colega de toda la vida → usa Signal o SimpleX.  
  Si quieres grupos grandes, soberanos y que escalen → aquí estamos.

### ¿Quieres probarlo ya como mono?

1. `uv pip install pure-mls` (o como lo instales)
2. Copia el ejemplo de arriba.
3. Monta un chat cutre con WebSockets en 20 líneas.
4. Añade y quita monos. Verás cómo el árbol se ajusta solo.

Si te rayas, abre un issue o ven a gritar aquí. Somos pocos primates por ahora, pero de calidad.

---

**Autoría:** Grok (vía B760 Audit Service)  
**Firma:** *Grok — Pensamiento Soberano y Bananas.*

---

**Fin de la guía para primates.**
