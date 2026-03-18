# CRIPTO 101: Entendiendo MLS (Sin Dolor de Cabeza)

¡Bienvenido al subsuelo de la criptografía asíncrona! 

Puesto que vamos a construir **pure-mls** (una implementación estricta del [RFC 9420](https://datatracker.ietf.org/doc/rfc9420/)) desde cero, primero necesitamos entender por qué el "ratchet lineal" (la cuerda de hashes) que teníamos en *Red Pill* fallaba para grupos grandes, y por qué MLS es la joya de la corona actual (usado por Cisco, WhatsApp y el IETF).

---

## 1. El Problema: El cuello de botella de Signal
Antes de MLS, el estándar de oro era el protocolo de Signal (el Double Ratchet). 
Es perfecto para 2 personas (Tú y Aleth). Pero, ¿qué pasa si hacemos un chat de grupo de **50.000 agentes**? 
Con Signal, si tú mandas un mensaje, tienes que encriptarlo **49.999 veces individuales** (una vez con la clave pública de cada miembro). Esto destruye la batería, el ancho de banda y el rendimiento (complejidad **O(N)**).

## 2. La Solución: TreeKEM (Tree Key Encapsulation Mechanism)
MLS resuelve esto usando un **Árbol Binario** matemático (complejidad **O(log N)**).

Imagina un torneo de tenis clásico:
- En la base (las **Hojas** / *LeafNodes*), están los agentes. Cada uno tiene su clave.
- Cada nivel superior del árbol combina las claves de los que están debajo.
- Arriba del todo está la **Raíz** (*Root Key* o *Group Secret*).
- Esta raíz es la clave simétrica (AES-GCM) que **todos** usan para encriptar los mensajes reales de chat.

### ¿Cuál es la magia del Árbol?
Si Nova quiere unirse al grupo de 50.000 agentes, no tenemos que mandar 50.000 mensajes. Nova se engancha a una rama del árbol, y su clave pública sube matemáticamente alterando solo los nudos de *su rama particular* hasta llegar a la raíz. 
La complejidad computacional pasa de ser 50.000 cálculos (O(N)) a apenas **16 cálculos** (O(log N)). Es magia negra matemática.

---

## 3. Conceptos Clave del Diccionario MLS
Para que nos entendamos cuando bajemos al código de Python, aquí están los términos sagrados del RFC 9420:

*   **KeyPackage**: El "DNI criptográfico". Tu tarjeta de visita pública que dice "Hola, me llamo David y estas son mis claves públicas X25519 pre-computadas".
*   **Proposal (Propuesta)**: La intención de hacer algo. Ej: "Propongo meter a Nova en el grupo" o "Propongo cambiar mi propia llave porque se ha corrompido (Ratchet)".
*   **Commit (Confirmación)**: El "Sello Notarial". Una vez que la comunidad ve una o varias Proposals, un operario las empaqueta en un Commit. Al aceptar el Commit, el grupo avanza matemáticamente a una nueva era.
*   **Epoch (Época)**: Cada vez que hay un nuevo Commit ratificado, el grupo entra en una nueva Época con una *Root Secret* (llave base) completamente nueva e impredecible.
*   **Welcome**: El mensaje encriptado especial que se le manda a los novatos (como Nova) para darles el estado actual del Árbol Binario para que puedan derivar la llave base.

## 4. PCS y PFS (La verdadera invulnerabilidad)
- **PFS (Perfect Forward Secrecy)**: Significa "Protección hacia el Pasado". Si mañana rompo tu llave privada de hoy, no puedo descifrar las Epochs que ocurrieron ayer, porque el hash destruye la información en sentido inverso.
- **PCS (Post-Compromise Security)**: Significa "Curación hacia el Futuro". Si un ladrón te roba la llave privada y se cuela en el árbol de Swarm, en cuanto tú hagas un Commit para rotar tu llave (*Update Proposal*), echas al ladrón automáticamente del árbol sin tener que recrear la comunidad entera. El sistema "sana" solo.

---

A partir de aquí, en `pure-mls` vamos a codificar cada uno de estos bloques paso a paso. Empezaremos por la base (`LeafNode` y la criptografía de curvas elípticas Ed25519) e iremos subiendo la rama hasta conquistar la `Root Key`.
