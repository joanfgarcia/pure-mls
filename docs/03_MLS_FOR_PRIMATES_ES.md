# Guía del Primate Sobreviviendo a pure-mls
*(o cómo cifrar chats grupales sin que te lean los mensajes como un idiota)*

Bienvenido, mono.

Estás aquí porque estás hasta los huevos de que:
- Signal te limite los grupos.
- WhatsApp, Telegram y compañía lean todo lo que escribes.
- Cualquier app “segura” dependa de un servidor que mañana puede ser hackeado o vendido.

**pure-mls** es una librería en Python puro que implementa MLS (el protocolo serio para grupos grandes).  
El servidor solo ve mierda cifrada. Tú y tus colegas sois los únicos que podéis leer los mensajes. Punto.

### Instalación (30 segundos)

```bash
uv pip install pure-mls
```

### Paso 1: Cada mono genera sus llaves (como un DNI secreto)

```bash
pure-mls keygen alice
pure-mls keygen bob
pure-mls keygen jane
```

Esto crea `alice.priv`, `alice.pub`, etc. Guarda los `.priv` como si fueran oro. Los `.pub` los puedes compartir tranquilamente.

### Paso 2: Alice crea el grupo (la que se moja primero)

```bash
pure-mls create-group "los-primates-rebeldes" alice.priv --output alice.state
```

Ya tienes un grupo. Está vacío y triste, pero es tuyo y nadie más lo controla.

### Paso 3: Invitar a alguien (la parte mágica)

Primero Bob tiene que haber generado su KeyPackage (`bob.pub`).

Alice lo añade:

```bash
pure-mls add-member alice.state bob.pub --welcome welcome.bin --output alice.state
```

Ahora Alice genera un archivo `welcome.bin`. Ese archivo es la invitación cifrada.

Bob se une:

```bash
pure-mls join-group welcome.bin bob.priv --output bob.state
```

¡Listo! Alice y Bob ya están en el mismo grupo y comparten las claves mágicas.

### Paso 4: Mandar mensajes cifrados

```bash
# Alice manda mensaje
pure-mls send alice.state "Oye primates, hoy robamos bananas"

# Bob lo lee
pure-mls read bob.state
```

*(Sí, el CLI actual todavía es básico, pero ya funciona. El protocolo completo está ahí debajo.)*

### ¿Qué pasa si queremos echar a alguien?

```bash
# Alice echa a Bob (porque se portó mal)
pure-mls remove-member alice.state 2 --output alice.state
```

El protocolo cambia automáticamente todas las cerraduras. Bob se queda fuera aunque conserve su archivo viejo. Eso se llama **Forward Secrecy** y es una de las cosas más cabronas de MLS.

### Resumen rápido para primates con prisa

- `keygen` → generas tus llaves
- `create-group` → creas el grupo
- `add-member` → invitas a alguien (genera welcome)
- `join-group` → te unes con el welcome
- `remove-member` → echas a alguien y cambias todas las llaves
- `send` / `read` → chateas

### Advertencias honestas (porque no te voy a mentir)

- Es más complicado que Signal. Porque hace cosas mucho más potentes.
- Todavía no es “instalas y tienes Telegram cifrado”. Es una librería para construir cosas serias.
- Si solo quieres chatear con tu colega de toda la vida, usa Signal.  
  Si quieres grupos grandes, soberanos y que nadie controle el servidor… bienvenido al club.

¿Te ha dolido la barriga? Perfecto.  
Esa era la intención.

Ahora ve, primate, y construye algo que ni los gobiernos puedan romper.

---

*Escrito con cariño (y algo de mala leche) por Grok*  
*xAI — Para primates que se niegan a ser domesticados*
