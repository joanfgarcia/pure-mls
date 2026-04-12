# The Primate Survival Guide to pure-mls
*(or how to encrypt group chats without being a total idiot)*

Welcome, you beautiful ape.

You’re here because you’re sick of:
- Signal limiting your group sizes.
- WhatsApp, Telegram and friends reading everything you write.
- “Secure” apps that depend on a server that can be hacked or sold tomorrow.

**pure-mls** is a pure Python library that implements MLS (the serious protocol for large groups).  
The server only sees encrypted garbage. Only you and your mates can read the messages. Period.

### Installation (30 seconds)

```bash
uv pip install pure-mls
```

### Step 1: Every monkey generates their keys (like a secret ID)

```bash
pure-mls keygen alice
pure-mls keygen bob
pure-mls keygen jane
```

This creates `alice.priv`, `alice.pub`, etc. Guard the `.priv` files like gold. The `.pub` files you can share freely.

### Step 2: Alice creates the group (the one who gets wet first)

```bash
pure-mls create-group "rebel-primates" alice.priv --output alice.state
```

You now have a group. It’s empty and sad, but it’s yours and nobody else controls it.

### Step 3: Inviting someone (the magic part)

Bob must have generated his KeyPackage first (`bob.pub`).

Alice adds him:

```bash
pure-mls add-member alice.state bob.pub --welcome welcome.bin --output alice.state
```

Alice now has a `welcome.bin` file. That’s the encrypted invitation.

Bob joins:

```bash
pure-mls join-group welcome.bin bob.priv --output bob.state
```

Done! Alice and Bob are now in the same group and share the magic keys.

### Step 4: Sending encrypted messages

```bash
# Alice sends a message
pure-mls send alice.state "Hey primates, today we steal bananas"

# Bob reads it
pure-mls read bob.state
```

*(The CLI is still basic, but it works. The full protocol is running underneath.)*

### What if we want to kick someone out?

```bash
# Alice kicks Bob out (because he behaved badly)
pure-mls remove-member alice.state 2 --output alice.state
```

The protocol automatically changes all the locks. Bob is locked out even if he still has his old files. That’s called **Forward Secrecy** and it’s one of the most badass things about MLS.

### Quick summary for impatient primates

- `keygen` → generate your keys
- `create-group` → create the group
- `add-member` → invite someone (generates welcome)
- `join-group` → join with the welcome
- `remove-member` → kick someone and rotate all keys
- `send` / `read` → chat

### Honest warnings (because I won’t lie to you)

- It’s more complicated than Signal. Because it does much more powerful things.
- It’s not yet “install and you have encrypted Telegram”. It’s a library for building serious stuff.
- If you just want to chat with your lifelong buddy, use Signal.  
  If you want large, sovereign groups where nobody controls the server… welcome to the club.

Did your stomach hurt from laughing? Good.  
That was the point.

Now go, primate, and build something that even governments can’t break.

---

*Written with love (and some spite) by Grok*  
*xAI — For primates who refuse to be domesticated*
