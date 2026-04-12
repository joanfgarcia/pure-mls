# La Guía Humana de MLS (Message Layer Security)

Esta guía es un cuento. Es la traducción de los fríos engranajes matemáticos del RFC 9420 a un idioma que podemos entender y visualizar sin perdernos en jerga técnica. 

Vamos a seguir a cuatro personajes en esta historia: **Alice**, **Bob**, **Jane** y **Peter**.

---

## Prólogo: Los Buzones Abiertos (`KeyPackages`)

Antes siquiera de que exista un grupo, en el mundo de MLS existe un directorio público. Imagina que es como la gran entrada de una oficina postal, llena de casilleros de cristal.

Cualquiera que quiera que le inviten a clubes secretos en el futuro, debe ir a esa oficina de correos y dejar un paquete en su casillero abierto.
Ese paquete se llama **`KeyPackage`** (Paquete de Claves).

¿Qué mete Bob dentro de su `KeyPackage`?
1. **Un candado público de identidad (`SignatureKey`)**: Con esto la gente podrá verificar si una firma realmente es de Bob.
2. **Un candado público para mensajes (`KemKey`)**: Si alguien quiere susurrarle un secreto a Bob para invitarle a un grupo, cerrará el mensaje con este candado. Solo la llave privada de Bob podrá abrirlo.

Jane y Peter hacen lo mismo. Dejan sus `KeyPackage` en la oficina postal y se van a casa a esperar.

---

## Capítulo 1: Fundando el Club (`Group Creation`)

Un día, **Alice** decide que quiere organizar un comité clandestino. 
Alice no puede "unirse" a algo que no existe, así que ella funda el grupo desde cero.

Crear el grupo ( `MLSGroup.create` ) es un acto solitario. Alice:
1. Compra una gran mesa redonda (el **`RatchetTree`** o Árbol de Claves). 
2. Se sienta en la mismísima silla número 0 (**Leaf 0**).
3. Genera el primer gran secreto de la mesa: una "llave maestra" aleatoria (`joiner_secret`) a partir de la cual nacerán todas las claves de encriptación de ese club de ahora en adelante.
4. Genera el acta constitutiva: *"Club creado hoy. Único miembro: Alice (Silla 0)"*. 

En este momento, Alice está sola en la sala. Es seguro, pero aburrido.

---

## Capítulo 2: Repartiendo las Invitaciones (`Add` y `Welcome`)

Alice quiere invitar a Bob, Jane y Peter. Para hacerlo de forma 100% segura, el protocolo MLS prohíbe pasar contraseñas "en claro". Se utiliza un mecanismo brillante llamado el mensaje **`Welcome`**.

Paso a paso, la magia ocurre así:

### 1. Recogiendo los candados
Alice va a la oficina pública, busca los casilleros de Bob, Jane y Peter, y agarra una copia de los **`KeyPackages`** que dejaron ahí. Ahora Alice tiene en sus manos el candado de identidad y el candado de mensajes de cada uno de ellos.

### 2. Acomodando las sillas (`RatchetTree`)
Sentada en su mesa (el Árbol), Alice añade tres sillas vacías a su derecha. 
- Silla 0: Alice
- Silla 1: Bob
- Silla 2: Jane
- Silla 3: Peter

Alice actualiza el mapa de la mesa para incluir las caras (claves públicas) de sus nuevos amigos.

### 3. Escondiendo el Secreto del Grupo (`EncryptedGroupSecrets`)
Alice no puede enviarles la llave maestra de la mesa por WhatsApp. 
Así que agarra tres cajas fuertes diminutas. 
- Mete una copia de la llave maestra del grupo en la caja fuerte 1 y la cierra usando el **candado de mensajes de Bob** (que sacó de su `KeyPackage`).
- Hace lo mismo para Jane.
- Hace lo mismo para Peter.
Mete estas tres cajas blindadas en un paquete más grande.

### 4. Levantando el Acta Inicial (`GroupInfo`)
Alice toma un pergamino y escribe: *"Acta inaugural. Estamos usando este cifrado, y de momento en la mesa estamos Alice, Bob, Jane y Peter. El resumen criptográfico actual de la sala es este"*.

Para garantizar que nadie ha alterado este pergamino, Alice echa una gota de cera en la parte inferior y, usando su propio anillo (El **`SignatureKey`** de la Silla 0), **estampa su firma**. Esta firma grita: *"Yo, la dueña de la silla 0, certifico que este es el estado con el que empezamos"*.

Para evitar que mirones lean el pergamino en tránsito, Alice lo encripta brevemente (`encrypted_group_info`).

---

## Capítulo 3: La Llegada del Nuevo (El Desembalaje)

El mensaje `Welcome` ya está terminado. Es un paquete gigante que contiene las tres cajitas fuertes de los secretos y el pergamino de las actas encriptado.
Alice pone el paquete en internet a la atención de los tres.

Cuando **Bob** recibe el `Welcome`, entra en acción (y aquí es donde nuestro código estaba atascado antes):

1. **Abriendo la cajita:** Bob busca entre las cajas fuertes (`EncryptedGroupSecrets`) y encuentra la que tiene su nombre. Usa la llave privada que guardó en su casa para quitar el candado. ¡Click! Obtiene el Secreto del Grupo.
2. **Desenrollando el pergamino:** Usando ese secreto que acaba de desencriptar, ahora puede quitarle la envoltura cifrada al acta de Alice (`GroupInfo`). 
3. **El Control de Seguridad Definitivo:** Bob lee las actas. Ve el membrete: *"Firmado por el ocupante de la Silla 0 (Alice)"*.
Bob saca su lupa, mira la firma de cera y va al mapa de la mesa (`RatchetTree`). Examina la silla 0, comprueba el anillo público de Alice... y si la fórmula matemática dice "¡Coincide!", Bob entra seguro al chat. Si una mínima letra ha sido alterada, o la firma no cuadra, Bob lanza un error, destruye el paquete y aborta.

¡Todos están dentro! ¡El grupo está formado!

---

## Capítulo 4: El Invitado Sorpresa (`Proposals` y `Commits`)

La fiesta ya ha empezado, las cervezas están servidas. De repente, Bob dice: *"¡Oye, deberíamos invitar a **Dave** al club!"*.

Dave no estaba en las cajas fuertes (`Welcome`) originales que hizo Alice. Dave está en su casa, ignorante de la existencia del club.

Para traer a Dave, MLS hace algo muy elegante. Divide la acción en dos momentos:

### 1. La Moción (`Add Proposal`)
Nadie mete a alguien en la sala directamente. Primero se levanta la mano. 
Bob va a la famosa oficina postal, saca una copia del `KeyPackage` de Dave (sus candados públicos), vuelve a la mesa redonda y pone un papelito encima de la mesa que dice: *"Propongo que invitemos a Dave. Aquí están sus candados"*. 

A este papelito se le llama **`Proposal`** (Propuesta). Puede haber varias propuestas encima de la mesa al mismo tiempo.

### 2. El Golpe de Mazo (`Commit`)
Una propuesta no hace nada por sí sola. Alguien tiene que agarrar el mazo de presidente y decir: *"¡Aprobadas las propuestas de la mesa!"*. Cualquiera puede dar el golpe de mazo. Digamos que es **Jane**.

Jane crea un mensaje especial llamado **`Commit`**. Literalmente significa "Efectuar cambios". 
Al dar el golpe de mazo con el `Commit`, Jane hace varias cosas a velocidad de vértigo:

1. **Añade una silla:** Mira su mapa de la mesa (`RatchetTree`), añade una nueva silla y sienta a Dave matemáticamente ahí.
2. **Cambia la cerradura principal:** Para que las matemáticas sean seguras, Jane usa una fórmula para generar un **nuevo Secreto de Grupo**. La llave maestra de la sala acaba de cambiar.
3. **Distribuye la nueva llave a los veteranos:** Jane encripta esta nueva llave maestra para que Alice, Bob y Peter puedan entenderla. Como ellos ya estaban en el club y sus árboles están sincronizados, Jane envía esta información cifrada *junto* con el mensaje de `Commit`.
4. **Prepara el paquete para Dave:** Y ahora viene el truco final. Puesto que Dave *todavía* no está dentro, a él no le sirve el mensaje de `Commit` (no entendería nada de lo que pasa dentro). Así que Jane coge los candados públicos de Dave que Bob dejó en la mesa y fabrica un **mensaje `Welcome` exclusivo para Dave** (exactamente igual que el cofre que Alice fabricó en el Capítulo 2), metiéndole el nuevo secreto de la mesa.

### Resumen para el novato vs los veteranos
- **Para los que ya estaban en la mesa (Alice, Bob, Peter):** Reciben el golpe de mazo (`Commit`). Actualizan sus mapas mentales de la sala, aprenden la nueva contraseña, ven que Dave tiene ahora una silla, y siguen bebiendo.
- **Para el que estaba fuera (Dave):** Recibe un paquete en su casa (`Welcome`). Lo abre con su llave privada, lee las actas, verifica la firma de cera (esta vez de Jane, porque ella pegó el golpe de mazo), se entera de que hay 4 personas más, y entra por la puerta triunfalmente.

---

## Capítulo 5: Nadie es el Jefe (La Despedida de Alice)

Aquí es donde MLS rompe el cerebro a la gente acostumbrada a los grupos de WhatsApp o Telegram. **En MLS no hay "Administradores".** 
No hay un dueño del grupo. Existe una Regla de Oro inquebrantable incrustada en las matemáticas: **Todos los participantes gozan de los mismos privilegios.**

Para demostrarlo, imaginemos que **Alice** (la mismísima fundadora del club, la que fabricó el Árbol inicial) decide que está cansada y quiere irse a dormir.
No tiene que pedirle permiso a un "Admin" (porque no existen). Ni tampoco puede "borrar" el grupo solo porque ella lo creó.

### 1. Levantando la mano para irse (`Remove Proposal`)
Alice se pone de pie, escribe un papelito y lo tira a la mesa: *"Propongo mi propia eliminación de la Silla 0"*. 
Esto es un **`Remove Proposal`**. (Curiosidad: Bob podría haber hecho esta misma propuesta para echar a Alice si ella se estuviera portando mal. ¡Cualquiera puede proponer echar a cualquiera!).

### 2. El Cambio de Cerraduras (Forward Secrecy)
Ese papel no echa a Alice físicamente. Hasta que alguien no da el golpe de mazo, Alice sigue escuchando.
Esta vez es **Bob** quien agarra el mazo y genera el **`Commit`**.

Cuando Bob pega el golpe de mazo para echar a Alice, hace algo fundamental para la seguridad del club (lo que los criptógrafos llaman *Forward Secrecy* o Secreto Hacia Adelante):

1. **Borra la Silla 0:** Bob va al mapa de la mesa (`RatchetTree`), coge una goma de borrar y elimina la cara, el nombre y los candados de Alice de la Silla 0. La silla no se quita de la sala (por temas de la estructura matemática), pero se queda "En Blanco" (`Blank Node`). 
2. **Cambia la cerradura (¡Otra vez!):** Bob genera una contraseña de grupo totalmente nueva. Alice no puede salir por la puerta llevándose la llave vieja, porque podría seguir espiando desde fuera.
3. **Reparte las llaves solo a los leales:** Aquí está la magia negra de TreeKEM. Bob tiene que comunicar esta nueva contraseña al resto de la mesa. En lugar de gritarla, la encripta matemáticamente usando *únicamente* los candados públicos de Jane, Peter, Dave y el suyo propio.  

### El resultado final
Alice, que ya está fuera del bar, intenta mirar por la ventana usando su llave vieja. Pero como sus candados públicos ya no están en la mesa matemática de Bob, nadie ha encriptado la nueva llave para ella. La ventana se vuelve opaca. Alice sabe que ha sido purgada y borra sus llaves locales.

**El grupo sobrevive a su creador.** El club es ahora de Bob, Jane, Peter y Dave.
