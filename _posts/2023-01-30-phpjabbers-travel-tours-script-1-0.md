---
layout: post
title: PHPJabbers Travel Tours Script 1.0
date: 2023-01-30 01:17 +0300
categories: [Exploits, Cross-Site Scripting (XSS)]
tags: [exploits]
---









![](../../../assets/img/Exploits/phpjabbers.png)

There is a cross-site scripting vulnerability in version 1.0 of the PHPJabbers Travel Tours Script.

  

```
SHA-256 | 0a7f5b626d6393bcc255133a21566a6f163578785f29510c84d73418a28fd1fe
```

```perl
    ┌┌───────────────────────────────────────────────────────────────────────────────────────┐
    ││                                     C r a C k E r                                    ┌┘
    ┌┘                 T H E   C R A C K   O F   E T E R N A L   M I G H T                  ││
    └───────────────────────────────────────────────────────────────────────────────────────┘┘
    
     ┌────              From The Ashes and Dust Rises An Unimaginable crack....          ────┐
    ┌┌───────────────────────────────────────────────────────────────────────────────────────┐
    ┌┘                                  [ Vulnerability ]                                   ┌┘
    └───────────────────────────────────────────────────────────────────────────────────────┘┘
    :  Author   : CraCkEr                                                                    :
    │  Website  : PHPJabbers.com                                                             │
    │  Vendor   : PHPJabbers                                                                 │
    │  Software : PHPJabbers Travel Tours Script 1.0                                         │
    │  Vuln Type: Reflected XSS                                                              │
    │  Impact   : Manipulate the content of the site                                         │
    │                                                                                        │
    │────────────────────────────────────────────────────────────────────────────────────────│
    │                                                                                       ┌┘
    └───────────────────────────────────────────────────────────────────────────────────────┘┘
    :                                                                                        :
    │  Release Notes:                                                                        │
    │  ═════════════                                                                         │
    │  The attacker can send to victim a link containing a malicious URL in an email or      │
    │  instant message can perform a wide variety of actions, such as stealing the victim's  │
    │  session token or login credentials                                                    │
    │                                                                                        │
    ┌┌───────────────────────────────────────────────────────────────────────────────────────┐
    ┌┘                                                                                      ┌┘
    └───────────────────────────────────────────────────────────────────────────────────────┘┘
    
    Greets:
    
        The_PitBull, Raz0r, iNs, SadsouL, His0k4, Hussin X, Mr. SQL
    
      CryptoJob (Twitter) twitter.com/CryptozJob
    
    ┌┌───────────────────────────────────────────────────────────────────────────────────────┐
    ┌┘                                    © CraCkEr 2023                                    ┌┘
    └───────────────────────────────────────────────────────────────────────────────────────┘┘
    
    Path: /front.php
    
    /front.php?controller=pjListings&action=pjActionListings&listing_search=[XSS]&view=[XSS]&season=[XSS]&price_from=[XSS]&price_to=[XSS]&rating_from=[XSS]&rating_to=[XSS]
    
    /front.php?controller=pjListings&action=pjActionRegister&view=[XSS]&direction=[XSS]&listing_search=[XSS]
    
    /front.php?controller=pjListings&action=pjActionListings&listing_search=[XSS]&view=[XSS]&season=[XSS]&pjPage=[XSS]
    
    
    GET parameter 'listing_search' is vulnerable to XSS
    
    GET parameter 'view' is vulnerable to XSS
    
    GET parameter 'season' is vulnerable to XSS
    
    GET parameter 'direction' is vulnerable to XSS
    
    GET parameter 'price_from' is vulnerable to XSS
    
    GET parameter 'price_to' is vulnerable to XSS
    
    GET parameter 'pjPage' is vulnerable to XSS
    
    GET parameter 'rating_from' is vulnerable to XSS
    
    GET parameter 'rating_to' is vulnerable to XSS
    
    
    URL parameter to XSS
    
    /front.php/[XSS]?controller=pjListings&action=pjActionRegister&view=[XSS]t&direction=[XSS]&listing_search=[XSS]
    
    
    [-] Done
```
{: .nolineno }

<br>

  

>*Source* :   [https://packetstormsecurity.com](https://packetstormsecurity.com)