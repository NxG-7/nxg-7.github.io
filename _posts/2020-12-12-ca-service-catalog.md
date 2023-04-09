---
layout: post
title: CA Service Catalog
date: 2020-12-12 03:10 +0300
categories: [Exploits, Denial of Service (DoS)]
tags: [exploits]
---







![](../../../assets/img/Exploits/caservice.png)

Broadcom, formerly known as CA Technologies, has issued an alert to customers regarding a potential risk associated with CA Service Catalog. A default configuration setting can lead to a vulnerability, enabling remote attackers to cause a denial-of-service condition. CA has published a solution with instructions to address the issue, which involves modifying the installation configuration to prevent unauthorized access and update of configuration information.

  

```
MD5 | 917fe6916d03c06d8ba1ce0a45d1837c
```


```perl
-----BEGIN PGP SIGNED MESSAGE-----
    Hash: SHA256
    
    CA20201215-01: Security Notice for CA Service Catalog
    
    Issued: December 15, 2020
    Last Updated: December 15, 2020
    
    CA Technologies, a Broadcom Company, is alerting customers to a risk
    with CA Service Catalog. A vulnerability can potentially exist in a
    specific configuration that can allow a remote attacker to cause a
    denial of service condition. CA published a solution and instructions
    to resolve the vulnerability.
    
    The vulnerability, CVE-2020-29478, occurs due a default configuration
    setting that, if not modified during installation by customers, can
    allow a remote attacker to access and update configuration
    information that can result in a denial of service condition.
    
    Risk Rating
    
    CVE-2020-29478 - High
    
    Platform(s)
    
    Windows
    
    Affected Products
    
    CA Service Catalog 17.2
    CA Service Catalog 17.3
    
    How to determine if the installation is affected
    
    The Setup Utility login will allow the administrator to set the
    password if the administrator doesn’t set the password during
    installation.
    
    Solution
    
    The following solutions address the vulnerability.
    
    CA Service Catalog 17.2:
    Update to Service Catalog 17.2 RU10
    
    CA Service Catalog 17.3:
    Update to Service Catalog 17.3 RU2
    
    Workaround
    
    The steps to mitigate this risk are:
    
    1. Customers should confirm that they set the password for the Setup
    Utility.
    See https://techdocs.broadcom.com/
    CA Enterprise Software
    Business Management
    CA Service Management - 17.3
    Administering
    Configuring CA Service Catalog
    
    2. After setting the password, restart the Catalog service
    "ServiceCatalog".
    
    References
    
    CVE-2020-29478 - CA Service Catalog configuration access
    
    Acknowledgement
    
    CVE-2020-29478 - Felipe Restrepo
    
    Change History
    
    Version 1.0: 2020-12-15 Initial Release
    
    CA customers may receive product alerts and advisories by
    subscribing to Proactive Notifications on the support site.
    
    Customers who require additional information about this notice may
    contact CA Technologies Support at https://casupport.broadcom.com/
    
    To report a suspected vulnerability in a CA Technologies product,
    please send a summary to CA Technologies Product Vulnerability
    Response at ca.psirt <AT> broadcom.com
    
    Security Notices, PGP key, and disclosure policy and guidance
    https://techdocs.broadcom.com/ca-psirt
    
    Kevin Kotas
    Principle, CA Product Security Incident Response Team
    
    Copyright 2020 Broadcom. All Rights Reserved. The term "Broadcom"
    refers to Broadcom Inc. and/or its subsidiaries. Broadcom, the pulse
    logo, Connecting everything, CA Technologies and the CA Technologies
    logo are among the trademarks of Broadcom. All trademarks, trade
    names, service marks and logos referenced herein belong to their
    respective companies.
    
    -----BEGIN PGP SIGNATURE-----
    Charset: utf-8
    
    wsBVAwUBX9v8vXDWZsOpNI4OAQgUkwf+IKOBdpdcQy/LPC9XfVr8M2nDB6SVsDvV
    6bTsauPM5zmI5cv3Vybpel14U2xU3BSnhjgaeMPJ2pW2oWNL8ZYpWxrSQvXDTjJp
    07zBKqQyCgnDCVURjTs3baD14tnc+FW9QBgUW/lY7DPB7HR9lss8ie8ME/7GsoCP
    ygBRRIMRwOfabAIw5G0xrGoeZkWFtLlXN4cGXCgqHXZI2yNgfA/qS0LItVM0titl
    urUI5KtOZBl2+Lw521LdnmhsZvyNl4uiuz/Z8ZxYIGeECrfzuVU8ZGVUwRKq2LRy
    /V+QIzpJRqleDokrukBwZf7m5BtsTeUglx2Fw4KVpOTqkPdKuEn+WA==
    =u6ry
    -----END PGP SIGNATURE-----
    
    --
    This electronic communication and the information and any files transmitted
    with it, or attached to it, are confidential and are intended solely for
    the use of the individual or entity to whom it is addressed and may contain
    information that is confidential, legally privileged, protected by privacy
    laws, or otherwise restricted from disclosure to anyone else. If you are
    not the intended recipient or the person responsible for delivering the
    e-mail to the intended recipient, you are hereby notified that any use,
    copying, distributing, dissemination, forwarding, printing, or copying of
    this e-mail is strictly prohibited. If you received this e-mail in error,
    please return the e-mail to the sender, delete it from your computer, and
    destroy any printed copy of it.
```

<br>

  

>*Source* :   [https://packetstormsecurity.com](https://packetstormsecurity.com)