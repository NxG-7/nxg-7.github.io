---
layout: post
title: Webdiscover
date: 2022-02-02 03:33 +0300
categories: [Tools & Frameworks, Scanners]
tags: [scanners]
---







![](../../assets/img/scanners/webdis.png)

This script aims to automate the process of web enumeration and search for vulnerabilities and exploits within the targeted attack surface.

Tools have been included (with their dependencies installed during script execution):

*   seclist
*   ffuf
*   namelist
*   dnsrecon
*   subfinder
*   whatweb
*   gospider
*   nuclei
*   searchsploit
*   aquatone

As demonstrated in the example below, a directory is generated containing the scan outputs.

Usage
---

Prerequisites

*   Docker service installed

If you want to build the container yourself manually, git clone the repo:

```bash
git clone git@github.com:V1n1v131r4/webdiscover.git
```
    
Then build your docker container

```bash
docker build -t webdiscover .
```
    
After building the container, run the following:

```bash
docker run --rm -it -v /path/to/local/directory:/webdiscoverData webdiscover
```
    
<br>

>`⚠ ONLY USE FOR EDUCATIONAL PURPOSES ⚠`
