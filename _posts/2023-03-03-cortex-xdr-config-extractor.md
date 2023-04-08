---
layout: post
title: Cortex XDR Config Extractor
date: 2023-03-03 03:21 +0300
categories: [Tools & Frameworks, Scanners]
tags: [scanners]
---






The purpose of this tool is to be utilized in Red Team Assessments and for auditing XDR Settings.

With this tool its possible to parse the `Database Lock Files` of the `Cortex XDR Agent` by Palo Alto Networks and extract `Agent Settings`, the `Hash and Salt` of the `Uninstall Password`, as well as possible `Exclusions`.

![](../../assets/img/scanners/cortex.png)

Supported Extractions
--

*   Uninstall Password Hash & Salt
*   Excluded Signer Names
*   DLL Security Exclusions & Settings
*   PE Security Exclusions & Settings
*   Office Files Security Exclusions & Settings
*   Credential Gathering Module Exclusions
*   Webshell Protection Module Exclusions
*   Childprocess Executionchain Exclusions
*   Behavorial Threat Module Exclusions
*   Local Malware Scan Module Exclusions
*   Memory Protection Module Status
*   Global Hash Exclusions
*   Ransomware Protection Module Modus & Settings

Usage
--

**Usage:**

```bash
./XDRConfExtractor.py [Filename].ldb
```

 **Help:**

 ```bash
 ./XDRConfExtractor.py -h
 ```


Getting Hold of Database Lock Files
--

Agent Version <7.8
------------------

Before Agent Version 7.8, any user who was authenticated could create a Support File on Windows using the Cortex XDR Console located in the System Tray. If you unzip the file, you will be able to locate the database lock files.

```diff
logs_[ID].zip\Persistence\agent_settings.db\
```
    

Agent Version ≥7.8
------------------

Files from Agents running Version 7.8 or above are encrypted. However, if you have elevated privileges on the Windows machine, you can copy the files directly from the specified directory without encryption.

Method I
--

```bash
C:\ProgramData\Cyvera\LocalSystem\Persistence\agent_settings.db\
```

Method II
--

Support Files that are generated are not regularly deleted, which means it is possible to come across old, unencrypted Support Files in the designated folder.

```bash
C:\Users\[Username]\AppData\Roaming\PaloAltoNetworks\Traps\support\
```   

Agent Version >8.1
------------------

It is believed that it is no longer feasible to retrieve data from the lock files starting from Agent version 8.1. However, this assertion has not yet been verified through testing.


Credit
--

The functionality of this tool is based on a technique that was initially introduced by [mr.d0x](https://twitter.com/mrd0x) in April 2022 [https://mrd0x.com/cortex-xdr-analysis-and-bypass/](https://mrd0x.com/cortex-xdr-analysis-and-bypass/)

Legal disclaimer
----------------

Usage of Cortex-XDR-Config-Extractor for attacking targets without prior mutual consent is illegal. It's the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program. Only use for educational purposes.

  
 <br> 

>`⚠ ONLY USE FOR EDUCATIONAL PURPOSES ⚠`
