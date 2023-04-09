---
layout: post
title: H4Rpy - Automated WPA/WPA2
date: 2020-09-13 01:59 +0300
categories: [Tools & Frameworks, Wireless]
tags: [wireless]
---







![](../../assets/img/wireless/h4rpy.png)

**H4rpy** is an automated WPA/WPA2 PSK attack tool, wrapper of [aircrack-ng framework](https://github.com/aircrack-ng/aircrack-ng).

**H4rpy** is a tool that facilitates automated cracking of WPA/WPA2 PSK networks through a user-friendly interface. It activates monitor mode on a designated wireless interface, searches for available access points in the wireless space, captures the WPA/WPA2 4-way handshake of the access point, and initiates a dictionary attack on the captured handshake. In addition, **h4rpy** can send disassociate packets to clients who are connected to the access point.

Installation:
--

Installation consists of cloning the repo, running a script that will install dependencies ([aircrack-ng framework](https://github.com/aircrack-ng/aircrack-ng) and [Terminator](https://code.launchpad.net/terminator/) are required in order to run **h4rpy**), or installing them manually, and making **h4rpy** executable. Installation script works with apt and pacman package managers (Debian and Arch).

```bash
git clone https://github.com/MS-WEB-BN/h4rpy/
```
```bash
cd h4rpy
```
```bash
sudo bash config.sh
```
```bash
sudo chmod +x h4rpy
```
    

Usage:
--

To run h4rpy:

```bash
sudo ./h4rpy
``` 

**Top-left**: Enabling monitor mode, scanning for access points (packet capturing of raw 802.11 frames);

**Top-right**: Packet capturing on selected wireless network, capturing the WPA/WPA2 4-way handshake;

**Bottom-left**: Sends disassocate packets to clients which are currently associated with a selected access point;

**Bottom-right**: Dictionary attack on the captured WPA/WPA2 4-way handshake.

Screenshots:
--

![](../../assets/img/wireless/h4rpy2.png) 
![](../../assets/img/wireless/h4rpy3.png)

License:
--

The software is free to use, modify and distribute, as long as the credit is given to the creator (_**n1x\_ [\[MS-WEB\]](https://www.ms-web.agency/)**_).

<br>
  

>`⚠ ONLY USE FOR EDUCATIONAL PURPOSES ⚠`
