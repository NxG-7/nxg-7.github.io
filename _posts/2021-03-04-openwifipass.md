---
layout: post
title: OpenWifiPass
date: 2021-03-04 02:04 +0300
categories: [Tools & Frameworks, Wireless]
tags: [wireless]
---





![](../../assets/img/wireless/open.png)

OpenWifiPass is an open source implementation of the grantor role in Apple's Wi-Fi Password Sharing protocol.

Disclaimer
--

OpenWifiPass is experimental software and is the result of reverse engineering efforts by the [Open Wireless Link](https://owlink.org) project. The code serves solely documentary and educational purposes. It is _untested_ and _incomplete_. For example, the code **does not verify the identity of the requestor**. So, do not use this implementation with sensitive Wi-Fi credentials. OpenWifiPass is not affiliated with or endorsed by Apple Inc.

Requirements
--

**Hardware:** Bluetooth Low Energy radio, e.g., Raspberry Pi 4

**OS:** Linux (due to the `bluepy` dependency)

Install
--

Clone this repository and install it:

```bash
git clone git@github.com/seemoo-lab/openwifipass.git
```
```bash
pip3 install ./openwifipass
```   

Run
--

Run `openwifipass` to share Wi-Fi credentials (`SSID` and `PSK`) with _any_ requestor (we need super user privileges to use the Bluetooth subsystem):

```bash
sudo -E python3 -m openwifipass --ssid <SSID> --psk <PSK>
```

**Use [quoting](https://www.gnu.org/savannah-checkouts/gnu/bash/manual/bash.html#Quoting) of your shell to remove special meaning of certain characters in `SSID`/`PSK`.** In the example below, we use single quotes (`'`) to prevent shell expansion of the `$` character in the PSK.

A successful run of the protocol would look as follows:

```shell
pi@raspberrypi:~/openwifipass $ sudo -E python3 -m openwifipass --ssid OWL --psk '$uper$ecretPassword'
Start scanning...
SSID match in PWS advertisement from aa:bb:cc:dd:ee:ff
Connect to device aa:bb:cc:dd:ee:ff
Send PWS1
Receive PWS2
Send M1
Receive M2
Send M3
Receive M4
Send PWS3
Receive PWS4
Wi-Fi Password Sharing completed
```
  

Publications
------------

*   Milan Stute, Alexander Heinrich, Jannik Lorenz, and Matthias Hollick. **Disrupting Continuity of Apple’s Wireless Ecosystem Security: New Tracking, DoS, and MitM Attacks on iOS and macOS Through Bluetooth Low Energy, AWDL, and Wi-Fi.** _30th USENIX Security Symposium (USENIX Security ’21)_, August 11–13, 2021, virtual Event. [Link](https://www.usenix.org/conference/usenixsecurity21/presentation/stute).
*   Jannik Lorenz. **Wi-Fi Sharing for All: Reverse Engineering and Breaking the Apple Wi-Fi Password Sharing Protocol.** Bachelor thesis, _Technical University of Darmstadt_, March 2020.

License
-------

OpenWifiPass is licensed under the **`GNU General Public License v3.0`**.

  
<br>  

>`⚠ ONLY USE FOR EDUCATIONAL PURPOSES ⚠`
