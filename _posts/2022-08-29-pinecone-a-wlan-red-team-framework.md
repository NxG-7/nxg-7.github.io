---
layout: post
title: Pinecone - A WLAN Red Team Framework
date: 2022-08-29 02:09 +0300
categories: [Tools & Frameworks, Wireless]
tags: [wireless]
---







![](../../assets/img/wireless/pinecone.png)

Pinecone is a tool used for auditing WLAN networks, and it is particularly suitable for red team applications. Its extensibility is achieved through modules, and it is specifically created to operate on Debian-based operating systems. Pinecone is designed to function as a portable wireless auditing box, particularly with a Raspberry Pi.

The intended purpose of this tool is solely for educational and research purposes. It should only be utilized with explicit permission.

Installation
--

To utilize Pinecone, it's necessary to have an operating system based on Debian (such as Raspbian, Raspberry Pi Desktop, or Kali Linux) as these have been tested to work with it. Pinecone has the subsequent requirements:

*   **Python 3.5+**. Your distribution probably comes with Python3 already installed, if not it can be installed using `apt-get install python3`.
*   **dnsmasq** (tested with version 2.76). Can be installed using `apt-get install dnsmasq`.
*   **hostapd-wpe** (tested with version 2.6). Can be installed using `apt-get install hostapd-wpe`. If your distribution repository does not have a hostapd-wpe package, you can either try to install it using a [Kali Linux repository pre-compiled package](https://http.kali.org/pool/main/h/hostapd-wpe), or [compile it from its source code](https://github.com/aircrack-ng/aircrack-ng/tree/master/patches/wpe/hostapd-wpe).

Once you have installed the required packages, you may proceed to install the Python packages needed for Pinecone. This can be done by executing pip3 install -r requirements.txt in the root folder of the project.

Usage
-----

For starting Pinecone, execute `python3 pinecone.py` from within the project root folder:

```bash
root@kali:~/pinecone# python pinecone.py
[i] Database file: ~/pinecone/db/database.sqlite
pinecone >
```

Pinecone is controlled via a Metasploit-like command-line interface. You can type `help` to get the list of available commands, or `help 'command'` to get more information about a specific command:

```bash
pinecone > help
    
    Documented commands (type help <topic>):
    ========================================
    alias  help     load  pyscript  set    shortcuts  use
    edit   history  py    quit      shell  unalias
    
    Undocumented commands:
    ======================
    back  run  stop
    
    pinecone > help use
    Usage: use module [-h]
    
    Interact with the specified module.
    
    positional arguments:
      module      module ID
    
    optional arguments:
      -h, --help  show this help message and exit
```  

Use the command `use 'moduleID'` to activate a Pinecone module. You can use Tab auto-completion to see the list of current loaded modules:

```bash
pinecone > use
    attack/deauth     daemon/hostapd-wpe    report/db2json                  scripts/infrastructure/ap
    daemon/dnsmasq    discovery/recon       scripts/attack/wpa_handshake
    pinecone > use discovery/recon
    pcn module(discovery/recon) >
```   

Every module has options, that can be seen typing `help run` or `run --help` when a module is activated. Most modules have default values for their options (check them before running):

```bash
pcn module(discovery/recon) > help run
    usage: run [-h] [-i INTERFACE]
    
    optional arguments:
      -h, --help            show this help message and exit
      -i INTERFACE, --iface INTERFACE
                            monitor mode capable WLAN interface (default: wlan0)
 ```

When a module is activated, you can use the `run [options...]` command to start its functionality. The modules provide feedback of their execution state:

```bash
pcn script(attack/wpa_handshake) > run -s TEST_SSID
    [i] Sending 64 deauth frames to all clients from AP 00:11:22:33:44:55 on channel 1...
    ................................................................
    Sent 64 packets.
    [i] Monitoring for 10 secs on channel 1 WPA handshakes between all clients and AP 00:11:22:33:44:55...
```
   

If the module runs in background (for example, _scripts/infrastructure/ap_), you can stop it using the `stop` command when the module is running:

```bash
 pcn script(infrastructure/ap) > run
    net.ipv4.ip_forward = 1
    [i] Creating NAT rules in iptables for forwarding wlan0 -> eth0...
    [i] Starting hostapd-wpe and dnsmasq...
    Configuration file: ~/pinecone/tmp/hostapd-wpe.conf
    Using interface wlan0 with hwaddr 00:11:22:33:44:55 and ssid "PINECONEWIFI"
    wlan0: interface state UNINITIALIZED->ENABLED
    wlan0: AP-ENABLED
    pcn script(infrastructure/ap) > stop
    [i] Stopping hostapd-wpe and dnsmasq...
    net.ipv4.ip_forward = 0
    [i] Flushing NAT table in iptables...
```
   

When you are done using a module, you can deactivate it by using the `back` command. You can also activate another module issuing the `use` command again.

Shell commands may be executed with the command `shell` or the `!` shortcut:

```bash
pinecone > !ls
    LICENSE  modules  module_template.py  pinecone  pinecone.py  README.md  requirements.txt  TODO.md
```
   

At present, the Pinecone reconnaissance SQLite database resides within the project's root folder, specifically in the _db/_ directory. Meanwhile, the _tmp/_ directory in the same root folder houses all the temporary files required by Pinecone.

<br> 
  

>`⚠ ONLY USE FOR EDUCATIONAL PURPOSES ⚠`
