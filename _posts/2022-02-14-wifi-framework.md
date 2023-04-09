---
layout: post
title: Wifi-Framework
date: 2022-02-14 02:16 +0300
categories: [Tools & Frameworks, Wireless]
tags: [wireless]
---








This kind of framework offers a simpler way to conduct Wi-Fi experiments. With its help, one can generate fuzzers, execute fresh attacks, build prototypes to identify security loopholes, automate experiments, design test suites, and much more.

The framework offers a significant benefit by **enabling the efficient implementation of attacks and/or tests through the reuse of Linux's Wi-Fi functionality**. With this framework, connecting to protected Wi-Fi networks and broadcasting beacons during client testing can be achieved with ease. Essentially, any Wi-Fi functionality that Linux provides can be reused to accelerate the process of performing attacks and tests. This is achieved by executing _test cases_ on top of the _hostap_ user space daemon.

![](../../assets/img/wireless/wifi.png)

For those who are new to conducting Wi-Fi experiments on Linux, it is strongly advised to read the [libwifi Linux Tutorial](https://github.com/vanhoefm/libwifi/blob/master/docs/linux_tutorial.md). When you are implementing basic Wi-Fi attacks without the need to reuse Linux functionality, then the framework provides limited advantages and you can instead consider directly implementing attacks in Scapy and optionally use the [libwifi](https://github.com/vanhoefm/libwifi) library.

Usage
--

To use the framework:

*   Install it by running `./setup.sh`

Example
--

Say you want to test whether a client ever encrypts frames using an all-zero key. This can happen during a [key reinstallation attack](https://www.krackattacks.com/#demo). By using the framework you do not need to reimplement all functionality of an access point, but only need to write the following test case:

```java
class ExampleKrackZerokey(Test):
        name = "example-krack-zero-key"
        kind = Test.Authenticator
    
        def __init__(self):
            super().__init__([
                # Replay 4-Way Handshake Message 3/4.
                Action( trigger=Trigger.Connected, action=Action.Function ),
                # Receive all frames and search for one encrypted with an all-zero key.
                Action( trigger=Trigger.NoTrigger, action=Action.Receive ),
                # When we receive such a frame, we can terminate the test.
                Action( trigger=Trigger.Received, action=Action.Terminate )
            ])
    
    
        def resend(self, station):
            # Resend 4-Way Handshake Message 3/4.
            station.wpaspy_command("RESEND_M3 " + station.clientmac )
    
    
        def receive(self, station, frame):
            if frame[Dot11].addr2 != station.clientmac or not frame.haslayer(Dot11CCMP):
                return False
    
            # Check if CCMP-encrypted frame can be decrypted using an all-zero key
            plaintext = decrypt_ccmp(frame.getlayer(Dot11), tk=b"\x00"*16)
            if plaintext is None: return False
    
            # We received a valid plaintext frame!
            log(STATUS,'Client encrypted a frame with an all-zero key!', color="green")
            return True
```
    

The above test case will create an access point that clients can connect to. After the client connects, a new 3rd message in the 4-way handshake will be sent to the client. A vulnerable client will then start using an all-zero encryption key, which the test case automatically detects.

You can run the above test case using simulated Wi-Fi radios as follows:

```bash
./setup/setup-hwsim.sh 4
```
```bash
source setup/venv/bin/activate
```
```bash
./run.py wlan1 example-krack-zero-key
```    

You can connect to the created access point to test it (network `testnetwork` with password `passphrase`):

```bash
./hostap.py wlan2
```   

By changing the network configuration this AP can easily be configured to use WPA2 or WPA3 and/or can be configured to use enterprise authentication, without making any changes to the test case that we wrote! Additional benifits of using the framework in this example are:

*   No need to manually broadcast beacons
*   The authentication and association stage is handled by the framework
*   The WPA2 and/or WPA3 handshake is handled by the framework
*   Injected packets will be automatically retransmitted by the Linux kernel
*   Packets sent _towards_ the AP will be acknowledged
*   Sleep mode of the client is automatically handled by the kernel

Publications
--

This work was published at ACM Conference on Security and Privacy in Wireless and Mobile Networks (WiSec '21):

*   [DEMO: A Framework to Test and Fuzz Wi-Fi Devices](https://dl.acm.org/doi/10.1145/3448300.3468261)

Works that have used this framework or a similar one:

*   [Systematically Analyzing Vulnerabilities in the Connection Establishment Phase of Wi-Fi Systems](http://rahbari.csec.rit.edu/papers/Systematically_naureen.pdf)
*   [FragAttacks: Fragmentation & Aggregation Attacks](https://github.com/vanhoefm/fragattacks)
*   [On the Robustness of Wi-Fi Deauthentication Countermeasures](https://papers.mathyvanhoef.com/wisec2022.pdf)
*   [Attacking WPA3: New Vulnerabilities and Exploit Framework (HITBSecConf)](https://conference.hitb.org/hitbsecconf2022sin/session/attacking-wpa3-new-vulnerabilities-and-exploit-framework/).

  
<br>  

>`⚠ ONLY USE FOR EDUCATIONAL PURPOSES ⚠`