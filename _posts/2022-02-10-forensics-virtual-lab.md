---
layout: post
title: Forensics Virtual Lab
date: 2022-02-10 21:16 +0300
categories: [Cybersecurity, Threat Intel]
tags: [forensics, lab]
---




During the upcoming session, we will demonstrate how to set up CAINE for a virtual Forensics lab. CAINE is an excellent digital forensics tool that includes pre-installed applications such as Autopsy and Volatility. Furthermore, we will present a brief demo based on ENISA's "Forensic Analysis: Network Incident Response" training ([https://www.enisa.europa.eu/topics/trainings-for-cybersecurity-specialists/online-training-material/technical-operational/#Forensic\_analysis\_Network\_Incident\_Response](https://www.enisa.europa.eu/topics/trainings-for-cybersecurity-specialists/online-training-material/technical-operational/#Forensic_analysis_Network_Incident_Response)).

Requirements
---

The following items are required for this setup:

*   CAINE iso ([https://www.caine-live.net/](https://www.caine-live.net/))
*   VirtualBox ([https://www.virtualbox.org/](https://www.virtualbox.org/))
*   An evidence drive (Example: [http://enisa.europa.eu/ftp/ENISA-Ex2-Evidence.vmdk](http://enisa.europa.eu/ftp/ENISA-Ex2-Evidence.vmdk))

Setup
--

Installing CAINE is not mandatory since it can be used live, but it can speed up exercises in a virtual environment.

However, if you decide to install CAINE within a virtual machine, you may encounter an issue with the GRUB bootloader. To address this problem, please refer to the tutorial available at [https://www.youtube.com/watch?v=atHr2OGCQiQ&t=1s&ab\_channel=CyberEntirety](https://www.youtube.com/watch?v=atHr2OGCQiQ&t=1s&ab_channel=CyberEntirety).

Apart from this, launching your CAINE VM should be straightforward. You might want to adjust the display resolution to fit your screen or install VirtualBox Guest Additions, which will automatically adjust the screen resolution for you.

If you have installed CAINE, ensure that you take a snapshot of your CAINE VM once you've completed the setup.

Demo
--

In this demonstration, I will be utilizing an image from the "Forensic Analysis: Network Incident Response" training website by ENISA (the link to which is available in the Requirements section).

Preparing the evidence drive
--

Prior to launching your CAINE VM, it is necessary to include the evidence vmdk drive as a storage device in the CAINE VM settings.

![](../../assets/img/threatintel/foren1.png)

To begin, launch your CAINE VM and log in. The next step is to mount the evidence image. For the safest approach, use the Mounter utility located on the bottom right of the taskbar in CAINE. This ensures that the device is mounted in read-only mode, preventing any accidental corruption of the drive.

![](../../assets/img/threatintel/foren2.png)

Alternatively, you have the option to mount the connected drive using the following commands:

```bash
lsblk # to check if device is in sdb1 (it should be by default)
sudo mount /dev/sdb1 
```

With the evidence drive now mounted, the next step is to copy the pfsense and dhcpsrv directories to our CAINE VM.

```bash
# Create empty directory
cd ~/Desktop/
mkdir forensic-demo && cd forensic-demo
# Copy directories to current directory
cp -r /media/sdb1/pfsense ./
cp -r /media/sdb1/dhcpsrv ./
```
    

Once this step is complete, you have the option to disconnect the mounted drive.

Tip: In case your VM is running slowly, consider establishing an SSH connection to it from your host machine.

```bash
sudo apt-get install openssh-server     # install ssh server
sudo systemctl status sshd              # Check status of ssh daemon
```    

Configure SSH port forwarding in your virtual box network settings: Set the guest port to 22 and your host port to 2222 (or any other port that’s not in use).

Collecting network evidence
--

Inside the pfsense directory, you will come across 3 archives:

*   log.tar.gz: firewall logs
*   nfdump.tar.gz: netflow dump
*   squid-logs.tar.gz: squid proxy logs

To read the netflow dump, we will require nfdump. You can install it by running the following command with sudo privileges:

```bash
sudo apt-get install nfdump
```

Network forensic analysis: nfdump
--

According to the scenario, the system at IP address 192.168.5.100 has been compromised. Our next step is to search for clues about the connections linked to the victim IP using nfdump.

To achieve this, we will sort the data by the number of flows using "-O flows" and apply a filter to display only the entries pertaining to IP 192.168.5.100 and protocol UDP:

```bash
nfdump -o long -R ./nfdump -A proto,dstport -O flows 'ip 192.168.5.100 and proto udp' | head
Date first seen          Duration Proto      Src IP Addr:Port          Dst IP Addr:Port   Flags Tos  Packets    Bytes Flows
2016-08-16 11:43:05.180 43254.352 UDP            0.0.0.0:0     ->          0.0.0.0:53    ......   0     4406   289737  3970
2016-06-28 02:24:32.625 4307914.637 UDP          0.0.0.0:0     ->          0.0.0.0:8572  ......   0      496    47954   234
2016-08-16 11:43:00.596 40562.491 UDP            0.0.0.0:0     ->          0.0.0.0:5355  ......   0      239    13582   121
2016-06-27 20:54:55.360 4309508.877 UDP          0.0.0.0:0     ->          0.0.0.0:3544  ......   0      507    43359    63
2016-08-16 11:50:31.397 11653.753 UDP            0.0.0.0:0     ->          0.0.0.0:1900  ......   0       92    14766    46
2016-08-16 11:50:08.447 11791.646 UDP            0.0.0.0:0     ->          0.0.0.0:3478  ......   0      133     7448    30
2016-06-28 04:24:32.963 4300365.056 UDP          0.0.0.0:0     ->          0.0.0.0:40018 ......   0       87    15045    28
2016-08-16 11:49:32.177 40336.276 UDP            0.0.0.0:0     ->          0.0.0.0:443   ......   0       24     1104    24
2016-06-27 19:50:20.901 4327722.503 UDP          0.0.0.0:0     ->          0.0.0.0:137   ......   0      415    34098    23
```

The majority of the UDP packets are generated by DNS traffic (using port 53). Regarding the remaining ports:

*   8572: Unassigned
*   5355: LLMNR service
*   3544: Teredo (RFC 4380)
*   1900: UPnP
*   3478: VoIP STUN
*   40018: Used by Microsoft
*   443: HTTPS
*   137: NetBIOS

We have utilized SpeedGuide as a reference for the ports, and nothing appears to be particularly suspicious. Therefore, let us examine the TCP packets.

```bash
nfdump -o long -R ./nfdump -A proto,dstport -O bytes 'ip 192.168.5.100 and proto tcp' | head
Date first seen          Duration Proto      Src IP Addr:Port          Dst IP Addr:Port   Flags Tos  Packets    Bytes Flows
2016-06-27 20:08:32.485 4319017.104 TCP            0.0.0.0:0     ->          0.0.0.0:12345 ......   0    1.1 M    1.5 G    91
2016-06-27 23:02:11.313 4297677.538 TCP            0.0.0.0:0     ->          0.0.0.0:22    ......   0    75846   89.0 M   250
2016-06-27 22:15:20.176 4294809.218 TCP            0.0.0.0:0     ->          0.0.0.0:50087 ......   0    25889   35.2 M     1
2016-06-27 21:08:52.091 4294720.356 TCP            0.0.0.0:0     ->          0.0.0.0:59694 ......   0    21598   29.1 M     1
2016-06-27 20:19:51.126 4301177.540 TCP            0.0.0.0:0     ->          0.0.0.0:49964 ......   0    15240   20.9 M     3
2016-06-27 22:15:39.248 4294701.500 TCP            0.0.0.0:0     ->          0.0.0.0:50082 ......   0    14692   20.2 M     1
2016-06-27 21:05:43.972 4294783.806 TCP            0.0.0.0:0     ->          0.0.0.0:59628 ......   0    14468   19.5 M     1
2016-06-28 00:37:49.495 4289492.757 TCP            0.0.0.0:0     ->          0.0.0.0:58838 ......   0   295049   12.5 M     1
2016-06-27 22:12:42.597 4294667.462 TCP            0.0.0.0:0     ->          0.0.0.0:50064 ......   0     8330   11.3 M     1
```

There appears to be a significant amount of traffic towards the atypical port 12345. Let us investigate further to see where this may lead us.

```bash
nfdump -o long -R ./nfdump -A proto,srcip,dstip,dstport 'src ip 192.168.5.100 and proto tcp and dst port 12345'
Date first seen          Duration Proto      Src IP Addr:Port          Dst IP Addr:Port   Flags Tos  Packets    Bytes Flows
2016-08-16 14:49:41.839  4194.136 TCP      192.168.5.100:0     ->     192.168.5.10:12345 ......   0        2       92     2
2016-06-27 20:08:32.485 4319017.104 TCP    192.168.5.100:0     ->     36.98.102.89:12345 ......   0    1.1 M    1.5 G    85
2016-08-16 14:49:44.104  4194.179 TCP      192.168.5.100:0     ->     192.168.5.15:12345 ......   0        2       92     2
2016-08-16 15:59:31.538     0.115 TCP      192.168.5.100:0     ->      192.168.5.1:12345 ......   0        2       92     2
Summary: total flows: 91, total bytes: 1496690321, total packets: 1122052, avg bps: 2772, avg pps: 0, avg bpp: 1333
Time window: 2016-06-27 02:18:14 - 2016-08-16 23:52:04
Total flows processed: 50089, Blocks skipped: 0, Bytes read: 3719736
Sys: 0.005s flows/second: 9987836.5  Wall: 0.003s flows/second: 16385018.0
```

The destination for the suspicious traffic is the address 36.98.102.89:12345.

Next, let us examine the traffic on the local network:

```bash
nfdump -o long -R ./nfdump -A proto,srcip,dstip -O flows 'ip 192.168.5.100 and proto tcp and dst net 192.168.5.0/24' | head
Date first seen          Duration Proto      Src IP Addr:Port          Dst IP Addr:Port   Flags Tos  Packets    Bytes Flows
2016-08-16 14:49:41.996  4207.123 TCP      192.168.5.100:0     ->     192.168.5.15:0     ......   0     2824   129904  2824
2016-06-27 23:02:11.313 4297677.538 TCP      192.168.5.100:0     ->     192.168.5.10:0     ......   0    78176   89.1 M  2572
2016-06-27 23:01:56.613 4297692.238 TCP       192.168.5.10:0     ->    192.168.5.100:0     ......   0    48992    5.3 M  2408
2016-08-16 14:49:44.122  4189.718 TCP      192.168.5.100:0     ->      192.168.5.1:0     ......   0     1893    87078  1893
2016-08-16 11:50:07.935 11798.417 TCP      208.73.211.70:0     ->    192.168.5.100:0     ......   0      242    11132   121
2016-06-27 19:56:31.305 4303049.443 TCP     54.229.228.176:0     ->    192.168.5.100:0     ......   0    34081   46.2 M   114
2016-06-27 20:08:32.485 4319017.104 TCP       36.98.102.89:0     ->    192.168.5.100:0     ......   0   488224   45.0 M    84
2016-06-27 19:55:50.710 4313185.516 TCP        40.115.1.44:0     ->    192.168.5.100:0     ......   0      850   489171    75
2016-06-27 21:00:14.196 4296132.010 TCP     93.184.220.239:0     ->    192.168.5.100:0     ......   0     1679    1.6 M    61
```

There is a significant amount of traffic being directed towards three IP addresses on the local network: 192.168.5.15, 192.168.5.10, and 192.168.5.100.

```bash
nfdump -o long -R ./nfdump -A proto,srcip,dstip,dstport -O bytes 'ip 192.168.5.100 and proto tcp and dst net 192.168.5.0/24' | head
Date first seen          Duration Proto      Src IP Addr:Port          Dst IP Addr:Port   Flags Tos  Packets    Bytes Flows
2016-06-27 23:02:11.313 4297677.538 TCP      192.168.5.100:0     ->     192.168.5.10:22    ......   0    75840   89.0 M   244
2016-06-27 22:15:20.176 4294809.218 TCP        13.107.4.50:0     ->    192.168.5.100:50087 ......   0    25889   35.2 M     1
2016-06-27 21:08:52.091 4294720.356 TCP        13.107.4.50:0     ->    192.168.5.100:59694 ......   0    21598   29.1 M     1
2016-06-27 20:19:51.126 4294440.801 TCP     54.229.228.176:0     ->    192.168.5.100:49964 ......   0    15226   20.9 M     1
2016-06-27 22:15:39.248 4294701.500 TCP     54.229.228.176:0     ->    192.168.5.100:50082 ......   0    14692   20.2 M     1
2016-06-27 21:05:43.972 4294783.806 TCP        13.107.4.50:0     ->    192.168.5.100:59628 ......   0    14468   19.5 M     1
2016-06-28 00:37:49.495 4289492.757 TCP       36.98.102.89:0     ->    192.168.5.100:58838 ......   0   295049   12.5 M     1
2016-06-27 22:12:42.597 4294667.462 TCP        13.107.4.50:0     ->    192.168.5.100:50064 ......   0     8330   11.3 M     1
2016-06-27 22:01:12.808 4294888.784 TCP        13.107.4.50:0     ->    192.168.5.100:49913 ......   0     7890   10.8 M     1
```

It appears that there is a substantial amount of SSH packets being sent to 192.168.5.10.

Now, let us examine the flows to other ports:

```bash
ubuntu@ubuntu-caine:~/Desktop/forensic-demo/pfsense$ nfdump -o long -R ./nfdump -A proto,srcip,dstip,srcport -O flows 'ip 192.168.5.100 and proto tcp and dst net 192.168.5.0/24' | head -O flows 'ip 192.168.5.100 and proto tcp and dst net 192.168.5.0/24' | head
Date first seen          Duration Proto      Src IP Addr:Port          Dst IP Addr:Port   Flags Tos  Packets    Bytes Flows
2016-08-16 14:49:39.451  4196.709 TCP      192.168.5.100:62604 ->     192.168.5.10:0     ......   0     1918    88228  1918
2016-08-16 14:49:41.996  4196.428 TCP      192.168.5.100:41476 ->     192.168.5.15:0     ......   0     1702    78292  1702
2016-08-16 14:49:43.757  4205.362 TCP      192.168.5.100:41477 ->     192.168.5.15:0     ......   0     1122    51612  1122
2016-08-16 15:59:30.431     3.409 TCP      192.168.5.100:39690 ->      192.168.5.1:0     ......   0      946    43516   946
2016-08-16 14:49:44.122  4189.609 TCP      192.168.5.100:39689 ->      192.168.5.1:0     ......   0      944    43424   944
2016-08-16 14:49:41.507  4194.926 TCP      192.168.5.100:62605 ->     192.168.5.10:0     ......   0      410    18860   410
2016-06-27 23:01:56.613 4297692.238 TCP       192.168.5.10:22    ->    192.168.5.100:0     ......   0    46812    5.2 M   244
2016-08-16 11:50:07.935 11798.417 TCP      208.73.211.70:80    ->    192.168.5.100:0     ......   0      242    11132   121
2016-06-27 19:56:31.305 4303049.443 TCP     54.229.228.176:80    ->    192.168.5.100:0     ......   0    34081   46.2 M   114
```

We have observed flows originating from atypical ports (such as 62604, 41476, 41477, and so on) directed towards IP 192.168.5.100. It is possible that there is some form of network scanning taking place. Let us investigate the traffic originating from port 62604:

```bash
nfdump -o long -R ./nfdump -O flows 'src ip 192.168.5.100 and src port 62604 and proto tcp and dst net 192.168.5.0/24' | head
Date first seen          Duration Proto      Src IP Addr:Port          Dst IP Addr:Port   Flags Tos  Packets    Bytes Flows
2016-08-16 14:49:39.686  4194.296 TCP      192.168.5.100:62604 ->     192.168.5.10:135   ....S.   0        1       46     1
2016-08-16 14:50:10.198  4163.306 TCP      192.168.5.100:62604 ->     192.168.5.10:53    ....S.   0        1       46     1
2016-08-16 14:50:10.145  4163.300 TCP      192.168.5.100:62604 ->     192.168.5.10:22    ....S.   0        1       46     1
2016-08-16 14:50:10.360  4163.307 TCP      192.168.5.100:62604 ->     192.168.5.10:53    ....S.   0        1       46     1
2016-08-16 14:50:10.308  4163.300 TCP      192.168.5.100:62604 ->     192.168.5.10:22    ....S.   0        1       46     1
2016-08-16 15:59:36.160     0.000 TCP      192.168.5.100:62604 ->     192.168.5.10:1247  ....S.   0        1       46     1
2016-08-16 15:59:36.160     0.000 TCP      192.168.5.100:62604 ->     192.168.5.10:49156 ....S.   0        1       46     1
2016-08-16 15:59:36.159     0.000 TCP      192.168.5.100:62604 ->     192.168.5.10:106   ....S.   0        1       46     1
2016-08-16 15:59:36.159     0.000 TCP      192.168.5.100:62604 ->     192.168.5.10:2033  ....S.   0        1       46     1
```

The observed traffic seems to be a port scan since we only see one packet sent to commonly used ports.

Network forensic analysis: Squid Proxy
--

To avoid analyzing "normal" traffic, it's better to filter out requests related to Ubuntu packages being downloaded, such as requests to de.archive.ubuntu.com, opensuse, openSUSE, and novell.com. We can write filters in a file that can be passed to grep:

```bash
cat filter.txt
ubuntu.com
opensuse
openSUSE
novell.com


grep -v access.log -F -f filter.txt
1467994225.265    100 192.168.5.10 TCP_MISS/301 661 GET http://www.dfn-cert.de/index.html - HIER_DIRECT/193.174.13.92 text/html
1467994225.371     96 192.168.5.10 TCP_TUNNEL/200 17744 CONNECT www.dfn-cert.de:443 - HIER_DIRECT/193.174.13.92 -
1467998887.429      3 193.174.12.200 TCP_DENIED/403 3926 GET http://www.heise.de/ - HIER_NONE/- text/html
1468234574.617    266 192.168.5.15 TCP_MISS/200 185310 GET http://www.heise.de/ - HIER_DIRECT/193.99.144.85 text/html
1469198547.567    306 192.168.5.15 TCP_REFRESH_MODIFIED/200 181483 GET http://www.heise.de/ - HIER_DIRECT/193.99.144.85 text/html
1471356766.997     43 192.168.5.10 TCP_MISS/503 4151 GET http://bl/? - HIER_NONE/- text/html
1471356988.431  59783 192.168.5.10 TCP_MISS/503 4163 GET http://blog.mysportclub.ex/wp-content/uploads/hk/files/binaries-only.zip - HIER_DIRECT/54.229.228.176 text/html
1471357647.942  60185 192.168.5.10 TCP_MISS/503 4143 GET http://54.229.228.176/wp-content/uploads/hk/files/binaries-only.zip - HIER_DIRECT/54.229.228.176 text/html
```

The final GET request on the last line indicates the download of the "binaries-only.zip" file from 54.229.228.176 at Tue Aug 16 2016 16:27:27 GMT+0200 (Central European Summer Time) (converted UNIX time 1471357647.942).

The cache.log does not provide any extra insights. Below is the modified filter file for reviewing the log:

```bash
cat filter.txt ubuntu.com opensuse openSUSE novell.com ERROR Starting Squid Squid Cache CPU Usage Maximum Resident Size Page faults Service Name: squid FATAL
```
    

Conclusion
--

To conclude, we were able to identify some suspicious activities during our analysis of the nfdump files:

*   Extensive traffic to 36.98.102.89:12345
*   Extensive SSH traffic to 192.168.5.10
*   port scans (notably from 192.168.5.100:62604)

In summary, we identified several suspicious activities from our analysis of the nfdump files. Additionally, we discovered that a file named binaries-only.zip was downloaded from 54.229.228.176 on Tue Aug 16 2016 16:27:27 GMT+0200, as shown in the access.log file. I hope you found this tutorial and demo engaging. It was a pleasure exploring the Network Incident Response toolset from ENISA and testing out CAINE. Despite the outdated documents on their website, they still offer valuable insights for anyone interested in the field of cybersecurity.
