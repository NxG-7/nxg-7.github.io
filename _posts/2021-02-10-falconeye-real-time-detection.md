---
layout: post
title: FalconEye - Real-time detection
date: 2021-02-10 22:47 +0300
categories: [Tools & Frameworks, Malware]
tags: [malware]
---





FalconEye is a software designed for endpoint detection on Windows operating systems that specializes in detecting real-time process injections. This is accomplished through the use of a kernel-mode driver that is capable of identifying process injections as they occur. By operating in kernel mode, FalconEye offers a robust and dependable defense against process injection techniques that attempt to bypass user-mode hooks.

Architecture Overview
--

  

![](../../assets/img/malware/falconeye.png)

  

1\. The driver is an on-demand load driver

2\. The initialization includes setting up callbacks and syscall hooks via libinfinityhook

3\. The callbacks maintain a map of Pids built from cross process activity such as OpenProcess but it is not limited to OpenProcess

4\. Subsequent callbacks and syscall hooks use this Pid map to reduce the noise in processing. As a part of noise reduction, syscall hooks filter out same process activity.

5\. The detection logic is divided into subcategories namely - stateless (example: Atombombing), stateful (Unmap+Overwrite) and Floating code(Shellcode from multiple techniques)

6\. For stateful detections, syscall hooks record an ActionHistory which is implemented as a circular buffer. e.g. It records all the NtWriteVirtualMemory calls where the caller process is different from the target process.

7\. The detection logic has common anomaly detection functionality such as floating code detection and detection for shellcode triggers in remote processes. Both callbacks and syscall hooks invoke this common functionality for actual detection.

`NOTE`: We have been concentrating on detection rather than developing an efficient detection engine. Our endeavors in this area will persist beyond the BlackHat presentation.

Files
--

```yml
.
├── src
│   ├── FalconEye ---------------------------# FalconEye user and kernel space
│   └── libinfinityhook ---------------------# Kernel hook implementation
├── 2021BHASIA_FalconEye.pdf
└── README.md
```

Getting Started
--

Required
--------

*   Windows 10 Build 1903/1909
*   Microsoft Visual Studio 2019 onwards
*   Virtualization Software such as VmWare, Hyper-V (Optional)

Installation
---

Build
-----

1\. Open the solution with Visual Studio 2019

2\. Select x64 as build platform

3\. Build solution. This should generate FalconEye.sys binary under src\\kernel\\FalconEye\\x64\\Debug or src\\kernel\\FalconEye\\x64\\Release

Test Machine Setup
------------------

1\. Install Windows 10 Build 1903/1909 in a VM

2\. Configure VM for testing unsigned driver (Using bcdedit, disable integrity checks : BCDEDIT /set nointegritychecks ON)

3\. Run DbgView from sysinternals in the VM or start a debugging connection using WinDbg.

Usage
--

1\. Copy FalconEye.sys to the Test Machine (Windows 10 VM)

2\. Load FalconEye.sys as 'On Demand' load driver using OSR Loader or similar tools

3\. Run injection test tools such as pinjectra, minjector or other samples

4\. Monitor debug logs either via WinDbg or DbgView

References
--

[InfinityHook, 2019](https://github.com/everdox/InfinityHook/)

[Itzik Kotler and Amit Klein. Process Injection Techniques - Gotta Catch Them All, Blackhat USA Briengs, 2019](https://www.blackhat.com/us-19/briefings/schedule/#process-injection-techniques---gotta-catch-them-all-16010)

[Pinjectra, 2019](https://github.com/SafeBreach-Labs/pinjectra/)

[Mapping-Injection, 2020](https://github.com/antonioCoco/Mapping-Injection)

[Atombombing: Brand new code injection for windows, 2016](https://blog.ensilo.com/atombombing-brand-new-code-injection-for-windows)

[Propagate - a new code injection trick, 2017](http://www.hexacorn.com/blog/2017/10/26/propagate-a-new-code-injection-trick/)

[Windows process injection: Extra window bytes, 2018](https://modexp.wordpress.com/2018/08/26/process-injection-ctray/)

[Pavel Asinovsky. Diving into zberp's unconventional process injection technique, 2016](https://securityintelligence.com/diving-into-zberps-unconventional-process-injection-technique/)

[Rotem Kerner. Ctrl-inject, 2018](https://blog.ensilo.com/ctrl-inject)

[Windows process injection: Consolewindowclass, 2018](https://modexp.wordpress.com/2018/09/12/process-injection-user-data/)

[Windows process injection: Windows notication facility, 2018](https://modexp.wordpress.com/2019/06/15/4083/)

[A paradox: Writing to another process without openning it nor actually writing to it, 2007](http://blog.txipinet.com/2007/04/05/69-a-paradox-writing-to-another-process-without-openning-it-nor-actually-writing-to-it/)

[Windows process injection: Service control handler, 2018](https://modexp.wordpress.com/2018/08/30/windows-process-injection-control-handler/)

[Marcos Oviedo. Memhunter - Automated hunting of memory resident malware at scale. Defcon Demo Labs, 2019](https://github.com/marcosd4h/memhunter)

<br>
  


> `⚠ ONLY USE FOR EDUCATIONAL PURPOSES ⚠`

  

Source : [https://github.com/rajiv2790/FalconEye](https://github.com/rajiv2790/FalconEye)
