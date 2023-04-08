---
layout: post
title: Aiodnsbrute - DNS Asynchronous
date: 2022-07-29 23:29 +0300
categories: [Tools & Frameworks, OSINT]
tags: [osint]
---





![](../../assets/img/osint/aiodns.png)

  

This tool utilizes asyncio in Python 3.5+ to carry out asynchronous brute force attacks on domain names.

Speed
--

The performance is impressive. Based on benchmarks conducted on small VPS hosts, the system can handle around 100k DNS resolutions in 1.5-2 minutes. Additionally, using an Amazon M3 box, the system was able to process 1 million requests in just over 3 minutes. However, actual results may vary. It is recommended to avoid using Google's resolvers if speed is your main concern.

Disclaimer
----------

1\. If you're looking for speed, it's likely that the DNS servers provided by your ISP and home router aren't very good. You might want to consider using a VPS with fast resolvers instead, or setting up your own.

2\. Please be advised that this tool has the potential to generate significant amounts of DNS traffic. Kindly note that I cannot be held liable if you inadvertently cause a Denial of Service (DoS) attack on someone's DNS servers.

Installation
--

```bash
pip install aiodnsbrute
```

`Note`: It is strongly advised to utilize a [virtualen](https://virtualenv.pypa.io/en/latest/userguide/#usage)

Alternate Install
--

```bash
git clone https://github.com/blark/aiodnsbrute.git
```

```bash
cd aiodnsbrute
```

```bash
python setup.py install .
```

Usage
--

```bash
aiodnsbrute --help

Usage: cli.py [OPTIONS] DOMAIN

  aiodnsbrute is a command line tool for brute forcing domain names
  utilizing Python's asyncio module.

  credit: blark (@markbaseggio)

Options:
  -w, --wordlist TEXT           Wordlist to use for brute force.
  -t, --max-tasks INTEGER       Maximum number of tasks to run asynchronosly.
  -r, --resolver-file FILENAME  A text file containing a list of DNS resolvers
                                to use, one per line, comments start with #.
                                Default: use system resolvers
  -v, --verbosity               Increase output verbosity
  -o, --output [csv|json|off]   Output results to DOMAIN.csv/json (extension
                                automatically appended when not using -f).
  -f, --outfile FILENAME        O   utput filename. Use '-f -' to send file
                                output to stdout overriding normal output.
  --query / --gethostbyname     DNS lookup type to use query (default) should
                                be faster, but won't return CNAME information.
  --wildcard / --no-wildcard    Wildcard detection, enabled by default
  --verify / --no-verify        Verify domain name is sane before beginning,
                                enabled by default
  --version                     Show the version and exit.
  --help                        Show this message and exit.
```

Usage
--

Perform a brute force operation with specific custom parameters:

```bash
aiodnsbrute -w wordlist.txt -vv -t 1024 domain.com
```

Execute a brute force operation, silence regular output, and exclusively transmit JSON data to the standard output.

```bash
aiodnbrute -f - -o json domain.com
```

If you require a more advanced pattern, you can employ customized resolvers and then direct the output through the powerful [jq tool](https://stedolan.github.io/jq/).

```bash
aiodnsbrute -r resolvers.txt -f - -o json google.com | jq '.[] | select(.ip[] | startswith("172."))'
```

By default, the detection of wildcards is enabled (it can be turned off using the flag "--no-wildcard").

```bash
aiodnsbrute foo.com

[*] Brute forcing foo.com with a maximum of 512 concurrent tasks...
[*] Using recursive DNS with the following servers: ['50.116.53.5', '50.116.58.5', '50.116.61.5']
[!] Wildcard response detected, ignoring answers containing ['23.23.86.44']
[*] Wordlist loaded, proceeding with 1000 DNS requests
[+] www.foo.com                         52.73.176.251, 52.4.225.20
100%|██████████████████████████████████████████████████████████████████████████████| 1000/1000 [00:   05<00:00, 140.18records/s]
```

The utilization of gethostbyname function can be advantageous in detecting CNAMEs, which is helpful in identifying potential subdomain takeover vulnerabilities.

```bash
aiodnsbrute --gethostbyname domain.com
```

To provide a list of resolvers from a file, omitting any blank lines and those starting with #, you can use the following command: "-r -" allows you to read the list from stdin.

```bash
aiodnsbrute -r resolvers.txt domain.com
```

`Note`: To determine the number of allowed open files, you could run the command "ulimit -n". Similarly, if you wish to increase this limit, you can utilize the same command by specifying a higher value, for instance, "ulimit -n <2048>".

<br>  
  

>`⚠ ONLY USE FOR EDUCATIONAL PURPOSES ⚠`