---
layout: post
title: Blackbird - An OSINT Tool
date: 2021-06-21 23:36 +0300
categories: [Tools & Frameworks, OSINT]
tags: [osint]
---





![](../../assets/img/osint/blackbird.png)

  

Blackbird
--

A tool for OSINT that quickly searches for accounts using a username on 581 different sites.

Developed and produced by the American aerospace company Lockheed Corporation, the Lockheed SR-71 "Blackbird" is a strategic reconnaissance aircraft capable of flying at high-altitude and Mach 3+ speeds over long distances.

Disclaimer
----------

The following program, whether current or previous, is intended solely for educational purposes. Any usage without permission is prohibited.

![](../../assets/img/osint/blackprev.png)

  

![](../../assets/img/osint/blackprev2.png)

  

Setup
--

Clone the repository

```bash
git clone https://github.com/p1ngul1n0/blackbird
```

```bash
cd blackbird
```

Install requirements

```bash
pip install -r requirements.txt
```

Usage
--

Search by username

```bash
python blackbird.py -u username
```

Run Webserver

```bash
python blackbird.py --web
```

Access [http://127.0.0.1:9797](http://127.0.0.1:9797) on the browser

Read the results file

```bash
python blackbird.py -f username.json
```

List supported sites

```bash
python blackbird.py --list-sites
```

Use proxy

```bash
python blackbird.py -u crash --proxy http://127.0.0.1:8080
```

Show all the results

The default setting displays only the discovered accounts, but you can view all of them by using the following argument.

```bash
python blackbird.py -u crash --show-all
```

Export results to CSV file

```bash
python blackbird.py -u crash --csv
```

Docker
--

Docker is also compatible with Blackbird.

Pull Image

```bash
docker pull p1ngul1n0/blackbird
```

Run Webserver

```bash
docker run -p 9797:9797 p1ngul1n0/blackbird "--web"
```

Metadata Extraction
--

Blackbird will attempt to extract the user's metadata whenever it is feasible, which includes information such as their name, bio, location, and profile picture.

Random UserAgent
--

To avoid being blocked, Blackbird selects a random UserAgent from a pool of [1000 UserAgents](https://gist.github.com/pzb/b4b6f57144aea7827ae4) for every request it makes.

Supersonic UserAgent
--

By enabling asynchronous HTTP requests, Blackbird significantly enhances the speed at which user accounts can be discovered.

 <br>
  

>`⚠ ONLY USE FOR EDUCATIONAL PURPOSES ⚠`
