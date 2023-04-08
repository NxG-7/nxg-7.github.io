---
layout: post
title: Socialhunter - Crawls The Website
date: 2021-06-16 02:09 +0300
categories: [Tools & Frameworks, OSINT]
tags: [osint]
---






![](../../assets/img/osint/socialhunter1.png)

  

Socialhunter is a tool that scans a provided URL to detect broken social media links that can be exploited for hijacking. Such broken links can potentially enable an attacker to carry out phishing attacks, which could result in a loss of the company's reputation. It's worth noting that the discovery of broken social media hijack issues is often eligible for recognition and reward in bug bounty programs.

At present, it is capable of supporting Twitter, Facebook, Instagram, and Tiktok without requiring any API keys.

<script async id="asciicast-wYMVXIHCxxOB3QPWq4Fe8Advn" src="https://asciinema.org/a/wYMVXIHCxxOB3QPWq4Fe8Advn.js"></script>

Installation
--

From Binary
-----------

```bash
wget https://github.com/utkusen/socialhunter/releases/download/v0.1.1/socialhunter_0.1.1_Linux_amd64.tar.gz
```

From Source
-----------

1\. Install Go on your machine.

2\. Run the following command:

```bash
go get -u github.com/utkusen/socialhunter
```

Usage
--

To run, Socialhunter needs two parameters.

1\. -f : Path of the text file that contains URLs line by line. The crawl function is path-aware. For example, if the URL is [https://utkusen.com/blog](https://utkusen.com/blog), it only crawls the pages under /blog path

2\. -w : The number of workers to run (e.g -w 10). The default value is 5. You can increase or decrease this by testing out the capability of your system.

 <br> 
  

>`⚠ ONLY USE FOR EDUCATIONAL PURPOSES ⚠`
