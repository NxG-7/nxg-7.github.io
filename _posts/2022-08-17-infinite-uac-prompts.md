---
layout: post
title: Infinite UAC Prompts
date: 2022-08-17 23:00 +0300
categories: [Tools & Frameworks, Malware]
tags: [malware]
---




![](../../assets/img/malware/infinite.png)

ForceAdmin is a C# tool that constructs payloads to generate an infinite number of UAC (User Account Control) pop-ups until the user consents to run the program. The tool executes inputted commands through PowerShell, invoking cmd.exe, and requires the batch syntax to be used. Its purpose is to overcome situations where UAC bypass techniques are not feasible due to users having their UAC settings configured to "always show." With this attack, the user is compelled to run the program as an administrator, effectively bypassing the UAC settings.

Demo Preview
--

![](../../assets/img/malware/infinitedemo.gif)

Required
--

For building on your own, the following NuGet packages are needed

*   Fody: "Extensible tool for weaving .net assemblies."
*   Costura.Fody "Fody add-in for embedding references as resources."
*   Microsoft.AspNet.WebApi.Client "This package adds support for formatting and content negotiation to System.Net.Http. It includes support for JSON, XML, and form URL encoded data."

Installation
--

1\. Download the project:

```bash
git clone https://github.com/catzsec/ForceAdmin.git
```

2\. Enter the project folder:

```bash
cd ForceAdmin
```

3\. Run ForceAdmin:

```bash
dotnet run
```

4\. Compile ForceAdmin:

```bash
dotnet publish -r win-x64 -c Release -o ./publish/
```
<br>
  

> `⚠ ONLY USE FOR EDUCATIONAL PURPOSES ⚠`
