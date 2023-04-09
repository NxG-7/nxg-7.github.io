---
layout: post
title: Online Learning Management System 1.0
date: 2020-12-23 01:14 +0300
categories: [Exploits, Cross-Site Scripting (XSS)]
tags: [exploits]
---






![](../../../assets/img/Exploits/onlinelearn.png)

There are various cross-site scripting vulnerabilities present in version 1.0 of the Online Learning Management System.

  

```
MD5 | 68e69d9e1042cc074baef57a56b42176
```

```perl
    # Exploit Title:  Online Learning Management System 1.0 - Multiple Stored XSS
    # Exploit Author: Aakash Madaan (Godsky)
    # Date: 2020-12-22
    # Vendor Homepage: https://www.sourcecodester.com/php/7339/learning-management-system.html
    # Software Link: https://www.sourcecodester.com/download-code?nid=7339&amp;title=Online+Learning+Management+System+using+PHP%2FMySQLi+with+Source+Code
    # Affected Version: Version 1
    # Category: Web Application
    # Tested on: Parrot OS
    
    [+] Step 1. Login to the application with admin credentials
    
    
    [+] Step 2.1
    
        (a). Click on &quot;Subject&quot; page.  {Uri :http(s)://&lt;host&gt;/admin/subject.php}
        (b). Now click on the &quot;Add Subject&quot; button to add a new subject.
        (c). In the &quot;Subject Title&quot; field, use XSS payload '&quot;&gt;&lt;script&gt;alert(&quot;subject&quot;)&lt;/script&gt;' as the name of new course (Also fill the respective sections if required).
        (d). Click on &quot;Save&quot; when done and this will trigger the Stored XSS payloads. Whenever you click on &quot;Subject&quot; section, your XSS Payloads will be triggered.
    
    [+] Step 2.2
    
        (a). Click on &quot;Class&quot; page.  {Uri : http(s)://&lt;host&gt;/admin/class.php}
        (b). Under the &quot;Add class&quot; in the &quot;Class Name&quot; field, use XSS payload '&quot;&gt;&lt;script&gt;alert(&quot;class&quot;)&lt;/script&gt;' as the name of new course.
        (c). Click on &quot;Save&quot; when done and this will trigger the Stored XSS payloads. Whenever you click on &quot;Class&quot; section, your XSS Payloads will be triggered.
    
    [+] Step 2.3
    
        (a). Click on &quot;Admin Users&quot; page.  {Uri :http(s)://&lt;host&gt;/admin/admin_user.php}
        (b). Under the &quot;Add user&quot; in the &quot;First Name&quot; field, use XSS payload '&quot;&gt;&lt;script&gt;alert(&quot;Admin User&quot;)&lt;/script&gt;' as the name of new course (Also fill the respective sections if required).
                  [ Note : The XSS can also be triggered if we put the same payload in &quot;Last Name&quot; or &quot;Username&quot; fields ]
        (c). Click on &quot;Save&quot; when done and this will trigger the Stored XSS payloads. Whenever you click on &quot;Admin Users&quot;, your XSS Payloads will be triggered.
    
    [+] Step 2.4
    
        (a). Click on &quot;Department&quot; page.  {Uri :http(s)://&lt;host&gt;/admin/department.php}
        (b). In the &quot;Department&quot; field, use XSS payload '&quot;&gt;&lt;script&gt;alert(&quot;Department&quot;)&lt;/script&gt;' as the name of new course (Also fill the respective sections if required).
                  [ Note : The XSS can also be triggered if we put the same payload in &quot;Person Incharge&quot; field ]
        (c). Click on &quot;Save&quot; when done and this will trigger the Stored XSS payloads. Whenever you click on &quot;Department&quot;, your XSS Payloads will be triggered.
    
    [+] Step 2.5
    
        (a). Click on &quot;Students&quot; page.  {Uri :http(s)://&lt;host&gt;/admin/students.php}
        (b). Under &quot;Add Student&quot; in the &quot;First Name&quot; field, use XSS payload '&quot;&gt;&lt;script&gt;alert(&quot;students&quot;)&lt;/script&gt;' as the name of new course (Also fill the respective sections if required).
                  [ Note : The XSS can also be triggered if we put the same payload in &quot;Last Name&quot; field ]
        (c). Click on &quot;Save&quot; when done and this will trigger the Stored XSS payloads. Whenever you click on &quot;Students&quot;, your XSS Payloads will be triggered.
    
    [+] Step 2.6
    
        (a). Click on &quot;Teachers&quot; page.  {Uri :http(s)://&lt;host&gt;/admin/teachers.php}
        (b). Under &quot;Add Student&quot; in the &quot;First Name&quot; field, use XSS payload '&quot;&gt;&lt;script&gt;alert(&quot;students&quot;)&lt;/script&gt;' as the name of new course (Also fill the respective sections if required).
                  [ Note : The XSS can also be triggered if we put the same payload in &quot;Last Name&quot; field ]
        (c). Click on &quot;Save&quot; when done and this will trigger the Stored XSS payloads. Whenever you click on &quot;Teachers&quot;, your XSS Payloads will be triggered.
    
    [+] Step 3. This should trigger the XSS payload and anytime you click on respective pages, your stored XSS payloads will be triggered.

```

<br>

  

>*Source* :   [https://packetstormsecurity.com](https://packetstormsecurity.com)
