---
layout: post
title: WordPress WP Super Edit 2.5.4
date: 2021-05-06 04:06 +0300
categories: [Exploits, File Upload]
tags: [exploits]
---







![](../../../assets/img/Exploits/wpsuper.png)

An arbitrary file upload vulnerability has been detected in version 2.5.4 of the WordPress WP Super Edit plugin.

  

```
MD5 | 40b02ffb098a5c31c187c21257fe02c9
```

```perl
# Title: Wordpress Plugin WP Super Edit 2.5.4 - Remote File Upload
    # Author: h4shur
    # date: 2021-05-06
    # Vendor Homepage: https://wordpress.org
    # Software Link: https://wordpress.org/plugins/wp-super-edit/
    # Version : 2.5.4 and earlier
    # Tested on: Windows 10 & Google Chrome
    # Category : Web Application Bugs
    # Dork :
    # inurl:"wp-content/plugins/wp-super-edit/superedit/"
    # inurl:"wp-content/plugins/wp-super-edit/superedit/tinymce_plugins/mse/fckeditor/editor/filemanager/upload/"
    
    
    ### Note:
    
    # 1. Technical Description:
    This plugin allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment. Uploaded files represent a significant risk to applications. The first step in many attacks is to get some code to the system to be attacked. Then the attack only needs to find a way to get the code executed. Using a file upload helps the attacker accomplish the first step.The consequences of unrestricted file upload can vary, including complete system takeover, an overloaded file system or database, forwarding attacks to back-end systems, client-side attacks, or simple defacement. It depends on what the application does with the uploaded file and especially where it is stored.
    
    # 2. Technical Description:
    WordPress Plugin "wp-super-edit" allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment. This vulnerability is caused by FCKeditor in this plugin. Uploaded files represent a significant risk to applications. The first step in many attacks is to get some code to the system to be attacked. Then the attack only needs to find a way to get the code executed. Using a file upload helps the attacker accomplish the first step. The consequences of unrestricted file upload can vary, including complete system takeover, an overloaded file system or database, forwarding attacks to back-end systems, client-side attacks, or simple defacement. It depends on what the application does with the uploaded file and especially where it is stored.
    
    ### POC:
    
    * Exploit 1 : site.com/wp-content/plugins/wp-super-edit/superedit/tinymce_plugins/mse/fckeditor/editor/filemanager/browser/default/browser.html
    * Exploit 2 : site.com/wp-content/plugins/wp-super-edit/superedit/tinymce_plugins/mse/fckeditor/editor/filemanager/browser/default/connectors/test.html
    * Exploit 3 : site.com/wp-content/plugins/wp-super-edit/superedit/tinymce_plugins/mse/fckeditor/editor/filemanager/upload/test.html
    * Exploit 4 : site.com/wp-content/plugins/wp-super-edit/superedit/tinymce_plugins/mse/fckeditor/editor/filemanager/browser/default/frmupload.html
```

<br>

  

>*Source* :   [https://packetstormsecurity.com](https://packetstormsecurity.com)