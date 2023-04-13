---
layout: post
title: Wholeaked - A File-Sharing Tool
date: 2021-01-08 02:15 +0300
categories: [Tools & Frameworks, OSINT]
tags: [osint]
---






Written in Go, Wholeaked is a tool for file-sharing that enables you to track down the individual responsible in the event of a leak.

How?
---

Wholeaked is a tool that receives a file and a list of recipients to share it with. It then generates a distinct signature for each recipient and covertly embeds it into the file. The tool can use integrations like Sendgrid, AWS SES or SMTP to automatically send the files to their respective recipients. Alternatively, the files can be manually shared instead of being sent via email.

Wholeaked is compatible with all types of files, but it offers extra functionalities for popular file formats such as PDF, DOCX, MOV, and more.

Sharing Process
---------------

```
+-----------+
                                                       |Top Secret |
                                                       |.pdf       |
                                                       |           |
                                                      -|           |
                                                     / |           |
                                                    /  |Hidden     |
                                             a@gov /   |signature1 |
                                                  /    +-----------+
                                                 /     +-----------+
+-----------++-----------+                      /      |Top Secret |
|Top Secret ||Recipient  |                     /       |.pdf       |
|.pdf       ||List       |      +---------+   /        |           |
|           ||           |      |utkusen/ |  /  b@gov  |           |
|           ||a@gov      |----->|wholeaked| /----------+           |
|           ||b@gov      |      |         | \          |Hidden     |
|           ||c@gov      |      +---------+  \         |signature2 |
|           ||           |                    \        +-----------+
+-----------++-----------+                     \       +-----------+
                                                \      |Top Secret |
                                                 \     |.pdf       |
                                           c@gov  \    |           |
                                                   \   |           |
                                                    \  |           |
                                                     \ |Hidden     |
                                                      -|signature3 |
                                                       +-----------+    
 ```

Validation Part
---------------

If you want to identify the person who leaked the document, simply submit the leaked file to wholeaked. The platform will compare the signatures in its database and disclose the responsible individual.

```
+-----------+             +---------+
|Top Secret |             |Signature|
|.pdf       |  +---------+|Database |
|           |  |utkusen/ ||         |         Document leaked by
|           |->|wholeaked||         |--------+
|           |  |         ||         |              b@gov
|Hidden     |  +---------+|         |
|Signature2 |             |         |
+-----------+             +---------+
```

Demo
---

<iframe width="100%" height="455" src="https://www.youtube.com/embed/EEDtXp9ngHw" title="wholeaked Demonstration Video" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen></iframe>

File Types and Detection Modes
--

Wholeaked has the ability to add a distinctive signature to various sections of a file. The following detection modes are currently available:

`File Hash:` SHA256 hash of the file. All file types are supported.

`Binary:` The signature is directly added to the binary. Almost all file types are supported.

`Metadata:` The signature is added to a metadata section of a file. Supported file types: PDF, DOCX, XLSX, PPTX, MOV, JPG, PNG, GIF, EPS, AI, PSD

`Watermark:` An invisible signature is inserted into the text. Only PDF files are supported.

Installation
---

From Binary
-----------

One way to run the program is to download the pre-built binaries from the releases page, like this:

```bash
unzip wholeaked\_0.1.0\_macOS\_amd64.zip
```

```bash
./wholeaked --help
```

From Source
-----------

1.  Install Go on your system
2.  Run: 
```bash
go install github.com/utkusen/wholeaked@latest
```

Installing Dependencies
-----------------------

To utilize the signature addition feature in the metadata section of files, wholeaked necessitates exiftool. However, if you prefer not to utilize this feature, there is no need to install exiftool.

1.  Debian-based Linux: Run apt install exiftool
2.  macOS: Run brew install exiftool
3.  Windows: Download exiftool from here [https://exiftool.org/](https://exiftool.org/) and put the exiftool.exe in the same directory with wholeaked.

To verify watermarks inside PDF files, Wholeaked relies on pdftotext. However, if you do not intend to use this feature, there is no need to install it.

1.  Download "Xpdf command line tools" for Linux, macOS or Windows from here: [https://www.xpdfreader.com/download.html](https://www.xpdfreader.com/download.html)
2.  Extract the archive and navigate to bin64 folder.
3.  Copy the pdftotext (or pdftotext.exe) executable to the same folder with wholeaked
4.  For Debian Based Linux: Run apt install libfontconfig command.

Usage
--

Basic Usage
-----------

To use Wholeaked, you need to specify a project name (-n), the path to the base file to which the signatures will be added (-f), and a list of intended recipients (-t).

Example command: ./wholeaked -n test\_project -f secret.pdf -t targets.txt

The format for the content of the targets.txt file should include both the name and email address in the following manner:

```yml
Utku Sen,utku@utkusen.com
Bill Gates,bill@microsoft.com
```

After execution is completed, the following unique files will be generated:

```yml
test_project/files/Utku_Sen/secret.pdf
test_project/files/Bill_Gates/secret.pdf
```

The "File Types and Detection Modes" section in wholeaked defines all the available places where signatures are added by default. In case you wish to exclude a particular method, you can define it using a false flag. For instance:

```bash
./wholeaked -n test_project -f secret.pdf -t targets.txt -binary=false -metadata=false -watermark=false
```

Sending E-mails
---------------

To be able to send emails, you must complete certain sections within the CONFIG file.

*   If you want to send e-mails via Sendgrid, type your API key to the SENDGRID\_API\_KEY section.
    
*   If you want to send e-mails via AWS SES integration, you need to install awscli on your machine and add the required AWS key to it. wholeaked will read the key by itself. But you need to fill the AWS\_REGION section in the config file.
    
*   If you want to send e-mails via a SMTP server, fill the SMTP\_SERVER, SMTP\_PORT, SMTP\_USERNAME, SMTP\_PASSWORD sections.
    

The other necessary fields to fill:

*   EMAIL\_TEMPLATE\_PATH Path of the e-mail's body. You can specify use HTML or text format.
*   EMAIL\_CONTENT\_TYPE Can be html or text
*   EMAIL\_SUBJECT Subject of the e-mail
*   FROM\_NAME From name of the e-mail
*   FROM\_EMAIL From e-mail of the e-mail

To specify the sending method, you can use -sendgrid, -ses or -smtp flags. For example:

```bash
./wholeaked -n test_project -f secret.pdf -t targets.txt -sendgrid
```

Validating a Leaked File
------------------------

The -validate flag can be utilized to uncover the possessor of a leaked file. By comparing the signatures identified in the file with the database situated in the project folder, wholeaked will execute this task. Here is an example:

```bash
./wholeaked -n test_project -f secret.pdf -validate
```

`Important:` To utilize the file validation feature, it's essential to avoid deleting the project\_folder/db.csv file. If this file is removed, wholeaked won't be able to compare the signatures.

  
  

>`⚠ ONLY USE FOR EDUCATIONAL PURPOSES ⚠`
