---
layout: post
title: pdfresurrect 0.15 Buffer Overflow
date: 2019-06-27 04:11 +0300
categories: [Exploits, Overflow]
tags: [exploits]
---







![](../../../assets/img/Exploits/pdf.png)

There is a buffer overflow vulnerability present in version 0.15 of pdfresurrect.

  

```
MD5 | 0b1d8046b3a8316d6ba8cc8c1309564f
```

```perl
    # Exploit Title: pdfresurrect 0.15 Buffer Overflow
    # Date: 2019-07-26
    # Exploit Author: j0lama
    # Vendor Homepage: https://github.com/enferex/pdfresurrect
    # Software Link: https://github.com/enferex/pdfresurrect
    # Version: 0.15
    # Tested on: Ubuntu 18.04
    # CVE : CVE-2019-14267
    
    Description
    ===========
    
    PDFResurrect 0.15 has a buffer overflow via a crafted PDF file because
    data associated with startxref and %%EOF is mishandled.
    
    
    Additional Information
    ======================
    
    There is a buffer overflow in pdfresurrect 0.14 caused by a malicious
     crafted pdf file.
    
    In function pdf_load_xrefs at pdf.c file, it counts how many times the
    strings '%%EOF' appear in the pdf file. Then for each xref the code
    starts to rewind incrementing the pos_count variable until found a 'f'
    character (the last character of the 'startxref' string). Then these
    bytes between the 'f' and '%%EOF' will be read with the 'fread'
    function and copied to a 256 char buffer. The 'pos_count' variable
    tells 'freads' how many bytes has to copy. If malicious user crafted a
    pdf file with more that 256 bytes between '%%EOF' and the immediately
    previous 'f' then a buffer overflow will occur overwriting everything
    after the 'buf' buffer.
    
    In the code:
    int pdf_load_xrefs(FILE *fp, pdf_t *pdf)
    {
        int  i, ver, is_linear;
        long pos, pos_count;
        char x, *c, buf[256];
    
        c = NULL;
    
        /* Count number of xrefs */
        pdf->n_xrefs = 0;
        fseek(fp, 0, SEEK_SET);
        while (get_next_eof(fp) >= 0)
          ++pdf->n_xrefs;
    
        if (!pdf->n_xrefs)
          return 0;
    
        /* Load in the start/end positions */
        fseek(fp, 0, SEEK_SET);
        pdf->xrefs = calloc(1, sizeof(xref_t) * pdf->n_xrefs);
        ver = 1;
        for (i=0; i<pdf->n_xrefs; i++)
        {
            /* Seek to %%EOF */
            if ((pos = get_next_eof(fp)) < 0)
              break;
    
            /* Set and increment the version */
            pdf->xrefs[i].version = ver++;
    
            /* Rewind until we find end of "startxref" */
            pos_count = 0;
            while (SAFE_F(fp, ((x = fgetc(fp)) != 'f'))) <== The loop will continue incrementing pos_count until find a 'f' char
              fseek(fp, pos - (++pos_count), SEEK_SET);
    
            /* Suck in end of "startxref" to start of %%EOF */
            memset(buf, 0, sizeof(buf));
            SAFE_E(fread(buf, 1, pos_count, fp), pos_count, <== If pos_count > 256 then a buffer overflow occur
                   "Failed to read startxref.\n");
            c = buf;
            while (*c == ' ' || *c == '\n' || *c == '\r')
              ++c;
    
            /* xref start position */
            pdf->xrefs[i].start = atol(c);
    
    This is a crafted PDF that produces a buffer overflow:
    
    http://www.mediafire.com/file/3540cyrl7o8p1rq/example_error.pdf/file
```
{: .nolineno }

<br>

  

>*Source* :   [https://packetstormsecurity.com](https://packetstormsecurity.com)
