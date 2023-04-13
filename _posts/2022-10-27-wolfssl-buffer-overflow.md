---
layout: post
title: wolfSSL Buffer Overflow
date: 2022-10-27 04:22 +0300
categories: [Exploits, Overflow]
tags: [exploits]
---








![](../../../assets/img/Exploits/wolfssl.png)

Before version 5.5.1 of wolfSSL, it was possible for nefarious clients to trigger a buffer overflow while resuming a TLS 1.3 handshake. An attacker could accomplish this by first sending a deliberately constructed Client Hello to resume a prior TLS session, followed by another similarly crafted Client Hello. This process required sending two Client Hellos: one masquerading as a session resumption request, and a second in response to a Hello Retry Request message.

  

```
SHA-256 | dc47311c0e4409688cd698016d1b6ec4010bff4dbccd63241e107b8a91774b58
```

```perl
    # wolfssl before 5.5.1: CVE-2022-39173 Buffer overflow when refining

    cipher suites
    ==================================================================================
    
    
    ## INFO
    =======
    
    The CVE project has assigned the id CVE-2022-39173 to this issue.
    
    Severity: high 7.5
    Affected version: before 5.5.1
    End of embargo: The embargo for this vulnerability ended 29th of September, 2022
    
    
    ## SUMMARY
    ==========
    
    In wolfSSL before 5.5.1 malicious clients can cause a buffer-overflow
    during a resumed TLS 1.3 handshake. If an attacker resumes a previous
    TLS session by sending a maliciously crafted Client Hello, followed by
    another maliciously crafted Client Hello. In total 2 Client Hellos
    have to be sent. One which pretends to resume a previous session and a
    second one as a response to a Hello Retry Request message.
    
    The malicious Client Hellos contain a list of supported cipher suites,
    which contain at least `⌊sqrt(150)⌋ + 1 = 13` duplicates and less than
    150 ciphers in total. The buffer-overflow occurs in the `RefineSuites`
    function. An overflow of 44700 bytes has been confirmed. Therefore,
    large portions of the stack can get overwritten, including return
    addresses.
    
    We confirmed the vulnerability by sending packets over TCP to a
    Wolfssl server, freshly built from the sources with the
    `--enable-session-ticket` flags (or simply `--enable-all`). We can
    provide sources for our software (tlspuffin) that produce those
    packets (and that automatically found the attack trace). The command
    given at the end of this document triggers the buffer overflow.
    
    It is very likely that there is a way to craft an exploit which can
    cause a RCE. We have not yet created such an exploit as it would
    likely depend on the memory layout of the binary which uses wolfSSL.
    
    Moreover, the size of the overflow can be fine-tuned in order to not
    smash the stack and continue the execution with a too large length of
    suites buffer and that will cause other routines that iterate over
    thus buffer (e.g., `FindSuiteSSL`) to misbehave. Hypothetically, this
    might be exploited to make the server use a cipher it should not
    accept such as `nullcipher` that would open up new attack vectors such
    as downgrade attacks.
    While this has not been confirmed yet, the buffer overflow itself has
    been confirmed.
    
    
    ## DETAILS
    ==========
    
    Line numbers below are valid for the wolfSSL Git tag
    [v5.4.0-stable](https://github.com/wolfSSL/wolfssl/tree/v5.4.0-stable).
    
    The bug we found is in the `RefineSuites` function. In the following
    we want to explain why the function is able to overflow the `suites`
    array.
    ```c
    /* Refine list of supported cipher suites to those common to server and client.
     *
     * ssl         SSL/TLS object.
     * peerSuites  The peer's advertised list of supported cipher suites.
     */
    static void RefineSuites(WOLFSSL* ssl, Suites* peerSuites)
    {
        byte   suites[WOLFSSL_MAX_SUITE_SZ];
        word16 suiteSz = 0;
        word16 i, j;
    
        XMEMSET(suites, 0, WOLFSSL_MAX_SUITE_SZ);
    
        for (i = 0; i < ssl->suites->suiteSz; i += 2) {
            for (j = 0; j < peerSuites->suiteSz; j += 2) {
                if (ssl->suites->suites[i+0] == peerSuites->suites[j+0] &&
                    ssl->suites->suites[i+1] == peerSuites->suites[j+1]) {
                    suites[suiteSz++] = peerSuites->suites[j+0];
                    suites[suiteSz++] = peerSuites->suites[j+1];
                }
            }
        }
    
        ssl->suites->suiteSz = suiteSz;
        XMEMCPY(ssl->suites->suites, &suites, sizeof(suites));
    #ifdef WOLFSSL_DEBUG_TLS
        [...]
```
{: .nolineno }

<br>

  

>*Source* :   [https://packetstormsecurity.com](https://packetstormsecurity.com)