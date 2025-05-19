---
layout: post
title: Pivoting Coldriver APT Infrastructure
date: '2025-05-17 00:00:00 +0800'
categories: [Adversary Infrastructure]
tags: [APT, Threat Intelligence]
image:
    path: /images/2025-05-17-Coldriver-Lostkeys/frozen-river.webp
---

# Introduction

Recently, Google Threat Intelligence Group (GTIG) has shared a new malware used by COLDRIVER which they called as LOSTKEYS. LOSTKEYS can steal specific files from hard-coded list of extensions and directories. It also collects system information and running processes from the victim's machine and send it to the attacker. 

In this write-up, I'll be sharing some of my findings and YARA rules to look for other IOCs related to COLDRIVER. 

You can read Google's original blog post here: [COLDRIVER Using New Malware To Steal Documents From Western Targets and NGOs](https://cloud.google.com/blog/topics/threat-intelligence/coldriver-steal-documents-western-targets-ngos)


# Stage 1 - Initial Access via ClickFix

LOSTKEYS is delivered using a Social Engineering technique known as `CLICKFIX`. In this method, the attacker creates a lure website that displays a fake CAPTCHA to trick the victim to "complete" a fake verification step. Instead of solving a real CAPTCHA, the victim is instructed to copy and paste a command into Windows `RUN` dialog. The command is actually a malicious Powershell command that will execute the malware.

According to the blog, the second stage will be retrieved from `165.227.148[.]68`. They also shared the SHA1 of the HTML file used for the fake CAPTCHA page.

SHA1: ff9824395c18e1cf70960862654eb0a8b012eeaa

Analyzing the file, we spot the malicious command copied to the clipboard. The command will execute a Powershell script that will download the next payload from the attacker's C2 via GET request.  

![img-description](/images/2025-05-17-Coldriver-Lostkeys/fake_captcha.png)

We can also create a YARA rule to monitor new similar samples in VirusTotal

```yara
rule Trojan_LOSTKEYS_ClickFix
{
meta:
	Description = "COLDRIVER - LOSTKEYS Stage 1 ClickFix"	
	Author = "epeyt-intel"
	Reference = "https://cloud.google.com/blog/topics/threat-intelligence/coldriver-steal-documents-western-targets-ngos"											

strings:
	$html1 = "<html"
	$html2 = "<head>"

	$url = "https://drive.proton.me"
	$command1 = "cmd /c start"
	$command2 = "powershell -c"
	$command3 = "Allow Capture request"
	$command4 = "GET"
	$command5 = "Invoke-Expression"

	$clickfix1 = "is_human"
	$clickfix2 = "verify"
	$clickfix3 = "captcha"
	$clickfix4 = "copyTextToClipboard"

condition:
	all of ($html*)
	and $url 
	and all of ($command*)
	and 3 of ($clickfix*)

}
```

This information can serve as a useful pivot point for identifying additional infrastructure used by the COLDRIVER in this related campaign.

# Stage 2 - Anti VM

Stage 2 is responsible for checking if the environment the malware was executed is a Virtual Machine. It checks this by calculating the MD5 hash of the display resolution and compare it with the 3 hardcoded hash values. If it passess the Anti VM check, it will proceed to download Stage 3.

![img-description](/images/2025-05-17-Coldriver-Lostkeys/stage2.png)

We can also create a YARA rule to monitor new similar samples in VirusTotal. 

```yara
rule Trojan_LOSTKEYS_Stage2Loader
{
meta:
	Description = "COLDRIVER - LOSTKEYS Stage 2 Powershell - Anti VM"	
	Author = "epeyt-intel"
	Reference = "https://cloud.google.com/blog/topics/threat-intelligence/coldriver-steal-documents-western-targets-ngos"											

strings:
	
	$res_hash1 = "8c8a58fa97c205ff222de3685497742c"
	$res_hash2 = "052335232b11864986bb2fa20fa38748"
	$res_hash3 = "e6c2dc3dee4a51dcec3a876aa2339a78"

	$command1 = "GET"
	$command2 = "http"
	$command3 = "Invoke-Expression"
	$command4 = "FromBase64String"
	$command5 = "ComputeHash"
	$command6 = "MD5CryptoServiceProvider"
	$command7 = "CurrentVerticalResolution"
	$command8 = "Win32_VideoController"


condition:
	all of ($res_hash*)
	and all of ($command*)

}
```


This time we discovered a new sample with low detection. The sample is similar to the IOC mentioned on the blog and just differs on the identifier for the request in retrieving the next stage.

**SHA1: e6e6648e087971cd311c3d2c27a0477fea674ded**
![img-description](/images/2025-05-17-Coldriver-Lostkeys/newstage2.png)


# Pivoting similar C2

According to the blog, the same IP address (*165.227.148[.]68*) was repeatedly used to download subsequent stages of the malware. For pivoting similar C2, we will also use the findings we got from the Stage 1 Loader. 

We can search the IP address in *urlscan.io*. [https://urlscan.io/search/#165.227.148.68](https://urlscan.io/search/#165.227.148.68)

![img-description](/images/2025-05-17-Coldriver-Lostkeys/urlscan1.png)

Most of the recent scans for this IP are currently down, and the response size was  *784 bytes*

![img-description](/images/2025-05-17-Coldriver-Lostkeys/error404.png)

We can check for older scans that returned a different response size to check for the site when it is still active and gain further insight into its past activity.

![img-description](/images/2025-05-17-Coldriver-Lostkeys/urlscan2.png)

We identified a scan from one month ago with a different response body and size. It has a Russian page title: **"Настоящее время"** which translates to **"Present Tense"**.

![img-description](/images/2025-05-17-Coldriver-Lostkeys/cloudmediaportal.png)

Since this is a ClickFix distribution, we can examine the DOM (Document Object Model) to check its HTML source code and identify any embedded malicious components

![img-description](/images/2025-05-17-Coldriver-Lostkeys/dom1.png)

Upon analyzing the code, we found a function that is part of the **ClickFix Stage 1 Loader**. This function executes a powershell command to download the next stage of the malware.

![img-description](/images/2025-05-17-Coldriver-Lostkeys/maldom1.png)

## Finding other C2 servers

By examining the code within the HTML response body, we can extract malicious functions and indicators that we can use to query similar C2 infrastructures.

To pivot, we can use [FOFA](https://en.fofa.info/) to identify additional C2 addresses containing the same function within their HTML response bodies.

[https://en.fofa.info/result?qbase64=ImZ1bmN0aW9uIGNvcHlUZXh0VG9DbGlwYm9hcmQodGV4dCkiICYmICJjbWQgL2Mgc3RhcnQgL21pbiBwb3dlcnNoZWxsIg%3D%3D](https://en.fofa.info/result?qbase64=ImZ1bmN0aW9uIGNvcHlUZXh0VG9DbGlwYm9hcmQodGV4dCkiICYmICJjbWQgL2Mgc3RhcnQgL21pbiBwb3dlcnNoZWxsIg%3D%3D)

```
"function copyTextToClipboard(text)" && "cmd /c start /min powershell"
```

From this query, we identified two IP addresses, including the one previously mentioned in the report:
- `165.227.148[.]68` — `cloudmediaportal[.]com`
- `193.43.104[.]109` — `mobilizationcenter[.]com.ua` **(new)**

## Verifying discovered C2 Servers

The newly discovered c2 has low detection on VirusTotal and currently does not have any community comments.

*mobilizationcenter[.]com.ua*
![img-description](/images/2025-05-17-Coldriver-Lostkeys/newc2.png)

We can query the newly discovered domain on [urlscan.io](https://urlscan.io) to gather additional information and to verify if this is part of the campaign.

![img-description](/images/2025-05-17-Coldriver-Lostkeys/urlscan3.png)

By examining the DOM, we can verify that this domain is part of the COLDRIVER infrastructure and is responsible for downloading the next stage from _165.227.148[.]68_, similar with the initial C2 identified in the blog.

![img-description](/images/2025-05-17-Coldriver-Lostkeys/newc2verify.png)


---

# LOSTKEYS IOCs
## additional samples
- e6e6648e087971cd311c3d2c27a0477fea674ded - Stage 2 Loader

## Additional C2
- 193.43.104[.]109 - mobilizationcenter[.]com.ua






