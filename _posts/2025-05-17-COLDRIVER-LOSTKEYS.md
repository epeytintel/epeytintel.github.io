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

For pivoting similar C2, we will use the information we got from the Stage 1 Loader. 




