---
layout: post
title: Zero2Auto Custom Sample 1
date: '2025-05-17 00:00:00 +0800'
categories: [Malware Analysis, CyberSecurity]
tags: [malware analysis, zero2auto]
---

For this write-up, I will share my analysis for the first custom sample from Zero2Auto Malware Analysis Course. For anyone interested in exploring the course further, you can access it through this link: [https://courses.zero2auto.com/](https://courses.zero2auto.com/)

# Initial Triage

This sample comes with an instruction asking us to analyze the sample.

```
Hi there,  
  
During an ongoing investigation, one of our IR team members managed to locate an unknown sample on an infected machine belonging to one of our clients. We cannot pass that sample onto you currently as we are still analyzing it to determine what data was exfilatrated. However, one of our backend analysts developed a YARA rule based on the malware packer, and we were able to locate a similar binary that seemed to be an earlier version of the sample we're dealing with. Would you be able to take a look at it? We're all hands on deck here, dealing with this situation, and so we are unable to take a look at it ourselves.  

We're not too sure how much the binary has changed, though developing some automation tools might be a good idea, in case the threat actors behind it start utilizing something like Cutwail to push their samples.  
I have uploaded the sample alongside this email.  
  
Thanks, and Good Luck!

```

Let us now look at the sample
SHA1: 1b76e5a645a0df61bb4569d54bd1183ab451c95e

The sample is compiled in C++ and has high entropy in the .text and .rsrc section. There were also no interesting strings found in the file so we can assume that the initial sample is packed. 

![[images/2025-05-17-Zero2Auto-CustomSample1/Pasted image 20250312164000.png]]

Upon execution in a controlled malware analysis environment, the sample spawns an  `svchost.exe` process, a sign that process injection techniques are likely being employed. 

Through analysis, I found that this sample runs in multiple stages, with each step revealing more of the hidden payload. Let's begin by diving into the first stage!

# First Stage 

Upon opening the sample in IDA, we see several functions that take hardcoded strings as input and use them with `LoadLibraryA` and `GetProcAddress`, likely to resolve API calls dynamically.

![[images/2025-05-17-Zero2Auto-CustomSample1/Pasted image 20250312183551.png]]
