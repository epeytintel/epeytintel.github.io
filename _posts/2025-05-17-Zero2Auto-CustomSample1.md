---
layout: post
title: Zero2Auto Custom Sample 1
date: '2025-05-17 00:00:00 +0800'
categories:
    - Malware Analysis
    - Cyber Security
tags: [malware analysis, zero2auto]
---

For this write-up, I will share my analysis for the first custom sample from Zero2Auto Malware Analysis Course. For anyone interested in exploring the course further, you can access it through this link: [https://courses.zero2auto.com/](https://courses.zero2auto.com/)

# Initial Triage

This sample comes with an instruction asking us to analyze the sample.

![](/images/2025-05-17-Zero2Auto-CustomSample1/Screenshot_2025-05-17_03-17-34.png)

Let us now look at the sample
SHA1: 1b76e5a645a0df61bb4569d54bd1183ab451c95e

The sample is compiled in C++ and has high entropy in the `.text` and `.rsrc` section. There were also no interesting strings found in the file so we can assume that the initial sample is packed. 

![img-description](/images/2025-05-17-Zero2Auto-CustomSample1/20250312164000.png)


Upon execution in a controlled malware analysis environment, the sample spawns an  `svchost.exe` process, a sign that `Process Injection` techniques are likely being employed. 

![](/images/2025-05-17-Zero2Auto-CustomSample1/Pasted image 20250315221116.png)

Through analysis, I found that this sample runs in multiple stages, with each step revealing more of the hidden payload. Let's begin by diving into the first stage!

# First Stage 

Upon opening the sample in IDA, we see several functions that take hardcoded strings as input and use them with `LoadLibraryA` and `GetProcAddress`, likely to resolve API calls dynamically.

![img-description](/images/2025-05-17-Zero2Auto-CustomSample1/20250312183551.png)


