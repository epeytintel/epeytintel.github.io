---
layout: post
title: Zero2Auto Custom Sample 1
date: '2025-05-17 00:00:00 +0800'
categories: [Malware Analysis, CyberSecurity]
---

For this write-up, I will share my analysis for the first custom sample from Zero2Auto Malware Analysis Course. For anyone interested in exploring the course further, you can access it through this link: https://courses.zero2auto.com/

# Initial Triage

This sample comes with an instruction asking us to analyze the sample.

```
Hi there,  
  
During an ongoing investigation, one of our IR team members managed to locate an unknown sample on an infected machine belonging to one of our clients. We cannot pass that sample onto you currently as we are still analyzing it to determine what data was exfilatrated. However, one of our backend analysts developed a YARA rule based on the malware packer, and we were able to locate a similar binary that seemed to be an earlier version of the sample we're dealing with. Would you be able to take a look at it? We're all hands on deck here, dealing with this situation, and so we are unable to take a look at it ourselves.  
We're not too sure how much the binary has changed, though developing some automation tools might be a good idea, in case the threat actors behind it start utilizing something like Cutwail to push their samples.  
I have uploaded the sample alongside this email.  
  
Thanks, and Good Luck!

```


Test 

# Test Header

This is a test