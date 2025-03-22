---
title: "THM: Conti"
date: 2025-02-02
categories: [CTF, Blue Team]
tags: [CTF, Blue Team]
permalink: /posts/ctf-blueteam-conti
image:
  path: /assets/img/thumbnails/ctf-blueteam-conti.png
---


### **Walkthrough**

#### **CTF Platform**: TryHackMe  
#### **Level**: Medium  

#### **Tools Used**: 
- Splunk
- VirusTotal
- Sysmon

#### **Resources Used**: 
- Conti: [TryHackMe](https://tryhackme.com/room/contiransomwarehgh)
- Sysmon Event Logs 
- Splunk Queries
- CVE Research  


## **Steps for the CTF**

---

### **Overview**

Some employees from your company reported that they can’t log into Outlook. The Exchange system admin also reported that he can’t log in to the Exchange Admin Center. After initial triage, they discovered some weird `ReadMe.txt` files settled on the Exchange server.

---

#### **Question 1:** Can you identify the location of the ransomware?

Search for Sysmon event code `11` (file creation events) in Splunk. Filter for logs related to the creation of `ReadMe.txt` files and examine the `Image` field to locate suspicious executables. Look for unusual directories, such as `C:\Users\Administrator\Documents`, to identify the ransomware's location.

---

#### **Question 2:** What is the Sysmon event ID for the related file creation event?

The Sysmon event ID associated with file creation events is `11`. This event was used to track the creation of the `ReadMe.txt` files.

---

#### **Question 3:** Can you find the MD5 hash of the ransomware?

Search Splunk for logs containing the suspicious executable identified in Question 1. Include the `MD5` string in your query to filter for logs that include the hash of the executable. Once located, analyze the hash using a tool like VirusTotal to confirm its malicious nature.

---

#### **Question 4:** What file was saved to multiple folder locations?

Search for Sysmon event code `11` (file creation events) in Splunk. Focus on the `TargetFileName` field to identify files created in multiple locations. Look for patterns or repeated filenames across different directories to determine the file in question.

---

#### **Question 5:** What was the command the attacker used to add a new user to the compromised system?

Search Splunk for instances of the `net user` command, which is commonly used to create new users. Examine the `CommandLine` field to locate the exact command executed by the attacker, including any suspicious usernames or passwords.

---

#### **Question 6:** The attacker migrated the process for better persistence. What is the migrated process image (executable), and what is the original process image (executable) when the attacker got on the system?

Search for Sysmon event code `8` (`CreateRemoteThread` events) in Splunk. Examine the `SourceImage` and `TargetImage` fields to identify the original and migrated processes. Look for evidence of a suspicious process injecting into a legitimate system process for persistence.

---

#### **Question 7:** The attacker also retrieved the system hashes. What is the process image used for getting the system hashes?

Analyze the logs for evidence of process migration or suspicious activity involving authentication-related processes. Research common Windows processes involved in handling system hashes (e.g., `lsass.exe`) and identify the process image in the logs that aligns with this behavior.

---

#### **Question 8:** What is the web shell the exploit deployed to the system?

Search Splunk for logs containing `.aspx` extensions, which are commonly associated with web shells. Examine the `cs_uri_stem` field to locate suspicious files requested over HTTP/HTTPS. Identify the file that matches the characteristics of a web shell.

---

#### **Question 9:** What is the command line that executed this web shell?

Search Splunk for logs containing the name of the web shell identified in Question 8. Examine the `CommandLine` field to locate the exact command used to execute the web shell, including any additional parameters or flags.

---

#### **Question 10:** What three CVEs did this exploit leverage?

Research known vulnerabilities associated with the Conti ransomware. Look for credible sources that list the specific CVEs exploited by Conti and identify the three most relevant CVEs based on the context of the challenge.


