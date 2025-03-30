---
title: "THM: Silver Platter"
date: 2025-03-03
categories: [CTF, Red Team]
tags: [CTF, Red Team]
permalink: /posts/ctf-silver-platter
image:
  path: /assets/img/thumbnails/ctf-silver-platter.png
---



### **Walkthrough**

#### **CTF Platform**: TryHackMe  
#### **Level**: Medium  

#### **Tools Used**:

- Nmap
- Dirsearch
- Burp Suite
- SSH Client

#### **Resources Used:**:

  - [Tryhackme](https://tryhackme.com/room/silverplatter)
  - `/usr/share/wordlists/rockyou.txt`


## **Steps for the CTF**

---

### **1. Reconnaissance**

The first step in any penetration test is reconnaissance—gathering as much information as possible about the target. In this case, we start by scanning the network using Nmap to identify open ports and running services.

```bash
nmap -sC -sV <ip>
```

**Command Used:**
```bash
death@esther:~$ nmap 10.10.12.168 -sV -sC
```

**Output:**
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-02 18:30 IST
Nmap scan report for 10.10.12.168
Host is up (0.16s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 1b:1c:87:8a:fe:34:16:c9:f7:82:37:2b:10:8f:8b:f1 (ECDSA)
|_  256 26:6d:17:ed:83:9e:4f:2d:f6:cd:53:17:c8:80:3d:09 (ED25519)
80/tcp   open  http       nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Hack Smarter Security
8080/tcp open  http-proxy
...
```

**Key Observations:**
- Port 22: SSH (OpenSSH 8.9p1 Ubuntu)
- Port 80: HTTP (nginx 1.18.0 Ubuntu)
- Port 8080: HTTP Proxy

---

### **2. Exploring the Web Application**

Since a web service is available on port 80, let's take a look at the web application.

#### **Enumerating Web Directories**
We use `dirsearch` to enumerate directories and files on port 80.

**Command Used:**
```bash
dirsearch -u 10.10.12.168
```

**Output Highlights:**
- `/assets` and `/images` were forbidden.
- `/LICENSE.txt` and `/README.txt` were accessible.

**Actionable Tip:**
Check `/LICENSE.txt` and `/README.txt` for any useful information or hints.

---

### **3. Enumerating HTTP Proxy**

Next, we enumerate the HTTP proxy on port 8080.

**Command Used:**
```bash
dirsearch -u 10.10.12.168:8080
```

**Key Findings:**
- Several paths redirected to `/noredirect.html`.
- The `/website` directory was forbidden.
- `/silverpeas` path hinted at the use of Silverpeas CMS.

---

### **4. Exploiting the Vulnerability**

Upon reaching the default login page, I noticed the version of the website was already displayed. This allowed me to search for any known exploits related to this version.

**Vulnerability Identified:**
- CVE-2024-36042: Authentication bypass vulnerability in Silverpeas CRM.

**Exploitation Steps:**
1. Use Burp Suite to intercept the login request.
2. Remove the `password` parameter from the intercepted request.
3. Follow the redirection to bypass authentication.

**Hint for the Viewer:**
Research the exploit details for CVE-2024-36042 and replicate the steps to bypass authentication.

---

### **5. Post-Exploitation**

After gaining access, navigate through the website to discover additional users (`admin`, `manager`) and an unread message containing SSH credentials.

**SSH Access:**
Use the discovered credentials to log in via SSH.

**Command Example:**
```bash
ssh tim@10.10.12.168
```

**Post-Exploitation Steps:**
1. Check user privileges with `id`.
2. Capture the `user.txt` flag in Tim's home directory.
3. Attempt to escalate privileges by checking other users' directories and logs.

**Hint for the Viewer:**
Look for sensitive information in `/var/log/auth*` logs to find Tyler's password.

---

### **6. Privilege Escalation**

Switch to Tyler's account using the discovered credentials and check sudo privileges.

**Command Example:**
```bash
su tyler
sudo -l
```

**Root Access:**
Tyler can execute all commands as root. Use `sudo su` to gain root access.

**Command Example:**
```bash
sudo su
```

**Capture the Root Flag:**
Read the `root.txt` flag in `/root`.
