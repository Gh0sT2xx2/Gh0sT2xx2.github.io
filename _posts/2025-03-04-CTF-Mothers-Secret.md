---
title: "THM: Mother´s Secret"
date: 2025-03-05
categories: [CTF, Red Team]
tags: [CTF, Red Team]
permalink: /posts/ctf-mother-secret
image:
  path: /assets/img/thumbnails/ctf-mother-secret.png
---



### **Walkthrough**

#### **CTF Platform**: TryHackMe  
#### **Level**: Easy 

#### **Tools Used**:

- Burp Suite  
- Web Browser (for manual testing)  
- Basic Linux Commands  

#### **Resources Used:**:

- [TryHackMe](https://tryhackme.com/room/codeanalysis)  
- Code Analysis Techniques  
- YAML File Documentation  


## **Steps for the CTF**

---

### Initial Hints
The Operating Manual gives us the following hint:
- **What is the number of the emergency command override?**
  - Answer: `100375`
  - This number seems significant and might represent a variable or a filename.

Additionally, we are provided with a configuration document named `router(2).txt`, which contains two configuration files. After starting the machine and performing basic enumeration, only ports **22 (SSH)** and **80 (HTTP)** are open.

---

### Step 1: Analyzing the First Configuration File (`yaml.js`)
The first configuration file, `yaml.js`, defines a router that processes POST requests. Here are the key points from the code:

1. The router checks if the uploaded file is a YAML file using the `isYaml()` function.
2. If valid, it reads the file and returns the parsed JavaScript data to the client at the `/yaml` endpoint.

#### Task for You:
- Visit the `/yaml` endpoint on the target machine's IP address.
- Use **Burp Suite** to intercept the request and change the HTTP method from `GET` to `POST`.
- Add a `file_path` parameter in the request body pointing to a YAML file.
- Test with the filename `100375.yaml` (derived from the emergency command override).

#### Expected Outcome:
You should retrieve the answer to the second question:  
**What is the special order number?**

---

### Step 2: Exploring the Second Router (`nostromo.js`)
The second configuration file, `nostromo.js`, defines two routes:
1. `/api/nostromo`: Processes POST requests and authenticates the user by setting `isNostromoAuthenticate` to `true`.
2. `/api/nostromo/mother`: Requires both `isNostromoAuthenticate` and `isYamlAuthenticate` to be `true` before processing requests.

#### Task for You:
- Send a POST request to `/api/nostromo` with the `file_path` parameter pointing to `0rd3r937.txt`.
- Once authenticated, send another POST request to `/api/nostromo/mother` with the `file_path` parameter pointing to `secret.txt`.

#### Expected Outcome:
You will uncover the following flags:
- **What is the hidden flag in the Nostromo route?**
- **What is the name of the Science Officer with permissions?**
- **What are the contents of the classified "Flag" box?**

---

### Step 3: Discovering Mother's Secret
From the hints in the Operating Manual, we know there is a file located at `/opt/m0th3r`. Using techniques like **Local File Inclusion (LFI)**, you can access this file.

#### Task for You:
- Append `/../` to the `file_path` parameter in your POST request to traverse directories.
- Access the file located at `/opt/m0th3r`.

#### Expected Outcome:
You will find the final flag:
- **What is Mother's secret?**
