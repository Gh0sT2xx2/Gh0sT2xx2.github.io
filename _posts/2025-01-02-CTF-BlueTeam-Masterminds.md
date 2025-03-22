---
title: "THM: Masterminds"
date: 2025-01-02
categories: [CTF, Blue Team]
tags: [CTF, Blue Team]
permalink: /posts/ctf-blueteam-masterminds
image:
  path: /assets/img/thumbnails/ctf-blueteam-masterminds.png
---


### **Walkthrough**

#### **CTF Platform**: TryHackMe  
#### **Level**: Medium

#### **Tools Used:**
- Brim
- Zeek (formerly Bro)
- Suricata
- VirusTotal
- URLhaus Database

#### **Resources Used:**
- Masterminds: [TryHackMe](https://tryhackme.com/room/mastermindsxlq)


### **Steps for the CTF**

---

#### **Task 2:** [Infection1.pcap]

**Provide the victim’s IP address.**

We will use the built-in queries to identify the victim IP. The correct IP can be identified as the only internal IP communicating with external IPs.

Another way to identify the IP address is by analyzing the total bytes transferred between endpoints:

```
_path=="conn" | put total_bytes := orig_bytes + resp_bytes | sort -r total_bytes | cut uid, id, orig_bytes, resp_bytes, total_bytes
```

Based on the results, the victim’s IP address can be identified due to its suspicious total number of bytes and the fact that it belongs to a private IP range.

---

**The victim attempted to make HTTP connections to two suspicious domains with the status ‘404 Not Found’. Provide the hosts/domains requested.**

```
_path=="http" | status_code==404 | cut host
```

---

**The victim made a successful HTTP connection to one of the domains and received the `response_body_len` of 1,309 (uncompressed content size of the data transferred from the server). Provide the domain and the destination IP address.**

Filter for HTTP connections with a status code of 200 and a response body length of 1,309:

```
_path=="http" | cut id.resp_h, host, status_code, response_body_len | 200 | 1309
```

---

**How many unique DNS requests were made to `cab[.]myfkn[.]com` domain (including the capitalized domain)?**

Use filters to count unique DNS queries to the specified domain.

---

**Provide the URI of the domain `bhaktivrind[.]com` that the victim reached out over HTTP.**

Filter for HTTP requests to the specific domain and extract the URI:

```
_path=="http" | cut host, uri | bhaktivrind.com
```

---

**Provide the IP address of the malicious server and the executable that the victim downloaded from the server.**

Filter for HTTP requests and analyze the source and destination IPs along with the downloaded file name:

```
_path=="http" | cut id.orig_h, id.resp_h, id.resp_p, method, host, uri | uniq -c
```

---

**Based on the information gathered from the second question, provide the name of the malware using VirusTotal.**

Upload or search for the binary hash obtained earlier in VirusTotal to identify the malware.

---

#### Task 3: [Infection2.pcap]

**Provide the IP address of the victim machine.**

We are going to use the same logic. Another thing to remember is that the IP address is within the same subnet.

```
_path=="conn" | put total_bytes := orig_bytes + resp_bytes | sort -r total_bytes | cut uid, id, orig_bytes, resp_bytes, total_bytes
```

---

**Provide the IP address the victim made the POST connections to.**

Filter for POST requests originating from the victim's IP and extract the destination IP:

```
method=="POST" | 192.168.75.146 | cut id.resp_h | sort -r | uniq
```

---

**How many POST connections were made to the IP address in the previous question?**

Count the number of POST requests made to the identified IP:

```
method=="POST" | 192.168.75.146 | cut id.resp_h | sort -r | uniq -c
```

---

**Provide the domain where the binary was downloaded from.**

Filter for HTTP requests and extract the domain and URI where the binary was downloaded:

With this filter, we can also answer the two next questions.

```
_path=="http" | cut id.resp_h, host, uri, mime_type | uniq
```

---

**Provide the name of the binary including the full URI.**

Extract the URI of the binary from the filtered HTTP requests.

---

**Provide the IP address of the domain that hosts the binary.**

Identify the IP address associated with the domain hosting the binary.

---

**There were 2 Suricata “A Network Trojan was detected” alerts. What were the source and destination IP addresses?**

Analyze Suricata alerts to identify the source and destination IPs involved.

---

**Taking a look at `.top` domain in HTTP requests, provide the name of the stealer (Trojan that gathers information from a system) involved in this packet capture using URLhaus Database.**

Search for the domain in URLhaus to identify the stealer's name.

---

#### **Task 4:** [Infection3.pcap]

**Provide the IP address of the victim machine.**

Same concept from the previous tasks, or I should say when analyzing network traffic.

```
_path=="conn" | put total_bytes := orig_bytes + resp_bytes | sort -r total_bytes | cut uid, id, orig_bytes, resp_bytes, total_bytes
```

---

**Provide three C2 domains from which the binaries were downloaded (starting from the earliest to the latest in the timestamp).**

Filter for HTTP requests and sort them by timestamp to identify the C2 domains:

```
_path=="http" | cut ts, id.orig_h, id.resp_h, id.resp_p, method, host, uri | uniq -c | sort ts
```

---

**Provide the IP addresses for all three domains in the previous question.**

We get the answer from the previous question, as shown in the filter result.

---

**How many unique DNS queries were made to the domain associated from the first IP address from the previous answer?**

Count the number of unique DNS queries made to the domain linked to the first IP:

```
_path=="dns" | count() by query | sort -r | efhoahegue.ru
```

---

**How many binaries were downloaded from the above domain in total?**

Filter for HTTP requests to the domain and count the number of binaries downloaded:

```
_path=="http" | efhoahegue.ru | cut uri, mime_type | uniq -c
```

---

**Provide the user-agent listed to download the binaries.**

Extract the user-agent used in the HTTP requests to the identified domain:

```
_path=="http" | efhoahegue.ru | cut uri, user_agent | uniq -c
```

---

**Provide the amount of DNS connections made in total for this packet capture.**

Count the total number of DNS connections in the packet capture:

```
_path=="dns" | count() by query | sort -r count | sum(count)
```

---

**With some OSINT skills, provide the name of the worm using the first domain you have managed to collect from Question 2. (Please use quotation marks for Google searches, don’t use .ru in your search, and DO NOT interact with the domain directly).**

Perform an OSINT investigation using the domain name to identify the worm's name.

