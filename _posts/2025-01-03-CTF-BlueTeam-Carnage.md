---
title: "THM: Carnage"
date: 2025-01-03
categories: [CTF, Blue Team]
tags: [CTF, Blue Team]
permalink: /posts/ctf-blueteam-carnage
image:
  path: /assets/img/thumbnails/ctf-blueteam-carnage.png
---


### **Walkthrough**

#### **CTF Platform**: TryHackMe  
#### **Level**: Medium  

#### **Tools Used**:

- Wireshark  

#### **Resources Used:**: 

- Carnage: [TryHackMe](https://tryhackme.com/room/c2carnage)
- VirusTotal
- Wireshark Documentation 



## **Steps for the CTF**

---

#### **1. What was the date and time for the first HTTP connection to the malicious IP?**
- Navigate to `View > Time Display Format > UTC Date and Time of Day` to set a human-readable timestamp format.
- Filter HTTP traffic using `http`.
- Use `Statistics > HTTP > Requests` to identify the malicious IP and locate the timestamp of the first HTTP connection.

---

#### **2. What is the name of the zip file that was downloaded?**
- Apply the filter: `http.host == "attirenepal.com"`.
- Analyze the HTTP requests and responses to locate the name of the downloaded zip file.

---

#### **3. What was the domain hosting the malicious zip file?**
- Apply the same filter: `http.host == "attirenepal.com"`.
- The domain name will be visible in the filtered packets.

---

#### **4. Without downloading the file, what is the name of the file in the zip file?**
- Follow the TCP stream for relevant traffic (e.g., `tcp.stream eq 73`).
- Look for references to the file name within the stream.

---

#### **5. What is the name of the webserver of the malicious IP from which the zip file was downloaded?**
- Search for the `.xls` file in the packet strings.
- Use `tcp.stream eq 73` to locate the webserver name in the HTTP headers.

---

#### **6. What is the version of the webserver from the previous question?**
- In the same TCP stream (`tcp.stream eq 73`), look for the `x-powered-by` header to identify the webserver version.

---

#### **7. Malicious files were downloaded to the victim host from multiple domains. What were the three domains involved with this activity?**
- Enable `View > Name Resolution > Resolve Network Addresses` to translate IPs into domain names.
- Analyze the traffic to identify the domains involved in downloading malicious files.

---

#### **8. Which certificate authority issued the SSL certificate to the first domain from the previous question?**
- Filter the traffic for the specific domain (e.g., `tcp.stream eq 90`).
- Look for the certificate details in the SSL/TLS handshake packets.

---

#### **9. What are the two IP addresses of the Cobalt Strike servers?**
- Go to `Statistics > Conversations > TCP Tab`.
- Look for patterns such as repeated packets of the same size.
- Verify suspected IPs using VirusTotal to confirm if they are Cobalt Strike servers.

---

#### **10. What is the Host header for the first Cobalt Strike IP address from the previous question?**
- Apply the filter: `ip.addr == <Cobalt Strike IP>`.
- Follow the TCP stream to locate the Host header.

---

#### **11. What is the domain name for the first IP address of the Cobalt Strike server?**
- With Name Resolution enabled, check the Source column for the domain name associated with the IP.
- Verify the domain using VirusTotal.

---

#### **12. What is the domain name of the second Cobalt Strike server IP?**
- Apply the filter: `ip.addr == <Second Cobalt Strike IP>`.
- Follow the TCP stream to locate the domain name.
- Verify the domain using VirusTotal.

---

#### **13. What is the domain name of the post-infection traffic?**
- Analyze the post-infection traffic for domain names.
- Look for suspicious domains in the HTTP or DNS traffic.

---

#### **14. What are the first eleven characters that the victim host sends out to the malicious domain involved in the post-infection traffic?**
- Analyze the TCP/HTTP stream for POST requests.
- Identify the first eleven characters of the data being sent.

---

#### **15. What was the length for the first packet sent out to the C2 server?**
- Locate the first packet sent to the C2 server.
- Check the packet details for its length.

---

#### **16. What was the Server header for the malicious domain from the previous question?**
- Analyze the HTTP stream for the Server header.
- Extract the value from the response headers.

---

#### **17. The malware used an API to check for the IP address of the victim’s machine. What was the date and time when the DNS query for the IP check domain occurred?**
- Apply the filter: `dns && frame contains "api"`.
- Locate the DNS query packet and extract the timestamp.

---

#### **18. What was the domain in the DNS query from the previous question?**
- Use the same filter: `dns && frame contains "api"`.
- Extract the domain name from the DNS query.

---

#### **19. Looks like there was some malicious spam (malspam) activity going on. What was the first MAIL FROM address observed in the traffic?**
- Remove all filters and search for `MAIL FROM`.
- Locate the email address in the SMTP traffic.

---

#### **20. How many packets were observed for the SMTP traffic?**
- Go to `Statistics > Protocol Hierarchy`.
- Locate the SMTP protocol and note the number of packets.




