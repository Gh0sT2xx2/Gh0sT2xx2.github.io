---
title: "THM: Benign"
date: 2025-01-02
categories: [CTF, Blue Team]
tags: [CTF, Blue Team]
permalink: /posts/ctf-blueteam-benign
image:
  path: /assets/img/thumbnails/ctf-blueteam-benign.png
---



### **Walkthrough**

#### **CTF Platform**: TryHackMe  
#### **Level**: Medium  

#### **Tools Used**:
- Splunk
- VirusTotal (for URL verification)

#### **Resources Used**:
- Benign: [Tryhackme](https://tryhackme.com/room/benign)
- Splunk Query Language (SPL)
- Event ID 4688 logs
- Knowledge of Windows processes and LOLBins


## **Steps for the CTF**

---

### **Overview**

In this scenario, you only have access to process execution logs with **Event ID: 4688** in Splunk. This means you won’t have access to all Sysmon logs, making the investigation more challenging.

The network is divided into three logical segments:

#### **IT Department**
- James
- Moin
- Katrina

#### **HR Department**
- Haroon
- Chris
- Diana

#### **Marketing Department**
- Bell
- Amelia
- Deepak

With these details in mind, let’s begin the investigation!

---

### **Questions**

#### **1. How many logs are ingested from the month of March, 2022?**

To answer this question, you need to filter the logs to only include events from March 2022. Use the following Splunk query:

```spl
index=win_eventlogs
```

Set the date range in Splunk to March 2022 (you can adjust this in the time picker). Count the total number of logs returned by the query.

---

#### **2. Imposter Alert: There seems to be an imposter account observed in the logs. What is the name of that user?**

To identify the imposter, create a table of unique usernames from the logs using the following query:

```spl
index=win_eventlogs | stats count by UserName
```

Compare the results with the list of known employees provided in the overview. Look for any anomalies or usernames that don’t match the expected names.

---

#### **3. Which user from the HR department was observed to be running scheduled tasks?**

Focus on the HR department users (`Haroon`, `Chris`, `Diana`) and search for events related to `schtasks.exe`, the Windows process used for managing scheduled tasks. Use the following query:

```spl
index=win_eventlogs AND (UserName="haroon" OR UserName="Daina" OR UserName="Chris.fort") schtasks
```

Examine the results to determine which user was running scheduled tasks.

---

#### **4. Which user from the HR department executed a system process (LOLBIN) to download a payload from a file-sharing host?**

To answer this question, create a table containing the `UserName`, `ProcessName`, and `CommandLine` fields for the HR department users. Use the following query:

```spl
index=win_eventlogs AND (UserName="haroon" OR UserName="Daina" OR UserName="Chris.fort")
| table UserName ProcessName CommandLine
| dedup UserName CommandLine
```

Look for commands that involve downloading files from external sources. Pay attention to system processes like `certutil.exe`, which can be abused as a LOLBin (Living Off the Land Binary).

---

#### **5. To bypass the security controls, which system process (LOLBIN) was used to download a payload from the internet?**

Using the results from the previous question, identify the system process (LOLBin) that was used to download the payload. Look for commands in the `CommandLine` field that indicate file downloads.

---

#### **6. What was the date that this binary was executed by the infected host? Format (YYYY-MM-DD)**

From the results of the previous queries, locate the timestamp associated with the execution of the suspicious binary. Ensure the date is formatted as `YYYY-MM-DD`.

---

#### **7. Which third-party site was accessed to download the malicious payload?**

Examine the `CommandLine` field in the logs to identify the URL or domain used to download the payload. Focus on commands involving the identified LOLBin.

---

#### **8. What is the name of the file that was saved on the host machine from the C2 server during the post-exploitation phase?**

Inspect the `CommandLine` field in the logs to determine the name of the file that was downloaded and saved on the host machine. Look for parameters that specify the output filename.

---

#### **9. The suspicious file downloaded from the C2 server contained malicious content with the pattern `THM{……….}`; what is that pattern?**

Once you’ve identified the URL where the payload was hosted, visit the link to view its contents. Before accessing the URL, verify its safety using tools like VirusTotal. The content of the file will contain the flag in the format `THM{...}`.

---

#### **10. What is the URL that the infected host connected to?**

From the results of your earlier queries, extract the URL or domain used to download the malicious payload. This URL will be visible in the `CommandLine` field.

