---
title: "FFUF: Fuzzing Guide to Web Applications"
date: 2025-02-16
categories: [Tools, FFUF Fuzzing Guide]
tags: [Tools, FFUF]
permalink: /posts/ffuf-Fuzzing-Guide
image:
  path: /assets/img/thumbnails/ffuf-Fuzzing-Guide.png
---


FFUF is a powerful, open-source fuzzing tool designed for web application security testing. It enables users to discover hidden files, directories, subdomains, and parameters through high-speed fuzzing. This guide will provide an in-depth explanation of FFUF commands, their use cases, and advanced techniques to help you leverage its full potential.

---

## Table of Contents
1. [Installation](#installation)
2. [Basic Commands](#basic-commands)
3. [Advanced Features](#advanced-features)
4. [Output Options](#output-options)
5. [Custom Wordlists](#custom-wordlists)


---

## Installation

To install FFUF on your system, follow the instructions below:

### Debian/Ubuntu Based Systems
```bash
sudo apt update && sudo apt install ffuf
```

### macOS (Using Homebrew)
```bash
brew install ffuf
```

### Other Operating Systems
For other operating systems, download the binary from the official GitHub repository:
[GitHub - ffuf: Fast web fuzzer written in Go](https://github.com/ffuf/ffuf)

Once downloaded, extract the binary and add it to your system's PATH.

---

## Basic Commands

### Directory and File Brute Force
One of the most common uses of FFUF is finding hidden directories and files on a web server. Use the `-u` flag to specify the target URL and the `-w` flag to provide a wordlist.

```bash
ffuf -u https://example.com/FUZZ -w wordlist.txt
```

**Explanation:**
- `FUZZ`: A placeholder that FFUF replaces with words from the wordlist.
- `wordlist.txt`: A text file containing potential directory or file names.

### POST Request with Wordlist
To fuzz POST requests, use the `-X POST` flag.

```bash
ffuf -w wordlist.txt -u https://website.com/FUZZ -X POST
```

This command sends POST requests while fuzzing the URL path.

### Case Insensitive Matching
Use the `-ic` flag for case-insensitive matching, which is useful when unsure about server case sensitivity.

```bash
ffuf -u https://example.com/FUZZ -w wordlist.txt -ic -c
```

The `-c` flag adds color-coded output for better readability.

### File Extension Fuzzing
To search for files with specific extensions, use the `-e` flag.

```bash
ffuf -u https://example.com/indexFUZZ -w wordlist.txt -e .php,.asp,.bak,.db
```

This command appends extensions like `.php`, `.asp`, `.bak`, and `.db` to each word in the wordlist.

### Recursive Fuzzing
For multi-level directory fuzzing, use the `-recursion` flag.

```bash
ffuf -u https://example.com/FUZZ -w wordlist.txt -recursion -recursion-depth 3
```

This scans up to three levels deep, helping uncover deeply nested directories.

---

## Advanced Features

### Filtering Responses
Filter responses based on HTTP status codes or response sizes.

```bash
ffuf -w wordlist.txt -u https://example.com/FUZZ -fc 404,500
```

This excludes responses with status codes `404` or `500`.

### Multi Wordlist Fuzzing
Fuzz multiple parameters using separate wordlists.

```bash
ffuf -u https://example.com/W2/W1/ -w dict.txt:W1 -w dns_dict.txt:W2
```

Here, `W1` and `W2` are placeholders replaced by words from `dict.txt` and `dns_dict.txt`, respectively.

### Subdomain and Virtual Host Fuzzing

#### Subdomain Fuzzing
Discover hidden subdomains by replacing the `FUZZ` keyword in the target URL.

```bash
ffuf -w subdomains.txt -u https://FUZZ.example.com/
```

#### Virtual Host (VHost) Fuzzing
Fuzz the `Host` header to detect virtual hosts.

```bash
ffuf -w vhosts.txt -u https://example.com/ -H "Host: FUZZ.example.com"
```

### Fuzzing HTTP Parameters

#### GET Parameter Fuzzing
Find potential GET parameters by fuzzing the query string.

```bash
ffuf -w wordlist.txt -u https://example.com/page.php?FUZZ=value
```

#### POST Parameter Fuzzing
Test APIs or login forms by fuzzing POST data.

```bash
ffuf -w wordlist.txt -u https://example.com/api -X POST -d 'FUZZ=value'
```

#### Login Bypass Testing
Brute force login systems by fuzzing the password parameter.

```bash
ffuf -w passwordlist.txt -X POST -d "username=admin&password=FUZZ" -u https://www.example.com/login
```

#### PUT Request Fuzzing
Test unauthorized file uploads or modifications.

```bash
ffuf -w /path/to/wordlist.txt -X PUT -u https://target.com/FUZZ -b 'session=abcdef'
```

---

## Advanced FFUF Techniques

### Clusterbomb Mode
Combine multiple wordlists for comprehensive testing.

```bash
ffuf -request req.txt -request-proto http -mode clusterbomb -w usernames.txt:HFUZZ -w passwords.txt:WFUZZ
```

This tests every combination of usernames and passwords.

```bash
ffuf -w users.txt:USER -w passwords.txt:PASS -u https://example.com/login?username=USER&password=PASS -mode clusterbomb
```

### Pitchfork Mode
Pair corresponding entries from two wordlists for controlled brute force testing.

```bash
ffuf -w users.txt:USER -w passwords.txt:PASS -u https://example.com/login?username=USER&password=PASS -mode pitchfork
```

### Setting Cookies
Include cookies in your requests for authenticated fuzzing.

```bash
ffuf -b "SESSIONID=abcd1234; USER=admin" -w wordlist.txt -u https://example.com/FUZZ
```

### Using Proxies
Route FFUF requests through a proxy like Burp Suite for deeper analysis.

```bash
ffuf -x http://127.0.0.1:8080 -w wordlist.txt -u https://example.com/FUZZ
```

### Custom Header Fuzzing
Fuzz custom headers to identify vulnerabilities.

```bash
ffuf -w headers.txt -u https://example.com/ -H "X-Custom-Header: FUZZ"
```

### Fuzzing with Custom User-Agent
Modify the `User-Agent` header to mimic specific browsers.

```bash
ffuf -u "https://example.com/FUZZ" -w wordlist.txt -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
```

### Rate Limiting Bypass
Control the request rate to avoid triggering rate limiting defenses.

```bash
ffuf -w wordlist.txt -u https://example.com/FUZZ -rate 50 -t 50
```

---

## Output Options

Save results in various formats for further analysis.

### HTML Output
```bash
ffuf -w wordlist.txt -u https://example.com/FUZZ -o results.html -of html
```

### JSON Output
```bash
ffuf -w wordlist.txt -u https://example.com/FUZZ -o results.json -of json
```

### CSV Output
```bash
ffuf -w wordlist.txt -u https://example.com/FUZZ -o results.csv -of csv
```

Save all output formats at once:
```bash
ffuf -w wordlist.txt -u https://example.com/FUZZ -o results -of all
```

---

## Custom Wordlists with Payloads

Access the wordlists with payloads here: 

- [SecLists](https://github.com/danielmiessler/SecLists)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) and [PayloadsAllTheThings Website](https://swisskyrepo.github.io/PayloadsAllTheThings/)
- [PayloadBox](https://github.com/orgs/payloadbox/repositories)





