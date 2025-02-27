---
title: "Discover the Origin IP Address of a Website and Identify WAF Protection"
date: 2025-01-15
categories: [Guides, Discover Origin IP Address of a Website and Identify WAF]
tags: [Guides, Origin IP, Identify WAF]
permalink: /posts/find-origin-ip-website
image:
  path: /assets/img/thumbnails/find-origin-ip-website.png
---


Web application firewalls (WAFs) and content delivery networks (CDNs) are commonly employed to enhance website security. These technologies often obscure the true IP address of a server, adding an additional layer of protection that can complicate security assessments and bug bounty testing. However, uncovering the source IP address allows you to bypass these layers and directly assess the server, potentially revealing vulnerabilities hidden by the WAF or CDN.

This guide will explore methods for identifying whether a website is behind a WAF/CDN and techniques for discovering its origin IP address.

---

### Step 1: Identifying if a Website is Behind a WAF/CDN

Before attempting to find the origin IP, it's crucial to confirm whether the website is protected by a WAF or CDN. Here are some methods to achieve this:

#### **1.1 Ping Test**
Perform a simple ping test to gather initial information about the IP address associated with the domain:
```bash
ping target.com
```
If the IP resolves to a known CDN/WAF provider (e.g., Cloudflare, Amazon CloudFront, Akamai), it indicates the presence of such protection.

#### **1.2 Browser Extensions**
Use browser extensions like **Wappalyzer** to detect CDNs and WAFs. Simply visit the target website and check for any indicators of protection mechanisms.

#### **1.3 WafWOOF Tool**
WafWOOF is a specialized tool designed to identify WAFs. Run the following command:
```bash
wafw00f https://target.com
```
This will reveal whether a WAF is in place and specify which one.

#### **1.4 WHOIS Lookup**
A WHOIS lookup can provide insights into the hosting provider. If the registrar or hosting details point to a CDN/WAF vendor, it confirms their usage.

---

### Step 2: Methods for Discovering the Origin IP Address

Once you've determined that a WAF/CDN is present, proceed with the following techniques to uncover the origin IP address:

#### **2.1 DNSRecon**
DNSRecon performs reverse DNS lookups and may expose the origin IP if the server lacks robust WAF protection:
```bash
dnsrecon -d target.com
```

#### **2.2 Shodan Dorks**
Leverage Shodan's search capabilities to locate leaked IPs:
```plaintext
ssl.cert.subject.CN:"<DOMAIN>" 200
```
For automated results, combine Shodan CLI with HTTPX:
```bash
shodan search ssl.cert.subject.CN:"<DOMAIN>" 200 --fields ip_str | httpx-toolkit -sc -title -server -td
```

#### **2.3 Censys**
Censys is another powerful tool for IP discovery. Search for the target domain and review IPv4 entries matching SSL certificates or host details:
```plaintext
https://search.censys.io/hosts?q=<DOMAIN>
```

#### **2.4 SecurityTrails**
SecurityTrails offers historical DNS records, which can be invaluable for identifying past IP associations:
```plaintext
https://securitytrails.com/domain/<DOMAIN>/history/a
```

#### **2.5 FOFA**
FOFA excels at finding specific server configurations. Use the favicon hash for refined results:
```plaintext
https://fofa.info/
```
Steps:
1. Extract the favicon URL from the website.
2. Generate its hash using tools like [favicon-hash](https://favicon-hash.kmsec.uk).
3. Search for the hash in FOFA.

#### **2.6 ZoomEye**
Similar to Shodan, ZoomEye indexes internet devices. Perform a domain search and filter results by favicon hash:
```plaintext
https://www.zoomeye.org/searchResult?q=<DOMAIN>
```

#### **2.7 ViewDNS.info**
ViewDNS provides historical DNS records, including previous IP addresses:
```plaintext
https://viewdns.info/iphistory/?domain=<DOMAIN>
```

#### **2.8 SPF Records**
SPF records list authorized sending IPs for email. While not always indicative of the web server, they can sometimes reveal relevant IPs:
```plaintext
https://mxtoolbox.com/SuperTool.aspx?action=spf:<DOMAIN>
```

#### **2.9 VirusTotal**
VirusTotal aggregates data from multiple sources, making it useful for discovering subdomains and associated IPs:
```plaintext
https://www.virustotal.com/gui/domain/<DOMAIN>/details
```

#### **2.10 AlienVault OTX**
AlienVault Open Threat Exchange (OTX) offers threat intelligence data, including IP mappings:
```plaintext
https://otx.alienvault.com/indicator/hostname/<DOMAIN>
```

#### **2.11 Custom Bash Script**
Combine VirusTotal and AlienVault outputs into a single script for streamlined results:
```bash
#!/bin/bash
# API keys (replace with your own keys)
VT_API_KEY="<api_key>"
OTX_API_KEY="<api_key>"

# Function to fetch IP addresses from VirusTotal
fetch_vt_ips() {
    local domain=$1
    curl -s "https://www.virustotal.com/vtapi/v2/domain/report?domain=$domain&apikey=$VT_API_KEY" \
        | jq -r '.. | .ip_address? // empty' \
        | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}'
}

# Function to fetch IP addresses from AlienVault
fetch_otx_ips() {
    local domain=$1
    curl -s -H "X-OTX-API-KEY: $OTX_API_KEY" "https://otx.alienvault.com/api/v1/indicators/hostname/$domain/url_list?limit=500&page=1" \
        | jq -r '.url_list[]?.result?.urlworker?.ip // empty' \
        | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}'
}

# Check if domain is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <domain_name_or_url>"
    exit 1
fi

DOMAIN=$1
OUTPUT_FILE="${DOMAIN}_ips.txt"

# Get IPs from both sources, remove duplicates, and save to file
echo "Collecting IP addresses for: $DOMAIN"
{
    fetch_vt_ips $DOMAIN
    fetch_otx_ips $DOMAIN
} | sort -u > "$OUTPUT_FILE"

echo "IP addresses saved to: $OUTPUT_FILE"
```

---

### Step 3: Verifying the Origin IP

After identifying potential IPs, verify them through the following steps:

#### **3.1 /etc/hosts File**
Modify your `/etc/hosts` file to map the domain to the suspected IP:
```plaintext
<ORIGIN_IP> target.com
```
Reload the browser and observe if the site loads correctly without WAF intervention.

#### **3.2 Nmap Certificate Check**
Use Nmap to inspect the SSL certificate of the IP:
```bash
nmap --script ssl-cert -p 443 <ORIGIN_IP>
```
Ensure the certificate matches the target domain.

#### **3.3 Burp Suite Testing**
Configure Burp Suite to route traffic through the discovered IP:
1. Set the upstream proxy to the origin IP.
2. Intercept requests and confirm responses originate from the backend server.

---

### Tips for Bug Bounty Hunters

1. **Avoid Premature Reporting**: Once you discover the origin IP, thoroughly explore it for vulnerabilities like SQL injection, XSS, or misconfigurations before submitting findings.
2. **Test Without WAF**: With direct access to the backend server, exploit testing becomes significantly easier due to the absence of WAF filtering.
3. **Document Your Process**: Maintain detailed records of your methodology and discoveries for transparency during reporting.



