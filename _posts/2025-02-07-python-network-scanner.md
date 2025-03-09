---
title: "Network Scanner"
date: 2025-02-07
categories: [Python, Network Scanner]
tags: [Python, Network Scanner]
permalink: /posts/python-network-scanner
image:
  path: /assets/img/thumbnails/Network-Scanner.png
---



Python-based tool designed for network reconnaissance, service detection, and vulnerability analysis. It supports port scanning, service fingerprinting, web analysis, geolocation, and detailed reporting in both HTML and JSON formats.

### Network Scanner Repository  

- **Link**: [Network Scanner Repository](https://github.com/Diogo-Lages/Network-Scanner)  

---

## Features  

The **Network Scanner** is a powerful Python-based tool designed for network reconnaissance, service detection, and vulnerability analysis. Key features include:  

- **Port Scanning**: Identify open ports and running services on both IPv4 and IPv6 addresses.  
- **Service Detection**: Detect services like HTTP, SSH, FTP, and more using banners, extended probes, and SSL/TLS analysis.  
- **Web Analysis**: Analyze websites for technologies, security headers, WAF detection, and potential vulnerabilities.  
- **Geolocation**: Pinpoint the physical location of IP addresses using the GeoLite2 database.  
- **DNS Information**: Retrieve DNS records (A, MX, TXT) and perform reverse DNS lookups.  
- **WHOIS Lookup**: Fetch domain registration details.  
- **Reporting**: Generate professional HTML and JSON reports with risk assessments.  
- **Customizable**: Configure timeouts, concurrent scans, and reporting formats via `config.yml`.  
- **Cross-Platform**: Works seamlessly on Windows, Linux, and macOS.  

---

## How It Works  

The **Network Scanner** operates in several stages:  

1. **Target Resolution**:  
   - Resolves hostnames to both IPv4 and IPv6 addresses.  
   - Performs reverse DNS lookups and geolocation for resolved IPs.  

2. **Port Scanning**:  
   - Scans default or custom ports using asynchronous techniques for efficiency.  
   - Supports retries, timeouts, and rate limiting to ensure reliability.  

3. **Service Detection**:  
   - Identifies services running on open ports using banners, SSL/TLS information, and extended probes.  
   - Analyzes web services for technologies, security headers, and vulnerabilities.  

4. **Reporting**:  
   - Generates detailed HTML and JSON reports with scan results, risk assessments, and metadata.  

5. **User Interaction**:  
   - Provides an interactive menu for selecting scan modes, entering targets, and specifying custom ports.  

---

## Code Structure  

The project is organized into modular components for maintainability and scalability:  

- **`network_scanner.py`**: Main entry point for the application. Handles user interaction and orchestrates the scanning process.  
- **`utils/async_scanner.py`**: Implements asynchronous port scanning and service detection.  
- **`utils/web_analyzer.py`**: Analyzes websites for technologies, vulnerabilities, and security headers.  
- **`utils/reporter.py`**: Generates HTML and JSON reports based on scan results.  
- **`utils/config_manager.py`**: Manages configuration loading and validation from `config.yml`.  
- **`utils/logger.py`**: Handles logging to both console and file outputs.  
- **`templates/`**: Contains HTML and CSS templates for report generation.  
- **`GeoLite2-City.mmdb`**: GeoIP database for geolocation features.  
- **`config.yml`**: Configuration file for scanner settings.  

---

## Interface  


![Main Dashboard](/assets/img/network_scanner.png)


---

## Future Enhancements  

The following features are planned for future releases:  

- **Enhanced Vulnerability Scanning**: Integrate with CVE databases for real-time vulnerability checks.  
- **Authentication Support**: Add support for scanning authenticated endpoints.  
- **Graphical User Interface (GUI)**: Develop a GUI for easier interaction.  
- **API Integration**: Provide an API for integrating the scanner into other tools or workflows.  
- **Improved Reporting**: Add PDF export and customizable report templates.  
- **Support for Additional Protocols**: Extend support for protocols like SNMP, SIP, and more.  

---

## Ethical Considerations  

The **Network Scanner** is intended for ethical use only. Users must adhere to the following guidelines:  

- **Authorization**: Always obtain explicit permission before scanning networks or systems.  
- **Legal Compliance**: Ensure compliance with local laws and regulations regarding network scanning.  
- **Responsible Use**: Avoid using the tool for malicious purposes or unauthorized activities.  
- **Data Privacy**: Handle any data collected during scans responsibly and securely.  

By using this tool, you agree to abide by these ethical considerations and assume full responsibility for its usage.
