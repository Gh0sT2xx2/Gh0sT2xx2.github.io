---
title: "Network Scanner"
date: 2025-02-13
categories: [Python, Network Scanner]
tags: [Python, Network Scanner]
permalink: /posts/python-network-scanner
image:
  path: /assets/img/thumbnails/Network-Scanner.png
---



Network scanning tool designed for cybersecurity. It offers features such as port scanning, service detection, OS fingerprinting, vulnerability scanning, traceroute, geolocation, WHOIS lookup, and SSL/TLS checks. By querying external databases like Shodan, NVD, and CIRCL, the tool identifies potential vulnerabilities and generates detailed HTML reports summarizing scan results.


## Network Scanner Repository

- **Link**: [Network Scanner Repository](https://github.com/Diogo-Lages/Network_Scanner.py)

## Features

- **Port Scanning**: Scan both TCP and UDP ports to identify open, closed, or filtered ports.
- **Service Detection**: Detect service versions running on open ports.
- **OS Fingerprinting**: Perform advanced OS fingerprinting to guess the operating system of the target.
- **Vulnerability Scanning**: Query external databases (Shodan, NVD, CIRCL) to identify potential vulnerabilities.
- **Traceroute**: Perform a traceroute to the target IP to identify the network path.
- **Geolocation**: Determine the geographical location of the target IP using the GeoIP database.
- **WHOIS Lookup**: Retrieve WHOIS information for the target domain or IP.
- **SSL/TLS Check**: Check SSL/TLS configurations for HTTPS services.
- **NSLookup**: Perform DNS resolution to convert IP addresses to domain names and vice versa.
- **HTML Report Generation**: Generate a detailed HTML report summarizing the scan results.
- **Website Vulnerability Check**: Query CVE Details for known vulnerabilities associated with the target domain.

## How It Works

The program starts by displaying a banner and prompting the user for a target IP address and a port range. It then proceeds to scan the specified ports using TCP or UDP protocols. For each open port, the program attempts to detect the service version and suggest potential vulnerabilities. It also performs additional tasks like OS fingerprinting, traceroute, geolocation, WHOIS lookup, and SSL/TLS checks. Finally, it compiles all the gathered information into an HTML report.

## Code Structure

The code is structured into several functions, each responsible for a specific task:

- **`scan_tcp_port`**: Scans a TCP port and determines if it is open, closed, or filtered.
- **`scan_udp_port`**: Scans a UDP port and determines if it is open, closed, or filtered.
- **`nslookup`**: Performs DNS resolution for the target IP or domain.
- **`query_website_vulnerabilities`**: Queries CVE Details for known vulnerabilities associated with the target domain.
- **`generate_html_report`**: Generates an HTML report summarizing the scan results.
- **`detect_service_version`**: Detects the service version running on an open port.
- **`suggest_exploits`**: Suggests potential exploits for the detected service.
- **`os_fingerprinting`**: Performs OS fingerprinting to guess the operating system of the target.
- **`query_shodan`**: Queries Shodan for information about the target IP.
- **`query_nvd`**: Queries the National Vulnerability Database (NVD) for known vulnerabilities.
- **`query_circl`**: Queries CIRCL for potential vulnerabilities.
- **`query_exploit_db`**: Queries Exploit-DB for potential exploits.
- **`vulnerability_scan`**: Performs a vulnerability scan using external APIs.
- **`traceroute`**: Performs a traceroute to the target IP.
- **`geolocation`**: Determines the geographical location of the target IP.
- **`whois_lookup`**: Performs a WHOIS lookup for the target domain or IP.
- **`ssl_tls_check`**: Checks SSL/TLS configurations for HTTPS services.
- **`start_scan`**: Orchestrates the entire scanning process.

## Interface

### **Command-Line Interface**

![Command-Line Interface](/assets/img/Command-Line-Interface.png)

### **HTML Report Template Interface**

![HTML Report Template Interface](/assets/img/HTML-Report-Template.png)

## Limitations

- **Rate Limiting**: The program may be rate-limited by external APIs like Shodan, NVD, and CIRCL.
- **Accuracy**: OS fingerprinting and service detection may not always be accurate.
- **GeoIP Database**: The program requires a local GeoIP database for geolocation. If the database is not present, geolocation will not work.
- **SSL/TLS Check**: The SSL/TLS check is limited to port 443 (HTTPS).
- **Vulnerability Scanning**: The vulnerability scanning feature relies on external APIs and may not cover all possible vulnerabilities.

## Future Enhancements

- **Support for IPv6**: Add support for scanning IPv6 addresses.
- **Enhanced OS Fingerprinting**: Improve the accuracy of OS fingerprinting by incorporating more advanced techniques.
- **Integration with More APIs**: Integrate with additional vulnerability databases and APIs.
- **User Interface**: Develop a graphical user interface (GUI) for easier interaction.
- **Automated Reporting**: Add support for automated email or Slack notifications with the scan report.
- **Customizable Port Ranges**: Allow users to define and save custom port ranges for scanning.
- **Performance Optimization**: Optimize the code for faster scanning and reduced resource usage.

## Ethical Considerations

- **Authorization**: Always ensure you have proper authorization before scanning any network or system. Unauthorized scanning can be illegal and unethical.
- **Data Privacy**: Be mindful of the data you collect during scanning. Ensure that any sensitive information is handled securely and in compliance with relevant laws and regulations.
- **Impact on Target Systems**: Be aware that aggressive scanning can impact the performance of target systems. Use the tool responsibly and avoid causing disruption.
- **Disclosure of Vulnerabilities**: If you discover vulnerabilities during your scan, follow responsible disclosure practices to inform the affected parties.

## Tips and Tricks

- **Use Top Ports**: For a quick scan, use the "Top Ports" option to scan commonly used ports.
- **Custom Port Ranges**: For a more thorough scan, specify a custom port range (e.g., 1-1024).
- **GeoIP Database**: Ensure the GeoIP database is present in the working directory for accurate geolocation.
- **External APIs**: If you have API keys for Shodan or other services, configure them in the code for enhanced vulnerability scanning.
- **HTML Report**: Always review the generated HTML report for a comprehensive summary of the scan results.

## Extra Insights

- **Service Banners**: The program attempts to grab service banners from open ports. This can provide valuable information about the services running on the target.
- **Vulnerability Suggestions**: The program suggests potential vulnerabilities based on the detected services. Use this information to prioritize further investigation.
- **Traceroute**: The traceroute feature can help you understand the network path to the target, which can be useful for troubleshooting or network analysis.
- **WHOIS Lookup**: The WHOIS lookup feature provides information about the domain registration, which can be useful for identifying the owner of the target.

## Conclusion

This Python-based network scanner is a tool for network reconnaissance and vulnerability assessment. It provides a wide range of features, from basic port scanning to advanced vulnerability detection and reporting.



