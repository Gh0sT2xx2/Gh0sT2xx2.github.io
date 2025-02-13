---
title: "Honeypot Suite"
date: 2025-02-11
categories: [Python, Honeypot Suite]
tags: [Python, Honeypot Suite]
permalink: /posts/python-honeypot-suite
image:
  path: /assets/img/thumbnails/Honeypot-Suite.png
---



The entire honeypot suite, including all protocol-specific implementations and the centralized management script (`menu.py`), is hosted in a single repository. This unified approach simplifies setup, maintenance, and contribution.

### **Honeypot Suite Repository**
- **Link**: [Honeypot Suite Repository](https://github.com/Diogo-Lages/Honeypot_Suite.py)


### **Directory Structure**
The repository follows a modular structure for clarity and extensibility:
```
honeypot-suite/
├── https_honeypot.py       # HTTPS honeypot implementation
├── dns_honeypot.py         # DNS honeypot implementation
├── ssh_honeypot.py         # SSH honeypot implementation
├── ftp_honeypot.py         # FTP honeypot implementation
├── postgresql_honeypot.py  # PostgreSQL honeypot implementation
├── menu.py                 # Centralized GUI for managing honeypots
└──  README.md               # Project documentation
```

---


## Features

The honeypot suite is designed to simulate various network services, allowing you to monitor and analyze malicious activities. Key features include:

- **Multi-Protocol Support**: Supports HTTPS, DNS, SSH, FTP, and PostgreSQL protocols.
- **Dynamic Configuration**: Allows users to configure host, port, and protocol-specific settings via a GUI or command-line interface.
- **Real-Time Logging**: Logs all interactions with the honeypot in real-time, providing detailed insights into attacker behavior.
- **Customizable Responses**: Each honeypot can be configured to respond with custom data (e.g., fake IP addresses for DNS, dummy responses for SSH).
- **Self-Signed Certificates**: Automatically generates SSL/TLS certificates for HTTPS and SSH honeypots.
- **Cross-Platform Compatibility**: Works on Windows, macOS, and Linux.

---

## How It Works

The honeypot suite operates by mimicking vulnerable network services to attract attackers and log their interactions. Here's an overview of how it works:

1. **Service Simulation**:
   - Each honeypot module simulates a specific protocol (e.g., DNS, SSH) and listens for incoming connections.
   - The honeypot responds to queries or login attempts with predefined or dynamically generated data.

2. **Logging**:
   - All interactions are logged to files (e.g., `dns_honeypot.log`, `ssh_honeypot.log`) for later analysis.
   - Logs include details such as source IP, port, query type, username/password attempts, and more.

3. **GUI Management**:
   - A professional GUI (`menu.py`) allows users to select, configure, and manage honeypots easily.
   - Start/stop buttons ensure seamless control over each service.

4. **Termination**:
   - Closing the Python program stops the honeypot service.
   - Ensure proper termination using tips provided below.

---

## Code Structure

The honeypot suite is modular and extensible, with each protocol implemented as a separate Python script. Below is the high-level structure:

1. **Honeypot Modules**:
   - Each protocol has its own script (e.g., `https_honeypot.py`, `dns_honeypot.py`).
   - Scripts expose `start_honeypot` and `stop_honeypot` functions for integration.

2. **Centralized Control**:
   - The `menu.py` script provides a unified interface for managing all honeypots.
   - Dynamically loads modules based on user selection.

3. **Twisted Framework**:
   - Built using Twisted, a powerful event-driven networking engine for Python.
   - Ensures efficient handling of network traffic and logging.

4. **Cryptography Library**:
   - Uses the `cryptography` library to generate self-signed certificates for HTTPS and SSH.

---

## Interface

### **Menu**
The `menu.py` script provides a clean and intuitive GUI for selecting and configuring honeypots:

![Honeypot Menu](/assets/img/Menu-Honeypot.png)

#### **Steps to Use the Menu**:
1. Select a protocol (e.g., DNS, SSH).
2. Configure settings such as host, port, and additional parameters (e.g., SSH version).
3. Click "Start Honeypot" to begin monitoring.
4. View logs in real-time within the GUI.

---

## Limitations

While the honeypot suite is robust, it has some limitations:

- **Resource Consumption**: Running multiple honeypots simultaneously may consume significant system resources.
- **False Positives**: Legitimate users interacting with the honeypot may generate logs that need filtering.
- **Single Process Reactor**: Only one Twisted reactor can run at a time, limiting simultaneous honeypot execution without subprocesses.
- **Basic Simulations**: The honeypots provide basic simulations and may not fully replicate complex production environments.

---

## Future Enhancements

Planned enhancements include:

- **Advanced Logging**: Integrate with centralized logging systems like Elasticsearch or Splunk for better analysis.
- **Machine Learning**: Use ML models to detect and classify attack patterns automatically.
- **Containerization**: Package each honeypot in Docker containers for easier deployment and isolation.
- **Web-Based Interface**: Replace the Tkinter GUI with a web-based dashboard for remote management.
- **Automated Alerts**: Send email or SMS alerts when suspicious activity is detected.

---

## Ethical Considerations

Using honeypots for cybersecurity research must adhere to ethical guidelines:

- **Authorization**: Deploy honeypots only in environments where you have explicit permission.
- **Data Privacy**: Avoid logging sensitive information from legitimate users.
- **Legal Compliance**: Ensure compliance with local laws and regulations regarding data collection and monitoring.
- **Isolation**: Run honeypots in isolated networks to prevent unintended exposure.

---

## Tips and Tricks

### **Ensuring Proper Termination**
To ensure the honeypot stops cleanly:
1. **Graceful Shutdown**:
   - Press `Ctrl+C` in the terminal running the honeypot.
   - Verify termination using tools like `netstat` or `tasklist`.

   Example:
   ```bash
   netstat -ano | findstr :<port>
   taskkill /PID <PID> /F
   ```

2. **Check Logs**:
   - Review the log file (e.g., `dns_honeypot.log`) to confirm the honeypot stopped successfully.

### **Setting Up the HTTPS Honeypot**
1. **Download Resources**:
   - Specify a target URL (e.g., `https://example.com`) to download and serve content.
   - The honeypot inlines CSS, JavaScript, and images to reduce external dependencies.

2. **Generate Certificates**:
   - Customize SSL certificate details (e.g., country, organization) during startup.
   - Certificates are stored locally in the script directory.

3. **Run the Honeypot**:
   - Execute the script with desired configurations:
     ```bash
     python https_honeypot.py --host 0.0.0.0 --port 443 --url https://example.com
     ```

4. **Test Locally**:
   - Use tools like `curl` or Postman to test the honeypot:
     ```bash
     curl -k https://127.0.0.1/
     ```

---

## Extra Insights

### **Why Use Honeypots?**
Honeypots are invaluable tools for:
- Gathering intelligence on attacker techniques and tools.
- Detecting and mitigating threats in real-time.
- Educating teams about security risks through practical demonstrations.

### **Best Practices**
- **Regular Updates**: Keep the honeypot scripts updated to handle new attack vectors.
- **Controlled Environment**: Deploy honeypots in sandboxed or virtualized environments to minimize risks.
- **Analyze Logs**: Regularly review logs to identify trends and improve your security posture.

### **Example Output**
Below is an example log entry from the DNS honeypot:
```
[2023-10-15 12:34:56] DNS Query Received - Query Name: example.com, Type: A, Class: IN, From: ('192.168.1.100', 5353)
```

From the SSH honeypot:
```
[2023-10-15 12:35:00] Login attempt - Username: admin, Password: password123
```

---

## Conclusion

This honeypot suite is a tool for cybersecurity researchers. By simulating vulnerable services, it helps you understand attacker behavior and strengthen your defenses. While the current implementation focuses on simplicity and usability, future enhancements will expand its capabilities and make it even more effective.





