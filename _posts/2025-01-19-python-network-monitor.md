---
title: "Network Monitor"
date: 2025-01-19
categories: [Python, Network Monitor]
tags: [Python, Network Monitor]
permalink: /posts/python-network-monitor
image:
  path: /assets/img/thumbnails/Network-Monitor.png
---



A Python-based desktop application to monitor and analyze real-time network traffic, system performance, and packet details.

### Network Monitor Repository

- **Link**: [Network Monitor Repository](https://github.com/Diogo-Lages/Network-Monitor)

---

## Features

- **Real-Time Packet Capture**: Capture and analyze network packets as they flow through your system.
- **Packet Filtering**: Filter packets by protocol (e.g., TCP, UDP) or IP address for focused analysis.
- **Location & Service Detection**: Automatically detect the location and service associated with destination IPs using an external API.
- **Data Export**: Export captured data in CSV, JSON, or HTML formats for offline analysis.
- **System Monitoring**: Track CPU, memory, disk, and network usage with warnings for high resource utilization.
- **Visualizations**: View real-time bandwidth usage, protocol distribution, and system performance graphs.
- **Auto-Scroll**: Automatically scroll through captured packets for continuous monitoring.
- **Dark/Light Theme**: Toggle between light and dark themes for better usability.

---

## How It Works

The **Network-Monitor** tool captures network packets using the `scapy` library and analyzes them in real-time. Each packet's details, such as source/destination IPs, protocol, size, and encryption status, are extracted and displayed in a user-friendly interface. The tool also integrates with the [ipapi.com](https://ipapi.com/) API to fetch location and service information for destination IPs.

Captured data is stored in an SQLite database for later retrieval and can be exported in multiple formats (CSV, JSON, HTML). System performance metrics like CPU and memory usage are monitored using the `psutil` library, and visualizations are created using `matplotlib` and `plotly`.

---

## Code Structure

The project is organized into modular components for clarity and maintainability:

- **`modules/data_manager.py`**: Handles database operations and data exports.
- **`modules/packet_analyzer.py`**: Analyzes captured packets and extracts details like protocol, size, and encryption status.
- **`modules/system_monitor.py`**: Monitors system resources (CPU, memory, disk, network).
- **`modules/visualizer.py`**: Creates visualizations for bandwidth usage, protocol distribution, and system performance.
- **`main.py`**: The main application file that ties everything together and provides the GUI.

This modular structure makes it easy to extend or modify specific functionalities without affecting the entire codebase.

---

## Interface


![Main Dashboard](/assets/img/network_monitor.png)



---

## Future Enhancements

We’re continuously working to improve the **Network-Monitor** tool. Here are some planned enhancements:

- **Advanced Filtering**: Add more filtering options, such as port numbers and packet size ranges.
- **Enhanced Visualizations**: Include heatmaps and more detailed graphs for deeper insights.
- **Cross-Platform Support**: Ensure seamless operation on Windows, macOS, and Linux.
- **Customizable Alerts**: Allow users to set custom thresholds for system resource warnings.
- **API Integration**: Add support for additional APIs to enhance location and service detection.
- **Offline Mode**: Provide offline functionality for environments without internet access.
