---
title: "Network Monitor Tool"
date: 2025-02-10
categories: [Python, Network Monitor]
tags: [Python, Network Monitor]
permalink: /posts/python-network-monitor-tool
image:
  path: /assets/img/thumbnails/Network-Monitor.png
---



The **Network Monitor** is a tool designed to capture, analyze, and display real-time network traffic. It provides insights into network packets, including source and destination IP addresses, protocols, ports, process names, packet sizes, and geographical locations of remote IPs. Additionally, it includes a real-time bandwidth usage graph to visualize inbound and outbound traffic.

## Key Features

- **Packet Capture**: Monitors and captures all incoming and outgoing network packets in real-time.
- **Detailed Packet Analysis**: Displays packet details such as:
  - Timestamp
  - Source and Destination IP Addresses
  - Protocol (TCP, UDP, ICMP, DNS, HTTP, FTP, SMTP, SNMP, IMAP)
  - Port Numbers
  - Associated Process Names
  - Packet Size (in bytes)
  - Geographical Location of Remote IPs
- **GeoIP Lookup**: Uses an external API (e.g., `ipstack`) to determine the country, city, and ISP of remote IP addresses.
- **Real-Time Bandwidth Graph**: Visualizes inbound and outbound traffic over time using a dynamic graph.
- **Filtering Capabilities**: Allows users to filter packets based on:
  - IP Address
  - Port Number
  - Protocol Type
- **Auto Scroll Toggle**: Enables or disables automatic scrolling in the packet list view.
- **User-Friendly Interface**: Built using Tkinter, providing an intuitive GUI for easy interaction.

## How It Works

1. **Initialization**: The application starts by retrieving the local machine's IP address and initializing the GUI.
2. **Packet Sniffing**: Using the `scapy` library, the application captures network packets in real-time.
3. **Packet Processing**: Each captured packet is analyzed to extract relevant information such as source/destination IPs, protocol, port, process name, and packet size.
4. **GeoIP Lookup**: For each remote IP address, a GeoIP lookup is performed to retrieve geographical details.
5. **Display**: The extracted information is displayed in a tabular format within the GUI, and the bandwidth graph is updated dynamically.
6. **Filters**: Users can apply filters to narrow down the displayed packets based on specific criteria.

---

## Full Code 

Github Repository:  [Network Monitor Tool](https://github.com/Diogo-Lages/Network_Monitor.py)

```python
import psutil
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS
from scapy.all import sniff, Raw
from datetime import datetime
import threading
import time
import platform
import socket
import tkinter as tk
from tkinter import ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import requests

# ANSI Color Codes
RESTART = '\033[0m'  # Reset to default
B = '\033[0;30m'  # Black
R = '\033[0;31m'  # Red
G = '\033[0;32m'  # Green
Y = '\033[0;33m'  # Yellow
BLU = '\033[0;34m'  # Blue
P = '\033[0;35m'  # Purple
C = '\033[0;36m'  # Cyan
W = '\033[0;37m'  # White

# Temporary LocalHost IP Address
IP_ADDRESS = "127.0.0.1"

def get_ip_address():
    """Get the local machine's IP address."""
    system = platform.system()
    if system == "Windows":
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
    else:
        try:
            ip_address = socket.gethostbyname(socket.gethostname())
            if ip_address.startswith("127."):
                ip_address = socket.gethostbyname(socket.getfqdn())
        except socket.gaierror:
            ip_address = "Unable to get IP address"
    return ip_address

def get_process_name_by_port(port):
    """
    Get the process name associated with a given port.
    Uses psutil.net_connections() to map ports to PIDs.
    """
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr.port == port or (conn.raddr and conn.raddr.port == port):
                if conn.pid:
                    try:
                        return psutil.Process(conn.pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        pass
        return "Unknown"
    except Exception as e:
        print(f"Error retrieving process name: {e}")
        return "Unknown"

class GeoIPLookup:
    def __init__(self, api_key=None):
        self.api_key = api_key

    def lookup(self, ip):
        """
        Perform a GeoIP lookup for the given IP address.
        Returns location details or "Unknown Location" on failure.
        """
        try:
            response = requests.get(f"http://api.ipstack.com/{ip}", params={"access_key": self.api_key})
            if response.status_code == 200:
                data = response.json()
                country = data.get("country_name", "Unknown")
                city = data.get("city", "Unknown")
                isp = data.get("connection", {}).get("isp", "Unknown")
                return f"{country}, {city} | ISP: {isp}"
            return "Unknown Location"
        except Exception as e:
            print(f"Error during GeoIP lookup: {e}")
            return "Error during lookup"

class NetworkMonitorApp:
    def __init__(self, root, api_key=None):
        self.root = root
        self.root.title("Network Monitor")
        self.root.geometry("1200x800")

        # Treeview for packet details
        self.tree = ttk.Treeview(
            root,
            columns=("Time", "Source", "Destination", "Protocol", "Port", "Process", "Size", "Location"),
            show="headings",
        )
        self.tree.heading("Time", text="Timestamp")
        self.tree.heading("Source", text="Source IP")
        self.tree.heading("Destination", text="Destination IP")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.heading("Port", text="Port")
        self.tree.heading("Process", text="Process")
        self.tree.heading("Size", text="Size (Bytes)")
        self.tree.heading("Location", text="Location")
        self.tree.pack(fill=tk.BOTH, expand=True)

        # Scrollbar for Treeview
        self.scrollbar = ttk.Scrollbar(root, orient=tk.VERTICAL, command=self.tree.yview)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=self.scrollbar.set)

        # Buttons
        self.start_button = tk.Button(root, text="Start Monitoring", command=self.start_monitoring)
        self.start_button.pack(pady=10)
        self.stop_button = tk.Button(root, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.pack(pady=10)

        # Filter Frame
        self.filter_frame = tk.Frame(root)
        self.filter_frame.pack(pady=10)
        tk.Label(self.filter_frame, text="Filter by IP:").grid(row=0, column=0)
        self.ip_filter = tk.Entry(self.filter_frame)
        self.ip_filter.grid(row=0, column=1)
        tk.Label(self.filter_frame, text="Filter by Port:").grid(row=0, column=2)
        self.port_filter = tk.Entry(self.filter_frame)
        self.port_filter.grid(row=0, column=3)
        tk.Label(self.filter_frame, text="Filter by Protocol:").grid(row=0, column=4)
        self.protocol_filter = ttk.Combobox(
            self.filter_frame, values=["TCP", "UDP", "ICMP", "DNS", "HTTP", "FTP", "SMTP", "SNMP", "IMAP"]
        )
        self.protocol_filter.grid(row=0, column=5)
        self.apply_filter_button = tk.Button(self.filter_frame, text="Apply Filters", command=self.apply_filters)
        self.apply_filter_button.grid(row=0, column=6)
        self.reset_filter_button = tk.Button(self.filter_frame, text="Reset Filters", command=self.reset_filters)
        self.reset_filter_button.grid(row=0, column=7)

        # Auto Scroll Toggle
        self.auto_scroll = True
        self.toggle_scroll_button = tk.Button(root, text="Disable Auto Scroll", command=self.toggle_auto_scroll)
        self.toggle_scroll_button.pack(pady=10)

        # Bandwidth Graph
        self.figure = plt.Figure(figsize=(6, 4), dpi=100)
        self.ax = self.figure.add_subplot(111)
        self.canvas = FigureCanvasTkAgg(self.figure, master=root)
        self.canvas.get_tk_widget().pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True)

        # GeoIP Lookup
        self.geoip_lookup = GeoIPLookup(api_key=api_key)
        self.running = False
        self.total_bytes_in = 0
        self.total_bytes_out = 0
        self.timestamps = []
        self.bandwidth_in = []
        self.bandwidth_out = []

    def packet_callback(self, packet):
        """Callback function to process each captured packet."""
        if not self.running:
            return
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            proto = ip_layer.proto
            protocol = "N/A"
            port = "N/A"
            size = len(packet)
            if proto == 6:  # TCP
                protocol = "TCP"
                if packet.haslayer(TCP):
                    port = packet[TCP].sport
                    process_name = get_process_name_by_port(packet[TCP].sport)
            elif proto == 17:  # UDP
                protocol = "UDP"
                if packet.haslayer(UDP):
                    port = packet[UDP].sport
                    process_name = get_process_name_by_port(packet[UDP].sport)
            elif proto == 1:  # ICMP
                protocol = "ICMP"
                process_name = "System"
            elif packet.haslayer(DNS):  # DNS
                protocol = "DNS"
                process_name = "System"
            elif packet.haslayer(Raw) and b"HTTP" in bytes(packet[Raw]):  # HTTP
                protocol = "HTTP"
                process_name = "System"
            elif packet.haslayer(TCP) and packet[TCP].dport == 21:  # FTP
                protocol = "FTP"
                process_name = "System"
            elif packet.haslayer(TCP) and packet[TCP].dport == 25:  # SMTP
                protocol = "SMTP"
                process_name = "System"
            elif packet.haslayer(UDP) and packet[UDP].dport == 161:  # SNMP
                protocol = "SNMP"
                process_name = "System"
            elif packet.haslayer(TCP) and packet[TCP].dport == 143:  # IMAP
                protocol = "IMAP"
                process_name = "System"
            else:
                process_name = "Unknown"

            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            location = self.geoip_lookup.lookup(dst_ip)

            # Insert into treeview
            item_id = self.tree.insert(
                "", tk.END, values=(timestamp, src_ip, dst_ip, protocol, port, process_name, size, location)
            )
            if self.auto_scroll:
                self.tree.see(item_id)

            # Update bandwidth stats
            if src_ip == IP_ADDRESS:
                self.total_bytes_out += size
            else:
                self.total_bytes_in += size
            self.update_bandwidth_graph()

    def start_monitoring(self):
        """Start capturing network packets."""
        self.running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.sniff_thread = threading.Thread(target=self.start_sniffing)
        self.sniff_thread.daemon = True
        self.sniff_thread.start()

    def stop_monitoring(self):
        """Stop capturing network packets."""
        self.running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def start_sniffing(self):
        """Start the packet sniffing process."""
        sniff(prn=self.packet_callback, filter="ip", store=0)

    def update_bandwidth_graph(self):
        """Update the real-time bandwidth graph."""
        self.timestamps.append(time.time())
        self.bandwidth_in.append(self.total_bytes_in)
        self.bandwidth_out.append(self.total_bytes_out)
        if len(self.timestamps) > 10:  # Limit data points to 10
            self.timestamps.pop(0)
            self.bandwidth_in.pop(0)
            self.bandwidth_out.pop(0)
        self.ax.clear()
        self.ax.plot(self.timestamps, self.bandwidth_in, label="Inbound", color="blue")
        self.ax.plot(self.timestamps, self.bandwidth_out, label="Outbound", color="red")
        self.ax.set_title("Real-Time Bandwidth Usage")
        self.ax.set_xlabel("Time")
        self.ax.set_ylabel("Bytes")
        self.ax.legend()
        self.canvas.draw()

    def apply_filters(self):
        """Apply filters based on user input."""
        ip_filter = self.ip_filter.get().strip()
        port_filter = self.port_filter.get().strip()
        protocol_filter = self.protocol_filter.get().strip()
        for child in self.tree.get_children():
            values = self.tree.item(child, "values")
            src_ip, dst_ip, protocol, port = values[1], values[2], values[3], values[4]
            if (
                (not ip_filter or ip_filter in src_ip or ip_filter in dst_ip)
                and (not port_filter or port_filter == port)
                and (not protocol_filter or protocol_filter == protocol)
            ):
                self.tree.reattach(child, "", 0)
            else:
                self.tree.detach(child)

    def reset_filters(self):
        """Reset all filters and restore the default view."""
        for child in self.tree.get_children():
            self.tree.reattach(child, "", 0)

    def toggle_auto_scroll(self):
        """Toggle auto-scroll functionality."""
        self.auto_scroll = not self.auto_scroll
        if self.auto_scroll:
            self.toggle_scroll_button.config(text="Disable Auto Scroll")
        else:
            self.toggle_scroll_button.config(text="Enable Auto Scroll")


if __name__ == "__main__":
    IP_ADDRESS = get_ip_address()
    GEOIP_API_KEY = ""  # Replace with your actual API key
    root = tk.Tk()
    app = NetworkMonitorApp(root, api_key=GEOIP_API_KEY)
    root.mainloop()
```

---

## Future Implementations

While the current version of the **Network Monitor Application** provides robust functionality, there are several potential enhancements and features that could be added in future iterations:

1. **Advanced Filtering**:
   - Allow filtering by MAC addresses.
   - Add support for filtering by packet payload content (e.g., keywords in HTTP requests).

2. **Export Functionality**:
   - Enable exporting packet logs to CSV, JSON, or other formats for further analysis.

3. **Enhanced GeoIP Lookup**:
   - Integrate more advanced GeoIP services for better accuracy and additional details (e.g., latitude/longitude).
   - Cache frequently accessed GeoIP lookups to reduce API calls and improve performance.

4. **Dark Mode Support**:
   - Add a dark mode theme for improved readability and aesthetics.

5. **Alert System**:
   - Implement alerts for suspicious activities, such as unexpected outbound connections or large data transfers.

6. **Multi-Interface Support**:
   - Allow monitoring of multiple network interfaces simultaneously.

7. **Performance Optimization**:
   - Optimize packet processing and UI updates for smoother performance on high-traffic networks.

8. **Packet Reconstruction**:
   - Add the ability to reconstruct and display full HTTP requests/responses or other protocol-specific data.

9. **User Authentication**:
   - Introduce user authentication and role-based access control for secure usage in enterprise environments.

10. **Cross-Platform Packaging**:
    - Package the application as a standalone executable for Windows, macOS, and Linux using tools like PyInstaller.

These enhancements would make the application even more versatile and valuable for both personal and professional use cases.

---

## Output

![Network Monitor Output](/assets/img/Network-Monitor-Output.png)


