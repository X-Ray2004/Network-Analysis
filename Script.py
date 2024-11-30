import tkinter as tk
from tkinter import messagebox, ttk, scrolledtext
import time
import csv
from scapy.all import *
from threading import Thread

# Initialize the CSV file for logging
log_file = "network_log.csv"
with open(log_file, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["Timestamp", "Function", "Details"])

# Function to log data to CSV file
def log_to_csv(function, details):
    with open(log_file, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), function, details])

# Global variable to control packet analysis
packet_analysis_active = False

# ---------------------------
# 1. Network Discovery (ARP Scan)
# ---------------------------
def arp_scan_gui():
    subnet = entry_subnet.get()
    if not subnet:
        messagebox.showerror("Input Error", "Please enter a subnet.")
        return

    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"Scanning subnet: {subnet}\n")

    def perform_arp_scan():
        arp = ARP(pdst=subnet)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        answered, _ = srp(packet, iface="br-979cf59e77a5", timeout=2, verbose=0)

        output_text.insert(tk.END, "{:<15}  {}\n".format("IP Address", "MAC Address"))
        output_text.insert(tk.END, "-" * 30 + "\n")

        for sent, received in answered:
            ip = received.psrc
            mac = received.hwsrc
            output_text.insert(tk.END, "{:<15}  {}\n".format(ip, mac))
            log_to_csv("ARP Scan", f"{ip}, {mac}")

    Thread(target=perform_arp_scan).start()

# ---------------------------
# 2. Packet Analysis
# ---------------------------
def packet_analysis_gui():
    global packet_analysis_active
    target_ip = entry_target_ip.get()
    protocol_filter = protocol_choice.get()
    
    if not target_ip:
        messagebox.showerror("Input Error", "Please enter a target IP address.")
        return

    output_text.insert(tk.END, f"Capturing packets for {target_ip} (Protocol: {protocol_filter})...\n")

    def analyze_packet(packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            length = len(packet)
            proto = packet.sprintf("%IP.proto%")

            if protocol_filter == "All" or proto == protocol_filter:
                output_text.insert(tk.END, f"Source: {src_ip}, Destination: {dst_ip}, Length: {length}, Protocol: {proto}\n")
                log_to_csv("Packet Analysis", f"Source: {src_ip}, Destination: {dst_ip}, Length: {length}, Protocol: {proto}")

    def sniff_packets():
        while packet_analysis_active:
            sniff(iface="br-979cf59e77a5", filter=f"host {target_ip}", prn=analyze_packet, timeout=2)

    if not packet_analysis_active:
        packet_analysis_active = True
        Thread(target=sniff_packets).start()

def stop_packet_analysis():
    global packet_analysis_active
    packet_analysis_active = False
    output_text.insert(tk.END, "Packet analysis stopped.\n")
    log_to_csv("Packet Analysis", "Packet analysis stopped")

# ---------------------------
# 3. Custom Packet Creation
# ---------------------------
def send_custom_packet_gui():
    target_ip = entry_target_ip.get()
    packet_type = packet_type_choice.get()

    if not target_ip:
        messagebox.showerror("Input Error", "Please enter a target IP address.")
        return

    if packet_type == "ICMP":
        packet = IP(dst=target_ip) / ICMP()
    elif packet_type == "TCP":
        packet = IP(dst=target_ip) / TCP(dport=80)
    else:
        packet = IP(dst=target_ip) / UDP(dport=53)

    send(packet, verbose=0)
    output_text.insert(tk.END, f"Sent {packet_type} packet to {target_ip}\n")
    log_to_csv("Custom Packet", f"Sent {packet_type} packet to {target_ip}")

# ---------------------------
# 4. Network Performance Measurement
# ---------------------------
def calculate_network_performance_gui():
    target_ip = entry_target_ip.get()
    if not target_ip:
        messagebox.showerror("Input Error", "Please enter a target IP address.")
        return

    latencies = []
    output_text.insert(tk.END, f"Measuring network performance for {target_ip}...\n")

    for _ in range(5):
        start_time = time.time()
        response = sr1(IP(dst=target_ip) / ICMP(), timeout=2, verbose=0)
        if response:
            latency = (time.time() - start_time) * 1000
            latencies.append(latency)
            output_text.insert(tk.END, f"Latency: {latency:.2f} ms\n")
        else:
            output_text.insert(tk.END, "Request timed out\n")

    if len(latencies) > 1:
        jitter = max(latencies) - min(latencies)
    else:
        jitter = 0.0

    output_text.insert(tk.END, f"Jitter: {jitter:.2f} ms\n")
    log_to_csv("Performance", f"Latency: {latencies}, Jitter: {jitter:.2f} ms")

# ---------------------------
# GUI Setup
# ---------------------------
root = tk.Tk()
root.title("Network Scanner Tool")
root.geometry("900x700")
root.configure(bg="#34495E")

# Title
tk.Label(root, text="Network Scanner Tool", font=("Helvetica", 16, "bold"), bg="#34495E", fg="#ECF0F1").pack(pady=10)

# Input Section
input_frame = tk.Frame(root, bg="#2C3E50", padx=10, pady=10)
input_frame.pack(fill="x", pady=5)

tk.Label(input_frame, text="Subnet:", bg="#2C3E50", fg="#ECF0F1").grid(row=0, column=0, padx=5, pady=5, sticky="w")
entry_subnet = tk.Entry(input_frame, width=30)
entry_subnet.grid(row=0, column=1, padx=5, pady=5)

tk.Label(input_frame, text="Target IP:", bg="#2C3E50", fg="#ECF0F1").grid(row=1, column=0, padx=5, pady=5, sticky="w")
entry_target_ip = tk.Entry(input_frame, width=30)
entry_target_ip.grid(row=1, column=1, padx=5, pady=5)

tk.Label(input_frame, text="Protocol Filter:", bg="#2C3E50", fg="#ECF0F1").grid(row=2, column=0, padx=5, pady=5, sticky="w")
protocol_choice = ttk.Combobox(input_frame, values=["All", "TCP", "UDP", "ICMP"], width=27)
protocol_choice.grid(row=2, column=1, padx=5, pady=5)
protocol_choice.current(0)

tk.Label(input_frame, text="Packet Type:", bg="#2C3E50", fg="#ECF0F1").grid(row=3, column=0, padx=5, pady=5, sticky="w")
packet_type_choice = ttk.Combobox(input_frame, values=["ICMP", "TCP", "UDP"], width=27)
packet_type_choice.grid(row=3, column=1, padx=5, pady=5)
packet_type_choice.current(0)

# Buttons Section
button_frame = tk.Frame(root, bg="#34495E", pady=10)
button_frame.pack(fill="x")

button_style = {"bg": "#1ABC9C", "fg": "#FFFFFF", "font": ("Helvetica", 10, "bold"), "width": 20, "pady": 5}
tk.Button(button_frame, text="ARP Scan", command=arp_scan_gui, **button_style).grid(row=0, column=0, padx=10, pady=5)
tk.Button(button_frame, text="Start Packet Analysis", command=packet_analysis_gui, **button_style).grid(row=0, column=1, padx=10, pady=5)
tk.Button(button_frame, text="Stop Packet Analysis", command=stop_packet_analysis, bg="#E74C3C", fg="#FFFFFF", font=("Helvetica", 10, "bold"), width=20, pady=5).grid(row=0, column=2, padx=10, pady=5)
tk.Button(button_frame, text="Send Packet", command=send_custom_packet_gui, **button_style).grid(row=1, column=0, padx=10, pady=5)
tk.Button(button_frame, text="Measure Performance", command=calculate_network_performance_gui, **button_style).grid(row=1, column=1, padx=10, pady=5)

# Output Section
output_frame = tk.Frame(root, bg="#2C3E50", pady=5)
output_frame.pack(fill="both", expand=True)

output_text = scrolledtext.ScrolledText(output_frame, wrap="word", font=("Courier", 10), bg="#2C3E50", fg="#ECF0F1", height=20)
output_text.pack(fill="both", expand=True, padx=5, pady=5)

root.mainloop()
