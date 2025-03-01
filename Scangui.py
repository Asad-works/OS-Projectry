import os
import socket
import subprocess
import platform
import hashlib
import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading

scan_running = False  # Flag to control scanning

def scan_ports(target):
    global scan_running
    open_ports = []
    for port in range(1, 1025):  # Limiting scan to common ports for efficiency
        if not scan_running:
            status_box.insert(tk.END, "Scan stopped by user.\n")
            status_box.see(tk.END)
            return []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            if sock.connect_ex((target, port)) == 0:
                open_ports.append(port)
            sock.close()
        except Exception as e:
            status_box.insert(tk.END, f"Error scanning port {port}: {e}\n")
            status_box.see(tk.END)
    return open_ports

def check_software():
    status_box.insert(tk.END, "Checking installed software versions...\n")
    root.update()
    outdated = []
    try:
        if platform.system() == "Linux":
            result = subprocess.getoutput("dpkg -l")
            if "python2" in result:
                outdated.append("Python 2 (deprecated)")
        elif platform.system() == "Windows":
            result = subprocess.getoutput("wmic product get name,version")
            if "Python 2" in result:
                outdated.append("Python 2 (deprecated)")
    except Exception as e:
        outdated.append(f"Error checking software: {e}")
    return outdated

def check_misconfigurations():
    status_box.insert(tk.END, "Checking system misconfigurations...\n")
    root.update()
    issues = []
    if os.name == "nt":
        firewall_status = subprocess.getoutput("netsh advfirewall show allprofiles state")
        if "OFF" in firewall_status:
            issues.append("Windows Firewall is turned off!")
    else:
        ssh_status = subprocess.getoutput("systemctl is-active ssh")
        if ssh_status == "active":
            issues.append("SSH service is running (Potential risk)")
    return issues

def check_malware():
    status_box.insert(tk.END, "Scanning for malware signatures...\n")
    root.update()
    suspicious_files = []
    directories = ["C:\\Windows\\System32", "C:\\Users"] if os.name == "nt" else ["/usr/bin", "/home"]
    known_signatures = {"e99a18c428cb38d5f260853678922e03": "Malware.exe"}
    for directory in directories:
        try:
            for root_dir, _, files in os.walk(directory):
                for file in files[:5]:
                    if not scan_running:
                        return []
                    file_path = os.path.join(root_dir, file)
                    with open(file_path, "rb") as f:
                        file_hash = hashlib.md5(f.read(1024)).hexdigest()
                        if file_hash in known_signatures:
                            suspicious_files.append(file_path)
        except:
            continue
    return suspicious_files

def run_scan():
    global scan_running
    scan_running = True
    
    def scan():
        target_ip = "127.0.0.1"
        status_box.insert(tk.END, "Starting security vulnerability scan...\n")
        root.update()
        results = {
            "Open Ports": scan_ports(target_ip),
            "Outdated Software": check_software(),
            "Misconfigurations": check_misconfigurations(),
            "Suspicious Files": check_malware()
        }
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, "--- Scan Results ---\n")
        for key, value in results.items():
            output_text.insert(tk.END, f"{key}: {value if value else 'No issues found'}\n")
        with open("scan_report.txt", "w") as report:
            for key, value in results.items():
                report.write(f"{key}: {value}\n")
        messagebox.showinfo("Scan Complete", "Scan finished. Results saved in scan_report.txt")
    
    threading.Thread(target=scan, daemon=True).start()

def stop_scan():
    global scan_running
    scan_running = False
    status_box.insert(tk.END, "Stopping scan...\n")
    status_box.see(tk.END)

root = tk.Tk()
root.title("Security Vulnerability Scanner")
root.geometry("800x550")
root.configure(bg="#2E2E2E")

status_box = scrolledtext.ScrolledText(root, width=90, height=4, font=("Courier", 10), bg="#1E1E1E", fg="#00FF00", insertbackground="white")
status_box.pack(pady=10)

frame = tk.Frame(root, bg="#2E2E2E")
frame.pack(pady=10)

scan_button = tk.Button(frame, text="Start Scan", command=run_scan, width=20, height=2, font=("Arial", 12, "bold"), bg="#4CAF50", fg="white")
scan_button.pack(side=tk.LEFT, padx=10)

stop_button = tk.Button(frame, text="Stop Scan", command=stop_scan, width=20, height=2, font=("Arial", 12, "bold"), bg="#FF5733", fg="white")
stop_button.pack(side=tk.LEFT, padx=10)

output_text = scrolledtext.ScrolledText(root, width=90, height=20, font=("Courier", 10), bg="#1E1E1E", fg="#00FF00", insertbackground="white")
output_text.pack(pady=10)

root.mainloop()
