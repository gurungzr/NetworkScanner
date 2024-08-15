import subprocess
import threading
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

running_process = None

def nmap_scan(command, output_text):
    global running_process
    output_text.insert(tk.END, "----------------------------------------------------------------------------------------\n", 'separator')
    output_text.insert(tk.END, f"Running command: {command}\n", 'command')
    output_text.insert(tk.END, "----------------------------------------------------------------------------------------\n", 'separator')
    output_text.update()

    running_process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = running_process.communicate()

    output_text.insert(tk.END, out.decode(), 'output')
    if err:
        output_text.insert(tk.END, err.decode(), 'error')

    output_text.insert(tk.END, "----------------------------------------------------------------------------------------\n", 'separator')
    output_text.update()

def stop_scan():
    global running_process
    if running_process:
        running_process.terminate()
        messagebox.showinfo("Info", "Scan stopped")
        running_process = None

def tcp_connect_scan(target, port, output_text):
    threading.Thread(target=nmap_scan, args=(f"nmap -sT -v {target} -p {port}", output_text)).start()

def udp_scan(target, port, output_text):
    threading.Thread(target=nmap_scan, args=(f"nmap -sU -v {target} -p {port}", output_text)).start()

def syn_scan(target, port, output_text):
    threading.Thread(target=nmap_scan, args=(f"nmap -sS -v {target} -p {port}", output_text)).start()

def ack_scan(target, port, output_text):
    threading.Thread(target=nmap_scan, args=(f"nmap -sA {target} -p {port}", output_text)).start()

def null_scan(target, port, output_text):
    threading.Thread(target=nmap_scan, args=(f"nmap -sN -v {target} -p {port}", output_text)).start()

def fin_scan(target, port, output_text):
    threading.Thread(target=nmap_scan, args=(f"nmap -sF -v {target} -p {port}", output_text)).start()

def xmas_scan(target, port, output_text):
    threading.Thread(target=nmap_scan, args=(f"nmap -sX -v {target} -p {port}", output_text)).start()

def arp_scan(output_text):
    threading.Thread(target=nmap_scan, args=("arp -a", output_text)).start()

def host_discovery(target, output_text):
    threading.Thread(target=nmap_scan, args=(f"nmap -sn {target}", output_text)).start()

def os_detection(target, output_text):
    threading.Thread(target=nmap_scan, args=(f"nmap -O -v {target}", output_text)).start()

def version_detection(target, output_text):
    threading.Thread(target=nmap_scan, args=(f"nmap -sV -v {target}", output_text)).start()

def firewall_evasion(target, output_text):
    threading.Thread(target=nmap_scan, args=(f"nmap -Pn -sS -sV -f -v {target}", output_text)).start()

def create_scan_frame(root, output_text):
    frame = ttk.LabelFrame(root, text="Scans", padding=10)
    frame.pack(side="left", fill="both", expand="yes", padx=10, pady=10)

    ttk.Label(frame, text="Target IP or domain:", font=('Helvetica', 10, 'bold')).grid(row=0, column=0, padx=5, pady=5)
    target_entry = ttk.Entry(frame, width=30)
    target_entry.grid(row=0, column=1, padx=5, pady=5)

    ttk.Label(frame, text="Port:", font=('Helvetica', 10, 'bold')).grid(row=1, column=0, padx=5, pady=5)
    port_entry = ttk.Entry(frame, width=30)
    port_entry.grid(row=1, column=1, padx=5, pady=5)

    scan_buttons = [
        ("TCP Connect Scan", lambda: tcp_connect_scan(target_entry.get(), port_entry.get(), output_text)),
        ("UDP Scan", lambda: udp_scan(target_entry.get(), port_entry.get(), output_text)),
        ("SYN Scan", lambda: syn_scan(target_entry.get(), port_entry.get(), output_text)),
        ("ACK Scan", lambda: ack_scan(target_entry.get(), port_entry.get(), output_text)),
        ("NULL Scan", lambda: null_scan(target_entry.get(), port_entry.get(), output_text)),
        ("FIN Scan", lambda: fin_scan(target_entry.get(), port_entry.get(), output_text)),
        ("XMAS Scan", lambda: xmas_scan(target_entry.get(), port_entry.get(), output_text)),
    ]

    for i, (text, command) in enumerate(scan_buttons):
        ttk.Button(frame, text=text, command=command, width=25).grid(row=i + 2, column=0, columnspan=2, pady=5)

    ttk.Button(frame, text="Stop Scan", command=stop_scan, width=25).grid(row=len(scan_buttons) + 2, column=0, columnspan=2, pady=5)

def create_main_frame(root, output_text):
    frame = ttk.LabelFrame(root, text="Main", padding=10)
    frame.pack(side="right", fill="both", expand="yes", padx=10, pady=10)

    main_buttons = [
        ("Host Discovery", lambda: host_discovery(simpledialog.askstring("Host Discovery", "Enter IP address with range (X.X.X.X/24):"), output_text)),
        ("OS Detection", lambda: os_detection(simpledialog.askstring("OS Detection", "Enter target IP:"), output_text)),
        ("Version Detection", lambda: version_detection(simpledialog.askstring("Version Detection", "Enter target IP:"), output_text)),
        ("Firewall/IDS Evasion", lambda: firewall_evasion(simpledialog.askstring("Firewall/IDS Evasion", "Enter target IP:"), output_text)),
        ("Show Connected Devices (ARP)", lambda: arp_scan(output_text)),
    ]

    for i, (text, command) in enumerate(main_buttons):
        ttk.Button(frame, text=text, command=command, width=30).grid(row=i, column=0, padx=5, pady=5)

def main():
    root = tk.Tk()
    root.title("Network Scanner")
    root.geometry("800x700")

    style = ttk.Style()
    style.configure("TLabel", font=('Helvetica', 10))
    style.configure("TButton", font=('Helvetica', 10))

    output_frame = ttk.Frame(root)
    output_frame.pack(fill="both", expand="yes", padx=10, pady=10)

    output_text = tk.Text(output_frame, wrap="word", height=15, width=80)
    output_text.pack(fill="both", expand="yes")

    output_text.tag_configure('separator', foreground='blue')
    output_text.tag_configure('command', foreground='green')
    output_text.tag_configure('output', foreground='black')
    output_text.tag_configure('error', foreground='red')

    create_main_frame(root, output_text)
    create_scan_frame(root, output_text)

    root.mainloop()

if __name__ == "__main__":
    main()
