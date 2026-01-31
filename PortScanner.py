#!/usr/bin/env python3
"""
Telnet Port 23 Security Scanner - GUI Version
Graphical interface for scanning networks for telnet vulnerabilities.

Author: Network Security Scanner
"""

import socket
import subprocess
import os
import ipaddress
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue


class TelnetScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Telnet Security Scanner - Port 23")
        self.root.geometry("700x600")
        self.root.resizable(True, True)
        
        # Variables
        self.scanning = False
        self.stop_requested = False
        self.log_file_path = tk.StringVar(value=os.path.join(os.getcwd(), "log.txt"))
        self.start_ip = tk.StringVar(value="192.168.1.1")
        self.end_ip = tk.StringVar(value="192.168.1.254")
        self.port = tk.IntVar(value=23)
        self.thread_count = tk.IntVar(value=50)
        self.timeout = tk.DoubleVar(value=2.0)
        
        # Statistics
        self.scanned_count = 0
        self.open_count = 0
        self.vulnerable_count = 0
        self.total_ips = 0
        
        # Message queue for thread-safe GUI updates
        self.message_queue = Queue()
        
        self.create_widgets()
        self.process_queue()
    
    def create_widgets(self):
        """Creates all GUI components."""
        
        # Main container with padding
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky="nsew")
        
        # Make window scalable
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # === IP RANGE SECTION ===
        ip_frame = ttk.LabelFrame(main_frame, text="IP Range", padding="10")
        ip_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        ip_frame.columnconfigure(1, weight=1)
        ip_frame.columnconfigure(3, weight=1)
        
        ttk.Label(ip_frame, text="Start IP:").grid(row=0, column=0, sticky="w", padx=(0, 5))
        self.start_ip_entry = ttk.Entry(ip_frame, textvariable=self.start_ip, width=20)
        self.start_ip_entry.grid(row=0, column=1, sticky="w", padx=(0, 20))
        
        ttk.Label(ip_frame, text="End IP:").grid(row=0, column=2, sticky="w", padx=(0, 5))
        self.end_ip_entry = ttk.Entry(ip_frame, textvariable=self.end_ip, width=20)
        self.end_ip_entry.grid(row=0, column=3, sticky="w")
        
        # === SETTINGS SECTION ===
        settings_frame = ttk.LabelFrame(main_frame, text="Settings", padding="10")
        settings_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        settings_frame.columnconfigure(1, weight=1)
        
        # Log file
        ttk.Label(settings_frame, text="Log file:").grid(row=0, column=0, sticky="w", padx=(0, 5))
        log_entry = ttk.Entry(settings_frame, textvariable=self.log_file_path, width=50)
        log_entry.grid(row=0, column=1, sticky="ew", padx=(0, 5))
        ttk.Button(settings_frame, text="Browse...", command=self.browse_log_file).grid(row=0, column=2)
        
        # Port
        ttk.Label(settings_frame, text="Port:").grid(row=1, column=0, sticky="w", padx=(0, 5), pady=(10, 0))
        port_spin = ttk.Spinbox(settings_frame, from_=1, to=65535, textvariable=self.port, width=10)
        port_spin.grid(row=1, column=1, sticky="w", pady=(10, 0))
        
        # Threads and timeout
        ttk.Label(settings_frame, text="Threads:").grid(row=2, column=0, sticky="w", padx=(0, 5), pady=(5, 0))
        thread_spin = ttk.Spinbox(settings_frame, from_=1, to=100, textvariable=self.thread_count, width=10)
        thread_spin.grid(row=2, column=1, sticky="w", pady=(5, 0))
        
        ttk.Label(settings_frame, text="Timeout (sec):").grid(row=3, column=0, sticky="w", padx=(0, 5), pady=(5, 0))
        timeout_spin = ttk.Spinbox(settings_frame, from_=0.5, to=10, increment=0.5, textvariable=self.timeout, width=10)
        timeout_spin.grid(row=3, column=1, sticky="w", pady=(5, 0))
        
        # === BUTTONS ===
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, columnspan=2, pady=10)
        
        self.start_button = ttk.Button(button_frame, text="▶ Start Scan", command=self.start_scan, width=20)
        self.start_button.grid(row=0, column=0, padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="⬛ Stop", command=self.stop_scan, width=20, state="disabled")
        self.stop_button.grid(row=0, column=1, padx=5)
        
        ttk.Button(button_frame, text="🗑 Clear Log", command=self.clear_log, width=15).grid(row=0, column=2, padx=5)
        
        # === PROGRESS ===
        progress_frame = ttk.Frame(main_frame)
        progress_frame.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        progress_frame.columnconfigure(0, weight=1)
        
        self.progress_var = tk.DoubleVar(value=0)
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.grid(row=0, column=0, sticky="ew")
        
        self.status_label = ttk.Label(progress_frame, text="Ready to scan")
        self.status_label.grid(row=1, column=0, sticky="w", pady=(5, 0))
        
        # === STATISTICS ===
        stats_frame = ttk.LabelFrame(main_frame, text="Statistics", padding="10")
        stats_frame.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        
        self.stats_label = ttk.Label(stats_frame, text="Scanned: 0 | Open ports: 0 | Vulnerable: 0")
        self.stats_label.grid(row=0, column=0, sticky="w")
        
        # === LOG OUTPUT ===
        log_frame = ttk.LabelFrame(main_frame, text="Scan Log", padding="10")
        log_frame.grid(row=5, column=0, columnspan=2, sticky="nsew", pady=(0, 10))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(5, weight=1)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=15, state="disabled", 
                                                   font=("Consolas", 9), bg="#1e1e1e", fg="#00ff00")
        self.log_text.grid(row=0, column=0, sticky="nsew")
        
        # Configure tags for colored text
        self.log_text.tag_configure("info", foreground="#00ff00")
        self.log_text.tag_configure("warning", foreground="#ffff00")
        self.log_text.tag_configure("error", foreground="#ff6666")
        self.log_text.tag_configure("success", foreground="#66ff66")
        self.log_text.tag_configure("vulnerable", foreground="#ff0000", font=("Consolas", 9, "bold"))
    
    def browse_log_file(self):
        """Opens file dialog for log file."""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Select log file"
        )
        if filename:
            self.log_file_path.set(filename)
    
    def log_message(self, message, tag="info"):
        """Adds message to queue for thread-safe update."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.message_queue.put((f"[{timestamp}] {message}\n", tag))
    
    def process_queue(self):
        """Processes message queue and updates GUI."""
        while not self.message_queue.empty():
            message, tag = self.message_queue.get()
            self.log_text.configure(state="normal")
            self.log_text.insert(tk.END, message, tag)
            self.log_text.see(tk.END)
            self.log_text.configure(state="disabled")
        
        self.root.after(100, self.process_queue)
    
    def clear_log(self):
        """Clears the log window."""
        self.log_text.configure(state="normal")
        self.log_text.delete(1.0, tk.END)
        self.log_text.configure(state="disabled")
    
    def update_stats(self):
        """Updates the statistics label."""
        self.stats_label.config(
            text=f"Scanned: {self.scanned_count}/{self.total_ips} | "
                 f"Open ports: {self.open_count} | "
                 f"Vulnerable: {self.vulnerable_count}"
        )
        if self.total_ips > 0:
            progress = (self.scanned_count / self.total_ips) * 100
            self.progress_var.set(progress)
    
    def validate_inputs(self):
        """Validates input IP addresses."""
        try:
            start = ipaddress.IPv4Address(self.start_ip.get())
            end = ipaddress.IPv4Address(self.end_ip.get())
            
            if start > end:
                messagebox.showerror("Error", "Start IP must be less than or equal to End IP")
                return False
            
            port = self.port.get()
            if port < 1 or port > 65535:
                messagebox.showerror("Error", "Port must be between 1 and 65535")
                return False
            
            return True
        except ipaddress.AddressValueError as e:
            messagebox.showerror("Invalid IP", f"Invalid IP address: {e}")
            return False
    
    def ip_range(self, start_ip, end_ip):
        """Generates list of IP addresses."""
        start = ipaddress.IPv4Address(start_ip)
        end = ipaddress.IPv4Address(end_ip)
        return [str(ipaddress.IPv4Address(ip)) for ip in range(int(start), int(end) + 1)]
    
    def check_port_open(self, ip, port):
        """Checks if specified port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout.get())
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except (socket.error, socket.timeout):
            return False
    
    def test_telnet_autologin(self, ip, port):
        """Tests telnet autologin vulnerability."""
        try:
            env = {**os.environ, "USER": "-f root"}
            
            # Use port argument if not default
            cmd = ["telnet", "-a", ip, str(port)]
            
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env
            )
            
            try:
                stdout, stderr = process.communicate(timeout=5)
                output = stdout.decode('utf-8', errors='ignore').lower()
                
                success_indicators = ['#', '$', 'welcome', 'last login', 'busybox', ':~']
                fail_indicators = ['login incorrect', 'authentication failed', 'access denied', 
                                   'connection refused', 'login:']
                
                for fail in fail_indicators:
                    if fail in output:
                        return False
                
                for success in success_indicators:
                    if success in output:
                        return True
                        
            except subprocess.TimeoutExpired:
                process.kill()
                
        except Exception:
            pass
        
        return False
    
    def scan_ip(self, ip):
        """Scans a single IP address."""
        if self.stop_requested:
            return None
        
        port = self.port.get()
        result = {"ip": ip, "port_open": False, "vulnerable": False}
        
        if self.check_port_open(ip, port):
            result["port_open"] = True
            self.log_message(f"[+] {ip}:{port} OPEN - testing autologin...", "warning")
            
            if self.test_telnet_autologin(ip, port):
                result["vulnerable"] = True
                self.log_message(f"[!] {ip} VULNERABLE! Autologin successful!", "vulnerable")
        
        return result
    
    def log_to_file(self, ip):
        """Logs vulnerable IP to file."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        port = self.port.get()
        try:
            with open(self.log_file_path.get(), "a") as f:
                f.write(f"{timestamp} - VULNERABLE: {ip}:{port} (telnet autologin with USER='-f root')\n")
        except Exception as e:
            self.log_message(f"Could not write to log file: {e}", "error")
    
    def run_scan(self):
        """Runs the actual scan in a separate thread."""
        ip_list = self.ip_range(self.start_ip.get(), self.end_ip.get())
        self.total_ips = len(ip_list)
        port = self.port.get()
        
        self.log_message(f"Starting scan of {self.total_ips} IP addresses...", "info")
        self.log_message(f"Range: {self.start_ip.get()} -> {self.end_ip.get()}", "info")
        self.log_message(f"Port: {port}", "info")
        self.log_message("-" * 50, "info")
        
        with ThreadPoolExecutor(max_workers=self.thread_count.get()) as executor:
            futures = {executor.submit(self.scan_ip, ip): ip for ip in ip_list}
            
            for future in as_completed(futures):
                if self.stop_requested:
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                
                result = future.result()
                if result:
                    self.scanned_count += 1
                    
                    if result["port_open"]:
                        self.open_count += 1
                    
                    if result["vulnerable"]:
                        self.vulnerable_count += 1
                        self.log_to_file(result["ip"])
                    
                    # Update GUI (thread-safe)
                    self.root.after(0, self.update_stats)
        
        # Scan complete
        self.scanning = False
        self.root.after(0, self.scan_complete)
    
    def scan_complete(self):
        """Called when scan is complete."""
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        
        if self.stop_requested:
            self.status_label.config(text="Scan stopped")
            self.log_message("Scan aborted by user", "warning")
        else:
            self.status_label.config(text="Scan complete!")
            self.log_message("-" * 50, "info")
            self.log_message(f"DONE! Scanned: {self.scanned_count}, Open: {self.open_count}, Vulnerable: {self.vulnerable_count}", "success")
            
            if self.vulnerable_count > 0:
                self.log_message(f"WARNING: {self.vulnerable_count} vulnerable device(s) found!", "vulnerable")
                self.log_message(f"See log file: {self.log_file_path.get()}", "warning")
                messagebox.showwarning(
                    "Vulnerable devices found!",
                    f"{self.vulnerable_count} vulnerable device(s) found!\n\n"
                    f"See {self.log_file_path.get()} for details.\n\n"
                    "Recommendations:\n"
                    "• Disable telnet on these devices\n"
                    "• Use SSH instead\n"
                    "• Update firmware"
                )
            else:
                self.log_message("No vulnerable devices found!", "success")
    
    def start_scan(self):
        """Starts the scan."""
        if not self.validate_inputs():
            return
        
        # Reset variables
        self.scanning = True
        self.stop_requested = False
        self.scanned_count = 0
        self.open_count = 0
        self.vulnerable_count = 0
        self.progress_var.set(0)
        
        # Update buttons
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.status_label.config(text="Scanning...")
        
        # Start scan in separate thread
        scan_thread = threading.Thread(target=self.run_scan, daemon=True)
        scan_thread.start()
    
    def stop_scan(self):
        """Stops the scan."""
        self.stop_requested = True
        self.stop_button.config(state="disabled")
        self.status_label.config(text="Stopping...")


def main():
    root = tk.Tk()
    
    # Try to set a modern theme
    try:
        root.tk.call("source", "azure.tcl")
        root.tk.call("set_theme", "dark")
    except:
        pass
    
    app = TelnetScannerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
