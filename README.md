# Telnet Security Scanner

A Python-based GUI tool for scanning networks to identify devices with open Telnet ports (port 23) and testing for autologin vulnerabilities.


## Background: CVE-2026-24061
On January 20, 2026, security researcher Kyu Neushwaistein discovered a critical vulnerability (CVE-2026-24061) in GNU InetUtils telnetd that had been hiding in plain sight for **nearly 11 years**. 
The bug was introduced in May 2015 and affects versions 1.9.3 through 2.7.

### Why This Matters Now

- **CVSS Score: 9.8 (Critical)** – Trivial to exploit, no authentication required
- **Active exploitation** – Within 24 hours of disclosure, attackers were already scanning the internet
- **~214,000+ exposed devices** – Shodan scans show hundreds of thousands of Telnet services still exposed online
- **Embedded systems at risk** – Routers, IoT devices, industrial equipment, and legacy systems often run vulnerable versions and may never receive updates

### The Vulnerability

The telnetd daemon passes the `USER` environment variable directly to the `login` program without sanitization. By setting `USER=-f root`, an attacker triggers the `-f` flag in login, which means "pre-authenticated user" – resulting in instant root shell access without any password.

```bash
# This is literally all it takes:
USER="-f root" telnet -a <target>
```

### Sources

- [The Register: Ancient telnet bug happily hands out root to attackers](https://www.theregister.com/2026/01/22/root_telnet_bug/)
- [BleepingComputer: Hackers exploit critical telnetd auth bypass flaw](https://www.bleepingcomputer.com/news/security/hackers-exploit-critical-telnetd-auth-bypass-flaw-to-get-root/)
- [GNU Security Advisory](https://lists.gnu.org/archive/html/bug-inetutils/2026-01/msg00004.html)

---

## Overview

This tool helps network administrators and security professionals identify vulnerable Telnet services on their networks. It specifically tests for the `-f root` autologin vulnerability, which allows unauthenticated access on misconfigured systems.

## Features

- **IP Range Scanning** – Scan custom IP ranges for open Telnet ports
- **Autologin Vulnerability Detection** – Tests for `-f root` authentication bypass
- **Multi-threaded Scanning** – Configurable thread count for faster scans
- **Real-time Progress** – Live statistics and progress bar
- **Logging** – Automatic logging of vulnerable devices to file
- **User-friendly GUI** – Built with Tkinter for easy operation

## Screenshot

```
┌─────────────────────────────────────────────────────────┐
│         Telnet Security Scanner - Port 23              │
├─────────────────────────────────────────────────────────┤
│  IP Range                                               │
│  Start IP: [192.168.1.1  ]  End IP: [192.168.1.254  ]  │
├─────────────────────────────────────────────────────────┤
│  Settings                                               │
│  Log file: [/path/to/log.txt            ] [Browse...]  │
│  Port: [23]  Threads: [50]  Timeout: [2.0]             │
├─────────────────────────────────────────────────────────┤
│  [▶ Start Scan]  [⬛ Stop]  [🗑 Clear Log]              │
├─────────────────────────────────────────────────────────┤
│  ████████████████████░░░░░░░░░░  67%                   │
│  Scanned: 170/254 | Open ports: 3 | Vulnerable: 1      │
├─────────────────────────────────────────────────────────┤
│  Scan Log                                               │
│  [12:34:56] Starting scan of 254 IP addresses...       │
│  [12:34:57] [+] 192.168.1.45:23 OPEN - testing...      │
│  [12:34:58] [!] 192.168.1.45 VULNERABLE!               │
└─────────────────────────────────────────────────────────┘
```

## Requirements

### Windows
- Download and run `PortScanner.exe` – no additional requirements

### Linux
- Python 3.7 or higher
- Tkinter (usually included with Python)
- Telnet client

### Dependencies

```bash
# Tkinter (if not already installed)
sudo apt install python3-tk

# Telnet client
sudo apt install telnet
```

## Installation

### Windows (Executable)

For Windows users, a pre-built executable is available:

1. Download `PortScanner.exe` from the [Releases](https://github.com/yourusername/telnet-scanner/releases) page
2. Run the executable – no Python installation required

> **Note:** Windows Defender or other antivirus software may flag the executable. This is a false positive due to the network scanning functionality. You may need to add an exception.

### Linux (Python)

```bash
# Clone the repository
git clone https://github.com/yourusername/telnet-scanner.git
cd telnet-scanner

# Make executable (optional)
chmod +x PortScanner.py

# Run
python3 PortScanner.py
```

### Building the Windows Executable

To build the `.exe` yourself using PyInstaller:

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name PortScanner PortScanner.py
```

The executable will be created in the `dist/` folder.

## Usage

1. **Set IP Range** – Enter the start and end IP addresses to scan
2. **Configure Settings**:
   - **Log file** – Where to save vulnerable device records
   - **Port** – Target port (default: 23)
   - **Threads** – Number of concurrent scan threads (default: 50)
   - **Timeout** – Connection timeout in seconds (default: 2.0)
3. **Start Scan** – Click "Start Scan" to begin
4. **Monitor Progress** – Watch real-time statistics and log output
5. **Review Results** – Check the log file for vulnerable devices

## How It Works

1. **Port Check** – First performs a TCP connection test to check if the port is open
2. **Vulnerability Test** – For open ports, attempts Telnet autologin using:
   ```bash
   USER="-f root" telnet -a <target>
   ```
3. **Detection** – Analyzes response for shell indicators (`#`, `$`, `welcome`, etc.)
4. **Logging** – Records vulnerable hosts with timestamps

## The Autologin Vulnerability

The `-f root` vulnerability exploits misconfigured Telnet daemons that trust the `USER` environment variable for authentication. When combined with the `-a` flag (automatic login), this can bypass authentication entirely on vulnerable systems.

**Vulnerable systems include:**
- GNU InetUtils telnetd versions 1.9.3 through 2.7
- Older embedded devices (routers, cameras, IoT)
- Misconfigured BusyBox-based systems
- Legacy network equipment
- Industrial control systems and SCADA devices

**Scale of the problem (January 2026):**
- 214,000+ Telnet services exposed on the internet (Shodan)
- Many embedded devices will never receive patches
- Legacy systems in industrial environments often cannot be updated

## Output Example

Log file (`log.txt`):
```
2024-01-15 14:32:45 - VULNERABLE: 192.168.1.45:23 (telnet autologin with USER='-f root')
2024-01-15 14:33:12 - VULNERABLE: 192.168.1.102:23 (telnet autologin with USER='-f root')
```

## Remediation

If vulnerable devices are found:

1. **Disable Telnet** – Use SSH instead for remote access
2. **Update Firmware** – Check for security patches from the manufacturer
3. **Network Segmentation** – Isolate vulnerable devices on separate VLANs
4. **Firewall Rules** – Block port 23 from untrusted networks
5. **Replace Device** – Consider replacing end-of-life equipment

## Legal Disclaimer

⚠️ **WARNING: Only scan networks you own or have explicit permission to test.**

Unauthorized network scanning may violate:
- Computer Fraud and Abuse Act (USA)
- Computer Misuse Act (UK)
- Similar laws in other jurisdictions

This tool is intended for:
- Network administrators testing their own infrastructure
- Security professionals during authorized penetration tests
- Educational purposes in controlled lab environments

The authors are not responsible for misuse of this tool.

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

### Ideas for Improvement

- [ ] Add CSV/JSON export
- [ ] Support for additional vulnerability checks
- [ ] Windows compatibility
- [ ] Command-line interface mode
- [ ] CIDR notation support
- [ ] Custom credential testing

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

Isak (SA7BNB)

## Acknowledgments

- Python `socket` library for network operations
- Tkinter for the GUI framework
- The security research community for vulnerability documentation
