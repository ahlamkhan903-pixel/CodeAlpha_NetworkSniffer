# 🔍 CodeAlpha — Basic Network Sniffer

A Python-based network packet sniffer built as part of the **CodeAlpha Cybersecurity Internship (Task 1)**.

---

## 📌 About

This tool captures live network traffic and displays detailed information about each packet including:
- Source and Destination IP addresses
- Protocol (TCP / UDP / ICMP)
- Source and Destination Port numbers
- Common service identification (HTTP, HTTPS, DNS, SSH, etc.)
- Packet payload preview (first 80 bytes)

Built using **Python** and the **Scapy** library.

---

## 🛠️ Requirements

- Python 3.x
- Scapy library
- **Administrator / Root privileges** (required to capture raw packets)

---

## ⚙️ Installation

**Step 1 — Clone the repository:**
```bash
git clone https://github.com/ahlamkhan903-pixel/CodeAlpha_NetworkSniffer.git
cd CodeAlpha_NetworkSniffer
```

**Step 2 — Install dependencies:**
```bash
pip install -r requirements.txt
```

> **Windows users:** Also install [Npcap](https://npcap.com/) — required for Scapy to capture packets on Windows.

---

## 🚀 Usage

**Run with default settings (capture all IP packets):**

```bash
# Linux / macOS
sudo python3 network_sniffer.py

# Windows (run Command Prompt as Administrator)
python network_sniffer.py
```

**Capture only 20 packets then stop:**
```bash
sudo python3 network_sniffer.py -c 20
```

**Capture only HTTP traffic (port 80):**
```bash
sudo python3 network_sniffer.py -f "port 80"
```

**Capture only TCP packets:**
```bash
sudo python3 network_sniffer.py -f "tcp"
```

**Capture only ICMP (ping) packets:**
```bash
sudo python3 network_sniffer.py -f "icmp"
```

Press **Ctrl+C** at any time to stop capturing and see a summary.

---

## 📸 Sample Output

```
╔══════════════════════════════════════════════════════╗
║        CodeAlpha — Basic Network Sniffer             ║
║        Cybersecurity Internship Task 1               ║
╚══════════════════════════════════════════════════════╝

  Filter   : ip
  Count    : Unlimited
  Started  : 2024-01-15 10:30:00
  Press Ctrl+C to stop capturing.

─────────────────────────────────────────────────────────

[Packet #1]  ⏰ 10:30:01
  Source IP       : 192.168.1.5
  Dest IP         : 142.250.80.46
  Protocol        : TCP
  Src Port        : 54321
  Dst Port        : 443
  TCP Flags       : PA
  Service         : HTTPS (Secure Web)
  ───────────────────────────────────────────────────────

[Packet #2]  ⏰ 10:30:01
  Source IP       : 192.168.1.5
  Dest IP         : 8.8.8.8
  Protocol        : UDP
  Src Port        : 50234
  Dst Port        : 53
  Service         : DNS
  ───────────────────────────────────────────────────────
```

---

## 📚 How It Works

| Concept | Explanation |
|--------|------------|
| **Packet** | A small unit of data traveling through a network |
| **IP Layer** | Contains source & destination IP addresses |
| **TCP** | Connection-oriented protocol used by HTTP, HTTPS, SSH |
| **UDP** | Connectionless protocol used by DNS, streaming |
| **ICMP** | Used for network diagnostics (e.g., ping) |
| **Port** | A number identifying a specific service (e.g., 80 = HTTP) |
| **Payload** | The actual data content inside the packet |
| **BPF Filter** | Berkeley Packet Filter — used to select specific traffic |

---

## ⚠️ Legal Disclaimer

This tool is built **for educational purposes only** as part of the CodeAlpha internship program.  
Only use it on networks you own or have explicit permission to monitor.  
Unauthorized packet sniffing is **illegal** and unethical.

---

## 👤 Author

- **Name:** [Ahlam]  
- **Internship:** CodeAlpha Cybersecurity Internship  
- **LinkedIn:** [Your LinkedIn Profile]  
- **GitHub:** [Your GitHub Profile]

---

## 🏢 About CodeAlpha

CodeAlpha is a leading software development company dedicated to building secure and resilient systems.  
Website: [www.codealpha.tech](https://www.codealpha.tech)
