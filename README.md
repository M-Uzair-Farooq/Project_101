#  Project 101 - IDS/IPS  

This project is a GUI-based Intrusion Detection and Prevention System (IDS/IPS) developed using Python. It monitors network traffic, detects suspicious activities based on user-defined rules, and takes action (e.g., blocking IPs, dropping packets). A web-based interface provides visualization and control.

---

## 📌 Features

- 🔍 Real-time packet sniffing and analysis
- 📁 Rule-based detection from CSV file
- 🚫 IP blocking using `iptables`
- 🧹 Packet dropping on suspicious activity
- 🖥️ Web-based GUI with Flask
  - Home page dashboard
  - View and manage rules
  - View blocked IPs
  - Alerts and logs page

---

## 🧠 How It Works

1. **Packet Capture**: Uses raw sockets to capture network packets.
2. **Packet Parsing**: Extracts IPv4 and TCP headers to gather IPs, ports, and flags.
3. **Rule Matching**: Matches incoming packets with rules defined in `rules.csv`.
4. **Threshold Checks**: Triggers alerts if rule conditions are repeatedly met.
5. **Action**:
   - Logs the incident in `logs.txt`
   - Drops the packet
   - Blocks the source IP (appends to `blocked_ip.txt`)

---

## 🛠️ Files Overview

| File | Description |
|------|-------------|
| `main.py` | Core script to capture, analyze, and act on network packets |
| `rules.csv` | CSV file containing detection rules |
| `blocked_ip.txt` | Stores list of blocked IPs |
| `logs.txt` | Intrusion detection logs |
| `templates/*.html` | GUI pages: Home, Alerts, Rules, Logs, etc. |
| `app.py` | Flask application to run the GUI |

---

## 📷 GUI Screenshots

- 🏠 Home Page
- 🚨 Alerts Page
- 🚫 Blocked IPs Page
- ⚙️ Rules Management Page
- 📜 Logs Page
- ▶️ Start Page (to launch IDS)

---

## 🚀 Getting Started

### ⚙️ Prerequisites

- Python 3.x
- Linux-based system (required for `AF_PACKET` and `iptables`)
- Root privileges

### 📦 Install Dependencies

```bash
pip install flask
```

### ▶️ Run the IDS

```bash
sudo python3 main.py
```

### 🖥️ Run the GUI

```bash
python3 app.py
```

Then open [http://localhost:5000](http://localhost:5000) in your browser.

---

## 📄 Rule Format (rules.csv)

Each rule should include:

```
RuleID,Direction,SourceIP,DestinationIP,SourcePort,DestinationPort,Flags,ThresholdCount,ThresholdSeconds
1,inbound,*,*,*,*,*,10,5
```

---

## 🛡️ Disclaimer

This is a project built for educational purposes. Modifying `iptables` and using raw sockets may disrupt your network if not handled carefully.

---


