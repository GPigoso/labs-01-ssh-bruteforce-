[port_scan_detection.md](https://github.com/user-attachments/files/26660295/port_scan_detection.md)
# Port Scan Detection with Splunk

**Author:** Guilherme Pigoso  
**GitHub:** [github.com/GPigoso](https://github.com/GPigoso)  
**Date:** April 2026  
**Difficulty:** Beginner  
**Category:** Blue Team | SIEM | Network Detection  

---

## Objective

Simulate a port scan attack in a controlled home lab environment, capture the network traffic, and detect the scanning activity using Splunk. The goal is to demonstrate the ability to identify reconnaissance activity — one of the earliest stages of an attack — using network logs and SIEM queries.

---

## Environment

| Component | Details |
|---|---|
| **Attacker** | Kali Linux (192.168.56.103) |
| **Target** | Metasploitable2 (192.168.56.102) |
| **SIEM** | Splunk Enterprise (running on Kali) |
| **Network** | VirtualBox Host-Only Adapter |
| **Virtualization** | Oracle VirtualBox |

---

## Tools Used

| Tool | Purpose |
|---|---|
| **Nmap** | Port scan simulation |
| **tcpdump** | Network traffic capture |
| **Splunk Enterprise** | Log ingestion, detection query and alerting |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Reconnaissance | Active Scanning: Scanning IP Blocks | T1595.001 |
| Discovery | Network Service Discovery | T1046 |

---

## Attack Simulation

### Step 1 — Run a SYN Scan with Nmap

```bash
nmap -sS -p 1-1000 192.168.56.102
```

**Command breakdown:**
- `-sS` — SYN Scan (Stealth Scan): sends SYN packets without completing the TCP handshake, making it faster and harder to detect than a full connect scan
- `-p 1-1000` — scans the 1000 most common ports

**Result:** 13 open ports identified on Metasploitable2:

```
PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
23/tcp  open  telnet
25/tcp  open  smtp
53/tcp  open  domain
80/tcp  open  http
111/tcp open  rpcbind
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
512/tcp open  exec
513/tcp open  login
514/tcp open  shell
```

**Notable high-risk ports:**
- **23 (Telnet)** — transmits data in plaintext, highly insecure
- **445 (SMB)** — common ransomware target
- **512/513/514** — legacy services with known vulnerabilities

---

## Traffic Capture

### Step 2 — Capture network traffic with tcpdump

On Terminal 1 (Kali), start capturing traffic on the Host-Only interface:

```bash
sudo tcpdump -i eth1 host 192.168.56.102 -w /tmp/portscan.pcap
```

**Command breakdown:**
- `-i eth1` — Host-Only network interface
- `host 192.168.56.102` — filter traffic to/from Metasploitable2
- `-w /tmp/portscan.pcap` — save capture to file

On Terminal 2 (Kali), run the port scan:

```bash
nmap -sS -p 1-1000 192.168.56.102
```

After the scan completes, stop tcpdump with **Ctrl+C**.

---

## Log Ingestion

### Step 3 — Send captured traffic to Splunk

Convert the pcap to readable text and send to Splunk via TCP port 8888:

```bash
sudo tcpdump -r /tmp/portscan.pcap -nn | nc 192.168.56.103 8888
```

**Command breakdown:**
- `-r /tmp/portscan.pcap` — read from capture file
- `-nn` — display IPs and ports as numbers (no DNS resolution)
- `| nc 192.168.56.103 8888` — pipe output to Splunk listener

The raw logs confirm the SYN scan signature — `Flags [S]` packets from attacker and `Flags [R.]` RST responses from closed ports:

```
11:06:10.378353 IP 192.168.56.103.34947 > 192.168.56.102.970: Flags [S], seq 1884254094, win 1024
11:06:10.379293 IP 192.168.56.102.970 > 192.168.56.103.34947: Flags [R.], seq 0, ack 1884254095
```

![Raw Logs in Splunk](screenshots/screenshot3.png)

---

## Detection

### Step 4 — Query to detect port scan activity

```splunk
index=* 192.168.56.102 
| rex "(?P<src_ip>\d+\.\d+\.\d+\.\d+)\.\d+ > (?P<dst_ip>\d+\.\d+\.\d+\.\d+)\.(?P<dst_port>\d+)" 
| stats dc(dst_port) as ports_scanned by src_ip 
| where ports_scanned > 10
```

**Query breakdown:**
- `index=* 192.168.56.102` — filter events involving the target
- `rex "..."` — extract source IP, destination IP and destination port using regex
- `stats dc(dst_port) as ports_scanned by src_ip` — count distinct ports contacted per source IP
- `where ports_scanned > 10` — flag IPs that contacted more than 10 distinct ports (port scan signature)

**Result:** IP `192.168.56.103` detected scanning **1000 ports** — confirmed port scan activity.

![Splunk Detection Query](screenshots/screenshot2.png)

---

## Alerting

### Step 5 — Create automated alert in Splunk

- **Alert name:** Port Scan Detection
- **Type:** Scheduled — runs every hour
- **Trigger condition:** Number of results > 0
- **Action:** Add to Triggered Alerts
- **Status:** Enabled

![Splunk Alert Configuration](screenshots/screenshot1.png)

---

## Key Takeaways

- A SYN scan generates a high volume of `Flags [S]` packets followed by `Flags [R.]` RST responses — this is the network signature of Nmap `-sS`
- Port scanning is a **Reconnaissance** technique — it happens before the actual attack. Detecting it early gives defenders time to respond
- A simple threshold-based rule (more than 10 distinct ports from the same IP) is an effective first detection layer
- In a real SOC environment, this alert would trigger an investigation to determine the intent of the scan and whether exploitation followed

---

## Next Steps

- Tune the threshold based on environment baseline — reduce false positives
- Correlate port scan alerts with subsequent exploitation attempts in the same SIEM
- Implement **GeoIP lookup** to flag scans from unexpected geographic locations
- Extend detection to cover **UDP scans** and **version detection scans** (`-sV`)
- Map to **MITRE ATT&CK Navigator** to visualise coverage
