# IDS Evasion and Detection using Snort

Deploying **Snort** as a network intrusion detection system on a cloud Ubuntu server, attacking it from a Kali Linux VM, and writing custom rules to detect reconnaissance, SSH brute-force, XSS and (obfuscated) SQL injection traffic.

![Snort](https://img.shields.io/badge/IDS-Snort-E8352E)
![Mode](https://img.shields.io/badge/Mode-NIDS-blueviolet)
![DigitalOcean](https://img.shields.io/badge/DigitalOcean-Ubuntu%20Droplet-0080FF)
![Kali](https://img.shields.io/badge/Attacker-Kali%20Linux-557C94)
![VirtualBox](https://img.shields.io/badge/Hypervisor-VirtualBox-183A61)
![Attacks](https://img.shields.io/badge/Attacks-Nmap%20%7C%20SSH%20%7C%20XSS%20%7C%20SQLi-red)

📄 **Full report:** [`IDS Evasion and Detection using Snort (PDF)`](docs/report.pdf)
<!-- MSc in Computing in Applied Cyber Security — Technological University Dublin -->
<!-- Author: Abhang Nitinkumar Mandwale -->

---

## Table of Contents

- [Overview](#overview)
- [Lab Architecture](#lab-architecture)
- [Setup](#setup)
  - [Victim Machine (Ubuntu + Snort)](#victim-machine-ubuntu--snort)
  - [Attack Machine (Kali Linux)](#attack-machine-kali-linux)
  - [Communication Establishment](#communication-establishment)
  - [Snort Configuration](#snort-configuration)
- [Custom Detection Rules](#custom-detection-rules)
- [Attacks and Detections](#attacks-and-detections)
  - [1. Nmap Scan Detection](#1-nmap-scan-detection)
  - [2. SSH Brute-Force Attempt](#2-ssh-brute-force-attempt)
  - [3. XSS Payload](#3-xss-payload)
  - [4. SQL Injection (Obfuscated Payload)](#4-sql-injection-obfuscated-payload)
- [Challenges](#challenges)
- [Learnings](#learnings)
- [Future Improvements](#future-improvements)
- [Conclusion](#conclusion)
- [References](#references)

---

## Overview

Intrusion Detection Systems (IDS) monitor traffic to detect malicious activity, cyber attacks and potential security policy violations. They are deployed alongside firewalls and connected to SIEM systems for log correlation. An IDS only *detects* malicious traffic; *prevention* is handled by Intrusion Prevention Systems (IPS).

The two main types of IDS, based on where they are deployed:

| Type | Description |
|------|-------------|
| **Network-Based IDS (NIDS)** | Deployed to capture traffic coming from the entire network |
| **Host-Based IDS (HIDS)** | Deployed to capture changes made within the host machine |

**Snort** is a widely known open-source intrusion detection and prevention system, classified as a network-based IDS. It detects attacks using rules, and with community-written rules it can detect attacks such as EternalBlue and attacks on Log4j. Snort runs fully in the terminal, which avoids the CPU overhead of GUI-based systems and makes it well suited to machines accessed over SSH.

This project covers the deployment and configuration of Snort, a set of attack/evasion techniques, and the rules used to detect them.

---

## Lab Architecture

```
┌──────────────────────────┐                    ┌──────────────────────────┐
│ Kali Linux Attack Machine│ ─ ─ ─ ─ ─ ─ ─ ─ ─ ▶│  Ubuntu Victim Machine   │
├──────────────────────────┤                    ├──────────────────────────┤
│   VirtualBox Hypervisor  │                    │  DigitalOcean Droplet    │
├──────────────────────────┤                    └──────────────────────────┘
│      Local Machine       │
└──────────────────────────┘
```

| Role | Platform | OS | Purpose |
|------|----------|----|---------|
| Victim | DigitalOcean Droplet (cloud VM) | Ubuntu | Hosts Snort; target of the attacks |
| Attacker | Oracle VirtualBox (local VM) | Kali Linux | Launches attacks using pre-loaded security tools |

---

## Setup

### Victim Machine (Ubuntu + Snort)

```bash
# Update existing packages
sudo apt-get update

# Install Snort
sudo apt-get install snort -y

# Verify the installation
snort --version
```

### Attack Machine (Kali Linux)

1. Install Oracle VirtualBox (any other hypervisor can also be used).
2. Download the Kali Linux ISO and load it into VirtualBox.
3. Allocate enough RAM and storage for the VM to run without issues.

> **Tip:** Older, stable versions of VirtualBox and Kali are recommended, as the newest versions are usually more prone to bugs.

### Communication Establishment

**DigitalOcean firewall (victim):** Add inbound rules allowing the public IP of the local network for every port used in the attacks. The public IP can be checked using `icanhazip`.

| Type | Protocol | Port Range |
|------|----------|------------|
| ICMP | ICMP | — |
| SSH | TCP | 22 |
| HTTP | TCP | 80 |

**VirtualBox network (attacker):** Change the adapter's attachment type from **NAT** to **Bridged Adapter**. This makes the Kali VM appear as a separate device on the network with its own IP address.

### Snort Configuration

By default, Snort uses `snort.conf` as the main source for all rules. Before running it, set `HOME_NET` to the local IP range in `/etc/snort/snort.conf`:

```conf
ipvar HOME_NET 192.168.0.0/16
ipvar EXTERNAL_NET any
```

The custom rules file is included in `snort.conf`:

```conf
include $RULE_PATH/local.rules
```

**Self-test mode** — verify Snort can read all available rules:

```bash
snort -T -i eth0 -c /etc/snort/snort.conf
```

Self-test output summary:

```
4061 Snort rules read
    3367 detection rules
    0 decoder rules
    0 preprocessor rules
3387 Option Chains linked into 951 Chain Headers
```

**Running Snort in console alert mode:**

```bash
snort -q -l /var/log/snort -i eth0 -A console -c /etc/snort/snort.conf
```

---

## Custom Detection Rules

All custom rules are added to `/etc/snort/rules/local.rules`:

```snort
alert icmp any any -> any any (msg:"ICMP Connection Detected"; sid:1000001; rev:1;)
alert tcp any any -> any 22 (msg:"Attempted SSH Authentication"; sid:1000002; rev:1;)
alert tcp any any -> any 80 (msg:"XSS Entry Detected"; content:"<script>"; nocase; sid:1000003; rev:1;)
alert tcp any any -> any 80 (msg:"SQL Query Detected"; content:"' OR 1=1 --"; http_uri; nocase; sid:1000004; rev:1;)
```

| SID | Protocol / Port | Detects |
|-----|-----------------|---------|
| 1000001 | ICMP | Nmap scans and pings |
| 1000002 | TCP / 22 | SSH connection / brute-force attempts |
| 1000003 | TCP / 80 | XSS payloads containing `<script>` |
| 1000004 | TCP / 80 | SQL injection (`' OR 1=1 --`), plain and URL-encoded |

---

## Attacks and Detections

### 1. Nmap Scan Detection

Reconnaissance is the first step of any cyber attack. Nmap, a built-in Kali tool, can scan all 65,535 TCP ports of a given IP address. Scanning the victim also confirms the communication setup works.

- **Result:** Port 22 (SSH) was found open on the victim.
- **Detection:** Nmap scans fall under the ICMP category and trigger rule `1000001`. A simple `ping` to the victim triggers the same alert, since ping also uses ICMP.

```
[**] [1:1000001:1] ICMP Connection Detected [**] [Priority: 0] {ICMP} ...
```

### 2. SSH Brute-Force Attempt

With port 22 open, an SSH credential brute-force attack was launched from Kali using Hydra.

- **Result:** No password was recovered — the cloud-hosted victim is required to use a secure password.
- **Detection:** Every SSH connection attempt on port 22 triggered rule `1000002`.

```
[**] [1:1000002:1] Attempted SSH Authentication [**] [Priority: 0] {TCP} ...
```

**Observation:** Alongside the attack machine's traffic, Snort captured SSH traffic from **other source IPs** — real threat actors trying to break into the victim, because port 22 was open to the whole internet. This can be mitigated by allowing only the attacker's IP in the DigitalOcean firewall, and shows the value of a password that cannot be cracked by brute force.

### 3. XSS Payload

Cross-Site Scripting (XSS) is an injection attack in which a threat actor compromises a user's interaction with a web application by sending malicious JavaScript to the browser. It can be used to steal session cookies, extract confidential user data or modify how a website is presented.

**Start a web server on the victim:**

```bash
python3 -m http.server 80
```

Port 80 then shows as open in an Nmap scan.

**Payload sent from Kali:**

```bash
curl "http://<VICTIM_IP>/?q=<script>alert(1)</script>"
```

- **Detection:** Rule `1000003` matches on `<script>` only, rather than the full payload. This catches the test payload as well as **any other payload that uses the script tag**.

```
[**] [1:1000003:1] XSS Entry Detected [**] [Priority: 0] {TCP} ...
```

### 4. SQL Injection (Obfuscated Payload)

SQL Injection is a server-side vulnerability that tricks databases into granting unauthorized access, commonly used on login forms to log into accounts without credentials — including gaining admin access to web applications. This attack also uses the web server on port 80.

| Payload | Form |
|---------|------|
| `' OR 1=1 --` | Plain — common and easy to catch |
| `%27%20OR%201%3D1%20--` | URL-encoded — used by threat actors to bypass weak security measures |

The obfuscated payload was used for the attack:

```bash
curl "http://<VICTIM_IP>/?q=%27%20OR%201%3D1%20--"
```

- **Detection:** Rule `1000004` is written with the **non-obfuscated** payload and the `http_uri` modifier, yet it catches **both** the obfuscated and plain payloads.

```
[**] [1:1000004:1] SQL Query Detected [**] [Priority: 0] {TCP} ...
```

---

## Challenges

- **Configuration and connectivity:** Establishing communication between the two machines took the most effort — in particular, switching the Kali VM from NAT to Bridged Adapter and finding the local network's public IP.
- **Noise on port 22:** With port 22 open to the entire internet, the volume of malicious SSH traffic made it difficult to isolate the Kali machine's traffic. Fix: allow only the Kali machine's IP in the DigitalOcean firewall settings.

## Learnings

- Hands-on understanding of Snort IDS configuration.
- Making two machines communicate regardless of their geographical separation.
- The capabilities of intrusion detection systems, and how versatile and robust open-source tools like Snort can be for corporate networks.

## Future Improvements

- Explore deeper attack methodologies using **Metasploit**, e.g. targeting the **EternalBlue** vulnerability on Windows systems.
- Review how community-written rules are engineered, to write better and more efficient rules.
- Use Snort's **IPS** capabilities to proactively prevent malicious traffic instead of only detecting it.
- Feed alerts into a **SIEM** or **SOAR** system for faster detection, and use SOAR automation to blacklist malicious IPs and raise incidents.

## Conclusion

This project shows how computers communicate and how any traffic reaching a machine can be detected. It also highlights the need for continuous monitoring and configuration management of IDS in organizations — rules must be revised regularly to detect and prevent new attacks. Snort is easy to work with, has great potential for detecting far more complex attacks, and as an open-source tool makes IDS deployment cost-efficient.

---

## References

1. Splunk, "Intrusion Detection Systems (IDS): Definition, Types, Purpose", Sep 3, 2024. https://www.splunk.com/en_us/blog/learn/ids-intrusion-detection-systems.html
2. Fortinet, "What is Snort?". https://www.fortinet.com/resources/cyberglossary/snort
3. Oracle VirtualBox, "VirtualBox". https://www.virtualbox.org/
4. OffSec, "Kali". https://www.kali.org/
5. SkillsBuild Security, "Installing & Configuring SNORT Network Intrusion Detection System", Sep 3, 2025. https://www.youtube.com/watch?v=RSeAlWnZUWA
6. HackerSploit, "Intrusion Detection With Snort", May 20, 2022. https://youtu.be/Gh0sweT-G30
7. Nmap, "Nmap.org". https://nmap.org/
8. Trend Micro, "What is SSH Brute Force Attack And How To Deal With It", May 9, 2023. https://helpcenter.trendmicro.com/en-us/article/tmka-19689
9. OWASP, "Cross Site Scripting (XSS)". https://owasp.org/www-community/attacks/xss/
10. OWASP, "SQL Injection". https://owasp.org/www-community/attacks/SQL_Injection
11. Ritwik Gupta, "IDS Evasion Techniques - SNORT". LinkedIn project.
