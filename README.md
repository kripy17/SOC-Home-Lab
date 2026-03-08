<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=venom&color=0:0d1117,100:003844&height=200&text=SOC%20Home%20Lab&fontSize=60&fontColor=00e5ff&fontAlignY=55&stroke=00bcd4&strokeWidth=2" />
</p>

<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=500&size=16&duration=3000&pause=1000&color=00bcd4&center=true&vCenter=true&width=700&lines=Endpoint+monitoring+%C2%B7+Sysmon+telemetry+%C2%B7+Live+alert+detection;Built+on+8GB+RAM+%E2%80%94+every+tradeoff+was+deliberate;Phase+3+incoming+%E2%80%94+attack+simulation+%26+incident+investigation" />
</p>

<br>

<p align="center">
  <img src="https://img.shields.io/badge/Phase%201-Complete-2ea44f?style=for-the-badge&labelColor=1a1a1a" />
  <img src="https://img.shields.io/badge/Phase%202-Complete-2ea44f?style=for-the-badge&labelColor=1a1a1a" />
  <img src="https://img.shields.io/badge/Phase%203-In%20Progress-f0a500?style=for-the-badge&labelColor=1a1a1a" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Wazuh-SIEM-0056D2?style=for-the-badge&logoColor=white" />
  <img src="https://img.shields.io/badge/Sysmon-Telemetry-0056D2?style=for-the-badge&logo=windows&logoColor=white" />
  <img src="https://img.shields.io/badge/VMware-Platform-607078?style=for-the-badge&logo=vmware&logoColor=white" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Ubuntu-22.04-E95420?style=for-the-badge&logo=ubuntu&logoColor=white" />
  <img src="https://img.shields.io/badge/Windows-10-0078D6?style=for-the-badge&logo=windows&logoColor=white" />
  <img src="https://img.shields.io/badge/Kali-Linux-268BEE?style=for-the-badge&logo=kali-linux&logoColor=white" />
</p>

<br>

---

## About

This repository documents a **home Security Operations Center** built across three progressive phases — infrastructure deployment, Windows endpoint monitoring, and live attack simulation.

Every phase builds on the last. The goal is to replicate how real SOC teams operate — standing up the monitoring stack, expanding endpoint coverage, then running attacks and investigating alerts end-to-end.

> Built on an **Intel i3 with 8GB RAM** — every architecture decision reflects real resource constraints and deliberate tradeoffs.

<br>

---

## Phases

<br>

<details open>
<summary>&nbsp;✅ &nbsp;<strong>Phase 1 &nbsp;—&nbsp; SIEM Infrastructure & Endpoint Monitoring</strong></summary>

<br>

> 📁 [`/phase-1-wazuh-deployment`](./phase-1-wazuh-deployment)

Deployed a full Wazuh SIEM stack on a hardened Ubuntu Server VM. Onboarded a Kali Linux endpoint via key-based agent authentication. Validated the complete log pipeline from endpoint activity through to dashboard alert visibility using controlled simulations.

```
Stack    →  Wazuh · Ubuntu 22.04 · Kali Linux · VMware · UFW
Network  →  NAT · 192.168.1.0/24 · Isolated subnet
```

| What Was Built | Outcome |
|---|---|
| Wazuh all-in-one deployment | Manager · Indexer · Dashboard · Filebeat ✅ |
| Server hardening | UFW · SSH hardening · minimal attack surface ✅ |
| Kali agent onboarding | Key-based auth · Active status confirmed ✅ |
| Log pipeline validation | Endpoint → Agent → Manager → Indexer → Dashboard ✅ |
| File Integrity Monitoring | `/etc/hosts` modification detected in real time ✅ |
| Attack simulations | Auth abuse · Privilege escalation · Tool install ✅ |

</details>

<br>

<details open>
<summary>&nbsp;✅ &nbsp;<strong>Phase 2 &nbsp;—&nbsp; Windows Telemetry & Sysmon Integration</strong></summary>

<br>

> 📁 [`/phase-2-windows-sysmon`](./phase-2-windows-sysmon)

Extended the lab to include a Windows 10 endpoint. Deployed and registered the Wazuh Windows agent, then integrated Sysmon using the SwiftOnSecurity configuration — enabling detailed process-level telemetry beyond default Windows Event Logs.

```
Stack    →  Wazuh Agent · Sysmon · SwiftOnSecurity config · Windows 10
```

| What Was Built | Outcome |
|---|---|
| Windows agent registration | Active status confirmed in Wazuh Dashboard ✅ |
| Sysmon configuration | SwiftOnSecurity ruleset applied ✅ |
| Process creation telemetry | Full command-line · parent-child chains · Event ID 1 ✅ |
| Network connection telemetry | Per-process with IP/port · Event ID 3 ✅ |
| Registry change telemetry | Key-level granularity · Event ID 13 ✅ |
| Pipeline validation | Sysmon events visible live in Wazuh Dashboard ✅ |

</details>

<br>

<details>
<summary>&nbsp;🔧 &nbsp;<strong>Phase 3 &nbsp;—&nbsp; Attack Simulation & SOC Investigation</strong>&nbsp; <em>(In Progress)</em></summary>

<br>

> 📁 [`/phase-3-attack-simulation`](./phase-3-attack-simulation)

Simulating real attack techniques against the Windows endpoint. Each attack is investigated as a SOC analyst — from raw alert through to a documented incident report with MITRE ATT&CK mapping.

```
Target   →  Windows 10 VM · Sysmon telemetry · Wazuh agent
Method   →  PowerShell scripts · manual attack techniques
Output   →  Incident reports · MITRE ATT&CK mappings
```

| Simulation | MITRE Technique | Key Event IDs | Status |
|---|---|---|---|
| Brute force login attempts | T1110.001 | Windows 4625 | 🔧 Pending |
| Suspicious PowerShell execution | T1059.001 | Sysmon 1 | 🔧 Pending |
| Abnormal process execution | T1055 | Sysmon 1, 8 | 🔧 Pending |
| Registry persistence mechanism | T1547.001 | Sysmon 13 | 🔧 Pending |
| Privilege escalation | T1068 | Windows 4672 | 🔧 Pending |

</details>

<br>

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                      HOST MACHINE                            │
│               VMware Workstation · i3 · 8GB                  │
│                                                              │
│  ┌─────────────────────┐      ┌──────────────────────┐       │
│  │   Ubuntu Server     │      │    Windows 10 VM     │       │
│  │   SOC Node          │◄────►│    Win Endpoint      │       │
│  │                     │      │                      │       │
│  │   Wazuh Manager     │      │   Wazuh Agent        │       │
│  │   Wazuh Indexer     │      │   Sysmon             │       │
│  │   Wazuh Dashboard   │      └──────────────────────┘       │
│  │   Filebeat          │      ┌──────────────────────┐       │
│  │                     │◄────►│    Kali Linux VM     │       │
│  └─────────────────────┘      │    Linux Endpoint    │       │
│                               │    Wazuh Agent       │       │
│                               └──────────────────────┘       │
│                  VMnet8 · NAT · 192.168.1.0/24                │
└──────────────────────────────────────────────────────────────┘
```

---

## Telemetry Pipeline

```
Windows Endpoint
  └── System activity (processes · network · registry · files)
        └── Sysmon (SwiftOnSecurity config)
              └── Wazuh Agent
                    └── port 1514 ──► Wazuh Manager
                                            └── Wazuh Indexer
                                                  └── Wazuh Dashboard
                                                        └── Alert · Search · Investigate
```

---

## Tools & Technologies

| Category | Tools |
|---|---|
| **SIEM** | Wazuh — Manager · Indexer · Dashboard · Filebeat |
| **Endpoint Telemetry** | Sysmon · SwiftOnSecurity configuration |
| **Operating Systems** | Ubuntu Server 22.04 · Windows 10 · Kali Linux |
| **Virtualisation** | VMware Workstation |
| **Log Sources** | Windows Event Logs · Sysmon · Linux Auth Logs · PAM |
| **Detection** | Wazuh built-in rules · File Integrity Monitoring |
| **Framework** | MITRE ATT&CK |
| **Simulation** | PowerShell scripts · Manual attack techniques |

---

## Repository Structure

```
SOC-Home-Lab/
│
├── README.md
│
├── phase-1-wazuh-deployment/
│   ├── README.md
│   └── screenshots/
│       ├── ubuntu/
│       ├── wazuh/
│       ├── agent/
│       └── attacks/
│           ├── kali/
│           └── dashboard/
│
├── phase-2-windows-sysmon/
│   ├── README.md
│   └── screenshots/
│       ├── windows/
│       └── wazuh/
│
└── phase-3-attack-simulation/
    ├── README.md
    ├── screenshots/
    └── incident_reports/
        ├── incident_bruteforce.md
        ├── incident_powershell.md
        ├── incident_abnormal_process.md
        ├── incident_persistence.md
        └── incident_privilege_escalation.md
```

---

## Hardware

| Resource | Spec |
|---|---|
| CPU | Intel Core i3 |
| RAM | 8 GB total |
| Virtualisation | VMware Workstation |
| SOC Server VM | 4 GB · 2 cores · 40 GB |
| Windows Endpoint VM | 4 GB · 2 cores · 40 GB |
| Kali Linux VM | 2 GB · 2 cores · 30 GB |

<br>

---

<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=venom&color=0:003844,100:0d1117&height=120&section=footer&fontColor=00e5ff&fontSize=14&text=All%20endpoints%20monitored.%20All%20logs%20analyzed.%20No%20alert%20ignored." />
</p>

<p align="center">
  <sub>
    <a href="./phase-1-wazuh-deployment">Phase 1: SIEM Infrastructure</a> ✅ &nbsp;·&nbsp;
    <a href="./phase-2-windows-sysmon">Phase 2: Windows + Sysmon</a> ✅ &nbsp;·&nbsp;
    Phase 3: Attack Simulation 🔧
    <br><br>
    <a href="https://github.com/kripy17">Krish Patel</a> &nbsp;·&nbsp; SOC Home Lab Series
  </sub>
</p>
