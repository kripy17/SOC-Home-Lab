<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=rect&color=0:0a0a0a,100:0d1117&height=180&text=SOC%20HOME%20LAB&fontSize=58&fontColor=00ff41&fontAlignY=52&stroke=00ff41&strokeWidth=1&desc=%5B%20Endpoint%20Detection%20%7C%20Threat%20Simulation%20%7C%20Incident%20Investigation%20%5D&descSize=13&descAlignY=73&descFontColor=4a9a5a" />
</p>

<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=500&size=15&duration=3000&pause=1000&color=00ff41&center=true&vCenter=true&width=750&lines=%24+sudo+.%2Fwazuh-install.sh+-a+%E2%80%94+SIEM+deployed+successfully;%24+5+attacks+simulated+%7C+68+alerts+generated+%7C+5+incidents+documented;%24+wazuh-agent+status%3A+ACTIVE+%7C+sysmon%3A+RUNNING+%7C+pipeline%3A+OPERATIONAL;%24+all+endpoints+monitored.+no+alert+ignored." />
</p>

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

<details open>
<summary>&nbsp;✅ &nbsp;<strong>Phase 3 &nbsp;—&nbsp; Attack Simulation & SOC Investigation</strong></summary>

<br>

> 📁 [`/phase-3-attack-simulation`](./phase-3-attack-simulation)

Simulated 5 real attack techniques against the Windows endpoint. Each attack was investigated as a SOC analyst — from raw alert through to a documented incident report with MITRE ATT&CK mapping. Detection gaps and false positives were identified and documented.

```
Target   →  Windows 10 VM · Sysmon telemetry · Wazuh agent
Method   →  PowerShell scripts · manual attack techniques
Output   →  5 incident reports · MITRE ATT&CK mappings · detection gap analysis
```

| Simulation | MITRE Technique | Key Event IDs | Alerts | Verdict |
|---|---|---|---|---|
| Brute force login attempts | T1110.001 | Windows 4625, 4740 | 11 | ✅ True Positive |
| Suspicious PowerShell execution | T1059.001 · T1027 | Sysmon 1 · PS 4104 | 14 | ✅ TP + FP identified |
| Abnormal process execution | T1059.003 · T1082 | Sysmon 1 | 33 | ✅ True Positive |
| Registry persistence mechanism | T1547.001 | Sysmon 13 | 3 | ✅ True Positive |
| Privilege escalation | T1134 · T1134.001 | Sysmon 1 · 4672 | 7 | ⚠️ Partial — gap identified |

> 📄 All 5 attacks are fully documented in [`/phase-3-attack-simulation/incident_reports/README.md`](./phase-3-attack-simulation/incident_reports/README.md) — including alert tables, triage notes, false positive analysis, detection gaps, and MITRE ATT&CK mappings.

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
│                  VMnet8 · NAT · 192.168.1.0/24               │
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
    │   ├── bruteforce/
    │   ├── powershell/
    │   ├── abnormal_process/
    │   ├── persistence/
    │   └── privilege_escalation/
    └── incident_reports/
        └── incident_reports.md
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
  <img src="https://capsule-render.vercel.app/api?type=rect&color=0:0d1117,100:0a0a0a&height=100&section=footer&fontColor=00ff41&fontSize=13&text=%5BSOC-HOME-LAB%5D%20%24%20All%20phases%20complete.%20All%20endpoints%20monitored.%20No%20alert%20ignored.&stroke=00ff41&strokeWidth=1" />
</p>

<p align="center">
  <sub>
    <a href="./phase-1-wazuh-deployment">Phase 1: SIEM Infrastructure</a> ✅ &nbsp;·&nbsp;
    <a href="./phase-2-windows-sysmon">Phase 2: Windows + Sysmon</a> ✅ &nbsp;·&nbsp;
    <a href="./phase-3-attack-simulation">Phase 3: Attack Simulation</a> ✅
    <br><br>
    <a href="https://github.com/sockr17">Krish Patel</a> &nbsp;·&nbsp; SOC Home Lab Series
  </sub>
</p>
