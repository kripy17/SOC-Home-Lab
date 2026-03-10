# Phase 3 — Incident Reports
### SOC Home Lab · Attack Simulation & Investigation
*Windows 10 Endpoint · Wazuh SIEM · Sysmon Telemetry*

---

## Table of Contents

| ID | Incident | Severity | Status |
|---|---|---|---|
| [INC-001](#inc-001--brute-force-login-attempt) | Brute Force Login Attempt | 🟠 High | ✅ Investigated |
| [INC-002](#inc-002--suspicious-powershell-execution) | Suspicious PowerShell Execution | 🔴 Critical | ✅ Investigated |
| [INC-003](#inc-003--abnormal-process-execution) | Abnormal Process Execution | 🟠 High | ✅ Investigated |
| [INC-004](#inc-004--registry-persistence-mechanism) | Registry Persistence Mechanism | 🟠 High | ✅ Investigated |
| [INC-005](#inc-005--privilege-escalation-attempt) | Privilege Escalation Attempt | 🟠 High | ✅ Investigated |

---

## INC-001 — Brute Force Login Attempt

**Date:** 2026-03-10
**Severity:** 🟠 High
**Status:** ✅ Investigated — True Positive

---

### Summary

A simulated brute force attack was launched against the Windows 10 endpoint using a PowerShell script that generated 20 consecutive failed login attempts against the local account `desktop-bhlhrb8\krish patel`. Wazuh successfully detected the attack across three escalating rule levels — from individual failures through pattern recognition to account lockout.

---

### Attack Details

```
Target Account   →  desktop-bhlhrb8\krish patel
Method           →  PowerShell script — 20 failed login attempts
Wrong Password   →  WrongPassword123!
Duration         →  ~20 seconds (1 attempt per second)
```

---

### Detection Evidence

| Rule ID | Description | Level | Count |
|---|---|---|---|
| 60204 | Multiple Windows Logon Failures | 10 | 1 |
| 60115 | User account locked out (multiple login errors) | 9 | 1 |
| 60122 | Logon Failure - Unknown user or bad password | 5 | 9 |

**Total Alerts Generated:** 11
**Key Event ID:** Windows 4625 — Logon Failure · Windows 4740 — Account Lockout

**Screenshots:**
- `screenshots/bruteforce/phase3_dashboard_ready.png` — baseline before attack
- `screenshots/bruteforce/bruteforce_powershell_executed.png` — script execution
- `screenshots/bruteforce/bruteforce_alerts_wazuh.png` — alert spike in Discover
- `screenshots/bruteforce/bruteforce_alert_detail.png` — expanded alert detail
- `screenshots/bruteforce/bruteforce_eventviewer_4625.png` — Event Viewer 4625 entries

---

### Investigation Steps

1. **Alert triage** — Rule 60204 (Multiple Logon Failures, Level 10) was the first high-confidence indicator. Multiple 4625 events in rapid succession confirmed brute force pattern rather than accidental mistype.
2. **Account lockout confirmed** — Rule 60115 (Level 9) fired indicating the account was locked out, confirming the volume of failures exceeded the lockout threshold.
3. **Timeline analysis** — Events spaced ~1 second apart, consistent with automated scripted attack rather than manual login attempts.
4. **Scope assessment** — Attack was isolated to a single account on a single endpoint. No lateral movement or follow-on activity observed.
5. **Verdict** — True Positive. Brute force attack confirmed and successfully detected.

---

### MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Credential Access | Brute Force — Password Guessing | T1110.001 |
| Impact | Account Lockout (side effect) | — |

---

### Response Actions

| Action | Detail |
|---|---|
| Account lockout | Windows automatically locked the account after threshold exceeded |
| Alert escalation | Level 10 alert would trigger Tier 2 escalation in a real SOC |
| Recommended | Enforce account lockout policy · Enable MFA · Monitor 4625 events |

---

### Lessons Learned

Wazuh's **3-tier detection cascade** was effective here — individual failures (Level 5) escalated to pattern recognition (Level 10) and then account lockout (Level 9). In a real SOC this would be a straightforward Tier 1 investigation with a clear escalation path. The account lockout is both a detection signal and a containment action.

---
---

## INC-002 — Suspicious PowerShell Execution

**Date:** 2026-03-10
**Severity:** 🔴 Critical (Level 15 alert)
**Status:** ✅ Investigated — Mixed: True Positive techniques + False Positive critical alert

---

### Summary

A series of suspicious PowerShell commands were executed on the Windows 10 endpoint — including base64 encoded commands, execution policy bypass, download cradle simulation, and process discovery. Wazuh generated 14 alerts across 9 distinct rules. The most significant finding was a Level 15 critical alert triggered by PowerShell dropping a temporary `.ps1` script file into `AppData\Local\Temp\` — a folder commonly used by malware droppers.

> **Note:** This attack initially failed to produce Sysmon alerts due to a misconfiguration in `ossec.conf` where multiple log sources were combined into a single `<localfile>` block. This was identified, fixed, and the attack was re-run successfully. The fix is documented under lessons learned.

---

### Attack Details

```
Commands Run     →  Encoded PowerShell · Execution policy bypass
                    Download cradle simulation · Process enumeration
                    Invoke-Expression execution
Tool             →  PowerShell.exe
```

---

### Detection Evidence

| Rule ID | Description | Level | Count |
|---|---|---|---|
| 92213 | Executable file dropped in folder commonly used by malware | 15 | 5 |
| 92057 | PowerShell.exe spawned a PowerShell process executing a base64 encoded command | 12 | 1 |
| 92217 | Executable dropped in Windows root folder | 6 | 1 |
| 92027 | PowerShell process spawned PowerShell instance | 4 | 3 |
| 91815 | PowerShell executing process discovery | 4 | 2 |
| 91837 | PowerShell executed `Invoke-Expression` — possible string execution as code | 4 | 1 |
| 92031 | Discovery activity executed | 3 | 1 |
| 92033 | Discovery activity spawned via PowerShell execution | 3 | 1 |
| 60642 | Software protection service scheduled successfully | 3 | 2 |

**Total Alerts Generated:** 14 direct · 2 background noise
**Key Event IDs:** Sysmon 1 — Process Creation · Sysmon 11 — File Create · PowerShell 4104

**Screenshots:**
- `screenshots/powershell/phase2_redo_dashboard_baseline.png` — baseline before attack
- `screenshots/powershell/powershell_commands_executed1.png` — commands 1 and 2
- `screenshots/powershell/powershell_commands_executed2.png` — commands 3 and 4
- `screenshots/powershell/powershell_alerts_table.png` — full alert table
- `screenshots/powershell/powershell_alert_detail.png` — expanded alert detail
- `screenshots/powershell/powershell_level15_alert.png` — critical Level 15 finding
- `screenshots/powershell/background_noise_dll_alert.png` — background noise example

---

### Investigation Steps

1. **Alert triage** — Level 15 alert immediately flagged as critical. `rule.id 92213` — Executable dropped in malware-commonly-used folder.
2. **File investigation** — Expanded alert revealed file: `C:\Users\Krish Patel\AppData\Local\Temp\__PSScriptPolicyTest_zfgmfsam.g1v.ps1` created by `powershell.exe`.
3. **False positive assessment** — Filename prefix `__PSScriptPolicyTest_` is a known Windows pattern. When `-ExecutionPolicy Bypass` is used, PowerShell creates a temporary policy test file in Temp. This is legitimate OS behaviour — not a malware dropper.
4. **Verdict on Level 15** — False Positive. The rule correctly identified a suspicious pattern but the underlying activity was benign. In a real SOC this would be investigated, documented, and the rule tuned or whitelisted for this specific filename pattern.
5. **Remaining alerts** — True Positives. Base64 encoded command (Level 12), Invoke-Expression, and process discovery rules all fired correctly and represent genuine suspicious PowerShell behaviour indicators.

---

### MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Execution | PowerShell | T1059.001 |
| Execution | Command and Scripting Interpreter | T1059 |
| Discovery | Process Discovery | T1057 |
| Defense Evasion | Obfuscated Files — Base64 Encoding | T1027 |

---

### Response Actions

| Action | Detail |
|---|---|
| Level 15 FP documented | Rule 92213 whitelisting recommended for `__PSScriptPolicyTest_*` pattern |
| Base64 alert escalated | Rule 92057 Level 12 would warrant Tier 2 investigation in real SOC |
| Recommended | PowerShell Constrained Language Mode · AMSI integration · Script block logging review |

---

### Lessons Learned

**Technical fix:** The initial failure to see Sysmon alerts was caused by `ossec.conf` having multiple `<location>` entries inside a single `<localfile>` block — invalid syntax that caused the Sysmon channel to be silently ignored. The fix was to separate each log source into its own `<localfile>` block. This is a real-world configuration mistake that would cause silent detection gaps in a production environment.

**Detection insight:** The Level 15 false positive is a valuable example of why alert investigation matters. A raw SIEM alert at maximum severity requires context before action — the filename pattern, the parent process, and the timing all pointed to benign OS behaviour despite the alarming severity level.

---
---

## INC-003 — Abnormal Process Execution

**Date:** 2026-03-10
**Severity:** 🟠 High
**Status:** ✅ Investigated — True Positive

---

### Summary

A series of commands were executed to simulate suspicious parent-child process chains — a common indicator of malicious activity where an attacker uses PowerShell to spawn `cmd.exe` and execute reconnaissance commands. Wazuh generated 33 alerts across 5 distinct rules, successfully detecting the process chain, discovery activity, and user enumeration.

---

### Attack Details

```
Commands Run     →  PowerShell spawning cmd.exe
                    cmd.exe running net user / net localgroup
                    Nested PowerShell → cmd.exe → systeminfo
                    wmic process enumeration
```

---

### Detection Evidence

| Rule ID | Description | Level | Count |
|---|---|---|---|
| 92004 | PowerShell process spawned Windows command shell instance | 4 | 4 |
| 92027 | PowerShell process spawned PowerShell instance | 4 | 1 |
| 92032 | Suspicious Windows cmd shell execution | 3 | 6 |
| 92031 | Discovery activity executed | 3 | 2 |
| 92036 | `net.exe` binary started by a Windows cmd shell | 3 | 2 |
| 92213 | Executable file dropped in folder commonly used by malware | 15 | 1 (FP) |

**Total Alerts Generated:** 33
**Key Event ID:** Sysmon 1 — Process Creation

**Screenshots:**
- `screenshots/abnormal_process/phase3_dashboard_ready_abnormal.png` — baseline
- `screenshots/abnormal_process/abnormal_process_commands_executed.png` — commands run
- `screenshots/abnormal_process/abnormal_process_alerts_table.png` — full alert table
- `screenshots/abnormal_process/abnormal_process_alert_detail.png` — parent-child chain detail

---

### Investigation Steps

1. **Alert triage** — Rules 92004 and 92032 immediately identified PowerShell spawning cmd.exe — a classic suspicious process chain indicator.
2. **Parent-child chain confirmed** — Sysmon Event ID 1 entries showed `parentImage: powershell.exe` → `Image: cmd.exe`. This chain is rarely legitimate in normal user activity.
3. **Discovery activity flagged** — Rules 92031 and 92036 confirmed recon commands (`whoami`, `hostname`, `ipconfig`, `net user`, `net localgroup administrators`) were executed via the spawned shell.
4. **Scope assessment** — Activity confined to single endpoint. No network connections or file writes beyond the process chain itself.
5. **Level 15 assessed** — Same FP pattern as INC-002. Dismissed after investigation.
6. **Verdict** — True Positive. Suspicious process chain with reconnaissance activity confirmed.

---

### MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Execution | Windows Command Shell | T1059.003 |
| Discovery | System Information Discovery | T1082 |
| Discovery | Account Discovery — Local Account | T1087.001 |
| Discovery | Process Discovery | T1057 |

---

### Response Actions

| Action | Detail |
|---|---|
| Process chain blocked | In production — PowerShell spawning cmd.exe should trigger automated containment |
| Recommended | AppLocker / WDAC policy · Restrict cmd.exe execution from PowerShell parent · Alert on net.exe recon |

---

### Lessons Learned

This attack produced the **most comprehensive rule coverage** of all five simulations — 5 distinct rules firing across process creation, discovery, and user enumeration. The Sysmon parent-child chain data is the most valuable forensic artefact here, clearly showing attacker progression from initial execution through to reconnaissance. In a real incident this chain would be the starting point for a full scope investigation.

---
---

## INC-004 — Registry Persistence Mechanism

**Date:** 2026-03-10
**Severity:** 🟠 High
**Status:** ✅ Investigated — True Positive

---

### Summary

Registry Run Keys were added to the Windows endpoint to simulate an attacker establishing persistence — ensuring a payload would execute on every system logon. Both `reg.exe` and PowerShell's `New-ItemProperty` were used to write entries to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`. Wazuh detected the activity across 3 direct rules including a Level 12 alert for the startup registry modification.

---

### Attack Details

```
Registry Key     →  HKCU\Software\Microsoft\Windows\CurrentVersion\Run
Values Added     →  WindowsUpdateService = C:\Users\Public\payload.exe
                    SecurityUpdate = C:\Windows\Temp\update.exe
Tools Used       →  reg.exe · PowerShell New-ItemProperty
```

---

### Detection Evidence

| Rule ID | Description | Level | Count |
|---|---|---|---|
| 91844 | Possible addition of new item to Windows startup registry | 12 | 1 |
| 92041 | Value added to registry key has Base64-like pattern | 10 | 1 |
| 92302 | Registry entry to be executed on next logon modified using `reg.exe` | 6 | 1 |
| 92219 | Possible DLL search order hijack — `fvereseal.dll` | 6 | 1 (background noise) |

**Total Alerts Generated:** 3 direct · 1 background noise
**Key Event ID:** Sysmon 13 — Registry Value Set · Sysmon 1 · PowerShell 4104

**Screenshots:**
- `screenshots/persistence/phase3_dashboard_ready_persistence.png` — baseline
- `screenshots/persistence/persistence_commands_executed.png` — commands run
- `screenshots/persistence/persistence_alerts_table.png` — alert table
- `screenshots/persistence/persistence_alert_detail.png` — Level 12 alert expanded

---

### Investigation Steps

1. **Alert triage** — Rule 91844 (Level 12) flagged a new item added to the Windows startup registry — a high-confidence persistence indicator.
2. **Registry key identified** — `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` — a standard persistence location used by both legitimate software and malware.
3. **Tool identification** — Rule 92302 specifically identified `reg.exe` as the modification tool — useful for attribution and hunting.
4. **Value assessment** — Both values pointed to non-existent executables (`payload.exe`, `update.exe`) in suspicious locations (`C:\Users\Public\`, `C:\Windows\Temp\`). In a real incident these paths would be investigated for actual payload presence.
5. **Base64 pattern alert** — Rule 92041 fired because the value paths contained patterns resembling encoded strings. Assessed as low-confidence FP in this context but worth noting.
6. **Remediation** — Registry keys removed after simulation using `Remove-ItemProperty`.
7. **Verdict** — True Positive. Persistence mechanism successfully planted and detected.

---

### MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Persistence | Registry Run Keys / Startup Folder | T1547.001 |
| Defense Evasion | Masquerading — Match Legitimate Name | T1036 |

---

### Response Actions

| Action | Detail |
|---|---|
| Registry keys removed | Both persistence entries cleaned up post-simulation |
| Recommended | Monitor `CurrentVersion\Run` for new entries · Alert on reg.exe writing to startup keys · Restrict write access to Run keys for standard users |

---

### Lessons Learned

Persistence detection is one of Wazuh's stronger default capabilities. The 3-tier detection — the action (registry write), the tool used (`reg.exe`), and the pattern (startup key) — gave clear, actionable intelligence. In a real SOC this would immediately prompt a search for the referenced executables and investigation of how the attacker gained initial access.

---
---

## INC-005 — Privilege Escalation Attempt

**Date:** 2026-03-10
**Severity:** 🟠 High
**Status:** ✅ Investigated — Partial Detection · Detection Gap Identified

---

### Summary

A privilege escalation simulation was performed using PowerShell token manipulation (`AdjustTokenPrivileges`) to enable `SeDebugPrivilege`, followed by LSASS process access and local administrator group enumeration. Wazuh detected the surrounding discovery activity and flagged the token manipulation code compilation as a file dropper, however the core privilege escalation technique (Event ID 4672 — Special Privileges Assigned) did not produce a direct Wazuh alert — a detection gap in the default ruleset.

---

### Attack Details

```
Techniques       →  AdjustTokenPrivileges — SeDebugPrivilege enablement
                    Get-Process lsass — LSASS access attempt
                    net localgroup administrators — privilege enumeration
Tools Used       →  PowerShell — inline C# compilation · net.exe
```

---

### Detection Evidence

| Rule ID | Description | Level | Count |
|---|---|---|---|
| 92213 | Executable file dropped in folder commonly used by malware | 15 | 3 (FP — compiled token code) |
| 91815 | PowerShell executing process discovery | 4 | 2 |
| 92031 | Discovery activity executed | 3 | 1 |
| 92033 | Discovery activity spawned via PowerShell execution | 3 | 1 |

**Total Alerts Generated:** 7
**Detection Gap:** Windows Event ID 4672 (Special Privileges Assigned) did not trigger a Wazuh alert
**Key Event IDs:** Sysmon 1 · Sysmon 11 · PowerShell 4104

**Screenshots:**
- `screenshots/privilege_escalation/phase3_dashboard_ready_privesc.png` — baseline
- `screenshots/privilege_escalation/privesc_commands_executed.png` — commands run
- `screenshots/privilege_escalation/privesc_alerts_table.png` — alert table
- `screenshots/privilege_escalation/privesc_alert_detail.png` — expanded alert detail

---

### Investigation Steps

1. **Alert triage** — Level 15 alerts appeared immediately. Investigation revealed these were caused by the inline C# code from the token manipulation script being compiled into a temporary file in `AppData\Local\Temp\` — same FP pattern as INC-002.
2. **Process discovery alerts** — Rules 91815 and 92031 fired for `Get-Process lsass` and `net localgroup administrators` — correctly identifying reconnaissance around privilege context.
3. **4672 gap investigated** — Windows Security log was checked directly in Event Viewer. Event ID 4672 entries were present confirming `SeDebugPrivilege` was assigned, however Wazuh's default rules did not have coverage for this specific event in this context.
4. **Detection gap documented** — This represents a real gap in Wazuh's default detection capability for token privilege manipulation. Custom rules targeting Event ID 4672 with `SeDebugPrivilege` in the privilege list would close this gap.
5. **Verdict** — Partial detection. Surrounding activity caught but core technique missed. Custom rule development recommended.

---

### MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Privilege Escalation | Access Token Manipulation | T1134 |
| Privilege Escalation | Token Impersonation/Theft | T1134.001 |
| Discovery | Process Discovery | T1057 |
| Discovery | Account Discovery — Local Account | T1087.001 |

---

### Response Actions

| Action | Detail |
|---|---|
| Detection gap flagged | Custom Wazuh rule needed for Event ID 4672 + SeDebugPrivilege |
| Recommended | Monitor for SeDebugPrivilege assignment outside of known system processes · Alert on LSASS access from non-system processes · Custom rule: `4672` + privilege list contains `SeDebugPrivilege` |

---

### Lessons Learned

This was the most important finding from a detection engineering perspective. A real attacker enabling `SeDebugPrivilege` — which allows access to any process including LSASS for credential dumping — would not have triggered a direct Wazuh alert with default rules. This highlights that **SIEM deployment is not the same as detection coverage**. Meaningful protection requires ongoing rule development and tuning aligned to the specific techniques being defended against. This gap would be the first custom rule written in a Phase 4 detection engineering phase.

---
---

## Phase 3 — Overall Detection Summary

| Attack | Alerts | Highest Level | Direct Detection | Notes |
|---|---|---|---|---|
| INC-001 Brute Force | 11 | 10 | ✅ Full | Account lockout triggered |
| INC-002 PowerShell | 14 | 15 | ✅ Full | Level 15 FP identified and explained |
| INC-003 Abnormal Process | 33 | 15 | ✅ Full | Best rule coverage — 5 distinct rules |
| INC-004 Persistence | 3 | 12 | ✅ Full | Clean 3-tier detection |
| INC-005 Privilege Escalation | 7 | 15 | ⚠️ Partial | 4672 detection gap identified |

---

## False Positives Identified

| Alert | Rule | Verdict | Reason |
|---|---|---|---|
| Executable dropped in malware folder | 92213 | FP | Windows Script Policy Test file — `__PSScriptPolicyTest_*` in Temp |
| DLL search order hijack | 92219 | FP | Windows Update staging `fvereseal.dll` — BitLocker component |
| Base64-like registry value | 92041 | Low confidence FP | Filepath pattern resembled encoding but was plaintext |

---

## Detection Gaps Identified

| Gap | Impact | Recommended Fix |
|---|---|---|
| Event ID 4672 — SeDebugPrivilege not alerted | High — token manipulation missed | Custom rule targeting 4672 + SeDebugPrivilege in privilege list |
| PowerShell encoded command coverage limited | Medium — some encoded commands not alerted | Tune rules 92057 and 91837 · Enable AMSI |
