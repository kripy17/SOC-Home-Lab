# WORK IN PROGRESS -HOLD YR WIN-DOORS MEANWHILE

# SOC Home Lab – Phase 2: Windows Telemetry & Sysmon Integration

*Windows Endpoint Integration | Security Event Monitoring | Sysmon Telemetry*
---

## 1. Project Overview

This repository documents the second phase of my Security Operations Center (SOC) home lab, focused on expanding monitoring capabilities to include Windows-based telemetry.

Following the successful deployment of a centralized SIEM infrastructure using the Wazuh platform, this phase integrates a Windows 10 endpoint to enhance visibility into operating system–level security events.

The objective of this phase is to:

• Deploy and register a Windows Wazuh agent
• Monitor native Windows Security Event logs
• Integrate and configure Sysmon for enhanced process-level telemetry
• Validate centralized log ingestion within the Wazuh Dashboard
• Troubleshoot agent registration and connectivity issues

By incorporating Sysmon telemetry, this lab extends beyond basic log collection into detailed endpoint activity monitoring, including process creation, command-line execution, and persistence-related events.

This phase transitions the lab from foundational infrastructure deployment into practical Windows endpoint monitoring, closely aligning with real-world SOC analyst workflows.

---

## 2. Lab Objectives & Initial Agent Onboarding

This project focuses on **onboarding a Windows endpoint with Sysmon telemetry** into the existing Wazuh SOC infrastructure and validating that the telemetry is successfully forwarded to the SOC server. The primary objectives are:

* Verify SOC server services are operational
* Confirm required network ports for Wazuh communication are open
* Register the Windows agent securely
* Start and validate the agent service on the Windows VM
* Confirm the agent is active and communicating with the SOC server
* Verify telemetry/log flow is functional

This ensures a **working endpoint-to-SIEM pipeline**, forming the foundation for further log analysis and attack simulation.

---

### 2.1 Windows VM Configuration

The Windows 10 endpoint VM is configured to balance realism with host system constraints (8GB total RAM):

| Resource | Allocation   |
| -------- | ------------ |
| RAM      | 4 GB         |
| CPU      | 2 Cores      |
| Disk     | 40 GB        |
| Network  | VMnet8 (NAT) |
| Sysmon   | Installed    |

<img src="screenshots/windows/windows_vm_allocation.png" width="700">

This allocation ensures the VM can run **Sysmon** and the **Wazuh agent** while maintaining stability alongside the SOC server and other lab VMs.

---

### 2.2 Verify SOC Server Services

Before onboarding any agent, it is important to ensure that all **Wazuh services** on the SOC server are running and ready to process incoming events.

<img src="screenshots/wazuh/deployment_wazuh_services_running1.png" width="700">  
<img src="screenshots/wazuh/deployment_wazuh_services_running2.png" width="700">

**Services verified:**

* Wazuh Manager
* Wazuh Indexer (OpenSearch)
* Wazuh Dashboard
* Filebeat

---

### 2.3 Confirm Required Ports Are Listening

Ensure the SOC server and Windows endpoint can communicate over the required Wazuh ports:

* **1514:** Agent data communication
* **1515:** Agent registration
* **443:** Wazuh Dashboard access

<img src="screenshots/wazuh/deployment_ports_listening.png" width="700">

---

### 2.4 Register the Windows Agent

The Windows agent is registered using the **Wazuh GUI**, and a secure key is generated for authentication.

<img src="screenshots/wazuh/deployment_agent_created.png" width="700">  
<img src="screenshots/wazuh/deployment_agent_active_server.png" width="700">  

The agent is assigned an ID and marked **Active** once connected.

---

### 2.5 Configure and Start Windows Agent

After registration:

1. **Configure the agent in the Wazuh Windows GUI**

<img src="screenshots/windows/deployment_windows_gui_configured.png" width="700">

2. **Start the Wazuh agent service** on the Windows VM and confirm it is running:

<img src="screenshots/windows/deployment_windows_service_running.png" width="700">

---

### 2.6 Verify Telemetry & Log Flow

Once the agent is active, generate test events via Sysmon and other system activity to validate telemetry:

<img src="screenshots/telemetry/telemetry_log_flow_verified.png" width="700">

**Validation ensures:**

* Windows endpoint logs are successfully forwarded to the SOC server
* Wazuh Manager receives and indexes the events
* Events are visible in the Wazuh Dashboard under the agent’s logs

---

# 3. Sysmon Configuration for Enhanced Endpoint Telemetry

## Objective

To improve endpoint visibility, **Sysmon (System Monitor)** was configured on the Windows endpoint to generate detailed telemetry for process execution, network connections, and system activity.

These logs are forwarded to the **Wazuh SIEM**, enabling deeper monitoring and improving the ability to detect suspicious behavior during attack simulations.

---

## Why Sysmon Is Important

Default Windows logging provides limited visibility into system activity. Sysmon enhances endpoint monitoring by generating detailed event logs related to system behavior.

Key telemetry provided by Sysmon includes:

* Process creation events
* Network connections initiated by processes
* File creation activity
* Registry modifications
* Driver loading events
* Suspicious command execution

This level of visibility is commonly used in **SOC environments for threat detection and incident investigation**.

---

## Sysmon Deployment

Sysmon was installed on the Windows endpoint and configured using a structured configuration file designed for security monitoring. The configuration enables logging for important system activities while filtering out unnecessary noise.

Once configured, Sysmon begins generating telemetry events that can be viewed through **Windows Event Viewer**.

### Verifying Sysmon Event Logs

Sysmon events can be observed in Windows under the following log location:

```
Applications and Services Logs
Microsoft
Windows
Sysmon
Operational
```

These logs contain detailed event records such as process creation, network connections, and other monitored system activities.

---

## Integration with Wazuh

After Sysmon was configured, the Windows endpoint continued forwarding logs to the **Wazuh SIEM server** through the installed Wazuh agent.

This allows Sysmon telemetry to be ingested by the SIEM platform, where it can be:

* Indexed and stored
* Monitored through the Wazuh dashboard
* Correlated with other security events
* Used for detection rule triggering

The integration enables centralized monitoring of endpoint activity from the SOC server.

---

## Telemetry Validation

To confirm that endpoint telemetry was successfully reaching the SIEM, events generated by the Windows system were observed within the **Wazuh Security Events dashboard**.

This confirmed that:

* The Windows agent was successfully forwarding logs
* Sysmon telemetry was being processed by the Wazuh manager
* Events were available for monitoring and detection

<img src="screenshots/wazuh/telemetry_log_flow_verified.png" width="700">

---

## Outcome

With Sysmon properly configured and integrated with Wazuh, the SOC lab now has **enhanced endpoint visibility**.

This improved telemetry will be used in the following phases of the project to:

* simulate attack activity
* observe generated security alerts
* analyze malicious behavior
* practice SOC alert investigation workflows

---




