# Detection-Lab

****Objective**
### [Detection and Response Lab: Network Traffic and Attack Detection](https://github.com/yourusername/soc-lab)
This hands-on lab focused on monitoring network traffic and detecting attacks in a simulated SOC environment. Using tools like Suricata and Arkime, I captured and analyzed network packets to identify malicious activity. I also emulated attacker behavior (e.g., privilege escalation, lateral movement) and crafted detection rules to alert on suspicious patterns. Key activities included log aggregation, threat hunting with YARA rules, and responding to simulated attacks.

**Key Skills**:  
- Network traffic monitoring and analysis  
- Attack detection and rule creation  
- Log aggregation and analysis  
- Threat hunting with YARA rules  

**Tools Used**: Suricata, Arkime, Graylog, ELK/OpenSearch, Kali Linux  **


**steps**
## Environment Setup

1. **Created a virtual environment**:
   - Windows 11 VM (victim)
   - Ubuntu Server VM (attacker)

2. **Disabled security features on the Windows VM** and installed Sysmon for enhanced logging.

## C2 Payload Deployment

1. **Generated a malicious payload** using Sliver on the Ubuntu Server.

2. **Deployed the payload** to the Windows VM and established a C2 session.

## EDR Telemetry Analysis

1. **Monitored system activity** using LimaCharlie:
   - Identified malicious processes
   - Monitored network connections
   - Analyzed file system activity

2. **Analyzed the payload’s behavior**:
   - Identified unsigned processes
   - Detected suspicious network traffic

## Detection Rule Creation

1. **Created detection rules** to identify sensitive process access (e.g., lsass.exe credential dumping).

2. **Detected and reported suspicious activity** in real-time.

## Attack Mitigation

1. **Blocked malicious commands** (e.g., `vssadmin delete shadows`) by crafting rules to terminate the parent process.

2. **Verified the effectiveness** of the rules by re-running the attack and observing the blocked activity.
