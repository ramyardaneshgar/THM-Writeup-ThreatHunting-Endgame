# THM-Writeup-ThreatHunting-Endgame
Writeup for TryHackMe ThreatHunting: Endgame- Keylogging, ICMP exfiltration, and system disruption, leveraging PowerShell, ELK Stack, and adversary behavior analysis.

By Ramyar Daneshgar 

### **TryHackMe Writeup: Threat Hunting - Endgame**

In this lab, I was identifying and investigating adversary tactics in the **Endgame** phase, focusing on **Collection (TA0009)**, **Exfiltration (TA0010)**, and **Impact (TA0040)** using the **ELK Stack**. By applying a proactive threat-hunting, I uncovered malicious activities like **keylogging**, **ICMP-based data exfiltration**, and **shadow copy removal**, emphasizing adversarial objectives within the **Cyber Kill Chain**.

---

### **Task 4: Tactic - Collection**
#### **Objective: Detect Keylogging Activity**
The **Collection tactic** involves adversaries gathering sensitive information like credentials or PII. In this case, I focused on detecting **keylogging activity**, particularly through API-based techniques.

1. **Formulating the Hypothesis**  
   I hypothesized that a keylogger might be using **Windows API calls** or low-level hooks to capture keystrokes. I crafted my initial query to search for suspicious **API calls** such as `GetKeyboardState` or `SetWindowsHookEx`.

2. **Initial Investigation**  
   Using the ELK dashboard, I ran a query to identify patterns associated with keylogging behavior:
   ```kql
   *GetKeyboardState* OR *SetWindowsHook* OR *GetAsyncKeyState*
   ```
   I observed multiple matches from **Microsoft-Windows-PowerShell/Operational logs**, which indicated that a suspicious **PowerShell script** (`chrome-update_api.ps1`) was executed.

3. **Tracing the Malicious Script**  
   I analyzed the associated logs and found that the script was downloaded using `wget` and then executed. The script appeared to log keystrokes into a database file (`chrome_local_profile.db`).

4. **Verifying Activity**  
   By correlating the parent-child relationships between processes, I confirmed that the database file was actively storing keystroke data. Using `View Surrounding Documents`, I also identified commands used to display the database contents, exposing the **logged email account**.

**Findings:**
- **Downloader Process ID:** `3388`
- **Logged Email Account:** `hunted-victim2323@gmail.com`

---

### **Task 5: Tactic - Exfiltration**
#### **Objective: Detect Data Exfiltration Over ICMP**
The **Exfiltration tactic** involves transferring stolen data out of the network. I focused on identifying data exfiltration over **ICMP**, a covert channel commonly used to bypass detection.

1. **Formulating the Hypothesis**  
   I hypothesized that ICMP traffic might be abused for data exfiltration. I crafted my query to search for common system utilities like `ping` or `Invoke-WebRequest` in the log files.

2. **Initial Investigation**  
   I ran the following query to find matches for suspicious system calls:
   ```kql
   *ping* OR *System.Net.Networkinformation.ping*
   ```
   My search returned evidence of a **PowerShell script** (`icmp4data.ps1`) that leveraged ICMP packets to transfer data.

3. **Analyzing the Script**  
   I investigated logs related to `icmp4data.ps1`, which revealed its behavior: the script divided the data into **15-byte chunks** and transmitted **21 ICMP packets** to a target server (`10[.]10[.]87[.]116`).

4. **Correlating Activity**  
   By analyzing the script’s execution and the associated data, I identified the **exfiltrated file** as `chrome_local_profile.db`.

**Findings:**
- **Total ICMP Packets Sent:** `21`
- **Chunk Size:** `15 bytes`
- **Exfiltrated File:** `chrome_local_profile.db`
- **Destination Server:** `10[.]10[.]87[.]116`

---

### **Task 6: Tactic - Impact**
#### **Objective: Detect System Disruption/Manipulation**
The **Impact tactic** is aimed at disrupting system availability or integrity. I focused on detecting **shadow copy removal** and **system recovery manipulation**, techniques often used to hinder recovery efforts after an attack.

1. **Formulating the Hypothesis**  
   I hypothesized that adversaries might have used native system tools like `vssadmin` to delete shadow copies or manipulate recovery points. These actions typically align with **ransomware-like behavior** or long-term disruption goals.

2. **Initial Investigation**  
   I queried for commands commonly associated with system disruption:
   ```kql
   *vssadmin* OR *shadow* OR *bcdedit*
   ```
   My query results pointed to **vssadmin.exe**, which was used to delete shadow copies. I also discovered that **powershell.exe** initiated the attack chain.

3. **Tracing the Attack Chain**  
   By investigating the **parent-child relationships** of processes, I confirmed that `powershell.exe` launched the attack, spawning commands to remove shadow copies and disrupt system recovery.

4. **Correlating Processes**  
   Using the `View Surrounding Documents` feature, I traced the sequence of commands and identified **Process ID 6512** as the origin of the attack chain.

**Findings:**
- **Executable Used:** `vssadmin.exe`
- **Main Shell Image:** `powershell.exe`
- **Attack Chain Process ID:** `6512`

---

### **Lessons Learned**
1. **Proactive Hunting:** I focused on reducing **dwell time** by proactively identifying keylogging, data exfiltration, and system disruption tactics.
2. **Correlating Activity:** Analyzing **parent-child process relationships** and surrounding documents allowed me to trace the full attack chain.
3. **Visibility:** The use of the **ELK Stack** provided a centralized view of logs, enabling efficient detection of advanced techniques.
4. **Mitigation Steps:**
   - Enforce **network monitoring** to detect covert exfiltration channels like ICMP.
   - Use **endpoint protection** to block malicious PowerShell scripts.
   - Implement **data encryption** and **DLP solutions** to protect sensitive information.
   - Regularly test **backup and recovery systems** are essential.
