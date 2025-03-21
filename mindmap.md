# OSCP+ EXAM STRATEGY Mindmap
## 1. Preparation & Planning

### 1.1 Lab & Practice
- Verify lab machines (AD labs, standalone labs)
- Practice manual enumeration & exploitation (No sqlmap, etc.)
- Document your steps, build reporting templates

### 1.2 Exam Tooling & Restrictions
- Allowed: nmap, Burp Suite Free, Nikto, etc.
- Disallowed: Automated scanners (sqlmap, Nessus, etc.)
- Check official guidelines (no AI chatbot usage)

### 1.3 Time Management
- Allocate hours per machine (e.g., 2–3 hr per standalone)
- Budget enough time for AD set (all-or-nothing 40 points)
- Switch if stuck (avoid rabbit holes, revert if needed)

---

## 2. Initial Recon & Enumeration

### 2.1 Network Discovery
- `nmap -p- -sC -sV <target> -oA initial`
- Identify open ports/services
- **IF** no open ports → Double-check scanning approach

### 2.2 Service-Specific Enumeration
- **SMB** → smbclient, smbmap, rpcclient
- **FTP** → check anonymous login, read/write perms
- **HTTP** → Gobuster/FFUF, Nikto, manual parameter checks
- **SNMP** → snmpwalk (common community strings)
- **IF** credentials found → test them on all open services

### 2.3 Decision: Standalone vs. AD
- **IF** machine is standalone → proceed with typical local exploit paths
- **IF** domain environment → pivot to Active Directory enumeration

---

## 3. Web / Perimeter Exploitation Flow

### 3.1 Web Application Scanning
- Manually look for forms, parameters
- Identify potential vulnerabilities (LFI, RFI, command injection)
- Use Burp Suite (Free) for intercept/repeater

### 3.2 SQL Injection (NO sqlmap)
- Try `' or '1'='1` or `UNION SELECT` checks manually
- If injection found → confirm DB type → harvest data
- If blind → boolean/time-based approach

### 3.3 File Upload / Web Shell
- Test file upload endpoints (php, asp, aspx)
- If upload succeeds → attempt shell execution

### 3.4 Command Injection
- Pass `;whoami` or `&& ping -c1 <YOUR_IP>` in parameters
- If confirmed → craft reverse shell
- Re-check firewalls/bad chars if shell fails

---

## 4. Network / Service Exploitation Flow

### 4.1 Check for Known Vulns (Manual)
- Based on version → searchsploit (but no “auto-exploit”)
- Read exploit code, compile if needed
- Confirm vulnerability by test or partial POC

### 4.2 Buffer Overflow
- Fuzz → find offset → EIP overwrite
- Check bad chars → find JMP ESP
- Insert msfvenom shellcode → final exploit

### 4.3 Get Initial Shell
- Reverse shell (nc, bash, powershell)
- Stabilize shell (upgrade TTY, etc.)
- Document commands for exam report

---

## 5. Privilege Escalation

### 5.1 Enumeration
- **Windows** → `whoami /all`, `systeminfo`, WinPEAS (allowed for enumeration)
- **Linux** → `sudo -l`, linpeas.sh, manual checks
- Identify misconfigurations, leftover credentials

### 5.2 Windows PrivEscs
- Insecure service perms (unquoted path, modifiable binary)
- Token impersonation (SeImpersonatePrivilege → JuicyPotato, etc.)
- SAM/SECURITY hives or plaintext creds in registry

### 5.3 Linux PrivEscs
- Sudo misconfig: `sudo -l` + GTFOBins
- SUID binaries, cron jobs, path hijacking
- Kernel exploits (check version, compile exploit)

### 5.4 Post-Exploit
- Dump hashes/creds
- Pivot or escalate further
- Confirm root/Administrator → gather `proof.txt`

---

## 6. Active Directory (AD) Attack Flow

### 6.1 Basic Enumeration
- `net user /domain`, `net group /domain`
- Powerview → `Get-NetUser`, `Get-NetComputer`, etc.
- SharpHound → BloodHound for graphing (data collection)

### 6.2 Credential Attacks
- Kerberoasting (`GetUserSPNs.py`) → crack hash
- AS-REP Roasting (`GetNPUsers.py` if "no preauth")
- Pass-the-Hash / Pass-the-Ticket (Impacket, Mimikatz)

### 6.3 Lateral Movement
- Use new creds/hashes on WinRM, SMB, WMI
- Evaluate local admin → pivot to more machines

### 6.4 Domain Admin Compromise
- DCSync (`secretsdump`) if replication rights
- Golden Ticket (krbtgt hash) or Silver Ticket
- Validate domain admin → gather proof

### 6.5 Decision: Still Need Standalone Boxes?
- If not enough points → pivot back to any missed standalones

---

## 7. Reporting & Documentation

### 7.1 Notes As You Go
- Screen captures (`whoami`, content of `proof.txt`)
- Save critical commands (exploit code, offsets, etc.)

### 7.2 Structure
- Executive summary + technical details
- Each machine: enumeration → exploitation → privesc
- Include recommended mitigations if relevant

### 7.3 Exam Submission
- Final check → all `local.txt` & `proof.txt`
- Correct file naming & required sections
- Submit before deadline

