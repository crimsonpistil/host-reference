// ── HUNT REFERENCE - core.js ──
// Shared UI logic for all tactic pages.
// DATA must be loaded before this file via a tactic-specific data/*.js script tag.

// ── CASE TEMPLATES ──
const CMS_TEMPLATES = {
  // ── Execution (TA0002) ──
  'T1059.001': { title:'T1059.001 - PowerShell', body:`## TAG - EXECUTION\n### Technique: PowerShell, T1059.001\n- Time:\n- Host:\n- User Account:\n- Parent Process:\n- Process Command Line:\n- Encoded Payload (decoded):\n- ScriptBlock Content (Event 4104):\n- AMSI Result:\n- Outbound Network Connections:\n- Tool Inferred: (Empire / Cobalt Strike / Nishang / manual)\n\nNotes:` },
  'T1059.003': { title:'T1059.003 - Windows Command Shell', body:`## TAG - EXECUTION\n### Technique: Windows Command Shell, T1059.003\n- Time:\n- Host:\n- User Account:\n- Parent Process:\n- Command Line:\n- Discovery Commands Observed:\n- Obfuscation Pattern: (caret / quote / hex / none)\n- Subsequent Process Spawned:\n\nNotes:` },
  'T1059.005': { title:'T1059.005 - Visual Basic', body:`## TAG - EXECUTION\n### Technique: Visual Basic, T1059.005\n- Time:\n- Host:\n- User Account:\n- Parent Process: (Office app?)\n- Script Path:\n- Script Content (sanitized):\n- Network Activity:\n\nNotes:` },
  'T1059.007': { title:'T1059.007 - JavaScript', body:`## TAG - EXECUTION\n### Technique: JavaScript, T1059.007\n- Time:\n- Host:\n- User Account:\n- Engine: (wscript / cscript / mshta)\n- Script Path:\n- Script Content (sanitized):\n\nNotes:` },
  'T1059.004': { title:'T1059.004 - Unix Shell', body:`## TAG - EXECUTION\n### Technique: Unix Shell, T1059.004 [LINUX]\n- Time:\n- Host:\n- User / UID:\n- Shell: (bash / sh / dash / zsh)\n- Parent Process: (web service? sshd?)\n- Command Line:\n- Pattern: (curl|bash / base64 -d / reverse shell / other)\n- /proc/<pid>/exe deleted (Y/N):\n- History Tampering (HISTFILE unset?) (Y/N):\n\nNotes:` },
  'T1059.006': { title:'T1059.006 - Python', body:`## TAG - EXECUTION\n### Technique: Python, T1059.006 [LINUX]\n- Time:\n- Host:\n- User / UID:\n- Interpreter: (python / python3)\n- Parent Process:\n- Command Line / -c payload:\n- Pattern: (socket / pty.spawn / os.system / temp-path script)\n- Script Path (if any):\n- sitecustomize.py planted (Y/N):\n\nNotes:` },
  T1047: { title:'T1047 - Windows Management Instrumentation', body:`## TAG - EXECUTION\n### Technique: WMI, T1047\n- Time:\n- Host:\n- User Account:\n- Process: (wmic.exe / Win32_Process)\n- Command Line:\n- Target Host (if remote):\n- WMI Subscription Created (Y/N):\n\nNotes:` },
  'T1053.005': { title:'T1053.005 - Scheduled Task', body:`## TAG - EXECUTION\n### Technique: Scheduled Task, T1053.005\n- Time:\n- Host:\n- User Account:\n- Task Name:\n- Task Action / Binary:\n- Task Trigger:\n- Run-As Account: (SYSTEM elevation?)\n- Created Locally or Remotely:\n\nNotes:` },
  'T1059.012': { title:'T1059.012 - Container Admin Command (docker/kubectl exec)', body:`## TAG - EXECUTION\n### Technique: Container Administration Command, T1059.012 [LINUX]\n- Time:\n- Host / Node:\n- Container ID / Name:\n- Runtime: (docker / containerd / CRI-O / runc)\n- Command Used: (docker exec / kubectl exec / nsenter / crictl exec)\n- Shell Spawned Inside Container: (bash / sh / ash)\n- Interactive Flags: (-it / -i -t)\n- Namespace Entry (nsenter --target / --mount / --pid):\n- Container Privileged: (Y/N)\n- Host Path Mounted in Container: (Y/N)\n- Kubernetes Pod Name / Namespace:\n- Service Account Token Used:\n- Breakout to Host Confirmed (Y/N):\n- Auditd Key Alert: (docker_exec / nsenter_exec)\n\nNotes:` },
  'T1059': { title:'T1059 - Perl / Legacy Interpreter Execution', body:`## TAG - EXECUTION\n### Technique: Perl / Legacy Interpreter, T1059 [LINUX]\n- Time:\n- Host:\n- User / UID:\n- Interpreter: (perl / ruby / awk / lua)\n- Invocation: (-e inline / script file)\n- Script Path: (/tmp/ / /dev/shm/ / cgi-bin/)\n- Payload Type: (reverse shell / downloader / backdoor)\n- Parent Process: (httpd? sshd? bash?)\n- CGI Context (Y/N):\n- Network Connection Observed (Y/N):\n- Socket / exec Pattern in Args:\n- Interpreter SUID Set (Y/N):\n\nNotes:` },
  'T1053.003': { title:'T1053.003 - Cron', body:`## TAG - PERSISTENCE\n### Technique: Cron, T1053.003 [LINUX]\n- Time:\n- Host:\n- User / UID:\n- Location: (/etc/crontab / cron.d / /var/spool/cron/ / systemd .timer)\n- Schedule: (@reboot? */1? specific interval?)\n- Command / Payload:\n- Payload Path: (/tmp/ / /dev/shm/ / home dir?)\n- Invokes: (curl|bash / downloader / interpreter)\n- crontab -l vs /var/spool/cron/ Discrepancy (Y/N):\n- Owner Expected vs Actual:\n- Auditd Key Alert: (cron_persist / crontab_exec)\n\nNotes:` },
  'T1543.002': { title:'T1543.002 - Systemd Service', body:`## TAG - PERSISTENCE\n### Technique: Systemd Service, T1543.002 [LINUX]\n- Time:\n- Host:\n- Service Unit File Path: (/etc/systemd/system/ / ~/.config/systemd/user/)\n- Service Name:\n- ExecStart Path:\n- ExecStart in Suspicious Location (/tmp/dev/shm/home)? (Y/N):\n- User= Directive: (root?)\n- Restart=always Set (Y/N):\n- systemctl enable Observed (Y/N):\n- From Package Manager (Y/N):\n- Parent of Spawned Process: (systemd PID 1?)\n- Generator-Based (Y/N):\n- Auditd Key Alert: (systemd_unit_write / systemctl_exec)\n\nNotes:` },
  'T1546.004': { title:'T1546.004 - Shell RC Backdoor', body:`## TAG - PERSISTENCE\n### Technique: Unix Shell Configuration Modification, T1546.004 [LINUX]\n- Time:\n- Host:\n- User / UID:\n- Modified File: (.bashrc / .bash_profile / /etc/profile.d/*.sh / other)\n- Scope: (single user / all users)\n- Injected Command:\n- Pattern: (downloader / reverse shell / history clear)\n- Triggers On: (login shell / interactive shell / logout)\n- Written By: (web process? non-bash parent?)\n- Baseline Delta (what was added):\n- Auditd Key Alert: (shell_rc_write)\n\nNotes:` },
  'T1098.004': { title:'T1098.004 - SSH Authorized Keys', body:`## TAG - PERSISTENCE\n### Technique: SSH Authorized Keys, T1098.004 [LINUX]\n- Time:\n- Host:\n- Target Account:\n- authorized_keys Path:\n- Key Fingerprint(s) Injected:\n- Key Comment / Label:\n- Key Previously in Baseline (Y/N):\n- sshd_config Also Modified (Y/N):\n- sshd_config Changes: (PermitRootLogin / AuthorizedKeysFile / AuthorizedKeysCommand)\n- Written By: (curl? web process? cloud API?)\n- Cloud Metadata API Used (Y/N):\n- Active SSH Session Identified (Y/N):\n- Auditd Key Alert: (ssh_key_write / sshd_config_write)\n\nNotes:` },
  'T1547.006': { title:'T1547.006 - Kernel Module / LKM Rootkit', body:`## TAG - PERSISTENCE\n### Technique: Kernel Modules / LKM Rootkit, T1547.006 [LINUX]\n- Time:\n- Host:\n- Module Name:\n- Module File Path:\n- Load Method: (insmod / modprobe / init_module syscall)\n- Module In /lib/modules/<kver>/ (Y/N):\n- From Package Manager (Y/N):\n- Module Signature: (valid / unsigned / void)\n- /proc/sys/kernel/tainted Value:\n- lsmod vs /sys/module/ Discrepancy (Y/N):\n- Boot Persistence: (/etc/modules / modules-load.d modified?)\n- Rootkit Family Suspected: (Diamorphine / Reptile / Snapekit / other)\n- Memory Acquisition Taken (Y/N):\n- Auditd Key Alert: (module_load / module_autoload)\n\nNotes:` },
  'T1556.003': { title:'T1556.003 - PAM Backdoor', body:`## TAG - PERSISTENCE\n### Technique: PAM Modification, T1556.003 [LINUX]\n- Time:\n- Host:\n- Artifact Type: (PAM config file / malicious .so module)\n- Modified File:\n- Change: (new module added / pam_unix.so replaced / auth bypassed)\n- pam_unix.so Hash Match (dpkg/rpm verify result):\n- Suspicious Module Path: (/tmp/ / non-package path?)\n- PAM Directive Injected: (auth sufficient pam_permit.so / other)\n- Affected Services: (sshd / sudo / su / common-auth / all)\n- Credential Harvesting Suspected (Y/N):\n- Compiled In Session (gcc observed?) (Y/N):\n- Auditd Key Alert: (pam_config_write / pam_module_write)\n\nNotes:` },
  'T1037.004': { title:'T1037.004 - RC Script Persistence', body:`## TAG - PERSISTENCE\n### Technique: RC Scripts / rc.local, T1037.004 [LINUX]\n- Time:\n- Host:\n- Modified File: (/etc/rc.local / /etc/rc.d/rc.local / /etc/init.d/<name>)\n- Executable Bit Set (Y/N):\n- Payload / Command Injected:\n- Payload Path: (/tmp/ / /dev/shm/ / other unusual)\n- update-rc.d / chkconfig Observed (Y/N):\n- rcN.d Symlink Created (Y/N):\n- systemd rc-local.service Status: (enabled?)\n- ESXi /etc/rc.local.d/ Affected (Y/N):\n- From Package Manager (Y/N):\n- Auditd Key Alert: (rclocal_write / initd_write / rcd_write)\n\nNotes:` },
  'T1569.002': { title:'T1569.002 - Service Execution', body:`## TAG - EXECUTION\n### Technique: Service Execution, T1569.002\n- Time:\n- Host:\n- User Account:\n- Service Name:\n- binPath:\n- Service Type / Start Type:\n- Tool Inferred: (sc.exe / PsExec / Impacket)\n\nNotes:` },
  'T1218.005': { title:'T1218.005 - Mshta', body:`## TAG - EXECUTION\n### Technique: Mshta, T1218.005\n- Time:\n- Host:\n- User Account:\n- mshta.exe Command Line:\n- HTA Source: (URL / inline VBS / inline JS)\n- Subsequent Process Spawned:\n- Outbound Network:\n\nNotes:` },
  'T1218.011': { title:'T1218.011 - Rundll32', body:`## TAG - EXECUTION\n### Technique: Rundll32, T1218.011\n- Time:\n- Host:\n- User Account:\n- rundll32.exe Command Line:\n- DLL Path:\n- Export Function:\n- DLL Signed (Y/N):\n\nNotes:` },
  'T1218.010': { title:'T1218.010 - Regsvr32', body:`## TAG - EXECUTION\n### Technique: Regsvr32, T1218.010\n- Time:\n- Host:\n- User Account:\n- regsvr32.exe Command Line:\n- /i: URL or Path:\n- Scriptlet Content (.sct):\n- Squiblydoo Pattern (Y/N):\n\nNotes:` },
  T1106: { title:'T1106 - Native API', body:`## TAG - EXECUTION\n### Technique: Native API, T1106\n- Time:\n- Host:\n- User Account:\n- Process Created Without CLI Trace:\n- Module Load Pattern:\n- CreateRemoteThread Observed (EID 8):\n- Memory Region Analysis:\n\nNotes:` },
  T1129: { title:'T1129 - Shared Modules', body:`## TAG - EXECUTION\n### Technique: Shared Modules / DLL Side-Loading, T1129\n- Time:\n- Host:\n- User Account:\n- Loading Process:\n- DLL Path:\n- DLL Signed (Y/N):\n- Search Order Hijack (Y/N):\n\nNotes:` },
  'T1204.002': { title:'T1204.002 - User Execution: Malicious File', body:`## TAG - EXECUTION\n### Technique: User Execution: Malicious File, T1204.002\n- Time:\n- Host:\n- User Account:\n- File Path:\n- File Type: (.exe / .lnk / .iso / .img / .one)\n- Source: (email attachment / browser download / removable media)\n- MOTW Present (Y/N):\n- Subsequent Activity:\n\nNotes:` },
  'T1548.002': { title:'T1548.002 - Bypass User Account Control', body:`## TAG - PRIVILEGE ESCALATION\n### Technique: Bypass UAC, T1548.002\n- Time:\n- Host:\n- User Account:\n- Method: (fodhelper / computerdefaults / eventvwr / cmstp / mock-folder / sdclt)\n- Auto-Elevating Binary:\n- Registry Handler Hijacked: (ms-settings / mscfile / other)\n- Child Process + Integrity:\n- Registry Artifact Deleted After (Y/N):\n\nNotes:` },
  T1134: { title:'T1134 - Access Token Manipulation', body:`## TAG - PRIVILEGE ESCALATION\n### Technique: Access Token Manipulation, T1134\n- Time:\n- Host:\n- Source Process / Account:\n- Target Token / Account Impersonated:\n- Sub-Technique: (.001 theft / .002 create-process-with-token / .005 SID-history)\n- SeImpersonate / SeAssignPrimaryToken Held (Y/N):\n- Potato Pattern (named-pipe coercion) (Y/N):\n- Resulting Context: (SYSTEM / admin)\n- Resulting Process + Parent:\n\nNotes:` },
  T1055: { title:'T1055 - Process Injection', body:`## TAG - PRIVILEGE ESCALATION\n### Technique: Process Injection, T1055\n- Time:\n- Host:\n- Source Process:\n- Target Process:\n- Sub-Technique: (.001 DLL / .002 PE / .003 thread-hijack / .012 hollowing)\n- Sysmon EID 8 (CreateRemoteThread) (Y/N):\n- EID 10 Access Rights:\n- Start Address Non-Image (Y/N):\n- Memory-Forensics Confirmation: (PE-sieve / malfind / hollowfind)\n\nNotes:` },
  T1068: { title:'T1068 - Exploitation for Privilege Escalation', body:`## TAG - PRIVILEGE ESCALATION\n### Technique: Exploitation for Privilege Escalation, T1068\n- Time:\n- Host:\n- Vector: (BYOVD / local CVE / Potato coercion / service exploit)\n- Driver or CVE:\n- Driver Path + Signed (Y/N):\n- Vulnerable-Driver List Match: (loldrivers / MS blocklist)\n- Service/Pipe Artifact:\n- Resulting SYSTEM Process + Parent:\n\nNotes:` },
  'T1574.011': { title:'T1574.011 - Services Registry Permissions Weakness', body:`## TAG - PRIVILEGE ESCALATION\n### Technique: Services Registry Permissions Weakness, T1574.011\n- Time:\n- Host:\n- Service Name + RunAs Account:\n- Value Modified: (ImagePath / ServiceDll / FailureCommand)\n- New Value / Payload Path:\n- Modifying Process:\n- Weak-ACL Confirmed (Y/N):\n- Service Restart Observed (Y/N):\n\nNotes:` },
  'T1574.005': { title:'T1574.005 - Unquoted Path / Weak Service Permissions', body:`## TAG - PRIVILEGE ESCALATION\n### Technique: Unquoted Path / Weak Service File Permissions, T1574.005/.009/.010\n- Time:\n- Host:\n- Service Name + RunAs Account:\n- Variant: (unquoted path / writable binary / writable folder)\n- Intercept Path or Planted File:\n- services.exe Child Path:\n- Resulting Context: (SYSTEM)\n\nNotes:` },
  'T1134.005': { title:'T1134.005 - SID-History Injection', body:`## TAG - PRIVILEGE ESCALATION\n### Technique: SID-History Injection, T1134.005\n- Time:\n- Domain / DC:\n- Target Account:\n- Injected SID(s) + RID: (512 DA / 519 EA / cross-domain)\n- Method: (mimikatz sid::add / DSInternals / DCShadow)\n- Security Event: (4765 added / 4766 failed / 4662 DRSUAPI)\n- Detected via Group Audit or sIDHistory Sweep:\n\nNotes:` },
  'T1546.008': { title:'T1546.008 - Accessibility Features', body:`## TAG - PRIVILEGE ESCALATION\n### Technique: Accessibility Features, T1546.008\n- Time:\n- Host:\n- Binary Targeted: (sethc / utilman / osk / Magnify / Narrator)\n- Mechanism: (binary replace / IFEO Debugger)\n- Debugger / Payload Value:\n- winlogon.exe Child Shell Observed (Y/N):\n- Triggered Pre-Auth at Logon Screen (Y/N):\n\nNotes:` },
  'T1546.012': { title:'T1546.012 - Image File Execution Options Injection', body:`## TAG - PRIVILEGE ESCALATION\n### Technique: IFEO Injection, T1546.012\n- Time:\n- Host:\n- Target Process:\n- Mechanism: (Debugger value / GlobalFlag + SilentProcessExit)\n- Payload / MonitorProcess Value:\n- Trigger: (on launch / on exit)\n- Real Debugger Allowlist Checked (Y/N):\n\nNotes:` },
  'T1574.001': { title:'T1574.001 - DLL Search Order Hijacking (Priv Esc)', body:`## TAG - PRIVILEGE ESCALATION\n### Technique: DLL Search Order Hijacking / Side-Loading, T1574.001\n- Time:\n- Host:\n- Privileged Process (loader) + Context:\n- Hijacked / Phantom DLL Name:\n- DLL Path (writable dir):\n- DLL Signed (Y/N):\n- Writable-Dir Precondition Confirmed (Y/N):\n\nNotes:` },
  'T1484.001': { title:'T1484.001 - Domain/Tenant Policy Modification', body:`## TAG - PRIVILEGE ESCALATION\n### Technique: GPO / Domain Trust Modification, T1484\n- Time:\n- Domain / DC:\n- Sub-Technique: (.001 GPO / .002 Domain Trust)\n- Artifact: (GptTmpl.inf / ScheduledTasks.xml / Groups.xml / TDO / federation)\n- ImmediateTaskV2 Present (Y/N):\n- Security Event: (5136 / 4706 / 4728)\n- Actor + Delegation Path:\n- Scope (hosts/domains affected):\n\nNotes:` },
  T1611: { title:'T1611 - Escape to Host', body:`## TAG - PRIVILEGE ESCALATION\n### Technique: Escape to Host (Container Breakout), T1611\n- Time:\n- Host / Node:\n- Container / Pod ID:\n- Vector: (privileged container / host mount / docker.sock / host namespace / runtime CVE)\n- Host Resource Accessed:\n- Runtime Detection: (Falco / eBPF / k8s audit)\n- Misconfig or Exploit:\n\nNotes:` },
  'T1548.001': { title:'T1548.001 - Setuid/Setgid & Capabilities', body:`## TAG - PRIVILEGE ESCALATION\n### Technique: Setuid/Setgid / Capabilities, T1548.001 [LINUX]\n- Time:\n- Host:\n- User / UID (auid login uid):\n- Vector: (SUID binary / SGID binary / file capability)\n- Binary Path:\n- From Package Manager (Y/N):\n- GTFOBins Method: (find -exec / awk system / vim :! / less ! / env / tee / python -p / perl)\n- Capability (if cap): (cap_setuid / cap_dac_override / cap_sys_admin / cap_sys_ptrace / cap_sys_module)\n- Resulting EUID: (0 = root)\n- Planted SUID in writable path (Y/N):\n- getcap baseline deviation (Y/N):\n- Auditd Key Alert: (suid_exec / setcap_exec / setuid_root)\n\nNotes:` },
  'T1548.003': { title:'T1548.003 - Sudo & Sudo Caching', body:`## TAG - PRIVILEGE ESCALATION\n### Technique: Sudo and Sudo Caching, T1548.003 [LINUX]\n- Time:\n- Host:\n- User / UID:\n- Vector: (sudoers misconfig / NOPASSWD GTFOBins / sudo CVE / token reuse)\n- sudo -l Enumeration Observed (Y/N):\n- Allowed Command Abused: (vim / find / less / awk / python / systemctl / tee / env)\n- NOPASSWD Rule (Y/N):\n- env_keep LD_PRELOAD/PYTHONPATH Abuse (Y/N):\n- CVE: (Baron Samedit CVE-2021-3156 / runas CVE-2019-14287 / CVE-2023-22809 / none)\n- sudo Version:\n- Token Reuse via ptrace (Y/N):\n- Sudoers File Modified (Y/N):\n- Auditd Key Alert: (sudo_exec / sudoers / ptrace_call)\n\nNotes:` },
  'T1574.006': { title:'T1574.006 - Dynamic Linker Hijacking (Priv Esc)', body:`## TAG - PRIVILEGE ESCALATION\n### Technique: Dynamic Linker Hijacking, T1574.006 [LINUX]\n- Time:\n- Host:\n- User / UID:\n- Vector: (sudo env_keep LD_PRELOAD / ld.so.preload / writable RPATH / ld.so.conf writable dir)\n- Malicious .so Path:\n- Privileged Process Affected: (sudo cmd / SUID binary / daemon)\n- /etc/ld.so.preload Present (Y/N):\n- sudoers env_keep includes LD_* (Y/N):\n- SUID RPATH/RUNPATH writable (Y/N):\n- Cross-ref T1106 (execution-side) (Y/N):\n- Auditd Key Alert: (ldso_preload / sudo_exec)\n\nNotes:` },
  T1098: { title:'T1098 - Account Manipulation (Priv Esc)', body:`## TAG - PRIVILEGE ESCALATION\n### Technique: Account Manipulation, T1098\n- Time:\n- Host / Domain:\n- Account Manipulated:\n- Mechanism: (privileged group add / user-right assignment / AdminSDHolder ACL)\n- Group or Privilege Granted:\n- Security Event: (4728 / 4732 / 4756 / 4704 / 5136)\n- Actor:\n- Crown-Jewel Group Affected (Y/N):\n\nNotes:` },
  'T1070.003': { title:'T1070.003 - Clear Command History', body:`## TAG - DEFENSE EVASION\n### Technique: Clear Command History, T1070.003 [LINUX]\n- Time:\n- Host:\n- User / UID (auid):\n- Method: (unset HISTFILE / HISTFILE=/dev/null / set +o history / history -c / symlink /dev/null / kill -9 $$)\n- History File Path: (~/.bash_history / .zsh_history / other)\n- File State: (symlink? zero-byte? truncated?)\n- rc File Modified (HISTFILE/HISTSIZE in .bashrc)? (Y/N):\n- Live Shell With History Disabled (PID):\n- Session in 'last' Without Matching History (Y/N):\n- Auditd execve Counter-Record Available (Y/N):\n- Auditd Key Alert: (bash_history / exec)\n\nNotes:` },
  'T1070.002': { title:'T1070.002 - Clear Linux System Logs', body:`## TAG - DEFENSE EVASION\n### Technique: Clear Linux System Logs, T1070.002 [LINUX]\n- Time:\n- Host:\n- User / UID (auid):\n- Target Logs: (auth.log / secure / syslog / messages / audit.log / journal / wtmp / btmp)\n- Method: (rm / shred / truncate / : > / sed -i excision / journalctl --vacuum)\n- Selective Excision Suspected (sed -i specific lines)? (Y/N):\n- Login-DB Tampering: (utmp / wtmp / btmp / lastlog) (Y/N):\n- utmpdump Round-Trip Observed (Y/N):\n- auth.log Accepted Count vs 'last' Session Count:\n- Zero-Byte / mtime>newest-entry Anomaly (Y/N):\n- Remote/Forwarded Copy Available for Diff (Y/N):\n- Auditd Key Alert: (var_log_tamper / auditlog_tamper / wtmp_tamper)\n\nNotes:` },
  'T1070.006': { title:'T1070.006 - Timestomp', body:`## TAG - DEFENSE EVASION\n### Technique: Timestomp, T1070.006 [LINUX]\n- Time:\n- Host:\n- User / UID (auid):\n- Method: (touch -r / touch -t / touch -d / utimensat syscall / debugfs)\n- Target File:\n- Reference File Cloned (touch -r source):\n- ctime > mtime Mismatch (the tell)? (Y/N):\n- mtime Predates Inode Allocation (high inode, old date)? (Y/N):\n- Package-Manifest mtime Drift (rpm -Va T flag)? (Y/N):\n- ext4 Birth/crtime Also Forged (debugfs)? (Y/N):\n- Clock Manipulation Evidence (NTP/journal jump)? (Y/N):\n- Auditd Key Alert: (timestomp / touch_exec)\n\nNotes:` },
  'T1070.004': { title:'T1070.004 - File Deletion', body:`## TAG - DEFENSE EVASION\n### Technique: File Deletion, T1070.004 [LINUX]\n- Time:\n- Host:\n- User / UID (auid):\n- Method: (rm -rf / shred -u / wipe / dd zero-then-rm / self-delete)\n- Target: (tool / staging dir / payload / log)\n- Self-Deleting Running Process? exe shows '(deleted)' (PID):\n- Recovered via /proc/<pid>/exe (Y/N):\n- Deleted-but-Open fd in /proc/*/fd (Y/N):\n- osquery on_disk=0 Match (Y/N):\n- Carving Attempted (extundelete/foremost)? (Y/N):\n- Part of Anti-Forensic Cluster (history+log+timestomp)? (Y/N):\n- Auditd Key Alert: (file_delete / shred_exec)\n\nNotes:` },
  'T1562.012': { title:'T1562.012 - Disable or Modify Linux Audit System', body:`## TAG - DEFENSE EVASION\n### Technique: Disable or Modify Linux Audit System, T1562.012 [LINUX]\n- Time:\n- Host:\n- User / UID (auid):\n- Method: (auditctl -e 0 / auditctl -D / stop/mask auditd / kill / config edit)\n- auditctl -s enabled Value: (0=off / 1=on / 2=immutable)\n- Loaded Rules vs On-Disk Rules Count:\n- CONFIG_CHANGE / DAEMON_END Event Seen (Y/N):\n- DAEMON_END Without DAEMON_START While Host Up (Y/N):\n- auditd.conf Tampered (log_file=/dev/null / flush=none)? (Y/N):\n- audisp-remote Forwarding Active (off-box copy)? (Y/N):\n- Event-Volume (EPS) Gap on Live Host (Y/N):\n- Immutable Mode (-e 2) Was Set (Y/N):\n- Auditd Key Alert: (auditconfig / auditctl_exec / daemon-end)\n\nNotes:` },
  'T1562.001': { title:'T1562.001 - Disable or Modify Tools', body:`## TAG - DEFENSE EVASION\n### Technique: Disable or Modify Tools, T1562.001\n- Time:\n- Host:\n- User / UID (auid) / SID:\n- OS: (Windows / Linux)\n- Target: (security agent / EDR / AV / Defender / cloud agent / SELinux / AppArmor / AMSI / ETW)\n- [LINUX] Agent: (Falco / Wazuh / osquery / ClamAV / falcon-sensor / aegis-AliYunDun / YunJing)\n- [LINUX] Method: (systemctl stop/disable/mask / kill / pkill / uninstall / package remove)\n- [LINUX] Cloud-Agent Uninstall (Alibaba/Tencent) crypto-crew TTP? (Y/N):\n- [LINUX] MAC Action: (setenforce 0 / SELINUX=disabled / aa-teardown / GRUB selinux=0):\n- [WIN] Defender Method: (Set-MpPreference disable / Add-MpPreference exclusion / sc stop WinDefend / DisableAntiSpyware key):\n- [WIN] Defender Exclusion Added (path/process/ext)? (Y/N):\n- [WIN] AMSI Bypass (AmsiScanBuffer patch / amsiInitFailed)? (Y/N):\n- [WIN] ETW Patch (ntdll!EtwEventWrite prologue)? (Y/N):\n- [WIN] Defender Operational Event (5001/5007/5010/5012/5013):\n- [WIN] Script Block Logging (4104) Captured Bypass (Y/N):\n- Off-Box Record (SIEM heartbeat / MDE cloud / audisp-remote) Available (Y/N):\n- Key Alert: (svc_change / kill_signal / selinux_config / Defender 5001-5013 / posh 4104)\n\nNotes:` },
  'T1562.004': { title:'T1562.004 - Disable or Modify System Firewall', body:`## TAG - DEFENSE EVASION\n### Technique: Disable or Modify System Firewall, T1562.004 [LINUX]\n- Time:\n- Host:\n- User / UID (auid):\n- Backend: (iptables / nftables / ufw / firewalld)\n- Method: (-F flush / nft flush ruleset / -P INPUT ACCEPT / ufw disable / stop firewalld / targeted ACCEPT)\n- Intent: (wide-open flush vs targeted allow rule):\n- Allow Rule Port / Source IP (if targeted):\n- Parent Process: (interactive shell vs docker/kube-proxy/fail2ban):\n- Legit-Churn Excluded by Provenance (Y/N):\n- Default Policy Now: (DROP / ACCEPT):\n- New Listening Socket Matching New ACCEPT (Y/N):\n- Firewall Config File Edited (mtime/auditd)? (Y/N):\n- Auditd Key Alert: (fw_config / iptables_exec / nft_exec)\n\nNotes:` },
  'T1562.006': { title:'T1562.006 - Indicator Blocking', body:`## TAG - DEFENSE EVASION\n### Technique: Indicator Blocking, T1562.006 [LINUX]\n- Time:\n- Host:\n- User / UID (auid):\n- Suppression Point: (logging daemon / forwarding directive / audisp-remote / network/DNS/hosts)\n- Method: (stop rsyslog/syslog-ng / strip @@forward / Storage=none / audisp active=no / OUTPUT DROP 514 / hosts poison)\n- Daemon State: (rsyslog/syslog-ng/journald active?):\n- Remote Forwarding Still Configured (Y/N):\n- audisp-remote active Value: (yes/no):\n- /etc/hosts Collector Poisoned (Y/N):\n- Egress DROP to 514/6514 (Y/N):\n- Ingestion-Gap / Source-Silence Alert Fired (Y/N):\n- Paired With T1562.012 (auditd disable) for Full Blinding (Y/N):\n- Auditd Key Alert: (log_config / audisp_config / hosts_tamper)\n\nNotes:` },
  'T1014': { title:'T1014 - Rootkit', body:`## TAG - DEFENSE EVASION\n### Technique: Rootkit, T1014 [LINUX]\n- Time:\n- Host:\n- User / UID (auid):\n- Rootkit Class: (LKM kernel-mode / userland LD_PRELOAD / eBPF)\n- Family (if known): (Diamorphine / Reptile / Adore-ng / Azazel / HiddenWasp / BPFDoor / Symbiote)\n- Kernel Taint Value (/proc/sys/kernel/tainted):\n- lsmod vs /sys/module Discrepancy (hidden module)? (Y/N):\n- /proc Walk vs ps Hidden PID (Y/N):\n- /proc/net/tcp vs ss Hidden Port (Y/N):\n- /etc/ld.so.preload Present/Non-Empty (Y/N):\n- Dynamic-vs-Static Listing Differential (ls vs busybox) (Y/N):\n- bpftool prog Unexpected Program (type/owner)? (Y/N):\n- AF_PACKET Raw-Socket Passive Listener (BPFDoor) (PID):\n- init_module / bpf() Load Event Captured (Y/N):\n- Memory Forensics (Volatility linux_check_*) Run (Y/N):\n- Auditd Key Alert: (module_ops / ldso_preload / bpf_ops)\n\nNotes:` },
  'T1036.005': { title:'T1036.005 - Match Legitimate Name or Location', body:`## TAG - DEFENSE EVASION\n### Technique: Match Legitimate Name or Location, T1036.005 [LINUX]\n- Time:\n- Host:\n- User / UID (auid):\n- Vector: (kernel-thread masquerade / binary name / binary location)\n- Masqueraded Name: (e.g. [kworker/0:1] / sshd / crond / systemd)\n- PID (if running):\n- KTHREAD CHECK - ppid (real kthread=2):\n- KTHREAD CHECK - /proc/<pid>/exe (real kthread=empty):\n- KTHREAD CHECK - /proc/<pid>/cmdline (real kthread=empty):\n- KTHREAD CHECK - /proc/<pid>/maps (real kthread=empty):\n- Binary Real Path (readlink exe) vs Canonical Daemon Path:\n- Package-Owned (rpm -qf / dpkg -S)? (Y/N):\n- Parent Process: (shell vs systemd/init):\n- Trailing-Space / Homoglyph / Case Trick (Y/N):\n- Backing Binary Recovered (cp /proc/<pid>/exe) (Y/N):\n- Paired With Timestomp (T1070.006)? (Y/N):\n- Auditd Key Alert: (exec_tmp / exec_shm / sysdir_write)\n\nNotes:` },
  'T1036.004': { title:'T1036.004 - Masquerade Task or Service', body:`## TAG - DEFENSE EVASION\n### Technique: Masquerade Task or Service, T1036.004 [LINUX]\n- Time:\n- Host:\n- User / UID (auid):\n- Artifact: (systemd .service / .timer / cron.d / crontab / cron.daily)\n- Masqueraded Name: (e.g. systemd-update / dbus-org-helper):\n- Unit / Entry Path:\n- ExecStart / Command Target Path:\n- ExecStart in Writable or Odd Path (/tmp /dev/shm /home)? (Y/N):\n- Unit File Package-Owned (rpm -qf / dpkg -S)? (Y/N):\n- Admin Unit in /etc/systemd/system (legitimately unowned)? (Y/N):\n- Backing Binary Package-Owned + Canonical Path? (Y/N):\n- Restart=always Resilience (Y/N):\n- Cron Payload (curl / wget / base64 / piped sh) (Y/N):\n- Cross-Ref Persistence (T1543.002 / T1053.003) (Y/N):\n- Auditd Key Alert: (systemd_unit / cron_change)\n\nNotes:` },
  'T1070.001': { title:'T1070.001 - Clear Windows Event Logs', body:`## TAG - DEFENSE EVASION\n### Technique: Clear Windows Event Logs, T1070.001\n- Time:\n- Host:\n- User / SID:\n- Method: (wevtutil cl / Clear-EventLog / Remove-EventLog / EventLog.Clear() / Phant0m thread suspend)\n- Target Log(s): (Security / System / Application / Sysmon / PowerShell-Operational)\n- Security 1102 Present (audit log cleared)? (Y/N):\n- System 104 Present (log file cleared)? (Y/N):\n- Clearing Account (from 1102):\n- Phant0m Suspected (EventLog Running but silent, no 1102)? (Y/N):\n- Source-Silence / EPS-Gap Alert Fired (Y/N):\n- Security.evtx Size/mtime Drop (recent clear)? (Y/N):\n- Disabled Channel (WINEVT Channels Enabled=0)? (Y/N):\n- WEF / Forwarded Copy Available for Recovery (Y/N):\n- Key Alert: (Security 1102 / System 104 / 7035-7040 EventLog svc)\n\nNotes:` },
  'T1112': { title:'T1112 - Modify Registry', body:`## TAG - DEFENSE EVASION\n### Technique: Modify Registry, T1112\n- Time:\n- Host:\n- User / SID:\n- Use: (disable defense / fileless storage / hidden key)\n- Tool: (reg.exe / PowerShell Set-ItemProperty / regini / reg save-restore / direct API)\n- Target Key / Value:\n- Defense Weakened: (EnableLUA=0 / DisableAntiSpyware / SmartScreen Off / service Start=4 / IFEO Debugger):\n- Fileless Blob (oversized base64/hex value)? (Y/N) Length:\n- Null-Byte Hidden Key (invisible to reg.exe, seen by Autoruns)? (Y/N):\n- Sysmon Event: (12 key create-delete / 13 value-set / 14 rename):\n- reg save of SAM/SYSTEM/SECURITY Co-Occurred (T1003)? (Y/N):\n- Baseline Diff Confirms Change (Y/N):\n- Key Alert: (Sysmon registry 12/13/14 on sensitive key)\n\nNotes:` },
  'T1218.004': { title:'T1218.004 - InstallUtil', body:`## TAG - DEFENSE EVASION\n### Technique: InstallUtil, T1218.004\n- Time:\n- Host:\n- User / SID:\n- InstallUtil Path: (Framework / Framework64 v4.0.30319)\n- Command Line (/U or /uninstall? /LogToConsole=false?):\n- Target Assembly Path (user-path Temp/AppData/Downloads?):\n- Parent (non-dev: Office / script / shell?):\n- Child Shell or Network Egress (loaded assembly beacon)? (Y/N):\n- App-Control Bypass via Trusted .NET Dir Confirmed (Y/N):\n- Key Alert: (Sysmon 1: /U + user-path assembly + non-dev parent)\n\nNotes:` },
  'T1127.001': { title:'T1127.001 - MSBuild Inline Task', body:`## TAG - DEFENSE EVASION\n### Technique: MSBuild Inline Task, T1127.001\n- Time:\n- Host:\n- User / SID:\n- MSBuild Path: (Framework[64] / Visual Studio):\n- Project File (.csproj / .xml) and Path (user-path?):\n- Parent (dev IDE / CI agent vs Office / script / shell):\n- Inline UsingTask + Code Language=cs Present (Y/N):\n- Runtime Compilation (csc / Roslyn loaded)? (Y/N):\n- Child Shell / rundll32 / Network Egress? (Y/N):\n- Content Tell (reflection / FromBase64String / Process.Start)? (Y/N):\n- Key Alert: (MSBuild user-path project + non-dev parent)\n\nNotes:` },
  'T1218.007': { title:'T1218.007 - Msiexec', body:`## TAG - DEFENSE EVASION\n### Technique: Msiexec, T1218.007\n- Time:\n- Host:\n- User / SID:\n- Command Line (/i + http? /q quiet? /y DLL?):\n- MSI Source: (remote URL / user-path local / managed share):\n- msiexec Network Egress (remote MSI fetch)? (Y/N):\n- Parent (Office / Outlook / mshta / powershell delivery chain)? (Y/N):\n- msiexec Spawned Shell or rundll32 (custom action)? (Y/N):\n- MsiInstaller App-Log Event (1033/1040/11707) Correlated:\n- Cached MSI (Windows\\Installer) / Installed Product Key:\n- Key Alert: (remote /i http + msiexec Sysmon EID 3 egress)\n\nNotes:` },
};

// ── STATE ──
let activeTech = 'all';
let activeApt  = null;
let activeOs   = null;
let huntOpen   = false;
let totalRows  = 0;
let selectedRows = new Set();
let huntItems  = {};     // rowId -> { indicator, techId, severity, addedAt, row }
let rowRegistry = {};    // rowId -> { row, techId }

// ── PERSISTENCE ──
// Hunt items survive across tabs and browser sessions via localStorage.
// Schema versioning lets us migrate or discard incompatible saved data.
const HUNT_STORAGE_KEY = 'hunt_reference_hunts_v1';
const HUNT_SCHEMA_VERSION = 1;

function loadHunts() {
  try {
    const raw = localStorage.getItem(HUNT_STORAGE_KEY);
    if (!raw) return;
    const parsed = JSON.parse(raw);
    if (!parsed || parsed._v !== HUNT_SCHEMA_VERSION) {
      console.warn('Hunt storage schema mismatch; discarding old data.');
      localStorage.removeItem(HUNT_STORAGE_KEY);
      return;
    }
    huntItems = parsed.items || {};
  } catch (e) {
    console.error('Failed to load hunts from localStorage:', e);
    huntItems = {};
  }
}

function saveHunts() {
  try {
    const payload = { _v: HUNT_SCHEMA_VERSION, items: huntItems };
    localStorage.setItem(HUNT_STORAGE_KEY, JSON.stringify(payload));
  } catch (e) {
    // QuotaExceededError is the realistic failure mode.
    console.error('Failed to save hunts to localStorage:', e);
  }
}

// Cross-tab sync: when another tab modifies the hunt list, refresh ours.
window.addEventListener('storage', e => {
  if (e.key !== HUNT_STORAGE_KEY) return;
  loadHunts();
  renderHunt();
  // Refresh star button states for indicators on the current page.
  document.querySelectorAll('.ind-row').forEach(rowEl => {
    const rowId = rowEl.dataset.rowId;
    const star = rowEl.querySelector('.star-btn');
    if (!star) return;
    if (huntItems[rowId]) {
      star.innerHTML = '&#9733;';
      star.classList.add('starred');
    } else {
      star.innerHTML = '&#9734;';
      star.classList.remove('starred');
    }
  });
});

// ── HELPERS ──
function esc(s) {
  return String(s)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;');
}

function aptOrigins(apt) {
  return apt.map(a => {
    if (a.cls === 'apt-cn') return 'CN';
    if (a.cls === 'apt-ru') return 'RU';
    if (a.cls === 'apt-ir') return 'IR';
    if (a.cls === 'apt-kp') return 'KP';
    return '';
  }).join(' ');
}

function copyText(text, btn, label) {
  navigator.clipboard.writeText(text.trim()).then(() => {
    const orig = btn.textContent;
    btn.textContent = label || 'Copied!';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = orig; btn.classList.remove('copied'); }, 1400);
  });
}

// ── BUILD ROW ──
function buildRow(row, techId, rowId) {
  const aptBadges = row.apt.map(a =>
    `<span class="apt-badge ${a.cls}">${a.name}</span>`
  ).join('');

  const searchText = [
    row.indicator, row.notes, row.sysmon, row.kibana, row.powershell,
    row.registry || '', row.tools || '', row.ossdetect || '',
    row.apt.map(a => a.name + ' ' + (a.note||'')).join(' '),
    row.cite || '', techId,
    (row.os === 'linux') ? 'linux unix' : 'windows win'
  ].join(' ').toLowerCase();

  const el = document.createElement('div');
  el.className = 'ind-row';
  el.dataset.tech = techId;
  el.dataset.apt  = aptOrigins(row.apt);
  el.dataset.os   = (row.os === 'linux') ? 'linux' : 'win';
  el.dataset.text = searchText;
  el.dataset.rowId = rowId;
  el.dataset.techId = techId;

  const isLinux = (row.os === 'linux');
  const osBadge = isLinux
    ? '<span class="os-badge os-linux" title="Linux indicator">LINUX</span>'
    : '<span class="os-badge os-win" title="Windows indicator">WIN</span>';
  // OS-aware quick-tool labels: PS slot is Auditd/Shell on Linux
  const psBtnLabel = isLinux ? 'AUD' : 'PS';
  const psBtnTitle = isLinux ? 'Copy Auditd / Shell hunt' : 'Copy PowerShell';

  // ── collapsed bar ──
  const bar = document.createElement('div');
  bar.className = 'ind-collapsed';
  const isStarred = !!huntItems[rowId];
  bar.innerHTML = `
    <input type="checkbox" class="row-check" title="Select for export">
    <button class="star-btn${isStarred ? ' starred' : ''}" title="Add to hunt">${isStarred ? '&#9733;' : '&#9734;'}</button>
    ${osBadge}
    <span class="ind-name">${esc(row.indicator)}</span>
    <div class="apt-badges">${aptBadges}</div>
    <div class="quick-tools">
      <button class="qtool qt-y" title="Copy Sysmon">SYS</button>
      <button class="qtool qt-k" title="Copy Kibana">KQL</button>
      <button class="qtool qt-p" title="${psBtnTitle}">${psBtnLabel}</button>
    </div>
    <span class="expand-icon">&#9662;</span>`;

  bar.querySelector('.row-check').addEventListener('click', e => {
    e.stopPropagation();
    toggleSelect(rowId, e.target);
  });
  bar.querySelector('.star-btn').addEventListener('click', e => {
    e.stopPropagation();
    toggleHuntItem(rowId, e.target);
  });
  bar.querySelector('.qt-y').addEventListener('click', e => {
    e.stopPropagation();
    copyText(row.sysmon, e.target);
  });
  bar.querySelector('.qt-k').addEventListener('click', e => {
    e.stopPropagation();
    copyText(row.kibana, e.target);
  });
  bar.querySelector('.qt-p').addEventListener('click', e => {
    e.stopPropagation();
    copyText(row.powershell, e.target);
  });
  bar.addEventListener('click', () => el.classList.toggle('open'));

  // ── detail panel ──
  const detail = document.createElement('div');
  detail.className = 'ind-detail';

  const tabs = [
    ['sys', 'Sysmon'],
    ['kib', 'Kibana'],
    ['ps',  isLinux ? 'Auditd/Shell' : 'PowerShell'],
    ['reg', isLinux ? 'File Artifacts' : 'Registry/Artifacts'],
    ['tool','Tools'],
    ['oss', 'OSS Detections'],
    ['not', 'Notes'],
    ['apt', 'APT'],
    ['cms', 'Case Template'],
  ];
  const tabBar = document.createElement('div');
  tabBar.className = 'tab-bar';
  tabs.forEach(([key, label], i) => {
    const btn = document.createElement('button');
    btn.className = 'dtab' + (i === 0 ? ' active' : '');
    btn.dataset.key = key;
    btn.textContent = label;
    btn.addEventListener('click', () => switchTab(detail, btn));
    tabBar.appendChild(btn);
  });
  detail.appendChild(tabBar);

  // code panels
  function codePanel(langCls, langLabel, content) {
    const wrap = document.createElement('div');
    wrap.className = 'code-wrap';
    const copyBtn = document.createElement('button');
    copyBtn.className = 'copy-btn';
    copyBtn.textContent = 'Copy';
    copyBtn.addEventListener('click', () => copyText(content, copyBtn));
    wrap.innerHTML = `<div class="code-hdr"><span class="code-lang ${langCls}">${langLabel}</span></div>`;
    wrap.querySelector('.code-hdr').appendChild(copyBtn);
    const pre = document.createElement('pre');
    pre.className = 'code-body';
    pre.textContent = content;
    wrap.appendChild(pre);
    return wrap;
  }

  // panels
  const panels = {
    'sys': codePanel('l-sys', isLinux ? 'Sysmon for Linux Event' : 'Sysmon Event', row.sysmon),
    'kib': codePanel('l-kib', 'Kibana KQL',      row.kibana),
    'ps':  codePanel('l-ps',  isLinux ? 'Auditd / Shell Hunt' : 'PowerShell Hunt',  row.powershell),
    'reg': (() => { const d = document.createElement('div'); d.className = 'notes-body'; d.textContent = row.registry || (isLinux ? '(no file artifacts documented)' : '(no registry/file artifacts documented)'); return d; })(),
    'tool': (() => { const d = document.createElement('div'); d.className = 'notes-body'; d.textContent = row.tools || '(no adversary tools documented)'; return d; })(),
    'oss': (() => { const d = document.createElement('div'); d.className = 'notes-body'; d.textContent = row.ossdetect || '(no open-source detections documented)'; return d; })(),
    'not': (() => { const d = document.createElement('div'); d.className = 'notes-body'; d.textContent = row.notes; return d; })(),
    'apt': (() => {
      const d = document.createElement('div');
      row.apt.forEach(a => {
        const item = document.createElement('div');
        item.className = 'apt-item';
        item.innerHTML = `<span class="apt-badge ${a.cls}" style="font-size:11px">${esc(a.name)}</span>`;
        if (a.note) {
          const note = document.createElement('div');
          note.className = 'apt-item-note';
          note.textContent = a.note;
          item.appendChild(note);
        }
        d.appendChild(item);
      });
      if (row.cite) {
        const cite = document.createElement('div');
        cite.className = 'apt-cite';
        cite.textContent = row.cite;
        d.appendChild(cite);
      }
      return d;
    })(),
    'cms': (() => {
      const d = document.createElement('div');
      const tpl = CMS_TEMPLATES[techId];
      if (tpl) {
        const hdr = document.createElement('div');
        hdr.className = 'cms-hdr';
        const title = document.createElement('span');
        title.className = 'cms-title';
        title.textContent = tpl.title;
        const copyBtn = document.createElement('button');
        copyBtn.className = 'copy-btn';
        copyBtn.style.borderColor = 'var(--teal)';
        copyBtn.textContent = 'Copy Template';
        copyBtn.addEventListener('click', () => copyText(tpl.body, copyBtn, 'Copied!'));
        hdr.appendChild(title);
        hdr.appendChild(copyBtn);
        const pre = document.createElement('pre');
        pre.className = 'cms-body-pre';
        pre.textContent = tpl.body;
        d.appendChild(hdr);
        d.appendChild(pre);
      } else {
        d.innerHTML = '<span style="color:var(--text3);font-size:12px">No case template for this technique yet.</span>';
      }
      return d;
    })(),
  };

  const panelKeys = ['sys','kib','ps','reg','tool','oss','not','apt','cms'];
  panelKeys.forEach((key, i) => {
    const wrap = document.createElement('div');
    wrap.className = 'tab-panel' + (i === 0 ? ' active' : '');
    wrap.dataset.key = key;
    wrap.appendChild(panels[key]);
    detail.appendChild(wrap);
  });

  el.appendChild(bar);
  el.appendChild(detail);
  rowRegistry[rowId] = { row, techId };
  return el;
}

function switchTab(detail, activeBtn) {
  detail.querySelectorAll('.dtab').forEach(b => b.classList.remove('active'));
  detail.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  activeBtn.classList.add('active');
  const key = activeBtn.dataset.key;
  const panel = detail.querySelector(`.tab-panel[data-key="${key}"]`);
  if (panel) panel.classList.add('active');
}

// ── RENDER ──
function render() {
  const content = document.getElementById('content');
  const toc     = document.getElementById('toc');
  const sidebarStats = document.getElementById('sidebar-stats');
  if (!content) return;

  DATA.forEach(tech => {
    // TOC
    const tocItem = document.createElement('div');
    tocItem.className = 'toc-item';
    tocItem.dataset.tech = tech.id;
    tocItem.innerHTML = `<span class="toc-id">${tech.id}</span><span class="toc-count">${tech.rows.length}</span>`;
    tocItem.addEventListener('click', () => {
      document.querySelectorAll('.fbtn[data-tech]').forEach(b => b.classList.remove('active'));
      const btn = document.querySelector(`.fbtn[data-tech="${tech.id}"]`);
      if (btn) { btn.classList.add('active'); activeTech = tech.id; applyFilters(); }
      document.getElementById('tech-' + tech.id)?.scrollIntoView({ behavior:'smooth', block:'start' });
    });
    if (toc) toc.appendChild(tocItem);

    // Section
    const section = document.createElement('div');
    section.className = 'technique-section';
    section.id = 'tech-' + tech.id;
    section.dataset.tech = tech.id;

    const hdr = document.createElement('div');
    hdr.className = 'tech-header';
    hdr.innerHTML = `<span class="tech-id">${tech.id}</span><span class="tech-name">${tech.name}</span><span class="tech-count">${tech.rows.length}</span><span class="tech-desc">${tech.desc || ''}</span><span class="tech-toggle">&#9662;</span>`;
    hdr.addEventListener('click', () => section.classList.toggle('collapsed'));
    section.appendChild(hdr);

    const wrap = document.createElement('div');
    wrap.className = 'rows-wrap';

    let lastSub = '';
    tech.rows.forEach((row, i) => {
      if (row.sub && row.sub !== lastSub) {
        const div = document.createElement('div');
        div.className = 'sub-divider';
        div.textContent = row.sub;
        wrap.appendChild(div);
        lastSub = row.sub;
      }
      const rowId = tech.id + '_' + i;
      wrap.appendChild(buildRow(row, tech.id, rowId));
      totalRows++;
    });

    section.appendChild(wrap);
    content.appendChild(section);
  });

  if (sidebarStats) {
    sidebarStats.innerHTML = DATA.map(t =>
      `<div><span style="color:var(--accent);font-family:var(--mono)">${t.id}</span> - ${t.rows.length}</div>`
    ).join('') + `<div style="margin-top:6px;color:var(--text2)">Total: <strong>${totalRows}</strong></div>`;
  }

  updateStats(totalRows, totalRows);
}

// ── SELECT / EXPORT SELECTED ──
function toggleSelect(rowId, cb) {
  if (cb.checked) selectedRows.add(rowId);
  else selectedRows.delete(rowId);
  const btn = document.getElementById('export-selected-btn');
  if (btn) btn.style.display = selectedRows.size > 0 ? 'flex' : 'none';
}

function exportSelected() {
  if (!selectedRows.size) return;
  let out = `Hunt Reference - Selected Indicators\nExported: ${new Date().toLocaleString()}\n${'='.repeat(60)}\n\n`;
  selectedRows.forEach(rowId => {
    const entry = rowRegistry[rowId];
    if (!entry) return;
    const { row, techId } = entry;
    out += `[${techId}] ${row.indicator}\n${'-'.repeat(50)}\nSYSMON:\n${row.sysmon}\n\nKIBANA:\n${row.kibana}\n\nPOWERSHELL:\n${row.powershell}\n\nREGISTRY/ARTIFACTS:\n${row.registry || '(none)'}\n\nTOOLS:\n${row.tools || '(none)'}\n\nOSS DETECTIONS:\n${row.ossdetect || '(none)'}\n\nNOTES:\n${row.notes}\n\n${'='.repeat(60)}\n\n`;
  });
  download(out, 'selected_indicators.txt', 'text/plain');
}

// ── HUNT ──
function toggleHunt() {
  huntOpen = !huntOpen;
  document.getElementById('hunt-panel').classList.toggle('open', huntOpen);
}

function toggleHuntItem(rowId, starBtn) {
  if (huntItems[rowId]) {
    delete huntItems[rowId];
    starBtn.innerHTML = '&#9734;';
    starBtn.classList.remove('starred');
  } else {
    const entry = rowRegistry[rowId];
    if (!entry) return;
    huntItems[rowId] = {
      indicator: entry.row.indicator,
      techId: entry.techId,
      severity: 'high',
      addedAt: Date.now(),
      row: entry.row  // full row data - enables cross-tactic export from any page
    };
    starBtn.innerHTML = '&#9733;';
    starBtn.classList.add('starred');
    if (!huntOpen) { huntOpen = true; document.getElementById('hunt-panel').classList.add('open'); }
  }
  saveHunts();
  renderHunt();
}

function renderHunt() {
  const list = document.getElementById('hunt-list');
  const countEl = document.getElementById('hunt-count');
  const keys = Object.keys(huntItems);

  if (!keys.length) {
    list.innerHTML = '<div class="hunt-empty">No indicators added. Click &#9734; on any row.</div>';
    if (countEl) countEl.style.display = 'none';
    return;
  }

  if (countEl) { countEl.textContent = keys.length; countEl.style.display = 'inline'; }

  // Sort by addedAt ascending - oldest first, building a hunt timeline.
  // Items added before persistence existed have no addedAt and sort as 0 (top).
  const sortedKeys = keys.slice().sort((a, b) => {
    const ta = huntItems[a].addedAt || 0;
    const tb = huntItems[b].addedAt || 0;
    return ta - tb;
  });

  // Group consecutive items by techId and insert a small header before each new group.
  let html = '';
  let lastTech = null;
  sortedKeys.forEach(rowId => {
    const item = huntItems[rowId];
    if (item.techId !== lastTech) {
      html += `<div class="hunt-group-header">${item.techId}</div>`;
      lastTech = item.techId;
    }
    const ts = item.addedAt
      ? new Date(item.addedAt).toLocaleString(undefined, { month:'short', day:'numeric', hour:'2-digit', minute:'2-digit' })
      : '';
    html += `<div class="hunt-item">
      <span class="hunt-item-tech">${item.techId}</span>
      <span class="hunt-item-name">${esc(item.indicator)}</span>
      ${ts ? `<span class="hunt-item-ts" title="Added">${ts}</span>` : ''}
      <select class="sev-sel sev-${item.severity}" data-rowid="${rowId}">
        <option value="critical" ${item.severity==='critical'?'selected':''}>CRITICAL</option>
        <option value="high"     ${item.severity==='high'    ?'selected':''}>HIGH</option>
        <option value="medium"   ${item.severity==='medium'  ?'selected':''}>MEDIUM</option>
        <option value="low"      ${item.severity==='low'     ?'selected':''}>LOW</option>
      </select>
      <button class="hunt-remove" data-rowid="${rowId}">&#10005;</button>
    </div>`;
  });
  list.innerHTML = html;

  // CSP-safe: wire up handlers via listeners instead of inline on* attributes
  list.querySelectorAll('.sev-sel').forEach(sel => {
    sel.addEventListener('change', () => setSev(sel.dataset.rowid, sel));
  });
  list.querySelectorAll('.hunt-remove').forEach(btn => {
    btn.addEventListener('click', () => removeHunt(btn.dataset.rowid));
  });
}

function setSev(rowId, sel) {
  if (huntItems[rowId]) {
    huntItems[rowId].severity = sel.value;
    sel.className = 'sev-sel sev-' + sel.value;
    saveHunts();
  }
}

function removeHunt(rowId) {
  delete huntItems[rowId];
  const el = document.querySelector(`.ind-row[data-row-id="${rowId}"] .star-btn`);
  if (el) { el.innerHTML = '&#9734;'; el.classList.remove('starred'); }
  saveHunts();
  renderHunt();
}

function clearHunt() {
  Object.keys(huntItems).forEach(rowId => {
    const el = document.querySelector(`.ind-row[data-row-id="${rowId}"] .star-btn`);
    if (el) { el.innerHTML = '&#9734;'; el.classList.remove('starred'); }
  });
  huntItems = {};
  saveHunts();
  renderHunt();
}

function exportHunt(fmt) {
  const keys = Object.keys(huntItems);
  if (!keys.length) return;

  // Sort by addedAt to preserve hunt timeline order in exports.
  const sortedKeys = keys.slice().sort((a, b) => {
    const ta = huntItems[a].addedAt || 0;
    const tb = huntItems[b].addedAt || 0;
    return ta - tb;
  });

  // Use stored row data first; fall back to rowRegistry for items added before
  // persistence existed, or that for some reason lack the .row field.
  const getRow = rowId => huntItems[rowId].row || (rowRegistry[rowId] && rowRegistry[rowId].row);

  if (fmt === 'csv') {
    const q = s => '"' + String(s||'').replace(/"/g,'""').replace(/\n/g,' ') + '"';
    let csv = 'Order,Added,Severity,Technique,Indicator,Sysmon,Kibana,PowerShell,Registry,Tools,OSSDetections,Notes\n';
    sortedKeys.forEach((rowId, i) => {
      const item = huntItems[rowId];
      const r = getRow(rowId);
      if (!r) return;
      const ts = item.addedAt ? new Date(item.addedAt).toISOString() : '';
      csv += [i+1, ts, item.severity.toUpperCase(), item.techId, r.indicator, r.sysmon, r.kibana, r.powershell, r.registry||'', r.tools||'', r.ossdetect||'', r.notes].map(q).join(',') + '\n';
    });
    download(csv, 'hunt_package.csv', 'text/csv');
  } else {
    let out = `Hunt Package\nExported: ${new Date().toLocaleString()}\nIndicators: ${sortedKeys.length}\n${'='.repeat(60)}\n\n`;
    sortedKeys.forEach((rowId, i) => {
      const item = huntItems[rowId];
      const r = getRow(rowId);
      if (!r) return;
      const ts = item.addedAt ? new Date(item.addedAt).toLocaleString() : 'unknown';
      out += `[${i+1}] [${item.severity.toUpperCase()}] ${item.techId} - ${r.indicator}\nAdded: ${ts}\n${'-'.repeat(50)}\nSYSMON:\n${r.sysmon}\n\nKIBANA:\n${r.kibana}\n\nPOWERSHELL:\n${r.powershell}\n\nREGISTRY/ARTIFACTS:\n${r.registry || '(none)'}\n\nTOOLS:\n${r.tools || '(none)'}\n\nOSS DETECTIONS:\n${r.ossdetect || '(none)'}\n\nNOTES:\n${r.notes}\n\n${'='.repeat(60)}\n\n`;
    });
    download(out, 'hunt_package.txt', 'text/plain');
  }
}

function download(content, filename, type) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([content], { type }));
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

// ── SEARCH + FILTER ──
function highlight(text, terms) {
  let result = esc(text);
  terms.forEach(t => {
    if (!t) return;
    const re = new RegExp('(' + t.replace(/[.*+?^${}()|[\]\\]/g,'\\$&') + ')', 'gi');
    result = result.replace(re, '<mark>$1</mark>');
  });
  return result;
}

function applyFilters() {
  const q   = (document.getElementById('search')?.value || '').toLowerCase().trim();
  const aq  = (document.getElementById('apt-search')?.value || '').toLowerCase().trim();
  const terms = q ? q.split(/\s+/).filter(Boolean) : [];
  let visible = 0;

  document.querySelectorAll('.ind-row').forEach(row => {
    const techMatch = activeTech === 'all' || row.dataset.tech === activeTech;
    const aptMatch  = !activeApt  || row.dataset.apt.includes(activeApt);
    const osMatch   = !activeOs   || row.dataset.os === activeOs;
    const textMatch = !terms.length || terms.every(t => row.dataset.text.includes(t));
    const aptTxt    = !aq || row.dataset.text.includes(aq);

    if (techMatch && aptMatch && osMatch && textMatch && aptTxt) {
      row.classList.remove('hidden');
      visible++;
      const nameEl = row.querySelector('.ind-name');
      if (nameEl) {
        const orig = row.querySelector('[data-row-id]')?.dataset.rowId
          ? rowRegistry[row.dataset.rowId]?.row.indicator
          : nameEl.textContent;
        if (orig) nameEl.innerHTML = highlight(orig, [...terms, aq].filter(Boolean));
      }
    } else {
      row.classList.add('hidden');
    }
  });

  document.querySelectorAll('.technique-section').forEach(sec => {
    sec.style.display = sec.querySelectorAll('.ind-row:not(.hidden)').length ? '' : 'none';
    const tocItem = document.querySelector(`.toc-item[data-tech="${sec.dataset.tech}"]`);
    if (tocItem) tocItem.classList.toggle('active', sec.dataset.tech === activeTech);
  });

  document.getElementById('no-results').style.display = visible ? 'none' : 'block';
  updateStats(visible, totalRows);
}

function updateStats(visible, total) {
  const el = document.getElementById('stats');
  if (el) el.textContent = `${visible} / ${total} indicators`;
}

// ── EVENT LISTENERS ──
document.getElementById('search')?.addEventListener('input', applyFilters);
document.getElementById('apt-search')?.addEventListener('input', applyFilters);

document.querySelectorAll('.fbtn[data-tech]').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.fbtn[data-tech]').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    activeTech = btn.dataset.tech;
    applyFilters();
  });
});

document.querySelectorAll('.fbtn[data-apt]').forEach(btn => {
  btn.addEventListener('click', () => {
    const key = btn.dataset.apt;
    if (activeApt === key) {
      activeApt = null;
      btn.className = 'fbtn';
    } else {
      document.querySelectorAll('.fbtn[data-apt]').forEach(b => b.className = 'fbtn');
      activeApt = key;
      btn.classList.add('apt-' + key.toLowerCase());
    }
    applyFilters();
  });
});

document.querySelectorAll('.fbtn[data-os]').forEach(btn => {
  btn.addEventListener('click', () => {
    const key = btn.dataset.os;
    if (activeOs === key) {
      activeOs = null;
      btn.classList.remove('active');
    } else {
      document.querySelectorAll('.fbtn[data-os]').forEach(b => b.classList.remove('active'));
      activeOs = key;
      btn.classList.add('active');
    }
    applyFilters();
  });
});

// CSP-safe wiring for static header / hunt-panel buttons (replaces inline onclick)
document.getElementById('export-selected-btn')?.addEventListener('click', exportSelected);
document.querySelector('.hunt-btn')?.addEventListener('click', toggleHunt);
document.querySelectorAll('.hunt-export-btn').forEach(btn => {
  const act = btn.dataset.act;
  if (act === 'txt' || act === 'csv') {
    btn.addEventListener('click', () => exportHunt(act));
  } else if (act === 'clear') {
    btn.addEventListener('click', clearHunt);
  }
});

// ── INIT ──
loadHunts();
render();
applyFilters();
renderHunt();

// ── SIDEBAR COLLAPSE ──
(function () {
  const sidebar   = document.getElementById('sidebar');
  const toggle    = document.getElementById('sidebar-toggle');
  const container = document.querySelector('.container');
  const backdrop  = document.getElementById('sidebar-backdrop');
  const mobileBtn = document.getElementById('mobile-sidebar-btn');
  if (!sidebar || !toggle) return;

  const MOBILE_BP = 900;
  const isMobile  = () => window.innerWidth <= MOBILE_BP;

  const PREF_KEY = 'sidebar_collapsed';
  let desktopCollapsed = localStorage.getItem(PREF_KEY) === '1';

  function applyDesktop() {
    sidebar.classList.toggle('collapsed', desktopCollapsed);
    if (container) container.classList.toggle('sidebar-collapsed', desktopCollapsed);
    toggle.setAttribute('title', desktopCollapsed ? 'Expand sidebar' : 'Collapse sidebar');
    toggle.innerHTML = desktopCollapsed ? '&#9654;' : '&#9776;';
  }

  function openMobile() {
    sidebar.classList.add('mobile-open');
    sidebar.classList.remove('collapsed');
    if (backdrop) backdrop.classList.add('active');
    if (mobileBtn) mobileBtn.classList.add('hidden');
  }

  function closeMobile() {
    sidebar.classList.remove('mobile-open');
    sidebar.classList.add('collapsed');
    if (backdrop) backdrop.classList.remove('active');
    if (mobileBtn) mobileBtn.classList.remove('hidden');
  }

  function initState() {
    if (isMobile()) {
      sidebar.classList.add('collapsed');
      sidebar.classList.remove('mobile-open');
      if (container) container.classList.remove('sidebar-collapsed');
      if (backdrop) backdrop.classList.remove('active');
      if (mobileBtn) mobileBtn.classList.remove('hidden');
    } else {
      sidebar.classList.remove('mobile-open', 'collapsed');
      if (backdrop) backdrop.classList.remove('active');
      if (mobileBtn) mobileBtn.classList.add('hidden');
      applyDesktop();
    }
  }

  toggle.addEventListener('click', () => {
    if (!isMobile()) {
      desktopCollapsed = !desktopCollapsed;
      localStorage.setItem(PREF_KEY, desktopCollapsed ? '1' : '0');
      applyDesktop();
    }
  });

  if (mobileBtn) mobileBtn.addEventListener('click', openMobile);
  if (backdrop)  backdrop.addEventListener('click', closeMobile);

  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && isMobile() && sidebar.classList.contains('mobile-open')) {
      closeMobile();
    }
  });

  let resizeTimer;
  window.addEventListener('resize', () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(initState, 80);
  });

  initState();
})();
