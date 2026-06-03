// TA0005 - Defense Evasion (Linux-focused tranche 1: Indicator Removal + Impair Defenses)
// 10 indicators across 8 sub-techniques, all Linux.
// T1070 Indicator Removal: .003 Clear Command History (1), .002 Clear System Logs +
//   utmp/wtmp tampering (2), .006 Timestomp (1), .004 File Deletion (1)
// T1562 Impair Defenses: .012 Disable Linux Audit System (1),
//   .001 Disable Tools/agents + SELinux/AppArmor (2), .004 Disable Firewall (1),
//   .006 Indicator Blocking (1)
// Themes: history evasion, log/journal/accounting-DB clearing, timestomp ctime tell,
//   /proc deletion recovery, the auditd-disable keystone, agent/MAC/firewall takedown,
//   and telemetry suppression. Defender leverage centers on off-box forwarding and
//   ingestion/EPS-gap detection.

const DATA = [
  {
    id: "T1070.003",
    name: "Indicator Removal: Clear Command History",
    desc: "Adversaries disable or wipe shell command history (HISTFILE manipulation, history -c, symlink to /dev/null, kill -9 of the shell) to remove the record of their interactive commands. The absence of history on an active session is itself the hunt; auditd execve logging is the authoritative counter-record.",
    rows: [
      {
        sub: "T1070.003 - Clear Command History (HISTFILE manipulation, history -c)",
        os: "linux",
        indicator: "Shell history evasion: HISTFILE unset or redirected to /dev/null, HISTSIZE/HISTFILESIZE set to 0, history -c / history -w to wipe, ~/.bash_history symlinked to /dev/null or truncated, set +o history to disable logging, or the shell killed with kill -9 $$ to skip history flush on exit",
        sysmon: `// Sysmon for Linux EID 1 - history-disabling commands

// History redirected/disabled in the running shell
CommandLine matches:
  *unset HISTFILE*      *HISTFILE=/dev/null*
  *export HISTFILE=*    *HISTSIZE=0*  *HISTFILESIZE=0*
  *set +o history*      *set +H*
  *history -c*          *history -w*   *history -r*

// Symlink/truncate of the history file
Image=*/ln  CommandLine matches: *-sf /dev/null*bash_history*
Image=(*/rm OR */shred OR */truncate) CommandLine matches: *bash_history*
CommandLine matches: *> ~/.bash_history*  OR  *cat /dev/null*bash_history*

// kill -9 of the current shell (skips history write on exit)
Image=*/kill CommandLine matches: *-9 $$*  OR  *-KILL $$*

// Auditd
-a always,exit -F arch=b64 -S execve -k exec
-w /root/.bash_history -p wa -k bash_history
-w /home -p wa -k home_hist  (scope per environment)`,
        kibana: `// History-disabling command lines
process.command_line: (
  "unset HISTFILE" OR *HISTFILE=/dev/null* OR "HISTSIZE=0"
  OR "HISTFILESIZE=0" OR "set +o history" OR "set +H"
  OR "history -c" OR "history -w"
)

// bash_history symlinked to /dev/null or wiped
process.name: ("ln" OR "rm" OR "shred" OR "truncate")
AND process.command_line: *bash_history*

// shell self-kill to skip history flush
process.name: "kill"
AND process.command_line: (*-9 $$* OR *-KILL $$*)

// File event: .bash_history becomes a symlink or is truncated
event.module: "file_integrity"
AND file.path: *bash_history*
AND event.action: ("deleted" OR "symlink" OR "truncated")

// Auditd: write/attr change on history files
event.module: "auditd"
AND tags: ("bash_history" OR "home_hist")
AND NOT process.name: ("bash" OR "zsh")  // normal append excluded by p=wa tuning`,
        powershell: `#!/bin/bash
# T1070.003 - Command history evasion hunt

echo "[*] === History environment in shells (per-user rc review) ==="
for h in /root /home/*; do
  [ -d "$h" ] || continue
  u=$(basename "$h")
  for rc in .bashrc .bash_profile .profile .zshrc; do
    f="$h/$rc"; [ -f "$f" ] || continue
    hits=$(grep -nE "HISTFILE=/dev/null|unset HISTFILE|HISTSIZE=0|HISTFILESIZE=0|set \\+o history|set \\+H" "$f")
    [ -n "$hits" ] && echo "[FLAG] $u:$rc -> $hits"
  done
done

echo ""
echo "[*] === .bash_history files: symlinks, zero-size, perms ==="
for h in /root /home/*; do
  bh="$h/.bash_history"; [ -e "$bh" ] || continue
  if [ -L "$bh" ]; then echo "[FLAG] symlink: $bh -> $(readlink "$bh")"; fi
  sz=$(stat -c '%s' "$bh" 2>/dev/null)
  [ "$sz" = "0" ] && echo "[FLAG] zero-byte history: $bh"
  echo "  $bh | size=$sz | mtime=$(stat -c '%y' "$bh" 2>/dev/null)"
done

echo ""
echo "[*] === Current shells with history disabled (live processes) ==="
for pid in $(ls /proc | grep -E '^[0-9]+$'); do
  comm=$(cat /proc/$pid/comm 2>/dev/null)
  case "$comm" in bash|sh|zsh|dash)
    hf=$(tr '\\0' '\\n' < /proc/$pid/environ 2>/dev/null | grep -E "^HISTFILE=|^HISTSIZE=|^HISTFILESIZE=")
    if echo "$hf" | grep -qE "/dev/null|=0$"; then
      echo "[FLAG] PID $pid ($comm): $hf"
    fi ;;
  esac
done

echo ""
echo "[*] === auditd: history file tampering events ==="
ausearch -k bash_history -i --start today 2>/dev/null | \\
  grep -iE "name=.*history" | grep -ivE "syscall=(read|openat.*O_APPEND)" | tail -20

echo ""
echo "[*] === Cross-check: logged-in users vs history activity ==="
echo "  (a session in 'last' with an empty/short history = suspicious)"
last -n 20 2>/dev/null | head -20`,
        registry: `Command history evasion artifacts:

History files:
  ~/.bash_history          (bash)
  ~/.zsh_history           (zsh)
  ~/.sh_history            (ksh/sh)
  /root/.bash_history      (root's - high value)
  ~/.local/share/fish/fish_history  (fish)
  ~/.python_history , ~/.mysql_history , ~/.psql_history

Disabling / wiping techniques and their traces:
  unset HISTFILE              - no file written this session
  export HISTFILE=/dev/null   - writes discarded
  HISTSIZE=0 / HISTFILESIZE=0 - nothing retained
  set +o history / set +H     - logging off mid-session
  history -c                  - clears in-memory list
  history -w /dev/null        - overwrites file with nothing
  ln -sf /dev/null ~/.bash_history - permanent redirect
  cat /dev/null > ~/.bash_history  - truncate
  shred -u ~/.bash_history    - secure delete
  kill -9 $$                  - shell dies, no flush on exit

Indicators in rc files (persistence of the evasion):
  HISTFILE / HISTSIZE manipulation in .bashrc/.profile
  /etc/profile.d/*.sh setting HISTFILE=/dev/null globally

Signals:
  .bash_history that is a SYMLINK (especially to /dev/null)
  zero-byte history file on an account with login activity
  history file mtime far older than last login (last/lastlog)
  HISTFILE=/dev/null in a live process environment
  account in 'last' output but empty history

Forensic recovery:
  Even after wipe, history fragments may persist in:
    shell process memory (/proc/<pid>/ if still running)
    swap, unallocated disk, terminal scrollback
    auditd execve logs (the authoritative shadow record)

Key principle:
  auditd execve logging is the COUNTER to history evasion -
  it records commands regardless of shell history settings.`,
        tools: `Command history evasion:

The most common, lowest-effort anti-forensics step on Linux.
Nearly every interactive intrusion includes some form of it,
because shell history is the first place a responder looks.

Typical attacker sequence (often the very first commands):
  unset HISTFILE ; export HISTFILE=/dev/null
  set +o history
  ... then operate ...
  history -c ; rm ~/.bash_history   (on the way out)

Why it matters for hunting:
  An empty or disabled history is itself an indicator. A real
  user's account almost always accumulates history. A login
  session (visible in last/wtmp) with no corresponding history
  is a strong tell that someone cleaned up.

The defender's leverage:
  Shell history was never designed as a security log. The
  authoritative record is auditd execve logging, which the
  attacker usually cannot retroactively edit without also
  tripping T1562/T1070.002 (disabling/clearing auditd itself).
  So history evasion + intact auditd = you still have the commands.
  History evasion + auditd tampering = escalate, that is a
  deliberate, knowledgeable adversary.

Hardening:
  readonly HISTFILE ; readonly HISTSIZE   (in /etc/profile)
  export PROMPT_COMMAND='history -a'      (flush each command)
  Ship history + auditd to a remote/immutable log store
  auditd is the real control; treat history as a bonus signal.

Threat actor use:
  TeamTNT, Rocke, and most cryptomining crews clear history
  as routine hygiene. Hands-on-keyboard intruders disable it
  at session start. It is near-universal, so its ABSENCE of
  evidence (empty history + active session) is the hunt.`,
        ossdetect: `Sigma rules:
- lnx_shell_clear_cmd_history.yml
- proc_creation_lnx_history_mod_disable.yml
- proc_creation_lnx_bash_history_symlink_devnull.yml

Elastic detection rules:
- Tampering of Bash Command-Line History
- Disabling of Shell History via HISTFILE/HISTSIZE

Auditd (the authoritative counter-record):
  -a always,exit -F arch=b64 -S execve -k exec
  -w /root/.bash_history -p wa -k bash_history
  Capture EVERY command via execve regardless of shell history.
  This is the primary control - history settings cannot evade it.

Falco:
  rule: Delete or rename shell history
  rule: Disable Shell History (set +o history / HISTFILE)

auditbeat / Elastic shell logging:
  Enable system module process dataset for command capture
  independent of shell history.

osquery:
  SELECT * FROM shell_history;   (reads history files)
  Snapshot regularly; compare for unexpected truncation
  SELECT * FROM file WHERE path LIKE '/home/%/.bash_history'
    AND type='symlink';   (flag symlinked history)

PROMPT_COMMAND enforcement + remote shipping:
  Force per-command flush and forward to a log store the
  attacker cannot reach. Defeats local wiping.

Atomic Red Team:
  T1070.003 - clear command history tests`,
        notes: "Clearing command history is the most common and lowest-effort anti-forensic action on Linux, and it appears in nearly every interactive intrusion because shell history is the first artifact a responder examines. The techniques range from session-level disabling (unset HISTFILE, export HISTFILE=/dev/null, set +o history, HISTSIZE=0) to file wiping (history -c, truncation, shred, symlinking ~/.bash_history to /dev/null) to the subtle kill -9 $$ that terminates the shell before it flushes history on exit. The key insight for hunters is that the absence of history is itself the signal: a login session visible in wtmp/last with no corresponding shell history strongly implies cleanup, so the hunt is a cross-reference between authenticated sessions and history activity rather than a search for the wiping command alone. The decisive defensive principle is that shell history was never a security log, and auditd execve logging is the authoritative shadow record that captures every command regardless of shell history settings. This creates a useful escalation ladder: history evasion with intact auditd means you still have the commands; history evasion combined with auditd tampering (T1562.012 / T1070.002) signals a deliberate, knowledgeable adversary and should raise the severity of the entire investigation. Hardening centers on forcing per-command flush via PROMPT_COMMAND and shipping both history and auditd to a remote or immutable store, but auditd is the real control and history is best treated as a bonus signal.",
        apt: [
          { cls: "apt-mul", name: "TeamTNT", note: "Clears bash history and disables logging as routine hygiene in cloud cryptojacking operations." },
          { cls: "apt-mul", name: "Rocke", note: "History clearing combined with cloud agent uninstallation as part of standard anti-forensic cleanup." },
          { cls: "apt-mul", name: "Hands-on intruders", note: "Disabling history at session start (unset HISTFILE / set +o history) is near-universal in interactive Linux intrusions." }
        ],
        cite: "MITRE ATT&CK T1070.003"
      }
    ]
  },
  {
    id: "T1070.002",
    name: "Indicator Removal: Clear Linux System Logs",
    desc: "Destruction, truncation, or selective excision of system logs under /var/log (auth/secure/syslog/messages, the systemd journal) and tampering with the binary login-accounting databases (utmp/wtmp/btmp/lastlog). Remote forwarding is the control: once events ship off-box, local clearing is moot and selective edits become detectable by diffing against the forwarded copy.",
    rows: [
      {
        sub: "T1070.002 - Clear Linux System Logs (/var/log, journald vacuum, truncate)",
        os: "linux",
        indicator: "Destruction or truncation of system logs: rm/shred of files under /var/log, truncation via : > file or cat /dev/null >, journalctl --vacuum-time/--vacuum-size or deletion of /var/log/journal, rsyslog/syslog-ng output files emptied, or selective line removal with sed/grep to excise specific events",
        sysmon: `// Sysmon for Linux EID 1 - log destruction commands

// Bulk removal / shred under /var/log
Image=(*/rm OR */shred OR */unlink) CommandLine matches:
  */var/log/*  (especially auth.log, secure, syslog, messages,
                wtmp, btmp, audit/audit.log)

// Truncation (the stealthier wipe - file stays, contents gone)
CommandLine matches:
  *: > /var/log/*      *> /var/log/*
  *cat /dev/null >*/var/log/*    *truncate -s0*/var/log/*
  *echo -n >*/var/log/*

// systemd journal vacuuming / deletion
Image=*/journalctl CommandLine matches:
  *--vacuum-time*  *--vacuum-size*  *--vacuum-files*  *--rotate*
Image=(*/rm OR */shred) CommandLine matches: */var/log/journal/*

// Selective excision (remove specific lines = targeted cover-up)
Image=(*/sed OR */grep) CommandLine matches:
  *-i*/var/log/*   *-v*>/var/log/*   (rewriting a log minus events)

// Auditd
-w /var/log -p wa -k var_log_tamper
-w /var/log/audit -p wa -k auditlog_tamper
-a always,exit -F arch=b64 -S unlink,unlinkat,truncate,ftruncate -F dir=/var/log -k log_destroy`,
        kibana: `// Removal / shred of log files
process.name: ("rm" OR "shred" OR "unlink")
AND process.command_line: */var/log/*

// Truncation of logs (file persists, emptied)
process.command_line: (
  *": > /var/log/"* OR *"> /var/log/"* OR *"cat /dev/null"*
  OR *"truncate -s0 /var/log"* OR *"truncate -s 0 /var/log"*
)

// journald vacuum / rotate
process.name: "journalctl"
AND process.command_line: (*vacuum* OR *--rotate*)

// journal directory deletion
process.name: ("rm" OR "shred")
AND process.command_line: */var/log/journal*

// Selective line excision (targeted log editing)
process.name: ("sed" OR "grep")
AND process.command_line: (*-i* AND */var/log/*)

// Auditd: unlink/truncate within /var/log
event.module: "auditd"
AND tags: ("var_log_tamper" OR "auditlog_tamper" OR "log_destroy")
AND NOT process.name: ("logrotate" OR "rsyslogd" OR "systemd-journald")

// Gap detection: sudden silence from a normally-chatty log source
// (alert when expected periodic log volume drops to zero)`,
        powershell: `#!/bin/bash
# T1070.002 - System log clearing hunt

echo "[*] === /var/log inventory: sizes, mtimes, zero-byte flags ==="
for f in /var/log/auth.log /var/log/secure /var/log/syslog \\
         /var/log/messages /var/log/audit/audit.log /var/log/cron \\
         /var/log/maillog /var/log/kern.log; do
  [ -e "$f" ] || continue
  sz=$(stat -c '%s' "$f" 2>/dev/null)
  mt=$(stat -c '%y' "$f" 2>/dev/null)
  flag=""; [ "$sz" = "0" ] && flag="  <-- ZERO BYTES"
  echo "  $f | size=$sz | mtime=$mt$flag"
done

echo ""
echo "[*] === journald: integrity + recent vacuum ==="
journalctl --disk-usage 2>/dev/null
journalctl --verify 2>/dev/null | tail -5
echo "  journal files:"; ls -la /var/log/journal/*/ 2>/dev/null | head -10

echo ""
echo "[*] === Log time-continuity gaps (missing periods) ==="
# auth.log should have steady entries; a gap = possible excision
if [ -f /var/log/auth.log ]; then
  echo "  auth.log first/last timestamps:"
  head -1 /var/log/auth.log 2>/dev/null | cut -c1-20
  tail -1 /var/log/auth.log 2>/dev/null | cut -c1-20
fi

echo ""
echo "[*] === logrotate state vs actual (unexpected rotation) ==="
cat /var/lib/logrotate/status 2>/dev/null | tail -15
cat /var/lib/logrotate.status 2>/dev/null | tail -15

echo ""
echo "[*] === auditd: log destruction events ==="
ausearch -k var_log_tamper -i --start today 2>/dev/null | \\
  grep -ivE "comm=.(logrotate|rsyslogd|systemd-journal)" | tail -25
ausearch -k auditlog_tamper -i --start today 2>/dev/null | tail -15

echo ""
echo "[*] === Deleted-but-open log handles (truncated while held open) ==="
ls -l /proc/*/fd/ 2>/dev/null | grep -E "/var/log.*deleted" | head -10

echo ""
echo "[*] === Remote log shipping configured? (resilience check) ==="
grep -rE "^\\*\\.\\*|@@?[0-9]|action.*omfwd|Target=" \\
  /etc/rsyslog.conf /etc/rsyslog.d/ /etc/syslog-ng/ 2>/dev/null | head -10
echo "  (if logs ship off-box, local clearing is recoverable)"
`,
        registry: `Linux system log clearing artifacts:

Primary log targets:
  /var/log/auth.log        (Debian/Ubuntu auth - high value)
  /var/log/secure          (RHEL auth - high value)
  /var/log/syslog          (Debian general)
  /var/log/messages        (RHEL general)
  /var/log/audit/audit.log (auditd - highest value)
  /var/log/cron , /var/log/maillog , /var/log/kern.log
  /var/log/wtmp /btmp /lastlog  (login records - see next row)
  /var/log/journal/        (systemd binary journal)

Clearing techniques and their forensic signatures:
  rm /var/log/X            - file gone; recreated by daemon later
  shred -u /var/log/X      - secure delete, harder recovery
  : > /var/log/X           - truncate; file persists, size 0,
                             inode unchanged, mtime updated
  cat /dev/null > X        - same as truncate
  truncate -s0 X           - explicit truncate
  sed -i '/pattern/d' X    - SELECTIVE excision (stealthiest -
                             removes only incriminating lines,
                             log looks normal otherwise)
  journalctl --vacuum-time=1s  - purge journal by age
  journalctl --rotate          - force rotation (then vacuum)

High-signal indicators:
  zero-byte auth.log / secure / audit.log on a live system
  log mtime newer than its newest internal entry (truncated)
  time-continuity GAP (e.g. auth.log jumps over an hour)
  journalctl --verify reports corruption / FAIL
  logrotate status file inconsistent with actual rotation
  a log file is a deleted-but-open fd in /proc/*/fd

Selective-edit detection (hardest):
  Cross-correlate with remote/forwarded copies. If the local
  log is missing lines the remote collector received, the
  local copy was edited. This is why remote shipping matters.

Recovery sources:
  remote syslog / SIEM (the authoritative copy)
  journald on other nodes, deleted-inode carving, the audit
  log if it was not also cleared`,
        tools: `Clearing Linux system logs:

After history (T1070.003), wiping /var/log is the next anti-
forensic step for a careful intruder. The targets are the
authentication and audit logs that would reveal the access.

Spectrum of sophistication:
  Crude:   rm -rf /var/log/*   (very noisy - breaks logging,
           daemons complain, obvious in any review)
  Better:  truncate individual auth/audit logs (less obvious)
  Skilled: sed -i to remove ONLY the attacker's own lines,
           leaving a plausible-looking log. Hardest to detect
           locally; only a remote copy reveals the deletion.
  journald: --vacuum / --rotate to purge the binary journal.

Why hunters win here:
  1. Daemons recreate deleted logs and may log the gap itself.
  2. journalctl --verify cryptographically checks journal
     integrity (with FSS / Forward Secure Sealing enabled).
  3. Remote log forwarding makes local clearing pointless -
     the SIEM already has the events. This is THE control.
  4. Truncation leaves the inode + a fresh mtime that is newer
     than the newest surviving entry - a detectable mismatch.

The escalation signal:
  Log clearing rarely happens alone. It pairs with history
  evasion (T1070.003), audit tampering (T1562.012), and
  timestomping (T1070.006). Seeing the cluster = deliberate
  anti-forensics, not a misconfiguration.

Threat actor use:
  Sandworm and other state actors have wiped logs to slow
  attribution. Ransomware crews clear logs pre-encryption.
  Cryptomining crews (TeamTNT, Rocke) clear logs as hygiene.
  Log clearing on Linux servers is documented across the
  full spectrum from commodity to APT.`,
        ossdetect: `Sigma rules:
- lnx_shell_clear_logs.yml
- proc_creation_lnx_logfile_deletion_via_rm.yml
- proc_creation_lnx_journald_vacuum.yml
- proc_creation_lnx_truncate_var_log.yml

Elastic detection rules:
- System Log File Deletion
- Tampering of System Log Files (truncate / shred)
- systemd journald Vacuum or Rotate

Auditd:
  -w /var/log -p wa -k var_log_tamper
  -w /var/log/audit -p wa -k auditlog_tamper
  -a always,exit -F arch=b64 -S unlink,unlinkat,truncate,ftruncate \\
    -F dir=/var/log -k log_destroy
  ausearch -k var_log_tamper | grep -v logrotate

Falco:
  rule: Clear Log Activities
  rule: Remove Bulk Data from Disk
  rule: journald Vacuum (custom)

REMOTE LOG FORWARDING (the primary control):
  rsyslog:  *.* @@central-collector:6514  (TCP/TLS)
  syslog-ng equivalent destination
  systemd-journal-remote / journal-upload
  Once events are off-box, local clearing is moot.

journald Forward Secure Sealing (tamper-evidence):
  journalctl --setup-keys ; Seal=yes in journald.conf
  journalctl --verify detects post-hoc edits.

osquery:
  schedule file table on /var/log for size/mtime deltas
  alert when a monitored log shrinks unexpectedly

Atomic Red Team:
  T1070.002 - clear Linux/Mac system logs tests`,
        notes: "Clearing system logs is the second anti-forensic step after history evasion, targeting the authentication and audit logs under /var/log that would otherwise reveal the intrusion. The techniques span a sophistication spectrum: crude bulk deletion (rm -rf /var/log/*, which is noisy and breaks logging), truncation of individual files (: > file, which leaves the inode intact but with a telltale mtime newer than the newest surviving entry), and the stealthiest approach, selective line excision via sed -i that removes only the attacker's own entries and leaves a plausible-looking log. systemd's binary journal is purged with journalctl --vacuum or --rotate. The decisive control is remote log forwarding: once events are shipped off-box to a SIEM or central collector, local clearing is pointless because the authoritative copy already exists elsewhere, and selective edits become detectable by diffing the local log against the forwarded copy. journald Forward Secure Sealing adds cryptographic tamper-evidence that journalctl --verify can check. For hunting, the high-signal indicators are zero-byte auth/audit logs on a live system, time-continuity gaps where a log jumps over a period, and a log mtime newer than its newest internal timestamp. Log clearing rarely occurs in isolation; it clusters with history evasion, audit tampering, and timestomping, and seeing that cluster together is a reliable marker of deliberate anti-forensics rather than misconfiguration.",
        apt: [
          { cls: "apt-ru", name: "Sandworm", note: "Log wiping used to slow incident response and attribution in destructive operations against Linux infrastructure." },
          { cls: "apt-mul", name: "Ransomware crews", note: "System log clearing performed pre-encryption to impede response and recovery timeline reconstruction." },
          { cls: "apt-mul", name: "TeamTNT / Rocke", note: "Routine /var/log clearing as part of cloud intrusion cleanup alongside cloud agent removal." }
        ],
        cite: "MITRE ATT&CK T1070.002"
      },
      {
        sub: "T1070.002 - Login Record Tampering (utmp / wtmp / btmp / lastlog)",
        os: "linux",
        indicator: "Manipulation of binary login-accounting databases to hide sessions: editing /var/run/utmp, /var/log/wtmp, /var/log/btmp, /var/log/lastlog with utmpdump round-trips, dedicated tools (logtamper, wipe, 0linux), or truncation, so that who/last/lastlog no longer show the attacker's logins",
        sysmon: `// Sysmon for Linux EID 1 - login-record tampering

// Direct writes / truncation of accounting DBs
Image=(*/rm OR */shred OR */truncate) CommandLine matches:
  */var/log/wtmp*  */var/log/btmp*  */var/log/lastlog*
  */var/run/utmp*  */run/utmp*
CommandLine matches: *: > /var/log/wtmp*  *> /var/run/utmp*

// utmpdump round-trip (dump -> edit -> reload = surgical removal)
Image=*/utmpdump CommandLine matches: *wtmp*  *utmp*
// followed by a reverse utmpdump write-back

// Known log-cleaning tools / compiled wipers
Image matches: */wipe  */logtamper  */0.0.0  */mig-logcleaner
CommandLine matches: *wtmp* *utmp* *lastlog*

// gcc compiling a wiper in-session (source then binary then run)
Image=*/gcc CommandLine matches: *utmp* OR *wtmp* OR *lastlog*

// Auditd
-w /var/log/wtmp -p wa -k wtmp_tamper
-w /var/log/btmp -p wa -k btmp_tamper
-w /var/run/utmp -p wa -k utmp_tamper
-w /var/log/lastlog -p wa -k lastlog_tamper`,
        kibana: `// Truncation / removal of accounting DBs
process.name: ("rm" OR "shred" OR "truncate")
AND process.command_line: (*wtmp* OR *btmp* OR *utmp* OR *lastlog*)

// utmpdump used against the accounting files (edit round-trip)
process.name: "utmpdump"

// gcc compiling something referencing utmp/wtmp (custom wiper)
process.name: ("gcc" OR "cc" OR "clang")
AND process.command_line: (*utmp* OR *wtmp* OR *lastlog*)

// Auditd write/attr on accounting DBs by non-login processes
event.module: "auditd"
AND tags: ("wtmp_tamper" OR "btmp_tamper" OR "utmp_tamper" OR "lastlog_tamper")
AND NOT process.name: ("sshd" OR "login" OR "systemd-logind" OR "init" OR "gdm" OR "lightdm")

// Discrepancy hunt: 'last' shows fewer sessions than auth.log logins
// (correlate auth.log Accepted entries vs wtmp session count)

// who/last output empty but active network sessions exist
// (enrich: ss -tnp ESTABLISHED :22 vs who output)`,
        powershell: `#!/bin/bash
# T1070.002 - Login record (utmp/wtmp/btmp) tampering hunt

echo "[*] === Accounting DB state ==="
for f in /var/run/utmp /run/utmp /var/log/wtmp /var/log/btmp /var/log/lastlog; do
  [ -e "$f" ] || continue
  sz=$(stat -c '%s' "$f" 2>/dev/null)
  flag=""; [ "$sz" = "0" ] && flag="  <-- ZERO BYTES (wiped)"
  echo "  $f | size=$sz | mtime=$(stat -c '%y' "$f" 2>/dev/null)$flag"
done

echo ""
echo "[*] === Cross-check: auth.log logins vs wtmp (last) sessions ==="
echo "  Accepted SSH logins in auth.log/secure:"
auth_count=$(grep -hcE "Accepted (password|publickey)" /var/log/auth.log /var/log/secure 2>/dev/null | paste -sd+ | bc 2>/dev/null)
echo "    auth.log Accepted count: \${auth_count:-0}"
echo "  Sessions recorded in wtmp (last):"
last_count=$(last -F 2>/dev/null | grep -vE "^$|wtmp begins|reboot" | wc -l)
echo "    last/wtmp session count: $last_count"
echo "  (a large auth.log count with near-empty 'last' = wtmp tampering)"

echo ""
echo "[*] === last / lastb / who consistency ==="
echo "  --- last (good logins, from wtmp) ---"; last -F -n 10 2>/dev/null
echo "  --- lastb (failed logins, from btmp) ---"; lastb -n 5 2>/dev/null | head -6
echo "  --- who (current, from utmp) ---"; who 2>/dev/null
echo "  --- active sshd sessions (ground truth) ---"
ss -tnp 2>/dev/null | grep -E ":22 .*ESTAB" | head

echo ""
echo "[*] === utmpdump integrity view (look for gaps in line/PID seq) ==="
utmpdump /var/log/wtmp 2>/dev/null | tail -20

echo ""
echo "[*] === Compiled log-cleaner artifacts in writable paths ==="
find /tmp /dev/shm /var/tmp -type f \\( -name "*.c" -o -perm -111 \\) 2>/dev/null | \\
  while read f; do
    strings "$f" 2>/dev/null | grep -qiE "wtmp|utmp|lastlog" && echo "[FLAG] $f references accounting DBs"
  done | head

echo ""
echo "[*] === auditd: accounting DB tamper events ==="
for k in wtmp_tamper btmp_tamper utmp_tamper lastlog_tamper; do
  ausearch -k $k -i --start today 2>/dev/null | \\
    grep -ivE "comm=.(sshd|login|systemd-logind|init)" | tail -8
done`,
        registry: `Login-record (accounting) tampering artifacts:

The binary accounting databases:
  /var/run/utmp (or /run/utmp)  - CURRENTLY logged-in users
                                  (read by: who, w, users)
  /var/log/wtmp                 - login/logout HISTORY
                                  (read by: last)
  /var/log/btmp                 - FAILED login attempts
                                  (read by: lastb)
  /var/log/lastlog              - each user's LAST login
                                  (read by: lastlog)

These are binary (utmp struct records), not text - so they
are edited with utmpdump (dump to text, edit, reload) or with
purpose-built tools, not with sed/vi directly.

Tampering techniques:
  : > /var/log/wtmp           - wipe all login history
  utmpdump wtmp > t; (edit t); utmpdump -r t > wtmp
                              - surgical removal of specific
                                sessions (stealthiest)
  dedicated wipers: wipe, logtamper, mig-logcleaner, 0.0.0,
                    cleaner.c variants (zero out matching records)

High-signal indicators:
  zero-byte wtmp/utmp on a system with login activity
  'last' shows far fewer sessions than auth.log Accepted lines
  'who' empty while ESTABLISHED sshd sessions exist in ss
  gaps in the utmpdump record sequence (missing PIDs/lines)
  wtmp mtime inconsistent with the newest session it contains
  a compiled binary in /tmp that strings-references utmp/wtmp

The cross-correlation hunt (most reliable):
  auth.log / secure records "Accepted password/publickey" for
  each SSH login as TEXT. wtmp records the same as BINARY.
  An attacker who wipes wtmp but not auth.log (common, since
  they are different formats and locations) leaves a count
  mismatch: many auth.log logins, few/no 'last' sessions.

Recovery / ground truth:
  auth.log/secure (text auth record, often not wiped together)
  remote syslog, systemd-logind journal entries, ss/netstat
  for live sessions, process tree of sshd children`,
        tools: `Login record tampering:

A more deliberate anti-forensic step than clearing text logs,
because the accounting databases are binary and require either
utmpdump or a compiled tool to edit cleanly. Seeing this is a
strong indicator of a knowledgeable adversary.

The classic tool lineage:
  utmpdump (part of util-linux) - legitimate tool that dumps
    wtmp/utmp to editable text and reloads it. The intended
    use is forensics, but it is equally an editing primitive.
  Historic wipers: zap, zap2, wipe, cloak, logwedge, and many
    cleaner.c variants - all zero out records matching a
    username/TTY/host so that login history omits the attacker.
  Modern: mig-logcleaner, 0.0.0, and bespoke compiled tools.

Why this is high-value to detect:
  Text log clearing can be a sloppy rm. Editing binary
  accounting DBs to remove SPECIFIC sessions is surgical and
  intentional - it signals an operator who understands Linux
  forensics and is actively hiding presence.

The defender's leverage (the count mismatch):
  Attackers frequently wipe wtmp but forget that the SAME
  login also produced a TEXT line in auth.log/secure ("Accepted
  publickey for ..."). The two live in different formats and
  files, so they are rarely cleaned in perfect sync. Counting
  auth.log Accepted lines against 'last' sessions exposes the
  gap. Live ESTABLISHED :22 sockets in ss with an empty 'who'
  is the same tell in real time.

Threat actor use:
  utmp/wtmp manipulation is a long-standing Unix intrusion
  craft, documented from historic rootkits through modern
  targeted Linux compromises. It is less common in commodity
  cryptomining (which is noisier) and more associated with
  hands-on, stealth-focused operators.`,
        ossdetect: `Sigma rules:
- proc_creation_lnx_wtmp_utmp_tampering.yml
- proc_creation_lnx_utmpdump_suspicious_use.yml
- file_event_lnx_login_accounting_truncate.yml

Elastic detection rules:
- Login Accounting File Tampering (wtmp/utmp/btmp)
- Suspicious utmpdump Execution

Auditd (watch all four DBs):
  -w /var/log/wtmp -p wa -k wtmp_tamper
  -w /var/log/btmp -p wa -k btmp_tamper
  -w /var/run/utmp -p wa -k utmp_tamper
  -w /var/log/lastlog -p wa -k lastlog_tamper
  Exclude legitimate writers (sshd, login, systemd-logind, init)
  ausearch -k wtmp_tamper | grep -vE "comm=.(sshd|login|logind)"

Falco:
  rule: Modify accounting / login records (custom)
  rule: Write below /var/log (covers wtmp/btmp)

Correlation rule (the key detection):
  count(auth.log "Accepted") over window
    vs count(wtmp sessions via last)
  alert if delta exceeds threshold -> wtmp tampering likely

osquery:
  SELECT * FROM last;          (parses wtmp)
  SELECT * FROM logged_in_users;  (parses utmp)
  Compare against auth event counts from the system log table

Remote forwarding + immutable accounting:
  Forward auth events to SIEM; the text auth trail survives
  binary-DB tampering and provides the count to compare.

Atomic Red Team:
  T1070.002 - includes utmp/wtmp manipulation coverage`,
        notes: "Login-record tampering targets the four binary accounting databases that drive who, w, last, lastb, and lastlog: utmp (current sessions), wtmp (login history), btmp (failed logins), and lastlog (last login per user). Because these are binary utmp-struct files rather than text, editing them cleanly requires utmpdump (dump to text, edit, reload) or a purpose-built wiper, which makes surgical removal of specific sessions a strong indicator of a knowledgeable, stealth-focused adversary rather than a sloppy smash-and-grab. The most reliable detection is a cross-correlation hunt that exploits a consistent attacker mistake: the same SSH login that writes a binary wtmp record also writes a text line to auth.log or secure ('Accepted publickey for ...'), and because those live in different formats and locations they are rarely cleaned in perfect sync. Counting auth.log Accepted lines against the session count from last exposes the gap, and in real time an empty who output alongside live ESTABLISHED port-22 sockets in ss is the same tell. The defensive posture is to audit all four databases with auditd (excluding the legitimate writers sshd, login, and systemd-logind), forward the text auth trail to a remote store so it survives binary-DB tampering, and treat any utmpdump round-trip or compiled binary in a writable path that strings-references utmp/wtmp as high-severity. This technique is long-standing Unix intrusion craft, more associated with hands-on operators than noisy commodity cryptomining.",
        apt: [
          { cls: "apt-mul", name: "Stealth-focused operators", note: "Surgical utmp/wtmp editing to remove specific sessions is long-standing Unix intrusion tradecraft signaling a forensics-aware adversary." },
          { cls: "apt-cn", name: "Winnti / APT41", note: "Linux intrusion toolsets include login-record and log manipulation to conceal interactive access to compromised servers." },
          { cls: "apt-mul", name: "Rootkit operators", note: "Historic and modern Linux rootkits bundle wtmp/utmp cleaners (zap/wipe lineage) to hide login accounting." }
        ],
        cite: "MITRE ATT&CK T1070.002"
      }
    ]
  },
  {
    id: "T1070.006",
    name: "Indicator Removal: Timestomp",
    desc: "Falsification of file mtime/atime via touch -r / -t / -d or the utimensat syscall to blend malicious files into the filesystem. The structural tell is ctime (inode change time), which the kernel updates on the stomp and userspace cannot trivially set: ctime newer than mtime exposes backdating.",
    rows: [
      {
        sub: "T1070.006 - Timestomping (touch -r / -t backdating, mtime/atime forgery)",
        os: "linux",
        indicator: "Falsification of file timestamps to blend malicious files into the filesystem: touch -r to clone a neighbor file's times, touch -t / -d to set arbitrary mtime/atime, or syscall-level (utimensat) forgery, frequently revealed by an mtime/atime that disagrees with the inode change time (ctime), which touch cannot trivially set",
        sysmon: `// Sysmon for Linux EID 1 - timestamp forgery

// touch used to copy or set timestamps on payload-like files
Image=*/touch CommandLine matches:
  *-r *           (reference: clone another file's times)
  *-t *           (explicit [[CC]YY]MMDDhhmm[.ss])
  *-d *  *--date* (date string)
  *-a*  *-m*      (atime/mtime specific)
AND target path in /tmp /dev/shm /var/www /usr/bin /etc or a
    recently-created file

// Reference cloning from a system binary (blend with /bin)
CommandLine matches: *touch -r /bin/*  *touch -r /usr/bin/*  *touch -r /etc/*

// Auditd - capture the timestamp syscalls directly
-a always,exit -F arch=b64 -S utimensat,utime,utimes,futimesat -k timestomp
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/touch -k touch_exec

// NOTE: ctime (inode change time) updates on ANY metadata change
// and is NOT settable via touch/utimensat from userspace without
// clock manipulation - so ctime > mtime is the core tell.`,
        kibana: `// touch with reference/explicit-time flags on suspicious paths
process.name: "touch"
AND process.command_line: (*"-r "* OR *"-t "* OR *"-d "* OR *--date*)
AND process.command_line: (*/tmp/* OR */dev/shm/* OR */var/www/* OR */usr/bin/* OR */etc/*)

// Reference-cloning timestamps from core system binaries
process.command_line: (*"touch -r /bin/"* OR *"touch -r /usr/bin/"* OR *"touch -r /etc/"*)

// Auditd: direct timestamp syscalls
event.module: "auditd"
AND tags: ("timestomp" OR "touch_exec")
AND NOT process.name: ("tar" OR "rsync" OR "cp" OR "unzip" OR "dpkg" OR "rpm")

// The structural tell (requires FIM that records all 3 times):
// ctime newer than mtime  ->  metadata changed after the
// claimed modification = timestamp was set backward
event.module: "file_integrity"
AND file.ctime > file.mtime
AND file.path: (*/tmp/* OR */usr/* OR */etc/* OR */var/www/*)

// mtime far in the past on a file whose inode number is high
// (recently allocated inode + old mtime = backdated)`,
        powershell: `#!/bin/bash
# T1070.006 - Timestomping hunt
# Core principle: compare mtime/atime vs ctime. touch sets
# mtime/atime; ctime updates on metadata change and resists
# userspace forgery. ctime > mtime = backdated file.

echo "[*] === ctime-vs-mtime anomalies in sensitive dirs ==="
for dir in /tmp /dev/shm /var/www /usr/bin /usr/local/bin /etc /home; do
  [ -d "$dir" ] || continue
  find "$dir" -type f 2>/dev/null | head -500 | while read f; do
    mt=$(stat -c '%Y' "$f" 2>/dev/null)   # mtime epoch
    ct=$(stat -c '%Z' "$f" 2>/dev/null)   # ctime epoch
    [ -z "$mt" ] || [ -z "$ct" ] && continue
    # ctime significantly newer than mtime (>1 day) = suspicious
    if [ "$ct" -gt "$((mt + 86400))" ]; then
      echo "[FLAG] $f"
      echo "    mtime=$(stat -c '%y' "$f") ctime=$(stat -c '%z' "$f")"
    fi
  done
done

echo ""
echo "[*] === Files with old mtime but high (recent) inode number ==="
echo "  (recently allocated inode + backdated mtime = timestomp)"
for dir in /usr/bin /usr/local/bin /tmp; do
  [ -d "$dir" ] || continue
  ls -i "$dir" 2>/dev/null | sort -n | tail -10 | while read ino name; do
    f="$dir/$name"; [ -f "$f" ] || continue
    yr=$(stat -c '%y' "$f" 2>/dev/null | cut -c1-4)
    [ -n "$yr" ] && [ "$yr" -lt 2020 ] 2>/dev/null && \\
      echo "[FLAG] high inode $ino but mtime year $yr: $f"
  done
done

echo ""
echo "[*] === SUID/recently-written binaries with suspicious times ==="
find /usr/bin /usr/local/bin /tmp /dev/shm -type f -perm -4000 2>/dev/null | while read f; do
  echo "  $f"
  echo "    mtime=$(stat -c '%y' "$f") ctime=$(stat -c '%z' "$f")"
done

echo ""
echo "[*] === Package-verify mtime mismatch (RHEL/Deb) ==="
rpm -Va 2>/dev/null | grep -E "^..\\.\\.\\.\\.\\.T|^.{8}T" | head -15
echo "  (T flag = mtime differs from package manifest)"

echo ""
echo "[*] === auditd: timestamp syscalls + touch usage ==="
ausearch -k timestomp -i --start today 2>/dev/null | \\
  grep -ivE "comm=.(tar|rsync|cp|dpkg|rpm)" | tail -20
ausearch -k touch_exec -i --start today 2>/dev/null | grep -E "\\-r|\\-t|\\-d" | tail -10`,
        registry: `Timestomping artifacts and the ctime principle:

The four inode timestamps (ext4/xfs):
  atime - last access (read)
  mtime - last content modification   <- touch sets this
  ctime - last INODE (metadata) change <- the tell
  crtime/btime - creation/birth (ext4, via statx/debugfs)

Why ctime is the key:
  touch -r / -t / -d sets atime and mtime to arbitrary values.
  But ctime updates whenever inode metadata changes - including
  when touch itself runs. ctime is NOT settable from userspace
  without changing the system clock. So after timestomping:
    mtime = backdated (attacker's chosen old time)
    ctime = NOW (when touch ran)
  => ctime > mtime is the structural signature of backdating.
  (Clock rollback to defeat this is itself highly detectable.)

Timestomping techniques:
  touch -r /bin/ls evil       - clone ls's timestamps onto evil
  touch -t 202001010000 evil  - set explicit old mtime/atime
  touch -d "2020-01-01" evil  - date-string form
  utimensat() syscall direct  - programmatic (malware/rootkits)
  debugfs -w (set crtime)     - advanced: forge birth time too

High-signal indicators:
  ctime newer than mtime (the primary tell)
  mtime predating the file's inode allocation (high inode #, old date)
  a file in /usr/bin whose mtime differs from the package manifest
    (rpm -Va shows 'T'; dpkg has no native mtime check)
  cluster of files sharing an identical odd timestamp (batch stomp)
  payload mtime exactly matching a neighbor system binary (touch -r)

Birth-time cross-check (ext4):
  stat shows Birth; if blank, use:
    debugfs -R 'stat <inode>' /dev/sdaN   (crtime)
  A crtime NEWER than mtime is as damning as ctime > mtime.

Limits:
  ctime forgery requires changing the system clock (loud) or
  raw filesystem edits (debugfs) - both leave their own traces.
  Forwarding file-create events to a SIEM in real time records
  the TRUE creation moment regardless of later stomping.`,
        tools: `Timestomping on Linux:

The goal is to make a malicious file's timestamps blend with
legitimate neighbors so timeline analysis skips over it. The
classic move is touch -r /bin/ls /tmp/backdoor, cloning a
trusted binary's times onto the payload.

Why it is weaker on Linux than attackers hope:
  Unlike NTFS (where all four MACB times are forgeable with the
  right tooling), standard Linux timestomping with touch or
  utimensat only moves atime and mtime. ctime - the inode change
  time - is updated by the kernel on the stomp itself and cannot
  be set from userspace without rolling the system clock. This
  leaves the ctime > mtime mismatch as a near-universal tell.

Tooling:
  touch (coreutils)    - the everyday primitive (-r/-t/-d)
  utimensat() in code  - malware/rootkit timestamp forgery
  timestomp (MSF/meterpreter Linux post) - automated stomping
  debugfs              - advanced, can edit crtime/birth on ext4
                         (requires raw device access = root + loud)

What sophisticated actors do:
  Clone times from a same-directory system binary (touch -r),
  apply to dropped tools, then ALSO attempt clock manipulation
  or debugfs to align ctime. The clock manipulation is itself
  detectable (NTP logs, journal time jumps), so even advanced
  stomping tends to leave a thread to pull.

Forensic counter:
  Timeline analysis with all timestamps (fls/mactime from
  Sleuth Kit) surfaces ctime/mtime disagreement immediately.
  Real-time file-create telemetry (Falco/auditd/FIM) records
  the genuine creation time before any stomp can occur.

Threat actor use:
  Timestomping is documented across APT Linux operations for
  blending implants into system directories, and is bundled
  into post-exploitation frameworks. Lazarus and other state
  actors have used timestamp forgery on Unix implants.`,
        ossdetect: `Sigma rules:
- proc_creation_lnx_touch_timestomp_reference.yml
- proc_creation_lnx_touch_explicit_backdate.yml

Elastic detection rules:
- Timestomping via Touch Command
- File Timestamp Modification (utimensat)

Auditd (capture the syscalls, not just touch):
  -a always,exit -F arch=b64 -S utimensat,utime,utimes,futimesat -k timestomp
  -a always,exit -F arch=b64 -S execve -F path=/usr/bin/touch -k touch_exec
  ausearch -k timestomp | grep -vE "comm=.(tar|rsync|cp|dpkg|rpm)"

Falco:
  rule: Set Timestamp on File (utimensat by non-archive process)
  rule: Suspicious touch with reference/backdate

File integrity monitoring (the structural detector):
  AIDE / Tripwire / Wazuh syscheck - record mtime AND ctime;
  alert on ctime > mtime, and on package-binary mtime drift.
  Wazuh syscheck reports whodata (who changed the file + when).

Timeline forensics:
  Sleuth Kit: fls -r -m / + mactime  -> full MACB timeline
  Disagreement between mtime and ctime/crtime stands out.
  log2timeline/plaso for super-timelines correlating with logs.

Real-time create telemetry (defeats after-the-fact stomp):
  Forward file-create events (Falco/auditbeat) so the TRUE
  creation time is recorded before any touch can rewrite it.

Package verification:
  rpm -Va (T flag = mtime mismatch vs manifest)

Atomic Red Team:
  T1070.006 - timestomp tests (touch -r / -t)`,
        notes: "Timestomping falsifies file timestamps so a malicious file blends into the filesystem and slips past timeline analysis, with the canonical move being touch -r /bin/ls /tmp/backdoor to clone a trusted binary's times onto a payload. The technique is meaningfully weaker on Linux than attackers tend to assume, and the reason is the ctime principle: touch and the utimensat syscall set only atime and mtime, but the kernel updates ctime (the inode change time) on the stomp operation itself, and ctime cannot be set from userspace without rolling the system clock. This leaves ctime newer than mtime as a near-universal structural signature of backdating, detectable by any file integrity monitor that records all three timestamps. Additional tells include an mtime predating the file's inode allocation (a high, recently-allocated inode number paired with an old date), a binary in /usr/bin whose mtime differs from its package manifest (rpm -Va shows a T flag), and clusters of files sharing one odd timestamp from a batch stomp. Advanced actors may attempt to align ctime by manipulating the system clock or using debugfs to edit the ext4 birth time directly, but clock manipulation is itself loud (NTP logs, journal time jumps) and debugfs requires raw device access, so even sophisticated stomping tends to leave a thread to pull. The strongest control is real-time file-create telemetry forwarded to a SIEM, which records the genuine creation time before any stomp can rewrite it; for retrospective work, a Sleuth Kit mactime timeline surfaces mtime/ctime disagreement immediately.",
        apt: [
          { cls: "apt-kp", name: "Lazarus Group", note: "Timestamp forgery on Unix/Linux implants to blend tooling into system directories and frustrate timeline analysis." },
          { cls: "apt-cn", name: "APT41 / Winnti", note: "Linux implants observed with backdated timestamps to match surrounding system binaries." },
          { cls: "apt-mul", name: "Post-exploitation frameworks", note: "touch -r / -t timestomping bundled into Meterpreter and similar Linux post-exploitation tooling." }
        ],
        cite: "MITRE ATT&CK T1070.006"
      }
    ]
  },
  {
    id: "T1070.004",
    name: "Indicator Removal: File Deletion",
    desc: "Removal of tooling and artifacts (shred, rm -rf of staging dirs, self-deleting payloads) as the final anti-forensic step. The /proc recovery path is decisive: a self-deleting running process is recoverable from /proc/<pid>/exe, and osquery on_disk=0 surfaces the pattern directly.",
    rows: [
      {
        sub: "T1070.004 - File Deletion (shred, secure wipe, self-deleting payloads)",
        os: "linux",
        indicator: "Removal of attacker tooling and artifacts to eliminate evidence: shred/wipe for unrecoverable deletion, rm -rf of staging directories, self-deleting droppers (binary unlinks itself then runs from memory), or overwriting before delete; often the last action before disconnect",
        sysmon: `// Sysmon for Linux EID 1 - evidence deletion

// Secure deletion (intent to prevent recovery)
Image=(*/shred OR */wipe OR */srm) CommandLine matches:
  *-u*  *-z*  *-f*   (unlink after overwrite / zero)
AND target in /tmp /dev/shm /var/tmp /home or a tool path

// Bulk removal of staging/tooling directories
Image=*/rm CommandLine matches:
  *-rf /tmp/*  *-rf /dev/shm/*  *-rf /var/tmp/*
  *-rf*.<staging>*  (operator's working dir)

// Self-deleting payload pattern: a binary deletes its own path
// then keeps running (path shows '(deleted)' in /proc/<pid>/exe)
// Detect via: running process whose exe link ends in ' (deleted)'

// Overwrite-then-delete (dd zeroing a file before rm)
Image=*/dd CommandLine matches: *of=*  *if=/dev/zero*  *if=/dev/urandom*

// Auditd
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F dir=/tmp -k file_delete
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/shred -k shred_exec`,
        kibana: `// Secure deletion tooling
process.name: ("shred" OR "wipe" OR "srm")
AND process.command_line: (*-u* OR *-z* OR *-f*)

// Bulk rm of staging dirs
process.name: "rm"
AND process.command_line: (*"-rf /tmp/"* OR *"-rf /dev/shm/"* OR *"-rf /var/tmp/"*)

// Overwrite-before-delete
process.name: "dd"
AND process.command_line: (*if=/dev/zero* OR *if=/dev/urandom*)

// Self-deleting binary: process exe path marked deleted
process.executable: *"(deleted)"*

// Auditd: deletions in working/staging dirs by interactive shells
event.module: "auditd"
AND tags: ("file_delete" OR "shred_exec")
AND process.parent.name: ("bash" OR "sh" OR "ssh" OR "python3")

// Spike detection: burst of unlink syscalls in a short window
// from a single process (mass cleanup before disconnect)`,
        powershell: `#!/bin/bash
# T1070.004 - File deletion / evidence removal hunt

echo "[*] === Running processes executing from DELETED binaries ==="
echo "  (self-deleting payloads keep running after unlinking their file)"
for pid in $(ls /proc | grep -E '^[0-9]+$'); do
  exe=$(readlink /proc/$pid/exe 2>/dev/null)
  if echo "$exe" | grep -q "(deleted)"; then
    echo "[FLAG] PID $pid exe=$exe comm=$(cat /proc/$pid/comm 2>/dev/null)"
    echo "    cmdline: $(tr '\\0' ' ' < /proc/$pid/cmdline 2>/dev/null)"
    echo "    recover: cp /proc/$pid/exe /tmp/recovered_$pid"
  fi
done

echo ""
echo "[*] === Deleted-but-open files (recoverable via /proc/<pid>/fd) ==="
ls -l /proc/*/fd/ 2>/dev/null | grep "(deleted)" | grep -vE "/dev/|pipe:|socket:|anon_inode" | head -20

echo ""
echo "[*] === auditd: shred + mass-delete events ==="
ausearch -k shred_exec -i --start today 2>/dev/null | tail -15
echo "  --- recent unlink bursts in staging dirs ---"
ausearch -k file_delete -i --start today 2>/dev/null | \\
  grep -E "comm=.(bash|sh|python|ssh)" | tail -25

echo ""
echo "[*] === shred/wipe presence + recent execution ==="
for t in shred wipe srm; do
  p=$(command -v $t 2>/dev/null); [ -n "$p" ] && echo "  $t available: $p"
done

echo ""
echo "[*] === Recently emptied directories in staging areas ==="
for d in /tmp /dev/shm /var/tmp; do
  [ -d "$d" ] || continue
  # dirs whose mtime is recent but now nearly empty = cleaned out
  find "$d" -maxdepth 2 -type d -mmin -1440 2>/dev/null | while read sd; do
    cnt=$(ls -A "$sd" 2>/dev/null | wc -l)
    [ "$cnt" -le 1 ] && echo "[FLAG] recently-modified but empty dir: $sd"
  done
done

echo ""
echo "[*] === Cross-ref: tools referenced in history/auditd but now absent ==="
echo "  (a downloaded/compiled file that no longer exists on disk = deleted artifact)"
ausearch -m EXECVE -i --start today 2>/dev/null | grep -oE "/(tmp|dev/shm|var/tmp)/[^ ]+" | sort -u | while read f; do
  [ ! -e "$f" ] && echo "[FLAG] executed but now missing: $f"
done | head -20`,
        registry: `File deletion / evidence removal artifacts:

Deletion methods and recoverability:
  rm file               - unlinks; data blocks may persist
                          until overwritten (carving possible)
  rm -rf dir            - bulk; same recoverability caveat
  shred -u file         - overwrites THEN unlinks (ext4: note
                          journaling/SSD wear-leveling can leave
                          remnants; less effective than on raw)
  wipe / srm            - secure-removal tools, multi-pass
  dd if=/dev/zero of=f  - zero the file, then rm
  truncate then rm      - shrink then unlink

The recovery windows defenders exploit:
  1. Deleted-but-open: if a process still holds the fd, the
     file is fully recoverable from /proc/<pid>/fd/<n> even
     after unlink. Self-deleting RUNNING payloads are
     recoverable from /proc/<pid>/exe (the '(deleted)' link).
  2. Unallocated space: rm only unlinks; until blocks are
     reused, ext4/xfs carving (extundelete, photorec, foremost)
     can recover. shred defeats this; plain rm does not.
  3. Journal/SSD: filesystem journals and SSD over-provisioning
     can retain fragments even after shred.

Self-deleting payload pattern (very common):
  Dropper writes binary -> execs it -> the running process
  unlinks its own file. On disk the file is gone, but:
    /proc/<pid>/exe -> "/path/to/binary (deleted)"
    cp /proc/<pid>/exe /tmp/recovered   (full recovery)
  This is the single highest-value live-response check.

High-signal indicators:
  process exe link ending in " (deleted)" (running implant)
  large deleted-but-open files in /proc/*/fd (held by a daemon)
  burst of unlink syscalls from an interactive shell (cleanup)
  shred/wipe execution (intent to prevent recovery = deliberate)
  staging dir (/tmp, /dev/shm) recently modified but now empty
  a path that appears in auditd EXECVE but no longer exists

The clustering signal:
  File deletion is usually the LAST anti-forensic step, paired
  with history clear, log wipe, and timestomp. The full cluster
  in one session = deliberate operator cleanup before exit.`,
        tools: `File deletion as anti-forensics:

Removing tools and artifacts is typically the final action
before an operator disconnects, intended to leave nothing for
responders to analyze. The sophistication ranges from a quick
rm -rf of the staging directory to multi-pass shred to self-
deleting payloads that never touch disk persistently.

Why defenders still recover plenty:
  rm only unlinks - the data blocks remain until overwritten,
  so prompt acquisition + carving (extundelete, foremost,
  photorec) recovers recently-deleted files on ext4/xfs.
  shred -u defeats carving but its EXECUTION is itself a loud,
  high-intent signal worth alerting on.

The /proc goldmine (memory-resident recovery):
  The most valuable technique in live response: a self-deleting
  malware process keeps running, and the kernel preserves the
  executable via /proc/<pid>/exe even though the path shows
  "(deleted)". A simple cp /proc/<pid>/exe recovers the full
  binary for analysis. Likewise, any deleted file still held
  open by a process is recoverable from /proc/<pid>/fd. Fileless
  and self-deleting implants routinely fall to this.

Self-deleting droppers:
  write -> chmod +x -> exec -> unlink(self) -> continue in RAM.
  Defeats on-disk scanning but NOT /proc/<pid>/exe recovery and
  NOT memory forensics (the code is mapped and dumpable).

Forensic counters:
  Real-time create/exec telemetry (auditd/Falco) records the
  file's existence and hash BEFORE deletion - the artifact's
  metadata survives even when the file does not.
  Centralized collection means the EXECVE record persists
  regardless of local cleanup.

Threat actor use:
  Self-deleting droppers are standard in Linux malware (many
  cryptominer loaders, ELF backdoors). Bulk staging cleanup is
  near-universal in hands-on intrusions. shred-based wiping
  appears in more deliberate, anti-forensic-aware operations.`,
        ossdetect: `Sigma rules:
- proc_creation_lnx_shred_secure_delete.yml
- proc_creation_lnx_mass_file_deletion_staging.yml
- proc_creation_lnx_self_deleting_payload.yml

Elastic detection rules:
- File Deletion via Shred
- Process Executing from Deleted Binary
- Mass File Deletion in Temporary Directory

Auditd:
  -a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat \\
    -F dir=/tmp -k file_delete
  -a always,exit -F arch=b64 -S execve -F path=/usr/bin/shred -k shred_exec
  ausearch -k shred_exec   (any hit = high intent)

Falco:
  rule: Delete or rename shell history (related)
  rule: Remove Bulk Data from Disk
  rule: Run shell untrusted (cleanup context)
  rule: Execution from deleted binary (custom: proc.exepath contains deleted)

Live-response checks (highest value):
  for p in /proc/[0-9]*; do ls -l $p/exe 2>/dev/null; done | grep deleted
  -> recover with cp /proc/<pid>/exe
  ls -l /proc/*/fd | grep deleted  -> recover held-open files

osquery:
  SELECT pid, path FROM processes WHERE on_disk=0;
  (on_disk=0 = the backing executable was deleted = self-delete)

Real-time hash-on-create:
  auditbeat/Falco hash files at creation so the artifact's
  identity survives subsequent deletion.

Atomic Red Team:
  T1070.004 - file deletion tests (rm, shred)`,
        notes: "File deletion is typically the final anti-forensic action before an operator disconnects, intended to leave responders nothing to analyze, and it ranges from a quick rm -rf of the staging directory to multi-pass shred to self-deleting payloads. The crucial point for defenders is how much remains recoverable: plain rm only unlinks the file, leaving data blocks intact until overwritten, so prompt acquisition and carving (extundelete, foremost, photorec) recover recently-deleted files on ext4 and xfs, while shred defeats carving but its execution is itself a loud, high-intent signal worth alerting on directly. The single highest-value live-response technique is the /proc recovery path: a self-deleting malware process keeps running, and the kernel preserves its executable via /proc/<pid>/exe even though the path is marked '(deleted)', so cp /proc/<pid>/exe recovers the full binary, and any deleted file still held open by a process is similarly recoverable from /proc/<pid>/fd. osquery exposes the same signal directly with SELECT pid, path FROM processes WHERE on_disk=0, where on_disk=0 means the backing executable was deleted, the textbook self-delete pattern. The durable defensive posture is real-time create and exec telemetry that hashes files at creation, so the artifact's identity and metadata survive even when the file itself is destroyed, combined with centralized collection so the EXECVE record persists regardless of local cleanup. File deletion is usually the last step in an anti-forensic cluster alongside history clearing, log wiping, and timestomping, and the full cluster in a single session is a reliable marker of deliberate operator cleanup.",
        apt: [
          { cls: "apt-mul", name: "Linux malware loaders", note: "Self-deleting droppers (write, exec, unlink self, continue in RAM) are standard in cryptominer loaders and ELF backdoors." },
          { cls: "apt-mul", name: "Hands-on intruders", note: "Bulk staging-directory cleanup (rm -rf /tmp working dirs) is near-universal as the final action before disconnect." },
          { cls: "apt-mul", name: "Anti-forensic operators", note: "shred-based unrecoverable wiping appears in deliberate operations aware of disk-carving recovery techniques." }
        ],
        cite: "MITRE ATT&CK T1070.004"
      }
    ]
  },
  {
    id: "T1562.012",
    name: "Impair Defenses: Disable or Modify Linux Audit System",
    desc: "The keystone evasion: tampering with auditd (auditctl -e 0, -D flush, stopping the daemon, editing rules.d/auditd.conf) blinds the telemetry source that most other Linux detections depend on. auditd narrates its own death via CONFIG_CHANGE/DAEMON_END events, and the event-volume gap from a live host is one of the most reliable detections in the tactic.",
    rows: [
      {
        sub: "T1562.012 - Disable or Modify Linux Audit System (auditd)",
        os: "linux",
        indicator: "Tampering with the auditd subsystem that most other Linux detections depend on: auditctl -e 0 to disable auditing, killing/stopping the auditd or auditd-dispatch daemon, flushing rules with auditctl -D, editing /etc/audit/audit.rules or auditd.conf, or unloading the audit backlog, blinding host telemetry at the source",
        sysmon: `// Sysmon for Linux EID 1 - auditd subsystem tampering
// (This is adversaries attacking the very telemetry your other
//  hunts rely on - treat as high severity.)

// Disabling / flushing audit at runtime
Image=*/auditctl CommandLine matches:
  *-e 0*        (disable auditing)
  *-D*          (delete ALL rules)
  *-e 2* later forced back to 0
CommandLine matches: *auditctl -e 0*  *auditctl -D*

// Stopping the daemon
Image=(*/systemctl OR */service) CommandLine matches:
  *stop auditd*  *disable auditd*  *mask auditd*
Image=*/kill* with target comm=auditd OR comm=auditd-dispatch
Image=*/pkill CommandLine matches: *auditd*

// Editing rules/config (persistent disablement)
Image=(*/vi OR */vim OR */nano OR */sed OR */tee) CommandLine matches:
  */etc/audit/audit.rules*  */etc/audit/rules.d/*  */etc/audit/auditd.conf*

// Unloading audit kernel backlog / setting failure mode to silent
CommandLine matches: *auditctl -b 0*  *-f 0*

// Auditd (self-monitoring - these rules must be immutable: -e 2)
-w /etc/audit/ -p wa -k auditconfig
-w /etc/audit/audit.rules -p wa -k auditconfig
-w /sbin/auditctl -p x -k auditctl_exec
-w /sbin/auditd -p x -k auditd_exec
-e 2   // lock the config; changes then require reboot (tamper-evident)`,
        kibana: `// auditctl disable / rule flush
process.name: "auditctl"
AND process.command_line: (*"-e 0"* OR *"-D"* OR *"-b 0"* OR *"-f 0"*)

// Stopping or masking the daemon
process.command_line: (
  *"stop auditd"* OR *"disable auditd"* OR *"mask auditd"*
  OR *"kill"* AND *auditd* OR *"pkill"* AND *auditd*
)

// Editing audit rules/config
process.name: ("vi" OR "vim" OR "nano" OR "sed" OR "tee")
AND process.command_line: (*/etc/audit/* )

// Auditd self-monitoring keys (config/binary tamper)
event.module: "auditd"
AND tags: ("auditconfig" OR "auditctl_exec" OR "auditd_exec")
AND NOT process.name: ("dpkg" OR "rpm" OR "augenrules")

// THE telemetry-gap signal (most important):
// auditd event stream from a host suddenly stops while the
// host is still up (heartbeat/other logs continue).
// Implement as: alert when expected auditd EPS -> 0 for a live host.
event.module: "auditd" AND event.action: "daemon-end"
// 'daemon-end' / 'daemon-abort' audit events mark auditd stopping

// Config change events emitted by auditd itself
event.module: "auditd"
AND auditd.message_type: ("CONFIG_CHANGE" OR "DAEMON_END" OR "DAEMON_ABORT")`,
        powershell: `#!/bin/bash
# T1562.012 - Linux audit system tampering hunt
# auditd is the backbone of most other Linux detections; verify
# it is RUNNING, ENABLED, and its rules/config are INTACT.

echo "[*] === auditd daemon state ==="
systemctl is-active auditd 2>/dev/null
systemctl is-enabled auditd 2>/dev/null
ps -ef | grep -E "[a]uditd|[a]udisp" | head

echo ""
echo "[*] === Audit enabled flag + backlog (auditctl -s) ==="
auditctl -s 2>/dev/null
echo "  enabled=1 expected (2=immutable/locked is even better)"
echo "  enabled=0 => AUDITING IS OFF (critical)"

echo ""
echo "[*] === Loaded rules count vs on-disk rules ==="
loaded=$(auditctl -l 2>/dev/null | grep -vc "No rules")
echo "  rules currently loaded: $loaded"
ondisk=$(cat /etc/audit/rules.d/*.rules /etc/audit/audit.rules 2>/dev/null | grep -vcE "^#|^$")
echo "  rules defined on disk:  $ondisk"
[ "$loaded" -lt "$ondisk" ] 2>/dev/null && echo "[FLAG] fewer rules loaded than defined - possible runtime flush (-D)"
[ "$loaded" = "0" ] && echo "[FLAG] ZERO rules loaded - auditing effectively blind"

echo ""
echo "[*] === Recent CONFIG_CHANGE / DAEMON events (auditd self-record) ==="
ausearch -m CONFIG_CHANGE -i --start today 2>/dev/null | tail -20
ausearch -m DAEMON_END,DAEMON_ABORT,DAEMON_START -i --start today 2>/dev/null | tail -15
echo "  (DAEMON_END followed by no DAEMON_START while host stayed up = disabled)"

echo ""
echo "[*] === audit config/rules file integrity ==="
for f in /etc/audit/auditd.conf /etc/audit/audit.rules; do
  [ -e "$f" ] && echo "  $f | mtime=$(stat -c '%y' "$f")"
done
ls -la /etc/audit/rules.d/ 2>/dev/null
echo "  package verify:"; rpm -V audit 2>/dev/null; dpkg --verify auditd 2>/dev/null | grep audit

echo ""
echo "[*] === auditd.conf: log routing tampering ==="
grep -E "^(log_file|log_format|flush|max_log_file|disk_full_action|disk_error_action)" \\
  /etc/audit/auditd.conf 2>/dev/null
echo "  (watch for log_file redirected, flush=none, or actions set to ignore)"

echo ""
echo "[*] === Is audit shipped off-box? (resilience) ==="
grep -rE "active = yes|direction = out|tcp_client|^remote_server" \\
  /etc/audit/audisp-remote.conf /etc/audisp/plugins.d/ /etc/audit/plugins.d/ 2>/dev/null
echo "  (audisp-remote forwarding survives local auditd disable)"

echo ""
echo "[*] === auditd EPS sanity (is it actually producing events?) ==="
echo "  events in last segment:"; ausearch -ts recent 2>/dev/null | grep -c "type=" `,
        registry: `Linux audit system tampering artifacts:

Why this technique is special:
  auditd is the telemetry SOURCE that most other Linux
  detections in this reference depend on (every 'Auditd Key
  Alert' field). Disabling it does not just hide one action -
  it blinds the host. Treat T1562.012 as the master evasion.

Runtime disablement:
  auditctl -e 0          - turn auditing OFF (events stop)
  auditctl -D            - delete ALL loaded rules
  auditctl -b 0          - zero the backlog buffer
  auditctl -f 0          - failure mode = silent (no panic/log)
  kill / systemctl stop auditd  - daemon down
  systemctl mask auditd  - prevent restart

Persistent disablement:
  edit /etc/audit/audit.rules or /etc/audit/rules.d/*.rules
    (remove rules so they never load at boot)
  edit /etc/audit/auditd.conf:
    log_file = /dev/null         (discard)
    flush = none                 (buffer, lose on crash)
    disk_full_action = ignore    (silently drop)
    max_log_file_action = ignore
  systemctl disable auditd

The auditd self-record (your evidence even when tampered):
  auditd emits its OWN events for these actions:
    CONFIG_CHANGE  - rule/config modification
    DAEMON_END     - daemon stopping
    DAEMON_ABORT   - daemon crash/kill
    DAEMON_START   - daemon starting
  A DAEMON_END with no following DAEMON_START while the host
  stayed up (other logs continue) = deliberate disablement.

High-signal indicators:
  auditctl -s shows enabled=0 on a host that should audit
  loaded rule count < on-disk rule count (runtime -D flush)
  zero rules loaded
  CONFIG_CHANGE / DAEMON_END events near an intrusion window
  auditd.conf log_file redirected or actions set to ignore
  sudden stop of the auditd event stream from a live host

The two controls that defeat this:
  1. -e 2 (immutable mode): rules lock until reboot, so any
     change is tamper-EVIDENT (requires a reboot to alter).
  2. audisp-remote forwarding: events ship off-box in real
     time, so local auditd disable cannot erase what already left.`,
        tools: `Disabling the Linux audit system:

This is the keystone evasion on Linux: auditd underpins the
detections for nearly every other technique, so a knowledgeable
adversary who intends sustained access disables or degrades it
early. Seeing auditd tampering should immediately raise the
severity of the whole investigation - it implies an operator
who understands the host's defenses.

Typical approaches by sophistication:
  Crude:   auditctl -e 0  (off) or systemctl stop auditd
           - very effective but leaves DAEMON_END / a telemetry
             gap that a SIEM watching event volume will notice.
  Quieter: auditctl -D to flush specific noisy rules, or edit
           rules.d to drop only the rules that would catch them,
           leaving auditd 'running' but selectively blind.
  Persistent: auditd.conf log_file=/dev/null or disable at boot.

Why defenders retain the upper hand:
  auditd narrates its own death. CONFIG_CHANGE, DAEMON_END, and
  DAEMON_ABORT are themselves audit events. If those events are
  forwarded off-box (audisp-remote), the adversary cannot unsay
  them. And the EVENT-VOLUME GAP - a live host that abruptly
  stops sending audit events while still emitting other logs -
  is one of the most reliable detections in the whole tactic.

The immutable-mode control (-e 2):
  Setting the audit config immutable means rule changes require
  a reboot. An adversary forced to reboot to alter auditing
  creates a loud, attributable event. This trades operational
  flexibility for strong tamper-evidence on critical hosts.

Threat actor use:
  Disabling or degrading host logging is broadly documented
  across Linux intrusions. Cryptomining crews stop noisy agents;
  stealth operators selectively prune audit rules; ransomware
  disables logging pre-encryption. In OT/ICS-adjacent Linux,
  audit tampering is especially concerning because monitoring
  is already sparse.`,
        ossdetect: `Sigma rules:
- lnx_auditd_disable_or_modify.yml
- proc_creation_lnx_auditctl_disable_flush.yml
- proc_creation_lnx_stop_auditd_service.yml
- lnx_auditd_config_change.yml

Elastic detection rules:
- Auditd Service Stopped or Disabled
- Audit Rules Flushed (auditctl -D)
- Tampering with Auditd Configuration

Auditd self-monitoring (make it watch itself, immutably):
  -w /etc/audit/ -p wa -k auditconfig
  -w /sbin/auditctl -p x -k auditctl_exec
  -w /sbin/auditd -p x -k auditd_exec
  -e 2     # immutable: changes require reboot = tamper-evident
  Monitor message types: CONFIG_CHANGE, DAEMON_END, DAEMON_ABORT

Falco (independent of auditd - key advantage):
  rule: Auditd Service Stopped
  rule: Clear Audit Rules
  Falco uses its own eBPF/kernel-module source, so it still
  sees the auditctl/kill even when auditd itself is down.
  Running Falco AND auditd gives cross-coverage.

THE telemetry-gap detection (SIEM-side, highest value):
  Alert when a host's auditd event rate drops to zero while
  heartbeat/other sources continue. This catches disablement
  regardless of method (kill, -e 0, mask, config).

audisp-remote forwarding (resilience):
  active = yes ; remote_server = <collector>
  Real-time off-box shipping; local disable cannot retract
  already-forwarded events including the DAEMON_END itself.

Atomic Red Team:
  T1562.012 / T1562.001 - disable auditd tests`,
        notes: "Disabling the Linux audit system is the keystone evasion technique, because auditd is the telemetry source that underpins detections for nearly every other Linux technique in this reference, so disabling it does not merely hide one action, it blinds the host. A knowledgeable adversary intending sustained access tampers with auditd early, which means any sign of audit tampering should immediately raise the severity of the entire investigation. The methods range from crude runtime disablement (auditctl -e 0, systemctl stop auditd) through selective rule flushing (auditctl -D, or editing rules.d to drop only the rules that would catch the operator while leaving auditd nominally running) to persistent config tampering (auditd.conf with log_file=/dev/null or disabling at boot). The defender retains the upper hand through three mechanisms. First, auditd narrates its own death: CONFIG_CHANGE, DAEMON_END, and DAEMON_ABORT are themselves audit events, and if forwarded off-box via audisp-remote they cannot be retracted. Second, the event-volume gap, where a live host abruptly stops sending audit events while still emitting other logs, is one of the most reliable detections in the whole tactic and catches disablement regardless of method. Third, immutable mode (auditctl -e 2) locks the configuration so changes require a reboot, forcing any adversary to generate a loud, attributable event to alter auditing. Running Falco alongside auditd adds critical cross-coverage because Falco uses its own eBPF or kernel-module source and still observes the auditctl or kill commands even when auditd itself is down. This is especially important in OT and ICS-adjacent Linux where monitoring is already sparse.",
        apt: [
          { cls: "apt-mul", name: "Stealth operators", note: "Selective auditd rule pruning to blind specific detections while leaving the daemon nominally running; signals deep host-defense awareness." },
          { cls: "apt-mul", name: "Ransomware crews", note: "Host logging including auditd disabled pre-encryption to impede detection and response." },
          { cls: "apt-mul", name: "Cryptomining crews", note: "Audit and monitoring degradation alongside security agent removal to reduce noise during miner operation." }
        ],
        cite: "MITRE ATT&CK T1562.012"
      }
    ]
  },
  {
    id: "T1562.001",
    name: "Impair Defenses: Disable or Modify Tools",
    desc: "Stopping, killing, masking, or uninstalling security agents (Falco, Wazuh, osquery, ClamAV, EDR, and cloud-provider agents) and neutralizing mandatory access control (SELinux setenforce 0, AppArmor teardown). Cloud-agent uninstallation (Alibaba aegis, Tencent YunJing) is a signature crypto-crew TTP. External-console heartbeat monitoring turns local kills into server-side alerts.",
    rows: [
      {
        sub: "T1562.001 - Disable Security Tools and EDR/Monitoring Agents",
        os: "linux",
        indicator: "Termination, stopping, or uninstallation of endpoint security and monitoring agents: killing or masking Falco, Wazuh, osquery, EDR sensors, ClamAV, or cloud-provider agents; cloud crypto crews specifically uninstall Alibaba/Tencent/AWS agents; or unloading kernel-based sensors (eBPF/kernel module)",
        sysmon: `// Sysmon for Linux EID 1 - security agent disablement

// Stopping / masking / disabling security services
Image=(*/systemctl OR */service) CommandLine matches:
  *stop* *disable* *mask* combined with:
  *falco*  *wazuh*  *osquery*  *clamav*  *clamd*  *ossec*
  *crowdstrike* *falcon-sensor* *carbonblack* *cbagent*
  *sysmon* *auditd* *filebeat* *auditbeat* *sentinelone*

// Killing agent processes
Image=(*/kill OR */pkill OR */killall) CommandLine matches:
  *falco* *wazuh* *osqueryd* *clamd* *falcon* *cbagent*
  *aliyun* *AliYunDun* *aegis* *YunJing* *BcmAgent* (cloud agents)

// Cloud-agent UNINSTALL (Rocke/TeamTNT signature behavior)
CommandLine matches:
  */uninstall.sh*  *aegis*uninstall*  *AliYunDunUpdate*
  *quartz_uninstall*  *YunJing*  *bcm*uninstall*
  *rpm -e* / *apt remove* with a security package name

// Unloading kernel/eBPF sensors
Image=(*/rmmod OR */modprobe) CommandLine matches: *-r* (sensor module)

// Auditd
-w /etc/systemd/system -p wa -k svc_change
-a always,exit -F arch=b64 -S kill -k kill_signal
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/pkill -k pkill_exec`,
        kibana: `// Stopping/disabling/masking security services
process.command_line: (
  (*stop* OR *disable* OR *mask*) AND
  (*falco* OR *wazuh* OR *osquery* OR *clamav* OR *clamd*
   OR *ossec* OR *falcon* OR *crowdstrike* OR *carbonblack*
   OR *sentinelone* OR *filebeat* OR *auditbeat*)
)

// Killing agent processes by name
process.name: ("kill" OR "pkill" OR "killall")
AND process.command_line: (
  *falco* OR *wazuh* OR *osqueryd* OR *clamd* OR *falcon*
  OR *aliyun* OR *aegis* OR *YunJing* OR *AliYunDun*
)

// Cloud agent uninstall (Rocke/TeamTNT TTP)
process.command_line: (
  *aegis*uninstall* OR *AliYunDun* OR *quartz_uninstall*
  OR *YunJing* OR (*uninstall.sh* AND (*aliyun* OR *aegis* OR *bcm*))
)

// Package removal of a security product
process.name: ("rpm" OR "apt" OR "apt-get" OR "dpkg" OR "yum" OR "dnf")
AND process.command_line: ((*-e* OR *remove* OR *purge* OR *erase*)
  AND (*falco* OR *clamav* OR *wazuh* OR *osquery* OR *falcon*))

// The agent-silence signal: a registered agent stops checking in
// (SIEM-side: alert on missing heartbeat from a live host)

// Auditd
event.module: "auditd"
AND tags: ("svc_change" OR "kill_signal" OR "pkill_exec")`,
        powershell: `#!/bin/bash
# T1562.001 - Security agent / EDR disablement hunt

echo "[*] === Expected security agents: are they RUNNING? ==="
for svc in falco wazuh-agent ossec osqueryd clamav-daemon clamd \\
           filebeat auditbeat falcon-sensor sysmon; do
  state=$(systemctl is-active "$svc" 2>/dev/null)
  enab=$(systemctl is-enabled "$svc" 2>/dev/null)
  [ "$state" = "unknown" ] && [ -z "$enab" ] && continue
  flag=""
  [ "$state" != "active" ] && flag="  <-- NOT ACTIVE"
  [ "$enab" = "masked" ] && flag="  <-- MASKED (blocked from starting)"
  echo "  $svc: active=$state enabled=$enab$flag"
done

echo ""
echo "[*] === Cloud security agents (Rocke/TeamTNT uninstall targets) ==="
for proc in aliyun AliYunDun aegis_cli AliHips YunJing BcmAgent \\
            qualys-cloud-agent amazon-ssm-agent; do
  if pgrep -f "$proc" >/dev/null 2>&1; then
    echo "  $proc: running"
  else
    # only flag if there's evidence it was once installed
    if ls /usr/local/aegis* /usr/local/qcloud* /opt/alibaba* 2>/dev/null | grep -q .; then
      echo "[FLAG] $proc: install dir present but process NOT running (uninstalled/killed?)"
    fi
  fi
done

echo ""
echo "[*] === Masked units (blocked from ever starting) ==="
systemctl list-unit-files --state=masked 2>/dev/null | grep -iE "falco|wazuh|clam|osquery|ossec|falcon|audit"

echo ""
echo "[*] === Recent service stop/disable in journal ==="
journalctl --since today 2>/dev/null | grep -iE "Stopped|Stopping|Deactivated" | \\
  grep -iE "falco|wazuh|clam|osquery|ossec|falcon|auditd" | tail -20

echo ""
echo "[*] === auditd: kills sent to agent PIDs + service edits ==="
ausearch -k kill_signal -i --start today 2>/dev/null | \\
  grep -iE "falco|wazuh|osquery|clam|falcon" | tail -15
ausearch -k svc_change -i --start today 2>/dev/null | tail -10

echo ""
echo "[*] === Security package removal evidence ==="
grep -hiE "remove|purge|erase" /var/log/dpkg.log /var/log/yum.log /var/log/dnf.log 2>/dev/null | \\
  grep -iE "falco|clamav|wazuh|osquery|falcon|ossec" | tail -15
echo "  (cross-check: agent install dir exists but package gone = uninstalled)"

echo ""
echo "[*] === eBPF/kernel sensor presence ==="
lsmod 2>/dev/null | grep -iE "falco|sysdig|sensor" || echo "  no obvious sensor kmod"
ls /sys/fs/bpf/ 2>/dev/null | head`,
        registry: `Security agent / EDR disablement artifacts:

Common Linux security agents (the targets):
  Detection/EDR: Falco, Wazuh, OSSEC, osquery/osqueryd,
    CrowdStrike falcon-sensor, SentinelOne, Carbon Black cbagent
  AV: ClamAV (clamd/clamav-daemon)
  Telemetry shippers: filebeat, auditbeat, fluentd
  Cloud-provider agents (heavily targeted by crypto crews):
    Alibaba: aegis / AliYunDun / AliHips (CloudMonitor, Security)
    Tencent: YunJing / BcmAgent (Yunjing host security)
    AWS: amazon-ssm-agent ; Qualys: qualys-cloud-agent

Disablement methods:
  systemctl stop/disable/mask <agent>   (mask = cannot restart)
  kill / pkill / killall <agent process>
  rpm -e / apt remove / yum erase <agent package>
  cloud-agent uninstall scripts (the Rocke/TeamTNT signature):
    /usr/local/aegis/aegis_uninstall.sh
    AliYunDunUpdate, quartz_uninstall, YunJing uninstall
  rmmod / modprobe -r <kernel sensor module>
  config neutering (point agent at /dev/null, blank ruleset)

The Rocke/TeamTNT cloud-agent TTP (well documented):
  These crews ship scripts that specifically detect and
  UNINSTALL Alibaba and Tencent cloud security agents before
  deploying miners. Presence of an agent's install directory
  WITHOUT its running process/package is the tell.

High-signal indicators:
  an expected agent service in state inactive/masked
  agent install dir present but process absent (uninstalled)
  kill/pkill targeting a known agent process name
  security package in dpkg/yum remove logs
  masked security units (blocked from starting)
  agent stopped checking in to its console (heartbeat gap)
  cloud-agent uninstall script names in history/auditd

The resilience principle:
  Agents that report to an external console make local
  disablement visible: the MISSING HEARTBEAT from a host that
  is otherwise alive is the detection. EDR consoles, Wazuh
  manager, and Falcon cloud all surface agent-down as an alert.`,
        tools: `Disabling security tools and agents:

Before deploying a payload (miner, ransomware, backdoor), an
adversary commonly clears the field by stopping or removing the
host's security agents. On Linux servers this prominently
includes CLOUD-PROVIDER agents, which is a defining behavior of
several cryptomining crews.

The signature cloud behavior (Rocke, TeamTNT, 8220):
  These actors ship uninstall routines that specifically target
  Alibaba Cloud (aegis/AliYunDun) and Tencent Cloud (YunJing)
  host-security agents. The scripts call the vendors' own
  uninstall paths to cleanly remove monitoring before mining.
  This is so consistent it is itself an attribution signal.

General agent-killing:
  systemctl stop/mask, kill/pkill of falco/wazuh/osquery/clamd,
  package removal, or unloading kernel/eBPF sensors. Masking is
  favored over stopping because it prevents auto-restart.

Why the cloud/console model wins:
  An on-host kill can blind the host locally, but agents that
  stream to an external manager (Wazuh manager, Falcon cloud,
  a SIEM) turn the kill into an alert: the agent-down / missing-
  heartbeat event fires from the SERVER side, which the attacker
  cannot reach. Local evasion, remote detection.

The cross-tool principle:
  No single agent should be the only sensor. auditd + Falco +
  an EDR provide overlapping coverage; disabling one is caught
  by another (e.g. auditd records the pkill of Falco; Falco
  records the stop of auditd). This reference's hunts assume
  this layered model.

Threat actor use:
  Rocke and TeamTNT cloud-agent uninstallation is extensively
  documented (Palo Alto Unit42, others). EDR/agent killing more
  broadly is near-universal pre-payload across crimeware and
  targeted Linux intrusions.`,
        ossdetect: `Sigma rules:
- lnx_security_tools_disabling.yml
- proc_creation_lnx_clamav_service_stop.yml
- proc_creation_lnx_cloud_agent_uninstall.yml
- proc_creation_lnx_kill_security_process.yml

Elastic detection rules:
- Security Software Discovery then Termination
- Cloud Security Agent Uninstallation (Alibaba/Tencent)
- Tampering or Stopping of Falco / Wazuh / osquery

Auditd:
  -w /etc/systemd/system -p wa -k svc_change
  -a always,exit -F arch=b64 -S kill -k kill_signal
  Correlate kill targets against known agent PIDs.

Falco (catches kills of OTHER agents, and vice versa):
  rule: Terminate Security Tool / agent process
  rule: Disable Security Service
  Layered sensors mutually witness each other's disablement.

THE control - external console / heartbeat monitoring:
  Wazuh manager: agent disconnected alert
  CrowdStrike/SentinelOne cloud: sensor-health / host-offline
  SIEM: missing-heartbeat rule per registered host
  Server-side agent-down alerting is unreachable by the host
  attacker and is the most reliable detection.

osquery (inventory + drift):
  SELECT name FROM services WHERE name LIKE '%falco%' ...;
  Compare running services against a golden security baseline.

Immutability / restart protection:
  systemd: Restart=always + protect units from masking via
  policy; file immutability (chattr +i) on agent configs.

Atomic Red Team:
  T1562.001 - disable/modify tools (service stop, kill, uninstall)`,
        notes: "Disabling security tools is a standard pre-payload step where an adversary clears the field before deploying a miner, ransomware, or backdoor, and on Linux servers it prominently includes cloud-provider agents, which is a defining behavior of several cryptomining crews. The signature cloud TTP, extensively documented for Rocke, TeamTNT, and 8220 Gang, is shipping uninstall routines that specifically target Alibaba Cloud (aegis/AliYunDun) and Tencent Cloud (YunJing) host-security agents by calling the vendors' own uninstall paths, a behavior so consistent it serves as an attribution signal. More generally, adversaries stop, kill, mask, or remove agents like Falco, Wazuh, osquery, ClamAV, and commercial EDR sensors, with masking favored over stopping because it prevents auto-restart. The decisive defensive principle is the external-console model: an on-host kill blinds the host locally, but agents that stream to an external manager turn the kill into a server-side alert, because the agent-down or missing-heartbeat event fires from infrastructure the attacker cannot reach, so local evasion becomes remote detection. The complementary principle is layered sensors, where auditd, Falco, and an EDR provide overlapping coverage so that disabling one is witnessed by another, for example auditd recording the pkill of Falco while Falco records the stop of auditd. For hunting, the highest-signal indicators are an expected agent in inactive or masked state, an agent install directory present without its running process (the uninstall tell), kill or pkill targeting known agent process names, and security packages appearing in removal logs.",
        apt: [
          { cls: "apt-mul", name: "Rocke", note: "Signature uninstallation of Alibaba Cloud (aegis) and Tencent Cloud (YunJing) agents before cryptominer deployment; well documented by Unit42." },
          { cls: "apt-mul", name: "TeamTNT", note: "Cloud security agent removal and EDR/AV disabling as a standard precursor to miner and backdoor installation." },
          { cls: "apt-mul", name: "8220 Gang", note: "Stops and uninstalls cloud-provider monitoring agents on compromised cloud Linux hosts to operate unobserved." }
        ],
        cite: "MITRE ATT&CK T1562.001"
      },
      {
        sub: "T1562.001 - Disable Linux Security Modules (SELinux / AppArmor)",
        os: "linux",
        indicator: "Neutralizing mandatory access control: setenforce 0 to put SELinux in permissive mode, editing /etc/selinux/config to SELINUX=disabled or permissive, aa-teardown / aa-complain / systemctl disable apparmor, or unloading AppArmor profiles, removing a key containment layer before further action",
        sysmon: `// Sysmon for Linux EID 1 - MAC (SELinux/AppArmor) disablement

// SELinux runtime + persistent disable
Image=*/setenforce CommandLine matches: *0*  *Permissive*
Image=(*/sed OR */vi OR */vim OR */nano OR */tee) CommandLine matches:
  */etc/selinux/config*
CommandLine matches:
  *SELINUX=disabled*  *SELINUX=permissive*
  *setenforce 0*  *echo 0 >*/sys/fs/selinux/enforce*

// AppArmor disable
Image=*/aa-teardown
Image=(*/aa-complain OR */aa-disable) CommandLine matches: */etc/apparmor.d/*
Image=(*/systemctl OR */service) CommandLine matches:
  *stop apparmor*  *disable apparmor*
Image=*/apparmor_parser CommandLine matches: *-R*  (remove profile)
CommandLine matches: *ln -s*/etc/apparmor.d/*disable*

// GRUB-level disable (persists across reinstall of policy)
Image=(*/sed OR */grubby) CommandLine matches: *selinux=0*  *apparmor=0*  *enforcing=0*

// Auditd
-w /etc/selinux/config -p wa -k selinux_config
-w /etc/apparmor.d/ -p wa -k apparmor_config
-a always,exit -F arch=b64 -S execve -F path=/usr/sbin/setenforce -k setenforce_exec`,
        kibana: `// SELinux disable (runtime + config)
process.name: "setenforce"
AND process.command_line: (*0* OR *Permissive*)

process.command_line: (
  *"SELINUX=disabled"* OR *"SELINUX=permissive"*
  OR *"setenforce 0"* OR (*"/sys/fs/selinux/enforce"* AND *"echo 0"*)
)

// Editing SELinux config file
process.name: ("sed" OR "vi" OR "vim" OR "nano" OR "tee")
AND process.command_line: */etc/selinux/config*

// AppArmor disable
process.name: ("aa-teardown" OR "aa-disable" OR "aa-complain")
OR (process.command_line: (*"stop apparmor"* OR *"disable apparmor"*))
OR (process.name: "apparmor_parser" AND process.command_line: *-R*)

// GRUB-level MAC disable
process.command_line: (*selinux=0* OR *apparmor=0* OR *enforcing=0*)

// Auditd
event.module: "auditd"
AND tags: ("selinux_config" OR "apparmor_config" OR "setenforce_exec")
AND NOT process.name: ("dpkg" OR "rpm")

// SELinux's own status-change audit event
event.module: "auditd"
AND auditd.message_type: ("MAC_STATUS" OR "MAC_CONFIG_CHANGE" OR "MAC_POLICY_LOAD")`,
        powershell: `#!/bin/bash
# T1562.001 - SELinux / AppArmor disablement hunt

echo "[*] === SELinux current state ==="
if command -v getenforce >/dev/null 2>&1; then
  cur=$(getenforce 2>/dev/null)
  echo "  getenforce (runtime): $cur"
  [ "$cur" = "Permissive" ] && echo "[FLAG] SELinux is PERMISSIVE (not enforcing)"
  [ "$cur" = "Disabled" ] && echo "[FLAG] SELinux is DISABLED"
  echo "  /etc/selinux/config:"
  grep -E "^SELINUX=" /etc/selinux/config 2>/dev/null
  cfg=$(grep -E "^SELINUX=" /etc/selinux/config 2>/dev/null | cut -d= -f2)
  [ "$cfg" != "enforcing" ] && [ -n "$cfg" ] && echo "[FLAG] config persists non-enforcing: $cfg"
  echo "  live enforce node: $(cat /sys/fs/selinux/enforce 2>/dev/null) (1=enforcing 0=permissive)"
else
  echo "  SELinux tools not present (likely an AppArmor distro)"
fi

echo ""
echo "[*] === AppArmor current state ==="
if command -v aa-status >/dev/null 2>&1; then
  aa-status --enabled 2>/dev/null && echo "  apparmor: enabled" || echo "[FLAG] apparmor NOT enabled"
  aa-status 2>/dev/null | grep -E "profiles are loaded|in enforce mode|in complain mode" | head
  comp=$(aa-status 2>/dev/null | grep -oE "[0-9]+ profiles are in complain" )
  [ -n "$comp" ] && echo "[FLAG] profiles in COMPLAIN mode (not enforcing): $comp"
  systemctl is-active apparmor 2>/dev/null
else
  echo "  AppArmor tools not present (likely a SELinux distro)"
fi

echo ""
echo "[*] === GRUB cmdline: MAC disabled at boot? ==="
grep -oE "(selinux=0|apparmor=0|enforcing=0)" /proc/cmdline 2>/dev/null && \\
  echo "[FLAG] MAC disabled via kernel cmdline (persists)"
grep -hoE "(selinux=0|apparmor=0|enforcing=0)" /etc/default/grub /boot/grub*/grub.cfg 2>/dev/null | sort -u

echo ""
echo "[*] === Config file mtimes (recent edits) ==="
for f in /etc/selinux/config /etc/default/grub; do
  [ -e "$f" ] && echo "  $f | mtime=$(stat -c '%y' "$f")"
done
ls -la /etc/apparmor.d/disable/ 2>/dev/null | head

echo ""
echo "[*] === auditd: MAC status changes + config edits ==="
ausearch -m MAC_STATUS,MAC_CONFIG_CHANGE -i --start today 2>/dev/null | tail -15
ausearch -k selinux_config -i --start today 2>/dev/null | tail -10
ausearch -k setenforce_exec -i --start today 2>/dev/null | tail -10
ausearch -k apparmor_config -i --start today 2>/dev/null | tail -10`,
        registry: `SELinux / AppArmor disablement artifacts:

SELinux (RHEL/Fedora/CentOS family):
  Runtime state:  getenforce  -> Enforcing/Permissive/Disabled
  Live node:      /sys/fs/selinux/enforce  (1=enforce, 0=permissive)
  Persistent cfg: /etc/selinux/config  -> SELINUX=enforcing|permissive|disabled
  Disable methods:
    setenforce 0                     (runtime -> permissive)
    echo 0 > /sys/fs/selinux/enforce (runtime, direct)
    edit config SELINUX=disabled     (persists across reboot)
    GRUB: selinux=0 / enforcing=0    (kernel cmdline, strongest)
  Self-audit events: MAC_STATUS, MAC_CONFIG_CHANGE, MAC_POLICY_LOAD

AppArmor (Debian/Ubuntu/SUSE family):
  Runtime state:  aa-status / apparmor_status
  Disable methods:
    aa-teardown                      (unload all profiles)
    aa-complain /etc/apparmor.d/*    (complain = log not block)
    aa-disable <profile>             (disable specific profile)
    ln -s profile /etc/apparmor.d/disable/  (persistent disable)
    apparmor_parser -R <profile>     (remove from kernel)
    systemctl stop/disable apparmor
    GRUB: apparmor=0                 (kernel cmdline)

Why it matters:
  SELinux/AppArmor are CONTAINMENT - they limit what a
  compromised process can do even after code execution. An
  attacker disables MAC to remove confinement before escalating
  or persisting (e.g. to let a web process write outside its
  domain, or load a module). Permissive mode is sneaky: the
  system looks 'on' (getenforce != Disabled) but enforcement
  is off and only logging occurs.

High-signal indicators:
  getenforce = Permissive/Disabled on a host that should enforce
  /etc/selinux/config non-enforcing (persistence of the change)
  selinux=0 / apparmor=0 in /proc/cmdline (boot-level disable)
  AppArmor profiles flipped to complain mode
  setenforce 0 in history/auditd
  symlinks in /etc/apparmor.d/disable/
  MAC_STATUS audit event showing enforce -> permissive

Nuance - permissive vs disabled:
  Permissive still LOGS AVC denials (so it leaves a trail and
  preserves some forensic value), while Disabled produces no
  SELinux telemetry at all. An attacker choosing Disabled is
  more thorough; Permissive may be a lazier or reversible step.`,
        tools: `Disabling SELinux / AppArmor:

Mandatory Access Control (MAC) is a containment layer: even
after gaining code execution, a process is confined to what its
SELinux domain or AppArmor profile permits. Adversaries disable
MAC to break out of that confinement before escalating,
persisting, or loading kernel components.

SELinux:
  setenforce 0 is the one-liner - instantly drops to permissive.
  Editing /etc/selinux/config makes it survive reboot. The
  thorough move is SELINUX=disabled plus a GRUB selinux=0, which
  removes SELinux telemetry entirely. Permissive is a softer
  step that still logs denials (leaving evidence).

AppArmor:
  aa-teardown unloads everything; aa-complain flips profiles to
  log-only; symlinking into /etc/apparmor.d/disable/ persists.
  apparmor_parser -R surgically removes a single profile (e.g.
  just the one confining the service the attacker is abusing).

Why it is detectable:
  Both systems emit their own audit records on state change
  (SELinux MAC_STATUS / MAC_CONFIG_CHANGE). The runtime state
  is trivially queryable (getenforce / aa-status), so a simple
  scheduled posture check catches a host that has been flipped.
  And because MAC config lives in well-known files, FIM on
  /etc/selinux/config and /etc/apparmor.d/ flags tampering.

The OT/ICS angle:
  Many hardened/regulated Linux deployments mandate enforcing
  SELinux. A host dropping to permissive/disabled is both a
  security event AND a compliance violation - doubly worth
  alerting in those environments.

Threat actor use:
  setenforce 0 and AppArmor teardown appear broadly in Linux
  intrusion playbooks, especially where the next step needs
  filesystem or kernel access the MAC policy would block (web
  shell breakout, module loading, container escape prep).`,
        ossdetect: `Sigma rules:
- proc_creation_lnx_setenforce_permissive.yml
- file_event_lnx_selinux_config_disable.yml
- proc_creation_lnx_apparmor_teardown_disable.yml

Elastic detection rules:
- SELinux Set to Permissive or Disabled
- AppArmor Profile Disabled or Torn Down
- MAC Policy Disabled via GRUB

Auditd:
  -w /etc/selinux/config -p wa -k selinux_config
  -w /etc/apparmor.d/ -p wa -k apparmor_config
  -a always,exit -F arch=b64 -S execve -F path=/usr/sbin/setenforce -k setenforce_exec
  Watch message types MAC_STATUS, MAC_CONFIG_CHANGE.

Falco:
  rule: Set SELinux to permissive / disabled
  rule: Disable AppArmor profile

Posture monitoring (the simplest reliable control):
  Scheduled check: getenforce must == Enforcing;
  aa-status must show profiles in enforce mode.
  Alert on any deviation. Trivial and high-fidelity.

osquery:
  SELECT * FROM selinux_settings WHERE name='enforce';
  SELECT * FROM apparmor_profiles;   (mode column)
  Compare against required-enforcing baseline.

File integrity (FIM):
  /etc/selinux/config, /etc/default/grub, /etc/apparmor.d/disable/
  Alert on edits.

Compliance overlap:
  Map to CIS benchmarks (SELinux/AppArmor must be enforcing).
  In regulated/OT environments a flip is a compliance alert too.

Atomic Red Team:
  T1562.001 - includes setenforce / SELinux disable tests`,
        notes: "SELinux and AppArmor are mandatory access control layers that confine what a process can do even after an adversary gains code execution, so disabling them removes containment before the attacker escalates, persists, or loads kernel components. On SELinux systems the one-liner setenforce 0 instantly drops to permissive mode, editing /etc/selinux/config makes the change survive reboot, and the thorough approach combines SELINUX=disabled with a GRUB selinux=0 to remove SELinux telemetry entirely. On AppArmor systems aa-teardown unloads all profiles, aa-complain flips profiles to log-only, symlinking into /etc/apparmor.d/disable/ persists the change, and apparmor_parser -R surgically removes just the profile confining the service being abused. A useful nuance is the difference between permissive and disabled: permissive mode still logs AVC denials and preserves some forensic value, while disabled produces no telemetry at all, so an attacker choosing disabled is more thorough. These actions are highly detectable because both systems emit their own audit records on state change (SELinux MAC_STATUS and MAC_CONFIG_CHANGE), the runtime state is trivially queryable with getenforce or aa-status, and the config lives in well-known files suited to file integrity monitoring. The simplest reliable control is scheduled posture monitoring that asserts getenforce equals Enforcing and AppArmor profiles are in enforce mode, alerting on any deviation. In OT, ICS-adjacent, and other regulated Linux deployments that mandate enforcing MAC, a host dropping to permissive or disabled is simultaneously a security event and a compliance violation, making it doubly worth alerting.",
        apt: [
          { cls: "apt-mul", name: "Web-shell operators", note: "setenforce 0 used to break a web process out of its SELinux domain confinement before writing payloads or escalating." },
          { cls: "apt-mul", name: "Linux intrusion playbooks", note: "MAC disablement precedes steps needing filesystem or kernel access that an enforcing policy would block, including module loading and container escape prep." },
          { cls: "apt-mul", name: "Cryptomining crews", note: "SELinux/AppArmor neutralization alongside agent removal to clear containment before miner and persistence deployment." }
        ],
        cite: "MITRE ATT&CK T1562.001"
      }
    ]
  },
  {
    id: "T1562.004",
    name: "Impair Defenses: Disable or Modify System Firewall",
    desc: "Flushing or opening the host firewall (iptables -F, nft flush ruleset, ufw disable, default-ACCEPT, or targeted allow rules) to enable C2 egress, inbound shells, and lateral movement. The detection challenge is baselining out the constant legitimate churn from Docker/Kubernetes/fail2ban: alert on firewall changes parented by interactive shells, not container runtimes.",
    rows: [
      {
        sub: "T1562.004 - Disable or Modify System Firewall (iptables/nftables/ufw flush)",
        os: "linux",
        indicator: "Weakening host firewall to enable C2, lateral movement, or inbound access: iptables -F / nft flush ruleset to clear rules, setting default policies to ACCEPT, ufw disable / firewalld stop, or inserting permissive allow rules for an attacker port or IP",
        sysmon: `// Sysmon for Linux EID 1 - host firewall tampering

// Flushing all rules (open the host)
Image=*/iptables CommandLine matches: *-F*  *--flush*  *-X*
Image=*/ip6tables CommandLine matches: *-F*  *--flush*
Image=*/nft CommandLine matches: *flush ruleset*  *flush table*

// Setting permissive default policy
Image=*/iptables CommandLine matches: *-P INPUT ACCEPT*  *-P FORWARD ACCEPT*

// Disabling firewall front-ends
Image=*/ufw CommandLine matches: *disable*
Image=(*/systemctl OR */service) CommandLine matches:
  *stop firewalld*  *disable firewalld*  *stop ufw*  *stop nftables*
Image=*/firewall-cmd CommandLine matches: *--panic-off*  *--set-default-zone=trusted*

// Inserting a targeted allow rule (attacker port/IP)
Image=*/iptables CommandLine matches:
  *-A INPUT*ACCEPT*  *-I INPUT*ACCEPT*  *--dport*ACCEPT*
Image=*/nft CommandLine matches: *add rule*accept*

// Auditd
-w /etc/sysconfig/iptables -p wa -k fw_config
-w /etc/nftables.conf -p wa -k fw_config
-a always,exit -F arch=b64 -S execve -F path=/usr/sbin/iptables -k iptables_exec
-a always,exit -F arch=b64 -S execve -F path=/usr/sbin/nft -k nft_exec`,
        kibana: `// Flushing firewall rules
process.name: ("iptables" OR "ip6tables")
AND process.command_line: (*"-F"* OR *--flush* OR *"-X"*)

process.name: "nft"
AND process.command_line: (*"flush ruleset"* OR *"flush table"*)

// Permissive default policy
process.name: "iptables"
AND process.command_line: (*"-P INPUT ACCEPT"* OR *"-P FORWARD ACCEPT"*)

// Disabling firewall services / front-ends
process.command_line: (
  *"ufw disable"* OR *"stop firewalld"* OR *"disable firewalld"*
  OR *"stop nftables"* OR *"--panic-off"* OR *"--set-default-zone=trusted"*
)

// Targeted allow-rule insertion
process.name: ("iptables" OR "nft")
AND process.command_line: ((*-A* OR *-I* OR *"add rule"*) AND *ACCEPT*) 
AND process.command_line: (*dport* OR *sport*)

// Auditd
event.module: "auditd"
AND tags: ("fw_config" OR "iptables_exec" OR "nft_exec")
AND NOT process.parent.name: ("firewalld" OR "ufw" OR "docker" OR "kube-proxy" OR "fail2ban")
// NOTE: docker/k8s/fail2ban legitimately churn iptables - baseline them out`,
        powershell: `#!/bin/bash
# T1562.004 - Host firewall tampering hunt

echo "[*] === Active firewall backend + state ==="
# Detect which backend is in use
if command -v nft >/dev/null 2>&1 && nft list ruleset >/dev/null 2>&1; then
  echo "  nftables ruleset (line count): $(nft list ruleset 2>/dev/null | wc -l)"
  [ "$(nft list ruleset 2>/dev/null | wc -l)" -lt 3 ] && echo "[FLAG] nftables ruleset is essentially EMPTY"
fi
echo "  iptables INPUT policy + rule count:"
iptables -L INPUT -n 2>/dev/null | head -1
ipc=$(iptables -S 2>/dev/null | grep -c "^-A")
echo "    iptables rules: $ipc"
iptables -S 2>/dev/null | grep -E "^-P (INPUT|FORWARD) ACCEPT" && echo "[FLAG] default policy ACCEPT (open)"

echo ""
echo "[*] === Firewall front-end service states ==="
for svc in firewalld ufw nftables iptables; do
  st=$(systemctl is-active "$svc" 2>/dev/null)
  [ "$st" = "unknown" ] && continue
  echo "  $svc: $st"
  [ "$st" = "inactive" ] || [ "$st" = "dead" ] && echo "[FLAG] $svc not active"
done
command -v ufw >/dev/null 2>&1 && { echo "  ufw status:"; ufw status 2>/dev/null | head -1; }

echo ""
echo "[*] === Suspicious permissive allow rules (attacker ports) ==="
iptables -S 2>/dev/null | grep ACCEPT | grep -E "dport (4444|1337|31337|6666|8080|9001|53|443)" 
nft list ruleset 2>/dev/null | grep -iE "accept" | grep -E "4444|1337|31337|6666" 
echo "  (review any ACCEPT for high/odd ports or specific source IPs)"

echo ""
echo "[*] === Firewall config file integrity ==="
for f in /etc/sysconfig/iptables /etc/nftables.conf /etc/ufw/user.rules; do
  [ -e "$f" ] && echo "  $f | mtime=$(stat -c '%y' "$f")"
done

echo ""
echo "[*] === Recent firewall changes in journal/auditd ==="
journalctl --since today 2>/dev/null | grep -iE "firewalld|ufw" | grep -iE "stop|disable|reload" | tail -10
ausearch -k iptables_exec -i --start today 2>/dev/null | \\
  grep -ivE "ppid.*(docker|firewalld|fail2ban)" | grep -E "\\-F|ACCEPT|\\-P " | tail -15
ausearch -k fw_config -i --start today 2>/dev/null | tail -10

echo ""
echo "[*] === Correlate: new listening ports after a firewall change ==="
ss -tlnp 2>/dev/null | awk 'NR>1{print $4}' | sort -u | tail -20
echo "  (a new listener + a fresh ACCEPT rule for its port = inbound access enabled)"
`,
        registry: `Host firewall tampering artifacts:

Linux firewall backends/front-ends:
  iptables / ip6tables   - classic netfilter front-end
  nftables (nft)         - modern replacement
  firewalld              - RHEL/Fedora dynamic front-end
  ufw                    - Ubuntu/Debian simple front-end
  (note: ufw and firewalld ultimately program nft/iptables)

Config persistence files:
  /etc/sysconfig/iptables , /etc/sysconfig/ip6tables  (RHEL save)
  /etc/nftables.conf , /etc/sysconfig/nftables.conf
  /etc/ufw/*.rules , /etc/ufw/ufw.conf
  /etc/firewalld/zones/*.xml

Tampering techniques:
  iptables -F ; iptables -X        - flush all rules/chains
  iptables -P INPUT ACCEPT         - default = allow everything
  nft flush ruleset                - wipe nftables entirely
  ufw disable                      - turn ufw off
  systemctl stop/disable firewalld - stop the front-end
  firewall-cmd --set-default-zone=trusted  - allow-all zone
  iptables -I INPUT -p tcp --dport <X> -j ACCEPT  - punch a hole
  nft add rule ... accept          - targeted allow

Intent matters - two distinct goals:
  WIDE OPEN (flush / default ACCEPT): enable C2 egress,
    inbound shells, lateral movement broadly.
  TARGETED HOLE (single allow rule): quietly permit one
    attacker port or source IP while the firewall still
    'looks' configured. Stealthier; review individual rules.

The baseline-noise problem (important):
  Docker, Kubernetes (kube-proxy), libvirt, fail2ban, and
  firewalld itself CONSTANTLY rewrite iptables/nft rules as
  normal operation. Detection MUST baseline these out by
  parent process, or it drowns in false positives. Focus on
  iptables/nft invoked by an INTERACTIVE shell (bash/ssh
  parent), not by a container runtime.

High-signal indicators:
  default policy ACCEPT on INPUT/FORWARD where it should DROP
  empty/near-empty ruleset on a host that should be filtered
  firewall service stopped/disabled
  an ACCEPT rule for an odd/high port (4444, 1337, 31337...)
  iptables -F / nft flush from a bash/ssh parent (not a runtime)
  firewall config file edited outside change control
  a new listening socket whose port matches a fresh ACCEPT rule`,
        tools: `Disabling / modifying the host firewall:

Adversaries weaken the local firewall to enable command-and-
control egress, accept inbound reverse/bind shells, or open
lateral-movement paths. The action divides into two intents
that call for different detection emphasis.

Wide-open (flush / accept-all):
  iptables -F, nft flush ruleset, ufw disable, or default
  policy ACCEPT. Maximally permissive, maximally noisy. Easy to
  spot via a posture check (empty ruleset / ACCEPT default).

Targeted hole (surgical allow):
  A single inserted ACCEPT for the attacker's port or source IP.
  The firewall still appears configured, so this evades a
  coarse 'is the firewall on?' check. Catching it requires
  reviewing individual rules for anomalies - unexpected ports,
  specific external source IPs, or rules out of change control.

The central detection challenge - legitimate churn:
  On modern Linux, iptables/nft are rewritten constantly by
  Docker, Kubernetes kube-proxy, libvirt, podman, and fail2ban.
  Naive alerting on 'iptables executed' is unusable. The
  reliable signal is PROVENANCE: firewall changes whose parent
  is an interactive shell (bash/sh/ssh) or an unexpected
  process, NOT a container/orchestration runtime. Baseline the
  runtimes, alert on the humans.

Defender leverage:
  Firewall posture is cheap to assert periodically (rule count,
  default policy, service state). Config files are FIM targets.
  And the OUTCOME often betrays the change: a new listening
  socket appearing together with a fresh ACCEPT for its port
  ties firewall tampering to the access it enabled.

Threat actor use:
  Firewall flushing/opening appears across Linux intrusions to
  enable miners' pool egress, backdoor inbound, and lateral
  movement. It frequently co-occurs with the rest of the T1562
  cluster (disabling agents/MAC) as part of 'clearing the way.'`,
        ossdetect: `Sigma rules:
- proc_creation_lnx_iptables_flush_disable.yml
- proc_creation_lnx_nft_flush_ruleset.yml
- proc_creation_lnx_ufw_firewalld_disable.yml

Elastic detection rules:
- Host Firewall Rules Flushed
- Firewall Service Stopped or Disabled
- Permissive Firewall Rule Added

Auditd:
  -w /etc/sysconfig/iptables -p wa -k fw_config
  -w /etc/nftables.conf -p wa -k fw_config
  -a always,exit -F arch=b64 -S execve -F path=/usr/sbin/iptables -k iptables_exec
  -a always,exit -F arch=b64 -S execve -F path=/usr/sbin/nft -k nft_exec
  CRITICAL: filter out ppid of docker/containerd/kube-proxy/fail2ban

Falco:
  rule: Modify Firewall Rules / Flush iptables
  rule: Disable Firewall Service
  (Falco can scope by proc.pname to exclude container runtimes)

Posture monitoring:
  Periodic assert: default INPUT policy == DROP/REJECT;
  rule count >= baseline; firewalld/ufw service active.
  Diff current ruleset against a golden ruleset hash.

osquery:
  SELECT * FROM iptables;          (full rule inventory)
  Snapshot + diff; alert on default-accept or rule-count drop.

Correlation (high value):
  Join firewall-change events with new listening sockets
  (SELECT * FROM listening_ports). A new listener + matching
  new ACCEPT = inbound access deliberately enabled.

Atomic Red Team:
  T1562.004 - disable/modify system firewall tests`,
        notes: "Adversaries weaken the host firewall to enable command-and-control egress, accept inbound reverse or bind shells, or open lateral-movement paths, and the action divides into two intents that call for different detection emphasis. The wide-open approach (iptables -F, nft flush ruleset, ufw disable, or default policy ACCEPT) is maximally permissive and noisy, easily caught by a posture check that asserts the default INPUT policy is DROP and the ruleset is non-empty. The targeted-hole approach inserts a single ACCEPT for the attacker's port or source IP, leaving the firewall apparently configured so it evades a coarse is-the-firewall-on check, and catching it requires reviewing individual rules for anomalies like odd high ports (4444, 1337, 31337) or specific external source IPs. The central detection challenge on modern Linux is legitimate churn: Docker, Kubernetes kube-proxy, libvirt, podman, and fail2ban rewrite iptables and nftables rules constantly as normal operation, so naive alerting on iptables execution is unusable. The reliable signal is provenance, meaning firewall changes whose parent process is an interactive shell or an unexpected process rather than a container or orchestration runtime, so the practical rule is to baseline the runtimes out and alert on the humans. Firewall posture is cheap to assert periodically, config files are good FIM targets, and the outcome often betrays the change because a new listening socket appearing together with a fresh ACCEPT rule for its port ties the firewall tampering directly to the access it enabled. Firewall opening frequently co-occurs with the rest of the T1562 cluster as part of clearing the way for a payload.",
        apt: [
          { cls: "apt-mul", name: "Cryptomining crews", note: "Firewall rules flushed or opened to permit mining-pool egress and inbound management of compromised Linux hosts." },
          { cls: "apt-mul", name: "Backdoor operators", note: "Targeted ACCEPT rules inserted for specific attacker ports to permit inbound reverse/bind shell access while the firewall appears configured." },
          { cls: "apt-mul", name: "Lateral-movement actors", note: "Default-ACCEPT policy or ruleset flush used to remove host-based filtering ahead of internal pivoting." }
        ],
        cite: "MITRE ATT&CK T1562.004"
      }
    ]
  },
  {
    id: "T1562.006",
    name: "Impair Defenses: Indicator Blocking",
    desc: "Suppressing telemetry generation or egress rather than deleting existing logs: stopping rsyslog/syslog-ng, stripping remote-forwarding directives, disabling audisp-remote, or blocking the collector via firewall/DNS/hosts. Ingestion-gap (source-silence) alerting on the collector side is the primary control, catching suppression regardless of method from infrastructure the attacker cannot reach.",
    rows: [
      {
        sub: "T1562.006 - Indicator Blocking (rsyslog/syslog tampering, remote log disruption)",
        os: "linux",
        indicator: "Suppressing telemetry generation or its egress rather than deleting existing logs: stopping or reconfiguring rsyslog/syslog-ng, removing remote-forwarding directives, blocking the log collector by firewall/DNS, disabling audisp-remote, or neutering a logging service so events are never recorded or never leave the host",
        sysmon: `// Sysmon for Linux EID 1 - indicator blocking (telemetry suppression)
// Distinct from T1070 (deleting logs that EXIST): here the goal is
// to PREVENT events being recorded or SHIPPED in the first place.

// Stopping / disabling the logging daemons
Image=(*/systemctl OR */service) CommandLine matches:
  *stop rsyslog*  *disable rsyslog*  *mask rsyslog*
  *stop syslog-ng*  *stop systemd-journald*  (journald is socket-
    activated; masking/altering is the tell)
Image=(*/kill OR */pkill) CommandLine matches: *rsyslog*  *syslog-ng*

// Editing logging config to break forwarding / drop facilities
Image=(*/vi OR */vim OR */nano OR */sed OR */tee) CommandLine matches:
  */etc/rsyslog.conf*  */etc/rsyslog.d/*  */etc/syslog-ng/*
  */etc/systemd/journald.conf*
// Watch for removal of @@remote / action(omfwd) forwarding lines,
// or Storage=none / ForwardToSyslog=no in journald.conf

// Disabling audit remote forwarding (pairs with T1562.012)
Image=(*/sed OR */tee) CommandLine matches: */etc/audit/audisp-remote.conf*
CommandLine matches: *active = no*  (audisp-remote disabled)

// Blocking the collector at the network layer
Image=*/iptables CommandLine matches: *-A OUTPUT*-j DROP* with the
  SIEM/collector IP or syslog port (514/6514)
Image=(*/tee OR */sed) CommandLine matches: */etc/hosts*  (poisoning
  the collector hostname to a dead IP)

// Auditd
-w /etc/rsyslog.conf -p wa -k log_config
-w /etc/rsyslog.d/ -p wa -k log_config
-w /etc/systemd/journald.conf -p wa -k log_config
-w /etc/audit/audisp-remote.conf -p wa -k audisp_config
-w /etc/hosts -p wa -k hosts_tamper`,
        kibana: `// Stopping/disabling logging daemons
process.command_line: (
  (*stop* OR *disable* OR *mask*) AND (*rsyslog* OR *syslog-ng*)
  OR ((*kill* OR *pkill*) AND (*rsyslog* OR *syslog-ng*))
)

// Editing logging configuration
process.name: ("vi" OR "vim" OR "nano" OR "sed" OR "tee")
AND process.command_line: (
  */etc/rsyslog* OR */etc/syslog-ng* OR */etc/systemd/journald.conf*
  OR */etc/audit/audisp-remote.conf*
)

// /etc/hosts tampering (poison the collector name)
process.name: ("sed" OR "tee" OR "vi" OR "vim")
AND process.command_line: */etc/hosts*

// Firewall DROP to the log collector port
process.name: "iptables"
AND process.command_line: (*OUTPUT* AND *DROP* AND (*514* OR *6514*))

// Auditd
event.module: "auditd"
AND tags: ("log_config" OR "audisp_config" OR "hosts_tamper")
AND NOT process.name: ("dpkg" OR "rpm" OR "ansible" OR "puppet" OR "chef-client")

// THE outcome signal (most reliable, SIEM-side):
// a host that was forwarding logs/audit STOPS arriving at the
// collector while still being reachable -> ingestion gap alert.
// Mirror of the auditd-EPS-gap idea, applied to syslog ingest.`,
        powershell: `#!/bin/bash
# T1562.006 - Indicator blocking / telemetry suppression hunt

echo "[*] === Logging daemons: running + enabled? ==="
for svc in rsyslog syslog-ng systemd-journald auditd; do
  st=$(systemctl is-active "$svc" 2>/dev/null)
  en=$(systemctl is-enabled "$svc" 2>/dev/null)
  [ "$st" = "unknown" ] && [ -z "$en" ] && continue
  flag=""; [ "$st" != "active" ] && flag="  <-- NOT ACTIVE"
  [ "$en" = "masked" ] && flag="  <-- MASKED"
  echo "  $svc: active=$st enabled=$en$flag"
done

echo ""
echo "[*] === Remote forwarding still configured? (rsyslog) ==="
fwd=$(grep -rhE "^\\*\\.\\*\\s+@@?|action\\(.*omfwd|Target=|@@?[0-9a-zA-Z]" \\
  /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null | grep -v "^#")
if [ -n "$fwd" ]; then echo "$fwd"; else echo "[FLAG] no rsyslog remote-forwarding directive found"; fi

echo ""
echo "[*] === syslog-ng destinations ==="
grep -rhE "destination|network\\(|tcp\\(|udp\\(" /etc/syslog-ng/ 2>/dev/null | grep -v "^#" | head -10

echo ""
echo "[*] === journald.conf: storage + forwarding neutered? ==="
grep -E "^(Storage|ForwardToSyslog|ForwardToWall|MaxRetentionSec|SystemMaxUse)" \\
  /etc/systemd/journald.conf 2>/dev/null
grep -qE "^Storage=none" /etc/systemd/journald.conf 2>/dev/null && echo "[FLAG] journald Storage=none (volatile only)"
grep -qE "^ForwardToSyslog=no" /etc/systemd/journald.conf 2>/dev/null && echo "  note: not forwarding to syslog"

echo ""
echo "[*] === audit remote forwarding (audisp-remote) ==="
grep -E "^(active|remote_server|port)" /etc/audit/audisp-remote.conf \\
  /etc/audisp/plugins.d/au-remote.conf /etc/audit/plugins.d/au-remote.conf 2>/dev/null
grep -qE "^active = no" /etc/audit/audisp-remote.conf 2>/dev/null && echo "[FLAG] audisp-remote DISABLED (audit not shipping off-box)"

echo ""
echo "[*] === /etc/hosts: collector hostname poisoned? ==="
echo "  recent /etc/hosts mtime: $(stat -c '%y' /etc/hosts 2>/dev/null)"
cat /etc/hosts 2>/dev/null | grep -vE "^#|^$" | tail -15
echo "  (check if your SIEM/collector name resolves to 127.0.0.1 or a dead IP)"

echo ""
echo "[*] === Firewall egress block to collector ports (514/6514) ==="
iptables -S OUTPUT 2>/dev/null | grep -E "514|6514" | grep -i drop && echo "[FLAG] egress to syslog port DROPped"

echo ""
echo "[*] === Config mtimes + recent edits (auditd) ==="
for f in /etc/rsyslog.conf /etc/systemd/journald.conf /etc/audit/audisp-remote.conf /etc/hosts; do
  [ -e "$f" ] && echo "  $f | mtime=$(stat -c '%y' "$f")"
done
ausearch -k log_config -i --start today 2>/dev/null | grep -ivE "comm=.(dpkg|rpm|ansible|puppet)" | tail -15
ausearch -k audisp_config -i --start today 2>/dev/null | tail -8`,
        registry: `Indicator blocking / telemetry suppression artifacts:

The distinction from T1070 (Indicator Removal):
  T1070 DELETES events that were already recorded.
  T1562.006 prevents events from being RECORDED or from
  LEAVING the host. It is upstream of deletion - if telemetry
  never reaches the SIEM, there is nothing to delete or detect.
  The two are often combined: suppress future logging, then
  wipe what already exists.

Suppression points and their artifacts:
  Logging daemons:
    systemctl stop/disable/mask rsyslog | syslog-ng
    kill/pkill the daemon
    -> local syslog files stop growing
  Config neutering:
    /etc/rsyslog.conf , /etc/rsyslog.d/*  - remove forwarding
      (@@collector:514 / action(type="omfwd")) or drop facilities
    /etc/syslog-ng/syslog-ng.conf - remove network destination
    /etc/systemd/journald.conf:
      Storage=none      (journal volatile/none)
      ForwardToSyslog=no
      SystemMaxUse tiny (rapid rollover discards events)
  Audit forwarding (pairs with T1562.012):
    /etc/audit/audisp-remote.conf  active = no
    -> auditd still runs locally but ships nothing off-box
  Network-layer blocking (telemetry generated, never delivered):
    iptables -A OUTPUT -d <collector> -j DROP
    /etc/hosts: point the collector hostname at 127.0.0.1 / dead IP
    DNS tampering so the collector FQDN fails to resolve

High-signal indicators:
  rsyslog/syslog-ng stopped, disabled, or masked
  forwarding directive REMOVED from rsyslog config (diff vs baseline)
  journald Storage=none or forwarding disabled
  audisp-remote active = no
  /etc/hosts entry mapping the SIEM/collector to a bogus IP
  OUTPUT DROP rule targeting syslog ports 514/6514
  config files edited outside change management (mtime, auditd)

THE outcome detection (most reliable):
  Ingestion-gap alerting: the SIEM/collector notices a host
  that WAS forwarding logs has gone silent while still being
  reachable (ping/heartbeat/other indices continue). This
  catches suppression no matter which point the attacker hit,
  and it fires from infrastructure the attacker cannot reach.

The pairing with T1562.012:
  Disabling auditd (T1562.012) + breaking log forwarding
  (T1562.006) together = comprehensive host blinding. Hunt for
  the combination; either alone is bad, both is an emergency.`,
        tools: `Indicator blocking (telemetry suppression):

Where log clearing (T1070) is reactive cleanup of evidence that
exists, indicator blocking is proactive: stop the host from
generating or shipping telemetry so the evidence never forms.
A sophisticated operator prefers this - there is nothing to
recover if it was never written or never sent.

The suppression chain, from local to network:
  1. Kill/disable the logging daemon (rsyslog/syslog-ng) -
     local logs stop.
  2. Strip the FORWARDING directive while leaving the daemon
     up - logs still write locally (looks normal) but nothing
     reaches the SIEM. Subtle and effective.
  3. Disable audisp-remote - auditd keeps running, console
     sees a healthy daemon, but audit events never leave.
  4. Network block - DROP egress to the collector, or poison
     /etc/hosts/DNS for the collector name. Telemetry is
     generated and even queued, but never delivered.

Why the SIEM still wins (ingestion-gap detection):
  Every one of these methods produces the same observable on
  the collector side: a host that used to send data stops
  sending it. An ingestion-gap / source-silence rule -
  'expected source X has sent nothing for N minutes while
  still reachable' - catches all of them, regardless of the
  technique, from infrastructure the attacker cannot touch.
  This is the indicator-blocking analogue of the auditd EPS
  gap, and it is the single most important control here.

The combined-blinding pattern:
  T1562.006 (break forwarding) + T1562.012 (disable auditd) +
  T1070.002 (wipe local logs) is the full anti-telemetry stack.
  Detecting the FORWARDING break early - before local wipe -
  preserves the off-box copy that solves the case.

Threat actor use:
  Reconfiguring or stopping log forwarding to evade central
  monitoring is documented in targeted Linux intrusions,
  particularly stealth-oriented operators who expect a SIEM and
  deliberately sever the host from it. Often paired with hosts-
  file or DNS manipulation to silently break collector delivery.`,
        ossdetect: `Sigma rules:
- proc_creation_lnx_stop_disable_rsyslog.yml
- file_event_lnx_rsyslog_forwarding_removed.yml
- file_event_lnx_journald_storage_none.yml
- file_event_lnx_audisp_remote_disabled.yml
- file_event_lnx_hosts_collector_poison.yml

Elastic detection rules:
- Logging Service Stopped or Disabled
- Remote Log Forwarding Configuration Removed
- Tampering with /etc/hosts (collector redirection)

Auditd:
  -w /etc/rsyslog.conf -p wa -k log_config
  -w /etc/rsyslog.d/ -p wa -k log_config
  -w /etc/systemd/journald.conf -p wa -k log_config
  -w /etc/audit/audisp-remote.conf -p wa -k audisp_config
  -w /etc/hosts -p wa -k hosts_tamper

Falco:
  rule: Stop or disable logging service
  rule: Modify syslog/journald configuration
  rule: Modify /etc/hosts

THE primary control - ingestion-gap / source-silence alerting:
  SIEM rule: alert when a known log source (per-host) stops
  arriving while the host remains reachable. Independent of the
  suppression method and unreachable by the host attacker.
  Pair with auditd-EPS-gap (T1562.012) for full coverage.

Config-as-code / drift detection:
  Manage rsyslog/journald/audisp configs via Ansible/Puppet;
  alert on any out-of-band change (the agent reverts + reports).
  chattr +i on forwarding configs to resist edits.

osquery:
  SELECT * FROM augeas WHERE path LIKE '/etc/rsyslog%';
  SELECT * FROM etc_hosts;   (collector poisoning)
  SELECT * FROM services WHERE name IN ('rsyslog','syslog-ng');

Atomic Red Team:
  T1562.006 - indicator blocking tests`,
        notes: "Indicator blocking is the proactive counterpart to log clearing: where T1070 reactively deletes evidence that already exists, T1562.006 stops the host from generating or shipping telemetry so the evidence never forms, which a sophisticated operator prefers because there is nothing to recover if it was never written or never sent. The suppression chain runs from local to network: killing or disabling the logging daemon stops local logs; stripping only the forwarding directive while leaving the daemon running is subtler because logs still write locally and look normal but nothing reaches the SIEM; disabling audisp-remote keeps auditd running and apparently healthy while audit events never leave the host; and network-layer blocking via an egress DROP to the collector or poisoning the collector's name in /etc/hosts or DNS means telemetry is generated and even queued but never delivered. The decisive control is ingestion-gap detection, because every one of these methods produces the same observable on the collector side, namely a host that used to send data stops sending it, so a source-silence rule that alerts when an expected source has sent nothing for a defined interval while still being reachable catches all of them regardless of technique and fires from infrastructure the attacker cannot touch. This is the indicator-blocking analogue of the auditd events-per-second gap, and detecting the forwarding break early, before any local wipe, preserves the off-box copy that solves the case. The full anti-telemetry stack combines T1562.006 (break forwarding), T1562.012 (disable auditd), and T1070.002 (wipe local logs), so detecting the forwarding break is the highest-leverage early intervention, and managing logging configuration as code with drift detection or chattr +i immutability resists the edits in the first place.",
        apt: [
          { cls: "apt-mul", name: "Stealth operators", note: "Severing host-to-SIEM log forwarding to evade central monitoring while leaving local logging apparently healthy; documented in targeted Linux intrusions." },
          { cls: "apt-mul", name: "Anti-telemetry actors", note: "Combine forwarding breakage, auditd disable, and local log wipe for comprehensive host blinding before further operations." },
          { cls: "apt-mul", name: "Collector-evasion actors", note: "/etc/hosts and DNS manipulation used to silently break delivery to the log collector while telemetry appears to be generated." }
        ],
        cite: "MITRE ATT&CK T1562.006"
      }
    ]
  }
];
