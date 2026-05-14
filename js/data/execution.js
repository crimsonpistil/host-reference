// TA0002 - Execution
// 13 techniques planned · ~32 indicators total when complete
// Currently built: T1059.001 (4 indicators)
// Other 12 techniques stubbed - see widgets in build session for headline indicators

const DATA = [
  {
    id: "T1059.001",
    name: "Command and Scripting Interpreter: PowerShell",
    desc: "Encoded commands, suspicious parents, in-memory IEX patterns, ExecutionPolicy bypass - the full PS detection stack",
    rows: [
      {
        sub: "T1059.001 - Encoded Command Execution",
        indicator: "powershell.exe with -EncodedCommand argument - base64-obfuscated payload",
        sysmon: `EventID=1
Image=*\\powershell.exe
CommandLine=*-enc*
  OR *-EncodedCommand*
  OR *-e *
  OR *-ec *`,
        kibana: `winlog.event_id: 1
AND process.name: "powershell.exe"
AND process.command_line: (*-enc* OR *-EncodedCommand* OR *-e\\ * OR *-ec\\ *)`,
        powershell: `Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=1
} | Where-Object {
  $_.Properties[4].Value -like '*powershell*' -and
  $_.Properties[10].Value -match '-e(nc|ncodedcommand)?\\s'
} | Select TimeCreated,
  @{n='CmdLine';e={$_.Properties[10].Value}}`,
        registry: `No persistent artifact unless the -EncodedCommand
payload writes to disk or registry on execution.

Investigation pivots:
- Decode the base64 payload (visible in CommandLine field)
- Check parent process for context - Office/Outlook/Acrobat
  spawning powershell with -enc is highly suspicious
- Look for outbound network connections from the PowerShell
  process (Sysmon EID 3) within the same session
- Check ScriptBlockLogging Event 4104 for the decoded
  script content if logging is enabled`,
        tools: `Cobalt Strike (default PS stagers)
Empire / Starkiller
Nishang
PoshC2
Sliver (PowerShell stagers)
Custom loaders
Manual operators

Note: Microsoft Defender, AMSI, and most EDRs flag
encoded commands by default. Adversaries who still
use them are typically operating against environments
with weaker host telemetry, or are using additional
obfuscation (string concatenation, format operators)
that defeats AMSI string matching.`,
        ossdetect: `Sigma:
- proc_creation_win_powershell_encoded_command.yml
- proc_creation_win_powershell_b64_encoded.yml

Atomic Red Team:
- T1059.001 (multiple atomic tests covering encoded execution)

Hayabusa:
- Multiple PowerShell-encoded rules in default ruleset

Velociraptor artifacts:
- Windows.Detection.PowerShell.EncodedCommand
- Windows.System.Powershell.PSReadline (history forensics)

YARA:
- Florian Roth's signature-base PowerShell rules`,
        notes: "Encoded PowerShell remains the most common adversary execution method even in 2026 because it (a) defeats simple keyword-matching detection, (b) handles arbitrary script content including special characters, and (c) is built into PowerShell itself with no additional tooling. Detection sweet spot: combine the -EncodedCommand arg with parent-process context. Office app spawning powershell -enc = high-confidence phish chain. Service spawning powershell -enc = potential persistence. svchost spawning powershell -enc = likely WMI-based execution. The encoded payload itself is base64; decoding requires UTF-16LE encoding (not ASCII) - a common pitfall in incident response.",
        apt: [
          { cls: "apt-mul", name: "Red Team", note: "Universal in Cobalt Strike, Empire, and most C2 framework default stagers." },
          { cls: "apt-mul", name: "Ransomware", note: "Universal across modern ransomware affiliate operations for staging." },
          { cls: "apt-ru", name: "APT29", note: "Encoded PowerShell extensively used in SolarWinds and ongoing operations." },
          { cls: "apt-kp", name: "Lazarus", note: "Encoded PowerShell stagers in cryptocurrency-targeted operations." },
          { cls: "apt-cn", name: "APT41", note: "Documented in operations against tech sector." },
          { cls: "apt-mul", name: "Multi", note: "Documented across virtually all modern operations using PowerShell." }
        ],
        cite: "MITRE ATT&CK T1059.001"
      },
      {
        sub: "T1059.001 - Suspicious Parent Process",
        indicator: "powershell.exe spawned by Office, Adobe, or other unusual parent - phishing chain indicator",
        sysmon: `EventID=1
Image=*\\powershell.exe
ParentImage=
  *\\winword.exe
  OR *\\excel.exe
  OR *\\powerpnt.exe
  OR *\\outlook.exe
  OR *\\acrord32.exe
  OR *\\acrobat.exe
  OR *\\mshta.exe
  OR *\\wmiprvse.exe
  OR *\\wscript.exe
  OR *\\cscript.exe`,
        kibana: `winlog.event_id: 1
AND process.name: "powershell.exe"
AND process.parent.name: ("winword.exe" OR "excel.exe" OR "powerpnt.exe" OR "outlook.exe" OR "acrord32.exe" OR "acrobat.exe" OR "mshta.exe" OR "wmiprvse.exe")`,
        powershell: `Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=1
} | Where-Object {
  $_.Properties[4].Value -match 'powershell' -and
  $_.Properties[20].Value -match
    'winword|excel|powerpnt|outlook|acrord32|acrobat|mshta|wmiprvse'
} | Select TimeCreated,
  @{n='Parent';e={$_.Properties[20].Value}},
  @{n='Child';e={$_.Properties[4].Value}},
  @{n='CmdLine';e={$_.Properties[10].Value}}`,
        registry: `Office macro artifacts:
- %APPDATA%\\Microsoft\\Templates\\*.dotm
- %APPDATA%\\Microsoft\\Word\\STARTUP\\*.dotm
- %APPDATA%\\Microsoft\\Excel\\XLSTART\\*.xlsm

Outlook attachment cache:
- %TEMP%\\Outlook Logging\\
- %APPDATA%\\Local\\Microsoft\\Windows\\INetCache\\
  Content.Outlook\\

PowerShell history (if not cleared):
- %APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\
  ConsoleHost_history.txt

Acrobat artifacts:
- %APPDATA%\\Adobe\\Acrobat\\<version>\\Cache\\`,
        tools: `Phishing operators (universal)
Malicious document loaders (Emotet, IcedID, QakBot history)
Malicious PDFs with embedded scripts
HTA droppers
Macro-based loaders (despite MOTW mitigations)
ISO/IMG/ONE container chains (post-MOTW evasion)

Modern observation: Microsoft's "Mark of the Web"
mitigations broke macro-based phishing in 2022.
Adversaries pivoted to ISO/IMG containers (no MOTW),
LNK files, and OneNote (.one) files. The parent-spawn
pattern still holds - just check additional parents.`,
        ossdetect: `Sigma:
- proc_creation_win_office_outlook_spawn_susp.yml
- proc_creation_win_office_susp_child.yml
- Many variants per Office app

Atomic Red Team:
- T1566.001 (phishing - linked technique)
- Various tests reproduce Office→PowerShell chain

Hayabusa:
- SuspParentChild rules in default ruleset
- Office spawn detection rules

Velociraptor:
- Windows.Detection.OfficeSpawn

EDR queries (CrowdStrike/Defender example):
event_simpleName=ProcessRollup2
ParentBaseFileName IN ("WINWORD.EXE","EXCEL.EXE",
  "POWERPNT.EXE","OUTLOOK.EXE","AcroRd32.exe")
ImageFileName IN ("powershell.exe","cmd.exe")`,
        notes: "Office-spawning-PowerShell is one of the highest-fidelity initial-access detections in modern environments. The technique pre-dates ATT&CK itself - 'macro spawns shell' has been a phishing detection target for over a decade. Modern phishing increasingly uses container-types (ISO/IMG/ONE) to bypass MOTW, but the ultimate execution still goes through PowerShell or CMD eventually. Tune by user role: developers and admins legitimately spawn PowerShell from various contexts; finance/HR/sales users almost never do, especially from Office apps. Pair with: outbound network connections in the PowerShell child process, file writes to %TEMP% / %APPDATA%, subsequent persistence creation (scheduled tasks, registry run keys).",
        apt: [
          { cls: "apt-mul", name: "Phishing", note: "Universal in phishing-based initial access operations." },
          { cls: "apt-mul", name: "Initial Access", note: "Standard pattern across initial access broker operations." },
          { cls: "apt-ru", name: "APT28", note: "Office-based phishing extensively documented." },
          { cls: "apt-kp", name: "Lazarus", note: "Office and HWP-based phishing in operations against South Korea and Japan." },
          { cls: "apt-mul", name: "Ransomware", note: "Standard phishing→PowerShell chain in many ransomware affiliate operations." },
          { cls: "apt-mul", name: "Multi", note: "Documented across virtually all phishing-based operations targeting Windows endpoints." }
        ],
        cite: "MITRE ATT&CK T1059.001, T1566.001"
      },
      {
        sub: "T1059.001 - Suspicious ScriptBlock Content",
        indicator: "PowerShell ScriptBlock containing IEX/DownloadString/Invoke-Expression - fileless execution patterns",
        sysmon: `[ScriptBlockLogging required - separate event channel]
EventID=4104 in
Microsoft-Windows-PowerShell/Operational
ScriptBlockText contains:
  IEX OR Invoke-Expression
  OR DownloadString
  OR Net.WebClient
  OR FromBase64String
  OR DownloadFile
  OR Reflection.Assembly`,
        kibana: `winlog.channel: "Microsoft-Windows-PowerShell/Operational"
AND winlog.event_id: 4104
AND winlog.event_data.ScriptBlockText: (*IEX* OR *Invoke-Expression* OR *DownloadString* OR *Net.WebClient* OR *FromBase64String* OR *DownloadFile* OR *Reflection.Assembly*)`,
        powershell: `Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-PowerShell/Operational';
  ID=4104
} | Where-Object {
  $_.Message -match
    'IEX|Invoke-Expression|DownloadString|FromBase64String|Net\\.WebClient|Reflection\\.Assembly'
} | Select TimeCreated, Id,
  @{n='Snippet';e={
    ($_.Message -split [Environment]::NewLine)[0..3] -join "; "
  }}`,
        registry: `ScriptBlockLogging must be enabled to capture this:
HKLM\\Software\\Policies\\Microsoft\\Windows\\
  PowerShell\\ScriptBlockLogging
  EnableScriptBlockLogging = 1 (REG_DWORD)

Module logging (broader, more verbose):
HKLM\\Software\\Policies\\Microsoft\\Windows\\
  PowerShell\\ModuleLogging
  EnableModuleLogging = 1
  ModuleNames\\* = * (log all modules)

Transcription (full session capture):
HKLM\\Software\\Policies\\Microsoft\\Windows\\
  PowerShell\\Transcription
  EnableTranscripting = 1
  OutputDirectory = <secure logging path>

These should be set via GPO across the enterprise.
If absent: this detection fires on nothing.`,
        tools: `Empire stagers (extensive use of IEX)
Cobalt Strike PowerShell delivery
Manual operators (post-exploitation)
Custom downloaders
PowerSploit (PowerView, PowerUp, etc.)
Nishang (extensive IEX use)
PoshC2

Common phrases to search:
- "IEX (New-Object Net.WebClient).DownloadString(..."
- "[System.Convert]::FromBase64String(..."
- "[Reflection.Assembly]::Load([Convert]::From..."`,
        ossdetect: `Sigma:
- ps_script_susp_iex.yml
- ps_script_download_string.yml
- ps_script_reflection_assembly_load.yml
- ps_script_net_webclient.yml
- Many additional PS rules in SigmaHQ repo

Atomic Red Team:
- T1059.001 #1, #2 (multiple ScriptBlock-triggering tests)

Hayabusa:
- Many ScriptBlock-based rules in default ruleset
- "Suspicious PowerShell ScriptBlock" category

Velociraptor:
- Windows.EventLogs.PowerShell
- Built-in IOC matching for known IOCs in script content`,
        notes: "ScriptBlock logging (Event 4104) captures the actual code being executed AFTER PowerShell de-obfuscates it - meaning even if the command-line shows -EncodedCommand <base64>, the 4104 event shows the decoded script. This is the most powerful PowerShell visibility you can get. Caveat: it must be enabled via GPO. Many environments don't have it on by default. Detection signal-to-noise is high: legitimate PowerShell use rarely contains IEX + DownloadString + Net.WebClient in the same script. AMSI integration with PowerShell 5+ further enhances this - when AMSI flags a ScriptBlock as malicious, you get Event ID 4104 with content + Event ID 5061 from Microsoft-Windows-PowerShell/Admin. Combine for highest fidelity. Adversary countermove: AMSI bypass via memory patching (Patriot, AMSI.fail) - detection shifts to Sysmon EID 7 (Image Load) of amsi.dll into PowerShell, which is itself suspicious.",
        apt: [
          { cls: "apt-mul", name: "Red Team", note: "Universal in red team post-exploitation." },
          { cls: "apt-mul", name: "Ransomware", note: "Standard staging pattern across ransomware operations." },
          { cls: "apt-ru", name: "APT29", note: "Documented in SolarWinds and ongoing espionage operations." },
          { cls: "apt-kp", name: "Lazarus", note: "PowerShell-based stagers in cryptocurrency operations." },
          { cls: "apt-cn", name: "APT41", note: "PowerShell post-exploitation in operations against tech sector." },
          { cls: "apt-mul", name: "Multi", note: "Documented in CISA AA23-320A Scattered Spider operations and across ransomware playbooks." }
        ],
        cite: "MITRE ATT&CK T1059.001"
      },
      {
        sub: "T1059.001 - Execution Policy Bypass",
        indicator: "powershell.exe with -ExecutionPolicy Bypass - script restrictions disabled",
        sysmon: `EventID=1
Image=*\\powershell.exe
CommandLine matches:
  *ExecutionPolicy*Bypass*
  OR *-ep bypass*
  OR *-ep unrestricted*
  OR *-exec bypass*
  OR *-exec unrestricted*`,
        kibana: `winlog.event_id: 1
AND process.name: "powershell.exe"
AND process.command_line: (*ExecutionPolicy*Bypass* OR *-ep\\ bypass* OR *-ep\\ unrestricted* OR *-exec\\ bypass* OR *-exec\\ unrestricted*)`,
        powershell: `Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=1
} | Where-Object {
  $_.Properties[4].Value -like '*powershell*' -and
  $_.Properties[10].Value -match
    '-(ExecutionPolicy|ep|exec)\\s+(bypass|unrestricted)'
} | Select TimeCreated,
  @{n='User';e={$_.Properties[12].Value}},
  @{n='Parent';e={$_.Properties[20].Value}},
  @{n='CmdLine';e={$_.Properties[10].Value}}`,
        registry: `No persistent artifact - the bypass is per-session.

Investigation pivots:
- Process ancestry: who called PowerShell with -ep bypass?
  Legitimate IT scripts often use this; legitimate user
  activity rarely does.
- Combined flags: -NoProfile -NonInteractive -WindowStyle Hidden
  alongside -ep bypass = adversary tooling fingerprint
- Session start time + outbound network connections = chain
  into broader investigation
- Check %APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\
  ConsoleHost_history.txt for command history if available`,
        tools: `Cobalt Strike default stagers
Empire stagers
Manual operators
Most adversary PowerShell tooling
PoshC2
Nishang

Common combined flag pattern (full adversary fingerprint):
powershell.exe -NoProfile -NonInteractive
  -WindowStyle Hidden -ExecutionPolicy Bypass
  -EncodedCommand <base64>

Or shortened:
powershell -nop -w hidden -ep bypass -enc <base64>`,
        ossdetect: `Sigma:
- proc_creation_win_powershell_execution_policy_bypass.yml
- proc_creation_win_powershell_susp_command_line.yml
  (combines -ep bypass + other suspicious flags)

Atomic Red Team:
- T1059.001 #3 (ExecutionPolicy bypass test)

Hayabusa:
- ExecPolicy bypass rules in default ruleset
- "PowerShell suspicious flags" category

Velociraptor:
- Windows.Detection.PowerShell.SuspiciousFlags`,
        notes: "ExecutionPolicy is one of the most misunderstood security features in PowerShell - it's not a security boundary. Microsoft documents it explicitly as 'not a security feature' but as a 'safety guardrail.' Adversaries bypass it trivially with -ExecutionPolicy Bypass, but ALSO with: -EncodedCommand (no script file = no policy check), running PowerShell scripts via Get-Content + IEX, or just calling powershell.exe -Command directly. The detection value of catching -ep bypass isn't in stopping the bypass - it's that legitimate IT scripts rarely need it (they sign their scripts) while adversary tooling almost always uses it. False-positive sources: software installers that bundle PowerShell scripts, vendor monitoring agents, some legitimate sysadmin one-liners. Build allowlists by source/parent process. Pair with combined-flag detection: -nop -w hidden -ep bypass is essentially an adversary fingerprint when seen together.",
        apt: [
          { cls: "apt-mul", name: "Red Team", note: "Universal flag pattern in red team operations." },
          { cls: "apt-mul", name: "Ransomware", note: "Standard in ransomware staging." },
          { cls: "apt-ru", name: "APT29", note: "Documented in ongoing espionage operations." },
          { cls: "apt-kp", name: "Lazarus", note: "Standard in PowerShell-based stagers." },
          { cls: "apt-mul", name: "Multi", note: "Often combined with -EncodedCommand and -NonInteractive flags as full adversary fingerprint." }
        ],
        cite: "MITRE ATT&CK T1059.001"
      }
    ]
  },
  // ── STUBS for remaining 12 techniques ──
  // Each stub has the structure ready and headline indicator from build session.
  // Future sessions fill out 2-4 indicators per technique with full schema.
  {
    id: "T1059.003",
    name: "Command and Scripting Interpreter: Windows Command Shell",
    desc: "cmd.exe LOLBin chains, recon command bursts, parent-process anomalies, DOSfuscation",
    rows: [
      {
        sub: "T1059.003 - Suspicious Parent Process",
        indicator: "cmd.exe spawned by Office, Adobe, or scripting host - phishing or macro execution chain",
        sysmon: `EventID=1
Image=*\\cmd.exe
ParentImage=
  *\\winword.exe
  OR *\\excel.exe
  OR *\\powerpnt.exe
  OR *\\outlook.exe
  OR *\\acrord32.exe
  OR *\\acrobat.exe
  OR *\\mshta.exe
  OR *\\wscript.exe
  OR *\\cscript.exe
  OR *\\wmiprvse.exe`,
        kibana: `winlog.event_id: 1
AND process.name: "cmd.exe"
AND process.parent.name: ("winword.exe" OR "excel.exe" OR "powerpnt.exe" OR "outlook.exe" OR "acrord32.exe" OR "acrobat.exe" OR "mshta.exe" OR "wscript.exe" OR "cscript.exe" OR "wmiprvse.exe")`,
        powershell: `Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=1
} | Where-Object {
  $_.Properties[4].Value -like '*\\cmd.exe' -and
  $_.Properties[20].Value -match
    'winword|excel|powerpnt|outlook|acrord32|acrobat|mshta|wscript|cscript|wmiprvse'
} | Select TimeCreated,
  @{n='Parent';e={$_.Properties[20].Value}},
  @{n='CmdLine';e={$_.Properties[10].Value}},
  @{n='User';e={$_.Properties[12].Value}}`,
        registry: `Office macro artifacts (same as T1059.001 parent indicator):
- %APPDATA%\\Microsoft\\Templates\\*.dotm
- %APPDATA%\\Microsoft\\Word\\STARTUP\\*.dotm
- %APPDATA%\\Microsoft\\Excel\\XLSTART\\*.xlsm

Outlook attachment cache:
- %APPDATA%\\Local\\Microsoft\\Windows\\INetCache\\
  Content.Outlook\\

LNK targets (often used as cmd.exe launchers post-MOTW):
- %APPDATA%\\Roaming\\Microsoft\\Windows\\Recent\\*.lnk
- Shell:startup\\*.lnk (if persistence also in play)

Zone.Identifier ADS on container files
(confirms download origin vs internal):
- Right-click file -> Properties -> Unblock, or
- Get-Item file.exe -Stream Zone.Identifier`,
        tools: `Phishing operators (universal)
Malicious Office macro loaders
HTA droppers (mshta -> cmd chain)
VBScript / WScript loaders
ISO/LNK containers (post-MOTW evasion, 2022+)
OneNote (.one) embedded attachment runners

Modern observation: as with PowerShell parent detection,
the parent list must evolve with phishing trends.
Post-2022 additions worth monitoring:
- explorer.exe (ISO mount auto-run via LNK)
- %TEMP%\\*.tmp (staging via temp dir)
- onenoteim.exe (OneNote embedded script runners)`,
        ossdetect: `Sigma:
- proc_creation_win_office_cmd_child.yml
- proc_creation_win_susp_cmd_parent_process.yml
- proc_creation_win_office_susp_child.yml (covers both cmd and PS)

Atomic Red Team:
- T1566.001 (phishing - upstream technique)
- T1059.003 Test #2 (cmd from script host)

Hayabusa:
- SuspParentChild rules include cmd.exe variants
- Office spawn detection (cmd + PS variants)

Velociraptor:
- Windows.Detection.OfficeSpawn
  (covers cmd.exe and powershell.exe children)`,
        notes: "Office-spawning-cmd is the cmd.exe equivalent of the PowerShell parent indicator - same logic, same high fidelity, slightly different toolchain. Where PowerShell is preferred for in-memory staging, cmd.exe is often used as a relay: the macro or HTA spawns cmd.exe, which then chains into something else (certutil, bitsadmin, curl, etc.). That chaining pattern - cmd spawning a network-capable LOLBin - is worth treating as a separate pivot: look at Sysmon EID 1 events where cmd.exe is BOTH child (suspicious parent) and parent (spawning LOLBin) within the same process tree. False positives are low for end-user machines. Admin and developer workstations will generate noise. Tune by user role and parent-child pair, not just parent alone.",
        apt: [
          { cls: "apt-mul", name: "Phishing", note: "Universal in phishing chains - macro or HTA drops cmd, cmd relays to next stage." },
          { cls: "apt-ru", name: "APT28", note: "Office-based phishing chains invoking cmd.exe extensively documented." },
          { cls: "apt-kp", name: "Lazarus", note: "HTA and Office macro loaders spawning cmd.exe in cryptocurrency-targeted operations." },
          { cls: "apt-ir", name: "APT35", note: "Macro-based initial access chains documented in CISA advisories." },
          { cls: "apt-mul", name: "Ransomware", note: "Affiliate operators use Office-to-cmd chains as standard initial access pathway." }
        ],
        cite: "MITRE ATT&CK T1059.003, T1566.001"
      },
      {
        sub: "T1059.003 - Post-Compromise Recon Command Burst",
        indicator: "Rapid sequence of discovery commands from cmd.exe - whoami, ipconfig, net user, systeminfo within short window",
        sysmon: `EventID=1
Image=*\\cmd.exe OR *\\whoami.exe
  OR *\\ipconfig.exe OR *\\net.exe
  OR *\\systeminfo.exe OR *\\hostname.exe
  OR *\\nltest.exe OR *\\arp.exe
  OR *\\route.exe OR *\\tasklist.exe

// Logical spec: alert when 4+ of these images
// appear with the same ParentProcessId or same
// user session within a 60-second window.
// Single-event Sysmon filters cannot express this;
// use Kibana or Sigma correlation rule below.`,
        kibana: `// Correlation query - run over short time window (60-120s)
winlog.event_id: 1
AND process.name: (
  "whoami.exe" OR "ipconfig.exe" OR "net.exe" OR
  "systeminfo.exe" OR "hostname.exe" OR "nltest.exe" OR
  "arp.exe" OR "route.exe" OR "tasklist.exe" OR
  "netstat.exe" OR "qwinsta.exe"
)
// Then aggregate: if same user or same parent spawns
// 4+ distinct process names in < 120s, alert.
// Use Kibana Threshold rule or EQL sequence for correlation.`,
        powershell: `# Hunt for recon command bursts in Sysmon EID 1
# Looks for 4+ distinct recon binaries per user per 2-minute window
$reconBinaries = @(
  'whoami.exe','ipconfig.exe','net.exe','systeminfo.exe',
  'hostname.exe','nltest.exe','arp.exe','route.exe',
  'tasklist.exe','netstat.exe','qwinsta.exe','nslookup.exe'
)

$windowSecs = 120

Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; ID=1
} | Where-Object {
  $bin = ($_.Properties[4].Value -split '\\\\')[-1]
  $reconBinaries -contains $bin
} | Select TimeCreated,
  @{n='Binary';e={($_.Properties[4].Value -split '\\\\')[-1]}},
  @{n='User';e={$_.Properties[12].Value}},
  @{n='CmdLine';e={$_.Properties[10].Value}},
  @{n='ParentCmdLine';e={$_.Properties[21].Value}} |
  Group-Object User |
  ForEach-Object {
    $user = $_.Name
    $events = $_.Group | Sort-Object TimeCreated
    for ($i=0; $i -lt $events.Count; $i++) {
      $window = $events | Where-Object {
        [Math]::Abs(($_.TimeCreated - $events[$i].TimeCreated).TotalSeconds) -le $windowSecs
      }
      if (($window.Binary | Select-Object -Unique).Count -ge 4) {
        [PSCustomObject]@{
          User       = $user
          StartTime  = $events[$i].TimeCreated
          BinariesRun = ($window.Binary | Select-Object -Unique) -join ', '
          Count      = ($window.Binary | Select-Object -Unique).Count
        }
        break
      }
    }
  } | Where-Object { $_ -ne $null }`,
        registry: `No direct registry artifact from recon commands.

Investigation pivots:
- Sysmon EID 3 (NetworkConnect) from same session:
  nltest and net.exe can generate LDAP/SMB traffic -
  pivot to network logs to see what systems were queried
- User profile writes from systeminfo:
  none by default; output is stdout only
- Command history if not cleared:
  %APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\
  ConsoleHost_history.txt (PowerShell-launched cmds only)
- Prefetch (if enabled - off by default on servers):
  C:\\Windows\\Prefetch\\WHOAMI.EXE-*.pf timestamps
  confirm first vs repeated execution`,
        tools: `Manual operator post-exploitation (most common)
Cobalt Strike built-in reconnaissance commands
Metasploit post-exploitation modules
Empire / Starkiller discovery modules
Impacket tooling (for remote variants)

Standard adversary recon sequence seen across
many documented operations:
  whoami /all          - current user + privileges
  hostname             - machine name
  ipconfig /all        - network config + DNS suffix
  net user             - local users
  net localgroup administrators - admin group members
  net view             - visible shares/hosts
  systeminfo           - OS/patch level
  nltest /domain_trusts - domain trust enumeration
  tasklist /svc        - running services

The sequence order and timing distinguishes manual
operators from scripted tooling - manual operators
run commands with human-paced gaps; scripts run
them near-simultaneously.`,
        ossdetect: `Sigma:
- win_susp_recon_activity.yml (Florian Roth)
- proc_creation_win_recon_discovery.yml
- Multiple individual detection rules per binary

Elastic EQL (Event Query Language) example:
sequence with maxspan=2m
  [process where process.name == "whoami.exe"]
  [process where process.name == "net.exe"]
  [process where process.name == "ipconfig.exe"]

Atomic Red Team:
- T1087.001 (Local Account Discovery)
- T1016 (System Network Configuration Discovery)
- T1082 (System Information Discovery)
- Many individual discovery tests that reproduce
  the component commands

Velociraptor:
- Windows.System.Pslist + correlation
- Windows.EventLogs.Sysmon (with filters)`,
        notes: "Individual recon commands like whoami and ipconfig run constantly in healthy enterprise environments - IT scripts, monitoring agents, login scripts. The detection is not per-command but per-burst: multiple distinct recon binaries run by the same user or from the same parent process within a short time window. This is almost exclusively human operator behavior post-compromise. The timing gap between commands is a secondary signal: automated tools run commands in milliseconds; human operators take 2-30 seconds between commands. Sysmon alone cannot express the windowed-count correlation - you need Kibana threshold rules, EQL sequences, or a SIEM aggregation query. This is one of the cases where the PowerShell hunt script above is genuinely useful for rapid triage without a SIEM. APT attribution is broad because this is a universal technique - every threat actor who gains shell access does some version of this recon sequence.",
        apt: [
          { cls: "apt-mul", name: "All Operators", note: "Universal post-compromise behavior - virtually every documented intrusion includes a recon command burst." },
          { cls: "apt-ru", name: "APT29", note: "Documented in SolarWinds post-compromise activity." },
          { cls: "apt-cn", name: "APT41", note: "Discovery command sequences documented across multiple sectors." },
          { cls: "apt-kp", name: "Lazarus", note: "Standard recon sequence documented in CISA advisories on DPRK operators." },
          { cls: "apt-mul", name: "Ransomware", note: "Pre-encryption recon (network share and user enumeration) is standard across ransomware operations." }
        ],
        cite: "MITRE ATT&CK T1059.003, T1087.001, T1016, T1082"
      },
      {
        sub: "T1059.003 - DOSfuscation / Command Obfuscation",
        indicator: "cmd.exe command string with excessive carets, quoted null insertions, or comma/semicolon delimiters - obfuscated shell syntax",
        sysmon: `EventID=1
Image=*\\cmd.exe
CommandLine matches (any of):
  - 3+ consecutive carets: ^^^
  - Quoted empty string insertion: ""c""m""d or s^e^t
  - Comma/semicolon as token separators: cmd,/c or
    c;m;d;.;e;x;e
  - Environment variable substring: %ComSpec:~0,3%

// Logical spec: regex on CommandLine field.
// Sysmon XML config does not support regex in
// CommandLine match; use Kibana pcre or Sigma
// detection below for runtime alerting.`,
        kibana: `winlog.event_id: 1
AND process.name: "cmd.exe"
AND process.command_line: /(\^{3,}|\"\"[a-z]\"\"|\,[\/\\\\]|;[a-z];|%[A-Za-z]+:~[0-9]+,[0-9]+%)/

// Alternative plaintext-match approach (lower fidelity):
AND process.command_line: (*^^^* OR *""c""* OR *,/c* OR *;m;d;*)`,
        powershell: `# Hunt for DOSfuscated cmd.exe command lines in Sysmon EID 1
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=1
} | Where-Object {
  $_.Properties[4].Value -like '*\\cmd.exe' -and (
    # 3+ consecutive carets
    $_.Properties[10].Value -match '\^{3,}' -or
    # Quoted null-string insertion (s""et, c""md, etc.)
    $_.Properties[10].Value -match '""\w""' -or
    # Comma or semicolon as command token separator
    $_.Properties[10].Value -match '[,;][/\\\\cC]' -or
    # Environment variable substring extraction
    $_.Properties[10].Value -match '%[A-Za-z_]+:~\d+,\d+%'
  )
} | Select TimeCreated,
  @{n='CmdLine';e={$_.Properties[10].Value}},
  @{n='Parent';e={$_.Properties[20].Value}},
  @{n='User';e={$_.Properties[12].Value}}`,
        registry: `No registry artifact directly.

Context: DOSfuscation is almost always a wrapper around
something substantive - the obfuscated outer shell
eventually invokes a real payload.

Investigation pivots:
- Child processes of the obfuscated cmd.exe:
  what did cmd.exe actually launch?
  Sysmon EID 1, filter ParentProcessId = <suspicious cmd PID>
- Network connections from child processes:
  Sysmon EID 3 within same session
- File writes from child processes:
  Sysmon EID 11 (FileCreate) or EID 15 (FileCreateStreamHash)
- Decode the obfuscation manually:
  Remove carets (they escape the next char in cmd.exe)
  Remove quoted null strings ("" between tokens = nothing)
  Reconstruct the actual command to understand intent`,
        tools: `DOSfuscation tool by Daniel Bohannon (2018)
  - Published tool for demonstrating cmd.exe obfuscation
  - Multiple layers: token, string, encoding techniques
  - GitHub: danielbohannon/Invoke-DOSfuscation

Manual operator technique (carets + quoted nulls)
Malware staging scripts
Some ransomware dropper chains

Note: DOSfuscation is significantly less common than
PowerShell obfuscation in modern operations. Most
adversaries prefer PowerShell's richer obfuscation
options (-EncodedCommand, string concatenation, etc.).
cmd.exe obfuscation appears most in:
- Older malware lineages
- Environments where PS execution is blocked or monitored
- Manual operators who default to cmd.exe tradecraft`,
        ossdetect: `Sigma:
- proc_creation_win_cmd_dosfuscation.yml (Florian Roth)
- proc_creation_win_cmd_susp_special_chars.yml
- proc_creation_win_susp_cmd_obfuscation.yml

Atomic Red Team:
- T1059.003 Test #3 (DOSfuscation variants)
- Invoke-DOSfuscation manual tests

Daniel Bohannon research:
- "DOSfuscation: Exploring the Depths of Cmd.exe
  Obfuscation and Detection Techniques" (2018 DEF CON)
- Core reference for understanding all variants

Hayabusa:
- cmd-obfuscation rules in default ruleset

Velociraptor:
- Windows.EventLogs.Sysmon + regex filter on CommandLine`,
        notes: "DOSfuscation exploits cmd.exe's quirky parsing rules - carets are escape characters, quoted empty strings are silently removed, commas and semicolons can substitute for spaces in certain positions. The result is command strings that look like noise but execute normally. The core reference is Daniel Bohannon's 2018 DEF CON talk and the Invoke-DOSfuscation tool. Detection angle: legitimate cmd.exe usage almost never contains 3+ consecutive carets or quoted null strings mid-token. These patterns have near-zero false-positive rate in normal enterprise telemetry - they're detectable because the obfuscation itself is anomalous. The deeper hunt is what the obfuscated command actually does: decode the outer shell (drop carets, remove quoted nulls, resolve env var substrings) and analyze the revealed payload. Kibana regex on CommandLine is more reliable than Sysmon config-level filtering here because Sysmon's XML match syntax doesn't support regex in CommandLine fields - this is one of the genuine cases where the Kibana column catches things the Sysmon column misses at config time.",
        apt: [
          { cls: "apt-mul", name: "Commodity Malware", note: "DOSfuscation present in several malware families using cmd.exe staging." },
          { cls: "apt-cn", name: "APT41", note: "Cmd-level obfuscation documented in intrusions against gaming and tech sectors." },
          { cls: "apt-mul", name: "Ransomware", note: "Some ransomware droppers use DOSfuscated cmd.exe wrappers for staging scripts." }
        ],
        cite: "MITRE ATT&CK T1059.003, T1027"
      }
    ]
  },
  {
    id: "T1059.005",
    name: "Command and Scripting Interpreter: Visual Basic",
    desc: "VBA macros, vbscript via wscript/cscript, Office-driven script execution",
    rows: [
      {
        sub: "T1059.005 - Office Macro Spawning Script Host",
        indicator: "wscript.exe or cscript.exe spawned by Office application - VBA macro executing VBScript payload",
        sysmon: `EventID=1
Image=*\\wscript.exe OR *\\cscript.exe
ParentImage=
  *\\winword.exe
  OR *\\excel.exe
  OR *\\powerpnt.exe
  OR *\\outlook.exe
  OR *\\onenote.exe
  OR *\\msaccess.exe
  OR *\\mspub.exe`,
        kibana: `winlog.event_id: 1
AND process.name: ("wscript.exe" OR "cscript.exe")
AND process.parent.name: ("winword.exe" OR "excel.exe" OR "powerpnt.exe" OR "outlook.exe" OR "onenote.exe" OR "msaccess.exe" OR "mspub.exe")`,
        powershell: `Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=1
} | Where-Object {
  $_.Properties[4].Value -match '(wscript|cscript)\.exe$' -and
  $_.Properties[20].Value -match
    'winword|excel|powerpnt|outlook|onenote|msaccess|mspub'
} | Select TimeCreated,
  @{n='ScriptHost';e={($_.Properties[4].Value -split '\\\\')[-1]}},
  @{n='Parent';e={($_.Properties[20].Value -split '\\\\')[-1]}},
  @{n='CmdLine';e={$_.Properties[10].Value}},
  @{n='User';e={$_.Properties[12].Value}}`,
        registry: `VBA macro artifacts:
- %APPDATA%\\Microsoft\\Templates\\Normal.dotm
  (Word global template - macros stored here persist
  across all Word sessions, high-value persistence location)
- %APPDATA%\\Microsoft\\Word\\STARTUP\\*.dotm
- %APPDATA%\\Microsoft\\Excel\\XLSTART\\*.xlam
- %APPDATA%\\Microsoft\\Excel\\XLSTART\\*.xlsm

Office Trust Center registry keys
(adversaries sometimes modify to enable macros silently):
HKCU\\Software\\Microsoft\\Office\\<version>\\<app>\\
  Security\\VBAWarnings = 1 (REG_DWORD)
  (1 = enable all macros without notification)
  AccessVBOM = 1
  (grants macro access to VBA object model)

Script dropped by macro - common staging locations:
- %TEMP%\\*.vbs
- %APPDATA%\\*.vbs
- %PUBLIC%\\*.vbs
- C:\\ProgramData\\*.vbs`,
        tools: `Emotet (VBA macro dropper - historically prolific)
QakBot / QBot (macro-based delivery pre-2022)
IcedID (macro delivery variants)
Dridex (Office macro delivery)
Agent Tesla (VBA macro stager)
Custom VBA macro loaders (common in targeted ops)

Note: Microsoft's 2022 internet-macro block
significantly reduced this vector for commodity
malware. It remains relevant for:
- Internally-sourced documents (no MOTW applied)
- Targeted ops where the attacker can social-engineer
  the victim into enabling macros
- Legacy environments where the block is not enforced
  (Office 2016 and earlier, or policy-disabled block)
- Macro-enabled templates delivered via SMB share
  (SMB-sourced files do not get MOTW in most configs)`,
        ossdetect: `Sigma:
- proc_creation_win_office_wscript_child.yml
- proc_creation_win_office_cscript_child.yml
- proc_creation_win_office_susp_child.yml
  (covers wscript, cscript, cmd, powershell children)

Atomic Red Team:
- T1059.005 (VBScript execution tests)
- T1566.001 (phishing with macro delivery)

Hayabusa:
- Office spawn detection rules cover wscript/cscript
- "SuspiciousOfficeChildProcess" category

Velociraptor:
- Windows.Detection.OfficeSpawn
- Windows.System.Autoruns (catches macro persistence
  via Normal.dotm and XLSTART locations)

YARA:
- Many VBA macro detection rules in community repos
- Didier Stevens' oledump.py for static macro analysis`,
        notes: "wscript.exe and cscript.exe are the two Windows Script Host engines - wscript runs scripts with a GUI context (no console window visible), cscript runs them in a console. Adversaries strongly prefer wscript for macro-dropped scripts because it runs silently. The detection is the same as the Office-spawning-PowerShell and Office-spawning-cmd patterns - the anomaly is the parent, not the child. One important addition to the parent list vs the cmd/PS indicators: onenote.exe. Since the MOTW macro block in 2022, OneNote became a popular delivery vehicle - embedded attachments inside .one files execute via the OneNote process, not a standard Office app. Also worth noting: msaccess.exe and mspub.exe are lower-volume Office apps that get less scrutiny but are used in targeted operations specifically because defenders don't always include them in parent-process watchlists. False positives: IT automation scripts occasionally use wscript legitimately - allowlist by known-good script paths and parent context.",
        apt: [
          { cls: "apt-mul", name: "Commodity Malware", note: "Emotet, QakBot, IcedID all used Office macro to wscript/cscript chains extensively pre-2022." },
          { cls: "apt-ru", name: "APT28", note: "VBA macro delivery documented in multiple spearphishing campaigns." },
          { cls: "apt-ir", name: "APT35", note: "Office macro-based initial access documented in CISA advisories targeting US organizations." },
          { cls: "apt-cn", name: "APT41", note: "VBA macro loaders documented in operations against multiple sectors." },
          { cls: "apt-mul", name: "TA505", note: "Prolific use of Office macro chains spawning wscript as part of Dridex and Clop distribution." }
        ],
        cite: "MITRE ATT&CK T1059.005, T1566.001"
      },
      {
        sub: "T1059.005 - ISO/LNK Container Dropping VBScript",
        indicator: "wscript.exe executing .vbs file from mounted ISO, %TEMP%, or %APPDATA% - post-MOTW container evasion chain",
        sysmon: `EventID=1
Image=*\\wscript.exe OR *\\cscript.exe
CommandLine matches:
  *.vbs* OR *.vbe* OR *.wsf*
AND CommandLine path matches:
  *\\AppData\\* OR *\\Temp\\* OR *\\Public\\*
  OR *\\ProgramData\\* OR [A-Z]:\\*.vbs
  (single drive-letter root = likely mounted ISO)

// Supplementary - Sysmon EID 11 FileCreate:
EventID=11
TargetFilename=*.vbs OR *.vbe OR *.wsf
TargetFilename path=*\\Temp\\* OR *\\AppData\\*
  OR *\\Public\\* OR *\\ProgramData\\*`,
        kibana: `// Primary: wscript/cscript running script from suspicious path
winlog.event_id: 1
AND process.name: ("wscript.exe" OR "cscript.exe")
AND process.command_line: (*.vbs* OR *.vbe* OR *.wsf*)
AND process.command_line: (*\\AppData\\* OR *\\Temp\\* OR *\\Public\\* OR *\\ProgramData\\*)

// Supplementary: VBScript file written to suspicious path
winlog.event_id: 11
AND file.extension: ("vbs" OR "vbe" OR "wsf")
AND file.path: (*\\Temp\\* OR *\\AppData\\* OR *\\Public\\* OR *\\ProgramData\\*)`,
        powershell: `# Hunt for wscript/cscript running scripts from non-standard paths
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=1
} | Where-Object {
  $_.Properties[4].Value -match '(wscript|cscript)\.exe$' -and
  $_.Properties[10].Value -match '\.(vbs|vbe|wsf)' -and
  $_.Properties[10].Value -match
    '(AppData|Temp|Public|ProgramData|^[A-Z]:\\\\[^\\\\]+\.(vbs|vbe|wsf))'
} | Select TimeCreated,
  @{n='CmdLine';e={$_.Properties[10].Value}},
  @{n='Parent';e={($_.Properties[20].Value -split '\\\\')[-1]}},
  @{n='User';e={$_.Properties[12].Value}} |
  Sort-Object TimeCreated -Descending

# Supplementary: VBS files written to suspicious locations (EID 11)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=11
} | Where-Object {
  $_.Properties[0].Value -match '\.(vbs|vbe|wsf)$' -and
  $_.Properties[0].Value -match '(Temp|AppData|Public|ProgramData)'
} | Select TimeCreated,
  @{n='File';e={$_.Properties[0].Value}},
  @{n='CreatingProcess';e={$_.Properties[5].Value}}`,
        registry: `ISO/container mount artifacts:
- HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\
  Explorer\\MountPoints2\\
  (records mounted drive letters including ISO mounts -
  entry appears when user opens/mounts an ISO file)

Zone.Identifier ADS on the ISO file itself
(present on the .iso - NOT on files extracted from it):
- Get-Item *.iso -Stream Zone.Identifier
  ZoneId=3 confirms internet origin

LNK file artifacts (the launcher inside the ISO):
- %APPDATA%\\Roaming\\Microsoft\\Windows\\Recent\\*.lnk
  (LNK files created when user double-clicks inside ISO)
- LNK target path will point to the .vbs inside the
  mounted drive letter (e.g., D:\\payload.vbs)

Script file on disk - investigate with:
- Get-Content <path>.vbs (read the actual script)
- Check file creation time vs execution time
  (gap indicates staging before execution)`,
        tools: `ISO/IMG container delivery (2022+ dominant vector):
- Adversary crafts ISO containing LNK + VBS payload
- LNK has custom icon to look like legitimate document
- User opens ISO (auto-mounts in Win10/11), double-clicks
  what appears to be a file, LNK runs wscript against VBS

ZIP delivery variants:
- Password-protected ZIP (bypasses email gateway AV scan)
- Extracts to %TEMP%, LNK or direct VBS execution

OneNote (.one) embedded attachments:
- .vbs embedded directly in OneNote section
- User prompted to click "Click to view attachment"
- File extracted to %TEMP% and executed via wscript

Tools/families using this chain:
Qakbot (post-macro-block ISO pivot, 2022-2023)
IcedID (ISO delivery variants)
Bumblebee loader (heavy ISO + LNK + VBS use)
Raspberry Robin (worm spread via LNK on USB/ISO)
Various initial access brokers (IABs)`,
        ossdetect: `Sigma:
- proc_creation_win_wscript_vbs_exec_susp_location.yml
- file_event_win_vbs_creation_susp_location.yml
- proc_creation_win_susp_script_exec_from_temp.yml

Atomic Red Team:
- T1059.005 (VBScript from temp directory tests)
- T1566.001 (ISO/LNK delivery chain)

Hayabusa:
- ScriptFromTemp and ScriptFromAppData rules
- ISO mount + LNK detection rules

Velociraptor:
- Windows.Detection.Autoruns
- Windows.Forensics.Lnk (LNK file analysis)
- Windows.System.MountedDevices (ISO mount history)

Any.run / VirusTotal sandbox:
- Submit suspicious VBS files for behavioral analysis
- VBS is often obfuscated but sandboxes detonate it`,
        notes: "This indicator represents the post-2022 evolution of VBScript delivery after Microsoft's macro block. The ISO container trick works because Windows auto-mounts ISO files when double-clicked (since Windows 8), and files inside the mounted ISO volume do not inherit the Zone.Identifier ADS from the outer ISO file - so the .vbs inside has no MOTW and runs without a macro security prompt. The detection pivot is twofold: first, the ISO mount event itself (MountPoints2 registry key, Sysmon EID 11 on the ISO), then wscript executing a script from a mounted drive letter or staging path. The drive-letter heuristic (wscript running D:\\something.vbs where D: is not a standard drive) is high-fidelity but requires knowing which drive letters are fixed vs removable vs mounted in your environment. The %TEMP% and %APPDATA% path heuristics are broader and catch the cases where the script is first dropped to disk before execution. VBE (.vbe) is encoded VBScript - the content is obfuscated using Microsoft's Script Encoder - and is a meaningful escalation signal when seen in these paths.",
        apt: [
          { cls: "apt-mul", name: "Initial Access Brokers", note: "ISO/LNK/VBS chains are the dominant IAB delivery method post-2022 macro block." },
          { cls: "apt-mul", name: "QakBot", note: "Pivoted to ISO + VBS delivery after the 2022 Microsoft macro block." },
          { cls: "apt-mul", name: "Bumblebee", note: "Heavy use of ISO container with LNK launching VBS or DLL payload." },
          { cls: "apt-kp", name: "Lazarus", note: "ISO-based delivery documented in operations against financial and defense sectors." },
          { cls: "apt-mul", name: "Raspberry Robin", note: "LNK-based worm using wscript for execution, spread via USB and ISO." }
        ],
        cite: "MITRE ATT&CK T1059.005, T1566.001, T1027"
      }
    ]
  },
  {
    id: "T1059.007",
    name: "Command and Scripting Interpreter: JavaScript",
    desc: "JScript via Windows Script Host, mshta+JS chains, fileless JS loaders",
    rows: [
      {
        sub: "T1059.007 - WSH Executing JScript from Suspicious Path",
        indicator: "wscript.exe or cscript.exe running .js or .jse file from %TEMP%, %APPDATA%, or mounted container path",
        sysmon: `EventID=1
Image=*\\wscript.exe OR *\\cscript.exe
CommandLine matches:
  *.js* OR *.jse*
AND CommandLine path matches:
  *\\AppData\\* OR *\\Temp\\* OR *\\Public\\*
  OR *\\ProgramData\\* OR [A-Z]:\\*.js

// Supplementary - Sysmon EID 11 FileCreate:
EventID=11
TargetFilename=*.js OR *.jse
TargetFilename path=
  *\\Temp\\* OR *\\AppData\\*
  OR *\\Public\\* OR *\\ProgramData\\*`,
        kibana: `// Primary: WSH executing JScript from suspicious path
winlog.event_id: 1
AND process.name: ("wscript.exe" OR "cscript.exe")
AND process.command_line: (*.js* OR *.jse*)
AND process.command_line: (*\\AppData\\* OR *\\Temp\\* OR *\\Public\\* OR *\\ProgramData\\*)

// Supplementary: JScript file written to suspicious path
winlog.event_id: 11
AND file.extension: ("js" OR "jse")
AND file.path: (*\\Temp\\* OR *\\AppData\\* OR *\\Public\\* OR *\\ProgramData\\*)`,
        powershell: `# Hunt for wscript/cscript executing JScript from non-standard paths
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=1
} | Where-Object {
  $_.Properties[4].Value -match '(wscript|cscript)\.exe$' -and
  $_.Properties[10].Value -match '\.(js|jse)(\s|"|$)' -and
  $_.Properties[10].Value -match
    '(AppData|Temp|Public|ProgramData|^[A-Z]:\\\\[^\\\\]+\.(js|jse))'
} | Select TimeCreated,
  @{n='CmdLine';e={$_.Properties[10].Value}},
  @{n='Parent';e={($_.Properties[20].Value -split '\\\\')[-1]}},
  @{n='User';e={$_.Properties[12].Value}} |
  Sort-Object TimeCreated -Descending

# Supplementary: JS/JSE files written to suspicious locations (EID 11)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=11
} | Where-Object {
  $_.Properties[0].Value -match '\.(js|jse)$' -and
  $_.Properties[0].Value -match '(Temp|AppData|Public|ProgramData)'
} | Select TimeCreated,
  @{n='File';e={$_.Properties[0].Value}},
  @{n='CreatingProcess';e={$_.Properties[5].Value}}`,
        registry: `No direct registry artifact from JScript execution itself.

JS/JSE file on disk - investigate with:
- Get-Content <path>.js (read the script - often obfuscated)
- Common obfuscation: eval(), String.fromCharCode(),
  ActiveXObject instantiation buried in encoded strings
- JSE (.jse) is Microsoft Script Encoded JScript -
  same obfuscation as VBE, content not human-readable
  without decoding

Container mount artifacts (same as T1059.005):
- HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\
  Explorer\\MountPoints2\\
  (ISO mount history)

Zone.Identifier ADS on source container:
- Get-Item *.iso -Stream Zone.Identifier
  ZoneId=3 confirms internet origin

File association context:
- .js files are associated with wscript.exe by default
  on Windows (HKCR\\.js\\Shell\\Open\\Command)
- Adversaries rely on this default association -
  user double-clicking a .js file triggers wscript
  with no visible console if using the GUI handler`,
        tools: `Delivery mechanisms for .js payloads:
- ZIP/RAR containing .js file (email attachment)
- ISO container with LNK pointing to .js (post-MOTW)
- Direct .js file attachment (increasingly blocked
  by mail gateways but still attempted)
- Drive-by download dropping .js to %TEMP%

Frameworks and families using JScript via WSH:
Gootloader (heavy use of .js delivery, multi-stage)
TA505 / Dridex variants
Qakbot (JS-based loader variants)
Bumblebee (JS staging in some variants)
Custom loaders (targeted ops favoring WSH over PS
  for lower detection profile)

Gootloader note: particularly notable for using
large, heavily obfuscated .js files (thousands of
lines) staged in registry or %APPDATA% - the file
size and obfuscation density are signals in addition
to path and execution context.`,
        ossdetect: `Sigma:
- proc_creation_win_wscript_jscript_exec_susp_location.yml
- file_event_win_jscript_creation_susp_location.yml
- proc_creation_win_wscript_susp_child_process.yml

Atomic Red Team:
- T1059.007 (WSH JScript execution tests)

Hayabusa:
- JScriptFromTemp and related rules
- WSH execution detection category

Velociraptor:
- Windows.EventLogs.Sysmon (EID 1 + EID 11 filters)
- Windows.Forensics.Gootloader (dedicated artifact
  for Gootloader JS registry staging)

Static analysis:
- CyberChef: decode JSE (Script Encoder decode recipe)
- js-beautify: deobfuscate minified/packed JS
- Any.run: sandbox detonation for behavioral analysis`,
        notes: "The detection pattern here is nearly identical to T1059.005 VBScript - same engines (wscript/cscript), same suspicious paths, same EID 11 supplementary hunt. The distinctions that matter: .js files have a user-visible double-click association on Windows (wscript runs them silently), making them effective for lure-based delivery without requiring a macro or container trick. The user sees what looks like a document icon, double-clicks, and wscript silently executes the payload. JSE (.jse) is encoded JScript using Microsoft's Script Encoder - same tool as VBE encoding - and is a stronger signal because legitimate software rarely produces .jse files in staging directories. Gootloader is worth calling out specifically because it uses an unusual pattern: a large multi-stage .js file (often 5,000+ lines of obfuscated code) that may be staged in the registry between stages rather than purely on disk - if you see wscript running a .js with an unusually large file size or see powershell.exe reading registry values and piping to wscript, that's a Gootloader indicator. False positives: some legitimate software installers use .js files during setup, typically from their own installation directory rather than temp paths - path context resolves most of these.",
        apt: [
          { cls: "apt-mul", name: "Gootloader", note: "Signature use of large obfuscated .js files for multi-stage delivery, heavily documented." },
          { cls: "apt-mul", name: "TA505", note: "JScript-based loaders used in Dridex and FlawedAmmyy distribution campaigns." },
          { cls: "apt-mul", name: "Initial Access Brokers", note: "ZIP-delivered .js files are a recurring IAB delivery mechanism." },
          { cls: "apt-cn", name: "APT41", note: "JScript-based loaders documented in operations against multiple sectors." },
          { cls: "apt-mul", name: "Commodity Malware", note: "JScript delivery present across multiple malware families favoring WSH over PowerShell for lower detection profile." }
        ],
        cite: "MITRE ATT&CK T1059.007"
      },
      {
        sub: "T1059.007 - Office or Browser Spawning WSH with JScript Payload",
        indicator: "wscript.exe with .js argument spawned by Office app, browser, or explorer.exe - delivery chain execution",
        sysmon: `EventID=1
Image=*\\wscript.exe OR *\\cscript.exe
CommandLine matches: *.js* OR *.jse*
ParentImage=
  *\\winword.exe
  OR *\\excel.exe
  OR *\\powerpnt.exe
  OR *\\outlook.exe
  OR *\\onenote.exe
  OR *\\explorer.exe
  OR *\\chrome.exe
  OR *\\msedge.exe
  OR *\\firefox.exe
  OR *\\iexplore.exe`,
        kibana: `winlog.event_id: 1
AND process.name: ("wscript.exe" OR "cscript.exe")
AND process.command_line: (*.js* OR *.jse*)
AND process.parent.name: ("winword.exe" OR "excel.exe" OR "powerpnt.exe" OR "outlook.exe" OR "onenote.exe" OR "explorer.exe" OR "chrome.exe" OR "msedge.exe" OR "firefox.exe" OR "iexplore.exe")`,
        powershell: `Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=1
} | Where-Object {
  $_.Properties[4].Value -match '(wscript|cscript)\.exe$' -and
  $_.Properties[10].Value -match '\.(js|jse)(\s|"|$)' -and
  $_.Properties[20].Value -match
    'winword|excel|powerpnt|outlook|onenote|explorer|chrome|msedge|firefox|iexplore'
} | Select TimeCreated,
  @{n='Parent';e={($_.Properties[20].Value -split '\\\\')[-1]}},
  @{n='CmdLine';e={$_.Properties[10].Value}},
  @{n='User';e={$_.Properties[12].Value}} |
  Sort-Object TimeCreated -Descending`,
        registry: `Browser download artifacts - confirm the JS file origin:
- Chrome download history:
  %LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\
  History (SQLite - query Downloads table)
- Edge download history:
  %LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\
  History (SQLite - same schema as Chrome)
- Firefox download history:
  %APPDATA%\\Mozilla\\Firefox\\Profiles\\*.default\\
  downloads.sqlite

Zone.Identifier ADS on the .js file itself
(if delivered via browser download, this will be present):
- Get-Item payload.js -Stream Zone.Identifier
  ZoneId=3 = internet origin
  ReferrerUrl and HostUrl fields present in Win10+
  (confirm which site delivered the file)

explorer.exe parent context:
- explorer spawning wscript means the user double-clicked
  the .js file directly in Explorer or from an email
  attachment saved to disk - check Recent files:
  %APPDATA%\\Roaming\\Microsoft\\Windows\\Recent\\*.lnk`,
        tools: `Explorer.exe parent (user double-click):
- Most common for commodity JS delivery
- User receives ZIP, extracts .js, double-clicks thinking
  it's a document - wscript runs silently

Browser parent:
- Drive-by download delivering .js file
- Browser auto-opens downloaded .js (rare - most browsers
  now prompt before opening script files, but older
  configs and IE/legacy Edge allow auto-open)
- More common: browser downloads, user manually opens

Office parent:
- VBA macro drops a .js file then executes it via Shell()
- Less common than direct wscript.exe delivery but creates
  a cleaner two-stage chain (macro handles download,
  JS handles execution/persistence)

Families using these chains:
Gootloader (SEO poisoning -> browser download -> user opens .js)
Qakbot variants
TA505 campaigns
Various phishing operators`,
        ossdetect: `Sigma:
- proc_creation_win_wscript_jscript_susp_parent.yml
- proc_creation_win_explorer_wscript_child.yml
- proc_creation_win_browser_susp_child_process.yml
  (covers browser spawning any script host)

Atomic Red Team:
- T1059.007 (parent process variants)

Hayabusa:
- BrowserSpawnScriptHost rules
- OfficeSpawnWSH category

Velociraptor:
- Windows.EventLogs.Sysmon
- Windows.Forensics.BrowserHistory
  (correlate download time with wscript execution time)

Gootloader-specific:
- ANY.RUN Gootloader behavioral signatures
- Velociraptor Windows.Forensics.Gootloader artifact`,
        notes: "The explorer.exe parent is the most common real-world path for JScript delivery - it means the user double-clicked the .js file directly, relying on the default Windows file association (wscript.exe handles .js). This is the 'ZIP attachment -> extract -> double-click' chain. Gootloader is the canonical example and worth understanding in depth: it uses SEO poisoning to rank malicious sites in search results for legal/business document searches, delivers a large obfuscated .js file disguised as the document, and relies entirely on the user double-clicking it. The browser parent variant is less common now because modern browsers (Chrome, Edge) warn before opening script files downloaded from the internet - but it still surfaces in environments with older browser configurations or where the .js is delivered inside a password-protected ZIP (bypasses browser warning because the file is 'opened' from the ZIP handler, not the browser directly). The Office parent variant is the most sophisticated - it means a macro is orchestrating the JScript execution as a second stage, suggesting a more deliberate operator rather than commodity tooling.",
        apt: [
          { cls: "apt-mul", name: "Gootloader", note: "Canonical example of explorer-spawned wscript via user double-click of SEO-poisoned .js lure." },
          { cls: "apt-mul", name: "TA505", note: "Browser and email delivery chains resulting in wscript execution documented across campaigns." },
          { cls: "apt-mul", name: "Phishing Operators", note: "ZIP-delivered .js with explorer parent is a standard commodity phishing pattern." },
          { cls: "apt-cn", name: "APT41", note: "Multi-stage chains using Office macro dropping and executing JScript documented in intrusion reports." }
        ],
        cite: "MITRE ATT&CK T1059.007, T1566.001"
      }
    ]
  },
  {
    id: "T1047",
    name: "Windows Management Instrumentation",
    desc: "wmic.exe process create, remote WMI execution, WMI subscription persistence",
    rows: [
      {
        sub: "T1047 - Local Process Creation via wmic",
        indicator: "wmic.exe with 'process call create' argument - spawning a process via WMI to avoid direct cmd/PS execution",
        sysmon: `EventID=1
Image=*\\wmic.exe
CommandLine=*process*call*create*

// Also watch for child processes of wmiprvse.exe
// that are not typical WMI management children:
EventID=1
ParentImage=*\\wmiprvse.exe
Image NOT IN:
  *\\WmiPrvSE.exe
  *\\msiexec.exe
  *\\scrcons.exe
  (other known-good WMI children in your environment)`,
        kibana: `// Primary: wmic process call create
winlog.event_id: 1
AND process.name: "wmic.exe"
AND process.command_line: (*process* AND *call* AND *create*)

// Supplementary: suspicious wmiprvse.exe children
winlog.event_id: 1
AND process.parent.name: "wmiprvse.exe"
AND NOT process.name: ("WmiPrvSE.exe" OR "msiexec.exe" OR "scrcons.exe")`,
        powershell: `# Hunt for wmic process call create executions
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=1
} | Where-Object {
  $_.Properties[4].Value -like '*\\wmic.exe' -and
  $_.Properties[10].Value -match 'process\s+call\s+create'
} | Select TimeCreated,
  @{n='CmdLine';e={$_.Properties[10].Value}},
  @{n='Parent';e={($_.Properties[20].Value -split '\\\\')[-1]}},
  @{n='User';e={$_.Properties[12].Value}} |
  Sort-Object TimeCreated -Descending

# Supplementary: unexpected wmiprvse.exe children
$knownGoodWmiChildren = @('WmiPrvSE.exe','msiexec.exe','scrcons.exe')
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=1
} | Where-Object {
  $_.Properties[20].Value -like '*\\wmiprvse.exe' -and
  $knownGoodWmiChildren -notcontains
    ($_.Properties[4].Value -split '\\\\')[-1]
} | Select TimeCreated,
  @{n='Child';e={($_.Properties[4].Value -split '\\\\')[-1]}},
  @{n='CmdLine';e={$_.Properties[10].Value}},
  @{n='User';e={$_.Properties[12].Value}}`,
        registry: `No direct registry artifact from wmic process execution.

WMI repository location (the underlying database):
- C:\\Windows\\System32\\wbem\\Repository\\
  (OBJECTS.DATA, INDEX.BTR, INDEX.MAP)
  Not human-readable directly - use specialized tools
  (PyWMIPersistenceFinder, WMI-Forensics) for analysis

Investigation pivots:
- Child process of wmic or wmiprvse.exe:
  Sysmon EID 1, filter ParentImage to find what
  wmic actually launched
- Network connections from spawned child:
  Sysmon EID 3 within same session
- wmic.exe is deprecated as of Windows 11 24H2 -
  its presence in Sysmon logs on modern endpoints
  is itself a mild anomaly worth noting

wmic.exe location:
- C:\\Windows\\System32\\wbem\\wmic.exe (legitimate)
- wmic.exe found anywhere else = high-confidence IOC`,
        tools: `Cobalt Strike (WMI lateral movement module)
Metasploit (exploit/windows/local/wmi)
Impacket wmiexec.py (remote WMI execution without wmic)
CrackMapExec (--exec-method wmiexec)
Custom scripts using WMI COM objects directly
  (bypasses wmic.exe entirely - harder to detect)
PowerShell Invoke-WmiMethod / Invoke-CimMethod
  (same underlying WMI, no wmic.exe on disk)

Note on detection evasion: sophisticated operators
avoid wmic.exe entirely and call WMI COM objects
directly from PowerShell or via compiled code.
In those cases, the execution artifact shifts to
wmiprvse.exe spawning unexpected children rather
than wmic.exe appearing in process logs.`,
        ossdetect: `Sigma:
- proc_creation_win_wmic_process_creation.yml
- proc_creation_win_wmiprvse_susp_child_process.yml
- proc_creation_win_wmic_susp_execution.yml

Atomic Red Team:
- T1047 Test #1 (wmic process call create)
- T1047 Test #2 (WMI via PowerShell)

Hayabusa:
- WMI process creation detection rules
- wmiprvse child process anomaly rules

Velociraptor:
- Windows.EventLogs.Sysmon
- Windows.System.Wmi (WMI namespace enumeration)
- Windows.Forensics.WMIPersistence`,
        notes: "wmic process call create is the most direct WMI execution path - it tells WMI to instantiate the Win32_Process class and call its Create method, spawning a new process. The resulting child process has wmiprvse.exe as its parent rather than cmd.exe or powershell.exe, which is the key detection pivot. This parent-swap is intentional: adversaries use it to break the process ancestry chain and make the spawned process appear to originate from a system management context rather than a user shell. The wmiprvse.exe suspicious child detection is arguably more durable than the wmic.exe detection because it catches cases where the attacker calls WMI COM objects directly (bypassing wmic.exe entirely) as well as the standard wmic path. False positives: wmiprvse.exe legitimately spawns msiexec.exe, scrcons.exe, and a handful of other management processes - build your allowlist from a baseline of normal WMI activity in your environment before alerting on everything. Also note: wmic.exe deprecated in Windows 11 24H2 but still present and functional on virtually all enterprise endpoints you will encounter in practice.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "WMI process execution documented across multiple operations including SolarWinds follow-on activity." },
          { cls: "apt-cn", name: "APT41", note: "wmic.exe and direct WMI COM execution documented in intrusions across multiple sectors." },
          { cls: "apt-cn", name: "APT32", note: "WMI-based execution used for lateral movement and staging in documented operations." },
          { cls: "apt-mul", name: "Ransomware", note: "WMI process creation used for lateral movement and payload execution across many ransomware operations." },
          { cls: "apt-mul", name: "Cobalt Strike", note: "Built-in WMI lateral movement module used extensively by ransomware affiliates and APT operators." }
        ],
        cite: "MITRE ATT&CK T1047"
      },
      {
        sub: "T1047 - Remote WMI Execution",
        indicator: "wmic.exe with /node: flag targeting remote host - lateral movement via WMI over DCOM/RPC",
        sysmon: `// On SOURCE host - wmic with remote /node: target:
EventID=1
Image=*\\wmic.exe
CommandLine=*/node:*

// On DESTINATION host - wmiprvse.exe spawning
// unexpected child process (incoming WMI execution):
EventID=1
ParentImage=*\\wmiprvse.exe
// Cross-reference: does this system normally receive
// remote WMI connections? If not, any wmiprvse child
// is suspicious.

// Network connection from source:
EventID=3
Image=*\\wmic.exe
DestinationPort=135
// (DCOM initial negotiation - then ephemeral port)`,
        kibana: `// Source host: wmic targeting remote system
winlog.event_id: 1
AND process.name: "wmic.exe"
AND process.command_line: *\/node\:*

// Destination host: wmiprvse spawning processes
// (correlate with source network events)
winlog.event_id: 1
AND process.parent.name: "wmiprvse.exe"
AND NOT process.name: ("WmiPrvSE.exe" OR "msiexec.exe")

// Network: wmic initiating DCOM connection
winlog.event_id: 3
AND process.name: "wmic.exe"
AND destination.port: 135`,
        powershell: `# Hunt for remote WMI execution attempts (source side)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=1
} | Where-Object {
  $_.Properties[4].Value -like '*\\wmic.exe' -and
  $_.Properties[10].Value -match '/node:'
} | Select TimeCreated,
  @{n='CmdLine';e={$_.Properties[10].Value}},
  @{n='User';e={$_.Properties[12].Value}},
  @{n='Parent';e={($_.Properties[20].Value -split '\\\\')[-1]}} |
  Sort-Object TimeCreated -Descending

# Hunt for DCOM network connections from wmic (EID 3)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=3
} | Where-Object {
  $_.Properties[4].Value -like '*\\wmic.exe' -and
  $_.Properties[14].Value -eq '135'
} | Select TimeCreated,
  @{n='DestIP';e={$_.Properties[14].Value}},
  @{n='DestPort';e={$_.Properties[16].Value}},
  @{n='User';e={$_.Properties[12].Value}}`,
        registry: `No registry artifact on source host from wmic /node: execution.

On DESTINATION host - Windows event log artifacts:
- Security Event ID 4624 (Logon):
  LogonType 3 (Network logon) from source IP
  around the same time as wmiprvse child spawn
  - this confirms the authentication leg of
  the WMI connection
- Security Event ID 4688 (Process Creation,
  if process auditing enabled):
  Child process of wmiprvse.exe on destination

Network forensics pivot:
- DCOM uses TCP 135 for initial negotiation
  then negotiates a dynamic high port (1024-65535)
  for the actual data transfer
- Zeek/Suricata DCOM logs on your network sensor
  can correlate the source-destination pair
- This is where host-side and network-side
  detection complement each other directly`,
        tools: `wmic.exe /node: (built-in, most common)
Impacket wmiexec.py
  - Implements WMI execution without wmic.exe
  - Operates over DCOM directly
  - Leaves wmiprvse.exe child artifact on target
  - Does not use wmic.exe on source host
CrackMapExec (wmiexec method)
Cobalt Strike WMI lateral movement
PowerShell Invoke-WmiMethod -ComputerName
PowerShell New-CimSession + Invoke-CimMethod
  (modern replacement for wmic, same detection surface)

Key distinction: Impacket wmiexec.py and CrackMapExec
wmiexec do NOT use wmic.exe on the source host -
the /node: indicator only catches wmic.exe usage.
For those tools, detection shifts entirely to the
destination host's wmiprvse.exe child process and
the Security Event 4624 network logon.`,
        ossdetect: `Sigma:
- proc_creation_win_wmic_remote_execution.yml
- proc_creation_win_wmiprvse_susp_child_process.yml
- network_connection_win_wmic_remote.yml

Atomic Red Team:
- T1047 Test #3 (remote WMI execution)
- T1021.006 (Windows Remote Management - related)

Hayabusa:
- RemoteWMIExecution rules
- DCOM lateral movement detection category

Velociraptor:
- Windows.EventLogs.Sysmon (both source and dest)
- Windows.Network.NetstatEnriched (active DCOM connections)

Network-side (complements host detection):
- Zeek dce_rpc.log: filter for WMI-related operations
- Suricata: DCOM/RPC anomaly rules
- hunt.6b74.dev Lateral Movement reference
  for the network-side complement to this detection`,
        notes: "Remote WMI execution is one of the cleanest lateral movement techniques from an adversary perspective: it requires no dropped binary on the target, uses a legitimate Windows protocol (DCOM/RPC), authenticates via normal Windows credentials, and leaves a minimal footprint. The network traffic blends into background Windows management noise in environments that use WMI for legitimate remote management. Detection requires correlating artifacts across two hosts: the source (wmic /node: command or DCOM network connection) and the destination (wmiprvse.exe spawning an unexpected child, Security Event 4624 network logon). Neither artifact alone is high-fidelity - combined they are. This is a genuine case where your network sensor (Zeek/Suricata on the wire) and host sensor (Sysmon on the endpoint) complement each other: the DCOM connection is visible at the network layer, and the process creation is visible at the host layer. Neither sensor alone gives the full picture. If you see wmiprvse.exe spawning cmd.exe or powershell.exe on a host that is not a WMI management server, treat it as high-confidence lateral movement until proven otherwise.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Remote WMI lateral movement documented extensively across espionage operations." },
          { cls: "apt-cn", name: "APT41", note: "WMI-based lateral movement documented in intrusions across tech, healthcare, and government sectors." },
          { cls: "apt-cn", name: "APT32", note: "wmiexec-style lateral movement documented in operations against Southeast Asian targets." },
          { cls: "apt-mul", name: "Ransomware", note: "WMI lateral movement used for ransomware propagation - Ryuk, Conti, and others documented." },
          { cls: "apt-mul", name: "Impacket", note: "wmiexec.py is a standard tool across red team and APT operations for agentless lateral movement." }
        ],
        cite: "MITRE ATT&CK T1047, T1021"
      },
      {
        sub: "T1047 - WMI Event Subscription Persistence",
        indicator: "WMI EventFilter, EventConsumer, or FilterToConsumerBinding creation - fileless persistence via WMI repository",
        sysmon: `// Sysmon has three dedicated WMI persistence event IDs:

EventID=19 (WmiEventFilter activity detected)
// Fires when a WMI event filter is registered
// Filter = the trigger condition (e.g., system boot,
// process creation, time interval)
// Key fields: Name, Query, QueryLanguage

EventID=20 (WmiEventConsumer activity detected)
// Fires when a WMI event consumer is registered
// Consumer = the action to take when filter fires
// Two dangerous consumer types:
//   CommandLineEventConsumer (runs a command)
//   ActiveScriptEventConsumer (runs VBScript/JScript)
// Key fields: Name, Type, Destination/ScriptText

EventID=21 (WmiEventConsumerToFilter activity)
// Fires when filter and consumer are bound together
// This is the final step that arms the subscription
// Key fields: Consumer, Filter`,
        kibana: `// Alert on any WMI subscription activity (EID 19/20/21)
winlog.event_id: (19 OR 20 OR 21)

// Narrow to high-risk consumer types:
winlog.event_id: 20
AND winlog.event_data.Type: ("CommandLineEventConsumer" OR "ActiveScriptEventConsumer")

// Full subscription chain (filter + consumer + binding):
winlog.event_id: 19
// then correlate by winlog.event_data.Name
// to find matching EID 20 and EID 21 events`,
        powershell: `# Hunt for WMI event subscriptions via Sysmon EID 19/20/21
19, 20, 21 | ForEach-Object {
  $id = $_
  Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational';
    ID=$id
  } -ErrorAction SilentlyContinue
} | Select TimeCreated, Id,
  @{n='EventType';e={
    switch ($_.Id) {
      19 { 'WMI Filter Registered' }
      20 { 'WMI Consumer Registered' }
      21 { 'Filter-Consumer Binding' }
    }
  }},
  @{n='Details';e={$_.Message}} |
  Sort-Object TimeCreated -Descending

# Direct WMI query for active subscriptions
# (run on live host or via Velociraptor/remote PS)
Get-WMIObject -Namespace root\subscription -Class __EventFilter |
  Select Name, Query, QueryLanguage

Get-WMIObject -Namespace root\subscription -Class __EventConsumer |
  Select Name, __CLASS, CommandLineTemplate, ScriptText

Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding |
  Select Filter, Consumer`,
        registry: `WMI persistence does NOT use registry run keys or
scheduled task XML - it lives in the WMI repository:

C:\\Windows\\System32\\wbem\\Repository\\
  OBJECTS.DATA  - main object store
  INDEX.BTR     - index file
  INDEX.MAP     - index map

Not directly human-readable - use these tools:
- PyWMIPersistenceFinder (David Reaves / mandiant)
  python PyWMIPersistenceFinder.py OBJECTS.DATA
- WMIForensics (python, similar capability)
- Velociraptor artifact Windows.Forensics.WMIPersistence
- autoruns.exe (Sysinternals) - lists WMI subscriptions
  under the WMI tab

Legitimate WMI subscriptions exist in healthy
environments (SCCM, monitoring agents, AV products)
- baseline before alerting on all subscriptions.
Known-good namespaces: root\ccm, root\cimv2\sms
Adversary subscriptions typically use: root\subscription`,
        tools: `PowerSploit / PowerShell Empire:
- New-UserPersistenceOption -WMI
- Installs CommandLineEventConsumer triggering on logon

Metasploit:
- exploit/windows/local/wmi_persistence

Sharp-WMI (C# WMI execution tool)
WMImplant (PowerShell WMI C2 framework)
Cobalt Strike (WMI persistence module)

Manual WMI subscription (PowerShell):
$filter = Set-WmiInstance -Namespace root\subscription
  -Class __EventFilter -Arguments @{
    Name='Updater';
    QueryLanguage='WQL';
    Query='SELECT * FROM __InstanceModificationEvent
      WITHIN 60 WHERE TargetInstance ISA "Win32_PerfFormattedData_PerfOS_System"'
  }
$consumer = Set-WmiInstance -Namespace root\subscription
  -Class CommandLineEventConsumer -Arguments @{
    Name='Updater';
    CommandLineTemplate='cmd /c payload.exe'
  }
Set-WmiInstance -Namespace root\subscription
  -Class __FilterToConsumerBinding -Arguments @{
    Filter=$filter; Consumer=$consumer
  }`,
        notes: "WMI event subscription persistence is the most forensically evasive standard persistence technique on Windows. There is no registry run key, no scheduled task XML, no startup folder file - the persistence object lives entirely inside the WMI repository binary (OBJECTS.DATA), which most IR tools and AV products do not inspect by default. Sysmon EID 19/20/21 are the primary detection mechanism and are only logged if Sysmon is deployed with WMI monitoring enabled in its config - verify your Sysmon config actually captures these before assuming you have coverage. The three-event chain (19 = filter registered, 20 = consumer registered, 21 = binding created) tells the complete story: what triggers it, what it does, and that it is now armed. In practice, EID 21 (binding) is the highest-value single alert because a filter and consumer registered independently are less meaningful than when they are bound together. Two consumer types are dangerous: CommandLineEventConsumer (runs a shell command) and ActiveScriptEventConsumer (runs VBScript or JScript inline - no file on disk at all). Legitimate WMI subscriptions exist (SCCM, some AV products) - baseline your environment before alerting on all subscription activity. The root\\subscription namespace is the canonical adversary location; legitimate subscriptions more often live under root\\cimv2 or vendor-specific namespaces.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "WMI subscription persistence documented in multiple long-dwell espionage operations." },
          { cls: "apt-cn", name: "APT41", note: "WMI event subscriptions used for persistence in operations across multiple sectors." },
          { cls: "apt-mul", name: "FIN6", note: "WMI subscription persistence documented in financial sector intrusions." },
          { cls: "apt-mul", name: "Turla", note: "WMI-based persistence documented across long-term espionage campaigns." },
          { cls: "apt-mul", name: "Red Teams", note: "WMI subscription persistence is a standard red team technique due to evasiveness - widely emulated." }
        ],
        cite: "MITRE ATT&CK T1047, T1546.003"
      }
    ]
  },
  {
    id: "T1053.005",
    name: "Scheduled Task/Job: Scheduled Task",
    desc: "schtasks.exe creation, COM-based task creation, remote scheduled tasks",
    rows: [
      {
        sub: "T1053.005 - Suspicious Task Creation via schtasks.exe",
        indicator: "schtasks.exe /create with action pointing to suspicious binary path or scripting interpreter",
        sysmon: `EventID=1
Image=*\\schtasks.exe
CommandLine=*/create*
AND CommandLine matches (any of):
  *\\AppData\\*
  OR *\\Temp\\*
  OR *\\ProgramData\\*
  OR *\\Users\\Public\\*
  OR *powershell*
  OR *cmd.exe*
  OR *wscript*
  OR *cscript*
  OR *mshta*
  OR *rundll32*
  OR *regsvr32*
  OR *certutil*

// Supplementary - Windows Security Event:
EventID=4698 (Task Scheduler / Security log)
// Fires on every task creation regardless of method
// (schtasks.exe, COM API, remote) - higher coverage
// than Sysmon EID 1 alone`,
        kibana: `// Primary: schtasks /create with suspicious action
winlog.event_id: 1
AND process.name: "schtasks.exe"
AND process.command_line: *\/create*
AND process.command_line: (*\\AppData\\* OR *\\Temp\\* OR *\\ProgramData\\* OR *powershell* OR *wscript* OR *mshta* OR *rundll32* OR *regsvr32* OR *certutil*)

// Supplementary: Windows Security Event 4698 (all task creation)
winlog.event_id: 4698
AND winlog.channel: "Security"`,
        powershell: `# Hunt for suspicious schtasks /create executions (Sysmon EID 1)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=1
} | Where-Object {
  $_.Properties[4].Value -like '*\\schtasks.exe' -and
  $_.Properties[10].Value -match '/create' -and
  $_.Properties[10].Value -match
    '(AppData|Temp|ProgramData|Public|powershell|wscript|cscript|mshta|rundll32|regsvr32|certutil)'
} | Select TimeCreated,
  @{n='CmdLine';e={$_.Properties[10].Value}},
  @{n='Parent';e={($_.Properties[20].Value -split '\\\\')[-1]}},
  @{n='User';e={$_.Properties[12].Value}} |
  Sort-Object TimeCreated -Descending

# Supplementary: Security Event 4698 (task created - all methods)
Get-WinEvent -FilterHashtable @{
  LogName='Security';
  ID=4698
} | Select TimeCreated,
  @{n='TaskName';e={
    ([xml]$_.ToXml()).Event.EventData.Data |
    Where-Object { $_.Name -eq 'TaskName' } | Select-Object -Expand '#text'
  }},
  @{n='TaskContent';e={
    ([xml]$_.ToXml()).Event.EventData.Data |
    Where-Object { $_.Name -eq 'TaskContent' } | Select-Object -Expand '#text'
  }},
  @{n='User';e={$_.UserId}} |
  Sort-Object TimeCreated -Descending`,
        registry: `Scheduled task artifacts on disk:
- C:\\Windows\\System32\\Tasks\\<TaskName>
  (XML file - human readable, contains full task config
  including action, trigger, principal, and run-as user)
- C:\\Windows\\SysWOW64\\Tasks\\<TaskName>
  (32-bit task storage on 64-bit systems)

Registry task keys (legacy/additional storage):
- HKLM\\SOFTWARE\\Microsoft\\Windows NT\\
  CurrentVersion\\Schedule\\TaskCache\\Tasks\\
- HKLM\\SOFTWARE\\Microsoft\\Windows NT\\
  CurrentVersion\\Schedule\\TaskCache\\Tree\\
  (tree view of task names by folder path)

Investigation pivots:
- Read the XML in C:\\Windows\\System32\\Tasks\\
  to see the full task definition:
  Get-Content "C:\\Windows\\System32\\Tasks\\<name>"
- Check SubjectUserName in Security EID 4698 -
  SYSTEM creating tasks is normal;
  a standard user account creating tasks is suspicious
- Check trigger type: OnLogon and AtStartup triggers
  indicate persistence intent vs one-time execution`,
        tools: `schtasks.exe /create (built-in - most common)
Task Scheduler MMC (taskschd.msc - GUI, less common in ops)
PowerShell New-ScheduledTask / Register-ScheduledTask
  (COM-based - does not invoke schtasks.exe,
  only detectable via EID 4698 not EID 1)
Impacket atexec.py (remote task scheduling)
CrackMapExec (--exec-method atexec)
Cobalt Strike (scheduled task persistence module)
SharPersist (C# persistence tool with schtasks support)

Common adversary task action patterns:
- /tr "powershell.exe -ep bypass -w hidden -c <cmd>"
- /tr "cmd.exe /c <staging command>"
- /tr "wscript.exe %APPDATA%\\payload.vbs"
- /tr "C:\\ProgramData\\<random>.exe"
- /sc ONLOGON /tn "Windows Update" (disguised name)
- /sc MINUTE /mo 5 (beacon persistence)`,
        ossdetect: `Sigma:
- proc_creation_win_schtasks_creation_susp_path.yml
- proc_creation_win_schtasks_creation_susp_action.yml
- win_security_scheduled_task_creation.yml (EID 4698)
- proc_creation_win_schtasks_susp_parent.yml

Atomic Red Team:
- T1053.005 Test #1 (schtasks /create local)
- T1053.005 Test #2 (PowerShell Register-ScheduledTask)
- Multiple variants covering different triggers/actions

Hayabusa:
- ScheduledTaskCreation rules (EID 1 + EID 4698)
- SuspiciousTaskAction detection category

Velociraptor:
- Windows.System.ScheduledTasks
  (enumerates all tasks with full XML content)
- Windows.EventLogs.Sysmon
- Windows.Forensics.Autoruns (lists scheduled tasks)

Sysinternals autoruns.exe:
- Scheduled Tasks tab shows all registered tasks
- Highlights unsigned task actions in yellow/red`,
        notes: "Scheduled tasks are one of the most commonly abused persistence mechanisms because they are well-understood by IT staff (reducing scrutiny), support a wide range of triggers (logon, startup, time interval, event-based), and can run as SYSTEM with minimal configuration. The schtasks.exe /create command is the most visible path - it generates Sysmon EID 1 with the full command line including the task action, which is often where the suspicious binary path or interpreter is visible. The detection is path-and-action focused: system binaries in standard paths (C:\\Windows\\System32) creating tasks that run system management tools are normal; tasks running interpreters (powershell, wscript, mshta) or binaries from user-writable paths (AppData, Temp, ProgramData) are suspicious. Security Event 4698 is the more comprehensive signal because it fires regardless of how the task was created - schtasks.exe, PowerShell COM API, or remote scheduling - and the event content includes the full task XML. The task XML file in C:\\Windows\\System32\\Tasks\\ is a valuable forensic artifact: it contains the full action, trigger, principal, and run-as context and persists even after the process that created it has exited. Adversaries frequently disguise task names as legitimate Windows tasks ('Windows Update', 'GoogleUpdateTask', 'AdobeFlashUpdate') - the action path is more reliable than the task name for detection.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Scheduled task persistence documented across multiple long-term espionage operations." },
          { cls: "apt-cn", name: "APT41", note: "schtasks-based persistence documented in intrusions across tech and healthcare sectors." },
          { cls: "apt-kp", name: "Lazarus", note: "Scheduled task persistence documented in CISA advisories on DPRK-attributed operations." },
          { cls: "apt-mul", name: "Ransomware", note: "Scheduled tasks used for persistence and propagation across Ryuk, Conti, LockBit operations." },
          { cls: "apt-mul", name: "Cobalt Strike", note: "Built-in scheduled task persistence module used across red team and APT operations." }
        ],
        cite: "MITRE ATT&CK T1053.005"
      },
      {
        sub: "T1053.005 - Remote Scheduled Task Creation",
        indicator: "schtasks.exe /create with /s flag targeting remote host - lateral movement or remote persistence via Task Scheduler",
        sysmon: `// On SOURCE host:
EventID=1
Image=*\\schtasks.exe
CommandLine=*/create*
AND CommandLine=*/s *
// /s <hostname/IP> = remote target

// Network connection from source:
EventID=3
Image=*\\schtasks.exe
DestinationPort=445
// (schtasks remote uses SMB - TCP 445)

// On DESTINATION host - Security Event:
EventID=4698 (task created)
// SubjectUserName will be the remote authenticating user
// SubjectLogonId correlates to a Type 3 network logon
// (Security EID 4624 LogonType=3 around same time)`,
        kibana: `// Source: schtasks targeting remote host
winlog.event_id: 1
AND process.name: "schtasks.exe"
AND process.command_line: (*\/create* AND *\/s\ *)

// Source: SMB connection from schtasks
winlog.event_id: 3
AND process.name: "schtasks.exe"
AND destination.port: 445

// Destination: task created (correlate by time + username)
winlog.event_id: 4698
AND winlog.channel: "Security"
// Then join on SubjectLogonId to Security EID 4624
// LogonType=3 to confirm remote origin`,
        powershell: `# Hunt for remote schtasks /create (source host)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=1
} | Where-Object {
  $_.Properties[4].Value -like '*\\schtasks.exe' -and
  $_.Properties[10].Value -match '/create' -and
  $_.Properties[10].Value -match '/s\s+\S+'
} | Select TimeCreated,
  @{n='CmdLine';e={$_.Properties[10].Value}},
  @{n='User';e={$_.Properties[12].Value}},
  @{n='Parent';e={($_.Properties[20].Value -split '\\\\')[-1]}} |
  Sort-Object TimeCreated -Descending

# SMB connections from schtasks (EID 3)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=3
} | Where-Object {
  $_.Properties[4].Value -like '*\\schtasks.exe' -and
  $_.Properties[16].Value -eq '445'
} | Select TimeCreated,
  @{n='DestIP';e={$_.Properties[14].Value}},
  @{n='User';e={$_.Properties[12].Value}}`,
        registry: `On DESTINATION host - task XML artifact:
- C:\\Windows\\System32\\Tasks\\<TaskName>
  Created by the remote scheduling operation
  SubjectUserName in EID 4698 is the remote user -
  correlate with Security EID 4624 (LogonType=3)
  to confirm which account was used and from where

Lateral movement context:
- Remote scheduled task creation requires:
  1. Valid credentials on the target (or pass-the-hash)
  2. SMB access to target (TCP 445)
  3. Task Scheduler service running on target
- This is the same credential/access requirement
  as PsExec, but uses a different protocol path
  and leaves a different artifact set

Network pivot:
- SMB connection (TCP 445) from source to target
  is visible in Zeek conn.log and Suricata alerts
- Cross-reference with hunt.6b74.dev Lateral Movement
  reference for the network-side complement`,
        tools: `schtasks.exe /create /s <target> (built-in)
Impacket atexec.py
  - Implements remote task scheduling over SMB
  - Does not use schtasks.exe on source host
  - Creates task, runs it, deletes it (less persistent)
CrackMapExec --exec-method atexec
PowerShell Register-ScheduledTask with
  -CimSession (remote CIM session)
Cobalt Strike (remote task scheduling module)

Key distinction: Impacket atexec and CrackMapExec
atexec do NOT generate schtasks.exe EID 1 on source -
detection shifts entirely to destination EID 4698
and the SMB/authentication artifacts.

atexec pattern: creates task, runs it immediately,
deletes it - watch for short-lived tasks (EID 4698
task created followed quickly by EID 4699 task deleted)`,
        ossdetect: `Sigma:
- proc_creation_win_schtasks_remote.yml
- win_security_scheduled_task_creation.yml
  (EID 4698 with network logon correlation)
- network_connection_win_schtasks_smb.yml

Atomic Red Team:
- T1053.005 Test #4 (remote scheduled task)

Hayabusa:
- RemoteScheduledTask rules
- SMB lateral movement correlation rules

Velociraptor:
- Windows.EventLogs.Sysmon (both hosts)
- Windows.System.ScheduledTasks (destination)
- Windows.Forensics.Autoruns (destination)`,
        notes: "Remote scheduled task creation is a lateral movement technique that predates most modern C2 frameworks - the Windows 'at' command (now deprecated) and its successor schtasks /s have been used for decades. The detection split between source and destination is the same pattern as remote WMI: the source generates a process creation event (schtasks /s) and a network connection (SMB to 445), while the destination generates a task creation event (Security EID 4698) with a network logon (Security EID 4624 LogonType=3). The EID 4699 (task deleted) paired shortly after EID 4698 is worth a separate alert - it's the signature of execution-only remote task use (Impacket atexec pattern) where the adversary creates a task, runs it immediately, and deletes it to minimize forensic evidence. A task that exists for less than 60 seconds and was created by a remote user is high-confidence malicious activity.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Remote scheduled task lateral movement documented in SolarWinds follow-on intrusion activity." },
          { cls: "apt-cn", name: "APT41", note: "Remote task scheduling documented as lateral movement method across multiple sector intrusions." },
          { cls: "apt-mul", name: "Impacket", note: "atexec.py is a standard tool in red team and APT lateral movement toolkits." },
          { cls: "apt-mul", name: "Ransomware", note: "Remote task creation for ransomware propagation documented across Conti, Ryuk, and LockBit operations." }
        ],
        cite: "MITRE ATT&CK T1053.005, T1021"
      },
      {
        sub: "T1053.005 - Scheduled Task Action Pointing to Suspicious Binary",
        indicator: "Existing or newly created scheduled task with action path in user-writable directory or running a scripting interpreter",
        sysmon: `// Sysmon does not directly inspect task XML content -
// use Windows Security Event 4698 for this.
// Sysmon contribution: catch the EXECUTION of the task:

EventID=1
// Task runs as SYSTEM or as a specific user account
// Parent will be taskeng.exe (legacy) or svchost.exe
// (modern Task Scheduler host):
ParentImage=*\\svchost.exe
ParentCommandLine=*Schedule*
// AND child Image is suspicious:
Image matches:
  *\\AppData\\* OR *\\Temp\\* OR *\\ProgramData\\*
  OR *\\powershell.exe OR *\\wscript.exe
  OR *\\mshta.exe OR *\\rundll32.exe`,
        kibana: `// Task execution: svchost (scheduler) spawning suspicious child
winlog.event_id: 1
AND process.parent.name: "svchost.exe"
AND process.parent.command_line: *Schedule*
AND process.command_line: (*\\AppData\\* OR *\\Temp\\* OR *\\ProgramData\\* OR *powershell* OR *wscript* OR *mshta* OR *rundll32*)

// Security Event: task created with suspicious action
// (parse TaskContent XML field for the action path)
winlog.event_id: 4698
AND winlog.channel: "Security"
AND winlog.event_data.TaskContent: (*AppData* OR *Temp* OR *ProgramData* OR *powershell* OR *wscript* OR *mshta* OR *rundll32*)`,
        powershell: `# Enumerate all scheduled tasks and flag suspicious actions
Get-ScheduledTask | ForEach-Object {
  $task = $_
  $actions = $task.Actions
  foreach ($action in $actions) {
    if ($action.Execute -match
      '(AppData|Temp|ProgramData|Public|powershell|wscript|cscript|mshta|rundll32|regsvr32|certutil)') {
      [PSCustomObject]@{
        TaskName    = $task.TaskName
        TaskPath    = $task.TaskPath
        Execute     = $action.Execute
        Arguments   = $action.Arguments
        State       = $task.State
        Author      = $task.Author
        RunAs       = $task.Principal.UserId
        LastRun     = $task.LastRunTime
        NextRun     = $task.NextRunTime
      }
    }
  }
} | Sort-Object TaskPath

# Also check raw XML for tasks that Get-ScheduledTask
# may not fully surface (e.g., broken/hidden tasks):
Get-ChildItem C:\\Windows\\System32\\Tasks -Recurse -File |
  ForEach-Object {
    $content = Get-Content $_.FullName -Raw
    if ($content -match
      '(AppData|Temp|ProgramData|powershell|wscript|mshta|rundll32)') {
      [PSCustomObject]@{
        File    = $_.FullName
        Snippet = ($content -split '\n' |
          Select-String 'AppData|Temp|ProgramData|powershell|wscript|mshta|rundll32' |
          Select-Object -First 3) -join '; '
      }
    }
  }`,
        registry: `Task XML files - primary forensic artifact:
- C:\\Windows\\System32\\Tasks\\<TaskName>
  Read with Get-Content or any text editor
  Key XML elements to inspect:
  <Exec><Command> - the binary being run
  <Exec><Arguments> - command line arguments
  <Principal><UserId> - run-as account
  <Triggers> - what causes the task to fire
  <RegistrationInfo><Author> - who created it

Registry task cache (secondary):
- HKLM\\SOFTWARE\\Microsoft\\Windows NT\\
  CurrentVersion\\Schedule\\TaskCache\\Tasks\\{GUID}\\
  Actions value contains the task action in binary
  format - use specialized tools to parse

Deleted task forensics:
- If task XML file is deleted, the registry cache
  may still contain the task GUID and action data
- $MFT (NTFS master file table) retains metadata
  for deleted task XML files including timestamps
  and original filename`,
        tools: `This indicator focuses on HUNTING existing tasks
rather than catching creation in real-time.

Useful for:
- Post-compromise triage (what persists on this host?)
- Baseline deviation (new tasks since last check)
- Threat hunting sweeps across fleet

Tools for task enumeration:
- Get-ScheduledTask (PowerShell - built-in)
- schtasks /query /fo LIST /v (schtasks.exe)
- autoruns.exe -a * -ct (Sysinternals - CSV output)
- Velociraptor Windows.System.ScheduledTasks
- Carbon Black / CrowdStrike scheduled task queries

Red team tools that create tasks:
SharPersist (/t schtask)
Cobalt Strike persistence module
Metasploit persistence/windows/schtasks
Custom .NET / C++ task COM API callers
  (bypass schtasks.exe entirely)`,
        ossdetect: `Sigma:
- win_security_scheduled_task_creation.yml
  (parse TaskContent for suspicious actions)
- proc_creation_win_svchost_susp_child_process.yml
  (svchost Schedule spawning suspicious children)

Atomic Red Team:
- T1053.005 (multiple task persistence tests)
- T1053.005 Test #6 (task pointing to LOLBin)

Hayabusa:
- SuspiciousScheduledTaskAction rules
- TaskSchedulerSvchost child detection

Velociraptor:
- Windows.System.ScheduledTasks
  (best single artifact - full task enumeration
  with action path, trigger, and run-as context)
- Windows.Forensics.Autoruns

Sysinternals autoruns.exe:
- Most effective single tool for manual triage
- Highlights unsigned task actions
- Shows hidden/broken tasks that PowerShell misses`,
        notes: "This indicator is hunting-oriented rather than real-time detection - it's about finding what already exists rather than catching creation live. The two previous T1053.005 indicators cover real-time creation via schtasks.exe EID 1 and Security EID 4698. This one covers the scenario where a task was created by a method that didn't generate obvious telemetry (COM API, fileless stager, pre-Sysmon deployment) and you need to sweep for it. The Get-ScheduledTask PowerShell script and the raw XML scan of C:\\Windows\\System32\\Tasks\\ are the most useful live-host forensic tools for this. The svchost.exe spawning suspicious children pattern bridges the gap - it fires when an existing task actually executes, regardless of how it was created, because all modern scheduled tasks run under the Task Scheduler svchost instance. The parent command line containing 'Schedule' distinguishes the Task Scheduler svchost from the dozens of other svchost instances running on a Windows system. Adversaries frequently disguise task names as Windows Update, Windows Defender, Google Update, or similar legitimate-sounding names - always inspect the action path, not the task name, as the primary detection signal.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Disguised scheduled task names with suspicious action paths documented in long-dwell operations." },
          { cls: "apt-cn", name: "APT41", note: "Scheduled task persistence with LOLBin or interpreter actions documented across multiple intrusions." },
          { cls: "apt-kp", name: "Lazarus", note: "Persistent scheduled tasks with obfuscated PowerShell actions documented in CISA advisories." },
          { cls: "apt-mul", name: "Ransomware", note: "Pre-encryption scheduled tasks for persistence and propagation documented across ransomware families." },
          { cls: "apt-mul", name: "Red Teams", note: "Task disguise (legitimate-looking name + suspicious action) is standard red team persistence tradecraft." }
        ],
        cite: "MITRE ATT&CK T1053.005"
      }
    ]
  },
  {
    id: "T1569.002",
    name: "System Services: Service Execution",
    desc: "sc.exe service creation, PsExec service signature, suspicious binPath patterns",
    rows: [
      {
        sub: "T1569.002 - sc.exe Service Creation with Suspicious binPath",
        indicator: "sc.exe create with binPath pointing to suspicious binary, user-writable path, or scripting interpreter",
        sysmon: `EventID=1
Image=*\\sc.exe
CommandLine=*create*
AND CommandLine matches (any of):
  *binPath=*\\AppData\\*
  OR *binPath=*\\Temp\\*
  OR *binPath=*\\ProgramData\\*
  OR *binPath=*\\Users\\Public\\*
  OR *binPath=*powershell*
  OR *binPath=*cmd.exe*
  OR *binPath=*rundll32*
  OR *binPath=*mshta*

// Supplementary - Windows System Event:
EventID=7045 (System log - Service Control Manager)
// Fires on every new service installation regardless
// of method (sc.exe, API, remote) - broader coverage`,
        kibana: `// Primary: sc.exe create with suspicious binPath
winlog.event_id: 1
AND process.name: "sc.exe"
AND process.command_line: (*create* AND *binPath*)
AND process.command_line: (*AppData* OR *Temp* OR *ProgramData* OR *powershell* OR *cmd.exe* OR *rundll32* OR *mshta*)

// Supplementary: System Event 7045 (all service installs)
winlog.event_id: 7045
AND winlog.channel: "System"`,
        powershell: `# Hunt for sc.exe service creation with suspicious binPath (Sysmon EID 1)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=1
} | Where-Object {
  $_.Properties[4].Value -like '*\\sc.exe' -and
  $_.Properties[10].Value -match 'create' -and
  $_.Properties[10].Value -match 'binPath' -and
  $_.Properties[10].Value -match
    '(AppData|Temp|ProgramData|Public|powershell|cmd\.exe|rundll32|mshta)'
} | Select TimeCreated,
  @{n='CmdLine';e={$_.Properties[10].Value}},
  @{n='Parent';e={($_.Properties[20].Value -split '\\\\')[-1]}},
  @{n='User';e={$_.Properties[12].Value}} |
  Sort-Object TimeCreated -Descending

# Supplementary: System Event 7045 (new service installed - all methods)
Get-WinEvent -FilterHashtable @{
  LogName='System';
  ID=7045
} | Select TimeCreated,
  @{n='ServiceName';e={$_.Properties[0].Value}},
  @{n='ServiceFile';e={$_.Properties[1].Value}},
  @{n='ServiceType';e={$_.Properties[2].Value}},
  @{n='StartType';e={$_.Properties[3].Value}},
  @{n='AccountName';e={$_.Properties[4].Value}} |
  Sort-Object TimeCreated -Descending`,
        registry: `Service registration in registry (primary artifact):
HKLM\\SYSTEM\\CurrentControlSet\\Services\\<ServiceName>\\
  ImagePath  - the binPath (binary + arguments)
  Start      - 0=Boot, 1=System, 2=Auto, 3=Demand, 4=Disabled
  Type       - service type (0x10=Win32OwnProcess most common)
  ObjectName - run-as account (LocalSystem, NetworkService, etc.)
  Description - often blank for adversary-created services

Investigate with:
- Get-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Services\\*
  | Where-Object { $_.ImagePath -match '(Temp|AppData|ProgramData)' }
- sc qc <ServiceName> (query service config via sc.exe)

Adversary service naming patterns:
- Random alphanumeric strings: "svc_a7f3b2"
- Typosquatting: "WindowsUpdater", "WinDefend32"
- Blank DisplayName + blank Description = anomaly
- Single-character or very short service names`,
        tools: `sc.exe create (built-in - most visible)
PowerShell New-Service (COM-based, no sc.exe in logs)
  New-Service -Name "svc" -BinaryPathName "C:\\payload.exe"
  -StartupType Automatic
Metasploit (windows/manage/persistence_exe)
SharPersist (/t service)
Cobalt Strike (service-based lateral movement)
Custom service wrappers compiled in C/C++/.NET

Dual-use remote tools (also create services):
PsExec (PSEXESVC - covered in next indicator)
Impacket svcctl.py
CrackMapExec service creation

Common adversary binPath patterns:
- cmd.exe /c <payload> (service wrapping a cmd chain)
- powershell.exe -ep bypass -w hidden -c <stager>
- C:\\Windows\\Temp\\<random>.exe
- %COMSPEC% /Q /c echo <commands> > pipe (cmd redirection)`,
        ossdetect: `Sigma:
- proc_creation_win_sc_service_creation_susp_binary.yml
- win_system_service_install.yml (EID 7045)
- proc_creation_win_sc_service_creation_susp_path.yml

Atomic Red Team:
- T1569.002 Test #1 (sc.exe service creation)
- T1569.002 Test #2 (PowerShell New-Service)

Hayabusa:
- ServiceCreationSuspBinPath rules (EID 1 + 7045)
- sc.exe suspicious argument detection

Velociraptor:
- Windows.System.Services
  (enumerates all services with ImagePath and config)
- Windows.Forensics.Autoruns (Services tab)
- Windows.EventLogs.Sysmon

Sysinternals autoruns.exe:
- Services tab - highlights non-Microsoft signed binaries
- Most effective single tool for manual service triage`,
        notes: "sc.exe create is the most explicit service creation path - the full binPath is visible in the Sysmon EID 1 command line, making it straightforward to detect suspicious binary paths at creation time. System Event 7045 is the broader net: it fires regardless of whether sc.exe, PowerShell, or a compiled binary's API call was used to create the service. 7045 is underutilized in many detection stacks - it's in the System log rather than Security, so it sometimes gets overlooked in log collection policies. Worth verifying your SIEM is ingesting System log events, not just Security. The registry artifact is the most durable - even if the service was created and the creating process logs have rolled, the registry entry under HKLM\\SYSTEM\\CurrentControlSet\\Services persists until the service is explicitly deleted. Services with a blank Description, blank DisplayName, and an ImagePath in a user-writable directory are a high-confidence IOC combination. Adversaries sometimes use sc.exe create with start=demand followed immediately by sc.exe start - watch for that rapid create-then-start sequence in the same session as it indicates immediate execution intent rather than persistence setup.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Service-based execution and persistence documented across multiple espionage operations." },
          { cls: "apt-cn", name: "APT41", note: "sc.exe service creation for lateral movement and persistence documented in multiple sector intrusions." },
          { cls: "apt-mul", name: "Ransomware", note: "Service creation for persistence and propagation documented across Ryuk, Conti, BlackCat operations." },
          { cls: "apt-mul", name: "Cobalt Strike", note: "Service-based lateral movement is a built-in Cobalt Strike capability used across APT and ransomware operations." },
          { cls: "apt-kp", name: "Lazarus", note: "Malicious service installation documented in CISA advisories on DPRK-attributed intrusions." }
        ],
        cite: "MITRE ATT&CK T1569.002"
      },
      {
        sub: "T1569.002 - PsExec Service Signature (PSEXESVC)",
        indicator: "PSEXESVC service installation or PSEXESVC.exe drop on target host - PsExec lateral movement artifact",
        sysmon: `// On DESTINATION host:

// PSEXESVC.exe written to C:\\Windows\\ (EID 11):
EventID=11
TargetFilename=*\\PSEXESVC.exe

// PSEXESVC service created (EID 13 - registry value set):
EventID=13
TargetObject=*\\Services\\PSEXESVC*

// PSEXESVC process execution (EID 1):
EventID=1
Image=*\\PSEXESVC.exe

// On SOURCE host:
// SMB connection from psexec.exe to target (EID 3):
EventID=3
Image=*\\psexec.exe OR *\\psexec64.exe
DestinationPort=445`,
        kibana: `// Destination: PSEXESVC binary written to disk
winlog.event_id: 11
AND file.path: *\\PSEXESVC.exe

// Destination: PSEXESVC service registry key set
winlog.event_id: 13
AND registry.path: *\\Services\\PSEXESVC*

// Destination: System Event 7045 (service installed)
winlog.event_id: 7045
AND winlog.channel: "System"
AND winlog.event_data.ServiceName: "PSEXESVC"

// Source: psexec.exe SMB connection
winlog.event_id: 3
AND process.name: ("psexec.exe" OR "psexec64.exe")
AND destination.port: 445`,
        powershell: `# Hunt for PSEXESVC artifacts on destination host

# File artifact: PSEXESVC.exe on disk
Get-ChildItem C:\\Windows\\PSEXESVC.exe -ErrorAction SilentlyContinue |
  Select FullName, CreationTime, LastWriteTime, Length

# Registry artifact: PSEXESVC service key
Get-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\PSEXESVC" \`
  -ErrorAction SilentlyContinue |
  Select ImagePath, Start, ObjectName

# System Event 7045: PSEXESVC service installation
Get-WinEvent -FilterHashtable @{
  LogName='System';
  ID=7045
} | Where-Object {
  $_.Properties[0].Value -eq 'PSEXESVC'
} | Select TimeCreated,
  @{n='ServiceName';e={$_.Properties[0].Value}},
  @{n='ServiceFile';e={$_.Properties[1].Value}},
  @{n='AccountName';e={$_.Properties[4].Value}}

# Sysmon EID 11: PSEXESVC.exe file creation
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=11
} | Where-Object {
  $_.Properties[0].Value -like '*PSEXESVC.exe'
} | Select TimeCreated,
  @{n='File';e={$_.Properties[0].Value}},
  @{n='CreatingProcess';e={$_.Properties[5].Value}}`,
        registry: `PSEXESVC service key (present while service is installed):
HKLM\\SYSTEM\\CurrentControlSet\\Services\\PSEXESVC\\
  ImagePath = C:\\Windows\\PSEXESVC.exe
  Start = 3 (Demand - created on-demand by PsExec)
  Type = 0x10 (Win32OwnProcess)
  ObjectName = LocalSystem

PsExec cleans up after itself - the service key and
binary are deleted after the PsExec session ends.
This means the registry artifact is transient.
Forensic artifacts that persist after cleanup:
- System Event 7045 (service installed) - log entry
  remains after service is deleted
- System Event 7009/7034 (service timeout/stop)
- MFT entry for PSEXESVC.exe (metadata persists
  in NTFS after file deletion)
- USN Journal entry for PSEXESVC.exe create/delete
- Sysmon EID 11 (FileCreate) log entry - persists
  in Sysmon log even after file is deleted

Authentication artifacts on destination:
- Security EID 4624 LogonType=3 (network logon)
  from source IP around time of PSEXESVC installation
- Security EID 4648 (explicit credentials used)
  if /u and /p flags were passed to psexec`,
        tools: `PsExec.exe / PsExec64.exe (Sysinternals/Microsoft)
  - Legitimate remote administration tool
  - Adversary use: lateral movement, remote execution
  - Leaves PSEXESVC artifact on destination
  - Context determines malicious vs legitimate

PsExec clones / reimplementations:
- Impacket psexec.py (creates same PSEXESVC artifact)
- CrackMapExec (--exec-method smbexec uses different
  service name - not PSEXESVC)
- SharpExec (C# reimplementation)
- PAExec (PsExec alternative, different service name)

Detection note: tools that reimplement the PsExec
protocol but use a different service name will NOT
trigger on PSEXESVC specifically. Broaden to:
- Any service installed with ImagePath in C:\\Windows\\
  that is not a known-good service
- Any short-lived service (EID 7045 create followed
  by EID 7036 stop within seconds)`,
        ossdetect: `Sigma:
- win_system_psexec_service_install.yml (EID 7045)
- file_event_win_psexec_service_binary.yml (EID 11)
- registry_event_win_psexec_service.yml (EID 13)
- proc_creation_win_psexec_execution.yml

Atomic Red Team:
- T1569.002 Test #3 (PsExec service creation)
- T1021.002 (SMB/Windows Admin Shares - related)

Hayabusa:
- PSEXESVCServiceInstall rules
- PsExec detection category (multiple event types)

Velociraptor:
- Windows.System.Services (catches live service)
- Windows.EventLogs.Sysmon (EID 11/13)
- Windows.Forensics.Usn (USN journal - catches
  PSEXESVC.exe create/delete even post-cleanup)

Network-side complement:
- hunt.6b74.dev Lateral Movement reference
  for SMB-based lateral movement network detection`,
        notes: "PSEXESVC is one of the most reliable lateral movement fingerprints in Windows forensics precisely because PsExec is so widely used - by both legitimate administrators and adversaries. The detection is straightforward: PSEXESVC.exe should never appear in C:\\Windows\\ in a healthy environment outside of an active PsExec session. The challenge is that PsExec cleans up after itself, so the window for live detection is short. The forensic artifacts that survive cleanup (System Event 7045, Sysmon EID 11, USN Journal) are your primary post-incident evidence sources. Context is everything here: seeing PSEXESVC in logs from a known IT admin workstation targeting a server it manages during business hours is probably legitimate. Seeing PSEXESVC originating from a developer workstation, a user endpoint, or targeting a domain controller is worth immediate investigation. Impacket psexec.py deserves a callout: it's a Python reimplementation of the PsExec protocol that produces the same PSEXESVC artifact on the destination, so this detection catches Impacket psexec.py as well as the legitimate Sysinternals tool.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "PsExec and Impacket psexec.py used for lateral movement in SolarWinds and other documented operations." },
          { cls: "apt-cn", name: "APT41", note: "PsExec-based lateral movement documented across multiple sector intrusions." },
          { cls: "apt-mul", name: "Ransomware", note: "PsExec is the single most commonly observed lateral movement tool in ransomware incident response engagements." },
          { cls: "apt-mul", name: "Impacket", note: "psexec.py produces identical PSEXESVC artifact - standard tool across red team and APT lateral movement." },
          { cls: "apt-mul", name: "FIN7", note: "PsExec lateral movement documented across financial sector intrusions." }
        ],
        cite: "MITRE ATT&CK T1569.002, T1021.002"
      },
      {
        sub: "T1569.002 - Service Binary in Non-Standard Path",
        indicator: "Registered service with ImagePath outside standard system directories - hunting for malicious persistence via service registry",
        sysmon: `// Real-time: Sysmon EID 13 (registry value set)
// catches service ImagePath being written:
EventID=13
TargetObject=*\\Services\\*\\ImagePath
Details NOT matching:
  C:\\Windows\\System32\\*
  C:\\Windows\\SysWOW64\\*
  C:\\Program Files\\*
  C:\\Program Files (x86)\\*

// Supplementary - service execution artifact:
EventID=1
ParentImage=*\\services.exe
Image NOT matching known-good service paths
// services.exe is the SCM host - it spawns
// services directly, making it a useful parent filter`,
        kibana: `// Real-time: ImagePath written outside standard paths
winlog.event_id: 13
AND registry.path: *\\Services\\*\\ImagePath
AND NOT registry.data.strings: ("C:\\\\Windows\\\\System32\\\\*" OR "C:\\\\Windows\\\\SysWOW64\\\\*" OR "C:\\\\Program Files\\\\*" OR "C:\\\\Program Files (x86)\\\\*")

// Service execution from non-standard path
winlog.event_id: 1
AND process.parent.name: "services.exe"
AND NOT process.executable: ("C:\\\\Windows\\\\*" OR "C:\\\\Program Files\\\\*" OR "C:\\\\Program Files (x86)\\\\*")`,
        powershell: `# Hunt for services with ImagePath outside standard directories
$standardPaths = @(
  'C:\\Windows\\',
  'C:\\Program Files\\',
  'C:\\Program Files (x86)\\'
)

Get-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\*" |
  Where-Object {
    $ip = $_.ImagePath
    if (-not $ip) { return $false }
    $ip = $ip.TrimStart('"') -replace '^([^"]+).*','$1'
    $ip = [System.Environment]::ExpandEnvironmentVariables($ip)
    -not ($standardPaths | Where-Object { $ip -like "$_*" })
  } | Select-Object \`
    @{n='ServiceName';e={$_.PSChildName}},
    @{n='ImagePath';e={$_.ImagePath}},
    @{n='Start';e={
      switch ($_.Start) {
        0 {'Boot'} 1 {'System'} 2 {'Auto'}
        3 {'Demand'} 4 {'Disabled'} default {$_}
      }
    }},
    @{n='ObjectName';e={$_.ObjectName}},
    @{n='DisplayName';e={$_.DisplayName}} |
  Sort-Object ServiceName`,
        registry: `Primary artifact - service ImagePath:
HKLM\\SYSTEM\\CurrentControlSet\\Services\\<Name>\\
  ImagePath - full path to service binary
  (may include arguments after the binary path)
  (may be quoted or unquoted)
  (may use environment variables: %SystemRoot%\\...)

Suspicious ImagePath patterns to hunt:
- C:\\Users\\<user>\\AppData\\*
- C:\\Windows\\Temp\\*
- C:\\ProgramData\\*
- C:\\Users\\Public\\*
- Relative paths (no drive letter)
- UNC paths (\\\\server\\share\\binary.exe)
- Paths containing scripting interpreters as the binary

Baseline approach:
- Export all service ImagePaths on a known-good system
- Compare against target system
- New entries with non-standard paths = investigate

Deleted service forensics:
- System Event 7036 (service stopped) and
  absence of 7045 for a service that previously
  existed suggests manual deletion
- MFT and USN Journal retain file metadata
  for the service binary even after deletion`,
        tools: `This indicator is hunting-oriented - sweep for
existing malicious services rather than real-time
creation detection (covered in indicator 1).

Most useful in:
- IR triage: what services exist that shouldn't?
- Baseline deviation: new services since last audit
- Post-persistence-establishment hunting
- Fleet-wide sweep via Velociraptor or EDR

Service creation tools (all leave ImagePath artifact):
sc.exe create
PowerShell New-Service / Register-ServiceJob
Compiled code using CreateService() Win32 API
Metasploit persistence modules
SharPersist
Cobalt Strike persistence
Any tool writing directly to the Services registry key

Known-good exceptions to tune out:
- Security software (AV, EDR agents)
- Monitoring agents (Elastic, Splunk UF, etc.)
- Vendor software with non-standard install paths
- Build allowlist from asset management / SCCM data`,
        ossdetect: `Sigma:
- registry_event_win_service_registry_susp_path.yml
- proc_creation_win_services_susp_child_process.yml

Atomic Red Team:
- T1569.002 (service creation variants)
- T1543.003 (Create or Modify System Process: Windows Service)

Hayabusa:
- ServiceBinaryNonStandardPath rules (EID 13)
- services.exe child process anomaly detection

Velociraptor:
- Windows.System.Services
  (best single artifact for fleet-wide service hunting)
- Windows.Forensics.Autoruns

Sysinternals autoruns.exe:
- Services tab with VirusTotal integration
- Highlights unsigned service binaries in red/yellow
- Most practical tool for manual IR triage`,
        notes: "This is the hunt-oriented companion to the real-time sc.exe detection - same concept as the scheduled task action hunting indicator in T1053.005. The PowerShell registry sweep is the core tool: it enumerates every registered service's ImagePath and flags anything outside standard system and program directories. The key challenge is normalization: ImagePath values can be quoted, unquoted, contain environment variables (%SystemRoot%), or embed arguments after the binary path - the hunt script handles this. Environment variable expansion is important because %SystemRoot%\\system32\\svchost.exe is legitimate but looks non-standard if you string-match on C:\\Windows without expanding the variable first. Services running from C:\\ProgramData\\ deserve particular scrutiny - it's a world-writable directory that doesn't appear in standard path allowlists, making it a common adversary staging location. The services.exe parent filter in the Sysmon section is a useful real-time complement: services.exe is the SCM binary that directly spawns services, so filtering Sysmon EID 1 on ParentImage=services.exe and checking the child's path against standard directories gives live execution coverage for this indicator.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Malicious service binaries in non-standard paths documented in long-dwell espionage operations." },
          { cls: "apt-cn", name: "APT41", note: "Services with ImagePath in ProgramData and AppData documented across multiple intrusions." },
          { cls: "apt-mul", name: "Ransomware", note: "Ransomware persistence via services with binaries in world-writable paths documented across multiple families." },
          { cls: "apt-mul", name: "FIN6", note: "Malicious service installation with non-standard binary paths documented in financial sector intrusions." },
          { cls: "apt-mul", name: "Red Teams", note: "Service binary staging in ProgramData or Temp is standard red team persistence tradecraft." }
        ],
        cite: "MITRE ATT&CK T1569.002, T1543.003"
      }
    ]
  },
  {
    id: "T1218.005",
    name: "System Binary Proxy Execution: Mshta",
    desc: "mshta.exe HTA execution, URL invocation, inline VBS/JS payloads",
    rows: [
      {
        sub: "T1218.005 - Coming Soon",
        indicator: "Full content for T1218.005 Mshta coming in next build session",
        sysmon: "(see widget summary in build session for headline indicator)",
        kibana: "(coming soon)",
        powershell: "(coming soon)",
        registry: "(coming soon)",
        tools: "(coming soon)",
        ossdetect: "(coming soon)",
        notes: "Planned coverage: mshta with HTTP URL, mshta with inline vbscript:/javascript: payload. 2 indicators planned. mshta.exe is a signed Microsoft binary - bypasses many script-based defenses.",
        apt: [{ cls: "apt-mul", name: "Coming soon", note: "Full APT attribution in next session" }],
        cite: "MITRE ATT&CK T1218.005"
      }
    ]
  },
  {
    id: "T1218.011",
    name: "System Binary Proxy Execution: Rundll32",
    desc: "rundll32.exe DLL execution abuse, javascript: invocation, no-args anomaly",
    rows: [
      {
        sub: "T1218.011 - Coming Soon",
        indicator: "Full content for T1218.011 Rundll32 coming in next build session",
        sysmon: "(see widget summary in build session for headline indicator)",
        kibana: "(coming soon)",
        powershell: "(coming soon)",
        registry: "(coming soon)",
        tools: "(coming soon)",
        ossdetect: "(coming soon)",
        notes: "Planned coverage: rundll32 with DLL path in non-system location, rundll32 with javascript: argument, rundll32 with no arguments (suspect injection). 3 indicators planned.",
        apt: [{ cls: "apt-mul", name: "Coming soon", note: "Full APT attribution in next session" }],
        cite: "MITRE ATT&CK T1218.011"
      }
    ]
  },
  {
    id: "T1218.010",
    name: "System Binary Proxy Execution: Regsvr32",
    desc: "regsvr32.exe Squiblydoo technique, scriptlet abuse, AppLocker bypass",
    rows: [
      {
        sub: "T1218.010 - Coming Soon",
        indicator: "Full content for T1218.010 Regsvr32 coming in next build session",
        sysmon: "(see widget summary in build session for headline indicator)",
        kibana: "(coming soon)",
        powershell: "(coming soon)",
        registry: "(coming soon)",
        tools: "(coming soon)",
        ossdetect: "(coming soon)",
        notes: "Planned coverage: Squiblydoo classic (regsvr32 /i:URL fetching .sct), remote scriptlet variants. 2 indicators planned. Casey Smith's original research.",
        apt: [{ cls: "apt-mul", name: "Coming soon", note: "Full APT attribution in next session" }],
        cite: "MITRE ATT&CK T1218.010"
      }
    ]
  },
  {
    id: "T1106",
    name: "Native API",
    desc: "Direct API calls bypassing CLI - process creation without command-line context",
    rows: [
      {
        sub: "T1106 - Native API Process Creation and Memory Injection Artifacts",
        indicator: "Process spawned with empty command line, suspicious cross-process memory access, or remote thread injection - Native API execution bypassing Win32 layer",
        sysmon: `// Three Sysmon event IDs cover Native API abuse:

// EID 1 - Process creation with empty/missing CommandLine:
EventID=1
CommandLine="" OR CommandLine IS NULL
// Legitimate processes rarely have empty command lines.
// Exceptions: some system processes (smss.exe, csrss.exe)
// Flag when: standard user-space processes appear
// with no command line context

// EID 8 - CreateRemoteThread (cross-process injection):
EventID=8
// All fields relevant - no filtering needed initially.
// Key fields:
//   SourceImage = injecting process
//   TargetImage = process being injected into
//   StartAddress = memory address of injected thread
//   StartModule  = DLL containing start address
//     (blank StartModule = shellcode, not a known DLL)
//   StartFunction = function name if resolvable

// EID 10 - ProcessAccess (handle to another process):
EventID=10
GrantedAccess=0x1fffff
  OR GrantedAccess=0x1f0fff
  OR GrantedAccess=0x143a
// These access masks include PROCESS_VM_WRITE +
// PROCESS_VM_OPERATION - required for memory injection
// TargetImage=*\\lsass.exe is a separate high-value alert
// (credential access - covered in Credential Access tactic)`,
        kibana: `// EID 1: Process with empty command line
winlog.event_id: 1
AND NOT process.command_line: *
AND NOT process.name: ("smss.exe" OR "csrss.exe" OR "wininit.exe" OR "services.exe")

// EID 8: Remote thread injection - blank StartModule = shellcode
winlog.event_id: 8
AND NOT winlog.event_data.StartModule: *

// EID 8: Remote thread into sensitive targets
winlog.event_id: 8
AND winlog.event_data.TargetImage: ("*\\lsass.exe" OR "*\\svchost.exe" OR "*\\explorer.exe" OR "*\\notepad.exe")

// EID 10: Suspicious cross-process handle with write access
winlog.event_id: 10
AND winlog.event_data.GrantedAccess: ("0x1fffff" OR "0x1f0fff" OR "0x143a")
AND NOT winlog.event_data.SourceImage: ("*\\MsMpEng.exe" OR "*\\svchost.exe" OR "*\\csrss.exe")`,
        powershell: `# Hunt for EID 8 - CreateRemoteThread with no StartModule (shellcode indicator)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=8
} | Where-Object {
  # Blank StartModule = thread start address not in any known DLL
  -not $_.Properties[8].Value
} | Select TimeCreated,
  @{n='SourceImage';e={($_.Properties[4].Value -split '\\\\')[-1]}},
  @{n='TargetImage';e={($_.Properties[6].Value -split '\\\\')[-1]}},
  @{n='StartAddress';e={$_.Properties[10].Value}},
  @{n='StartModule';e={$_.Properties[8].Value}},
  @{n='StartFunction';e={$_.Properties[9].Value}} |
  Sort-Object TimeCreated -Descending

# Hunt for EID 10 - suspicious cross-process memory access
$suspiciousAccess = @('0x1fffff','0x1f0fff','0x143a','0x40','0x1410')
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=10
} | Where-Object {
  $access = $_.Properties[8].Value
  $suspiciousAccess -contains $access -and
  # Exclude known-good sources
  $_.Properties[4].Value -notmatch '(MsMpEng|svchost|csrss|lsass|werfault)\.exe'
} | Select TimeCreated,
  @{n='SourceImage';e={($_.Properties[4].Value -split '\\\\')[-1]}},
  @{n='TargetImage';e={($_.Properties[6].Value -split '\\\\')[-1]}},
  @{n='GrantedAccess';e={$_.Properties[8].Value}} |
  Sort-Object TimeCreated -Descending

# Hunt for EID 1 - processes with empty command line
$knownNoCLI = @('smss.exe','csrss.exe','wininit.exe','services.exe','lsass.exe')
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=1
} | Where-Object {
  -not $_.Properties[10].Value -and
  $knownNoCLI -notcontains ($_.Properties[4].Value -split '\\\\')[-1]
} | Select TimeCreated,
  @{n='Image';e={$_.Properties[4].Value}},
  @{n='Parent';e={($_.Properties[20].Value -split '\\\\')[-1]}},
  @{n='User';e={$_.Properties[12].Value}}`,
        registry: `No direct registry artifact from Native API execution.

Native API calls operate entirely in memory - the
execution path bypasses the filesystem artifacts
that most other techniques leave behind.

Indirect forensic artifacts to investigate:
- Memory forensics (most reliable for Native API):
  Volatility / Rekall plugins:
  - malfind: scans for injected code regions
    (RWX memory pages with PE headers or shellcode)
  - dlllist: lists loaded modules per process
    (compare against expected DLLs for that process)
  - cmdline: dumps command lines from PEB structure
    (if empty for a user-space process = anomaly)
  - handles: open handles per process

- Sysmon EID 7 (Image Load) context:
  Watch for ntdll.dll loaded into unexpected processes,
  or unusual DLLs appearing in memory of known-good
  processes shortly before EID 8/10 events

- Process hollowing artifact:
  SectionObjectPointers divergence in memory -
  detectable via Get-InjectedThread (PowerShell tool)
  or process memory scanners`,
        tools: `Native API functions commonly abused:
- NtCreateProcess / NtCreateProcessEx
  (process creation without Win32 CreateProcess)
- NtAllocateVirtualMemory + NtWriteVirtualMemory
  (allocate + write shellcode to remote process)
- NtCreateThreadEx / RtlCreateUserThread
  (thread creation in remote process)
- NtMapViewOfSection
  (map shared memory section into target process)
- NtQueueApcThread
  (queue APC - Asynchronous Procedure Call - for injection)

Frameworks using Native API:
Cobalt Strike (multiple injection techniques)
Metasploit (meterpreter injection)
Sliver C2 (process injection modules)
Donut (shellcode generator - produces Native API stagers)
Syswhispers / Syswhispers2 / Syswhispers3
  (toolkits for making direct syscalls, bypassing
  ntdll.dll hooks by going straight to kernel)
HellsGate / HalosGate (syscall bypass techniques)

Syscall-level evasion note: the most advanced
adversaries don't just call ntdll.dll Native API -
they use direct syscalls (int 2e / syscall instruction)
to bypass ntdll.dll entirely, defeating EDR hooks
placed there. Detection at that level requires
kernel-mode visibility (ETW, kernel sensors).`,
        ossdetect: `Sigma:
- proc_creation_win_susp_empty_commandline.yml
- sysmon_createremotethread_win_susp.yml (EID 8)
- sysmon_proc_access_win_susp_access_mask.yml (EID 10)
- sysmon_createremotethread_win_shellcode.yml
  (EID 8 with blank StartModule)

Atomic Red Team:
- T1106 (Native API process creation tests)
- T1055 (Process Injection - overlapping technique)

Hayabusa:
- CreateRemoteThread detection rules (EID 8)
- SuspiciousProcessAccess rules (EID 10)

Velociraptor:
- Windows.Detection.Injection
  (combines EID 8 + EID 10 + memory scanning)
- Windows.Memory.Acquisition (full memory capture)

Dedicated injection detection tools:
- Get-InjectedThread (PowerShell, Jared Atkinson)
  Scans running processes for injected threads
  by checking thread start address against
  known module ranges - shellcode threads have
  start addresses in unattributed memory regions
- PE-sieve (hasherezade) - process memory scanner`,
        notes: "T1106 is the most detection-resistant technique in the Execution tactic because its entire value to an adversary is avoiding the artifacts that other techniques generate. The three Sysmon event IDs here (1, 8, 10) are the best available host-side telemetry, but each has significant false-positive challenges that require careful tuning. EID 8 (CreateRemoteThread) is the most actionable: legitimate software rarely injects threads into other processes, and a CreateRemoteThread event where StartModule is blank almost always indicates shellcode rather than a legitimate DLL-based operation. EID 10 (ProcessAccess) with write-capable access masks is noisier - AV and EDR products themselves open handles to other processes for scanning, so source-image allowlisting is essential. The empty command line on EID 1 is worth monitoring but generates false positives from some legitimate system processes and certain vendor software that uses Win32 CreateProcess with a NULL lpCommandLine argument. The honest detection gap to acknowledge: the most sophisticated operators use direct syscalls (Syswhispers-style) to bypass even ntdll.dll, making user-mode detection insufficient. Kernel-mode ETW (Event Tracing for Windows) sensors in modern EDR products are the frontier for that level of evasion. For most environments and most adversaries, the Sysmon EID 8 blank-StartModule detection is the highest-value single alert in this indicator.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Process injection via Native API documented across multiple long-dwell espionage operations." },
          { cls: "apt-cn", name: "APT41", note: "Native API injection techniques documented in operations targeting multiple sectors." },
          { cls: "apt-mul", name: "Cobalt Strike", note: "Multiple Native API injection techniques (CreateRemoteThread, NtMapViewOfSection, APC) built into Beacon." },
          { cls: "apt-mul", name: "Ransomware", note: "Process injection for AV evasion documented across Conti, BlackCat, and other ransomware families." },
          { cls: "apt-mul", name: "Red Teams", note: "Direct syscall techniques (Syswhispers, HellsGate) are standard modern red team evasion tradecraft." }
        ],
        cite: "MITRE ATT&CK T1106, T1055"
      }
    ]
  },
  {
    id: "T1129",
    name: "Shared Modules",
    desc: "DLL side-loading, search-order hijacking, suspicious-path module loads",
    rows: [
      {
        sub: "T1129 - Coming Soon",
        indicator: "Full content for T1129 Shared Modules coming in next build session",
        sysmon: "(see widget summary in build session for headline indicator)",
        kibana: "(coming soon)",
        powershell: "(coming soon)",
        registry: "(coming soon)",
        tools: "(coming soon)",
        ossdetect: "(coming soon)",
        notes: "Planned coverage: DLL load from %TEMP%/%APPDATA%, DLL search-order hijack pattern. 2 indicators planned. Heavily used by APT41, Lazarus.",
        apt: [{ cls: "apt-mul", name: "Coming soon", note: "Full APT attribution in next session" }],
        cite: "MITRE ATT&CK T1129"
      }
    ]
  },
  {
    id: "T1204.002",
    name: "User Execution: Malicious File",
    desc: "User clicks .exe/.lnk/.iso/.one - file launched from email or download path",
    rows: [
      {
        sub: "T1204.002 - Coming Soon",
        indicator: "Full content for T1204.002 User Execution coming in next build session",
        sysmon: "(see widget summary in build session for headline indicator)",
        kibana: "(coming soon)",
        powershell: "(coming soon)",
        registry: "(coming soon)",
        tools: "(coming soon)",
        ossdetect: "(coming soon)",
        notes: "Planned coverage: container-type executions (ISO/IMG/VHD launching from %TEMP%), LNK files with suspicious targets. 2 indicators planned. Container types became common in 2022+ to bypass MOTW.",
        apt: [{ cls: "apt-mul", name: "Coming soon", note: "Full APT attribution in next session" }],
        cite: "MITRE ATT&CK T1204.002"
      }
    ]
  }
];
