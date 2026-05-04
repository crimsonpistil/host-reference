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
        sub: "T1059.003 - Coming Soon",
        indicator: "Full content for T1059.003 cmd.exe (3+ indicators) coming in next build session",
        sysmon: "(see widget summary in build session for headline indicator)",
        kibana: "(coming soon)",
        powershell: "(coming soon)",
        registry: "(coming soon)",
        tools: "(coming soon)",
        ossdetect: "(coming soon)",
        notes: "Planned coverage: discovery command chains (whoami + ipconfig + net user combinations), Office-spawning-cmd phishing chains, DOSfuscation (caret/quote escape obfuscation). See build session widget for summary detection patterns.",
        apt: [
          { cls: "apt-mul", name: "Coming soon", note: "Full APT attribution in next session" }
        ],
        cite: "MITRE ATT&CK T1059.003"
      }
    ]
  },
  {
    id: "T1059.005",
    name: "Command and Scripting Interpreter: Visual Basic",
    desc: "VBA macros, vbscript via wscript/cscript, Office-driven script execution",
    rows: [
      {
        sub: "T1059.005 - Coming Soon",
        indicator: "Full content for T1059.005 VBA/VBScript coming in next build session",
        sysmon: "(see widget summary in build session for headline indicator)",
        kibana: "(coming soon)",
        powershell: "(coming soon)",
        registry: "(coming soon)",
        tools: "(coming soon)",
        ossdetect: "(coming soon)",
        notes: "Planned coverage: Office app spawning wscript.exe / cscript.exe (macro chain), ISO/LNK→VBS chain (post-MOTW evasion). 2 indicators planned.",
        apt: [{ cls: "apt-mul", name: "Coming soon", note: "Full APT attribution in next session" }],
        cite: "MITRE ATT&CK T1059.005"
      }
    ]
  },
  {
    id: "T1059.007",
    name: "Command and Scripting Interpreter: JavaScript",
    desc: "JScript via Windows Script Host, mshta+JS chains, fileless JS loaders",
    rows: [
      {
        sub: "T1059.007 - Coming Soon",
        indicator: "Full content for T1059.007 JavaScript coming in next build session",
        sysmon: "(see widget summary in build session for headline indicator)",
        kibana: "(coming soon)",
        powershell: "(coming soon)",
        registry: "(coming soon)",
        tools: "(coming soon)",
        ossdetect: "(coming soon)",
        notes: "Planned coverage: WSH (wscript/cscript) executing .js/.jse, mshta JS chain. 2 indicators planned. JScript is a quieter alternative to PowerShell - fewer defenders watch it closely.",
        apt: [{ cls: "apt-mul", name: "Coming soon", note: "Full APT attribution in next session" }],
        cite: "MITRE ATT&CK T1059.007"
      }
    ]
  },
  {
    id: "T1047",
    name: "Windows Management Instrumentation",
    desc: "wmic.exe process create, remote WMI execution, WMI subscription persistence",
    rows: [
      {
        sub: "T1047 - Coming Soon",
        indicator: "Full content for T1047 WMI coming in next build session",
        sysmon: "(see widget summary in build session for headline indicator)",
        kibana: "(coming soon)",
        powershell: "(coming soon)",
        registry: "(coming soon)",
        tools: "(coming soon)",
        ossdetect: "(coming soon)",
        notes: "Planned coverage: wmic process call create (local + remote), WMI subscription persistence (Sysmon EID 19/20/21). 3 indicators planned. Note wmic.exe is deprecated as of Windows 11 24H2 but still ships and works on most enterprise endpoints.",
        apt: [{ cls: "apt-mul", name: "Coming soon", note: "Full APT attribution in next session" }],
        cite: "MITRE ATT&CK T1047"
      }
    ]
  },
  {
    id: "T1053.005",
    name: "Scheduled Task/Job: Scheduled Task",
    desc: "schtasks.exe creation, COM-based task creation, remote scheduled tasks",
    rows: [
      {
        sub: "T1053.005 - Coming Soon",
        indicator: "Full content for T1053.005 Scheduled Tasks coming in next build session",
        sysmon: "(see widget summary in build session for headline indicator)",
        kibana: "(coming soon)",
        powershell: "(coming soon)",
        registry: "(coming soon)",
        tools: "(coming soon)",
        ossdetect: "(coming soon)",
        notes: "Planned coverage: local schtasks /create with suspicious binary path, remote schtasks creation, task action pointing to suspicious binary. 3 indicators planned. Pair with Windows Event ID 4698 (task created).",
        apt: [{ cls: "apt-mul", name: "Coming soon", note: "Full APT attribution in next session" }],
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
        sub: "T1569.002 - Coming Soon",
        indicator: "Full content for T1569.002 Service Execution coming in next build session",
        sysmon: "(see widget summary in build session for headline indicator)",
        kibana: "(coming soon)",
        powershell: "(coming soon)",
        registry: "(coming soon)",
        tools: "(coming soon)",
        ossdetect: "(coming soon)",
        notes: "Planned coverage: sc.exe create with suspicious binPath, PsExec service-creation signature (PSEXESVC), service binary in non-standard path. 3 indicators planned. Pair with Windows Event ID 7045 (service installed).",
        apt: [{ cls: "apt-mul", name: "Coming soon", note: "Full APT attribution in next session" }],
        cite: "MITRE ATT&CK T1569.002"
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
        sub: "T1106 - Coming Soon",
        indicator: "Full content for T1106 Native API coming in next build session",
        sysmon: "(see widget summary in build session for headline indicator)",
        kibana: "(coming soon)",
        powershell: "(coming soon)",
        registry: "(coming soon)",
        tools: "(coming soon)",
        ossdetect: "(coming soon)",
        notes: "Planned coverage: process creation without expected CLI signature. 1 indicator planned. Detection requires module load monitoring + memory access monitoring (Sysmon EID 7/8/10).",
        apt: [{ cls: "apt-mul", name: "Coming soon", note: "Full APT attribution in next session" }],
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
