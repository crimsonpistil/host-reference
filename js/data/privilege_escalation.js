// TA0004 - Privilege Escalation (complete - Windows-relevant techniques)
// 21 indicators across 13 techniques.
// Core: T1548.002 Bypass UAC (3), T1134 Access Token Manipulation (2),
//       T1055 Process Injection (3), T1068 Exploitation / BYOVD (2)
// Config/hijack: T1574.011 Service Registry Permissions (1),
//       T1574.005/.009/.010 Unquoted Path / Weak Service Perms (2),
//       T1574.001 DLL Search-Order Hijack priv-esc angle (1)
// Token/directory: T1134.005 SID-History Injection (1),
//       T1484.001/.002 GPO & Domain-Trust Modification (2),
//       T1098 Account Manipulation / AdminSDHolder (1)
// Triggered execution: T1546.008 Accessibility Features (1), T1546.012 IFEO Injection (1)
// Container: T1611 Escape to Host (1)
// Out of scope (Linux/macOS): T1548.001/.003/.004 setuid/sudo/elevated-prompt.
// Covered in Persistence (shared techniques): T1543.003, T1546.003/.015, T1053.005, T1547.x, T1037.

const DATA = [
  {
    id: "T1548.002",
    name: "Abuse Elevation Control Mechanism: Bypass User Account Control",
    desc: "Adversaries bypass UAC to elevate from medium to high integrity without a consent prompt, using auto-elevating binaries, registry hijacks, and trusted-directory mock folders.",
    rows: [
      {
        sub: "T1548.002 - Fodhelper / Computerdefaults Registry Hijack",
        os: "win",
        indicator: "fodhelper.exe or computerdefaults.exe spawning a child process after a HKCU ms-settings shell-command registry write",
        sysmon: `// Two-part signal. First the registry write (EID 12/13):
EventID=12 OR 13
TargetObject matches:
  *\\Software\\Classes\\ms-settings\\Shell\\Open\\command*
  OR *\\Software\\Classes\\ms-settings\\CurVer*
  OR *\\Software\\Classes\\.pwn\\Shell\\Open\\command*

// Then the auto-elevated parent spawning a child (EID 1):
EventID=1
ParentImage=*\\fodhelper.exe
  OR *\\computerdefaults.exe
  OR *\\slui.exe
  OR *\\sdclt.exe
// Child is typically cmd/powershell or the payload itself.
// Integrity of the child = High while parent ran without
// a visible consent prompt = the tell.`,
        kibana: `// Registry hijack of the ms-settings handler
winlog.event_id: (12 OR 13)
AND registry.path: (*\\Classes\\ms-settings\\Shell\\Open\\command* OR *\\Classes\\ms-settings\\CurVer* OR *\\Classes\\.pwn\\*)

// Auto-elevating binary spawning a child
winlog.event_id: 1
AND process.parent.name: ("fodhelper.exe" OR "computerdefaults.exe" OR "slui.exe" OR "sdclt.exe")
AND NOT process.name: ("SystemSettings.exe" OR "ApplicationFrameHost.exe")

// Tighten: child at High integrity launched by a Medium-integrity user session
winlog.event_id: 1
AND process.parent.name: ("fodhelper.exe" OR "computerdefaults.exe")
AND process.name: ("cmd.exe" OR "powershell.exe" OR "pwsh.exe" OR "rundll32.exe" OR "mshta.exe")`,
        powershell: `# Hunt the ms-settings handler hijack (Sysmon EID 13)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=13
} | Where-Object {
  $_.Properties[4].Value -match 'Classes\\\\(ms-settings|\\.pwn).*Shell\\\\Open\\\\command'
} | Select TimeCreated,
  @{n='Target';e={$_.Properties[4].Value}},
  @{n='Details';e={$_.Properties[5].Value}},
  @{n='Image';e={($_.Properties[3].Value -split '\\\\')[-1]}}

# Auto-elevating parents spawning interactive children (EID 1)
$elevators = 'fodhelper\\.exe|computerdefaults\\.exe|slui\\.exe|sdclt\\.exe'
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=1
} | Where-Object {
  ($_.Properties[20].Value -match $elevators)
} | Select TimeCreated,
  @{n='Parent';e={($_.Properties[20].Value -split '\\\\')[-1]}},
  @{n='Child';e={($_.Properties[4].Value -split '\\\\')[-1]}},
  @{n='CmdLine';e={$_.Properties[10].Value}}

# The live registry artifact (often deleted after exec, but check)
Get-Item 'HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command' -EA SilentlyContinue`,
        registry: `Fodhelper / computerdefaults handler hijack:
HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command
  (Default) = <payload command>
  DelegateExecute = "" (empty - the key trick)

Alternative CurVer redirection:
HKCU\\Software\\Classes\\ms-settings\\CurVer
  (Default) = .pwn  (points handler at a custom ProgID)
HKCU\\Software\\Classes\\.pwn\\Shell\\Open\\command
  (Default) = <payload command>

sdclt.exe variant (App Paths / IsolatedCommand):
HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\
  App Paths\\control.exe = <payload>
HKCU\\Software\\Classes\\exefile\\shell\\runas\\command\\
  IsolatedCommand = <payload>

slui.exe variant:
HKCU\\Software\\Classes\\exefile\\shell\\open\\command
  = <payload>

Key forensic note: these HKCU keys are usually written,
the auto-elevated binary launched, then the key deleted
within seconds. Sysmon EID 12 (key/value delete) right
after EID 13 (value set) on the same handler path is a
very strong signal. The transient nature means real-time
logging beats point-in-time registry snapshots.`,
        tools: `UACMe (hfiref0x) - the reference implementation,
  50+ documented UAC bypass methods including fodhelper
  (method 33), computerdefaults, sdclt, slui
Metasploit - bypassuac_fodhelper, bypassuac_sdclt modules
Cobalt Strike - elevate uac-token-duplication, and
  fodhelper via execute-assembly
Empire / Starkiller - bypassuac_fodhelper module
Manual operators - trivially scripted in PowerShell;
  the fodhelper technique is ~6 lines of reg writes

Common in commodity loaders too - many info-stealers
and RATs bundle a fodhelper bypass for the elevation step
before installing persistence.`,
        ossdetect: `Sigma:
- registry_set_uac_bypass_fodhelper.yml
- registry_set_uac_bypass_ms_settings.yml
- process_creation_uac_bypass_fodhelper.yml
- process_creation_uac_bypass_computerdefaults.yml
- registry_set_sdclt_uac_bypass.yml

Atomic Red Team:
- T1548.002 Test #5 (fodhelper)
- T1548.002 Test #6 (sdclt)
- T1548.002 Test #20+ (computerdefaults, ms-settings)

Hayabusa:
- UACBypassFodhelper rules (EID 13 + EID 1 correlation)

Velociraptor:
- Windows.Detection.UACBypass
- Windows.Registry.UACBypass artifacts`,
        notes: "Fodhelper is the single most common UAC bypass in the wild because it's reliable, file-less (registry-only), and works without admin. The mechanism: fodhelper.exe is auto-elevating (autoElevate=true in its manifest) and, when launched, queries HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command to decide what to run - HKCU is user-writable, so an attacker plants their command there and fodhelper runs it elevated. The DelegateExecute empty-string trick forces the older Open\\command path to be honored. Detection is reliable because legitimate software essentially never writes to the ms-settings class handler under HKCU. The strongest single signal is the registry write to that path; the second-best is an auto-elevating binary (fodhelper/computerdefaults/sdclt/slui) spawning cmd/powershell/rundll32. Correlate the two and false positives are near zero. Note that UAC bypass is NOT a privilege boundary Microsoft commits to defend - they treat it as a convenience feature - so these techniques persist version to version with new auto-elevating binaries replacing patched ones. Hunt by behavior (auto-elevator spawning a shell) rather than chasing the specific binary of the month.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "UAC bypass via auto-elevating binaries documented in multiple intrusion sets." },
          { cls: "apt-cn", name: "APT41", note: "Fodhelper and related UAC bypasses used in elevation steps." },
          { cls: "apt-mul", name: "Commodity Malware", note: "Fodhelper bypass bundled in many info-stealers and RAT loaders (Emotet, AgentTesla, etc.)." },
          { cls: "apt-mul", name: "Ransomware", note: "UAC bypass commonly used to elevate before disabling defenses and encrypting." }
        ],
        cite: "MITRE ATT&CK T1548.002"
      },
      {
        sub: "T1548.002 - Trusted Directory / Mock Folder Bypass",
        os: "win",
        indicator: "Process running from a spoofed trusted directory (e.g. 'C:\\Windows \\System32') or a DLL loaded by an auto-elevating binary from a user-writable path",
        sysmon: `// Mock trusted directory - note the trailing space in "Windows "
EventID=1 OR 11
Image OR TargetFilename matches:
  C:\\Windows \\System32\\*      (trailing space after Windows)
  OR C:\\Windows\\System32 \\*   (trailing space after System32)
  OR *\\Windows\\ \\*

// DLL load by auto-elevating binary from a writable path (EID 7)
EventID=7
Image=*\\(fodhelper|computerdefaults|sdclt|slui|
  dccw|wsreset|consent|taskhostw).exe
ImageLoaded=*\\AppData\\* OR *\\Temp\\* OR *\\Users\\Public\\*
Signed=false`,
        kibana: `// Mock/trusted-directory spoof (trailing-space dirs)
winlog.event_id: (1 OR 11)
AND (process.executable: "C\\:\\\\Windows \\\\*" OR file.path: "C\\:\\\\Windows \\\\*")

// Unsigned DLL loaded by an auto-elevating binary from a writable dir
winlog.event_id: 7
AND process.name: ("fodhelper.exe" OR "computerdefaults.exe" OR "sdclt.exe" OR "dccw.exe" OR "wsreset.exe" OR "consent.exe")
AND dll.path: (*\\AppData\\* OR *\\Temp\\* OR *\\Public\\*)
AND dll.code_signature.signed: false`,
        powershell: `# Hunt mock trusted directories (trailing-space variants)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=1
} | Where-Object {
  $_.Properties[4].Value -match 'Windows \\\\|System32 \\\\| \\\\'
} | Select TimeCreated,
  @{n='Image';e={$_.Properties[4].Value}},
  @{n='User';e={$_.Properties[12].Value}}

# Hunt unsigned DLLs loaded by auto-elevating binaries (EID 7)
$elevators = 'fodhelper|computerdefaults|sdclt|slui|dccw|wsreset|consent'
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=7
} | Where-Object {
  ($_.Properties[3].Value -match $elevators) -and
  ($_.Properties[4].Value -match 'AppData|\\\\Temp\\\\|\\\\Public\\\\') -and
  ($_.Properties[6].Value -eq 'false')
} | Select TimeCreated,
  @{n='Binary';e={($_.Properties[3].Value -split '\\\\')[-1]}},
  @{n='DLL';e={$_.Properties[4].Value}}

# Filesystem scan for mock directories
Get-ChildItem 'C:\\' -Directory -EA SilentlyContinue |
  Where-Object { $_.Name -match ' $|^Windows $' }`,
        registry: `No persistent registry artifact for the mock-folder
variant - it's filesystem + DLL-load based. Forensic
artifacts live on disk:

Mock trusted directories (note trailing spaces):
  "C:\\Windows \\System32\\"   <- space after Windows
  "C:\\Windows\\System32 \\"   <- space after System32
These pass the "trusted directory" check in some
auto-elevation manifests because the Win32 path
normalizer strips trailing spaces during the trust
check but not during the actual file open.

Side-loaded DLL drop locations vary - commonly:
  %APPDATA%\\<spoofed>\\<dllname>.dll
  %TEMP%\\<random>\\<dllname>.dll

Investigation pivots:
- Any directory under C:\\ with a trailing space is
  almost always malicious - legitimate installers do
  not create them
- Check the loaded DLL's signature and original
  filename (often mismatched against the hijacked name)`,
        tools: `UACMe - multiple mock-folder and DLL-hijack methods
  (methods 30+, including the "Windows " trusted-dir trick)
Custom loaders - the trailing-space directory trick is
  widely copy-pasted from public PoCs
DLL side-loading kits - any tool that drops a proxy DLL
  next to an auto-elevating binary

Frequently combined with DLL search-order hijack
(T1574.001) - the elevation and the hijack are the same
DLL load from the attacker's perspective.`,
        ossdetect: `Sigma:
- file_event_win_creation_mock_directory.yml
- image_load_uac_bypass_unsigned_dll_autoelevate.yml
- process_creation_susp_windows_dir_trailing_space.yml

Atomic Red Team:
- T1548.002 (mock-folder and DLL-hijack variants)

Velociraptor:
- Windows.Detection.MockDirectories
- Windows.Forensics.FilenameSearch (trailing-space hunt)

Sysinternals:
- sigcheck against DLLs loaded by auto-elevating binaries`,
        notes: "This is the quieter cousin of the registry-based UAC bypass and it's worth a dedicated indicator because it's registry-clean and easy to miss. Two mechanisms ride under this row. First, the mock trusted directory: Windows path normalization strips trailing spaces, so 'C:\\Windows \\System32\\' (note the space after Windows) gets treated as the trusted System32 by the auto-elevation trust check, but the file open resolves to the attacker's spoofed folder. Any directory on disk with a trailing space is essentially always malicious. Second, DLL hijack of an auto-elevating binary: several auto-elevating system binaries (fodhelper, dccw, wsreset, slui, computerdefaults) load DLLs by relative or user-influenceable paths, so dropping a malicious proxy DLL where they look gets your code running at high integrity. Detection: hunt for unsigned DLLs loaded by the known auto-elevating binary set from AppData/Temp/Public, and scan the filesystem for trailing-space directories. Both signals are low-volume and high-fidelity. This technique overlaps heavily with DLL search-order hijack (T1574.001) - the difference is intent (elevation vs persistence/defense-evasion), not mechanism.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "DLL hijack of auto-elevating binaries used for elevation in multiple campaigns." },
          { cls: "apt-mul", name: "Red Team / UACMe", note: "Mock-folder and auto-elevator DLL-hijack methods are standard UACMe tradecraft." },
          { cls: "apt-mul", name: "Commodity Loaders", note: "Trailing-space trusted-directory trick widely reused from public PoCs." }
        ],
        cite: "MITRE ATT&CK T1548.002"
      },
      {
        sub: "T1548.002 - Eventvwr / CMSTP / Disk Cleanup Auto-Elevate Abuse",
        os: "win",
        indicator: "eventvwr.exe, CompMgmtLauncher, or cmstp.exe launched immediately before an unexpected elevated child via a HKCU class hijack or INF AutoInstall",
        sysmon: `// eventvwr.exe mmc hijack (HKCU mscfile handler)
EventID=12 OR 13
TargetObject=*\\Software\\Classes\\mscfile\\shell\\
  open\\command*

// eventvwr/CompMgmtLauncher spawning a shell (EID 1)
EventID=1
ParentImage=*\\eventvwr.exe
  OR *\\CompMgmtLauncher.exe
Image=*\\cmd.exe OR *\\powershell.exe OR *\\mshta.exe

// cmstp.exe with an INF (EID 1)
EventID=1
Image=*\\cmstp.exe
CommandLine=*/s* OR *.inf*`,
        kibana: `// mscfile handler hijack (eventvwr bypass)
winlog.event_id: (12 OR 13)
AND registry.path: *\\Classes\\mscfile\\shell\\open\\command*

// auto-elevating MMC launchers spawning a shell
winlog.event_id: 1
AND process.parent.name: ("eventvwr.exe" OR "CompMgmtLauncher.exe")
AND process.name: ("cmd.exe" OR "powershell.exe" OR "pwsh.exe" OR "mshta.exe" OR "rundll32.exe")

// cmstp.exe INF abuse
winlog.event_id: 1
AND process.name: "cmstp.exe"
AND process.command_line: (*\\/s* OR *.inf*)`,
        powershell: `# mscfile handler hijack (eventvwr UAC bypass)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=13
} | Where-Object {
  $_.Properties[4].Value -match 'Classes\\\\mscfile\\\\shell\\\\open\\\\command'
} | Select TimeCreated,
  @{n='Target';e={$_.Properties[4].Value}},
  @{n='Payload';e={$_.Properties[5].Value}}

# eventvwr / CompMgmtLauncher spawning interactive children
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=1
} | Where-Object {
  $_.Properties[20].Value -match 'eventvwr\\.exe|CompMgmtLauncher\\.exe'
} | Select TimeCreated,
  @{n='Parent';e={($_.Properties[20].Value -split '\\\\')[-1]}},
  @{n='Child';e={($_.Properties[4].Value -split '\\\\')[-1]}},
  @{n='CmdLine';e={$_.Properties[10].Value}}

# cmstp.exe invocations (rare on most hosts)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=1
} | Where-Object { $_.Properties[4].Value -match 'cmstp\\.exe' }`,
        registry: `eventvwr.exe bypass (mscfile handler):
HKCU\\Software\\Classes\\mscfile\\shell\\open\\command
  (Default) = <payload>
  eventvwr.exe auto-elevates and opens an .msc via this
  handler; HKCU shadows HKCR so the attacker's command runs.

CompMgmtLauncher.exe bypass (older builds):
HKCU\\Software\\Classes\\mscfile\\shell\\open\\command
  Same handler, different auto-elevating trigger binary.

cmstp.exe abuse - no registry; INF-driven:
- Attacker crafts a malicious .inf with an
  [CustomDestination] / RunPreSetupCommands section
- cmstp.exe /s <malicious.inf> executes the command
  in an auto-elevated context bypassing UAC
- Forensic artifact is the .inf file on disk (often
  in %TEMP%) plus the cmstp.exe command line

Investigation pivots:
- mscfile handler under HKCU is never legitimate
- cmstp.exe is rarely run interactively on endpoints;
  any cmstp + .inf combination warrants review`,
        tools: `UACMe - eventvwr (method 25), CompMgmtLauncher,
  cmstp INF methods all implemented
Metasploit - bypassuac_eventvwr module
Empire - Invoke-EventVwrBypass
Cobalt Strike - cmstp.exe execution via aggressor scripts
GreatSCT / various INF-payload generators for cmstp

cmstp.exe doubles as a defense-evasion / app-control
bypass (T1218.003) since it's a signed Microsoft binary
that executes arbitrary INF commands - so it shows up in
both privilege-escalation and AWL-bypass tradecraft.`,
        ossdetect: `Sigma:
- registry_set_uac_bypass_eventvwr.yml
- process_creation_uac_bypass_eventvwr.yml
- process_creation_cmstp_execution.yml
- process_creation_cmstp_susp_inf.yml

Atomic Red Team:
- T1548.002 Test #1 (eventvwr)
- T1218.003 (cmstp INF execution)

Hayabusa:
- UACBypassEventvwr, CMSTPExecution rules

Velociraptor:
- Windows.Detection.UACBypass (eventvwr coverage)`,
        notes: "Grouping eventvwr, CompMgmtLauncher, and cmstp here because they're the next-tier auto-elevate abuses after fodhelper - less common now but still seen, and cmstp in particular doubles as an application-control bypass. eventvwr/CompMgmtLauncher work like fodhelper but via the mscfile class handler instead of ms-settings: the auto-elevating MMC launcher opens an .msc through HKCU\\...\\mscfile\\shell\\open\\command, which the attacker has hijacked. cmstp.exe is different - it's a signed Microsoft binary that processes Connection Manager INF files, and a crafted INF with a RunPreSetupCommands/CustomDestination section executes arbitrary commands auto-elevated. Detection priorities: the mscfile HKCU handler write is the cleanest eventvwr signal (legitimate software never touches it); for cmstp, watch for cmstp.exe running with /s and an .inf argument, especially an INF in a temp/user path. cmstp invocations are rare enough on most endpoints that nearly any occurrence merits a look. As with all UAC bypasses, hunt the behavior pattern (auto-elevator -> shell, or signed-binary -> arbitrary-INF) rather than the specific binary, since Microsoft does not service UAC as a security boundary.",
        apt: [
          { cls: "apt-ru", name: "APT28", note: "eventvwr-style UAC bypass documented in intrusion reporting." },
          { cls: "apt-ir", name: "MuddyWater", note: "cmstp.exe INF abuse used for execution and elevation." },
          { cls: "apt-mul", name: "Cobalt Strike Operators", note: "cmstp INF execution is a common red-team and crimeware technique." }
        ],
        cite: "MITRE ATT&CK T1548.002"
      }
    ]
  },
  {
    id: "T1134",
    name: "Access Token Manipulation",
    desc: "Adversaries duplicate, impersonate, or steal Windows access tokens to run code in another security context - moving from a service account to SYSTEM, or impersonating a logged-on privileged user.",
    rows: [
      {
        sub: "T1134.001 - Token Impersonation / Theft",
        os: "win",
        indicator: "Process calling DuplicateToken(Ex)/ImpersonateLoggedOnUser to assume another user's token - often a SYSTEM or domain-admin context obtained from an existing process",
        sysmon: `// Token theft is API-level - the on-host signals are
// indirect. Watch for a process accessing another
// process's token (EID 10, GRANTED_ACCESS includes
// PROCESS_QUERY_INFORMATION + token rights):
EventID=10
TargetImage=*\\lsass.exe
  OR *\\winlogon.exe OR *\\services.exe
GrantedAccess=0x1410 OR 0x1010 OR 0x1438
  (QUERY_INFORMATION / DUP_HANDLE combinations)
SourceImage != known admin tooling

// Process spawned under a different user than the parent
// (EID 1 - compare User field to parent's User):
EventID=1
// child User = NT AUTHORITY\\SYSTEM while parent User =
// a normal account, with no service/scheduled-task lineage`,
        kibana: `// Cross-process token/handle access to privileged procs
winlog.event_id: 10
AND winlog.event_data.TargetImage: (*\\lsass.exe OR *\\winlogon.exe OR *\\services.exe)
AND winlog.event_data.GrantedAccess: ("0x1410" OR "0x1010" OR "0x1438" OR "0x143a")
AND NOT process.name: ("MsMpEng.exe" OR "wmiprvse.exe" OR "taskmgr.exe")

// Process running as SYSTEM with a non-service parent
winlog.event_id: 1
AND user.name: "SYSTEM"
AND NOT process.parent.name: ("services.exe" OR "svchost.exe" OR "wininit.exe" OR "lsass.exe" OR "smss.exe")
AND process.name: ("cmd.exe" OR "powershell.exe" OR "pwsh.exe")`,
        powershell: `# Cross-process access to privileged tokens (EID 10)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=10
} | Where-Object {
  ($_.Properties[7].Value -match 'lsass|winlogon|services\\.exe') -and
  ($_.Properties[9].Value -match '0x1410|0x1010|0x1438|0x143a')
} | Select TimeCreated,
  @{n='Source';e={($_.Properties[3].Value -split '\\\\')[-1]}},
  @{n='Target';e={($_.Properties[7].Value -split '\\\\')[-1]}},
  @{n='Access';e={$_.Properties[9].Value}}

# Interactive shells running as SYSTEM with odd parentage (EID 1)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=1
} | Where-Object {
  ($_.Properties[12].Value -match 'SYSTEM') -and
  ($_.Properties[4].Value -match 'cmd\\.exe|powershell\\.exe|pwsh\\.exe') -and
  ($_.Properties[20].Value -notmatch 'services\\.exe|svchost\\.exe|wininit\\.exe')
} | Select TimeCreated,
  @{n='Image';e={($_.Properties[4].Value -split '\\\\')[-1]}},
  @{n='Parent';e={($_.Properties[20].Value -split '\\\\')[-1]}},
  @{n='User';e={$_.Properties[12].Value}}

# Security log: special-privilege logon / token events
Get-WinEvent -FilterHashtable @{ LogName='Security'; ID=4624,4672,4648 } -MaxEvents 200 |
  Where-Object { $_.Message -match 'SeImpersonate|SeAssignPrimaryToken|Logon Type:\\s+9' }`,
        registry: `No persistent registry artifact - token manipulation is
entirely in-memory and process-context based. Forensic
and detection artifacts live in event logs:

Sysmon:
- EID 10 (ProcessAccess) - cross-process token/handle grabs
- EID 1 (ProcessCreate) - resulting process context

Security log (if SeImpersonate auditing enabled):
- 4624 Logon Type 9 (NewCredentials) - often present
  when a token is used with alternate creds
- 4672 (Special privileges assigned) - SYSTEM-level
  privilege set assigned to a logon
- 4648 (Logon with explicit credentials)

Investigation pivots:
- A process holding a token for a user who has no
  interactive session on the host is suspicious
- SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege
  held by a non-service process is the enabler for most
  token theft -> check which accounts/processes hold it
- Look for the classic "Potato" pattern: a service
  account with SeImpersonate spawning SYSTEM`,
        tools: `Incognito (Metasploit) - the original token-stealing tool
Cobalt Strike - steal_token, make_token, rev2self
Mimikatz - token::elevate, token::list
Invoke-TokenManipulation (PowerSploit)
Rubeus - token-related operations alongside Kerberos
RottenPotato / JuicyPotato / PrintSpoofer / GodPotato -
  the "Potato" family: abuse SeImpersonate to escalate a
  service account to SYSTEM via COM/RPC coercion + token
  impersonation (very common on web/SQL servers)

The Potato family is the highest-value pattern to hunt -
it's the standard service-account-to-SYSTEM path on
IIS/MSSQL boxes where the service identity holds
SeImpersonatePrivilege.`,
        ossdetect: `Sigma:
- process_access_lsass_susp_access_rights.yml
- process_creation_system_shell_unusual_parent.yml
- proc_access_win_token_impersonation.yml

Atomic Red Team:
- T1134.001 (token impersonation tests)
- T1134.001 Test #1 (Invoke-TokenManipulation)

Hayabusa:
- TokenImpersonation, PotatoExploitPattern rules

Velociraptor:
- Windows.Detection.Tokens
- Windows.System.Privileges (who holds SeImpersonate)

Note: many EDRs detect the Potato pattern via the
named-pipe/COM coercion + immediate SYSTEM shell, which
is more reliable than the raw token API calls.`,
        notes: "Token manipulation is API-driven and largely in-memory, so there's no clean single log line - you hunt the surrounding behavior. The highest-value pattern by far is the 'Potato' chain: on servers running IIS or MSSQL, the service account (e.g. an app-pool identity) holds SeImpersonatePrivilege, and tools like PrintSpoofer/GodPotato/JuicyPotato coerce a SYSTEM process to authenticate over a named pipe or COM, then impersonate the resulting SYSTEM token - escalating service-account to SYSTEM in seconds. Hunt this two ways: (1) a process running as SYSTEM whose parent is not the normal service chain (services.exe/svchost/wininit/lsass/smss) - especially an interactive shell as SYSTEM with a weird parent; (2) Security 4672 special-privilege assignment combined with named-pipe creation from a service account. The cross-process EID 10 signals are noisier (legit tools touch lsass), so lead with the resulting-context anomaly rather than the API call. As a hardening pivot, enumerate which non-service processes hold SeImpersonate/SeAssignPrimaryToken - that's the attack surface for this entire technique.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Token theft and the Potato pattern used for service-account to SYSTEM escalation on web/DB servers." },
          { cls: "apt-ru", name: "APT29", note: "Token impersonation documented for moving between security contexts." },
          { cls: "apt-mul", name: "Ransomware Affiliates", note: "PrintSpoofer/GodPotato heavily used by ransomware crews on exposed IIS/MSSQL hosts." },
          { cls: "apt-mul", name: "Red Team", note: "steal_token / make_token is standard Cobalt Strike post-exploitation." }
        ],
        cite: "MITRE ATT&CK T1134.001"
      },
      {
        sub: "T1134.002 - Create Process with Token",
        os: "win",
        indicator: "CreateProcessWithTokenW / CreateProcessAsUser used to launch a process under a stolen or duplicated token - child process security context diverges from the launching process",
        sysmon: `EventID=1
// Child process whose integrity/user context does not
// match its parent's, with no legitimate runas/service
// explanation:
LogonId of child != LogonId of parent
  AND child User is more privileged
  AND ParentImage is not runas.exe / a service host

// Often paired with EID 10 immediately prior where the
// source process opened a token-bearing target:
EventID=10
GrantedAccess includes PROCESS_DUP_HANDLE (0x0040)
  or token-query rights against a privileged process`,
        kibana: `// New process whose logon session differs from parent
// and lands in a higher-privileged user context
winlog.event_id: 1
AND NOT process.parent.name: ("runas.exe" OR "services.exe" OR "svchost.exe" OR "wininit.exe")
AND user.name: ("SYSTEM" OR "*ADMIN*" OR "*Administrator*")
AND process.name: ("cmd.exe" OR "powershell.exe" OR "pwsh.exe" OR "rundll32.exe" OR "regsvr32.exe")

// Security log corroboration: 4688 with a new logon id
winlog.event_id: 4688
AND winlog.event_data.TokenElevationType: "%%1937"

// 4624 Logon Type 9 (NewCredentials) - token created
winlog.event_id: 4624
AND winlog.event_data.LogonType: "9"`,
        powershell: `# 4624 Logon Type 9 (NewCredentials = token creation)
Get-WinEvent -FilterHashtable @{ LogName='Security'; ID=4624 } -MaxEvents 500 |
  Where-Object { $_.Properties[8].Value -eq 9 } |
  Select TimeCreated,
    @{n='Account';e={$_.Properties[5].Value}},
    @{n='LogonType';e={$_.Properties[8].Value}},
    @{n='Process';e={$_.Properties[17].Value}}

# 4688 with full-token elevation type, unusual parent
Get-WinEvent -FilterHashtable @{ LogName='Security'; ID=4688 } -MaxEvents 500 |
  Where-Object { $_.Message -match 'TokenElevationTypeFull|%%1937' } |
  Select TimeCreated, @{n='New';e={$_.Properties[5].Value}},
    @{n='Creator';e={$_.Properties[13].Value}}

# Sysmon: shells in privileged context with odd parentage
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; ID=1
} | Where-Object {
  ($_.Properties[12].Value -match 'SYSTEM|ADMIN') -and
  ($_.Properties[20].Value -notmatch 'runas|services\\.exe|svchost')
} | Select TimeCreated,
  @{n='Image';e={($_.Properties[4].Value -split '\\\\')[-1]}},
  @{n='User';e={$_.Properties[12].Value}},
  @{n='Parent';e={($_.Properties[20].Value -split '\\\\')[-1]}}`,
        registry: `No registry artifact - this is process-creation + token
API behavior. Authoritative artifacts are in the event
logs:

Security log:
- 4624 Logon Type 9 (NewCredentials) - the token used to
  start the process under alternate credentials
- 4688 (Process Creation) with TokenElevationType:
  TokenElevationTypeFull (%%1937) = fully elevated token
- 4672 (Special privileges) on the new logon session

Sysmon:
- EID 1 with mismatched LogonId vs parent
- EID 10 just prior (the token acquisition step)

Investigation pivots:
- CreateProcessWithTokenW requires SeImpersonatePrivilege;
  CreateProcessAsUser requires SeAssignPrimaryTokenPrivilege
  - so the launching process must hold one of these
- Map the logon session of the new process back to its
  origin: a SYSTEM-context process with a brand-new
  logon id and a user-level parent is the signature`,
        tools: `Cobalt Strike - spawnas, runas, the token APIs underneath
Metasploit - migrate + execute under stolen token
Mimikatz - sekurlsa / token modules feeding process launch
Invoke-TokenManipulation -CreateProcess (PowerSploit)
The Potato family - the escalation usually ends in a
  CreateProcessWithTokenW(SYSTEM token) call to spawn the
  payload as SYSTEM
runas /netonly - legitimate analogue (a FP source)`,
        ossdetect: `Sigma:
- process_creation_susp_token_elevation_full.yml
- security_4624_logon_type_9_newcredentials.yml
- process_creation_system_context_unusual_parent.yml

Atomic Red Team:
- T1134.002 (create process with token tests)

Hayabusa:
- LogonType9NewCredentials, FullTokenElevation rules

Velociraptor:
- Windows.EventLogs.Evtx (4624/4688 correlation)
- Windows.Detection.Tokens`,
        notes: "T1134.002 is the action that consumes a stolen/duplicated token: CreateProcessWithTokenW (needs SeImpersonatePrivilege) or CreateProcessAsUser (needs SeAssignPrimaryTokenPrivilege) launches a new process under that token. It's the natural follow-on to .001 token theft, and the cleanest single detection is in the Security log: a 4624 Logon Type 9 (NewCredentials) closely followed by a 4688 carrying TokenElevationTypeFull, where the new process is a shell/LOLBin running in a higher context than its creator. On the Sysmon side, the tell is a process whose user context and logon session diverge from its parent with no runas/service lineage. The privilege prerequisite is the key hunting pivot - only processes holding SeImpersonate or SeAssignPrimaryToken can do this, and those are typically service accounts on IIS/MSSQL, which is exactly where the Potato escalations land. Beware false positives from legitimate runas /netonly and from EDR/management agents that impersonate; baseline those by parent image and account before alerting.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "CreateProcessWithToken used to spawn SYSTEM payloads after token theft." },
          { cls: "apt-kp", name: "Lazarus", note: "Token-based process creation documented in DPRK financial-sector intrusions." },
          { cls: "apt-mul", name: "Ransomware Affiliates", note: "Standard final step of Potato escalations on server targets." }
        ],
        cite: "MITRE ATT&CK T1134.002"
      }
    ]
  },
  {
    id: "T1055",
    name: "Process Injection",
    desc: "Adversaries inject code into legitimate processes to execute in their context, evade defenses, and inherit their privileges. Covers classic CreateRemoteThread DLL/PE injection, process hollowing, thread hijacking, and APC injection.",
    rows: [
      {
        sub: "T1055.001 / .002 - Remote DLL & PE Injection (CreateRemoteThread)",
        os: "win",
        indicator: "Sysmon EID 8 (CreateRemoteThread) into a process the source has no business writing to - classic VirtualAllocEx + WriteProcessMemory + CreateRemoteThread chain",
        sysmon: `// The canonical remote-thread injection signal:
EventID=8 (CreateRemoteThread)
SourceImage = <attacker process>
TargetImage = *\\explorer.exe OR *\\svchost.exe
  OR *\\rundll32.exe OR *\\notepad.exe
  OR *\\spoolsv.exe OR *\\dllhost.exe
StartAddress in a non-image region (not backed by a
  module on disk) - a frequent marker of injected code

// Corroborating remote memory write (EID 10 with write
// access rights to a foreign process):
EventID=10
GrantedAccess=0x1F0FFF (PROCESS_ALL_ACCESS)
  OR includes 0x0020 (VM_WRITE) + 0x0008 (VM_OPERATION)
TargetImage = a normal system/user process`,
        kibana: `// CreateRemoteThread into common injection targets
winlog.event_id: 8
AND winlog.event_data.TargetImage: (*\\explorer.exe OR *\\svchost.exe OR *\\rundll32.exe OR *\\notepad.exe OR *\\spoolsv.exe OR *\\dllhost.exe OR *\\werfault.exe)
AND NOT process.name: ("MsMpEng.exe" OR "CSFalconService.exe")

// Remote process opened with write+operation rights
winlog.event_id: 10
AND winlog.event_data.GrantedAccess: ("0x1f0fff" OR "0x1f1fff" OR "0x143a")
AND NOT winlog.event_data.SourceImage: (*\\MsMpEng.exe OR *\\wmiprvse.exe)

// Tighten EID 8 to non-image start addresses if your
// pipeline parses StartModule (null/blank = injected)
winlog.event_id: 8
AND NOT winlog.event_data.StartModule: *`,
        powershell: `# CreateRemoteThread events (Sysmon EID 8)
$targets = 'explorer|svchost|rundll32|notepad|spoolsv|dllhost|werfault'
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=8
} | Where-Object {
  $_.Properties[5].Value -match $targets
} | Select TimeCreated,
  @{n='Source';e={($_.Properties[1].Value -split '\\\\')[-1]}},
  @{n='Target';e={($_.Properties[5].Value -split '\\\\')[-1]}},
  @{n='StartAddr';e={$_.Properties[7].Value}},
  @{n='StartModule';e={$_.Properties[8].Value}} |
  Where-Object { -not $_.StartModule }   # null module = likely injected

# Remote-write handle opens (EID 10, ALL_ACCESS to normal procs)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; ID=10
} | Where-Object {
  $_.Properties[9].Value -match '0x1f0fff|0x1f1fff'
} | Select TimeCreated,
  @{n='Source';e={($_.Properties[3].Value -split '\\\\')[-1]}},
  @{n='Target';e={($_.Properties[7].Value -split '\\\\')[-1]}},
  @{n='Access';e={$_.Properties[9].Value}}`,
        registry: `No registry artifact - injection is in-memory. Forensic
and detection artifacts are runtime/event-based:

Sysmon:
- EID 8 (CreateRemoteThread) - the injection itself
- EID 10 (ProcessAccess) - the OpenProcess with write rights
- EID 7 (ImageLoad) - if a DLL was loaded into the target
  from disk (LoadLibrary-style injection leaves a path)

Memory-forensics pivots (Volatility / live):
- malfind - finds injected, executable, non-image memory
- ldrmodules - DLLs not in the PEB module lists (reflective)
- hollowfind / threadmap - hollowing & orphan threads
- VAD regions with PAGE_EXECUTE_READWRITE not backed by a
  file = the strongest single memory indicator

Investigation pivots:
- Injected threads have a StartAddress in private/mapped
  memory rather than a loaded module - the key triage tell
- A target process loading a DLL from AppData/Temp is the
  on-disk LoadLibrary variant (visible via EID 7)`,
        tools: `Cobalt Strike - inject, shinject, dllinject (the de
  facto standard; default targets explorer/rundll32)
Metasploit - migrate, post/windows/manage/reflective_dll
Meterpreter reflective DLL injection
Sliver / Havoc / Mythic - all ship injection primitives
PowerSploit - Invoke-DllInjection, Invoke-ReflectivePEInjection
Process Hacker / custom loaders
sRDI (shellcode reflective DLL injection) - widely reused

Nearly every C2 framework injects by default to get off
the initial loader and into a long-lived host process -
so remote-thread injection is one of the highest-value
host behaviors to hunt.`,
        ossdetect: `Sigma:
- create_remote_thread_win_susp_target.yml
- proc_access_win_susp_proc_access_lsass_ppl.yml
- create_remote_thread_win_cobaltstrike.yml

Atomic Red Team:
- T1055.001 (DLL injection)
- T1055.002 (PE injection)
- T1055 Test #1 (Invoke-DllInjection)

Hayabusa:
- CreateRemoteThreadInjection, SuspiciousProcAccess rules

Velociraptor:
- Windows.Detection.ProcessInjection
- Windows.Memory.InjectedThreads (yara over private RX mem)

Moneta / PE-sieve / Hollows-Hunter (Hasherezade):
- Scan live processes for injected/hollowed/implanted code
- Among the best free tooling for confirming injection`,
        notes: "Remote-thread injection is the workhorse of post-exploitation - almost every C2 framework injects its beacon into a long-lived host process (explorer, svchost, rundll32) to survive the loader exiting and to blend in. The classic chain is OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread, and Sysmon EID 8 captures that final CreateRemoteThread directly. The single most useful refinement is the StartAddress / StartModule: a remote thread whose start address is in private or mapped memory not backed by a module on disk (StartModule null/blank) is very likely injected code, whereas legit cross-process threads start in a known module. Pair EID 8 with EID 10 OpenProcess events carrying VM_WRITE/ALL_ACCESS to the same target. Expect false positives from EDR/AV (MsMpEng, Falcon), debuggers, and some installers - baseline those source images. When you get a hit, confirm with memory tooling (PE-sieve/Moneta/Volatility malfind) which finds the executable non-image regions definitively. This row deliberately covers .001 (DLL) and .002 (PE) together since the detection surface - remote write + remote thread into a foreign process - is identical; the difference is only what gets written.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Reflective and remote-thread injection used to run implants inside trusted processes." },
          { cls: "apt-cn", name: "APT41", note: "Process injection into system binaries documented across espionage and crimeware ops." },
          { cls: "apt-kp", name: "Lazarus", note: "Custom injectors and reflective loaders used extensively." },
          { cls: "apt-mul", name: "Cobalt Strike", note: "inject/shinject is default tradecraft for nearly all C2 operators." }
        ],
        cite: "MITRE ATT&CK T1055.001"
      },
      {
        sub: "T1055.012 - Process Hollowing",
        os: "win",
        indicator: "A process created suspended, its image unmapped and replaced, then resumed - parent/child mismatch, on-disk image vs in-memory image divergence, or a benign binary running attacker code",
        sysmon: `// Hollowing creates a legit process suspended, swaps its
// memory, then resumes. On-host signals:
EventID=1 (ProcessCreate)
// A signed/legit Image (e.g. svchost.exe, RegAsm.exe,
// MSBuild.exe, dllhost.exe) launched from an unusual
// parent (Office, a loader in AppData, a script host),
// frequently from a non-standard path:
Image=*\\svchost.exe launched WITHOUT services.exe parent
  OR *\\RegAsm.exe / *\\RegSvcs.exe / *\\MSBuild.exe
     spawned by a user-level loader
  OR a System32 binary running from a non-System32 path

// Remote memory ops on the suspended child (EID 10):
EventID=10
GrantedAccess includes VM_WRITE + VM_OPERATION +
  SUSPEND_RESUME (0x0800) against the freshly-created child`,
        kibana: `// svchost without services.exe parent (classic hollow target)
winlog.event_id: 1
AND process.name: "svchost.exe"
AND NOT process.parent.name: "services.exe"

// .NET LOLBins commonly hollowed by loaders
winlog.event_id: 1
AND process.name: ("RegAsm.exe" OR "RegSvcs.exe" OR "MSBuild.exe" OR "InstallUtil.exe" OR "AddInProcess.exe")
AND process.parent.name: ("winword.exe" OR "excel.exe" OR "powershell.exe" OR "wscript.exe" OR "mshta.exe" OR "explorer.exe")

// System32 image running from a non-system path
winlog.event_id: 1
AND process.name: ("svchost.exe" OR "dllhost.exe" OR "rundll32.exe")
AND NOT process.executable: (C\\:\\\\Windows\\\\System32\\\\* OR C\\:\\\\Windows\\\\SysWOW64\\\\*)`,
        powershell: `# svchost.exe NOT parented by services.exe (hollow target)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; ID=1
} | Where-Object {
  ($_.Properties[4].Value -match '\\\\svchost\\.exe$') -and
  ($_.Properties[20].Value -notmatch 'services\\.exe')
} | Select TimeCreated,
  @{n='Image';e={$_.Properties[4].Value}},
  @{n='Parent';e={($_.Properties[20].Value -split '\\\\')[-1]}},
  @{n='User';e={$_.Properties[12].Value}}

# .NET LOLBins spawned by document/script hosts
$lolbins='RegAsm|RegSvcs|MSBuild|InstallUtil|AddInProcess'
$hosts='winword|excel|powershell|wscript|mshta|cscript'
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; ID=1
} | Where-Object {
  ($_.Properties[4].Value -match $lolbins) -and
  ($_.Properties[20].Value -match $hosts)
} | Select TimeCreated,
  @{n='Image';e={($_.Properties[4].Value -split '\\\\')[-1]}},
  @{n='Parent';e={($_.Properties[20].Value -split '\\\\')[-1]}},
  @{n='CmdLine';e={$_.Properties[10].Value}}

# System32 images running from the wrong path
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; ID=1
} | Where-Object {
  ($_.Properties[4].Value -match 'svchost|dllhost|rundll32') -and
  ($_.Properties[4].Value -notmatch 'System32|SysWOW64')
} | Select TimeCreated,
  @{n='Image';e={$_.Properties[4].Value}}`,
        registry: `No registry artifact - hollowing is a memory operation.
Detection and forensics are runtime/memory-based:

On-disk vs in-memory divergence is the defining property:
- The process's backing file on disk is the legit binary
- The in-memory image has been unmapped and replaced
- Tools that diff disk image vs memory image catch it

Memory-forensics pivots:
- hollowfind (Volatility plugin) - purpose-built
- malfind - flags the replaced executable regions
- PE-sieve / Hollows-Hunter - detect replaced/implanted
  image and dump the real (injected) PE
- Compare the in-memory PE header / entrypoint against
  the on-disk file's

Process-lineage pivots (cheaper, log-based):
- svchost.exe whose parent is not services.exe
- A signed Microsoft binary spawned by Office / a script
  host / a loader in AppData
- A System32 binary executing from a non-System32 path
- Created-suspended then resumed (rarely logged directly,
  but EID 10 SUSPEND_RESUME access on a new child hints)`,
        tools: `Cobalt Strike - spawnto + the hollowing-style spawn of a
  sacrificial process for post-ex jobs
Metasploit - various hollowing payload generators
Donut - shellcode generation often paired with hollowing
  loaders (RegAsm/MSBuild .NET hosts)
GadgetToJScript / .NET loaders - hollow RegAsm/RegSvcs/
  MSBuild/InstallUtil as sacrificial .NET hosts
Process Hollowing PoCs (many public) - widely copy-pasted
Commodity loaders - GuLoader, AgentTesla, Formbook, and
  many stealers hollow RegAsm.exe / MSBuild.exe routinely`,
        ossdetect: `Sigma:
- process_creation_svchost_no_services_parent.yml
- process_creation_net_lolbin_susp_parent.yml
- process_creation_susp_system_binary_anomaly_path.yml

Atomic Red Team:
- T1055.012 (process hollowing tests)

Hayabusa:
- SvchostNoServicesParent, NetLOLBinHollow rules

Velociraptor:
- Windows.Detection.ProcessHollowing
- Windows.Memory.HollowedProcess

PE-sieve / Hollows-Hunter:
- The reference free tooling for confirming hollowing on
  a live host - scans all processes, dumps implanted PEs`,
        notes: "Process hollowing replaces the in-memory image of a legitimately-created (usually suspended) process with attacker code, so the process looks normal in a task list and on disk while running something else entirely. It's harder to catch than remote-thread injection because there's no CreateRemoteThread into a foreign process - the malicious code runs in the process's own primary thread. Lean on two cheap, log-based tells before reaching for memory forensics: (1) process lineage anomalies - svchost.exe must be parented by services.exe; the .NET LOLBins (RegAsm, RegSvcs, MSBuild, InstallUtil, AddInProcess) are favorite sacrificial hosts and rarely have a legitimate reason to be spawned by Office or a script host; (2) path anomalies - a System32 binary running from anywhere but System32/SysWOW64. These catch the overwhelming majority of commodity hollowing (GuLoader, AgentTesla, Formbook all hollow .NET hosts). For confirmation, PE-sieve/Hollows-Hunter on the live host or hollowfind in Volatility will show the disk-vs-memory image divergence definitively. Commodity malware uses this constantly, so once you've baselined your legit RegAsm/MSBuild usage (dev machines, some installers), the document-host-spawns-.NET-LOLBin pattern is very high fidelity.",
        apt: [
          { cls: "apt-kp", name: "Lazarus", note: "Process hollowing of system binaries documented across DPRK financial operations." },
          { cls: "apt-ru", name: "Turla", note: "Hollowing used to run implants inside trusted Windows processes." },
          { cls: "apt-mul", name: "Commodity Stealers", note: "GuLoader, AgentTesla, Formbook routinely hollow RegAsm/MSBuild as .NET hosts." },
          { cls: "apt-mul", name: "Ransomware", note: "Hollowing used to stage encryptors inside benign-looking processes." }
        ],
        cite: "MITRE ATT&CK T1055.012"
      },
      {
        sub: "T1055.003 - Thread Execution Hijacking",
        os: "win",
        indicator: "An existing thread in a remote process suspended, its context (instruction pointer) redirected to attacker code via SetThreadContext, then resumed - no new remote thread is created",
        sysmon: `// Thread hijacking avoids CreateRemoteThread (no EID 8).
// The signals are the OpenThread/OpenProcess + context
// manipulation, visible mainly via EID 10:
EventID=10 (ProcessAccess)
GrantedAccess includes:
  THREAD_SUSPEND_RESUME (0x0002)
  + THREAD_SET_CONTEXT (0x0010)
  + THREAD_GET_CONTEXT (0x0008)
  OR PROCESS_VM_WRITE + PROCESS_VM_OPERATION on target
TargetImage = a normal user/system process
SourceImage = an unexpected, often unsigned, process

// Look for a preceding memory write (VM_WRITE) to the
// same target with no subsequent EID 8 - that absence of
// CreateRemoteThread is itself the differentiator.`,
        kibana: `// Process/thread access with set-context style rights
winlog.event_id: 10
AND winlog.event_data.GrantedAccess: ("0x0018" OR "0x001a" OR "0x143a" OR "0x1f0fff")
AND NOT winlog.event_data.SourceImage: (*\\MsMpEng.exe OR *\\devenv.exe OR *\\windbg.exe OR *\\vsdbg* )

// Correlate: VM_WRITE to a target with NO EID 8 follow-up
// (thread hijack writes code then redirects an existing
// thread instead of creating one)
winlog.event_id: 10
AND winlog.event_data.GrantedAccess: ("0x143a" OR "0x1f0fff")
AND winlog.event_data.TargetImage: (*\\explorer.exe OR *\\svchost.exe OR *\\rundll32.exe OR *\\notepad.exe)`,
        powershell: `# Set-context style access rights to remote threads (EID 10)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; ID=10
} | Where-Object {
  ($_.Properties[9].Value -match '0x0018|0x001a|0x143a|0x1f0fff') -and
  ($_.Properties[3].Value -notmatch 'MsMpEng|devenv|windbg|vsdbg')
} | Select TimeCreated,
  @{n='Source';e={($_.Properties[3].Value -split '\\\\')[-1]}},
  @{n='Target';e={($_.Properties[7].Value -split '\\\\')[-1]}},
  @{n='Access';e={$_.Properties[9].Value}}

# Find VM_WRITE opens to common targets that have NO
# matching CreateRemoteThread (EID 8) - hijack signature.
# (Correlation done in your SIEM; this lists the EID 10 leg.)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; ID=10
} | Where-Object {
  ($_.Properties[7].Value -match 'explorer|svchost|rundll32|notepad') -and
  ($_.Properties[9].Value -match '0x143a|0x1f0fff')
} | Select TimeCreated,
  @{n='Source';e={($_.Properties[3].Value -split '\\\\')[-1]}},
  @{n='Target';e={($_.Properties[7].Value -split '\\\\')[-1]}}`,
        registry: `No registry artifact - thread hijacking is in-memory.
Distinguishing property vs other injection: NO new remote
thread is created (so no Sysmon EID 8), which is exactly
why it's used to evade CreateRemoteThread-based detection.

Detection / forensic surface:
- Sysmon EID 10 with THREAD_SET_CONTEXT (0x0010) +
  THREAD_SUSPEND_RESUME (0x0002) rights = the redirection
- A preceding PROCESS_VM_WRITE to the same target (the
  code being staged) with no EID 8 afterward
- Memory forensics: malfind still finds the injected
  executable region; the hijacked thread's start context
  points into that region rather than a module

Memory pivots:
- Volatility malfind / threadmap - injected RX region +
  a thread whose EIP/RIP is inside it
- PE-sieve - detects the implanted code regardless of how
  execution was redirected

Investigation pivots:
- The absence of EID 8 alongside VM_WRITE + SET_CONTEXT is
  the signature - hunt the combination, not one event`,
        tools: `Cobalt Strike - thread-hijack style injection options
Meterpreter - some migrate paths use thread context
  manipulation
Custom loaders - SetThreadContext hijacking is a common
  "avoid CreateRemoteThread" evasion in modern loaders
Various open-source injectors (ThreadContext PoCs)
Donut-style loaders configured for thread hijacking

Increasingly common precisely because EID 8 (remote
thread) is well-monitored - hijacking an existing thread
sidesteps that single highest-value injection signal.`,
        ossdetect: `Sigma:
- proc_access_win_susp_thread_context_access.yml
- proc_access_win_in_memory_susp_access_rights.yml

Atomic Red Team:
- T1055.003 (thread execution hijacking tests)

Hayabusa:
- ThreadContextHijack, SuspiciousThreadAccess rules

Velociraptor:
- Windows.Detection.ProcessInjection (memory scan covers
  hijacked threads via injected RX regions)

Moneta / PE-sieve:
- Detect the implanted code region regardless of the
  execution-redirection method used`,
        notes: "Thread execution hijacking is the stealthier sibling of remote-thread injection: instead of CreateRemoteThread, the attacker opens an existing thread in the target, suspends it, points its instruction pointer at code they've already written into the process (SetThreadContext), and resumes it. The operational reason matters for hunting - it specifically exists to avoid Sysmon EID 8, which is the highest-fidelity injection signal most defenders rely on. So the detection inverts: hunt for the OpenThread/OpenProcess with THREAD_SET_CONTEXT + SUSPEND_RESUME rights (EID 10), ideally correlated with a PROCESS_VM_WRITE to the same target and the ABSENCE of any EID 8 to that process. That correlation is SIEM work, but the EID 10 set-context access leg is a usable starting filter on its own once you baseline debuggers (devenv, windbg, vsdbg) and EDR. Confirmation is the same as other injection: memory scanners (PE-sieve, Volatility malfind) find the injected executable region, and the hijacked thread's context points into it. Treat this as a must-have companion to the CreateRemoteThread row - an environment that only watches EID 8 has a blind spot exactly the shape of this technique.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Modern loaders favor thread hijacking to evade CreateRemoteThread monitoring." },
          { cls: "apt-cn", name: "APT41", note: "Thread-context manipulation used in stealthier injection chains." },
          { cls: "apt-mul", name: "Modern Loaders", note: "SetThreadContext hijacking widely adopted as an EID-8 evasion." }
        ],
        cite: "MITRE ATT&CK T1055.003"
      }
    ]
  },
  {
    id: "T1068",
    name: "Exploitation for Privilege Escalation",
    desc: "Adversaries exploit software or kernel vulnerabilities to elevate privileges - including bring-your-own-vulnerable-driver (BYOVD) to gain kernel execution and local exploits against services or the OS.",
    rows: [
      {
        sub: "T1068 - Bring Your Own Vulnerable Driver (BYOVD)",
        os: "win",
        indicator: "A new kernel driver service created/loaded for a known-vulnerable signed driver (e.g. RTCore64, dbutil, gdrv, procexp) - typically dropped to a user-writable path and loaded to gain kernel R/W",
        sysmon: `// Driver load (Sysmon EID 6) of a vulnerable/abusable
// driver, often from a non-standard path:
EventID=6 (DriverLoad)
ImageLoaded matches known-vulnerable drivers:
  *RTCore64.sys (MSI Afterburner - very common)
  OR *dbutil_2_3.sys / *DBUtilDrv2.sys (Dell)
  OR *gdrv.sys (Gigabyte) OR *gdrv2.sys
  OR *procexp*.sys (abused builds)
  OR *WinRing0.sys OR *PROCEXP152.sys
  OR *aswArPot.sys OR *iqvw64e.sys (Intel)
Signed=true (they ARE signed - that's the point)
  but loaded from AppData/Temp/ProgramData

// The service/registry creation that loads it (EID 13):
EventID=13
TargetObject=*\\Services\\<drivername>\\ImagePath
Details=*\\AppData\\* OR *\\Temp\\* OR *\\Users\\*`,
        kibana: `// Vulnerable driver load (EID 6)
winlog.event_id: 6
AND winlog.event_data.ImageLoaded: (*RTCore64.sys OR *dbutil_2_3.sys OR *DBUtilDrv2.sys OR *gdrv.sys OR *gdrv2.sys OR *WinRing0.sys OR *iqvw64e.sys OR *aswArPot.sys OR *PROCEXP152.sys)

// Driver loaded from a user-writable path (strong signal)
winlog.event_id: 6
AND winlog.event_data.ImageLoaded: (*\\AppData\\* OR *\\Temp\\* OR *\\ProgramData\\* OR *\\Users\\Public\\*)

// Kernel service registration pointing at a writable path
winlog.event_id: 13
AND registry.path: *\\Services\\*\\ImagePath
AND registry.data.strings: (*\\AppData\\* OR *\\Temp\\* OR *\\Users\\*)

// System log: a new kernel-mode service installed
winlog.event_id: 7045
AND winlog.event_data.ServiceType: "kernel mode driver"`,
        powershell: `# Vulnerable driver loads (Sysmon EID 6)
$vuln='RTCore64|dbutil_2_3|DBUtilDrv2|gdrv2?|WinRing0|iqvw64e|aswArPot|PROCEXP152|procexp.*\\.sys'
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; ID=6
} | Where-Object {
  ($_.Properties[1].Value -match $vuln) -or
  ($_.Properties[1].Value -match 'AppData|\\\\Temp\\\\|\\\\ProgramData\\\\|\\\\Public\\\\')
} | Select TimeCreated,
  @{n='Driver';e={$_.Properties[1].Value}},
  @{n='Signed';e={$_.Properties[3].Value}},
  @{n='Signature';e={$_.Properties[4].Value}}

# New kernel-mode service installs (System log 7045)
Get-WinEvent -FilterHashtable @{ LogName='System'; ID=7045 } -MaxEvents 200 |
  Where-Object { $_.Message -match 'kernel mode|\\.sys' } |
  Select TimeCreated,
    @{n='Service';e={$_.Properties[0].Value}},
    @{n='ImagePath';e={$_.Properties[1].Value}},
    @{n='Type';e={$_.Properties[2].Value}}

# Cross-check loaded drivers against a known-vuln list
Get-CimInstance Win32_SystemDriver |
  Where-Object { $_.PathName -match $vuln } |
  Select Name, State, PathName`,
        registry: `Kernel driver service registration:
HKLM\\SYSTEM\\CurrentControlSet\\Services\\<DriverName>
  ImagePath = <path to .sys>   (watch for user-writable)
  Type = 1 (kernel driver) or 2
  Start = 3 (demand) typical for on-the-fly BYOVD load

Key forensic notes:
- Legit drivers live in C:\\Windows\\System32\\drivers\\
  and are installed by signed installers. A .sys loaded
  from AppData/Temp/ProgramData/Users is a major red flag.
- The driver IS validly signed (that's the whole point of
  BYOVD - it passes Driver Signature Enforcement) - so
  signature alone does not clear it. Match on the file
  hash/name against vulnerable-driver lists.
- After exploitation the service is often deleted, but
  the EID 6 load and 7045 install events persist in logs.

Reference lists to match against:
- Microsoft Vulnerable Driver Blocklist
- loldrivers.io (community vulnerable-driver database)`,
        tools: `KDMapper - maps unsigned drivers via a vulnerable signed
  one (iqvw64e.sys / Intel)
gdrvldr / various Gigabyte gdrv.sys loaders
RTCore64 abuse (from MSI Afterburner) - extremely common
  in EDR-killer tooling
DBUtil (Dell) - CVE-2021-21551 priv-esc
EDR killers (AuKill, Terminator/Spyboy, GhostDriver, etc.)
  - load a vulnerable driver to kill AV/EDR from kernel
Ransomware crews increasingly bundle a BYOVD EDR-killer as
  a pre-encryption step
Public PoCs for dozens of vulnerable drivers (loldrivers)`,
        ossdetect: `Sigma:
- driver_load_vuln_drivers.yml (matches known-vuln list)
- driver_load_susp_driver_path.yml (non-standard path)
- sysmon_susp_kernel_driver_unsigned_or_vuln.yml
- system_7045_kernel_service_install.yml

Atomic Red Team:
- T1068 (BYOVD / vulnerable driver tests)

Microsoft:
- Vulnerable Driver Blocklist (HVCI / WDAC) - enable it
- Attack Surface Reduction (ASR) driver rules

loldrivers.io:
- Authoritative community vuln-driver hash/name feed -
  build a detection list from it

Velociraptor:
- Windows.System.Drivers (enumerate + match vuln list)
- Windows.Detection.BYOVD`,
        notes: "BYOVD is the dominant kernel-privilege-escalation and EDR-evasion technique in current ransomware and APT tradecraft. The trick: Windows enforces Driver Signature Enforcement, so attackers don't write their own kernel driver - they load a legitimately-signed but vulnerable one (RTCore64 from MSI Afterburner, Dell's dbutil, Gigabyte's gdrv, Intel's iqvw64e, etc.) and exploit its arbitrary kernel read/write primitive to disable protections, kill EDR from kernel space, or elevate. Because the driver is validly signed, signature checks pass - so detection must be name/hash-based against a vulnerable-driver list (loldrivers.io and Microsoft's blocklist are the references) plus path heuristics. The highest-fidelity signals: Sysmon EID 6 driver loads matching the known-vulnerable set OR loading from a user-writable path (legit drivers load from System32\\drivers), and System 7045 kernel-mode service installs. The strongest single hardening control is enabling Microsoft's Vulnerable Driver Blocklist (HVCI/WDAC), which blocks the known-bad drivers outright. Operationally, a BYOVD load is rarely benign on an endpoint - any .sys from AppData/Temp, or any load matching the vuln list, warrants immediate investigation, since the next step is usually EDR being blinded right before ransomware detonates.",
        apt: [
          { cls: "apt-kp", name: "Lazarus", note: "BYOVD (incl. Dell dbutil) used to disable security tooling and gain kernel access." },
          { cls: "apt-mul", name: "Ransomware (BlackByte, Cuba, AvosLocker)", note: "RTCore64 / vulnerable-driver EDR-killers bundled as a pre-encryption step." },
          { cls: "apt-mul", name: "EDR Killers (AuKill, Terminator)", note: "Commodity tools that load a vulnerable driver to terminate AV/EDR from kernel." },
          { cls: "apt-cn", name: "APT41", note: "Vulnerable-driver abuse for kernel-level access documented in multiple operations." }
        ],
        cite: "MITRE ATT&CK T1068"
      },
      {
        sub: "T1068 - Local Service / OS Exploit (Named-Pipe & Coercion Primitives)",
        os: "win",
        indicator: "Local exploitation of a privileged service or OS component - including SeImpersonate-coercion ('Potato') chains and known local CVEs - yielding a SYSTEM process from an unprivileged context",
        sysmon: `// Coercion/Potato chains create a named pipe then
// impersonate the SYSTEM token that connects to it:
EventID=17 OR 18 (Pipe Created / Pipe Connected)
PipeName matches suspicious patterns:
  \\*\\pipe\\roguepotato* OR *\\pipe\\*epmapper*
  OR random/guid-like pipe names created by a
  service-account process right before a SYSTEM shell

// SYSTEM process spawned from a service-account parent
// with no normal service lineage (EID 1):
EventID=1
User=NT AUTHORITY\\SYSTEM
ParentImage = w3wp.exe OR sqlservr.exe OR a service acct
  process that should NOT be spawning SYSTEM shells
Image=*\\cmd.exe OR *\\powershell.exe

// A privileged service crashing/respawning oddly (EID 1
// lineage breaks) can indicate a service exploit.`,
        kibana: `// SYSTEM shell spawned by a web/db service identity
winlog.event_id: 1
AND user.name: "SYSTEM"
AND process.parent.name: ("w3wp.exe" OR "sqlservr.exe" OR "httpd.exe" OR "tomcat*.exe" OR "java.exe")
AND process.name: ("cmd.exe" OR "powershell.exe" OR "pwsh.exe" OR "rundll32.exe")

// Suspicious named pipes (Potato-family coercion)
winlog.event_id: (17 OR 18)
AND winlog.event_data.PipeName: (*potato* OR *epmapper* OR *roguepotato* OR *\\pipe\\* )
AND NOT process.name: ("services.exe" OR "svchost.exe" OR "spoolsv.exe")

// Service control manager: unexpected service crash/start
winlog.event_id: (7031 OR 7034 OR 7045)`,
        powershell: `# SYSTEM shells parented by service identities (Potato tell)
$svcParents='w3wp|sqlservr|httpd|tomcat|java\\.exe'
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; ID=1
} | Where-Object {
  ($_.Properties[12].Value -match 'SYSTEM') -and
  ($_.Properties[20].Value -match $svcParents) -and
  ($_.Properties[4].Value -match 'cmd\\.exe|powershell|pwsh|rundll32')
} | Select TimeCreated,
  @{n='Image';e={($_.Properties[4].Value -split '\\\\')[-1]}},
  @{n='Parent';e={($_.Properties[20].Value -split '\\\\')[-1]}},
  @{n='User';e={$_.Properties[12].Value}}

# Suspicious named pipes (EID 17/18)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; ID=17,18
} | Where-Object {
  $_.Properties[4].Value -match 'potato|epmapper|roguepotato'
} | Select TimeCreated,
  @{n='Pipe';e={$_.Properties[4].Value}},
  @{n='Image';e={($_.Properties[5].Value -split '\\\\')[-1]}}

# Accounts holding SeImpersonate (the Potato attack surface)
whoami /priv | Select-String 'SeImpersonate|SeAssignPrimaryToken'`,
        registry: `Local-exploit primitives are largely in-memory / runtime;
artifacts depend on the specific exploit. General pivots:

Potato-family (SeImpersonate coercion -> SYSTEM):
- No registry artifact; signature is named-pipe creation
  by a service account immediately before a SYSTEM child
- Attack surface = accounts/processes holding
  SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege
  (default for many service identities: IIS app pools,
  MSSQL, some scheduled-task contexts)

Known local CVE exploits (examples):
- Print Spooler (PrintNightmare, T-adjacent) - spoolsv.exe
  loading a DLL from a remote/odd path; check EID 7
- CVE-2021-1675 / 2021-34527 - spoolsv anomalies
- Various afd.sys / clfs.sys / win32k LPE - kernel crash
  or unusual SYSTEM process post-exploit

Investigation pivots:
- Map SeImpersonate holders for hardening
- Watch spoolsv.exe / privileged services loading DLLs
  from non-System32 paths (EID 7)
- A SYSTEM shell with a web/db-service parent is the
  cleanest single behavioral indicator`,
        tools: `PrintSpoofer - SeImpersonate -> SYSTEM via spooler RPC
  (the most common single tool on IIS/MSSQL boxes)
GodPotato - modern, broad-Windows-version Potato variant
JuicyPotato / JuicyPotatoNG - COM-based coercion
RoguePotato / RemotePotato0 - cross-session coercion
PrintNightmare exploits (CVE-2021-34527) - spooler LPE
Metasploit local_exploit_suggester + LPE modules
Watson / WinPEAS / Seatbelt - enumerate missing patches &
  exploitable LPE conditions (recon for this technique)
SharpUp - finds exploitable service/config LPE paths`,
        ossdetect: `Sigma:
- process_creation_system_shell_service_parent.yml
- proc_creation_win_susp_system_user_anomaly.yml
- pipe_created_susp_potato_named_pipe.yml
- win_security_susp_4672_service_account.yml

Atomic Red Team:
- T1068 (local privilege escalation tests)
- T1134.001 (Potato-family impersonation overlap)

Hayabusa:
- PotatoNamedPipe, SystemShellServiceParent rules

Velociraptor:
- Windows.System.Privileges (SeImpersonate holders)
- Windows.Detection.Potato
- Windows.Detection.PrintNightmare (spooler DLL loads)

Recon/hardening tooling (defender-side use):
- WinPEAS / Seatbelt / SharpUp to find the same LPE
  conditions attackers enumerate, and close them`,
        notes: "This row covers the 'exploit something local to become SYSTEM' bucket, with the SeImpersonate-coercion ('Potato') family as the dominant real-world case because it needs no memory-corruption exploit at all - it abuses a privilege many service accounts hold by default. On any IIS or MSSQL server, the service identity typically holds SeImpersonatePrivilege; PrintSpoofer/GodPotato/JuicyPotato coerce a SYSTEM process to authenticate to an attacker-controlled named pipe or COM endpoint, then impersonate the SYSTEM token - instant escalation. The cleanest behavioral detection is a SYSTEM-context shell (cmd/powershell) whose parent is a web/db service process (w3wp.exe, sqlservr.exe, tomcat, java) - that lineage is almost never legitimate. Supplement with named-pipe creation (EID 17/18) by a service account right before the SYSTEM child, and enumerate SeImpersonate holders as your attack surface. The other half - genuine local CVE exploitation (spooler PrintNightmare, kernel LPEs in clfs.sys/afd.sys/win32k) - is more variable, but shares the end-state tell: an unexpected SYSTEM process or a privileged service (spoolsv) loading a DLL from an odd path (EID 7). Pair this with the BYOVD row for full T1068 coverage; together they cover the overwhelming majority of host privilege-escalation-by-exploitation seen in the wild.",
        apt: [
          { cls: "apt-mul", name: "Ransomware Affiliates", note: "PrintSpoofer/GodPotato are go-to SYSTEM escalations on exposed IIS/MSSQL servers." },
          { cls: "apt-cn", name: "APT41", note: "Local service exploitation and Potato-style escalation on web-facing servers." },
          { cls: "apt-ir", name: "MuddyWater", note: "Local privilege-escalation exploits used following initial web-server access." },
          { cls: "apt-mul", name: "Red Team", note: "Potato family + SharpUp/WinPEAS enumeration is standard LPE tradecraft." }
        ],
        cite: "MITRE ATT&CK T1068"
      },
      {
        sub: "T1068 - Polkit pkexec Exploitation (PwnKit CVE-2021-4034)",
        os: "linux",
        indicator: "pkexec invoked with malformed/empty argv or unusual environment leading to a root shell; PwnKit-style exploitation of the SUID polkit pkexec binary, or pkexec spawning an unexpected child as root from a non-interactive context",
        sysmon: `// Sysmon for Linux EID 1 (ProcessCreate)
// pkexec is SUID-root; abuse spawns root shell from low-priv user

EventID=1
Image=*/pkexec
// PwnKit signature: pkexec called with no/empty arguments
// then a root shell or arbitrary binary executes
CommandLine matches:
  *pkexec*           (with argc=0 / empty argv = PwnKit primitive)
ParentImage matches (any low-priv context):
  */bash */sh */python* (exploit launcher)
AND child of pkexec runs as uid=0

// PwnKit drops a GCONV_PATH-controlled shared object;
// watch for a new .so loaded via GCONV_PATH manipulation
// and an unexpected directory created pre-exploit:
EventID=11 (FileCreate)
TargetFilename matches:
  *GCONV_PATH=*  (in environment)
  /tmp/*  with a .so + gconv-modules file dropped

// Auditd execve where pkexec yields uid=0 from non-root auid:
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/pkexec -k pkexec_exec`,
        kibana: `// pkexec execution - baseline then hunt anomalies
process.name: "pkexec"

// PwnKit: pkexec executed then a root shell with same session
process.name: "pkexec"
AND process.parent.name: ("bash" OR "sh" OR "python" OR "python3" OR "perl")

// Root shell whose parent was pkexec (successful escalation)
process.parent.name: "pkexec"
AND user.id: "0"
AND process.name: ("bash" OR "sh" OR "dash")

// GCONV_PATH in environment (PwnKit exploitation primitive)
process.env_vars: (*GCONV_PATH=* AND (*tmp* OR *dev/shm*))

// Auditd: pkexec execve where auid != 0 but resulting uid=0
event.module: "auditd"
AND tags: "pkexec_exec"
AND auditd.data.uid: "0"
AND NOT auditd.data.auid: ("0" OR "4294967295")

// pkexec error log entries (failed/abnormal invocations)
// /var/log/auth.log: "pkexec: ... The value for environment variable
// XAUTHORITY contains suspicious content"
message: ("pkexec" AND ("suspicious content" OR "cannot run" OR "must be setuid"))`,
        powershell: `#!/bin/bash
# T1068 - PwnKit / polkit pkexec exploitation hunt

echo "[*] === pkexec binary state ==="
ls -la /usr/bin/pkexec 2>/dev/null
echo "  package: $(dpkg -S /usr/bin/pkexec 2>/dev/null || rpm -qf /usr/bin/pkexec 2>/dev/null)"
echo "  version: $(pkexec --version 2>/dev/null)"

echo ""
echo "[*] === polkit version (PwnKit affects all before fix) ==="
# CVE-2021-4034 fixed: polkit 0.120-3 (Debian), 0.117-13 (RHEL8)
dpkg -l | grep -i polkit 2>/dev/null
rpm -qa | grep -i polkit 2>/dev/null

echo ""
echo "[*] === auth.log: pkexec abnormal invocations ==="
grep -h "pkexec" /var/log/auth.log /var/log/secure 2>/dev/null | \\
  grep -iE "(suspicious|cannot run|must be setuid|argv)" | tail -30

echo ""
echo "[*] === auditd: pkexec execve resulting in uid=0 from non-root ==="
ausearch -k pkexec_exec -i 2>/dev/null | tail -40
ausearch -m EXECVE -i 2>/dev/null | grep -B2 pkexec | tail -40

echo ""
echo "[*] === GCONV_PATH abuse artifacts in running processes ==="
for pid in $(ls /proc | grep -E '^[0-9]+$'); do
  gconv=$(tr '\\0' '\\n' < /proc/$pid/environ 2>/dev/null | grep GCONV_PATH)
  [ -n "$gconv" ] && echo "[FLAG] PID $pid: $gconv ($(cat /proc/$pid/comm 2>/dev/null))"
done

echo ""
echo "[*] === Suspicious gconv-modules / .so drops in writable dirs ==="
find /tmp /dev/shm /var/tmp -name "gconv-modules" -o -name "*.so" 2>/dev/null | \\
  grep -vE "^/usr|^/lib" | head -20

echo ""
echo "[*] === Recently spawned root shells with unusual parents ==="
ps -eo pid,ppid,user,comm,lstart,args 2>/dev/null | \\
  awk '$3=="root"' | grep -E "(bash|sh|dash)" | head -30`,
        registry: `PwnKit / polkit pkexec artifacts:

Vulnerable binary:
  /usr/bin/pkexec     - SUID-root; CVE-2021-4034 (PwnKit)
  Affects polkit versions from 2009 until Jan 2022 fix
  Fixed: polkit 0.120-3 (Debian), 0.117-13.el8 (RHEL)

Exploitation artifacts:
  GCONV_PATH env var pointing to attacker /tmp dir
  /tmp/<dir>/gconv-modules     - crafted iconv config
  /tmp/<dir>/<evil>.so         - malicious shared object
  (PwnKit drops these to hijack iconv() via GCONV_PATH)

Log evidence:
  /var/log/auth.log (Debian/Ubuntu)
  /var/log/secure   (RHEL/CentOS)
  Look for pkexec lines mentioning:
    "The value for the SHELL variable was not found"
    "The value for environment variable [X] contains
     suspicious content"
  These appear when PwnKit-style exploitation runs.

Process evidence:
  Root shell (uid=0) whose parent is pkexec
  pkexec invoked by a low-privilege user session
  auid (login uid) != 0 but resulting euid = 0

Related polkit CVE:
  CVE-2021-3560 - polkit auth bypass (DBus race)
    pkexec/dbus privilege grant via timed disconnect
  Watch dbus-daemon + polkitd interaction logs

Detection priority:
  Verify polkit is patched (primary control)
  Monitor pkexec execve where auid != 0 → uid 0`,
        tools: `PwnKit (CVE-2021-4034) - polkit pkexec:
  Disclosed Jan 2022 by Qualys. Memory-corruption in
  pkexec argument handling; weaponized within hours.
  Trivially reliable, no crash, works on default installs.
  One of the most widely exploited Linux LPE bugs ever.

Public exploit availability:
  Dozens of public PoCs (C, Python, Go, even one-file).
  Included in LinPEAS, linux-exploit-suggester output.
  Metasploit module: exploit/linux/local/cve_2021_4034_pwnkit

Threat actor adoption:
  TeamTNT, 8220 Gang, and multiple cryptomining crews
    adopted PwnKit for container-to-root and host LPE
  Used opportunistically after initial web/SSH access
    where pkexec was unpatched

CVE-2021-3560 (polkit auth bypass):
  Companion polkit bug; DBus timing race grants
  privileged action. Different mechanism, same target.

Related polkit-adjacent escalation:
  pkexec is on the GTFOBins list for sudo-allowed abuse
  separate from the memory-corruption CVE

Why pkexec is high-value to attackers:
  SUID-root by default on virtually every desktop and
  many server Linux installs; reliable; quiet; no kernel
  dependency (unlike kernel exploits which are version-locked)`,
        ossdetect: `Sigma rules:
- proc_creation_lnx_pkexec_privilege_escalation.yml
- proc_creation_lnx_cve_2021_4034_pwnkit.yml
- file_event_lnx_pwnkit_gconv_drop.yml

Elastic detection rules:
- Potential PwnKit Exploitation (CVE-2021-4034)
- Privilege Escalation via pkexec

Auditd:
  -a always,exit -F arch=b64 -S execve \\
    -F path=/usr/bin/pkexec -k pkexec_exec
  ausearch -k pkexec_exec -i | \\
    awk '/auid=/ && !/auid=0/ && /uid=0/'

Falco:
  rule: Polkit Local Privilege Escalation (CVE-2021-4034)
  condition: spawned_process and proc.name=pkexec
    and proc.args = ""   (empty args = PwnKit primitive)

Patch verification (primary defense):
  Debian/Ubuntu: dpkg -l policykit-1 (need >= 0.105-31+deb11u1)
  RHEL: rpm -q polkit (need >= 0.115-13.el8_5.1 / patched)

Vulners / OpenSCAP:
  Scan for CVE-2021-4034 presence by package version

Atomic Red Team:
  T1068 includes PwnKit simulation tests`,
        notes: "PwnKit (CVE-2021-4034) is among the most consequential Linux local privilege escalation vulnerabilities ever disclosed: it affects the SUID-root pkexec binary present by default on nearly every Linux desktop and a large fraction of servers, it requires no special preconditions, and the exploit is trivially reliable with no crash. Disclosed by Qualys in January 2022, it was weaponized within hours and is now a standard tool in post-initial-access escalation. The exploitation primitive abuses pkexec's argument handling combined with GCONV_PATH environment manipulation to load an attacker-controlled shared object as root. The two highest-value detection signals are: a root shell whose parent process is pkexec invoked from a non-root session, and GCONV_PATH pointing to a writable directory in a process environment. Auditd execve capture comparing auid (login UID) against the resulting uid=0 is the most reliable telemetry. The primary control is patching - verify polkit is at the fixed version - but because pkexec is legitimately used, behavioral detection of the escalation pattern catches both PwnKit and the companion CVE-2021-3560 auth bypass.",
        apt: [
          { cls: "apt-mul", name: "TeamTNT", note: "Adopted PwnKit for container-to-host and host privilege escalation after initial cloud/container access." },
          { cls: "apt-mul", name: "8220 Gang / cryptomining crews", note: "PwnKit used opportunistically post-access on unpatched hosts to gain root for miner deployment." },
          { cls: "apt-mul", name: "Commodity / red team", note: "CVE-2021-4034 is in LinPEAS, linux-exploit-suggester, and Metasploit; near-universal LPE option on unpatched Linux." }
        ],
        cite: "MITRE ATT&CK T1068"
      },
      {
        sub: "T1068 - Linux Kernel Exploitation (DirtyPipe, DirtyCOW, Looney Tunables)",
        os: "linux",
        indicator: "Local kernel or glibc exploit yielding root: DirtyPipe (CVE-2022-0847) overwriting read-only files, DirtyCOW (CVE-2016-5195) COW race, or Looney Tunables (CVE-2023-4911) glibc GLIBC_TUNABLES buffer overflow; signaled by unexpected root processes, modified system binaries, or anomalous syscall patterns",
        sysmon: `// Kernel/glibc LPE is hard to catch at syscall level alone;
// focus on the OUTCOME and the exploit's side effects.

// DirtyPipe (CVE-2022-0847): overwrites read-only files via
// splice() into a pipe. Watch for modification of files the
// process should not be able to write (e.g. /etc/passwd by
// a non-root process, or a SUID binary's content changing).
EventID=11 (FileModify)
TargetFilename matches:
  /etc/passwd  /etc/shadow  /etc/sudoers
  /usr/bin/su  /usr/bin/sudo  /usr/bin/passwd  (SUID binaries)
AND modifying process is NOT root / NOT a package manager

// Looney Tunables (CVE-2023-4911): GLIBC_TUNABLES env overflow
// run via a SUID binary. Watch for the env var:
process env contains: GLIBC_TUNABLES=glibc.* (malformed/oversized)

// Auditd: any process that gains uid=0 without a known
// escalation path (su/sudo/pkexec) - inferred root.
-a always,exit -F arch=b64 -S setuid,setresuid -k setuid_call
-a always,exit -F arch=b64 -S execve -k exec

// DirtyCOW (CVE-2016-5195): COW race; often modifies a SUID
// binary or /etc/passwd. Same file-modify signal as DirtyPipe.`,
        kibana: `// Modification of sensitive files by a non-root process
event.module: "file_integrity"
AND file.path: (
  "/etc/passwd" OR "/etc/shadow" OR "/etc/sudoers"
  OR "/usr/bin/su" OR "/usr/bin/sudo" OR "/usr/bin/passwd"
)
AND NOT process.name: ("dpkg" OR "rpm" OR "apt" OR "yum" OR "dnf" OR "passwd" OR "usermod" OR "useradd")

// GLIBC_TUNABLES in process environment (Looney Tunables)
process.env_vars: *GLIBC_TUNABLES=glibc.*

// Auditd: setuid/setresuid to 0 outside known escalation tools
event.module: "auditd"
AND auditd.data.syscall: ("setuid" OR "setresuid")
AND auditd.data.arg: "0"
AND NOT process.parent.name: ("su" OR "sudo" OR "sshd" OR "login" OR "pkexec")

// New root process whose ancestry has no su/sudo/sshd
user.id: "0"
AND process.name: ("bash" OR "sh" OR "dash")
AND NOT process.parent.name: ("su" OR "sudo" OR "sshd" OR "login" OR "pkexec" OR "systemd" OR "cron")

// Kernel ring buffer anomalies (dmesg) - segfaults in setuid bins
message: ("segfault" AND ("pkexec" OR "sudo" OR "su" OR "mount"))`,
        powershell: `#!/bin/bash
# T1068 - Kernel / glibc LPE hunt

echo "[*] === Kernel version vs known LPE CVEs ==="
uname -r
echo "  DirtyPipe   (CVE-2022-0847): kernels 5.8 - 5.16.11/5.15.25/5.10.102"
echo "  DirtyCOW    (CVE-2016-5195): kernels < 4.8.3 (legacy)"
echo "  Looney Tun. (CVE-2023-4911): glibc 2.34+ (env GLIBC_TUNABLES)"
echo "  glibc: $(ldd --version 2>/dev/null | head -1)"

echo ""
echo "[*] === Integrity check on sensitive files (DirtyPipe/COW targets) ==="
for f in /etc/passwd /etc/shadow /etc/sudoers /usr/bin/su /usr/bin/sudo /usr/bin/passwd; do
  [ -e "$f" ] || continue
  echo "$f | mtime: $(stat -c '%y' "$f") | $(sha256sum "$f" 2>/dev/null | cut -d' ' -f1)"
done
echo "  (compare hashes/mtimes against known-good baseline)"

echo ""
echo "[*] === Package verification of SUID binaries ==="
rpm -Va 2>/dev/null | grep -E "/(su|sudo|passwd|mount|pkexec)$" || \\
dpkg --verify 2>/dev/null | grep -E "/(su|sudo|passwd|mount|pkexec)$" || \\
  echo "  (run rpm -Va or dpkg --verify; '5' flag = checksum changed)"

echo ""
echo "[*] === GLIBC_TUNABLES abuse in running processes (Looney Tunables) ==="
for pid in $(ls /proc | grep -E '^[0-9]+$'); do
  tun=$(tr '\\0' '\\n' < /proc/$pid/environ 2>/dev/null | grep GLIBC_TUNABLES)
  [ -n "$tun" ] && echo "[FLAG] PID $pid ($(cat /proc/$pid/comm 2>/dev/null)): $tun"
done

echo ""
echo "[*] === dmesg: segfaults in SUID binaries (exploit attempts) ==="
dmesg 2>/dev/null | grep -iE "segfault.*(pkexec|sudo|su|mount|passwd)" | tail -20

echo ""
echo "[*] === Root processes with no su/sudo/sshd ancestry ==="
ps -eo pid,ppid,user,comm,args 2>/dev/null | awk '$3=="root"' | \\
  grep -E "(bash|sh|dash)" | head -20

echo ""
echo "[*] === Public LPE tooling artifacts in writable paths ==="
find /tmp /dev/shm /var/tmp -type f \\( -name "*.c" -o -name "dirtypipe*" \\
  -o -name "*exploit*" -o -name "cve-*" \\) 2>/dev/null | head -20`,
        registry: `Linux kernel / glibc LPE artifacts:

DirtyPipe (CVE-2022-0847):
  Kernels 5.8 through 5.16.11 / 5.15.25 / 5.10.102
  Overwrites read-only files via splice() pipe flag bug
  Common targets:
    /etc/passwd  (add root user / clear root password)
    SUID binaries (overwrite to inject payload)
  Artifact: modified /etc/passwd with anomalous mtime,
    or a SUID binary whose hash no longer matches package

DirtyCOW (CVE-2016-5195):
  Kernels < 4.8.3 (legacy RHEL6/7, old Ubuntu)
  Copy-on-write race; writes to read-only mappings
  Targets: SUID binaries, /etc/passwd
  Still relevant for legacy OT/embedded Linux

Looney Tunables (CVE-2023-4911):
  glibc 2.34+ ; GLIBC_TUNABLES env buffer overflow
  Triggered via any SUID binary
  Artifact: GLIBC_TUNABLES=glibc.malloc... in env;
    malformed/oversized tunables string

Netfilter / nf_tables CVEs (2022-2024):
  Multiple kernel LPEs (CVE-2022-32250, CVE-2023-32233,
    CVE-2024-1086). Exploit via crafted netlink messages.
  Artifact: unusual unprivileged user namespace creation,
    nft/netlink activity from non-admin processes

General detection signals:
  /var/log/kern.log , dmesg     - segfaults, oops, taints
  /etc/passwd , /etc/shadow     - mtime + hash baseline
  SUID binary integrity         - rpm -Va / dpkg --verify
  Unexpected root shells        - ancestry without su/sudo

User namespace abuse (precondition for many kernel LPEs):
  /proc/sys/kernel/unprivileged_userns_clone (should be 0)
  unshare -r often precedes kernel exploitation`,
        tools: `Linux kernel LPE landscape:

DirtyPipe (CVE-2022-0847):
  Disclosed Mar 2022 by Max Kellermann. Extremely reliable,
  no crash. Public PoCs overwrite /etc/passwd or hijack a
  SUID binary. Trivial to use. Affects Android too.
  Adopted by cryptomining and container-escape actors.

DirtyCOW (CVE-2016-5195):
  2016 disclosure; one of the most famous Linux LPEs.
  Still relevant on legacy/embedded/OT Linux that is
  rarely patched. Many public PoC variants.

Looney Tunables (CVE-2023-4911):
  Qualys, Oct 2023. glibc GLIBC_TUNABLES overflow via
  SUID binary. Public exploits within days. Affects
  Fedora, Ubuntu, Debian, RHEL defaults.

Netfilter/nf_tables family (2022-2024):
  CVE-2024-1086 (double-free) heavily weaponized 2024.
  Reliable root via unprivileged user namespaces.
  Used in container escapes and host LPE.

Common enumeration → exploit tooling:
  linux-exploit-suggester / les2: maps uname -r to CVEs
  LinPEAS: flags kernel version + applicable exploits
  Metasploit: many local exploit modules per CVE
  GitHub: public PoC for nearly every modern Linux LPE

Threat actor use:
  Cryptomining crews (TeamTNT, 8220, Kinsing) chain a
  web/SSH foothold to a kernel/pkexec LPE for root, then
  deploy miners + persistence.
  APT use is more targeted but documented (e.g. kernel
  LPEs staged after initial Linux server compromise).`,
        ossdetect: `Sigma rules:
- file_event_lnx_dirtypipe_passwd_modification.yml
- proc_creation_lnx_glibc_tunables_priv_esc.yml
- proc_creation_lnx_unshare_userns_priv_esc.yml

Elastic detection rules:
- Potential DirtyPipe Exploitation (CVE-2022-0847)
- Potential Privilege Escalation via GLIBC_TUNABLES
- Unprivileged User Namespace Creation

Patch / version verification (primary control):
  uname -r  → map to les2 / linux-exploit-suggester
  rpm -q kernel / dpkg -l linux-image-*
  rpm -q glibc / dpkg -l libc6  (Looney Tunables)

Auditd:
  -a always,exit -F arch=b64 -S setuid,setresuid -k setuid_call
  -w /etc/passwd -p wa -k passwd_write
  -w /etc/shadow -p wa -k shadow_write
  ausearch -k passwd_write | grep -v "auid=0"

Falco:
  rule: Write below etc (passwd/shadow by non-root)
  rule: Mkdir binary dirs / Modify binary dirs
  rule: Unprivileged Delegation of Page Faults (kernel exploit hint)

File integrity (AIDE / Tripwire / Wazuh syscheck):
  /etc/passwd /etc/shadow /etc/sudoers + all SUID binaries
  Any change outside a package-install window = critical

Disable attack surface:
  sysctl kernel.unprivileged_userns_clone=0
  (removes precondition for many netfilter kernel LPEs)`,
        notes: "Kernel and glibc local privilege escalation exploits are the second major Linux root path after pkexec/sudo abuse, and they are particularly relevant in environments with infrequent patching - legacy RHEL, embedded systems, and OT-adjacent Linux. Unlike pkexec abuse, kernel exploits are version-locked: the specific CVE that works depends on the exact kernel or glibc version, which is why attacker tooling (linux-exploit-suggester, LinPEAS) starts by mapping uname -r to applicable CVEs. This version-dependence is also a defender's advantage - knowing your kernel and glibc versions tells you precisely which exploits apply. The detection challenge is that the exploitation itself happens in kernel space and is hard to observe directly; the reliable signals are the outcomes and side effects: DirtyPipe and DirtyCOW typically modify /etc/passwd or overwrite a SUID binary (catch via file integrity monitoring on those targets by non-package-manager processes), Looney Tunables leaves a distinctive GLIBC_TUNABLES environment string, and most netfilter kernel LPEs require unprivileged user namespace creation (unshare -r) which can be disabled outright via sysctl. The single most valuable control beyond patching is file integrity monitoring on /etc/passwd, /etc/shadow, and all SUID binaries, combined with auditd setuid syscall capture to flag processes reaching uid=0 without traversing su/sudo/sshd.",
        apt: [
          { cls: "apt-mul", name: "TeamTNT / Kinsing", note: "Chain web/SSH foothold to kernel or pkexec LPE for root, then deploy cryptominers and persistence." },
          { cls: "apt-mul", name: "8220 Gang", note: "Opportunistic kernel LPE use on unpatched cloud Linux hosts following initial access." },
          { cls: "apt-mul", name: "Container-escape operators", note: "CVE-2024-1086 (nf_tables) and DirtyPipe used to break out of containers to host root via kernel bugs." }
        ],
        cite: "MITRE ATT&CK T1068"
      }
    ]
  },
{
    id: "T1574.011",
    name: "Hijack Execution Flow: Services Registry Permissions Weakness",
    desc: "Adversaries modify a service's registry configuration (ImagePath, FailureCommand, ServiceDll, Parameters) where the service key ACL is weak, redirecting a SYSTEM-context service to attacker code.",
    rows: [
      {
        sub: "T1574.011 - Service ImagePath / FailureCommand Redirect",
        os: "win",
        indicator: "Sysmon EID 13 modifying ImagePath, FailureCommand, or ServiceDll under a Services key by a non-installer process - redirecting a SYSTEM service binary",
        sysmon: `EventID=13 (RegistryValueSet)
TargetObject matches:
  *\\System\\CurrentControlSet\\Services\\*\\ImagePath
  OR *\\Services\\*\\Parameters\\ServiceDll
  OR *\\Services\\*\\FailureCommand
  OR *\\Services\\*\\FailureActions
Image NOT in (services.exe, TrustedInstaller.exe,
  msiexec.exe, a known installer/updater)
Details points at a user-writable path or interpreter:
  *\\AppData\\* OR *\\Temp\\* OR *\\ProgramData\\*
  OR *powershell* OR *cmd.exe* OR *rundll32*

// Often paired with a subsequent service start (EID 1
// child of services.exe running the redirected binary).`,
        kibana: `// Service config value redirected by a non-installer
winlog.event_id: 13
AND registry.path: (*\\Services\\*\\ImagePath OR *\\Services\\*\\ServiceDll OR *\\Services\\*\\FailureCommand OR *\\Services\\*\\FailureActions)
AND NOT process.name: ("services.exe" OR "TrustedInstaller.exe" OR "msiexec.exe" OR "svchost.exe")

// Tighten: redirected to a user-writable path / interpreter
winlog.event_id: 13
AND registry.path: (*\\Services\\*\\ImagePath OR *\\Services\\*\\ServiceDll)
AND registry.data.strings: (*\\AppData\\* OR *\\Temp\\* OR *\\ProgramData\\* OR *\\Public\\* OR *powershell* OR *cmd.exe* OR *rundll32*)

// Service control: the modified service then starting
winlog.event_id: 7036
AND winlog.event_data.param2: "running"`,
        powershell: `# Service config redirects by non-installer (Sysmon EID 13)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; ID=13
} | Where-Object {
  ($_.Properties[4].Value -match 'Services\\\\[^\\\\]+\\\\(ImagePath|ServiceDll|FailureCommand|FailureActions)') -and
  ($_.Properties[3].Value -notmatch 'services\\.exe|TrustedInstaller|msiexec')
} | Select TimeCreated,
  @{n='Target';e={$_.Properties[4].Value}},
  @{n='NewValue';e={$_.Properties[5].Value}},
  @{n='By';e={($_.Properties[3].Value -split '\\\\')[-1]}}

# Audit service key ACLs for weak (writable-by-user) perms
Get-ChildItem 'HKLM:\\SYSTEM\\CurrentControlSet\\Services' |
  ForEach-Object {
    $acl = Get-Acl $_.PSPath -EA SilentlyContinue
    $weak = $acl.Access | Where-Object {
      ($_.IdentityReference -match 'Users|Everyone|Authenticated Users|INTERACTIVE') -and
      ($_.RegistryRights -match 'FullControl|SetValue|WriteKey') -and
      ($_.AccessControlType -eq 'Allow')
    }
    if ($weak) { [pscustomobject]@{ Service=$_.PSChildName; WeakACE=$weak.IdentityReference } }
  }`,
        registry: `Service configuration values that grant code execution:
HKLM\\SYSTEM\\CurrentControlSet\\Services\\<svc>\\
  ImagePath        - the binary the SCM launches (SYSTEM)
  ServiceDll       - (under \\Parameters) for svchost svcs
  FailureCommand   - command run on service failure
  FailureActions   - can specify a run-program action
  ObjectName       - the account the service runs as
                     (LocalSystem = SYSTEM)

Weak-ACL escalation path:
- If a low-priv user has SetValue/WriteKey on the service
  key, they rewrite ImagePath to their payload, then
  trigger a service restart (or wait for reboot) - the
  SCM launches their binary as the service account
  (commonly LocalSystem = SYSTEM).
- FailureCommand/FailureActions variant: set a failure
  command, then crash the service to trigger it.

Investigation pivots:
- Compare ImagePath against the service's installer
  provenance; a recently-changed ImagePath on a SYSTEM
  service pointing at AppData/Temp is the signature
- Enumerate service-key ACLs for non-admin write access
  (the precondition) - tools: accesschk -kvuqsw, PowerUp`,
        tools: `PowerUp (Get-ModifiableService / Invoke-ServiceAbuse)
SharpUp - finds modifiable services / weak service ACLs
accesschk.exe -kvuqsw (Sysinternals) - service key ACL audit
WinPEAS / Seatbelt - enumerate weak service permissions
Metasploit - service_permissions LPE module
sc.exe config <svc> binPath= ... - the built-in redirect
reg.exe - direct ImagePath rewrite where key is writable`,
        ossdetect: `Sigma:
- registry_set_service_imagepath_change_susp.yml
- registry_set_service_dll_susp_path.yml
- registry_set_service_failure_command.yml

Atomic Red Team:
- T1574.011 (service registry permissions tests)
- T1543.003 (overlapping service-config tests)

Hayabusa:
- ServiceImagePathModification, ServiceDllHijack rules

Velociraptor:
- Windows.System.Services (config + ACL enumeration)
- Windows.Detection.ServiceRegistryHijack`,
        notes: "This is one of the classic Windows local-privilege-escalation primitives and it's distinct from the persistence framing of services: here the goal is escalation via a weak service-key ACL. The precondition is that a non-admin user holds SetValue/WriteKey on a service's registry key (or has write access to the service binary itself - see the file-permissions row). When that's true, the attacker rewrites ImagePath (or ServiceDll for svchost-hosted services, or FailureCommand) to point at their payload, then triggers a restart - and the Service Control Manager launches it as the service account, almost always LocalSystem. The detection that matters most: Sysmon EID 13 writes to a Services\\*\\ImagePath|ServiceDll|FailureCommand value by anything other than services.exe/TrustedInstaller/msiexec/a known installer, especially when the new value points at AppData/Temp or an interpreter. Correlate with a subsequent service-start (7036 'running' or an EID 1 child of services.exe). The proactive hardening pivot is to enumerate service-key ACLs for non-admin write access (accesschk -kvuqsw / PowerUp) and fix them - that closes the technique entirely. Baseline legitimate updaters that rewrite ImagePath during version upgrades to avoid false positives.",
        apt: [
          { cls: "apt-mul", name: "Red Team / PowerUp", note: "Modifiable-service abuse is a staple of PowerUp/SharpUp LPE enumeration." },
          { cls: "apt-mul", name: "Ransomware Affiliates", note: "Weak service ACLs used to gain SYSTEM before disabling defenses." },
          { cls: "apt-cn", name: "APT41", note: "Service configuration tampering documented for privileged execution." }
        ],
        cite: "MITRE ATT&CK T1574.011"
      }
    ]
  },
  {
    id: "T1574.005",
    name: "Hijack Execution Flow: Executable Installer File / Unquoted Path / Weak Permissions",
    desc: "Adversaries exploit unquoted service paths and weak file or directory permissions on service binaries and their folders to plant code that a SYSTEM service will execute.",
    rows: [
      {
        sub: "T1574.009 - Unquoted Service Path Exploitation",
        os: "win",
        indicator: "A file written to an intermediate path of an unquoted SYSTEM service binary (e.g. C:\\Program.exe for 'C:\\Program Files\\App\\svc.exe'), then executed by the SCM at service start",
        sysmon: `// Stage 1 - file drop at an unquoted-path intercept point
EventID=11 (FileCreate)
TargetFilename matches a space-truncated service path:
  C:\\Program.exe
  OR C:\\Program Files\\<vendor>\\<firstword>.exe
  (i.e. the path up to the first space + .exe)
Image = a non-installer process

// Stage 2 - the planted exe launched by the SCM (SYSTEM)
EventID=1 (ProcessCreate)
ParentImage=*\\services.exe
Image = the intercept exe (e.g. C:\\Program.exe)
User=NT AUTHORITY\\SYSTEM
// A services.exe child running from a root or space-
// truncated path is the smoking gun.`,
        kibana: `// File dropped at a classic unquoted-path intercept
winlog.event_id: 11
AND file.path: (C\\:\\\\Program.exe OR C\\:\\\\Program Files\\\\*\\\\*.exe)
AND NOT process.name: ("msiexec.exe" OR "TrustedInstaller.exe")

// services.exe launching a binary from an odd/truncated path
winlog.event_id: 1
AND process.parent.name: "services.exe"
AND (process.executable: C\\:\\\\Program.exe OR NOT process.executable: (C\\:\\\\Windows\\\\* OR C\\:\\\\Program Files\\\\* OR C\\:\\\\Program Files \\(x86\\)\\\\*))
AND user.name: "SYSTEM"`,
        powershell: `# Enumerate unquoted service paths with spaces (the vuln)
Get-CimInstance Win32_Service |
  Where-Object {
    $_.PathName -and
    $_.PathName -notmatch '^"' -and
    $_.PathName -match ' ' -and
    $_.PathName -notmatch '^[A-Za-z]:\\\\Windows\\\\'
  } | Select Name, StartName, PathName

# Sysmon: services.exe children from truncated/root paths (EID 1)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; ID=1
} | Where-Object {
  ($_.Properties[20].Value -match 'services\\.exe') -and
  ($_.Properties[4].Value -match '^[A-Za-z]:\\\\[^\\\\]+\\.exe$')   # exe in a drive root
} | Select TimeCreated,
  @{n='Image';e={$_.Properties[4].Value}},
  @{n='User';e={$_.Properties[12].Value}}

# File drops at intercept points (EID 11)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; ID=11
} | Where-Object {
  $_.Properties[4].Value -match '^C:\\\\Program\\.exe$|^C:\\\\Program Files\\\\[^\\\\]+\\.exe$'
}`,
        registry: `No new registry artifact - the vulnerable config already
exists in the service's ImagePath. The artifact is on disk
(the planted exe) plus the service's existing unquoted
ImagePath.

The vulnerable configuration:
HKLM\\SYSTEM\\CurrentControlSet\\Services\\<svc>\\ImagePath
  = C:\\Program Files\\Some App\\service.exe
    (NO surrounding quotes, AND a space in the path)

How Windows resolves it (the bug):
  The SCM tries each space-delimited prefix + ".exe":
    1. C:\\Program.exe
    2. C:\\Program Files\\Some.exe
    3. C:\\Program Files\\Some App\\service.exe
  If an attacker can write C:\\Program.exe (or the
  intermediate), it runs first - as the service account.

Escalation precondition:
- Service runs as LocalSystem (usual)
- Attacker can write to C:\\ or the intermediate dir
  (C:\\ root is often writable by Authenticated Users on
  misconfigured or older systems)

Investigation pivots:
- Enumerate services with unquoted paths containing spaces
  outside C:\\Windows (the candidate set)
- Any .exe in a drive root or at a space-truncation point
  of a service path is almost always malicious`,
        tools: `PowerUp - Get-UnquotedService / Write-ServiceBinary
SharpUp - unquoted service path detection
WinPEAS / Seatbelt / Watson - LPE enumeration incl. this
Metasploit - trusted_service_path module
sc.exe qc <svc> - manual config inspection
accesschk.exe - verify writability of the intercept dir`,
        ossdetect: `Sigma:
- file_event_win_exe_in_drive_root.yml
- process_creation_services_exe_susp_child_path.yml
- proc_creation_win_service_path_hijack.yml

Atomic Red Team:
- T1574.009 (unquoted service path tests)

Hayabusa:
- UnquotedServicePathExploit, ServicesExeOddChild rules

Velociraptor:
- Windows.System.Services (unquoted-path enumeration)
- Windows.Detection.UnquotedServicePath`,
        notes: "Unquoted service path is a textbook Windows LPE that still appears constantly on third-party software. The vulnerability: a service's ImagePath is stored without quotes and contains spaces (e.g. C:\\Program Files\\Some App\\svc.exe), so the SCM tries each space-delimited prefix in turn - C:\\Program.exe, then C:\\Program Files\\Some.exe, then the real path. If a low-priv user can write a file at one of those intercept points (C:\\ root is writable by Authenticated Users on a surprising number of systems), it executes first as the service account - almost always SYSTEM. Detection has two clean signals: (1) the candidate set is enumerable - services with unquoted, space-containing paths outside C:\\Windows; (2) the exploitation is a file drop at an intercept point (C:\\Program.exe or C:\\Program Files\\<word>.exe) followed by services.exe launching a binary from a drive root or truncation point as SYSTEM. That services.exe-child-from-a-weird-path pattern is the smoking gun and is very low-FP. The hardening fix is trivial (quote the ImagePath, or fix the directory ACL), which is why proactive enumeration with PowerUp/WinPEAS is the right defensive posture - find and fix them before an attacker does.",
        apt: [
          { cls: "apt-mul", name: "Red Team / PowerUp", note: "Unquoted service path is one of the first LPE checks any operator runs." },
          { cls: "apt-mul", name: "Commodity Malware", note: "Some loaders opportunistically exploit unquoted paths on third-party services." },
          { cls: "apt-ir", name: "MuddyWater", note: "Local privilege escalation via service misconfiguration documented post-access." }
        ],
        cite: "MITRE ATT&CK T1574.009"
      },
      {
        sub: "T1574.010 - Weak Service Binary / Folder Permissions",
        os: "win",
        indicator: "A SYSTEM service's executable or its containing folder is writable by a non-admin; the binary is overwritten or a DLL it loads is planted, then run as SYSTEM at service start",
        sysmon: `// Overwrite/replace of a service binary (EID 11)
EventID=11 (FileCreate) OR FileCreateStreamHash
TargetFilename = the on-disk path of a known service exe
  (e.g. C:\\Program Files\\<vendor>\\service.exe)
Image = a non-installer, non-TrustedInstaller process
  (a normal user process rewriting a service exe is the
   tell)

// Or a DLL planted next to a service exe (side-load) (EID 11/7)
EventID=7 (ImageLoad)
Image = <a SYSTEM service exe>
ImageLoaded = a DLL in the service's own folder that is
  unsigned / recently written by a user process

// Service restart launching the replaced binary (EID 1)
EventID=1
ParentImage=*\\services.exe
User=NT AUTHORITY\\SYSTEM`,
        kibana: `// Non-installer writing a service binary path
winlog.event_id: 11
AND file.path: (C\\:\\\\Program Files\\\\*\\\\*.exe OR C\\:\\\\Program Files \\(x86\\)\\\\*\\\\*.exe)
AND NOT process.name: ("msiexec.exe" OR "TrustedInstaller.exe" OR "*setup*.exe" OR "*update*.exe")

// Unsigned DLL loaded by a SYSTEM service from its own dir
winlog.event_id: 7
AND dll.code_signature.signed: false
AND process.parent.name: "services.exe"

// Service started after a recent binary write
winlog.event_id: 7036
AND winlog.event_data.param2: "running"`,
        powershell: `# Enumerate services whose binary or folder is user-writable
Get-CimInstance Win32_Service | ForEach-Object {
  $path = ($_.PathName -replace '^"','' -split '"')[0]
  $path = ($path -split '\\.exe')[0] + '.exe'
  if (Test-Path $path) {
    $acl = Get-Acl $path -EA SilentlyContinue
    $dir = Split-Path $path
    $dacl = Get-Acl $dir -EA SilentlyContinue
    $weakFile = $acl.Access | Where-Object {
      $_.IdentityReference -match 'Users|Everyone|Authenticated|INTERACTIVE' -and
      $_.FileSystemRights -match 'Write|FullControl|Modify' -and
      $_.AccessControlType -eq 'Allow'
    }
    $weakDir = $dacl.Access | Where-Object {
      $_.IdentityReference -match 'Users|Everyone|Authenticated|INTERACTIVE' -and
      $_.FileSystemRights -match 'Write|FullControl|Modify' -and
      $_.AccessControlType -eq 'Allow'
    }
    if ($weakFile -or $weakDir) {
      [pscustomobject]@{ Service=$_.Name; RunAs=$_.StartName;
        Binary=$path; WeakBinary=[bool]$weakFile; WeakFolder=[bool]$weakDir }
    }
  }
}

# Non-installer writes to a Program Files exe (EID 11)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; ID=11
} | Where-Object {
  ($_.Properties[4].Value -match 'Program Files.*\\.exe$') -and
  ($_.Properties[5].Value -notmatch 'msiexec|TrustedInstaller|setup|update')
}`,
        registry: `No registry artifact - this is a filesystem-ACL weakness.
The vulnerable configuration is a permission, not a value:

Escalation preconditions (either is sufficient):
1. The service EXE itself is writable by a non-admin
   -> attacker overwrites it, restarts the service,
      their code runs as the service account (SYSTEM)
2. The service's FOLDER is writable by a non-admin
   -> attacker plants a DLL the service loads (search
      order / known-DLL) OR replaces the exe
3. A DLL the service depends on lives in a writable dir
   -> classic DLL hijack into a SYSTEM process

On-disk artifacts:
- A service exe with a recent modified-time written by a
  non-installer process
- An unsigned/odd DLL in a service's program folder
- Backup copies attackers sometimes leave (svc.exe.bak)

Enumeration (precondition discovery):
- accesschk.exe -quvw "Authenticated Users" <service dir>
- accesschk.exe -quvw <service exe>
- PowerUp Get-ModifiableServiceFile / Get-ModifiablePath

Investigation pivots:
- Diff the service binary's hash/signature vs the vendor
  original; a SYSTEM service exe that is unsigned or
  signature-mismatched and recently modified is the tell`,
        tools: `PowerUp - Get-ModifiableServiceFile, Get-ModifiablePath,
  Install-ServiceBinary (weaponizes the overwrite)
SharpUp - modifiable service binary / path detection
accesschk.exe -quvw (Sysinternals) - ACL verification
WinPEAS / Seatbelt - weak-permission enumeration
Metasploit - service_permissions (file mode)
DLL side-loading kits (when the folder, not the exe, is
  the writable target)`,
        ossdetect: `Sigma:
- file_event_win_service_binary_overwrite.yml
- image_load_susp_unsigned_dll_system_service.yml
- proc_creation_win_modified_service_binary.yml

Atomic Red Team:
- T1574.010 (weak service permissions tests)
- T1574.001 (DLL search-order overlap for the folder case)

Hayabusa:
- ServiceBinaryOverwrite, SystemServiceUnsignedDll rules

Velociraptor:
- Windows.System.Services (binary/folder ACL audit)
- Windows.Detection.WeakServicePermissions`,
        notes: "The file-permissions sibling of the registry-ACL row: instead of rewriting ImagePath, the attacker exploits write access to the service's binary or its folder. Three variants share this row - (1) the service EXE itself is writable, so the attacker overwrites it; (2) the service's folder is writable, so the attacker plants a DLL the service loads (a DLL search-order hijack landing in a SYSTEM process); (3) a dependency DLL lives in a writable location. All three end the same way: at the next service start the SCM runs the service as LocalSystem and the attacker's code executes as SYSTEM. The precondition is enumerable - non-admin Write/Modify/FullControl on a service exe or its directory (accesschk -quvw, PowerUp Get-ModifiableServiceFile). The runtime detection: a non-installer process writing to a Program Files .exe that belongs to a service, an unsigned DLL loaded by a services.exe child, or a SYSTEM service binary whose signature suddenly mismatches the vendor original. Lead with the signature/modified-time anomaly on SYSTEM service binaries - it's high fidelity. As always the fix is cheap (correct the ACL), so proactive enumeration is the strongest defense; this technique disappears the moment service binaries and folders are admin-write-only.",
        apt: [
          { cls: "apt-mul", name: "Red Team / PowerUp", note: "Modifiable service binary/path is core PowerUp/SharpUp LPE tradecraft." },
          { cls: "apt-mul", name: "Ransomware Affiliates", note: "Weak service-binary permissions abused to reach SYSTEM before encryption." },
          { cls: "apt-kp", name: "Lazarus", note: "Service binary replacement documented for privileged execution and persistence." }
        ],
        cite: "MITRE ATT&CK T1574.010"
      }
    ]
  },
  {
    id: "T1134.005",
    name: "Access Token Manipulation: SID-History Injection",
    desc: "Adversaries add a privileged SID (e.g. Domain Admins, Enterprise Admins) to an account's SID-History so it inherits those rights transparently - a stealthy domain privilege escalation and persistence primitive.",
    rows: [
      {
        sub: "T1134.005 - SID-History Injection (DCShadow / Mimikatz / Native)",
        os: "win",
        indicator: "An account's sIDHistory attribute modified to include a high-privilege or cross-domain SID - via mimikatz sid::add, DSInternals, or a rogue directory replication (DCShadow)",
        sysmon: `// SID-History injection is a directory-level action; the
// best host-side signals are around the tools and the DC:
EventID=1 (on a DC or admin host)
Image=*\\mimikatz.exe OR CommandLine matches:
  *sid::add* OR *sid::patch* OR *misc::addsid*
OR Image=*\\powershell.exe with DSInternals cmdlets:
  *Add-ADDBSidHistory* OR *Set-ADDBPrimaryGroup*

// DCShadow / rogue replication pattern (registering a
// fake DC) shows as RPC/DRSUAPI from a non-DC host -
// pairs with network detection on the DRSUAPI interface.

// Primary detection is in the DC Security log (see kibana
// / notes) rather than Sysmon - this row leans on 4765/
// 4766/4738 + 4662 directory-object access.`,
        kibana: `// SID History added to an account (DC Security log)
winlog.event_id: 4765
// 4765 = SID History was added to an account

// SID History add FAILED (attempt signal)
winlog.event_id: 4766

// Account changed - watch sIDHistory in 4738 details
winlog.event_id: 4738
AND winlog.event_data.SidHistory: *

// Directory replication / DCShadow: DRSUAPI from non-DC
// (4662 with the replication GUIDs) by an unexpected actor
winlog.event_id: 4662
AND winlog.event_data.Properties: (*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2* OR *1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*)
AND NOT winlog.event_data.SubjectUserName: (*$ )

// Mimikatz/DSInternals on host
winlog.event_id: 1
AND process.command_line: (*sid\\:\\:add* OR *misc\\:\\:addsid* OR *Add-ADDBSidHistory*)`,
        powershell: `# DC Security log: SID History added (4765) / failed (4766)
Get-WinEvent -FilterHashtable @{ LogName='Security'; ID=4765,4766 } -MaxEvents 200 |
  Select TimeCreated, Id,
    @{n='Target';e={$_.Properties[1].Value}},
    @{n='SourceSID';e={$_.Properties[5].Value}}

# Hunt accounts that currently HAVE sIDHistory (review all)
Get-ADUser -Filter 'SIDHistory -like "*"' -Properties SIDHistory |
  Select SamAccountName, SIDHistory
Get-ADGroup -Filter 'SIDHistory -like "*"' -Properties SIDHistory |
  Select Name, SIDHistory
# Any sIDHistory containing a RID 512 (Domain Admins),
# 519 (Enterprise Admins), 518 (Schema Admins) on a normal
# user account is a major red flag.

# DCShadow / suspicious replication (4662 DRSUAPI by non-DC)
Get-WinEvent -FilterHashtable @{ LogName='Security'; ID=4662 } -MaxEvents 500 |
  Where-Object { $_.Message -match '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' } |
  Select TimeCreated, @{n='Actor';e={$_.Properties[1].Value}}

# Mimikatz/DSInternals on host (Sysmon EID 1)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; ID=1
} | Where-Object { $_.Properties[10].Value -match 'sid::add|misc::addsid|Add-ADDBSidHistory' }`,
        registry: `No registry artifact - SID-History lives in Active
Directory, on the account's sIDHistory attribute. The
authoritative artifacts are in AD and the DC Security log:

Directory object:
- <account>.sIDHistory now contains one or more SIDs that
  were not granted through a legitimate migration
- Especially dangerous: a SID with RID 512 (Domain
  Admins), 519 (Enterprise Admins), 518 (Schema Admins),
  or 516 (Domain Controllers), or a cross-domain SID

DC Security log:
- 4765 SID History was added to an account
- 4766 An attempt to add SID History FAILED
- 4738 User account changed (sIDHistory in detail)
- 4662 (with DRSUAPI replication GUIDs) for DCShadow-style
  injection that bypasses normal write paths

Why it's nasty:
- The injected SID is honored at logon transparently - the
  account gets DA rights without being IN Domain Admins,
  so it hides from group-membership audits
- Survives password resets; only an explicit sIDHistory
  cleanup removes it

Investigation pivots:
- Periodically enumerate ALL accounts with non-empty
  sIDHistory and validate each against migration records
- Legitimate sIDHistory only appears after a real domain
  migration; on a single-domain forest it should be empty`,
        tools: `Mimikatz - sid::add, sid::patch, misc::addsid
DSInternals - Add-ADDBSidHistory (offline NTDS edit)
DCShadow (mimikatz lsadump::dcshadow) - inject via rogue
  replication, bypassing normal directory-write logging
Impacket - ntlmrelayx / secretsdump adjacent tooling
Native: ntdsutil / Active Directory Migration Tool (ADMT)
  is the LEGITIMATE source of sIDHistory (migration only)`,
        ossdetect: `Sigma:
- win_security_sid_history_added_4765.yml
- win_security_susp_sid_history_dcshadow.yml
- proc_creation_win_mimikatz_sid_add.yml

Atomic Red Team:
- T1134.005 (SID-History injection tests)

Hayabusa:
- SIDHistoryInjection (4765), DCShadowReplication rules

Velociraptor:
- Windows.AD.SIDHistory (enumerate accounts with sIDHistory)
- Windows.Detection.DCShadow

Microsoft Defender for Identity:
- Detects SID-History injection and DCShadow natively at
  the directory level - the strongest single control`,
        notes: "SID-History injection is a high-impact domain privilege escalation that doubles as stealthy persistence, so it belongs in the priv-esc set even though it's directory-centric rather than pure host. The sIDHistory attribute legitimately exists to support domain migrations (an account keeps its old SIDs so it retains access during a move). Attackers abuse it by injecting a privileged SID - Domain Admins (RID 512), Enterprise Admins (519) - into a normal account's sIDHistory; Windows then honors those rights at every logon, transparently, so the account wields DA without ever appearing in the Domain Admins group. That invisibility to group-membership audits is exactly what makes it dangerous. Three injection routes: mimikatz sid::add (needs DA already - so it's persistence after escalation), DSInternals offline NTDS editing, and DCShadow (lsadump::dcshadow) which registers a rogue DC and writes the attribute via replication to evade normal directory-change logging. Detection priorities: (1) DC Security 4765 (SID History added) and 4766 (failed attempt) - direct signals; (2) periodic enumeration of every account with non-empty sIDHistory, validating each against real migration records - on a single-domain forest sIDHistory should essentially be empty; (3) 4662 with DRSUAPI replication GUIDs from a non-DC for the DCShadow variant. Microsoft Defender for Identity detects both the injection and DCShadow natively and is the strongest single control if you have it. This requires DC-level audit logging (Directory Service Access auditing) to catch reliably - flag that as a prerequisite if it's not enabled.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "SID-History and golden-ticket-adjacent directory abuse documented in domain-dominance operations." },
          { cls: "apt-ru", name: "APT28", note: "Directory manipulation incl. SID-History injection in long-dwell intrusions." },
          { cls: "apt-mul", name: "Ransomware Operators", note: "SID-History injection used for stealthy DA-equivalent persistence pre-encryption." },
          { cls: "apt-cn", name: "APT41", note: "Domain privilege escalation via directory attribute abuse documented across operations." }
        ],
        cite: "MITRE ATT&CK T1134.005"
      }
    ]
  },
  {
    id: "T1546.008",
    name: "Event Triggered Execution: Accessibility Features",
    desc: "Adversaries replace or hijack Windows accessibility binaries (sethc.exe sticky keys, utilman.exe) or their IFEO debugger so an attacker-controlled SYSTEM shell launches from the logon screen.",
    rows: [
      {
        sub: "T1546.008 - Accessibility Binary Replace / IFEO Debugger (Sticky Keys, Utilman)",
        os: "win",
        indicator: "Replacement of sethc.exe/utilman.exe/osk.exe/Magnify.exe, or an IFEO Debugger value pointing them at cmd.exe - yielding a SYSTEM shell from the lock screen",
        sysmon: `// Variant A - binary replacement (EID 11)
EventID=11 (FileCreate)
TargetFilename matches:
  C:\\Windows\\System32\\sethc.exe
  OR *\\System32\\utilman.exe
  OR *\\System32\\osk.exe
  OR *\\System32\\Magnify.exe
  OR *\\System32\\Narrator.exe
  OR *\\System32\\DisplaySwitch.exe
  OR *\\System32\\AtBroker.exe
Image NOT TrustedInstaller.exe (System32 writes by
  anything else are highly suspicious)

// Variant B - IFEO Debugger hijack (EID 13)
EventID=13
TargetObject=*\\Image File Execution Options\\
  (sethc.exe|utilman.exe|osk.exe|Magnify.exe|
   Narrator.exe|DisplaySwitch.exe)\\Debugger
Details=*cmd.exe* OR *powershell* OR *\\Temp\\* etc.

// Variant C - the payoff (EID 1): the accessibility exe
// (or its Debugger) spawning a shell as SYSTEM, often
// parented by winlogon.exe at the logon desktop.
EventID=1
ParentImage=*\\winlogon.exe
Image=*\\cmd.exe OR *\\powershell.exe`,
        kibana: `// Accessibility binary written by non-TrustedInstaller
winlog.event_id: 11
AND file.path: (*\\System32\\sethc.exe OR *\\System32\\utilman.exe OR *\\System32\\osk.exe OR *\\System32\\Magnify.exe OR *\\System32\\Narrator.exe OR *\\System32\\DisplaySwitch.exe OR *\\System32\\AtBroker.exe)
AND NOT process.name: "TrustedInstaller.exe"

// IFEO Debugger set on an accessibility binary
winlog.event_id: 13
AND registry.path: (*\\Image File Execution Options\\sethc.exe\\Debugger OR *\\Image File Execution Options\\utilman.exe\\Debugger OR *\\Image File Execution Options\\osk.exe\\Debugger OR *\\Image File Execution Options\\Magnify.exe\\Debugger OR *\\Image File Execution Options\\Narrator.exe\\Debugger)

// winlogon.exe spawning a shell (lock-screen SYSTEM shell)
winlog.event_id: 1
AND process.parent.name: "winlogon.exe"
AND process.name: ("cmd.exe" OR "powershell.exe" OR "pwsh.exe")`,
        powershell: `# Accessibility binaries modified (compare hash to known-good)
$acc = 'sethc','utilman','osk','Magnify','Narrator','DisplaySwitch','AtBroker'
$acc | ForEach-Object {
  $p = "C:\\Windows\\System32\\$_.exe"
  if (Test-Path $p) {
    $sig = Get-AuthenticodeSignature $p
    [pscustomobject]@{ File=$_; Status=$sig.Status;
      Signer=$sig.SignerCertificate.Subject;
      Modified=(Get-Item $p).LastWriteTime }
  }
}  # Any non-Valid signature or recent LastWriteTime = suspect

# IFEO Debugger hijacks on accessibility binaries
$acc | ForEach-Object {
  $k = "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\$_.exe"
  $d = (Get-ItemProperty $k -Name Debugger -EA SilentlyContinue).Debugger
  if ($d) { [pscustomobject]@{ Binary="$_.exe"; Debugger=$d } }
}

# winlogon.exe spawning shells (Sysmon EID 1) - the payoff
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; ID=1
} | Where-Object {
  ($_.Properties[20].Value -match 'winlogon\\.exe') -and
  ($_.Properties[4].Value -match 'cmd\\.exe|powershell|pwsh')
} | Select TimeCreated,
  @{n='Image';e={($_.Properties[4].Value -split '\\\\')[-1]}},
  @{n='User';e={$_.Properties[12].Value}}`,
        registry: `Two mechanisms - one filesystem, one registry:

Variant A - binary replacement (filesystem):
C:\\Windows\\System32\\sethc.exe   (Sticky Keys, 5x Shift)
C:\\Windows\\System32\\utilman.exe  (Ease of Access, Win+U)
C:\\Windows\\System32\\osk.exe      (On-Screen Keyboard)
C:\\Windows\\System32\\Magnify.exe  (Magnifier)
C:\\Windows\\System32\\Narrator.exe
C:\\Windows\\System32\\DisplaySwitch.exe (Win+P)
C:\\Windows\\System32\\AtBroker.exe
  - Replace any with cmd.exe (or a payload). The
    accessibility hotkey at the LOGON SCREEN then launches
    it as SYSTEM (winlogon's context) - pre-authentication.
  - Requires defeating WRP/TrustedInstaller ownership
    (take-ownership + ACL change), which itself is a tell.

Variant B - IFEO Debugger (registry, cleaner):
HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\
  Image File Execution Options\\sethc.exe\\Debugger
  = C:\\Windows\\System32\\cmd.exe
  - When sethc.exe is invoked, Windows launches the
    Debugger value instead - so the hotkey opens cmd as
    SYSTEM without touching the protected binary.
  - Also applies to utilman.exe, osk.exe, etc.

Investigation pivots:
- Any accessibility binary with an invalid signature or a
  recent LastWriteTime = replacement
- ANY Debugger value under IFEO for an accessibility exe
  is essentially always malicious
- winlogon.exe -> cmd/powershell is the runtime payoff
  and is never legitimate`,
        tools: `Metasploit - sticky_keys persistence module
Built-in only (no special tooling needed):
  takeown /f sethc.exe + icacls grant + copy cmd.exe
  OR reg add the IFEO Debugger value
Empire / various persistence frameworks include it
Manual operators - extremely common in hands-on-keyboard
  intrusions and in physical/console-access scenarios
  (RDP login screen sticky-keys backdoor is a classic)`,
        ossdetect: `Sigma:
- file_event_win_creation_accessibility_binary.yml
- registry_set_ifeo_debugger_accessibility.yml
- process_creation_winlogon_susp_child_shell.yml
- process_creation_sticky_keys_backdoor.yml

Atomic Red Team:
- T1546.008 (accessibility features tests - sethc, utilman,
  IFEO debugger variants)

Hayabusa:
- StickyKeysBackdoor, IFEODebuggerAccessibility rules

Velociraptor:
- Windows.Detection.AccessibilityBackdoor
- Windows.Registry.IFEO

Sysinternals autoruns.exe:
- Surfaces IFEO Debugger entries and modified System32
  binaries in its IFEO / Image Hijacks tab`,
        notes: "The sticky-keys/utilman backdoor is a classic that endures because it grants a SYSTEM shell from the logon screen, before any user authenticates - which makes it both a privilege escalation and a brutally effective access backdoor (especially over RDP). Two mechanisms: replace the accessibility binary on disk (sethc.exe for 5x-Shift sticky keys, utilman.exe for Win+U ease-of-access) with cmd.exe, or - cleaner and more common now - set an IFEO Debugger value so invoking the accessibility binary launches cmd instead without touching the WRP-protected file. Either way, triggering the accessibility hotkey at the lock screen spawns the shell in winlogon's SYSTEM context. Detection is high-fidelity on all three legs: (1) any write to a System32 accessibility binary by something other than TrustedInstaller, or a signature/modified-time anomaly on those specific binaries; (2) ANY IFEO Debugger value on an accessibility exe (essentially never legitimate); (3) the runtime payoff - winlogon.exe spawning cmd/powershell, which is never normal. The IFEO Debugger leg overlaps mechanism with T1546.012 (IFEO injection) but the accessibility-binary targeting is the distinguishing escalation/backdoor pattern. A periodic signature check across the seven accessibility binaries plus an IFEO Debugger sweep catches the persistent installs; the winlogon-child-shell rule catches live use.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Sticky-keys / accessibility backdoors documented for SYSTEM access and re-entry." },
          { cls: "apt-ir", name: "APT33/APT34", note: "Accessibility-feature backdoors used in Iranian intrusion sets." },
          { cls: "apt-mul", name: "Hands-on-Keyboard Operators", note: "RDP sticky-keys backdoor is among the most common manual persistence/escalation tricks." },
          { cls: "apt-mul", name: "Ransomware Affiliates", note: "Accessibility backdoors used for resilient SYSTEM-level re-entry." }
        ],
        cite: "MITRE ATT&CK T1546.008"
      }
    ]
  },
  {
    id: "T1546.012",
    name: "Event Triggered Execution: Image File Execution Options Injection",
    desc: "Adversaries set an IFEO Debugger value or a GlobalFlag + SilentProcessExit monitor so that launching (or exiting) a target process triggers attacker code - frequently against high-privilege or frequently-run binaries.",
    rows: [
      {
        sub: "T1546.012 - IFEO Debugger & SilentProcessExit Monitor",
        os: "win",
        indicator: "A Debugger value under Image File Execution Options, or a MonitorProcess under SilentProcessExit, pointing a frequently-run or privileged process at attacker code",
        sysmon: `// Variant A - IFEO Debugger value (EID 13)
EventID=13
TargetObject=*\\Image File Execution Options\\
  <target.exe>\\Debugger
Details = a payload path / interpreter (not a real
  debugger like vsjitdebugger / windbg)

// Variant B - GlobalFlag + SilentProcessExit (EID 13)
EventID=13
TargetObject matches BOTH (as a pair):
  *\\Image File Execution Options\\<target.exe>\\GlobalFlag
    = 0x200 (FLG_MONITOR_SILENT_PROCESS_EXIT)
  *\\SilentProcessExit\\<target.exe>\\MonitorProcess
    = <payload>
  *\\SilentProcessExit\\<target.exe>\\ReportingMode = 1

// Payoff (EID 1): payload launched by the target's start
// or exit, often as the target's (possibly SYSTEM) context.`,
        kibana: `// IFEO Debugger set (excluding legit debuggers)
winlog.event_id: 13
AND registry.path: *\\Image File Execution Options\\*\\Debugger
AND NOT registry.data.strings: (*vsjitdebugger* OR *windbg* OR *vsdebugger* OR *DbgX*)

// SilentProcessExit monitor configured
winlog.event_id: 13
AND registry.path: (*\\SilentProcessExit\\*\\MonitorProcess OR *\\SilentProcessExit\\*\\ReportingMode)

// GlobalFlag enabling silent-exit monitoring
winlog.event_id: 13
AND registry.path: *\\Image File Execution Options\\*\\GlobalFlag
AND registry.data.strings: ("0x200" OR "512")`,
        powershell: `# Enumerate ALL IFEO Debugger values (review every one)
$ifeo='HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options'
Get-ChildItem $ifeo | ForEach-Object {
  $dbg=(Get-ItemProperty $_.PSPath -Name Debugger -EA SilentlyContinue).Debugger
  $gf =(Get-ItemProperty $_.PSPath -Name GlobalFlag -EA SilentlyContinue).GlobalFlag
  if ($dbg -or $gf) {
    [pscustomobject]@{ Target=$_.PSChildName; Debugger=$dbg; GlobalFlag=$gf }
  }
}  # Debugger not pointing at a real debugger = suspect

# SilentProcessExit monitors
$spe='HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit'
if (Test-Path $spe) {
  Get-ChildItem $spe | ForEach-Object {
    $mp=(Get-ItemProperty $_.PSPath -Name MonitorProcess -EA SilentlyContinue).MonitorProcess
    [pscustomobject]@{ Target=$_.PSChildName; Monitor=$mp }
  }
}

# Real-time IFEO/SilentProcessExit writes (Sysmon EID 13)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; ID=13
} | Where-Object {
  $_.Properties[4].Value -match 'Image File Execution Options\\\\.+\\\\(Debugger|GlobalFlag)|SilentProcessExit\\\\.+\\\\MonitorProcess'
} | Select TimeCreated,
  @{n='Target';e={$_.Properties[4].Value}},
  @{n='Value';e={$_.Properties[5].Value}}`,
        registry: `Two related IFEO-based mechanisms:

Variant A - Debugger hijack:
HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\
  Image File Execution Options\\<target.exe>\\Debugger
  = <payload>
  - Launching <target.exe> runs <payload> instead (with
    the original passed as an argument). Hijack a binary
    that runs as SYSTEM or runs frequently for escalation/
    persistence. Note WOW6432Node variant for 32-bit.

Variant B - SilentProcessExit (triggers on EXIT):
HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\
  Image File Execution Options\\<target.exe>\\
    GlobalFlag = 0x200 (FLG_MONITOR_SILENT_PROCESS_EXIT)
HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\
  SilentProcessExit\\<target.exe>\\
    ReportingMode = 1
    MonitorProcess = <payload>
  - When <target.exe> exits, WerFault launches
    <payload> - a stealthier, exit-triggered variant.

Legitimate Debugger values (allowlist):
- vsjitdebugger.exe, windbg.exe, vsdebugger, DbgX - real
  debuggers. Anything else under Debugger is suspect.

Investigation pivots:
- Enumerate every IFEO Debugger and SilentProcessExit
  MonitorProcess value; validate each target/payload
- A Debugger on a SYSTEM service binary or a common app
  (chrome, explorer, a login binary) = escalation/persist
- GlobalFlag 0x200 + a SilentProcessExit monitor is almost
  never legitimate outside developer/debugging setups`,
        tools: `Built-in (reg.exe / PowerShell) - no special tooling
  needed; both variants are a few registry writes
Metasploit - IFEO persistence modules
Empire / various frameworks - IFEO + SilentProcessExit
  persistence/escalation modules
SharPersist - IFEO persistence support
Manual operators - SilentProcessExit in particular is a
  favored stealthy variant in hands-on intrusions`,
        ossdetect: `Sigma:
- registry_set_ifeo_debugger_value.yml
- registry_set_silentprocessexit_monitor.yml
- registry_set_ifeo_globalflag_silent_exit.yml

Atomic Red Team:
- T1546.012 (IFEO injection - Debugger and
  GlobalFlag/SilentProcessExit tests)

Hayabusa:
- IFEODebuggerInjection, SilentProcessExitMonitor rules

Velociraptor:
- Windows.Registry.IFEO
- Windows.Detection.SilentProcessExit

Sysinternals autoruns.exe:
- Image Hijacks tab surfaces IFEO Debugger entries`,
        notes: "IFEO injection is a flexible trigger primitive used for both privilege escalation and persistence, and it shares mechanism with two other rows (the accessibility backdoor's IFEO variant and the run-key IFEO Debugger noted in persistence) - so this row focuses on the general technique and the stealthier SilentProcessExit variant. The Debugger value is the classic form: setting Image File Execution Options\\<target>\\Debugger = payload causes Windows to launch the payload whenever <target> runs, with the original as an argument. Point it at a SYSTEM service binary or a frequently-run app and you have escalation and/or persistence. The SilentProcessExit variant is sneakier and exit-triggered: GlobalFlag = 0x200 plus a SilentProcessExit\\<target>\\MonitorProcess value makes WerFault launch the payload when the target process exits - easy to miss because it fires on exit, not launch, and lives under a less-watched key. Detection is enumerable and high-fidelity: list every IFEO Debugger value and validate against the short allowlist of real debuggers (vsjitdebugger, windbg, vsdebugger); list every SilentProcessExit MonitorProcess (almost never legitimate); and watch Sysmon EID 13 writes to both key families in real time. Because both mechanisms are pure registry, a periodic sweep plus real-time EID 13 monitoring gives complete coverage. Beware the rare legitimate developer/debugging configuration as the only real FP source.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "IFEO Debugger injection documented for privileged execution and persistence." },
          { cls: "apt-ru", name: "Turla", note: "IFEO-based triggers used in stealthy long-dwell intrusions." },
          { cls: "apt-mul", name: "Red Team", note: "SilentProcessExit and IFEO Debugger are standard escalation/persistence tradecraft." },
          { cls: "apt-mul", name: "Commodity Malware", note: "IFEO Debugger hijacks used by various families for persistence and defense evasion." }
        ],
        cite: "MITRE ATT&CK T1546.012"
      }
    ]
  },
{
    id: "T1574.001",
    name: "Hijack Execution Flow: DLL Search Order Hijacking & Side-Loading (Privilege Escalation Angle)",
    desc: "Adversaries place a malicious DLL where a privileged or auto-elevated process will load it ahead of the legitimate one, inheriting that process's higher integrity or SYSTEM context. Distinct from the execution-framed T1129 coverage.",
    rows: [
      {
        sub: "T1574.001 - Search-Order Hijack into a Privileged / SYSTEM Process",
        os: "win",
        indicator: "An unsigned or user-written DLL loaded by a SYSTEM service, auto-elevated binary, or scheduled task running as SYSTEM - from a writable directory earlier in the search order than the real DLL",
        sysmon: `// The load itself (EID 7) into a privileged process:
EventID=7 (ImageLoad)
Image = a process running as SYSTEM / high integrity:
  *\\services.exe-spawned service exe
  OR an auto-elevating binary
  OR a scheduled-task host running as SYSTEM
ImageLoaded = a DLL in a writable / non-System32 path:
  *\\AppData\\* OR *\\Temp\\* OR *\\ProgramData\\*
  OR the application's own (user-writable) folder
Signed = false  OR  signature does not chain to MS/vendor

// The drop (EID 11) of the planted DLL just prior:
EventID=11 (FileCreate)
TargetFilename = *.dll in a directory that precedes the
  legitimate DLL location in the search order
Image = a non-installer (a user process planting a DLL
  next to a privileged binary is the tell)`,
        kibana: `// Unsigned/odd-path DLL loaded by a SYSTEM-context process
winlog.event_id: 7
AND dll.path: (*\\AppData\\* OR *\\Temp\\* OR *\\ProgramData\\* OR *\\Public\\* OR *\\Users\\*)
AND dll.code_signature.signed: false
AND NOT process.executable: (C\\:\\\\Windows\\\\System32\\\\* OR C\\:\\\\Windows\\\\SysWOW64\\\\*)

// DLL planted next to / ahead of a privileged binary (EID 11)
winlog.event_id: 11
AND file.path: *.dll
AND NOT process.name: ("msiexec.exe" OR "TrustedInstaller.exe" OR "*setup*.exe" OR "*update*.exe")
AND file.path: (*\\Program Files\\* OR *\\Program Files \\(x86\\)\\* OR C\\:\\\\Windows\\\\*)

// Phantom DLL: a process probing for a DLL that doesn't exist
// (best seen via Procmon NAME NOT FOUND, noted below)`,
        powershell: `# Unsigned DLLs loaded by SYSTEM-context processes (EID 7)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; ID=7
} | Where-Object {
  ($_.Properties[6].Value -eq 'false') -and
  ($_.Properties[4].Value -match 'AppData|\\\\Temp\\\\|\\\\ProgramData\\\\|\\\\Public\\\\|\\\\Users\\\\')
} | Select TimeCreated,
  @{n='Process';e={($_.Properties[3].Value -split '\\\\')[-1]}},
  @{n='DLL';e={$_.Properties[4].Value}},
  @{n='Signed';e={$_.Properties[6].Value}}

# DLLs planted in privileged program folders by non-installers (EID 11)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; ID=11
} | Where-Object {
  ($_.Properties[4].Value -match '\\.dll$') -and
  ($_.Properties[4].Value -match 'Program Files|System32|SysWOW64') -and
  ($_.Properties[5].Value -notmatch 'msiexec|TrustedInstaller|setup|update')
} | Select TimeCreated,
  @{n='DLL';e={$_.Properties[4].Value}},
  @{n='By';e={($_.Properties[5].Value -split '\\\\')[-1]}}

# Cross-ref: which privileged services/dirs are user-writable
# (the precondition) - PowerUp Get-ModifiablePath equivalent
Get-CimInstance Win32_Service |
  Where-Object { $_.StartName -match 'LocalSystem|SYSTEM' } |
  ForEach-Object {
    $dir = Split-Path (($_.PathName -replace '^"','' -split '"')[0])
    $acl = Get-Acl $dir -EA SilentlyContinue
    $w = $acl.Access | Where-Object {
      $_.IdentityReference -match 'Users|Everyone|Authenticated|INTERACTIVE' -and
      $_.FileSystemRights -match 'Write|Modify|FullControl' -and $_.AccessControlType -eq 'Allow'
    }
    if ($w) { [pscustomobject]@{ Service=$_.Name; WritableDir=$dir } }
  }`,
        registry: `No direct registry artifact - this is a DLL-load + file
weakness. The escalation comes from WHERE the DLL loads,
not a registry value. Relevant locations and concepts:

Windows DLL search order (simplified, safe-mode on):
1. The directory of the loading EXE
2. System32, then System (16-bit), then Windows dir
3. Current directory
4. PATH directories
   -> A writable directory appearing before the real DLL's
      location lets an attacker's DLL win the search.

Escalation preconditions:
- A privileged process (SYSTEM service / auto-elevated /
  SYSTEM scheduled task) loads a DLL by name (not full
  path), AND
- The attacker can write to a directory searched before
  the legitimate DLL (the EXE's own folder if writable,
  or a missing/'phantom' DLL the process probes for)

Phantom DLL hijack (a common variant):
- The privileged process tries to load a DLL that does
  NOT exist on the system (a known set of phantom DLLs).
- Attacker drops that DLL in a searched, writable path.
- Procmon 'NAME NOT FOUND' on a DLL load by a SYSTEM
  process reveals these targets.

Investigation pivots:
- Diff loaded-DLL signatures against vendor originals
- Hunt SYSTEM-context processes loading DLLs from
  user-writable paths (the highest-value single signal)
- Enumerate writable dirs of SYSTEM-service binaries`,
        tools: `PowerUp - Find-ProcessDLLHijack, Find-PathDLLHijack
SharpUp - DLL hijack opportunity detection
Robber / Spartacus / Koppeling - DLL-hijack discovery and
  proxy-DLL generation (Spartacus parses Procmon for
  NAME NOT FOUND phantom-DLL targets)
PE-sieve / Hollows-Hunter - confirm injected/proxy DLLs
Procmon (Sysinternals) - the classic way to find missing
  /phantom DLLs a privileged process probes for
Manual operators - proxy-DLL (DLL that forwards real
  exports + runs payload) is standard tradecraft`,
        ossdetect: `Sigma:
- image_load_susp_unsigned_dll_from_writable_path.yml
- image_load_dll_hijack_system_process.yml
- file_event_win_dll_dropped_in_system_dir.yml

Atomic Red Team:
- T1574.001 (DLL search-order hijack tests)
- T1574.002 (side-loading tests)

Hayabusa:
- DLLSearchOrderHijack, UnsignedDLLSystemProcess rules

Velociraptor:
- Windows.Detection.DLLHijack
- Windows.System.DLLs (loaded-module signature audit)

Sysinternals:
- Procmon (NAME NOT FOUND phantom-DLL discovery)
- sigcheck / autorunsc for unsigned loaded modules`,
        notes: "DLL search-order hijacking and side-loading appear in execution (T1129) framing already, so this row is deliberately the privilege-escalation angle: the hijack lands in a process that runs at higher integrity or as SYSTEM, so the attacker inherits that context. The escalation precondition is the combination of (a) a privileged process loading a DLL by name rather than full path, and (b) a directory searched before the legitimate DLL that the attacker can write to - most often the privileged EXE's own folder when it has weak ACLs, or a 'phantom' DLL the process probes for but that doesn't exist on the system. The single highest-value detection is a SYSTEM-context process loading an unsigned DLL from a user-writable path (AppData/Temp/ProgramData/a writable program folder) - that pattern is rarely legitimate and catches both classic and phantom hijacks. Pair the EID 7 load signal with the EID 11 drop (a non-installer writing a .dll into a privileged program folder or System dir). Proactive hunting mirrors the attacker's recon: enumerate writable directories of SYSTEM-service binaries (the precondition), and use Procmon/Spartacus to find phantom-DLL targets before an adversary does. Baseline legitimate side-loading-prone apps (some vendor software genuinely loads unsigned helper DLLs from their own folder) to control FPs. Confirmation is the same as injection - PE-sieve flags proxy/implanted DLLs.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "DLL search-order hijack and side-loading into trusted/privileged binaries is signature APT41 tradecraft." },
          { cls: "apt-cn", name: "APT10", note: "Heavy use of DLL side-loading via signed executables for privileged execution." },
          { cls: "apt-kp", name: "Lazarus", note: "Side-loading malicious DLLs through legitimate signed binaries documented widely." },
          { cls: "apt-mul", name: "PlugX / ShadowPad", note: "DLL side-loading is the core delivery mechanism for these widely-shared implants." }
        ],
        cite: "MITRE ATT&CK T1574.001"
      }
    ]
  },
  {
    id: "T1484.001",
    name: "Domain or Tenant Policy Modification",
    desc: "Adversaries modify Group Policy Objects or domain trust settings to push privileged execution, scheduled tasks, or immediate tasks to many hosts at once - a domain-wide privilege escalation and lateral primitive.",
    rows: [
      {
        sub: "T1484.001 - Group Policy Modification (GPO Abuse)",
        os: "win",
        indicator: "Modification of GPO files in SYSVOL (GptTmpl.inf, ScheduledTasks.xml, Groups.xml) or directory changes to gPCMachineExtensionNames - pushing tasks, scripts, or group membership to domain hosts",
        sysmon: `// On a DC / via SYSVOL share - file writes to GPO content:
EventID=11 (FileCreate / modify)
TargetFilename matches SYSVOL policy paths:
  *\\SYSVOL\\*\\Policies\\*\\Machine\\Microsoft\\
    Windows NT\\SecEdit\\GptTmpl.inf
  OR *\\Policies\\*\\Machine\\Preferences\\
    ScheduledTasks\\ScheduledTasks.xml
  OR *\\Policies\\*\\Machine\\Preferences\\Groups\\Groups.xml
  OR *\\Policies\\*\\Machine\\Scripts\\
    (Startup|Shutdown)\\*
Image NOT a normal GP management process on a DC

// Immediate Scheduled Task GPP (runs once, then deletes)
// leaves a ScheduledTasks.xml with <ImmediateTaskV2>.

// Directory-side: gPCMachineExtensionNames / versionNumber
// changes show via 5136 (see kibana).`,
        kibana: `// SYSVOL GPO content modification
winlog.event_id: 11
AND file.path: (*\\SYSVOL\\*\\Policies\\* )
AND file.name: ("GptTmpl.inf" OR "ScheduledTasks.xml" OR "Groups.xml" OR "Registry.xml" OR "*.ini")

// Directory Service change to a GPO object (DC, 4662/5136/5137)
winlog.event_id: 5136
AND winlog.event_data.AttributeLDAPDisplayName: ("gPCMachineExtensionNames" OR "gPCUserExtensionNames" OR "versionNumber")

// GPO created / deleted / linked (5137 / 5141 / 5139)
winlog.event_id: (5137 OR 5141 OR 5139)
AND winlog.event_data.ObjectClass: "groupPolicyContainer"`,
        powershell: `# SYSVOL GPP files modified recently (run on a DC or share)
$sysvol = "\\\\$env:USERDNSDOMAIN\\SYSVOL\\$env:USERDNSDOMAIN\\Policies"
Get-ChildItem $sysvol -Recurse -Include ScheduledTasks.xml,Groups.xml,GptTmpl.inf,*.ini -EA SilentlyContinue |
  Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } |
  Select FullName, LastWriteTime

# Directory Service changes to GPOs (Security 5136 on DC)
Get-WinEvent -FilterHashtable @{ LogName='Security'; ID=5136 } -MaxEvents 500 |
  Where-Object { $_.Message -match 'gPCMachineExtensionNames|versionNumber|groupPolicyContainer' } |
  Select TimeCreated,
    @{n='Actor';e={$_.Properties[3].Value}},
    @{n='Object';e={$_.Properties[8].Value}}

# Look for Immediate Task GPP (ran-once) artifacts
Get-ChildItem $sysvol -Recurse -Filter ScheduledTasks.xml -EA SilentlyContinue |
  ForEach-Object { if ((Get-Content $_.FullName -Raw) -match 'ImmediateTaskV2') { $_.FullName } }

# Review who can write GPOs / has linked-GPO edit rights
Get-GPO -All | ForEach-Object {
  [pscustomobject]@{ GPO=$_.DisplayName;
    Modified=$_.ModificationTime }
} | Sort-Object Modified -Descending | Select -First 20`,
        registry: `No local registry artifact at the source (the change is
in AD + SYSVOL). On TARGET hosts, applied GPO settings
land in the registry under Policies hives, but the
escalation artifact lives at the domain level:

SYSVOL GPO file artifacts (the payload):
\\<domain>\\SYSVOL\\<domain>\\Policies\\{GUID}\\Machine\\
  Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf
    - [Group Membership] section can add an attacker to
      local Administrators on every host the GPO applies to
  Preferences\\ScheduledTasks\\ScheduledTasks.xml
    - <ImmediateTaskV2> runs a command as SYSTEM on apply
  Preferences\\Groups\\Groups.xml
    - Restricted Groups / local group membership push
  Scripts\\Startup\\ - startup scripts run as SYSTEM

Directory object artifacts:
- groupPolicyContainer object versionNumber increments
- gPCMachineExtensionNames updated to register the new
  client-side extension (CSE) that will process the change

Why it's high-impact:
- One GPO edit can add the attacker to local admins, or
  run a SYSTEM task, on hundreds or thousands of hosts at
  the next policy refresh - domain-wide escalation + spread.

Investigation pivots:
- Audit who holds write/link rights on GPOs (often
  over-delegated); BloodHound maps GPO control edges
- Any ImmediateTaskV2 in a GPP is suspicious - it's a
  fire-once task pattern favored by attackers
- Correlate SYSVOL file changes with 5136 directory edits`,
        tools: `SharpGPOAbuse - the standard GPO-abuse tool (add local
  admin, add immediate task, add startup script, add
  user/computer rights)
PowerView - Get-DomainGPO, Get-DomainGPOLocalGroup,
  New-GPOImmediateTask
BloodHound - maps GPO control / edit / link edges
  (GpLink, WriteGPLink, GenericWrite on GPO objects)
Group Policy Management Console (legit tool, abused)
pyGPOAbuse - cross-platform GPO abuse
Manual operators - direct SYSVOL file edits + version bump`,
        ossdetect: `Sigma:
- file_event_win_gpo_scheduledtasks_xml_mod.yml
- file_event_win_gpo_groups_xml_mod.yml
- win_security_gpo_object_change_5136.yml
- win_security_immediate_scheduledtask_gpp.yml

Atomic Red Team:
- T1484.001 (GPO modification tests)

Hayabusa:
- GPOModification (5136), SYSVOLPolicyFileChange rules

Velociraptor:
- Windows.Detection.GPOAbuse
- Windows.Sysvol.GPP (SYSVOL policy-file enumeration)

Microsoft Defender for Identity:
- Detects suspicious GPO modifications and risky GPO
  delegation at the directory level`,
        notes: "GPO modification is one of the most powerful domain privilege-escalation primitives because a single edit propagates SYSTEM-level execution or local-admin membership to every host the GPO applies to, at the next policy refresh. The two artifact surfaces are SYSVOL (the policy files - GptTmpl.inf for group membership and user rights, ScheduledTasks.xml for tasks including the fire-once ImmediateTaskV2, Groups.xml for local group pushes, Scripts\\Startup for SYSTEM scripts) and the directory object (the groupPolicyContainer's versionNumber and gPCMachineExtensionNames, which must update for clients to process the change). Detection should cover both: file-modify events on SYSVOL policy files (EID 11 / file auditing), especially any ImmediateTaskV2 which is almost always malicious, and Security 5136 directory-change events on GPO objects and their extension-name attributes. The strongest proactive control is auditing GPO write/link delegation - it's frequently over-granted, and BloodHound maps exactly who can edit or link which GPOs (the WriteGPLink/GenericWrite-on-GPO edges that SharpGPOAbuse weaponizes). This needs SYSVOL file auditing and Directory Service Changes auditing enabled on DCs to catch reliably - flag that as a prerequisite. Defender for Identity detects this natively at the directory level and is the strongest single control if available. Note this requires existing GPO-edit rights, so it's typically post-initial-escalation domain dominance rather than a first-foothold technique.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "GPO abuse for domain-wide deployment of payloads and privileged tasks documented in major intrusions." },
          { cls: "apt-mul", name: "Ransomware Operators", note: "GPO modification (esp. immediate tasks / startup scripts) is a favored mass-deployment vector for encryptors." },
          { cls: "apt-ir", name: "APT34", note: "Group Policy abuse used for lateral movement and privileged execution across domains." },
          { cls: "apt-mul", name: "Red Team", note: "SharpGPOAbuse / PowerView GPO abuse is standard post-DA-rights tradecraft." }
        ],
        cite: "MITRE ATT&CK T1484.001"
      },
      {
        sub: "T1484.002 - Domain Trust Modification",
        os: "win",
        indicator: "Creation or modification of a domain/federation trust - new trusted domain object, or AD FS federation trust / token-signing changes - enabling forged cross-domain or cross-tenant authentication",
        sysmon: `// On-prem: trusted domain object creation/change (DC)
// Best seen via Security 4706/4707/5136 (see kibana).
// Host-side Sysmon signal is limited; watch for the tools:
EventID=1
Image=*\\netdom.exe CommandLine=*trust*
  OR *\\powershell.exe with New-ADTrust / nltest /domain_trusts
  OR AD FS / federation cmdlets:
    *Set-MsolDomainFederationSettings*
    OR *Update-MSOLFederatedDomain*
    OR *Set-AdfsRelyingPartyTrust*

// AD FS token-signing cert export (Golden SAML precursor)
// shows as access to the AD FS config DB / cert store on
// the ADFS server.`,
        kibana: `// Trusted domain object created / modified / removed (DC)
winlog.event_id: (4706 OR 4707 OR 4716 OR 4865 OR 4866 OR 4867)
// 4706 new trust, 4707 trust removed, 4716/4865-4867 trust info changed

// Directory change touching trustedDomain objects
winlog.event_id: 5136
AND winlog.event_data.ObjectClass: "trustedDomain"

// Federation trust / AD FS changes (cloud + ADFS hosts)
winlog.event_id: 1
AND process.command_line: (*Set-MsolDomainFederationSettings* OR *Update-MSOLFederatedDomain* OR *Set-AdfsRelyingPartyTrust* OR *Add-AdfsRelyingPartyTrust*)`,
        powershell: `# Trust changes on DC (Security 4706/4707/4716)
Get-WinEvent -FilterHashtable @{ LogName='Security'; ID=4706,4707,4716 } -MaxEvents 200 |
  Select TimeCreated, Id,
    @{n='Actor';e={$_.Properties[1].Value}},
    @{n='TrustTarget';e={$_.Properties[0].Value}}

# Enumerate current domain trusts (review for unexpected ones)
Get-ADTrust -Filter * |
  Select Name, Source, Target, Direction, TrustType, IntraForest

# Directory changes to trustedDomain objects (5136)
Get-WinEvent -FilterHashtable @{ LogName='Security'; ID=5136 } -MaxEvents 500 |
  Where-Object { $_.Message -match 'trustedDomain' } |
  Select TimeCreated, @{n='Actor';e={$_.Properties[3].Value}}

# Federation: review trusted realms / claims (ADFS host)
# Get-AdfsRelyingPartyTrust | Select Name, Identifier, Enabled
# Watch for new/modified relying-party trusts or altered
# token-signing certificates (Golden SAML enabler).`,
        registry: `No local registry artifact - trust objects live in AD;
federation config lives in the AD FS database / cloud
tenant. Authoritative artifacts:

On-prem AD trust artifacts:
- trustedDomain objects under
  CN=System,DC=<domain> - a new or modified TDO
- Trust attributes: trustDirection, trustType,
  trustAttributes (e.g. enabling SID-history across the
  trust by clearing quarantine / SID-filtering)
- Security events: 4706 (new trust), 4707 (removed),
  4716/4865/4866/4867 (trust info changed)

Federation (Golden SAML / cloud) artifacts:
- AD FS relying-party trust additions/changes
- Token-signing certificate export or replacement (the
  key enabler for forging SAML tokens = Golden SAML)
- Cloud: Set-MsolDomainFederationSettings altering the
  IssuerUri / signing cert for a federated domain

Why it's high-impact:
- Disabling SID filtering on a trust lets injected
  SID-history (see T1134.005) escalate ACROSS domains
- A forged federation trust / stolen token-signing cert
  lets an attacker mint authentication tokens for ANY
  user (incl. admins) - persistent, cross-tenant access

Investigation pivots:
- Enumerate all trusts; validate each is expected and has
  SID filtering / quarantine intact
- On ADFS: monitor token-signing cert lifecycle and
  relying-party trust changes closely
- Pairs with T1134.005 SID-History for cross-domain escal.`,
        tools: `netdom.exe / nltest - native trust enumeration/creation
PowerView - Get-DomainTrust, Get-ForestTrust
BloodHound - maps trust relationships and attack paths
  across domains
Mimikatz - lsadump for token-signing material; Golden
  SAML tooling (ADFSDump / AADInternals)
AADInternals - Azure AD / federation trust abuse toolkit
Set-MsolDomainFederationSettings (legit cmdlet, abused
  for Golden SAML federated-domain attacks)`,
        ossdetect: `Sigma:
- win_security_domain_trust_created_4706.yml
- win_security_trusted_domain_object_change_5136.yml
- proc_creation_win_federation_trust_modification.yml

Atomic Red Team:
- T1484.002 (domain trust modification tests)

Hayabusa:
- DomainTrustCreated (4706), TrustedDomainObjectChange rules

Velociraptor:
- Windows.AD.Trusts (enumerate + baseline trusts)

Microsoft Defender for Identity / Defender for Cloud Apps:
- Detect suspicious trust and federation changes,
  including Golden SAML indicators, at the identity layer`,
        notes: "Domain trust modification is the heavier, less-common sibling of GPO abuse and it's included to complete T1484 - it's a domain/forest/tenant-level escalation and persistence primitive rather than an endpoint technique. Two flavors. On-prem: creating or altering a trusted domain object, notably weakening SID filtering / quarantine on a trust so that injected SID-history (T1134.005) is honored across domains - turning a single-domain compromise into forest-wide rights. Federation: the Golden SAML family - stealing or replacing the AD FS token-signing certificate, or repointing a federated domain's settings (Set-MsolDomainFederationSettings), lets an attacker forge SAML tokens for arbitrary users including admins, granting persistent cross-tenant access that survives password resets and MFA. Detection is identity-layer-centric: Security 4706/4707/4716 for on-prem trust changes, 5136 directory changes on trustedDomain objects, and federation cmdlet execution (Set-MsolDomainFederationSettings, Set-AdfsRelyingPartyTrust) on ADFS/admin hosts. The strongest controls are monitoring the AD FS token-signing certificate lifecycle and enumerating/baselining all trusts with SID filtering intact. Microsoft Defender for Identity and Defender for Cloud Apps detect both on-prem trust abuse and Golden SAML natively. As with GPO abuse, this is post-escalation domain-dominance tradecraft and requires directory/federation auditing to catch - note that prerequisite. It pairs directly with the SID-History row for the cross-domain escalation chain.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Golden SAML / federation-trust abuse (token-signing cert theft) was central to the SolarWinds-era cloud persistence." },
          { cls: "apt-ru", name: "APT28", note: "Domain trust manipulation documented in forest-wide compromise operations." },
          { cls: "apt-cn", name: "APT41", note: "Trust relationship abuse for cross-domain movement documented across campaigns." },
          { cls: "apt-mul", name: "Red Team", note: "AADInternals / ADFSDump Golden SAML tradecraft for persistent cross-tenant access." }
        ],
        cite: "MITRE ATT&CK T1484.002"
      }
    ]
  },
  {
    id: "T1611",
    name: "Escape to Host",
    desc: "Adversaries break out of a container to the underlying host - via privileged containers, sensitive host mounts, exposed Docker sockets, or kernel exploits - gaining the host's far broader privilege context.",
    rows: [
      {
        sub: "T1611 - Container Breakout (Privileged Container / Host Mount / Docker Socket)",
        os: "win",
        indicator: "A containerized process accessing host resources it should not - the Docker/containerd socket, host filesystem mounts, /proc or kernel interfaces, or spawning with host namespaces",
        sysmon: `// Note: container-host visibility depends on Sysmon for
// Linux or host-level container runtime auditing. Windows
// containers map to host process/registry telemetry. Key
// host-side signals:

// Mounting or accessing the container runtime socket:
ProcessCreate / FileAccess where a container-origin
  process touches:
    /var/run/docker.sock  (Docker socket - full host RCE)
    /run/containerd/containerd.sock
    \\\\.\\pipe\\docker_engine (Windows)

// Host filesystem escape via a sensitive mount:
A container process writing to host paths via a mounted
  volume:
    /host/* , / (root mount), /etc, /root/.ssh,
    C:\\ProgramData\\Docker on Windows hosts

// Privileged-container / host-namespace launch:
container runtime spawning a container with --privileged,
  --pid=host, --net=host, or hostPath volume mounts
  (capture via runtime audit / k8s admission logs)`,
        kibana: `// Container runtime socket access (Docker/containerd)
process.command_line: (*docker.sock* OR *containerd.sock* OR *docker_engine*)
OR file.path: ("/var/run/docker.sock" OR "/run/containerd/containerd.sock")

// Sensitive host mounts / host-root access from a container
file.path: ("/host/*" OR "/etc/shadow" OR "/root/.ssh/*" OR "/proc/sys/kernel/*")
AND container.id: *

// Privileged container / host namespace (runtime + k8s audit)
// (field names vary by collector; examples below)
kubernetes.audit.requestObject.spec.containers.securityContext.privileged: true
OR kubernetes.audit.requestObject.spec.hostPID: true
OR kubernetes.audit.requestObject.spec.hostNetwork: true
OR kubernetes.audit.requestObject.spec.volumes.hostPath.path: "/"`,
        powershell: `# Windows containers: host-side process/registry telemetry
# (PowerShell hunts apply to Windows container hosts;
#  Linux container hosts use auditd / Sysmon-for-Linux.)

# Detect docker named-pipe access from container processes
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; ID=1
} | Where-Object {
  $_.Properties[10].Value -match 'docker_engine|\\\\pipe\\\\docker'
} | Select TimeCreated,
  @{n='Image';e={($_.Properties[4].Value -split '\\\\')[-1]}},
  @{n='CmdLine';e={$_.Properties[10].Value}}

# Enumerate running containers + flag privileged / host-mount
# (run on the container host)
# docker ps --quiet | ForEach-Object {
#   docker inspect $_ |
#     ConvertFrom-Json |
#     Select @{n='Name';e={$_.Name}},
#       @{n='Privileged';e={$_.HostConfig.Privileged}},
#       @{n='PidMode';e={$_.HostConfig.PidMode}},
#       @{n='Binds';e={$_.HostConfig.Binds}}
# } | Where-Object { $_.Privileged -or $_.PidMode -eq 'host' -or
#       ($_.Binds -match '^/:|:/host|docker.sock') }

# Linux hosts (auditd / Sysmon-for-Linux is the right tool):
# - auditctl -w /var/run/docker.sock -p rwa -k docker_sock
# - watch for nsenter / unshare / capsh from container PIDs`,
        registry: `Largely not a registry technique (containers are
filesystem/namespace/runtime constructs). Artifacts and
config to inspect depend on the runtime:

Container misconfigurations that enable escape:
- Privileged container (--privileged): grants nearly all
  host capabilities; the most common escape vector
- Host PID/IPC/Network namespace (--pid=host, --net=host)
- hostPath volume mounting / or a sensitive host dir
  (/, /etc, /root, /var/run/docker.sock)
- Exposed/mounted container runtime socket
  (/var/run/docker.sock) = trivial full host takeover:
  a container with the socket can create a new privileged
  container mounting host root
- Excessive Linux capabilities (CAP_SYS_ADMIN, CAP_SYS_PTRACE)
- Writable /proc or /sys interfaces

Kubernetes-specific:
- Pods with securityContext.privileged: true
- hostPID / hostNetwork / hostPath
- Over-permissive serviceaccount tokens mounted in pod

Investigation pivots:
- Inventory containers/pods for privileged flag, host
  namespaces, host mounts, and socket exposure (the
  preconditions) - most escapes are misconfig, not 0-day
- On the host, watch for container-origin processes
  touching the runtime socket or host filesystem
- nsenter / unshare / capsh / mount executed inside a
  container is a strong escape signal`,
        tools: `deepce - container enumeration + escape automation
CDK (Container DucK) - container pentest / escape toolkit
amicontained - capability/namespace enumeration
nsenter / unshare - native namespace manipulation used in
  socket-based escapes
kubeletctl / kube-hunter - Kubernetes attack tooling
Exploits for runc/containerd CVEs (e.g. CVE-2019-5736
  runc, CVE-2022-0492 cgroups) when misconfig isn't present
Manual operators - the docker.sock-mounted-in-container
  escape is a few commands and extremely common`,
        ossdetect: `Sigma (Linux / container rulesets):
- lnx_auditd_container_escape_nsenter.yml
- lnx_auditd_docker_socket_access.yml
- container_privileged_or_host_namespace.yml

Atomic Red Team:
- T1611 (escape to host tests - docker socket, privileged)

Falco (the de-facto container runtime detector):
- "Launch Privileged Container"
- "Container Run as Root"
- "Mount sensitive host path / docker.sock"
- "Terminal shell in container" + escape rules

Kubernetes:
- OPA Gatekeeper / Kyverno admission policies blocking
  privileged pods, hostPath, host namespaces
- Pod Security Standards (Restricted) enforcement

Tracee / Tetragon (eBPF) - syscall-level escape detection`,
        notes: "Escape to host completes the TA0004 set and is increasingly relevant as workloads containerize - though it's worth being upfront that this Windows-host kit's Sysmon/PowerShell/registry telemetry only partially covers it. Most container escapes are misconfiguration rather than exploit: a privileged container (--privileged), host namespace sharing (--pid/--net=host), a sensitive host filesystem mount, or - the big one - the container runtime socket (/var/run/docker.sock) mounted inside a container, which is trivial full host takeover since the container can then create a new privileged container mounting host root. The right telemetry for this lives at the container/runtime layer: Falco is the de-facto runtime detector (privileged container launch, docker.sock access, sensitive host mounts, in-container shells), eBPF tools (Tracee/Tetragon) catch the syscall-level escape, and Kubernetes admission control (OPA Gatekeeper/Kyverno, Pod Security Standards) blocks the misconfigurations outright. On a Windows container host, the docker named-pipe access pattern is visible in Sysmon EID 1; on Linux hosts, auditd/Sysmon-for-Linux watching the docker socket and for nsenter/unshare/capsh from container PIDs is the play. The highest-value defensive posture is preventative: inventory containers/pods for the privileged flag, host namespaces, host mounts, and socket exposure - those preconditions are enumerable and fixing them eliminates the overwhelming majority of escapes. I've included the host-side signals this kit can express and pointed clearly at the container-native tooling (Falco/eBPF/admission control) that owns the rest, rather than overstating what Sysmon alone covers here.",
        apt: [
          { cls: "apt-mul", name: "TeamTNT", note: "Cloud/container-focused crimeware; docker.sock and privileged-container escapes are core tradecraft." },
          { cls: "apt-mul", name: "Hildegard / Kinsing", note: "Container-targeting malware exploiting exposed Docker APIs and escaping to host." },
          { cls: "apt-cn", name: "APT-class cloud operators", note: "Container escape via misconfiguration and runc/containerd CVEs documented in cloud intrusions." },
          { cls: "apt-mul", name: "Cryptojacking Crews", note: "Privileged-container and docker-socket escapes widely used to pivot to host for resource hijacking." }
        ],
        cite: "MITRE ATT&CK T1611"
      },
      {
        sub: "T1611 - Privileged Container & Docker Socket Escape",
        os: "linux",
        indicator: "Container escape via --privileged flag, mounted docker.sock, host namespace sharing (--pid=host), or dangerous capabilities (CAP_SYS_ADMIN); detectable by host filesystem access from inside a container, nsenter into PID 1, or docker client activity originating from within a container",
        sysmon: `// Sysmon for Linux EID 1 - escape primitives from inside container

// nsenter into host PID 1 namespaces (classic privileged escape)
Image=*/nsenter AND CommandLine matches:
  *--target 1* OR *-t 1*
  AND (*--mount* OR *-m*) AND (*--pid* OR *-p*)

// Mounting host device / filesystem from inside container
Image=*/mount AND CommandLine matches:
  */dev/sd*  OR  */dev/nvme*  OR  */dev/vda*
  (privileged container can mount host block devices)

// Access to mounted docker socket from inside container
EventID=1
Image=*/docker  (docker client running INSIDE a container)
AND a unix socket /var/run/docker.sock is mounted in

// fdisk / lsblk enumerating host disks from container
Image=(*/fdisk OR */lsblk) inside container namespace

// chroot into mounted host root
Image=*/chroot AND CommandLine matches: */mnt* OR */host*

// Auditd
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/nsenter -k nsenter_exec
-a always,exit -F arch=b64 -S mount -k mount_call`,
        kibana: `// nsenter targeting host PID 1 (privileged container escape)
process.name: "nsenter"
AND process.command_line: ((*--target 1* OR *-t 1*) AND (*--mount* OR *--pid*))

// docker client running inside a container (mounted socket abuse)
process.name: "docker"
AND container.id: *
AND process.command_line: (*run* OR *exec* OR *-H unix*)

// Host block device mount from inside container
process.name: "mount"
AND container.id: *
AND process.command_line: (*/dev/sd* OR */dev/nvme* OR */dev/vda*)

// chroot to mounted host root inside container
process.name: "chroot"
AND container.id: *

// Shell whose namespace differs from container but matches host
// (escaped process now in host mount namespace)
process.name: ("bash" OR "sh")
AND process.parent.name: ("nsenter" OR "chroot")

// Auditd
event.module: "auditd"
AND tags: ("nsenter_exec" OR "mount_call")
AND container.id: *`,
        powershell: `#!/bin/bash
# T1611 - Privileged container / docker socket escape hunt
# Run on the HOST to inventory escape exposure.

echo "[*] === Running containers and their privilege posture ==="
docker ps -q 2>/dev/null | while read cid; do
  name=$(docker inspect --format '{{.Name}}' "$cid" 2>/dev/null)
  priv=$(docker inspect --format '{{.HostConfig.Privileged}}' "$cid" 2>/dev/null)
  pidmode=$(docker inspect --format '{{.HostConfig.PidMode}}' "$cid" 2>/dev/null)
  caps=$(docker inspect --format '{{.HostConfig.CapAdd}}' "$cid" 2>/dev/null)
  echo "$name | privileged=$priv | pidmode=$pidmode | capadd=$caps"
done

echo ""
echo "[*] === Containers with docker.sock mounted (socket escape) ==="
docker ps -q 2>/dev/null | while read cid; do
  mounts=$(docker inspect --format '{{range .Mounts}}{{.Source}} {{end}}' "$cid" 2>/dev/null)
  if echo "$mounts" | grep -q "docker.sock"; then
    echo "[FLAG] $(docker inspect --format '{{.Name}}' "$cid") mounts docker.sock"
  fi
  if echo "$mounts" | grep -qE "(^| )/( |$)"; then
    echo "[FLAG] $(docker inspect --format '{{.Name}}' "$cid") mounts host root /"
  fi
done

echo ""
echo "[*] === Containers sharing host namespaces ==="
docker ps -q 2>/dev/null | while read cid; do
  net=$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$cid" 2>/dev/null)
  ipc=$(docker inspect --format '{{.HostConfig.IpcMode}}' "$cid" 2>/dev/null)
  [ "$net" = "host" ] && echo "[FLAG] $(docker inspect --format '{{.Name}}' "$cid"): --net=host"
  [ "$ipc" = "host" ] && echo "[FLAG] $(docker inspect --format '{{.Name}}' "$cid"): --ipc=host"
done

echo ""
echo "[*] === nsenter / chroot escape events (auditd) ==="
ausearch -k nsenter_exec -i --start today 2>/dev/null | tail -20

echo ""
echo "[*] === In-container self-check (run INSIDE a container) ==="
echo "  Capabilities:"; capsh --print 2>/dev/null | grep -i "current\\|bounding" | head -3
echo "  docker.sock present:"; ls -la /var/run/docker.sock 2>/dev/null
echo "  Host devices visible:"; ls /dev/sd* /dev/nvme* /dev/vda* 2>/dev/null
echo "  /proc/1/cgroup (docker = container):"; cat /proc/1/cgroup 2>/dev/null | head -3`,
        registry: `Container escape primitives & artifacts:

Privileged container (--privileged):
  Grants ALL capabilities + device access. Escape is trivial:
    mount host disk → chroot, OR nsenter --target 1
  Check: docker inspect → .HostConfig.Privileged = true

Mounted docker socket (/var/run/docker.sock):
  Container can control the host Docker daemon:
    docker -H unix:///var/run/docker.sock run -v /:/host ...
  Spawns a new privileged container mounting host root.
  Check: docker inspect → .Mounts contains docker.sock

Host namespace sharing:
  --pid=host    : see + nsenter host processes
  --net=host    : host network stack access
  --ipc=host    : host shared memory
  Check: .HostConfig.PidMode/NetworkMode/IpcMode = "host"

Dangerous capabilities (without full --privileged):
  CAP_SYS_ADMIN  : mount, many escape paths
  CAP_SYS_PTRACE : ptrace host processes (with pid=host)
  CAP_SYS_MODULE : load kernel module → full host control
  CAP_DAC_READ_SEARCH : read any host file (Shocker attack)
  Check: capsh --print  (from inside container)

Host filesystem mounts:
  -v /:/host  or  -v /etc:/etc  etc.
  Check: .Mounts with Source = / or sensitive host paths

In-container indicators:
  /proc/1/cgroup            - shows docker/containerd = in container
  /.dockerenv               - presence = Docker container
  ls /dev/sd* /dev/nvme*    - host block devices visible = privileged
  capsh --print             - CAP_SYS_ADMIN = escape-capable

Escape execution artifacts (host-side):
  nsenter --target 1 --mount --pid --net  (enter host ns)
  mount /dev/sda1 /mnt && chroot /mnt
  New container spawned via mounted docker.sock`,
        tools: `Container escape techniques & tooling:

Privileged container escape (most common):
  --privileged grants device access; mount host disk:
    fdisk -l ; mount /dev/sda1 /mnt ; chroot /mnt
  Or enter host namespaces: nsenter -t 1 -m -p -n bash
  This is the #1 misconfiguration exploited in the wild.

Docker socket escape:
  Mounted /var/run/docker.sock = host root equivalent.
  Attacker runs a new container mounting / with full caps.
  Extremely common in CI/CD containers and dev setups.

CAP_SYS_ADMIN / capability escapes:
  Even without --privileged, CAP_SYS_ADMIN enables mounting
  and cgroup release_agent escape (see companion row).
  CAP_DAC_READ_SEARCH → Shocker attack (open_by_handle_at).

Tooling:
  deepce      - container enumeration + escape automation
  CDK         - container penetration toolkit
  amicontained- enumerate capabilities/namespaces
  BOtB        - break out the box; automated escape checks
  Peirates    - Kubernetes-focused escape/lateral tool

Threat actor use:
  TeamTNT     - automated docker.sock + privileged escape
                in cloud cryptojacking campaigns
  Kinsing     - exposed docker API + escape to host
  Hildegard   - Kubernetes/container escape for mining
  Siloscape   - container escape (Windows containers)

Detection-relevant fact:
  Escape itself (nsenter/mount/chroot) is observable on the
  HOST if the host PID namespace sees container processes,
  or via Falco runtime rules watching container syscalls.`,
        ossdetect: `Sigma rules:
- proc_creation_lnx_nsenter_container_escape.yml
- proc_creation_lnx_docker_socket_abuse.yml
- proc_creation_lnx_privileged_container_mount.yml

Falco (best-in-class for this technique):
  rule: Launch Privileged Container
  rule: Launch Sensitive Mount Container
  rule: Change thread namespace (nsenter escape)
  rule: Mount Launched in Privileged Container
  rule: Container Drift Detected (new executable in container)
  Falco is the primary runtime control for container escape.

Elastic detection rules:
- Container Escape via nsenter
- Sensitive Host Path Mounted in Container
- Privileged Docker Container Created

Kubernetes:
  Pod Security Admission / Pod Security Standards:
    block privileged, hostPID, hostNetwork, hostPath mounts
  OPA Gatekeeper / Kyverno policies to deny escape-enabling specs
  Falco + Sysdig for runtime container escape detection

Hardening / prevention (primary controls):
  - Never run --privileged in production
  - Never mount docker.sock into containers
  - Drop ALL capabilities, add back only what's needed
  - Use rootless Docker / user namespace remapping
  - gVisor or Kata Containers for stronger isolation
  - seccomp + AppArmor/SELinux profiles on containers

docker bench security:
  Automated CIS Docker benchmark; flags privileged
  containers, socket mounts, dangerous capabilities.`,
        notes: "Privileged containers and mounted Docker sockets are the two most exploited container escape paths, and both are misconfigurations rather than vulnerabilities - meaning they are entirely preventable but extremely common in real environments, especially CI/CD pipelines and developer setups. A --privileged container can escape to host root in a single command by mounting the host disk and chrooting into it, or by using nsenter to enter PID 1's namespaces. A mounted /var/run/docker.sock is functionally equivalent to giving the container host root, because the container can instruct the host Docker daemon to spawn a new container mounting the entire host filesystem. The detection strategy operates at two levels: posture (inventory containers for --privileged, socket mounts, host namespace sharing, and dangerous capabilities like CAP_SYS_ADMIN - this is a configuration audit) and runtime (Falco is the definitive tool, with built-in rules for privileged container launch, sensitive mount detection, namespace changes via nsenter, and container drift). From the host side, if the host PID namespace can see container processes, the escape commands (nsenter --target 1, mount of host devices, chroot to mounted root) are directly observable. The strongest controls are preventive: Kubernetes Pod Security Standards or OPA/Kyverno policies that simply refuse to schedule escape-enabling pod specs.",
        apt: [
          { cls: "apt-mul", name: "TeamTNT", note: "Automated docker.sock and privileged-container escape to host in large-scale cloud cryptojacking operations." },
          { cls: "apt-mul", name: "Kinsing", note: "Exploits exposed Docker API and escapes privileged containers to deploy miners on the host." },
          { cls: "apt-mul", name: "Hildegard / TeamTNT", note: "Kubernetes and container escape chains for resource hijacking documented across cloud campaigns." }
        ],
        cite: "MITRE ATT&CK T1611"
      },
      {
        sub: "T1611 - runc / cgroups release_agent Escape (CVE-2019-5736)",
        os: "linux",
        indicator: "Container-to-host escape via overwriting the runc binary (CVE-2019-5736) when entering a container, or via the cgroups v1 release_agent mechanism in a CAP_SYS_ADMIN container; detectable by modification of the host runc binary or release_agent writes from a container context",
        sysmon: `// CVE-2019-5736: malicious container overwrites host /usr/bin/runc
// when an admin runs docker exec into it. Watch for runc binary
// modification - it should NEVER change outside a package update.
EventID=11 (FileModify)
TargetFilename matches:
  /usr/bin/runc  /usr/sbin/runc
  /usr/bin/docker-runc
  /var/run/docker/runtime-runc/*
AND NOT modified by package manager (dpkg/rpm/yum/dnf)

// cgroups release_agent escape (CAP_SYS_ADMIN container):
// attacker mounts cgroup, writes a release_agent path, and
// triggers it to execute a payload as root on the HOST.
EventID=11 (FileModify)
TargetFilename matches:
  */sys/fs/cgroup/*/release_agent
  */sys/fs/cgroup/*/notify_on_release

// Mount of cgroup filesystem from inside a container
Image=*/mount AND CommandLine matches:
  *-t cgroup*  OR  *cgroup*release_agent*

// Auditd
-w /usr/bin/runc -p wa -k runc_modify
-a always,exit -F arch=b64 -S mount -F fstype=cgroup -k cgroup_mount`,
        kibana: `// runc binary modification - critical, near-zero legit cases
event.module: "file_integrity"
AND file.path: ("/usr/bin/runc" OR "/usr/sbin/runc" OR "/usr/bin/docker-runc")
AND NOT process.name: ("dpkg" OR "rpm" OR "apt" OR "yum" OR "dnf")

// cgroups release_agent write (escape primitive)
event.module: "file_integrity"
AND file.path: (*release_agent OR *notify_on_release)

// cgroup mount from inside a container
process.name: "mount"
AND container.id: *
AND process.command_line: (*cgroup* OR *release_agent*)

// Auditd keys
event.module: "auditd"
AND tags: ("runc_modify" OR "cgroup_mount")

// Host process spawned by release_agent trigger
// (payload runs as root with empty/unusual parent)
user.id: "0"
AND process.parent.pid: "1"
AND process.name: ("sh" OR "bash")
AND process.command_line: (*/tmp/* OR */cmd* OR *cgroup*)`,
        powershell: `#!/bin/bash
# T1611 - runc / cgroups release_agent escape hunt (run on HOST)

echo "[*] === runc binary integrity (CVE-2019-5736) ==="
for r in /usr/bin/runc /usr/sbin/runc /usr/bin/docker-runc; do
  [ -e "$r" ] || continue
  echo "$r | mtime: $(stat -c '%y' "$r") | $(sha256sum "$r" | cut -d' ' -f1)"
  echo "  package: $(dpkg -S "$r" 2>/dev/null || rpm -qf "$r" 2>/dev/null || echo NOT FROM PACKAGE)"
done
echo "  runc version: $(runc --version 2>/dev/null | head -1)"
echo "  (CVE-2019-5736 fixed in runc 1.0-rc7+ / docker 18.09.2+)"

echo ""
echo "[*] === Package verification of runc ==="
dpkg --verify runc 2>/dev/null | grep runc
rpm -V runc 2>/dev/null
rpm -V containerd.io 2>/dev/null | grep runc

echo ""
echo "[*] === cgroups release_agent contents (should be empty/default) ==="
find /sys/fs/cgroup -name release_agent 2>/dev/null | while read f; do
  content=$(cat "$f" 2>/dev/null)
  if [ -n "$content" ]; then
    echo "[FLAG] $f = $content"
  fi
done

echo ""
echo "[*] === auditd: runc modification + cgroup mount events ==="
ausearch -k runc_modify -i --start today 2>/dev/null | tail -20
ausearch -k cgroup_mount -i --start today 2>/dev/null | tail -20

echo ""
echo "[*] === Containers with CAP_SYS_ADMIN (release_agent precondition) ==="
docker ps -q 2>/dev/null | while read cid; do
  caps=$(docker inspect --format '{{.HostConfig.CapAdd}}' "$cid" 2>/dev/null)
  priv=$(docker inspect --format '{{.HostConfig.Privileged}}' "$cid" 2>/dev/null)
  if echo "$caps" | grep -qi "SYS_ADMIN" || [ "$priv" = "true" ]; then
    echo "[FLAG] $(docker inspect --format '{{.Name}}' "$cid"): caps=$caps privileged=$priv"
  fi
done`,
        registry: `runc / cgroups escape artifacts:

CVE-2019-5736 (runc overwrite):
  Vulnerable: runc < 1.0-rc7, Docker < 18.09.2
  Mechanism: malicious container image causes the host
    runc binary to be overwritten when an operator runs
    docker exec / attach into the container. Next runc
    use executes attacker code as root on the host.
  Artifact: /usr/bin/runc modified outside a package update
    (hash/mtime change is the definitive indicator)
  Targets: /usr/bin/runc, /usr/sbin/runc, docker-runc

cgroups v1 release_agent escape:
  Precondition: container with CAP_SYS_ADMIN (or privileged)
  Mechanism:
    1. mount -t cgroup -o rdma cgroup /tmp/cgrp
    2. echo 1 > /tmp/cgrp/x/notify_on_release
    3. echo "/path/to/payload" > /tmp/cgrp/release_agent
    4. trigger empty cgroup → kernel runs payload as ROOT on host
  Artifact: release_agent file containing a host path;
    notify_on_release set to 1; cgroup mount from container

cgroups v2:
  release_agent removed; this specific escape does not apply.
  Check: stat -fc %T /sys/fs/cgroup  (cgroup2fs = v2)

Detection priority:
  runc binary integrity monitoring (rpm -V / AIDE) - critical
  release_agent file monitoring across /sys/fs/cgroup
  Inventory containers with CAP_SYS_ADMIN / privileged

Related runtime CVEs to track:
  CVE-2022-0811 (CRI-O cgroup kernel param)
  CVE-2024-21626 (runc leaked fd / WORKDIR escape)`,
        tools: `runc / cgroups escape in the wild:

CVE-2019-5736 (runc):
  Disclosed Feb 2019. High-impact: overwrites host runc.
  Public PoCs immediately available. Requires an operator
  to exec into a malicious container, or attacker control
  of a container image + the ability to get it run.
  Notable because it turns "docker exec into a container"
  into host compromise.

CVE-2024-21626 (runc, "Leaky Vessels"):
  Jan 2024. WORKDIR / leaked file descriptor escape.
  Allows container build/run to access host filesystem.
  Public exploits; affects many runc versions.

cgroups release_agent escape:
  Not a CVE - a feature abuse requiring CAP_SYS_ADMIN.
  Widely documented (Felix Wilhelm PoC is canonical).
  Works on any cgroups v1 host where a container has
  CAP_SYS_ADMIN. The classic "one-liner container escape."

Tooling:
  CDK, deepce, BOtB all automate release_agent escape
  and check for runc-version vulnerability.

Threat actor relevance:
  These are higher-skill escapes than privileged/socket
  misconfig, but the cgroups release_agent technique is
  simple enough that it appears in commodity container
  attack toolkits. CVE-2024-21626 saw rapid weaponization.

Why runc integrity matters:
  The runc binary is the single most security-critical
  file in a container host. Any change to it outside a
  controlled package update is a critical incident.`,
        ossdetect: `Sigma rules:
- file_event_lnx_runc_binary_overwrite_cve_2019_5736.yml
- file_event_lnx_cgroup_release_agent_write.yml
- proc_creation_lnx_cgroup_mount_container_escape.yml

Falco (built-in runtime detection):
  rule: Modify container entrypoint / runc binary
  rule: Write below /sys/fs/cgroup (release_agent abuse)
  rule: Detect release_agent File Container Escapes
  (Falco ships a dedicated release_agent escape rule)

Elastic detection rules:
- runc Binary Overwrite (CVE-2019-5736)
- cgroups release_agent Container Escape

File integrity (critical control):
  AIDE/Tripwire/Wazuh: monitor /usr/bin/runc with sha256
  Any change = critical, page immediately
  rpm -V runc / dpkg --verify runc in scheduled checks

Auditd:
  -w /usr/bin/runc -p wa -k runc_modify
  -a always,exit -F arch=b64 -S mount -F fstype=cgroup -k cgroup_mount
  ausearch -k runc_modify | grep -v "comm=\\"dpkg\\"\\|comm=\\"rpm\\""

Patch verification (primary defense):
  runc --version  (need >= 1.1.12 for CVE-2024-21626)
  docker --version (>= 18.09.2 for CVE-2019-5736)

Prevention:
  - Drop CAP_SYS_ADMIN from all containers (blocks release_agent)
  - Use cgroups v2 (release_agent removed entirely)
  - Read-only host runc via immutable bit / verified boot
  - gVisor / Kata for runtime isolation`,
        notes: "The runc binary overwrite (CVE-2019-5736) and the cgroups release_agent escape represent the more sophisticated tier of container escape, beyond simple privileged/socket misconfiguration. CVE-2019-5736 is notable because it weaponizes a routine administrative action: when an operator runs docker exec into a malicious container, the container overwrites the host's runc binary, and the next invocation of runc executes attacker code as root on the host. This makes runc binary integrity the single most critical file-monitoring target on any container host - the runc binary should never change except during a controlled package update, so any modification is a critical incident warranting immediate response. The cgroups v1 release_agent escape is not a CVE but a feature abuse: a container with CAP_SYS_ADMIN can mount a cgroup hierarchy, set a release_agent path pointing to an attacker payload, and trigger it to execute as root on the host when a cgroup empties. The two preventive controls that eliminate this entire class are dropping CAP_SYS_ADMIN from containers (which removes the release_agent precondition) and migrating to cgroups v2, which removed the release_agent mechanism entirely. For detection, Falco ships a dedicated release_agent escape rule, and file integrity monitoring on /usr/bin/runc with SHA-256 is the essential complement. Track CVE-2024-21626 (Leaky Vessels) as the modern runc escape requiring updated patching.",
        apt: [
          { cls: "apt-mul", name: "Container-escape operators", note: "CVE-2019-5736 runc overwrite and release_agent escapes appear in commodity container attack toolkits (CDK, deepce, BOtB)." },
          { cls: "apt-mul", name: "Cryptojacking crews", note: "Container escapes chained to host access for persistent miner deployment in cloud environments." },
          { cls: "apt-mul", name: "Leaky Vessels exploiters", note: "CVE-2024-21626 runc escape saw rapid weaponization in 2024 against container build and runtime environments." }
        ],
        cite: "MITRE ATT&CK T1611"
      }
    ]
  },
  {
    id: "T1098",
    name: "Account Manipulation (Privilege Escalation Angle)",
    desc: "Adversaries grant an account they control elevated rights - adding it to a privileged group, assigning dangerous user-rights/privileges, or attaching directory ACLs/AdminSDHolder - to escalate. Distinct from the persistence-framed coverage.",
    rows: [
      {
        sub: "T1098 - Privileged Group Add / Rights Assignment / AdminSDHolder",
        os: "win",
        indicator: "An account added to a privileged group (Domain/Enterprise/Schema Admins, local Administrators), granted a dangerous privilege/user-right, or given control via an AdminSDHolder or directory ACL change",
        sysmon: `// Local Administrators add (host) - net/PowerShell:
EventID=1
Image=*\\net.exe OR *\\net1.exe
CommandLine=*localgroup* *administrators* *\\/add*
  OR *\\powershell.exe with Add-LocalGroupMember
     -Group Administrators
  OR *\\powershell.exe Add-ADGroupMember to a privileged
     domain group

// Privilege/user-right assignment (SeDebug, SeBackup,
// SeTakeOwnership, SeImpersonate, SeLoadDriver) - often
// via secedit/ntrights or a GPO (see T1484.001).

// Primary detection is the Security log (4728/4732/4756/
// 4704/5136) - see kibana. Sysmon corroborates the tool.`,
        kibana: `// Member added to a security-enabled GLOBAL group (4728)
// LOCAL group (4732), UNIVERSAL group (4756) - privileged
winlog.event_id: (4728 OR 4732 OR 4756)
AND winlog.event_data.TargetUserName: (*Admins* OR "Administrators" OR "Backup Operators" OR "Account Operators" OR "Server Operators" OR "Print Operators" OR "DnsAdmins" OR "Remote Desktop Users")

// User-right assigned (4704) - dangerous privileges
winlog.event_id: 4704
AND winlog.event_data.PrivilegeList: (*SeDebugPrivilege* OR *SeTakeOwnershipPrivilege* OR *SeBackupPrivilege* OR *SeLoadDriverPrivilege* OR *SeImpersonatePrivilege* OR *SeTcbPrivilege*)

// Directory ACL / AdminSDHolder change (5136 on a DC)
winlog.event_id: 5136
AND (winlog.event_data.ObjectDN: *CN=AdminSDHolder* OR winlog.event_data.AttributeLDAPDisplayName: "nTSecurityDescriptor")`,
        powershell: `# Privileged group membership changes (Security 4728/4732/4756)
Get-WinEvent -FilterHashtable @{ LogName='Security'; ID=4728,4732,4756 } -MaxEvents 500 |
  Select TimeCreated, Id,
    @{n='Group';e={$_.Properties[2].Value}},
    @{n='MemberAdded';e={$_.Properties[0].Value}},
    @{n='By';e={$_.Properties[6].Value}} |
  Where-Object { $_.Group -match 'Admin|Operators|DnsAdmins|Remote Desktop' }

# Dangerous user-right assignments (4704)
Get-WinEvent -FilterHashtable @{ LogName='Security'; ID=4704 } -MaxEvents 200 |
  Where-Object { $_.Message -match 'SeDebug|SeTakeOwnership|SeBackup|SeLoadDriver|SeImpersonate|SeTcb' } |
  Select TimeCreated, @{n='Detail';e={$_.Message.Split(\"\`n\")[0]}}

# AdminSDHolder ACL changes (5136 on DC) - stealthy persistence/escal
Get-WinEvent -FilterHashtable @{ LogName='Security'; ID=5136 } -MaxEvents 500 |
  Where-Object { $_.Message -match 'AdminSDHolder|nTSecurityDescriptor' } |
  Select TimeCreated, @{n='Actor';e={$_.Properties[3].Value}}

# Current membership of the crown-jewel groups (review/baseline)
'Domain Admins','Enterprise Admins','Schema Admins','Administrators' | ForEach-Object {
  try { Get-ADGroupMember $_ -EA Stop | Select @{n='Group';e={$_}}, SamAccountName }
  catch { Get-LocalGroupMember Administrators | Select Name }
}`,
        registry: `Local rights/privileges are stored in the LSA policy
(not a normal registry hive you browse); domain group
membership and ACLs live in AD. Key artifacts:

Privileged groups (membership add = escalation):
- Domain Admins (RID 512), Enterprise Admins (519),
  Schema Admins (518), Administrators (544 local/builtin),
  Backup/Account/Server/Print Operators, DnsAdmins
  (DnsAdmins -> SYSTEM via ServerLevelPluginDll), Remote
  Desktop Users
- Security events: 4728 (global group add), 4732 (local
  group add), 4756 (universal group add)

Dangerous user-rights / privileges (4704 assignment):
- SeDebugPrivilege (access any process -> SYSTEM)
- SeTakeOwnershipPrivilege, SeBackup/SeRestorePrivilege
- SeLoadDriverPrivilege (load a driver -> BYOVD/kernel)
- SeImpersonatePrivilege (Potato -> SYSTEM)
- SeTcbPrivilege (act as part of the OS)

AdminSDHolder / SDProp:
- CN=AdminSDHolder,CN=System,DC=<domain> - its ACL is
  stamped onto all protected (admin) accounts hourly by
  SDProp. An attacker who adds an ACE here gains durable
  control over every privileged account = escalation +
  stealthy persistence.
- nTSecurityDescriptor changes on privileged objects

Investigation pivots:
- Baseline and alert on ANY change to crown-jewel group
  membership and to AdminSDHolder's ACL
- DnsAdmins membership is an under-watched DA-equivalent
- Review who can write to privileged group objects
  (BloodHound AddMember / WriteDACL edges)`,
        tools: `net.exe / net1.exe localgroup ... /add (native)
Add-LocalGroupMember / Add-ADGroupMember (PowerShell)
PowerView - Add-DomainGroupMember, Add-DomainObjectAcl,
  Set-DomainObject (AdminSDHolder / ACL abuse)
BloodHound - maps AddMember, WriteDACL, GenericAll,
  AddSelf edges to privileged groups and AdminSDHolder
Mimikatz - privilege::debug etc. (uses the rights)
ntrights.exe / secedit / SharpGPOAbuse (rights via GPO)
DnsAdmins -> SYSTEM: dnscmd /config serverlevelplugindll`,
        ossdetect: `Sigma:
- win_security_add_to_privileged_group_4728_4732.yml
- win_security_user_right_assignment_4704_dangerous.yml
- win_security_adminsdholder_acl_change.yml
- win_security_dnsadmins_member_added.yml

Atomic Red Team:
- T1098 (account manipulation tests)
- T1098.007 (additional local/cloud group variants)

Hayabusa:
- PrivilegedGroupAdd (4728/4732/4756), DangerousPrivilege
  Assignment, AdminSDHolderChange rules

Velociraptor:
- Windows.AD.PrivilegedGroups (membership baseline/diff)
- Windows.Detection.AdminSDHolder

Microsoft Defender for Identity:
- Detects suspicious privileged group additions and
  AdminSDHolder manipulation at the directory level`,
        notes: "Account Manipulation appears in the persistence file (group changes / password resets framed as maintaining access), so this row is the privilege-escalation angle: granting an attacker-controlled account elevated rights to climb. Three mechanisms share the row. First, privileged group membership - adding the account to Domain/Enterprise/Schema Admins, local Administrators, or the under-watched DA-equivalents (DnsAdmins, which reaches SYSTEM via a malicious ServerLevelPluginDll; Backup/Account/Server Operators) - detected by Security 4728/4732/4756. Second, dangerous user-right/privilege assignment - SeDebug (own any process -> SYSTEM), SeImpersonate (Potato -> SYSTEM), SeLoadDriver (BYOVD -> kernel), SeBackup/Restore, SeTakeOwnership - via 4704, often pushed through a GPO (ties to T1484.001). Third, AdminSDHolder/SDProp abuse - adding an ACE to CN=AdminSDHolder propagates control over every protected admin account hourly, a durable escalation-and-persistence combo, visible as a 5136 nTSecurityDescriptor change. Lead detection with crown-jewel group-membership monitoring and AdminSDHolder ACL change alerts - both are low-volume and extremely high-fidelity. BloodHound maps the AddMember/WriteDACL/GenericAll edges attackers use to perform these. This needs Security audit policy for group membership and Directory Service Changes enabled on DCs; Defender for Identity detects the group adds and AdminSDHolder manipulation natively. The line vs persistence is intent: here the account-rights change is the escalation step itself, not just a way back in.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Privileged group additions and AdminSDHolder abuse documented in domain-dominance operations." },
          { cls: "apt-cn", name: "APT41", note: "Account rights manipulation incl. DnsAdmins and privileged group abuse for escalation." },
          { cls: "apt-mul", name: "Ransomware Operators", note: "Adding controlled accounts to Domain Admins is a near-universal pre-encryption step." },
          { cls: "apt-mul", name: "Red Team", note: "PowerView/BloodHound ACL and group-membership abuse is core escalation tradecraft." }
        ],
        cite: "MITRE ATT&CK T1098"
      }
    ]
  },
  {
    id: "T1548.001",
    name: "Abuse Elevation Control Mechanism: Setuid and Setgid",
    desc: "SUID/SGID binary abuse and Linux capabilities for privilege escalation - GTFOBins shell-spawning via SUID binaries, attacker-planted SUID root shells, and capability abuse (cap_setuid, cap_dac_override, cap_sys_admin) invisible to standard SUID checks",
    rows: [
      {
        sub: "T1548.001 - SUID/SGID Binary Abuse and GTFOBins Escalation",
        os: "linux",
        indicator: "Execution of a SUID/SGID binary that yields elevated privileges - either a custom/non-package SUID binary, or a standard GTFOBins-listed binary (find, awk, vim, less, env, tee) with the SUID bit set used to spawn a root shell or read/write protected files",
        sysmon: `// Sysmon for Linux EID 1 - SUID/SGID abuse for escalation
// The signal is euid=0 resulting from a non-root invocation.

// GTFOBins shell-spawn patterns via SUID binary:
Image=*/find  AND CommandLine matches: *-exec*/bin/sh* OR *-exec bash*
Image=*/awk   AND CommandLine matches: *BEGIN*system* OR *system("/bin/*
Image=(*vim OR *vi) AND CommandLine matches: *!/bin/sh* OR *:!bash*
Image=*/less  AND CommandLine matches: *!/bin/* (shell escape from pager)
Image=*/env   AND CommandLine matches: *env /bin/sh* OR *env bash*
Image=*/tee   AND CommandLine matches: */etc/sudoers* OR */etc/passwd*
Image=(*python* OR *perl) AND CommandLine matches: *-p* OR *setuid*

// bash invoked with -p (preserves SUID effective UID)
Image=*/bash AND CommandLine matches: *-p* OR *--privileged*

// Auditd: execve where resulting euid=0 but auid != 0
-a always,exit -F arch=b64 -S execve -C uid!=euid -k suid_exec
-a always,exit -F arch=b64 -S execve -F euid=0 -k root_exec`,
        kibana: `// GTFOBins escalation patterns
process.name: "find"
AND process.command_line: (*-exec* AND (*bash* OR */bin/sh*))

process.name: "awk"
AND process.command_line: (*system(* OR *BEGIN{*) AND (*bash* OR *sh*))

process.name: ("vim" OR "vi" OR "less" OR "more")
AND process.command_line: (*!/bin/* OR *shell* OR *:!*)

process.name: "env"
AND process.command_line: (*env /bin/* OR *env bash*)

// bash -p preserving SUID privilege
process.command_line: ("bash -p" OR "bash --privileged")

// Auditd: euid != uid (SUID executed), resulting euid=0
event.module: "auditd"
AND tags: "suid_exec"
AND auditd.data.euid: "0"
AND NOT auditd.data.auid: ("0" OR "4294967295")

// A SUID binary not from any package (high signal)
// (enrich file events with package-membership lookup)
event.module: "file_integrity"
AND file.mode: ("4*")
AND file.path: NOT (/usr/* OR /bin/* OR /sbin/*)`,
        powershell: `#!/bin/bash
# T1548.001 - SUID/SGID abuse hunt

echo "[*] === All SUID binaries ==="
find / -perm -4000 -type f 2>/dev/null | sort | while read f; do
  echo "$f | owner: $(stat -c '%U' "$f") | perms: $(stat -c '%a' "$f")"
done

echo ""
echo "[*] === All SGID binaries ==="
find / -perm -2000 -type f 2>/dev/null | sort | head -40

echo ""
echo "[*] === SUID/SGID binaries NOT owned by package manager (HIGH SIGNAL) ==="
find / -perm -4000 -type f 2>/dev/null | while read f; do
  if ! (dpkg -S "$f" 2>/dev/null || rpm -qf "$f" 2>/dev/null) | grep -q .; then
    echo "[FLAG] Non-packaged SUID: $f"; ls -la "$f"
  fi
done

echo ""
echo "[*] === GTFOBins-exploitable binaries with SUID set ==="
for b in find awk nmap vim vi less more nano env tee python python3 \\
         perl ruby lua node php cp mv dd nano sed; do
  p=$(command -v $b 2>/dev/null); [ -z "$p" ] && continue
  perms=$(stat -c '%a' "$p" 2>/dev/null)
  [ "\${perms:0:1}" -ge 4 ] 2>/dev/null && echo "[FLAG] SUID GTFOBin: $p ($perms)"
done

echo ""
echo "[*] === Baseline-deviation SUID set (compare to known-good list) ==="
echo "  Common-legit SUID: su sudo passwd chsh chfn newgrp gpasswd"
echo "    mount umount ping pkexec fusermount"
echo "  Anything else = investigate"

echo ""
echo "[*] === auditd: SUID executions reaching euid=0 from non-root ==="
ausearch -k suid_exec -i --start today 2>/dev/null | \\
  awk '/euid=0/ && !/auid=0/' | tail -30`,
        registry: `SUID/SGID escalation artifacts:

Enumeration:
  find / -perm -4000 -type f 2>/dev/null   (SUID)
  find / -perm -2000 -type f 2>/dev/null   (SGID)
  find / -perm -6000 -type f 2>/dev/null   (both)

Expected-legitimate SUID binaries (baseline):
  /usr/bin/su /usr/bin/sudo /usr/bin/passwd
  /usr/bin/chsh /usr/bin/chfn /usr/bin/newgrp
  /usr/bin/gpasswd /usr/bin/mount /usr/bin/umount
  /usr/bin/pkexec /usr/bin/fusermount /bin/ping
  (anything outside this set warrants a look)

High-risk GTFOBins when SUID is set:
  find    : find . -exec /bin/sh -p \\; -quit
  awk     : awk 'BEGIN {system("/bin/sh")}'
  vim/vi  : vim -c ':!/bin/sh'
  less    : less file → !/bin/sh
  env     : env /bin/sh
  tee     : echo "evil::0:0::/:/bin/bash" | tee -a /etc/passwd
  python  : python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
  perl    : perl -e 'exec "/bin/sh";'
  cp      : overwrite /etc/passwd or a SUID binary
  dd      : write to protected files
  nano    : ^R^X to run command, or write protected files

Attacker-planted SUID (persistence + escalation):
  /tmp/<name>  with 4755 perms, owner root
  cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash
  Then: /tmp/rootbash -p  → root shell
  Watch for: root-owned SUID binary in /tmp, /dev/shm, /home

Reference: gtfobins.github.io (filter: SUID)`,
        tools: `SUID/SGID abuse - the foundational Linux LPE path:

Why it matters:
  SUID binaries run with the file owner's privileges
  (often root) regardless of who executes them. A SUID
  binary that can spawn a shell or write arbitrary files
  is an instant privilege escalation.

GTFOBins (gtfobins.github.io):
  The definitive catalog of Unix binaries abusable when
  SUID-set or sudo-allowed. Hundreds of entries. Both red
  and blue teams reference it constantly.

Enumeration tooling:
  LinPEAS / LinEnum   - automated SUID/SGID enumeration
  linux-smart-enum    - SUID + GTFOBins cross-reference
  GTFOBins lookup is built into most privesc scripts

Attacker workflow:
  1. find / -perm -4000 2>/dev/null
  2. Cross-reference results against GTFOBins
  3. Execute the GTFOBins escalation one-liner
  Often automated end-to-end by LinPEAS.

Persistence variant:
  Attacker who already has root drops a SUID-root copy of
  bash (chmod 4755 /tmp/.x) as a re-escalation backdoor.
  cp /bin/bash /tmp/.bd; chmod +s /tmp/.bd; /tmp/.bd -p

Threat actor use:
  Rocke, 8220, TeamTNT all enumerate SUID post-access.
  Web-shell → www-data → SUID perl/python = instant root
  on misconfigured legacy servers. Extremely common.

Note vs T1059.004 execution row:
  Execution page covers SUID as an execution vector;
  this row is the privilege-escalation focus - the
  euid transition to root is the key signal here.`,
        ossdetect: `Sigma rules:
- proc_creation_lnx_susp_suid_sgid_execution.yml
- proc_creation_lnx_gtfobins_suid_shell.yml
- file_event_lnx_suid_binary_creation.yml

Elastic detection rules:
- Setuid/Setgid Bit Set on Binary
- Privilege Escalation via SUID Binary
- Potential GTFOBins Abuse

osquery (find unexpected SUID):
  SELECT path, mode, uid FROM file
  WHERE directory IN ('/usr/bin','/usr/local/bin','/tmp')
    AND (mode LIKE '4%' OR mode LIKE '6%');
  suid_bin table also available

Velociraptor:
  Linux.Sys.SUID  (enumerate all SUID/SGID binaries)
  Compare against golden baseline

Auditd:
  -a always,exit -F arch=b64 -S execve -C uid!=euid -k suid_exec
  -a always,exit -F arch=b64 -S chmod,fchmod -F a1&04000 -k suid_set
  (second rule catches the SETTING of a SUID bit)
  ausearch -k suid_exec -i | awk '/euid=0/ && !/auid=0/'

File integrity (AIDE/Tripwire/Wazuh):
  Baseline all SUID/SGID binaries; alert on:
    - new SUID binary anywhere
    - SUID bit added to a previously-normal file
    - SUID binary outside /usr /bin /sbin

LinPEAS (attack-surface discovery):
  ./linpeas.sh | grep -A5 "SUID"
  Run on suspect host to see own exposure

Atomic Red Team:
  T1548.001 - tests for setuid/setgid bit abuse`,
        notes: "SUID/SGID abuse is the foundational Linux privilege escalation technique and the first thing nearly every post-exploitation enumeration script checks. A SUID binary executes with its owner's privileges (commonly root) regardless of the invoking user, so any SUID binary capable of spawning a shell, writing arbitrary files, or reading protected files is a direct escalation path. The GTFOBins project catalogs every standard Unix binary that can be abused this way, and the list is longer than most defenders expect - find, awk, vim, less, env, tee, cp, dd, python, perl, and dozens more. The detection approach has two halves: a static posture audit (enumerate all SUID/SGID binaries and compare against a known-good baseline - the legitimate set on a stock system is small, roughly su, sudo, passwd, chsh, chfn, newgrp, gpasswd, mount, umount, pkexec, fusermount, ping, so anything outside that set deserves scrutiny, and any SUID binary outside /usr, /bin, /sbin is highly suspicious), and a behavioral signal (auditd execve capture where the effective UID becomes 0 while the audit/login UID is non-zero, which precisely identifies a SUID-to-root transition). A common attacker persistence pattern that doubles as re-escalation is dropping a SUID-root copy of bash in /tmp - watch for root-owned SUID binaries in writable directories. This row is the privilege-escalation counterpart to the SUID execution row on the Execution page; the distinguishing signal here is the euid transition to root.",
        apt: [
          { cls: "apt-mul", name: "TeamTNT / Rocke / 8220", note: "SUID enumeration via LinPEAS-style tooling is a standard post-access escalation step in cloud cryptojacking campaigns." },
          { cls: "apt-mul", name: "Web-shell operators", note: "www-data context plus a SUID perl/python on legacy servers yields instant root; extremely common in web exploitation chains." },
          { cls: "apt-mul", name: "Red team / commodity", note: "GTFOBins-based SUID escalation is automated by LinPEAS, LinEnum, and linux-smart-enumeration; near-universal first escalation attempt." }
        ],
        cite: "MITRE ATT&CK T1548.001"
      },
      {
        sub: "T1548.001 - Linux Capabilities Abuse (cap_setuid, cap_dac_override, cap_sys_admin)",
        os: "linux",
        indicator: "A binary granted dangerous Linux file capabilities (via setcap) abused for privilege escalation - cap_setuid+ep on an interpreter enabling silent setuid(0), cap_dac_override for arbitrary file access, or cap_sys_admin/cap_sys_ptrace for broader system control; invisible to standard SUID checks, only visible via getcap",
        sysmon: `// Capabilities are NOT visible in ls -la / SUID checks.
// They are file attributes set via setcap. Two angles:

// 1. setcap invocation (granting a capability) - watch the act
EventID=1
Image=*/setcap
CommandLine matches:
  *cap_setuid*  *cap_setgid*  *cap_dac_override*
  *cap_sys_admin*  *cap_sys_ptrace*  *cap_net_raw*
  *+ep*  *+ei*  *=ep*
AND target binary is an interpreter (python/perl/ruby/node)
  OR a binary in a writable/non-standard path

// 2. Execution of a capability-enabled interpreter that then
//    calls setuid(0) - the escalation moment
Image=(*python* OR *perl OR *ruby OR *node)
CommandLine matches: *setuid* OR *os.setuid(0)* OR *POSIX*setuid*

// Auditd: capset syscall, and setcap execve
-a always,exit -F arch=b64 -S capset -k capset_call
-a always,exit -F arch=b64 -S execve -F path=/usr/sbin/setcap -k setcap_exec
-a always,exit -F arch=b64 -S setuid -F a0=0 -k setuid_root`,
        kibana: `// setcap granting dangerous capability
process.name: "setcap"
AND process.command_line: (
  *cap_setuid* OR *cap_setgid* OR *cap_dac_override*
  OR *cap_sys_admin* OR *cap_sys_ptrace* OR *cap_net_admin*
)

// Interpreter calling setuid(0) (capability escalation moment)
process.name: ("python" OR "python3" OR "perl" OR "ruby" OR "node")
AND process.command_line: (*setuid(0)* OR *os.setuid* OR *POSIX::setuid*)

// Auditd: setcap execution
event.module: "auditd"
AND tags: ("setcap_exec" OR "capset_call")

// setuid(0) syscall from a non-root process
event.module: "auditd"
AND tags: "setuid_root"
AND NOT auditd.data.auid: ("0" OR "4294967295")

// File with capabilities outside expected set
// (requires enrichment - getcap inventory fed to SIEM)
event.module: "file_integrity"
AND file.capabilities: (*cap_setuid* OR *cap_dac_override* OR *cap_sys_admin*)`,
        powershell: `#!/bin/bash
# T1548.001 - Linux capabilities abuse hunt

echo "[*] === ALL file capabilities on the system ==="
getcap -r / 2>/dev/null

echo ""
echo "[*] === DANGEROUS capabilities (escalation-enabling) ==="
getcap -r / 2>/dev/null | grep -iE \\
  "cap_setuid|cap_setgid|cap_dac_override|cap_dac_read_search|cap_sys_admin|cap_sys_ptrace|cap_sys_module|cap_net_admin|cap_chown|cap_fowner"

echo ""
echo "[*] === Capabilities on interpreters (highest risk) ==="
for b in python python2 python3 perl ruby node lua php tar; do
  p=$(command -v $b 2>/dev/null); [ -z "$p" ] && continue
  caps=$(getcap "$p" 2>/dev/null)
  [ -n "$caps" ] && echo "[FLAG] $caps"
  # also resolve symlinks
  rp=$(readlink -f "$p" 2>/dev/null)
  caps2=$(getcap "$rp" 2>/dev/null)
  [ -n "$caps2" ] && [ "$rp" != "$p" ] && echo "[FLAG] $caps2"
done

echo ""
echo "[*] === Capabilities on binaries outside /usr (suspicious) ==="
getcap -r / 2>/dev/null | grep -vE "^/usr/(bin|sbin|lib)" | grep -vE "^/(bin|sbin)"

echo ""
echo "[*] === auditd: setcap execution + setuid(0) from non-root ==="
ausearch -k setcap_exec -i --start today 2>/dev/null | tail -20
ausearch -k setuid_root -i --start today 2>/dev/null | awk '!/auid=0/' | tail -20

echo ""
echo "[*] === Expected-legit capability holders (baseline) ==="
echo "  /usr/bin/ping            cap_net_raw"
echo "  /usr/bin/mtr-packet      cap_net_raw"
echo "  /usr/sbin/arping         cap_net_raw"
echo "  /usr/bin/systemd-detect-virt (varies)"
echo "  Anything with cap_setuid/cap_dac_override/cap_sys_admin = investigate"

echo ""
echo "[*] === Container capability check (run inside container) ==="
capsh --print 2>/dev/null | grep -iE "current|bounding"
grep CapEff /proc/self/status 2>/dev/null`,
        registry: `Linux capabilities escalation artifacts:

Enumeration (capabilities are INVISIBLE to ls/SUID checks):
  getcap -r / 2>/dev/null        - list all file capabilities
  getpcaps <pid>                 - capabilities of a process
  grep Cap /proc/<pid>/status    - CapEff/CapPrm bitmasks
  capsh --decode=<hex>           - decode a capability bitmask

Dangerous capabilities and their escalation paths:
  cap_setuid+ep   : binary can setuid(0) → root
    python3: os.setuid(0); os.system("/bin/bash")
  cap_dac_override+ep : bypass file permission checks
    read /etc/shadow, write /etc/passwd
  cap_dac_read_search+ep : read any file (Shocker-style)
  cap_sys_admin+ep : mount, many escape paths (near-root)
  cap_sys_ptrace+ep : ptrace any process → inject into root proc
  cap_sys_module+ep : load kernel module → total host control
  cap_chown+ep / cap_fowner+ep : change ownership of files
  cap_net_admin / cap_net_raw : network manipulation

Expected-legitimate capability holders (baseline):
  /usr/bin/ping            cap_net_raw   (or SUID on some distros)
  /usr/sbin/arping         cap_net_raw
  /usr/bin/mtr-packet      cap_net_raw
  (cap_setuid, cap_dac_override, cap_sys_admin on a file
   are almost never legitimate on a normal server)

Setting a capability (the attack/persistence act):
  setcap cap_setuid+ep /usr/bin/python3
  Then any user runs: python3 -c 'import os;os.setuid(0);os.system("/bin/sh")'

Why this is stealthy:
  find -perm -4000 does NOT show capability-enabled binaries.
  Only getcap reveals them. Many defenders never check.
  A cap_setuid python3 is functionally SUID-root but invisible
  to the standard SUID hunt.`,
        tools: `Linux capabilities abuse:

The stealthy cousin of SUID:
  Capabilities split root's power into ~40 distinct units.
  setcap assigns specific capabilities to a binary file.
  A binary with cap_setuid+ep can become root, but it does
  NOT show up in find -perm -4000. This invisibility makes
  it a favored persistence + escalation mechanism.

Most dangerous for escalation:
  cap_setuid    - direct path to root (setuid(0) + exec shell)
  cap_dac_override / cap_dac_read_search - read/write any file
  cap_sys_admin - the "new root"; enables mount + many escapes
  cap_sys_ptrace - inject into privileged processes
  cap_sys_module - load a malicious kernel module = game over

Enumeration tooling:
  LinPEAS    - dedicated capabilities section, flags dangerous ones
  getcap -r / - the core command; attackers run it first
  linux-smart-enumeration - capability + GTFOBins cross-ref

GTFOBins has a Capabilities filter:
  gtfobins.github.io - filter by "Capabilities" shows which
  binaries escalate with which capability set

Persistence angle:
  An attacker with root sets cap_setuid+ep on a benign-looking
  binary, then drops to a low-priv user. Re-escalation is one
  command and leaves no SUID artifact. Survives many cleanups.

Container relevance:
  Container capabilities (capsh --print) determine escape
  surface. CAP_SYS_ADMIN in a container = likely escapable.
  See T1611 for the container escape chains these enable.

Threat actor use:
  Less common than SUID in commodity malware (because it's
  less universally understood), but documented in targeted
  Linux intrusions and increasingly in container attacks.`,
        ossdetect: `Sigma rules:
- proc_creation_lnx_setcap_dangerous_capability.yml
- proc_creation_lnx_capability_priv_esc.yml

Elastic detection rules:
- File Capability Modification via setcap
- Privilege Escalation via Linux Capabilities

Auditd:
  -a always,exit -F arch=b64 -S execve \\
    -F path=/usr/sbin/setcap -k setcap_exec
  -a always,exit -F arch=b64 -S capset -k capset_call
  -a always,exit -F arch=b64 -S setuid -F a0=0 -k setuid_root
  ausearch -k setcap_exec -i

osquery:
  SELECT * FROM process_file_events WHERE ...
  (capability inventory typically via scheduled getcap)

Velociraptor:
  Custom VQL: execve(argv=["getcap","-r","/"]) periodically
  Diff against baseline; alert on new dangerous caps

File integrity / scheduled audit:
  Run getcap -r / on a schedule, diff against golden baseline
  Alert on any new file with cap_setuid, cap_dac_override,
  cap_sys_admin, cap_sys_ptrace, cap_sys_module
  (this is the PRIMARY detection - most tools miss capabilities)

LinPEAS:
  ./linpeas.sh | grep -A10 -i "capabilit"
  Shows own exposure to capability-based escalation

Atomic Red Team:
  T1548.001 includes capability-based escalation tests

Hardening:
  Audit and minimize file capabilities org-wide
  Most servers should have NO cap_setuid/cap_dac_override files`,
        notes: "Linux capabilities are the stealthy counterpart to SUID and represent a frequently-missed escalation and persistence vector precisely because they are invisible to the standard SUID hunt (find -perm -4000). Capabilities split root's monolithic power into roughly 40 distinct units, and the setcap command assigns specific ones to a binary file. A binary with cap_setuid+ep can call setuid(0) and become root - functionally identical to SUID-root - but it does not appear in any permission-based search; only getcap -r / reveals it. This invisibility is exactly why it appeals to attackers for persistence: an attacker with root can grant cap_setuid+ep to a benign-looking binary, drop to a low-privilege account, and retain a one-command re-escalation path that survives cleanups focused on SUID binaries and cron jobs. The most dangerous capabilities for escalation are cap_setuid (direct root), cap_dac_override and cap_dac_read_search (read/write any file, including /etc/shadow and /etc/passwd), cap_sys_admin (the de facto new root, enabling mount and numerous escape paths), cap_sys_ptrace (inject into privileged processes), and cap_sys_module (load a malicious kernel module for total control). The single most important detection control is running getcap -r / on a schedule and diffing against a known-good baseline - on a normal server the legitimate capability set is tiny (typically just cap_net_raw on ping and a few network tools), so cap_setuid, cap_dac_override, or cap_sys_admin on any file is almost always worth investigating. GTFOBins includes a Capabilities filter mapping binaries to the capability needed for escalation.",
        apt: [
          { cls: "apt-mul", name: "Targeted Linux intrusions", note: "Capability-based escalation and persistence (cap_setuid on interpreters) documented in targeted server compromises; survives SUID-focused cleanup." },
          { cls: "apt-mul", name: "Container attackers", note: "CAP_SYS_ADMIN and related capabilities in containers are the precondition for multiple T1611 escape chains." },
          { cls: "apt-mul", name: "Red team / LinPEAS users", note: "getcap enumeration and GTFOBins capability cross-reference are standard in modern Linux privilege-escalation tooling." }
        ],
        cite: "MITRE ATT&CK T1548.001"
      }
    ]
  },
  {
    id: "T1548.003",
    name: "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
    desc: "Sudo-based privilege escalation - sudoers NOPASSWD and GTFOBins misconfiguration abuse, sudo binary CVEs (Baron Samedit CVE-2021-3156, runas bypass CVE-2019-14287), and sudo credential-cache token reuse via process injection",
    rows: [
      {
        sub: "T1548.003 - Sudoers Misconfiguration and NOPASSWD GTFOBins Abuse",
        os: "linux",
        indicator: "Abuse of an overly-permissive sudoers entry - a NOPASSWD rule for a GTFOBins-exploitable command (vim, find, less, awk, python), a wildcard or env-preserving rule, or sudo access to an editor/interpreter - to execute commands as root; preceded by sudo -l enumeration",
        sysmon: `// Sysmon for Linux EID 1 - sudo abuse via misconfig

// sudo -l enumeration (recon - what can I run as root?)
Image=*/sudo AND CommandLine matches: *-l* OR *--list*

// sudo running a GTFOBins-exploitable command
Image=*/sudo AND CommandLine matches:
  *sudo vim* OR *sudo vi*       (vim → :!/bin/sh)
  *sudo find* *-exec*           (find -exec /bin/sh)
  *sudo less* OR *sudo more*    (pager shell escape)
  *sudo awk* *system*           (awk system())
  *sudo python* OR *sudo perl*  (interpreter → shell)
  *sudo nmap*                   (--interactive, old)
  *sudo tee* */etc/*            (write protected files)
  *sudo env*                    (env /bin/sh)
  *sudo man*                    (pager escape)

// sudo with env_keep abuse (LD_PRELOAD / PYTHONPATH passed through)
Image=*/sudo AND environment contains LD_PRELOAD or PYTHONPATH

// Auditd
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/sudo -k sudo_exec
-w /etc/sudoers -p rwa -k sudoers
-w /etc/sudoers.d -p rwa -k sudoers`,
        kibana: `// sudo -l enumeration
process.name: "sudo"
AND process.command_line: (*-l* OR *--list*)

// sudo invoking a GTFOBins-exploitable command
process.name: "sudo"
AND process.command_line: (
  *vim* OR *vi * OR *find* OR *less* OR *more* OR *awk*
  OR *python* OR *perl* OR *ruby* OR *nmap* OR *man *
  OR *env * OR *tee * OR *ftp* OR *gdb*
)

// Shell whose parent is one of those sudo-run binaries
process.name: ("bash" OR "sh" OR "dash")
AND process.parent.name: ("vim" OR "vi" OR "find" OR "less" OR "awk" OR "python3" OR "perl")
AND user.id: "0"

// sudoers file modification
event.module: "auditd"
AND tags: "sudoers"
AND NOT process.name: ("visudo" OR "dpkg" OR "rpm")

// env_keep abuse: LD_PRELOAD/PYTHONPATH surviving into sudo
process.name: "sudo"
AND process.env_vars: (*LD_PRELOAD=* OR *PYTHONPATH=*)

// Auditd: sudo execve resulting in root child
event.module: "auditd"
AND tags: "sudo_exec"
AND auditd.data.euid: "0"
AND auditd.data.command: (*vim* OR *find* OR *less* OR *python* OR *awk*)`,
        powershell: `#!/bin/bash
# T1548.003 - Sudoers misconfiguration hunt

echo "[*] === /etc/sudoers + /etc/sudoers.d (full review) ==="
cat /etc/sudoers 2>/dev/null | grep -vE "^#|^$"
for f in /etc/sudoers.d/*; do
  [ -f "$f" ] || continue
  echo "--- $f ---"; cat "$f" | grep -vE "^#|^$"
done

echo ""
echo "[*] === NOPASSWD entries (no-auth escalation) ==="
grep -rE "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -vE "^#"

echo ""
echo "[*] === Dangerous GTFOBins commands granted via sudo ==="
grep -rE "(vim|vi|find|less|more|awk|nano|python|perl|ruby|nmap|man|env|tee|cp|dd|ftp|gdb|tar|zip|systemctl|apt|dpkg)" \\
  /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -vE "^#"

echo ""
echo "[*] === env_keep / SETENV (LD_PRELOAD passthrough risk) ==="
grep -rE "(env_keep|SETENV|!env_reset)" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -vE "^#"

echo ""
echo "[*] === Wildcard sudo rules (often exploitable) ==="
grep -rE "\\*" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -vE "^#"

echo ""
echo "[*] === Per-user sudo rights (what each account can run) ==="
getent passwd | awk -F: '$3>=1000 && $7!~/nologin|false/{print $1}' | \\
  while read u; do
    out=$(sudo -l -U "$u" 2>/dev/null | grep -vE "not allowed|not in sudoers|may not|Matching")
    [ -n "$out" ] && { echo "--- $u ---"; echo "$out"; }
  done

echo ""
echo "[*] === auditd: sudo running editors/interpreters (today) ==="
ausearch -k sudo_exec -i --start today 2>/dev/null | \\
  grep -E "(vim|vi|find|less|awk|python|perl)" | tail -20

echo ""
echo "[*] === Recent sudoers modifications ==="
ausearch -k sudoers -i --start today 2>/dev/null | tail -20
ls -la /etc/sudoers /etc/sudoers.d/ 2>/dev/null`,
        registry: `Sudoers misconfiguration artifacts:

Configuration files:
  /etc/sudoers                  - main policy (edit via visudo)
  /etc/sudoers.d/*              - drop-in fragments
  sudo -l                       - list invoking user's privileges
  sudo -l -U <user>             - list another user's (as root)

Dangerous sudoers patterns:
  user ALL=(ALL) NOPASSWD: ALL          - full root, no password
  user ALL=(ALL) NOPASSWD: /usr/bin/vim - GTFOBins → root shell
  user ALL=(ALL) /usr/bin/find          - find -exec /bin/sh
  user ALL=(ALL) /usr/bin/less          - less → !/bin/sh
  user ALL=(ALL) /usr/bin/python3       - python → os.system
  Defaults env_keep += "LD_PRELOAD"     - preload passthrough
  user ALL=(ALL) /path/*                - wildcard injection
  user ALL=(ALL) /usr/bin/systemctl     - systemctl → pager → shell

GTFOBins sudo escalation one-liners:
  sudo vim -c ':!/bin/sh'
  sudo find . -exec /bin/sh \\; -quit
  sudo less /etc/profile → !/bin/sh
  sudo awk 'BEGIN {system("/bin/sh")}'
  sudo python3 -c 'import os; os.system("/bin/sh")'
  sudo env /bin/sh
  echo "evil ALL=(ALL) NOPASSWD: ALL" | sudo tee -a /etc/sudoers

env_keep / LD_PRELOAD abuse:
  If sudoers has: Defaults env_keep += "LD_PRELOAD"
  Attacker: LD_PRELOAD=/tmp/evil.so sudo <any-allowed-cmd>
  The .so runs as root via the preload.

Sudo logs:
  /var/log/auth.log (Debian)  /var/log/secure (RHEL)
  Records: "USER : TTY=... ; PWD=... ; USER=root ; COMMAND=..."
  Hunt for sudo COMMAND= entries running editors/interpreters

Reference: gtfobins.github.io (filter: Sudo)`,
        tools: `Sudo misconfiguration abuse:

The #1 real-world Linux LPE in CTFs and pentests:
  Overly-permissive sudoers rules are extremely common.
  The workflow is universal:
    1. sudo -l        (what can I run?)
    2. Cross-reference allowed commands with GTFOBins
    3. Execute the escalation one-liner

GTFOBins (gtfobins.github.io):
  "Sudo" filter lists every binary that escalates to root
  when sudo-allowed. Hundreds of entries: editors, pagers,
  interpreters, archivers, even seemingly-harmless tools.

Common dangerous grants seen in the wild:
  systemctl, apt, dpkg, git, tar, zip, vim, find, less,
  python, perl, awk, nmap, man, env, tee, dd, cp

env_keep / LD_PRELOAD passthrough:
  If sudoers preserves LD_PRELOAD, an attacker preloads a
  malicious .so that runs as root via any allowed sudo command.

Tooling:
  sudo -l        - the attacker's first command
  LinPEAS        - parses sudo -l, flags GTFOBins matches
  sudo_killer    - dedicated sudo misconfig + CVE exploitation
  GTFOBins lookup is built into every privesc script

Threat actor use:
  Less "APT signature," more universal opportunism. Any
  actor with a foothold runs sudo -l. Cryptomining crews,
  red teams, and manual intruders all exploit sudo misconfig
  as the path of least resistance to root.

Note: this row is misconfiguration abuse; the companion row
covers sudo binary CVEs (Baron Samedit, etc.).`,
        ossdetect: `Sigma rules:
- proc_creation_lnx_sudo_gtfobins_shell.yml
- proc_creation_lnx_sudo_list_enumeration.yml
- file_event_lnx_sudoers_modification.yml

Elastic detection rules:
- Sudo Command Enumeration (sudo -l)
- Potential Sudo GTFOBins Privilege Escalation
- Sudoers File Modification

Auditd:
  -a always,exit -F arch=b64 -S execve -F path=/usr/bin/sudo -k sudo_exec
  -w /etc/sudoers -p rwa -k sudoers
  -w /etc/sudoers.d -p rwa -k sudoers
  ausearch -k sudoers | grep -v "comm=\\"visudo\\""

Sudo logging (enable I/O logging for forensics):
  Defaults log_input, log_output
  Defaults iolog_dir="/var/log/sudo-io"
  Captures full session of every sudo command

Falco:
  rule: Sudo Potential Privilege Escalation
  rule: Modify Sudoers File
  rule: Read sensitive file untrusted (sudoers)

Config audit (primary control):
  sudo -l -U <each-user> as part of scheduled audit
  Flag NOPASSWD rules, GTFOBins commands, env_keep,
  wildcards, and editor/interpreter grants
  visudo -c  (syntax check)

Lynis:
  lynis audit system - flags sudoers weaknesses

Atomic Red Team:
  T1548.003 - sudo caching and sudoers abuse tests`,
        notes: "Sudoers misconfiguration is the single most common real-world Linux privilege escalation path - more prevalent than kernel exploits or pkexec because it requires no vulnerability, just an overly-permissive policy that administrators create routinely for convenience. The attacker workflow is universal and is the first thing run after any foothold: sudo -l to enumerate allowed commands, cross-reference against GTFOBins, and execute the escalation one-liner. The danger is that many seemingly-reasonable sudo grants are exploitable: allowing a user to run vim, find, less, awk, python, systemctl, apt, git, or tar via sudo grants effective root, because all of those binaries can spawn a shell or write arbitrary files from within their privileged execution. NOPASSWD rules compound the risk by removing even the password barrier. A subtler vector is env_keep: if sudoers preserves LD_PRELOAD or PYTHONPATH, an attacker can preload a malicious shared object that executes as root through any allowed sudo command. The detection approach is primarily configuration audit - regularly enumerate each user's sudo rights (sudo -l -U), flagging NOPASSWD entries, GTFOBins-exploitable commands, wildcards, and env_keep directives - supplemented by behavioral detection of sudo invoking editors or interpreters followed by a root shell. Enabling sudo I/O logging (log_input/log_output) provides full forensic capture of every sudo session. This row covers misconfiguration abuse; the companion row addresses sudo binary CVEs.",
        apt: [
          { cls: "apt-mul", name: "Universal post-access", note: "sudo -l enumeration and GTFOBins escalation is run by virtually every actor with a Linux foothold; the path of least resistance to root." },
          { cls: "apt-mul", name: "Cryptomining crews", note: "Sudo misconfiguration exploited opportunistically for root before miner deployment on compromised servers." },
          { cls: "apt-mul", name: "Red team / LinPEAS", note: "LinPEAS and sudo_killer automate sudo -l parsing and GTFOBins matching; standard escalation tooling." }
        ],
        cite: "MITRE ATT&CK T1548.003"
      },
      {
        sub: "T1548.003 - Sudo Binary Exploitation and Token Reuse (Baron Samedit, CVE-2019-14287)",
        os: "linux",
        indicator: "Exploitation of a sudo binary vulnerability for root - Baron Samedit heap overflow (CVE-2021-3156) via sudoedit -s, the runas -u#-1 user-ID bypass (CVE-2019-14287), or sudo credential-cache/token reuse by injecting into a process with a valid sudo timestamp",
        sysmon: `// Sysmon for Linux EID 1 - sudo CVE exploitation patterns

// CVE-2019-14287: sudo runas with -u#-1 / -u#4294967295
Image=*/sudo AND CommandLine matches:
  *-u#-1*  OR  *-u#4294967295*  OR  *--user=#-1*

// Baron Samedit (CVE-2021-3156): sudoedit -s with trailing
// backslash triggers heap overflow. Watch sudoedit -s usage.
Image=(*/sudoedit OR */sudo) AND CommandLine matches:
  *sudoedit -s*  OR  *-s \\*       (trailing backslash arg)

// Generic: sudo crashing / segfaulting (exploit attempt)
// dmesg / kern.log: "sudo[PID]: segfault"

// Sudo token reuse: attacker injects into a process that
// recently ran sudo (valid timestamp in /run/sudo/ts/<user>)
// Watch ptrace into a shell with a fresh sudo timestamp.
-a always,exit -F arch=b64 -S ptrace -k ptrace_call

// Auditd
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/sudo -k sudo_exec
-w /run/sudo/ts -p wa -k sudo_token`,
        kibana: `// CVE-2019-14287: runas -1 / 4294967295 bypass
process.name: "sudo"
AND process.command_line: (*-u#-1* OR *-u#4294967295* OR *"--user=#-1"*)

// Baron Samedit: sudoedit -s exploitation pattern
process.name: ("sudoedit" OR "sudo")
AND process.command_line: (*"sudoedit -s"* OR *"-s \\\\"*)

// sudo segfault (exploit attempt) from kernel log
message: ("sudo" AND "segfault")

// sudo token reuse via ptrace into a session with valid timestamp
event.module: "auditd"
AND tags: "ptrace_call"
AND process.name: ("bash" OR "sh")

// sudo timestamp file manipulation
event.module: "auditd"
AND tags: "sudo_token"

// Successful root from sudo by a user/version that shouldn't
process.name: "sudo"
AND user.id: "0"
AND process.command_line: (*-u#* OR *-s*)

// Version-based: alert if sudo version is known-vulnerable
// (enrich from package inventory: sudo < 1.9.5p2 = Baron Samedit)`,
        powershell: `#!/bin/bash
# T1548.003 - Sudo CVE / token reuse hunt

echo "[*] === Sudo version vs known CVEs ==="
sudo --version 2>/dev/null | head -1
echo "  Baron Samedit (CVE-2021-3156): sudo 1.8.2 - 1.8.31p2, 1.9.0 - 1.9.5p1"
echo "    FIXED in 1.9.5p2"
echo "  Runas bypass (CVE-2019-14287): sudo < 1.8.28"
echo "  CVE-2023-22809 (sudoedit arbitrary file): 1.8.0 - 1.9.12p1"

echo ""
echo "[*] === Test Baron Samedit (non-destructive check) ==="
# Vulnerable sudo returns a specific error; patched returns usage
out=$(sudoedit -s '\\' 2>&1)
if echo "$out" | grep -qi "malloc\\|corrupt\\|segmentation"; then
  echo "[CRITICAL] sudo appears VULNERABLE to Baron Samedit"
else
  echo "[INFO] sudoedit -s test output: $out"
fi

echo ""
echo "[*] === auth.log: sudo runas -1 bypass attempts ==="
grep -hE "sudo.*(-u#-1|4294967295|user=#-1)" \\
  /var/log/auth.log /var/log/secure 2>/dev/null | tail -20

echo ""
echo "[*] === kern.log/dmesg: sudo segfaults (exploit attempts) ==="
dmesg 2>/dev/null | grep -iE "sudo.*segfault|sudoedit.*segfault" | tail -10
grep -hi "sudo.*segfault" /var/log/kern.log 2>/dev/null | tail -10

echo ""
echo "[*] === Active sudo timestamps (token reuse opportunity) ==="
ls -la /run/sudo/ts/ 2>/dev/null
echo "  (a valid timestamp lets a process re-sudo without password;"
echo "   ptrace into such a process = token reuse escalation)"

echo ""
echo "[*] === auditd: ptrace into shells (token reuse) ==="
ausearch -k ptrace_call -i --start today 2>/dev/null | tail -20

echo ""
echo "[*] === auditd: sudo runas bypass attempts ==="
ausearch -k sudo_exec -i --start today 2>/dev/null | \\
  grep -E "(-u#-1|4294967295)" | tail -20`,
        registry: `Sudo CVE / token-reuse artifacts:

Baron Samedit (CVE-2021-3156):
  Heap-based buffer overflow in sudo's command-line parsing.
  Affects sudo 1.8.2 - 1.8.31p2 and 1.9.0 - 1.9.5p1.
  Fixed in sudo 1.9.5p2 (Jan 2021).
  Trigger: sudoedit -s with a trailing backslash.
  Reliable, no-auth root. Affects default installs widely.
  Artifact: sudo/sudoedit segfault in dmesg/kern.log;
    sudoedit -s invocations with backslash args.

CVE-2019-14287 (runas user-ID bypass):
  sudo < 1.8.28. If a user is allowed to run a command as
  any user EXCEPT root (e.g. user ALL=(ALL,!root) ...),
  they can bypass with:  sudo -u#-1 <cmd>  (resolves to 0).
  Artifact: sudo invoked with -u#-1 or -u#4294967295.

CVE-2023-22809 (sudoedit arbitrary file write):
  sudo 1.8.0 - 1.9.12p1. EDITOR/SUDO_EDITOR injection with
  extra file argument allows editing arbitrary files as root.
  Artifact: EDITOR env containing "-- /etc/sudoers" style args.

Sudo token / timestamp reuse:
  /run/sudo/ts/<user>   - sudo credential cache timestamp
  When valid (default 15 min), sudo runs without re-prompting.
  Attack: inject (ptrace) into a process owned by a user with
    a valid timestamp, then run sudo - no password needed.
  Tools: sudo_inject, "sudo token" exploitation.
  Artifact: ptrace of a shell process + subsequent sudo;
    manipulation of /run/sudo/ts/ files.

Version check:
  sudo --version   (first line shows version)
  dpkg -l sudo / rpm -q sudo

Logs:
  /var/log/auth.log (Debian) /var/log/secure (RHEL)
  dmesg / /var/log/kern.log  (segfaults)`,
        tools: `Sudo binary exploitation:

Baron Samedit (CVE-2021-3156):
  Qualys, Jan 2021. One of the most impactful sudo bugs.
  Heap overflow reachable by any local user (no sudo rights
  required at all). Public exploits within hours. Reliable
  root on a huge range of distros. Still found unpatched on
  legacy and OT-adjacent systems.

CVE-2019-14287 (runas bypass):
  The "-u#-1" bug. Only relevant when a sudoers rule allows
  running as any user except root - the bypass turns "not
  root" into root via integer wraparound. Simple, no exploit
  binary needed - just a sudo command-line trick.

CVE-2023-22809 (sudoedit):
  EDITOR variable injection allows editing arbitrary files
  (like /etc/sudoers or /etc/shadow) as root via sudoedit.

Sudo token reuse (not a CVE - design abuse):
  sudo caches credentials for ~15 min in /run/sudo/ts/.
  If an attacker controls a process owned by a user who
  recently sudo'd, they can ptrace-inject and reuse the
  cached token - root with no password.
  Tooling: sudo_inject (github), "sudo token" technique.

Enumeration/exploitation tooling:
  sudo_killer     - detects vulnerable sudo + misconfig
  LinPEAS         - flags sudo version against CVEs
  linux-exploit-suggester - maps sudo version to CVEs

Threat actor use:
  Baron Samedit was rapidly adopted by cryptomining crews
  and is a staple in commodity Linux LPE toolchains. Token
  reuse is more targeted/manual but documented in hands-on
  intrusions.

Companion row: sudoers misconfiguration abuse (GTFOBins).`,
        ossdetect: `Sigma rules:
- proc_creation_lnx_sudo_cve_2019_14287_runas_bypass.yml
- proc_creation_lnx_sudoedit_cve_2021_3156.yml
- proc_creation_lnx_sudo_token_reuse_ptrace.yml

Elastic detection rules:
- Sudo Privilege Escalation via -u#-1 (CVE-2019-14287)
- Potential Baron Samedit Exploitation
- ptrace Process Injection

Patch verification (primary control):
  sudo --version  (need >= 1.9.5p2 for Baron Samedit)
  dpkg -l sudo / rpm -q sudo
  Map version to CVE list

Auditd:
  -a always,exit -F arch=b64 -S execve -F path=/usr/bin/sudo -k sudo_exec
  -a always,exit -F arch=b64 -S ptrace -k ptrace_call
  -w /run/sudo/ts -p wa -k sudo_token
  ausearch -k sudo_exec | grep -E "u#-1|4294967295"

Disable ptrace (mitigates token reuse + injection):
  sysctl kernel.yama.ptrace_scope=1  (or 2/3 for stricter)
  /etc/sysctl.d/10-ptrace.conf

Falco:
  rule: Sudo Potential Privilege Escalation
  rule: PTRACE attached to process (token reuse / injection)

Sudo hardening:
  Defaults timestamp_timeout=0   (disable credential caching;
    eliminates token reuse entirely, at a usability cost)
  Defaults !tty_tickets removed  (per-tty tickets reduce reuse)

Lynis / OpenSCAP:
  Flag vulnerable sudo versions and weak timestamp settings

Atomic Red Team:
  T1548.003 - includes sudo caching/token abuse tests`,
        notes: "Sudo binary vulnerabilities complement sudoers misconfiguration as a root path, and Baron Samedit (CVE-2021-3156) is the standout: a heap-based buffer overflow in sudo's argument parsing that any local user can trigger with no sudo rights whatsoever, fixed only in sudo 1.9.5p2 (January 2021). It is reliable, leaves a segfault trace in kernel logs when exploitation is attempted, and remains unpatched on many legacy and OT-adjacent systems where sudo is rarely updated - making version verification the primary control. CVE-2019-14287 is a narrower but elegant bug: when a sudoers rule grants a user the right to run a command as any user except root (a pattern administrators sometimes use thinking it is safe), the user can specify -u#-1, which wraps around to UID 0, bypassing the restriction with nothing more than a command-line trick. Sudo token reuse is a design-level abuse rather than a CVE: sudo caches credentials for roughly 15 minutes in /run/sudo/ts/, so an attacker who controls a process owned by a user with a valid timestamp can ptrace-inject into it and run sudo without a password. The two most effective hardening controls beyond patching are setting kernel.yama.ptrace_scope to 1 or higher (which blocks the ptrace injection underlying token reuse) and setting timestamp_timeout=0 in sudoers (which disables credential caching entirely). For detection, watch for sudo invoked with -u#-1 or -u#4294967295, sudo/sudoedit segfaults in kernel logs, and ptrace of shell processes followed by sudo execution.",
        apt: [
          { cls: "apt-mul", name: "Cryptomining crews", note: "Baron Samedit (CVE-2021-3156) rapidly adopted for root on unpatched Linux hosts prior to miner deployment." },
          { cls: "apt-mul", name: "Commodity Linux LPE", note: "CVE-2021-3156 and CVE-2019-14287 are staples in linux-exploit-suggester, sudo_killer, and LinPEAS output." },
          { cls: "apt-mul", name: "Hands-on intruders", note: "Sudo token reuse via ptrace injection documented in targeted, interactive Linux intrusions where a privileged user session is present." }
        ],
        cite: "MITRE ATT&CK T1548.003"
      }
    ]
  },
  {
    id: "T1574.006",
    name: "Hijack Execution Flow: Dynamic Linker Hijacking",
    desc: "Privilege escalation via dynamic linker abuse - LD_PRELOAD preserved through sudo env_keep, /etc/ld.so.preload injection into SUID processes, and writable RPATH/RUNPATH or library search paths; the privesc-focused counterpart to T1106 execution-side LD_PRELOAD coverage",
    rows: [
      {
        sub: "T1574.006 - Dynamic Linker Hijacking for Privilege Escalation (LD_PRELOAD / LD_LIBRARY_PATH)",
        os: "linux",
        indicator: "Privilege escalation via dynamic linker abuse - LD_PRELOAD preserved through a sudo env_keep rule to load a malicious .so as root, a writable directory in LD_LIBRARY_PATH for a privileged binary, or /etc/ld.so.preload injection affecting SUID processes; the privesc-focused counterpart to the T1106 execution-side coverage",
        sysmon: `// Sysmon for Linux EID 1 - linker hijack for ESCALATION
// (privesc angle: malicious lib loaded into a PRIVILEGED process)

// LD_PRELOAD surviving into a sudo/SUID context
Image=*/sudo AND environment contains LD_PRELOAD
// (only exploitable if sudoers has env_keep += LD_PRELOAD)

// Privileged binary run with attacker-controlled LD_LIBRARY_PATH
EventID=1 with environment LD_LIBRARY_PATH pointing to
  /tmp /dev/shm /home/* (writable) for a root/SUID process

// /etc/ld.so.preload affecting SUID binaries
// (any .so here loads into SUID-root processes too = root code exec)
EventID=11 (FileModify)
TargetFilename matches: /etc/ld.so.preload

// .so dropped then a SUID/sudo binary executed shortly after
EventID=11 TargetFilename matches: */tmp/*.so OR */dev/shm/*.so
  followed by sudo/SUID execution loading from that path

// Auditd
-w /etc/ld.so.preload -p wa -k ldso_preload
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/sudo -k sudo_exec`,
        kibana: `// LD_PRELOAD present in a sudo invocation environment
process.name: "sudo"
AND process.env_vars: *LD_PRELOAD=*

// Privileged process with LD_LIBRARY_PATH to a writable dir
process.env_vars: (*LD_LIBRARY_PATH=* AND (*tmp* OR *dev/shm* OR */home/*))
AND user.id: "0"

// /etc/ld.so.preload modification (affects SUID processes)
event.module: "file_integrity"
AND file.path: "/etc/ld.so.preload"

// .so in writable path loaded by a root process
event.module: "auditd"
AND auditd.data.name: (*/tmp/*.so* OR */dev/shm/*.so*)
AND auditd.data.euid: "0"

// sudoers env_keep including LD_PRELOAD/LD_LIBRARY_PATH (config risk)
event.module: "file_integrity"
AND file.path: (/etc/sudoers OR /etc/sudoers.d/*)
// then content review for env_keep += "LD_PRELOAD"

// Auditd preload write
event.module: "auditd"
AND tags: "ldso_preload" `,
        powershell: `#!/bin/bash
# T1574.006 - Dynamic linker hijack (privesc angle) hunt

echo "[*] === sudoers env_keep for LD_* (the escalation enabler) ==="
grep -rE "env_keep.*(LD_PRELOAD|LD_LIBRARY_PATH)" \\
  /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -vE "^#"
echo "  (if LD_PRELOAD is kept, any allowed sudo cmd loads attacker .so as root)"

echo ""
echo "[*] === /etc/ld.so.preload (affects SUID-root processes) ==="
if [ -f /etc/ld.so.preload ]; then
  echo "[CRITICAL] exists:"; cat /etc/ld.so.preload
  echo "  mtime: $(stat -c '%y' /etc/ld.so.preload)"
else
  echo "[OK] does not exist"
fi

echo ""
echo "[*] === LD_PRELOAD / LD_LIBRARY_PATH in root process environments ==="
for pid in $(ls /proc | grep -E '^[0-9]+$'); do
  owner=$(stat -c '%U' /proc/$pid 2>/dev/null)
  [ "$owner" = "root" ] || continue
  ld=$(tr '\\0' '\\n' < /proc/$pid/environ 2>/dev/null | grep -E "^LD_PRELOAD=|^LD_LIBRARY_PATH=")
  if echo "$ld" | grep -qE "(tmp|dev/shm|/home)"; then
    echo "[FLAG] root PID $pid ($(cat /proc/$pid/comm 2>/dev/null)): $ld"
  fi
done

echo ""
echo "[*] === World-writable dirs in ld.so.conf search paths ==="
cat /etc/ld.so.conf /etc/ld.so.conf.d/* 2>/dev/null | grep -vE "^#|^include" | \\
  while read d; do
    [ -d "$d" ] && [ -w "$d" ] && echo "[FLAG] writable lib dir in search path: $d"
  done

echo ""
echo "[*] === .so files in writable paths (preload candidates) ==="
find /tmp /dev/shm /var/tmp -name "*.so*" -type f 2>/dev/null | head -20

echo ""
echo "[*] === SUID binaries + their RUNPATH/RPATH (hijackable lib search) ==="
for f in $(find / -perm -4000 -type f 2>/dev/null); do
  rpath=$(readelf -d "$f" 2>/dev/null | grep -E "RPATH|RUNPATH")
  [ -n "$rpath" ] && echo "$f : $rpath"
done | head -20

echo ""
echo "[*] === auditd: ld.so.preload writes ==="
ausearch -k ldso_preload -i --start today 2>/dev/null | tail -20`,
        registry: `Dynamic linker hijack (privesc) artifacts:

Escalation vectors (distinct from execution-side T1106):

1. sudo env_keep LD_PRELOAD passthrough:
   /etc/sudoers with: Defaults env_keep += "LD_PRELOAD"
   Attack: LD_PRELOAD=/tmp/evil.so sudo <allowed-cmd>
   The .so's constructor runs as root.
   Artifact: env_keep LD_PRELOAD in sudoers; .so in /tmp.

2. /etc/ld.so.preload affecting SUID binaries:
   Any .so listed loads into EVERY process - including
   SUID-root binaries. So a low-priv attacker who can write
   ld.so.preload (or already has root and wants persistence)
   gets code execution in root context.
   Artifact: /etc/ld.so.preload exists (should not on clean host).

3. Writable directory in library search path:
   /etc/ld.so.conf.d/*.conf listing a writable dir, OR a
   SUID binary with RPATH/RUNPATH pointing to a writable path.
   Attacker drops a malicious lib with a name the binary loads.
   Artifact: writable dir in ld.so.conf paths; RPATH to /tmp etc.

4. RPATH/RUNPATH hijack on SUID binaries:
   readelf -d <suid_binary> | grep RPATH
   If RPATH is writable, drop a matching .so name there.

Inspection commands:
  ldd <binary>              - libraries a binary loads
  readelf -d <binary>       - RPATH/RUNPATH entries
  cat /etc/ld.so.conf.d/*   - configured search paths
  /proc/<pid>/maps          - libs actually mapped in a process

Relationship to T1106:
  T1106 (Execution) covers LD_PRELOAD for general code exec
  and userland rootkits (Ebury, Azazel). This row is the
  privilege-escalation framing: loading attacker code into a
  PRIVILEGED (root/SUID/sudo) process specifically to escalate.`,
        tools: `Dynamic linker hijacking for escalation:

The privesc-specific framing:
  LD_PRELOAD/LD_LIBRARY_PATH are normally stripped for SUID
  binaries (the linker ignores them for setuid programs - a
  deliberate security measure). So the escalation paths are
  the cases where that protection does NOT apply:

  a) sudo with env_keep += LD_PRELOAD - the sudoers admin
     explicitly preserved it, re-opening the hole. Common
     misconfiguration. Attacker preloads .so → root.
  b) /etc/ld.so.preload - a SYSTEM-WIDE preload file that
     applies even to SUID binaries (it is not the LD_PRELOAD
     env var, so the setuid protection does not strip it).
  c) Writable RPATH/RUNPATH or ld.so.conf dir - the binary's
     own configured search path includes a writable location.

Why SUID strips LD_PRELOAD (and why these bypass it):
  glibc ignores LD_PRELOAD/LD_LIBRARY_PATH from the environment
  for setuid binaries. But /etc/ld.so.preload is a file, not
  an env var, so it still applies. And sudo env_keep re-injects
  the env var into the privileged process explicitly.

Tooling:
  LinPEAS    - checks sudo env_keep, ld.so.preload, writable
               lib paths, and RPATH on SUID binaries
  GTFOBins   - notes which sudo-allowed binaries pair with
               LD_PRELOAD env_keep for escalation

Threat actor use:
  Ebury (the libssl LD_PRELOAD rootkit) is the famous example
  of linker abuse, though primarily for credential theft and
  persistence. The sudo env_keep LD_PRELOAD escalation is a
  classic CTF/pentest finding and appears in real misconfigs.

See T1106 (Execution) for the rootkit/code-exec framing of
the same mechanism.`,
        ossdetect: `Sigma rules:
- proc_creation_lnx_sudo_ld_preload_env_keep.yml
- file_event_lnx_ld_so_preload_modification.yml
- proc_creation_lnx_ld_library_path_priv_process.yml

Elastic detection rules:
- LD_PRELOAD via Sudo env_keep
- Modification of /etc/ld.so.preload
- Shared Library Loaded from Writable Path by Root Process

Config audit (primary controls):
  grep -r env_keep /etc/sudoers /etc/sudoers.d/
    → remove LD_PRELOAD / LD_LIBRARY_PATH from env_keep
  Verify /etc/ld.so.preload does not exist
  Audit RPATH/RUNPATH of SUID binaries (readelf -d)
  Ensure no writable dirs in ld.so.conf paths

Auditd:
  -w /etc/ld.so.preload -p wa -k ldso_preload
  -w /etc/sudoers -p wa -k sudoers
  -a always,exit -F arch=b64 -S execve -F path=/usr/bin/sudo -k sudo_exec

Falco:
  rule: Modify /etc/ld.so.preload
  rule: Sudo with preserved LD_PRELOAD environment

File integrity (AIDE/Tripwire/Wazuh):
  /etc/ld.so.preload, /etc/ld.so.conf, /etc/ld.so.conf.d/
  /etc/sudoers, /etc/sudoers.d/  - alert on any change

rkhunter / chkrootkit:
  Both check /etc/ld.so.preload for rootkit indicators

Atomic Red Team:
  T1574.006 - dynamic linker hijacking tests`,
        notes: "Dynamic linker hijacking for privilege escalation is the privesc-focused framing of the LD_PRELOAD mechanism covered on the Execution page under T1106, and the distinction matters because of an important security control: glibc deliberately ignores the LD_PRELOAD and LD_LIBRARY_PATH environment variables for SUID binaries, precisely to prevent trivial escalation. The escalation paths in this row are therefore the specific cases where that protection does not apply. First and most common is sudo with env_keep += LD_PRELOAD: when a sudoers rule explicitly preserves LD_PRELOAD, it re-injects the variable into the privileged process, so an attacker can preload a malicious shared object that executes as root through any allowed sudo command. Second is /etc/ld.so.preload, which is a file rather than an environment variable - the setuid protection does not strip it, so any library listed there loads into SUID-root processes, granting root-context code execution. Third is a writable directory in the library search path (via ld.so.conf or a SUID binary's RPATH/RUNPATH), where the attacker drops a library with a name the privileged binary loads. The primary controls are configuration audits: remove LD_PRELOAD and LD_LIBRARY_PATH from any sudoers env_keep directive, verify /etc/ld.so.preload does not exist, and check the RPATH/RUNPATH of SUID binaries for writable paths. This row cross-references the T1106 Execution coverage, which addresses the same mechanism from the code-execution and userland-rootkit (Ebury, Azazel) perspective.",
        apt: [
          { cls: "apt-ru", name: "Ebury / Windigo", note: "Canonical example of dynamic linker abuse (libssl LD_PRELOAD); primarily credential theft/persistence but demonstrates the privileged-process injection mechanism." },
          { cls: "apt-mul", name: "Pentest / CTF-documented", note: "sudo env_keep LD_PRELOAD escalation is a classic real-world misconfiguration finding, flagged by LinPEAS and GTFOBins." },
          { cls: "apt-mul", name: "Linux rootkit operators", note: "/etc/ld.so.preload injection used for both root-context execution and persistence across SUID and daemon processes." }
        ],
        cite: "MITRE ATT&CK T1574.006"
      }
    ]
  }
];
