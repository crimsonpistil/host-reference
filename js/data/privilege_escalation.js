// TA0004 - Privilege Escalation
// First pass (Tier 1 - core, high-signal techniques): 10 indicators across 4 techniques
// Built: T1548.002 Bypass UAC (3), T1134 Access Token Manipulation (2),
//        T1055 Process Injection (3), T1068 Exploitation for Priv Esc / BYOVD (2)
// Long-tail techniques (T1543/T1546/T1574 priv-esc angles, T1484, etc.) to follow.

const DATA = [
  {
    id: "T1548.002",
    name: "Abuse Elevation Control Mechanism: Bypass User Account Control",
    desc: "Adversaries bypass UAC to elevate from medium to high integrity without a consent prompt, using auto-elevating binaries, registry hijacks, and trusted-directory mock folders.",
    rows: [
      {
        sub: "T1548.002 - Fodhelper / Computerdefaults Registry Hijack",
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
      }
    ]
  }
];
