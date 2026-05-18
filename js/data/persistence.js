// =====================================================
// MITRE ATT&CK - TA0003 Persistence (Host Reference)
// =====================================================
// Schema matches execution.js:
//   id, name, desc
//   rows[]: sub, indicator, sysmon, kibana, powershell,
//           registry, tools, ossdetect, notes, apt[], cite
// =====================================================

const DATA = [
  {
    id: "T1547.001",
    name: "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
    desc: "Run/RunOnce registry keys, Startup folder LNK and binary persistence, hunting established autostarts",
    rows: [
      {
        sub: "T1547.001 - Real-Time Registry Run Key Modification",
        indicator: "Sysmon EID 13 - registry value written to Run/RunOnce key, especially with target in user-writable path",
        sysmon: `EventID=13
TargetObject matches (any of):
  *\\Microsoft\\Windows\\CurrentVersion\\Run\\*
  *\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*
  *\\Microsoft\\Windows\\CurrentVersion\\RunServices\\*
  *\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce\\*
  *\\Microsoft\\Windows\\CurrentVersion\\Explorer\\
    User Shell Folders\\Startup
  *\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\
    Userinit
  *\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell
  *\\Microsoft\\Windows NT\\CurrentVersion\\Image File
    Execution Options\\*\\Debugger

// Value being written (the Details field) usually
// contains the binary path - check for user-writable
// paths or interpreter invocations:
Details matches:
  *\\AppData\\* OR *\\Temp\\* OR *\\ProgramData\\*
  OR *\\Users\\Public\\*
  OR *powershell* OR *cmd.exe* OR *wscript*
  OR *mshta* OR *rundll32* OR *regsvr32*`,
        kibana: `// Primary: Run key registry modification
winlog.event_id: 13
AND registry.path: (*\\Run\\* OR *\\RunOnce\\* OR *\\RunServices\\* OR *\\RunServicesOnce\\* OR *Userinit OR *\\Winlogon\\Shell OR *\\Image File Execution Options\\*\\Debugger)

// Tighten by suspicious target path / interpreter
winlog.event_id: 13
AND registry.path: (*\\Run\\* OR *\\RunOnce\\*)
AND registry.data.strings: (*\\AppData\\* OR *\\Temp\\* OR *\\ProgramData\\* OR *\\Public\\* OR *powershell* OR *cmd.exe* OR *wscript* OR *mshta* OR *rundll32*)

// Startup folder file write (alternative to registry)
winlog.event_id: 11
AND file.path: (*\\Start Menu\\Programs\\StartUp\\* OR *\\Start Menu\\Programs\\Startup\\*)`,
        powershell: `# Hunt for real-time Run key modifications (Sysmon EID 13)
$autoStartKeys = @(
  '\\Run\\','\\RunOnce\\','\\RunServices\\','\\RunServicesOnce\\',
  'Userinit','Winlogon\\Shell',
  'Image File Execution Options\\.*\\Debugger'
)

Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=13
} | Where-Object {
  $target = $_.Properties[4].Value
  $autoStartKeys | Where-Object { $target -match $_ }
} | Select TimeCreated,
  @{n='TargetKey';e={$_.Properties[4].Value}},
  @{n='Details';e={$_.Properties[5].Value}},
  @{n='Image';e={($_.Properties[3].Value -split '\\\\')[-1]}},
  @{n='User';e={$_.Properties[2].Value}} |
  Sort-Object TimeCreated -Descending

# Startup folder file creates (Sysmon EID 11)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=11
} | Where-Object {
  $_.Properties[0].Value -match 'Start Menu\\\\Programs\\\\Start[Uu]p'
} | Select TimeCreated,
  @{n='File';e={$_.Properties[0].Value}},
  @{n='CreatingProcess';e={$_.Properties[5].Value}}`,
        registry: `Primary autostart registry locations:

User-context (no admin required):
HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce
HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\
  Windows\\Load
HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\
  Windows\\Run

Machine-context (requires admin):
HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run
HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce
HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\
  RunServices
HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\
  RunServicesOnce
HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\
  CurrentVersion\\Run (32-bit equivalent)

Winlogon variants:
HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\
  Winlogon\\Userinit
HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\
  Winlogon\\Shell

Image File Execution Options (IFEO debugger hijack):
HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\
  Image File Execution Options\\<TargetEXE>\\Debugger
  - Value here causes Debugger to launch instead of
    the target EXE when that EXE is invoked
  - Classic abuse: hijack a frequently-run binary

Startup folder file locations:
- All-users startup:
  C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\
    Programs\\StartUp\\
- Per-user startup:
  %APPDATA%\\Microsoft\\Windows\\Start Menu\\
    Programs\\Startup\\
- Anything (.exe/.lnk/.bat/.vbs) here runs at logon`,
        tools: `Almost universal across malware families:
- Commodity malware (Emotet, TrickBot, IcedID,
  QakBot, Agent Tesla, Formbook, etc.)
- Most RATs (NjRAT, DarkComet, Remcos, etc.)
- Most ransomware staging
- Manual operator persistence
- Some legitimate vendor software (false positive source)

Tool / framework support:
- SharPersist (Brian Mulligan):
  Built-in support for all Run key variants
  Standard red team persistence tool
- Empire / Starkiller persistence modules
- Cobalt Strike persistence aggressor scripts
- Metasploit persistence_exe / registry_persistence
- Built-in Windows reg.exe and PowerShell:
  reg add "HKCU\\Software\\Microsoft\\Windows\\
    CurrentVersion\\Run" /v Updater /t REG_SZ
    /d "C:\\Users\\victim\\AppData\\evil.exe"

Common adversary value name patterns:
- Spoofed Microsoft names: "Windows Update",
  "Microsoft Defender", "Adobe Updater"
- Random strings: "svc_a8f3", "winupd_x64"
- Blank or whitespace value names
- Names mimicking installed legitimate software`,
        ossdetect: `Sigma:
- registry_event_run_key_modification.yml
- registry_event_run_key_susp_path.yml
- registry_event_winlogon_userinit_susp_change.yml
- registry_event_ifeo_debugger_set.yml
- file_event_win_startup_folder_persistence.yml

Atomic Red Team:
- T1547.001 (multiple Run key variants tested)
- T1547.001 Test #1 (Run key add via reg.exe)
- T1547.001 Test #5 (Startup folder file drop)

Hayabusa:
- RegistryRunKeyMod rules (EID 13)
- StartupFolderFileWrite rules (EID 11)
- High coverage of the autostart locations

Velociraptor:
- Windows.Sys.AutoRuns (the dedicated artifact)
- Windows.Forensics.Autoruns
- Windows.Registry.NTUser (HKCU enumeration)
- Best fleet-wide tooling for this technique

Sysinternals autoruns.exe:
- The canonical persistence-hunting tool
- Enumerates 200+ autostart locations
- Highlights unsigned entries in red/yellow
- VirusTotal integration for reputation checking
- For manual IR triage - close to essential`,
        notes: "Registry Run Keys + Startup Folders is the single most common persistence technique on Windows - if a piece of malware persists, there's a good chance it's using one of these mechanisms. The technique is so common that detection cannot be 'alert on every Run key modification' - that would be overwhelming. Tune by value-data context: alert on Run key writes where the target path is in AppData/Temp/ProgramData, contains an interpreter (powershell/cmd/wscript/mshta), or matches known suspicious patterns. HKCU variants don't require admin privileges - any compromised user can persist their own session through HKCU\\Run. The IFEO Debugger trick is worth understanding: setting an Image File Execution Options Debugger value causes Windows to launch the Debugger value instead of the original binary when the original is invoked - so hijacking sethc.exe (Sticky Keys), magnify.exe, or osk.exe creates accessibility-feature persistence that triggers from the logon screen. Pair this real-time detection with the next indicator (hunting all locations) for full coverage - real-time catches new persistence as it's installed; hunting catches persistence that was installed before logging started or that bypassed Sysmon coverage.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Registry Run key persistence documented across SolarWinds and other operations." },
          { cls: "apt-cn", name: "APT41", note: "Run key and Winlogon variant persistence documented across operations." },
          { cls: "apt-ir", name: "APT35", note: "Run key persistence documented in CISA advisories on Iranian operations." },
          { cls: "apt-kp", name: "Lazarus", note: "Registry Run key persistence documented across DPRK-attributed operations." },
          { cls: "apt-mul", name: "Commodity Malware", note: "Universal - Emotet, TrickBot, IcedID, QakBot, Agent Tesla, and most RAT families use Run keys." },
          { cls: "apt-mul", name: "Ransomware", note: "Run key persistence documented across nearly all ransomware families." }
        ],
        cite: "MITRE ATT&CK T1547.001"
      },
      {
        sub: "T1547.001 - Hunt Established Autostart Persistence",
        indicator: "Enumerate all known Run keys, RunOnce variants, Startup folders, Winlogon hooks, and IFEO debuggers - find what already persists",
        sysmon: `// This indicator is hunting-oriented - sweeping
// existing autostart locations rather than catching
// new writes in real-time (previous indicator).
//
// Sysmon is not the primary tool here - PowerShell
// enumeration and autoruns.exe are. However, EID 12
// (registry key/value access) can supplement:

EventID=12 (RegistryEvent Object create/delete)
TargetObject=<any Run key path>
// Useful for catching deletion events that hunting
// might miss (adversary cleans up after staging)`,
        kibana: `// EID 13 + EID 12 sweep for any historical activity
// in autostart paths (broader than real-time alerting):
winlog.event_id: (12 OR 13)
AND registry.path: (*\\Run\\* OR *\\RunOnce\\* OR *\\Userinit OR *\\Winlogon\\Shell OR *\\Image File Execution Options\\*)

// Note: live registry enumeration is the better tool
// for this indicator - see PowerShell column
// Kibana shines for the audit-trail / historical
// view of who modified what when`,
        powershell: `# Comprehensive autostart enumeration - live host
# Covers Run keys, Startup folders, Winlogon, IFEO

$results = @()

# Run key variants (HKLM + HKCU + Wow6432Node)
$runKeys = @(
  'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
  'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
  'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices',
  'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce',
  'HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run',
  'HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
  'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
  'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
  'HKCU:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Load',
  'HKCU:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Run'
)

foreach ($key in $runKeys) {
  if (Test-Path $key) {
    $props = Get-ItemProperty $key
    $props.PSObject.Properties | Where-Object {
      $_.Name -notmatch '^PS' -and $_.Value
    } | ForEach-Object {
      $results += [PSCustomObject]@{
        Source = $key
        Name = $_.Name
        Value = $_.Value
      }
    }
  }
}

# Winlogon Userinit + Shell
$winlogon = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'
$results += [PSCustomObject]@{
  Source = 'Winlogon\\Userinit'; Name = 'Userinit'; Value = $winlogon.Userinit
}
$results += [PSCustomObject]@{
  Source = 'Winlogon\\Shell'; Name = 'Shell'; Value = $winlogon.Shell
}

# Image File Execution Options - any Debugger values
Get-ChildItem 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options' |
  ForEach-Object {
    $dbg = (Get-ItemProperty $_.PSPath -Name Debugger -EA SilentlyContinue).Debugger
    if ($dbg) {
      $results += [PSCustomObject]@{
        Source = 'IFEO Debugger'
        Name = $_.PSChildName
        Value = $dbg
      }
    }
  }

# Startup folder contents (both machine and user)
$startupPaths = @(
  "$env:ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp",
  "$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
)
foreach ($path in $startupPaths) {
  if (Test-Path $path) {
    Get-ChildItem $path -File | ForEach-Object {
      $results += [PSCustomObject]@{
        Source = "StartupFolder: $path"
        Name = $_.Name
        Value = $_.FullName
      }
    }
  }
}

# Output and flag suspicious
$results | ForEach-Object {
  $_ | Add-Member -NotePropertyName Suspicious -NotePropertyValue (
    $_.Value -match '(AppData|Temp|ProgramData|\\\\Users\\\\Public|powershell|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32)'
  ) -PassThru
} | Sort-Object Suspicious -Descending | Format-Table -AutoSize`,
        registry: `Same registry paths as previous indicator -
the difference is approach: real-time vs hunting.

Hunting workflow:
1. Run the PowerShell sweep above on the target host
2. Diff against a known-good baseline if available
3. For each result, check:
   - Is the value path signed? (Authenticode check)
   - Is the value path in a standard install location?
   - Does the value name match known legitimate
     software, or is it spoofed/random?
   - When was the registry key last modified?
     (Get-Item <key> | Select LastWriteTime)
4. Suspicious entries: pivot to file analysis
   of the target binary

Baseline approach:
- Export current autostart inventory from a clean
  reference machine: autoruns.exe -a * -ct
- Save as baseline CSV
- Compare against suspect systems with:
  Compare-Object (Import-CSV baseline.csv)
    (Import-CSV suspect.csv) -Property Image
- Diff highlights additions and deletions

Last-write timestamps:
- Each registry KEY has a LastWriteTime
- Useful for narrowing 'when was this persistence
  installed' during IR triage
- Available via:
  (Get-Item <path>).LastWriteTime
  or RegRipper / RECmd for offline registry analysis`,
        tools: `Sysinternals autoruns.exe:
- The definitive tool for this kind of sweep
- Run with: autoruns.exe -a * -accepteula -nobanner -ct > out.csv
- Output columns: Entry Location, Entry, Enabled,
  Description, Publisher, Image Path, Version,
  Time, Hash (MD5/SHA1/SHA256), Virus Total
- Flags unsigned entries in red
- Can submit hashes directly to VirusTotal
- For live host triage - close to mandatory

Velociraptor (fleet-wide):
- Windows.Sys.AutoRuns
- Runs autoruns equivalent across many hosts
- Best for environment-wide persistence sweeps
- Output normalized for cross-host comparison

KAPE (Eric Zimmerman):
- Targets/Compound/AutomaticDestinations.tkape
- AutomaticDestinations target captures Recent
  files / jump lists which can reveal persistence
- Useful for IR forensic timeline building

RegRipper (offline registry analysis):
- Parses registry hives extracted from images
- Plugins for Run keys, Winlogon, services, etc.
- Useful when working from forensic image vs live host

PowerShell native (the script above):
- No tool deploy required
- Works on any modern Windows
- Good for ad-hoc remote IR via WinRM`,
        ossdetect: `Sigma:
- Detection rules in Sigma cover real-time writes
  (previous indicator) - hunting is a manual sweep
  process, not a real-time rule

Atomic Red Team:
- T1547.001 (multiple tests reproduce persistence)
- Use to validate the hunt: install via Atomic,
  then run the PowerShell sweep to confirm it surfaces

Hayabusa:
- Hayabusa rules cover the real-time side
- For hunting use, run autoruns/Velociraptor

Velociraptor:
- Windows.Sys.AutoRuns (dedicated artifact)
- The gold standard for this type of sweep
- Returns parsed autostart entries with
  signature and reputation context

Open-source autoruns hunters:
- Various community PowerShell scripts on GitHub
- ThreatHunting repos by F-Secure, MITRE, Splunk

Reference: SANS poster
'Hunt Evil: Persistence Mechanisms'
- Updated annually with new persistence locations
- Good single-page reference for the technique surface`,
        notes: "Hunting established autostart persistence is one of the most fundamental Windows IR skills - if a host is suspected of being compromised, this sweep is almost always the first or second step. Sysinternals autoruns.exe is the canonical tool because Microsoft maintains its list of autostart locations and it covers 200+ extension points that PowerShell scripts miss. The PowerShell script above covers the high-value subset and is useful when you can't or shouldn't deploy autoruns.exe to a host (forensic preservation, locked-down environments, remote IR via WinRM where pushing a binary is awkward). The baseline-and-diff approach is the highest-fidelity hunting method: capture autoruns output on a known-good reference image, then diff against suspect hosts to surface only the entries that don't appear in the baseline. This collapses a 200-entry autoruns output into 5-10 entries worth investigating. The LastWriteTime trick for registry keys is genuinely useful in incident timelining - it tells you when the persistence was established, which often correlates with initial compromise or lateral movement events visible in other logs.",
        apt: [
          { cls: "apt-mul", name: "Universal", note: "Autostart persistence hunting catches virtually every malware family that survives reboots." },
          { cls: "apt-ru", name: "APT29", note: "Long-dwell operations require persistence hunting for full eviction - SolarWinds investigations relied heavily on autoruns-style sweeps." },
          { cls: "apt-cn", name: "APT41", note: "Multi-stage operations with multiple persistence layers - hunting required to find all of them." },
          { cls: "apt-mul", name: "Red Teams", note: "Red team assessments commonly use established autostart locations - hunting is part of standard defensive validation." }
        ],
        cite: "MITRE ATT&CK T1547.001"
      },
      {
        sub: "T1547.001 - Suspicious Value Names and Spoofing Patterns",
        indicator: "Autostart entry value name mimics legitimate software, contains random strings, or has anomalous characteristics suggesting impersonation",
        sysmon: `// EID 13 with value-name-specific filtering:
EventID=13
TargetObject matches: *\\Run\\*

// Suspicious value name patterns:
// - Spoofing Microsoft/Adobe/Google product names:
ValueName matches:
  *Microsoft* OR *Windows* OR *Defender*
  OR *Update* OR *Adobe* OR *Google*
  OR *Chrome* OR *Firefox*
// AND target path is NOT in expected location:
Details NOT matching:
  C:\\Program Files\\<expected_publisher>\\*
  C:\\Program Files (x86)\\<expected_publisher>\\*

// - Random alphanumeric (machine-generated names):
ValueName matches: [a-z0-9]{8,16} (regex - 8+ random chars)

// - Blank or whitespace-only value names:
ValueName="" OR ValueName=" " OR ValueName matches: ^\\s+$`,
        kibana: `// Run key with potentially spoofed name + wrong path
winlog.event_id: 13
AND registry.path: *\\Run\\*
AND registry.value: (*Microsoft* OR *Windows* OR *Defender* OR *Update* OR *Adobe* OR *Google*)
AND NOT registry.data.strings: ("C:\\\\Program Files\\\\*" OR "C:\\\\Program Files (x86)\\\\*" OR "C:\\\\Windows\\\\*")

// Pure-random-looking value names (regex)
winlog.event_id: 13
AND registry.path: *\\Run\\*
AND registry.value: /^[a-z0-9]{8,16}$/`,
        powershell: `# Hunt for spoofed / suspicious value names in Run keys
$runKeys = @(
  'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
  'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
  'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
  'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
)

# Spoofable product names (commonly impersonated)
$spoofableNames = 'Microsoft|Windows|Defender|Update|Adobe|Google|Chrome|Firefox|Apple|iTunes|Skype|Office|OneDrive|Dropbox|Java'

# Expected publishers for each spoofed name
$expectedPaths = @{
  'Microsoft' = 'Program Files\\\\(Microsoft|Common Files)'
  'Windows'   = 'C:\\\\Windows\\\\'
  'Adobe'     = 'Program Files\\\\Adobe'
  'Google'    = 'Program Files\\\\Google'
  'Chrome'    = 'Program Files\\\\Google\\\\Chrome'
}

foreach ($key in $runKeys) {
  if (Test-Path $key) {
    $props = Get-ItemProperty $key
    $props.PSObject.Properties | Where-Object {
      $_.Name -notmatch '^PS' -and $_.Value
    } | ForEach-Object {
      $name = $_.Name
      $value = $_.Value -as [string]
      $suspicious = @()

      # Check 1: spoofed name with wrong path
      if ($name -match $spoofableNames) {
        $matchedTerm = $matches[0]
        $expected = $expectedPaths[$matchedTerm]
        if ($expected -and $value -notmatch $expected) {
          $suspicious += "Spoof: name=$matchedTerm but path doesn't match expected $expected"
        }
      }

      # Check 2: random-looking value name
      if ($name -match '^[a-z0-9]{8,16}$') {
        $suspicious += "Random value name: $name"
      }

      # Check 3: blank/whitespace name
      if ([string]::IsNullOrWhiteSpace($name) -or $name -match '^\\s+$') {
        $suspicious += "Blank or whitespace value name"
      }

      # Check 4: value path in user-writable directory
      if ($value -match '(AppData|Temp|ProgramData|Public)') {
        $suspicious += "Value in user-writable path"
      }

      # Check 5: value path is an interpreter
      if ($value -match '(powershell|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32)') {
        $suspicious += "Value invokes interpreter"
      }

      if ($suspicious.Count -gt 0) {
        [PSCustomObject]@{
          Key   = $key
          Name  = $name
          Value = $value
          Suspicious = ($suspicious -join '; ')
        }
      }
    }
  }
}`,
        registry: `Adversary value name patterns documented in
real-world incidents:

Spoofed Microsoft/system product names:
- "Microsoft Defender", "WindowsDefender",
  "WinDefender" (often with path NOT in C:\\Program
  Files\\Windows Defender\\)
- "Windows Update", "WindowsUpdater", "WinUpdate"
- "Microsoft Office Update Service"
- "Microsoft Edge Update"
- "OneDriveStandaloneUpdater"

Spoofed third-party product names:
- "Adobe Updater", "AdobeARMservice"
- "Google Update", "GoogleUpdaterTaskMachine"
- "iTunes Helper", "Apple Push"
- "Skype Helper"
- "Chrome Helper", "ChromeUpdater"

Random / machine-generated names:
- 8-16 character lowercase alphanumeric strings
- GUID-format strings (sometimes)
- Names matching the executable filename
  (poor opsec - the value name matching the EXE
  name is a tell)

Blank/whitespace abuse:
- Some malware uses empty string value names
- Older Windows versions render these as blanks
  in regedit, making them visually 'hidden'
- This is detectable; regedit lists them but
  with empty Name field

Hunt with: combine the PowerShell scan with
manual investigation of any flagged entries.
Pattern-match alone has false positives -
investigation confirms.`,
        tools: `Adversary tradecraft using these patterns:

Manual operators:
- Choose value names to blend in with installed
  software fingerprint of the target
- Adjust naming based on what runs on the host
  (recon first, persist with matching names)

Commodity malware default names (don't always bother
to spoof - just use whatever the loader picks):
- Emotet variants: random or product-mimicking
- IcedID: often impersonates Microsoft/Adobe
- QakBot: random alphanumeric
- Agent Tesla: varies by sample

Red team tools:
- SharPersist supports custom value names
- Cobalt Strike aggressor scripts allow naming
  control for value entries
- Empire persistence modules

Legitimate software that this hunt may flag
(tune accordingly):
- Hardware vendor utilities with random IDs in
  value names (Dell, HP, Lenovo)
- Some game launchers
- IT management agents with non-standard install
  paths and generic-sounding names`,
        ossdetect: `Sigma:
- registry_event_run_key_susp_value_name.yml
- registry_event_run_key_susp_path.yml
- registry_event_susp_run_key_spoofed_name.yml

Atomic Red Team:
- T1547.001 (tests cover varied value naming)

Hayabusa:
- RegistryRunKeyMod rules
- Generic patterns; manual investigation needed
  for the spoofing-detection cases

Velociraptor:
- Windows.Sys.AutoRuns
- Output includes Publisher field; cross-reference
  against ExpectedPublisher for each value name

YARA / static analysis:
- Many YARA rules exist for malware families
  that use specific value name patterns
- Useful for tying a Run key entry back to a
  specific known family

Reference: SANS DFIR
'Windows Registry Forensics' poster
- Comprehensive coverage of Run key abuse patterns`,
        notes: "Value name analysis is a behavioral fingerprinting approach to autostart hunting - it asks 'does this entry look like something a legitimate vendor would create, or does it look like an adversary's attempt to blend in?' The detection is necessarily fuzzy because legitimate software does occasionally use random-looking or generic value names, and adversaries with good opsec choose names that match the actual installed software on the target host. The strongest signals combine multiple flags: a Microsoft-sounding value name pointing to a binary in AppData is high-confidence malicious; a Microsoft-sounding value name pointing to a binary in C:\\Program Files\\Microsoft is probably legitimate. The 'name spoof + path mismatch' pattern is the highest-value single check because legitimate Microsoft software is consistently installed under Program Files paths, never in user-writable directories. Pair this hunt with the previous indicator's general autostart sweep - this indicator adds the spoofing/naming dimension that pure path-based detection might miss. False positives are inherent here - run this as a triage prioritizer, not a final alert.",
        apt: [
          { cls: "apt-mul", name: "Commodity Malware", note: "Most malware families use spoofed value names - product-name impersonation is universal tradecraft." },
          { cls: "apt-kp", name: "Lazarus", note: "Documented use of spoofed Microsoft / Adobe value names for Run key persistence." },
          { cls: "apt-cn", name: "APT41", note: "Value name spoofing documented across operations - matched to target environment's installed software." },
          { cls: "apt-ir", name: "APT35", note: "Spoofed legitimate software names documented in CISA advisories on Iranian operations." },
          { cls: "apt-mul", name: "Red Teams", note: "Custom value naming to blend with target environment is standard red team persistence opsec." }
        ],
        cite: "MITRE ATT&CK T1547.001"
      }
    ]
  },
  {
    id: "T1546.003",
    name: "Event Triggered Execution: WMI Event Subscription",
    desc: "Hunting established WMI event filter/consumer/binding persistence in the WMI repository",
    rows: [
      {
        sub: "T1546.003 - Live Enumeration of WMI Event Subscriptions",
        indicator: "Direct query of WMI subscription namespaces (root\\subscription) on live host - find established filter/consumer/binding triples",
        sysmon: `// This indicator is hunting-oriented - PowerShell
// WMI queries against live host, not Sysmon detection.
//
// Sysmon detects subscription CREATION in real-time via
// EID 19/20/21 (covered in T1047). This indicator
// finds subscriptions that were established BEFORE
// Sysmon coverage began, or in environments where
// Sysmon WMI monitoring is not enabled.
//
// Sysmon contribution: re-check EID 19/20/21 history
// during incident investigation:

EventID=19 OR EventID=20 OR EventID=21
// Filter on Operation=Created
// Useful for retroactive timeline of when a
// subscription was established`,
        kibana: `// Historical Sysmon EID 19/20/21 events
// (find when a subscription was registered):
winlog.event_id: (19 OR 20 OR 21)
AND winlog.event_data.Operation: "Created"

// Cross-reference subscription Name field
// across all three events to build the
// filter + consumer + binding triple:
winlog.event_id: (19 OR 20 OR 21)
AND winlog.event_data.Name: "<suspicious_name>"`,
        powershell: `# Enumerate all WMI event subscriptions on live host
# Run with admin privileges for full namespace access

Write-Host "=== Event Filters (triggers) ===" -ForegroundColor Cyan
Get-WMIObject -Namespace root\\subscription -Class __EventFilter |
  Select Name, Query, QueryLanguage, EventNamespace

Write-Host "\`n=== Event Consumers (actions) ===" -ForegroundColor Cyan
Get-WMIObject -Namespace root\\subscription -Class __EventConsumer |
  Select Name, __CLASS,
    @{n='CommandLine';e={$_.CommandLineTemplate}},
    @{n='ScriptText';e={$_.ScriptText}},
    @{n='ScriptFileName';e={$_.ScriptFileName}}

Write-Host "\`n=== Filter-Consumer Bindings (armed subscriptions) ===" -ForegroundColor Cyan
Get-WMIObject -Namespace root\\subscription -Class __FilterToConsumerBinding |
  Select Filter, Consumer

# Also check other namespaces sometimes used:
Write-Host "\`n=== root\\default subscriptions ===" -ForegroundColor Cyan
Get-WMIObject -Namespace root\\default -Class __EventFilter -EA SilentlyContinue
Get-WMIObject -Namespace root\\default -Class __EventConsumer -EA SilentlyContinue

# Suspicious patterns to flag:
$consumers = Get-WMIObject -Namespace root\\subscription -Class __EventConsumer
foreach ($c in $consumers) {
  $suspicious = @()

  # CommandLineEventConsumer or ActiveScriptEventConsumer
  # are the two execution-capable consumer types
  if ($c.__CLASS -eq 'CommandLineEventConsumer' -or
      $c.__CLASS -eq 'ActiveScriptEventConsumer') {
    $suspicious += "Execution-capable consumer type"
  }

  # Command line points to interpreter or user-writable path
  if ($c.CommandLineTemplate -match
    '(powershell|cmd\\.exe|wscript|cscript|mshta|rundll32|AppData|Temp|ProgramData)') {
    $suspicious += "Suspicious target in CommandLineTemplate"
  }

  # Inline ScriptText present (ActiveScriptEventConsumer)
  if ($c.ScriptText) {
    $suspicious += "Inline script content - no file artifact"
  }

  # Name not matching known-good vendor pattern
  if ($c.Name -match '^[a-z0-9]{8,}$' -or
      [string]::IsNullOrWhiteSpace($c.Name)) {
    $suspicious += "Random or blank consumer name"
  }

  if ($suspicious.Count -gt 0) {
    [PSCustomObject]@{
      Name = $c.Name
      Class = $c.__CLASS
      Suspicious = ($suspicious -join '; ')
      Detail = ($c.CommandLineTemplate, $c.ScriptText, $c.ScriptFileName |
                Where-Object { $_ } | Select-Object -First 1)
    }
  }
}`,
        registry: `WMI repository - the underlying database:
C:\\Windows\\System32\\wbem\\Repository\\
  OBJECTS.DATA  - main object store (binary)
  INDEX.BTR     - B-tree index
  INDEX.MAP     - index map
  MAPPING1.MAP  - namespace mapping
  MAPPING2.MAP  - namespace mapping

The repository is NOT human-readable and is NOT
in the registry despite the name 'WMI Event
Subscription' suggesting registry storage.

Offline analysis tools (forensic image investigation):
- PyWMIPersistenceFinder (David Reaves / Mandiant)
  python PyWMIPersistenceFinder.py OBJECTS.DATA
  Parses the binary repository and lists all
  filter/consumer/binding triples
- WMI-Forensics (Python toolkit)
- Velociraptor Windows.Forensics.WMIPersistence
  (fleet-wide artifact)

Live host alternative:
- mofcomp.exe can compile/decompile MOF files
- Get-WMIObject queries (PowerShell - shown above)
- wmic /namespace:\\\\root\\subscription path
  __EventFilter (command line equivalent)

Legitimate subscription namespaces:
- root\\ccm (SCCM - Microsoft Configuration Manager)
- root\\cimv2\\sms (SMS/SCCM)
- root\\McAfee (McAfee AV - if installed)
- Vendor-specific namespaces from installed AV/EDR
- Build allowlist from clean-baseline environment

Adversary-favored namespace:
- root\\subscription is the canonical persistence
  location - if you see subscriptions here that
  aren't tied to known IT/security software, treat
  as suspicious until proven otherwise`,
        tools: `Live-host enumeration tools:

Get-WMIObject (PowerShell - shown in script):
- Built-in, no deploy required
- Returns objects with full property access
- Works on any Windows with PowerShell 2.0+

wmic.exe (legacy, deprecated Win11 24H2):
wmic /namespace:\\\\root\\subscription path __EventFilter get /value
wmic /namespace:\\\\root\\subscription path __EventConsumer get /value
wmic /namespace:\\\\root\\subscription path __FilterToConsumerBinding get /value

Sysinternals autoruns.exe:
- WMI tab lists all event subscriptions
- Highlights non-Microsoft entries
- VirusTotal lookup on consumer command lines
- Excellent triage tool for live hosts

Velociraptor:
- Windows.Forensics.WMIPersistence
  (live host enumeration with parsing)
- Fleet-wide deployment for environment-wide hunt
- Single best tool for hunting this technique
  across many systems

KAPE (Eric Zimmerman):
- Targets/Compound/RegistryHives.tkape
  (collects related artifacts)
- Combined with WMI repository extraction
  for forensic timeline

Offline (from forensic images):
- PyWMIPersistenceFinder
- WMI-Forensics (Mandiant)
- Both parse the binary repository extracted
  from a disk image
- Useful when working post-incident from a
  full forensic capture`,
        ossdetect: `Sigma:
- Sigma rules cover real-time EID 19/20/21
  (handled in T1047)
- Hunting via live enumeration is a manual
  workflow, not a real-time rule

Atomic Red Team:
- T1546.003 (subscription persistence tests)
- Use to validate the hunt: install subscription
  via Atomic, then run PowerShell sweep to confirm
  it surfaces in your detection

Hayabusa:
- WMISubscriptionRegistration rules (real-time)
- For hunting, manual enumeration is the approach

Velociraptor:
- Windows.Forensics.WMIPersistence
  (the gold-standard hunting artifact)
- Parses subscription objects from live WMI
- Returns filter Query, consumer command/script,
  and binding relationships

MITRE / community references:
- Mandiant 2014 paper:
  'WMI Offense, Defense, and Forensics' (Ballenthin
  / Graeber / Teodorescu) - foundational research
- DEF CON 23 talk on WMI persistence
- These remain canonical references for the
  technique 10+ years later`,
        notes: "This indicator is the hunting counterpart to the real-time WMI subscription detection in T1047 - same technique, different question. T1047 asks 'is a subscription being created right now?' This indicator asks 'what subscriptions exist on this host today?' For incident response, the live enumeration approach is genuinely essential because WMI persistence can be established before any Sysmon coverage existed, or in environments where Sysmon WMI monitoring is not configured. The Get-WMIObject query against root\\subscription returns the full subscription inventory in seconds and is one of the highest-value single commands in Windows IR. The suspicious-pattern flagging in the script (CommandLineEventConsumer + interpreter path + random name) catches the typical adversary pattern while letting legitimate SCCM/AV subscriptions pass through. The hardest part of this hunt is baseline establishment: every environment has different legitimate WMI subscriptions from installed software, so 'alert on anything in root\\subscription' is too noisy in practice. Capture a baseline from a clean reference host, then diff suspect systems against it. PyWMIPersistenceFinder is the canonical offline tool when you're working from a forensic image rather than a live host - the Mandiant 2014 paper on WMI persistence is the foundational reference and remains accurate.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "WMI subscription persistence documented across long-dwell espionage operations including SolarWinds." },
          { cls: "apt-cn", name: "APT41", note: "WMI event subscriptions used for persistence across multiple sector intrusions." },
          { cls: "apt-mul", name: "Turla", note: "Heavy use of WMI persistence documented in long-term espionage campaigns." },
          { cls: "apt-mul", name: "FIN6", note: "WMI subscription persistence documented in financial sector intrusions." },
          { cls: "apt-mul", name: "Red Teams", note: "WMI subscription is standard red team persistence due to forensic evasiveness." }
        ],
        cite: "MITRE ATT&CK T1546.003"
      },
      {
        sub: "T1546.003 - Suspicious Consumer Patterns and Trigger Analysis",
        indicator: "WMI consumer with execution-capable type pointing to interpreter, or filter with persistence-intent trigger (system boot, logon, perfdata polling)",
        sysmon: `// Real-time Sysmon detection of suspicious patterns
// during subscription creation (EID 19/20/21):

EventID=20 (Consumer Created)
Type=CommandLineEventConsumer OR ActiveScriptEventConsumer
// These two consumer types execute code -
// other consumer types (NTEventLogEventConsumer,
// SMTPEventConsumer, LogFileEventConsumer)
// don't execute attacker code directly

EventID=19 (Filter Created)
// Suspicious filter queries indicating persistence:
Query matches (any of):
  *__InstanceCreationEvent* (process / file create triggers)
  *__InstanceModificationEvent* (state change triggers)
  *Win32_LocalTime* (time-based triggers)
  *Win32_PerfFormattedData_PerfOS_System*
    (uptime-based triggers - fires after N seconds boot)
  *Win32_LogonSession* (logon triggers)`,
        kibana: `// Real-time: dangerous consumer types
winlog.event_id: 20
AND winlog.event_data.Type: ("CommandLineEventConsumer" OR "ActiveScriptEventConsumer")

// Real-time: persistence-intent filter queries
winlog.event_id: 19
AND winlog.event_data.Query: (*__InstanceCreationEvent* OR *__InstanceModificationEvent* OR *Win32_LocalTime* OR *Win32_PerfFormattedData* OR *Win32_LogonSession*)

// Cross-correlate: pair a suspicious filter (EID 19)
// with a CommandLine/Script consumer (EID 20) and
// a binding (EID 21) within a short time window =
// armed persistence subscription`,
        powershell: `# Hunt for suspicious consumer + filter pairings on live host

# 1. Inventory all execution-capable consumers
$execConsumers = Get-WMIObject -Namespace root\\subscription -Class __EventConsumer |
  Where-Object {
    $_.__CLASS -eq 'CommandLineEventConsumer' -or
    $_.__CLASS -eq 'ActiveScriptEventConsumer'
  }

# 2. Pull all filters
$filters = Get-WMIObject -Namespace root\\subscription -Class __EventFilter

# 3. Pull all bindings (the link between filters and consumers)
$bindings = Get-WMIObject -Namespace root\\subscription -Class __FilterToConsumerBinding

# 4. Reconstruct armed subscriptions (filter + consumer + binding triple)
foreach ($binding in $bindings) {
  # Binding properties reference objects via __RELPATH
  $filterPath = $binding.Filter
  $consumerPath = $binding.Consumer

  $filterName = $filterPath -replace '.*Name="([^"]+)".*','$1'
  $consumerName = $consumerPath -replace '.*Name="([^"]+)".*','$1'

  $filter = $filters | Where-Object { $_.Name -eq $filterName }
  $consumer = $execConsumers | Where-Object { $_.Name -eq $consumerName }

  if ($consumer) {
    # This is an execution-capable armed subscription
    [PSCustomObject]@{
      FilterName = $filterName
      FilterQuery = $filter.Query
      ConsumerName = $consumerName
      ConsumerClass = $consumer.__CLASS
      Action = if ($consumer.CommandLineTemplate) {
                 $consumer.CommandLineTemplate
               } else {
                 $consumer.ScriptText
               }
      TriggerType = switch -Regex ($filter.Query) {
        '__InstanceCreationEvent' { 'Object created (process/file)' }
        '__InstanceModificationEvent' { 'State change' }
        'Win32_LocalTime' { 'Time-based' }
        'Win32_PerfFormattedData' { 'Uptime / perfdata polling' }
        'Win32_LogonSession' { 'Logon event' }
        default { 'Other' }
      }
    }
  }
}`,
        registry: `No registry artifacts - all data is in the
WMI repository binary files.

Consumer type analysis - what each does:

CommandLineEventConsumer:
- Runs an arbitrary command via the Win32_Process
  Create method when the bound filter fires
- CommandLineTemplate property = the command
- Highest-risk consumer type
- Example: cmd /c C:\\evil.exe

ActiveScriptEventConsumer:
- Runs inline VBScript or JScript when the bound
  filter fires
- ScriptText property = the inline code
- ScriptFileName property = optional file path
  (less common; most adversary use is inline)
- High-risk; no file artifact when inline

NTEventLogEventConsumer:
- Writes to Windows Event Log
- Not directly attacker-executable
- Lower-risk classification

SMTPEventConsumer:
- Sends email
- Not directly attacker-executable
- Could be used for data exfiltration but rare

LogFileEventConsumer:
- Writes to a text file
- Not directly attacker-executable

Filter query patterns and their meaning:

__InstanceCreationEvent + Win32_Process:
- Fires when ANY process is created
- Adversary use: 'every time notepad.exe runs,
  also run my code'

__InstanceModificationEvent + Win32_PerfFormattedData_PerfOS_System:
- Fires when system uptime crosses N seconds
- Adversary use: 'run my code 5 minutes after
  every boot' (classic boot-persistence trigger)

__InstanceCreationEvent + __TimerEvent / Win32_LocalTime:
- Time-based triggers
- Adversary use: scheduled-task-like behavior
  without a scheduled task artifact`,
        tools: `Subscription persistence frameworks:

PowerSploit / Empire:
- New-UserPersistenceOption -WMI
- Creates CommandLineEventConsumer with logon trigger
- Documented adversary tradecraft

WMI-Persistence (Matt Graeber / Justin Warner):
- PowerShell module for WMI persistence creation
- Multiple trigger types supported
- Reference for understanding the technique

SharPersist:
- /t wmi flag adds WMI subscription
- Standard red team persistence option

Cobalt Strike:
- Aggressor scripts for WMI persistence
- Multiple trigger and consumer combinations

Manual operator pattern:
- Create filter using stable trigger
  (perf data polling or logon event)
- Create CommandLineEventConsumer pointing
  to staged payload
- Bind them together
- Subscription persists until explicitly removed
- No registry entry, no scheduled task,
  no startup folder file - invisible to most
  standard persistence checks

Defensive note - subscription removal:
Remove-WmiObject -Namespace root\\subscription
  -Class __FilterToConsumerBinding
  -Filter "Filter='...'"
(removes the binding; filter/consumer remain
 unless removed separately)`,
        ossdetect: `Sigma:
- sysmon_wmi_susp_consumer_type.yml (EID 20)
- sysmon_wmi_susp_filter_query.yml (EID 19)
- sysmon_wmi_persistence_binding.yml (EID 21)

Atomic Red Team:
- T1546.003 (multiple subscription persistence tests)
- T1546.003 Test #1 (CommandLineEventConsumer + filter)
- T1546.003 Test #5 (ActiveScriptEventConsumer)

Hayabusa:
- WMIDangerousConsumerType rules
- WMISuspFilterQuery detection

Velociraptor:
- Windows.Forensics.WMIPersistence
  (returns parsed subscriptions with consumer
  type and filter query exposed for analysis)

Foundational research:
- 'WMI Offense, Defense, and Forensics' -
  William Ballenthin, Matt Graeber, Claudiu
  Teodorescu (Mandiant, 2014)
- The single most cited reference for WMI
  persistence detection
- Still accurate today; the technique
  hasn't fundamentally changed

DEF CON / Black Hat talks:
- Various WMI persistence talks 2014-2018
- All build on the Mandiant 2014 foundation`,
        notes: "This indicator narrows the WMI subscription hunt to the highest-risk subset: consumers with execution capability (CommandLineEventConsumer, ActiveScriptEventConsumer) paired with filters that have persistence intent (boot triggers, logon triggers, periodic polling). The 'trigger type' classification in the PowerShell script is genuinely useful for triage: a boot-uptime trigger (Win32_PerfFormattedData_PerfOS_System) paired with a CommandLineEventConsumer running powershell is the classic adversary persistence pattern documented across many incidents. The reverse - benign trigger types like '__InstanceModificationEvent + a tracked legitimate object' paired with NTEventLogEventConsumer - is more often a legitimate monitoring or AV subscription. Subscription persistence is genuinely hard to detect without targeted hunting because Sysmon's WMI monitoring (EID 19/20/21) requires explicit config-level opt-in and many Sysmon deployments don't include it. Velociraptor's Windows.Forensics.WMIPersistence artifact is the single most valuable tool for fleet-wide hunting of this technique. The Mandiant 2014 paper remains the foundational reference - if you want to dig deeper into the technique, it's the canonical read.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Persistence-intent WMI subscriptions with boot triggers documented across long-dwell operations." },
          { cls: "apt-cn", name: "APT41", note: "WMI subscription with boot/logon triggers documented in sector-targeting intrusions." },
          { cls: "apt-mul", name: "Turla", note: "Sophisticated WMI subscription persistence documented across espionage campaigns." },
          { cls: "apt-mul", name: "FIN6", note: "WMI persistence with CommandLineEventConsumer documented in financial sector cases." },
          { cls: "apt-mul", name: "Red Teams", note: "Boot-trigger + interpreter consumer is the canonical WMI persistence pattern - standard tradecraft." }
        ],
        cite: "MITRE ATT&CK T1546.003"
      }
    ]
  },
  {
    id: "T1543.003",
    name: "Create or Modify System Process: Windows Service",
    desc: "Hunting established services with suspicious config - baseline deviation, binary path analysis, hidden service detection",
    rows: [
      {
        sub: "T1543.003 - Service Inventory with Suspicious Configuration",
        indicator: "Enumerate all registered services and flag those with non-standard paths, unsigned binaries, blank descriptions, or other anomalous configuration",
        sysmon: `// This indicator is hunting-oriented - PowerShell
// registry sweep, not Sysmon detection.
//
// Sysmon detects service CREATION in real-time via
// EID 13 (Run/Services registry write) and Windows
// System Event 7045 - both covered in T1569.002.
// This indicator finds services that were established
// before logging coverage began.
//
// Sysmon contribution: re-check service event history:

EventID=13 (registry value set)
TargetObject=*\\Services\\*\\ImagePath
// Useful for retroactive timeline of when a
// service was installed or modified

// Windows System Event 7045 (service installed):
EventID=7045
LogName=System
// Captures all service installations including
// those by sc.exe, PowerShell New-Service,
// PsExec PSEXESVC, and direct API calls`,
        kibana: `// Historical Sysmon EID 13 for service registry writes
winlog.event_id: 13
AND registry.path: *\\Services\\*\\ImagePath

// Windows System Event 7045 (all service installs)
winlog.event_id: 7045
AND winlog.channel: "System"

// Filter to suspicious service file paths
winlog.event_id: 7045
AND winlog.event_data.ImagePath: (*\\AppData\\* OR *\\Temp\\* OR *\\ProgramData\\* OR *\\Public\\* OR *powershell* OR *cmd.exe* OR *rundll32* OR *mshta*)`,
        powershell: `# Comprehensive service inventory hunt - flag suspicious config

$results = @()

# Pull all services with their full registry config
Get-ChildItem "HKLM:\\SYSTEM\\CurrentControlSet\\Services" | ForEach-Object {
  $svc = $_
  $props = Get-ItemProperty $svc.PSPath -ErrorAction SilentlyContinue
  if (-not $props.ImagePath) { return }

  $name = $svc.PSChildName
  $ipRaw = $props.ImagePath
  # Strip leading quotes, extract just the binary path
  $ipPath = $ipRaw.TrimStart('"') -replace '^([^"]+).*','$1'
  $ipPath = [System.Environment]::ExpandEnvironmentVariables($ipPath)

  $suspicious = @()

  # Check 1: ImagePath in user-writable directory
  if ($ipPath -match '(AppData|Temp|ProgramData|\\\\Users\\\\Public|\\\\Downloads)') {
    $suspicious += "ImagePath in user-writable path"
  }

  # Check 2: ImagePath outside standard system/program dirs
  $standardPaths = @('C:\\\\Windows\\\\','C:\\\\Program Files\\\\','C:\\\\Program Files \\(x86\\)\\\\')
  $inStandard = $false
  foreach ($p in $standardPaths) {
    if ($ipPath -match "^$p") { $inStandard = $true; break }
  }
  if (-not $inStandard) {
    $suspicious += "ImagePath outside standard directories"
  }

  # Check 3: ImagePath is an interpreter (LOLBin service)
  if ($ipPath -match '(powershell|cmd\\.exe|wscript|cscript|mshta|rundll32|regsvr32)\\.exe$') {
    $suspicious += "Service wraps interpreter (LOLBin pattern)"
  }

  # Check 4: Binary unsigned (check Authenticode)
  if (Test-Path $ipPath) {
    $sig = Get-AuthenticodeSignature $ipPath -ErrorAction SilentlyContinue
    if ($sig.Status -ne 'Valid') {
      $suspicious += "Binary unsigned or invalid signature ($($sig.Status))"
    }
  } else {
    $suspicious += "Binary file does not exist at ImagePath"
  }

  # Check 5: Blank Description and DisplayName (anomalous)
  if ([string]::IsNullOrWhiteSpace($props.Description) -and
      [string]::IsNullOrWhiteSpace($props.DisplayName)) {
    $suspicious += "Blank Description AND DisplayName"
  }

  # Check 6: Auto-start service with no DependOnService
  # (anomalous for non-Microsoft services)
  if ($props.Start -eq 2 -and -not $props.DependOnService -and
      $ipPath -notmatch 'C:\\\\Windows\\\\') {
    $suspicious += "Auto-start with no dependencies, non-system path"
  }

  if ($suspicious.Count -gt 0) {
    $results += [PSCustomObject]@{
      ServiceName = $name
      DisplayName = $props.DisplayName
      ImagePath = $ipRaw
      StartType = switch ($props.Start) {
        0 {'Boot'} 1 {'System'} 2 {'Auto'}
        3 {'Demand'} 4 {'Disabled'} default {$_}
      }
      RunAs = $props.ObjectName
      Description = $props.Description
      Suspicious = ($suspicious -join '; ')
    }
  }
}

$results | Sort-Object ServiceName | Format-Table -AutoSize`,
        registry: `Service registry structure:
HKLM\\SYSTEM\\CurrentControlSet\\Services\\<ServiceName>\\
  ImagePath     - binary path + arguments
  Start         - 0=Boot, 1=System, 2=Auto, 3=Demand, 4=Disabled
  Type          - 0x10=Win32OwnProcess, 0x20=Win32ShareProcess (svchost),
                  0x110=interactive Win32OwnProcess
  ObjectName    - run-as account (LocalSystem, NetworkService, etc.)
  Description   - human-readable description
  DisplayName   - shown in services.msc
  DependOnService - service dependencies (REG_MULTI_SZ)
  ErrorControl  - error handling on failure

Service hunting workflow:
1. Run the PowerShell sweep above
2. For each flagged service, investigate:
   - File hash of ImagePath binary (VirusTotal lookup)
   - When was the service key last modified?
     (Get-Item <key> | Select LastWriteTime)
   - Process activity history for that service name
   - Network connections from service process

Baseline approach:
- Capture service inventory on known-good reference
  system: Get-Service | Export-CSV baseline.csv
- Diff suspect host:
  Compare-Object (Import-CSV baseline.csv)
    (Get-Service | Select Name,DisplayName)
- New service entries warrant investigation

Last-write timestamps for IR timelining:
(Get-Item "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\<name>").LastWriteTime
- Tells you when the service was installed or last
  modified - useful for correlating with other
  intrusion timeline events

Standard service binary locations:
- C:\\Windows\\System32\\
- C:\\Windows\\SysWOW64\\
- C:\\Program Files\\<vendor>\\
- C:\\Program Files (x86)\\<vendor>\\
- Anything else = investigate`,
        tools: `Hunting / enumeration tools:

PowerShell (the script above):
- No tool deploy required
- Works on any Windows
- Best for ad-hoc IR triage

Sysinternals autoruns.exe:
- Services tab - all registered services
- Highlights unsigned and unverified binaries
- VirusTotal integration for reputation
- Single best tool for manual triage

Velociraptor:
- Windows.System.Services
  (full service enumeration artifact)
- Returns ImagePath, signature status, last-write
  time, and dependencies for each service
- Best for fleet-wide service hunting

KAPE (Eric Zimmerman):
- Targets/Compound/SystemHive.tkape
  (collects SYSTEM registry hive for offline analysis)
- Combined with RECmd plugins for service enumeration

Sigma rules apply mostly to creation-time
detection (covered in T1569.002) - hunting
established services is more of a manual workflow

Adversary tool patterns to recognize:
- Cobalt Strike services: random short names,
  ImagePath often points to a DLL via rundll32,
  or to a small EXE in user-writable location
- PSEXESVC: well-known PsExec pattern (C:\\Windows\\PSEXESVC.exe)
- SharPersist: configurable but typically uses
  legitimate-sounding names with binaries in
  C:\\ProgramData
- Empire / Metasploit: predictable naming patterns
  (mostly addressed by their respective module docs)`,
        ossdetect: `Sigma:
- Real-time detection rules cover creation
  (proc_creation_win_sc_service_creation_*.yml)
- Hunting existing services is a manual workflow

Atomic Red Team:
- T1543.003 Test #1 (sc.exe service creation)
- T1543.003 Test #2 (PowerShell New-Service)
- Use to validate the hunt: install service via
  Atomic, run the PowerShell sweep, confirm it
  surfaces in your detection

Hayabusa:
- ServiceCreationSuspBinPath rules (real-time)
- For hunting, use PowerShell or autoruns

Velociraptor:
- Windows.System.Services (best fleet-wide artifact)
- Returns full service config including signature
  status for each ImagePath binary

Reference - SANS DFIR poster:
'Windows Services Forensics'
- Comprehensive coverage of service abuse patterns
- Annual updates with new techniques

Microsoft documentation:
- Service security and access rights
- Useful for understanding the technique surface`,
        notes: "Service hunting is one of the most important persistence-detection workflows in Windows IR. The PowerShell sweep covers the high-fidelity flags: services with binaries in user-writable paths, services wrapping interpreters (LOLBin pattern), unsigned binaries, missing files (orphaned service entries), blank metadata. Each flag alone is moderate confidence; multiple flags on the same service is high confidence. The baseline-and-diff approach is especially powerful for services because legitimate service inventories are stable over time - the same set of services with the same configs runs on every workstation of the same build. Deviations from baseline are immediately suspicious. The unsigned binary check is particularly useful: legitimate Microsoft and major-vendor services are virtually always Authenticode-signed. An unsigned binary running as a service is rare in enterprise environments outside of in-house developed software. Pair this hunt with autoruns.exe for the highest coverage - autoruns includes services in its 200+ autostart inventory and adds VirusTotal reputation lookups that the PowerShell sweep doesn't have. The last-write timestamp trick on the service registry key is genuinely useful in IR timelining: it tells you when the service was installed or last modified, which often correlates with initial compromise events visible in other logs.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Service-based persistence with custom binaries documented across espionage operations." },
          { cls: "apt-cn", name: "APT41", note: "Service persistence with binaries in non-standard paths documented in multiple intrusions." },
          { cls: "apt-kp", name: "Lazarus", note: "Malicious service installation documented in CISA advisories on DPRK operations." },
          { cls: "apt-mul", name: "Ransomware", note: "Service persistence for propagation and re-encryption documented across Ryuk, Conti, BlackCat, LockBit families." },
          { cls: "apt-mul", name: "Cobalt Strike", note: "Service-based persistence is built-in - common across red team and APT operations using the framework." }
        ],
        cite: "MITRE ATT&CK T1543.003"
      },
      {
        sub: "T1543.003 - ServiceDLL Hijack (svchost-hosted Service Persistence)",
        indicator: "Service of Type=0x20 (Win32ShareProcess) with ServiceDll registry value pointing to user-writable or unsigned DLL - svchost-loaded malicious DLL",
        sysmon: `// Real-time detection - registry write to ServiceDll:
EventID=13
TargetObject=*\\Services\\*\\Parameters\\ServiceDll
Details matches:
  *\\AppData\\* OR *\\Temp\\*
  OR *\\ProgramData\\* OR *\\Users\\Public\\*
  OR <DLL path outside System32>

// Real-time detection - svchost loading unsigned DLL:
EventID=7 (Image Load)
Image=*\\svchost.exe
ImageLoaded NOT in standard system paths
Signed=false`,
        kibana: `// ServiceDll registry value set
winlog.event_id: 13
AND registry.path: *\\Services\\*\\Parameters\\ServiceDll
AND registry.data.strings: (*\\AppData\\* OR *\\Temp\\* OR *\\ProgramData\\* OR *\\Public\\*)

// svchost loading unsigned DLL from non-system path
winlog.event_id: 7
AND process.name: "svchost.exe"
AND file.code_signature.signed: false
AND NOT file.path: ("C:\\\\Windows\\\\System32\\\\*" OR "C:\\\\Windows\\\\SysWOW64\\\\*")`,
        powershell: `# Hunt for ServiceDll values pointing to suspicious paths
Get-ChildItem "HKLM:\\SYSTEM\\CurrentControlSet\\Services" | ForEach-Object {
  $svc = $_
  $paramKey = Join-Path $svc.PSPath 'Parameters'
  if (Test-Path $paramKey) {
    $dll = (Get-ItemProperty $paramKey -Name ServiceDll -EA SilentlyContinue).ServiceDll
    if ($dll) {
      $dllExpanded = [System.Environment]::ExpandEnvironmentVariables($dll)

      $suspicious = @()

      # User-writable path
      if ($dllExpanded -match '(AppData|Temp|ProgramData|\\\\Users\\\\Public)') {
        $suspicious += "ServiceDll in user-writable path"
      }

      # Outside standard system / program directories
      if ($dllExpanded -notmatch '^(C:\\\\Windows\\\\|C:\\\\Program Files)') {
        $suspicious += "ServiceDll outside standard paths"
      }

      # Signature check
      if (Test-Path $dllExpanded) {
        $sig = Get-AuthenticodeSignature $dllExpanded -EA SilentlyContinue
        if ($sig.Status -ne 'Valid') {
          $suspicious += "ServiceDll unsigned ($($sig.Status))"
        }
      } else {
        $suspicious += "ServiceDll file does not exist"
      }

      if ($suspicious.Count -gt 0) {
        [PSCustomObject]@{
          ServiceName = $svc.PSChildName
          ServiceDll = $dll
          Resolved = $dllExpanded
          Suspicious = ($suspicious -join '; ')
        }
      }
    }
  }
}

# Cross-reference: which svchost group hosts this service?
# Get-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\<name>" -Name ImagePath
# The ImagePath typically contains: %SystemRoot%\\system32\\svchost.exe -k <group>`,
        registry: `svchost service architecture:
- svchost.exe hosts multiple services in one process
- Service "groups" allow related services to share
  a single svchost instance (memory efficiency)
- Each service has:
  HKLM\\SYSTEM\\CurrentControlSet\\Services\\<Name>\\
    ImagePath = %SystemRoot%\\system32\\svchost.exe
                -k <group_name>
    Parameters\\
      ServiceDll = <path to DLL implementing service>
      ServiceMain = <export function name, optional>

The hijack technique:
- Adversary creates a service of Type=0x20 (shared)
  with ImagePath pointing to legitimate svchost.exe
- Sets Parameters\\ServiceDll to point to attacker-
  controlled DLL
- When service starts, svchost.exe (trusted Microsoft
  binary) loads the attacker DLL
- Process tree shows svchost.exe as the running
  process - looks legitimate to most monitoring

Why adversaries favor this:
- Hides under svchost.exe process name (40-100 svchosts
  run on a typical Windows host - blending is easy)
- ImagePath is the legitimate Microsoft svchost.exe -
  bypasses path-based detection
- Detection requires looking at the ServiceDll parameter
  rather than the ImagePath
- The malicious DLL runs in a SYSTEM-privileged
  process context

Hunting workflow:
- Enumerate Services with ImagePath=svchost.exe -k *
- For each, check Parameters\\ServiceDll
- Flag ServiceDll values outside System32/SysWOW64

Defensive registry:
- KnownDLLs (HKLM\\SYSTEM\\CurrentControlSet\\Control\\
  Session Manager\\KnownDLLs) does NOT protect against
  ServiceDll hijack since the DLL is loaded by explicit
  path, not by search order`,
        tools: `Adversary frameworks using ServiceDll hijack:
- Various long-dwell espionage operators
- ShadowPad / PlugX variants
- Some commodity malware (less common - prefers
  simpler Run key persistence)

Build process:
- Adversary writes a DLL exporting ServiceMain function
- Optionally exports SvchostPushServiceGlobals
  (some service groups require it)
- DLL placed in attacker-chosen location
- Service registered via sc.exe or registry edit

Reference DLL structure:
- DllMain entry point
- ServiceMain export (the service implementation)
- ServiceCtrlHandler for SCM control messages
- Most malicious ServiceDlls implement minimal
  legitimate-looking service interface, then run
  attacker code in a separate thread

Detection note: this is a more sophisticated
persistence than simple service installation,
typically associated with deliberate operators
rather than commodity malware. Finding ServiceDll
hijack on a host is usually a strong indicator
of APT-level compromise rather than opportunistic
infection.

Service group context:
- netsvcs (the most populated group - 30+ services)
- LocalService, NetworkService, LocalSystemNetworkRestricted
- Each group has its own svchost instance
- Adversaries often target netsvcs because it's
  the most crowded and most generic`,
        ossdetect: `Sigma:
- registry_event_servicedll_susp_path.yml
- image_load_win_svchost_susp_dll.yml
- registry_event_servicedll_modification.yml

Atomic Red Team:
- T1543.003 (service variants)
- Some tests cover ServiceDll modification

Hayabusa:
- ServiceDllSuspPath rules (EID 13)
- SvchostUnsignedDllLoad detection (EID 7)

Velociraptor:
- Windows.System.Services (returns Parameters\\ServiceDll
  alongside ImagePath for each service)
- Windows.System.DLL (loaded DLLs per process)

Reference - Microsoft documentation:
- 'Working with the AllJoyn Service Manager'
  and similar svchost service implementation docs
- Useful for understanding the legitimate side
  of the technique surface

Threat hunting references:
- PlugX malware family analyses
- Various China-nexus APT reports documenting
  ServiceDll hijack tradecraft`,
        notes: "ServiceDll hijack is a more sophisticated persistence technique than basic service installation - it specifically targets the svchost-hosted service model where multiple services share a single host process. The detection pivot is that you're not looking at the ImagePath (which is legitimate svchost.exe), you're looking at the Parameters\\ServiceDll value which actually points to the executable code. This is a high-value indicator when found because it's predominantly associated with deliberate, capable operators rather than commodity malware - most opportunistic infections use simpler Run key or service-with-EXE persistence rather than going through the trouble of building a proper ServiceDll. ShadowPad and PlugX malware families are the canonical examples and are heavily associated with China-nexus APT operations. The KnownDLLs registry protection does NOT apply here since the DLL is loaded by explicit path, not search order - so this technique works regardless of DLL search order hardening. False positives: legitimate Microsoft services use ServiceDll extensively (it's the standard svchost service pattern), so the filter must include 'path outside System32/SysWOW64' and 'unsigned' to surface anomalies. Pair the Sysmon EID 13 real-time detection with the PowerShell hunt for full coverage.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "ServiceDll hijack documented across multiple sector intrusions - signature tradecraft." },
          { cls: "apt-cn", name: "ShadowPad", note: "ServiceDll-based persistence via svchost - canonical malware family for this technique." },
          { cls: "apt-cn", name: "PlugX", note: "Heavy use of svchost ServiceDll persistence - one of the most well-documented examples." },
          { cls: "apt-cn", name: "Winnti", note: "ServiceDll hijack documented across the broader APT41 / Winnti ecosystem." },
          { cls: "apt-mul", name: "Advanced Operators", note: "ServiceDll persistence indicates capable operators - rare in commodity malware, common in APT operations." }
        ],
        cite: "MITRE ATT&CK T1543.003"
      },
      {
        sub: "T1543.003 - Hidden Services via Security Descriptor Manipulation",
        indicator: "Service registry key with ACL preventing standard enumeration tools from listing it - service exists but invisible to sc.exe and services.msc",
        sysmon: `// EID 12 (registry key create/delete) or EID 13
// catching changes to Service Security Descriptor:
EventID=13
TargetObject=*\\Services\\*\\Security
// The Security value contains the ACL for the
// service registry key - modifications to it
// indicate access control changes

// Also watch sc.exe sdset commands:
EventID=1
Image=*\\sc.exe
CommandLine matches: *sdset*
// sc sdset modifies a service's security descriptor`,
        kibana: `// Service security descriptor modification
winlog.event_id: 13
AND registry.path: *\\Services\\*\\Security

// sc.exe used to set service security
winlog.event_id: 1
AND process.name: "sc.exe"
AND process.command_line: *sdset*`,
        powershell: `# Hunt for hidden services - registry enumeration bypass
# Method 1: Compare what sc.exe sees vs what's in the registry

# What sc.exe / Get-Service can see:
$visible = Get-Service | Select-Object -ExpandProperty Name

# What's actually in the registry:
$registry = Get-ChildItem "HKLM:\\SYSTEM\\CurrentControlSet\\Services" |
  Where-Object { $_.GetValue('ImagePath') } |
  Select-Object -ExpandProperty PSChildName

# Diff: services in registry but not visible to Get-Service
$hidden = Compare-Object -ReferenceObject $registry -DifferenceObject $visible |
  Where-Object { $_.SideIndicator -eq '<=' } |
  Select-Object -ExpandProperty InputObject

if ($hidden) {
  Write-Host "Potentially hidden services detected:" -ForegroundColor Red
  $hidden | ForEach-Object {
    $key = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$_"
    $props = Get-ItemProperty $key -EA SilentlyContinue
    [PSCustomObject]@{
      Name = $_
      ImagePath = $props.ImagePath
      DisplayName = $props.DisplayName
      RegistryKey = $key
    }
  }
} else {
  Write-Host "No hidden services detected via registry/SCM diff" -ForegroundColor Green
}

# Method 2: Check for modified service security descriptors
# (requires reading the binary SD - shown conceptually)
# Use: sc.exe sdshow <ServiceName>
# Compare against known-good SD for that service type

# Method 3: Enumerate service security from registry
Get-ChildItem "HKLM:\\SYSTEM\\CurrentControlSet\\Services" | ForEach-Object {
  $sec = (Get-ItemProperty $_.PSPath -Name Security -EA SilentlyContinue).Security
  if ($sec) {
    # Security value present means SD has been explicitly set
    # Default services don't have an explicit Security value -
    # they inherit from the parent key
    [PSCustomObject]@{
      ServiceName = $_.PSChildName
      HasExplicitSecurity = $true
      ImagePath = (Get-ItemProperty $_.PSPath -Name ImagePath -EA SilentlyContinue).ImagePath
    }
  }
}`,
        registry: `Service hiding via ACL manipulation:

How it works:
- Service registry key has a SECURITY_DESCRIPTOR (SD)
  controlling who can read/modify the key
- Standard service SDs allow SYSTEM, Administrators,
  and authenticated users to enumerate
- Adversary modifies SD to DENY access to
  Administrators and SYSTEM (or just deny READ to
  the specific accounts used by sc.exe / services.msc)
- sc.exe and services.msc can't see the service
- Service still runs because the SCM uses a different
  privilege level than user enumeration tools

The Security value:
HKLM\\SYSTEM\\CurrentControlSet\\Services\\<Name>\\Security
- Binary REG_BINARY value containing the SD
- Optional - if absent, service uses default SD
- Presence of this value on a non-system service
  is itself unusual

Detection approaches:

1. Diff registry vs SCM enumeration (shown in script):
   - List services from HKLM\\SYSTEM\\...Services\\
   - List services from Get-Service / sc query
   - Difference = services hidden via ACL

2. Inspect service SD directly:
   sc.exe sdshow <ServiceName>
   - Returns SDDL string
   - Compare against known-good SD format
   - Adversary SDs typically contain explicit DENY
     ACEs (D:...DENY... in SDDL format)

3. Check for explicit Security value:
   - Most services don't have an explicit Security
     value (they inherit from parent)
   - A non-system service with explicit Security
     value warrants investigation

Reset hidden service ACL (if found):
sc.exe sdset <ServiceName>
  D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)
  (A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)
  (A;;CCLCSWLOCRRC;;;IU)
  (A;;CCLCSWLOCRRC;;;SU)
(restores default service SD)

Memory forensics for confirmation:
- Volatility psscan: lists running processes
  including those hidden from standard tools
- Match running svchost / service processes
  against registry-enumerated services to identify
  processes belonging to hidden services`,
        tools: `Service hiding tradecraft:

Known adversary toolkits with hidden service support:
- Various custom China-nexus implants
- Some advanced ransomware variants
- Custom red team implants for evasion

Standard implementation:
- After installing the service, run:
  sc.exe sdset <ServiceName> <restrictive_SDDL>
- Or modify the Security value in registry directly
- Tools available for SDDL manipulation:
  - sc.exe sdshow / sdset (built-in)
  - PsService (Sysinternals)
  - Custom code using Win32 API
    (RegSetKeySecurity, SetServiceObjectSecurity)

Why this technique is relatively rare:
- More sophisticated than typical malware
- Many adversaries don't bother because basic
  persistence works fine against most defenders
- When you DO see it, treat as high-confidence
  evidence of capable / deliberate operator

Detection note:
- Defenders running sc query or services.msc will
  miss hidden services entirely
- The registry diff approach is the most reliable
  detection - works even against SDs that deny
  access to all standard enumeration paths
- Velociraptor's service enumeration uses registry
  reads, so it surfaces hidden services that sc.exe
  cannot see

Real-world examples:
- Reported in Mandiant and CrowdStrike intrusion
  reports on advanced operators
- Less common than ServiceDll hijack but appears
  in long-dwell espionage cases`,
        ossdetect: `Sigma:
- registry_event_service_security_descriptor_change.yml
- proc_creation_win_sc_sdset.yml

Atomic Red Team:
- T1543.003 has tests for service modification
- Hidden service variant less commonly automated

Hayabusa:
- ServiceSDModification rules (EID 13)
- ScSdSetExecution rules (EID 1)

Velociraptor:
- Windows.System.Services
  (enumerates from registry - surfaces hidden services
  that sc.exe / Get-Service cannot see)
- Windows.Registry.NTUser
- Best tool for fleet-wide hidden service hunting

Reference:
- Microsoft service security documentation
- Windows Internals 7th edition - chapter on services
- Various APT analyses describing service hiding
  tradecraft

Manual workflow:
1. Run registry/SCM diff script (shown above)
2. For any flagged services, run sc.exe sdshow
3. Compare SDDL against baseline
4. Examine ImagePath and binary signature
5. Restore default ACL only after collecting
   forensic evidence`,
        notes: "Service hiding via security descriptor manipulation is one of the more sophisticated persistence techniques in Windows - it specifically targets the gap between how services are stored (registry) and how they're typically enumerated (Service Control Manager via sc.exe). The technique works because Windows allows arbitrary ACLs on service registry keys, and the standard enumeration tools respect those ACLs - so if the ACL denies your account read access, the service appears not to exist from your perspective. The registry-vs-SCM diff approach is the most reliable detection because it bypasses the ACL entirely: you're reading the registry directly and comparing against what the SCM returns. Any service in the registry that doesn't appear in the SCM enumeration is either hidden, broken, or in an unusual state - all warrant investigation. This is a relatively rare technique - more common in APT-level operations than commodity malware - so finding it is a strong signal of deliberate compromise. Pair with the ServiceDll hijack indicator: an adversary using ServiceDll hijack AND hiding the service via SD manipulation has built a particularly stealthy persistence layer that defeats most standard defender workflows. Velociraptor's Windows.System.Services artifact reads directly from the registry and is the best fleet-wide tool for surfacing this technique.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Service hiding via SD manipulation documented in long-dwell intrusion reports." },
          { cls: "apt-cn", name: "Advanced China-nexus", note: "Service hiding tradecraft associated with capable operators - documented across multiple campaigns." },
          { cls: "apt-mul", name: "Advanced Operators", note: "Service hiding indicates deliberate evasion focus - rare in opportunistic intrusions." },
          { cls: "apt-mul", name: "Red Teams", note: "Custom implants supporting service hiding documented in red team toolkits." }
        ],
        cite: "MITRE ATT&CK T1543.003"
      }
    ]
  },
  {
    id: "T1053.005",
    name: "Scheduled Task/Job: Scheduled Task (Persistence Angle)",
    desc: "Hunting established scheduled tasks with persistence intent - logon/startup triggers, hidden tasks, action analysis",
    rows: [
      {
        sub: "T1053.005 - Coming Soon",
        indicator: "Full content for T1053.005 Scheduled Task Persistence Hunt coming in next build session",
        sysmon: "(see widget summary in build session for headline indicator)",
        kibana: "(coming soon)",
        powershell: "(coming soon)",
        registry: "(coming soon)",
        tools: "(coming soon)",
        ossdetect: "(coming soon)",
        notes: "Planned coverage: hunting established tasks with persistence-specific triggers (OnLogon, AtStartup, OnEvent) - complements T1053.005 in Execution which covers creation. 2 indicators planned. Cross-reference Execution tactic's third indicator (action hunting) for binary-path angle.",
        apt: [{ cls: "apt-mul", name: "Coming soon", note: "Full APT attribution in next session" }],
        cite: "MITRE ATT&CK T1053.005"
      }
    ]
  },
  {
    id: "T1547.009",
    name: "Boot or Logon Autostart Execution: Shortcut Modification",
    desc: "LNK files in startup folders, modified existing LNK targets - shortcut-based persistence",
    rows: [
      {
        sub: "T1547.009 - Coming Soon",
        indicator: "Full content for T1547.009 Shortcut Modification coming in next build session",
        sysmon: "(see widget summary in build session for headline indicator)",
        kibana: "(coming soon)",
        powershell: "(coming soon)",
        registry: "(coming soon)",
        tools: "(coming soon)",
        ossdetect: "(coming soon)",
        notes: "Planned coverage: LNK creation in Startup folder, modification of existing user LNKs (Quick Launch, desktop, Recent) to point to malicious targets. 2 indicators planned.",
        apt: [{ cls: "apt-mul", name: "Coming soon", note: "Full APT attribution in next session" }],
        cite: "MITRE ATT&CK T1547.009"
      }
    ]
  }
];
