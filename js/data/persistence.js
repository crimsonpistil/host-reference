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
        sub: "T1543.003 - Coming Soon",
        indicator: "Full content for T1543.003 Service Persistence Hunt coming in next build session",
        sysmon: "(see widget summary in build session for headline indicator)",
        kibana: "(coming soon)",
        powershell: "(coming soon)",
        registry: "(coming soon)",
        tools: "(coming soon)",
        ossdetect: "(coming soon)",
        notes: "Planned coverage: hunting established services rather than catching creation (complements T1569.002 in Execution). 2-3 indicators planned - service hunting by config anomaly, hidden services via SD manipulation, ServiceDLL svchost-host persistence.",
        apt: [{ cls: "apt-mul", name: "Coming soon", note: "Full APT attribution in next session" }],
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
