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
        sub: "T1053.005 - Tasks with Persistence-Intent Triggers",
        indicator: "Enumerate scheduled tasks and filter to those with OnLogon, AtStartup, OnEvent, or short-interval triggers - the persistence-specific subset",
        sysmon: `// This indicator is hunting-oriented - PowerShell
// enumeration of established tasks rather than
// real-time creation detection (T1053.005 in Execution).
//
// Sysmon contribution: historical task creation events:
EventID=1
Image=*\\schtasks.exe
CommandLine=*/create*
// Cross-reference with /sc ONLOGON, /sc ONSTART,
// /sc ONEVENT to find persistence-intent creations

// Security Event 4698 (task created) - broader coverage:
EventID=4698
LogName=Security
// TaskContent XML field reveals trigger type
// Look for: <LogonTrigger>, <BootTrigger>,
// <EventTrigger>, <TimeTrigger Repetition Interval="PT<short>">`,
        kibana: `// Historical task creation with persistence trigger
winlog.event_id: 1
AND process.name: "schtasks.exe"
AND process.command_line: (*\/sc ONLOGON* OR *\/sc ONSTART* OR *\/sc ONEVENT*)

// Security Event 4698 with persistence triggers in XML
winlog.event_id: 4698
AND winlog.event_data.TaskContent: (*LogonTrigger* OR *BootTrigger* OR *EventTrigger*)

// Short-interval recurring tasks (beacon persistence)
winlog.event_id: 4698
AND winlog.event_data.TaskContent: (*PT1M* OR *PT5M* OR *PT10M* OR *PT15M*)`,
        powershell: `# Hunt scheduled tasks with persistence-intent triggers
# OnLogon, AtStartup, OnEvent, or short recurring interval

$persistenceTasks = @()

Get-ScheduledTask | ForEach-Object {
  $task = $_
  $triggerTypes = @()
  $suspicious = @()

  foreach ($trigger in $task.Triggers) {
    $type = $trigger.CimClass.CimClassName

    # Classify the trigger
    switch ($type) {
      'MSFT_TaskLogonTrigger'   { $triggerTypes += 'OnLogon' }
      'MSFT_TaskBootTrigger'    { $triggerTypes += 'AtStartup' }
      'MSFT_TaskEventTrigger'   { $triggerTypes += 'OnEvent' }
      'MSFT_TaskSessionStateChangeTrigger' { $triggerTypes += 'SessionStateChange' }
      'MSFT_TaskTimeTrigger'    { $triggerTypes += 'Time' }
      'MSFT_TaskDailyTrigger'   { $triggerTypes += 'Daily' }
      'MSFT_TaskRegistrationTrigger' { $triggerTypes += 'OnRegistration' }
    }

    # Check for short recurring intervals (beacon-like)
    if ($trigger.Repetition.Interval) {
      $interval = $trigger.Repetition.Interval
      if ($interval -match 'PT([0-9]+)M' -and [int]$matches[1] -le 15) {
        $suspicious += "Short repetition interval ($interval)"
      }
      if ($interval -match 'PT([0-9]+)S' -and [int]$matches[1] -le 600) {
        $suspicious += "Sub-minute repetition ($interval)"
      }
    }
  }

  # Persistence-intent triggers (any of these alone qualifies)
  $persistenceTriggers = @('OnLogon','AtStartup','OnEvent','SessionStateChange')
  $isPersistence = $false
  foreach ($t in $triggerTypes) {
    if ($persistenceTriggers -contains $t) { $isPersistence = $true; break }
  }

  if (-not $isPersistence -and $suspicious.Count -eq 0) { return }

  # Pull the action details
  $actions = $task.Actions | ForEach-Object {
    if ($_.Execute) { "$($_.Execute) $($_.Arguments)" }
  }

  # Check action for additional risk signals
  $actionStr = $actions -join ' | '
  if ($actionStr -match '(powershell|cmd\\.exe|wscript|cscript|mshta|rundll32|regsvr32)') {
    $suspicious += "Action invokes interpreter"
  }
  if ($actionStr -match '(AppData|Temp|ProgramData|\\\\Users\\\\Public)') {
    $suspicious += "Action in user-writable path"
  }

  $persistenceTasks += [PSCustomObject]@{
    TaskName    = $task.TaskName
    TaskPath    = $task.TaskPath
    Triggers    = ($triggerTypes -join ', ')
    Action      = $actionStr
    RunAs       = $task.Principal.UserId
    State       = $task.State
    Author      = $task.Author
    LastRunTime = $task.LastRunTime
    Suspicious  = ($suspicious -join '; ')
  }
}

$persistenceTasks | Sort-Object TaskPath | Format-Table -AutoSize`,
        registry: `Scheduled task storage on disk:

C:\\Windows\\System32\\Tasks\\<TaskPath>\\<TaskName>
- XML file containing full task definition
- Human-readable - inspect with Get-Content

Key XML elements for persistence analysis:
<Triggers>
  <LogonTrigger>     <!-- persistence intent -->
    <UserId>...</UserId>
  </LogonTrigger>
  <BootTrigger>      <!-- persistence intent -->
  </BootTrigger>
  <EventTrigger>     <!-- can be persistence -->
    <Subscription>...event XPath query...</Subscription>
  </EventTrigger>
  <CalendarTrigger>  <!-- scheduled, may not be persistence -->
    <Repetition>
      <Interval>PT5M</Interval>  <!-- short = suspicious -->
    </Repetition>
  </CalendarTrigger>
</Triggers>

<Principal>
  <UserId>S-1-5-18</UserId>  <!-- SYSTEM = high privilege -->
  <RunLevel>HighestAvailable</RunLevel>
</Principal>

Registry equivalent locations:
HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\
  Schedule\\TaskCache\\Tree\\<TaskPath>\\<TaskName>
HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\
  Schedule\\TaskCache\\Tasks\\{GUID}\\
- TaskCache\\Tree maps task names to GUIDs
- TaskCache\\Tasks contains the action data per GUID
- Useful for finding tasks that exist in registry
  but not in C:\\Windows\\System32\\Tasks (rare,
  indicates manipulation)

Cross-reference with Execution tactic:
- T1053.005 in Execution covers task CREATION
  (real-time schtasks.exe, Security EID 4698)
- This indicator covers HUNTING established tasks
- Use both for full coverage

Last-modified timestamps:
(Get-Item "C:\\Windows\\System32\\Tasks\\<name>").LastWriteTime
- Useful for incident timelining
- Tells you when the task was installed or modified`,
        tools: `Persistence-intent trigger types:

OnLogon (most common):
- Fires when specified user logs in
- "Any user" or specific account
- Most common adversary persistence trigger
- Standard Cobalt Strike persistence default

AtStartup (system boot):
- Fires when system boots
- Requires SYSTEM-level task (admin to create)
- Stronger persistence: runs before user logon

OnEvent (event-driven):
- Fires when specific Windows event log entry appears
- Adversaries use specific event IDs as triggers
- Example: trigger on Event ID 4624 LogonType=2
  (interactive logon - run code when someone logs in)
- More evasive than OnLogon - less commonly monitored

SessionStateChange:
- Fires on logon/logoff/lock/unlock
- Less common but documented

Short recurring intervals:
- PT1M, PT5M, PT10M repetitions
- Used for beacon-style persistence
- Adversary runs a check-in script every N minutes
- Combined with stub task that contacts C2

Adversary frameworks:
SharPersist (/t schtask)
Cobalt Strike (built-in task persistence)
Empire / Starkiller modules
Metasploit persistence
Most commodity malware uses simpler schtasks /create
  with /sc ONLOGON

Task disguise patterns (covered in T1053.005 Execution):
- Names mimicking Windows tasks: "Windows Update",
  "Microsoft Office Health", "Google Update Task"
- Task paths in \\Microsoft\\Windows\\ to blend with
  legitimate Windows tasks
- Author field set to "Microsoft Corporation"
  (easily spoofed, low fidelity by itself)`,
        ossdetect: `Sigma:
- Real-time detection rules cover creation
- Hunting established tasks is a manual workflow

Atomic Red Team:
- T1053.005 (multiple persistence trigger variants)
- T1053.005 Test #1, #6 (OnLogon and OnStartup tasks)
- Use to validate the hunt: install via Atomic,
  run PowerShell sweep, confirm detection

Hayabusa:
- ScheduledTaskCreation rules (real-time, EID 4698)
- For hunting, use Get-ScheduledTask or schtasks /query

Velociraptor:
- Windows.System.ScheduledTasks
  (best fleet-wide artifact - enumerates all tasks
  with trigger and action detail)
- Windows.Forensics.Autoruns

Sysinternals autoruns.exe:
- Scheduled Tasks tab
- Highlights non-Microsoft signed tasks
- VirusTotal lookup integration
- For manual IR triage

PowerShell native (the script above):
- No tool deploy required
- Works on any Windows with PowerShell 3.0+
- Returns parsed trigger type and timing info`,
        notes: "This is the persistence-hunting counterpart to T1053.005 in Execution. The Execution side covers task CREATION (real-time schtasks.exe and Security EID 4698); this side covers HUNTING established tasks with persistence-specific characteristics. The detection narrows by trigger type: OnLogon, AtStartup, OnEvent, and SessionStateChange are the persistence-intent trigger families. Time-based triggers can be persistence (daily/weekly recurring) but are also legitimate for many scheduled jobs - they need additional context (action analysis) to classify. Short recurring intervals (PT1M-PT15M) are a strong signal for beacon-style persistence: legitimate tasks rarely repeat that frequently, while adversary beacons commonly do. The combination 'OnLogon trigger + action invokes powershell + action contains EncodedCommand or AppData path' is high-confidence malicious - any one of those alone has false positives, but the combination is rarely legitimate. Pair this hunt with the Execution side's third indicator (task action hunting) for full coverage: this indicator filters by trigger type, that one filters by action path - together they catch the persistence-intent + suspicious-execution combination from both angles.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "OnLogon scheduled tasks documented across long-dwell operations." },
          { cls: "apt-cn", name: "APT41", note: "Scheduled task persistence with OnLogon and OnEvent triggers documented across multiple sector intrusions." },
          { cls: "apt-kp", name: "Lazarus", note: "Persistence-intent scheduled tasks documented in CISA advisories on DPRK operations." },
          { cls: "apt-mul", name: "Ransomware", note: "Pre-encryption persistence via OnLogon tasks documented across Ryuk, Conti, BlackCat families." },
          { cls: "apt-mul", name: "Cobalt Strike", note: "Default task persistence module uses OnLogon trigger - common across red team and APT operations." }
        ],
        cite: "MITRE ATT&CK T1053.005"
      },
      {
        sub: "T1053.005 - Hidden Scheduled Tasks (SD Manipulation and Tree Hiding)",
        indicator: "Tasks present in C:\\Windows\\System32\\Tasks XML but missing from schtasks.exe enumeration - registry/filesystem diff reveals hidden tasks",
        sysmon: `// Hidden task creation typically involves direct
// registry/filesystem manipulation rather than
// schtasks.exe, so process-based detection misses it.

// EID 11 (FileCreate) catching task XML write:
EventID=11
TargetFilename=C:\\Windows\\System32\\Tasks\\*

// EID 13 catching TaskCache registry manipulation:
EventID=13
TargetObject matches:
  *\\Schedule\\TaskCache\\Tree\\*
  OR *\\Schedule\\TaskCache\\Tasks\\*

// Cross-correlate: XML written without corresponding
// schtasks.exe process creation = direct manipulation

// Security Event 4698 (created) WITHOUT a paired
// schtasks.exe Sysmon EID 1 is unusual:
EventID=4698
LogName=Security
// Then look for absence of corresponding EID 1`,
        kibana: `// Task XML write detected
winlog.event_id: 11
AND file.path: C:\\\\Windows\\\\System32\\\\Tasks\\\\*

// TaskCache registry manipulation
winlog.event_id: 13
AND registry.path: (*\\Schedule\\TaskCache\\Tree\\* OR *\\Schedule\\TaskCache\\Tasks\\*)

// Security Event 4698 created
winlog.event_id: 4698
AND winlog.channel: "Security"`,
        powershell: `# Hunt for hidden scheduled tasks - filesystem vs SCM diff

# Method 1: Tasks in filesystem but not visible to Get-ScheduledTask
$visibleTasks = Get-ScheduledTask | ForEach-Object {
  ($_.TaskPath + $_.TaskName).TrimStart('\\\\')
}

$fsTasks = Get-ChildItem 'C:\\Windows\\System32\\Tasks' -Recurse -File |
  ForEach-Object {
    $_.FullName.Replace('C:\\Windows\\System32\\Tasks\\','').Replace('\\\\','\\\\')
  }

$hidden = $fsTasks | Where-Object { $_ -notin $visibleTasks }

if ($hidden) {
  Write-Host "Potentially hidden tasks (filesystem but not enumerable):" -ForegroundColor Red
  $hidden | ForEach-Object {
    $path = "C:\\Windows\\System32\\Tasks\\$_"
    if (Test-Path $path) {
      [PSCustomObject]@{
        TaskPath = $_
        XmlFile = $path
        Created = (Get-Item $path).CreationTime
        Modified = (Get-Item $path).LastWriteTime
        Size = (Get-Item $path).Length
      }
    }
  }
} else {
  Write-Host "No hidden tasks detected via filesystem/SCM diff" -ForegroundColor Green
}

# Method 2: Check TaskCache registry for orphaned entries
$registryGuids = Get-ChildItem 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks' |
  Select-Object -ExpandProperty PSChildName

$treeGuids = @()
function Get-AllTreeTasks($key) {
  Get-ChildItem $key -EA SilentlyContinue | ForEach-Object {
    $id = (Get-ItemProperty $_.PSPath -Name Id -EA SilentlyContinue).Id
    if ($id) { $script:treeGuids += $id }
    Get-AllTreeTasks $_.PSPath
  }
}
Get-AllTreeTasks 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree'

# GUIDs in Tasks key but not in Tree = orphaned/hidden tasks
$orphans = $registryGuids | Where-Object { $_ -notin $treeGuids }
if ($orphans) {
  Write-Host "Orphaned task GUIDs (in Tasks key but not in Tree):" -ForegroundColor Red
  $orphans
}

# Method 3: Read raw task XML for tasks that Get-ScheduledTask
# may not fully surface
Get-ChildItem 'C:\\Windows\\System32\\Tasks' -Recurse -File | ForEach-Object {
  try {
    $xml = [xml](Get-Content $_.FullName -Raw)
    [PSCustomObject]@{
      Path = $_.FullName
      Author = $xml.Task.RegistrationInfo.Author
      RunAs = $xml.Task.Principals.Principal.UserId
      Trigger = ($xml.Task.Triggers.ChildNodes.Name) -join ', '
      Action = ($xml.Task.Actions.Exec.Command + ' ' + $xml.Task.Actions.Exec.Arguments)
    }
  } catch { }
}`,
        registry: `Scheduled task storage structure (Windows 10+):

Filesystem:
C:\\Windows\\System32\\Tasks\\<TaskPath>\\<TaskName>
- XML file with full task definition
- This is the canonical task storage

Registry mirror:
HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\
  TaskCache\\
    Tree\\<TaskPath>\\<TaskName>\\
      Id = {GUID}  (links to Tasks key below)
      Index = <byte>
    Tasks\\{GUID}\\
      Actions = REG_BINARY  (action data)
      Triggers = REG_BINARY (trigger data)
      DynamicInfo = REG_BINARY (last run/result)
      Path = <task path back-reference>

Hiding techniques:

1. Filesystem only, no registry entry:
   - Write task XML to C:\\Windows\\System32\\Tasks
   - Skip the registry TaskCache entries
   - Get-ScheduledTask uses registry - misses it
   - Task may or may not run depending on Windows version
     (newer Windows requires both)

2. Registry only, no filesystem XML:
   - Write to TaskCache\\Tasks\\{GUID}
   - Reverses the above hiding pattern
   - Less common but documented in some malware

3. Security descriptor manipulation:
   - HKLM\\...\\Schedule\\TaskCache\\Tree\\<task>\\
     SD = REG_BINARY (security descriptor)
   - Modify SD to deny enumeration access
   - Get-ScheduledTask and schtasks /query miss it
   - Task still runs because Task Scheduler service
     uses a different privilege level

4. Tree entry hidden, GUID entry present:
   - Delete the Tree\\<TaskName>\\Id value
   - Task data still in Tasks\\{GUID} - task runs
   - Tree enumeration misses the entry
   - PowerShell COM API and schtasks /query both miss it

Detection approaches:

- Diff filesystem vs Get-ScheduledTask output
  (shown in script above)
- Check TaskCache\\Tasks GUIDs against Tree entries
  (shown in script above)
- Inspect task SD values for non-default ACLs:
  Get-Item 'HKLM:\\...\\TaskCache\\Tree\\<name>' |
  Get-Acl | Select-Object -Expand AccessToString

The XML-based hunt approach reads C:\\Windows\\System32\\
Tasks directly and bypasses any registry-based hiding -
even tasks hidden via SD manipulation in the registry
remain visible if their XML still exists.`,
        tools: `Hidden scheduled task tradecraft:

Known adversary toolkits:
- Various custom implants used by capable operators
- Reported in Mandiant / CrowdStrike intrusion analyses
- Documented use by Tarrask malware family
  (Microsoft 2022 disclosure on HAFNIUM tradecraft)

Tarrask specifically (HAFNIUM):
- Created scheduled tasks with deleted SD security
  descriptor in registry
- Tasks invisible to schtasks.exe and services.msc
- Persisted for months in long-dwell intrusions
- Microsoft's 2022 disclosure brought the technique
  into mainstream defender awareness

Standard implementation approach:
1. Create task via schtasks.exe or COM API (visible)
2. Modify TaskCache\\Tree\\<name>\\SD value to deny
   enumeration access OR delete the SD value entirely
3. Optional: also remove the Tree\\<name>\\Id mapping
   so registry-based enumeration misses it
4. Task XML remains in filesystem - the run mechanism
   uses it - but standard enumeration tools don't
   surface the task

Detection note:
- This is sophisticated tradecraft - typically
  associated with APT-level operators
- Commodity malware rarely bothers with this
- Finding hidden tasks is high-confidence signal
  of capable / deliberate compromise

Defensive recommendation:
- Always cross-reference filesystem (System32\\Tasks)
  against schtasks.exe / Get-ScheduledTask output
- Use Velociraptor or similar XML-based enumeration
  rather than relying on the registry path alone`,
        ossdetect: `Sigma:
- file_event_win_scheduled_task_xml_creation.yml
- registry_event_taskcache_modification.yml
- registry_event_taskcache_sd_modification.yml

Atomic Red Team:
- T1053.005 has tests for task creation variants
- Hidden task variant less commonly automated

Hayabusa:
- ScheduledTaskXmlWrite rules (EID 11)
- TaskCacheModification rules (EID 13)

Velociraptor:
- Windows.System.ScheduledTasks
  (parses XML directly - surfaces hidden tasks
  that registry-based tools miss)
- Best single tool for fleet-wide hunting

Microsoft references:
- 'Tarrask malware uses scheduled tasks for defense
  evasion' (Microsoft Threat Intelligence, 2022)
- Foundational reference for SD-based task hiding
- HAFNIUM tradecraft documentation

KAPE (Eric Zimmerman):
- Targets/Compound/ScheduledTasks.tkape
  (collects both XML files and registry hive)
- Enables offline forensic analysis of
  both visible and hidden tasks`,
        notes: "Hidden scheduled tasks via SD manipulation came to mainstream attention in April 2022 when Microsoft disclosed the Tarrask malware family used by HAFNIUM (China-nexus). The technique exploits the gap between how tasks are stored (filesystem XML + registry TaskCache mirror) and how they're typically enumerated (schtasks.exe and Get-ScheduledTask use the registry). By modifying or deleting the security descriptor on the TaskCache\\Tree registry entry, the adversary makes the task invisible to standard tools while leaving the XML in place so it still runs. The filesystem-vs-SCM diff in the PowerShell script is the most reliable detection because it bypasses the registry entirely - if the XML exists in C:\\Windows\\System32\\Tasks but Get-ScheduledTask doesn't list it, something is hiding it. This is one of those techniques that's rare enough that most defenders don't actively look for it, which makes it disproportionately valuable for adversaries who do use it. Tarrask persisted in HAFNIUM intrusions for months in some cases before being detected. Pair this hunt with the standard task enumeration in the previous indicator: together they cover both visible-but-suspicious tasks and tasks that have been deliberately hidden. Velociraptor's Windows.System.ScheduledTasks is the best fleet-wide tool because it reads XML directly rather than depending on the registry path.",
        apt: [
          { cls: "apt-cn", name: "HAFNIUM", note: "Tarrask malware - documented use of SD manipulation to hide scheduled tasks across long-dwell intrusions." },
          { cls: "apt-cn", name: "APT41", note: "Hidden task tradecraft documented in sector-targeting operations." },
          { cls: "apt-mul", name: "Advanced Operators", note: "Hidden tasks indicate deliberate evasion focus - rare in commodity malware, common in APT operations." },
          { cls: "apt-mul", name: "Red Teams", note: "Custom implants supporting hidden task creation documented in advanced red team toolkits." }
        ],
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
        sub: "T1547.009 - LNK File in Startup Folder",
        indicator: "LNK shortcut written to per-user or all-users Startup folder - file launched at every logon",
        sysmon: `// Real-time detection - LNK file create in Startup folder:
EventID=11
TargetFilename matches:
  *\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*.lnk
  OR *\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\*.lnk

// Also catch non-LNK files in Startup folder
// (some adversaries drop .exe/.bat/.vbs directly):
EventID=11
TargetFilename matches:
  *\\Start Menu\\Programs\\Startup\\*
  OR *\\Start Menu\\Programs\\StartUp\\*

// LNK execution at logon - explorer parent + LNK target:
EventID=1
ParentImage=*\\explorer.exe
CommandLine matches: suspicious interpreter or path
// (the LNK launches whatever its target says)`,
        kibana: `// LNK file creation in Startup folders
winlog.event_id: 11
AND file.extension: "lnk"
AND file.path: (*\\Start Menu\\Programs\\Startup\\* OR *\\Start Menu\\Programs\\StartUp\\*)

// Any file dropped to Startup folder (LNK or otherwise)
winlog.event_id: 11
AND file.path: (*\\Start Menu\\Programs\\Startup\\* OR *\\Start Menu\\Programs\\StartUp\\*)

// LNK-launched suspicious process at logon
winlog.event_id: 1
AND process.parent.name: "explorer.exe"
AND process.command_line: (*powershell* OR *cmd.exe* OR *wscript* OR *mshta* OR *rundll32*)
AND process.command_line: (*\\AppData\\* OR *\\Temp\\* OR *\\ProgramData\\* OR *http* OR *EncodedCommand*)`,
        powershell: `# Hunt for LNK files in Startup folders + parse their targets

$startupPaths = @(
  "$env:ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp",
  "$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
)

# Some systems have additional per-user paths - enumerate all users:
$additionalPaths = Get-ChildItem 'C:\\Users' -Directory -EA SilentlyContinue | ForEach-Object {
  Join-Path $_.FullName 'AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'
} | Where-Object { Test-Path $_ }

$allPaths = $startupPaths + $additionalPaths | Sort-Object -Unique

$shell = New-Object -ComObject WScript.Shell

foreach ($path in $allPaths) {
  if (-not (Test-Path $path)) { continue }

  Get-ChildItem $path -File | ForEach-Object {
    $suspicious = @()

    if ($_.Extension -eq '.lnk') {
      # Parse LNK target/args
      try {
        $lnk = $shell.CreateShortcut($_.FullName)
        $target = $lnk.TargetPath
        $args = $lnk.Arguments

        # Check 1: LNK target is an interpreter
        if ($target -match '(powershell|cmd\\.exe|wscript|cscript|mshta|rundll32|regsvr32)') {
          $suspicious += "Target invokes interpreter"
        }

        # Check 2: LNK target in user-writable path
        if ($target -match '(AppData|Temp|ProgramData|\\\\Users\\\\Public)') {
          $suspicious += "Target in user-writable path"
        }

        # Check 3: Arguments contain risk keywords
        if ($args -match '(ExecutionPolicy.*Bypass|EncodedCommand|WindowStyle.*Hidden|vbscript:|javascript:|http://|https://)') {
          $suspicious += "Risky arguments"
        }

        # Check 4: Target unsigned (if it exists)
        if ($target -and (Test-Path $target)) {
          $sig = Get-AuthenticodeSignature $target -EA SilentlyContinue
          if ($sig.Status -ne 'Valid') {
            $suspicious += "Target unsigned ($($sig.Status))"
          }
        }

        [PSCustomObject]@{
          Path = $_.FullName
          Type = 'LNK'
          Target = $target
          Arguments = $args
          Created = $_.CreationTime
          Modified = $_.LastWriteTime
          Suspicious = if ($suspicious) { $suspicious -join '; ' } else { '' }
        }
      } catch {
        Write-Warning "Failed to parse $($_.FullName): $_"
      }
    } else {
      # Non-LNK file in Startup folder (always worth flagging)
      $suspicious += "Non-LNK file in Startup folder (.$($_.Extension))"

      [PSCustomObject]@{
        Path = $_.FullName
        Type = $_.Extension
        Target = $_.FullName
        Arguments = ''
        Created = $_.CreationTime
        Modified = $_.LastWriteTime
        Suspicious = $suspicious -join '; '
      }
    }
  }
} | Sort-Object Suspicious -Descending | Format-Table -AutoSize`,
        registry: `Startup folder paths:

All-users (machine-wide, requires admin to write):
C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\
  Programs\\StartUp\\

Per-user (any user can write to their own):
C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\
  Windows\\Start Menu\\Programs\\Startup\\

Note the casing: 'StartUp' (machine) vs 'Startup'
(per-user) - Microsoft's inconsistency. File system
is case-insensitive so detection patterns work
either way but it's worth knowing.

Files in these folders launch at logon - any
extension that Windows knows how to execute:
- .lnk (most common - shortcut to actual binary)
- .exe (direct binary)
- .bat / .cmd (batch script)
- .vbs / .vbe (VBScript)
- .js / .jse (JScript)
- .ps1 (PowerShell - only if execution policy allows)
- .hta (HTA - launches via mshta.exe)

LNK file structure (binary format):
- Inspect with LECmd (Eric Zimmerman) or
  PowerShell WScript.Shell COM object (shown above)
- Key fields:
  - TargetPath: the binary actually launched
  - Arguments: command-line arguments
  - WorkingDirectory: where target runs from
  - IconLocation: icon path (often spoofed -
    document icon on a cmd-launching LNK)
  - Description: tooltip (often blank for adversary
    LNKs)
  - Hotkey: keyboard shortcut (rare for malicious)

Registry mirror of Startup folder location:
HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\
  Explorer\\Shell Folders\\Startup
HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\
  Explorer\\User Shell Folders\\Startup
- Default values point to the per-user Startup path
- Adversaries occasionally REDIRECT these to a
  different folder they control - rare but documented
- Worth checking these registry values match the
  expected default path

File creation timestamps:
- LNK files have their own MACB timestamps
- LNK files also EMBED target file timestamps
  inside the binary structure
- Useful for forensic timeline reconstruction`,
        tools: `LNK creation methods:

Built-in Windows:
- Right-click > New > Shortcut (GUI)
- PowerShell WScript.Shell COM object (most common
  for adversary use):
    $s = New-Object -ComObject WScript.Shell
    $lnk = $s.CreateShortcut("$startupPath\\Update.lnk")
    $lnk.TargetPath = "C:\\Windows\\System32\\powershell.exe"
    $lnk.Arguments = "-ep bypass -w hidden -file C:\\path\\payload.ps1"
    $lnk.Save()

Adversary frameworks:
- SharPersist (/t startupfolder)
- Empire / Starkiller persistence modules
- Cobalt Strike persistence aggressor scripts
- Most commodity malware uses this technique:
  Emotet, IcedID, QakBot, AgentTesla, RemcosRAT,
  NjRAT, DarkComet, and many more

Common adversary LNK patterns:
- LNK named to mimic legitimate startup items:
  "Microsoft Office Quick Start.lnk"
  "OneDrive.lnk", "Adobe Updater.lnk"
- TargetPath = powershell.exe or wscript.exe
- Arguments contain encoded/obfuscated payload
- IconLocation set to mimic the spoofed app icon
- Working directory = user's home folder (looks normal)

Detection note:
- Per-user startup is more common because it requires
  no admin privileges - any compromised user can
  persist their own session
- All-users startup requires admin and indicates
  more capable / privileged compromise

Non-LNK files in Startup folder:
- Adversaries occasionally drop .exe, .bat, .vbs
  directly without using LNK
- Slightly noisier (less common in legitimate use)
- Same detection - any file in Startup folder warrants
  inspection`,
        ossdetect: `Sigma:
- file_event_win_startup_folder_persistence.yml
- file_event_win_lnk_creation_in_startup.yml
- proc_creation_win_susp_explorer_child.yml
  (catches the execution side at logon)

Atomic Red Team:
- T1547.001 (includes Startup folder tests)
- T1547.009 Test #1 (LNK file creation in Startup)
- T1547.009 Test #2 (modified existing LNK target)

Hayabusa:
- StartupFolderFileWrite rules (EID 11)
- LnkLaunchingInterpreter detection (EID 1)

Velociraptor:
- Windows.Sys.AutoRuns
  (enumerates Startup folder contents alongside
  Run keys and other autostart locations)
- Windows.Forensics.Lnk
  (LNK file parser - extracts target, arguments,
  working dir, and embedded timestamps)

Sysinternals autoruns.exe:
- Logon tab includes Startup folder entries
- Highlights non-Microsoft signed entries
- Excellent for manual IR triage

LECmd by Eric Zimmerman:
- Standalone LNK file parser
- Extracts every field including hidden ones
- Free tool, essential for LNK forensic work
- Useful when handling LNKs collected from
  a forensic image rather than live host`,
        notes: "Startup folder persistence is the filesystem complement to Run key persistence - same effect (run at logon), different mechanism. The technique is universal: virtually every commodity malware family uses either Run keys, Startup folder LNKs, or both. The detection focus is twofold: real-time file creation in Startup paths (Sysmon EID 11) and hunting established LNKs with suspicious targets. The PowerShell LNK parser in the script is genuinely useful - it reads every LNK in every Startup path, parses the COM-accessible properties (TargetPath, Arguments, WorkingDirectory), and flags ones that point to interpreters or user-writable paths. Per-user Startup is more common than all-users because it requires no admin privileges - any compromised user account can persist itself. The non-LNK file check matters: while most adversary persistence uses LNK shortcuts, some malware drops .vbs or .bat files directly into the Startup folder. Any non-LNK file in a Startup folder is worth investigating because legitimate software almost always uses LNK shortcuts for startup entries. False positives: legitimate vendor software does create LNKs in the all-users Startup folder during install - signature checking on the LNK target binary helps filter these out.",
        apt: [
          { cls: "apt-mul", name: "Commodity Malware", note: "Universal across Emotet, IcedID, QakBot, AgentTesla, RemcosRAT, NjRAT, and most RAT families." },
          { cls: "apt-ru", name: "APT28", note: "Startup folder LNK persistence documented in spearphishing campaigns." },
          { cls: "apt-cn", name: "APT41", note: "Startup folder persistence documented across multiple sector intrusions." },
          { cls: "apt-kp", name: "Lazarus", note: "LNK-based startup persistence documented in CISA advisories on DPRK operations." },
          { cls: "apt-mul", name: "Ransomware", note: "Persistence via Startup folder documented across most ransomware families." }
        ],
        cite: "MITRE ATT&CK T1547.009"
      },
      {
        sub: "T1547.009 - Modified Existing LNK with Malicious Target",
        indicator: "Pre-existing legitimate LNK shortcut modified to point to attacker-controlled binary - hijacks normal user behavior",
        sysmon: `// Modification of existing LNK (vs creation):
EventID=11 (FileCreate fires on overwrite too)
TargetFilename=*.lnk

// Useful filter: LNK file MODIFIED (not created)
// in user shortcut locations:
TargetFilename matches:
  *\\Desktop\\*.lnk
  OR *\\Roaming\\Microsoft\\Windows\\Recent\\*.lnk
  OR *\\Roaming\\Microsoft\\Internet Explorer\\Quick Launch\\*.lnk
  OR *\\Microsoft\\Windows\\Start Menu\\Programs\\*.lnk
  (existing LNK overwritten in any of these)

// Process spawning from a hijacked LNK:
EventID=1
ParentImage=*\\explorer.exe
CommandLine matches: suspicious interpreter or args
// (same pattern as Startup folder LNK execution,
// but triggered when user clicks any modified shortcut)`,
        kibana: `// LNK file write in user shortcut locations
// (modification of existing LNKs - higher fidelity
// than alerting on any LNK creation)
winlog.event_id: 11
AND file.extension: "lnk"
AND file.path: (*\\Desktop\\* OR *\\Quick Launch\\* OR *\\Start Menu\\Programs\\*)

// Suspicious explorer-spawned process with risky args
winlog.event_id: 1
AND process.parent.name: "explorer.exe"
AND process.command_line: (*ExecutionPolicy*Bypass* OR *EncodedCommand* OR *WindowStyle*Hidden* OR *vbscript\:* OR *javascript\:*)`,
        powershell: `# Hunt for LNKs in user shortcut locations with suspicious targets
# Covers Desktop, Quick Launch, Start Menu, Recent

$searchPaths = @(
  "$env:USERPROFILE\\Desktop",
  "$env:PUBLIC\\Desktop",
  "$env:APPDATA\\Microsoft\\Windows\\Recent",
  "$env:APPDATA\\Microsoft\\Internet Explorer\\Quick Launch",
  "$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs",
  "$env:PROGRAMDATA\\Microsoft\\Windows\\Start Menu\\Programs"
)

# Enumerate per-user paths across all users:
$additionalPaths = Get-ChildItem 'C:\\Users' -Directory -EA SilentlyContinue | ForEach-Object {
  @(
    Join-Path $_.FullName 'Desktop'
    Join-Path $_.FullName 'AppData\\Roaming\\Microsoft\\Windows\\Recent'
    Join-Path $_.FullName 'AppData\\Roaming\\Microsoft\\Internet Explorer\\Quick Launch'
    Join-Path $_.FullName 'AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs'
  )
} | Where-Object { Test-Path $_ }

$allPaths = $searchPaths + $additionalPaths | Sort-Object -Unique

$shell = New-Object -ComObject WScript.Shell

foreach ($path in $allPaths) {
  if (-not (Test-Path $path)) { continue }

  Get-ChildItem $path -Filter *.lnk -File -Recurse -EA SilentlyContinue | ForEach-Object {
    try {
      $lnk = $shell.CreateShortcut($_.FullName)
      $target = $lnk.TargetPath
      $args = $lnk.Arguments
      $iconLoc = $lnk.IconLocation

      $suspicious = @()

      # Target is an interpreter - high signal
      if ($target -match '(powershell|cmd\\.exe|wscript|cscript|mshta|rundll32|regsvr32)') {
        $suspicious += "Target invokes interpreter"
      }

      # Target in user-writable path
      if ($target -match '(AppData|Temp|ProgramData|\\\\Users\\\\Public)') {
        $suspicious += "Target in user-writable path"
      }

      # Arguments with risk keywords
      if ($args -match '(ExecutionPolicy.*Bypass|EncodedCommand|WindowStyle.*Hidden|vbscript:|javascript:|http://|https://)') {
        $suspicious += "Risky arguments"
      }

      # Icon spoofing: icon path != target path base
      # (legitimate LNKs usually have icon matching target)
      if ($iconLoc -and $target) {
        $iconBase = ($iconLoc -split ',')[0]
        if ($iconBase -and $iconBase -ne $target -and
            $iconBase -match '\\.(exe|dll|ico)$' -and
            (Split-Path $iconBase -Leaf) -ne (Split-Path $target -Leaf)) {
          $suspicious += "Icon mismatch (possible icon spoof)"
        }
      }

      # LNK modified recently but target is old / mismatched
      $lnkMod = $_.LastWriteTime
      if ((Test-Path $target) -and ((Get-Item $target).CreationTime -gt $lnkMod.AddDays(-30))) {
        # Target binary younger than 30 days but LNK is older - suspicious
        if ($lnkMod -lt (Get-Date).AddDays(-90)) {
          $suspicious += "LNK modified recently, but its target binary is newer than LNK creation"
        }
      }

      if ($suspicious.Count -gt 0) {
        [PSCustomObject]@{
          LnkFile     = $_.FullName
          Target      = $target
          Arguments   = $args
          IconLocation = $iconLoc
          LnkModified = $lnkMod
          Suspicious  = $suspicious -join '; '
        }
      }
    } catch {
      # Skip unreadable LNKs
    }
  }
} | Sort-Object Suspicious -Descending | Format-Table -AutoSize`,
        registry: `LNK file locations for shortcut hijacking:

User Desktop (per-user):
- C:\\Users\\<user>\\Desktop\\*.lnk
- High-value target: shortcuts user clicks daily
- Modifying Chrome.lnk on desktop = persistence
  every time user opens Chrome

Public Desktop (all users):
- C:\\Users\\Public\\Desktop\\*.lnk
- Same idea, all-users visibility

Quick Launch / Pinned Taskbar items:
- %APPDATA%\\Microsoft\\Internet Explorer\\
    Quick Launch\\*.lnk
- %APPDATA%\\Microsoft\\Internet Explorer\\
    Quick Launch\\User Pinned\\TaskBar\\*.lnk
- Pinned taskbar items live here as LNKs
- Modifying them hijacks every taskbar click

Start Menu:
- %APPDATA%\\Microsoft\\Windows\\Start Menu\\
    Programs\\*.lnk (per-user)
- %PROGRAMDATA%\\Microsoft\\Windows\\Start Menu\\
    Programs\\*.lnk (all users)
- Triggered when user opens Start menu and clicks
  the LNK

Recent files:
- %APPDATA%\\Microsoft\\Windows\\Recent\\*.lnk
- Created automatically by Windows when documents
  opened
- Less common adversary target but documented

Adversary tradecraft for LNK hijacking:
1. Identify high-value user shortcuts (browser,
   email client, IDE - whatever the user clicks
   most often)
2. Read original LNK target with WScript.Shell
3. Replace TargetPath with attacker binary
4. (Optionally) keep IconLocation pointing to
   original binary so the icon looks normal
5. (Optionally) have attacker binary launch the
   original binary as a child - user sees expected
   behavior, doesn't notice compromise

Detection focus:
- LNK with Target != IconLocation base (icon spoof)
- LNK with Target pointing to interpreter
- LNK in user shortcut location modified after
  initial creation (modification timestamp newer
  than creation timestamp + 24 hours)
- LNK Author / Description fields suggesting
  Microsoft origin but TargetPath outside
  Microsoft installation directories`,
        tools: `Existing-LNK hijack tradecraft:

This technique is less common than dropping a new
LNK in Startup folder because:
- Requires read-and-modify operation (more API calls)
- User may notice if launch behavior changes
- More forensic evidence (modified-not-created LNK)

When used, typically by:
- Targeted operators (manual LNK modification)
- Custom red team implants
- Some sophisticated malware variants

Standard implementation:
$shell = New-Object -ComObject WScript.Shell
$lnk = $shell.CreateShortcut(
  "C:\\Users\\victim\\Desktop\\Chrome.lnk")
$originalTarget = $lnk.TargetPath
# Replace with malicious wrapper:
$lnk.TargetPath = "C:\\ProgramData\\wrapper.exe"
$lnk.Arguments = $originalTarget  # pass original
                                  # as arg
$lnk.Save()
# wrapper.exe runs adversary code, then launches
# original Chrome with the passed argument so user
# sees expected behavior

Why this technique is harder to detect than
fresh-LNK-in-Startup:
- LNK already exists - file creation alerts don't fire
- LNK already trusted by user
- Hijacked LNK launches at every user click,
  no schedule needed
- Forensic signal is the MODIFICATION timestamp,
  not creation - requires explicit hunting

Pair with execution-time detection: when user
clicks the hijacked LNK, explorer.exe spawns the
malicious target - same Sysmon EID 1 pattern as
T1204.002 indicator 2 (suspicious LNK targets).

Less common variant: LNK with Description field
modified to suggest legitimate Microsoft software
while TargetPath points elsewhere - relies on
defenders not parsing LNK contents thoroughly.`,
        ossdetect: `Sigma:
- file_event_win_lnk_modification_user_locations.yml
- proc_creation_win_lnk_susp_target.yml
- file_event_win_lnk_icon_target_mismatch.yml

Atomic Red Team:
- T1547.009 Test #2 (existing LNK target modified)

Hayabusa:
- LnkModificationInUserPath rules
- LnkIconTargetMismatch detection

Velociraptor:
- Windows.Forensics.Lnk
  (LNK file parser with target/icon analysis)
- Custom artifact possible for icon-vs-target diff

LECmd (Eric Zimmerman):
- Standalone LNK parser
- Best for offline forensic analysis
- Returns all LNK fields including embedded
  timestamps that can show original creation vs
  later modification

Sysinternals autoruns.exe:
- Logon tab covers Startup folder LNKs but does
  NOT enumerate Desktop / Quick Launch / Recent
- This indicator's PowerShell sweep complements
  autoruns by covering those gaps

Reference:
- LNK file format documentation (Microsoft)
- Forensic Wiki - LNK file analysis
- LECmd documentation for field interpretation`,
        notes: "LNK hijacking is the more sophisticated cousin of Startup folder LNK persistence. Instead of dropping a new shortcut in Startup, the adversary modifies a pre-existing shortcut the user already clicks regularly (browser, email client, IDE on the desktop or taskbar). The hijack triggers every time the user clicks that shortcut, providing persistence without a scheduled task or registry entry. The detection challenge: legitimate software occasionally modifies existing LNKs during updates (updating the target path when the binary moves to a versioned subdirectory), so 'any LNK modification' is too noisy. The PowerShell hunt focuses on suspicious target characteristics (interpreter, user-writable path, risky arguments) and icon-vs-target mismatch which is a strong indicator of the wrapper-and-launch hijack pattern - the LNK still has Chrome's icon but the target is now wrapper.exe. The technique is less common than Startup folder LNK persistence because it requires reading-and-modifying an existing file rather than just dropping a new one, but when found it's higher-confidence malicious because legitimate software very rarely targets pre-existing user shortcuts for modification. Pair this hunt with T1204.002 (User Execution) which covers the execution side when the user clicks the hijacked LNK.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "LNK modification documented in operations targeting multiple sectors." },
          { cls: "apt-cn", name: "Mustang Panda", note: "LNK-based persistence including modification of existing shortcuts documented in operations against Southeast Asian governments." },
          { cls: "apt-mul", name: "Advanced Operators", note: "LNK hijacking indicates deliberate operator presence - rare in commodity malware, more common in targeted operations." },
          { cls: "apt-mul", name: "Red Teams", note: "Existing LNK hijacking documented in red team toolkits for evasive persistence." }
        ],
        cite: "MITRE ATT&CK T1547.009"
      }
    ]
  },
  {
    id: "T1037",
    name: "Boot or Logon Initialization Scripts",
    desc: "Registry logon scripts, GPO logon/startup scripts, SYSVOL-based domain-wide persistence",
    rows: [
      {
        sub: "T1037.001 - Registry-Based Logon Script (UserInitMprLogonScript)",
        indicator: "HKCU\\Environment\\UserInitMprLogonScript value set - obscure registry-based logon script trigger with near-zero legitimate use",
        sysmon: `// Real-time registry write to the logon script value:
EventID=13
TargetObject=*\\Environment\\UserInitMprLogonScript

// Also watch the less common variants:
EventID=13
TargetObject matches:
  *\\Environment\\UserInitMprLogonScript
  OR *\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\
       Userinit
  OR *\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\
       AppInit_DLLs

// Process execution from logon script trigger:
EventID=1
ParentImage=*\\userinit.exe
// userinit.exe is the standard logon driver - it
// spawns explorer and runs any configured scripts.
// Children of userinit.exe OTHER than explorer.exe
// are worth scrutiny.`,
        kibana: `// Primary: UserInitMprLogonScript write
winlog.event_id: 13
AND registry.path: *\\Environment\\UserInitMprLogonScript

// Userinit registry modification (different but related)
winlog.event_id: 13
AND registry.path: *\\Winlogon\\Userinit

// userinit.exe spawning unexpected children
winlog.event_id: 1
AND process.parent.name: "userinit.exe"
AND NOT process.name: "explorer.exe"`,
        powershell: `# Hunt for UserInitMprLogonScript across all user hives
# This is the obscure-but-effective logon script trigger

# Current user
$current = Get-ItemProperty 'HKCU:\\Environment' -Name UserInitMprLogonScript -EA SilentlyContinue
if ($current.UserInitMprLogonScript) {
  [PSCustomObject]@{
    User = $env:USERNAME
    Hive = 'HKCU (current)'
    Value = $current.UserInitMprLogonScript
  }
}

# All loaded user hives via HKU
Get-ChildItem 'HKU:\\' -EA SilentlyContinue | Where-Object {
  $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '_Classes$'
} | ForEach-Object {
  $sid = $_.PSChildName
  $envKey = "HKU:\\$sid\\Environment"
  if (Test-Path $envKey) {
    $val = (Get-ItemProperty $envKey -Name UserInitMprLogonScript -EA SilentlyContinue).UserInitMprLogonScript
    if ($val) {
      [PSCustomObject]@{
        User = $sid
        Hive = "HKU\\$sid"
        Value = $val
      }
    }
  }
}

# Also check the related Winlogon\\Userinit value (system-wide)
# Default value is C:\\Windows\\system32\\userinit.exe,
# anything additional here is suspicious
$userinit = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name Userinit -EA SilentlyContinue
[PSCustomObject]@{
  Source = 'HKLM\\Winlogon\\Userinit'
  Default = 'C:\\Windows\\system32\\userinit.exe,'
  Current = $userinit.Userinit
  Suspicious = ($userinit.Userinit -ne 'C:\\Windows\\system32\\userinit.exe,' -and
                $userinit.Userinit -notlike 'C:\\Windows\\system32\\userinit.exe,*')
}`,
        registry: `Primary logon script registry locations:

HKCU\\Environment\\UserInitMprLogonScript
- The obscure logon script trigger
- Per-user, no admin required to set
- Near-zero legitimate use - GPO mechanisms are
  the standard for legitimate logon scripts
- Value is a path to a script or executable
- Runs at user logon as the logging-on user

HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\
  Winlogon\\Userinit
- The Userinit process configuration
- DEFAULT VALUE: C:\\Windows\\system32\\userinit.exe,
  (note the trailing comma - intentional)
- Adversaries APPEND additional paths:
  C:\\Windows\\system32\\userinit.exe,C:\\malicious.exe
- All listed paths run at logon
- Modification requires admin / SYSTEM
- High-value adversary persistence (machine-wide)

HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\
  Winlogon\\Shell
- Default value: explorer.exe
- Adversaries replace with: explorer.exe,malicious.exe
  (multiple shells supported)
- Same-level visibility as Userinit changes

HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\
  Winlogon\\AppInit_DLLs
- List of DLLs loaded into every user32.dll-linked
  process (essentially everything)
- Disabled by default since Windows 8 if Secure Boot
  is enabled
- Still works on older systems / non-Secure-Boot
- Pair with LoadAppInit_DLLs = 1 to actually activate

Investigation pivots:
- Get the path/value, then:
  - Authenticode check on referenced binary
  - Last-write time on the registry key
    (Get-Item <key>).LastWriteTime
- Process tree at logon: did userinit spawn anything
  unexpected? (Sysmon EID 1, ParentImage=userinit.exe)`,
        tools: `Adversary use:

The UserInitMprLogonScript value is documented
in Mandiant / Microsoft post-incident analyses as
an underutilized persistence vector that bypasses
many common autorun checks (autoruns.exe DOES
catch it but custom defender scripts often don't).

Frameworks supporting this technique:
- Empire / Starkiller persistence modules
- SharPersist (registry persistence variants)
- Some commodity malware (less common - prefers
  the more well-known Run keys)
- Manual operator persistence in targeted ops

Why adversaries pick this over Run keys:
- Less commonly checked by defenders
- Per-user so any user can persist their own session
- Bypasses some EDR persistence-monitoring focused
  on Run/RunOnce paths
- Same effect (runs at logon) with less detection

Winlogon\\Userinit appending tradecraft:
- Most powerful of this technique family
- Machine-wide persistence as SYSTEM
- Runs BEFORE explorer.exe spawns
- Used by sophisticated operators
- Requires admin to set up

Detection note:
- These are not 'common' techniques in commodity
  malware - finding one suggests deliberate operator
- The default Userinit value is well-known
  (C:\\Windows\\system32\\userinit.exe,) - any
  deviation is anomalous

Sysinternals autoruns.exe coverage:
- Logon tab includes Userinit, Shell, AppInit_DLLs
- Also covers UserInitMprLogonScript
- Best for manual triage of this whole family`,
        ossdetect: `Sigma:
- registry_event_userinitmprlogonscript.yml
- registry_event_winlogon_userinit_modification.yml
- registry_event_winlogon_shell_modification.yml
- registry_event_appinit_dll_modification.yml

Atomic Red Team:
- T1037.001 (logon script via registry tests)

Hayabusa:
- UserInitMprLogonScript detection rules
- WinlogonUserinitModification rules

Velociraptor:
- Windows.Sys.AutoRuns (covers the whole family)
- Windows.Registry.NTUser (HKCU\\Environment enumeration)
- Best fleet-wide tooling

Sysinternals autoruns.exe:
- Logon tab - canonical coverage of this technique
- Highlights non-default Userinit / Shell values
- VirusTotal lookup on referenced binaries`,
        notes: "T1037.001 covers a small but high-signal cluster of logon script triggers. UserInitMprLogonScript is the most under-monitored: it's an obscure registry value that has essentially no legitimate use in modern Windows environments, so any value set there is high-confidence malicious. Compare to Run keys where dozens of legitimate entries exist - a UserInitMprLogonScript value is anomalous on first principles. The Winlogon\\Userinit append trick is more dangerous (runs as SYSTEM, machine-wide) and produces a distinctive artifact: the default value C:\\Windows\\system32\\userinit.exe, (with trailing comma) is well-known, so any deviation immediately stands out. The AppInit_DLLs technique was historically common but is largely defunct on modern Windows (Secure Boot disables it by default since Windows 8) - still worth checking on older systems or environments without Secure Boot enforced. The userinit.exe parent-process check in Sysmon EID 1 is the execution-time complement: userinit.exe spawning anything other than explorer.exe at logon time is worth investigating. This is the kind of technique that finding even once strongly suggests deliberate adversary presence - commodity malware rarely bothers with these because Run keys are simpler and work fine.",
        apt: [
          { cls: "apt-cn", name: "APT41", note: "Logon script persistence documented across multiple sector intrusions." },
          { cls: "apt-ru", name: "APT29", note: "Winlogon-family persistence documented in long-dwell espionage operations." },
          { cls: "apt-kp", name: "Lazarus", note: "Userinit-family persistence documented in CISA advisories on DPRK operations." },
          { cls: "apt-mul", name: "Advanced Operators", note: "Less-known persistence locations preferred over common Run keys for evasion." },
          { cls: "apt-mul", name: "Red Teams", note: "Empire and SharPersist support these locations - standard advanced red team persistence." }
        ],
        cite: "MITRE ATT&CK T1037.001"
      },
      {
        sub: "T1037.003 - Network Logon Script (Group Policy)",
        indicator: "Logon or startup script configured via Group Policy - distributed from domain controller SYSVOL to all targeted workstations",
        sysmon: `// On workstation receiving GPO logon scripts:

// EID 11 - GPO scripts cached locally:
EventID=11
TargetFilename matches:
  *\\System32\\GroupPolicy\\User\\Scripts\\Logon\\*
  OR *\\System32\\GroupPolicy\\Machine\\Scripts\\Startup\\*
  OR *\\System32\\GroupPolicy\\Machine\\Scripts\\Shutdown\\*

// EID 1 - script execution at logon/startup:
EventID=1
ParentImage=*\\gpscript.exe
// gpscript.exe is the GPO script runner
// Children of gpscript indicate logon/startup scripts
// running - inspect what they execute

// On domain controller (if Sysmon deployed there):

// EID 11 - SYSVOL script changes:
EventID=11
TargetFilename matches:
  *\\SYSVOL\\<domain>\\Policies\\{GUID}\\
    User\\Scripts\\Logon\\*
  OR *\\SYSVOL\\<domain>\\Policies\\{GUID}\\
    Machine\\Scripts\\Startup\\*`,
        kibana: `// Workstation: GPO script files cached locally
winlog.event_id: 11
AND file.path: (*\\GroupPolicy\\User\\Scripts\\Logon\\* OR *\\GroupPolicy\\Machine\\Scripts\\Startup\\* OR *\\GroupPolicy\\Machine\\Scripts\\Shutdown\\*)

// Workstation: gpscript-spawned process at logon/startup
winlog.event_id: 1
AND process.parent.name: "gpscript.exe"

// Domain controller: SYSVOL script changes
winlog.event_id: 11
AND file.path: *\\SYSVOL\\*\\Policies\\*\\Scripts\\*

// Active Directory audit events (DC-side):
// 5136 Directory Service object modified
// 5137 Directory Service object created
// Filter to attribute changes on GPO objects (gPCMachineExtensionNames, gPCUserExtensionNames)`,
        powershell: `# Hunt for GPO-pushed logon/startup scripts on a workstation

# 1. Local GPO cache - scripts pulled from domain controller
$gpoPaths = @(
  'C:\\Windows\\System32\\GroupPolicy\\User\\Scripts\\Logon',
  'C:\\Windows\\System32\\GroupPolicy\\User\\Scripts\\Logoff',
  'C:\\Windows\\System32\\GroupPolicy\\Machine\\Scripts\\Startup',
  'C:\\Windows\\System32\\GroupPolicy\\Machine\\Scripts\\Shutdown'
)

foreach ($path in $gpoPaths) {
  if (Test-Path $path) {
    Get-ChildItem $path -Recurse -File -EA SilentlyContinue | ForEach-Object {
      $suspicious = @()

      # Check signature on executable scripts
      if ($_.Extension -match '\\.(exe|dll|ps1)$') {
        $sig = Get-AuthenticodeSignature $_.FullName -EA SilentlyContinue
        if ($sig.Status -ne 'Valid') {
          $suspicious += "Unsigned binary in GPO script path"
        }
      }

      # Read content for batch/script files
      if ($_.Extension -match '\\.(bat|cmd|vbs|ps1)$') {
        $content = Get-Content $_.FullName -Raw -EA SilentlyContinue
        if ($content -match '(http://|https://|powershell.*-enc|EncodedCommand|certutil|bitsadmin|FromBase64String)') {
          $suspicious += "Suspicious content in script"
        }
      }

      [PSCustomObject]@{
        Path = $_.FullName
        Size = $_.Length
        Modified = $_.LastWriteTime
        Type = if ($path -match 'Logon') { 'Logon' }
               elseif ($path -match 'Startup') { 'Startup' }
               elseif ($path -match 'Shutdown') { 'Shutdown' }
               elseif ($path -match 'Logoff') { 'Logoff' }
               else { 'Other' }
        Suspicious = if ($suspicious) { $suspicious -join '; ' } else { '' }
      }
    }
  }
}

# 2. Group Policy Resultant Set of Policy - what scripts actually apply
# Requires admin to run gpresult fully
$report = gpresult /Scope:Computer /R /Z 2>&1 |
  Select-String -Pattern 'Script Name|Last Time|GPO|Filtering' -Context 0,2
$report

# 3. Check the registry side of GPO script configuration:
$scriptKeys = @(
  'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts',
  'HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts'
)
foreach ($key in $scriptKeys) {
  if (Test-Path $key) {
    Write-Host "Found policy script key: $key" -ForegroundColor Yellow
    Get-ChildItem $key -Recurse | ForEach-Object {
      Get-ItemProperty $_.PSPath -EA SilentlyContinue
    }
  }
}`,
        registry: `Group Policy script storage and configuration:

On DOMAIN CONTROLLER (the canonical source):
\\\\<domain>\\SYSVOL\\<domain>\\Policies\\{GPO-GUID}\\
  User\\Scripts\\Logon\\
  User\\Scripts\\Logoff\\
  Machine\\Scripts\\Startup\\
  Machine\\Scripts\\Shutdown\\
- Scripts placed here are distributed to workstations
- {GPO-GUID} identifies the specific Group Policy Object
- gpt.ini in the GPO folder defines policy version
- scripts.ini in Scripts folder lists ordered script
  execution

On WORKSTATION (the local cache):
C:\\Windows\\System32\\GroupPolicy\\
  User\\Scripts\\Logon\\
  User\\Scripts\\Logoff\\
  Machine\\Scripts\\Startup\\
  Machine\\Scripts\\Shutdown\\
- Cached copy of GPO scripts pulled from domain controller
- Refreshed at GPO update intervals (default 90 min)
- Run by gpscript.exe at appropriate trigger

Registry policy configuration:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\
  Startup\\<index>\\
  Shutdown\\<index>\\
HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\
  Logon\\<index>\\
  Logoff\\<index>\\
- Each numbered subkey is a configured script
- Values: Script (path), Parameters, FileSysPath, GPO link
- Presence of these keys means GPO scripts are configured

Adversary tradecraft - domain-wide persistence:
1. Compromise a domain admin account
2. Create or modify a GPO with malicious logon script
3. Apply GPO to broad scope (Domain Users group,
   specific OU, or whole domain)
4. Script distributes via SYSVOL replication to all DCs
5. Workstations pull and execute at next logon
6. Every user in scope runs adversary code at logon
   on every workstation - massive persistence multiplier

This is one of the highest-impact persistence techniques
in Active Directory environments - one GPO modification
can establish persistence on thousands of endpoints
simultaneously.

Investigation pivots:
- AD audit events 5136/5137 on DC (GPO modifications)
- SYSVOL file write events on DC (script content changes)
- Workstation gpscript.exe child process events
- Compare GPO version numbers across DCs (replication
  validation)`,
        tools: `GPO-based persistence is a sophisticated adversary
technique - typically requires domain admin
compromise as a prerequisite.

Used by:
- APT operators after AD compromise
- Ransomware operators for mass deployment
- BloodHound / SharpHound-equipped red teams who
  identify domain admin paths
- Various China-nexus and Russia-nexus APT groups
- Documented heavily in 2017+ as a primary
  ransomware deployment mechanism

Tool support:
- New-GPLink / Set-GPLink (built-in PowerShell ActiveDirectory module)
- Group Policy Management Console (gpmc.msc)
- SharpGPOAbuse (red team tool for GPO modification)
- Custom scripts using AD COM objects

Why this is uniquely powerful:
- One modification = persistence on many endpoints
- Native AD mechanism - signed/trusted Microsoft code
- Bypasses endpoint-only persistence detection
  (the artifact lives on the DC, not the endpoint)
- Replication ensures redundancy across DCs

Common adversary GPO script patterns:
- Drop and run beacon binary
- Add user to local admin group
- Disable security tools
- Stage credential dumpers
- Modify defender registry settings

Detection note:
This technique is fundamentally about DOMAIN-level
detection rather than endpoint-only - the most
valuable telemetry comes from the DC:
- AD audit logs (EID 5136/5137 on GPO objects)
- SYSVOL file change monitoring
- GPO version number tracking

For endpoint detection, focus on:
- The local GroupPolicy cache (script files cached
  on workstation)
- gpscript.exe parent process events at logon/startup
- Anomalous script content in cached files

Red team reference:
- 'The Most Dangerous User Right You Probably Never
  Heard Of' - SpecterOps research on GPO abuse
- BloodHound documentation on GPO attack paths`,
        ossdetect: `Sigma:
- file_event_win_gpo_script_creation.yml
- proc_creation_win_gpscript_child.yml
- ad_security_gpo_object_modification.yml (EID 5136)

Atomic Red Team:
- T1037.003 (network logon script tests)
- T1484.001 (GPO modification - upstream technique)

Hayabusa:
- GPOScriptCacheModification rules
- GpScriptUnexpectedChild detection
- ADGPOObjectModification (DC-side rules)

Velociraptor:
- Windows.AD.GPOAnalysis (GPO-focused artifact)
- Windows.System.GroupPolicy
- Best for fleet-wide / cross-domain analysis

PingCastle / BloodHound:
- AD-focused security analysis tools
- Identify GPO attack paths and unusual GPO
  configurations
- Useful for proactive AD security review

Microsoft documentation:
- Group Policy security best practices
- GPO audit configuration guidance

SpecterOps research:
- Various GPO abuse and detection writeups
- Foundational understanding of the attack surface

Critical reference - SANS:
'Detecting GPO Abuse for Persistence'
- Foundational defender reading for this technique`,
        notes: "GPO-based persistence (T1037.003) is one of the highest-impact persistence techniques in Active Directory environments because a single GPO modification on a domain controller can establish persistence on every workstation joined to the domain. This is a 'force multiplier' technique - it requires more initial access (domain admin) but provides exponentially more persistence reach than per-endpoint techniques. The technique is heavily documented in ransomware incident response: ransomware operators commonly compromise domain admin, then push deployment via GPO logon script to ensure ransomware runs on every workstation at next logon. Detection is split between endpoint and DC: endpoint detection focuses on the local GroupPolicy cache and gpscript.exe parent process events; DC detection focuses on AD audit events (5136/5137) on GPO objects and SYSVOL file changes. The endpoint side alone is not sufficient because the artifact source is the DC - a GPO change replicates to all workstations, and by the time you notice at one workstation, hundreds may already be affected. Pair endpoint detection with DC-side audit log forwarding and SYSVOL file change monitoring for full coverage. T1037.001 (registry-based logon script) is per-user / per-endpoint scope; T1037.003 (GPO) is domain-wide scope - the difference in impact is enormous.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "GPO-based persistence documented in SolarWinds and other long-dwell operations." },
          { cls: "apt-cn", name: "APT41", note: "GPO modification for persistence documented across sector-targeting operations." },
          { cls: "apt-mul", name: "Ransomware", note: "GPO logon script deployment is a standard ransomware mass-deployment mechanism - documented across Ryuk, Conti, BlackCat, LockBit, REvil." },
          { cls: "apt-mul", name: "FIN6", note: "Domain-level persistence including GPO abuse documented in financial sector intrusions." },
          { cls: "apt-mul", name: "Red Teams", note: "SharpGPOAbuse and BloodHound-driven attack paths make this standard advanced red team tradecraft after domain admin." }
        ],
        cite: "MITRE ATT&CK T1037.003, T1484.001"
      }
    ]
  },
  {
    id: "T1098",
    name: "Account Manipulation",
    desc: "Modifying existing accounts for persistence - password resets, group additions, ACL changes, SID history injection",
    rows: [
      {
        sub: "T1098 - Privileged Group Membership Changes",
        indicator: "User added to local Administrators, Domain Admins, Enterprise Admins, or other high-privilege group - backdoor admin or privilege retention",
        sysmon: `// Sysmon EID 1 - net.exe / dsadd / dsmod / Add-LocalGroupMember:
EventID=1
Image matches:
  *\\net.exe OR *\\net1.exe
  OR *\\dsadd.exe OR *\\dsmod.exe
  OR *\\powershell.exe
CommandLine matches:
  *localgroup*add*
  OR *group*/add*
  OR *Add-LocalGroupMember*
  OR *Add-ADGroupMember*
  OR *Administrators*
  OR *Domain Admins*
  OR *Enterprise Admins*

// Windows Security Event - the gold standard:
EventID=4732 (member added to security-enabled local group)
EventID=4728 (member added to security-enabled global group)
EventID=4756 (member added to security-enabled universal group)`,
        kibana: `// Process-based: group manipulation commands
winlog.event_id: 1
AND process.command_line: (*localgroup*add* OR *Add-LocalGroupMember* OR *Add-ADGroupMember* OR (*group*/add* AND (*Administrators* OR *Domain Admins* OR *Enterprise Admins*)))

// Security event: group membership changes (most reliable)
winlog.event_id: (4732 OR 4728 OR 4756)
AND winlog.channel: "Security"

// Tighten to high-privilege groups by SID:
// S-1-5-32-544 = Administrators (built-in)
// Domain Admins / Enterprise Admins = dynamic SIDs ending in -512 / -519
winlog.event_id: (4732 OR 4728 OR 4756)
AND winlog.event_data.TargetSid: (*-512 OR *-519 OR "S-1-5-32-544")`,
        powershell: `# Hunt 1: Recent privileged group membership changes (Security log)
$privGroupEvents = @(4732, 4728, 4756)
Get-WinEvent -FilterHashtable @{
  LogName='Security';
  ID=$privGroupEvents
} -ErrorAction SilentlyContinue | ForEach-Object {
  $xml = [xml]$_.ToXml()
  $data = @{}
  $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }

  [PSCustomObject]@{
    Time = $_.TimeCreated
    EventID = $_.Id
    Action = switch ($_.Id) {
      4732 {'Added to local group'}
      4728 {'Added to global group'}
      4756 {'Added to universal group'}
    }
    GroupName = $data['TargetUserName']
    MemberSid = $data['MemberSid']
    MemberName = $data['MemberName']
    AddedBy = $data['SubjectUserName']
  }
} | Sort-Object Time -Descending

# Hunt 2: Current membership of high-privilege groups
Write-Host "\`n=== Local Administrators ===" -ForegroundColor Cyan
Get-LocalGroupMember -Group 'Administrators' |
  Select Name, ObjectClass, PrincipalSource

# Domain Admins (run on domain-joined host with RSAT)
if (Get-Module -ListAvailable ActiveDirectory) {
  Write-Host "\`n=== Domain Admins ===" -ForegroundColor Cyan
  Import-Module ActiveDirectory
  Get-ADGroupMember -Identity 'Domain Admins' |
    Select Name, SamAccountName, ObjectClass, DistinguishedName

  Write-Host "\`n=== Enterprise Admins ===" -ForegroundColor Cyan
  Get-ADGroupMember -Identity 'Enterprise Admins' |
    Select Name, SamAccountName, ObjectClass, DistinguishedName

  Write-Host "\`n=== Schema Admins ===" -ForegroundColor Cyan
  Get-ADGroupMember -Identity 'Schema Admins' |
    Select Name, SamAccountName, ObjectClass, DistinguishedName
}

# Hunt 3: Local admin via process execution (Sysmon)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational';
  ID=1
} | Where-Object {
  $_.Properties[10].Value -match
    '(localgroup\\s+(?:administrators|admins)\\s+/add|Add-LocalGroupMember|Add-ADGroupMember.*(?:Domain|Enterprise|Schema)\\s+Admins)'
} | Select TimeCreated,
  @{n='User';e={$_.Properties[12].Value}},
  @{n='CmdLine';e={$_.Properties[10].Value}} |
  Sort-Object TimeCreated -Descending`,
        registry: `Local group membership storage:
- HKLM\\SAM\\SAM\\Domains\\Builtin\\Aliases\\Members\\
  S-1-5-32\\<group RID>\\
  Binary values listing member SIDs
- Default access via SYSTEM only - not readable
  with typical admin tools without elevation
- Use Get-LocalGroupMember or net localgroup
  for live-host enumeration

Domain group membership (DC-side):
- Stored in ntds.dit on domain controllers
- 'member' attribute on group objects
- Backlinks via 'memberOf' attribute on user objects
- Hunt with Active Directory PowerShell module:
  Get-ADGroupMember -Identity 'Domain Admins'
- Or ADSI Edit / ADUC GUI on the DC

Key forensic events to correlate:

Windows Security log (DC for domain, local for workstation):
4720 - User account created (T1136 - covered separately)
4722 - User account enabled (re-enabled disabled account)
4724 - Password reset (admin reset another user's password)
4725 - User account disabled
4728 - Member added to security-enabled global group
4729 - Member removed from security-enabled global group
4732 - Member added to security-enabled local group
4733 - Member removed from security-enabled local group
4738 - User account changed
4756 - Member added to security-enabled universal group
4767 - User account unlocked
4781 - User account name changed

Investigation pivots:
- Who initiated the change? (SubjectUserName in 4732/4728)
- Was the change made remotely? Cross-reference with
  4624 logon events from the same SubjectLogonId
- Was the new admin used immediately afterward?
  Look for 4624 LogonType=2 (interactive) or
  LogonType=3 (network) with the added account

Long-dwell adversary pattern:
- Add backup admin account
- Wait days/weeks before using it (defender attention fades)
- Use only periodically to maintain access
- Detection requires looking at the membership snapshot,
  not just real-time additions`,
        tools: `Tools used to manipulate group membership:

Built-in Windows:
- net.exe localgroup <group> <user> /add
- net.exe group <group> <user> /add /domain
- dsadd / dsmod (AD command-line tools)
- PowerShell ActiveDirectory module:
  Add-ADGroupMember -Identity 'Domain Admins'
    -Members 'compromised_user'
- PowerShell LocalAccounts module:
  Add-LocalGroupMember -Group 'Administrators'
    -Member 'backdoor_user'

Adversary frameworks:
- Cobalt Strike (built-in 'powershell-import' for AD commands)
- Empire / Starkiller (privesc and persistence modules)
- BloodHound + SharpHound (identify privilege paths,
  then operators execute the membership changes manually)
- Mimikatz (Kerberos manipulation often paired with
  group changes for persistence)

Common adversary patterns:

Pattern 1 - 'Add and wait':
- Add a low-profile existing account to Administrators
- Don't use immediately
- Used as backup access if primary persistence is found

Pattern 2 - 'Service account hijack':
- Identify existing service account (less monitored)
- Add to Domain Admins
- Use service account's existing logon patterns to blend in

Pattern 3 - 'Nested group abuse':
- Add user to a group that's nested INSIDE Administrators
- E.g. add to 'Help Desk' group if Help Desk is a member
  of Administrators
- More evasive because direct admin enumeration may miss
  nested membership

Detection considerations:
- Recursive group membership analysis is essential -
  Get-ADGroupMember -Recursive
- Some legitimate IT operations cause these events
  (new admin onboarding, group restructuring) -
  context matters
- Frequency baseline helps: changes to Domain Admins
  in a stable environment should be rare`,
        ossdetect: `Sigma:
- win_security_admin_group_modification.yml (EID 4732/4728)
- proc_creation_win_net_admin_add.yml
- proc_creation_win_powershell_add_localgroup_member.yml

Atomic Red Team:
- T1098.007 (Add local user to admin group)
- T1098 (broader account manipulation tests)

Hayabusa:
- LocalAdminGroupChange rules (EID 4732)
- DomainAdminGroupChange rules (EID 4728)
- High-priority alerts in default ruleset

Velociraptor:
- Windows.System.LocalGroups
- Windows.AD.GroupMembership
- Run on demand for fleet-wide membership snapshots

PingCastle / BloodHound:
- AD-focused security analysis
- Identify abnormal group memberships and attack paths
- Useful for proactive review and baseline establishment

ADRecon (Sense of Security):
- PowerShell-based AD reconnaissance / audit tool
- Returns comprehensive privileged group inventory

Microsoft Defender for Identity (if licensed):
- AD-aware monitoring with built-in alerts
- Catches anomalous privileged group additions
- Useful supplementary detection layer`,
        notes: "Privileged group manipulation is one of the most consequential persistence techniques because it directly grants the adversary administrative authority. The detection lives primarily in Windows Security events (4732 for local groups, 4728/4756 for domain global/universal groups) rather than Sysmon - Security log monitoring is essential for this technique. The high-value events to monitor are additions to: built-in Administrators (SID S-1-5-32-544), Domain Admins (RID 512), Enterprise Admins (RID 519), and Schema Admins. Nested group abuse is worth understanding: defenders often check direct Administrators membership but miss nested memberships - if 'Help Desk' is a member of 'Administrators' and the adversary adds themselves to 'Help Desk', direct enumeration misses them. The recursive enumeration in the PowerShell script handles this. The 'add and wait' pattern is the classic long-dwell adversary tradecraft: backdoor account added, then sits unused for weeks while initial intrusion artifacts are investigated and cleaned. Membership snapshot comparison against a known-good baseline is the only reliable detection for this pattern - real-time event detection works for fresh additions but misses pre-existing manipulation. PingCastle is genuinely useful for proactive AD security review; if you have RSAT and AD access, run it on a domain controller periodically.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Account manipulation for persistence documented extensively across SolarWinds follow-on activity." },
          { cls: "apt-cn", name: "APT41", note: "Privilege group additions and backdoor account creation documented across multiple sector intrusions." },
          { cls: "apt-mul", name: "Ransomware", note: "Privileged group additions standard tradecraft before encryption deployment - documented across Ryuk, Conti, BlackCat, LockBit." },
          { cls: "apt-mul", name: "Red Teams", note: "BloodHound-identified privilege paths + manual group additions are standard advanced red team tradecraft." },
          { cls: "apt-ir", name: "APT34", note: "Account manipulation for persistence documented in operations against Middle East targets." }
        ],
        cite: "MITRE ATT&CK T1098, T1098.007"
      },
      {
        sub: "T1098 - Password Reset and Service Account Manipulation",
        indicator: "Administrator reset password for another user (especially privileged), or service account credentials modified - credential-based persistence",
        sysmon: `// Sysmon EID 1 - password reset commands:
EventID=1
Image matches:
  *\\net.exe OR *\\net1.exe
  OR *\\powershell.exe
CommandLine matches:
  *user*<username>* AND *password*
  OR *Set-ADAccountPassword*
  OR *Reset-AD*

// Security Events (more reliable than Sysmon for this):
EventID=4724 (admin reset another user's password)
EventID=4723 (user changed own password - normal but
              worth correlating)
EventID=4738 (user account changed - broader event
              that fires on many attribute changes
              including password reset)`,
        kibana: `// Password reset events (admin reset, not self-change)
winlog.event_id: 4724
AND winlog.channel: "Security"

// User account modified - broad attribute changes
winlog.event_id: 4738
AND winlog.channel: "Security"

// Process-based detection
winlog.event_id: 1
AND process.command_line: (*Set-ADAccountPassword* OR *Reset-AD* OR (*net user* AND *password*))`,
        powershell: `# Hunt for recent password reset events (admin reset another user)
Get-WinEvent -FilterHashtable @{
  LogName='Security';
  ID=4724
} -ErrorAction SilentlyContinue | ForEach-Object {
  $xml = [xml]$_.ToXml()
  $data = @{}
  $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }

  [PSCustomObject]@{
    Time = $_.TimeCreated
    TargetAccount = $data['TargetUserName']
    TargetDomain = $data['TargetDomainName']
    ResetBy = $data['SubjectUserName']
    ResetByDomain = $data['SubjectDomainName']
  }
} | Sort-Object Time -Descending

# Hunt for kerberos ticket-granting-ticket changes
# (krbtgt password reset is a common DCSync recovery
# operation but also an adversary cleanup activity)
Get-WinEvent -FilterHashtable @{
  LogName='Security';
  ID=4738
} -ErrorAction SilentlyContinue | ForEach-Object {
  $xml = [xml]$_.ToXml()
  $data = @{}
  $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }

  if ($data['TargetUserName'] -match '(krbtgt|admin|administrator|svc_|service)') {
    [PSCustomObject]@{
      Time = $_.TimeCreated
      Target = $data['TargetUserName']
      ModifiedBy = $data['SubjectUserName']
      AttributeChange = $data['AttributeLDAPDisplayName']
    }
  }
} | Sort-Object Time -Descending

# AD attribute hunt - users with recent pwdLastSet
# (requires RSAT / ActiveDirectory module)
if (Get-Module -ListAvailable ActiveDirectory) {
  $cutoff = (Get-Date).AddDays(-30)
  Get-ADUser -Filter * -Properties PasswordLastSet, MemberOf |
    Where-Object { $_.PasswordLastSet -gt $cutoff } |
    Select Name, SamAccountName, PasswordLastSet,
      @{n='MemberOf';e={($_.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace '^CN=','' }) -join '; '}} |
    Sort-Object PasswordLastSet -Descending
}`,
        registry: `Password storage references:

Local accounts:
- HKLM\\SAM\\SAM\\Domains\\Account\\Users\\<RID>\\
  V (binary value containing user account data
     including encrypted password hash)
- Default access SYSTEM only - inaccessible to
  normal admin tools
- Hash extraction requires reg save + offline parsing
  (or live-system memory access via Mimikatz etc.)
- DPAPI master keys protect cached credentials

Domain accounts:
- Stored in ntds.dit on domain controllers
- Not directly readable - requires DC privilege
  or DCSync to extract
- Password reset events on DC are the primary
  detection point

Service account specifics:
- Service accounts have passwords stored in LSA Secrets:
  HKLM\\SECURITY\\Policy\\Secrets\\<service_account>
- Each service running as a named account has its
  password cached here
- Adversaries with SYSTEM privilege can read these
  (Mimikatz lsadump::secrets)
- Recovery scenario: adversary reads service account
  password, then uses it from elsewhere - no
  reset event needed, just a normal logon from
  a new location

Key audit events:

DC-side (domain accounts):
- 4724 - Admin reset another user's password
- 4723 - User changed own password
- 4738 - User account changed (catches password reset
         and many other attribute changes)
- 4781 - User account name changed (sAMAccountName)
- 5136 - Directory service object modified
         (raw attribute-level changes including
          password-related attributes)

Local workstation:
- Same 4724/4723/4738 in workstation Security log
  for local account changes

Forensic timeline reconstruction:
- Correlate 4724 (reset) with subsequent 4624 (logon)
  events for the same TargetUserName
- If reset by suspicious account, and account then
  used immediately = high-confidence credential
  manipulation for access

Service account manipulation patterns:
- Reset password of low-monitored service account
- Use the new password for lateral movement / persistence
- Service still functions because adversary controls
  the new credentials
- Detection: pwdLastSet attribute change on service
  account, then anomalous logon source for that account`,
        tools: `Tools and frameworks:

Built-in Windows:
- net user <name> <new_password>
- net user <name> <new_password> /domain
- Set-ADAccountPassword (PowerShell AD module)
- dsmod user <DN> -pwd <new_password>
- Windows ADUC GUI

Adversary tools:
- Mimikatz (sekurlsa::pth - pass-the-hash bypasses
  the need for password reset)
- Mimikatz (lsadump::secrets - extract service
  account passwords)
- Impacket (various credential manipulation)
- DSInternals (PowerShell module - low-level AD
  credential operations)
- Custom scripts using Kerberos APIs

Common adversary patterns:

Pattern 1 - Service account takeover:
- Identify high-privilege service account
- Reset its password (or read existing via LSA secrets)
- Use credentials for lateral movement
- Service still functions = no operational alert

Pattern 2 - Disabled account reactivation:
- Find disabled account with previous privileges
- Reset password and re-enable
- Account has historic legitimacy - blends in
- Especially effective with former-employee accounts
  that weren't fully purged

Pattern 3 - Krbtgt password reset abuse:
- The krbtgt account encrypts all Kerberos TGTs
- Adversary with DCSync rights extracts krbtgt hash
- Creates 'golden tickets' valid for 10 years (default)
- Even if other persistence is removed, golden tickets
  remain valid until krbtgt is reset TWICE
- Detection challenge: krbtgt hash extraction may not
  generate distinctive events depending on technique

Defensive note - krbtgt rotation:
- Microsoft recommends krbtgt password reset twice
  consecutively (with ~10 hour gap) after suspected
  compromise to invalidate any extracted hashes
- Reset twice because Kerberos retains previous
  krbtgt key for backward compatibility
- This is sometimes called 'krbtgt double-tap'`,
        ossdetect: `Sigma:
- win_security_user_password_reset.yml (EID 4724)
- win_security_user_modified.yml (EID 4738)
- proc_creation_win_net_user_password.yml
- proc_creation_win_powershell_set_adaccount_password.yml

Atomic Red Team:
- T1098 (account manipulation tests including
  password reset variants)

Hayabusa:
- AdminPasswordReset rules (EID 4724)
- ServiceAccountPasswordChange detection

Velociraptor:
- Windows.AD.UserAccountChanges
- Windows.AD.PrivilegedUserChanges
- Windows.EventLogs.AdvancedSecurityAuditing

Microsoft Defender for Identity:
- Built-in alerts for suspicious password reset
- AD-aware so it catches DC-side events natively
- One of the more valuable supplementary tools
  for this technique class

PingCastle:
- AD security review tool
- Identifies abnormal account configurations
- Useful for proactive baseline establishment

Reference:
- Microsoft 'Securing Privileged Access' guidance
- SANS DFIR poster on Active Directory forensics`,
        notes: "Password reset and service account manipulation is a subtle form of persistence - the account already exists, so there's no creation event to detect; the manipulation is purely a credential operation. The Windows Security event 4724 (admin reset another user's password) is the primary signal but requires context to be useful: legitimate IT help desk operations cause this event constantly. Detection focus should be: who reset whose password, was the target a privileged or service account, was the resetter expected to perform that action, and was the target account used immediately after the reset from an unusual location. The 'pwdLastSet attribute hunt' in the PowerShell script is a useful baseline-deviation approach: list all AD users whose password changed in the last 30 days, focus on privileged accounts and service accounts in that list. Krbtgt password reset is the high-value extreme of this technique - the krbtgt account encrypts all Kerberos TGTs, so adversaries who extract the krbtgt hash can mint 'golden tickets' valid for years. This is why Microsoft recommends 'krbtgt double-tap' (reset twice consecutively) after suspected compromise - one reset isn't enough because Kerberos retains the previous key for backward compatibility. Pair this hunt with privileged group membership analysis (previous indicator) - account manipulation often combines with group additions for compound persistence.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Account manipulation and credential persistence documented across long-dwell espionage operations." },
          { cls: "apt-cn", name: "APT41", note: "Service account password manipulation documented across sector-targeting operations." },
          { cls: "apt-mul", name: "Ransomware", note: "Service account takeover for lateral movement standard across Ryuk, Conti, BlackCat operations." },
          { cls: "apt-mul", name: "Golden Ticket Operators", note: "Krbtgt manipulation for long-term Kerberos persistence documented across multiple advanced groups." },
          { cls: "apt-ir", name: "APT34", note: "Account credential manipulation documented in operations targeting Middle East infrastructure." }
        ],
        cite: "MITRE ATT&CK T1098"
      }
    ]
  },
  {
    id: "T1136",
    name: "Create Account",
    desc: "Creating new local or domain accounts for persistence - hidden accounts, RID-cloned accounts, machine accounts",
    rows: [
      {
        sub: "T1136.001 - Local Account Creation",
        indicator: "New local user account created on workstation or server - backdoor account for persistent local access",
        sysmon: `// Sysmon EID 1 - account creation commands:
EventID=1
Image matches:
  *\\net.exe OR *\\net1.exe
  OR *\\powershell.exe
CommandLine matches:
  *user*/add*
  OR *New-LocalUser*

// Security Event (more reliable - all creation methods):
EventID=4720 (user account created - workstation/local)
EventID=4722 (user account enabled - account just created
              is implicitly enabled; this event often
              fires alongside 4720)
EventID=4732 (added to local group - follow-up event
              after creation, often Administrators)`,
        kibana: `// Account creation events
winlog.event_id: 4720
AND winlog.channel: "Security"

// Process-based detection
winlog.event_id: 1
AND process.command_line: (*New-LocalUser* OR (*net user* AND */add*))

// Local Administrators addition after creation
winlog.event_id: 4732
AND winlog.event_data.TargetSid: "S-1-5-32-544"`,
        powershell: `# Hunt 1: Recent local user account creation events
Get-WinEvent -FilterHashtable @{
  LogName='Security';
  ID=4720
} -ErrorAction SilentlyContinue | ForEach-Object {
  $xml = [xml]$_.ToXml()
  $data = @{}
  $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }

  [PSCustomObject]@{
    Time = $_.TimeCreated
    NewAccount = $data['TargetUserName']
    CreatedBy = $data['SubjectUserName']
    SubjectDomain = $data['SubjectDomainName']
  }
} | Sort-Object Time -Descending

# Hunt 2: Current local account inventory + recent
$cutoff = (Get-Date).AddDays(-30)
Get-LocalUser | ForEach-Object {
  $user = $_
  $isRecent = $user.PasswordLastSet -gt $cutoff

  $suspicious = @()
  if ($isRecent) { $suspicious += "Password set within 30 days" }
  if ([string]::IsNullOrEmpty($user.FullName) -and
      [string]::IsNullOrEmpty($user.Description)) {
    $suspicious += "No FullName or Description"
  }
  if ($user.Name -match '^[a-z0-9]{1,4}$') {
    $suspicious += "Short / generic name"
  }

  # Check if member of Administrators
  $isAdmin = $false
  try {
    Get-LocalGroupMember -Group 'Administrators' -EA SilentlyContinue |
      ForEach-Object {
        if ($_.Name -match $user.Name -or $_.SID -eq $user.SID) { $isAdmin = $true }
      }
  } catch { }
  if ($isAdmin) { $suspicious += "Member of Administrators" }

  [PSCustomObject]@{
    Name = $user.Name
    FullName = $user.FullName
    Description = $user.Description
    Enabled = $user.Enabled
    PasswordLastSet = $user.PasswordLastSet
    LastLogon = $user.LastLogon
    IsAdmin = $isAdmin
    Suspicious = if ($suspicious) { $suspicious -join '; ' } else { '' }
  }
} | Sort-Object Suspicious -Descending | Format-Table -AutoSize

# Hunt 3: Hidden accounts - check SAM registry for
# accounts not visible to Get-LocalUser
# (requires SAM access - usually SYSTEM or reg.exe save)
Write-Host "\`nNote: Use 'reg save HKLM\\SAM samdump.hive'" -ForegroundColor Yellow
Write-Host "then parse offline with secretsdump or impacket" -ForegroundColor Yellow
Write-Host "to surface accounts hidden via SAM manipulation" -ForegroundColor Yellow`,
        registry: `Local account storage:
HKLM\\SAM\\SAM\\Domains\\Account\\Users\\
  Names\\<username>\\(default) = (RID)
  <RID>\\
    V = (binary - account data including hash)
    F = (binary - account flags)

Hiding techniques:

1. SAM ACL manipulation:
- Modify ACL on HKLM\\SAM\\SAM\\Domains\\Account\\Users\\
  Names\\<username>\\ to deny standard enumeration
- Get-LocalUser misses the account
- Account still functions
- Detection: reg save the SAM hive and parse offline -
  bypasses live ACL enforcement

2. Special name characters:
- Append '$' to account name (signals 'computer account'
  to many tools but creates a normal user)
- Some enumeration tools filter out '$'-suffixed names
- Hides from casual review
- Pattern: backupadmin$, svc_temp$, etc.

3. RID hijacking (rare but documented):
- Modify the SAM 'F' value to set a different RID
- Account inherits permissions of the RID's true owner
- Defender sees a low-privilege account name but
  the actual permissions are admin-level
- Detection requires SAM parsing comparing username
  field against actual RID value

Key audit events:
- 4720 - User account created
- 4722 - User account enabled
- 4724 - Password reset (paired with creation - admin
         sets initial password)
- 4738 - User account changed (broader event)

Investigation pivots after 4720:
- What account created the new user?
  (SubjectUserName / SubjectLogonId in 4720)
- Was the new account added to a privileged group
  immediately afterward? (EID 4732 with same subject)
- First logon by the new account? (4624 with the
  new account as TargetUserName)
- Lifecycle: 4720 (create) -> 4722 (enable) ->
  4724 (set password) -> 4732 (add to admins) ->
  4624 (first logon) - this sequence in close
  proximity is the classic adversary chain`,
        tools: `Account creation methods:

Built-in Windows:
- net user <name> <password> /add
- net user <name> <password> /add /domain (DC)
- New-LocalUser -Name <name> -Password <secure>
- New-ADUser (PowerShell AD module)
- Windows Users and Computers ADUC GUI
- Computer Management lusrmgr.msc GUI

Adversary frameworks:
- SharPersist (account creation variants)
- Empire / Starkiller (privesc and persistence modules)
- Cobalt Strike (built-in user/group commands)
- Most commodity malware avoids account creation
  (too noisy - generates 4720) but it's standard
  in manual operator persistence

Common adversary patterns:

Pattern 1 - Backup admin:
- Create account with innocuous name (svc_backup,
  helpdesk2, _system_user)
- Add to Administrators
- Use only sparingly to maintain access
- Often paired with disabling default Administrator

Pattern 2 - Mimicry account:
- Create account with name matching legitimate
  patterns (admin1 if admin exists, IT_Support2
  if IT_Support exists)
- Defender at-a-glance review misses one extra account

Pattern 3 - Hidden ($-suffix) account:
- Create account named like 'backup$' or 'svc_temp$'
- $-suffix sometimes signals 'computer account' to tools
- May not appear in standard Get-LocalUser output
  depending on tool implementation

Pattern 4 - Disable existing, create new:
- Disable legitimate admin (preventing log review
  by that user)
- Create new admin for adversary use
- Detection: 4725 (account disabled) paired with
  4720 (account created) in close time = anomalous

Detection considerations:
- Most environments have very low rates of new
  local account creation - any 4720 event on a
  workstation is worth review
- Server / domain controller account creation is
  more common (service accounts, admin onboarding)
- Combine with parent context: was the creating
  user expected to have user management privileges?`,
        ossdetect: `Sigma:
- win_security_local_user_creation.yml (EID 4720)
- win_security_admin_group_modification.yml (EID 4732)
- proc_creation_win_net_user_add.yml
- proc_creation_win_powershell_new_localuser.yml

Atomic Red Team:
- T1136.001 (local account creation tests)
- T1136.002 (domain account creation tests)

Hayabusa:
- LocalAccountCreation rules (EID 4720)
- High-priority alert in default ruleset
- LocalAdminAddedAfterCreation (correlates 4720+4732)

Velociraptor:
- Windows.System.LocalUsers
- Windows.SAM.OfflineParser (catches hidden accounts)

Sysinternals:
- AccessChk for ACL inspection on user objects
- Not specific to account creation but useful for
  identifying ACL-based hiding

Microsoft Defender:
- Built-in alerts for suspicious account creation
- Particularly aggressive on Defender for Endpoint
  for high-privilege accounts`,
        notes: "Local account creation is a noisy persistence technique - Windows Security Event 4720 fires reliably on every new user. The challenge is volume in larger environments where IT operations create new accounts regularly. The detection focus should be context: was the creating user expected to have user management rights, was the new account added to a privileged group within minutes (4720 + 4732 correlation), was the new account used from an unusual location at first logon. The 'lifecycle pattern' is the highest-fidelity signal: 4720 (create) -> 4722 (enable) -> 4724 (password set) -> 4732 (add to Administrators) -> 4624 (first logon) all within a short time window is the classic adversary chain. Legitimate IT onboarding usually has gaps between these events (separate help desk tickets, password coordination). Hidden accounts are a more sophisticated subset - SAM ACL manipulation makes the account invisible to Get-LocalUser, requiring offline SAM parsing to surface. The '$' suffix trick is sometimes used to hide accounts from casual review since many tools filter out '$'-suffixed names assuming they're computer accounts. Workstation account creation is rare in most environments - any 4720 on a workstation warrants investigation. Server account creation is more common but still worth context-checking. Pair with the T1098 indicators: account creation + group manipulation are often combined for compound persistence (new account + Administrators membership = backdoor admin).",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Local and domain account creation for persistence documented across espionage operations." },
          { cls: "apt-cn", name: "APT41", note: "Backdoor account creation documented across multiple sector intrusions." },
          { cls: "apt-mul", name: "Ransomware", note: "Backdoor admin account creation standard pre-encryption tradecraft across most ransomware operations." },
          { cls: "apt-kp", name: "Lazarus", note: "Local account creation for persistence documented in CISA advisories on DPRK operations." },
          { cls: "apt-mul", name: "Red Teams", note: "Account creation with mimicry naming standard advanced red team persistence." }
        ],
        cite: "MITRE ATT&CK T1136.001"
      },
      {
        sub: "T1136.002 - Domain Account Creation",
        indicator: "New domain user account created on domain controller - high-impact persistence across the entire AD environment",
        sysmon: `// On DOMAIN CONTROLLER (where this technique fires):

EventID=4720 (user account created)
LogName=Security
// Same event ID as local, but on DC = domain account

// Subsequent events to correlate:
EventID=4722 (account enabled)
EventID=4724 (initial password set)
EventID=4728 (added to Domain Admins or other
              global group)

// Sysmon process detection (if deployed on DC):
EventID=1
Image=*\\net.exe OR *\\powershell.exe OR *\\dsadd.exe
CommandLine matches:
  *user*/add*/domain*
  OR *New-ADUser*
  OR *dsadd*user*

// AD object creation event (DC-side):
EventID=5137 (Directory Service object created)
// More detailed than 4720 - includes the full DN
// of the new object and the creator's identity`,
        kibana: `// Domain user creation on DC
winlog.event_id: 4720
AND winlog.channel: "Security"
AND host.name: <domain controller>

// AD object creation
winlog.event_id: 5137
AND winlog.event_data.ObjectClass: "user"

// Process-based on DC
winlog.event_id: 1
AND host.name: <domain controller>
AND process.command_line: (*New-ADUser* OR (*net user* AND */add* AND */domain*) OR *dsadd*user*)`,
        powershell: `# Hunt for recent domain user creation (run on DC or via remote query)
# Requires Security log access on the domain controller

Get-WinEvent -ComputerName <DC_name> -FilterHashtable @{
  LogName='Security';
  ID=4720
} -ErrorAction SilentlyContinue | ForEach-Object {
  $xml = [xml]$_.ToXml()
  $data = @{}
  $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }

  [PSCustomObject]@{
    Time = $_.TimeCreated
    NewAccount = $data['TargetUserName']
    TargetDomain = $data['TargetDomainName']
    CreatedBy = $data['SubjectUserName']
    SubjectDomain = $data['SubjectDomainName']
  }
} | Sort-Object Time -Descending

# AD-side enumeration (requires ActiveDirectory module + permissions)
if (Get-Module -ListAvailable ActiveDirectory) {
  Import-Module ActiveDirectory
  $cutoff = (Get-Date).AddDays(-30)

  # Recently created user accounts
  Get-ADUser -Filter * -Properties whenCreated, MemberOf,
    Description, ServicePrincipalName |
    Where-Object { $_.whenCreated -gt $cutoff } |
    Select-Object Name, SamAccountName, whenCreated,
      @{n='Description';e={$_.Description}},
      @{n='Groups';e={
        $_.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace '^CN=','' }
      }},
      @{n='HasSPN';e={if ($_.ServicePrincipalName) { 'Yes' } else { 'No' }}} |
    Sort-Object whenCreated -Descending

  # Anomalous patterns
  Write-Host "\`n=== Accounts with no description ===" -ForegroundColor Yellow
  Get-ADUser -Filter * -Properties Description, whenCreated |
    Where-Object {
      [string]::IsNullOrEmpty($_.Description) -and
      $_.whenCreated -gt (Get-Date).AddDays(-90)
    } |
    Select Name, whenCreated

  Write-Host "\`n=== Accounts in 'CN=Users' default container ===" -ForegroundColor Yellow
  # Adversary-created accounts often left in default Users
  # CN rather than moved to proper OUs
  Get-ADUser -SearchBase "CN=Users,$((Get-ADDomain).DistinguishedName)" -Filter * -Properties whenCreated |
    Where-Object { $_.whenCreated -gt (Get-Date).AddDays(-30) } |
    Select Name, whenCreated, DistinguishedName
}`,
        registry: `Domain accounts live in ntds.dit on domain controllers,
not in the workstation registry. The relevant artifacts:

On DOMAIN CONTROLLER:
- ntds.dit (NTDS database) - contains all domain
  object data including user accounts
- C:\\Windows\\NTDS\\ntds.dit (default location)
- Modifications appear in Directory Service log:
  Event 5137 (object created)
  Event 5136 (object modified)
  Event 5141 (object deleted)

Key events to monitor on DC Security log:
- 4720 - User account created
- 4722 - Account enabled
- 4723 - User changed own password (later, after creation)
- 4724 - Admin set/reset password
- 4725 - Account disabled
- 4726 - Account deleted
- 4728 - Added to global group (Domain Admins etc.)
- 4738 - Account changed (general attribute changes)
- 4781 - Account name changed

Directory Service log events (more detailed):
- 5136 - Object modified
- 5137 - Object created
- 5138 - Object undeleted
- 5139 - Object moved
- 5141 - Object deleted

Adversary patterns specific to DC:

Pattern 1 - Add to standard Users CN:
- New accounts created via 'net user /domain' default to
  the CN=Users container
- Legitimate AD admins typically move accounts to
  proper OUs
- Accounts left in CN=Users are a soft signal

Pattern 2 - Service Principal Name (SPN) abuse:
- Set SPN on the new account to enable Kerberoasting
- Adversary then requests TGS for the SPN and cracks
  offline
- Detection: new account WITH a SPN attribute is
  unusual for non-service accounts

Pattern 3 - LAPS bypass via new admin:
- LAPS (Local Administrator Password Solution) only
  manages the BUILT-IN Administrator
- Creating a NEW domain account and adding to local
  Administrators on workstations bypasses LAPS
  rotation
- Backdoor that survives LAPS password rotation

Investigation pivots after 4720 on DC:
- Was creator a high-privilege admin? (subjects to scrutiny)
- Was the new account immediately added to a privileged
  group? (4728 with same subject)
- First logon for the new account? (4624 with new acct
  as target)
- What workstations did the account log onto?
  (Pattern analysis - sudden new account logging into
  many workstations = lateral movement)`,
        tools: `Tools for domain account creation:

Built-in:
- New-ADUser (PowerShell ActiveDirectory module)
- net user /add /domain (legacy command)
- dsadd user (legacy command-line tool)
- Active Directory Users and Computers (ADUC GUI)
- Active Directory Administrative Center (DSAC GUI)

Adversary tools:
- PowerShell Empire / Starkiller AD modules
- BloodHound + custom scripts (BloodHound identifies
  paths, manual creation executed afterward)
- Mimikatz (typically for credential ops alongside)
- Impacket (psexec.py + remote AD ops)
- Cobalt Strike with PowerShell-import for AD cmdlets

Domain account abuse patterns:

Pattern 1 - 'Just another user':
- Create account with name matching environment
  conventions (FirstName.LastName, F.LastName, etc.)
- Often pulled from publicly available employee
  information (LinkedIn, company website)
- Looks legitimate at first glance
- May survive months in environments with poor
  account hygiene

Pattern 2 - Service account creation:
- Create account named like a service account
  (svc_<something>, _service_user, etc.)
- Set never-expire password
- Add to Domain Admins or other privileged group
- Service accounts often have password rotation
  exemptions = long-lived persistence

Pattern 3 - Computer account abuse (T1136.003):
- Create COMPUTER account in AD
- Computer accounts have different audit footprint
- Some tools/queries filter out computer accounts
- Used for stealth or Kerberos protocol attacks
  (S4U2Self abuse, etc.)

Detection considerations:
- Domain account creation should be FAR rarer than
  workstation account creation in well-managed
  environments
- Establish baseline: how many new domain users per
  week is normal in your environment?
- Anomaly detection on creation rate alone catches
  bulk-creation incidents (mass automated account
  generation for spam, etc.)
- Pair user creation with subsequent privilege
  assignment events for highest-fidelity alerting`,
        ossdetect: `Sigma:
- win_security_domain_user_creation.yml (EID 4720 on DC)
- ad_security_object_creation.yml (EID 5137)
- proc_creation_win_powershell_new_aduser.yml
- proc_creation_win_dsadd_user.yml

Atomic Red Team:
- T1136.002 (domain account creation tests)
- T1136.003 (computer account creation tests)

Hayabusa:
- DomainUserCreation rules (EID 4720 on DC)
- DomainUserPrivEscalation (4720+4728 correlation)
- ADObjectCreation (EID 5137)

Velociraptor:
- Windows.AD.UserAccounts
- Windows.AD.RecentChanges
- Windows.AD.PrivilegedUserChanges

Microsoft Defender for Identity:
- Built-in alerts for anomalous user creation
- AD-aware so it catches DC-side events natively
- Reputation-based scoring on new accounts

PingCastle:
- AD security review tool
- Reports on recent account changes
- Useful for periodic AD security audit

ADRecon:
- Comprehensive AD enumeration tool
- Returns recent account creation alongside other
  AD metadata

Microsoft documentation:
- 'Best Practices for Securing Active Directory'
- Audit policy configuration guidance for DC events`,
        notes: "Domain account creation (T1136.002) is significantly higher impact than local account creation because the resulting account has domain-wide reach - it can authenticate to any workstation in the domain. The detection point is the Security log on the domain controller, not the workstation. This requires AD audit log forwarding to your SIEM and ensuring DC Security logs are actually being collected (a surprising number of environments don't forward DC logs centrally). The DS audit events (5136/5137) provide more detail than the user creation events but require Directory Service auditing to be enabled in Group Policy - check your audit configuration if these aren't appearing. The 'CN=Users default container' hunt in the PowerShell script is a useful soft signal: legitimate AD admins typically move new accounts to proper OUs after creation, while adversary-created accounts are often left in the default Users container. SPN attribute presence on a new user account is another useful flag - normal user accounts rarely have SPNs, but adversaries set them to enable Kerberoasting. Computer account creation (T1136.003) is sometimes preferred by adversaries because computer accounts have different audit characteristics and some defensive tools filter them out of user-focused queries. The compound pattern - 4720 (create) + 4724 (set password) + 4728 (add to Domain Admins) + 4624 (logon) in close time proximity - is the classic adversary chain and the highest-fidelity multi-event correlation for this technique.",
        apt: [
          { cls: "apt-ru", name: "APT29", note: "Domain account creation for persistence documented across SolarWinds and long-dwell operations." },
          { cls: "apt-cn", name: "APT41", note: "Backdoor domain accounts documented across sector-targeting operations." },
          { cls: "apt-mul", name: "Ransomware", note: "Domain admin account creation standard pre-encryption tradecraft across most ransomware operations." },
          { cls: "apt-mul", name: "FIN6", note: "Domain account creation documented in financial sector intrusions." },
          { cls: "apt-ir", name: "APT34", note: "Domain account manipulation documented in operations against Middle East infrastructure." }
        ],
        cite: "MITRE ATT&CK T1136.002, T1136.003"
      }
    ]
  }
];
