# host-reference

MITRE ATT&CK host-based detection reference. Sister site to [hunt-reference](https://hunt.6b74.dev) (network-side).

Live at: **https://host.6b74.dev**

## What this is

Offline-first single-page reference for host-based threat hunting. Each indicator includes:

- **Sysmon** event ID and field criteria
- **Kibana (KQL)** paste-ready query
- **PowerShell** hunt script (runs against Windows event logs directly)
- **Registry / file artifacts** to investigate
- **Adversary tools** known to use the technique
- **OSS detections** — Sigma rule references, Velociraptor artifacts, Hayabusa rules, Atomic Red Team test IDs
- **APT attribution** with color-coded origin chips
- **Operational notes** with FP guidance and edge cases

Persistent hunts via localStorage, cross-tab sync, CSV/TXT export with CMS-ready format.

## Architecture

| Path | Purpose |
|---|---|
| `index.html` | Tactic landing grid + switcher to network site |
| `<tactic>.html` | Per-tactic page (filter + render) |
| `js/core.js` | UI logic, hunt persistence, CMS templates |
| `js/data/<tactic>.js` | DATA array per tactic |
| `css/style.css` | Shared styling, dark theme matching network site |

Adding a new tactic:

1. Create `js/data/<tactic>.js` defining `const DATA = [...]`
2. Create `<tactic>.html` (copy `execution.html`, swap title and filter buttons)
3. Add a card to `index.html`
4. Add CMS_TEMPLATES entries to `js/core.js` for each new T-number

## Schema (per indicator row)

```js
{
  sub: "T1059.001 — Encoded Command Execution",
  indicator: "powershell.exe with -EncodedCommand argument...",
  sysmon: `EventID=1\nImage=*\\powershell.exe\nCommandLine=*-enc*`,
  kibana: `winlog.event_id: 1 AND process.name: ...`,
  powershell: `Get-WinEvent -FilterHashtable @{...}`,
  registry: "Registry/file artifact paths and investigation pivots",
  tools: "Adversary tools using this technique",
  ossdetect: "Sigma / Velociraptor / Hayabusa / Atomic Red Team references",
  notes: "Operational guidance and FP tuning",
  apt: [
    { cls: "apt-cn", name: "APT41", note: "Documented usage context" },
    { cls: "apt-mul", name: "Multi", note: "Cross-actor pattern" }
  ],
  cite: "MITRE ATT&CK T1059.001"
}
```

APT class values: `apt-cn` (China), `apt-ru` (Russia), `apt-ir` (Iran), `apt-kp` (DPRK), `apt-mul` (multi/red team/cybercrime).

## Coverage

| Tactic | ID | Techniques | Indicators |
|---|---|---|---|
| Execution | TA0002 | 1 of 13 built | 4 |
| Persistence | TA0003 | planned | - |
| Defense Evasion | TA0005 | planned | - |
| Privilege Escalation | TA0004 | planned | - |
| Credential Access (host) | TA0006 | planned | - |
| Discovery (host) | TA0007 | planned | - |

## Build status (Execution)

| Technique | Status |
|---|---|
| T1059.001 PowerShell | built (4 indicators) |
| T1059.003 cmd.exe | stub |
| T1059.005 Visual Basic | stub |
| T1059.007 JavaScript | stub |
| T1047 WMI | stub |
| T1053.005 Scheduled Task | stub |
| T1569.002 Service Execution | stub |
| T1218.005 Mshta | stub |
| T1218.011 Rundll32 | stub |
| T1218.010 Regsvr32 | stub |
| T1106 Native API | stub |
| T1129 Shared Modules | stub |
| T1204.002 User Execution | stub |

## Deploy (GitHub Pages)

1. Push this folder to a GitHub repo (e.g., `host-reference`)
2. Add a `CNAME` file at root containing `host.6b74.dev`
3. In Cloudflare DNS, add `CNAME` record: name `host`, target `<username>.github.io`, proxy OFF (gray cloud)
4. In GitHub repo Settings -> Pages, set custom domain to `host.6b74.dev`
5. Wait for DNS check + cert provisioning
6. Enable Enforce HTTPS

## License

MIT.
