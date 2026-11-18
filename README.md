
# 🛡️ Block RDP Brute Force Attacks on Windows
 
**A *fast* PowerShell script that detects and blocks RDP brute-force attacks on Windows, using only the Windows Event Log and the built-in Windows Firewall.**
 
Windows 10/11, Windows Server 2019/2022/2025
 
If you expose Remote Desktop (RDP, TCP 3389), including Web Access (RDWeb) and RD Gateways, to the internet, your Security log will fill up with failed logons within minutes. This script reads those failed logons, finds the offending IP addresses and blocks them in the Windows Firewall. Think of it as a lightweight **fail2ban alternative for Windows**: no agent, no service, no third-party software, no cloud.
 
`block_rdp_brute.ps1` It has been the "default go to" solution for native RD bruteforce protection in production since 2019.
 
## Features
 
- **No dependencies.** One `.ps1` file. Uses the Windows Event Log and Windows Firewall - which are already on your system.
- **Catches fast and slow attacks.** Three detection windows (15 minutes, 1 hour, 6 hours) find both noisy bots and "low and slow" brute-force attempts that stay below a single short threshold.
- **Fast.** The Security log is read with compiled C# (`EventLogReader`) and a time-bounded query instead of slow `Get-WinEvent` filtering.
- **IPv4 and IPv6.** Addresses are normalized (IPv4-mapped IPv6, zone IDs) before they are counted.
- **One firewall rule.** All blocked addresses go into a single inbound block rule (`BlockRDPBruteForce`). Entries and Options you add to that rule manually are preserved.
- **Safe by design.** Loopback, ULA, PIR and all addresses of the server itself are never blocked.
- **Auditable.** Every change is written to the Windows Application log (Event ID `13370`)
- **SOC Transparent** Errors are logged to the Eventlog, instead of silently swallowed.
- **Works everywhere PowerShell does.** Windows PowerShell 5.1 and PowerShell 7+ (recommended).
## Quick install
 
Run in an **elevated** PowerShell on Windows 10/11 or Windows Server 2025.
 
```powershell
# Create directory
New-Item -ItemType Directory -Path C:\Scripts -Force | Out-Null
# Download
curl.exe -fsSL -o C:\Scripts\block_rdp_brute.ps1 https://raw.githubusercontent.com/DATA-Systems/block-rdp-bruteforce/main/block_rdp_brute.ps1
# Create Scheduled Task
Register-ScheduledTask -TaskName "BlockRDPBruteForce" -User "SYSTEM" -RunLevel Highest -Force -Action (New-ScheduledTaskAction -Execute "powershell.exe" -Argument '-NoProfile -NoLogo -NonInteractive -ExecutionPolicy Bypass -File "C:\Scripts\block_rdp_brute.ps1"') -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5))
```
 
> ⚠️ Stay safe
> - Use `curl.exe`, not `curl`. In Windows PowerShell 5.1, `curl` is an alias for `Invoke-WebRequest` and the flags above do not work.
> - As with any script that runs as `SYSTEM`, read it before you schedule it. For reproducible installs, download from a release tag or a commit hash instead of `main`.
 
## How it works
 
On every run the script counts failed logons (Security log, Event ID `4625`) per source IP address and blocks every address that exceeds a threshold:
 
| Window | Blocks IPs with more than | When it is checked |
|---|---|---|
| Last 15 minutes | 25 failed logons | every run |
| Last 60 minutes | 45 failed logons | once per hour |
| Last 6 hours | 90 failed logons | every 3 hours (00:00, 03:00, 06:00, ...) |
 
New addresses are added to the inbound firewall rule `BlockRDPBruteForce` (`TCP`, local port `3389`, name customizeable). If the rule does not exist yet, it is created on the first hit. Run the task every 5 to 10 minutes; the longer windows are picked up automatically at the right times.
 
Each change is logged to the Application event log:
 
```
[BlockRDPBruteForce] Total: 12 / New: 203.0.113.7, 203.0.113.222
```
 
## Requirements
 
- Windows 10, Windows 11
- Windows Server 2019, 2022, 2025
- Windows PowerShell 5.1 (included) or (recommended) [PowerShell 7+](https://github.com/powershell/powershell/releases)
- Administrator rights (the script reads the Security log and changes firewall rules). A scheduled task running as `SYSTEM` covers this.
- Logon failure auditing enabled. This is the default on current Windows versions. Check it with:
```powershell
auditpol /get /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}"
```
 
If "Failure" is missing, enable it with:
 
```powershell
auditpol /set /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /failure:enable
```
 
## Manual run and verification
 
```powershell
# Run once (elevated)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Scripts\block_rdp_brute.ps1
 
# Show what the script has logged
Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Id = 13370 } -MaxEvents 20 |
    Format-List TimeCreated, LevelDisplayName, Message
 
# Show the firewall rule
Get-NetFirewallRule -DisplayName BlockRDPBruteForce | Get-NetFirewallAddressFilter
```
 
No output is normal: the script only logs and changes something when it finds new addresses to block.
 
## Unblocking an address
 
Open `wf.msc`, edit the rule **BlockRDPBruteForce**, go to *Properties → Scope → Remote IP address* and remove the entry.

To **clear the whole list**, just delete the rule; it is recreated freshly on the next hit. To remove the rule:
 
```powershell
Remove-NetFirewallRule -DisplayName BlockRDPBruteForce
```

 
## Configuration
 
Everything is configured inside this script (comes with prod defaults).
 
| Setting | Where | Default |
|---|---|---|
| Firewall rule name | `$ruleName` | `BlockRDPBruteForce` |
| 15-minute window | `DefaultTimeframe` / `DefaultThreshold` in the `Events` class | 15 min / 25 |
| 1-hour window | `[Events]::new(60, 45)` | 60 min / 45 |
| 6-hour window | `[Events]::new(360, 90)` | 360 min / 90 |
| Protected port | `-LocalPort` in `New-NetFirewallRule` | 3389 |
 
## Limitations
 
- **Blocks do not expire.** Addresses stay in the rule until you remove them.
- **No allowlist.** Only loopback and the server's own addresses are exempt.
    - Private address ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) are not exempt, so an internal host that produces enough failed logons is blocked as well. Useful for larger setups using internal or NAT'ed IPs.
- **Counts all failed logons, blocks RDP only.** Event ID 4625 is not RDP-specific, but the firewall rule only affects TCP port 3389.
- **Not a replacement for hardening.** Don't expose RDP directly to the internet if you can avoid it. Use a VPN or Remote Desktop Gateway (ideally RD Gateway *with* this script). Setup MFA, and set an account lockout policy. This script reduces noise and risk; it does not remove the attack surface in the RD protocol.
## FAQ
 
**How do I stop RDP brute-force attacks on Windows without third-party software?**
Schedule this script. It uses only the Event Log and Windows Firewall that ship with Windows. Customize it to protect other services.
 
**Does it work on Windows Server?**
Yes. It is tested on Windows 10/11 and Windows Server 2019/2022/2025, and has been used in production on servers since 2022.
 
**Does it need PowerShell 7?**
No. PowerShell 7 is recommended, but the built-in Windows PowerShell 5.1 is enough.
 
**Does it send any data anywhere?**
No.
 
**How do I uninstall it?**
 
```powershell
Unregister-ScheduledTask -TaskName BlockRDPBruteForce -Confirm:$false
Remove-NetFirewallRule -DisplayName BlockRDPBruteForce
Remove-Item C:\Scripts\block_rdp_brute.ps1
```
 
## Contributing
 
Issues and pull requests are welcome. Because this script runs in production, please test contributions on a real Windows system and describe how you tested them.
 
## Credits
 
Maintained by DATA-Systems (FL/BS). Original version by FL (2022).
 
## License
 
[GNU General Public License v3.0](https://choosealicense.com/licenses/gpl-3.0/)