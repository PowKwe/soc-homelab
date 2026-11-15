# Lab setup

Single-analyst SOC lab for detection engineering and triage practice. The victim has no internet access. Attacks run only on the isolated lab link.

Times in this document are UTC unless marked local. Splunk displays local time (UTC+2) by default.

## Hardware

| Machine | Specs | Role |
|---|---|---|
| PC (Windows 11 Pro, Hyper-V) | i5-13600KF, 16 GB RAM, Wi-Fi + Ethernet | Hosts the lab VMs. Wi-Fi provides internet. Ethernet (Realtek Gaming 2.5GbE) is the lab link. |
| Laptop (Linux Mint) | i5-7200U, 8 GB RAM, Ethernet + Wi-Fi | Runs Splunk Enterprise. Ethernet is the lab link. Wi-Fi is the home network. |

## Topology

Lab link: direct Ethernet cable between PC and laptop, subnet 10.10.10.0/24, no DHCP, no default gateway.

Address scheme (blocks of ten, by role):

| Range | Role | Current hosts |
|---|---|---|
| .1 | Host PC (reserved, not on lab link) | none |
| .5 | Attacker | kali |
| .10 | Domain controllers | none yet |
| .20 | Linux servers | none yet |
| .30 | Windows workstations | ws01 |
| .40 | SIEM | Mint (Splunk) |
| .50 and up | Vulnerable targets | none yet |

| Host | Role | IP | MAC | OS | Notes |
|---|---|---|---|---|---|
| Mint laptop | Splunk Enterprise 10.4.2 | 10.10.10.40 | a8-1e-84-0b-4d-47 | Linux Mint | Physical, interface enp4s0f1 |
| ws01 | Victim | 10.10.10.30 | 00-15-5D-64-27-04 | Windows 11 Pro | Hyper-V VM. Hostname ws01 (renamed from pow-victim) |
| kali | Attacker | 10.10.10.5 | 00-15-5D-64-27-03 | Kali Linux | Hyper-V VM. Moved from .20 to .5 |

## Folder layout

ws01 (Windows):

```
C:\lab\
├── tools\
│   ├── atomic\
│   │   ├── invoke-atomicredteam\     Invoke-AtomicRedTeam.psd1 and module files
│   │   └── atomics\                  Atomic Red Team test library
│   └── sysmon\
│       └── sysmonconfig-export.xml   active Sysmon config
└── transfer\                         landing zone for Copy-VMFile
```

PC host:

```
C:\lab\
└── transfer\                         staging for files copied into ws01
```

Kali:

```
~/lab/
├── wordlists/                        test wordlists
└── loot/                             tool output per run
```

Mint: Splunk stays in `/opt/splunk`. The repo lives at `~/soc-homelab/`.

Repo (`~/soc-homelab/`):

```
soc-homelab/
├── lab/SETUP.md
├── detections/                       one .md per detection
├── scenarios/                        S1-S8 attack steps and expected events
└── wordlists/                        only non-secret test lists
```

Test passwords stay on Kali and out of the repo.

## Hyper-V (PC host)

- [x] Virtual switch `Lab-Switch`: External, bound to Realtek Gaming 2.5GbE Family Controller, management OS sharing on
- [x] Host has no address on the lab link, by design. Windows auto-assigns a link-local `169.254.x.x` address, which is harmless
- [x] Hyper-V Management Tools and PowerShell module installed on host
- [x] Enhanced session mode enabled (`Get-VMHost` reports `True`)
- [x] `Default Switch` is not attached to any VM
- [x] ws01 has one network adapter, MAC `00-15-5D-64-27-04`, on `Lab-Switch`
- [x] kali has one network adapter, MAC `00-15-5D-64-27-03`, on `Lab-Switch`
- [x] Guest Service Interface enabled on ws01 (required for `Copy-VMFile`)

## Static addresses

- Mint Ethernet (enp4s0f1): `10.10.10.40/24`, no gateway, no DNS
- ws01 Ethernet: `10.10.10.30/24`, no gateway, profile Private (verified after reboot)
- Kali lab interface: NetworkManager profile `lab`, `10.10.10.5/24`, `ipv4.method manual`, `ipv4.never-default yes`, `connection.autoconnect yes`. Verified after reboot.

## Firewall (Mint, ufw)

- [x] Status: active
- [x] Default policies: deny incoming, allow outgoing, deny routed
- [x] Port 9997/tcp: allowed from `10.10.10.0/24` only
- [x] Port 8000/tcp: allowed from `10.10.10.0/24` only
- [x] Port 8000/tcp on `tailscale0`: allowed from anywhere on the tailnet (`ufw allow in on tailscale0 to any port 8000 proto tcp`)
- [x] Home LAN access to the web UI: not allowed, by design. Splunk does not need to be on the home network
- Splunk UI access: from Mint's browser at `http://localhost:8000`, or from a tailnet device at `http://<mint-tailscale-ip>:8000` (the `100.x` address from `tailscale ip -4`)

## Splunk (Mint)

- [x] Version: 10.4.2 (build 33c3bf42cd73)
- [x] Licence: Developer, 10 GB/day, expires 3 May 2027
- [x] Receiving: TCP 9997, listening on `0.0.0.0:9997`
- [x] Web UI: listening on `0.0.0.0:8000`
- [x] Indexes:
  - `sysmon`: Sysmon Operational log
  - `wineventlog`: Security, System and PowerShell logs
- [x] Splunk Add-on for Microsoft Windows (`Splunk_TA_windows`) 11.0.2 installed and enabled. Left at 11.0.2 during the lab build. Update to 12.0.0 only after checking its release notes
- Note: 685 Windows Security events were indexed into `sysmon` before the input was fixed. They remain there
- Field names for 4625 (failed logon): `Account_Name`, `Source_Network_Address` and `Failure_Reason` are not populated for these events in this add-on version. Searches use the raw names instead: `TargetUserName`, `IpAddress`, `WorkstationName`, `LogonType`, `Status`, `SubStatus`

## Forwarder (ws01)

- [x] Splunk Universal Forwarder 10.4.2 (build 33c3bf42cd73)
- [x] Service `SplunkForwarder` running
- [x] Forwarder reaches Splunk: `Test-NetConnection 10.10.10.40 -Port 9997` returns `TcpTestSucceeded : True`
- Install path: `C:\Program Files\SplunkUniversalForwarder`
- `outputs.conf` (in `etc\system\local`):
  ```ini
  [tcpout]
  defaultGroup = lab

  [tcpout:lab]
  server = 10.10.10.40:9997
  ```
  TLS certificate verification is disabled and the forwarder logs warnings about it (lab only).
- `inputs.conf` (in `etc\system\local`):
  - Sysmon/Operational: `index = sysmon`
  - Security, PowerShell/Operational, System: `index = wineventlog`
- [x] Events confirmed in Splunk: `index=sysmon host=ws01` and `index=wineventlog host=ws01`

## Sysmon (ws01)

- [x] Service `Sysmon` running, driver `SysmonDrv`
- [x] Binary: `C:\WINDOWS\system32\sysmon.exe`
- [x] Version: 10.0.26100.8521 (ProductName "Sysinternals Sysmon")
- [x] Config: `C:\lab\tools\sysmon\sysmonconfig-export.xml`, SHA256 `055FEBC600E6D7448CDF3812307275912927A62B1F94D0D933B64B294BC87162`, matches the loaded config
- [x] Config source: SwiftOnSecurity's `sysmon-config` repository on GitHub, file `sysmonconfig-export.xml`
- [x] Config rule schema: 4.50
- [x] Event 3 (network connection) verified: `powershell.exe` to `10.10.10.40:9997`
- Known logging limits from the config:
  - Disabled: image load (Event 7), process access (Event 10, so LSASS-access detections won't work), raw disk access (Event 9)
  - Network connections are filtered by program, path and port
  - Registry: `CurrentVersion\Run` and `fDenyTSConnections` are logged
- Moving the config file does not change the running service. Point `sysmon -c` at the new path when reloading.

## Windows audit configuration (ws01)

- [x] Process creation auditing: `Success`
- [x] Command-line logging in 4688: `ProcessCreationIncludeCmdLine_Enabled = 0x1`
- [x] PowerShell script block logging: `EnableScriptBlockLogging = 0x1`. Applies only to PowerShell sessions started after the policy was set
- [x] Logon auditing: `Success and Failure` (verified with `auditpol /get /subcategory:"Logon"`). Failed logons (4625) are now logged
- [ ] Filtering Platform auditing: planned for the scan scenario (Week 3)
- [ ] Other Object Access auditing: planned for the scheduled task scenario (Week 4)

## Network profile (ws01)

- [x] Lab adapter is Private after a reboot
- Fallback if it reverts: a startup task `LabSetPrivateProfile` runs `Set-NetConnectionProfile -InterfaceAlias Ethernet -NetworkCategory Private` at boot. Create it only if the profile reverts again

## Remote Desktop (ws01)

- [x] Edition: Windows 11 Pro
- [x] `TermService` running, listening on TCP/UDP 3389
- [x] Remote Desktop firewall rules enabled (`Profile: Any`)
- [x] Kali can connect: `nmap -Pn -p 3389 10.10.10.30` returns `open`, and an RDP session as `testuser` succeeded
- [x] Test account `testuser` is a member of Remote Desktop Users
- [x] Lockout threshold: `Never`, so repeated failures won't lock out any account
- [x] Install account (admin) is separate from `testuser`. Keep it out of attack wordlists

## Atomic Red Team (ws01)

- [x] Invoke-AtomicRedTeam module at `C:\lab\tools\atomic\invoke-atomicredteam`
- [x] Atomic test library at `C:\lab\tools\atomic\atomics`
- [x] PowerShell profile (`$PROFILE`) loads the module and sets the atomics path for every session:
  ```powershell
  Import-Module "C:\lab\tools\atomic\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
  $PSDefaultParameterValues['Invoke-AtomicTest:PathToAtomicsFolder'] = 'C:\lab\tools\atomic\atomics'
  ```
- [x] `Invoke-AtomicTest T1053.005 -ShowDetailsBrief` lists 14 variants (listing only, nothing executed)
- [x] Guest Service Interface enabled on the host, required for `Copy-VMFile`

## Kali

- [x] Timezone: UTC (`sudo timedatectl set-timezone UTC`)
- [x] Lab link: NetworkManager profile `lab` with static `10.10.10.5/24`, autoconnect on. Address survives reboot
- [x] Folders: `~/lab/wordlists`, `~/lab/loot`

## Health check

On ws01:
```powershell
Get-Service SplunkForwarder, Sysmon, TermService
Test-NetConnection 10.10.10.40 -Port 9997
Get-NetRoute -DestinationPrefix 0.0.0.0/0   # should return nothing
Get-NetConnectionProfile                    # lab adapter should be Private
```

On Mint:
```bash
sudo ufw status verbose
ss -tlnp | grep -E '8000|9997'
tailscale ip -4
```

On Kali:
```bash
ip -br a                                    # lab interface should show 10.10.10.5/24
```

In Splunk:
```
index=sysmon host=ws01 | stats count by EventCode
index=wineventlog host=ws01 | stats count by EventCode
```

## Troubleshooting log

1. Hyper-V cmdlets such as `Set-VMHost` only work on the host, not inside a VM. Running them in ws01 returns "not recognised".
2. An IP stuck on `Tentative` or `Invalid` meant the cable wasn't connected. It was not a duplicate address.
3. Security events were routed to `sysmon` because `inputs.conf` set the wrong index. Fixed by setting `wineventlog`.
4. Events were dropped because the `wineventlog` index didn't exist. Splunk logged "unconfigured/disabled/deleted index". Created the index.
5. Splunk's `host` field is the Windows computer name, not the Hyper-V VM name. Renamed the computer to `ws01`.
6. An empty `Get-NetRoute` result on the victim is expected, since there's no default route.
7. Windows 11 Home can't host enhanced session or RDP. Upgraded ws01 to Pro.
8. The Default Switch NAT gives VMs a route to the home LAN, so it isn't suitable for attack traffic. Use `Lab-Switch` instead.
9. Both VM adapters are called "Network Adapter". Identify them by MAC or switch name before removing one.
10. ufw was inactive, so the lab rules weren't enforced. Enabled it and scoped 8000 and 9997 to the lab subnet.
11. Splunk's web UI was unreachable from the home Wi-Fi even with ufw off. Pings between home devices failed in both directions, so Wi-Fi client isolation is the likely cause. Use Mint's browser, or Tailscale.
12. The RDP scan returned `filtered`, and the Ethernet profile had reverted to Public. Set it back to Private and the port opened.
13. Kali lost contact with the lab after a while. Pinging from Mint refreshed the ARP entries. Recurred: ws01 got "Destination host unreachable" from its own address because Kali's lab interface had no address after a reboot. Fixed by creating a static NetworkManager profile `lab`.
14. `Invoke-AtomicTest` reported "Found 0 atomic tests" and path errors. The module's default atomics path was wrong. Fixed by setting `PathToAtomicsFolder` in the profile.
15. The atomics library was nested one level too deep after moving the repo (`atomics\atomics`). Fixed by moving the inner folder up.
16. The Atomic module wasn't loaded after opening a new PowerShell window. Fixed by loading it from the profile.
17. Hydra's log header uses Kali's local clock, which was UTC-5. `date -u` shows UTC. Logs and notes now use UTC.
18. Failed RDP logons didn't appear in Splunk because Logon failure auditing was off. Enabled `Success and Failure`.
19. The 4625 search with `Logon_Type=10` returned nothing because NLA rejects bad passwords before the RDP session starts, so they're logged as `LogonType 3`.
20. `Account_Name`, `Source_Network_Address` and `Failure_Reason` were empty for 4625 events. Raw names work: `TargetUserName`, `IpAddress`, `SubStatus`.
21. Kali's address disappeared after a reboot because it had been set in the GUI only. Fixed with a static NetworkManager profile.
22. ws01's network profile reverted to Public after a reboot. Set back to Private (see the network profile section for the fallback).
23. The Splunk UI couldn't be reached over Tailscale because the URL used the lab address. Use the `100.x` tailnet address.

## Hydra runs (Kali, RDP brute force, S2 preparation)

Times are UTC.

| Run | Start (UTC) | Result |
|---|---|---|
| 1 | 17:51:32 | Password found after 5 failures and 1 success |
| 2 | 17:56:43 | Password found after 4 failures and 1 success |

Output files are in `~/lab/loot/` on Kali. Wordlist: `~/lab/wordlists/rdp-test.txt`.

## Open items

- [ ] Week 3: enable Filtering Platform auditing (scan detection)
- [ ] Week 4: enable Other Object Access auditing (scheduled task detection)
- [ ] Decide whether to add the startup task for the private network profile, if the profile reverts again
- [ ] Linux server VM: deferred to Week 5