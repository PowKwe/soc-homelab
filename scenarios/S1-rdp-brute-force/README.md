# Scenario S1: Password Guessing via RDP (T1110.001)

## 1. Scenario Metadata
- **MITRE ATT&CK:** T1110.001 — Brute Force: Password Guessing
- **Date / Time (UTC):** 2026-11-15 17:51:32 UTC (Run 1) and 2026-11-15 17:56:43 UTC (Run 2)
- **Attacker Host:** `kali` (`10.10.10.5`)
- **Target Host:** `ws01` (`10.10.10.30`)
- **Log Sources Analyzed:** `index=wineventlog` (Windows Security Event Log) and `index=sysmon` (`Microsoft-Windows-Sysmon/Operational`)

## 2. Executive Summary
On `2026-11-15` between `17:51:32 UTC` and `17:56:43 UTC`, two automated RDP password-guessing bursts originated from `kali` (`10.10.10.5`) targeting the local account `testuser` on `ws01` (`10.10.10.30`). The first burst generated `5` failed authentications followed by `1` successful logon, and the second burst generated `4` failed authentications followed by `1` successful logon. Correlation across `index=wineventlog` (`LogonType=3` only, with no subsequent `LogonType=10` interactive session) and `index=sysmon` (`0` events recorded) confirmed that the tool disconnected immediately after Network Level Authentication (NLA) without executing post-compromise actions.

## 3. Attack Timeline & Telemetry Analysis
- **Initial Investigation Query:**
```spl
index=wineventlog EventCode=4625 IpAddress="10.10.10.5" LogonType=3 | table EventCode LogonType TargetUserName IpAddress WorkstationName Status SubStatus AuthenticationPackageName
```
- **Key Artifacts Observed:**
  - **`EventCode` & `LogonType`:** `4625` (failed logon) and `4624` (successful logon) with `LogonType=3` (Network), confirming RDP authentication negotiated via Network Level Authentication (NLA).
  - **`Status` & `SubStatus`:** `0xc000006d` (general logon failure) paired with `0xc000006a` (valid username, incorrect password), proving that `testuser` is an active local account on `ws01`.
  - **`WorkstationName` / `IpAddress` / `TargetUserName`:** `kali` / `10.10.10.5` / `testuser` under `AuthenticationPackageName=NTLM`, exposing the attacker's client hostname directly inside the NTLM authentication exchange.
- **Sysmon / Secondary Telemetry:**
```spl
index=sysmon host=ws01
```
  - Querying `index=sysmon` across the attack window returned `0` events. SwiftOnSecurity's Sysmon configuration excludes inbound network connections (`EventCode=3`) to `svchost.exe` (`TermService` on TCP `3389`), and the tool terminated immediately after NLA authentication without launching an interactive desktop session (`rdpclip.exe`, `explorer.exe`) that would generate `EventCode=1` process creation logs.

## 4. Detection Rule (Splunk SPL)
```spl
index=wineventlog EventCode IN (4624 4625) LogonType IN (3,10) | bin _time span=5m | stats count(eval(EventCode=4625)) as Failed count(eval(EventCode=4624)) as Successful values(WorkstationName) as WorkstationName values(SubStatus) as SubStatus values(LogonType) as LogonType by _time, IpAddress, TargetUserName | where Failed >= 4 AND IpAddress!="-" | eval Alert_Status = if(Successful > 0, "CRITICAL - Brute Force Succeeded", "HIGH - Brute Force Blocked")
```
- **Detection Logic & Threshold Rationale:** Bucketing events with `bin _time span=5m` and filtering on `Failed >= 4 AND IpAddress!="-"` isolates low-volume automated password-guessing bursts (such as the 4- and 5-attempt runs) while filtering out 1–2 accidental human typos and blank/local source addresses. Using `eval Alert_Status = if(Successful > 0, ...)` elevates confirmed credential compromises (`CRITICAL`) above blocked attempts (`HIGH`).
- **False Positive Considerations & Triage Guidance:** Legitimate users mistyping passwords or stale cached credentials on mapped network shares (`LogonType=3`) can generate `4625` bursts. When `Successful > 0` triggers, an analyst must immediately pivot to `index=wineventlog` for follow-on `LogonType=10` (`RemoteInteractive`) events and `index=sysmon` for suspicious process execution (`EventCode=1`).

## 5. Containment & Remediation
- Block source IP `10.10.10.5` at the host/network firewall or isolate `ws01` (`10.10.10.30`) if unauthorized interactive activity is detected.
- Force an immediate password reset for `testuser` and verify account lockout thresholds (`net accounts`) are active.
- Audit active and disconnected RDP sessions on `ws01` (`qwinsta`) to ensure no lingering session remains open.
- Hunt across `index=sysmon` and `index=wineventlog` after `17:56:43 UTC` for persistence indicators (new local accounts `4720`, scheduled tasks `4698`, or service installations `7045`).