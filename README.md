# Sentinel Detection Lab

Building and testing detections in Microsoft Sentinel, mapped to MITRE ATT&CK. Follow-on to my [Sysmon masquerading detection](https://github.com/JesseLanceB/sysmon-masquerading-detection) and [LLM chatbot security assessment](https://github.com/JesseLanceB/llm-chatbot-security).

## Goal

Collect Windows and Azure logs in Microsoft Sentinel, simulate attacks with Atomic Red Team, and write KQL analytics rules that catch them. The first rule ports my Sysmon detection for renamed system binaries (T1036.003) into a cloud SIEM.

## Architecture

- **Endpoint:** Windows Server 2022 VM (`Standard_B2ls_v2`) in Sweden Central, running Sysmon with a widely used community configuration
- **Collection:** the Azure Monitor Agent, with a data collection rule created through the Windows Forwarded Events connector (XPath `Microsoft-Windows-Sysmon/Operational!*`), sends Sysmon events to the `WindowsEvent` table
- **SIEM:** Microsoft Sentinel on a Log Analytics workspace in Canada Central
- **Cloud audit:** Azure Activity logs (free) through a subscription diagnostic setting, for control-plane detections

## Cost guardrails

- **Azure for Students subscription, no credit card attached.** Spending stops at the credit limit instead of billing a card.
- **Sentinel free trial, active November 8 to December 9, 2026.** The first 10 GB/day is free for both Log Analytics ingestion and Sentinel charges. The lab is planned to finish, and be torn down, inside that window. [Screenshot](screenshots/sentinel-trial-activated.png)
- **Daily cap of 1 GB/day** on the workspace (resets 02:00 UTC). Outside the trial, Analytics Logs ingestion is listed at $2.76/GB in this region, plus Sentinel charges, so the cap limits the worst-case daily cost. The trade-off: once the cap is hit, logs stop until the reset, which would be a blind spot in a production SOC. [Screenshot](screenshots/cost-guardrails.png)
- **One resource group** (`rg-sentinel-lab`) holds every lab resource, in Canada Central (one of the subscription's allowed regions).
- **VM at $0.0524/hour, deallocated after every session,** so compute isn't billed while idle. Auto-shutdown at 11:30 PM Eastern catches a forgotten session.
- **RDP allowed from a single IP address only.** Internet-facing RDP is brute-forced within minutes of exposure.
- **Credit checked weekly.**

## Teardown

Delete `rg-sentinel-lab`. Every lab resource goes with it.

## Detections

| Rule | MITRE ATT&CK | Data source | Status |
|---|---|---|---|
| [Renamed system binary executed](kql/rule1-renamed-binaries.kql) | T1036.003, Masquerading: Rename System Utilities | Sysmon Event 1 (`WindowsEvent`) | Live, tested |

**Rule 1 logic.** Alerts when either condition is true:
- **A:** a commonly abused Windows tool (`cmd`, `powershell`, `rundll32`, `mshta`, `wscript`, `cscript`, `certutil`) runs under a different file name than the one built into the binary (Sysmon `OriginalFileName`).
- **B:** a file named `lsass.exe` runs from anywhere other than `C:\Windows\System32`.

Names are normalized before comparing, because legitimate Windows binaries differ in three ways: `Image` is a full path while `OriginalFileName` is a bare name, case varies (`notepad.exe` vs `NOTEPAD.EXE`), and some names omit `.exe` (`UsoClient.exe` vs `UsoClient`). Without normalizing, all three would cause false positives.

**Schedule:** runs every 5 minutes, looks back 30 minutes, with an ingestion-time filter (see the November 11 notes). Triage helper: [child processes of the flagged process](kql/triage-child-processes.kql).

## Progress

- [x] Azure for Students subscription
- [x] Resource group and Log Analytics workspace, with a 1 GB/day cap
- [x] Microsoft Sentinel enabled, Azure Activity logs connected
- [x] Windows VM with Sysmon and Azure Monitor Agent
- [x] Sysmon logs arriving in Sentinel
- [x] Rule 1: renamed system binaries (T1036.003)
- [ ] Rule 2: Microsoft Defender exclusion added (T1562.001)
- [ ] Stretch rule: cloud logging disabled, such as a deleted diagnostic setting (T1562.008)
- [ ] Writeup and lessons learned

## Lab notes

**November 8: first data.** Azure Activity logs reach the workspace through a subscription diagnostic setting. My first query returned 114 events from my own setup actions. [Screenshot](screenshots/first-azureactivity-query.png)

- **One action can log twice.** Adding a tag produced a `Start` event and a `Success` event. Rules that count operations should filter on `ActivityStatusValue == "Success"` to avoid double counting.
- **Volume alone is a weak signal.** Installing the Azure Activity solution wrote dozens of content templates within one second, from one account. That burst is harmless automation here, but the same pattern from an unexpected account or location is what mass-resource-creation detections look for. A useful rule needs context, such as who acted and from where, not just a count.

**November 9: endpoint telemetry.** Sysmon on the cloud VM now feeds Sentinel. [Sysmon running on the VM](screenshots/sysmon-installed-vm.png) · [Events in Sentinel](screenshots/sysmon-in-windowsevent.png) · [Event fields](screenshots/eventdata-fields.png)

- **Quota and capacity are different limits.** In Canada Central, B-series sizes were "not available" (no capacity for this subscription offer), and a `D2als_v7` deployment failed with `QuotaExceeded` (a family limit of 0 vCPUs). The Quotas page showed most VM families restricted for this subscription in that region. Sweden Central had capacity for `B2ls_v2`, a family with quota, so the VM runs there while logs go to the Canada Central workspace. In a production environment with data-residency rules, the fix would be a quota or capacity request in the home region instead.
- **The OS blocked the downloaded `.rdp` file.** Smart App Control flagged it, a reasonable defense because malicious `.rdp` attachments have been used in phishing campaigns. I connected by entering the VM's IP in Remote Desktop Connection instead of turning the protection off.
- **Sysmon fields are nested.** Events land in `WindowsEvent`, with Sysmon's fields (`Image`, `OriginalFileName`, `ParentImage`, `CommandLine`, `Hashes`) inside the dynamic `EventData` column. KQL reads them with `tostring(EventData.OriginalFileName)`.
- **The tuning case reproduced on a new machine.** As in my [masquerading lab](https://github.com/JesseLanceB/sysmon-masquerading-detection), the legitimate `unsecapp.exe` reports OriginalFileName `unsecapp.dll`, and `Sysmon64.exe` reports none. Both are normal Windows behaviour, which confirms why Rule 1 can't alert on every name mismatch. The Sysmon config hash also matched the earlier lab exactly: identical hash, identical file.

**November 11: Rule 1 built, tested and live.**

- **Baseline first.** Before simulating anything, the rule's query returned 0 results across 7 days of normal activity, while the same window held real process events, including the benign mismatches above. So it ignores legitimate activity. [Baseline](screenshots/rule1-baseline-7days.png) · [Data present](screenshots/rule1-data-present.png)
- **True positive.** I copied `cmd.exe` to `C:\Windows\Temp\lsass.exe` and ran `whoami` through it. The query returned exactly one row, with four red flags: OriginalFileName `Cmd.Exe`, location `Temp` instead of System32, a `/c whoami` command line, and `powershell.exe` as the parent (the real lsass is started by `wininit.exe`). [Screenshot](screenshots/rule1-true-positive.png)
- **The first live test missed, because of ingestion delay.** Logs reached the workspace an average of 9 minutes and up to 17 minutes after the event, but the rule only looked back 10 minutes. Events arrived after the window that should have checked them had already closed. I fixed it by extending the lookback to 30 minutes and adding `ingestion_time() > ago(6m)`, so each event is evaluated once, when it arrives. [Delay measurement](screenshots/ingestion-delay.png)
- **After the fix, an incident in 10 minutes.** The retest at 7:56 PM produced an incident at 8:06 PM, with the host and process entities mapped and the MITRE tactic and technique attached. I classified it as a benign positive: the rule worked correctly, and the activity was an authorized test. [Rule](screenshots/rule1-analytics-rule.png) · [Incident](screenshots/rule1-incident.png) · [Incident details](screenshots/rule1-incident-details.png)
- **Smaller lessons.** MITRE IDs starting with T08 belong to the ICS (industrial control systems) matrix, so the rule is mapped to Enterprise T1036.003. One test ran from 32-bit PowerShell, so Windows redirected the copy to the 32-bit `cmd.exe` in `SysWOW64`, and its child `whoami.exe` also ran from `SysWOW64`. Unusual paths often have a mundane explanation.
