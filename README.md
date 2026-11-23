# Sentinel Detection Lab

Building and testing detections in Microsoft Sentinel, mapped to MITRE ATT&CK. Follow-on to my [Sysmon masquerading detection](https://github.com/JesseLanceB/sysmon-masquerading-detection) and [LLM chatbot security assessment](https://github.com/JesseLanceB/llm-chatbot-security).

## Goal

Collect Windows and Azure logs in Microsoft Sentinel, simulate attacker techniques with harmless tests, and write KQL analytics rules that catch them. The first rule ports my Sysmon detection for renamed system binaries (T1036.003) into a cloud SIEM. The second catches an attacker switching off antivirus scanning for their files (T1562.001), and the third catches someone cutting the pipes that send Azure logs to the SIEM (T1562.008).

## Architecture

- **Endpoint:** Windows Server 2022 VM (`Standard_B2ls_v2`) in Sweden Central, running Sysmon with a widely used community configuration
- **Collection:** the Azure Monitor Agent, with a data collection rule created through the Windows Forwarded Events connector, sends events to the `WindowsEvent` table. Two XPath queries: `Microsoft-Windows-Sysmon/Operational!*` (all Sysmon events) and `Microsoft-Windows-Windows Defender/Operational!*[System[(EventID=5007)]]` (Defender configuration changes only)
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

| Rule | MITRE ATT&CK | Data source | Rule type | Status |
|---|---|---|---|---|
| [Renamed system binary executed](kql/rule1-renamed-binaries.kql) | T1036.003, Masquerading: Rename System Utilities | Sysmon Event 1 | Near-real-time (NRT) | Live, tested |
| [Defender exclusion added](kql/rule2-defender-exclusion-added.kql) | T1562.001, Impair Defenses: Disable or Modify Tools | Defender Operational Event 5007 | Near-real-time (NRT) | Live, tested |
| [Diagnostic setting deleted](kql/rule3-diagnostic-setting-deleted.kql) | T1562.008, Impair Defenses: Disable or Modify Cloud Logs | Azure Activity log (`AzureActivity`) | Near-real-time (NRT) | Live, tested |

All three are NRT rules, which Sentinel runs every minute on newly arrived events. Rules 1 and 2 started as scheduled rules and were moved to NRT after an investigation into duplicate alerts (November 16 notes). Rule 3 was built as NRT from the start.

**Rule 1 logic.** Alerts when either condition is true:
- **A:** a commonly abused Windows tool (`cmd`, `powershell`, `rundll32`, `mshta`, `wscript`, `cscript`, `certutil`) runs under a different file name than the one built into the binary (Sysmon `OriginalFileName`).
- **B:** a file named `lsass.exe` runs from anywhere other than `C:\Windows\System32`.

Names are normalized before comparing, because legitimate Windows binaries differ in three ways: `Image` is a full path while `OriginalFileName` is a bare name, case varies (`notepad.exe` vs `NOTEPAD.EXE`), and some names omit `.exe` (`UsoClient.exe` vs `UsoClient`). Without normalizing, all three would cause false positives.

Triage helper: [child processes of the flagged process](kql/triage-child-processes.kql).

**Rule 2 logic.** Alerts when Defender's Event 5007 (configuration changed) shows a new value under the `Exclusions` registry key: a folder, file type or process that Defender will no longer scan. Attackers add exclusions so their tools aren't detected. The query extracts the exclusion type and the excluded item, so the alert shows *what* was excluded without opening the raw event. Removals and the many routine 5007 events (service start, configuration hash, notification settings) don't match.

**Why Defender's log and not Sysmon:** in testing, Sysmon only saw exclusions added by starting a new PowerShell process. Defender's own log caught every addition (November 15 notes).

**Investigation helper:** [rebuild each rule run's query window from SecurityAlert](kql/investigation-alert-query-windows.kql).

**Rule 3 logic.** Alerts when an Azure diagnostic setting is deleted (`MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE`), or when someone tries and fails. Diagnostic settings are the pipes that send Azure logs to the SIEM, so deleting one blinds the SOC before the attacker's main action. Each action logs a `Start` row and an outcome row, so the query keeps only `Success` and `Failure`; otherwise one delete would raise two alerts. A failed attempt is kept on purpose, because it can mean someone testing what a stolen account is allowed to do. The alert names the deleted setting, taken from the end of `_ResourceId`, and maps the caller's account, their IP address and the Azure resource as entities.

**Not covered yet:** an attacker could also *edit* a setting, unticking its log categories or pointing it at another workspace. That logs as `DIAGNOSTICSETTINGS/WRITE`, exactly like every legitimate creation, so alerting on every WRITE would be noisy. A better rule would flag a WRITE by someone who hasn't changed diagnostic settings in the last 30 days. That needs history, so it would be a scheduled rule, not NRT.

## Progress

- [x] Azure for Students subscription
- [x] Resource group and Log Analytics workspace, with a 1 GB/day cap
- [x] Microsoft Sentinel enabled, Azure Activity logs connected
- [x] Windows VM with Sysmon and Azure Monitor Agent
- [x] Sysmon logs arriving in Sentinel
- [x] Rule 1: renamed system binaries (T1036.003)
- [x] Rule 2: Microsoft Defender exclusion added (T1562.001)
- [x] Duplicate alerts investigated; both rules moved to near-real-time (NRT)
- [x] Rule 3: diagnostic setting deleted (T1562.008)
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
- **What I thought was a miss.** After the first live test (7:30 PM), no incident had appeared when I checked. I measured log delay: events reached the workspace an average of 9 minutes and up to 17 minutes after they happened, while the rule only looked back 10 minutes. So I extended the lookback to 30 minutes and added `ingestion_time() > ago(6m)`, meant to evaluate each event once, when it arrives. [Delay measurement](screenshots/ingestion-delay.png)
- **Correction (November 16).** The first test didn't miss. The SecurityAlert table shows the original rule alerted on it twice, at 7:38 and 7:43 PM. The event arrived in 44 seconds, and I had checked before the alerts existed. The duplicate came from the original settings: a 10-minute lookback on a 5-minute schedule makes each window overlap the previous one, so the event sat in two windows. The delay risk I measured was real, but it wasn't what happened in that test. [Three alerts for two tests](screenshots/rule1-three-alerts.png) · [Arrival times](screenshots/test-event-arrival-times.png)
- **After the fix, an incident in 10 minutes.** The retest at 7:56 PM produced an incident at 8:06 PM, with the host and process entities mapped and the MITRE tactic and technique attached. I classified it as a benign positive: the rule worked correctly, and the activity was an authorized test. [Rule](screenshots/rule1-analytics-rule.png) · [Incident](screenshots/rule1-incident.png) · [Incident details](screenshots/rule1-incident-details.png)
- **Smaller lessons.** MITRE IDs starting with T08 belong to the ICS (industrial control systems) matrix, so the rule is mapped to Enterprise T1036.003. One test ran from 32-bit PowerShell, so Windows redirected the copy to the 32-bit `cmd.exe` in `SysWOW64`, and its child `whoami.exe` also ran from `SysWOW64`. Unusual paths often have a mundane explanation.

**November 15: Rule 2 telemetry check.** Before writing the rule, I checked which logs record a Defender exclusion. I added two test exclusions in two different ways:

- **Test A**, typed in an open PowerShell session: `Add-MpPreference -ExclusionPath "C:\LabTestA"`
- **Test B**, launched as a new process: `powershell.exe -NoProfile -Command "Add-MpPreference -ExclusionPath 'C:\LabTestB'"`

| Log | Test A (open session) | Test B (new process) |
|---|---|---|
| Defender Event 5007 | Recorded | Recorded |
| Sysmon Event 1 (process creation) | Not recorded | Recorded |

- **Sysmon only saw Test B,** because Test A didn't start a new process. An attacker typing commands in an existing shell leaves no process-creation event. [Sysmon result](screenshots/rule2-sysmon-sees-test-b-only.png)
- **The two logs agreed on Test B.** Sysmon recorded the PowerShell process at 3:07:19 UTC and Defender recorded the exclusion at 3:07:21, two seconds apart. Matching events across logs by time like this is how one log confirms another.
- **Event 5007 is noisy.** Of 16 events in the test window, 12 were routine configuration changes, such as the service starting or the configuration hash updating. Filtering on the `\Exclusions\` registry path kept only the additions. [All 5007 events](screenshots/rule2-5007-all-events.png)
- **The Sysmon configuration has a gap.** The community configuration watches the Group Policy exclusions key (`HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions`), but not the key that `Add-MpPreference` writes to, so its registry monitoring doesn't cover these changes. Defender's own log was the reliable source.
- **Not covered yet:** Event 5007 records the change, not the command behind it. PowerShell Script Block Logging (Event 4104) would record commands typed inside a session, such as Test A.

**November 16: Rule 2 built, and a duplicate-alert investigation.**

- **Query test.** Over the test window, the query returned exactly the two test exclusions and none of the noise. [Screenshot](screenshots/rule2-query-test.png)
- **Scheduled rule.** Medium severity, Defense Evasion T1562.001, Host entity mapped, every 5 minutes with a 30-minute lookback and the same `ingestion_time() > ago(6m)` filter as Rule 1. [Rule](screenshots/rule2-scheduled-rule.png)
- **Live test: one event, two incidents.** I added `C:\LabTestC` at 8:21 PM. The rule fired, but incidents 12865 and 12866 both pointed at the same single event. [Incidents](screenshots/rule2-duplicate-incidents.png)
- **Tracing it.** The event arrived 8 minutes 23 seconds after it happened. [Arrival](screenshots/rule2-labtestc-arrival.png) SecurityAlert showed two alerts with the same event time. [Alerts](screenshots/rule2-two-alerts.png) The alerts' `ExtendedProperties` field records each run's query window: the two windows ended at 1:29:35 and 1:34:35 UTC, and each alert was created about 5 minutes after its window ended. This matches Microsoft's documented five-minute delay for scheduled rules. [Query windows](screenshots/rule2-alert-query-windows.png)
- **Rule 1 had it too.** The same check on Rule 1 found three alerts for two tests: the 7:30 PM duplicate from the original settings (see the November 11 correction), and one alert for the 7:56 PM retest. Then I pulled the arrival time of every test event: 40 to 53 seconds for the Rule 1 tests, 8 minutes 23 seconds for LabTestC.
- **Two explanations, one ruled out.** The rule only keeps events that arrived in the last 6 minutes, and the question was when Sentinel starts counting those 6 minutes back.
  - **From when the query actually runs:** then the 7:56 PM test would have produced no alert at all. It did alert, so this is ruled out.
  - **From the end of the query window:** then each run accepts events that arrived over an 11-minute range (6 minutes before the window ended, through the run 5 minutes later), while runs are only 5 minutes apart. A slow arrival lands in two runs' ranges, so LabTestC alerted twice. A fast arrival usually lands in one, so the 7:56 PM test alerted once. This fits both test events that ran under the filter. Microsoft doesn't document this behaviour, so it's my inference from the data.
- **The fix: near-real-time (NRT) rules.** NRT rules run every minute and evaluate events by arrival time, which is Microsoft's designed answer to late logs. The query needs no timing workaround. Under my inferred model, a scheduled rule could also be fixed by capping the filter (`ingestion_time() <= now()`), but that depends on undocumented behaviour, so I chose the documented design.
- **NRT verified on Rule 2.** I added `C:\LabTestD` at 11:05 PM. It arrived 36 seconds later, and the NRT rule raised one alert 2 minutes 22 seconds after arrival, still one alert when rechecked 12 minutes later. From event to alert took about 3 minutes, compared with 13 minutes and two alerts under the scheduled rule. This event arrived quickly, but the duplicate had come from a slow arrival, so the next test needed a slow one (November 17). [Arrival](screenshots/rule2-nrt-event-arrival.png) · [One alert](screenshots/rule2-nrt-one-alert.png)

**November 17: Rule 1 moved to NRT and tested with a slow arrival.**

- I disabled the scheduled Rule 1 and recreated it as an NRT rule: the same query without the `ingestion_time()` filter, the same MITRE mapping and entities. [Rule](screenshots/rule1-nrt-rule.png)
- The test event happened at 9:58 PM and took 8 minutes 29 seconds to arrive, about as slow as LabTestC, the event that alerted twice under the scheduled rule. [Arrival](screenshots/rule1-nrt-event-arrival.png)
- The NRT rule raised one alert 2 minutes 52 seconds after arrival, and it was still the only alert 7 minutes later. [One alert](screenshots/rule1-nrt-one-alert.png)
- Across both rules, NRT has now produced exactly one alert per event for a fast arrival (36 seconds) and a slow one (8 and a half minutes).

**November 22: Rule 3, cloud logging deleted (T1562.008).** Built as an NRT rule from the start, because one event is enough to alert.

- **Telemetry first, on a throwaway.** I created and deleted a test diagnostic setting (`diag-test-delete`) on the workspace, not the real `activity-to-sentinel` setting. That one is the pipe that delivers `AzureActivity` itself, so deleting it might stop its own delete event from arriving. It gets a separate test.
- **Four rows for two actions.** The create logged as `DIAGNOSTICSETTINGS/WRITE` and the delete as `DIAGNOSTICSETTINGS/DELETE`, each with a `Start` and a `Success` row, as in the November 8 tag test. [Screenshot](screenshots/rule3-telemetry-arrival.png)
- **Logs don't arrive in order.** The delete happened 2.5 minutes after the create but arrived first, after 4.5 minutes of delay against 8.5. A rule about a sequence of actions has to order events by `TimeGenerated`, never by arrival.
- **Query test.** One row: `Success`, setting `diag-test-delete`. [Screenshot](screenshots/rule3-query-test.png) My first run returned nothing, because by then the event was older than the query's `ago(2h)` filter. `ago()` always counts back from the moment the query runs.
- **Rule.** High severity: legitimate deletions are rare and should go through change management, and cutting logs usually comes right before an attacker's main action. Account, IP and Azure resource entities mapped. [Rule](screenshots/rule3-nrt-rule.png)
- **Live test.** I created and deleted `diag-test-delete2`. The delete happened at 8:08:25 PM and arrived 3 minutes 43 seconds later. The NRT rule raised one alert 2 minutes 16 seconds after arrival, about 6 minutes after the delete. The create raised nothing. [Arrival](screenshots/rule3-nrt-event-arrival.png) · [Alert](screenshots/rule3-nrt-one-alert.png)
- **Time to alert = log delay + rule delay.** Across all three rules, NRT added about 2 to 3 minutes after arrival. The rest was log delay, which I can't control.
