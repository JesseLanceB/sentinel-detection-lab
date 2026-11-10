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

## Progress

- [x] Azure for Students subscription
- [x] Resource group and Log Analytics workspace, with a 1 GB/day cap
- [x] Microsoft Sentinel enabled, Azure Activity logs connected
- [x] Windows VM with Sysmon and Azure Monitor Agent
- [x] Sysmon logs arriving in Sentinel
- [ ] Rule 1: renamed system binaries (T1036.003)
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
