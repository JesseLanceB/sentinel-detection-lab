# Sentinel Detection Lab

Building and testing detections in Microsoft Sentinel, mapped to MITRE ATT&CK. Follow-on to my [Sysmon masquerading detection](https://github.com/JesseLanceB/sysmon-masquerading-detection) and [LLM chatbot security assessment](https://github.com/JesseLanceB/llm-chatbot-security).

## Goal

Collect Windows and Azure logs in Microsoft Sentinel, simulate attacks with Atomic Red Team, and write KQL analytics rules that catch them. The first rule ports my Sysmon detection for renamed system binaries (T1036.003) into a cloud SIEM.

## Planned architecture

- Windows Server VM in Azure with Sysmon
- Azure Monitor Agent sending Sysmon and Windows Security events to a Log Analytics workspace
- Microsoft Sentinel enabled on that workspace
- Azure Activity logs (a free connector) for cloud control-plane detections

## Cost guardrails

- **Azure for Students subscription, no credit card attached.** Spending stops at the credit limit instead of billing a card.
- **Sentinel free trial, active November 8 to December 9, 2026.** The first 10 GB/day is free for both Log Analytics ingestion and Sentinel charges. The lab is planned to finish, and be torn down, inside that window. [Screenshot](screenshots/sentinel-trial-activated.png)
- **Daily cap of 1 GB/day** on the workspace (resets 02:00 UTC). Outside the trial, Analytics Logs ingestion is listed at $2.76/GB in this region, plus Sentinel charges, so the cap limits the worst-case daily cost. The trade-off: once the cap is hit, logs stop until the reset, which would be a blind spot in a production SOC. [Screenshot](screenshots/cost-guardrails.png)
- **One resource group** (`rg-sentinel-lab`) holds every lab resource, in Canada Central (one of the subscription's allowed regions).
- **VM shut down (deallocated) after every session**, so compute isn't billed while idle.
- **Credit checked weekly.**

## Teardown

Delete `rg-sentinel-lab`. Every lab resource goes with it.

## Progress

- [x] Azure for Students subscription
- [x] Resource group and Log Analytics workspace, with a 1 GB/day cap
- [x] Microsoft Sentinel enabled, Azure Activity logs connected
- [ ] Windows VM with Sysmon and Azure Monitor Agent
- [ ] Windows logs arriving in Sentinel
- [ ] Rule 1: renamed system binaries (T1036.003)
- [ ] Rule 2: Microsoft Defender exclusion added (T1562.001)
- [ ] Stretch rule: cloud logging disabled, such as a deleted diagnostic setting (T1562.008)
- [ ] Writeup and lessons learned

## Lab notes

**November 8: first data.** Azure Activity logs reach the workspace through a subscription diagnostic setting. My first query returned 114 events from my own setup actions. [Screenshot](screenshots/first-azureactivity-query.png)

- **One action can log twice.** Adding a tag produced a `Start` event and a `Success` event. Rules that count operations should filter on `ActivityStatusValue == "Success"` to avoid double counting.
- **Volume alone is a weak signal.** Installing the Azure Activity solution wrote dozens of content templates within one second, from one account. That burst is harmless automation here, but the same pattern from an unexpected account or location is what mass-resource-creation detections look for. A useful rule needs context, such as who acted and from where, not just a count.
