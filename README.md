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
- **Sentinel free trial.** After Sentinel is enabled on a workspace, the first 10 GB/day is free for 31 days, covering both Log Analytics ingestion and Sentinel charges. The lab is planned to finish inside that window.
- **One resource group** (`rg-sentinel-lab`) holds every lab resource.
- **VM shut down (deallocated) after every session**, so compute isn't billed while idle.
- **Credit checked weekly.**

## Teardown

Delete `rg-sentinel-lab`. Every lab resource goes with it.

## Progress

- [x] Azure for Students subscription
- [ ] Resource group, Log Analytics workspace, Sentinel enabled
- [ ] Windows VM with Sysmon and Azure Monitor Agent
- [ ] Logs arriving in Sentinel
- [ ] Rule 1: renamed system binaries (T1036.003)
- [ ] Rule 2: Microsoft Defender exclusion added (T1562.001)
- [ ] Writeup and lessons learned
