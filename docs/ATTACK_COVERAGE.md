# ATT&CK coverage

The bundled `data/attack.json` contains seven original active MITRE STIX attack-pattern objects, with source URL and source-content SHA-256. The runtime reads names, technique IDs, links and tactics from that subset. Run `python scripts/update_attack.py` to explicitly refresh from MITRE, then review and commit changes. No event data is sent during the download.

| Technique | Signal evidence in this project | Validation status |
|---|---|---|
| [T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001/) | Same-host/source-IP SSH failure burst; no proof of guessing intent or success | Synthetic positive/negative + boundary/order tests |
| [T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001/) | Recognized PowerShell process and monitored command-line markers | Synthetic fixtures; narrow command-line coverage |
| [T1059.004 Unix Shell](https://attack.mitre.org/techniques/T1059/004/) | Recognized Unix shell using `/dev/tcp/` | Synthetic fixtures; not general shell abuse detection |
| [T1053.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005/) | schtasks creation command | Synthetic fixtures; no task artifact confirmation |
| [T1136.001 Local Account](https://attack.mitre.org/techniques/T1136/001/) | useradd requesting UID zero | Synthetic fixtures; command intent, not confirmed account creation |
| [T1548.003 Sudo and Sudo Caching](https://attack.mitre.org/techniques/T1548/003/) | Root shell launched via logged sudo command | Synthetic fixtures; authorization context still required |
| [T1571 Non-Standard Port](https://attack.mitre.org/techniques/T1571/) | Public destination on configured uncommon port | Weak heuristic; cannot establish C2 by itself |

These are behavioral associations to ATT&CK, not claims of full technique coverage. Seven observed technique IDs do not mean seven complete techniques have been detected. The dashboard heat strip counts alerts tagged with each technique; it is neither a coverage percentage over all ATT&CK nor an adversary attribution score. Several techniques have multiple tactics; the dashboard shows the first bundled tactic for compact display while the API returns the complete list.

No malware-family, campaign, actor, exploit, privilege-success or exfiltration claim is inferred solely from these signals. Distinguish what was observed, what the rule inferred and what further evidence would establish intent.
