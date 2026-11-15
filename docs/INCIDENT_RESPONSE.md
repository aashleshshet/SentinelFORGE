# Incident response workflow

The system records decisions; it does not act on endpoints.

1. **Validate the signal.** Open an alert's case and inspect its rule rationale, required telemetry, confidence and exact event evidence. Confirm the source/sensor and account attribution. A command string alone may not prove successful execution.
2. **Scope activity.** Review case hosts/users and the event-time timeline. Host matching wins before non-generic user matching within the 15-minute activity interval. Unrelated activity may correlate, and related cases are not automatically merged.
3. **Assign and record.** Assign a configured analyst, change Open → Investigating, and add investigation notes. Notes are append-only through the API, stored with author and server timestamp. Checklists are analyst attestations, not automated proof.
4. **Preserve.** Create an evidence snapshot before changing your conclusions. It includes the case, its notes, alerts, normalized evidence and original raw envelopes, plus preservation time and actor. Subsequent notes do not alter earlier snapshots.
5. **Export and verify.** Download the JSON report and run `python scripts/verify_evidence.py REPORT.json`. A matching SHA-256 means the report matches its manifest, not that it is authenticated or legally admissible evidence.
6. **Escalate deliberately.** Set the case to Escalated and record scope, evidence, uncertainty and the next decision. There is no automatic email, ticket or Slack notification.
7. **Simulate response.** An analyst requests simulated isolation with a reason. A different administrator approves it once. The result is an audit entry stating that no endpoint/network action occurred. Self-approval and repeat approval are rejected. Local token-free mode has one identity; use authenticated mode to demonstrate two-person approval.
8. **Close with context.** Record your disposition and why. Closing excludes the case from future automatic correlation. Status can be corrected or reopened; that change is audited.

## Example: edge-01

The synthetic demo's SSH password-guessing case collects five failures from `192.0.2.45`, a shell TCP-redirection command, a UID-zero account-creation command, and a sudo root-shell entry. The UID-zero event intentionally arrives after later event-time data. The timeline sorts by original event time, and the risk heuristic caps at 100. This is a teaching sequence, not evidence that a real attack occurred.

A useful note separates observation from inference: “Observed five failed SSH authentications, followed by shell and account-management commands. Need successful-login/session linkage and account inventory before asserting compromise.” Then preserve the evidence, record the missing information and choose escalation or closure.

## Forensic limits

This is application-level evidence preservation. It does not acquire disk/memory images, validate sensor signatures, synchronize endpoint clocks, capture full packet payloads, sign reports or enforce WORM retention. Database operators can modify stored data. Restrict database access and export a signed external manifest if custody matters. Avoid pasting credentials or unnecessary personal information into notes.
