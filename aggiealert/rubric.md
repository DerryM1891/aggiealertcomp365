# AggieAlert Severity Rubric (v2)

Applied to grouped SSH authentication alerts (one alert = one connection attempt,
grouped by PID from the OpenSSH Loghub sample). Implemented in `ground_truth.py`.

| Label | Criteria | Example MITRE ATT&CK mapping |
|---|---|---|
| **Critical** | A password was accepted (successful authentication) during the attempt. | T1078 Valid Accounts |
| **High** | Repeated failed-password attempts against the same account in one alert (brute force pattern), OR a failed password targeting `root`. | T1110 Brute Force / T1110.001 |
| **Medium** | (a) An invalid/unknown username was attempted, with or without the "POSSIBLE BREAK-IN ATTEMPT" reverse-DNS flag, OR (b) **new in v2:** a failed password targeted an **existing non-root account** (no "invalid user" tag), with no repeated failures and no success. | T1589.002 / T1110.003 (a), T1110.001 (b) |
| **Low** | Connection opened and closed with no authentication failure recorded (protocol negotiation only, or disconnect before auth). | Reconnaissance / benign scan |

## What changed from v1 and why

v1 had no condition for (b), so `Failed password for mysql` (no "invalid user" tag, which
means the account exists on the host) fell through to Low. Checkpoint 2 found this when
Claude rated two mysql alerts Medium. v2 relabels **15 of 519 alerts** from Low to Medium
(uucp 5, ftp 3, git 3, sshd 2, mysql 2). Nothing else changes.

The detection signal is sshd's own wording: `invalid user <name>` appears only when the
account does not exist.

## Caveat to carry into the write-up

Ground truth is derived deterministically from fields extracted from the same log lines
the rule-based scorer reads, and v2 was written after the Checkpoint 2 disagreement was
seen. Agreement with this rubric measures consistency with a documented policy, not
accuracy against independent analyst labels. Report v1 and v2 together.
