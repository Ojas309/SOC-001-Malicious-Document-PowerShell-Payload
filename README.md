# SOC-001 — Malicious Document → PowerShell → Payload

## Incident Overview

- Incident ID: SOC-001
- Severity: High
- Affected Host: PC-15
- User: User01
- Status: Contained / Under Investigation

## 1. Initial Access

The attack likely began when the user opened the malicious `Salary_Revision.docx` document.

The document then caused `winword.exe` to launch PowerShell.

## 2. Execution

PowerShell was executed by Microsoft Word using suspicious parameters including:

- `-ExecutionPolicy Bypass`
- `-WindowStyle Hidden`

**MITRE ATT&CK:** T1059.001 — PowerShell

## 3. Payload Delivery

PowerShell used `Invoke-WebRequest` to download `a.exe` from:

`185.20.10.5`

**MITRE ATT&CK:** T1105 — Ingress Tool Transfer

## 4. Persistence

A Windows Registry Run Key was created so the executable could potentially run automatically when the user logs in.

**MITRE ATT&CK:** T1547.001 — Registry Run Keys / Startup Folder

## 5. Network Activity

The downloaded executable was located at:

`C:\Users\Public\a.exe`

Observed network activity:

`a.exe → 185.20.10.5:443`

Data theft has **not** been confirmed from the available evidence.

## 6. MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|---|---|---|
| User Execution: Malicious File | T1204.002 | User opened suspicious document |
| PowerShell | T1059.001 | Word launched PowerShell |
| Ingress Tool Transfer | T1105 | PowerShell downloaded `a.exe` |
| Registry Run Keys / Startup Folder | T1547.001 | Registry persistence created |

## 7. Attack Chain

```text
Salary_Revision.docx
        ↓
winword.exe
        ↓
powershell.exe
        ↓
Invoke-WebRequest
        ↓
a.exe
        ↓
185.20.10.5:443
        ↓
Registry Run Key Persistence
