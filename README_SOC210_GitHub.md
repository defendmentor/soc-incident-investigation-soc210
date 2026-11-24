# SOC Incident Investigation Report -- VPN Brute Force (SOC210)

**Project:** Week 6 -- Task 18 Capstone\
**Author:** Yash Jadhav\
**Program:** SOC Analyst Internship -- TechBiz Academy\
**Date:** 24 November 2026\
**Case:** LetsDefend SOC210 -- Possible Brute Force Detected on VPN\
**Event ID:** 162\
**Final verdict:** **TRUE POSITIVE**\
**Analyst-assessed severity:** **High**

## 1. Project overview

This project documents an end-to-end investigation of a simulated VPN
brute-force incident in the LetsDefend SOC training environment. The
investigation correlates the SIEM alert with firewall, VPN
authentication and endpoint detection and response (EDR) events to
determine whether an account was compromised and what happened after
access was obtained.

The analysis covers alert triage, log correlation, username enumeration,
password guessing, successful VPN access, endpoint activity, indicators
of compromise (IOCs), threat-intelligence context, MITRE ATT&CK mapping,
incident impact and response recommendations.

> **Environment note:** The activity and timestamps in this report are
> from LetsDefend's simulated training dataset (21 June 2023). This is a
> lab investigation, not evidence of a real-world compromise.

## 2. Incident summary

An external IP address, `37.19.221[.]229`, generated ten requests to the
VPN gateway over approximately four minutes. The source first attempted
four non-existent usernames (`sane`, `zane`, `fane` and `tane`), then
identified the valid account `mane@letsdefend.io`.

The account experienced three failed password attempts, followed by a
successful VPN login at **13:51:03**. The SOC210 alert was raised at
**13:51:49**. Subsequent endpoint events on host **Mane**
(`172.16.17.210`) recorded a user logon, execution of `powershell.exe`,
and an outbound connection to `185.220.101[.]45:443`.

The successful account access and suspicious post-login activity support
a **True Positive** verdict. The PowerShell command's purpose and the
nature of the outbound traffic were not established in the available
evidence and require L2/Incident Response validation.

## 3. Key investigation findings

-   **Alert:** SOC210 -- Possible Brute Force Detected on VPN (Event ID
    162).
-   **Source IP:** `37.19.221[.]229`.
-   **Target account:** `mane@letsdefend.io`.
-   **Authentication pattern:** Four invalid usernames were tested;
    three password failures for the valid account were followed by a
    successful login.
-   **VPN access:** Successful at 13:51:03 to internal host
    `172.16.17.210`.
-   **Endpoint activity:** User logon at 13:52:10; `powershell.exe`
    execution at 13:54:26.
-   **Outbound activity:** Connection to `185.220.101[.]45:443` at
    13:55:07.
-   **Threat-intelligence context:** AbuseIPDB information recorded in
    the report showed 84 reports and 24% abuse confidence for the source
    IP. Reputation is supporting context, not proof by itself.
-   **Control gaps identified:** No effective VPN MFA, account
    lockout/rate limiting, or generic authentication error messages were
    evident in the scenario.

## 4. Timeline

All times below are the raw log times recorded in the simulated case on
21 June 2023.

  -------------------------------------------------------------------------
  Time                    Source                  Event
  ----------------------- ----------------------- -------------------------
  13:47                   Firewall / VPN          Requests from
                                                  `37.19.221[.]229`; four
                                                  non-existent usernames
                                                  were rejected.

  13:47:12                VPN authentication      First failed login for
                                                  `mane@letsdefend.io`.

  13:48:26                VPN authentication      Second failed login for
                                                  the account.

  13:49:57                VPN authentication      Third failed login for
                                                  the account.

  13:51:03                VPN                     Successful login for
                                                  `mane`; VPN session to
                                                  `172.16.17.210`.

  13:51:49                SIEM                    SOC210 alert raised.

  13:52:10                EDR                     User logon on endpoint
                                                  Mane.

  13:54:26                EDR                     `powershell.exe` process
                                                  execution.

  13:55:07                EDR                     Outbound connection to
                                                  `185.220.101[.]45:443`.
  -------------------------------------------------------------------------

## 5. Indicators of compromise (IOCs)

  ------------------------------------------------------------------------
  Type                    Value                    Context
  ----------------------- ------------------------ -----------------------
  Source IP               `37.19.221[.]229`        External source
                                                   associated with VPN
                                                   brute-force activity.

  Outbound IP             `185.220.101[.]45:443`   Outbound connection
                                                   observed after
                                                   PowerShell execution;
                                                   suspected C2, not
                                                   confirmed.

  Account                 `mane@letsdefend.io`     Valid account used for
                                                   the successful VPN
                                                   login.

  Probed usernames        `sane`, `zane`, `fane`,  Rejected as
                          `tane`                   non-existent; supports
                                                   username-enumeration
                                                   finding.

  Host                    `Mane` --                Endpoint reached
                          `172.16.17[.]210`        through the VPN
                                                   session.

  Process                 `powershell.exe`         Executed at 13:54:26;
                                                   command line requires
                                                   review.
  ------------------------------------------------------------------------

## 6. MITRE ATT&CK mapping

  ------------------------------------------------------------------------
  Tactic            Technique         Evidence /         Confidence
                                      rationale          
  ----------------- ----------------- ------------------ -----------------
  Credential Access **T1110.001 --    Failed logins for  High
                    Brute Force:      the valid account  
                    Password          and username       
                    Guessing**        probing.           

  Initial Access    **T1133 --        Successful login   High
                    External Remote   to the             
                    Services**        internet-facing    
                                      VPN from an        
                                      external IP.       

  Initial Access /  **T1078 -- Valid  Successful use of  High
  Persistence       Accounts**        the valid account. 

  Execution         **T1059.001 --    `powershell.exe`   Medium; command
                    PowerShell**      execution recorded line not reviewed
                                      by EDR.            

  Command and       **T1071.001 --    Outbound           Low; requires
  Control           Web Protocols**   HTTPS-port         validation
                                      connection;        
                                      purpose not        
                                      confirmed.         
  ------------------------------------------------------------------------

## 7. Root cause and impact

### Root cause

The primary weakness was a password-only VPN account that was
successfully guessed within a short period. Contributing factors
identified in the scenario were:

1.  No effective MFA requirement for VPN access.
2.  No effective account lockout or rate limiting after repeated
    failures.
3.  Different error messages for non-existent usernames and incorrect
    passwords, enabling username enumeration.
4.  Detection occurred after the successful login, allowing post-login
    activity before the alert was raised.

### Impact assessment

  -----------------------------------------------------------------------
  Area                    Assessment              Rationale
  ----------------------- ----------------------- -----------------------
  Confidentiality         High                    A valid internal
                                                  session was established
                                                  and outbound
                                                  communication was
                                                  observed; data transfer
                                                  is not confirmed.

  Integrity               Medium                  PowerShell ran on the
                                                  endpoint, but actual
                                                  system changes were not
                                                  established.

  Availability            Low                     No service disruption
                                                  or destructive activity
                                                  was evidenced.

  Scope                   1 user, 1 host          Other accounts and
                          confirmed               hosts would need
                                                  additional hunting.
  -----------------------------------------------------------------------

## 8. Recommended response actions

### Immediate (0--24 hours)

1.  Disable the affected account, revoke active VPN sessions and reset
    its password through the identity team.
2.  Isolate the affected endpoint using the approved EDR process;
    preserve relevant logs, memory and the PowerShell command line.
3.  Review and, where justified, block the source and outbound IPs at
    the firewall.
4.  Search available logs for both IPs and related authentication
    activity to identify any additional affected accounts or hosts.

### Short term (1--2 weeks)

1.  Enforce MFA for all VPN accounts.
2.  Implement account lockout and rate limiting on the VPN gateway.
3.  Return a consistent authentication error for unknown users and
    incorrect passwords.
4.  Create a SIEM detection for three or more VPN failures followed by a
    success from the same IP within ten minutes, with alerting as early
    as possible.

### Long term (30--90 days)

1.  Enforce strong-password controls and screen passwords against known
    breached-password lists.
2.  Restrict VPN access by geography or allow-list where appropriate.
3.  Enable and monitor PowerShell script-block logging and related
    endpoint telemetry.
4.  Run a tabletop exercise using this scenario and update the
    brute-force incident-response playbook.

## 9. Tools and data sources

-   **LetsDefend:** SOC training platform used to review the alert and
    simulated logs.
-   **Monitoring / SIEM alert view:** Initial alert triage and SOC210
    review.
-   **Log Management:** Firewall and VPN authentication event searches
    and correlation.
-   **Endpoint Security / EDR logs:** Endpoint logon, process execution
    and outbound connection review.
-   **AbuseIPDB:** External reputation context for the suspicious source
    IP.
-   **MITRE ATT&CK:** Classification of observed behaviours and
    techniques.

## 10. Final verdict and limitations

**Verdict: TRUE POSITIVE -- VPN brute force resulting in confirmed
account compromise.**

The evidence supports successful use of a valid VPN account and
suspicious activity on the associated endpoint. The case should be
escalated to **L2 / Incident Response** rather than closed at L1.

The available evidence does **not** establish what the PowerShell
command did, whether the outbound connection carried data, or whether
additional hosts or accounts were affected. These remain open
investigation questions.

## 11. Repository contents

Suggested GitHub repository structure:

``` text
soc-incident-investigation-soc210/
├── README.md
├── SOC210_Incident_Investigation_Report.pdf
└── evidence/
    ├── 01-letsdefend-alert.png
    ├── 02-firewall-source-ip-events.png
    ├── 03-vpn-username-enumeration.png
    ├── 04-vpn-failed-and-successful-logins.png
    └── 05-edr-endpoint-activity.png
```

Replace the example filenames with the actual files you upload. Include
the PDF report and relevant screenshots in the repository; do not upload
passwords, access tokens, personal data or unrelated sensitive
information.

## 12. Disclaimer

This repository is for educational and portfolio purposes. It documents
analysis of simulated security events in a controlled training platform.
All testing and investigation activities should be performed only in
environments for which you have explicit authorization.
