# docs/templates/

The structure of every controlled document behind a NIST SP 800-171 / CMMC Level 2 self-assessment, with the contents removed. Each file keeps the original's title, document-control table, section headings and table headers; every section body is a placeholder telling you what the original said there. Fill them in your own words, for your own system. Licence: CC BY 4.0.

## The set

| ID | Document | What it is for | Requirements it mainly evidences |
|---|---|---|---|
| SSP-001 | System Security Plan | The one document an assessor reads first: boundary, components, users, data flows, and for every requirement what is in force and where the evidence is | 3.12.4 and all others by reference |
| POAM-002 | Plan of Action and Milestones | Every weakness, numbered, with owner, milestone and status; closed items kept with their closure evidence | 3.12.2 |
| POL-003 | Access Control and Identification | Accounts, roles, privilege, authentication methods, session rules, break-glass | 3.1.x, 3.5.x |
| POL-004 | Awareness and Training | Who is trained in what, how often, where the record is | 3.2.x |
| POL-008 | AI Acceptable Use | Which AI services are approved, what may and may not be sent to them, how it is enforced | 3.1.20, 3.1.22, 3.13.x |
| POL-009 | Personnel and Physical Protection | Screening, termination, visitors, home-office and travel controls | 3.9.x, 3.10.x |
| PRO-005 | Audit and Accountability | What is logged, where it goes, retention and immutability, alerting, the review schedule and its record | 3.3.x |
| PRO-008 | Maintenance and Media Protection | Maintenance by whom and how, removable media, sanitisation, backups | 3.7.x, 3.8.x |
| PRO-010 | Risk and Security Assessment | The risk register, the assessment method and schedule, vulnerability review | 3.11.x, 3.12.x |
| PLN-006 | Configuration Management and Change Register | The baseline principle, the change process, and the dated register every change goes into | 3.4.x |
| PLN-007 | Incident Response and Register | Roles, detection sources, the response steps, the 72-hour reporting path, the tested escalation, the register | 3.6.x |
| PLN-010 | Endpoint Baseline Architecture | How the device baseline is built, enforced and held (policies, remediations, firewall model) | 3.4.x, 3.13.x |
| STD-011 | Service Baseline | Which Windows services must run, must not run, and how that is enforced | 3.4.6, 3.4.7 |
| STD-021 | Network Gateway Rules | The egress and DNS filtering rules, in precedence order, each with its log-then-block history | 3.1.20, 3.13.1, 3.13.6 |
| STD-023 | Endpoint and Tenant Baseline Standard | The approved baseline: which snapshot, how it is compared, how a change gets approved | 3.4.1, 3.4.2 |
| STM-011 | System and Communications Protection | Encryption in transit and at rest, FIPS, boundary protection, session security | 3.13.x |
| RUN-016 | Break-Glass Account Runbook | How the emergency account is kept, tested, used and recorded | 3.1.1, 3.5.3, 3.6.1 |
| GDE-012 | New Computer Set-up | The enrolment procedure a non-specialist can follow | 3.4.1, 3.4.2 |
| RUN-013 | Workstation Rebuild Test | Proof that a wiped device returns to the baseline from the tenant alone | 3.4.1 |
| INV-012 | Asset Inventory | Every device, account, service and key in the boundary | 3.4.1 |
| TCP-017 | Technology Control Plan | For export-controlled data: who may access, how it is marked, stored, transmitted and destroyed | 3.1.x, 3.8.x, 3.13.x |
| TRN-019 | Security Training Modules | The training content itself, module by module, with the record of completion | 3.2.1–3.2.3 |
| LOG-020 | Security Advisory Review | The record of advisories read and acted on | 3.11.3, 3.14.3 |
| DOC-000 | Completion Checklist | The order in which the set was completed, and what "complete" meant for each | — |

## How to fill them

- **Write what is true, not what is planned.** Every sentence that says "is" must be true on the day; plans go in the POA&M with a date.
- **Name the evidence.** A policy object, a script, an evidence file, a register row. "See Evidence\<date>\audit-tenant-<time>.txt §5" is the sentence an assessor wants; "we have MFA" is not.
- **Keep the registers alive.** PLN-006's change register and PLN-007's incident register are the two documents that prove the others are real. A register with no entries for a month is a finding.
- **Correct, never rewrite.** When a statement turns out to be wrong, add a dated correction next to it. A silently edited document is worse than a wrong one.
- **Version and sign.** The document-control table carries version, date and the approver's name. SPRS asks for the SSP's version and date; keep them exact.

## Numbering

`<TYPE>-<NNN>` where TYPE is POL (policy), PRO (procedure), PLN (plan), STD (standard), RUN (runbook), GDE (guide), TRN (training), INV (inventory), LOG (log), TCP (technology control plan), SSP, POAM. The numbers are the order they were written; keep yours stable once a document is cited by another.
