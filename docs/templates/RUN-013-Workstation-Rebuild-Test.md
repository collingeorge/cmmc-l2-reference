<!-- Template from the Sanctir reference implementation (CC BY 4.0). Structure of a document that passed a NIST SP 800-171 / CMMC Level 2 self-assessment; contents removed. Replace every placeholder; delete sections that do not apply and say why in the document control table. -->


# REF-RUN-013 — Rebuild test of WS01 against GDE-012

_[Write this section for your company. The original described, in plain sentences: what is in force, who does it, how often, where the evidence is. Cite policy objects, scripts and evidence files by name; an assessor reads this against them.]_

## Gate 0 — WS02 is the admin console for the whole test

_[Write this section for your company. The original described, in plain sentences: what is in force, who does it, how often, where the evidence is. Cite policy objects, scripts and evidence files by name; an assessor reads this against them.]_

## Why this needs gates (lesson from 30 September)

_[Write this section for your company. The original described, in plain sentences: what is in force, who does it, how often, where the evidence is. Cite policy objects, scripts and evidence files by name; an assessor reads this against them.]_

## Gate 1 — Nothing on WS01 is the only copy

| Item | Where it lives | Action before reset |
|------|---------------|---------------------|
| _one row per item; delete this line_ |


## Gate 2 — Break-glass and keys are provably in the tenant (read from the tenant, not the device)

_[Write this section for your company. The original described, in plain sentences: what is in force, who does it, how often, where the evidence is. Cite policy objects, scripts and evidence files by name; an assessor reads this against them.]_

# LAPS backup exists for WS01 (metadata only)
_[Write this section for your company. The original described, in plain sentences: what is in force, who does it, how often, where the evidence is. Cite policy objects, scripts and evidence files by name; an assessor reads this against them.]_

# BitLocker keys, all devices - look for WS01's device id with volumeType 1 (operating system drive).

# Do NOT use a $filter on deviceId: on 30 Sep it returned nothing for a device that had six keys.
_[Write this section for your company. The original described, in plain sentences: what is in force, who does it, how often, where the evidence is. Cite policy objects, scripts and evidence files by name; an assessor reads this against them.]_

## Gate 3 — The join will be accepted

_[Write this section for your company. The original described, in plain sentences: what is in force, who does it, how often, where the evidence is. Cite policy objects, scripts and evidence files by name; an assessor reads this against them.]_

## Gate 4 — Azure Arc will accept the name WS01 again

_[Write this section for your company. The original described, in plain sentences: what is in force, who does it, how often, where the evidence is. Cite policy objects, scripts and evidence files by name; an assessor reads this against them.]_

## Reset

_[Write this section for your company. The original described, in plain sentences: what is in force, who does it, how often, where the evidence is. Cite policy objects, scripts and evidence files by name; an assessor reads this against them.]_

## What to do as Security Officer while it provisions

_[Write this section for your company. The original described, in plain sentences: what is in force, who does it, how often, where the evidence is. Cite policy objects, scripts and evidence files by name; an assessor reads this against them.]_

## Pass criteria (all measured, none assumed)

| Check | Pass |
|-------|------|
| _one row per item; delete this line_ |


## Roll-back

_[Write this section for your company. The original described, in plain sentences: what is in force, who does it, how often, where the evidence is. Cite policy objects, scripts and evidence files by name; an assessor reads this against them.]_
