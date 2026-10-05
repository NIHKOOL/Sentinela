# Writing detection rules

Every `.yml` file in this folder is a detection rule, written in a Sigma-style YAML format ([Sigma](https://sigmahq.io) is the open standard for SIEM rules). Sentinela loads the rules at startup. After you add or change a file, click **Reload rules** on the Overview page; you don't need to restart.

If a rule has a mistake, Sentinela skips it and shows the reason on the Overview page and in the terminal. The other rules keep working.

## A detection rule (one event)

```yaml
title: Discovery command executed      # required: shown in alerts
id: SEN-001                            # required to raise alerts
status: stable
description: A built-in tool attackers use to learn about a system was run.
author: Your Name
date: 2026-10-06
tags:
  - attack.discovery                   # MITRE tactic
  - attack.t1033                       # MITRE technique -> shown as T1033
logsource:
  category: process_creation           # which events to look at
detection:
  selection:                           # a named group of conditions
    process_file:
      - whoami.exe
      - net.exe
  filter_it:
    user: it-admin
  condition: selection and not filter_it
falsepositives:                        # shown to the SOC analyst
  - Administrators checking a server
level: medium                          # informational, low, medium, high, critical
details: "'{process_file}' was run by '{user}' on {hostname}."   # alert message
```

### logsource categories

| `category` | Event types |
|---|---|
| `process_creation` | `process_creation` |
| `authentication` | `authentication_success`, `authentication_failure` |
| `network_connection` | `network_connection` |
| `account_management` | `account_created` |

Without a `logsource`, the rule looks at every event.

### Fields

| Field | Example |
|---|---|
| `hostname` | `DC01` |
| `event_type` | `authentication_failure` |
| `user` | `administrator` |
| `source_ip` | `203.0.113.7` |
| `process_name` | `C:\Windows\System32\whoami.exe` |
| `process_file` | `whoami.exe` (file name only, lowercase) |
| `command_line` | `net user` |
| `target_user` | `svc-update` (the new account, for `account_created`) |
| `dest_ip`, `dest_port` | `203.0.113.50`, `443` |
| `bytes_out`, `bytes_out_mb` | `300000000`, `300` |

The common Sigma names `Image`, `CommandLine`, `User`, `TargetUserName`, `IpAddress`, `SourceIp`, `DestinationIp`, `DestinationPort` and `Computer` also work.

### Matching values

* Text matching ignores upper and lower case.
* A list means **any** of the values: `user: [administrator, root]`.
* `*` matches any text and `?` matches one character: `process_name: 'C:\Users\*\tool.exe'`.
* `null` means the field is empty: `source_ip: null`.

| Modifier | Meaning | Example |
|---|---|---|
| `contains` | text appears anywhere | `command_line\|contains: '/domain'` |
| `startswith` / `endswith` | text at the start / end | `process_name\|endswith: '\cmd.exe'` |
| `re` | regular expression (case-sensitive) | `command_line\|re: '-enc(odedcommand)?\s'` |
| `cidr` | IP address is in a network | `source_ip\|cidr: 10.0.0.0/8` |
| `gt`, `gte`, `lt`, `lte` | number comparison | `bytes_out\|gte: 50000000` |
| `exists` | field has a value (`true`) or not (`false`) | `dest_ip\|exists: true` |
| `all` | **all** list values must match | `command_line\|contains\|all: [net, user]` |

### Selections and conditions

* Inside a selection, every field must match (**and**).
* A selection can also be a list of mappings, in which case any one of them may match (**or**).
* `condition` combines selections with `and`, `or`, `not` and parentheses.
* `1 of filter_*` means any selection whose name starts with `filter_`; `all of them` means every selection.

## A correlation rule (a pattern over time)

A correlation rule builds on other rules by their `name`. A rule with a `name` but no `id` is a **building block**: it never raises alerts by itself. You can put several rules in one file, separated by `---`.

```yaml
title: Failed logon
name: failed_logon
logsource:
  category: authentication
detection:
  selection:
    event_type: authentication_failure
  condition: selection
---
title: "Brute force: many failed logons"
id: SEN-003
name: brute_force_logons       # optional: lets other correlations use this one
correlation:
  type: event_count
  rules: [failed_logon]
  group-by: [hostname, source_ip]   # count separately per host + source IP
  timespan: 60s                     # s, m, h or d
  condition:
    gte: 5
level: high
details: "{count} failed logons on {hostname} from {source_ip} within {timespan}."
```

| `type` | Fires when… | `condition` |
|---|---|---|
| `event_count` | enough matching events happen within the timespan | `gte: 5` (or `gt`, `lt`, `lte`, `eq`) |
| `value_count` | enough **different** values of a field appear | `field: user` plus `gte: 10` |
| `temporal` | all listed rules match within the timespan, in any order | not needed |
| `temporal_ordered` | all listed rules match within the timespan, in the listed order | not needed |

In `details`, correlations can also use `{count}` and `{timespan}`.

## Exercise: catch lateral movement

The **Lateral movement** attack is not detected by any of the shipped rules. Create `sen-008-lateral-movement.yml`:

```yaml
title: Admin logon from a non-IT workstation
id: SEN-008
description: An admin account logged on from an internal machine that is not the IT workstation.
tags:
  - attack.lateral_movement
  - attack.t1021
logsource:
  category: authentication
detection:
  selection:
    event_type: authentication_success
    user: [administrator, root]
    source_ip|cidr: 10.0.0.0/8       # from inside the company network
  it_workstation:
    source_ip: 10.0.1.20             # WS-IT01, where admins normally work
  condition: selection and not it_workstation
falsepositives:
  - An administrator working from another desk
level: high
details: "'{user}' logged on to {hostname} from {source_ip}, which is not an IT workstation."
```

Then click **Reload rules**, launch **Lateral movement** on the Attacker page, and watch "Not detected" turn into "Detected".

**More ideas to try:**
* **Password spraying:** use `value_count` to catch one source IP failing logons for many different users.
* **Tuning:** remove SEN-001's false positives from `it-admin` with a filter, then check whether you would still catch a real attacker.

## Differences from Sigma

* A rule raises alerts only if it has an `id`, which can be any text such as `SEN-008`. Sigma uses UUIDs, plus `generate` for building blocks.
* `details` is a Sentinela addition.
* `logsource.product` and `logsource.service` are ignored. Only `category` is used.
* The field names are Sentinela's own, plus the aliases listed above.
