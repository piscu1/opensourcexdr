# Hardened profile

`ansible/playbooks/hardened/` deploys the same architecture as the lab, without any of the deliberate weaknesses. It follows the policy I originally wrote for the thesis (default deny, least privilege between zones, management only from the admin network) and fixes the places where the lab code never actually matched that policy.

All topology values live in `ansible/playbooks/hardened/vars/network.yml`, and the firewall ruleset is data in `vars/firewall_rules.yml`. Changing an address or adding a rule doesn't mean touching any task.

## Network policy

Every OPNsense interface ends with a logged `default deny`, so anything not listed below is dropped and shows up in Wazuh as a firewall event. Internet egress is limited to web and NTP, and it explicitly excludes RFC 1918 space. That way an "allow web out" rule can't be used to reach another internal zone.

| Zone | Allowed flows |
|------|---------------|
| WAN | admin networks to VLAN 10 on 22/443/9392 (SSH, Wazuh, OpenVAS UI); admin networks to all zones on 22/5986 (Ansible over SSH and WinRM); DMZ services only if listed in `edge_published_ports` (empty by default) |
| All internal | anything sourced from `Blocked_IPs` is dropped first, so SOAR blocks also stop lateral movement, not only inbound traffic |
| SEC (10) | DNS to the firewall; SOAR to the OPNsense API and to Proxmox SSH; OpenVAS to the core, user and edge zones (scanning); web and NTP egress |
| CORE (20) | Wazuh agent; DC DNS forwarding to the firewall; Windows Update; NTP from the DC only |
| USER (30) | AD services to the DC only (DNS, Kerberos, LDAP/LDAPS, SMB, GC, RPC); Wazuh agent; web egress. No DNS to the internet, clients resolve through the DC |
| EDGE (40) | Wazuh agent; DNS to the firewall; web/NTP egress; everything else toward private ranges is blocked and logged |
| Quarantine (99) | not attached to OPNsense at all, a VM moved here has no route anywhere |

Rules are matched on their description, so running the playbook again updates rules in place instead of stacking duplicates.

## Hosts

**Linux (all VMs, including the DMZ host)**
- key-only SSH, no root login, `MaxAuthTries 3`, validated with `sshd -t` before it's applied and checked with `sshd -T` afterwards
- sysctl hardening (no redirects, no source routing, rp_filter, ASLR, no suid core dumps)
- auditd, fail2ban, unattended-upgrades
- UFW with default deny. SSH and the web UIs only from the admin network, and Wazuh agent ports only from the lab zones.

**Windows (DC and endpoints)**
- firewall on for every profile, default deny inbound, blocked connections logged; WinRM over HTTPS only from the admin network
- SMBv1 off, SMB signing required, NTLMv2 only, LLMNR and NetBIOS off
- LSASS as a protected process, WDigest off, Guest disabled
- Print Spooler and Remote Registry disabled, RDP requires NLA
- Defender real-time protection with ASR rules in block mode
- Sysmon (SwiftOnSecurity config), advanced audit policy, PowerShell script block logging, larger event logs
- Wazuh agent

**Domain controller**
- 14 character minimum password length with complexity, a history of 24 passwords, and lockout after 5 failures
- LDAP signing required
- AD ports open only to the user zone

## Secrets

Nothing is stored in the repository. Every credential is read from an environment variable at run time, and a preflight check fails the run early if one is missing or too short.

| Variable | Used for |
|----------|----------|
| `OPNSENSE_API_KEY`, `OPNSENSE_API_SECRET` | OPNsense API (Ansible and the SOAR engine) |
| `WINDOWS_ADMIN_PASSWORD` | WinRM |
| `AD_DSRM_PASSWORD` | Directory Services Restore Mode, 14+ characters |
| `AD_JOIN_USER`, `AD_JOIN_PASSWORD` | joining endpoints to the domain |
| `OPENVAS_ADMIN_PASSWORD` | Greenbone admin, 12+ characters |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | SOAR notifications |

For anything past a home lab, put these in Ansible Vault or your secrets manager and export them in CI rather than in a shell.

## What it doesn't do (yet)

- TLS verification to OPNsense and Proxmox is still off by default, because both use self-signed certificates out of the box. Set `opnsense_ssl_verify: true` and `soar_verify_tls: true` once you have a proper CA.
- The SOAR engine reaches Proxmox as root over SSH. A dedicated Proxmox user with only `VM.Config.Network` through the API would be the right fix.
- Single firewall, no HA.
