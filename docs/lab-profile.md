# Lab profile

`ansible/playbooks/lab/` is the environment I used for the thesis experiments. It's meant to look like a small company that grew its network without much discipline: a few "temporary" firewall exceptions, a vendor with remote access, a DC with legacy protocols still enabled. The detection and response stack is the same as in the hardened profile, but the targets are deliberately easy to hit so there's something to detect.

Never expose this profile to the internet or to a network you care about.

## Deliberate weaknesses

| Where | What | Why it's there | ATT&CK |
|-------|------|----------------|--------|
| `opnsense/02-setup-aliases.yml` | `VENDOR_REMOTE_IPS` and `DEV_TEAM_HOME_IPS` are `0.0.0.0/0` | "temporary" access ranges that were never narrowed | T1133 |
| `opnsense/03-setup-firewall-wan.yml` | RDP and SSH from the WAN to the edge host, Wazuh UI and SEC zone SSH from the WAN | external entry points for the brute force scenarios | T1110, T1133 |
| `opnsense/04-setup-firewall-vlan10.yml` | OpenVAS can reach all of 10.0.0.0/8 on any port | an over-broad scanner exception | T1046 |
| `opnsense/05-setup-firewall-vlan20.yml` | users to the DC on 1024-65535, DC to the edge on any port | the "admin convenience" RPC range and a patch management path that also works as a reverse shell path | T1021, T1071 |
| `opnsense/06-setup-firewall-vlan30.yml` | users to the DC on any port, ICMP to all internal ranges | troubleshooting rules that were never removed | T1018, T1021 |
| `opnsense/07-setup-firewall-vlan40.yml` | edge to the DC, extra dev ports, full internal access to the edge | a DMZ that isn't really a DMZ | T1210 |
| `15-edge-vulnerable-services.yml` | Apache with `ServerTokens Full` and path traversal, MySQL root from anywhere, Postgres `trust` | vulnerable services for OpenVAS to find | T1190 |
| `12-edge-docker-*.yml` | OWASP Juice Shop, DVWA, UFW disabled on the edge | web targets for the SQL injection scenario | T1190 |
| `terraform-prod/edge-docker-setup.yml` | SSH password authentication enabled | target for the SSH brute force scenario | T1110.001 |
| `windows/setup_dc_vulnerable.yml` | no password complexity, 0 minimum length, weak DSRM password, SMBv1 and Print Spooler on | a legacy DC for the RDP brute force scenario | T1110, T1210 |

Apart from fixes for broken module names and file paths, the lab playbooks are kept as they were when the thesis results were measured, so they are excluded from ansible-lint. Everything else in the repository is linted with the `production` profile.

## Scenarios

The five experiments and their results are in the main [README](../README.md#experiments).
