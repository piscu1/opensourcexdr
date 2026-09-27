# Security

## Intentionally vulnerable code

The lab profile (`ansible/playbooks/lab/`) deliberately deploys weak firewall rules, vulnerable services and a misconfigured domain controller. That is by design and is documented in [docs/lab-profile.md](docs/lab-profile.md). Please don't report those as vulnerabilities.

If you want something you can actually run, use the hardened profile in `ansible/playbooks/hardened/`.

## Reporting a problem

If you find a real issue, like a weakness in the hardened profile, a flaw in the SOAR engine that could be abused, or a secret that ended up in the repository, please report it privately through GitHub's "Report a vulnerability" button on the Security tab rather than opening a public issue. I'll reply as soon as I can.
