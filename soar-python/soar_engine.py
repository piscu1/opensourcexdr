import json
import time
import requests
import urllib3
import asyncio
import os
import subprocess
import re
from collections import defaultdict
from datetime import datetime
from typing import Optional

def load_env(path: str = ".env") -> None:
    if os.path.exists(path):
        with open(path, "r") as f:
            for line in f:
                if line.strip() and not line.startswith("#"):
                    key, value = line.strip().split("=", 1)
                    os.environ[key] = value

load_env()
load_env("/opt/soar/.env")

ALERTS_FILE      = os.getenv("WAZUH_ALERTS_FILE",    "/var/ossec/logs/alerts/alerts.json")
OPENVAS_MAP_FILE = os.getenv("OPENVAS_VULN_MAP_PATH", "/opt/soar/openvas_snapshot.json")
POINTER_FILE     = os.getenv("SOAR_POINTER_FILE",     "/opt/soar/alerts.pointer")
WHITELIST_FILE   = os.getenv("SOAR_WHITELIST_FILE",   "/opt/soar/whitelist.json")
REPORT_FILE      = os.getenv("SOAR_REPORT_FILE",      "/opt/soar/daily_report.json")

OPNSENSE_URL    = os.getenv("OPNSENSE_BASE_URL", "https://10.0.10.1/api/firewall/alias_util/add/Blocked_IPs")
OPNSENSE_KEY    = os.getenv("OPNSENSE_API_KEY", "")
OPNSENSE_SECRET = os.getenv("OPNSENSE_API_SECRET", "")
VERIFY_TLS      = os.getenv("VERIFY_TLS", "false").lower() == "true"
PROXMOX_HOST    = os.getenv("PROXMOX_HOST", "192.168.1.7")

if not VERIFY_TLS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TG_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TG_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID", "")

WHITELIST = ["10.0.10.1", "10.0.10.5", "10.0.10.6", "127.0.0.1"]

VM_MAP = {
    "10.0.40.5": "400",
    "10.0.20.5": "500",
    "10.0.30.5": "600",
}

COOLDOWN_SECONDS  = 300
BLOCK_THRESHOLD   = 50
ISOLATE_THRESHOLD = 80

LATERAL_N    = 3
LATERAL_T    = 300
EXFIL_BYTES  = 10 * 1024 * 1024
EXFIL_T      = 300
DEST_TTL     = 86400
REPORT_HOUR  = 8

_notify_cache:    dict = {}
_blocked_cache:   dict[str, float] = {}
_lateral_tracker: dict[str, list]  = defaultdict(list)
_exfil_tracker:   dict[str, list]  = defaultdict(list)
_dest_cache:      dict[str, float] = {}
_stats: dict = {
    "total":      0,
    "sources":    defaultdict(int),
    "rules":      defaultdict(int),
    "blocks":     0,
    "isolations": 0,
    "failed":     0,
    "mttd":       [],
    "mttr":       [],
    "since":      time.time(),
}
_last_report_day: Optional[str] = None


def notify(msg: str, key: Optional[tuple] = None) -> None:
    if key:
        now = time.time()
        if now - _notify_cache.get(key, 0) < COOLDOWN_SECONDS:
            return
        _notify_cache[key] = now
    url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
    try:
        requests.post(url, json={"chat_id": TG_CHAT_ID, "text": msg, "parse_mode": "Markdown"}, timeout=2)
    except:
        pass


def load_dynamic_whitelist() -> list[str]:
    if not os.path.exists(WHITELIST_FILE):
        return []
    try:
        with open(WHITELIST_FILE, "r") as f:
            data = json.load(f)
        return data if isinstance(data, list) else data.get("whitelist", [])
    except:
        return []


def _opnsense_block(ip: str) -> bool:
    for attempt in range(3):
        try:
            requests.post(
                OPNSENSE_URL,
                json={"address": ip},
                auth=(OPNSENSE_KEY, OPNSENSE_SECRET),
                verify=VERIFY_TLS,
                timeout=2,
            )
            return True
        except:
            if attempt < 2:
                time.sleep(2 ** attempt)
    return False


def block_ip(ip: str, agent_ip: str, rule_id: str, breakdown: str) -> None:
    if not ip or ip in WHITELIST:
        return
    t0 = time.time()
    print(f"[ACTION] Null Routing {ip} on OPNsense...")
    msg = (
        f"*PHASE 1: NETWORK BLOCK*\n\nDetected attack from `{ip}`.\n\n"
        f"*Scoring Breakdown:*\n{breakdown}\n\n*Action:* Null-routing IP at firewall."
    )
    notify(msg, key=(ip, agent_ip, rule_id))
    if _opnsense_block(ip):
        _blocked_cache[ip] = time.time()
        _stats["blocks"] += 1
        _stats["mttr"].append(time.time() - t0)
    else:
        _stats["failed"] += 1
        notify(
            f"*ACTION FAILED — MANUAL INTERVENTION REQUIRED*\n\n"
            f"SOAR could not block `{ip}` after 3 retries.\n"
            f"OPNsense API is unreachable or returned an error.\n"
            f"*Threat remains UNMITIGATED.*"
        )
        print(f"[UNMITIGATED] Block failed for {ip} — OPNsense API error.")


def isolate_vm(agent_ip: str, src_ip: str, score: int, breakdown: str) -> None:
    vmid = VM_MAP.get(agent_ip)
    if not vmid:
        return
    proxmox_host = PROXMOX_HOST
    t0 = time.time()
    try:
        out = subprocess.check_output(
            f"ssh -o StrictHostKeyChecking=no root@{proxmox_host} 'qm config {vmid} | grep ^net0:'",
            shell=True, text=True
        ).strip()
        net0 = out.split("net0: ")[1].strip()
        if "tag=99" in net0:
            return
        msg = (
            f"*PHASE 2: HOST ISOLATION*\n\nCritical score reached on `{agent_ip}` (VM {vmid}).\n\n"
            f"*Scoring Breakdown:*\n{breakdown}\n\n*Action:* Instructing Proxmox to move host to **VLAN 99** (Isolated)."
        )
        notify(msg)
        new_net0 = re.sub(r'tag=\d+', 'tag=99', net0) if "tag=" in net0 else f"{net0},tag=99"
        for attempt in range(3):
            try:
                subprocess.check_call(
                    f"ssh -o StrictHostKeyChecking=no root@{proxmox_host} 'qm set {vmid} -net0 {new_net0}'",
                    shell=True
                )
                notify(f"*SUCCESS*\n\nVM {vmid} is now air-gapped.")
                _stats["isolations"] += 1
                _stats["mttr"].append(time.time() - t0)
                return
            except:
                if attempt < 2:
                    time.sleep(2 ** attempt)
        _stats["failed"] += 1
        notify(
            f"*ACTION FAILED — MANUAL INTERVENTION REQUIRED*\n\n"
            f"SOAR could not isolate VM `{vmid}` after 3 retries.\n"
            f"Proxmox SSH is unreachable.\n"
            f"*Host `{agent_ip}` remains UNMITIGATED.*"
        )
    except Exception as e:
        notify(f"*ERROR*\n\nFailed to isolate VM {vmid}. Error: `{e}`")


def check_lateral_movement(src_ip: str, target_ip: str) -> bool:
    if not src_ip or not src_ip.startswith("10.0."):
        return False
    now = time.time()
    events = [(ts, dst) for ts, dst in _lateral_tracker[src_ip] if now - ts < LATERAL_T]
    if target_ip not in {dst for _, dst in events}:
        events.append((now, target_ip))
    _lateral_tracker[src_ip] = events
    unique_targets = {dst for _, dst in events}
    if len(unique_targets) >= LATERAL_N:
        affected = ", ".join(f"`{t}`" for t in unique_targets)
        notify(
            f"*LATERAL MOVEMENT DETECTED*\n\n"
            f"Source `{src_ip}` reached {len(unique_targets)} distinct hosts in {LATERAL_T}s.\n"
            f"*Affected hosts:* {affected}\n\n"
            f"*Action:* Isolating source host.",
            key=(src_ip, "lateral"),
        )
        return True
    return False


def check_exfiltration(src_ip: str, dst_ip: str, bytes_out: int) -> None:
    if bytes_out <= 0 or not dst_ip:
        return
    now = time.time()
    if now - _dest_cache.get(dst_ip, 0) > DEST_TTL:
        events = [(ts, dst, b) for ts, dst, b in _exfil_tracker[src_ip] if now - ts < EXFIL_T]
        events.append((now, dst_ip, bytes_out))
        _exfil_tracker[src_ip] = events
        total = sum(b for _, d, b in events if d == dst_ip)
        if total > EXFIL_BYTES:
            mb = total / (1024 * 1024)
            notify(
                f"*DATA EXFILTRATION DETECTED*\n\n"
                f"Host `{src_ip}` sent {mb:.1f} MB to `{dst_ip}` in {EXFIL_T}s.\n"
                f"Destination not seen in last 24h.\n"
                f"*Action:* Manual investigation required.",
                key=(src_ip, dst_ip, "exfil"),
            )
    _dest_cache[dst_ip] = now


def generate_daily_report() -> None:
    global _last_report_day
    today = datetime.now().strftime("%Y-%m-%d")
    if _last_report_day == today:
        return
    _last_report_day = today

    top_sources = sorted(_stats["sources"].items(), key=lambda x: x[1], reverse=True)[:5]
    top_rules   = sorted(_stats["rules"].items(),   key=lambda x: x[1], reverse=True)[:5]
    mttd_avg    = sum(_stats["mttd"]) / len(_stats["mttd"]) if _stats["mttd"] else 0
    mttr_avg    = sum(_stats["mttr"]) / len(_stats["mttr"]) if _stats["mttr"] else 0

    report = {
        "date":          today,
        "total_alerts":  _stats["total"],
        "top_sources":   top_sources,
        "top_rules":     top_rules,
        "blocks":        _stats["blocks"],
        "isolations":    _stats["isolations"],
        "failed_actions": _stats["failed"],
        "mttd_avg_s":    round(mttd_avg, 2),
        "mttr_avg_s":    round(mttr_avg, 2),
    }
    try:
        with open(REPORT_FILE, "w") as f:
            json.dump(report, f, indent=2)
    except:
        pass

    src_lines  = "\n".join(f"  {ip}: {n}" for ip, n in top_sources)  or "  N/A"
    rule_lines = "\n".join(f"  {r}: {n}"  for r, n in top_rules)     or "  N/A"
    notify(
        f"*SOAR Daily Report — {today}*\n\n"
        f"Total alerts: {_stats['total']}\n"
        f"Blocks: {_stats['blocks']} | Isolations: {_stats['isolations']} | Failed: {_stats['failed']}\n"
        f"MTTD avg: {mttd_avg:.1f}s | MTTR avg: {mttr_avg:.1f}s\n\n"
        f"*Top sources:*\n{src_lines}\n\n"
        f"*Top rules:*\n{rule_lines}"
    )

    _stats["total"]      = 0
    _stats["sources"]    = defaultdict(int)
    _stats["rules"]      = defaultdict(int)
    _stats["blocks"]     = 0
    _stats["isolations"] = 0
    _stats["failed"]     = 0
    _stats["mttd"]       = []
    _stats["mttr"]       = []
    _stats["since"]      = time.time()


async def daily_report_scheduler() -> None:
    while True:
        if datetime.now().hour == REPORT_HOUR:
            generate_daily_report()
        await asyncio.sleep(60)


async def tail() -> None:
    pos = 0
    if os.path.exists(POINTER_FILE):
        with open(POINTER_FILE, 'r') as f:
            try:
                pos = int(f.read().strip() or 0)
            except:
                pass
    while not os.path.exists(ALERTS_FILE):
        await asyncio.sleep(1)
    with open(ALERTS_FILE, 'r') as f:
        f.seek(pos)
        while True:
            line = f.readline()
            if not line:
                await asyncio.sleep(0.1)
                continue
            with open(POINTER_FILE, 'w') as ptr:
                ptr.write(str(f.tell()))
            try:
                await evaluate(json.loads(line))
            except:
                continue


async def evaluate(alert: dict) -> None:
    rule        = alert.get('rule', {})
    level       = rule.get('level', 0)
    rule_id     = rule.get('id', '0000')
    description = rule.get('description', '')
    groups      = str(rule.get('groups', ''))

    src_ip = alert.get('data', {}).get('win', {}).get('eventdata', {}).get('ipAddress', '')
    if not src_ip: src_ip = alert.get('data', {}).get('srcip', '')
    if not src_ip: src_ip = alert.get('data', {}).get('src_ip', '')
    if not src_ip: src_ip = alert.get('srcip', '')
    if src_ip and "::ffff:" in src_ip:
        src_ip = src_ip.replace("::ffff:", "")

    target_ip = alert.get('agent', {}).get('ip', '')
    if not target_ip or target_ip == 'any':
        target_ip = alert.get('data', {}).get('dest_ip', '')
    if not target_ip:
        target_ip = alert.get('data', {}).get('dstip', '')

    dynamic_wl = load_dynamic_whitelist()
    effective_whitelist = WHITELIST + dynamic_wl
    if src_ip and src_ip in effective_whitelist:
        print(f"[WHITELIST] {src_ip} — log-only, no action.")
        return

    if src_ip and src_ip in _blocked_cache:
        if time.time() - _blocked_cache[src_ip] < COOLDOWN_SECONDS:
            print(f"[SUPPRESS] {src_ip} already blocked, suppressing.")
            _stats["total"] += 1
            return

    if (level < 5
            and "sqlinjection" not in groups.lower()
            and "scan" not in description.lower()
            and "syscheck" not in groups.lower()):
        return

    t_start = time.time()
    _stats["total"] += 1
    if src_ip:
        _stats["sources"][src_ip] += 1
    _stats["rules"][rule_id] += 1

    bytes_out = int(alert.get('data', {}).get('bytes_toserver', 0) or 0)
    dst_ip    = alert.get('data', {}).get('dest_ip', '') or alert.get('data', {}).get('dstip', '')
    if bytes_out and src_ip and dst_ip:
        check_exfiltration(src_ip, dst_ip, bytes_out)

    lateral = check_lateral_movement(src_ip, target_ip) if src_ip and target_ip else False

    score  = level * 2
    detail = [f"- Base Score (Lvl {level}*2): {score}"]

    if target_ip.startswith("10.0.20."):
        score += 40
        detail.append("- Zone Boost (CORE/DC): +40")
    elif target_ip.startswith("10.0.30."):
        score += 20
        detail.append("- Zone Boost (USER/WS): +20")
    elif target_ip.startswith("10.0.40."):
        score += 10
        detail.append("- Zone Boost (EDGE): +10")

    bf_keywords = ["brute force", "multiple failed", "authentication failed", "logon failure", "scan", "reconnaissance"]
    if any(k in description.lower() for k in bf_keywords):
        score += 30
        detail.append("- Attack Pattern (Brute/Scan): +30")

    if "sqlinjection" in groups.lower() or "sql injection" in description.lower():
        score += 40
        detail.append("- Attack Type (SQLi): +40")

    is_fim = False
    if "syscheck" in groups.lower() or rule_id in ['550', '553', '554']:
        file_path = str(alert.get('syscheck', {}).get('path', ''))
        if '.encrypted' in file_path.lower() or 'ransom' in description.lower():
            score += 50
            detail.append("- Attack Pattern (Ransomware/FIM): +50")
            is_fim = True

    if lateral:
        score = max(score, ISOLATE_THRESHOLD)
        detail.append("- Lateral Movement: score forced to ISOLATE threshold")

    try:
        with open(OPENVAS_MAP_FILE, 'r') as f:
            vuln_map = json.load(f)
    except:
        vuln_map = {}

    for vuln in vuln_map.get(target_ip, []):
        if "sql" in vuln.lower() and ("sql" in description.lower() or "sqlinjection" in groups.lower()):
            score += 80
            detail.append(f"- Vuln Correlation ({vuln}): +80")
        elif "rdp" in vuln.lower() and "rdp" in description.lower():
            score += 80
            detail.append(f"- Vuln Correlation ({vuln}): +80")

    detail.append(f"*Total Score: {score}*")
    breakdown = "\n".join(detail)

    _stats["mttd"].append(time.time() - t_start)
    print(f"\n[EVAL] {description} | Target: {target_ip} | Score: {score}")

    if src_ip in effective_whitelist:
        return

    if score >= BLOCK_THRESHOLD:
        if is_fim:
            notify(
                f"*PHASE 1: MALWARE DETECTED*\n\nRansomware-like FIM activity on `{target_ip}`.\n\n"
                f"*Scoring Breakdown:*\n{breakdown}\n\n*Action:* Escalating to host isolation.",
                key=(target_ip, rule_id, "fim")
            )
        else:
            block_ip(src_ip, target_ip, rule_id, breakdown)

    if score >= ISOLATE_THRESHOLD:
        isolate_vm(target_ip, src_ip if src_ip else target_ip, score, breakdown)


if __name__ == "__main__":
    print("Starting Transparent SOAR Engine...")
    asyncio.run(asyncio.gather(tail(), daily_report_scheduler()))
