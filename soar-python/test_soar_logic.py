import pytest
import json
import time
from unittest.mock import patch, mock_open, MagicMock
import soar_engine
from soar_engine import evaluate, check_lateral_movement, check_exfiltration, generate_daily_report

BASE_ALERT = {
    "rule": {"level": 12, "id": "5712", "description": "SSH brute force", "groups": ["syslog", "authentication_failed"]},
    "agent": {"id": "001", "ip": "10.0.20.5"},
    "data": {"srcip": "1.2.3.4"}
}


@pytest.fixture(autouse=True)
def reset_state():
    soar_engine._notify_cache.clear()
    soar_engine._blocked_cache.clear()
    soar_engine._lateral_tracker.clear()
    soar_engine._exfil_tracker.clear()
    soar_engine._dest_cache.clear()
    soar_engine._stats["total"]      = 0
    soar_engine._stats["blocks"]     = 0
    soar_engine._stats["isolations"] = 0
    soar_engine._stats["failed"]     = 0
    soar_engine._stats["mttd"]       = []
    soar_engine._stats["mttr"]       = []
    soar_engine._last_report_day     = None


@pytest.mark.asyncio
async def test_base_score_triggers_block():
    with patch("soar_engine.requests.post") as mock_post, \
         patch("builtins.open", mock_open(read_data=json.dumps({}))), \
         patch("os.path.exists", return_value=False):
        mock_post.return_value.status_code = 200
        await evaluate(BASE_ALERT)
        mock_post.assert_called()


@pytest.mark.asyncio
async def test_zone_and_brute_boost_reaches_isolate_threshold():
    with patch("soar_engine.requests.post") as mock_post, \
         patch("soar_engine.subprocess.check_output", return_value="net0: virtio=AA:BB,tag=20"), \
         patch("soar_engine.subprocess.check_call"), \
         patch("builtins.open", mock_open(read_data=json.dumps({}))), \
         patch("os.path.exists", return_value=False):
        mock_post.return_value.status_code = 200
        await evaluate(BASE_ALERT)
        mock_post.assert_called()


@pytest.mark.asyncio
async def test_sqli_alert_triggers_block():
    sqli_alert = {
        "rule": {"level": 10, "id": "31103", "description": "SQL injection attempt", "groups": ["sqlinjection"]},
        "agent": {"id": "002", "ip": "10.0.40.5"},
        "data": {"srcip": "2.3.4.5"}
    }
    with patch("soar_engine.requests.post") as mock_post, \
         patch("builtins.open", mock_open(read_data=json.dumps({}))), \
         patch("os.path.exists", return_value=False):
        mock_post.return_value.status_code = 200
        await evaluate(sqli_alert)
        mock_post.assert_called()


@pytest.mark.asyncio
async def test_fim_ransomware_sends_malware_notification():
    fim_alert = {
        "rule": {"level": 7, "id": "554", "description": "File modified", "groups": ["syscheck"]},
        "agent": {"id": "003", "ip": "10.0.30.5"},
        "data": {},
        "syscheck": {"path": "C:\\TestRansom\\file1.encrypted"}
    }
    with patch("soar_engine.requests.post") as mock_post, \
         patch("builtins.open", mock_open(read_data=json.dumps({}))), \
         patch("os.path.exists", return_value=False):
        mock_post.return_value.status_code = 200
        await evaluate(fim_alert)
        calls = [str(c) for c in mock_post.call_args_list]
        assert any("MALWARE" in c for c in calls)


@pytest.mark.asyncio
async def test_low_level_alert_ignored():
    low_alert = {"rule": {"level": 3, "id": "1000", "description": "Info event", "groups": []}}
    with patch("soar_engine.requests.post") as mock_post, \
         patch("os.path.exists", return_value=False):
        await evaluate(low_alert)
        mock_post.assert_not_called()


def test_lateral_movement_triggers_after_n_hosts():
    with patch("soar_engine.requests.post") as mock_post:
        mock_post.return_value.status_code = 200
        result1 = check_lateral_movement("10.0.20.3", "10.0.10.5")
        result2 = check_lateral_movement("10.0.20.3", "10.0.10.6")
        result3 = check_lateral_movement("10.0.20.3", "10.0.10.7")
        assert not result1
        assert not result2
        assert result3
        calls = [str(c) for c in mock_post.call_args_list]
        assert any("LATERAL" in c for c in calls)


def test_lateral_movement_external_ip_ignored():
    result = check_lateral_movement("8.8.8.8", "10.0.10.5")
    assert not result


@pytest.mark.asyncio
async def test_suppression_of_already_blocked_ip():
    soar_engine._blocked_cache["5.5.5.5"] = time.time()
    alert = {
        "rule": {"level": 12, "id": "5712", "description": "SSH brute force", "groups": []},
        "agent": {"ip": "10.0.20.5"},
        "data": {"srcip": "5.5.5.5"}
    }
    with patch("soar_engine.requests.post") as mock_post, \
         patch("os.path.exists", return_value=False):
        await evaluate(alert)
        mock_post.assert_not_called()
    assert soar_engine._stats["total"] == 1


@pytest.mark.asyncio
async def test_block_failure_sends_escalation_notification():
    with patch("soar_engine.requests.post") as mock_post, \
         patch("builtins.open", mock_open(read_data=json.dumps({}))), \
         patch("os.path.exists", return_value=False):
        mock_post.side_effect = Exception("OPNsense unreachable")
        await evaluate(BASE_ALERT)
        calls = [str(c) for c in mock_post.call_args_list]
        assert any("FAILED" in c or "UNMITIGATED" in c.upper() for c in calls)
    assert soar_engine._stats["failed"] == 1


def test_exfiltration_triggers_above_threshold():
    with patch("soar_engine.requests.post") as mock_post:
        mock_post.return_value.status_code = 200
        soar_engine._dest_cache.clear()
        check_exfiltration("10.0.40.5", "203.0.113.1", 11 * 1024 * 1024)
        calls = [str(c) for c in mock_post.call_args_list]
        assert any("EXFIL" in c for c in calls)


def test_exfiltration_known_destination_ignored():
    with patch("soar_engine.requests.post") as mock_post:
        soar_engine._dest_cache["203.0.113.2"] = time.time()
        check_exfiltration("10.0.40.5", "203.0.113.2", 50 * 1024 * 1024)
        mock_post.assert_not_called()


def test_daily_report_sends_and_resets_stats():
    soar_engine._stats["total"]      = 42
    soar_engine._stats["blocks"]     = 5
    soar_engine._stats["isolations"] = 2
    soar_engine._stats["failed"]     = 1
    with patch("soar_engine.requests.post") as mock_post, \
         patch("builtins.open", mock_open()), \
         patch("os.path.exists", return_value=False):
        mock_post.return_value.status_code = 200
        generate_daily_report()
        calls = [str(c) for c in mock_post.call_args_list]
        assert any("Daily Report" in c for c in calls)
    assert soar_engine._stats["total"] == 0
    assert soar_engine._stats["blocks"] == 0


def test_daily_report_not_sent_twice_same_day():
    with patch("soar_engine.requests.post") as mock_post, \
         patch("builtins.open", mock_open()), \
         patch("os.path.exists", return_value=False):
        mock_post.return_value.status_code = 200
        generate_daily_report()
        generate_daily_report()
        assert mock_post.call_count <= 1


@pytest.mark.asyncio
async def test_dynamic_whitelist_suppresses_action():
    whitelist_data = json.dumps(["9.9.9.9"])
    alert = {
        "rule": {"level": 15, "id": "5712", "description": "SSH brute force", "groups": []},
        "agent": {"ip": "10.0.20.5"},
        "data": {"srcip": "9.9.9.9"}
    }
    with patch("soar_engine.requests.post") as mock_post, \
         patch("os.path.exists", return_value=True), \
         patch("builtins.open", mock_open(read_data=whitelist_data)):
        await evaluate(alert)
        mock_post.assert_not_called()
