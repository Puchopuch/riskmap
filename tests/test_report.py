import json

from riskmap.parser import Host, Service
from riskmap.report import to_html, to_json
from riskmap.rules import evaluate, load_rules


def telnet_host(banner: str):
    hosts = [Host(ip="10.0.0.66", services=[Service(23, "tcp", "telnet", banner)])]
    return hosts, evaluate(hosts, load_rules())


def test_html_report_escapes_banners():
    hosts, findings = telnet_host("<script>alert('XSS')</script>")
    html = to_html(hosts, findings)
    assert "<script>alert" not in html
    assert "&lt;script&gt;alert" in html


def test_json_report_is_valid():
    hosts, findings = telnet_host("Linux telnetd")
    data = json.loads(to_json(hosts, findings))
    assert data["summary"]["critical"] == 1
    assert data["findings"][0]["id"] == "TELNET"
    assert data["hosts"][0]["services"][0]["port"] == 23
