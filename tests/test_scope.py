import ipaddress

import pytest

from riskmap import checks
from riskmap.cli import main
from riskmap.parser import Host, Service
from riskmap.scope import in_scope, load_scope

LAB = [ipaddress.IPv4Network("192.168.242.0/24")]


def test_scope_file_ignores_comments_and_blank_lines(tmp_path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("# my lab\n\n192.168.242.0/24  # host-only network\n10.0.0.5\n")
    assert load_scope(scope_file) == [ipaddress.IPv4Network("192.168.242.0/24"), ipaddress.IPv4Network("10.0.0.5/32")]


def test_scope_file_with_a_bad_line_is_refused(tmp_path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("192.168.242.0/24\nexample.com\n")
    with pytest.raises(ValueError, match="line 2"):
        load_scope(scope_file)


def test_empty_scope_file_is_refused(tmp_path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("# nothing yet\n")
    with pytest.raises(ValueError):
        load_scope(scope_file)


@pytest.mark.parametrize("target, expected", [
    ("192.168.242.128", True),
    ("192.168.242.0/25", True),
    ("192.168.0.0/16", False),   # bigger than the authorized network
    ("10.0.0.1", False),
    ("", False),
])
def test_in_scope(target, expected):
    assert in_scope(target, LAB) is expected


def test_no_login_attempt_outside_the_scope(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("a login was attempted outside the scope")

    monkeypatch.setattr(checks, "mysql_empty_password", forbidden)
    host = Host(ip="10.9.9.9", services=[Service(3306, "tcp", "mysql", "MySQL", "5.0.51a")])
    checks.run_checks([host], LAB)
    assert "mysql-empty-password" not in host.services[0].scripts


def test_checks_without_scope_are_refused():
    assert main(["report", "tests/data/metasploitable.xml", "--checks"]) == 1


def test_scan_outside_the_scope_is_refused(tmp_path, monkeypatch):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("192.168.242.0/24\n")
    monkeypatch.setattr("riskmap.cli.run_nmap", lambda target: pytest.fail("Nmap was started"))
    assert main(["scan", "10.0.0.1", "--scope", str(scope_file)]) == 1


def test_check_still_runs_when_the_nmap_script_failed(monkeypatch):
    monkeypatch.setattr(checks, "mysql_empty_password", lambda *args, **kwargs: True)
    service = Service(3306, "tcp", "mysql", "MySQL", "8.4.3",
                      scripts={"mysql-empty-password": "ERROR: Script execution failed (use -d to debug)"})
    checks.run_checks([Host(ip="192.168.242.10", services=[service])], LAB)
    assert "checked by riskmap" in service.scripts["mysql-empty-password"]


def test_no_second_login_when_nmap_already_found_it(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("useless second login attempt")

    monkeypatch.setattr(checks, "mysql_empty_password", forbidden)
    service = Service(3306, "tcp", "mysql", "MySQL", "5.0.51a",
                      scripts={"mysql-empty-password": "root account has empty password"})
    checks.run_checks([Host(ip="192.168.242.10", services=[service])], LAB)
