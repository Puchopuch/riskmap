from pathlib import Path

import pytest
from defusedxml import DefusedXmlException

from riskmap.parser import parse_file, parse_nmap_xml

DATA = Path(__file__).parent / "data"


def test_metasploitable_scan_is_parsed():
    hosts = parse_file(DATA / "metasploitable.xml")
    assert len(hosts) == 1
    host = hosts[0]
    assert host.ip == "192.168.242.128"
    assert len(host.services) == 23
    ftp = next(service for service in host.services if service.port == 21)
    assert ftp.banner == "vsftpd 2.3.4"
    assert "Anonymous FTP login allowed" in ftp.scripts["ftp-anon"]
    assert "SMBv1" in host.scripts["smb-protocols"]


def test_down_hosts_and_closed_ports_are_ignored():
    xml = """<nmaprun>
      <host><status state="down"/><address addr="10.0.0.1" addrtype="ipv4"/></host>
      <host><status state="up"/><address addr="10.0.0.2" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
          <port protocol="tcp" portid="23"><state state="closed"/><service name="telnet"/></port>
        </ports>
      </host>
    </nmaprun>"""
    hosts = parse_nmap_xml(xml)
    assert [host.ip for host in hosts] == ["10.0.0.2"]
    assert [service.port for service in hosts[0].services] == [22]


def test_xml_bomb_is_refused():
    bomb = """<?xml version="1.0"?>
    <!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">]>
    <nmaprun>&lol2;</nmaprun>"""
    with pytest.raises(DefusedXmlException):
        parse_nmap_xml(bomb)
