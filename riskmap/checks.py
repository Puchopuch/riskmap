"""Active checks that complete the Nmap scan.

These checks log in to services, so only run them against machines you are allowed to test.
"""

import socket
import struct
import sys

from riskmap.parser import Host, parse_file
from riskmap.rules import evaluate, load_rules

# MySQL capability flags (see the MySQL "Client/Server Protocol" documentation).
CLIENT_LONG_PASSWORD = 0x00000001
CLIENT_PROTOCOL_41 = 0x00000200
CLIENT_SECURE_CONNECTION = 0x00008000
CLIENT_PLUGIN_AUTH = 0x00080000

RESULT_TEXT = {True: "ACCEPTED", False: "refused", None: "unknown"}


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    """Read exactly `size` bytes (recv can return less than asked)."""
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("connection closed by the server")
        data += chunk
    return data


def _read_packet(sock: socket.socket) -> bytes:
    """A MySQL packet = 3 bytes of length + 1 byte of sequence number + the payload."""
    header = _recv_exact(sock, 4)
    return _recv_exact(sock, int.from_bytes(header[:3], "little"))


def _send_packet(sock: socket.socket, sequence: int, payload: bytes) -> None:
    sock.sendall(len(payload).to_bytes(3, "little") + bytes([sequence]) + payload)


def mysql_empty_password(ip: str, port: int = 3306, user: str = "root", timeout: float = 20) -> bool | None:
    """Try to log in to MySQL with an empty password.

    Returns True (login accepted), False (refused) or None (could not tell).
    The Nmap script waits 5 s for the server greeting. We wait up to `timeout` seconds,
    because old MySQL servers look up the client's name in DNS before they answer.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            # 1. The server speaks first: the greeting starts with the protocol version (10).
            greeting = _read_packet(sock)
            if greeting[0] != 10:  # 0xff = error, e.g. "Host is not allowed to connect"
                return None

            # 2. Read the server capabilities: after the version text, the connection id (4 bytes),
            #    the first part of the salt (8 bytes) and a filler byte.
            pos = greeting.index(b"\x00", 1) + 1 + 4 + 8 + 1
            server_caps = int.from_bytes(greeting[pos:pos + 2], "little")
            if len(greeting) >= pos + 7:
                server_caps |= int.from_bytes(greeting[pos + 5:pos + 7], "little") << 16

            # 3. Answer with the user name and an empty password (auth data of length 0).
            caps = CLIENT_LONG_PASSWORD | CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION
            caps |= server_caps & CLIENT_PLUGIN_AUTH  # only if the server supports it (MySQL >= 5.5)
            login = struct.pack("<IIB23x", caps, 2**24, 33)  # capabilities, max packet size, charset, 23 zero bytes
            login += user.encode() + b"\x00"                  # user name, ended by a zero byte
            login += b"\x00"                                  # password length = 0: empty password
            if caps & CLIENT_PLUGIN_AUTH:
                login += b"mysql_native_password\x00"
            _send_packet(sock, 1, login)

            # 4. 0x00 = OK, 0xff = access denied, 0xfe = "use another auth method": send an empty password again.
            answer = _read_packet(sock)
            if answer[0] == 0xFE:
                _send_packet(sock, 3, b"")
                answer = _read_packet(sock)
            return answer[0] == 0x00
    except (OSError, ValueError, IndexError):
        return None


def run_checks(hosts: list[Host], timeout: float = 20) -> None:
    """Test MySQL root with an empty password wherever Nmap did not report a result."""
    for host in hosts:
        for service in host.services:
            if service.name != "mysql" or "mysql-empty-password" in service.scripts:
                continue
            print(f"[*] {host.ip}:{service.port} MySQL: trying root with an empty password (up to {timeout:.0f} s)...")
            result = mysql_empty_password(host.ip, service.port, timeout=timeout)
            print(f"    result: {RESULT_TEXT[result]}")
            if result:
                service.scripts["mysql-empty-password"] = "root account has empty password (checked by riskmap)"


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python -m riskmap.checks <nmap_report.xml>")
        sys.exit(1)

    hosts = parse_file(sys.argv[1])
    run_checks(hosts)
    critical = [f for f in evaluate(hosts, load_rules()) if f.rule.severity == "critical"]
    for finding in critical:
        print(f"[CRITICAL] {finding.location:<25} {finding.rule.title}  ({finding.evidence})")
    print(f"\n{len(critical)} critical findings")


if __name__ == "__main__":
    main()
