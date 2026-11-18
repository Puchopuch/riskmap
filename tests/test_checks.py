import socket
import struct
import threading

from riskmap.checks import mysql_empty_password


def fake_mysql_server(accepted_user: str) -> int:
    """Start a tiny fake MySQL 5.0 server for one connection. It accepts `accepted_user` with an empty password."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))  # port 0: the system picks a free port
    server.listen(1)

    def handle():
        conn, _ = server.accept()
        with conn, server:
            greeting = (b"\x0a" + b"5.0.51a-3ubuntu5\x00" + struct.pack("<I", 1) + b"12345678\x00"
                        + struct.pack("<H", 0x8201) + b"\x08" + struct.pack("<H", 2) + b"\x00" * 13)
            conn.sendall(len(greeting).to_bytes(3, "little") + b"\x00" + greeting)
            header = conn.recv(4)
            body = conn.recv(int.from_bytes(header[:3], "little"))
            end = body.index(b"\x00", 32)
            user, password_length = body[32:end].decode(), body[end + 1]
            if user == accepted_user and password_length == 0:
                answer = b"\x00\x00\x00\x02\x00"
            else:
                answer = b"\xff\x15\x04#28000Access denied"
            conn.sendall(len(answer).to_bytes(3, "little") + b"\x02" + answer)

    threading.Thread(target=handle, daemon=True).start()
    return server.getsockname()[1]


def test_empty_password_is_detected():
    port = fake_mysql_server(accepted_user="root")
    assert mysql_empty_password("127.0.0.1", port, timeout=5) is True


def test_refused_login_is_reported():
    port = fake_mysql_server(accepted_user="admin")
    assert mysql_empty_password("127.0.0.1", port, timeout=5) is False


def test_closed_port_gives_unknown():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    assert mysql_empty_password("127.0.0.1", port, timeout=2) is None
