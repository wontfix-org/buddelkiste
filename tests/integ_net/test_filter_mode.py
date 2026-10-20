from __future__ import annotations

import pytest

pytestmark = pytest.mark.e2e


def test_filter_mode_runs_command(run_bk) -> None:
    proc = run_bk("--net-allow", "1.1.1.1/32", "--", "/bin/true")
    assert proc.returncode == 0, proc.stderr or proc.stdout


def test_filter_mode_implies_from_deny_preset(run_bk) -> None:
    proc = run_bk("--net-deny-preset", "metadata", "--", "/bin/true")
    assert proc.returncode == 0, proc.stderr or proc.stdout


def test_filter_allows_listed_ip(run_bk) -> None:
    proc = run_bk(
        "--net-allow",
        "1.1.1.1/32",
        "--",
        "/usr/bin/python3",
        "-c",
        "import socket; "
        "s=socket.create_connection(('1.1.1.1', 443), 5); "
        "s.close(); "
        "print('OK')",
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    assert "OK" in proc.stdout


def test_filter_denies_unlisted_ip(run_bk) -> None:
    """Deny policy rejects a public address that is not on the allow list.

    Default policy is allow, so this case has to opt into deny. 9.9.9.9 is
    not on the allow list.
    """
    proc = run_bk(
        "--net-policy",
        "deny",
        "--net-allow",
        "1.1.1.1/32",
        "--",
        "/usr/bin/python3",
        "-c",
        "import socket; "
        "socket.create_connection(('9.9.9.9', 443), 3)",
    )
    assert proc.returncode != 0
    # Connection should fail before printing success.
    assert "OK" not in proc.stdout


def test_filter_default_policy_resolves_public_names(run_bk) -> None:
    """Default allow must still resolve public names.

    A host resolv.conf that only lists the systemd-resolved stub (127.0.0.53)
    is not a usable resolver inside the pasta netns. ``bk run`` with no
    hostname rules must still answer getaddrinfo for a public name.
    """
    proc = run_bk(
        "--",
        "/usr/bin/python3",
        "-c",
        "import socket; "
        "infos=socket.getaddrinfo("
        "'www.heise.de', 80, family=socket.AF_INET); "
        "print(infos[0][4][0])",
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    assert proc.stdout.strip()


def test_filter_default_policy_connects_public_https(run_bk) -> None:
    """Default filter must open TCP/443 to a public name.

    Same path as ``curl --connect-timeout=3 https://www.heise.de`` inside
    ``bk run`` with no extra allow rules: resolve IPv4, then connect.
    Default policy is allow, so the public address is reachable. The internal
    and localhost deny presets still reject private and loopback ranges.
    """
    proc = run_bk(
        "--",
        "/usr/bin/python3",
        "-c",
        "import socket\n"
        "infos=socket.getaddrinfo("
        "'www.heise.de', 443, family=socket.AF_INET, type=socket.SOCK_STREAM)\n"
        "ip=infos[0][4][0]\n"
        "print('IP:'+ip)\n"
        "s=socket.create_connection((ip, 443), 3)\n"
        "s.close()\n"
        "print('OK')\n",
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    assert "OK" in proc.stdout


def test_filter_hostname_allow_via_dns_proxy(run_bk) -> None:
    # Prefer IPv4: pasta filter netns often has no IPv6 route, so connecting to
    # the first getaddrinfo result (commonly AAAA) fails with ENETUNREACH.
    proc = run_bk(
        "--net-allow",
        "one.one.one.one",
        "--",
        "/usr/bin/python3",
        "-c",
        "import socket; "
        "infos=socket.getaddrinfo("
        "'one.one.one.one', 443, family=socket.AF_INET, type=socket.SOCK_STREAM); "
        "info=infos[0]; "
        "s=socket.socket(info[0], info[1], info[2]); "
        "s.settimeout(5); "
        "s.connect(info[4]); "
        "s.close(); "
        "print('OK')",
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    assert "OK" in proc.stdout

