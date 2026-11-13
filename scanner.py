"""LAN discovery: ping sweep + ARP table + reverse DNS. Stdlib only."""
import ipaddress
import re
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

IS_WIN = sys.platform == "win32"
NOFLAGS = subprocess.CREATE_NO_WINDOW if IS_WIN else 0


def detect_network():
    """Return the IPv4 network of the interface that owns the default route."""
    if IS_WIN:
        out = subprocess.run(["ipconfig"], capture_output=True, text=True,
                             creationflags=NOFLAGS).stdout
        # split into adapter blocks; pick the one with a default gateway
        for block in re.split(r"\r?\n(?=\S)", out):
            ip = re.search(r"IPv4[^:]*:\s*([\d.]+)", block)
            mask = re.search(r"Subnet Mask[^:]*:\s*([\d.]+)", block)
            gw = re.search(r"Default Gateway[^:]*:\s*([\d.]+)", block)
            if ip and mask and gw:
                return ipaddress.ip_network(f"{ip.group(1)}/{mask.group(1)}", strict=False), ip.group(1), gw.group(1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ipaddress.ip_network(f"{ip}/24", strict=False), ip, None


def _ping(ip):
    args = ["ping", "-n", "1", "-w", "400", ip] if IS_WIN else ["ping", "-c", "1", "-W", "1", ip]
    r = subprocess.run(args, capture_output=True, text=True, creationflags=NOFLAGS)
    return ip if r.returncode == 0 and "unreachable" not in r.stdout.lower() else None


def _arp_table():
    out = subprocess.run(["arp", "-a"], capture_output=True, text=True, creationflags=NOFLAGS).stdout
    table = {}
    for m in re.finditer(r"(\d+\.\d+\.\d+\.\d+)\s+(?:at\s+)?([0-9a-fA-F]{2}[:-][0-9a-fA-F:-]{14})", out):
        mac = m.group(2).lower().replace("-", ":")
        if mac not in ("ff:ff:ff:ff:ff:ff",) and not mac.startswith("01:00:5e"):
            table[m.group(1)] = mac
    return table


def _hostname(ip):
    try:
        socket.setdefaulttimeout(1.0)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def scan(network=None):
    net, my_ip, gw = detect_network()
    if network:
        net = ipaddress.ip_network(network, strict=False)
    hosts = [str(h) for h in net.hosts()]
    if len(hosts) > 1024:
        raise ValueError("Network too large to sweep (max /22)")
    with ThreadPoolExecutor(max_workers=128) as ex:
        alive = {ip for ip in ex.map(_ping, hosts) if ip}
    arp = _arp_table()
    in_net = {ip: mac for ip, mac in arp.items() if ipaddress.ip_address(ip) in net}
    ips = sorted(alive | set(in_net), key=lambda x: ipaddress.ip_address(x))
    with ThreadPoolExecutor(max_workers=32) as ex:
        names = dict(zip(ips, ex.map(_hostname, ips)))
    now = int(time.time())
    return {
        "network": str(net), "self": my_ip, "gateway": gw, "scanned_at": now,
        "devices": [{
            "ip": ip, "mac": in_net.get(ip, ""), "hostname": names[ip],
            "online": ip in alive, "is_self": ip == my_ip, "is_gateway": ip == gw,
        } for ip in ips],
    }


def wake_on_lan(mac, broadcast="255.255.255.255"):
    clean = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(clean) != 12:
        raise ValueError("Invalid MAC address")
    packet = b"\xff" * 6 + bytes.fromhex(clean) * 16
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(packet, (broadcast, 9))
