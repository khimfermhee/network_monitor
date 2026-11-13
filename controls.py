"""Control backends.

Wake-on-LAN and remote power commands work on any network.
Block/unblock and bandwidth limits need a router you can script, so they go
through a pluggable RouterBackend. The default backend is "none" (unsupported).
Configure another one in config.json, e.g.:

  {"router": {"type": "openwrt", "host": "192.168.1.1", "user": "root"}}
"""
import ipaddress
import re
import subprocess
import sys

NOFLAGS = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
HOST_RE = re.compile(r"^[A-Za-z0-9.\-]{1,253}$")


class Unsupported(Exception):
    pass


class RouterBackend:
    name = "none"

    def block(self, mac):
        raise Unsupported("No router backend configured. Set one in config.json (see controls.py).")

    def unblock(self, mac):
        raise Unsupported("No router backend configured.")

    def limit(self, mac, kbps, ip=None):
        raise Unsupported("Bandwidth limits are not available with this router backend.")


class OpenWrtBackend(RouterBackend):
    """Blocks by MAC via nftables over SSH (key-based auth required).
    NOTE: untested against real hardware. Bandwidth limiting (tc/SQM) not implemented yet."""
    name = "openwrt"

    def __init__(self, host, user="root"):
        if not HOST_RE.match(host) or not HOST_RE.match(user):
            raise ValueError("bad router host/user")
        self.target = f"{user}@{host}"

    def _ssh(self, cmd):
        r = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", self.target, cmd],
                           capture_output=True, text=True, timeout=20, creationflags=NOFLAGS)
        if r.returncode != 0:
            raise RuntimeError(r.stderr.strip() or "ssh failed")

    def block(self, mac):
        self._ssh("nft add table inet lanctl 2>/dev/null; "
                  "nft add chain inet lanctl fwd '{ type filter hook forward priority -5 ; }' 2>/dev/null; "
                  f"nft add rule inet lanctl fwd ether saddr {mac} drop comment lanctl-{mac.replace(':','')}")

    def limit(self, mac, kbps, ip=None):
        """Cap a device's speed (kbit/s, both directions) with nft rate-policing by IP. 0 removes the cap.
        Policing drops excess packets (cruder than SQM shaping, but needs no extra packages).
        IP-based: give the device a DHCP reservation so its IP doesn't change."""
        tag = f"lanctl-lim-{mac.replace(':','')}"
        self._ssh(f"for h in $(nft -a list chain inet lanctl fwd 2>/dev/null | grep {tag} "
                  "| sed 's/.*handle //'); do nft delete rule inet lanctl fwd handle $h; done")
        if not kbps:
            return
        ip = str(ipaddress.IPv4Address(ip))
        rate = max(1, int(kbps) // 8)
        self._ssh("nft add table inet lanctl 2>/dev/null; "
                  "nft add chain inet lanctl fwd '{ type filter hook forward priority -5 ; }' 2>/dev/null; "
                  f"nft add rule inet lanctl fwd ip saddr {ip} limit rate over {rate} kbytes/second drop comment {tag}; "
                  f"nft add rule inet lanctl fwd ip daddr {ip} limit rate over {rate} kbytes/second drop comment {tag}")

    def unblock(self, mac):
        self._ssh(f"for h in $(nft -a list chain inet lanctl fwd | grep lanctl-{mac.replace(':','')} "
                  "| sed 's/.*handle //'); do nft delete rule inet lanctl fwd handle $h; done")


def make_router(cfg):
    r = (cfg or {}).get("router") or {}
    if r.get("type") == "openwrt":
        return OpenWrtBackend(r["host"], r.get("user", "root"))
    return RouterBackend()


def valid_mac(mac):
    mac = (mac or "").lower()
    if not MAC_RE.match(mac):
        raise ValueError("Invalid MAC address")
    return mac


def power_action(host, action):
    """Remote shutdown/restart/abort of a Windows PC you administer (needs admin rights + remote shutdown enabled)."""
    if not HOST_RE.match(host or ""):
        raise ValueError("Invalid host")
    flags = {"shutdown": ["/s"], "restart": ["/r"], "abort": ["/a"]}.get(action)
    if flags is None:
        raise ValueError("Unknown action")
    delay = [] if action == "abort" else ["/t", "30"]
    r = subprocess.run(["shutdown", "/m", f"\\\\{host}", *flags, *delay],
                       capture_output=True, text=True, creationflags=NOFLAGS, timeout=20)
    if r.returncode != 0:
        raise RuntimeError((r.stderr or r.stdout).strip() or "shutdown command failed")
