"""LAN monitor/controller. Run: python server.py [--host 127.0.0.1] [--port 8080] [--interval 60]"""
import argparse
import json
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import controls
import scanner

ROOT = Path(__file__).parent
DATA_FILE = ROOT / "data.json"
CFG_FILE = ROOT / "config.json"

lock = threading.Lock()
state = {"scan": None, "scanning": False, "events": []}
saved = {"labels": {}, "blocked": [], "limits": {}}  # labels keyed by MAC (or IP if no MAC)
router = controls.RouterBackend()
TOKEN = ""


def load():
    global router
    if DATA_FILE.exists():
        saved.update(json.loads(DATA_FILE.read_text()))
    if CFG_FILE.exists():
        router = controls.make_router(json.loads(CFG_FILE.read_text()))


def persist():
    DATA_FILE.write_text(json.dumps(saved, indent=2))


def key_of(d):
    return d["mac"] or d["ip"]


def do_scan():
    with lock:
        if state["scanning"]:
            return
        state["scanning"] = True
    try:
        result = scanner.scan()
        with lock:
            prev = {key_of(d): d for d in (state["scan"] or {}).get("devices", [])}
            for d in result["devices"]:
                k = key_of(d)
                d["label"] = saved["labels"].get(k, "")
                d["blocked"] = d["mac"] in saved["blocked"]
                d["limit"] = saved["limits"].get(d["mac"], 0)
                was = prev.get(k)
                if state["scan"] and (was is None or was["online"] != d["online"]):
                    state["events"].insert(0, {"t": result["scanned_at"], "key": k, "ip": d["ip"],
                                               "name": d["label"] or d["hostname"],
                                               "what": "joined" if was is None else ("online" if d["online"] else "offline")})
            state["events"] = state["events"][:200]
            state["scan"] = result
    finally:
        state["scanning"] = False


def scan_loop(interval):
    while True:
        try:
            do_scan()
        except Exception as e:  # keep the loop alive
            print("scan error:", e)
        time.sleep(interval)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/api/state":
            with lock:
                self._send(200, {**state, "router": router.name})
        elif self.path in ("/", "/index.html"):
            self._send(200, (ROOT / "index.html").read_bytes(), "text/html; charset=utf-8")
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        # control actions need the token printed at startup (blocks drive-by requests from other sites/devices)
        if not secrets.compare_digest(self.headers.get("X-Token", ""), TOKEN):
            return self._send(401, {"error": "Missing or wrong token"})
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            self._send(200, self.route(body) or {"ok": True})
        except controls.Unsupported as e:
            self._send(501, {"error": str(e)})
        except (ValueError, KeyError) as e:
            self._send(400, {"error": str(e)})
        except Exception as e:
            self._send(500, {"error": str(e)})

    def route(self, b):
        p = self.path
        if p == "/api/scan":
            threading.Thread(target=do_scan, daemon=True).start()
        elif p == "/api/label":
            with lock:
                saved["labels"][b["key"]] = str(b["label"])[:60]
                persist()
        elif p == "/api/wake":
            scanner.wake_on_lan(controls.valid_mac(b["mac"]))
        elif p == "/api/block":
            mac = controls.valid_mac(b["mac"])
            router.block(mac)
            with lock:
                if mac not in saved["blocked"]:
                    saved["blocked"].append(mac)
                persist()
        elif p == "/api/unblock":
            mac = controls.valid_mac(b["mac"])
            router.unblock(mac)
            with lock:
                if mac in saved["blocked"]:
                    saved["blocked"].remove(mac)
                persist()
        elif p == "/api/limit":
            mac, kbps = controls.valid_mac(b["mac"]), int(b["kbps"])
            if kbps < 0:
                raise ValueError("kbps must be >= 0")
            router.limit(mac, kbps, b.get("ip"))
            with lock:
                if kbps:
                    saved["limits"][mac] = kbps
                else:
                    saved["limits"].pop(mac, None)
                persist()
        elif p == "/api/power":
            controls.power_action(b["host"], b["action"])
        else:
            raise KeyError("unknown endpoint")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--interval", type=int, default=60)
    a = ap.parse_args()
    load()
    TOKEN = secrets.token_urlsafe(16)
    threading.Thread(target=scan_loop, args=(a.interval,), daemon=True).start()
    print(f"Dashboard: http://{a.host}:{a.port}\nControl token (paste into the page): {TOKEN}")
    ThreadingHTTPServer((a.host, a.port), Handler).serve_forever()
