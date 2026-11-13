# network_monitor

Web dashboard that scans your LAN and controls devices. Python standard library only.

    python server.py [--host 127.0.0.1] [--port 8080] [--interval 60]

Open the printed URL and paste the control token into the page to use actions.

- Monitoring: ping sweep + ARP, hostnames, join/offline log, device names
- Wake-on-LAN, remote Windows shutdown/restart
- Block / bandwidth limit: need a scriptable router. Set `config.json`:
  `{"router": {"type": "openwrt", "host": "192.168.1.1", "user": "root"}}`
  (OpenWrt backend is untested on real hardware)
