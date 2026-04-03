import socket
import ipaddress
from urllib.parse import urlparse

BLOCKED_RANGES = [
    "169.254.0.0/16",  # AWS metadata
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16"
]

def is_safe_target(url: str):
    try:
        host = urlparse(url).hostname
        ip = socket.gethostbyname(host)
        ip_obj = ipaddress.ip_address(ip)

        for r in BLOCKED_RANGES:
            if ip_obj in ipaddress.ip_network(r):
                return False
        return True
    except:
        return False