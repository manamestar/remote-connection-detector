import psutil
import socket
import requests

def get_public_ip():
    try:
        return requests.get("https://api.ipify.org").text
    except:
        return None

def is_remote(ip):
    # Ignore localhost and private IPs
    private_ranges = [
        ('127.', 'Loopback'),
        ('10.', 'Private'),
        ('172.', 'Private'),
        ('192.168.', 'Private')
    ]
    for prefix, _ in private_ranges:
        if ip.startswith(prefix):
            return False
    return True

def resolve_ip(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"

def check_connections():
    public_ip = get_public_ip()
    print(f"Your public IP: {public_ip}\n")
    connections = psutil.net_connections()
    seen_ips = set()

    for conn in connections:
        if conn.raddr:
            remote_ip = conn.raddr.ip
            if remote_ip not in seen_ips and is_remote(remote_ip):
                seen_ips.add(remote_ip)
                hostname = resolve_ip(remote_ip)
                print(f"[!] Remote Connection Detected:")
                print(f"    ↳ IP: {remote_ip}")
                print(f"    ↳ Hostname: {hostname}")
                print(f"    ↳ Status: {conn.status}")
                print(f"    ↳ Process: {psutil.Process(conn.pid).name()} (PID {conn.pid})\n")

if __name__ == "__main__":
    print("Scanning for remote connections...\n")
    check_connections()
