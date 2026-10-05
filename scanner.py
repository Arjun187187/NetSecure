import socket
import subprocess
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Alt"
}

RISK_RULES = {
    23: ("HIGH", "Telnet is exposed. Prefer SSH or another encrypted management protocol."),
    21: ("MEDIUM", "FTP is exposed. Prefer SFTP/FTPS and disable anonymous access."),
    445: ("HIGH", "SMB is exposed. Restrict it to trusted hosts/networks."),
    3389: ("HIGH", "RDP is exposed. Restrict access and require strong authentication."),
    3306: ("HIGH", "MySQL is network-exposed. Restrict database access to trusted hosts."),
    5432: ("HIGH", "PostgreSQL is network-exposed. Restrict database access to trusted hosts."),
    80: ("LOW", "HTTP is exposed. If sensitive data is served, use HTTPS."),
    8080: ("LOW", "An alternate HTTP service is exposed. Verify that it is required."),
    139: ("MEDIUM", "NetBIOS is exposed. Restrict legacy file-sharing services where possible.")
}

def check_port(target, port, timeout=0.6):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        return port if sock.connect_ex((target, port)) == 0 else None
    finally:
        sock.close()

def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve target: {target}") from exc

def nmap_service_scan(target, ports):
    if not ports or not shutil.which("nmap"):
        return {}
    port_arg = ",".join(map(str, ports))
    try:
        proc = subprocess.run(
            ["nmap", "-sV", "--open", "-p", port_arg, target],
            capture_output=True, text=True, timeout=60
        )
        services = {}
        for line in proc.stdout.splitlines():
            line = line.strip()
            parts = line.split()
            if len(parts) >= 3 and "/" in parts[0]:
                try:
                    port = int(parts[0].split("/")[0])
                except ValueError:
                    continue
                service = parts[2]
                version = " ".join(parts[3:]) if len(parts) > 3 else ""
                services[port] = {"service": service, "version": version}
        return services
    except (subprocess.SubprocessError, OSError):
        return {}

def scan_target(target):
    ip = resolve_target(target)
    started = datetime.now().isoformat(timespec="seconds")

    open_ports = []
    with ThreadPoolExecutor(max_workers=40) as pool:
        futures = {pool.submit(check_port, ip, p): p for p in COMMON_PORTS}
        for future in as_completed(futures):
            port = future.result()
            if port:
                open_ports.append(port)

    open_ports.sort()
    nmap_data = nmap_service_scan(ip, open_ports)

    findings = []
    for port in open_ports:
        if port in RISK_RULES:
            risk, recommendation = RISK_RULES[port]
        else:
            risk, recommendation = "INFO", "Verify that this service is required and appropriately restricted."

        service = nmap_data.get(port, {}).get("service", COMMON_PORTS.get(port, "Unknown"))
        version = nmap_data.get(port, {}).get("version", "")
        findings.append({
            "port": port,
            "service": service,
            "version": version,
            "risk": risk,
            "recommendation": recommendation
        })

    counts = {level: sum(1 for f in findings if f["risk"] == level)
              for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}

    return {
        "target": target,
        "ip": ip,
        "started": started,
        "ports_scanned": len(COMMON_PORTS),
        "open_ports": len(open_ports),
        "findings": findings,
        "counts": counts,
        "nmap_available": bool(shutil.which("nmap"))
    }
