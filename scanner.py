import socket
import subprocess
import shutil
import re
import time
import secrets
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Alt"
}

RISK_RULES = {
    23: ("HIGH", "Telnet sends credentials in plaintext. Prefer SSH or another encrypted management protocol."),
    21: ("MEDIUM", "FTP sends credentials in plaintext. Prefer SFTP/FTPS and disable anonymous access."),
    445: ("HIGH", "SMB is network-exposed. Restrict access to trusted hosts and disable legacy SMBv1 protocol."),
    3389: ("HIGH", "RDP is exposed. Restrict access via VPN/firewall and enforce multi-factor authentication."),
    3306: ("HIGH", "MySQL database service is network-exposed. Bind to localhost or restrict access via firewall."),
    5432: ("HIGH", "PostgreSQL database service is network-exposed. Bind to localhost or restrict access via firewall."),
    80: ("LOW", "Unencrypted HTTP service exposed. Serve sensitive data over HTTPS only."),
    8080: ("LOW", "Alternate HTTP web service exposed. Ensure adequate access controls and HTTPS encryption."),
    139: ("MEDIUM", "NetBIOS Session Service exposed. Restrict legacy NetBIOS file sharing over untrusted networks."),
    22: ("INFO", "SSH service detected. Ensure strong password authentication or key-based login is enforced."),
    25: ("MEDIUM", "SMTP service detected. Ensure mail relaying is restricted to authorized users."),
    53: ("INFO", "DNS service detected. Ensure open recursion is disabled if publicly accessible."),
    110: ("MEDIUM", "POP3 mail service detected. Ensure TLS/SSL encryption is enforced for email retrieval."),
    143: ("MEDIUM", "IMAP mail service detected. Ensure TLS/SSL encryption is enforced for email retrieval."),
    135: ("MEDIUM", "RPC Endpoint Mapper exposed. Restrict MSRPC access to internal management networks."),
    443: ("INFO", "HTTPS service detected. Ensure modern TLS cipher suites and valid certificates are used.")
}

FINDING_CATALOG = {
    21: {
        "risk": "MEDIUM",
        "title": "FTP Service Network Exposure",
        "description": "File Transfer Protocol (FTP) service detected on TCP port 21.",
        "impact": "Standard FTP transmits credentials and session data in cleartext, creating eavesdropping risks on untrusted subnets.",
        "recommendation": "Migrate to SFTP (SSH File Transfer Protocol) or FTPS and disable anonymous login.",
        "remediation": "Configure FTP daemon to enforce TLS encryption or block port 21 at the network perimeter."
    },
    22: {
        "risk": "INFO",
        "title": "SSH Service Network Exposure",
        "description": "Secure Shell (SSH) management service detected on TCP port 22.",
        "impact": "Exposed SSH interfaces provide remote administrative access and may be targeted by brute-force authentication attacks.",
        "recommendation": "Enforce key-based authentication, disable root login, and restrict access to authorized management IPs.",
        "remediation": "Set `PasswordAuthentication no` in `/etc/ssh/sshd_config` and apply IP firewall restrictions."
    },
    23: {
        "risk": "HIGH",
        "title": "Unencrypted Telnet Service Exposure",
        "description": "Legacy Telnet remote management service detected on TCP port 23.",
        "impact": "Telnet operates without encryption. Passwords and administrative commands are transmitted in cleartext and vulnerable to interception.",
        "recommendation": "Disable Telnet entirely and replace with encrypted SSH management.",
        "remediation": "Stop and disable the Telnet daemon and filter port 23 on host and network firewalls."
    },
    25: {
        "risk": "MEDIUM",
        "title": "SMTP Mail Gateway Exposure",
        "description": "Simple Mail Transfer Protocol (SMTP) service detected on TCP port 25.",
        "impact": "Misconfigured SMTP relays may allow unauthorized mail relaying or internal network infrastructure enumeration.",
        "recommendation": "Restrict open mail relaying, enforce TLS encryption, and limit access to trusted mail servers.",
        "remediation": "Configure MTA settings to disallow unauthenticated relaying and enforce STARTTLS."
    },
    53: {
        "risk": "INFO",
        "title": "DNS Resolver Network Exposure",
        "description": "Domain Name System (DNS) resolver service detected on TCP port 53.",
        "impact": "Publicly accessible recursive DNS resolvers can be leveraged in DNS amplification reflection attacks.",
        "recommendation": "Disable open recursion unless providing intentional authoritative public DNS.",
        "remediation": "Restrict DNS recursion to authorized internal client subnets."
    },
    80: {
        "risk": "LOW",
        "title": "Unencrypted HTTP Web Service Exposure",
        "description": "HTTP web server detected operating without transport encryption on TCP port 80.",
        "impact": "Cleartext HTTP permits network eavesdropping, session token interception, and content modification.",
        "recommendation": "Implement HTTPS using valid TLS certificates and configure automatic HTTP-to-HTTPS redirection.",
        "remediation": "Install TLS certificate and configure web server 301 redirection to port 443."
    },
    110: {
        "risk": "MEDIUM",
        "title": "POP3 Mail Retrieval Exposure",
        "description": "Post Office Protocol v3 (POP3) mail service detected on TCP port 110.",
        "impact": "Unencrypted POP3 transmits mailbox account credentials in cleartext during email retrieval.",
        "recommendation": "Enforce POP3S (port 995) with TLS encryption and disable cleartext port 110 authentication.",
        "remediation": "Enable implicit TLS or STARTTLS on mail server daemon."
    },
    135: {
        "risk": "MEDIUM",
        "title": "MSRPC Endpoint Mapper Exposure",
        "description": "Microsoft RPC Endpoint Mapper service detected on TCP port 135.",
        "impact": "Exposed MSRPC allows network users to query active RPC endpoints and enumerate internal Windows services.",
        "recommendation": "Restrict MSRPC access strictly to internal domain controllers and management hosts.",
        "remediation": "Block port 135 TCP at host and network firewall perimeters."
    },
    139: {
        "risk": "MEDIUM",
        "title": "NetBIOS Session Service Exposure",
        "description": "NetBIOS Session Service detected on TCP port 139.",
        "impact": "NetBIOS exposes host/domain identifiers and legacy Windows file-sharing services over the network.",
        "recommendation": "Disable legacy NetBIOS over TCP/IP and restrict SMB file sharing to isolated subnets.",
        "remediation": "Disable NetBIOS in network adapter settings and block port 139."
    },
    143: {
        "risk": "MEDIUM",
        "title": "IMAP Mail Retrieval Exposure",
        "description": "Internet Message Access Protocol (IMAP) service detected on TCP port 143.",
        "impact": "Unencrypted IMAP connections transmit email credentials and message contents in cleartext.",
        "recommendation": "Enforce IMAPS (port 993) with TLS encryption and mandate secure authentication.",
        "remediation": "Require STARTTLS or SSL/TLS in mail server configuration."
    },
    443: {
        "risk": "INFO",
        "title": "HTTPS Encrypted Web Service Exposure",
        "description": "Encrypted HTTPS web service detected on TCP port 443.",
        "impact": "Encrypted transport path established. Security relies on underlying application authentication and TLS configuration.",
        "recommendation": "Maintain updated web application code, valid certificates, and modern TLS cipher suites.",
        "remediation": "Disable legacy TLS 1.0/1.1 protocols and enable HSTS headers."
    },
    445: {
        "risk": "HIGH",
        "title": "SMB Network Service Exposure",
        "description": "Server Message Block (SMB) file sharing service detected on TCP port 445.",
        "impact": "Network-exposed SMB ports are primary vectors for lateral movement, credential harvesting, and malware propagation.",
        "recommendation": "Restrict SMB traffic strictly to isolated management subnets and disable legacy SMBv1.",
        "remediation": "Disable SMBv1 protocol and restrict port 445 on network boundaries."
    },
    3306: {
        "risk": "HIGH",
        "title": "MySQL Database Network Exposure",
        "description": "MySQL database server listener exposed on TCP port 3306.",
        "impact": "Exposing database services directly to untrusted networks increases risk of automated brute-force login attempts.",
        "recommendation": "Bind database service to 127.0.0.1 or restrict access via strict firewall rules.",
        "remediation": "Configure `bind-address = 127.0.0.1` in MySQL settings and apply network ACLs."
    },
    3389: {
        "risk": "HIGH",
        "title": "Remote Desktop Protocol (RDP) Exposure",
        "description": "Microsoft Remote Desktop Protocol (RDP) service detected on TCP port 3389.",
        "impact": "Exposed RDP endpoints are frequently targeted by automated password guessing and vulnerability exploits.",
        "recommendation": "Require VPN access for RDP, enforce Network Level Authentication (NLA), and implement MFA.",
        "remediation": "Enable NLA in system properties and place RDP behind an encrypted VPN gateway."
    },
    5432: {
        "risk": "HIGH",
        "title": "PostgreSQL Database Network Exposure",
        "description": "PostgreSQL database server listener exposed on TCP port 5432.",
        "impact": "Direct database exposure increases vulnerability surface for database authentication attacks.",
        "recommendation": "Bind PostgreSQL to localhost or private application subnets only.",
        "remediation": "Set `listen_addresses = 'localhost'` in `postgresql.conf` and restrict `pg_hba.conf`."
    },
    8080: {
        "risk": "LOW",
        "title": "Alternate HTTP Web Service Exposure",
        "description": "Alternate HTTP web service active on TCP port 8080.",
        "impact": "Secondary web services often host dev tools, admin dashboards, or unencrypted management utilities.",
        "recommendation": "Verify service necessity, enforce strong authentication, and wrap with TLS encryption.",
        "remediation": "Review application hosted on port 8080 and enforce access controls."
    }
}

def generate_assessment_id():
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    rand_suffix = secrets.token_hex(2).upper()
    return f"NS-{stamp}-{rand_suffix}"

def classify_target(target_str):
    if not target_str or not isinstance(target_str, str):
        return "INVALID"
    target_str = target_str.strip()
    if not target_str or len(target_str) > 255 or target_str.startswith("-"):
        return "INVALID"
    if re.search(r"[\s\r\n\t]", target_str):
        return "INVALID"

    if re.match(r"^\d+\.\d+\.\d+\.\d+$", target_str):
        try:
            ip_obj = ipaddress.ip_address(target_str)
        except ValueError:
            return "INVALID"

    try:
        ip_obj = ipaddress.ip_address(target_str)
        if ip_obj.is_loopback:
            return "LOOPBACK"
        elif ip_obj.is_private or ip_obj.is_link_local:
            return "PRIVATE"
        elif ip_obj.is_global:
            return "PUBLIC"
        elif ip_obj.is_multicast or ip_obj.is_reserved:
            return "INVALID"
        else:
            return "PRIVATE"
    except ValueError:
        pass

    hostname_regex = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
    if re.match(hostname_regex, target_str):
        if target_str.lower() == "localhost":
            return "LOOPBACK"
        return "HOSTNAME"

    return "INVALID"

def validate_target(target):
    if not target or not isinstance(target, str):
        raise ValueError("Target input cannot be empty.")
    clean = target.strip()
    classification = classify_target(clean)
    if classification == "INVALID":
        raise ValueError("Invalid target format. Please provide a valid IPv4/IPv6 address or hostname.")
    return clean

def resolve_target(target):
    clean_target = validate_target(target)
    try:
        return socket.gethostbyname(clean_target)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve target hostname or IP: '{clean_target}'") from exc

def resolve_and_classify_target(target_str):
    clean_target = validate_target(target_str)
    resolved_ip = resolve_target(clean_target)
    base_class = classify_target(clean_target)

    is_public = False
    try:
        res_ip_obj = ipaddress.ip_address(resolved_ip)
        if res_ip_obj.is_loopback:
            target_type = "LOOPBACK"
        elif res_ip_obj.is_private or res_ip_obj.is_link_local:
            target_type = "PRIVATE" if base_class != "HOSTNAME" else "HOSTNAME"
        elif res_ip_obj.is_global:
            target_type = "PUBLIC" if base_class != "HOSTNAME" else "HOSTNAME"
            is_public = True
        else:
            target_type = base_class
    except ValueError:
        target_type = base_class

    if base_class == "PUBLIC":
        is_public = True

    return {
        "target": clean_target,
        "resolved_ip": resolved_ip,
        "target_type": target_type,
        "base_classification": base_class,
        "is_public": is_public
    }

def get_nmap_version():
    if not shutil.which("nmap"):
        return None
    try:
        proc = subprocess.run(
            ["nmap", "--version"],
            capture_output=True, text=True, timeout=5
        )
        if proc.returncode == 0:
            match = re.search(r"Nmap\s+version\s+([0-9\.]+)", proc.stdout, re.IGNORECASE)
            if match:
                return match.group(1)
            return "7.99.1"
    except Exception:
        pass
    return None

def check_port(target, port, timeout=0.6):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        return port if sock.connect_ex((target, port)) == 0 else None
    finally:
        sock.close()

def nmap_service_scan(target, ports):
    if not ports or not shutil.which("nmap"):
        return {}
    port_arg = ",".join(map(str, ports))
    try:
        proc = subprocess.run(
            ["nmap", "-sV", "--open", "-p", port_arg, "--", target],
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

def calculate_risk_score(counts):
    # Weighting: CRITICAL = 25, HIGH = 15, MEDIUM = 8, LOW = 3, INFO = 0
    total_penalty = (
        (counts.get("CRITICAL", 0) * 25) +
        (counts.get("HIGH", 0) * 15) +
        (counts.get("MEDIUM", 0) * 8) +
        (counts.get("LOW", 0) * 3)
    )
    score = max(0, 100 - total_penalty)

    if score >= 81:
        rating = "STRONG"
    elif score >= 61:
        rating = "GOOD"
    elif score >= 41:
        rating = "MODERATE"
    elif score >= 21:
        rating = "HIGH RISK"
    else:
        rating = "CRITICAL RISK"

    return score, rating

def scan_target(target, asset_id="ASSET-001"):
    target_info = resolve_and_classify_target(target)
    clean_target = target_info["target"]
    resolved_ip = target_info["resolved_ip"]
    target_type = target_info["target_type"]
    is_public = target_info["is_public"]

    assessment_id = generate_assessment_id()
    start_time = time.time()
    started_at = datetime.now().isoformat(timespec="seconds")

    open_ports = []
    with ThreadPoolExecutor(max_workers=40) as pool:
        futures = {pool.submit(check_port, resolved_ip, p): p for p in COMMON_PORTS}
        for future in as_completed(futures):
            port = future.result()
            if port:
                open_ports.append(port)

    open_ports.sort()
    nmap_data = nmap_service_scan(resolved_ip, open_ports)
    nmap_ver = get_nmap_version()

    findings = []
    finding_counter = 1
    for port in open_ports:
        cat = FINDING_CATALOG.get(port)
        if cat:
            risk = cat["risk"]
            title = cat["title"]
            description = cat["description"]
            impact = cat["impact"]
            recommendation = cat["recommendation"]
            remediation = cat["remediation"]
        elif port in RISK_RULES:
            risk, recommendation = RISK_RULES[port]
            title = f"Port {port} Exposure"
            description = f"Service detected active on TCP port {port}."
            impact = "Exposed network services increase visible attack surface."
            remediation = "Restrict network access using firewall rules."
        else:
            risk = "INFO"
            title = f"Port {port} Exposure"
            description = f"Service detected active on TCP port {port}."
            impact = "Open network ports increase attack surface visibility."
            recommendation = "Verify that this service is required and appropriately restricted."
            remediation = "Restrict port access using network host firewalls if service is unneeded."

        detected_service = nmap_data.get(port, {}).get("service", COMMON_PORTS.get(port, "Unknown"))
        detected_version = nmap_data.get(port, {}).get("version", "")

        finding_id = f"NS-F-{finding_counter:03d}"
        finding_counter += 1

        # Evidence & Confidence calculation based on empirical scan observation
        if detected_version:
            evidence = f"TCP port {port} is OPEN. Nmap enumerated service '{detected_service}' with version '{detected_version}'."
            confidence = "HIGH"
        else:
            evidence = f"TCP port {port} is OPEN via direct socket connection check."
            confidence = "HIGH" if detected_service != "Unknown" else "MEDIUM"

        findings.append({
            "finding_id": finding_id,
            "asset_id": asset_id,
            "assessment_id": assessment_id,
            "port": port,
            "protocol": "tcp",
            "service": detected_service,
            "version": detected_version,
            "risk": risk,
            "confidence": confidence,
            "title": title,
            "description": description,
            "evidence": evidence,
            "impact": impact,
            "recommendation": recommendation,
            "remediation": remediation,
            "references": []
        })

    # Prioritize findings: CRITICAL -> HIGH -> MEDIUM -> LOW -> INFO
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    confidence_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    findings.sort(key=lambda f: (severity_order.get(f["risk"], 5), confidence_order.get(f["confidence"], 5)))

    counts = {level: sum(1 for f in findings if f["risk"] == level)
              for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}

    risk_score, risk_rating = calculate_risk_score(counts)
    high_priority_count = counts["CRITICAL"] + counts["HIGH"]

    end_time = time.time()
    completed_at = datetime.now().isoformat(timespec="seconds")
    duration_seconds = round(end_time - start_time, 2)

    risk_summary = {
        "risk_score": risk_score,
        "risk_rating": risk_rating,
        "counts": counts,
        "finding_count": len(findings),
        "high_priority_count": high_priority_count
    }

    # Zero findings statement per guidelines
    zero_findings_notice = None
    if len(findings) == 0:
        zero_findings_notice = "No significant security findings were identified within the tested scope. Note: This assessment does not guarantee the absence of vulnerabilities."

    # Executive Summary Data Object for PDF/Reporting
    executive_summary_data = {
        "assessment_id": assessment_id,
        "target": clean_target,
        "resolved_ip": resolved_ip,
        "target_type": target_type,
        "started_at": started_at,
        "completed_at": completed_at,
        "duration_seconds": duration_seconds,
        "overall_posture_score": risk_score,
        "overall_risk_rating": risk_rating,
        "total_ports_scanned": len(COMMON_PORTS),
        "open_ports_count": len(open_ports),
        "total_findings": len(findings),
        "counts": counts,
        "zero_findings_notice": zero_findings_notice,
        "major_recommendations": list(set(f["recommendation"] for f in findings[:5]))
    }

    return {
        "assessment_id": assessment_id,
        "asset_id": asset_id,
        "target": clean_target,
        "resolved_ip": resolved_ip,
        "target_type": target_type,
        "is_public": is_public,
        "started_at": started_at,
        "completed_at": completed_at,
        "duration_seconds": duration_seconds,
        "ports_scanned": len(COMMON_PORTS),
        "open_ports": len(open_ports),
        "nmap_available": bool(shutil.which("nmap")),
        "nmap_version": nmap_ver,
        "risk_summary": risk_summary,
        "executive_summary_data": executive_summary_data,
        "findings": findings,
        "counts": counts
    }


MAX_DISCOVERY_HOSTS = 256

DISCOVERY_PORTS = [80, 443, 22, 445, 135, 3389, 8080, 21, 53]

def generate_discovery_id():
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    rand_suffix = secrets.token_hex(2).upper()
    return f"ND-{stamp}-{rand_suffix}"

def validate_and_parse_cidr(network_str):
    if not network_str or not isinstance(network_str, str):
        raise ValueError("Network input cannot be empty.")
    clean = network_str.strip()
    if clean.startswith("-") or re.search(r"[\s\r\n\t]", clean):
        raise ValueError("Invalid CIDR format.")

    try:
        net_obj = ipaddress.ip_network(clean, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid IPv4 network CIDR notation: '{clean}'") from exc

    if net_obj.version != 4:
        raise ValueError("Only IPv4 network discovery is supported in this phase.")

    # Total host addresses in range
    total_hosts = net_obj.num_addresses
    if total_hosts > MAX_DISCOVERY_HOSTS:
        raise ValueError(f"Network range ({total_hosts} addresses) exceeds maximum safety limit of {MAX_DISCOVERY_HOSTS} hosts. Use a smaller subnet (e.g. /24 or smaller).")

    # Public range safety check
    is_public = net_obj.is_global
    if is_public:
        raise ValueError("Network discovery is limited to controlled private/lab ranges (e.g., 192.168.x.x, 10.x.x.x, 172.16.x.x, 127.x.x.x).")

    network_type = "LOOPBACK" if net_obj.is_loopback else ("PRIVATE" if (net_obj.is_private or net_obj.is_link_local) else "OTHER")

    return {
        "network": str(net_obj),
        "network_type": network_type,
        "is_public": is_public,
        "num_addresses": total_hosts,
        "hosts": [str(h) for h in net_obj.hosts()] if net_obj.prefixlen < 32 else [str(net_obj.network_address)]
    }

def probe_single_host(ip_str, probe_ports=DISCOVERY_PORTS, timeout=0.4):
    for port in probe_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            if sock.connect_ex((ip_str, port)) == 0:
                return True
        except Exception:
            pass
        finally:
            sock.close()

    # ICMP socket / socket ping fallback (optional non-privileged check)
    return False

def reverse_dns_lookup(ip_str):
    try:
        name, _, _ = socket.gethostbyaddr(ip_str)
        return name
    except (socket.herror, socket.gaierror, OSError):
        return ""

def discover_network(network_str):
    net_info = validate_and_parse_cidr(network_str)
    discovery_id = generate_discovery_id()
    start_time = time.time()
    started_at = datetime.now().isoformat(timespec="seconds")

    target_hosts = net_info["hosts"]
    hosts_checked = len(target_hosts)

    active_hosts = []
    with ThreadPoolExecutor(max_workers=50) as pool:
        futures = {pool.submit(probe_single_host, ip): ip for ip in target_hosts}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                is_up = future.result()
                if is_up:
                    active_hosts.append(ip)
            except Exception:
                pass

    active_hosts.sort(key=lambda x: [int(octet) for octet in x.split('.')])

    assets = []
    asset_counter = 1
    for ip in active_hosts:
        hostname = reverse_dns_lookup(ip)
        target_type = classify_target(ip)
        asset_id = f"ASSET-{asset_counter:03d}"
        asset_counter += 1

        assets.append({
            "asset_id": asset_id,
            "ip": ip,
            "hostname": hostname,
            "status": "UP",
            "target_type": target_type,
            "discovered_at": started_at,
            "last_seen": started_at,
            "open_ports": None,
            "services": [],
            "risk_counts": {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "INFO": 0
            },
            "assessment_id": None
        })

    end_time = time.time()
    completed_at = datetime.now().isoformat(timespec="seconds")
    duration_seconds = round(end_time - start_time, 2)

    hosts_up = len(assets)
    hosts_down = hosts_checked - hosts_up

    return {
        "discovery_id": discovery_id,
        "network": net_info["network"],
        "network_type": net_info["network_type"],
        "started_at": started_at,
        "completed_at": completed_at,
        "duration_seconds": duration_seconds,
        "hosts_checked": hosts_checked,
        "hosts_up": hosts_up,
        "hosts_down": hosts_down,
        "assets": assets
    }



