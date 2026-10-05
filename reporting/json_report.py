import json
from pathlib import Path
from datetime import datetime

REPORT_JSON_DIR = Path("reports/json")
REPORT_JSON_DIR.mkdir(parents=True, exist_ok=True)

def generate_json_report(assessment_data, output_dir=None):
    if output_dir:
        out_path = Path(output_dir)
    else:
        out_path = REPORT_JSON_DIR
    out_path.mkdir(parents=True, exist_ok=True)

    is_discovery = "discovery_id" in assessment_data
    report_id = assessment_data.get("assessment_id") or assessment_data.get("discovery_id") or "NS-UNKNOWN"

    report_type = "Network Discovery Assessment" if is_discovery else "Network Vulnerability Assessment"
    generated_at = datetime.now().isoformat(timespec="seconds")

    report_metadata = {
        "report_type": report_type,
        "report_version": "1.0",
        "generated_at": generated_at,
        "assessment_id": report_id,
        "tool": "NetSecure Defensive Assessment Platform",
        "tool_version": "1.0.0"
    }

    if is_discovery:
        filename = f"NetSecure_ND-{report_id.replace('ND-', '')}.json"
        payload = {
            "report_metadata": report_metadata,
            "discovery": {
                "discovery_id": report_id,
                "network": assessment_data.get("network"),
                "network_type": assessment_data.get("network_type"),
                "started_at": assessment_data.get("started_at"),
                "completed_at": assessment_data.get("completed_at"),
                "duration_seconds": assessment_data.get("duration_seconds", 0.0),
                "hosts_checked": assessment_data.get("hosts_checked", 0),
                "hosts_up": assessment_data.get("hosts_up", 0),
                "hosts_down": assessment_data.get("hosts_down", 0)
            },
            "assets": assessment_data.get("assets", []),
            "disclaimer": "This report reflects asset reachability observations from the defined CIDR network discovery scope."
        }
    else:
        filename = f"NetSecure_NS-{report_id.replace('NS-', '')}.json"
        risk_summary = assessment_data.get("risk_summary") or {}
        exec_data = assessment_data.get("executive_summary_data") or {}
        findings = assessment_data.get("findings") or []

        open_ports = []
        for f in findings:
            open_ports.append({
                "port": f.get("port"),
                "protocol": f.get("protocol", "tcp"),
                "service": f.get("service", "Unknown"),
                "version": f.get("version", ""),
                "risk": f.get("risk", "INFO")
            })

        recommendations = []
        for f in findings:
            if f.get("recommendation") and f["recommendation"] not in recommendations:
                recommendations.append(f["recommendation"])

        payload = {
            "report_metadata": report_metadata,
            "assessment": {
                "assessment_id": report_id,
                "asset_id": assessment_data.get("asset_id", "ASSET-001"),
                "target": assessment_data.get("target"),
                "resolved_ip": assessment_data.get("resolved_ip"),
                "target_type": assessment_data.get("target_type"),
                "is_public": assessment_data.get("is_public", False),
                "started_at": assessment_data.get("started_at"),
                "completed_at": assessment_data.get("completed_at"),
                "duration_seconds": assessment_data.get("duration_seconds", 0.0)
            },
            "scope": {
                "ports_scanned": assessment_data.get("ports_scanned", 16),
                "network": None
            },
            "scanner": {
                "nmap_available": assessment_data.get("nmap_available", False),
                "nmap_version": assessment_data.get("nmap_version") or "N/A"
            },
            "summary": {
                "risk_score": risk_summary.get("risk_score", 100),
                "risk_rating": risk_summary.get("risk_rating", "STRONG"),
                "finding_count": len(findings),
                "high_priority_count": risk_summary.get("high_priority_count", 0),
                "counts": risk_summary.get("counts") or {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
                "zero_findings_notice": exec_data.get("zero_findings_notice")
            },
            "open_ports": open_ports,
            "findings": findings,
            "recommendations": recommendations,
            "disclaimer": "This report reflects observations from the defined assessment scope and time of testing. It does not guarantee the absence of vulnerabilities or security weaknesses outside the tested scope. Assessment activities should only be performed against systems for which the assessor has ownership or explicit authorization."
        }

    filepath = out_path / filename
    filepath.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    return filepath, filename, payload
